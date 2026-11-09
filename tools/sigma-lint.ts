#!/usr/bin/env bun
// *****************************************************************************
// *Title: sigma-lint*
// *Author: Kyle Versluis*
// *Description: Hold each pack rule's Sigma YAML and Wazuh XML to one another.*
// *****************************************************************************

// *--- Imports ---*

import { Database } from "bun:sqlite";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { isPack, readRulesDir, repeatedIds, type WazuhRule } from "./wazuh-rules.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const SIGMA_DIR = "phase-b-detection/sigma";
const RULES_DIR = "deploy/soc-recon/wazuh/custom-rules";
const MITRE_IDS = "phase-b-detection/mitre-db-ids.txt";
const SIGMAHQ_IDS = "phase-b-detection/sigmahq-ids.txt";
// ISA ISC-140: the only levels a pack rule may carry.
const LEVELS: Record<string, number> = { medium: 10, high: 12, critical: 15 };
// Paths the command line reads when no flag names one, relative to the repo root.
export const DEFAULTS = { sigma: SIGMA_DIR, rules: RULES_DIR, mitre: MITRE_IDS, sigmahq: SIGMAHQ_IDS };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Technique tags compare without regard to case; anything else that starts like one is
// malformed rather than ignored.
const ATTACK_TAG = /^attack\.t\d{4}(\.\d{3})?$/i;
// No ATT&CK tactic tag starts with "t", so any attack.t tag must be a technique.
const ATTACK_TAG_START = /^attack\.t/i;
// The only <mitre><id> form a pack rule may carry: the reader keeps the text as written.
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;

// *--- Types ---*

export interface Finding {
  file: string;
  rule: number;
  problem: string;
}

export interface SigmaRule {
  file: string;
  // Untyped YAML until lintPack has checked it.
  doc: any;
}

// *--- Helper Functions ---*

const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join() === [...b].sort().join();

// *--- Core Logic ---*

// A YAML the lint and logtest cannot both see is one they would silently pass, so a
// subfolder YAML or one that does not parse throws instead of being dropped.
/** Every Sigma YAML at the top of a folder; a missing folder holds none. */
export function readSigma(dir: string): SigmaRule[] {
  if (!existsSync(dir)) return [];
  const isYaml = (n: string) => /\.ya?ml$/i.test(n);
  const walk = (d: string) => {
    for (const n of readdirSync(d).sort()) {
      const path = join(d, n);
      if (statSync(path).isDirectory()) walk(path);
      else if (d !== dir && isYaml(n)) throw new Error(`${relative(ROOT, path)}: Sigma YAML in a subfolder, which sigma-lint never reads`);
    }
  };
  walk(dir);
  return readdirSync(dir)
    .filter((n) => isYaml(n) && !statSync(join(dir, n)).isDirectory())
    .sort()
    .map((n) => {
      const file = relative(ROOT, join(dir, n));
      try {
        return { file, doc: Bun.YAML.parse(readFileSync(join(dir, n), "utf8")) };
      } catch (e) {
        throw new Error(`${file}: YAML does not parse: ${e instanceof Error ? e.message : String(e)}`);
      }
    });
}

// An empty status is active; any other names an id its source has withdrawn. Only the words
// the list's own refresh writes are read, and a line holding more is refused, because the
// lint would otherwise take a hand-edited word as a withdrawn status. A repeated id throws,
// because the later line would silently replace the earlier status.
/** An id list as a refresh command writes it: an id and an optional status per line. */
function readIdList(text: string, what: string, statuses: string[], normal = (id: string) => id): Map<string, string> {
  const ids = new Map<string, string>();
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const [raw, status = "", ...rest] = t.split(/\s+/);
    const id = normal(raw);
    if (rest.length) throw new Error(`${what} ${id} has more than an id and a status on its line`);
    if (status && !statuses.includes(status)) {
      throw new Error(`${what} ${id} has status ${status}, which the refresh never writes (${statuses.join(", ")})`);
    }
    if (ids.has(id)) throw new Error(`${what} ${id} is listed twice`);
    ids.set(id, status);
  }
  return ids;
}

/** Technique IDs from the checked-in mitre.db list, mapped to "", "revoked" or "deprecated". */
export const readMitreIds = (text: string) => readIdList(text, "MITRE ID", ["revoked", "deprecated"]);

// UUIDs compare without case and the lookup lowercases, so a repeat in another case is a repeat.
/** SigmaHQ rule ids from the checked-in list, lower-cased, mapped to "" or "deprecated". */
export const readSigmahqIds = (text: string) => readIdList(text, "SigmaHQ id", ["deprecated"], (id) => id.toLowerCase());

/** The list readMitreIds reads, built from a mitre.db copied out of the manager image. */
export function mitreIdList(dbPath: string, label: string): string {
  const db = new Database(dbPath, { readonly: true });
  const rows = db
    .query(
      `select r.external_id as id, t.deprecated as dep, t.revoked_by as rev from reference r
       join technique t on t.id = r.id where r.source = 'mitre-attack' and r.external_id is not null
       order by r.external_id`,
    )
    .all() as { id: string; dep: number; rev: string | null }[];
  db.close();
  // readMitreIds refuses a repeat, so a list holding one must never be written.
  const twice = rows.find((r, i) => i > 0 && rows[i - 1].id === r.id);
  if (twice) throw new Error(`MITRE ID ${twice.id} is returned twice by ${dbPath}, so no list was written`);
  const lines = rows.map((r) => (r.rev ? `${r.id} revoked` : r.dep ? `${r.id} deprecated` : r.id));
  return [
    `# Technique IDs in Wazuh's mitre.db (${label}), ${rows.length} in all.`,
    "# A <mitre> ID missing here is dropped from rule.mitre at alert time (ISA Decisions 2026-10-26).",
    '# Regenerate: bun tools/sigma-lint.ts --refresh-mitre <path to mitre.db> "<label>"',
    ...lines,
    "",
  ].join("\n");
}

// Each rule is parsed and its root mapping's id taken, so an id under related: never counts
// and an indented root still reads. The rules-prefixed folders and deprecated/ are read;
// unsupported/ and other/ are not.
/** The list readSigmahqIds reads, built from a SigmaHQ/sigma checkout. */
export function sigmahqIdList(checkout: string, label: string): string {
  const git = Bun.spawnSync(["git", "-C", checkout, "rev-parse", "--short", "HEAD"]);
  if (git.exitCode !== 0) throw new Error(`git rev-parse failed in ${checkout}: ${git.stderr.toString().trim()}`);
  const head = git.stdout.toString().trim();
  // The header names HEAD, which describes the files read only if nothing has changed since.
  // Untracked files are listed whatever status.showUntrackedFiles says, and ignored ones too,
  // because the walk reads a YAML whatever .gitignore or .git/info/exclude says of it.
  const status = Bun.spawnSync(["git", "-C", checkout, "status", "--porcelain", "--untracked-files=normal", "--ignored"]);
  if (status.exitCode !== 0) throw new Error(`git status failed in ${checkout}: ${status.stderr.toString().trim()}`);
  if (status.stdout.toString().trim()) throw new Error(`${checkout}: checkout is not clean, so HEAD ${head} would not describe the files read`);
  const folders = readdirSync(checkout)
    .filter((n) => (n.startsWith("rules") || n === "deprecated") && statSync(join(checkout, n)).isDirectory())
    .sort();
  if (!folders.some((n) => n.startsWith("rules"))) throw new Error(`${checkout} has no rules folder, so it is not a SigmaHQ checkout`);
  const seen = new Map<string, string>();
  const entries: [string, string][] = [];
  const walk = (d: string, status: string) => {
    for (const n of readdirSync(d).sort()) {
      const path = join(d, n);
      if (statSync(path).isDirectory()) {
        walk(path, status);
        continue;
      }
      if (!/\.ya?ml$/i.test(n)) continue;
      const file = relative(checkout, path);
      let doc: any;
      try {
        doc = Bun.YAML.parse(readFileSync(path, "utf8"));
      } catch (e) {
        throw new Error(`${file}: YAML does not parse: ${e instanceof Error ? e.message : String(e)}`);
      }
      if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw new Error(`${file}: YAML is not a single mapping`);
      if (typeof doc.id !== "string" || !UUID.test(doc.id)) throw new Error(`${file}: no UUID id at the top of the rule`);
      // UUIDs compare without regard to case, so the list holds them in one.
      const id = doc.id.toLowerCase();
      const prev = seen.get(id);
      if (prev) throw new Error(`${file}: id ${id} is also in ${prev}`);
      seen.set(id, file);
      entries.push([id, status]);
    }
  };
  for (const f of folders) walk(join(checkout, f), f === "deprecated" ? "deprecated" : "");
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return [
    `# Rule ids in a SigmaHQ/sigma checkout (${label}), HEAD ${head}, ${entries.length} in all.`,
    `# Top-level id: lines from ${folders.map((f) => `${f}/`).join(", ")}; "deprecated" marks one from deprecated/.`,
    "# A related: entry of type derived must name an id here that is not deprecated.",
    '# Regenerate: bun tools/sigma-lint.ts --refresh-sigmahq <path to a SigmaHQ/sigma checkout> "<label>"',
    ...entries.map(([id, s]) => (s ? `${id} ${s}` : id)),
    "",
  ].join("\n");
}

/** Lint the pack: each Sigma YAML against its XML rule, and each pack XML rule against a YAML. */
export function lintPack(
  sigma: SigmaRule[],
  tree: { rules: WazuhRule[]; skippedRules: WazuhRule[]; skippedFiles: string[] },
  mitre: Map<string, string>,
  sigmahq: Map<string, string>,
): Finding[] {
  const out: Finding[] = [];
  const byId = new Map<number, WazuhRule[]>();
  for (const r of tree.rules) byId.set(r.id, [...(byId.get(r.id) ?? []), r]);
  const sourced = new Map<number, string>();
  const uuids = new Map<string, string>();

  for (const f of tree.skippedFiles) out.push({ file: f, rule: 0, problem: "XML in a subfolder, which rule_dir never reads" });

  for (const s of sigma) {
    const bad = (problem: string, rule = 0) => out.push({ file: s.file, rule, problem });
    // An empty file parses to null and a multi-document file to a list.
    if (typeof s.doc !== "object" || s.doc === null || Array.isArray(s.doc)) {
      bad("YAML is not a single mapping");
      continue;
    }
    const d = s.doc;
    const w = d.custom?.wazuh;
    const rule = typeof w?.id === "number" && Number.isInteger(w.id) ? w.id : 0;
    // Each compared field is held to its type first, so a one-element sequence never passes
    // as the scalar inside it. A field that fails is reported once and skips its later checks.
    // listOnly refuses a scalar that would otherwise be wrapped into a one-item list.
    const strings = (v: unknown, field: string, listOnly = false): string[] | undefined => {
      if (listOnly && v !== undefined && !Array.isArray(v)) {
        bad(`${field} is not a list`, rule);
        return undefined;
      }
      const list: unknown[] = Array.isArray(v) ? v : v === undefined ? [] : [v];
      let ok = true;
      list.forEach((x, i) => {
        if (typeof x === "string") return;
        bad(`${Array.isArray(v) ? `${field}[${i}]` : field} is not a string`, rule);
        ok = false;
      });
      return ok ? (list as string[]) : undefined;
    };

    for (const k of ["title", "status", "description", "logsource", "detection"]) if (d[k] == null) bad(`no ${k}`, rule);
    if (d.id !== undefined && typeof d.id !== "string") bad("id is not a string", rule);
    else if (!UUID.test(d.id ?? "")) bad("id is not a UUID", rule);
    else {
      // UUIDs compare without regard to case, so a repeat in another case is a repeat.
      const prevId = uuids.get(d.id.toLowerCase());
      if (prevId) bad(`id also used in ${prevId}`, rule);
      else uuids.set(d.id.toLowerCase(), s.file);
    }
    // A missing detection is already "no detection"; any other non-mapping is refused here, so
    // false, 0 or "" can no longer skip the condition checks. "condition:" with nothing after
    // it parses to null, so null is empty, not missing.
    const det = d.detection;
    if (det != null && (typeof det !== "object" || Array.isArray(det))) bad("detection is not a mapping", rule);
    else if (det != null) {
      const cond = det.condition;
      if (cond === null || (typeof cond === "string" && !cond.trim())) bad("detection condition is empty", rule);
      else if (typeof cond !== "string") bad("detection has no condition", rule);
    }
    // Sigma's tags is a sequence. custom.wazuh.mitre keeps the scalar wrap.
    const sigmaTags = strings(d.tags, "tags", true);
    if (sigmaTags && !sigmaTags.some((t) => ATTACK_TAG.test(t))) bad("no ATT&CK technique tag", rule);
    for (const t of sigmaTags ?? []) {
      if (ATTACK_TAG_START.test(t) && !ATTACK_TAG.test(t)) bad(`ATT&CK technique tag ${t} is malformed (attack.tNNNN or attack.tNNNN.NNN)`, rule);
    }
    // Every related entry must be a mapping with a string type and id. Attribution must then
    // point at a live SigmaHQ rule; an entry that could have been the derived one leaves the
    // attribution unjudged, so one defect gives one finding.
    const related: unknown[] = Array.isArray(d.related) ? d.related : [];
    const derived: string[] = [];
    let unsure = false;
    related.forEach((x: any, i) => {
      if (typeof x !== "object" || x === null || Array.isArray(x)) {
        bad(`related[${i}] is not a mapping`, rule);
        unsure = true;
        return;
      }
      if (typeof x.type !== "string") bad(`related[${i}].type is not a string`, rule);
      if (typeof x.id !== "string") bad(`related[${i}].id is not a string`, rule);
      if (typeof x.type !== "string" || (x.type === "derived" && typeof x.id !== "string")) unsure = true;
      else if (x.type === "derived") derived.push(x.id);
    });
    if (!unsure && !derived.some((id) => UUID.test(id))) bad("no upstream attribution (related: type derived, with the upstream id)", rule);
    for (const id of derived) {
      const status = sigmahq.get(id.toLowerCase());
      if (status === undefined) bad(`upstream id ${id} is not a SigmaHQ rule id`, rule);
      else if (status) bad(`upstream id ${id} is ${status} in SigmaHQ`, rule);
    }
    let want: number | undefined;
    if (d.level !== undefined && typeof d.level !== "string") bad("level is not a string", rule);
    else {
      want = Object.hasOwn(LEVELS, d.level ?? "") ? LEVELS[d.level] : undefined;
      if (want === undefined) bad(`Sigma level ${d.level} is not a pack level (medium, high, critical)`, rule);
    }

    if (typeof w !== "object" || w === null) {
      bad("no custom.wazuh block");
      continue;
    }
    if (typeof w.id !== "number") {
      bad("custom.wazuh.id is not a number");
      continue;
    }
    if (!rule) {
      bad("custom.wazuh.id is not a whole number");
      continue;
    }
    if (!isPack(rule)) bad("custom.wazuh.id is outside the pack ranges", rule);
    const prev = sourced.get(rule);
    if (prev) bad(`custom.wazuh.id also used in ${prev}`, rule);
    else sourced.set(rule, s.file);
    const level: number | undefined = typeof w.level === "number" ? w.level : undefined;
    if (level === undefined) bad("custom.wazuh.level is not a number", rule);
    else if (want !== undefined && level !== want) bad(`custom.wazuh.level ${level} does not match Sigma level ${d.level} (${want})`, rule);
    // Several parents go in one comma string, as the XML <if_sid> writes them.
    let ifSid: string[] | undefined;
    if (typeof w.if_sid === "number") ifSid = [String(w.if_sid)];
    else if (typeof w.if_sid === "string") ifSid = w.if_sid.split(/[ ,]+/).filter(Boolean);
    else if (w.if_sid === undefined) ifSid = [];
    else bad("custom.wazuh.if_sid is not a number or string", rule);
    if (ifSid && !ifSid.length) bad("no custom.wazuh.if_sid", rule);
    const tags = strings(w.mitre, "custom.wazuh.mitre");
    if (tags && !tags.length) bad("no custom.wazuh.mitre", rule);
    for (const t of tags ?? []) {
      const status = mitre.get(t);
      if (status === undefined) bad(`MITRE ID ${t} is not in Wazuh's mitre.db, so the alert would drop it`, rule);
      else if (status) bad(`MITRE ID ${t} is ${status} in mitre.db`, rule);
    }
    // An empty side is already a finding above, so only two real lists are compared. Case
    // is the mitre.db check's business, so it plays no part here.
    const tagged = (sigmaTags ?? []).filter((t) => ATTACK_TAG.test(t)).map((t) => t.slice("attack.".length).toUpperCase());
    const upper = (tags ?? []).map((t) => t.toUpperCase());
    if (tagged.length && upper.length && !sameSet([...new Set(tagged)], [...new Set(upper)]))
      bad(`Sigma tags ${tagged.join(",")} do not match custom.wazuh.mitre ${(tags ?? []).join(",")}`, rule);

    const xml = byId.get(rule) ?? [];
    const skipped = tree.skippedRules.find((r) => r.id === rule);
    if (!xml.length) bad(skipped ? `XML rule is in ${skipped.file}, a subfolder rule_dir never reads` : "no XML rule with this id", rule);
    const x = xml[0];
    if (!x) continue;
    if (level !== undefined && x.level !== level) bad(`XML level ${x.level} does not match custom.wazuh.level ${level}`, rule);
    if (ifSid && !sameSet(x.ifSid, ifSid)) bad(`XML if_sid ${x.ifSid.join(",")} does not match custom.wazuh.if_sid ${ifSid.join(",")}`, rule);
    if (tags && !sameSet(x.mitre, tags)) bad(`XML mitre ${x.mitre.join(",") || "(none)"} does not match custom.wazuh.mitre ${tags.join(",")}`, rule);
  }

  // The lint compares only the first definition of an id, so any repeat fails, pack or
  // not. One finding per id names every file.
  for (const [id, defs] of repeatedIds(tree.rules)) {
    out.push({ file: defs[0].file, rule: id, problem: `XML rule defined ${defs.length} times (${defs.map((r) => r.file).join(", ")})` });
  }
  for (const r of [...tree.rules, ...tree.skippedRules]) {
    if (!isPack(r.id)) continue;
    if (!sourced.has(r.id)) out.push({ file: r.file, rule: r.id, problem: "pack rule with no Sigma YAML" });
    for (const name of r.repeated) out.push({ file: r.file, rule: r.id, problem: `XML has more than one <${name}> element` });
    // Whether the alert-time lookup trims a padded id is unknown, so neither form is guessed at.
    for (const m of r.mitre) {
      const shown = JSON.stringify(m);
      if (m !== m.trim()) out.push({ file: r.file, rule: r.id, problem: `MITRE id ${shown} has surrounding whitespace` });
      else if (!TECHNIQUE.test(m)) out.push({ file: r.file, rule: r.id, problem: `MITRE id ${shown} is not a technique id (TNNNN or TNNNN.NNN)` });
    }
    // Wazuh keeps a pair apart from the <id> list (rules.c 1585-1611), and the mitre.db list
    // holds techniques only, not the tactics each belongs to, so no pair can be checked.
    for (const [tactic, technique] of r.mitrePairs) {
      const pair = `tacticID ${JSON.stringify(tactic)} with techniqueID ${JSON.stringify(technique)}`;
      out.push({ file: r.file, rule: r.id, problem: `XML <mitre> pairs ${pair}, a form the lint does not check (pack rules use <id>)` });
    }
  }
  return out;
}

// *--- Entry Point ---*

// Exit 1 must mean the lint ran and found something, so every other stop is a one-line 2.
// The default Sigma folder may be absent (no YAML yet); one named on the command line may not.
/** Run the command line; 0 is clean, 1 is lint findings, 2 is a lint that could not run. */
export function main(args: string[], defaults = DEFAULTS): number {
  const fail = (message: string) => {
    console.error(`sigma-lint: ${message}`);
    return 2;
  };
  const opt = (flag: string, dflt: string) => {
    const i = args.indexOf(flag);
    return resolve(ROOT, i >= 0 ? (args[i + 1] ?? "") : dflt);
  };
  const rel = (p: string) => relative(ROOT, p);
  try {
    // --out writes somewhere other than the checked-in list, which is how the tests run it.
    const refresh: Record<string, [string, string, (source: string, label: string) => string]> = {
      "--refresh-mitre": ["<mitre.db>", MITRE_IDS, mitreIdList],
      "--refresh-sigmahq": ["<SigmaHQ/sigma checkout>", SIGMAHQ_IDS, sigmahqIdList],
    };
    const r = refresh[args[0]];
    if (r) {
      const [source, list, build] = r;
      // A line break in the label would add header lines to the list, fake ids among them.
      if (!(args.length === 3 || (args.length === 5 && args[3] === "--out")) || /[\r\n]/.test(args[2] ?? "")) {
        console.error(`usage: bun tools/sigma-lint.ts ${args[0]} ${source} "<label>" [--out <file>]`);
        return 2;
      }
      const out = resolve(ROOT, args[4] ?? list);
      writeFileSync(out, build(resolve(ROOT, args[1]), args[2]));
      console.error(`sigma-lint: wrote ${rel(out)}`);
      return 0;
    }
    for (let i = 0; i < args.length; i += 2) {
      if (!["--sigma", "--rules", "--mitre", "--sigmahq"].includes(args[i]) || args[i + 1] === undefined) {
        console.error("usage: bun tools/sigma-lint.ts [--sigma <dir>] [--rules <dir>] [--mitre <ids file>] [--sigmahq <ids file>]");
        return 2;
      }
    }
    const mitreFile = opt("--mitre", defaults.mitre);
    const sigmahqFile = opt("--sigmahq", defaults.sigmahq);
    const sigmaDir = opt("--sigma", defaults.sigma);
    const rulesDir = opt("--rules", defaults.rules);
    if (!existsSync(mitreFile)) return fail(`no MITRE ID list at ${rel(mitreFile)}`);
    if (!existsSync(sigmahqFile)) return fail(`no SigmaHQ id list at ${rel(sigmahqFile)}`);
    if (!existsSync(sigmaDir)) {
      if (args.includes("--sigma")) return fail(`no Sigma folder at ${rel(sigmaDir)}`);
      console.error(`sigma-lint: no Sigma folder at ${rel(sigmaDir)}, so only the XML is linted`);
    }
    if (!existsSync(rulesDir)) return fail(`no rules folder at ${rel(rulesDir)}`);
    const mitre = readMitreIds(readFileSync(mitreFile, "utf8"));
    const sigmahq = readSigmahqIds(readFileSync(sigmahqFile, "utf8"));
    const findings = lintPack(readSigma(sigmaDir), readRulesDir(rulesDir, ROOT), mitre, sigmahq);
    for (const f of findings) console.log(`${f.file}: rule ${f.rule}: ${f.problem}`);
    console.error(`sigma-lint: ${findings.length} finding(s)`);
    return findings.length ? 1 : 0;
  } catch (e) {
    return fail((e instanceof Error ? e.message : String(e)).split("\n")[0]);
  }
}

if (import.meta.main) process.exit(main(Bun.argv.slice(2)));
