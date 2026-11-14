#!/usr/bin/env bun
// *****************************************************************************
// *Title: noise-lint*
// *Author: Kyle Versluis*
// *Description: Hold every Wazuh suppression rule to the B.0 keying rules.*
// *****************************************************************************

// *--- Imports ---*

import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { PROFILES } from "./apparmor-profiles.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const RULES_DIR = "deploy/soc-recon/wazuh/custom-rules";
const NOISE_MIN = 100100;
const NOISE_MAX = 100199;
// log_alert_level in config/wazuh_cluster/wazuh_manager.conf. Any rule below it is never
// indexed, so it silences as surely as level 0.
const LOG_ALERT_LEVEL = 3;
// Parents a suppression may hang off. A new parent is added here on purpose, never by accident.
const PARENTS = new Set(["80792"]);
// Fields that name the process image. A suppression must pin one, anchored.
const IMAGE_FIELDS = new Set(["audit.exe", "win.eventdata.image"]);
// An auditd suppression pins all of these (NOISE-BASELINE.md "How the suppressions are keyed").
const AUDIT_FIELDS = ["audit.auid", "audit.tty", "audit.exe", "audit.cwd", "audit.uid", "audit.euid", "audit.gid"];
// Probes for a pattern that matches anything: the empty string and a value no rule names.
const PROBES = ["", "zq9 not-a-real-value /tmp/x;id"];
// NOTE: silencing rules outside the noise range, each kept on purpose. 100200 is the
// Phase A Suricata ethertype rule; narrowing it is out of Phase B scope (ISA).
// SECURITY: each is pinned to the SHA-256 of its attributes and body, so the exemption
// covers the rule that was reviewed and nothing a later edit turns it into.
const GRANDFATHERED = new Map([[100200, "3e1d7b9ddc3e3aabd0c0db3ffd23e82cbc66cb5e56faaddaef874c0d2ae08e81"]]);
// The one tag shape the lint reads: lower-case names, double-quoted attributes, single
// spaces. Wazuh's parser takes more than this, and may compare names without case (not
// measured here), so anything else is refused instead of guessed at.
const TAG = /^<[a-z_][a-z0-9_]*(?: [a-z_]+="[^"<>]*")*>$/;
// AppArmor labels a suppression may pin: runc, the host, and each service's own profile.
// SECURITY: docker-default is left out. Every other container on the box runs under it, so
// a rule pinning it trusts all of them (ISA ISC-116).
const SHARED_LABEL = "docker-default";
const LABELS = new Set(["runc", "unconfined", ...PROFILES]);
// SECURITY: the pattern subset. Wazuh runs these patterns with PCRE2 and this lint reads
// them with JS, and the two disagree on more constructs than can be listed (audits found
// five in 2026-11: a class opening with "]", a POSIX class, \cX, \N, an XML entity). So a
// suppression may use only what is named here, and anything else is refused. Inside the
// subset two differences in matching are known, both on input auditd would hex-encode
// before it reached a rule: PCRE2's "$" also matches before a final newline, and "." reads
// a carriage return and bytes above 0x7F differently in the two engines. Some
// patterns were also found that PCRE2 will not compile at all ("[.a.]", very large or deep
// patterns, a counted repeat of a group), and those are refused in outsideSubset(). Each set holds what the committed rules use. Adding to one
// is a decision, not a fix.
const LITERAL = /^[A-Za-z0-9 ",\-/:=_]$/;
const CLASS_MEMBER = /^[A-Za-z0-9._+\-]$/;
const ESCAPED = new Set(["d", ".", "(", ")", "?", "{", "}"]);
const ALTERNATES = "alternates outside a group";
const MAX_PATTERN = 1000;
const MAX_DEPTH = 4;
// Rule options the lint knows. no_log keeps an alert out of the index and is handled below.
const OPTIONS = new Set(["no_full_log", "no_log", "alert_by_email", "no_email_alert", "no_counter"]);
// A closing tag carries no attributes.
const CLOSE_TAG = /^<\/[a-z_][a-z0-9_]*>$/;
// What a suppression rule may hold besides its matchers.
const ELEMENTS = new Set(["if_sid", "field", "regex", "description"]);
const RULE_ATTRS = new Set(["id", "level"]);

// *--- Types ---*

export interface Finding {
  file: string;
  rule: number;
  problem: string;
}

// *--- Helper Functions ---*

// JS RegExp stands in for PCRE2 here. That is only sound inside the pattern subset, which
// outsideSubset() enforces on the same matcher. A pattern JS cannot compile fails closed.
function compiles(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}

/**
 * Why a pattern is outside the subset, or null when it is inside. The subset: the literal
 * characters in LITERAL; "."; the escapes \d \. \( \) \? \{ \} and \xHH; a class of
 * CLASS_MEMBER characters, never negated; a group with "|" inside it; one of * + ? or {n}
 * after an atom; "^" as the first character and "$" as the last. No "|" outside a group:
 * "^a$|b" is two patterns, and nothing would hold the second to an anchor or a label.
 */
export function outsideSubset(p: string): string | null {
  let i = 0;
  const at = (why: string) => `${why} at character ${i + 1}`;
  // PCRE2 refuses what JS compiles when a pattern is large or deep enough (errors 105, 119,
  // 120 in 10.49). The caps sit far above the committed rules: 630 characters, depth 1, {64}.
  if (p.length > MAX_PATTERN) return `longer than ${MAX_PATTERN} characters`;
  const branches = (depth: number): string | null => {
    if (depth > MAX_DEPTH) return at("group nested too deep");
    let atoms = 0;
    for (;;) {
      const c = p[i];
      if (c === undefined || c === ")") {
        if (c === undefined && depth > 0) return at("group never closed");
        if (c === ")" && depth === 0) return at("unopened )");
        return atoms ? null : at("empty branch");
      }
      if (c === "|") {
        if (depth === 0) return ALTERNATES;
        if (!atoms) return at("empty branch");
        atoms = 0;
        i++;
        continue;
      }
      if (c === "^" || c === "$") {
        // "^a$|^b$": name the alternation, which is the real fault, not the anchor beside it.
        if (depth === 0 && (c === "$" ? p[i + 1] === "|" : p[i - 1] === "|")) return ALTERNATES;
        if (c === "^" ? i !== 0 : i !== p.length - 1) return at(`${c} inside the pattern`);
        i++;
        continue;
      }
      if (c === "\\") {
        const n = p[i + 1];
        if (n === "x" && /^[0-9A-Fa-f]{2}$/.test(p.slice(i + 2, i + 4))) i += 4;
        else if (n !== undefined && ESCAPED.has(n)) i += 2;
        else return at(`escape \\${n ?? ""}`);
      } else if (c === "[") {
        const start = ++i;
        while (p[i] !== undefined && CLASS_MEMBER.test(p[i])) i++;
        if (p[i] !== "]" || i === start) return at("class");
        // "[.a.]" is a POSIX collating element to PCRE2, which refuses to compile it
        // (error 113), and a plain class to JS.
        if (i - start > 1 && p[start] === "." && p[i - 1] === ".") return at("class");
        i++;
      } else if (c === "(") {
        i++;
        const why = branches(depth + 1);
        if (why) return why;
        i++;
        // PCRE2 copies a group once per counted repeat, so "((ab){99}){99}" compiles to a size
        // it refuses (error 120) under every other cap here. A group takes * + or ? only.
        if (p[i] === "{") return at("counted repeat of a group");
      } else if (c === "." || LITERAL.test(c)) i++;
      else return at(`character ${JSON.stringify(c)}`);
      atoms++;
      // One quantifier, greedy. "{n}" only: "{,n}" is a quantifier to PCRE2 and text to JS.
      const q = /^(?:[*+?]|\{[1-9][0-9]{0,2}\})/.exec(p.slice(i));
      if (q) i += q[0].length;
      if (q && /^[*+?{]/.test(p.slice(i))) return at("second quantifier");
      if (!q && p[i] === "{") return at("brace");
    }
  };
  return branches(0);
}

const sha256 = (text: string) => new Bun.CryptoHasher("sha256").update(text).digest("hex");

// One rule's matchers (<field>, <regex>, <match>) with their attributes and pattern.
function matchers(inner: string) {
  return [...inner.matchAll(/<(field|regex|match)\b([^>]*)>([\s\S]*?)<\/\1>/g)].map((m) => ({
    tag: m[1],
    name: /\bname="([^"]+)"/.exec(m[2])?.[1] ?? "",
    attrs: m[2],
    pattern: m[3].trim(),
  }));
}

// *--- Core Logic ---*

// Lint one rules file. Comments are dropped first so a commented-out rule is ignored.
export function lint(xml: string, file: string): Finding[] {
  const out: Finding[] = [];
  const body = xml.replace(/<!--[\s\S]*?-->/g, "");
  if (body.includes("<![CDATA[")) out.push({ file, rule: 0, problem: "CDATA in a rules file" });
  // SECURITY: a rule inside a comment is never checked here. If Wazuh's parser ends a comment
  // at "!>", or takes "<!-->" as a whole one, that rule is live for Wazuh and invisible to
  // the lint. Not measured, so both spellings are refused wherever they appear.
  if (/!>|<!--?-?>/.test(xml)) out.push({ file, rule: 0, problem: "comment the lint and Wazuh could end at different places" });
  // SECURITY: no "&" outside a comment. A parser that decodes entities would hand Wazuh text
  // the lint never saw, in an option or an attribute as much as in a pattern.
  if (body.includes("&")) out.push({ file, rule: 0, problem: 'holds "&" outside a comment; write it as \\x26 in a pattern' });
  // Every tag in the file, not only the noise range: a tag read differently by Wazuh could
  // hide a whole rule from the checks below.
  for (const m of body.matchAll(/<[^>]*>?/g)) {
    const names = [...m[0].matchAll(/ ([a-z_]+)="/g)].map((a) => a[1]);
    if (!(m[0].startsWith("</") ? CLOSE_TAG : TAG).test(m[0]) || new Set(names).size !== names.length) {
      out.push({ file, rule: 0, problem: `tag the lint cannot read: ${m[0].slice(0, 60)}` });
    }
    if (/^<var[ >]/.test(m[0])) out.push({ file, rule: 0, problem: "var element: Wazuh would substitute it into text the lint reads as written" });
  }
  // Every rule the file opens must be one the loop below reads: closed, and not inside another.
  const rules = [...body.matchAll(/<rule\b([^>]*)>([\s\S]*?)<\/rule>/g)];
  const opened = (body.match(/<rule[ >]/g) ?? []).length;
  if (opened !== rules.length || (body.match(/<\/rule>/g) ?? []).length !== rules.length || rules.some((m) => /<rule[ >]/.test(m[2]))) {
    out.push({ file, rule: 0, problem: "a rule is unclosed or sits inside another rule" });
  }
  for (const m of rules) {
    const attrs = m[1];
    const inner = m[2];
    // SECURITY: plain numbers only. Wazuh reads these with C integer parsing, so "0003",
    // a 7-digit id or 4294967296 can be one number to the lint and another to Wazuh.
    const idText = / id="([1-9][0-9]{0,5})"/.exec(attrs)?.[1];
    const levelText = / level="(0|[1-9]|1[0-6])"/.exec(attrs)?.[1];
    const id = Number(idText ?? NaN);
    const level = Number(levelText ?? NaN);
    const bad = (problem: string) => out.push({ file, rule: Number.isNaN(id) ? 0 : id, problem });
    const inRange = id >= NOISE_MIN && id <= NOISE_MAX;
    if (idText === undefined || levelText === undefined) {
      bad("rule without a plain id (1 to 999999) and level (0 to 16)");
      continue;
    }
    // An option the lint does not recognise could be one that keeps the alert out of the index.
    for (const o of inner.matchAll(/<options>([\s\S]*?)<\/options>/g)) {
      if (!OPTIONS.has(o[1])) bad(`option ${JSON.stringify(o[1].slice(0, 30))} is not one the lint knows`);
    }
    // Any rule, any id: an overwrite edits a rule this file does not show, a stock one too.
    if (/ overwrite="/.test(attrs)) {
      bad("overwrite replaces a rule defined elsewhere, which this lint does not follow");
      continue;
    }
    const silences =
      level < LOG_ALERT_LEVEL || /\bnoalert\s*=/.test(attrs) || /<options>[^<]*\bno_log\b/.test(inner);
    if (silences && !inRange && !GRANDFATHERED.has(id)) {
      bad(`silencing rule outside ${NOISE_MIN}-${NOISE_MAX}`);
      continue;
    }
    if (GRANDFATHERED.has(id) && sha256(`${attrs}\n${inner}`) !== GRANDFATHERED.get(id)) {
      bad(`grandfathered rule ${id} is not the rule that was kept`);
      continue;
    }
    if (!inRange) continue;

    // Shape: level 0 under one listed parent, nothing else deciding whether it fires.
    if (level !== 0) bad("noise-range rule is not level 0");
    const parents = [...inner.matchAll(/<if_sid>([^<]*)<\/if_sid>/g)];
    if (parents.length === 0) bad("no if_sid parent");
    for (const p of parents) {
      for (const sid of p[1].split(/[\s,]+/).filter(Boolean)) {
        if (!PARENTS.has(sid)) bad(`if_sid ${sid} is not a listed parent`);
      }
    }
    for (const t of ["if_group", "if_level", "if_matched_sid", "if_matched_group"]) {
      if (inner.includes(`<${t}>`)) bad(`<${t}> parent`);
    }

    // Nothing in the rule but its parent, its matchers and a description: any other
    // element or attribute is something Wazuh acts on and this lint does not read.
    for (const a of attrs.matchAll(/ ([a-z_]+)="/g)) {
      if (!RULE_ATTRS.has(a[1])) bad(`rule attribute ${a[1]} is not one a suppression may use`);
    }
    for (const e of inner.matchAll(/<([a-z_][a-z0-9_]*)[ >]/g)) {
      if (!ELEMENTS.has(e[1])) bad(`<${e[1]}> is not an element a suppression may use`);
    }

    // Matchers: pcre2 only, never negated, never able to match anything.
    const all = matchers(inner);
    for (const x of all) {
      const label = x.name || `<${x.tag}>`;
      if (!/\btype="pcre2"/.test(x.attrs)) bad(`${label} is not type="pcre2"`);
      if (/\bnegate\s*=/.test(x.attrs)) bad(`${label} is negated`);
      const re = compiles(x.pattern);
      if (!re) bad(`${label} does not compile`);
      else if (PROBES.some((p) => re.test(p))) bad(`${label} matches anything`);
      const why = outsideSubset(x.pattern);
      if (why === ALTERNATES) bad(`${label} ${ALTERNATES}`);
      else if (why) bad(`${label} is outside the pattern subset: ${why}`);
    }
    const fields = all.filter((x) => x.tag === "field");
    for (const name of new Set(fields.map((f) => f.name))) {
      if (fields.filter((f) => f.name === name).length > 1) bad(`${name} is constrained twice`);
    }
    if (fields.length < 2) bad(`${fields.length} field constraint(s), need at least 2`);
    for (const f of fields) {
      if (!/^\^[\s\S]*\$$/.test(f.pattern)) bad(`${f.name} is not anchored ^...$`);
    }
    const image = fields.find((f) => IMAGE_FIELDS.has(f.name));
    if (!image) bad("no image field (audit.exe or win.eventdata.image)");

    // auditd shapes: every keying field, and the argv (or the failed path) pinned in full_log.
    if (image?.name === "audit.exe") {
      const names = new Set(fields.map((f) => f.name));
      for (const need of AUDIT_FIELDS) if (!names.has(need)) bad(`no ${need} field`);
      const failed = fields.some((f) => f.name === "audit.success" && f.pattern === "^no$");
      // One regex: a second one could widen what the first one pins.
      const regexes = all.filter((x) => x.tag === "regex");
      const regex = regexes[0];
      if (!regex) bad("no full_log regex");
      else if (regexes.length > 1) bad(`${regexes.length} full_log regexes, need 1`);
      else {
        // The label comes first and once, as plain text, so no branch can skip it.
        const pin = /^subj=(\S+) key=/.exec(regex.pattern);
        if (!pin) bad("regex does not pin the AppArmor label");
        else if (pin[1] === SHARED_LABEL) bad(`regex pins ${SHARED_LABEL}, the label every other container shares`);
        else if (!LABELS.has(pin[1])) bad(`regex pins the label ${pin[1]}, not runc, unconfined or a service profile`);
        if (pin && regex.pattern.split("subj=").length !== 2) bad("regex names subj= more than once");
        if (!failed && !/argc=\d+ /.test(regex.pattern)) bad("regex does not pin argc");
        if (failed && !/type=PATH /.test(regex.pattern)) bad("failed-exec regex does not pin the PATH record");
      }
    }
  }
  return out;
}

// Lint every file in the rules folder, and flag an id used twice anywhere in it.
export function lintDir(dir: string): Finding[] {
  const out: Finding[] = [];
  const seen = new Map<number, string>();
  // The whole folder is mounted into the manager, so a file the lint skips is still there.
  for (const name of readdirSync(dir).filter((n) => !n.endsWith(".xml") && n !== ".gitkeep").sort()) {
    out.push({ file: relative(ROOT, join(dir, name)), rule: 0, problem: "not a .xml file: the manager gets it and the lint does not read it" });
  }
  for (const name of readdirSync(dir).filter((n) => n.endsWith(".xml")).sort()) {
    const path = join(dir, name);
    const file = relative(ROOT, path);
    const xml = readFileSync(path, "utf8");
    out.push(...lint(xml, file));
    const body = xml.replace(/<!--[\s\S]*?-->/g, "");
    for (const m of body.matchAll(/<rule\b[^>]*\bid="(\d+)"/g)) {
      const id = Number(m[1]);
      const prev = seen.get(id);
      if (prev) out.push({ file, rule: id, problem: `id also used in ${prev}` });
      else seen.set(id, file);
    }
  }
  return out;
}

// *--- Entry Point ---*

if (import.meta.main) {
  const dir = resolve(ROOT, Bun.argv[2] ?? RULES_DIR);
  const findings = lintDir(dir);
  for (const f of findings) console.log(`${f.file}: rule ${f.rule}: ${f.problem}`);
  console.error(`noise-lint: ${findings.length} finding(s)`);
  process.exit(findings.length ? 1 : 0);
}
