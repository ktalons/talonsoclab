#!/usr/bin/env bun
// *****************************************************************************
// *Title: coverage*
// *Author: Kyle Versluis*
// *Description: Build ATT&CK layers from the pack and live-alert evidence.*
// *****************************************************************************

// *--- Imports ---*

import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { EXIT, type ExitCode, type SessionRecord, type TestRecord } from "./art-harness.ts";
import { isPack, readRulesDir, repeatedIds, RulesError } from "./wazuh-rules.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const RULES_DIR = "deploy/soc-recon/wazuh/custom-rules";
const ATTACK_TSV = "phase-b-detection/attack/enterprise-19.2-techniques.tsv";
const CROSSWALK = "phase-b-detection/attack/crosswalk.json";
const RECORD_DIR = "phase-b-detection/art-runs";
const VALIDATION_DIR = "phase-b-detection/validation";
const MISSES = `${VALIDATION_DIR}/misses.json`;
const COVERAGE_DIR = "phase-b-detection/coverage";
const OUT_EXISTS = "layer-rule-exists.json";
const OUT_VALIDATED = "layer-validated.json";
const OUT_SUMMARY = "coverage.json";
// Where the self-test finds the evidence the integration test and the control build read.
const FIXTURE_DIR = "tools/fixtures/coverage";
const LOGTEST_FIXTURE = "tools/fixtures/logtest/transcript-20261106.txt";

const TSV_FORMAT = "talonsoclab-attack-techniques/1";
const CROSSWALK_FORMAT = "talonsoclab-attack-crosswalk/1";
const RECORD_FORMAT = "talonsoclab-art-session/1";
const ALERTS_FORMAT = "talonsoclab-art-alerts/1";
const MISSES_FORMAT = "talonsoclab-art-misses/1";
const COVERAGE_FORMAT = "talonsoclab-coverage/1";

// The one ATT&CK release the pack is mapped to. The bundle is pinned by content, not by name.
const ATTACK_VERSION = "19.2";
const ATTACK_MAJOR = "19";
const ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json";
export const ATTACK_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4";
const ATTACK_COLLECTION = `enterprise-attack ${ATTACK_VERSION}`;
const REGENERATE = `bun tools/coverage.ts refresh-attack <path to enterprise-attack-${ATTACK_VERSION}.json>`;

// The Navigator layer file format. 4.5 is the format the 5.x app reads.
const LAYER_FORMAT = "4.5";
// NOTE: the layer spec (4.5) requires versions.navigator of at least 4.9.0, and the hosted app is
// 5.3.2. The layers have not yet been opened in Navigator, so that stays unconfirmed until they are.
export const NAVIGATOR_VERSION = "5.3.2";

// Live-index evidence: the agent, the Defender rules a block cites, the index shape.
const AGENT = "001";
const DEFENDER_RULES = [62123, 62124];
const INDEX_PATTERN = "wazuh-alerts-*";
const INDEX_NAME = /^wazuh-alerts-4\.x-\d{4}\.\d{2}\.\d{2}$/;
// Fetch pads the query so an alert indexed a moment late is still returned. Matching never uses it.
const PAD_MS = 60_000;
const HITS_MAX = 10_000;
const REMOTE_COMMAND = 'cd ~/talonsoclab/deploy/soc-recon && bin/idx "/_msearch" --data-binary @-';
const FETCH_TIMEOUT_MS = 120_000;
const MISS_CLASSES = ["blocked-by-defender", "sensor-gap", "rule-gap", "prerequisite-failed", "not-run"] as const;
type MissClass = (typeof MISS_CLASSES)[number];
const FINDER = ".DS_Store";

// SECURITY: every value that reaches the ssh argv or a path is held to one of these first.
const SAFE_GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SAFE_TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;
const SAFE_HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_SESSION = /^\d{8}T\d{6}Z-[0-9a-f]{6}$/;
const SAFE_DOC_ID = /^[A-Za-z0-9_-]{16,64}$/;
const SAFE_TEXT = /^[\x20-\x7e]{1,500}$/;
const SAFE_CHANNEL = /^[\x20-\x7e]{1,128}$/;
const SAFE_IMAGE = /^[A-Za-z0-9._ +()$-]{1,128}$/;
const SAFE_TACTICS = /^[a-z]+(?:-[a-z]+)*(?:,[a-z]+(?:-[a-z]+)*)*$/;
const SAFE_HEX64 = /^[0-9a-f]{64}$/;
const ISO_UTC = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z$/;

const USAGE = `usage: bun tools/coverage.ts <command> [options]

commands
  build                        read the pack, the records and the evidence; write the two
                               layers and coverage.json under phase-b-detection/coverage/
  check [--final]              rebuild in memory; fail if a checked-in output differs by a
                               byte or is missing. --final also refuses while the coverage
                               is not complete
  fetch --host <ssh alias>     ask the live index for each session's agent ${AGENT} alerts and
                               write phase-b-detection/validation/<session>.alerts.json
  refresh-attack <bundle>      write the pinned technique list from a local STIX bundle
                               [--sha256 <hex>] [--out <path>]
  --self-test                  plant each refusal on temp copies and report one line each

options
  --root <dir>                 treat <dir> as the repo root (the self-test and the tests)

exit 0 ok, 1 failed, 2 setup problem, 3 refused
`;

// *--- Types ---*

/** A typed refusal, failure or setup problem; code names the check, item the offender. */
export class CoverageError extends Error {
  constructor(
    readonly exit: ExitCode,
    readonly code: string,
    readonly item: string,
    message: string,
  ) {
    super(message);
  }
}

export interface Layout {
  root: string;
  rules: string;
  attackTsv: string;
  crosswalk: string;
  records: string;
  validation: string;
  misses: string;
  coverage: string;
}

export interface Technique {
  id: string;
  status: "active" | "revoked" | "deprecated";
  successor: string;
  tactics: string[];
  name: string;
}

export interface AttackList {
  byId: Map<string, Technique>;
  counts: { total: number; active: number; revoked: number; deprecated: number };
}

export interface CrosswalkEntry {
  from: string;
  to: string;
  how: "unchanged" | "revoked-by";
}

export interface PackRule {
  id: number;
  level: number;
  written: string[];
  attack19: string[];
}

export interface RunWindow {
  guid: string;
  technique: string;
  testNumber: number;
  rules: number[];
  position: number;
  start: bigint;
  end: bigint;
}

export type Record0 = Pick<SessionRecord, "format" | "session" | "verdict" | "failures"> & { tests: TestRecord[] };

export interface Session {
  record: Record0;
  file: string;
  sha256: string;
  windows: RunWindow[];
  span: { from: bigint; to: bigint } | null;
}

export interface EvidenceAlert {
  index: string;
  id: string;
  ruleId: number;
  ruleLevel: number;
  mitre: string[];
  agentId: string;
  timestamp: string;
  eventTime: string;
  systemTime: string | null;
  eventId: number | null;
  channel: string;
  image: string | null;
}

export interface ShardCounts {
  total: number;
  successful: number;
  skipped: number;
  failed: number;
}

export interface Evidence {
  format: string;
  session: string;
  recordSha256: string;
  query: { index: string; agent: string; rules: number[]; fromUtc: string; toUtc: string };
  shards: { alerts: ShardCounts; control: ShardCounts };
  control: { agent001Alerts: number };
  alerts: EvidenceAlert[];
}

export interface Counted {
  rule: number;
  session: string;
  test: string;
  art: string;
  index: string;
  id: string;
  eventTime: string;
  indexTime: string;
}

export interface Uncounted {
  session: string;
  index: string;
  id: string;
  rule: number;
  eventTime: string;
  indexTime: string;
  reason: string;
}

export interface Miss {
  rule: number;
  class: MissClass;
  evidence: string;
  session: string | null;
  test: string | null;
  alertId: string | null;
  ruling: string | null;
}

export interface Built {
  files: Map<string, string>;
  packSize: number;
  validated: number[];
  unclassified: number[];
  complete: boolean;
}

/** The remote the index is reached through: NDJSON in, the raw answer out. */
export type Remote = (ndjson: string, timeoutMs: number) => { code: number | null; out: string; timedOut: boolean };

/** A leak scan over the files about to be written; it throws when any holds an identifier. */
export type LeakScan = (files: Map<string, string>) => void;

export interface Io {
  log: (line: string) => void;
  err: (line: string) => void;
}

export interface Deps {
  remote?: Remote;
  leakScan?: LeakScan;
}

// *--- Helper Functions ---*

const sha256 = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");
const ordinal = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const cmpBig = (a: bigint, b: bigint) => (a < b ? -1 : a > b ? 1 : 0);
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const jsonText = (x: unknown) => `${JSON.stringify(x, null, 2)}\n`;
const isInt = (x: unknown): x is number => typeof x === "number" && Number.isInteger(x);
const isNat = (x: unknown): x is number => isInt(x) && x >= 0;

const refuse = (code: string, item: string, message: string): never => {
  throw new CoverageError(EXIT.refused, code, item, message);
};
const setup = (code: string, item: string, message: string): never => {
  throw new CoverageError(EXIT.setup, code, item, message);
};
const failed = (code: string, item: string, message: string): never => {
  throw new CoverageError(EXIT.failed, code, item, message);
};

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

// An extra key could carry what the shape check never reads, so every object is closed.
function exactKeys(o: Record<string, unknown>, keys: string[], code: string, item: string): void {
  const have = Object.keys(o).sort();
  const want = [...keys].sort();
  if (have.join() !== want.join()) refuse(code, item, `${item} must have exactly the keys ${want.join(", ")}`);
}

/** The relative path of a file under the layout root, for messages. */
const rel = (l: Layout, path: string) => relative(l.root, path) || ".";

/** The folders and files every command reads, under one root. */
export function layoutFor(root: string): Layout {
  const r = resolve(root);
  return {
    root: r,
    rules: join(r, RULES_DIR),
    attackTsv: join(r, ATTACK_TSV),
    crosswalk: join(r, CROSSWALK),
    records: join(r, RECORD_DIR),
    validation: join(r, VALIDATION_DIR),
    misses: join(r, MISSES),
    coverage: join(r, COVERAGE_DIR),
  };
}

/** One input file as text; a missing one is a setup problem, not a refusal. */
function readInput(l: Layout, path: string): string {
  if (!existsSync(path)) return setup("input-missing", rel(l, path), `${rel(l, path)} is missing`);
  return readFileSync(path, "utf8");
}

// A real logtest transcript (tools/logtest.ts --save) is a rule check on a hand-fed line,
// never a live alert, so no input of this tool may be one.
/** The JSON in one input, refusing a logtest transcript and anything that does not parse. */
function readJson(text: string, file: string): unknown {
  if (text.includes("wazuh_logtest[") || text.includes("Reply: {")) {
    return refuse("logtest-transcript", file, `${file} is a logtest transcript; logtest output never counts as evidence`);
  }
  try {
    return JSON.parse(text);
  } catch {
    return refuse("bad-json", file, `${file} is not valid JSON`);
  }
}

/** The files of a folder with one extension, in order; the Finder file is skipped, anything else refused. */
function listFiles(l: Layout, dir: string, pattern: RegExp, code: string): string[] {
  if (!existsSync(dir)) return setup("input-missing", rel(l, dir), `${rel(l, dir)} is missing`);
  const names = readdirSync(dir).sort(ordinal);
  for (const n of names) if (n !== FINDER && !pattern.test(n)) refuse(code, `${rel(l, dir)}/${n}`, `${rel(l, dir)}/${n} is not a file this tool reads`);
  return names.filter((n) => n !== FINDER);
}

/** An exact instant in nanoseconds since the epoch; a non-ISO or impossible time is refused. */
export function parseInstant(s: unknown, code: string, item: string): bigint {
  const m = typeof s === "string" ? ISO_UTC.exec(s) : null;
  if (!m) return refuse(code, item, `${item} is not an ISO UTC time: ${typeof s === "string" ? s.slice(0, 40) : typeof s}`);
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, se);
  const back = new Date(ms);
  const same =
    back.getUTCFullYear() === y && back.getUTCMonth() === mo - 1 && back.getUTCDate() === d && back.getUTCHours() === h && back.getUTCMinutes() === mi && back.getUTCSeconds() === se;
  if (!same) return refuse(code, item, `${item} is not a real calendar time: ${s}`);
  return BigInt(ms) * 1_000_000n + BigInt((m[7] ?? "").padEnd(9, "0"));
}

/** A time from the index in any form it uses, as ISO UTC with the fraction kept. */
export function normalizeTime(raw: unknown, item: string): string {
  const m = typeof raw === "string" ? /^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d(?:\.\d{1,9})?)(Z|\+0000|\+00:00)?$/.exec(raw) : null;
  if (!m) return refuse("fetch-time", item, `${item} is not a UTC time the index uses`);
  // A Sysmon utcTime has no zone and a space; only that form may omit the zone.
  if (m[3] === undefined && !(raw as string).includes(" ")) return refuse("fetch-time", item, `${item} has no zone`);
  const iso = `${m[1]}T${m[2]}Z`;
  parseInstant(iso, "fetch-time", item);
  return iso;
}

/** True when a rule id reads as a pack rule or one of the two Defender rules a block cites. */
const inScope = (id: number) => isPack(id) || DEFENDER_RULES.includes(id);

// *--- Core Logic ---*

// -- The pinned technique list --

/** The comment block a technique list opens with, from the counts of its rows. */
function attackHeader(counts: AttackList["counts"]): string {
  return [
    `# talonsoclab ATT&CK Enterprise ${ATTACK_VERSION} technique list`,
    `# format: ${TSV_FORMAT}`,
    `# source: ${ATTACK_URL}`,
    `# sha256: ${ATTACK_SHA256}`,
    `# collection: ${ATTACK_COLLECTION}`,
    `# counts: total=${counts.total} active=${counts.active} revoked=${counts.revoked} deprecated=${counts.deprecated}`,
    `# regenerate: ${REGENERATE}`,
    "# columns: id, status (active|revoked|deprecated), successor (revoked only), tactics, name; tab separated",
    "",
  ].join("\n");
}

/** The pinned list as a map, refusing any line the generator could not have written. */
export function parseAttackTsv(text: string, file = ATTACK_TSV): AttackList {
  if (text.includes("wazuh_logtest[") || text.includes("Reply: {")) refuse("logtest-transcript", file, `${file} is a logtest transcript`);
  if (!text.endsWith("\n") || text.includes("\r")) refuse("attack-tsv", file, `${file} must use LF line ends and end with one`);
  const lines = text.slice(0, -1).split("\n");
  const rows = lines.filter((x) => !x.startsWith("#"));
  const byId = new Map<string, Technique>();
  const counts = { total: 0, active: 0, revoked: 0, deprecated: 0 };
  let prev = "";
  rows.forEach((line, i) => {
    const at = `${file} row ${i + 1}`;
    const f = line.split("\t");
    if (f.length !== 5) refuse("attack-tsv", at, `${at} must have five tab separated columns`);
    const [id, status, successor, tactics, name] = f;
    if (!SAFE_TECHNIQUE.test(id)) refuse("attack-tsv", at, `${at}: ${id} is not an ATT&CK technique id`);
    if (prev !== "" && ordinal(prev, id) >= 0) refuse("attack-tsv", at, `${at}: ${id} is out of order or repeated`);
    prev = id;
    if (status !== "active" && status !== "revoked" && status !== "deprecated") refuse("attack-tsv", at, `${at}: status ${status} is not active, revoked or deprecated`);
    if ((status === "revoked") !== (successor !== "")) refuse("attack-tsv", at, `${at}: only a revoked technique carries a successor, and it must`);
    if (successor !== "" && !SAFE_TECHNIQUE.test(successor)) refuse("attack-tsv", at, `${at}: successor ${successor} is not a technique id`);
    if (tactics !== "" && !SAFE_TACTICS.test(tactics)) refuse("attack-tsv", at, `${at}: tactics are not a comma list of phase names`);
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the point is to refuse them.
    if (name === "" || /[\x00-\x1f]/.test(name)) refuse("attack-tsv", at, `${at}: the name is empty or holds a control character`);
    byId.set(id, { id, status, successor, tactics: tactics === "" ? [] : tactics.split(","), name });
    counts.total++;
    counts[status]++;
  });
  for (const t of byId.values()) {
    if (t.successor !== "" && !byId.has(t.successor)) refuse("attack-tsv", `${file} ${t.id}`, `${file}: ${t.id} names successor ${t.successor}, which is not in the list`);
  }
  const header = lines.filter((x) => x.startsWith("#")).join("\n");
  if (`${header}\n` !== attackHeader(counts).replace(/\n$/, "\n")) {
    refuse("attack-tsv-header", file, `${file}: the header comments are not the pinned ones for these rows (source, sha256, collection or counts differ)`);
  }
  return { byId, counts };
}

/** The technique list text from a STIX bundle, after its SHA-256 matches the expected one. */
export function buildAttackTsv(bundle: Uint8Array, expected: string): string {
  if (!SAFE_HEX64.test(expected)) refuse("bundle-sha256", "--sha256", "the expected SHA-256 is not 64 hex digits");
  const got = sha256(bundle);
  if (got !== expected) refuse("bundle-sha256", "bundle", `the bundle SHA-256 ${got} is not the expected ${expected}`);
  let doc: unknown;
  try {
    doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bundle));
  } catch {
    return refuse("bundle-json", "bundle", "the bundle is not UTF-8 JSON");
  }
  const objects = isObject(doc) && Array.isArray(doc.objects) ? doc.objects : refuse("bundle-shape", "bundle", "the bundle has no objects list");
  const collections = objects.filter((o) => isObject(o) && o.type === "x-mitre-collection");
  if (collections.length !== 1) refuse("bundle-shape", "bundle", `the bundle must hold exactly one x-mitre-collection, found ${collections.length}`);
  const version = (collections[0] as Record<string, unknown>).x_mitre_version;
  if (version !== ATTACK_VERSION) refuse("bundle-version", "bundle", `the bundle is collection version ${String(version)}, not ${ATTACK_VERSION}`);

  const attackId = new Map<string, string>();
  const patterns: Record<string, unknown>[] = [];
  for (const o of objects) {
    if (!isObject(o) || o.type !== "attack-pattern") continue;
    const stix = typeof o.id === "string" ? o.id : refuse("bundle-shape", "bundle", "an attack-pattern has no id");
    const refs = Array.isArray(o.external_references) ? o.external_references.filter((r) => isObject(r) && r.source_name === "mitre-attack") : [];
    if (refs.length !== 1) refuse("bundle-shape", stix, `${stix} must have exactly one mitre-attack external reference, found ${refs.length}`);
    const id = (refs[0] as Record<string, unknown>).external_id;
    if (typeof id !== "string" || !SAFE_TECHNIQUE.test(id)) refuse("bundle-shape", stix, `${stix} has an ATT&CK id outside the pattern`);
    if ([...attackId.values()].includes(id as string)) refuse("bundle-shape", id as string, `${id} is used by two attack-patterns`);
    attackId.set(stix, id as string);
    patterns.push(o);
  }
  const successorOf = new Map<string, string>();
  for (const o of objects) {
    if (!isObject(o) || o.type !== "relationship" || o.relationship_type !== "revoked-by") continue;
    if (typeof o.source_ref !== "string" || !o.source_ref.startsWith("attack-pattern--")) continue;
    if (successorOf.has(o.source_ref)) refuse("bundle-shape", o.source_ref, `${o.source_ref} has two revoked-by relationships`);
    successorOf.set(o.source_ref, String(o.target_ref));
  }

  const rows: Technique[] = patterns.map((o) => {
    const stix = o.id as string;
    const id = attackId.get(stix) as string;
    const revoked = o.revoked === true;
    const deprecated = o.x_mitre_deprecated === true;
    if (revoked && deprecated) refuse("bundle-shape", id, `${id} is both revoked and deprecated`);
    let successor = "";
    if (revoked) {
      const target = successorOf.get(stix);
      const to = target === undefined ? undefined : attackId.get(target);
      if (to === undefined) refuse("bundle-successor", id, `${id} is revoked but has no revoked-by successor that is an attack-pattern`);
      successor = to as string;
    }
    const phases = Array.isArray(o.kill_chain_phases) ? o.kill_chain_phases : [];
    const tactics = [...new Set(phases.filter((p) => isObject(p) && p.kill_chain_name === "mitre-attack" && typeof p.phase_name === "string").map((p) => (p as Record<string, string>).phase_name))].sort(ordinal);
    const name = typeof o.name === "string" ? o.name : refuse("bundle-shape", id, `${id} has no name`);
    return { id, status: revoked ? "revoked" : deprecated ? "deprecated" : "active", successor, tactics, name };
  });
  rows.sort((a, b) => ordinal(a.id, b.id));

  if (expected === ATTACK_SHA256) {
    const at = (id: string) => rows.find((r) => r.id === id);
    const ok =
      at("T1562.001")?.status === "revoked" &&
      at("T1562.001")?.successor === "T1685" &&
      at("T1685")?.status === "active" &&
      at("T1685")?.tactics.includes("defense-impairment") === true &&
      at("T1027")?.status === "active" &&
      at("T1027")?.tactics.includes("stealth") === true;
    if (!ok) refuse("bundle-check", "bundle", "the check values (T1562.001 revoked by T1685, T1685 under defense-impairment, T1027 under stealth) do not hold");
  }
  const counts = { total: rows.length, active: 0, revoked: 0, deprecated: 0 };
  for (const r of rows) counts[r.status]++;
  const body = rows.map((r) => [r.id, r.status, r.successor, r.tactics.join(","), r.name].join("\t"));
  for (const line of body) if (line.split("\t").length !== 5) refuse("bundle-shape", line.split("\t")[0], "a technique name holds a tab");
  const text = `${attackHeader(counts)}${body.join("\n")}\n`;
  // The generator has to read back what it wrote, so a bad row stops here, not in a build.
  if (expected === ATTACK_SHA256) parseAttackTsv(text, "generated list");
  return text;
}

// -- The crosswalk --

/** The crosswalk as a map from ID as written to its entry, after every entry is checked. */
export function parseCrosswalk(text: string, attack: AttackList, file = CROSSWALK): Map<string, CrosswalkEntry> {
  const doc = readJson(text, file);
  if (!isObject(doc)) return refuse("crosswalk-shape", file, `${file} must be one JSON object`);
  exactKeys(doc, ["format", "attack", "entries"], "crosswalk-shape", file);
  if (doc.format !== CROSSWALK_FORMAT) refuse("crosswalk-shape", file, `${file} format must be ${CROSSWALK_FORMAT}`);
  if (doc.attack !== ATTACK_VERSION) refuse("crosswalk-shape", file, `${file} attack must be ${ATTACK_VERSION}`);
  if (!Array.isArray(doc.entries)) return refuse("crosswalk-shape", file, `${file} entries must be a list`);
  const out = new Map<string, CrosswalkEntry>();
  for (const [i, e] of doc.entries.entries()) {
    const at = `${file} entry ${i + 1}`;
    if (!isObject(e)) refuse("crosswalk-shape", at, `${at} must be an object`);
    const o = e as Record<string, unknown>;
    exactKeys(o, ["from", "to", "how"], "crosswalk-shape", at);
    const { from, to, how } = o;
    if (typeof from !== "string" || !SAFE_TECHNIQUE.test(from)) refuse("crosswalk-shape", at, `${at}: from is not a technique id`);
    if (typeof to !== "string" || !SAFE_TECHNIQUE.test(to)) refuse("crosswalk-shape", at, `${at}: to is not a technique id`);
    if (how !== "unchanged" && how !== "revoked-by") refuse("crosswalk-shape", at, `${at}: how must be unchanged or revoked-by`);
    const f = from as string;
    const t = to as string;
    if (out.has(f)) refuse("crosswalk-duplicate", f, `${file} has two entries for ${f}`);
    // The target comes first: whatever the entry claims, it may not point at a technique that is gone.
    const target = attack.byId.get(t);
    if (!target) refuse("crosswalk-target-absent", t, `${file}: the target ${t} (from ${f}) is not in the ${ATTACK_VERSION} list`);
    if (target?.status !== "active") refuse("crosswalk-target-inactive", t, `${file}: the target ${t} (from ${f}) is ${target?.status} in ${ATTACK_VERSION}`);
    const origin = attack.byId.get(f);
    if (how === "unchanged") {
      if (origin?.status !== "active") refuse("crosswalk-unchanged-not-active", f, `${file}: ${f} is marked unchanged but is ${origin ? origin.status : "absent"} in ${ATTACK_VERSION}`);
      if (f !== t) refuse("crosswalk-unchanged-differs", f, `${file}: ${f} is marked unchanged but maps to ${t}`);
    } else {
      if (origin?.status !== "revoked") refuse("crosswalk-revoked-by-not-revoked", f, `${file}: ${f} is marked revoked-by but is ${origin ? origin.status : "absent"} in ${ATTACK_VERSION}`);
      if (origin.successor !== t) refuse("crosswalk-wrong-successor", f, `${file}: ${f} was revoked by ${origin.successor}, not ${t}`);
    }
    out.set(f, { from: f, to: t, how });
  }
  return out;
}

// -- The pack --

/** The pack rules from the rules folder, each with its ATT&CK ids as written and as 19.2. */
export function loadPack(l: Layout, crosswalk: Map<string, CrosswalkEntry>): PackRule[] {
  if (!existsSync(l.rules)) setup("input-missing", rel(l, l.rules), `${rel(l, l.rules)} is missing`);
  let read: ReturnType<typeof readRulesDir>;
  try {
    read = readRulesDir(l.rules);
  } catch (e) {
    if (e instanceof RulesError) return refuse("rules-xml", rel(l, l.rules), e.message);
    throw e;
  }
  for (const r of read.skippedRules) {
    if (isPack(r.id)) refuse("pack-rule-skipped", `rule ${r.id}`, `rule ${r.id} sits in ${r.file}, a folder the manager never reads`);
  }
  const pack = read.rules.filter((r) => isPack(r.id));
  for (const [id] of repeatedIds(pack)) refuse("pack-rule-duplicate", `rule ${id}`, `rule ${id} is defined more than once`);
  if (pack.length === 0) refuse("pack-empty", rel(l, l.rules), "the rules folder holds no pack rule");
  const out: PackRule[] = [];
  for (const r of [...pack].sort((a, b) => a.id - b.id)) {
    if (r.mitrePairs.length > 0) refuse("pack-rule-mitre-pairs", `rule ${r.id}`, `rule ${r.id} maps through tactic and technique pairs, which this tool does not read`);
    const written = [...new Set(r.mitre)].sort(ordinal);
    const attack19 = new Set<string>();
    for (const id of written) {
      const entry = crosswalk.get(id);
      if (!entry) refuse("crosswalk-missing", id, `${id} (rule ${r.id}) has no entry in ${CROSSWALK}`);
      attack19.add((entry as CrosswalkEntry).to);
    }
    out.push({ id: r.id, level: r.level, written, attack19: [...attack19].sort(ordinal) });
  }
  return out;
}

// -- The session records --

/** One record, whose every field this tool reads is checked; it holds its run windows. */
export function parseRecord(file: string, text: string): Session {
  const doc = readJson(text, file);
  if (!isObject(doc)) return refuse("record-shape", file, `${file} must be one JSON object`);
  if (doc.format !== RECORD_FORMAT) refuse("record-format", file, `${file} format must be ${RECORD_FORMAT}`);
  if (typeof doc.session !== "string" || !SAFE_SESSION.test(doc.session)) refuse("record-session", file, `${file} has no session id in the pattern`);
  if (doc.verdict !== "pass" && doc.verdict !== "fail") refuse("record-verdict", file, `${file} verdict must be pass or fail`);
  if (!Array.isArray(doc.failures) || !doc.failures.every((f) => typeof f === "string")) refuse("record-shape", file, `${file} failures must be a list of text`);
  if (!Array.isArray(doc.tests)) return refuse("record-tests", file, `${file} tests must be a list`);
  const windows: RunWindow[] = [];
  const starts: bigint[] = [];
  const ends: bigint[] = [];
  const guids = new Set<string>();
  const step = (t: Record<string, unknown>, which: "run" | "cleanup", at: string) => {
    const s = t[which];
    const name = `${at} ${which}`;
    if (!isObject(s)) return refuse("record-step", name, `${name} must be an object`);
    if (typeof s.status !== "string") refuse("record-step", name, `${name} has no status`);
    if (s.exitCode !== null && !isInt(s.exitCode)) refuse("record-step", name, `${name} exitCode must be a number or null`);
    if (s.startUtc === null && s.endUtc === null) return null;
    const start = parseInstant(s.startUtc, "record-time", `${name} startUtc`);
    const end = parseInstant(s.endUtc, "record-time", `${name} endUtc`);
    if (end < start) refuse("record-window", name, `${name} ends before it starts`);
    starts.push(start);
    ends.push(end);
    return { start, end };
  };
  const tests: TestRecord[] = [];
  doc.tests.forEach((raw, position) => {
    const at = `${file} test ${position + 1}`;
    if (!isObject(raw)) return refuse("record-test", at, `${at} must be an object`);
    if (typeof raw.guid !== "string" || !SAFE_GUID.test(raw.guid)) refuse("record-test", at, `${at} has no guid in the pattern`);
    const guid = raw.guid as string;
    if (guids.has(guid)) refuse("record-duplicate-guid", guid, `${file} lists test ${guid} twice`);
    guids.add(guid);
    if (typeof raw.technique !== "string" || !SAFE_TECHNIQUE.test(raw.technique)) refuse("record-test", at, `${at} technique is outside the pattern`);
    if (!isInt(raw.testNumber) || raw.testNumber < 1) refuse("record-test", at, `${at} testNumber must be a whole number from 1`);
    if (typeof raw.testName !== "string") refuse("record-test", at, `${at} has no testName`);
    if (!Array.isArray(raw.rules) || !raw.rules.every((r) => isInt(r) && isPack(r))) refuse("record-rules", at, `${at} rules must be pack rule ids`);
    const run = step(raw, "run", at);
    step(raw, "cleanup", at);
    if (run) windows.push({ guid, technique: raw.technique as string, testNumber: raw.testNumber as number, rules: raw.rules as number[], position, start: run.start, end: run.end });
    tests.push(raw as unknown as TestRecord);
  });
  const span = starts.length ? { from: starts.reduce((a, b) => (b < a ? b : a)), to: ends.reduce((a, b) => (b > a ? b : a)) } : null;
  const record: Record0 = { format: doc.format, session: doc.session, verdict: doc.verdict, failures: doc.failures as string[], tests };
  return { record, file, sha256: sha256(text), windows, span };
}

/** Every record under art-runs, in file order; a repeated session or a name that is not the session is refused. */
export function loadRecords(l: Layout): Session[] {
  const out: Session[] = [];
  const seen = new Set<string>();
  const names = listFiles(l, l.records, /\.json$/, "record-file");
  for (const name of names) {
    const s = parseRecord(`${rel(l, l.records)}/${name}`, readFileSync(join(l.records, name), "utf8"));
    if (seen.has(s.record.session)) refuse("record-duplicate-session", s.record.session, `session ${s.record.session} is recorded in two files`);
    seen.add(s.record.session);
    out.push(s);
  }
  // The name check comes last so a copy that sorts first is still reported as a repeated session.
  for (const [i, s] of out.entries()) {
    if (names[i] !== `${s.record.session}.json`) refuse("record-name", s.file, `${s.file} holds session ${s.record.session}, so it must be named for it`);
  }
  return out;
}

// -- The live-index evidence --

function shardCounts(x: unknown, item: string): ShardCounts {
  if (!isObject(x)) return refuse("evidence-shards", item, `${item} must be an object`);
  exactKeys(x, ["total", "successful", "skipped", "failed"], "evidence-shards", item);
  for (const k of ["total", "successful", "skipped", "failed"]) if (!isNat(x[k])) refuse("evidence-shards", item, `${item}.${k} must be a whole number`);
  const c = x as unknown as ShardCounts;
  if (c.failed !== 0) refuse("evidence-shards", item, `${item}: ${c.failed} shard(s) failed, so the answer may be partial`);
  if (c.successful !== c.total) refuse("evidence-shards", item, `${item}: ${c.successful} of ${c.total} shards answered`);
  return c;
}

/** One evidence file, shape-checked, and held to the record of its session. */
export function parseEvidence(file: string, text: string, sessions: Map<string, Session>): Evidence {
  const doc = readJson(text, file);
  if (!isObject(doc)) return refuse("evidence-shape", file, `${file} must be one JSON object`);
  if (doc.format !== ALERTS_FORMAT) refuse("evidence-format", file, `${file} format must be ${ALERTS_FORMAT}`);
  exactKeys(doc, ["format", "session", "recordSha256", "query", "shards", "control", "alerts"], "evidence-shape", file);
  const named = /^(.*)\.alerts\.json$/.exec(file.split("/").pop() ?? "");
  if (typeof doc.session !== "string" || !SAFE_SESSION.test(doc.session)) refuse("evidence-shape", file, `${file} has no session id in the pattern`);
  const session = doc.session as string;
  const s = sessions.get(session);
  if (!s) refuse("evidence-no-record", session, `${file} is for session ${session}, which has no record under art-runs`);
  if (named?.[1] !== session) refuse("evidence-name", file, `${file} holds session ${session}, so it must be named for it`);
  if (doc.recordSha256 !== (s as Session).sha256) refuse("evidence-record-sha", session, `${file} was taken against another copy of the record for ${session}`);

  const q = doc.query;
  if (!isObject(q)) return refuse("evidence-query", file, `${file} query must be an object`);
  exactKeys(q, ["index", "agent", "rules", "fromUtc", "toUtc"], "evidence-query", `${file} query`);
  if (q.index !== INDEX_PATTERN) refuse("evidence-query", file, `${file} query index must be ${INDEX_PATTERN}`);
  if (q.agent !== AGENT) refuse("evidence-agent", file, `${file} query is for agent ${String(q.agent)}, not ${AGENT}`);
  const queried = Array.isArray(q.rules) && q.rules.every((r) => isInt(r) && inScope(r)) ? (q.rules as number[]) : refuse("evidence-query", file, `${file} query rules must be pack ids and the Defender rules`);
  // A rule the query never asked for cannot be shown silent: every rule a test of the session lists, and both Defender rules, must be in it.
  for (const need of [...(s as Session).windows.flatMap((w) => w.rules), ...DEFENDER_RULES]) {
    if (!queried.includes(need)) refuse("evidence-query", file, `${file} query did not ask for rule ${need}, which ${session} needs`);
  }
  const from = parseInstant(q.fromUtc, "evidence-time", `${file} query fromUtc`);
  const to = parseInstant(q.toUtc, "evidence-time", `${file} query toUtc`);
  if (to < from) refuse("evidence-query", file, `${file} query ends before it starts`);
  const span = (s as Session).span;
  if (span && (from > span.from || to < span.to)) refuse("evidence-span", session, `${file} query does not cover every run and cleanup window of ${session}`);

  if (!isObject(doc.shards)) return refuse("evidence-shards", file, `${file} shards must be an object`);
  exactKeys(doc.shards, ["alerts", "control"], "evidence-shards", `${file} shards`);
  const shards = { alerts: shardCounts(doc.shards.alerts, `${file} shards.alerts`), control: shardCounts(doc.shards.control, `${file} shards.control`) };
  if (!isObject(doc.control)) return refuse("evidence-control", file, `${file} control must be an object`);
  exactKeys(doc.control, ["agent001Alerts"], "evidence-control", `${file} control`);
  if (!isNat(doc.control.agent001Alerts)) refuse("evidence-control", file, `${file} control count must be a whole number`);
  if (!Array.isArray(doc.alerts)) return refuse("evidence-alerts", file, `${file} alerts must be a list`);
  if (doc.alerts.length > (doc.control.agent001Alerts as number)) refuse("evidence-control", file, `${file} lists ${doc.alerts.length} alerts but the control counted ${doc.control.agent001Alerts} for the agent`);

  const seen = new Set<string>();
  const alerts: EvidenceAlert[] = [];
  for (const [i, raw] of doc.alerts.entries()) {
    const at = `${file} alert ${i + 1}`;
    if (!isObject(raw)) return refuse("evidence-alerts", at, `${at} must be an object`);
    exactKeys(raw, ["index", "id", "ruleId", "ruleLevel", "mitre", "agentId", "timestamp", "eventTime", "systemTime", "eventId", "channel", "image"], "evidence-alerts", at);
    if (typeof raw.index !== "string" || !INDEX_NAME.test(raw.index)) refuse("evidence-index", at, `${at} index is not a Wazuh 4.x daily alerts index`);
    if (typeof raw.id !== "string" || raw.id === "" || !SAFE_DOC_ID.test(raw.id)) refuse("evidence-alert-id", at, `${at} has no document id, so it cannot be looked up in the index`);
    if (raw.agentId !== AGENT) refuse("evidence-agent", at, `${at} is from agent ${String(raw.agentId)}, not ${AGENT}`);
    if (!isInt(raw.ruleId) || !inScope(raw.ruleId)) refuse("evidence-rule", at, `${at} rule id is neither a pack rule nor a Defender rule`);
    if (!isInt(raw.ruleLevel) || raw.ruleLevel < 0 || raw.ruleLevel > 16) refuse("evidence-alerts", at, `${at} level must run 0 to 16`);
    if (!Array.isArray(raw.mitre) || !raw.mitre.every((m) => typeof m === "string" && /^[A-Za-z0-9.]{1,16}$/.test(m))) refuse("evidence-alerts", at, `${at} mitre must be a list of ids`);
    parseInstant(raw.timestamp, "evidence-time", `${at} timestamp`);
    parseInstant(raw.eventTime, "evidence-time", `${at} eventTime`);
    if (raw.systemTime !== null) parseInstant(raw.systemTime, "evidence-time", `${at} systemTime`);
    if (raw.eventId !== null && !isNat(raw.eventId)) refuse("evidence-alerts", at, `${at} eventId must be a number or null`);
    if (typeof raw.channel !== "string" || !SAFE_CHANNEL.test(raw.channel)) refuse("evidence-alerts", at, `${at} channel is outside its pattern`);
    if (raw.image !== null && (typeof raw.image !== "string" || !SAFE_IMAGE.test(raw.image))) refuse("evidence-alerts", at, `${at} image must be a bare file name or null`);
    const key = `${raw.index}/${raw.id}`;
    if (seen.has(key)) refuse("evidence-duplicate", key, `${file} lists ${key} twice`);
    seen.add(key);
    if (!queried.includes(raw.ruleId as number)) refuse("evidence-alerts", at, `${at} is for rule ${raw.ruleId}, which the query did not ask for`);
    const stamp = parseInstant(raw.timestamp, "evidence-time", `${at} timestamp`);
    if (stamp < from || stamp > to) refuse("evidence-alerts", at, `${at} was indexed outside the query's span`);
    alerts.push(raw as unknown as EvidenceAlert);
  }
  return {
    format: ALERTS_FORMAT,
    session,
    recordSha256: (s as Session).sha256,
    query: { index: INDEX_PATTERN, agent: AGENT, rules: queried, fromUtc: q.fromUtc as string, toUtc: q.toUtc as string },
    shards,
    control: { agent001Alerts: doc.control.agent001Alerts as number },
    alerts,
  };
}

/** Every evidence file under validation/ and misses.json's text; any other file there is refused. */
export function loadEvidence(l: Layout, sessions: Session[]): Evidence[] {
  const bySession = new Map(sessions.map((s) => [s.record.session, s]));
  const out: Evidence[] = [];
  const seen = new Set<string>();
  const names = listFiles(l, l.validation, /^(?:misses\.json|[^/]+\.alerts\.json)$/, "validation-file");
  for (const name of names.filter((n) => n !== "misses.json")) {
    const file = `${rel(l, l.validation)}/${name}`;
    const text = readFileSync(join(l.validation, name), "utf8");
    const e = parseEvidence(file, text, bySession);
    if (seen.has(e.session)) refuse("evidence-duplicate-session", e.session, `session ${e.session} has two evidence files`);
    seen.add(e.session);
    out.push(e);
  }
  return out;
}

// -- What counts as validated --

/** Each pack alert as counted or not, and the first counted alert for each rule. */
export function classify(sessions: Session[], evidence: Evidence[], pack: PackRule[]): { counted: Map<number, Counted>; uncounted: Uncounted[] } {
  const inXml = new Set(pack.map((r) => r.id));
  const bySession = new Map(sessions.map((s) => [s.record.session, s]));
  const candidates = new Map<number, { c: Counted; order: [string, number, bigint, string, string] }[]>();
  const uncounted: Uncounted[] = [];
  for (const ev of evidence) {
    const s = bySession.get(ev.session) as Session;
    for (const a of ev.alerts) {
      if (!isPack(a.ruleId)) continue;
      // Matching is on the event time alone; the index time lags by about a second and is only recorded.
      const t = parseInstant(a.eventTime, "evidence-time", `alert ${a.id} eventTime`);
      const inWindow = s.windows.filter((w) => w.start <= t && t <= w.end);
      const note = (reason: string) => uncounted.push({ session: ev.session, index: a.index, id: a.id, rule: a.ruleId, eventTime: a.eventTime, indexTime: a.timestamp, reason });
      if (!inXml.has(a.ruleId)) {
        if (inWindow.length) refuse("validated-not-subset", `rule ${a.ruleId}`, `rule ${a.ruleId} raised alert ${a.id} inside a run window of ${ev.session} but is not in the pack XML`);
        note("rule-not-in-xml");
        continue;
      }
      if (!inWindow.length) {
        note("outside-run-window");
        continue;
      }
      const listed = inWindow.filter((w) => w.rules.includes(a.ruleId));
      if (!listed.length) {
        note("rule-not-in-test-rules");
        continue;
      }
      if (s.record.verdict !== "pass") {
        note("session-verdict-not-pass");
        continue;
      }
      const w = [...listed].sort((x, y) => x.position - y.position)[0];
      const c: Counted = { rule: a.ruleId, session: ev.session, test: w.guid, art: `${w.technique} #${w.testNumber}`, index: a.index, id: a.id, eventTime: a.eventTime, indexTime: a.timestamp };
      const list = candidates.get(a.ruleId) ?? [];
      list.push({ c, order: [ev.session, w.position, t, a.index, a.id] });
      candidates.set(a.ruleId, list);
    }
  }
  const counted = new Map<number, Counted>();
  for (const [rule, list] of candidates) {
    list.sort((x, y) => ordinal(x.order[0], y.order[0]) || x.order[1] - y.order[1] || cmpBig(x.order[2], y.order[2]) || ordinal(x.order[3], y.order[3]) || ordinal(x.order[4], y.order[4]));
    counted.set(rule, list[0].c);
    // Every counted alert past the first is still an alert that counted; only the first is the row's.
  }
  uncounted.sort((x, y) => ordinal(x.session, y.session) || ordinal(x.eventTime, y.eventTime) || ordinal(x.id, y.id));
  return { counted, uncounted };
}

/** The post-check the validated sets must pass: every validated rule and technique is in the exists set. */
export function assertSubset(validated: number[], pack: PackRule[]): void {
  const exists = new Set(pack.map((r) => r.id));
  for (const id of validated) if (!exists.has(id)) refuse("validated-not-subset", `rule ${id}`, `rule ${id} is validated but is not in the pack`);
  const existsTech = new Set(pack.flatMap((r) => r.attack19));
  for (const r of pack) {
    if (!validated.includes(r.id)) continue;
    for (const t of r.attack19) if (!existsTech.has(t)) refuse("validated-not-subset", t, `technique ${t} is validated but no pack rule maps to it`);
  }
}

// -- The hand-kept miss list --

/** The miss entries, each held to its class, to the pack and to the evidence it cites. */
export function parseMisses(text: string, file: string, pack: PackRule[], counted: Map<number, Counted>, sessions: Session[], evidence: Evidence[]): Map<number, Miss> {
  const doc = readJson(text, file);
  if (!isObject(doc)) return refuse("misses-shape", file, `${file} must be one JSON object`);
  exactKeys(doc, ["format", "entries"], "misses-shape", file);
  if (doc.format !== MISSES_FORMAT) refuse("misses-shape", file, `${file} format must be ${MISSES_FORMAT}`);
  if (!Array.isArray(doc.entries)) return refuse("misses-shape", file, `${file} entries must be a list`);
  const inPack = new Set(pack.map((r) => r.id));
  const bySession = new Map(sessions.map((s) => [s.record.session, s]));
  const evBySession = new Map(evidence.map((e) => [e.session, e]));
  const out = new Map<number, Miss>();
  for (const [i, raw] of doc.entries.entries()) {
    const at = `${file} entry ${i + 1}`;
    if (!isObject(raw)) return refuse("misses-shape", at, `${at} must be an object`);
    if (!isInt(raw.rule)) return refuse("misses-shape", at, `${at} has no rule id`);
    const rule = raw.rule;
    const item = `rule ${rule}`;
    const cls = MISS_CLASSES.find((c) => c === raw.class);
    if (!cls) return refuse("misses-class", item, `${at} (${item}): ${String(raw.class)} is not a miss class`);
    const allowed = ["rule", "class", "evidence", ...(cls === "not-run" ? ["ruling"] : cls === "blocked-by-defender" ? ["session", "test", "alertId"] : ["session", "test"])];
    for (const k of Object.keys(raw)) if (!allowed.includes(k)) refuse("misses-shape", item, `${at} (${item}): ${k} is not a field of a ${cls} entry`);
    if (out.has(rule)) refuse("misses-duplicate-rule", item, `${file} has two entries for ${item}`);
    if (!inPack.has(rule)) refuse("misses-not-pack", item, `${at}: ${item} is not a rule of the pack`);
    if (counted.has(rule)) refuse("misses-rule-validated", item, `${at}: ${item} is validated, so it cannot be a miss`);
    if (typeof raw.evidence !== "string" || raw.evidence.trim() === "" || !SAFE_TEXT.test(raw.evidence)) refuse("misses-evidence", item, `${at} (${item}) needs evidence text of plain printable characters`);
    const miss: Miss = { rule, class: cls, evidence: raw.evidence as string, session: null, test: null, alertId: null, ruling: null };
    if (cls === "not-run") {
      if (typeof raw.ruling !== "string" || raw.ruling.trim() === "" || !SAFE_TEXT.test(raw.ruling)) refuse("misses-ruling", item, `${at} (${item}): a not-run entry needs a ruling`);
      miss.ruling = raw.ruling as string;
    } else {
      const s = typeof raw.session === "string" ? bySession.get(raw.session) : undefined;
      if (!s) refuse("misses-session", item, `${at} (${item}) cites a session that has no record`);
      const t = (s as Session).record.tests.find((x) => x.guid === raw.test);
      if (!t || !t.rules.includes(rule)) refuse("misses-test", item, `${at} (${item}) cites a test of ${(s as Session).record.session} that does not list ${item}`);
      miss.session = raw.session as string;
      miss.test = raw.test as string;
      if (cls === "blocked-by-defender") {
        const w = (s as Session).windows.find((x) => x.guid === raw.test);
        const a = evBySession.get(miss.session)?.alerts.find((x) => x.id === raw.alertId && DEFENDER_RULES.includes(x.ruleId));
        const at2 = a ? parseInstant(a.eventTime, "evidence-time", `alert ${a.id} eventTime`) : 0n;
        if (!w || !a || at2 < w.start || at2 > w.end) {
          refuse("misses-defender-evidence", item, `${at} (${item}): a blocked-by-defender entry must cite a rule 62123 or 62124 alert whose event time is inside the cited test's run window`);
        }
        miss.alertId = raw.alertId as string;
      }
    }
    out.set(rule, miss);
  }
  return out;
}

// -- The outputs --

interface LayerInfo {
  rules: number[];
  arts: string[];
}

/** One Navigator layer. A scored sub-technique brings its parent along, unscored unless mapped. */
export function buildLayer(kind: "exists" | "validated", byTechnique: Map<string, LayerInfo>, attack: AttackList): string {
  const entries = new Map<string, Record<string, unknown>>();
  let max = 1;
  for (const [id, info] of byTechnique) {
    const score = info.rules.length;
    max = Math.max(max, score);
    const metadata = [{ name: "rules", value: info.rules.join(", ") }, ...info.arts.map((a) => ({ name: "art", value: a }))];
    const comment = `${kind === "exists" ? "pack rules" : "validated rules"}: ${info.rules.join(", ")}${info.arts.length ? `; ${info.arts.join("; ")}` : ""}`;
    entries.set(id, { techniqueID: id, score, comment, enabled: true, metadata, links: [], showSubtechniques: !id.includes(".") ? true : false });
    const parent = id.split(".")[0];
    if (id.includes(".") && !byTechnique.has(parent)) {
      if (attack.byId.get(parent)?.status !== "active") refuse("layer-parent", parent, `the parent ${parent} of ${id} is not an active technique in ${ATTACK_VERSION}`);
      entries.set(parent, { techniqueID: parent, enabled: true, showSubtechniques: true });
    }
  }
  const title = kind === "exists" ? "TalonSocLab detection pack: a rule exists" : "TalonSocLab detection pack: validated by a live alert";
  const note =
    kind === "exists"
      ? "Score is the number of pack rules whose <mitre> ids map to the technique."
      : "Score is the number of pack rules that raised a live alert from agent 001 inside an ART run window; logtest output never counts.";
  const layer = {
    name: title,
    versions: { attack: ATTACK_MAJOR, navigator: NAVIGATOR_VERSION, layer: LAYER_FORMAT },
    domain: "enterprise-attack",
    description: `${note} ATT&CK ${ATTACK_VERSION}.`,
    sorting: 0,
    layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregatedTechniques: false, countUnscored: false, expandedSubtechniques: "annotated" },
    hideDisabled: false,
    techniques: [...entries.values()].sort((a, b) => ordinal(a.techniqueID as string, b.techniqueID as string)),
    gradient: { colors: ["#ffffff", "#66b1ff"], minValue: 0, maxValue: max },
    legendItems: [],
    metadata: [],
    links: [],
    showTacticRowBackground: false,
    tacticRowBackground: "#dddddd",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
  return jsonText(layer);
}

/** Everything build writes, from the inputs under one layout; nothing is written here. */
export function buildAll(l: Layout): Built {
  const attack = parseAttackTsv(readInput(l, l.attackTsv), rel(l, l.attackTsv));
  const crosswalk = parseCrosswalk(readInput(l, l.crosswalk), attack, rel(l, l.crosswalk));
  const pack = loadPack(l, crosswalk);
  const sessions = loadRecords(l);
  const evidence = loadEvidence(l, sessions);
  const { counted, uncounted } = classify(sessions, evidence, pack);
  const validated = [...counted.keys()].sort((a, b) => a - b);
  assertSubset(validated, pack);
  const misses = parseMisses(readInput(l, l.misses), rel(l, l.misses), pack, counted, sessions, evidence);

  const existsMap = new Map<string, LayerInfo>();
  const validatedMap = new Map<string, LayerInfo>();
  for (const r of pack) {
    for (const t of r.attack19) {
      const e = existsMap.get(t) ?? { rules: [], arts: [] };
      e.rules.push(r.id);
      existsMap.set(t, e);
      const c = counted.get(r.id);
      if (c) {
        const v = validatedMap.get(t) ?? { rules: [], arts: [] };
        v.rules.push(r.id);
        v.arts.push(`art:${c.art} ${c.session}`);
        validatedMap.set(t, v);
      }
    }
  }
  for (const m of [existsMap, validatedMap]) for (const info of m.values()) info.arts = [...new Set(info.arts)].sort(ordinal);

  const rows = pack.map((r) => {
    const c = counted.get(r.id);
    const m = misses.get(r.id);
    return {
      rule: r.id,
      level: r.level,
      attackAsWritten: r.written,
      attack19: r.attack19,
      status: c ? "validated" : "not-validated",
      validation: c ? { session: c.session, test: c.test, art: c.art, alertIndex: c.index, docId: c.id, eventTime: c.eventTime, indexTime: c.indexTime } : null,
      miss: m ? { class: m.class, evidence: m.evidence, session: m.session, test: m.test, alertId: m.alertId, ruling: m.ruling } : null,
    };
  });
  const unclassified = pack.filter((r) => !counted.has(r.id) && !misses.has(r.id)).map((r) => r.id);
  // complete is derived, never stated: it holds only when no not-validated rule lacks a valid entry.
  const complete = unclassified.length === 0;
  const summary = {
    format: COVERAGE_FORMAT,
    attack: ATTACK_VERSION,
    packSize: pack.length,
    validatedRules: validated,
    ratio: { validated: validated.length, of: pack.length },
    complete,
    unclassified,
    rules: rows,
    sessions: sessions.map((s) => ({ session: s.record.session, verdict: s.record.verdict, recordSha256: s.sha256, evidence: evidence.some((e) => e.session === s.record.session) })),
    uncounted,
  };
  const files = new Map<string, string>([
    [OUT_EXISTS, buildLayer("exists", existsMap, attack)],
    [OUT_VALIDATED, buildLayer("validated", validatedMap, attack)],
    [OUT_SUMMARY, jsonText(summary)],
  ]);
  return { files, packSize: pack.length, validated, unclassified, complete };
}

/** Write files into a folder through temp names, so a failure leaves each old file whole. */
function writeAll(dir: string, files: Map<string, string>): void {
  mkdirSync(dir, { recursive: true });
  const staged: [string, string][] = [];
  try {
    for (const [name, text] of files) {
      const tmp = join(dir, `.${name}.${process.pid}.tmp`);
      writeFileSync(tmp, text);
      staged.push([tmp, join(dir, name)]);
    }
    for (const [tmp, dest] of staged) renameSync(tmp, dest);
  } finally {
    for (const [tmp] of staged) rmSync(tmp, { force: true });
  }
}

/** The outputs that differ from the rebuild, or are missing, as one line each. */
export function diffOutputs(l: Layout, files: Map<string, string>): string[] {
  const bad: string[] = [];
  for (const [name, text] of files) {
    const path = join(l.coverage, name);
    if (!existsSync(path)) bad.push(`${rel(l, path)} is missing`);
    else if (readFileSync(path, "utf8") !== text) bad.push(`${rel(l, path)} differs from the rebuild`);
  }
  return bad;
}

// -- Fetching the evidence --

/** The ssh remote for one alias: BatchMode, an argv array, NDJSON on stdin. */
export function sshRemote(alias: string): Remote {
  if (!SAFE_HOST.test(alias)) refuse("fetch-host", "--host", "the ssh host alias holds characters an alias never has");
  return (ndjson, timeoutMs) => {
    try {
      const r = Bun.spawnSync(["ssh", "-o", "BatchMode=yes", alias, REMOTE_COMMAND], { stdin: Buffer.from(ndjson), stdout: "pipe", stderr: "pipe", timeout: timeoutMs });
      return { code: r.exitCode, out: r.stdout.toString(), timedOut: r.exitedDueToTimeout === true };
    } catch {
      return { code: null, out: "", timedOut: false };
    }
  };
}

/** The two-query _msearch body for one session: the alerts of interest, and the control count. */
export function msearchBody(s: Session, packIds: number[]): { text: string; query: Evidence["query"] } {
  const span = s.span as { from: bigint; to: bigint };
  const pad = BigInt(PAD_MS) * 1_000_000n;
  const iso = (ns: bigint) => {
    const ms = ns / 1_000_000n;
    return new Date(Number(ms)).toISOString();
  };
  const fromUtc = iso(span.from - pad);
  const toUtc = iso(span.to + pad);
  // Every pack rule in the XML is asked for, so an alert from a rule the test did not list is still seen and listed.
  const rules = [...new Set([...packIds, ...DEFENDER_RULES])].sort((a, b) => a - b);
  const range = { range: { timestamp: { gte: fromUtc, lte: toUtc, format: "strict_date_optional_time" } } };
  const agent = { term: { "agent.id": AGENT } };
  const header = JSON.stringify({ index: INDEX_PATTERN });
  const alerts = {
    size: HITS_MAX,
    track_total_hits: true,
    sort: [{ timestamp: "asc" }],
    query: { bool: { filter: [agent, { terms: { "rule.id": rules.map(String) } }, range] } },
    _source: ["timestamp", "rule.id", "rule.level", "rule.mitre.id", "agent.id", "data.win.system.eventID", "data.win.system.channel", "data.win.system.systemTime", "data.win.eventdata.utcTime", "data.win.eventdata.image"],
  };
  const control = { size: 0, track_total_hits: true, query: { bool: { filter: [agent, range] } } };
  return { text: `${header}\n${JSON.stringify(alerts)}\n${header}\n${JSON.stringify(control)}\n`, query: { index: INDEX_PATTERN, agent: AGENT, rules, fromUtc, toUtc } };
}

function responseShards(x: unknown, item: string): ShardCounts {
  const o = isObject(x) ? x : {};
  const c = { total: o.total, successful: o.successful, skipped: o.skipped ?? 0, failed: o.failed };
  return shardCounts(c, item);
}

/** One session's evidence from the _msearch answer, every failure mode refused. */
export function evidenceFromAnswer(s: Session, query: Evidence["query"], answer: string): Evidence {
  let doc: unknown;
  try {
    doc = JSON.parse(answer);
  } catch {
    return setup("fetch-answer", s.record.session, "the index did not answer with JSON");
  }
  const res = isObject(doc) && Array.isArray(doc.responses) ? doc.responses : refuse("fetch-answer", s.record.session, "the answer has no responses list");
  if (res.length !== 2) refuse("fetch-answer", s.record.session, `the answer holds ${res.length} responses, not 2`);
  const [ra, rc] = res as Record<string, unknown>[];
  for (const [name, r] of [["alerts", ra], ["control", rc]] as const) {
    if (!isObject(r)) refuse("fetch-answer", s.record.session, `the ${name} response is not an object`);
    if (r.status !== 200) refuse("fetch-status", s.record.session, `the ${name} query answered status ${String(r.status)}`);
    if (r.timed_out !== false) refuse("fetch-timeout", s.record.session, `the ${name} query timed out inside the index`);
  }
  const shards = { alerts: responseShards(ra._shards, "alerts shards"), control: responseShards(rc._shards, "control shards") };
  const total = (r: Record<string, unknown>, name: string) => {
    const h = r.hits;
    const t = isObject(h) && isObject(h.total) ? h.total : {};
    if (t.relation !== "eq" || !isNat(t.value)) refuse("fetch-answer", s.record.session, `the ${name} total is not an exact count`);
    return t.value as number;
  };
  const control = total(rc, "control");
  const n = total(ra, "alerts");
  const hits = isObject(ra.hits) && Array.isArray(ra.hits.hits) ? (ra.hits.hits as unknown[]) : refuse("fetch-answer", s.record.session, "the alerts response has no hits list");
  if (hits.length !== n) refuse("fetch-truncated", s.record.session, `the alerts query matched ${n} but returned ${hits.length}`);
  const alerts: EvidenceAlert[] = hits.map((h, i) => {
    const at = `${s.record.session} hit ${i + 1}`;
    if (!isObject(h) || !isObject(h._source)) return refuse("fetch-alert", at, `${at} is not a document`);
    const src = h._source as Record<string, unknown>;
    const dig = (...path: string[]) => path.reduce<unknown>((o, k) => (isObject(o) ? o[k] : undefined), src);
    const ruleId = Number(dig("rule", "id"));
    const sys = dig("data", "win", "system", "systemTime");
    const utc = dig("data", "win", "eventdata", "utcTime");
    const systemTime = sys === undefined ? null : normalizeTime(sys, `${at} systemTime`);
    const eventTime = utc !== undefined ? normalizeTime(utc, `${at} utcTime`) : systemTime ?? refuse("fetch-alert", at, `${at} has neither a utcTime nor a systemTime`);
    const eid = dig("data", "win", "system", "eventID");
    const image = dig("data", "win", "eventdata", "image");
    const mitre = dig("rule", "mitre", "id");
    return {
      index: String(h._index),
      id: String(h._id ?? ""),
      ruleId,
      ruleLevel: Number(dig("rule", "level")),
      mitre: Array.isArray(mitre) ? (mitre as string[]) : [],
      agentId: String(dig("agent", "id")),
      timestamp: normalizeTime(dig("timestamp"), `${at} timestamp`),
      eventTime,
      systemTime,
      eventId: eid === undefined ? null : Number(eid),
      channel: String(dig("data", "win", "system", "channel")),
      image: typeof image === "string" ? (image.split(/[\\/]/).pop() ?? null) : null,
    };
  });
  alerts.sort((a, b) => ordinal(a.timestamp, b.timestamp) || ordinal(a.index, b.index) || ordinal(a.id, b.id));
  return { format: ALERTS_FORMAT, session: s.record.session, recordSha256: s.sha256, query, shards, control: { agent001Alerts: control }, alerts };
}

/** The real leak scan: the repo's leakcheck over the text, on a scratch copy, as art-harness does. */
export const realLeakScan: LeakScan = (files) => {
  const tmp = mkdtempSync(join(tmpdir(), "coverage-scan-"));
  try {
    for (const [name, text] of files) writeFileSync(join(tmp, name), text);
    const r = Bun.spawnSync(["bun", resolve(ROOT, "tools/leakcheck.ts"), "--paths", tmp], { stdout: "pipe", stderr: "pipe", timeout: 120_000 });
    if (r.exitCode !== 0) refuse("leak-scan", "evidence", `leakcheck did not pass the evidence text (exit ${r.exitCode}); nothing was written`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
};

/** Ask the index for every record's evidence, check it all, scan it, then write it. */
export function fetchAll(l: Layout, remote: Remote, scan: LeakScan = realLeakScan): string[] {
  const attack = parseAttackTsv(readInput(l, l.attackTsv), rel(l, l.attackTsv));
  const packIds = loadPack(l, parseCrosswalk(readInput(l, l.crosswalk), attack, rel(l, l.crosswalk))).map((r) => r.id);
  const sessions = loadRecords(l);
  if (!sessions.length) setup("fetch-no-records", rel(l, l.records), `${rel(l, l.records)} holds no session record to fetch for`);
  const bySession = new Map(sessions.map((s) => [s.record.session, s]));
  const files = new Map<string, string>();
  for (const s of sessions) {
    if (!s.span) continue;
    const { text, query } = msearchBody(s, packIds);
    const r = remote(text, FETCH_TIMEOUT_MS);
    if (r.timedOut || r.code !== 0) setup("fetch-ssh", s.record.session, `the index query for ${s.record.session} did not complete (${r.timedOut ? "timed out" : `ssh exit ${r.code}`})`);
    const ev = evidenceFromAnswer(s, query, r.out);
    const name = `${s.record.session}.alerts.json`;
    const body = jsonText(ev);
    // The same reader build uses has to accept what is about to be written.
    parseEvidence(`${rel(l, l.validation)}/${name}`, body, bySession);
    files.set(name, body);
  }
  scan(files);
  writeAll(l.validation, files);
  return [...files.keys()].map((n) => `${rel(l, l.validation)}/${n}`);
}

// -- Self-test --

export interface Plant {
  name: string;
  // Applied to a temp copy of the control root.
  mutate: (root: string) => void;
  argv?: string[];
  exit: ExitCode;
  code: string;
  item: string;
}

const readJsonFile = (path: string) => JSON.parse(readFileSync(path, "utf8"));
const writeJsonFile = (path: string, x: unknown) => writeFileSync(path, jsonText(x));

/** Edit a JSON file of a scratch root in place. */
export function editJson(root: string, relPath: string, fn: (x: any) => void): void {
  const path = join(root, relPath);
  const x = readJsonFile(path);
  fn(x);
  writeJsonFile(path, x);
}

const EV1 = "20261122T035219Z-95651d";
const EV2 = "20261122T035737Z-cb8eb2";
const evPath = (s: string) => `${VALIDATION_DIR}/${s}.alerts.json`;
const NOREC = "20261122T000000Z-000000";
const T_PASSWORD = "56506854-89d6-46a3-9804-b7fde90791f9";

/** Point every evidence file of a scratch root at the record's current bytes after a plant edits a record. */
export function rehash(root: string): void {
  for (const n of readdirSync(join(root, VALIDATION_DIR))) {
    if (!n.endsWith(".alerts.json")) continue;
    const e = readJsonFile(join(root, VALIDATION_DIR, n));
    e.recordSha256 = sha256(readFileSync(join(root, RECORD_DIR, `${e.session}.json`), "utf8"));
    writeJsonFile(join(root, VALIDATION_DIR, n), e);
  }
}

/** A scratch root with every input copied from the repo and the fixture evidence in place. */
export function makeScratch(withEvidence: boolean): string {
  const dir = mkdtempSync(join(tmpdir(), "coverage-root-"));
  for (const p of [RULES_DIR, "phase-b-detection/attack", RECORD_DIR]) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    cpSync(join(ROOT, p), join(dir, p), { recursive: true });
  }
  mkdirSync(join(dir, VALIDATION_DIR), { recursive: true });
  writeJsonFile(join(dir, MISSES), { format: MISSES_FORMAT, entries: [] });
  if (withEvidence) for (const s of [EV1, EV2]) cpSync(join(ROOT, FIXTURE_DIR, `${s}.alerts.json`), join(dir, evPath(s)));
  return dir;
}

const missEntry = (e: Record<string, unknown>) => (root: string) => editJson(root, MISSES, (m) => m.entries.push(e));

/** Every planted refusal: the mutation, the exit it must end in, and the check and item that must be named. */
export const PLANTS: Plant[] = [
  { name: "pack rule id with no crosswalk entry", mutate: (r) => editJson(r, CROSSWALK, (c) => (c.entries = c.entries.filter((e: any) => e.from !== "T1027"))), exit: EXIT.refused, code: "crosswalk-missing", item: "T1027" },
  { name: "crosswalk target that is revoked (T1562.001)", mutate: (r) => editJson(r, CROSSWALK, (c) => (c.entries.find((e: any) => e.from === "T1027").to = "T1562.001")), exit: EXIT.refused, code: "crosswalk-target-inactive", item: "T1562.001" },
  { name: "crosswalk target absent from the list", mutate: (r) => editJson(r, CROSSWALK, (c) => (c.entries.find((e: any) => e.from === "T1027").to = "T9999")), exit: EXIT.refused, code: "crosswalk-target-absent", item: "T9999" },
  { name: "unchanged on a revoked id", mutate: (r) => editJson(r, CROSSWALK, (c) => c.entries.push({ from: "T1562.001", to: "T1685", how: "unchanged" })), exit: EXIT.refused, code: "crosswalk-unchanged-not-active", item: "T1562.001" },
  { name: "unchanged that maps elsewhere", mutate: (r) => editJson(r, CROSSWALK, (c) => (c.entries.find((e: any) => e.from === "T1027").to = "T1033")), exit: EXIT.refused, code: "crosswalk-unchanged-differs", item: "T1027" },
  { name: "revoked-by to a technique that is not the successor", mutate: (r) => editJson(r, CROSSWALK, (c) => c.entries.push({ from: "T1562.001", to: "T1027", how: "revoked-by" })), exit: EXIT.refused, code: "crosswalk-wrong-successor", item: "T1562.001" },
  { name: "revoked-by on an id that is active", mutate: (r) => editJson(r, CROSSWALK, (c) => (c.entries.find((e: any) => e.from === "T1027").how = "revoked-by")), exit: EXIT.refused, code: "crosswalk-revoked-by-not-revoked", item: "T1027" },
  { name: "evidence alert in a run window for a pack-range rule not in the XML", mutate: (r) => editJson(r, evPath(EV1), (e) => { e.query.rules.push(100499); e.alerts.push({ ...e.alerts[0], id: "FIXTUREDOCID00000099", ruleId: 100499 }); }), exit: EXIT.refused, code: "validated-not-subset", item: "rule 100499" },
  { name: "evidence index outside the live pattern", mutate: (r) => editJson(r, evPath(EV1), (e) => (e.alerts[0].index = "wazuh-alerts-4.x-2026.11.22-copy")), exit: EXIT.refused, code: "evidence-index", item: `${evPath(EV1)} alert 1` },
  { name: "evidence alert with no document id", mutate: (r) => editJson(r, evPath(EV1), (e) => (e.alerts[0].id = "")), exit: EXIT.refused, code: "evidence-alert-id", item: `${evPath(EV1)} alert 1` },
  { name: "evidence alert from another agent", mutate: (r) => editJson(r, evPath(EV1), (e) => (e.alerts[0].agentId = "002")), exit: EXIT.refused, code: "evidence-agent", item: `${evPath(EV1)} alert 1` },
  { name: "evidence in the wrong format", mutate: (r) => editJson(r, evPath(EV1), (e) => (e.format = "talonsoclab-art-alerts/2")), exit: EXIT.refused, code: "evidence-format", item: evPath(EV1) },
  { name: "evidence for a session with no record", mutate: (r) => { cpSync(join(r, evPath(EV1)), join(r, evPath(NOREC))); editJson(r, evPath(NOREC), (e) => (e.session = NOREC)); }, exit: EXIT.refused, code: "evidence-no-record", item: NOREC },
  { name: "evidence taken against another copy of the record", mutate: (r) => editJson(r, evPath(EV1), (e) => (e.recordSha256 = "0".repeat(64))), exit: EXIT.refused, code: "evidence-record-sha", item: EV1 },
  { name: "evidence with a failed shard", mutate: (r) => editJson(r, evPath(EV1), (e) => (e.shards.alerts.failed = 1)), exit: EXIT.refused, code: "evidence-shards", item: `${evPath(EV1)} shards.alerts` },
  { name: "a real logtest transcript given as evidence", mutate: (r) => cpSync(join(ROOT, LOGTEST_FIXTURE), join(r, evPath(EV1))), exit: EXIT.refused, code: "logtest-transcript", item: evPath(EV1) },
  { name: "a real logtest transcript given as the miss list", mutate: (r) => cpSync(join(ROOT, LOGTEST_FIXTURE), join(r, MISSES)), exit: EXIT.refused, code: "logtest-transcript", item: MISSES },
  { name: "bad JSON in the evidence", mutate: (r) => writeFileSync(join(r, evPath(EV1)), "{not json"), exit: EXIT.refused, code: "bad-json", item: evPath(EV1) },
  { name: "bad JSON in a session record", mutate: (r) => writeFileSync(join(r, RECORD_DIR, `${EV1}.json`), "{not json"), exit: EXIT.refused, code: "bad-json", item: `${RECORD_DIR}/${EV1}.json` },
  { name: "session record missing a field", mutate: (r) => editJson(r, `${RECORD_DIR}/${EV1}.json`, (x) => delete x.tests), exit: EXIT.refused, code: "record-tests", item: `${RECORD_DIR}/${EV1}.json` },
  { name: "session record with a non-ISO time", mutate: (r) => editJson(r, `${RECORD_DIR}/${EV1}.json`, (x) => (x.tests[0].run.startUtc = "2026-11-22 03:52:39")), exit: EXIT.refused, code: "record-time", item: `${RECORD_DIR}/${EV1}.json test 1 run startUtc` },
  { name: "session record with a window that ends before it starts", mutate: (r) => editJson(r, `${RECORD_DIR}/${EV1}.json`, (x) => (x.tests[0].run.endUtc = "2026-11-22T03:52:39.0000000Z")), exit: EXIT.refused, code: "record-window", item: `${RECORD_DIR}/${EV1}.json test 1 run` },
  { name: "the same session recorded twice", mutate: (r) => cpSync(join(r, RECORD_DIR, `${EV1}.json`), join(r, RECORD_DIR, `${EV1}-copy.json`)), exit: EXIT.refused, code: "record-duplicate-session", item: EV1 },
  { name: "miss entry for a rule that is validated", mutate: missEntry({ rule: 100410, class: "rule-gap", evidence: "x", session: EV1, test: T_PASSWORD }), exit: EXIT.refused, code: "misses-rule-validated", item: "rule 100410" },
  { name: "miss entry for a rule outside the pack", mutate: missEntry({ rule: 100999, class: "not-run", evidence: "x", ruling: "x" }), exit: EXIT.refused, code: "misses-not-pack", item: "rule 100999" },
  { name: "miss entry with an unknown class", mutate: missEntry({ rule: 100405, class: "flaky", evidence: "x", ruling: "x" }), exit: EXIT.refused, code: "misses-class", item: "rule 100405" },
  { name: "miss entry with empty evidence text", mutate: missEntry({ rule: 100405, class: "not-run", evidence: "  ", ruling: "x" }), exit: EXIT.refused, code: "misses-evidence", item: "rule 100405" },
  { name: "not-run miss with no ruling", mutate: missEntry({ rule: 100405, class: "not-run", evidence: "x" }), exit: EXIT.refused, code: "misses-ruling", item: "rule 100405" },
  { name: "blocked-by-defender citing no Defender alert", mutate: (r) => { editJson(r, `${RECORD_DIR}/${EV1}.json`, (x) => x.tests[0].rules.push(100405)); rehash(r); missEntry({ rule: 100405, class: "blocked-by-defender", evidence: "x", session: EV1, test: T_PASSWORD, alertId: "FIXTUREDOCID00000001" })(r); }, exit: EXIT.refused, code: "misses-defender-evidence", item: "rule 100405" },
  { name: "miss entry citing a test that does not list the rule", mutate: missEntry({ rule: 100405, class: "rule-gap", evidence: "x", session: EV1, test: T_PASSWORD }), exit: EXIT.refused, code: "misses-test", item: "rule 100405" },
  { name: "miss entry citing no session", mutate: missEntry({ rule: 100405, class: "sensor-gap", evidence: "x" }), exit: EXIT.refused, code: "misses-session", item: "rule 100405" },
  { name: "two miss entries for one rule", mutate: (r) => { missEntry({ rule: 100405, class: "not-run", evidence: "x", ruling: "x" })(r); missEntry({ rule: 100405, class: "not-run", evidence: "y", ruling: "y" })(r); }, exit: EXIT.refused, code: "misses-duplicate-rule", item: "rule 100405" },
  { name: "check on a missing output", mutate: (r) => rmSync(join(r, COVERAGE_DIR, OUT_SUMMARY)), argv: ["check"], exit: EXIT.failed, code: "output-differs", item: `${COVERAGE_DIR}/${OUT_SUMMARY}` },
  { name: "check on an output that differs by one byte", mutate: (r) => writeFileSync(join(r, COVERAGE_DIR, OUT_EXISTS), `${readFileSync(join(r, COVERAGE_DIR, OUT_EXISTS), "utf8")} `), argv: ["check"], exit: EXIT.failed, code: "output-differs", item: `${COVERAGE_DIR}/${OUT_EXISTS}` },
  { name: "check --final while the coverage is not complete", mutate: () => {}, argv: ["check", "--final"], exit: EXIT.refused, code: "not-complete", item: "coverage" },
];

/** Run each plant through the real entry point on a copy; one line each, true only if every plant is refused and the control builds. */
export function selfTest(log: (line: string) => void): boolean {
  const quiet: Io = { log: () => {}, err: () => {} };
  const control = makeScratch(true);
  let ok = true;
  try {
    const built = run(["build", "--root", control], quiet);
    const summaryPath = join(control, COVERAGE_DIR, OUT_SUMMARY);
    const summary = built.exit === EXIT.ok ? readJsonFile(summaryPath) : null;
    const right = summary && JSON.stringify(summary.validatedRules) === JSON.stringify([100400, 100407, 100410, 100411]) && summary.packSize === 18;
    log(`${right ? "OK  " : "FAIL"} control builds: ${summary ? `${summary.ratio.validated} of ${summary.ratio.of} validated, complete ${summary.complete}` : `exit ${built.exit}`}`);
    if (!right) return false;
    const snapshot = (root: string) => [OUT_EXISTS, OUT_VALIDATED, OUT_SUMMARY].map((n) => (existsSync(join(root, COVERAGE_DIR, n)) ? sha256(readFileSync(join(root, COVERAGE_DIR, n))) : "absent")).join();
    const before = snapshot(control);
    const again = run(["check", "--root", control], quiet);
    log(`${again.exit === EXIT.ok ? "OK  " : "FAIL"} control check passes`);
    ok = again.exit === EXIT.ok;
    for (const p of PLANTS) {
      const root = mkdtempSync(join(tmpdir(), "coverage-plant-"));
      try {
        cpSync(control, root, { recursive: true });
        p.mutate(root);
        const mid = snapshot(root);
        const r = run([...(p.argv ?? ["build"]), "--root", root], quiet);
        const same = snapshot(root) === mid;
        const good = r.exit === p.exit && r.error?.code === p.code && r.error?.item === p.item && same;
        if (!good) ok = false;
        log(`${good ? "OK  " : "FAIL"} ${p.name}: ${r.error ? `${r.error.code} (${r.error.item})` : `exit ${r.exit}, nothing refused`}${same ? "" : "; AN OUTPUT CHANGED"}`);
        if (p.exit === EXIT.refused && !p.argv && mid !== before) ok = false;
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }
    return ok;
  } finally {
    rmSync(control, { recursive: true, force: true });
  }
}

// *--- Entry Point ---*

interface Cli {
  cmd: string;
  root: string;
  host?: string;
  sha?: string;
  out?: string;
  final: boolean;
  positional: string[];
}

function parseCli(argv: string[]): Cli {
  const c: Cli = { cmd: argv[0] ?? "", root: ROOT, final: false, positional: [] };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) refuse("usage", a, `${a} needs a value`);
      return v as string;
    };
    if (a === "--root") c.root = resolve(value());
    else if (a === "--host") c.host = value();
    else if (a === "--sha256") c.sha = value();
    else if (a === "--out") c.out = resolve(value());
    else if (a === "--final") c.final = true;
    else if (a.startsWith("--")) refuse("usage", a, `unknown argument: ${a}`);
    else c.positional.push(a);
  }
  return c;
}

function main(argv: string[], io: Io, deps: Deps): ExitCode {
  if (argv[0] === "--help" || argv[0] === "-h") {
    io.log(USAGE);
    return EXIT.ok;
  }
  if (argv[0] === "--self-test") return selfTest(io.log) ? EXIT.ok : EXIT.failed;
  const c = parseCli(argv);
  const l = layoutFor(c.root);
  if (c.positional.length && c.cmd !== "refresh-attack") refuse("usage", c.positional[0], `unexpected argument: ${c.positional[0]}`);
  if (c.cmd === "build") {
    const b = buildAll(l);
    writeAll(l.coverage, b.files);
    io.log(`coverage: wrote ${plural(b.files.size, "file")} under ${rel(l, l.coverage)}`);
    io.log(`coverage: ${b.validated.length} of ${b.packSize} pack rules validated; ${plural(b.unclassified.length, "rule")} unclassified; complete ${b.complete}`);
    return EXIT.ok;
  }
  if (c.cmd === "check") {
    const b = buildAll(l);
    const bad = diffOutputs(l, b.files);
    for (const line of bad) io.err(`coverage: ${line}`);
    if (bad.length) failed("output-differs", bad[0].split(" ")[0], `${plural(bad.length, "checked-in output")} differ from the rebuild; run build`);
    if (c.final && !b.complete) refuse("not-complete", "coverage", `the coverage is not complete: ${plural(b.unclassified.length, "rule")} neither validated nor classified (${b.unclassified.join(", ")})`);
    io.log(`coverage: the checked-in outputs match the rebuild; ${b.validated.length} of ${b.packSize} validated; complete ${b.complete}`);
    return EXIT.ok;
  }
  if (c.cmd === "fetch") {
    if (!c.host || !SAFE_HOST.test(c.host)) refuse("fetch-host", "--host", "--host must be an ssh alias");
    const written = fetchAll(l, deps.remote ?? sshRemote(c.host), deps.leakScan ?? realLeakScan);
    for (const w of written) io.log(`coverage: wrote ${w}`);
    return EXIT.ok;
  }
  if (c.cmd === "refresh-attack") {
    if (c.positional.length !== 1) refuse("usage", "refresh-attack", "refresh-attack needs one path to a STIX bundle");
    const bundlePath = resolve(c.positional[0]);
    if (!existsSync(bundlePath)) setup("input-missing", c.positional[0], `${c.positional[0]} is missing`);
    const text = buildAttackTsv(readFileSync(bundlePath), c.sha ?? ATTACK_SHA256);
    const dest = c.out ?? l.attackTsv;
    mkdirSync(dirname(dest), { recursive: true });
    const tmp = `${dest}.${process.pid}.tmp`;
    writeFileSync(tmp, text);
    renameSync(tmp, dest);
    io.log(`coverage: wrote ${relative(process.cwd(), dest) || dest}, ${plural(text.split("\n").filter((x) => x && !x.startsWith("#")).length, "technique")}`);
    return EXIT.ok;
  }
  return refuse("usage", c.cmd || "(none)", `${c.cmd ? "unknown command" : "no command"}\n${USAGE}`);
}

/** One run of the CLI: the exit code, and the refusal that ended it when there was one. */
export function run(argv: string[], io: Io = { log: (l) => console.log(l), err: (l) => console.error(l) }, deps: Deps = {}): { exit: ExitCode; error?: CoverageError } {
  try {
    return { exit: main(argv, io, deps) };
  } catch (e) {
    if (e instanceof CoverageError) {
      io.err(`coverage: ${e.code}: ${e.message}`);
      return { exit: e.exit, error: e };
    }
    io.err(`coverage: unexpected ${e instanceof Error ? e.name : "error"}`);
    return { exit: EXIT.setup };
  }
}

if (import.meta.main) process.exit(run(Bun.argv.slice(2)).exit);
