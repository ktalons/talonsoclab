#!/usr/bin/env bun
// *****************************************************************************
// *Title: art-harness*
// *Author: Kyle Versluis*
// *Description: Run allowlisted Atomic Red Team tests on the Dell over ssh.*
// *****************************************************************************

// *--- Imports ---*

import { createHash, randomBytes } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { sshArgv } from "./winevt-capture.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
export const ALLOWLIST_PATH = "atomics/allowlist.json";
export const MANIFEST_PATH = "atomics/manifest.json";
const RECORD_DIR = "phase-b-detection/art-runs";
// Gitignored: raw snapshots and remote output hold host and user names.
const RAW_DIR = "Plans/b4-harness/runs";
export const ATOMICS_COMMIT = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6";
export const MODULE_NAME = "Invoke-AtomicRedTeam";
export const MODULE_VERSION = "2.3.0";
export const YAML_MODULE = "powershell-yaml";
// From the PowerShell Gallery; .nupkg SHA-256 d4602bc7a4a093766520422d53ca8b09acde162286fae11e2ee6c8edfea07810.
export const YAML_VERSION = "0.4.12";
const ALLOWLIST_FORMAT = "talonsoclab-art-allowlist/1";
const MANIFEST_FORMAT = "talonsoclab-art-manifest/1";
const RECORD_FORMAT = "talonsoclab-art-session/1";
const ATOMICS_REPO = "redcanaryco/atomic-red-team";
export const STAGED_ROOT = "C:\\AtomicRedTeam";
const ATOMICS = "atomics";
// nupkg packaging that Install-Module would drop too; nothing in it is loaded.
const PACKAGING = new Set(["_rels", "package", "[Content_Types].xml"]);
const FINDER = ".DS_Store";

// SECURITY: every value spliced into PowerShell or the ssh argv is held to one of these first.
const SAFE_GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SAFE_TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;
const SAFE_HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_PATH = /^[A-Za-z0-9_][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_][A-Za-z0-9._-]*)*$/;
const SAFE_INPUT = /^[a-z_][a-z0-9_]{0,63}$/;
const SAFE_URL = /^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9._~%/-]*$/;
const SAFE_TEST_NAME = /^[\x20-\x7e]{1,200}$/;
const SAFE_SESSION = /^\d{8}T\d{6}Z-[0-9a-f]{6}$/;
const SAFE_DESC = /^talonsoclab-b4-\d{8}T\d{6}Z-[0-9a-f]{6}$/;
const SAFE_VERSION = /^\d{1,4}(?:\.\d{1,6}){1,3}$/;
const SHA_HEX = /^[0-9a-f]{64}$/;
const COMMIT_HEX = /^[0-9a-f]{40}$/;
const ISO_UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z$/;
// The pack ranges: EID-3 rules 100340-100399, the B.3 rules 100400-100499.
const RULE_MIN = 100340;
const RULE_MAX = 100499;
const EXECUTORS = new Set(["command_prompt", "powershell"]);
const ANSWER_TAG = "TSLART1 ";
const DEFAULT_TIMEOUT_S = 120;
const TIMEOUT_MIN_S = 10;
const TIMEOUT_MAX_S = 1800;
// Slack on top of the module's own timeout: module import, re-hashing the staged tree, the gate.
const STEP_SLACK_MS = 240_000;
const GATE_MS = 300_000;
const RESTORE_MS = 600_000;
const SNAPSHOT_MS = 600_000;
const GIT_MS = 30_000;
// The Windows command line limit; the bootstrap must fit under it with room to spare.
export const CMDLINE_MAX = 8191;
// The bootstrap exits 97 when the payload on stdin does not hash to what it was built for.
const PAYLOAD_MISMATCH = 97;
// The bootstrap exits 96 when no payload line arrived in time: nothing ran, so one retry is safe.
export const PAYLOAD_MISSING = 96;
// How long the bootstrap waits for the payload line before it exits by itself.
export const STDIN_WAIT_MS = 60_000;
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/g;
const SID_MACHINE = /S-1-5-21-\d+-\d+-\d+/gi;
const PRIVATE_V4 = /(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3}(?!\d)/g;
const PRIVATE_V6 = /(?<![0-9a-f:])(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2}):[0-9a-f:]*[0-9a-f]/gi;

export const EXIT = { ok: 0, failed: 1, setup: 2, refused: 3 } as const;
export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

export const CATEGORIES = ["services", "tasks", "runKeys", "wmi", "users", "admins", "defender", "watched"] as const;
export type Category = (typeof CATEGORIES)[number];

// What the Dell-side step gate can answer instead of running a step; the Mac maps each to text.
const REFUSALS: Record<string, string> = {
  "not-allowlisted": "the Dell refused the GUID: it is not in the allowed set the script carries",
  "not-elevated": "the ssh session on the Dell is not elevated",
  "staged-files-changed": "the staged files under C:\\AtomicRedTeam no longer match atomics/manifest.json",
  "defender-gate": "Defender no longer meets the gate (real-time protection on, one exclusion)",
  "restore-point-missing": "this session's restore point is no longer on the Dell",
  "module-import": "the staged modules did not import as the pinned versions from C:\\AtomicRedTeam",
};

// *--- Types ---*

export interface AllowEntry {
  rules: number[];
  technique: string;
  testNumber: number;
  testName: string;
  guid: string;
  executor: string;
  elevationRequired: boolean;
  inputArguments: string[];
  fetches: string[];
  runsFetchedCode: boolean;
}

export interface Allowlist {
  format: string;
  atomicsRepo: string;
  atomicsCommit: string;
  module: { name: string; version: string };
  tests: AllowEntry[];
}

export interface ManifestFile {
  path: string;
  size: number;
  sha256: string;
}

export interface ManifestModule {
  name: string;
  version: string;
  root: string;
}

/** Why each atomics file is staged: the files one test references, and what it names outside. */
export interface ManifestTest {
  guid: string;
  technique: string;
  testNumber: number;
  files: string[];
  outside: string[];
}

export interface Manifest {
  format: string;
  stagedRoot: string;
  atomicsCommit: string;
  allowlistSha256: string;
  modules: ManifestModule[];
  atomicsRoot: string;
  owed: string[];
  tests: ManifestTest[];
  files: ManifestFile[];
}

/** One remote call: its exit code, stdout, stderr and whether the timeout killed it. */
export interface RemoteResult {
  code: number | null;
  out: string;
  err: string;
  timedOut: boolean;
}

/** Runs one PowerShell payload on the Dell. The tests and the self-test pass a fake. */
export type Remote = (payload: string, timeoutMs: number) => RemoteResult;

/** What the Dell reports of its staged tree. */
export interface Listing {
  missingRoot: boolean;
  files: ManifestFile[];
  odd: number;
}

export interface DefenderState {
  rtp: boolean;
  path: string[];
  process: string[];
  extension: string[];
  ip: string[];
}

export interface Identity {
  literal: string;
  label: string;
}

export interface GateAnswer {
  utc: string;
  elevated: boolean;
  ids: Identity[];
  defender: DefenderState;
  listing: Listing;
  frequency: number | null;
}

export interface Segment {
  m: string;
  c: string;
  n: boolean;
}

export interface StepAnswer {
  refused: string | null;
  start: string | null;
  end: string | null;
  threw: boolean;
  segments: Segment[];
}

export type Snapshot = Record<Category, Map<string, string>>;

export interface DiffItem {
  category: Category;
  change: "added" | "removed" | "changed";
  item: string;
}

export interface StepRecord {
  startUtc: string | null;
  endUtc: string | null;
  status: string;
  exitCode: number | null;
}

export interface TestRecord {
  guid: string;
  technique: string;
  testNumber: number;
  testName: string;
  rules: number[];
  run: StepRecord;
  cleanup: StepRecord;
}

export interface SessionRecord {
  format: string;
  session: string;
  verdict: "pass" | "fail";
  failures: string[];
  // GUIDs whose run step the module killed at the timeout; data, not a failure.
  timedOut: string[];
  allowlistSha256: string;
  manifestSha256: string;
  atomicsCommit: string;
  module: { name: string; version: string };
  timeoutSeconds: number;
  gateUtc: string;
  defenderGate: { realTimeProtection: boolean; exclusionPath: string[]; pass: boolean };
  restorePoint: { description: string; createdUtc: string };
  tests: TestRecord[];
  stateDiff: { verdict: "no-difference" | "different" | "not-taken"; items: DiffItem[] };
  stagedAfter: { verdict: "unchanged" | "changed" | "not-checked"; changed: number; missing: number; extra: number };
}

export interface SessionOptions {
  mode: "run" | "check-prereqs";
  guids: string[] | "all";
  timeoutSeconds: number;
  allowRemoteCode: boolean;
  remote: Remote;
  allowlistText: string;
  manifestText: string;
  sessionId?: string;
  // Raw remote output and snapshots, never the committed record. Gitignored in real runs.
  raw: (name: string, data: string) => void;
  // Writes the record after the in-process leak guard passed; returns where it went.
  writeRecord: (id: string, json: string) => string;
  log: (line: string) => void;
}

export interface SessionOutcome {
  exit: ExitCode;
  messages: string[];
  record?: SessionRecord;
  recordPath?: string;
  testsSent: number;
}

export interface GitState {
  head: string;
  dirty: boolean;
}

/** A refusal, setup failure or failed session; the message never holds remote text. */
export class HarnessError extends Error {
  constructor(
    readonly exit: ExitCode,
    message: string,
  ) {
    super(message);
  }
}

// *--- Helper Functions ---*

const sha256 = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const byOrdinal = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const refuse = (msg: string): never => {
  throw new HarnessError(EXIT.refused, msg);
};
const setup = (msg: string): never => {
  throw new HarnessError(EXIT.setup, msg);
};
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

// An extra key could carry what the shape check never reads, so every object is closed.
function exactKeys(o: Record<string, unknown>, keys: string[], what: string, fail: (m: string) => never): void {
  const have = Object.keys(o).sort();
  const want = [...keys].sort();
  if (have.join() !== want.join()) fail(`${what} must have exactly the keys ${want.join(", ")}`);
}

/** Fill @@NAME@@ placeholders, each value already held to its pattern; refuse any left over. */
export function fill(template: string, values: Record<string, string>): string {
  let out = template;
  for (const [k, v] of Object.entries(values)) out = out.split(`@@${k}@@`).join(v);
  if (/@@[A-Z]+@@/.test(out)) throw new HarnessError(EXIT.refused, "a PowerShell placeholder was left unfilled");
  return out;
}

/** The SHA-256 of the canonical listing, as the Dell computes it in Get-TreeDigest. */
export function treeDigest(files: ManifestFile[]): string {
  const lines = files.map((f) => `${f.path}\t${f.size}\t${f.sha256}\n`).sort(byOrdinal);
  return sha256(lines.join(""));
}

function walk(dir: string, rel = ""): string[] {
  const out: string[] = [];
  for (const name of readdirSync(join(dir, rel)).sort(byOrdinal)) {
    if (name === FINDER) continue;
    const r = rel ? `${rel}/${name}` : name;
    const st = lstatSync(join(dir, r));
    if (st.isSymbolicLink()) refuse(`${r} is a symlink; nothing linked is staged`);
    if (st.isDirectory()) out.push(...walk(dir, r));
    else if (st.isFile()) out.push(r);
    else refuse(`${r} is neither a file nor a folder`);
  }
  return out;
}

function fileEntry(abs: string, path: string): ManifestFile {
  if (!SAFE_PATH.test(path)) refuse(`${path}: a file name outside letters, digits, dot, dash and underscore, or starting with a dot or dash`);
  const bytes = readFileSync(abs);
  return { path, size: bytes.length, sha256: sha256(bytes) };
}

const MODULE_VERSION_LINE = /^\s*ModuleVersion\s*=\s*['"]([^'"]+)['"]/m;

// A settings file such as PSScriptAnalyzerSettings.psd1 is a .psd1 too; only a module
// manifest carries ModuleVersion.
/** The module's name and version from the one module manifest at the folder root. */
function psd1Of(dir: string): { name: string; version: string } {
  const found = readdirSync(dir)
    .filter((n) => n.toLowerCase().endsWith(".psd1") && lstatSync(join(dir, n)).isFile())
    .flatMap((n) => {
      const m = MODULE_VERSION_LINE.exec(readFileSync(join(dir, n), "utf8"));
      return m ? [{ name: n.slice(0, -5), version: m[1] }] : [];
    });
  if (found.length !== 1) return refuse(`${dir} must hold exactly one module manifest (.psd1 with ModuleVersion) at its root`);
  if (!SAFE_PATH.test(found[0].name) || !SAFE_VERSION.test(found[0].version)) refuse(`${found[0].name}.psd1 has a name or ModuleVersion this tool does not accept`);
  return found[0];
}

const realGit = (dir: string, techniques: string[]): GitState => {
  const run = (args: string[]) => {
    const r = Bun.spawnSync(["git", "-C", dir, ...args], { stdout: "pipe", stderr: "pipe", timeout: GIT_MS });
    if (r.exitCode !== 0) setup(`git ${args[0]} failed in the atomics checkout (exit ${r.exitCode})`);
    return r.stdout.toString();
  };
  const head = run(["rev-parse", "HEAD"]).trim();
  const dirty = run(["status", "--porcelain", "--", ...techniques.map((t) => `${ATOMICS}/${t}`)]).trim() !== "";
  return { head, dirty };
};

// *--- Allowlist ---*

/** Parse and check the allowlist; any fault refuses it whole. */
export function parseAllowlist(text: string): Allowlist {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return refuse("atomics/allowlist.json is not JSON");
  }
  if (!isObject(raw)) return refuse("the allowlist must be an object");
  exactKeys(raw, ["format", "atomicsRepo", "atomicsCommit", "module", "tests"], "the allowlist", refuse);
  if (raw.format !== ALLOWLIST_FORMAT) refuse(`the allowlist format must be ${ALLOWLIST_FORMAT}`);
  if (raw.atomicsRepo !== ATOMICS_REPO) refuse(`atomicsRepo must be ${ATOMICS_REPO}`);
  if (typeof raw.atomicsCommit !== "string" || !COMMIT_HEX.test(raw.atomicsCommit)) refuse("atomicsCommit must be a 40-hex commit");
  if (raw.atomicsCommit !== ATOMICS_COMMIT) refuse(`atomicsCommit must be the pinned ${ATOMICS_COMMIT}`);
  const mod = raw.module;
  if (!isObject(mod)) return refuse("module must be an object");
  exactKeys(mod, ["name", "version"], "module", refuse);
  if (mod.name !== MODULE_NAME || mod.version !== MODULE_VERSION) refuse(`module must be ${MODULE_NAME} ${MODULE_VERSION}`);
  if (!Array.isArray(raw.tests) || raw.tests.length === 0) refuse("tests must be a non-empty list");
  const seenGuid = new Set<string>();
  const seenTest = new Set<string>();
  const tests = (raw.tests as unknown[]).map((t, i): AllowEntry => {
    const at = `tests[${i}]`;
    if (!isObject(t)) return refuse(`${at} must be an object`);
    exactKeys(
      t,
      ["rules", "technique", "testNumber", "testName", "guid", "executor", "elevationRequired", "inputArguments", "fetches", "runsFetchedCode"],
      at,
      refuse,
    );
    const { rules, technique, testNumber, testName, guid, executor, elevationRequired, inputArguments, fetches, runsFetchedCode } = t;
    if (!Array.isArray(rules) || rules.length === 0) refuse(`${at}.rules must be a non-empty list`);
    for (const r of rules as unknown[]) {
      if (!Number.isInteger(r) || (r as number) < RULE_MIN || (r as number) > RULE_MAX) refuse(`${at}.rules holds an ID outside the pack ranges ${RULE_MIN}-${RULE_MAX}`);
    }
    if (new Set(rules as number[]).size !== (rules as number[]).length) refuse(`${at}.rules repeats an ID`);
    if (typeof technique !== "string" || !SAFE_TECHNIQUE.test(technique)) refuse(`${at}.technique must look like T1234 or T1234.001`);
    if (!Number.isInteger(testNumber) || (testNumber as number) < 1 || (testNumber as number) > 999) refuse(`${at}.testNumber must be 1 to 999`);
    if (typeof testName !== "string" || !SAFE_TEST_NAME.test(testName)) refuse(`${at}.testName must be printable ASCII, 1 to 200 characters`);
    if (typeof guid !== "string" || !SAFE_GUID.test(guid)) refuse(`${at}.guid must be a lower-case GUID`);
    if (typeof executor !== "string" || !EXECUTORS.has(executor)) refuse(`${at}.executor must be command_prompt or powershell`);
    if (typeof elevationRequired !== "boolean") refuse(`${at}.elevationRequired must be true or false`);
    if (!Array.isArray(inputArguments) || !inputArguments.every((a) => typeof a === "string" && SAFE_INPUT.test(a))) {
      refuse(`${at}.inputArguments must be a list of input names`);
    }
    if (!Array.isArray(fetches) || !fetches.every((u) => typeof u === "string" && SAFE_URL.test(u))) refuse(`${at}.fetches must be a list of https URLs`);
    if (typeof runsFetchedCode !== "boolean") refuse(`${at}.runsFetchedCode must be true or false`);
    if (runsFetchedCode && (fetches as string[]).length === 0) refuse(`${at} runs fetched code but names nothing it fetches`);
    if (seenGuid.has(guid as string)) refuse(`${at}.guid is already in the allowlist`);
    seenGuid.add(guid as string);
    const key = `${technique} #${testNumber}`;
    if (seenTest.has(key)) refuse(`${at} names ${key} a second time`);
    seenTest.add(key);
    return {
      rules: rules as number[],
      technique: technique as string,
      testNumber: testNumber as number,
      testName: testName as string,
      guid: guid as string,
      executor: executor as string,
      elevationRequired: elevationRequired as boolean,
      inputArguments: inputArguments as string[],
      fetches: fetches as string[],
      runsFetchedCode: runsFetchedCode as boolean,
    };
  });
  return {
    format: ALLOWLIST_FORMAT,
    atomicsRepo: ATOMICS_REPO,
    atomicsCommit: raw.atomicsCommit as string,
    module: { name: MODULE_NAME, version: MODULE_VERSION },
    tests,
  };
}

const techniquesOf = (al: Allowlist) => [...new Set(al.tests.map((t) => t.technique))].sort(byOrdinal);

/** Every way an entry disagrees with the pinned checkout; empty when all match. */
export function checkAllowlist(al: Allowlist, checkout: string, git: (dir: string, techniques: string[]) => GitState = realGit): string[] {
  if (!existsSync(join(checkout, ATOMICS))) setup(`no ${ATOMICS} folder in the checkout given`);
  const out: string[] = [];
  const state = git(checkout, techniquesOf(al));
  if (state.head !== al.atomicsCommit) out.push(`the checkout is not at the recorded commit ${al.atomicsCommit}`);
  if (state.dirty) out.push("the checkout has uncommitted changes under a technique folder the allowlist names");
  const parser = (Bun as unknown as { YAML?: { parse(s: string): unknown } }).YAML;
  if (!parser) return setup("this Bun has no YAML parser (Bun.YAML)");
  const yaml = new Map<string, unknown>();
  for (const e of al.tests) {
    const at = `${e.technique} #${e.testNumber} (${e.guid})`;
    const file = join(checkout, ATOMICS, e.technique, `${e.technique}.yaml`);
    if (!yaml.has(e.technique)) {
      if (!existsSync(file)) {
        out.push(`${at}: no ${ATOMICS}/${e.technique}/${e.technique}.yaml in the checkout`);
        continue;
      }
      try {
        yaml.set(e.technique, parser.parse(readFileSync(file, "utf8")));
      } catch {
        out.push(`${at}: the technique YAML does not parse`);
        continue;
      }
    }
    const doc = yaml.get(e.technique);
    const tests = isObject(doc) && Array.isArray(doc.atomic_tests) ? (doc.atomic_tests as unknown[]) : [];
    const holders = tests.filter((t) => isObject(t) && t.auto_generated_guid === e.guid).length;
    if (holders !== 1) out.push(`${at}: the GUID appears ${holders} times in the technique, not once`);
    const t = tests[e.testNumber - 1];
    if (!isObject(t)) {
      out.push(`${at}: the technique has no test ${e.testNumber}`);
      continue;
    }
    if (t.auto_generated_guid !== e.guid) out.push(`${at}: test ${e.testNumber} carries another GUID`);
    if (t.name !== e.testName) out.push(`${at}: the test name differs`);
    const ex = isObject(t.executor) ? t.executor : {};
    if (ex.name !== e.executor) out.push(`${at}: the executor differs`);
    if ((ex.elevation_required === true) !== e.elevationRequired) out.push(`${at}: elevationRequired differs`);
    if (!Array.isArray(t.supported_platforms) || !t.supported_platforms.includes("windows")) out.push(`${at}: Windows is not a supported platform`);
    const inputs = isObject(t.input_arguments) ? t.input_arguments : {};
    if (Object.keys(inputs).sort(byOrdinal).join() !== [...e.inputArguments].sort(byOrdinal).join()) out.push(`${at}: inputArguments differ from the test's input_arguments`);
    for (const [name, spec] of Object.entries(inputs)) {
      if (isObject(spec) && spec.type === "url" && !e.fetches.includes(String(spec.default))) out.push(`${at}: the default of url input ${name} is not in fetches`);
    }
  }
  return out;
}

// *--- Manifest ---*

// Merge-InputArgs swaps "$PathToAtomicsFolder" and the bare word, in any case, for the folder.
const ATOMICS_TOKEN = /\$?PathToAtomicsFolder/gi;
// A reference runs to the first character that ends a word on a command line.
const REF_TAIL = /^[^\s"'<>|;,()&]*/;
// Anything that makes a path computed or a pattern rather than one named file.
const REF_UNSURE = /[*?$%#{}[\]`~]/;
const OUTSIDE_REF = /^(?:\.\.\/)+(?:[A-Za-z0-9_][A-Za-z0-9._-]*\/?)*$/;

/** The text Merge-InputArgs builds a test's commands from, with default inputs filled in. */
function testTexts(t: Record<string, unknown>, at: string): string[] {
  const ex = isObject(t.executor) ? t.executor : {};
  const deps = Array.isArray(t.dependencies) ? t.dependencies : [];
  const raw = [ex.command, ex.cleanup_command, ...deps.flatMap((d) => (isObject(d) ? [d.prereq_command, d.get_prereq_command] : []))];
  const inputs = isObject(t.input_arguments) ? t.input_arguments : {};
  const defaults: [string, string][] = Object.entries(inputs).map(([name, spec]) => {
    const v = isObject(spec) ? spec.default : undefined;
    if (typeof v !== "string" && typeof v !== "number") return refuse(`${at}: input ${name} has no plain default, so its references cannot be resolved`);
    if (String(v).includes("#{")) refuse(`${at}: input ${name}'s default holds another input, which the module fills in no fixed order`);
    return [name, String(v)];
  });
  const filled = raw.map((x) => {
    let s = typeof x === "string" ? x : "";
    for (const [name, v] of defaults) s = s.split(`#{${name}}`).join(v);
    if (s.includes("#{")) refuse(`${at}: a command names an input the test does not define`);
    return s;
  });
  return [...filled, ...defaults.map(([, v]) => v)];
}

/**
 * Every atomics file one test references, and every reference that leaves the atomics folder.
 * A reference that is computed, a pattern, a folder or not a file in the checkout refuses.
 */
export function testReferences(t: Record<string, unknown>, checkout: string, at: string): { files: string[]; outside: string[] } {
  const files = new Set<string>();
  const outside = new Set<string>();
  for (const text of testTexts(t, at)) {
    for (const m of text.matchAll(ATOMICS_TOKEN)) {
      const tail = REF_TAIL.exec(text.slice(m.index + m[0].length))![0];
      if (!/^[\\/]/.test(tail)) refuse(`${at}: a reference to the whole atomics folder, or one glued to other text, cannot be resolved to files`);
      if (REF_UNSURE.test(tail)) refuse(`${at}: a reference holds a variable or a wildcard, so the file it names is not certain`);
      const segs = tail.split(/[\\/]/).slice(1);
      const folder = segs[segs.length - 1] === "";
      const parts: string[] = [ATOMICS];
      let escaped = false;
      for (const s of segs.filter((x) => x !== "" && x !== ".")) {
        if (s === "..") {
          if (parts.length === 0) escaped = true;
          else parts.pop();
        } else if (!escaped) parts.push(s);
      }
      if (escaped || parts[0] !== ATOMICS || parts.length < 2) {
        const rel = tail.replace(/\\/g, "/").slice(1);
        if (!OUTSIDE_REF.test(rel)) refuse(`${at}: a reference outside the atomics folder has an unexpected shape`);
        outside.add(rel);
        continue;
      }
      const path = parts.join("/");
      if (folder) refuse(`${at}: ${path}/ names a folder, so the files it needs are not certain`);
      if (!SAFE_PATH.test(path)) refuse(`${at}: ${path} has a name outside the allowed pattern`);
      const abs = join(checkout, ...parts);
      if (!existsSync(abs)) refuse(`${at}: ${path} is referenced but missing from the checkout`);
      const st = lstatSync(abs);
      if (st.isSymbolicLink() || !st.isFile()) refuse(`${at}: ${path} is referenced but is not a plain file`);
      files.add(path);
    }
  }
  return { files: [...files].sort(byOrdinal), outside: [...outside].sort(byOrdinal) };
}

/** Each allowlisted test's own atomics files, derived from the pinned YAML. */
export function deriveTests(al: Allowlist, checkout: string): ManifestTest[] {
  const parser = (Bun as unknown as { YAML?: { parse(s: string): unknown } }).YAML;
  if (!parser) return setup("this Bun has no YAML parser (Bun.YAML)");
  const docs = new Map<string, unknown>();
  return al.tests.map((e) => {
    const at = `${e.technique} #${e.testNumber} (${e.guid})`;
    if (!docs.has(e.technique)) {
      const file = join(checkout, ATOMICS, e.technique, `${e.technique}.yaml`);
      if (!existsSync(file)) refuse(`the checkout has no ${ATOMICS}/${e.technique}/${e.technique}.yaml`);
      try {
        docs.set(e.technique, parser.parse(readFileSync(file, "utf8")));
      } catch {
        refuse(`${at}: the technique YAML does not parse`);
      }
    }
    const doc = docs.get(e.technique);
    const t = isObject(doc) && Array.isArray(doc.atomic_tests) ? doc.atomic_tests[e.testNumber - 1] : undefined;
    if (!isObject(t) || t.auto_generated_guid !== e.guid) return refuse(`${at}: test ${e.testNumber} in the checkout does not carry this GUID; run check-allowlist`);
    return { guid: e.guid, technique: e.technique, testNumber: e.testNumber, ...testReferences(t, checkout, at) };
  });
}

/** Hash the modules, each technique's YAML and only the files the tests reference. */
export function buildManifest(al: Allowlist, allowlistText: string, moduleDirs: string[], checkout: string, git = realGit): Manifest {
  if (moduleDirs.length < 1 || moduleDirs.length > 2) refuse("give the Invoke-AtomicRedTeam folder, then optionally the powershell-yaml folder");
  const state = git(checkout, techniquesOf(al));
  if (state.head !== al.atomicsCommit) refuse(`the atomics checkout is not at the recorded commit ${al.atomicsCommit}`);
  if (state.dirty) refuse("the atomics checkout has uncommitted changes under a technique folder the allowlist names");
  const modules: ManifestModule[] = [];
  const files: ManifestFile[] = [];
  moduleDirs.forEach((dir, i) => {
    const { name, version } = psd1Of(dir);
    if (i === 0 && (name !== MODULE_NAME || version !== MODULE_VERSION)) refuse(`the first module must be ${MODULE_NAME} ${MODULE_VERSION}`);
    if (i === 1 && (name !== YAML_MODULE || version !== YAML_VERSION)) refuse(`the second module must be ${YAML_MODULE} ${YAML_VERSION}`);
    modules.push({ name, version, root: name });
    for (const rel of walk(dir)) {
      const top = rel.split("/")[0];
      if (PACKAGING.has(top) || (!rel.includes("/") && rel.toLowerCase().endsWith(".nuspec"))) continue;
      files.push(fileEntry(join(dir, rel), `${name}/${rel}`));
    }
  });
  const tests = deriveTests(al, checkout);
  const atomics = new Set([...techniquesOf(al).map((t) => `${ATOMICS}/${t}/${t}.yaml`), ...tests.flatMap((t) => t.files)]);
  for (const p of atomics) files.push(fileEntry(join(checkout, ...p.split("/")), p));
  files.sort((a, b) => byOrdinal(a.path, b.path));
  return {
    format: MANIFEST_FORMAT,
    stagedRoot: STAGED_ROOT,
    atomicsCommit: al.atomicsCommit,
    allowlistSha256: sha256(allowlistText),
    modules,
    atomicsRoot: ATOMICS,
    owed: modules.some((m) => m.name === YAML_MODULE) ? [] : [YAML_MODULE],
    tests,
    files,
  };
}

export const manifestText = (m: Manifest) => `${JSON.stringify(m, null, 2)}\n`;

/** Parse the manifest and hold it to the allowlist it was built from. */
export function parseManifest(text: string, al: Allowlist, allowlistText: string): Manifest {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return refuse("atomics/manifest.json is not JSON");
  }
  if (!isObject(raw)) return refuse("the manifest must be an object");
  exactKeys(raw, ["format", "stagedRoot", "atomicsCommit", "allowlistSha256", "modules", "atomicsRoot", "owed", "tests", "files"], "the manifest", refuse);
  if (raw.format !== MANIFEST_FORMAT) refuse(`the manifest format must be ${MANIFEST_FORMAT}`);
  if (raw.stagedRoot !== STAGED_ROOT) refuse(`the manifest's stagedRoot must be ${STAGED_ROOT}`);
  if (raw.atomicsCommit !== al.atomicsCommit) refuse("the manifest names another atomics commit than the allowlist");
  if (raw.allowlistSha256 !== sha256(allowlistText)) refuse("the manifest was built from another allowlist; rebuild it with build-manifest");
  if (raw.atomicsRoot !== ATOMICS) refuse(`the manifest's atomicsRoot must be ${ATOMICS}`);
  if (!Array.isArray(raw.modules) || raw.modules.length < 1 || raw.modules.length > 2) refuse("the manifest must list one or two modules");
  const modules = (raw.modules as unknown[]).map((m, i): ManifestModule => {
    if (!isObject(m)) return refuse(`modules[${i}] must be an object`);
    exactKeys(m, ["name", "version", "root"], `modules[${i}]`, refuse);
    if (typeof m.version !== "string" || !SAFE_VERSION.test(m.version)) refuse(`modules[${i}].version is not a version`);
    const want = i === 0 ? MODULE_NAME : YAML_MODULE;
    if (m.name !== want || m.root !== want) refuse(`modules[${i}] must be ${want}, staged at ${want}`);
    if (m.version !== (i === 0 ? MODULE_VERSION : YAML_VERSION)) refuse(`modules[${i}] must be version ${i === 0 ? MODULE_VERSION : YAML_VERSION}`);
    return { name: want, version: m.version as string, root: want };
  });
  const hasYaml = modules.some((m) => m.name === YAML_MODULE);
  if (!Array.isArray(raw.owed) || (raw.owed as unknown[]).join() !== (hasYaml ? "" : YAML_MODULE)) refuse(`owed must be [] with ${YAML_MODULE} staged, ["${YAML_MODULE}"] without`);
  if (!Array.isArray(raw.tests) || raw.tests.length !== al.tests.length) refuse("the manifest must list one entry per allowlisted test");
  const tests = (raw.tests as unknown[]).map((t, i): ManifestTest => {
    const at = `tests[${i}]`;
    const e = al.tests[i];
    if (!isObject(t)) return refuse(`${at} must be an object`);
    exactKeys(t, ["guid", "technique", "testNumber", "files", "outside"], at, refuse);
    if (t.guid !== e.guid || t.technique !== e.technique || t.testNumber !== e.testNumber) refuse(`${at} is not the allowlist's test ${i + 1}`);
    const list = (v: unknown, ok: (s: string) => boolean, what: string) => {
      if (!Array.isArray(v) || !v.every((s) => typeof s === "string" && ok(s))) refuse(`${at}.${what} must be a list of paths of the right shape`);
      return v as string[];
    };
    return {
      guid: e.guid,
      technique: e.technique,
      testNumber: e.testNumber,
      files: list(t.files, (s) => SAFE_PATH.test(s) && s.startsWith(`${ATOMICS}/`), "files"),
      outside: list(t.outside, (s) => OUTSIDE_REF.test(s), "outside"),
    };
  });
  // SECURITY: an atomics file is staged only as a technique's YAML or as a file a test references.
  const justified = new Set([...techniquesOf(al).map((t) => `${ATOMICS}/${t}/${t}.yaml`), ...tests.flatMap((t) => t.files)]);
  if (!Array.isArray(raw.files) || raw.files.length === 0) refuse("the manifest lists no files");
  const roots = new Set(modules.map((m) => m.root));
  let last = "";
  const files = (raw.files as unknown[]).map((f, i): ManifestFile => {
    const at = `files[${i}]`;
    if (!isObject(f)) return refuse(`${at} must be an object`);
    exactKeys(f, ["path", "size", "sha256"], at, refuse);
    const { path, size, sha256: h } = f;
    if (typeof path !== "string" || !SAFE_PATH.test(path)) refuse(`${at}.path is outside the allowed pattern`);
    if (!Number.isSafeInteger(size) || (size as number) < 0) refuse(`${at}.size must be a whole number`);
    if (typeof h !== "string" || !SHA_HEX.test(h)) refuse(`${at}.sha256 must be 64 lower-case hex`);
    if ((path as string) <= last) refuse(`${at}.path is out of order or repeated`);
    last = path as string;
    const parts = (path as string).split("/");
    if (parts[0] === ATOMICS) {
      if (!justified.has(path as string)) refuse(`${at} is in the atomics folder but no allowlisted test references it`);
    } else if (!roots.has(parts[0]) || parts.length < 2) refuse(`${at} is outside every staged root`);
    return { path: path as string, size: size as number, sha256: h as string };
  });
  const paths = new Set(files.map((f) => f.path));
  for (const p of justified) if (!paths.has(p)) refuse(`the manifest lacks ${p}`);
  for (const m of modules) if (!paths.has(`${m.root}/${m.root}.psd1`)) refuse(`the manifest lacks ${m.root}/${m.root}.psd1`);
  return { format: MANIFEST_FORMAT, stagedRoot: STAGED_ROOT, atomicsCommit: al.atomicsCommit, allowlistSha256: raw.allowlistSha256 as string, modules, atomicsRoot: ATOMICS, owed: raw.owed as string[], tests, files };
}

/** How the Dell's staged tree differs from the manifest. Extra and odd entries are counted, never named. */
export function compareListing(m: Manifest, l: Listing): { changed: string[]; missing: string[]; extra: number; odd: number; missingRoot: boolean } {
  if (l.missingRoot) return { changed: [], missing: m.files.map((f) => f.path), extra: 0, odd: 0, missingRoot: true };
  const have = new Map(l.files.map((f) => [f.path, f]));
  const want = new Set(m.files.map((f) => f.path));
  const changed: string[] = [];
  const missing: string[] = [];
  for (const f of m.files) {
    const g = have.get(f.path);
    if (!g) missing.push(f.path);
    else if (g.size !== f.size || g.sha256 !== f.sha256) changed.push(f.path);
  }
  const extra = l.files.filter((f) => !want.has(f.path)).length;
  return { changed, missing, extra, odd: l.odd, missingRoot: false };
}

/** Copy exactly the manifest's files into a new folder for transport, checking each hash. */
export function stageFiles(m: Manifest, moduleDirs: string[], checkout: string, out: string): number {
  if (existsSync(out)) refuse("the stage folder must not exist yet");
  const source = new Map<string, string>();
  moduleDirs.forEach((dir) => source.set(psd1Of(dir).name, dir));
  for (const mod of m.modules) if (!source.has(mod.root)) refuse(`no folder given for module ${mod.root}`);
  for (const f of m.files) {
    const [top, ...rest] = f.path.split("/");
    const from = top === ATOMICS ? join(checkout, ATOMICS, ...rest) : join(source.get(top)!, ...rest);
    const bytes = readFileSync(from);
    if (bytes.length !== f.size || sha256(bytes) !== f.sha256) refuse(`${f.path} differs from the manifest; nothing more was staged`);
    const to = join(out, ...f.path.split("/"));
    mkdirSync(dirname(to), { recursive: true });
    copyFileSync(from, to);
  }
  return m.files.length;
}

// *--- Dell Scripts ---*

// NOTE: first run on the Dell 2026-11-22, with read-only tests: the gate, the restore point,
// the snapshot and the run, cleanup and prerequisite steps each passed there. No refusal branch
// and no timeout has run there. Every script here is Windows PowerShell 5.1, written from the
// module's source and Microsoft's documentation. No template holds a backtick or "${".
// WARN: the bootstrap sets $ErrorActionPreference to Stop in the global scope, so module code
// runs under it too: a non-terminating module error throws. That fails safe (the step reads as
// "threw"), but live it may surface as a false failure. Progress is silenced globally as well.
const PS_LIB = String.raw`$ErrorActionPreference = 'Stop'
$global:ProgressPreference = 'SilentlyContinue'
$Root = 'C:\AtomicRedTeam'
function Send-Answer($o) {
  $j = ConvertTo-Json -InputObject $o -Depth 8 -Compress
  'TSLART1 ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))
}
function Get-Hex([byte[]]$b) { ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant() }
function Get-Sha([string]$p) {
  $a = [Security.Cryptography.SHA256]::Create()
  $f = [IO.File]::OpenRead($p)
  try { Get-Hex ($a.ComputeHash($f)) } finally { $f.Dispose(); $a.Dispose() }
}
function Get-Listing {
  $files = New-Object 'System.Collections.Generic.List[object]'
  $odd = 0
  if (-not [IO.Directory]::Exists($Root)) { return @{ missingRoot = $true; files = @(); odd = 0 } }
  $top = New-Object IO.DirectoryInfo $Root
  if ($top.Attributes -band [IO.FileAttributes]::ReparsePoint) { return @{ missingRoot = $false; files = @(); odd = 1 } }
  $stack = New-Object 'System.Collections.Generic.Stack[IO.DirectoryInfo]'
  $stack.Push($top)
  $n = $Root.Length + 1
  while ($stack.Count -gt 0) {
    foreach ($e in $stack.Pop().GetFileSystemInfos()) {
      if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { $odd++; continue }
      if ($e -is [IO.DirectoryInfo]) { $stack.Push($e); continue }
      $files.Add([ordered]@{ path = $e.FullName.Substring($n).Replace('\', '/'); size = $e.Length; sha256 = (Get-Sha $e.FullName) })
    }
  }
  @{ missingRoot = $false; files = $files.ToArray(); odd = $odd }
}
function Get-TreeDigest($l) {
  if ($l.missingRoot -or $l.odd -gt 0) { return 'none' }
  $lines = New-Object 'System.Collections.Generic.List[string]'
  foreach ($f in @($l.files)) { $lines.Add($f.path + [char]9 + [string]$f.size + [char]9 + $f.sha256 + [char]10) }
  $arr = $lines.ToArray()
  [Array]::Sort($arr, [StringComparer]::Ordinal)
  $a = [Security.Cryptography.SHA256]::Create()
  try { Get-Hex ($a.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]::Concat($arr)))) } finally { $a.Dispose() }
}
function Get-List($v) {
  $o = New-Object 'System.Collections.Generic.List[string]'
  foreach ($x in @($v)) { if ($null -ne $x -and ([string]$x) -ne '') { $o.Add([string]$x) } }
  , $o.ToArray()
}
function Get-DefenderState {
  $s = Get-MpComputerStatus
  $p = Get-MpPreference
  [ordered]@{ rtp = [bool]$s.RealTimeProtectionEnabled; path = (Get-List $p.ExclusionPath); process = (Get-List $p.ExclusionProcess); extension = (Get-List $p.ExclusionExtension); ip = (Get-List $p.ExclusionIpAddress) }
}
function Test-DefenderGate($d) {
  $d.rtp -and $d.path.Count -eq 1 -and $d.path[0] -eq $Root -and $d.process.Count -eq 0 -and $d.extension.Count -eq 0 -and $d.ip.Count -eq 0
}
function Test-Elevated { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function Get-PointCount([string]$d) { @(Get-ComputerRestorePoint | Where-Object { $_.Description -ceq $d }).Count }
function Get-RestoreFrequency {
  $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue).SystemRestorePointCreationFrequency
  if ($null -eq $v) { return $null }
  [int]$v
}
`;

const PS_GATE = String.raw`# talonsoclab-art step=gate
$l = Get-Listing
$builtin = @('500', '501', '503', '504')
$names = @(Get-LocalUser | Where-Object { $builtin -notcontains $_.SID.Value.Split('-')[-1] } | ForEach-Object { [string]$_.Name })
$ids = [ordered]@{ computer = [string]$env:COMPUTERNAME; user = [string]$env:USERNAME; domain = [string]$env:USERDOMAIN; accounts = (Get-List $names) }
Send-Answer ([ordered]@{ step = 'gate'; utc = [DateTime]::UtcNow.ToString('o'); elevated = [bool](Test-Elevated); ids = $ids; defender = (Get-DefenderState); listing = $l; frequency = (Get-RestoreFrequency) })
`;

const PS_RESTORE = String.raw`# talonsoclab-art step=restore-point
$d = '@@DESC@@'
$before = Get-PointCount $d
$err = $false
if ($before -eq 0) {
  try { Checkpoint-Computer -Description $d -RestorePointType 'MODIFY_SETTINGS' -WarningAction SilentlyContinue } catch { $err = $true }
}
$rp = @(Get-ComputerRestorePoint | Where-Object { $_.Description -ceq $d })
$created = $null
if ($rp.Count -eq 1) { $created = ([Management.ManagementDateTimeConverter]::ToDateTime($rp[0].CreationTime)).ToUniversalTime().ToString('o') }
Send-Answer ([ordered]@{ step = 'restore-point'; existedBefore = $before; count = $rp.Count; createdUtc = $created; error = $err; frequency = (Get-RestoreFrequency) })
`;

// Definitions only: a service's start mode, account and binary, never whether it runs; a task's
// actions, triggers, principal and enabled flag, never its last or next run.
const PS_SNAPSHOT = String.raw`# talonsoclab-art step=snapshot
$cat = [ordered]@{}
$failed = New-Object 'System.Collections.Generic.List[string]'
function Get-Text($v) {
  if ($null -eq $v) { return '' }
  if ($v -is [Microsoft.Management.Infrastructure.CimInstance]) { return '{' + (Get-Flat $v) + '}' }
  if ($v -is [byte[]]) { return (Get-Hex $v) }
  if ($v -is [Array]) {
    [string[]]$t = @(foreach ($x in $v) { Get-Text $x })
    [Array]::Sort($t, [StringComparer]::Ordinal)
    return '[' + ($t -join ',') + ']'
  }
  if ($v -is [DateTime]) { return $v.ToUniversalTime().ToString('o') }
  [string]$v
}
function Get-Flat($o) {
  $pairs = New-Object 'System.Collections.Generic.List[string]'
  foreach ($p in $o.CimInstanceProperties) { if ($p.Name -ne 'PSComputerName') { $pairs.Add($p.Name + '=' + (Get-Text $p.Value)) } }
  $arr = $pairs.ToArray()
  [Array]::Sort($arr, [StringComparer]::Ordinal)
  $arr -join ';'
}
function Get-RegValue($key, $n) { [string]$key.GetValueKind($n) + ':' + (Get-Text $key.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) }
function Get-KeyText($key) {
  $vals = New-Object 'System.Collections.Generic.List[string]'
  foreach ($n in $key.GetValueNames()) { $vals.Add($n + '=' + (Get-RegValue $key $n)) }
  $arr = $vals.ToArray()
  [Array]::Sort($arr, [StringComparer]::Ordinal)
  $arr -join ';'
}
function Add-Category($name, [scriptblock]$body) {
  $list = New-Object 'System.Collections.Generic.List[object]'
  try { & $body $list; $cat[$name] = $list.ToArray() } catch { $failed.Add($name); $cat[$name] = @() }
}
function Add-Key($o, $label, $hive, $path) {
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
  try {
    $key = $base.OpenSubKey($path)
    if ($null -eq $key) { $o.Add([ordered]@{ k = $label; d = 'absent' }); return }
    try {
      foreach ($n in $key.GetValueNames()) { $o.Add([ordered]@{ k = $label + '/value/' + $n; d = (Get-RegValue $key $n) }) }
      foreach ($s in $key.GetSubKeyNames()) {
        $sub = $key.OpenSubKey($s)
        if ($null -eq $sub) { $o.Add([ordered]@{ k = $label + '/key/' + $s; d = 'unreadable' }); continue }
        try { $o.Add([ordered]@{ k = $label + '/key/' + $s; d = (Get-KeyText $sub) }) } finally { $sub.Close() }
      }
    } finally { $key.Close() }
  } finally { $base.Close() }
}
function Add-Folder($o, $label, $path) {
  if (-not [IO.Directory]::Exists($path)) { $o.Add([ordered]@{ k = $label; d = 'absent' }); return }
  $n = $path.TrimEnd('\').Length + 1
  foreach ($f in (New-Object IO.DirectoryInfo $path).GetFiles('*', [IO.SearchOption]::AllDirectories)) {
    $o.Add([ordered]@{ k = $label + '/' + $f.FullName.Substring($n).Replace('\', '/'); d = [string]$f.Length + ':' + (Get-Sha $f.FullName) })
  }
}
Add-Category 'services' { param($o)
  foreach ($s in @(Get-CimInstance -ClassName Win32_Service)) {
    $o.Add([ordered]@{ k = [string]$s.Name; d = 'StartMode=' + $s.StartMode + ';StartName=' + $s.StartName + ';PathName=' + $s.PathName + ';DelayedAutoStart=' + $s.DelayedAutoStart + ';ServiceType=' + $s.ServiceType })
  }
}
Add-Category 'tasks' { param($o)
  foreach ($t in @(Get-ScheduledTask)) {
    $o.Add([ordered]@{ k = [string]$t.TaskPath + [string]$t.TaskName; d = 'Actions=' + (Get-Text $t.Actions) + '|Triggers=' + (Get-Text $t.Triggers) + '|Principal=' + (Get-Text $t.Principal) + '|Enabled=' + $t.Settings.Enabled + '|Hidden=' + $t.Settings.Hidden })
  }
}
Add-Category 'runKeys' { param($o)
  foreach ($hive in 'LocalMachine', 'CurrentUser') {
    foreach ($view in 'Registry64', 'Registry32') {
      $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive, [Microsoft.Win32.RegistryView]::$view)
      try {
        foreach ($sub in 'Run', 'RunOnce') {
          $label = $hive + '/' + $view + '/' + $sub
          $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\' + $sub)
          if ($null -eq $key) { $o.Add([ordered]@{ k = $label; d = 'absent' }); continue }
          try { foreach ($n in $key.GetValueNames()) { $o.Add([ordered]@{ k = $label + '/' + $n; d = (Get-RegValue $key $n) }) } } finally { $key.Close() }
        }
      } finally { $base.Close() }
    }
  }
}
Add-Category 'wmi' { param($o)
  foreach ($c in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
    foreach ($i in @(Get-CimInstance -Namespace 'root/subscription' -ClassName $c)) {
      $flat = Get-Flat $i
      $name = ''
      if ($null -ne $i.CimInstanceProperties['Name']) { $name = [string]$i.CimInstanceProperties['Name'].Value }
      if ($name -eq '') { $name = $flat }
      $o.Add([ordered]@{ k = [string]$i.CimClass.CimClassName + '/' + $name; d = $flat })
    }
  }
}
Add-Category 'users' { param($o)
  foreach ($u in @(Get-LocalUser)) {
    $o.Add([ordered]@{ k = [string]$u.Name; d = 'SID=' + $u.SID.Value + ';Enabled=' + $u.Enabled + ';PasswordRequired=' + $u.PasswordRequired + ';UserMayChangePassword=' + $u.UserMayChangePassword + ';PasswordExpires=' + (Get-Text $u.PasswordExpires) + ';PasswordLastSet=' + (Get-Text $u.PasswordLastSet) + ';AccountExpires=' + (Get-Text $u.AccountExpires) + ';Description=' + $u.Description + ';FullName=' + $u.FullName })
  }
}
Add-Category 'admins' { param($o)
  $name = ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
  $g = [ADSI]('WinNT://' + $env:COMPUTERNAME + '/' + $name + ',group')
  foreach ($m in @($g.psbase.Invoke('Members'))) {
    [byte[]]$b = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
    $o.Add([ordered]@{ k = ([Security.Principal.SecurityIdentifier]::new($b, 0)).Value; d = 'member' })
  }
}
Add-Category 'defender' { param($o)
  foreach ($p in (Get-MpPreference).CimInstanceProperties) { if ($p.Name -ne 'PSComputerName') { $o.Add([ordered]@{ k = $p.Name; d = (Get-Text $p.Value) }) } }
}
Add-Category 'watched' { param($o)
  $cu = [Microsoft.Win32.RegistryHive]::CurrentUser
  $lm = [Microsoft.Win32.RegistryHive]::LocalMachine
  Add-Key $o 'hkcu-environment' $cu 'Environment'
  Add-Key $o 'print-monitors' $lm 'SYSTEM\CurrentControlSet\Control\Print\Monitors'
  Add-Key $o 'appcompat-custom' $lm 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom'
  Add-Key $o 'appcompat-installedsdb' $lm 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB'
  Add-Key $o 'lanmanserver-parameters' $lm 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
  Add-Key $o 'policies-system' $lm 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  Add-Folder $o 'user-startup' ([Environment]::GetFolderPath('Startup'))
  Add-Folder $o 'common-startup' ([Environment]::GetFolderPath('CommonStartup'))
  Add-Folder $o 'apppatch-custom' (Join-Path $env:windir 'apppatch\Custom')
}
Send-Answer ([ordered]@{ step = 'snapshot'; utc = [DateTime]::UtcNow.ToString('o'); categories = $cat; failed = $failed.ToArray() })
`;

// The allowed set rides in every step, so the Dell refuses a GUID the Mac let through by mistake.
// Invoke-ExecuteCommand names %TEMP%\art-out.txt and art-err.txt as capture files; 2.3.0 keeps
// output in memory and never writes them, but each step removes exactly those two if present.
const PS_STEP = String.raw`# talonsoclab-art step=@@MODE@@
$Allowed = @{ @@ALLOWED@@ }
$Guid = '@@GUID@@'
$Technique = '@@TECHNIQUE@@'
$Expect = '@@DIGEST@@'
$Desc = '@@DESC@@'
$Mode = '@@MODE@@'
$Timeout = @@TIMEOUT@@
$refused = $null
if (-not $Allowed.ContainsKey($Guid) -or $Allowed[$Guid] -cne $Technique) { $refused = 'not-allowlisted' }
if ($null -eq $refused -and -not (Test-Elevated)) { $refused = 'not-elevated' }
if ($null -eq $refused -and (Get-TreeDigest (Get-Listing)) -ne $Expect) { $refused = 'staged-files-changed' }
if ($null -eq $refused -and -not (Test-DefenderGate (Get-DefenderState))) { $refused = 'defender-gate' }
if ($null -eq $refused -and $Desc -ne '' -and (Get-PointCount $Desc) -ne 1) { $refused = 'restore-point-missing' }
if ($null -eq $refused) {
  try {
    Import-Module (Join-Path $Root '@@YAML@@\@@YAML@@.psd1') -Force
    Import-Module (Join-Path $Root '@@MODULE@@\@@MODULE@@.psd1') -Force
    $m = @(Get-Module '@@MODULE@@')
    $y = @(Get-Module '@@YAML@@')
    if ($m.Count -ne 1 -or [string]$m[0].Version -ne '@@VERSION@@' -or $m[0].ModuleBase -ne (Join-Path $Root '@@MODULE@@')) { throw 'module' }
    if ($y.Count -ne 1 -or [string]$y[0].Version -ne '@@YAMLVERSION@@' -or $y[0].ModuleBase -ne (Join-Path $Root '@@YAML@@')) { throw 'yaml' }
  } catch { $refused = 'module-import' }
}
$start = $null
$end = $null
$threw = $false
$recs = $null
if ($null -eq $refused) {
  $atomics = Join-Path $Root 'atomics'
  $start = [DateTime]::UtcNow.ToString('o')
  try {
    if ($Mode -eq 'run') { $recs = & { Invoke-AtomicTest $Technique -TestGuids $Guid -PathToAtomicsFolder $atomics -TimeoutSeconds $Timeout -NoExecutionLog -Confirm:$false } 6>&1 2>&1 }
    elseif ($Mode -eq 'cleanup') { $recs = & { Invoke-AtomicTest $Technique -TestGuids $Guid -PathToAtomicsFolder $atomics -TimeoutSeconds $Timeout -NoExecutionLog -Confirm:$false -Cleanup } 6>&1 2>&1 }
    else { $recs = & { Invoke-AtomicTest $Technique -TestGuids $Guid -PathToAtomicsFolder $atomics -TimeoutSeconds $Timeout -NoExecutionLog -Confirm:$false -CheckPrereqs } 6>&1 2>&1 }
  } catch { $threw = $true }
  $end = [DateTime]::UtcNow.ToString('o')
  foreach ($cap in 'art-out.txt', 'art-err.txt') {
    $capPath = Join-Path $env:TEMP $cap
    try { if (Test-Path -LiteralPath $capPath -PathType Leaf) { Remove-Item -LiteralPath $capPath -Force } } catch { }
  }
}
$segs = New-Object 'System.Collections.Generic.List[object]'
foreach ($r in @($recs)) {
  if ($null -eq $r) { continue }
  if ($r -is [Management.Automation.InformationRecord] -and $r.MessageData -is [Management.Automation.HostInformationMessage]) {
    $segs.Add([ordered]@{ m = [string]$r.MessageData.Message; c = [string]$r.MessageData.ForegroundColor; n = [bool]$r.MessageData.NoNewLine })
  } elseif ($r -is [Management.Automation.ErrorRecord]) { $segs.Add([ordered]@{ m = [string]$r; c = 'error'; n = $false }) }
  else { $segs.Add([ordered]@{ m = [string]$r; c = 'output'; n = $false }) }
}
Send-Answer ([ordered]@{ step = $Mode; refused = $refused; start = $start; end = $end; threw = $threw; segments = $segs.ToArray() })
`;

export type StepMode = "run" | "cleanup" | "prereqs";

export const gateScript = () => PS_LIB + PS_GATE;
export const snapshotScript = () => PS_LIB + PS_SNAPSHOT;

export function restoreScript(desc: string): string {
  if (!SAFE_DESC.test(desc)) refuse("the restore point description is outside its pattern");
  return PS_LIB + fill(PS_RESTORE, { DESC: desc });
}

/** One run, cleanup or prerequisite step, carrying the allowed set and every gate value. */
export function stepScript(mode: StepMode, e: AllowEntry, al: Allowlist, digest: string, desc: string, timeoutSeconds: number): string {
  if (!SAFE_GUID.test(e.guid) || !SAFE_TECHNIQUE.test(e.technique)) refuse("a GUID or technique is outside its pattern");
  if (!al.tests.some((t) => t.guid === e.guid && t.technique === e.technique)) refuse(`${e.guid} is not in the allowlist`);
  if (!SHA_HEX.test(digest)) refuse("the tree digest is not 64 hex");
  if (mode === "prereqs" ? desc !== "" : !SAFE_DESC.test(desc)) refuse("the restore point description is outside its pattern");
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < TIMEOUT_MIN_S || timeoutSeconds > TIMEOUT_MAX_S) refuse("the timeout is out of range");
  const allowed = al.tests
    .map((t) => {
      if (!SAFE_GUID.test(t.guid) || !SAFE_TECHNIQUE.test(t.technique)) refuse("an allowlist entry is outside its pattern");
      return `'${t.guid}' = '${t.technique}'`;
    })
    .join("; ");
  return (
    PS_LIB +
    fill(PS_STEP, {
      MODE: mode,
      ALLOWED: allowed,
      GUID: e.guid,
      TECHNIQUE: e.technique,
      DIGEST: digest,
      DESC: desc,
      TIMEOUT: String(timeoutSeconds),
      MODULE: MODULE_NAME,
      YAML: YAML_MODULE,
      VERSION: MODULE_VERSION,
      YAMLVERSION: YAML_VERSION,
    })
  );
}

// WARN: Windows sshd keeps a child's stdin open after the client is gone, so a reader waiting
// for end of input can block for ever (seen live, 2 in 45). The bootstrap reads one line from
// the raw stream with a time limit: [Console]::In is synchronized, so its async read cannot be.
/** The command line that reads one payload line from stdin, checks its hash and runs it. */
export function bootstrap(payloadSha: string): string {
  if (!SHA_HEX.test(payloadSha)) refuse("the payload hash is not 64 hex");
  return [
    "$ErrorActionPreference='Stop'",
    "$r=New-Object IO.StreamReader([Console]::OpenStandardInput())",
    "$t=$r.ReadLineAsync()",
    `if(-not $t.Wait(${STDIN_WAIT_MS})){[Environment]::Exit(${PAYLOAD_MISSING})}`,
    "$b=$t.Result",
    `if($null -eq $b -or $b.Trim() -eq ''){[Environment]::Exit(${PAYLOAD_MISSING})}`,
    "$y=[Convert]::FromBase64String($b.Trim())",
    "$s=[Security.Cryptography.SHA256]::Create()",
    "$h=([BitConverter]::ToString($s.ComputeHash($y))).Replace('-','').ToLowerInvariant()",
    `if($h -ne '${payloadSha}'){exit ${PAYLOAD_MISMATCH}}`,
    "& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($y)))",
  ].join(";");
}

/** The powershell command ssh runs, payload excluded. */
export function remoteCommand(payload: string): string {
  const encoded = Buffer.from(bootstrap(sha256(payload)), "utf16le").toString("base64");
  return `powershell -NoProfile -NonInteractive -EncodedCommand ${encoded}`;
}

/** The real Dell: ssh with the payload as base64 on stdin. */
export function sshRemote(host: string): Remote {
  if (!SAFE_HOST.test(host)) refuse("the ssh host alias holds characters an alias never has");
  return (payload, timeoutMs) => {
    try {
      const r = Bun.spawnSync(sshArgv(host, remoteCommand(payload)), {
        stdin: Buffer.from(`${Buffer.from(payload, "utf8").toString("base64")}\n`),
        stdout: "pipe",
        stderr: "pipe",
        timeout: timeoutMs,
      });
      return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString(), timedOut: r.exitedDueToTimeout === true };
    } catch {
      return { code: null, out: "", err: "", timedOut: false };
    }
  };
}

// *--- Answers ---*

/** The object in the last line of a step's stdout, which must be the tagged base64 answer. */
export function decodeAnswer(stdout: string, step: string): Record<string, unknown> {
  const last = stdout.trim().split(/\r?\n/).pop() ?? "";
  const b64 = last.startsWith(ANSWER_TAG) ? last.slice(ANSWER_TAG.length) : "";
  if (!b64 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64)) setup(`${step}: the Dell did not answer in the expected form`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(b64, "base64")));
  } catch {
    return setup(`${step}: the Dell's answer is not UTF-8 JSON`);
  }
  if (!isObject(parsed) || parsed.step !== step) return setup(`${step}: the Dell answered for another step`);
  return parsed;
}

const shape = (step: string, field: string): never => setup(`${step}: unexpected shape at ${field}`);

function strOf(o: Record<string, unknown>, k: string, step: string): string {
  if (typeof o[k] !== "string") shape(step, k);
  return o[k] as string;
}

function utcOf(o: Record<string, unknown>, k: string, step: string): string {
  const v = strOf(o, k, step);
  if (!ISO_UTC.test(v)) shape(step, k);
  return v;
}

// SECURITY: a null or empty entry is no exclusion, so it is dropped rather than counted;
// the Dell drops them too, since @($null).Count is 1 in PowerShell.
function listOf(v: unknown, step: string, field: string): string[] {
  if (v === null || v === undefined) return [];
  if (!Array.isArray(v)) return shape(step, field);
  return v.flatMap((x) => {
    if (x === null || x === "") return [];
    if (typeof x !== "string") return shape(step, field);
    return [x];
  });
}

function listingOf(v: unknown, step: string): Listing {
  if (!isObject(v)) return shape(step, "listing");
  if (typeof v.missingRoot !== "boolean") shape(step, "listing.missingRoot");
  if (!Number.isSafeInteger(v.odd) || (v.odd as number) < 0) shape(step, "listing.odd");
  const files = v.files === null ? [] : v.files;
  if (!Array.isArray(files)) return shape(step, "listing.files");
  const seen = new Set<string>();
  return {
    missingRoot: v.missingRoot as boolean,
    odd: v.odd as number,
    files: files.map((f) => {
      if (!isObject(f) || typeof f.path !== "string" || !Number.isSafeInteger(f.size) || typeof f.sha256 !== "string") return shape(step, "listing.files");
      if (seen.has(f.path as string)) shape(step, "listing.files (a path twice)");
      seen.add(f.path as string);
      return { path: f.path as string, size: f.size as number, sha256: (f.sha256 as string).toLowerCase() };
    }),
  };
}

function defenderOf(v: unknown, step: string): DefenderState {
  if (!isObject(v) || typeof v.rtp !== "boolean") return shape(step, "defender");
  return {
    rtp: v.rtp,
    path: listOf(v.path, step, "defender.path"),
    process: listOf(v.process, step, "defender.process"),
    extension: listOf(v.extension, step, "defender.extension"),
    ip: listOf(v.ip, step, "defender.ip"),
  };
}

function frequencyOf(v: unknown, step: string): number | null {
  if (v === null || v === undefined) return null;
  if (!Number.isSafeInteger(v)) return shape(step, "frequency");
  return v as number;
}

export function parseGate(o: Record<string, unknown>): GateAnswer {
  const step = "gate";
  if (typeof o.elevated !== "boolean") shape(step, "elevated");
  const ids = o.ids;
  if (!isObject(ids)) return shape(step, "ids");
  const found: Identity[] = [];
  for (const [k, label] of [
    ["computer", "<host>"],
    ["user", "<user>"],
    ["domain", "<domain>"],
  ]) {
    const v = ids[k];
    if (typeof v !== "string") shape(step, `ids.${k}`);
    if ((v as string).trim()) found.push({ literal: (v as string).trim(), label });
  }
  // Every local account but the well-known built-ins, which the Dell leaves out by RID.
  for (const name of listOf(ids.accounts, step, "ids.accounts")) {
    if (name.trim() && !found.some((f) => f.literal.toLowerCase() === name.trim().toLowerCase())) found.push({ literal: name.trim(), label: "<account>" });
  }
  return {
    utc: utcOf(o, "utc", step),
    elevated: o.elevated as boolean,
    ids: found,
    defender: defenderOf(o.defender, step),
    listing: listingOf(o.listing, step),
    frequency: frequencyOf(o.frequency, step),
  };
}

/** Why Defender fails the gate, or null when it passes (ISC-150). */
export function defenderVerdict(d: DefenderState): string | null {
  if (!d.rtp) return "Defender real-time protection is off";
  const exact = d.path.length === 1 && d.path[0].toLowerCase() === STAGED_ROOT.toLowerCase();
  if (!exact) return `Defender's ExclusionPath must be exactly ${STAGED_ROOT}; the Dell has ${plural(d.path.length, "entry", "entries")}${d.path.length === 1 ? " and it is another path" : ""}`;
  for (const [name, list] of [
    ["ExclusionProcess", d.process],
    ["ExclusionExtension", d.extension],
    ["ExclusionIpAddress", d.ip],
  ] as const) {
    if (list.length) return `Defender's ${name} must be empty; the Dell has ${plural(list.length, "entry", "entries")}`;
  }
  return null;
}

/** The restore point answer: its creation time, or why no test may start (ISC-154, ISC-157). */
export function restoreVerdict(o: Record<string, unknown>, desc: string): { createdUtc: string } | { why: string } {
  const step = "restore-point";
  const { existedBefore, count, createdUtc, error } = o;
  if (!Number.isSafeInteger(existedBefore) || !Number.isSafeInteger(count) || typeof error !== "boolean") return shape(step, "counts");
  const freq = frequencyOf(o.frequency, step);
  if (existedBefore !== 0) return { why: `a restore point named ${desc} already existed, so this session's own point cannot be told apart; no test was sent` };
  if (count === 1 && typeof createdUtc === "string" && ISO_UTC.test(createdUtc)) return { createdUtc };
  const freqText = freq === null ? "it is unset" : `it is ${freq}`;
  const why = error
    ? "Checkpoint-Computer failed on the Dell (is System Protection on for C:?)"
    : `Windows did not create the restore point. It skips a new one within 24 hours of the last unless SystemRestorePointCreationFrequency is 0 (${freqText})`;
  return { why: `${why}; this session's restore point is not confirmed, so no test was sent` };
}

export function parseSnapshot(o: Record<string, unknown>): Snapshot {
  const step = "snapshot";
  const cats = o.categories;
  if (!isObject(cats)) return shape(step, "categories");
  exactKeys(cats, [...CATEGORIES], "snapshot categories", (m) => setup(`snapshot: ${m}`));
  const failed = listOf(o.failed, step, "failed");
  const unknown = failed.filter((f) => !(CATEGORIES as readonly string[]).includes(f));
  if (unknown.length) shape(step, "failed");
  if (failed.length) setup(`snapshot: the Dell could not read ${failed.join(", ")}, so the state cannot be compared`);
  const snap = {} as Snapshot;
  for (const c of CATEGORIES) {
    const list = cats[c] === null ? [] : cats[c];
    if (!Array.isArray(list)) return shape(step, c);
    const m = new Map<string, string>();
    for (const it of list) {
      if (!isObject(it) || typeof it.k !== "string" || typeof it.d !== "string") return shape(step, c);
      if (m.has(it.k)) setup(`snapshot: ${c} names one item twice`);
      m.set(it.k, it.d);
    }
    snap[c] = m;
  }
  return snap;
}

export function parseStep(o: Record<string, unknown>, step: string): StepAnswer {
  const refused = o.refused;
  if (refused !== null && (typeof refused !== "string" || !(refused in REFUSALS))) shape(step, "refused");
  if (typeof o.threw !== "boolean") shape(step, "threw");
  const segsRaw = o.segments === null ? [] : o.segments;
  if (!Array.isArray(segsRaw)) return shape(step, "segments");
  const segments = segsRaw.map((s): Segment => {
    if (!isObject(s) || typeof s.m !== "string" || typeof s.c !== "string" || typeof s.n !== "boolean") return shape(step, "segments");
    return { m: s.m, c: s.c, n: s.n };
  });
  if (refused !== null) return { refused: refused as string, start: null, end: null, threw: false, segments: [] };
  return { refused: null, start: utcOf(o, "start", step), end: utcOf(o, "end", step), threw: o.threw as boolean, segments };
}

// Write-KeyValue prints its key as one NoNewLine segment and its value as more, up to an empty
// line end. A test's own stdout comes as one segment with a line end, so it cannot pass as a key.
function keyAt(segs: Segment[], key: string): number[] {
  return segs.flatMap((s, i) => (s.n && s.m === key ? [i] : []));
}

function valueAfter(segs: Segment[], i: number): string {
  let v = "";
  for (let j = i + 1; j < segs.length; j++) {
    v += segs[j].m;
    if (!segs[j].n) break;
  }
  return v;
}

export const testId = (e: AllowEntry) => `${e.technique.toUpperCase()}-${e.testNumber} ${e.testName}`;
const timedOut = (segs: Segment[]) => segs.some((s) => s.m.startsWith("Process Timed out after "));

/** The test step as the module reported it: ran once with an exit code, or why not. */
export function readRun(segs: Segment[], e: AllowEntry): { status: string; exitCode: number | null } {
  const start = keyAt(segs, "Executing test: ");
  const done = keyAt(segs, "Done executing test: ");
  if (start.length !== 1 || done.length !== 1 || done[0] < start[0] || valueAfter(segs, start[0]) !== testId(e)) return { status: "did-not-run-once", exitCode: null };
  if (timedOut(segs)) return { status: "timed-out", exitCode: null };
  const m = /^Exit code: (-?\d{1,10})$/.exec(segs[done[0] - 1]?.m ?? "");
  return m ? { status: "exited", exitCode: Number(m[1]) } : { status: "no-exit-code", exitCode: null };
}

// NOTE: Invoke-AtomicTest 2.3.0 never prints the cleanup command's exit code, so a cleanup
// counts as completed when the module ran it once to its "Done" line without a timeout.
export function readCleanup(segs: Segment[], e: AllowEntry): { status: string; exitCode: null } {
  const start = keyAt(segs, "Executing cleanup for test: ");
  const done = keyAt(segs, "Done executing cleanup for test: ");
  if (start.length !== 1 || done.length !== 1 || done[0] < start[0] || valueAfter(segs, start[0]) !== testId(e)) return { status: "did-not-run-once", exitCode: null };
  return { status: timedOut(segs) ? "timed-out" : "completed", exitCode: null };
}

export function readPrereqs(segs: Segment[], e: AllowEntry): "met" | "not-met" | "unknown" {
  const start = keyAt(segs, "CheckPrereq's for: ");
  if (start.length !== 1 || valueAfter(segs, start[0]) !== testId(e)) return "unknown";
  const met = keyAt(segs, "Prerequisites met: ").filter((i) => valueAfter(segs, i) === testId(e)).length;
  const notMet = segs.filter((s) => !s.n && s.m === `Prerequisites not met: ${testId(e)}`).length;
  if (met + notMet !== 1) return "unknown";
  return met ? "met" : "not-met";
}

// *--- State Diff ---*

/** Every item added, removed or changed between two snapshots, by category (ISC-153). */
export function diffSnapshots(before: Snapshot, after: Snapshot): DiffItem[] {
  const out: DiffItem[] = [];
  for (const c of CATEGORIES) {
    const a = before[c];
    const b = after[c];
    for (const k of [...new Set([...a.keys(), ...b.keys()])].sort(byOrdinal)) {
      if (!b.has(k)) out.push({ category: c, change: "removed", item: k });
      else if (!a.has(k)) out.push({ category: c, change: "added", item: k });
      else if (a.get(k) !== b.get(k)) out.push({ category: c, change: "changed", item: k });
    }
  }
  return out;
}

// *--- Record ---*

/** An item name fit for the committed record: SID machine parts, Dell names and addresses replaced. */
export function redactName(s: string, ids: Identity[]): string {
  let t = s.replace(CONTROL, "?").replace(SID_MACHINE, "S-1-5-21-<machine>");
  for (const id of [...ids].sort((a, b) => b.literal.length - a.literal.length)) t = t.replace(new RegExp(escapeRe(id.literal), "gi"), id.label);
  return t.replace(PRIVATE_V4, "<private-address>").replace(PRIVATE_V6, "<private-address>");
}

/** What in a record's text still identifies the Dell; empty when it is clean (ISC-156). */
export function recordFindings(json: string, ids: Identity[]): string[] {
  const out = new Set<string>();
  const lower = json.toLowerCase();
  for (const id of ids) if (lower.includes(id.literal.toLowerCase())) out.add(`the Dell's ${id.label.slice(1, -1)} name`);
  if (json.search(SID_MACHINE) !== -1) out.add("a SID machine part");
  if (json.search(PRIVATE_V4) !== -1 || json.search(PRIVATE_V6) !== -1) out.add("a private address");
  return [...out];
}

/** The real record writer: leakcheck on a scratch copy, then the file under art-runs. */
export function writeRecordFile(id: string, json: string): string {
  if (!SAFE_SESSION.test(id)) refuse("the session id is outside its pattern");
  const tmp = mkdtempSync(join(tmpdir(), "art-record-"));
  try {
    const scratch = join(tmp, `${id}.json`);
    writeFileSync(scratch, json);
    const r = Bun.spawnSync(["bun", resolve(ROOT, "tools/leakcheck.ts"), "--paths", scratch], { stdout: "pipe", stderr: "pipe", timeout: 120_000 });
    if (r.exitCode !== 0) throw new HarnessError(EXIT.failed, `leakcheck did not pass the session record (exit ${r.exitCode}); it was not written to ${RECORD_DIR}`);
    const dest = resolve(ROOT, RECORD_DIR, `${id}.json`);
    mkdirSync(dirname(dest), { recursive: true });
    if (existsSync(dest)) throw new HarnessError(EXIT.failed, `${relative(ROOT, dest)} already exists`);
    renameSync(scratch, dest);
    return relative(ROOT, dest);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** The raw sink under Plans/b4-harness/runs/<session>/, gitignored. */
export function rawFolder(id: string): (name: string, data: string) => void {
  const dir = resolve(ROOT, RAW_DIR, id);
  return (name, data) => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, name), data);
  };
}

// *--- Core Logic ---*

export function newSessionId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  return `${stamp}-${randomBytes(3).toString("hex")}`;
}

/** Pick the entries a session runs; any GUID outside the allowlist refuses before ssh (ISC-152). */
export function selectTests(al: Allowlist, guids: string[] | "all", allowRemoteCode: boolean): AllowEntry[] {
  let picked: AllowEntry[];
  if (guids === "all") picked = al.tests.filter((t) => allowRemoteCode || !t.runsFetchedCode);
  else {
    if (guids.length === 0) refuse("name at least one --guid, or --all");
    if (new Set(guids).size !== guids.length) refuse("a GUID is named twice");
    picked = guids.map((g) => {
      if (!SAFE_GUID.test(g)) return refuse("a --guid is not a lower-case GUID");
      const e = al.tests.find((t) => t.guid === g);
      if (!e) return refuse(`${g} is not in atomics/allowlist.json; nothing was sent`);
      if (e.runsFetchedCode && !allowRemoteCode) refuse(`${g} runs code it fetches from an unpinned URL; pass --allow-remote-code to run it`);
      return e;
    });
  }
  if (picked.length === 0) refuse("no test is left to run");
  return picked;
}

/** One gated session: refusals, gate, restore point, snapshot, run and cleanup per test, diff, record. */
export function runSession(o: SessionOptions): SessionOutcome {
  const messages: string[] = [];
  let testsSent = 0;
  let calls = 0;
  const id = o.sessionId ?? newSessionId();
  try {
    if (!SAFE_SESSION.test(id)) refuse("the session id is outside its pattern");
    if (!Number.isInteger(o.timeoutSeconds) || o.timeoutSeconds < TIMEOUT_MIN_S || o.timeoutSeconds > TIMEOUT_MAX_S) {
      refuse(`--timeout must be ${TIMEOUT_MIN_S} to ${TIMEOUT_MAX_S} seconds`);
    }
    const al = parseAllowlist(o.allowlistText);
    const tests = selectTests(al, o.guids, o.allowRemoteCode);
    const manifest = parseManifest(o.manifestText, al, o.allowlistText);
    if (manifest.owed.length) refuse(`the manifest still owes ${manifest.owed.join(", ")}: stage it and rebuild the manifest before a session`);
    const digest = treeDigest(manifest.files);

    // Every remote call is saved raw under the session's folder and never printed. Only a
    // payload that never arrived (nothing ran) is retried, once; every other failure stands.
    const call = (name: string, step: string, payload: string, timeoutMs: number): Record<string, unknown> => {
      calls++;
      const tag = `${String(calls).padStart(2, "0")}-${name}`;
      let r = o.remote(payload, timeoutMs);
      o.raw(`${tag}.out`, r.out);
      o.raw(`${tag}.err`, r.err);
      if (!r.timedOut && r.code === PAYLOAD_MISSING) {
        o.log(`RETRY ${name}: the payload did not reach the Dell and nothing ran; sending it once more`);
        r = o.remote(payload, timeoutMs);
        o.raw(`${tag}-attempt2.out`, r.out);
        o.raw(`${tag}-attempt2.err`, r.err);
        if (!r.timedOut && r.code === PAYLOAD_MISSING) setup(`${name}: the payload did not arrive on the Dell, twice; nothing ran`);
      }
      if (r.timedOut) setup(`${name}: ssh did not finish in ${Math.round(timeoutMs / 1000)} s; the remote process may still be running on the Dell, and the harness cannot end it`);
      if (r.code === PAYLOAD_MISMATCH) setup(`${name}: the Dell received a payload that does not hash to what was sent`);
      if (r.code === null) setup(`${name}: ssh could not start or was killed`);
      if (r.code !== 0) setup(`${name}: ssh exited ${r.code}; its output is saved under ${RAW_DIR}/${id}/ and not shown, since it can hold host and user names`);
      const answer = decodeAnswer(r.out, step);
      o.raw(`${tag}.json`, `${JSON.stringify(answer, null, 1)}\n`);
      return answer;
    };

    const skipped = o.guids === "all" ? al.tests.length - tests.length : 0;
    if (skipped) o.log(`SKIP ${plural(skipped, "test")} that run code fetched from an unpinned URL (--allow-remote-code includes them)`);
    const gate = parseGate(call("gate", "gate", gateScript(), GATE_MS));
    if (!gate.elevated) setup("the ssh session on the Dell is not elevated; no test was sent");
    const staged = compareListing(manifest, gate.listing);
    if (staged.missingRoot) setup(`${STAGED_ROOT} does not exist on the Dell; no test was sent`);
    if (staged.changed.length || staged.missing.length || staged.extra || staged.odd) {
      const parts = [
        ...staged.changed.slice(0, 5).map((p) => `changed ${p}`),
        ...staged.missing.slice(0, 5).map((p) => `missing ${p}`),
        ...(staged.extra ? [plural(staged.extra, "extra file")] : []),
        ...(staged.odd ? [plural(staged.odd, "link or reparse point")] : []),
      ];
      setup(`the staged files under ${STAGED_ROOT} differ from ${MANIFEST_PATH} (${parts.join("; ")}); no test was sent (ISC-155)`);
    }
    const defender = defenderVerdict(gate.defender);
    if (defender) setup(`${defender}; no test was sent (ISC-150)`);

    if (o.mode === "check-prereqs") {
      let unknown = 0;
      let notMet = 0;
      for (const [i, e] of tests.entries()) {
        const ans = parseStep(call(`prereqs-${i + 1}`, "prereqs", stepScript("prereqs", e, al, digest, "", o.timeoutSeconds), 2 * o.timeoutSeconds * 1000 + STEP_SLACK_MS), "prereqs");
        if (ans.refused) setup(`prereqs for ${e.guid}: ${REFUSALS[ans.refused]}`);
        const verdict = ans.threw ? "unknown" : readPrereqs(ans.segments, e);
        if (verdict === "unknown") unknown++;
        if (verdict === "not-met") notMet++;
        o.log(`PREREQ ${verdict} ${e.technique} #${e.testNumber} ${e.guid}`);
      }
      if (notMet) messages.push(`${plural(notMet, "test")} did not meet its prerequisites`);
      if (unknown) messages.push(`${plural(unknown, "test")} gave no readable prerequisite result`);
      return { exit: unknown || notMet ? EXIT.failed : EXIT.ok, messages, testsSent: 0 };
    }

    const desc = `talonsoclab-b4-${id}`;
    const rp = restoreVerdict(call("restore-point", "restore-point", restoreScript(desc), RESTORE_MS), desc);
    if ("why" in rp) setup(`${rp.why} (ISC-157)`);
    const createdUtc = (rp as { createdUtc: string }).createdUtc;
    const before = parseSnapshot(call("snapshot-before", "snapshot", snapshotScript(), SNAPSHOT_MS));

    // From here a test may have run, so every failure is a failed session (exit 1), not setup.
    const failures: string[] = [];
    const stepMs = o.timeoutSeconds * 1000 + STEP_SLACK_MS;
    const blank = (status: string): StepRecord => ({ startUtc: null, endUtc: null, status, exitCode: null });
    // Every selected test is in the record; one never sent after a failure stays "not-sent".
    const records: TestRecord[] = tests.map((e) => ({ guid: e.guid, technique: e.technique, testNumber: e.testNumber, testName: e.testName, rules: e.rules, run: blank("not-sent"), cleanup: blank("not-sent") }));
    for (const [i, e] of tests.entries()) {
      const rec = records[i];
      let stop = false;
      try {
        testsSent++;
        const ans = parseStep(call(`run-${i + 1}`, "run", stepScript("run", e, al, digest, desc, o.timeoutSeconds), stepMs), "run");
        if (ans.refused) {
          rec.run = blank("refused");
          failures.push(`${e.guid}: ${REFUSALS[ans.refused]}`);
          stop = true;
        } else {
          const r = ans.threw ? { status: "threw", exitCode: null } : readRun(ans.segments, e);
          rec.run = { startUtc: ans.start, endUtc: ans.end, status: r.status, exitCode: r.exitCode };
          if (r.status !== "exited" && r.status !== "timed-out") {
            failures.push(`${e.guid}: the test step ${r.status}`);
            stop = true;
          }
        }
      } catch (err) {
        rec.run = blank("remote-error");
        failures.push(`${e.guid}: ${err instanceof HarnessError ? err.message : "the test step failed"}`);
        stop = true;
      }
      // Cleanup runs whatever the test step did, a timeout or a refusal included.
      try {
        const ans = parseStep(call(`cleanup-${i + 1}`, "cleanup", stepScript("cleanup", e, al, digest, desc, o.timeoutSeconds), stepMs), "cleanup");
        if (ans.refused) {
          rec.cleanup = blank("refused");
          failures.push(`${e.guid} cleanup: ${REFUSALS[ans.refused]}`);
          stop = true;
        } else {
          const c = ans.threw ? { status: "threw", exitCode: null } : readCleanup(ans.segments, e);
          rec.cleanup = { startUtc: ans.start, endUtc: ans.end, status: c.status, exitCode: null };
          if (c.status !== "completed") {
            failures.push(`${e.guid}: the cleanup step ${c.status}`);
            stop = true;
          }
        }
      } catch (err) {
        rec.cleanup = blank("remote-error");
        failures.push(`${e.guid} cleanup: ${err instanceof HarnessError ? err.message : "the cleanup step failed"}`);
        stop = true;
      }
      if (stop) {
        if (i + 1 < tests.length) failures.push(`${plural(tests.length - i - 1, "test")} not sent after that failure`);
        break;
      }
    }

    let diff: DiffItem[] = [];
    let diffVerdict: SessionRecord["stateDiff"]["verdict"] = "not-taken";
    try {
      diff = diffSnapshots(before, parseSnapshot(call("snapshot-after", "snapshot", snapshotScript(), SNAPSHOT_MS)));
      diffVerdict = diff.length ? "different" : "no-difference";
      if (diff.length) failures.push(`the Dell's state differs after cleanup: ${plural(diff.length, "item")} (ISC-153)`);
    } catch (err) {
      failures.push(`snapshot after: ${err instanceof HarnessError ? err.message : "failed"}`);
    }
    let stagedAfter: SessionRecord["stagedAfter"] = { verdict: "not-checked", changed: 0, missing: 0, extra: 0 };
    try {
      const after = compareListing(manifest, parseGate(call("gate-after", "gate", gateScript(), GATE_MS)).listing);
      const changed = after.changed.length + after.odd;
      stagedAfter = { verdict: changed || after.missing.length || after.extra ? "changed" : "unchanged", changed, missing: after.missing.length, extra: after.extra };
      if (stagedAfter.verdict === "changed") failures.push(`the staged files under ${STAGED_ROOT} changed during the session`);
    } catch (err) {
      failures.push(`staged files after: ${err instanceof HarnessError ? err.message : "failed"}`);
    }

    // A module-level timeout is data, not a failure, but it is listed and printed, never hidden.
    const timedOutGuids = records.filter((t) => t.run.status === "timed-out").map((t) => t.guid);
    for (const t of records.filter((r) => r.run.status === "timed-out")) o.log(`TIMEOUT ${t.technique} #${t.testNumber} ${t.guid}: the module killed the test after ${o.timeoutSeconds} s`);
    const record: SessionRecord = {
      format: RECORD_FORMAT,
      session: id,
      verdict: failures.length ? "fail" : "pass",
      failures: failures.map((f) => redactName(f, gate.ids)),
      timedOut: timedOutGuids,
      allowlistSha256: sha256(o.allowlistText),
      manifestSha256: sha256(o.manifestText),
      atomicsCommit: al.atomicsCommit,
      module: { name: MODULE_NAME, version: MODULE_VERSION },
      timeoutSeconds: o.timeoutSeconds,
      gateUtc: gate.utc,
      defenderGate: { realTimeProtection: gate.defender.rtp, exclusionPath: [STAGED_ROOT], pass: true },
      restorePoint: { description: desc, createdUtc },
      tests: records,
      // SECURITY: a users item is an account name, so it never reaches the record, only a label.
      stateDiff: { verdict: diffVerdict, items: diff.map((d) => ({ ...d, item: d.category === "users" ? "<local-account>" : redactName(d.item, gate.ids) })) },
      stagedAfter,
    };
    const json = `${JSON.stringify(record, null, 2)}\n`;
    o.raw("record.json", json);
    const leaks = recordFindings(json, gate.ids);
    let recordPath: string | undefined;
    if (leaks.length) failures.push(`the record still holds ${leaks.join(" and ")}, so it was not written`);
    else {
      try {
        recordPath = o.writeRecord(id, json);
      } catch (err) {
        failures.push(err instanceof HarnessError ? err.message : "the record could not be written");
      }
    }
    messages.push(...failures);
    return { exit: failures.length ? EXIT.failed : EXIT.ok, messages, record, recordPath, testsSent };
  } catch (err) {
    if (!(err instanceof HarnessError)) throw err;
    messages.push(err.message);
    return { exit: err.exit, messages, testsSent };
  }
}

// *--- Self-Test ---*

interface FakeDell {
  listing: Listing;
  defender: DefenderState;
  restore: { existedBefore: number; count: number; error: boolean; frequency: number | null };
  before: Record<Category, [string, string][]>;
  after: Record<Category, [string, string][]>;
  ids: { computer: string; user: string; domain: string; accounts: string[] };
}

const STEP_LINE = /^# talonsoclab-art step=([a-z-]+)$/m;

/** A fake Dell that answers each step from a scenario and logs what it was sent. */
export function fakeRemote(d: FakeDell, sent: { step: string; payload: string }[], al: Allowlist): Remote {
  const answer = (o: unknown): RemoteResult => ({ code: 0, out: `noise line\n${ANSWER_TAG}${Buffer.from(JSON.stringify(o)).toString("base64")}\n`, err: "", timedOut: false });
  let snaps = 0;
  return (payload) => {
    const step = STEP_LINE.exec(payload)?.[1] ?? "unknown";
    sent.push({ step, payload });
    const utc = "2026-11-22T03:00:00.0000000Z";
    if (step === "gate") return answer({ step, utc, elevated: true, ids: d.ids, defender: d.defender, listing: d.listing, frequency: d.restore.frequency });
    if (step === "restore-point") return answer({ step, ...d.restore, createdUtc: d.restore.count === 1 ? utc : null });
    if (step === "snapshot") {
      const src = snaps++ === 0 ? d.before : d.after;
      const categories = Object.fromEntries(CATEGORIES.map((c) => [c, src[c].map(([k, v]) => ({ k, d: v }))]));
      return answer({ step, utc, categories, failed: [] });
    }
    const guid = /\$Guid = '([^']+)'/.exec(payload)?.[1] ?? "";
    const e = al.tests.find((t) => t.guid === guid);
    if (!e) return answer({ step, refused: "not-allowlisted", start: null, end: null, threw: false, segments: [] });
    const kv = (k: string, v: string) => [
      { m: k, c: "Cyan", n: true },
      { m: v, c: "Green", n: true },
      { m: "", c: "", n: false },
    ];
    const id = testId(e);
    const segments =
      step === "run"
        ? [...kv("Executing test: ", id), { m: "test output", c: "", n: false }, { m: "Exit code: 0", c: "", n: false }, ...kv("Done executing test: ", id)]
        : step === "cleanup"
          ? [...kv("Executing cleanup for test: ", id), ...kv("Done executing cleanup for test: ", id)]
          : [...kv("CheckPrereq's for: ", id), ...kv("Prerequisites met: ", id)];
    return answer({ step, refused: null, start: utc, end: "2026-11-22T03:00:05.0000000Z", threw: false, segments });
  };
}

/** A clean scenario: the listing equals the manifest, Defender passes, one restore point is made. */
export function cleanDell(m: Manifest): FakeDell {
  const base = (): Record<Category, [string, string][]> => ({
    services: [["Spooler", "StartMode=Auto"]],
    tasks: [["\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "Actions=x"]],
    runKeys: [["LocalMachine/Registry64/Run/SecurityHealth", "ExpandString:x"]],
    wmi: [["__EventFilter/SCM Event Log Filter", "Query=x"]],
    users: [["labuser", "Enabled=True"]],
    admins: [["S-1-5-21-1111111111-2222222222-3333333333-500", "member"]],
    defender: [["DisableRealtimeMonitoring", "False"]],
    watched: [["policies-system/value/EnableLUA", "DWord:1"]],
  });
  return {
    listing: { missingRoot: false, files: m.files.map((f) => ({ ...f })), odd: 0 },
    defender: { rtp: true, path: [STAGED_ROOT], process: [], extension: [], ip: [] },
    restore: { existedBefore: 0, count: 1, error: false, frequency: 0 },
    before: base(),
    after: base(),
    ids: { computer: "labhost", user: "labuser", domain: "labhost", accounts: ["labuser", "labsecond"] },
  };
}

// Built at run time, as winevt.test.ts does, so no private address sits in the source.
const plantedV4 = () => [10, 20, 30, 41].join(".");

// One added item per category, each carrying a planted identifier where a name could hold one.
const PLANTS: Record<Category, [string, string]> = {
  services: ["svc-labhost-planted", "StartMode=Auto"],
  tasks: ["\\OneDrive Standalone Update Task-S-1-5-21-1111111111-2222222222-3333333333-1001", "Actions=x"],
  runKeys: ["CurrentUser/Registry64/Run/labuser-agent", "String:x"],
  wmi: [`__EventFilter/planted-${plantedV4()}`, "Query=x"],
  users: ["planted-admin", "Enabled=True"],
  admins: ["S-1-5-21-1111111111-2222222222-3333333333-1002", "member"],
  defender: ["ExclusionProcess", "[x.exe]"],
  watched: ["print-monitors/key/AtomicRedTeam", "Driver=x"],
};

/**
 * A checkout whose technique YAML holds each allowlisted test at its number, with an unused
 * file in every folder; commands maps a GUID to the command its test gets.
 */
export function fixtureCheckout(checkout: string, al: Allowlist, commands: Record<string, string> = {}): void {
  for (const tech of techniquesOf(al)) {
    const entries = al.tests.filter((e) => e.technique === tech);
    const size = Math.max(...entries.map((e) => e.testNumber));
    const atomicTests = Array.from({ length: size }, (_, i) => {
      const e = entries.find((x) => x.testNumber === i + 1);
      return {
        name: e?.testName ?? `filler ${i + 1}`,
        auto_generated_guid: e?.guid ?? `00000000-0000-4000-8000-${String(i + 1).padStart(12, "0")}`,
        supported_platforms: ["windows"],
        executor: { name: e?.executor ?? "command_prompt", command: (e && commands[e.guid]) ?? "echo fixture", cleanup_command: "echo done" },
      };
    });
    mkdirSync(join(checkout, ATOMICS, tech, "bin"), { recursive: true });
    writeFileSync(join(checkout, ATOMICS, tech, `${tech}.yaml`), JSON.stringify({ attack_technique: tech, atomic_tests: atomicTests }, null, 1));
    writeFileSync(join(checkout, ATOMICS, tech, "bin", "unused.zip"), `not referenced by ${tech}\n`);
  }
}

/** Build a small manifest from real bytes in a temp tree, so a planted byte is a real byte. */
function selfTestManifest(al: Allowlist, allowlistText: string, tmp: string): { m: Manifest; text: string; flipped: ManifestFile } {
  const mod = join(tmp, "module");
  mkdirSync(join(mod, "Public"), { recursive: true });
  writeFileSync(join(mod, `${MODULE_NAME}.psd1`), `@{\n  ModuleVersion = '${MODULE_VERSION}'\n}\n`);
  writeFileSync(join(mod, "Public", "Invoke-AtomicTest.ps1"), "function Invoke-AtomicTest {}\n");
  const yaml = join(tmp, "yaml");
  mkdirSync(yaml);
  writeFileSync(join(yaml, `${YAML_MODULE}.psd1`), `@{\n  ModuleVersion = '${YAML_VERSION}'\n}\n`);
  const checkout = join(tmp, "checkout");
  fixtureCheckout(checkout, al);
  const m = buildManifest(al, allowlistText, [mod, yaml], checkout, () => ({ head: ATOMICS_COMMIT, dirty: false }));
  const target = m.files.find((f) => f.path.endsWith("Invoke-AtomicTest.ps1"))!;
  const bytes = readFileSync(join(mod, "Public", "Invoke-AtomicTest.ps1"));
  bytes[0] ^= 0x01;
  return { m, text: manifestText(m), flipped: { ...target, sha256: sha256(bytes) } };
}

/** Plant each fault in a fake session and prove the harness catches it; offline. */
export function selfTest(log: (line: string) => void = console.log): boolean {
  const allowlistText = readFileSync(resolve(ROOT, ALLOWLIST_PATH), "utf8");
  const al = parseAllowlist(allowlistText);
  const tmp = mkdtempSync(join(tmpdir(), "art-harness-self-"));
  const checks: [string, boolean][] = [];
  try {
    const { m, text, flipped } = selfTestManifest(al, allowlistText, tmp);
    const two = al.tests.filter((t) => !t.runsFetchedCode).slice(0, 2).map((t) => t.guid);
    // lost: how many deliveries the fake drops (exit 96, nothing run) before it answers again.
    const session = (d: FakeDell, guids: string[] | "all" = two, lost = 0) => {
      const sent: { step: string; payload: string }[] = [];
      const written: string[] = [];
      const base = fakeRemote(d, sent, al);
      let dropped = 0;
      const remote: Remote = (payload, ms) => {
        if (dropped >= lost) return base(payload, ms);
        dropped++;
        sent.push({ step: "lost", payload });
        return { code: PAYLOAD_MISSING, out: "", err: "", timedOut: false };
      };
      const out = runSession({
        mode: "run",
        guids,
        timeoutSeconds: DEFAULT_TIMEOUT_S,
        allowRemoteCode: false,
        remote,
        allowlistText,
        manifestText: text,
        sessionId: "20261122T030000Z-abcdef",
        raw: () => {},
        writeRecord: (_id, json) => {
          written.push(json);
          return "memory";
        },
        log: () => {},
      });
      const ran = sent.filter((s) => s.step === "run").length;
      return { out, sent, written, ran };
    };
    const clean = session(cleanDell(m));
    checks.push(["clean session passes and writes one record", clean.out.exit === EXIT.ok && clean.written.length === 1 && clean.ran === 2]);

    const stray = session(cleanDell(m), ["00000000-0000-4000-8000-000000000000"]);
    checks.push(["non-allowlisted GUID refused before any ssh (ISC-152)", stray.out.exit === EXIT.refused && stray.sent.length === 0]);

    const byte = cleanDell(m);
    byte.listing.files = byte.listing.files.map((f) => (f.path === flipped.path ? flipped : f));
    const b = session(byte);
    checks.push(["one-byte change in a staged file stops the session before any test (ISC-155)", b.out.exit === EXIT.setup && b.ran === 0 && b.out.messages.join().includes(flipped.path)]);

    const rp = cleanDell(m);
    rp.restore = { existedBefore: 0, count: 0, error: false, frequency: null };
    const r = session(rp);
    checks.push(["refused restore point stops the session before any test (ISC-157)", r.out.exit === EXIT.setup && r.ran === 0 && r.out.messages.join().includes("SystemRestorePointCreationFrequency")]);

    const extra = cleanDell(m);
    extra.defender.path = [STAGED_ROOT, "C:\\Temp"];
    const nulls = cleanDell(m);
    nulls.defender.path = [null as unknown as string];
    const de = session(extra);
    const dn = session(nulls);
    checks.push(["wrong Defender exclusion list stops the session before any test (ISC-150)", de.out.exit === EXIT.setup && de.ran === 0 && dn.out.exit === EXIT.setup && dn.ran === 0]);

    for (const c of CATEGORIES) {
      const d = cleanDell(m);
      d.after[c] = [...d.after[c], PLANTS[c]];
      const s = session(d);
      const items = s.out.record?.stateDiff.items ?? [];
      const json = s.out.record ? JSON.stringify(s.out.record) : "";
      const named = items.length === 1 && items[0].category === c && items[0].change === "added";
      const clean = !/labhost|labuser|S-1-5-21-\d/i.test(json) && !json.includes(plantedV4());
      const cleanupRan = s.sent.filter((x) => x.step === "cleanup").length === 2;
      checks.push([`a difference in ${c} fails the session, redacted (ISC-153)`, s.out.exit === EXIT.failed && named && clean && cleanupRan]);
    }

    const leaky = recordFindings(JSON.stringify({ item: "svc-LABHOST" }), [{ literal: "labhost", label: "<host>" }]);
    checks.push(["a record still holding a planted identifier is refused (ISC-156)", leaky.length === 1]);

    const never = session(cleanDell(m), two, 99);
    const once = session(cleanDell(m), two, 1);
    const neverOk = never.out.exit === EXIT.setup && never.sent.length === 2 && never.out.messages.join().includes("did not arrive");
    checks.push(["a payload that never arrives is sent twice, then stops the session before any test", neverOk && once.out.exit === EXIT.ok && once.ran === 2]);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  for (const [name, ok] of checks) log(`${ok ? "OK  " : "BAD "} self-test ${name}`);
  return checks.length === 7 + CATEGORIES.length && checks.every(([, ok]) => ok);
}

// *--- Entry Point ---*

const USAGE = `usage: bun tools/art-harness.ts check-allowlist --atomics <checkout>
       bun tools/art-harness.ts build-manifest --module <dir> [--module <dir>] --atomics <checkout> [--check]
       bun tools/art-harness.ts stage --module <dir> [--module <dir>] --atomics <checkout> --out <new dir>
       bun tools/art-harness.ts check-prereqs --host <ssh alias> (--guid <guid>... | --all) [--timeout <s>]
       bun tools/art-harness.ts run --host <ssh alias> (--guid <guid>... | --all) [--timeout <s>] [--allow-remote-code]
       bun tools/art-harness.ts --self-test

exit 0 ok, 1 failed check or session, 2 setup failure (no test sent), 3 refused (nothing sent)`;

interface Cli {
  cmd: string;
  atomics?: string;
  modules: string[];
  out?: string;
  host?: string;
  guids: string[];
  all: boolean;
  timeout: number;
  allowRemoteCode: boolean;
  check: boolean;
}

function parseCli(argv: string[]): Cli {
  const c: Cli = { cmd: argv[0] ?? "", modules: [], guids: [], all: false, timeout: DEFAULT_TIMEOUT_S, allowRemoteCode: false, check: false };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) refuse(`${a} needs a value`);
      return v;
    };
    if (a === "--atomics") c.atomics = resolve(value());
    else if (a === "--module") c.modules.push(resolve(value()));
    else if (a === "--out") c.out = resolve(value());
    else if (a === "--host") c.host = value();
    else if (a === "--guid") c.guids.push(value());
    else if (a === "--all") c.all = true;
    else if (a === "--timeout") {
      const v = value();
      if (!/^\d{1,5}$/.test(v)) refuse("--timeout needs a whole number of seconds");
      c.timeout = Number(v);
    } else if (a === "--allow-remote-code") c.allowRemoteCode = true;
    else if (a === "--check") c.check = true;
    else refuse(`unknown argument: ${a}`);
  }
  return c;
}

function main(argv: string[]): ExitCode {
  if (argv[0] === "--help" || argv[0] === "-h") {
    console.log(USAGE);
    return EXIT.ok;
  }
  if (argv[0] === "--self-test") return selfTest() ? EXIT.ok : EXIT.failed;
  const c = parseCli(argv);
  const allowlistText = readFileSync(resolve(ROOT, ALLOWLIST_PATH), "utf8");
  const al = parseAllowlist(allowlistText);
  if (c.cmd === "check-allowlist") {
    if (!c.atomics) refuse("check-allowlist needs --atomics <checkout>");
    const bad = checkAllowlist(al, c.atomics!);
    for (const b of bad) console.log(`MISMATCH ${b}`);
    console.error(`art-harness: ${al.tests.length} allowlist entries checked against the checkout, ${plural(bad.length, "mismatch", "mismatches")}`);
    return bad.length ? EXIT.failed : EXIT.ok;
  }
  if (c.cmd === "build-manifest" || c.cmd === "stage") {
    if (!c.atomics || c.modules.length === 0) refuse(`${c.cmd} needs --module <dir> and --atomics <checkout>`);
    const m = buildManifest(al, allowlistText, c.modules, c.atomics!);
    if (c.cmd === "stage") {
      if (!c.out) refuse("stage needs --out <new dir>");
      const onDisk = parseManifest(readFileSync(resolve(ROOT, MANIFEST_PATH), "utf8"), al, allowlistText);
      if (manifestText(onDisk) !== manifestText(m)) refuse(`the sources differ from ${MANIFEST_PATH}; rebuild it first`);
      const n = stageFiles(onDisk, c.modules, c.atomics!, c.out!);
      console.error(`art-harness: staged ${plural(n, "file")} into ${relative(process.cwd(), c.out!) || "."}`);
      return EXIT.ok;
    }
    const text = manifestText(m);
    const path = resolve(ROOT, MANIFEST_PATH);
    if (c.check) {
      const same = existsSync(path) && readFileSync(path, "utf8") === text;
      console.error(`art-harness: ${MANIFEST_PATH} ${same ? "matches" : "differs from"} the sources`);
      return same ? EXIT.ok : EXIT.failed;
    }
    writeFileSync(path, text);
    console.error(`art-harness: wrote ${MANIFEST_PATH}, ${plural(m.files.length, "file")}${m.owed.length ? `; still owed: ${m.owed.join(", ")}` : ""}`);
    return EXIT.ok;
  }
  if (c.cmd === "run" || c.cmd === "check-prereqs") {
    if (!c.host || !SAFE_HOST.test(c.host)) refuse("--host must be an ssh alias");
    if (c.all === c.guids.length > 0) refuse("give either --all or one or more --guid");
    const id = newSessionId();
    const out = runSession({
      mode: c.cmd === "run" ? "run" : "check-prereqs",
      guids: c.all ? "all" : c.guids,
      timeoutSeconds: c.timeout,
      allowRemoteCode: c.allowRemoteCode,
      remote: sshRemote(c.host!),
      allowlistText,
      manifestText: existsSync(resolve(ROOT, MANIFEST_PATH)) ? readFileSync(resolve(ROOT, MANIFEST_PATH), "utf8") : "",
      sessionId: id,
      raw: rawFolder(id),
      writeRecord: writeRecordFile,
      log: (l) => console.log(l),
    });
    for (const msg of out.messages) console.error(`art-harness: ${msg.replace(CONTROL, "?")}`);
    if (out.record) {
      for (const t of out.record.tests) console.log(`TEST ${t.technique} #${t.testNumber} ${t.guid} run=${t.run.status}${t.run.exitCode === null ? "" : `(${t.run.exitCode})`} cleanup=${t.cleanup.status}`);
      console.log(`STATE ${out.record.stateDiff.verdict} STAGED ${out.record.stagedAfter.verdict}`);
    }
    console.error(`art-harness: session ${id}: ${out.exit === EXIT.ok ? "pass" : "not passed"} (exit ${out.exit})${out.recordPath ? `, record ${out.recordPath}` : ""}`);
    return out.exit;
  }
  return refuse(`unknown command\n${USAGE}`);
}

if (import.meta.main) {
  try {
    process.exit(main(Bun.argv.slice(2)));
  } catch (e) {
    if (e instanceof HarnessError) {
      console.error(`art-harness: ${e.message}`);
      process.exit(e.exit);
    }
    console.error(`art-harness: unexpected ${e instanceof Error ? e.name : "error"}`);
    process.exit(EXIT.setup);
  }
}
