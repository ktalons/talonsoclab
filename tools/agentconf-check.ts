#!/usr/bin/env bun
// *****************************************************************************
// *Title: agentconf-check*
// *Author: Kyle Versluis*
// *Description: Run every shared agent.conf through Wazuh's verify-agent-conf.*
// *****************************************************************************

// *--- Imports ---*

import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, type Stats, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { type Box, clean, managerImage, packStage, SetupError } from "./logtest.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
export const SHARED = "deploy/soc-recon/wazuh/shared";
export const COMPOSE = "deploy/soc-recon/docker-compose.yml";
// Tracked beside the group folders, never inside one: a file in a group folder ships to
// every agent in that group.
export const RECEIPT = `${SHARED}/agentconf.verified`;
const CONF = "agent.conf";
const FIXTURES = "tools/fixtures/agentconf";
const DEFAULT_HOST = "talonsoc";
// SECURITY: an ssh alias and never an option. No leading dash, and remote() puts "--"
// before it.
const SAFE_HOST = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/;
// A group is a folder name Wazuh and the shell both read as plain text.
const GROUP_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// SECURITY: the only text a box script carries besides its constants. The image is the
// tag managerImage() already held to Docker's grammar, and a staged name is made here,
// never read from the tree, so nothing from a config file reaches the shell.
const IMAGE = /^wazuh\/wazuh-manager:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const STAGED_NAME = /^[a-z0-9][a-z0-9-]{0,31}\.conf$/;
// Exit codes of the box script's own steps, kept clear of the checker's 0 and 1, docker's
// 125 to 127 and ssh's 255.
const STAGE_FAILED = 90;
const UNPACK_FAILED = 91;
const CLEANUP_FAILED = 92;
const SSH_FAILED = 255;
const DOCKER_FAILED = [125, 126, 127];
// The manager image keeps a pristine etc under data_tmp. verify-agent-conf reads its
// definitions from internal_options.conf and stops with CRITICAL 2301 without it.
const INTERNAL_OPTIONS = "/var/ossec/data_tmp/exclusion/var/ossec/etc/internal_options.conf";
// SECURITY: docker and tar read these from the environment, so a login profile on the box
// that sets one could point the run at another daemon or hand tar a checkpoint command.
const TOOL_ENV = "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_TLS_VERIFY DOCKER_CERT_PATH TAR_OPTIONS TAR_READER_OPTIONS TAR_WRITER_OPTIONS";
const OK_LINE = "verify-agent-conf: OK";
// A Wazuh log line as the checker prints it (first real run, 2026-11-20): a timestamp,
// an optional "<tag>: " or "<tag>:<module>: " prefix, then the level. The OK line alone
// is bare. A level line with no timestamp is output this gate does not know.
const STAMP = String.raw`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `;
const TAG_PREFIX = String.raw`(?:[\w.-]+(?::[\w.-]+)*: )?`;
const ERROR_LINE = new RegExp(`^${STAMP}${TAG_PREFIX}ERROR: \\(\\d+\\): `);
const WARNING_LINE = new RegExp(`^${STAMP}${TAG_PREFIX}WARNING: `);
const CRITICAL_LINE = /\bCRITICAL\b/;
// SECURITY: a record is plain text or it is output this gate does not know. A carriage
// return inside a record hides what follows it from a prefix match, and a byte-order mark
// or a no-break space is whitespace to trim(), which would turn a malformed OK line into
// the exact one. Tab is the one control character let through.
const NOT_PLAIN = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f\u00a0\u2028\u2029\ufeff]/;
// The box script's first line of output: the SHA-256 of the file as the box unpacked it.
// An empty hash (sha256sum found no file) loses its trailing space with the line's others.
const STAGED_HASH = /^agentconf-staged(?: ([0-9a-f]{64}))?$/;
// Every path the checker names under the mount. Group 1 is the staged file name.
const STAGED_PATH = /\/t\/([^\s'":]*)/g;
// The XML reader's own error, the one the 2026-11-14 file raised.
const XML_ERROR = /XMLERR: Element '[^']+' not closed/;
const DEFINITION_MISSING = /\(2301\): Definition not found/;
// One receipt line per group: sha256sum's format, then the group's agent.conf path.
const RECEIPT_HASH = /^([0-9a-f]{64}) {2}([^/\s]+)\/agent\.conf$/;
const RECEIPT_IMAGE = /^image (\S+)$/;

// *--- Types ---*

/** What one checker run says about one file. */
export type Verdict =
  | { kind: "pass"; warnings: string[] }
  | { kind: "rejected"; lines: string[] }
  | { kind: "setup"; why: string; lines: string[] };

export interface Group {
  group: string;
  // The repo-relative path, for messages.
  path: string;
  bytes: Buffer;
  sha256: string;
}

export interface GroupResult {
  group: string;
  path: string;
  staged: string;
  sha256: string;
  verdict: Verdict;
}

export interface RunResult {
  code: 0 | 1 | 2;
  image: string;
  results: GroupResult[];
  // Why no receipt was written although every group passed.
  unwritten?: string;
}

export interface RunOptions {
  host: string;
  // The repo root the shared folder and compose file are read from; tests pass a copy.
  root?: string;
}

/** The shared folder as one commit would hold it: each group's agent.conf hash or problem. */
export interface Tree {
  compose: string;
  receipt?: string;
  groups: { group: string; sha256?: string; problem?: string }[];
}

// *--- Helper Functions ---*

const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const reason = (e: unknown) => (e instanceof Error ? e.message : String(e));
/** The manager image reference the compose file pins. */
export const imageOf = (compose: string) => `wazuh/wazuh-manager:${managerImage(compose, COMPOSE)}`;

// A hung ssh is killed after 5 minutes; its null exit code is a setup failure.
const remote: Box = (host, script, input) => {
  const r = Bun.spawnSync(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "--", host, script], {
    stdin: input ?? "ignore",
    stdout: "pipe",
    stderr: "pipe",
    timeout: 300_000,
  });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString().trim() };
};

/** A single file as the tar stream the box script unpacks. */
function packOne(staged: string, bytes: Uint8Array): Uint8Array {
  const dir = mkdtempSync(join(tmpdir(), "agentconf-"));
  try {
    // The container may read the mount as another user than the one that unpacked it.
    chmodSync(dir, 0o755);
    writeFileSync(join(dir, staged), bytes, { mode: 0o644 });
    return packStage(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// *--- Core Logic ---*

// WARN: docker in an ssh one-liner reads the ssh stdin unless told otherwise, so it gets
// /dev/null; the tar stream is for tar alone.
// The folder is made fresh by mktemp and removed on every way out the shell controls. A
// removal that leaves it behind exits CLEANUP_FAILED, whatever the checker said.
/** The box script that checks one staged file in a throwaway container of the image. */
export function boxScript(image: string, staged: string, setup = true): string {
  if (!IMAGE.test(image)) throw new SetupError(`refusing to run the image ${JSON.stringify(image).slice(0, 160)}`);
  if (!STAGED_NAME.test(staged)) throw new SetupError(`refusing the staged name ${JSON.stringify(staged)}`);
  // The self-test leaves the internal_options copy out to plant a setup failure.
  const prep = setup ? `mkdir -p /var/ossec/etc && cp ${INTERNAL_OPTIONS} /var/ossec/etc/internal_options.conf` : "mkdir -p /var/ossec/etc";
  return [
    `unset ${TOOL_ENV} || exit ${STAGE_FAILED}`,
    "umask 022",
    `d=$(mktemp -d "$HOME/.agentconf.XXXXXX") && [ -d "$d" ] || { echo "cannot make a staging folder" >&2; exit ${STAGE_FAILED}; }`,
    `trap 'rm -rf -- "$d"' EXIT`,
    "trap 'exit 129' HUP INT TERM",
    `tar -xf - -C "$d" && chmod 755 "$d" || { echo "cannot unpack the stage" >&2; exit ${UNPACK_FAILED}; }`,
    `printf 'agentconf-staged %s\\n' "$(sha256sum < "$d/${staged}" | cut -c1-64)"`,
    `docker run --rm --pull never --network none -w /var/ossec -v "$d:/t:ro" --entrypoint sh ${image} -c '${prep} && /var/ossec/bin/verify-agent-conf -f /t/${staged}' </dev/null 2>&1`,
    "rc=$?",
    "trap - EXIT",
    'rm -rf -- "$d"',
    `if [ -e "$d" ]; then echo "the staging folder was not removed" >&2; exit ${CLEANUP_FAILED}; fi`,
    'exit "$rc"',
  ].join("\n");
}

// SECURITY: the output counts for this file only when it opens with the hash of the bytes
// this call sent, as the box unpacked them. A pass then needs exit 0, exactly one OK line
// and nothing but warnings beside it; a rejection needs exit 1 and an ERROR line naming
// this call's own staged file. Anything else is a setup failure, so a broken setup can
// never read as either verdict, and no output is credited to a file it was not run on.
// That covers stderr too: docker's is merged into stdout on the box, so whatever arrives
// on stderr came from ssh or the box shell, and a verdict beside it is not a clean one.
/** Read one box call's result as a pass, a rejection by the checker, or a setup failure. */
export function classify(r: ReturnType<Box>, staged: string, sent: string): Verdict {
  // A record ends at LF or CRLF. Only spaces and tabs are trimmed from its end.
  const all = r.out
    .split("\n")
    .map((l) => l.replace(/\r$/, "").replace(/[ \t]+$/, ""))
    .filter((l) => l !== "");
  const head = STAGED_HASH.exec(all[0] ?? "");
  const lines = head ? all.slice(1) : all;
  const setup = (why: string): Verdict => ({ kind: "setup", why, lines });
  const err = r.err ? `: ${r.err.slice(0, 300)}` : "";
  if (r.code === null) return setup("the box command did not finish (ssh timeout or signal)");
  if (r.code === SSH_FAILED) return setup(`ssh failed${err}`);
  if (r.code === STAGE_FAILED || r.code === UNPACK_FAILED) return setup(`staging on the box failed (exit ${r.code})${err}`);
  if (r.code === CLEANUP_FAILED) return setup(`the staging folder on the box was not removed${err}`);
  const odd = all.find((l) => NOT_PLAIN.test(l));
  if (odd !== undefined) return setup(`a control character or other non-plain text in the output: ${JSON.stringify(odd).slice(0, 200)}`);
  if (!head) return setup("the output does not open with the hash of the staged file");
  if (head[1] === undefined) return setup("the box could not hash the staged file");
  if (head[1] !== sent) return setup("the box staged other bytes than this call sent, or the output is another call's");
  if (DOCKER_FAILED.includes(r.code)) return setup(`docker could not run the checker (exit ${r.code})`);
  if (r.err) return setup(`the box call wrote to stderr: ${r.err.slice(0, 300)}`);
  const foreign = [...new Set(lines.flatMap((l) => [...l.matchAll(STAGED_PATH)].map((m) => m[1])))].filter((n) => n !== staged);
  if (foreign.length) return setup(`the output names /t/${foreign[0]}, not /t/${staged}, the file this call staged`);
  const critical = lines.find((l) => CRITICAL_LINE.test(l));
  if (critical) return setup(`the checker did not start: ${critical}`);
  const errors = lines.filter((l) => ERROR_LINE.test(l));
  const oks = lines.filter((l) => l === OK_LINE);
  const other = lines.find((l) => l !== OK_LINE && !ERROR_LINE.test(l) && !WARNING_LINE.test(l));
  if (other !== undefined) return setup(`unrecognized checker output: ${other}`);
  if (r.code === 0) {
    if (errors.length) return setup("the checker exited 0 but printed an error");
    if (oks.length !== 1) return setup(`the checker exited 0 with ${oks.length} OK lines, not 1`);
    return { kind: "pass", warnings: lines.filter((l) => WARNING_LINE.test(l)) };
  }
  if (r.code === 1) {
    if (oks.length) return setup("the checker exited 1 but printed OK");
    if (!errors.some((l) => l.includes(`'/t/${staged}'`))) return setup(`the checker exited 1 without naming /t/${staged}`);
    return { kind: "rejected", lines };
  }
  return setup(`the box command exited ${r.code}${err}`);
}

/** Stage one file on the box, run the checker on it there, and read the result. */
export function checkOne(box: Box, host: string, image: string, staged: string, bytes: Uint8Array, setup = true): Verdict {
  const script = boxScript(image, staged, setup);
  return classify(box(host, script, packOne(staged, bytes)), staged, sha256(bytes));
}

// A folder with no agent.conf is refused rather than skipped: the receipt would have no
// entry for it, and the offline check would then fail every commit.
/** Every group folder under the shared folder with its agent.conf; anything odd is a setup error. */
export function findGroups(root = ROOT): Group[] {
  const dir = join(root, SHARED);
  if (!existsSync(dir) || !lstatSync(dir).isDirectory()) throw new SetupError(`no shared folder at ${SHARED}`);
  const out: Group[] = [];
  for (const name of readdirSync(dir).sort()) {
    const st = lstatSync(join(dir, name));
    if (st.isSymbolicLink()) throw new SetupError(`${SHARED}/${name} is a symlink`);
    if (!st.isDirectory()) continue;
    if (!GROUP_NAME.test(name)) throw new SetupError(`${SHARED}/${JSON.stringify(name)} is not a plain group name (letters, digits, dot, dash, underscore)`);
    const path = `${SHARED}/${name}/${CONF}`;
    const file = join(root, path);
    let fst: Stats;
    try {
      fst = lstatSync(file);
    } catch {
      throw new SetupError(`${SHARED}/${name} has no ${CONF}`);
    }
    // SECURITY: a symlink would be hashed and checked as its target here, which need not
    // be what the manager's copy of the folder holds.
    if (!fst.isFile()) throw new SetupError(`${path} is not a regular file`);
    const bytes = readFileSync(file);
    out.push({ group: name, path, bytes, sha256: sha256(bytes) });
  }
  if (!out.length) throw new SetupError(`no group folders under ${SHARED}`);
  return out;
}

/** The receipt a full pass writes: the image, then each group's agent.conf hash. */
export function receiptText(image: string, groups: { group: string; sha256: string }[]): string {
  const lines = [...groups].sort((a, b) => (a.group < b.group ? -1 : a.group > b.group ? 1 : 0)).map((g) => `${g.sha256}  ${g.group}/${CONF}`);
  return [
    "# agentconf-check receipt (ISA ISC-105). Written by tools/agentconf-check.ts after every",
    "# group's agent.conf passed verify-agent-conf on the box. Do not edit by hand.",
    `image ${image}`,
    ...lines,
    "",
  ].join("\n");
}

/** The receipt's image and hashes, or the lines it could not read. */
export function parseReceipt(text: string): { image?: string; hashes: Map<string, string>; problems: string[] } {
  const hashes = new Map<string, string>();
  const problems: string[] = [];
  let image: string | undefined;
  text.split("\n").forEach((line, i) => {
    if (line === "" || line.startsWith("#")) return;
    const img = RECEIPT_IMAGE.exec(line);
    const h = RECEIPT_HASH.exec(line);
    if (img && image === undefined) image = img[1];
    else if (img) problems.push(`line ${i + 1} names a second image`);
    else if (h && !hashes.has(h[2])) hashes.set(h[2], h[1]);
    else if (h) problems.push(`line ${i + 1} lists ${h[2]} a second time`);
    else problems.push(`line ${i + 1} is not an image or hash line`);
  });
  if (image === undefined) problems.push("names no image");
  return { image, hashes, problems };
}

/** Each way the receipt fails to describe the tree, one line each; none means it matches. */
export function compareReceipt(tree: Tree): string[] {
  const image = imageOf(tree.compose);
  const run = "run bun tools/agentconf-check.ts to verify every group on the box";
  if (tree.receipt === undefined) return [`${RECEIPT}: no receipt; ${run}`];
  const r = parseReceipt(tree.receipt);
  const out = r.problems.map((p) => `${RECEIPT}: ${p}; ${run}`);
  if (r.image !== undefined && r.image !== image) out.push(`${RECEIPT}: verified on ${r.image}, but ${COMPOSE} pins ${image}; ${run}`);
  const seen = new Set<string>();
  for (const g of tree.groups) {
    seen.add(g.group);
    const path = `${SHARED}/${g.group}/${CONF}`;
    const want = r.hashes.get(g.group);
    if (g.problem) out.push(`${SHARED}/${g.group}: ${g.problem}`);
    else if (want === undefined) out.push(`${path}: no entry in the receipt; ${run}`);
    else if (want !== g.sha256) out.push(`${path}: changed since the last verified run; ${run}`);
  }
  for (const group of [...r.hashes.keys()].sort()) {
    if (!seen.has(group)) out.push(`${RECEIPT}: lists ${group}, which is not a group folder in the tree; ${run}`);
  }
  return out;
}

/** The shared folder, compose file and receipt as the working tree holds them. */
export function readWorkingTree(root = ROOT): Tree {
  const composePath = join(root, COMPOSE);
  if (!existsSync(composePath)) throw new SetupError(`no compose file at ${COMPOSE}`);
  const dir = join(root, SHARED);
  if (!existsSync(dir)) throw new SetupError(`no shared folder at ${SHARED}`);
  const receiptPath = join(root, RECEIPT);
  let receipt: string | undefined;
  if (existsSync(receiptPath)) {
    if (!lstatSync(receiptPath).isFile()) throw new SetupError(`${RECEIPT} is not a regular file`);
    receipt = readFileSync(receiptPath, "utf8");
  }
  const groups: Tree["groups"] = [];
  for (const name of readdirSync(dir).sort()) {
    const st = lstatSync(join(dir, name));
    if (!st.isDirectory() && !st.isSymbolicLink()) continue;
    if (st.isSymbolicLink()) groups.push({ group: name, problem: "is a symlink" });
    else if (!GROUP_NAME.test(name)) groups.push({ group: name, problem: "is not a plain group name" });
    else {
      const file = join(dir, name, CONF);
      let fst: Stats | undefined;
      try {
        fst = lstatSync(file);
      } catch {
        fst = undefined;
      }
      if (!fst) groups.push({ group: name, problem: `has no ${CONF}` });
      else if (!fst.isFile()) groups.push({ group: name, problem: `${CONF} is not a regular file` });
      else groups.push({ group: name, sha256: sha256(readFileSync(file)) });
    }
  }
  return { compose: readFileSync(composePath, "utf8"), receipt, groups };
}

// SECURITY: a replace ref would make cat-file hand back another blob than the one the
// commit records, so replacements are off, as in leakcheck.
/** One git command's stdout in the repo root; a failure is a setup error. */
function git(root: string, args: string[]): Buffer {
  const env = { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" };
  const r = Bun.spawnSync(["git", ...args], { cwd: root, env, stdout: "pipe", stderr: "pipe" });
  if (r.exitCode !== 0) throw new SetupError(`git ${args[0]} failed: ${r.stderr.toString().trim().slice(0, 300)}`);
  return r.stdout;
}

// The pre-commit hook judges what the commit will hold, so an unstaged edit cannot hide a
// staged file the receipt does not cover. Git hands the hook its index (GIT_INDEX_FILE),
// and the git calls here inherit it.
/** The shared folder, compose file and receipt as the index holds them. */
export function readIndex(root = ROOT): Tree {
  const entries = git(root, ["ls-files", "-s", "-z", "--", SHARED, COMPOSE])
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  const blob = (sha: string) => git(root, ["cat-file", "blob", sha]);
  let compose: string | undefined;
  let receipt: string | undefined;
  const groups = new Map<string, { sha256?: string; problem?: string }>();
  const regular = (mode: string) => mode === "100644" || mode === "100755";
  for (const e of entries) {
    // <mode> <object> <stage>\t<path>
    const m = /^(\d{6}) ([0-9a-f]{40,64}) (\d)\t(.+)$/.exec(e);
    if (!m) throw new SetupError("cannot parse the output of git ls-files");
    const [, mode, sha, stage, path] = m;
    if (path === COMPOSE) {
      if (stage !== "0" || !regular(mode)) throw new SetupError(`${COMPOSE} is unmerged or not a regular file in the index`);
      compose = blob(sha).toString("utf8");
      continue;
    }
    const rest = path.slice(SHARED.length + 1).split("/");
    if (rest.length === 1) {
      if (path === RECEIPT) {
        if (stage !== "0" || !regular(mode)) throw new SetupError(`${RECEIPT} is unmerged or not a regular file in the index`);
        receipt = blob(sha).toString("utf8");
      } else if (!regular(mode)) {
        // SECURITY: an ordinary file beside the groups is not a group. A symlink or a
        // submodule is a folder to the manager, holding a config no run has checked.
        groups.set(rest[0], { problem: mode === "120000" ? "is a symlink" : "is not a regular file or a group folder" });
      }
      continue;
    }
    const group = rest[0];
    const g = groups.get(group) ?? {};
    groups.set(group, g);
    if (!GROUP_NAME.test(group)) g.problem = "is not a plain group name";
    else if (stage !== "0") g.problem = "is unmerged in the index";
    else if (rest.length === 2 && rest[1] === CONF) {
      if (!regular(mode)) g.problem ??= `${CONF} is not a regular file in the index`;
      else g.sha256 = sha256(blob(sha));
    }
  }
  if (compose === undefined) throw new SetupError(`${COMPOSE} is not in the index`);
  const list = [...groups].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return {
    compose,
    receipt,
    groups: list.map(([group, g]) => (g.problem || g.sha256 ? { group, ...g } : { group, problem: `has no ${CONF}` })),
  };
}

/** Check every group on the box; on a full pass, write the receipt. */
export function run(o: RunOptions, box: Box = remote): RunResult {
  const root = o.root ?? ROOT;
  const groups = findGroups(root);
  const image = imageOf(readFileSync(join(root, COMPOSE), "utf8"));
  const results = groups.map((g, i) => {
    const staged = `g${i}.conf`;
    return { group: g.group, path: g.path, staged, sha256: g.sha256, verdict: checkOne(box, o.host, image, staged, g.bytes) };
  });
  const kinds = results.map((r) => r.verdict.kind);
  // A rejection is a verdict on a file whatever else broke, so it outranks a setup failure.
  const code = kinds.includes("rejected") ? 1 : kinds.includes("setup") ? 2 : 0;
  if (code !== 0) return { code, image, results };
  // The receipt vouches for the bytes the box checked, so a file saved during the run
  // stops it.
  const now = findGroups(root);
  const same = now.length === groups.length && now.every((g, i) => g.group === groups[i].group && g.sha256 === groups[i].sha256);
  if (!same) return { code: 2, image, results, unwritten: "a group's agent.conf changed while the run was on the box" };
  const target = join(root, RECEIPT);
  const tmp = join(root, SHARED, `.agentconf.verified.${process.pid}`);
  try {
    writeFileSync(tmp, receiptText(image, groups));
    renameSync(tmp, target);
  } catch (e) {
    rmSync(tmp, { force: true });
    return { code: 2, image, results, unwritten: `writing the receipt failed: ${reason(e)}` };
  }
  return { code: 0, image, results };
}

/** One printable line for a checked file. */
export function verdictLine(label: string, path: string, v: Verdict): string {
  if (v.kind === "pass") {
    const w = v.warnings.length ? `, ${v.warnings.length} warning(s): ${v.warnings.join(" | ")}` : "";
    return clean(`PASS ${label} ${path}: verify-agent-conf OK${w}`);
  }
  if (v.kind === "rejected") return clean(`FAIL ${label} ${path}: rejected by verify-agent-conf: ${v.lines.join(" | ")}`);
  const shown = v.lines.length ? `; output: ${v.lines.slice(0, 5).join(" | ")}` : "";
  return clean(`SETUP ${label} ${path}: ${v.why}${shown}`);
}

// ISA ISC-105: a planted pattern ending in a backslash must fail the gate. The setup case
// runs the clean file without internal_options.conf, which must come back as a setup
// failure naming 2301, never a pass and never a rejection.
/** Three checks on the fixtures; true when each ends the way it must. */
export function selfTest(host: string, box: Box = remote, root = ROOT): boolean {
  const read = (name: string) => {
    const p = join(root, FIXTURES, name);
    if (!existsSync(p)) throw new SetupError(`no self-test fixture at ${FIXTURES}/${name}`);
    return readFileSync(p);
  };
  const planted = read("planted-backslash.conf");
  const control = read("clean.conf");
  // A fixture edited out of its shape would prove nothing, so the shapes are checked first.
  if (!/\\<\//.test(planted.toString("utf8"))) throw new SetupError(`${FIXTURES}/planted-backslash.conf has no element text ending in a backslash`);
  if (/\\<\//.test(control.toString("utf8"))) throw new SetupError(`${FIXTURES}/clean.conf has element text ending in a backslash`);
  const image = imageOf(readFileSync(join(root, COMPOSE), "utf8"));
  const a = checkOne(box, host, image, "planted.conf", planted);
  console.log(verdictLine("planted", `${FIXTURES}/planted-backslash.conf`, a));
  const b = checkOne(box, host, image, "clean.conf", control);
  console.log(verdictLine("control", `${FIXTURES}/clean.conf`, b));
  const c = checkOne(box, host, image, "nosetup.conf", control, false);
  console.log(verdictLine("no-setup", `${FIXTURES}/clean.conf`, c));
  const checks: [string, boolean][] = [
    ["planted backslash is rejected with the XML error", a.kind === "rejected" && a.lines.some((l) => XML_ERROR.test(l))],
    ["clean control passes", b.kind === "pass"],
    ["checker without internal_options.conf is a setup failure", c.kind === "setup" && c.lines.some((l) => DEFINITION_MISSING.test(l))],
  ];
  for (const [name, ok] of checks) console.log(`${ok ? "OK  " : "BAD "} self-test ${name}`);
  return checks.every(([, ok]) => ok);
}

// *--- Entry Point ---*

const USAGE = `usage: bun tools/agentconf-check.ts [--host <ssh alias>]     check every group on the box, write the receipt on a pass
       bun tools/agentconf-check.ts --offline [--staged]         compare the receipt to the tree (or the index), no network
       bun tools/agentconf-check.ts --self-test [--host <ssh alias>]`;

if (import.meta.main) {
  const args = Bun.argv.slice(2);
  let host = DEFAULT_HOST;
  let mode: "run" | "offline" | "self-test" = "run";
  let staged = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--host") {
      if (args[i + 1] === undefined) {
        console.error(USAGE);
        process.exit(2);
      }
      host = args[++i];
    } else if (a === "--offline") mode = "offline";
    else if (a === "--staged") staged = true;
    else if (a === "--self-test") mode = "self-test";
    else {
      const help = a === "--help" || a === "-h";
      console.error(help ? USAGE : `agentconf-check: unknown argument: ${clean(a)}\n${USAGE}`);
      process.exit(help ? 0 : 2);
    }
  }
  if (staged && mode !== "offline") {
    console.error(`agentconf-check: --staged goes with --offline\n${USAGE}`);
    process.exit(2);
  }
  if (!SAFE_HOST.test(host)) {
    console.error("agentconf-check: --host must be an ssh alias");
    process.exit(2);
  }
  try {
    if (mode === "offline") {
      const tree = staged ? readIndex() : readWorkingTree();
      const problems = compareReceipt(tree);
      for (const p of problems) console.log(clean(`agentconf-check: ${p}`));
      if (problems.length) {
        console.error(`agentconf-check: ${problems.length} problem(s); the receipt does not cover this ${staged ? "commit" : "tree"}`);
        process.exit(1);
      }
      console.error(`agentconf-check: the receipt covers ${tree.groups.length} group(s) on ${imageOf(tree.compose)}`);
      process.exit(0);
    }
    if (mode === "self-test") process.exit(selfTest(host) ? 0 : 1);
    const out = run({ host });
    for (const r of out.results) console.log(verdictLine(r.group, r.path, r.verdict));
    const count = (k: Verdict["kind"]) => out.results.filter((r) => r.verdict.kind === k).length;
    const tail = out.code === 0 ? `receipt written to ${RECEIPT}` : `receipt left as it was${out.unwritten ? ` (${out.unwritten})` : ""}`;
    console.error(clean(`agentconf-check: ${out.results.length} group(s) on ${out.image}, ${count("rejected")} rejected, ${count("setup")} setup failure(s); ${tail}`));
    process.exit(out.code);
  } catch (e) {
    console.error(`agentconf-check: ${clean(e instanceof SetupError ? e.message : `unexpected ${e instanceof Error ? e.name : "error"}: ${reason(e)}`)}`);
    process.exit(2);
  }
}
