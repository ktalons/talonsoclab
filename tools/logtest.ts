#!/usr/bin/env bun
// *****************************************************************************
// *Title: logtest*
// *Author: Kyle Versluis*
// *Description: Run rule test cases through logtest on a scratch manager.*
// *****************************************************************************

// *--- Imports ---*

import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  cpSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { readSigma } from "./sigma-lint.ts";
import { decodeWinevt } from "./winevt.ts";
import { isPack, readRulesDir, repeatedIds, type WazuhRule } from "./wazuh-rules.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
// SECURITY: the only compose project this tool touches. It has no network, so nothing
// it runs can reach the live indexer, and it never reads the live checkout on the box.
const SCRATCH = "b1test";
const SERVICE = "wazuh.manager";
const DEFAULT_HOST = "talonsoc";
const RULES_DIR = "deploy/soc-recon/wazuh/custom-rules";
const CASES_DIR = "phase-b-detection/tests";
const SIGMA_DIR = "phase-b-detection/sigma";
const LIVE_COMPOSE = "deploy/soc-recon/docker-compose.yml";
const MANAGER_CONF = "deploy/soc-recon/config/wazuh_cluster/wazuh_manager.conf";
const KIT = "tools/logtest";
// The manager image: a literal tag, or one ${NAME:-tag} that compose fills with the tag
// when NAME is unset or empty. Tags follow Docker's reference grammar; group 1 is the
// default, group 2 the literal tag.
const TAG = "[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}";
const MANAGER_IMAGE = new RegExp(`^wazuh/wazuh-manager:(?:\\$\\{[A-Za-z_][A-Za-z0-9_]*:-(${TAG})\\}|(${TAG}))$`);
const SELFTEST = "tools/fixtures/logtest";
const DECODER_DIR = "<decoder_dir>ruleset/decoders</decoder_dir>";
const JSON_EXCLUDE = "<decoder_exclude>ruleset/decoders/0006-json_decoders.xml</decoder_exclude>";
// rule_dir is not recursive, so the staged custom rules load through this element alone.
const CUSTOM_DIR = "<rule_dir>etc/rules/custom</rule_dir>";
// pos.json or pos-<name>.json, so a "positive.json" or "posture.json" is refused, not read.
const CASE_FILE = /^(pos|neg)(?:-[\w.-]+)?\.json$/;
// Why a case fails when its reply names a pack rule the folder under test does not hold.
const FOREIGN = "fired but is not in the rules folder under test";
// SECURITY: the service keys the kit uses, and no others. A key outside the list (build,
// logging, a container name, a capability) is refused, not judged.
const KIT_KEYS = ["image", "hostname", "mem_limit", "network_mode", "environment", "volumes"];
// A "!" where a YAML node can start: at the start of the text or after whitespace (NEL too,
// a YAML line break that \s misses), ":", "-", "[", "{" or ",". Group 1 is the tag.
const YAML_TAG = /(?:^|[\s\u0085:\-[{,])(![^\s\u0085"',[\]{}]{0,40})/;
// A short-form mount, "<source>:<absolute path>" with an optional ":ro"; group 2 is the path.
const MOUNT = /^([^:]+):(\/[^:]*)(?::ro)?$/;
// SECURITY: where each kit source mounts, as tools/logtest/compose.yml has it. A staged
// file or a volume mounted anywhere else (over /var/ossec/bin, say) would replace what the
// manager runs, so the destination is held as well as the source.
const KIT_MOUNTS: Record<string, string> = {
  etc: "/var/ossec/etc",
  logs: "/var/ossec/logs",
  queue: "/var/ossec/queue",
  "./ossec.conf": "/wazuh-config-mount/etc/ossec.conf",
  "./custom-rules": "/wazuh-config-mount/etc/rules/custom",
  "./local_logtest_winevt.xml": "/wazuh-config-mount/etc/decoders/local_logtest_winevt.xml",
};
// Compose reads a source that starts with ".", "/" or "~" as a host path, so a kit volume
// name may not, and a staged file is "./" and one plain name.
const VOLUME_NAME = /^[A-Za-z0-9][\w.-]*$/;
const STAGED_FILE = /^\.\/[A-Za-z0-9][\w.-]*$/;
// SECURITY: the environment keys the kit uses, and no others; LD_PRELOAD and the like
// would load code into the manager.
const KIT_ENV = ["INDEXER_URL", "INDEXER_USERNAME", "INDEXER_PASSWORD", "FILEBEAT_SSL_VERIFICATION_MODE", "API_USERNAME", "API_PASSWORD"];
// SECURITY: the only "$" the kit holds, each once, as KEY=value. Compose fills them from
// the box's .env, which ENV_INIT writes, and ":?" stops compose when one is missing.
const KIT_SECRETS = [
  "INDEXER_PASSWORD=${SCRATCH_INDEXER_PASS:?logtest.ts writes .env first}",
  "API_PASSWORD=${SCRATCH_API_PASS:?logtest.ts writes .env first}",
];
// SECURITY: only rules files reach the box. A rules folder may hold these two besides,
// and both stay on the Mac: Finder's .DS_Store and the repo's .gitkeep.
const RULES_FILE = /^[^.].*\.xml$/i;
const LOCAL_ONLY = new Set([".DS_Store", ".gitkeep"]);
// SECURITY: an ssh alias and never an option. No leading dash, and remote() puts "--"
// before it.
const SAFE_HOST = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/;
// Names sha256sum prints unescaped, so a local list compares to the box's line for line.
const PLAIN_NAME = /^[A-Za-z0-9._/-]+$/;
// SECURITY: a symlink at the scratch folder, its .env or its stage would send the writes
// below somewhere else on the box, so every script that works in the folder checks first.
// The scratch folder or stage being a mount point (another device than its parent) is
// refused too: rm --one-file-system skips mounts under the stage, not the stage itself.
// A stat that fails is a refusal, and no path is printed either way.
const SYMLINKS = `for p in "$HOME/${SCRATCH}" "$HOME/${SCRATCH}/.env" "$HOME/${SCRATCH}/stage"; do if [ -L "$p" ]; then echo "refusing: $(basename "$p") is a symlink" >&2; exit 3; fi; done`;
const MOUNTS = `for p in "$HOME/${SCRATCH}" "$HOME/${SCRATCH}/stage"; do if [ -d "$p" ]; then d=$(stat -c %d "$p" 2>/dev/null) && u=$(stat -c %d "$p/.." 2>/dev/null) || { echo "refusing: cannot stat $(basename "$p")" >&2; exit 3; }; [ "$d" = "$u" ] || { echo "refusing: $(basename "$p") is a mount point" >&2; exit 3; }; fi; done`;
const GUARD = `${SYMLINKS}; ${MOUNTS}`;
// SECURITY: tar reads options from the environment: GNU tar (the box's) TAR_OPTIONS, where
// a checkpoint action can run a command, and libarchive tar (macOS's) TAR_READER_OPTIONS
// and TAR_WRITER_OPTIONS. The local archive runs without them and the box clears them.
const TAR_ENV = ["TAR_OPTIONS", "TAR_READER_OPTIONS", "TAR_WRITER_OPTIONS"];
// SECURITY: compose and docker read these from the environment, so a login profile on the
// box that sets one could point the file-less removal at another daemon, file or project,
// or hand it env files (COMPOSE_ENV_FILES, read when no --env-file is given). A SCRATCH_*
// password set there would win over the .env one, since compose interpolates the shell's
// value first. Every script that runs docker or tar clears them first, and goes on only
// when that worked: unset fails on a variable the profile made readonly, and bash goes on.
const NO_TOOL_ENV = `unset COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PATH_SEPARATOR COMPOSE_PROJECT_NAME COMPOSE_ENV_FILES DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_TLS_VERIFY DOCKER_CERT_PATH SCRATCH_INDEXER_PASS SCRATCH_API_PASS ${TAR_ENV.join(" ")}`;
const IN_SCRATCH = `${GUARD}; ${NO_TOOL_ENV} && cd "$HOME/${SCRATCH}" && grep -qx 'name: ${SCRATCH}' stage/compose.yml`;
const COMPOSE = `docker compose -p ${SCRATCH} -f stage/compose.yml --env-file .env`;
// Every compose call that reads the staged file runs from the scratch folder, behind a
// check that the file names the scratch project; -p pins the project either way.
const DC = `${IN_SCRATCH} && ${COMPOSE}`;
// The scratch passwords are made on the box and never cross argv (run.sh, B.1 spike).
const ENV_INIT = `${GUARD}; mkdir -p "$HOME/${SCRATCH}" && cd "$HOME/${SCRATCH}" && if [ ! -e .env ]; then
  a=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n'); b=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \\n')
  (umask 077 && printf 'SCRATCH_INDEXER_PASS=%s\\nSCRATCH_API_PASS=Sx9.%s\\n' "$a" "$b" >.env); fi`;
// Removal goes by project name alone, from a folder with no compose file (EMPTY_DIR below),
// so it works when the stage is missing or half written. It then checks that nothing of the
// project is left.
const LEFT = `--filter label=com.docker.compose.project=${SCRATCH}`;
// SECURITY: a project of the same name started from any folder but the stage is not this
// tool's, so removal stops (exit 4) before touching it. Compose labels each container with
// its compose file's folder; the box compares it and prints no path.
const NOT_OURS = 4;
const OWNED = `for c in $(docker ps -aq ${LEFT}); do [ "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$c")" = "$HOME/${SCRATCH}/stage" ] || { echo "another folder" >&2; exit ${NOT_OURS}; }; done`;
// SECURITY: compose with no -f looks for a compose file in its working folder and in every
// folder above it. Removal runs from a fresh empty folder inside the scratch folder, the one
// folder it may write in, made after the guard (exit 3), so no folder above it is
// world-writable. The scratch folder holds no compose file (the staged one is in stage/, off
// the walk), and one in any folder above stops the removal (exit 5). The trap removes the
// folder whatever happened, the exit 4 above included; no path is printed.
const COMPOSE_NAMES = "compose.yaml compose.yml docker-compose.yaml docker-compose.yml";
const EMPTY_DIR = `${GUARD}; mkdir -p "$HOME/${SCRATCH}" && d=$(mktemp -d "$HOME/${SCRATCH}/.down.XXXXXX" 2>/dev/null) || { echo "refusing: cannot make an empty folder for the removal" >&2; exit 5; }; trap 'cd / && rmdir "$d" 2>/dev/null' EXIT; cd "$d" || exit 5; p=$d; while :; do for f in ${COMPOSE_NAMES}; do [ -e "$p/$f" ] && { echo "refusing: a compose file sits in a folder above the removal" >&2; exit 5; }; done; [ "$p" = / ] && break; p=$(dirname "$p"); done`;
const DOWN = `${EMPTY_DIR}; ${NO_TOOL_ENV} && ${OWNED} && docker compose -p ${SCRATCH} down -v --remove-orphans && [ -z "$(docker ps -aq ${LEFT})" ] && [ -z "$(docker volume ls -q ${LEFT})" ]`;
// The stage as the box holds it, in manifest()'s format.
const STAGED = `${GUARD}; cd "$HOME/${SCRATCH}/stage" && find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2 && find . ! -type f ! -type d -exec echo "not-a-file  {}" \\; | LC_ALL=C sort`;
const MANAGER = `${IN_SCRATCH} && CID=$(${COMPOSE} ps -q ${SERVICE})`;
// One line about the running container: id|started|image|network|running|project, then
// |<mount> each. The home folder is cut from bind sources, so no box path reaches a message.
// NOTE: a bind mount has no Name key, and Docker 29 makes "{{if .Name}}" a template error
// that empties the whole line (seen 2026-11-06 on the box), so each mount key goes through
// index, which yields the zero value for a key that is not there.
const INSPECT = `${MANAGER} && [ -n "$CID" ] && docker inspect --format '{{.Id}}|{{.State.StartedAt}}|{{.Config.Image}}|{{.HostConfig.NetworkMode}}|{{.State.Running}}|{{index .Config.Labels "com.docker.compose.project"}}{{range .Mounts}}{{$m := .}}|{{$m.Type}} {{with index $m "Name"}}{{.}}{{else}}{{index $m "Source"}}{{end}}{{end}}' "$CID" | sed "s#bind $HOME/#bind ~/#g"`;
// The id and start time again after the cases, or "gone" when no manager is running.
const RECHECK = `${MANAGER} && if [ -n "$CID" ]; then docker inspect --format '{{.Id}}|{{.State.StartedAt}}' "$CID"; else echo gone; fi`;
const OWN_MOUNT = new RegExp(`^(?:volume ${SCRATCH}_[\\w.-]+|bind ~/${SCRATCH}/stage/[\\w./-]+)$`);
// What the manager loaded: the conf and the shim the init copied in, then the custom rules.
const LOADED = `${DC} exec -T ${SERVICE} sh -c 'cd /var/ossec/etc && sha256sum ossec.conf decoders/local_logtest_winevt.xml && cd rules/custom && find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2'`;
// grep exits 1 when it finds nothing, which is the clean answer here.
const BOOT_LOG = `${DC} exec -T ${SERVICE} sh -c 'grep -E "WARNING|ERROR|CRITICAL" /var/ossec/logs/ossec.log; [ $? -le 1 ]'`;

// *--- Types ---*

export interface Case {
  file: string;
  rule: number;
  kind: "pos" | "neg";
  event: string;
}

export interface Result {
  rule?: number;
  level?: number;
  mitre: string[];
  decoder?: string;
  alert: boolean;
  warnings: string[];
}

export interface Verdict {
  case: Case;
  pass: boolean;
  got: string;
  why: string;
}

export interface Outcome {
  code: 0 | 1 | 2;
  verdicts: Verdict[];
  coverage: string[];
  // Pack rule ids held to coverage; cases on stock rules are judged but not counted.
  packRules: number;
}

export interface RunOptions {
  host: string;
  rules: string;
  cases: string;
  sigma: string;
  reuse: boolean;
  keep: boolean;
  save?: string;
  // The kit folder, tools/logtest unless a test points it at a copy.
  kit?: string;
}

/** One command on the box: its exit code, stdout and stderr. The tests pass a fake. */
export type Box = (host: string, script: string, input?: Uint8Array) => { code: number | null; out: string; err: string };

/** A harness or scratch-stack problem: exit 2, never a test verdict. */
export class SetupError extends Error {}

// *--- Helper Functions ---*

const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join() === [...b].sort().join();
const rel = (p: string) => relative(ROOT, p);
const reason = (e: unknown) => (e instanceof Error ? e.message : String(e));
const sha = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");
const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
// ASCII case folding, as strncasecmp and Wazuh's charmap compare.
const fold = (s: string) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

/** How many "$" the strings of a parsed YAML value hold, keys included. */
function dollarsIn(v: unknown): number {
  if (typeof v === "string") return v.split("$").length - 1;
  if (Array.isArray(v)) return v.reduce((n: number, x) => n + dollarsIn(x), 0);
  if (typeof v === "object" && v !== null) return Object.entries(v).reduce((n, [k, x]) => n + dollarsIn(k) + dollarsIn(x), 0);
  return 0;
}

// SECURITY: replies, decoder names and warnings carry event text, which can hold escape
// sequences that redraw the terminal line, a line break that starts a forged verdict line,
// or a bidi control (U+061C, U+200E-U+200F, U+202A-U+202E, U+2066-U+2069) that reorders how
// the line displays. Each of these, tabs and line breaks included, becomes "?".
/** Text made safe to print on one line. */
export function clean(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/g, "?");
}

// A hung ssh is killed after 10 minutes; its null exit code then fails must().
const remote: Box = (host, script, input) => {
  const r = Bun.spawnSync(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "--", host, script], {
    stdin: input ?? "ignore",
    stdout: "pipe",
    stderr: "pipe",
    timeout: 600_000,
  });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString().trim() };
};

function must(r: ReturnType<Box>, what: string) {
  if (r.code !== 0) throw new SetupError(`${what} failed (exit ${r.code})${r.err ? `: ${r.err.slice(0, 400)}` : ""}`);
  return r.out;
}

const NOT_OURS_MSG = `the scratch project name ${SCRATCH} is in use by a project this tool did not stage; nothing was removed`;
/** Why a removal failed, for a run that is already ending; NOT_OURS has its own reason. */
const removalFailed = (r: ReturnType<Box>) => (r.code === NOT_OURS ? NOT_OURS_MSG : `removing the scratch manager failed (exit ${r.code}); run --down`);
/** must() for a removal, where NOT_OURS has its own reason. */
function mustRemove(r: ReturnType<Box>, what: string) {
  if (r.code === NOT_OURS) throw new SetupError(NOT_OURS_MSG);
  must(r, what);
}

// sha256sum's own format and "sort -k2" order, so the box's list compares line for line.
/** Each file under a folder with its SHA-256; a link or device is listed as not-a-file. */
export function manifest(dir: string): string {
  const files: string[] = [];
  const odd: string[] = [];
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      const path = `./${relative(dir, p)}`;
      if (!PLAIN_NAME.test(path)) throw new SetupError(`${rel(p)}: the hash check compares names of letters, digits, dot, dash and underscore only`);
      const st = lstatSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile()) files.push(path);
      else odd.push(path);
    }
  };
  walk(dir);
  return [...files.sort(byText).map((f) => `${sha(join(dir, f))}  ${f}`), ...odd.sort(byText).map((f) => `not-a-file  ${f}`)].join("\n");
}

// SECURITY: cpSync would stage a symlink as a symlink to a Mac path. On the box that
// dangles, or resolves to whatever sits at the same path there.
// A name the hash check cannot compare, and any file but a rules file, is refused here
// too, before the old manager is removed, not after.
function plainFolder(dir: string, what: string) {
  const at = (p: string) => {
    try {
      return lstatSync(p);
    } catch {
      throw new SetupError(`no ${what} folder at ${rel(p)}`);
    }
  };
  const top = at(dir);
  if (top.isSymbolicLink()) throw new SetupError(`the ${what} folder ${rel(dir)} is a symlink`);
  if (!top.isDirectory()) throw new SetupError(`${rel(dir)} is not a folder`);
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) throw new SetupError(`${rel(p)} is a symlink, which the box cannot follow`);
      if (!PLAIN_NAME.test(`./${relative(dir, p)}`))
        throw new SetupError(
          `the ${what} folder ${rel(dir)} holds ${JSON.stringify(relative(dir, p))}, a name the hash check cannot compare (letters, digits, dot, dash and underscore only)`,
        );
      // SECURITY: a folder under a LOCAL_ONLY name would leave the stage with every rules
      // file in it, and no check would see them go.
      if (st.isDirectory() && LOCAL_ONLY.has(name))
        throw new SetupError(`the ${what} folder ${rel(dir)} holds the folder ${JSON.stringify(relative(dir, p))}, a name the copy keeps off the box`);
      if (!st.isDirectory() && !LOCAL_ONLY.has(name) && !(st.isFile() && RULES_FILE.test(name)))
        throw new SetupError(`the ${what} folder ${rel(dir)} holds ${JSON.stringify(relative(dir, p))}, which is not an .xml rules file`);
      if (st.isDirectory()) walk(p);
    }
  };
  walk(dir);
}

// os_xml skips "<!--" to the first "-->" after it. Each comment becomes one space, so the
// text on either side never joins into an element the manager would not read. Any other
// "<!" or "<?" is refused: the manager may skip it too, and this check cannot tell.
/** XML text with every comment blanked, and each comment's span in the original; an open comment or other "<!" is a setup error. */
function uncommented(xml: string, file: string): { bare: string; comments: [number, number][] } {
  let out = "";
  let from = 0;
  const comments: [number, number][] = [];
  for (let at = xml.indexOf("<!--"); at !== -1; at = xml.indexOf("<!--", from)) {
    const end = xml.indexOf("-->", at + 4);
    if (end === -1) throw new SetupError(`${file} has a comment that never closes`);
    out += `${xml.slice(from, at)} `;
    from = end + 3;
    comments.push([at, from]);
  }
  out += xml.slice(from);
  if (/<[!?]/.test(out)) throw new SetupError(`${file} holds "<!" or "<?" outside a comment, which the manager may skip as one`);
  return { bare: out, comments };
}

// SECURITY: the shim decodes a line that opens {"win":{"system": as a Windows event without
// the port (winevt.ts), so its backslashes and quirks are not live's; a win object the json
// decoder takes instead never reaches a Windows rule. Either way the case means nothing live.
/** Whether event text is a Windows event: it opens like one, or is JSON with a top-level win key. */
function windowsEvent(event: string): boolean {
  if (event.replace(/\s/g, "").startsWith('{"win":')) return true;
  try {
    const v = JSON.parse(event);
    return typeof v === "object" && v !== null && !Array.isArray(v) && Object.hasOwn(v, "win");
  } catch {
    return false;
  }
}

// SECURITY: Finder's .DS_Store is a file. A folder of that name in the cases tree would be
// skipped with every case in it, unseen, so it is refused, as the rules folder refuses one.
/** Whether a .DS_Store entry in the cases tree may be skipped; a folder is a setup error. */
function finderFile(p: string): boolean {
  if (statSync(p).isDirectory()) throw new SetupError(`${rel(p)} is a folder, and the case reader skips only a .DS_Store file`);
  return true;
}

/** The first ERROR and CRITICAL lines of a compose boot log, as a suffix for a setup error. */
export function bootErrors(log: string): string {
  const lines = log
    .split("\n")
    .filter((l) => /\b(ERROR|CRITICAL)\b/.test(l))
    .map((l) => l.replace(/^[\w.-]+\s+\|\s/, "").trim());
  const first = [...new Set(lines)].slice(0, 5);
  return first.length ? `:\n${first.join("\n")}` : "";
}

// *--- Core Logic ---*

/** The live manager conf with the stock json decoders excluded, so the shim decodes first. */
export function scratchConf(live: string): string {
  const { bare, comments } = uncommented(live, MANAGER_CONF);
  const all = bare.split(CUSTOM_DIR).length - 1;
  const inside = [...bare.matchAll(/<ruleset>([\s\S]*?)<\/ruleset>/g)].reduce((n, m) => n + m[1].split(CUSTOM_DIR).length - 1, 0);
  if (all !== 1 || inside !== 1)
    throw new SetupError(`${MANAGER_CONF} must load the custom rules: ${CUSTOM_DIR} once inside <ruleset>, outside any comment (found ${all}, ${inside} inside <ruleset>)`);
  // The manager never reads a decoder_dir inside a comment, so the exclusion goes after the
  // one outside every comment, and a commented copy beside it is left as it was.
  const ends: number[] = [];
  for (let at = live.indexOf(DECODER_DIR); at !== -1; at = live.indexOf(DECODER_DIR, at + 1)) {
    if (!comments.some(([from, to]) => at >= from && at < to)) ends.push(at + DECODER_DIR.length);
  }
  if (ends.length !== 1) throw new SetupError(`${MANAGER_CONF} must hold ${DECODER_DIR} once outside any comment (found ${ends.length})`);
  if (live.includes(JSON_EXCLUDE)) throw new SetupError(`${MANAGER_CONF} already excludes the stock json decoders`);
  return `${live.slice(0, ends[0])}\n    ${JSON_EXCLUDE}${live.slice(ends[0])}`;
}

// Parsed, never scanned: a comment, a block scalar or another service can hold
// image-shaped text, and compose runs the manager service's own image key.
/** The manager image tag a compose file names, with a ${VAR:-default} reduced to its default. */
export function managerImage(compose: string, file = "the compose file"): string {
  let doc: any;
  try {
    doc = Bun.YAML.parse(compose);
  } catch {
    throw new SetupError(`${file} is not YAML`);
  }
  const mapping = (v: unknown) => typeof v === "object" && v !== null && !Array.isArray(v);
  const svc = mapping(doc) && mapping(doc.services) ? doc.services[SERVICE] : undefined;
  if (!mapping(svc)) throw new SetupError(`${file} has no ${SERVICE} service`);
  if (svc.image == null) throw new SetupError(`${file}: ${SERVICE} has no image`);
  const m = typeof svc.image === "string" ? MANAGER_IMAGE.exec(svc.image) : null;
  if (!m) throw new SetupError(`${file}: ${SERVICE} image ${JSON.stringify(svc.image).slice(0, 160)} is not wazuh/wazuh-manager:<tag> or wazuh/wazuh-manager:\${NAME:-<tag>}`);
  return m[1] ?? m[2];
}

// NOTE: this compares two files in the repo. The live compose's default tag stands in for
// what live runs, because this tool never reads the live project (tools/README.md).
/** The kit's image tag, refused unless it is the live compose file's default. */
export function kitImage(kitCompose: string, liveCompose: string): string {
  const live = managerImage(liveCompose, LIVE_COMPOSE);
  const kit = managerImage(kitCompose, `${KIT}/compose.yml`);
  if (kit !== live) throw new SetupError(`${KIT}/compose.yml is on ${kit}, not the live compose default ${live}`);
  return kit;
}

// SECURITY: the kit is what "scratch only" rests on, so an edit that gives it a network,
// a port or storage of its own choosing stops the run before anything is staged.
/** Refuse a kit compose that is not the scratch project with no network and only its own storage. */
export function checkKit(compose: string): void {
  const bad = (why: string) => new SetupError(`${KIT}/compose.yml ${why}`);
  // SECURITY: Bun.YAML drops tags, so "network_mode: !reset none" reads as "none" while
  // compose's !reset removes the key. Quoted text is not exempt: a quote tracker short of a
  // YAML tokenizer misreads a ' inside a block scalar and would hide a later real tag.
  const tag = YAML_TAG.exec(compose)?.[1];
  if (tag) throw bad(`must not use the YAML tag ${tag}; compose acts on tags, which this check never sees`);
  let doc: any;
  try {
    doc = Bun.YAML.parse(compose);
  } catch {
    throw bad("is not YAML");
  }
  if (typeof doc !== "object" || doc === null) throw bad("is not a mapping");
  if (doc.name !== SCRATCH) throw bad(`must name the project ${SCRATCH}`);
  for (const k of Object.keys(doc)) if (!["name", "services", "volumes"].includes(k)) throw bad(`must not set ${k}`);
  if (Object.keys(doc.services ?? {}).join() !== SERVICE) throw bad(`must hold the one service ${SERVICE}`);
  const svc = doc.services[SERVICE] ?? {};
  for (const k of Object.keys(svc)) if (!KIT_KEYS.includes(k)) throw bad(`must not set ${k}`);
  if (svc.network_mode !== "none") throw bad("must set network_mode: none");
  // managerImage reduces ${NAME:-tag} to its tag, but on the box compose would fill NAME
  // from the box's environment, so the kit's image key must be the literal tag.
  const image = `wazuh/wazuh-manager:${managerImage(compose, `${KIT}/compose.yml`)}`;
  if (svc.image !== image) throw bad(`image ${svc.image} is not ${image}`);
  // Compose takes the environment as KEY=value lines or as a mapping. A line with no "="
  // reads as a key with no value (null), like a mapping key with nothing after it.
  const env = svc.environment;
  let pairs: [string, unknown][] = [];
  if (Array.isArray(env) && env.every((e) => typeof e === "string"))
    pairs = env.map((e: string) => (e.includes("=") ? [e.slice(0, e.indexOf("=")), e.slice(e.indexOf("=") + 1)] : [e, null]));
  else if (typeof env === "object" && env !== null && !Array.isArray(env)) pairs = Object.entries(env);
  else if (env !== undefined) throw bad("environment must be a list or a mapping");
  for (const [k, v] of pairs) {
    if (!KIT_ENV.includes(k)) throw bad(`must not set environment.${k}`);
    // SECURITY: compose fills a key with no value from the box's own environment, which
    // nothing here checks and which can hold a line break, so every key needs its value.
    if (v == null) throw bad(`environment.${k} has no value; compose would take it from the box's environment`);
    if (/[\r\n]/.test(String(v))) throw bad(`environment.${k} must be one line`);
  }
  // SECURITY: compose fills ${VAR} and $VAR from the box's environment and reads $$ as "$",
  // so the kit holds exactly the "$" of KIT_SECRETS, each once as a whole entry. The text
  // and the parsed strings are both counted: a comment hides a "$" from the parser, and an
  // alias or an escape makes one the text does not show.
  const entries = pairs.map(([k, v]) => `${k}=${v}`);
  const once = KIT_SECRETS.every((s) => entries.filter((e) => e === s).length === 1);
  if (!once || compose.split("$").length - 1 !== KIT_SECRETS.length || dollarsIn(doc) !== KIT_SECRETS.length)
    throw bad("must hold no $ but the two scratch password values, each once on its own key; compose would fill it from the box's environment");
  const named = Object.keys(doc.volumes ?? {});
  for (const n of named) {
    if (!VOLUME_NAME.test(n)) throw bad(`volume ${n} is not a plain volume name`);
    if (doc.volumes[n] != null) throw bad(`volume ${n} must be a plain named volume`);
  }
  if (svc.volumes !== undefined && !Array.isArray(svc.volumes)) throw bad("volumes must be a list");
  for (const v of svc.volumes ?? []) {
    if (typeof v !== "string") throw bad("mounts must be short-form <source>:<path> lines");
    const [, src = "", dest = ""] = MOUNT.exec(v) ?? [];
    const staged = STAGED_FILE.test(src) && !src.includes("..");
    if (!named.includes(src) && !staged) throw bad("mounts something that is neither its own volume nor a staged file");
    if (!Object.hasOwn(KIT_MOUNTS, src)) throw bad(`mounts ${src}, which the kit does not mount`);
    if (dest !== KIT_MOUNTS[src]) throw bad(`mounts ${src} at ${dest}, not at ${KIT_MOUNTS[src]}`);
  }
}

// One case per file: <dir>/<rule id>/{pos,neg}-<name>.json holding {"capture": {...}} from
// winevt-capture.ts, or {"event": "<one log line>"} for anything that is not Windows.
/** Read and decode every case under a folder; anything malformed is a setup error. */
export function loadCases(dir: string): Case[] {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new SetupError(`no cases folder at ${rel(dir)}`);
  const out: Case[] = [];
  for (const sub of readdirSync(dir).sort()) {
    const subPath = join(dir, sub);
    if (sub === ".DS_Store" && finderFile(subPath)) continue;
    if (!/^\d+$/.test(sub) || !statSync(subPath).isDirectory()) throw new SetupError(`${rel(subPath)} is not a rule id folder`);
    for (const name of readdirSync(subPath).sort()) {
      const file = join(subPath, name);
      if (name === ".DS_Store" && finderFile(file)) continue;
      const kind = CASE_FILE.exec(name)?.[1] as "pos" | "neg" | undefined;
      if (!kind) throw new SetupError(`${rel(file)} is not named pos-<name>.json or neg-<name>.json`);
      let body: { capture?: unknown; event?: unknown };
      try {
        body = JSON.parse(readFileSync(file, "utf8"));
      } catch {
        throw new SetupError(`${rel(file)} is not JSON`);
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) throw new SetupError(`${rel(file)} is not a JSON object`);
      let event = body.event;
      if (body.capture !== undefined) {
        // The decoder refuses what it cannot port; that is a bad case file, not a verdict.
        try {
          event = JSON.stringify(decodeWinevt(body.capture as Parameters<typeof decodeWinevt>[0]));
        } catch (e) {
          throw new SetupError(`${rel(file)}: the capture does not decode: ${reason(e)}`);
        }
      } else if (typeof event === "string" && windowsEvent(event)) {
        throw new SetupError(`${rel(file)}: an event case holds a Windows event, which the shim decodes without the port; use capture for Windows events`);
      }
      if (typeof event !== "string" || !event) throw new SetupError(`${rel(file)} holds neither a capture nor an event`);
      if (/[\r\n]/.test(event)) throw new SetupError(`${rel(file)}: wazuh-logtest reads one event per line`);
      out.push({ file: rel(file), rule: Number(sub), kind, event });
    }
  }
  if (!out.length) throw new SetupError(`no cases under ${rel(dir)}`);
  return out;
}

// wazuh-logtest -d logs each raw socket reply as one "Reply: {json}" line (stderr), so the
// verdict reads analysisd's own answer, never the human-formatted phases.
// SECURITY: event text is attacker-shaped, and the line anchor alone does not keep it
// out. The CLI prints a decoded field raw, so the second line of a multi-line value starts
// at column 0 and can be a whole logger-shaped Reply line. What binds a reply to this run
// is the session token. Every event is on stdin before analysisd picks it, the first
// Reply line is logged before any raw event text (the Request line ahead of it carries
// the event JSON-escaped on one line), and every later reply must repeat it.
// The body is [^\n]* and not ".", which stops at U+2028 and U+2029 and would drop a
// real reply that carries one.
const REPLY = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} [\w.-]+\[DEBUG\] Reply: (\{[^\n]*\})\s*$/;

/** One result per event, from the CLI's debug transcript. */
export function parseReplies(transcript: string): Result[] {
  const out: Result[] = [];
  let session: string | undefined;
  for (const line of transcript.split("\n")) {
    const m = REPLY.exec(line);
    if (!m) continue;
    let reply: {
      error?: number;
      message?: string;
      data?: { codemsg?: number; alert?: boolean; messages?: string[]; token?: unknown; output?: Record<string, any> };
    };
    try {
      reply = JSON.parse(m[1]);
    } catch {
      throw new SetupError(`a logtest reply did not parse: ${m[1].slice(0, 120)}`);
    }
    if (reply.error || !reply.data) throw new SetupError(`logtest error ${reply.error}: ${reply.message}`);
    const d = reply.data;
    if ((d.codemsg ?? 0) < 0) throw new SetupError(`logtest refused an event: ${(d.messages ?? []).join("; ")}`);
    if (typeof d.token !== "string" || !d.token) throw new SetupError("a logtest reply carries no session token");
    session ??= d.token;
    if (d.token !== session) throw new SetupError("a Reply line carries another session's token: event text shaped like a reply");
    const rule = d.output?.rule;
    const ids = rule?.mitre?.id;
    out.push({
      rule: rule ? Number(rule.id) : undefined,
      level: rule ? Number(rule.level) : undefined,
      mitre: Array.isArray(ids) ? ids.map(String) : [],
      decoder: d.output?.decoder?.name,
      alert: d.alert === true,
      warnings: (d.messages ?? []).filter((x) => String(x).startsWith("WARNING")),
    });
  }
  return out;
}

// OS_WordMatch (os_regex_match.c 32-121): the pattern splits on "|"; a piece that starts
// "^" is a case-insensitive prefix of the group text, any other a case-insensitive
// substring, and "$" is literal. An empty pattern matches nothing. An empty piece is taken
// as a match, so an error fails a negative rather than passing one. if_matched_group also
// goes through OSMatch (rules_list.c 536), so there a trailing "$" may anchor the end too.
/** Whether a parent pattern names a rule's group text. */
function groupLink(pattern: string, group: string, matched: boolean): boolean {
  if (!pattern) return false;
  const text = fold(group);
  const pieces = fold(pattern).split("|");
  return pieces.some((piece) => {
    if (!piece) return true;
    const head = piece.startsWith("^");
    const body = head ? piece.slice(1) : piece;
    if (head ? text.startsWith(body) : text.includes(body)) return true;
    const core = body.slice(0, -1);
    return matched && body.endsWith("$") && (head ? text === core : text.endsWith(core));
  });
}

// A rule hangs from an id by if_sid or if_matched_sid, from every rule whose group text
// its if_group or if_matched_group names (rules.c 988-1017, 1662-1678; rules_list.c 72-80),
// and by if_level N from every other rule of level N or more (rules_list.c 82-89). Levels
// are compared while a level-0 rule still reads as 99 (rules.c 393-404). Groups and levels
// are known for rules in the folder only, so neither link reaches a stock rule. All five
// are followed even where Wazuh places a rule by one alone: a superset.
/** The ids a rule in the folder may hang from. */
function parents(r: WazuhRule, rules: Map<number, WazuhRule>): number[] {
  const out = r.ifSid.map(Number);
  if (r.ifMatchedSid) out.push(r.ifMatchedSid);
  for (const [id, x] of rules) {
    const byLevel = r.ifLevel !== undefined && (x.level || 99) >= r.ifLevel;
    if (byLevel || groupLink(r.ifGroup, x.group, false) || groupLink(r.ifMatchedGroup, x.group, true)) out.push(id);
  }
  return out;
}

// An event that matched A and then a child of A ends on the child, so a negative for A
// looks past the final rule. The walk starts from any rule in the folder under test, pack
// or not, and climbs every parent link through that folder only: a stock id outside it
// ends the walk, since its own parents are not known here. A visited set ends a loop.
/** Whether the final rule descends from another through parent links in the folder. */
function descends(final: number, ancestor: number, rules: Map<number, WazuhRule>): boolean {
  if (!rules.has(final)) return false;
  const seen = new Set([final]);
  const todo = [final];
  for (let id = todo.pop(); id !== undefined; id = todo.pop()) {
    const rule = rules.get(id);
    for (const p of rule ? parents(rule, rules) : []) {
      if (p === ancestor) return true;
      if (rules.has(p) && !seen.has(p)) {
        seen.add(p);
        todo.push(p);
      }
    }
  }
  return false;
}

// A negative fails when its rule is the final one or an ancestor of it (descends above).
// A positive passes only when its rule is the final one and it alerted; for a rule in the
// XML under test, the level and MITRE IDs must also be what the XML says. A stock rule
// passes on id and alert alone, but a pack id the folder lacks fails any case it fires
// on: that rule was loaded from somewhere else, such as a manager kept with --reuse.
// A logtest warning fails the case it rides on, whatever the case: ruleset warnings
// arrive on the first reply, and the first case is usually a negative.
/** Judge each case against its result. */
export function evaluate(cases: Case[], results: Result[], rules: Map<number, WazuhRule>): Verdict[] {
  if (results.length !== cases.length) throw new SetupError(`${cases.length} events sent, ${results.length} replies read`);
  return cases.map((c, i) => {
    const r = results[i];
    const got = `${r.rule ?? "no rule"} L${r.level ?? "-"} [${r.mitre.join(",")}] via ${r.decoder ?? "no decoder"}`;
    const why: string[] = [];
    if (c.kind === "neg" && r.rule === c.rule) why.push(`rule ${c.rule} fired`);
    if (c.kind === "neg" && r.rule !== undefined && r.rule !== c.rule && descends(r.rule, c.rule, rules))
      why.push(`rule ${c.rule} fired (final rule ${r.rule} descends from it)`);
    if (c.kind === "pos" && r.rule !== c.rule) why.push(`expected rule ${c.rule}`);
    if (r.rule !== undefined && isPack(r.rule) && !rules.has(r.rule)) why.push(`pack rule ${r.rule} ${FOREIGN}`);
    // A rule that fires without an alert (level 0, no_log) never reaches the indexer.
    if (c.kind === "pos" && r.rule === c.rule && !r.alert) why.push(`rule ${c.rule} fired with no alert`);
    const x = rules.get(c.rule);
    if (c.kind === "pos" && r.rule === c.rule && x) {
      if (r.level !== x.level) why.push(`XML level is ${x.level}`);
      if (!sameSet(r.mitre, x.mitre)) why.push(`XML mitre is [${x.mitre.join(",")}]`);
    }
    why.push(...r.warnings);
    return { case: c, pass: why.length === 0, got, why: why.join("; ") };
  });
}

// ISA ISC-121: every pack rule the XML or the Sigma YAML names must fire in a passing
// positive and have a negative. A file in a subfolder (never loaded) fails on its own as
// well, because a copy of a loaded rule's id would otherwise ride on that rule's cases.
// So does a case folder for a pack id nothing under test names, whose negatives would pass
// on any other rule; a stock-rule folder such as 92900 is judged without coverage.
/** Problems with pack coverage, one line each. */
export function coverage(verdicts: Verdict[], expected: number[], skippedFiles: string[] = []): string[] {
  const out = skippedFiles.map((f) => `${f}: XML in a subfolder, which the manager never loads`);
  const orphans = new Map(verdicts.filter((v) => isPack(v.case.rule) && !expected.includes(v.case.rule)).map((v) => [v.case.rule, dirname(v.case.file)]));
  for (const [id, folder] of [...orphans].sort(([a], [b]) => a - b)) out.push(`${folder}: cases for pack rule ${id}, which is in neither the rules folder nor the Sigma YAML`);
  for (const id of [...new Set(expected)].sort((a, b) => a - b)) {
    const mine = verdicts.filter((v) => v.case.rule === id);
    const pos = mine.filter((v) => v.case.kind === "pos");
    if (!pos.length) out.push(`rule ${id}: no positive case`);
    else if (!pos.some((v) => v.pass)) out.push(`rule ${id}: never fired in a positive case`);
    if (!mine.some((v) => v.case.kind === "neg")) out.push(`rule ${id}: no negative case`);
  }
  return out;
}

// SECURITY: cpSync copies a symlink as a symlink, and on the box compose would mount
// whatever the link names there. O_NOFOLLOW refuses a link rather than follow it, one
// swapped in after a check included, and O_NONBLOCK refuses a FIFO rather than wait on it.
/** A kit file's bytes; a symlink or anything but a file is a setup error. */
function kitFile(kit: string, name: string): Buffer {
  const path = join(kit, name);
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === "ELOOP") throw new SetupError(`the kit file ${rel(path)} is a symlink, and kit files are staged from their own bytes`);
    throw new SetupError(`the kit file ${rel(path)} cannot be opened: ${code ?? reason(e)}`);
  }
  try {
    if (!fstatSync(fd).isFile()) throw new SetupError(`the kit file ${rel(path)} is not a file`);
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}

// Built on the Mac, then copied whole; the box's old stage folder is replaced, so a rule
// file removed here cannot linger there. The kit files are written from their own bytes.
function stage(rulesDir: string, kit = resolve(ROOT, KIT)): string {
  const kitCompose = kitFile(kit, "compose.yml").toString("utf8");
  const shim = kitFile(kit, "local_logtest_winevt.xml");
  checkKit(kitCompose);
  kitImage(kitCompose, readFileSync(resolve(ROOT, LIVE_COMPOSE), "utf8"));
  const dir = mkdtempSync(join(tmpdir(), "logtest-"));
  try {
    writeFileSync(join(dir, "compose.yml"), kitCompose);
    writeFileSync(join(dir, "local_logtest_winevt.xml"), shim);
    writeFileSync(join(dir, "ossec.conf"), scratchConf(readFileSync(resolve(ROOT, MANAGER_CONF), "utf8")));
    // Files only: a folder of such a name is copied, so the staged check still refuses it.
    cpSync(rulesDir, join(dir, "custom-rules"), { recursive: true, filter: (p) => !LOCAL_ONLY.has(basename(p)) || lstatSync(p).isDirectory() });
    return dir;
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
}

// WARN: without COPYFILE_DISABLE, macOS tar adds a "._name" entry for every file with an
// extended attribute. One of those in custom-rules is read as a rules file, analysisd
// exits on it, and the logtest socket never opens.
/** The staged folder as one tar stream for the box. */
export function packStage(dir: string): Uint8Array {
  const env: Record<string, string | undefined> = { ...process.env, COPYFILE_DISABLE: "1" };
  for (const k of TAR_ENV) delete env[k];
  const tar = Bun.spawnSync(["tar", "-C", dir, "-cf", "-", "."], { stdout: "pipe", stderr: "pipe", env });
  if (tar.exitCode !== 0) throw new SetupError(`tar failed: ${tar.stderr.toString()}`);
  return tar.stdout;
}

// verify() pins the box to the stage, so the verdicts, coverage and descent walk read the
// staged copy: a file saved in the source folder after the copy changes neither. The folder
// checks run on the copy too, since anything added before the copy is in it. Files keep the
// source folder's names, so a message points at a file that can be opened.
/** The staged rules, read as the manager will load them; anything run() refuses throws. */
export function stagedRules(dir: string, source: string): ReturnType<typeof readRulesDir> {
  const staged = join(dir, "custom-rules");
  plainFolder(staged, "staged rules");
  let tree: ReturnType<typeof readRulesDir>;
  try {
    tree = readRulesDir(staged, ROOT, source);
  } catch (e) {
    throw new SetupError(`reading the rules: ${reason(e)}`);
  }
  // The id map run() builds holds one copy of each id, but Wazuh places a repeated id by its
  // first copy and takes a later overwrite's group and level, so a child hung under the first
  // copy would drop out of the walk and its parent's negative could pass.
  const [twice] = repeatedIds(tree.rules);
  if (twice) {
    const [id, defs] = twice;
    throw new SetupError(`rule ${id} is defined ${defs.length} times (${defs.map((r) => r.file).join(", ")}), which the walk cannot judge; sigma-lint refuses it too`);
  }
  return tree;
}

// The old manager and its volumes go first: the etc volume outlives a recreate, and init
// copies files in without ever deleting, so a fresh volume is the only way to drop a rule
// removed from the tree. Removing before the stage is replaced also means a failed
// staging never leaves a manager up that nothing can take down.
function deploy(box: Box, host: string, dir: string) {
  mustRemove(box(host, DOWN), "removing the old scratch manager");
  // SECURITY: --one-file-system (GNU rm, the box's) does not descend into a mount at the
  // stage, so a bind mount there cannot turn the stage reset into a wider delete.
  must(box(host, `${ENV_INIT} && ${NO_TOOL_ENV} && rm -rf --one-file-system -- stage && mkdir stage && tar -xf - -C stage`, packStage(dir)), "staging on the box");
  must(box(host, `${DC} up -d --force-recreate ${SERVICE}`), "starting the scratch manager");
  const wait = box(
    host,
    `${DC} exec -T ${SERVICE} sh -c 'for i in $(seq 1 60); do test -S /var/ossec/queue/sockets/logtest && exit 0; sleep 5; done; exit 1'`,
  );
  // No socket means analysisd never came up; its reason is in the boot log, which the
  // caller's removal is about to delete.
  if (wait.code !== 0) throw new SetupError(`the logtest socket did not open in 5 minutes${bootErrors(box(host, `${DC} logs --no-color ${SERVICE}`).out)}`);
}

// Runs before the cases on every run, so --reuse skips the restart and nothing else: the
// stage on the box, the container's settings, the files the manager loaded and its boot
// log must all be this tree's, whoever started the manager.
/** Check the scratch manager is this tree's; returns its id and start time, to recheck. */
function verify(box: Box, host: string, dir: string): string {
  const staged = must(box(host, STAGED), "hashing the stage on the box");
  if (staged.trim() !== manifest(dir)) throw new SetupError("the stage on the box is not the kit and rules under test");

  const [id, started, image, net, running, project, ...mounts] = must(box(host, INSPECT), "inspecting the scratch manager").trim().split("|");
  if (!id || !started) throw new SetupError("the scratch manager has no container id or start time");
  const want = `wazuh/wazuh-manager:${managerImage(readFileSync(join(dir, "compose.yml"), "utf8"))}`;
  if (image !== want) throw new SetupError(`the scratch manager runs ${image || "an unknown image"}, not ${want}`);
  if (net !== "none" || running !== "true" || project !== SCRATCH) throw new SetupError("the scratch manager is not running with no network in the scratch project");
  const foreign = mounts.filter((m) => !OWN_MOUNT.test(m) || m.includes(".."));
  if (!mounts.length || foreign.length) throw new SetupError(`the scratch manager mounts storage outside the scratch project: ${foreign.join(", ") || "no mount listed"}`);

  const loaded = must(box(host, LOADED), "hashing what the scratch manager loaded");
  const mine = [
    `${sha(join(dir, "ossec.conf"))}  ossec.conf`,
    `${sha(join(dir, "local_logtest_winevt.xml"))}  decoders/local_logtest_winevt.xml`,
    manifest(join(dir, "custom-rules")),
  ];
  if (loaded.trim() !== mine.filter(Boolean).join("\n")) throw new SetupError("the scratch manager's conf, decoder or rules differ from the tree under test");

  const logs = must(box(host, `${DC} logs --no-color ${SERVICE}`), "reading the boot log");
  if (!logs.includes("0-wazuh-init: exited 0")) throw new SetupError("the scratch init did not exit 0");
  // A clean boot logs nothing from analysisd at these levels (probe, 2026-11-06); what it
  // does log there is about the ruleset: a duplicate id, an unknown parent, a bad file.
  const lines = must(box(host, BOOT_LOG), "reading ossec.log").split("\n");
  const bad = lines.filter((l) => /analysisd|rule|decoder|xml/i.test(l));
  if (bad.length) throw new SetupError(`ossec.log reports ruleset problems:\n${bad.slice(0, 5).join("\n")}`);
  return `${id}|${started}`;
}

/** Stage, start the scratch manager, run every case and judge it. */
export function run(o: RunOptions, box: Box = remote): Outcome {
  const cases = loadCases(o.cases);
  // SECURITY: checked before the copy as well as after it (stagedRules), because cpSync
  // would stage a symlink in the folder as a symlink.
  plainFolder(o.rules, "rules");
  // readSigma throws on a YAML it cannot read or one in a subfolder, and hands back a
  // multi-document file as an array and an empty one as null. Any of these could hide a
  // pack id, so each stops the run rather than shrinking what coverage expects. An id
  // that is present must be a plain whole number, as sigma-lint requires; Number() would
  // also read a one-element list or a quoted id.
  let sigma: number[];
  try {
    sigma = readSigma(o.sigma).map((s) => {
      if (typeof s.doc !== "object" || s.doc === null || Array.isArray(s.doc)) throw new Error(`${s.file}: not one mapping (a multi-document or empty file)`);
      const wazuh = s.doc.custom?.wazuh;
      if (typeof wazuh !== "object" || wazuh === null || !("id" in wazuh)) return Number.NaN;
      if (typeof wazuh.id !== "number") throw new Error(`${s.file}: custom.wazuh.id is not a number`);
      if (!Number.isInteger(wazuh.id)) throw new Error(`${s.file}: custom.wazuh.id is not a whole number`);
      return wazuh.id;
    });
  } catch (e) {
    throw new SetupError(`reading the Sigma YAML: ${reason(e)}`);
  }
  sigma = sigma.filter((id) => Number.isInteger(id) && isPack(id));
  const dir = stage(o.rules, o.kit);
  // Every refusal here still comes before the box is touched; only the local stage is removed.
  let tree: ReturnType<typeof readRulesDir>;
  try {
    tree = stagedRules(dir, o.rules);
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
  const rules = new Map(tree.rules.map((r) => [r.id, r]));
  const expected = [...tree.rules, ...tree.skippedRules].map((r) => r.id).filter(isPack).concat(sigma);
  let judged = false;
  try {
    if (!o.reuse) deploy(box, o.host, dir);
    const pinned = verify(box, o.host, dir);
    const events = new TextEncoder().encode(`${cases.map((c) => c.event).join("\n")}\n`);
    const r = box(o.host, `${DC} exec -T ${SERVICE} /var/ossec/bin/wazuh-logtest -d 2>&1`, events);
    // Saved raw on purpose, control characters and all: the file is the evidence, and
    // clean() is only for what reaches the terminal.
    if (o.save) writeFileSync(o.save, r.out);
    // Nothing locks the scratch project, so another run can swap the manager between the
    // checks and the cases. A new id or start time means these replies are not this tree's.
    const now = must(box(o.host, RECHECK), "inspecting the scratch manager after the cases").trim();
    if (now !== pinned) throw new SetupError("the scratch manager changed while the cases ran: another run swapped it");
    // wazuh-logtest exits 0 at the end of stdin (probe, 2026-11-06), so anything else is
    // a broken run even when the transcript looks whole.
    if (r.code !== 0) throw new SetupError(`wazuh-logtest exited ${r.code}${r.err ? `: ${r.err.slice(0, 400)}` : ""}`);
    const verdicts = evaluate(cases, parseReplies(r.out), rules);
    const cov = coverage(verdicts, expected, tree.skippedFiles);
    const code = verdicts.every((v) => v.pass) && !cov.length ? 0 : 1;
    const out: Outcome = { code, verdicts, coverage: cov, packRules: new Set(expected).size };
    judged = true;
    return out;
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (!o.keep) {
      const down = box(o.host, DOWN);
      if (down.code !== 0) {
        const msg = removalFailed(down);
        // A run that leaves the manager behind is not a clean result. When another
        // error is already on its way out, this one is added beside it.
        if (judged) throw new SetupError(msg);
        console.error(`logtest: ${msg}`);
      }
    }
  }
}

function report(o: Outcome) {
  for (const v of o.verdicts) {
    const tail = v.pass ? v.got : `${v.got}: ${v.why}`;
    console.log(clean(`${v.pass ? "PASS" : "FAIL"} ${v.case.kind} ${v.case.rule} ${v.case.file}: ${tail}`));
  }
  for (const c of o.coverage) console.log(clean(`FAIL coverage ${c}`));
  const failed = o.verdicts.filter((v) => !v.pass).length + o.coverage.length;
  console.error(`logtest: ${o.verdicts.length} case(s), ${o.packRules} pack rule(s) under test, ${failed} failure(s)`);
}

// ISA ISC-122: a planted flip must fail the run, for the expectation and for the rule.
// A scratch manager left up at the end is a setup error (exit 2), not a failed check.
/** Four scenarios on the fixture pack; true when each ends the way it must. */
export function selfTest(host: string, box: Box = remote, fix = resolve(ROOT, SELFTEST)): boolean {
  const tmp = mkdtempSync(join(tmpdir(), "logtest-self-"));
  const base = { host, cases: join(fix, "cases"), sigma: join(tmp, "no-sigma"), reuse: false, keep: true };
  const failing = (o: Outcome) => o.verdicts.filter((v) => !v.pass).map((v) => basename(v.case.file));
  const checks: [string, boolean][] = [];
  let done = false;
  let left: string | undefined;
  try {
    const a = run({ ...base, rules: join(fix, "rules") }, box);
    report(a);
    checks.push(["A fixture pack passes", a.code === 0 && a.verdicts.length === 5]);

    const flipped = join(tmp, "cases-b");
    cpSync(base.cases, flipped, { recursive: true });
    cpSync(join(flipped, "100399/pos-powershell.json"), join(flipped, "100399/neg-planted-flip.json"));
    const b = run({ ...base, cases: flipped, reuse: true, rules: join(fix, "rules") }, box);
    report(b);
    // A coverage line fails the run too, so "that case only" means none.
    checks.push(["B flipped expectation fails on that case only", b.code === 1 && failing(b).join() === "neg-planted-flip.json" && !b.coverage.length]);

    const field = `<field name="win.eventdata.image" type="pcre2">(?i)\\\\powershell\\.exe$</field>`;
    const xml = readFileSync(join(fix, "rules/selftest.xml"), "utf8");
    const parts = xml.split(field);
    if (parts.length !== 2) throw new SetupError("the condition-flip patch did not apply");
    mkdirSync(join(tmp, "rules-c"));
    writeFileSync(join(tmp, "rules-c/selftest.xml"), parts.join(field.replace('type="pcre2"', 'type="pcre2" negate="yes"')));
    const c = run({ ...base, rules: join(tmp, "rules-c") }, box);
    report(c);
    checks.push(["C flipped condition fails both 100399 cases", c.code === 1 && failing(c).sort().join() === "neg-updater.json,pos-powershell.json"]);

    mkdirSync(join(tmp, "rules-d/sub"), { recursive: true });
    cpSync(join(fix, "rules/selftest.xml"), join(tmp, "rules-d/sub/selftest.xml"));
    const d = run({ ...base, rules: join(tmp, "rules-d"), keep: false }, box);
    report(d);
    const missing = [
      `${rel(join(tmp, "rules-d/sub/selftest.xml"))}: XML in a subfolder, which the manager never loads`,
      "rule 100398: never fired in a positive case",
      "rule 100399: never fired in a positive case",
    ];
    // The subfolder line and a foreign-pack verdict fail D's run whatever the box does, so
    // only a reply that names no pack rule shows the manager really skipped the subfolder.
    const fired = d.verdicts.some((v) => v.why.includes(FOREIGN));
    checks.push(["D rules in a subfolder never fire", d.code === 1 && d.coverage.join() === missing.join() && !fired]);
    done = true;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    const down = box(host, DOWN);
    if (down.code !== 0) {
      left = removalFailed(down);
      // An error already on its way out wins; this one is added beside it.
      if (!done) console.error(`logtest: ${left}`);
    }
  }
  for (const [name, ok] of checks) console.log(`${ok ? "OK  " : "BAD "} self-test ${name}`);
  if (left) throw new SetupError(left);
  return checks.length === 4 && checks.every(([, ok]) => ok);
}

// *--- Entry Point ---*

const USAGE = `usage: bun tools/logtest.ts [--host <ssh alias>] [--rules <dir>] [--cases <dir>] [--sigma <dir>]
                           [--reuse] [--keep] [--save <transcript file>]
       bun tools/logtest.ts --self-test [--host <ssh alias>]
       bun tools/logtest.ts --down [--host <ssh alias>]`;

if (import.meta.main) {
  const args = Bun.argv.slice(2);
  const o: RunOptions = {
    host: DEFAULT_HOST,
    rules: resolve(ROOT, RULES_DIR),
    cases: resolve(ROOT, CASES_DIR),
    sigma: resolve(ROOT, SIGMA_DIR),
    reuse: false,
    keep: false,
  };
  let mode: "run" | "self-test" | "down" = "run";
  let sigmaNamed = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const value = () => {
      const v = args[++i];
      if (v === undefined) {
        console.error(USAGE);
        process.exit(2);
      }
      return v;
    };
    if (a === "--host") o.host = value();
    else if (a === "--rules") o.rules = resolve(value());
    else if (a === "--cases") o.cases = resolve(value());
    else if (a === "--sigma") {
      o.sigma = resolve(value());
      sigmaNamed = true;
    } else if (a === "--save") {
      // "--save --keep" would write the transcript to a file named --keep and drop the flag.
      const v = value();
      if (v.startsWith("-")) {
        console.error(clean(`logtest: --save needs a file name, and ${v} starts with - (write ./${v} for a file of that name)`));
        process.exit(2);
      }
      o.save = resolve(v);
    } else if (a === "--reuse") o.reuse = true;
    else if (a === "--keep") o.keep = true;
    else if (a === "--self-test") mode = "self-test";
    else if (a === "--down") mode = "down";
    else {
      console.error(a === "--help" || a === "-h" ? USAGE : `logtest: unknown argument: ${a}\n${USAGE}`);
      process.exit(a === "--help" || a === "-h" ? 0 : 2);
    }
  }
  if (!SAFE_HOST.test(o.host)) {
    console.error("logtest: --host must be an ssh alias");
    process.exit(2);
  }
  // The default Sigma folder may be absent (no YAML yet); one named here may not.
  if (mode === "run" && sigmaNamed && !existsSync(o.sigma)) {
    console.error(clean(`logtest: no Sigma folder at ${rel(o.sigma)}`));
    process.exit(2);
  }
  // Exit 1 is kept for a failed case or a coverage gap. Anything thrown is a setup
  // problem, a SetupError or not: a missing folder, a file that cannot be written.
  try {
    if (mode === "down") {
      mustRemove(remote(o.host, DOWN), "removing the scratch manager");
      process.exit(0);
    }
    if (mode === "self-test") process.exit(selfTest(o.host) ? 0 : 1);
    const out = run(o);
    report(out);
    process.exit(out.code);
  } catch (e) {
    console.error(`logtest: ${clean(e instanceof SetupError ? e.message : `unexpected ${e instanceof Error ? e.name : "error"}: ${reason(e)}`)}`);
    process.exit(2);
  }
}
