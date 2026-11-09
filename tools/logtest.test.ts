// *****************************************************************************
// *Title: logtest.test*
// *Author: Kyle Versluis*
// *Description: Offline checks of the harness: cases, replies and verdicts.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, afterEach, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import {
  type Box,
  bootErrors,
  type Case,
  checkKit,
  clean,
  coverage,
  evaluate,
  kitImage,
  loadCases,
  managerImage,
  manifest,
  packStage,
  parseReplies,
  type Result,
  type RunOptions,
  run,
  SetupError,
  scratchConf,
  selfTest,
  stagedRules,
} from "./logtest.ts";
import { lintPack } from "./sigma-lint.ts";
import { isPack, parseRules, readRulesDir } from "./wazuh-rules.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const CASES = resolve(ROOT, "tools/fixtures/logtest/cases");
const FIX_RULES = resolve(ROOT, "tools/fixtures/logtest/rules");
const KIT = readFileSync(resolve(ROOT, "tools/logtest/compose.yml"), "utf8");
const LIVE = readFileSync(resolve(ROOT, "deploy/soc-recon/docker-compose.yml"), "utf8");
const RULES = new Map(
  parseRules(readFileSync(resolve(ROOT, "tools/fixtures/logtest/rules/selftest.xml"), "utf8"), "selftest.xml").map((r) => [r.id, r]),
);
// A real scratch run's transcript, whole (2026-11-06, the five fixture cases).
const REAL = readFileSync(resolve(ROOT, "tools/fixtures/logtest/transcript-20261106.txt"), "utf8");
// The fixture cases in the order a run sends them; REAL answers them in that order.
const FIXTURES = loadCases(CASES);
const EVENTS = FIXTURES.map((c) => c.event);
const REAL_REPLIES = REAL.split("\n").filter((l) => /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} wazuh_logtest\[DEBUG\] Reply: /.test(l));
const at = (file: string) => FIXTURES.findIndex((c) => c.file.endsWith(file));
// REAL with the PowerShell positive's rule still firing, but with no alert.
const NO_ALERT = (() => {
  const line = REAL_REPLIES[at("100399/pos-powershell.json")];
  expect(line.split('"alert":true').length).toBe(2);
  return REAL.replace(line, line.replace('"alert":true', '"alert":false'));
})();
// The reply shape in that transcript: "messages" is absent when there are none, and
// codemsg is 0 for a clean reply, 1 when a warning rides along.
const reply = (rule?: { id: string; level: number; mitre?: string[] }, messages: string[] = [], token = "1a2b3c4d") => {
  const output: Record<string, unknown> = { decoder: { name: "windows_eventchannel" }, location: "stdin" };
  if (rule) output.rule = { id: rule.id, level: rule.level, ...(rule.mitre ? { mitre: { id: rule.mitre } } : {}) };
  const data = { ...(messages.length ? { messages } : {}), token, output, alert: !!rule && rule.level >= 3, codemsg: messages.length ? 1 : 0 };
  return `2026-11-02 18:00:00,001 wazuh_logtest[DEBUG] Reply: ${JSON.stringify({ error: 0, data })}\n`;
};
const transcript = (...replies: string[]) =>
  ["Starting wazuh-logtest v4.14.9", "Type one log per line", ...replies.flatMap((r) => [r, "**Phase 1: Completed pre-decoding."])].join(
    "\n",
  );
const res = (rule: number | undefined, level?: number, mitre: string[] = [], warnings: string[] = []): Result => ({
  rule,
  level,
  mitre,
  decoder: "windows_eventchannel",
  alert: true,
  warnings,
});
const kase = (rule: number, kind: "pos" | "neg", file = `${kind}.json`): Case => ({ file, rule, kind, event: "{}" });
const whys = (cases: Case[], results: Result[]) => evaluate(cases, results, RULES).map((v) => (v.pass ? "pass" : v.why));

// *--- Fake Box ---*

// The remote side of run(), answered from a folder on this machine. The stage is really
// unpacked and really hashed, so the checks in run() compare real files.
const h = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");
// id|started|image|network|running|project, then one field per mount.
const INSPECT = [
  "0123456789abcdef".repeat(4),
  "2026-11-06T07:27:15.123456789Z",
  `wazuh/wazuh-manager:${managerImage(KIT)}`,
  "none",
  "true",
  "b1test",
  "volume b1test_etc",
  "volume b1test_logs",
  "volume b1test_queue",
  "bind ~/b1test/stage/ossec.conf",
  "bind ~/b1test/stage/local_logtest_winevt.xml",
  "bind ~/b1test/stage/custom-rules",
];
// What a clean boot logs at these levels (probe of the scratch manager, 2026-11-06).
const CLEAN_BOOT = [
  "2026/11/06 07:27:23 indexer-connector: WARNING: IndexerConnector initialization failed for index 'wazuh-states-vulnerabilities-b1test', retrying until the connection is successful.",
  "2026/11/06 07:29:30 wazuh-modulesd:content-updater: ERROR: Action for 'vulnerability_feed_manager' failed: Error -1 from server: Could not resolve hostname",
].join("\n");
const ruleOf = (line: string): number => Number(JSON.parse(line.slice(line.indexOf(" Reply: ") + 8)).data.output.rule?.id);

// A stub docker for the ownership check that opens the removal script: "ps" lists the
// containers in $IDS, and "inspect" prints each one's working_dir label from $DIR_<id>.
// With $SEEN set, "ps" also logs the folder the removal runs from and what the home holds
// at that moment, while the removal's own empty folder still exists.
const STUB_DOCKER = String.raw`#!/bin/sh
case "$*" in
  "ps -aq --filter label=com.docker.compose.project=b1test")
    [ -z "$SEEN" ] || { echo "cwd $(pwd -P)"; echo "home $(ls -A "$HOME" | LC_ALL=C sort | tr '\n' ' ')"; } >> "$SEEN"
    [ -z "$IDS" ] || printf '%s\n' $IDS ;;
  "inspect --format {{index .Config.Labels \"com.docker.compose.project.working_dir\"}} c0") printf '%s\n' "$DIR_c0" ;;
  "inspect --format {{index .Config.Labels \"com.docker.compose.project.working_dir\"}} c1") printf '%s\n' "$DIR_c1" ;;
  *) echo "stub docker: unexpected $*" >&2; exit 64 ;;
esac
`;
// The box's rm is GNU; macOS rm takes -x for --one-file-system. This stands in for it
// when the staging script runs here, and refuses a recursive rm that would cross mounts.
const STUB_RM = String.raw`#!/bin/sh
case "$1" in
  -r|-rf|-fr|-R|-Rf)
    [ "$2" = "--one-file-system" ] || { echo "rm stub: recursive rm without --one-file-system" >&2; exit 97; }
    flag=$1; shift 2; exec /bin/rm "$flag" -x "$@" ;;
  *) exec /bin/rm "$@" ;;
esac
`;
// The box's stat is GNU; macOS stat takes -f %d for -c %d. A path in $MOUNTS reports
// another device, standing in for a mount point; one in $NOSTAT fails, naming the path on
// stderr as GNU stat does.
const STUB_STAT = String.raw`#!/bin/sh
[ $# -eq 3 ] && [ "$1" = "-c" ] && [ "$2" = "%d" ] || { echo "stat stub: unexpected $*" >&2; exit 64; }
for m in $NOSTAT; do [ "$3" = "$m" ] && { echo "stat: cannot statx '$3': No such file or directory" >&2; exit 1; }; done
for m in $MOUNTS; do [ "$3" = "$m" ] && { echo 999999; exit 0; }; done
exec /usr/bin/stat -f %d "$3"
`;
// The box's tar is GNU, which takes options from TAR_OPTIONS; libarchive's tar reads
// TAR_READER_OPTIONS and TAR_WRITER_OPTIONS. This stands in for it and refuses to run with
// any of them in its environment.
const STUB_TAR = String.raw`#!/bin/sh
if env | grep -Eq '^TAR_(OPTIONS|READER_OPTIONS|WRITER_OPTIONS)='; then echo "tar stub: a tar options variable is set" >&2; exit 98; fi
exec /usr/bin/tar "$@"
`;
const ownerDir = mkdtempSync(join(tmpdir(), "logtest-owner-"));
mkdirSync(join(ownerDir, "bin"));
mkdirSync(join(ownerDir, "gnu"));
mkdirSync(join(ownerDir, "home"));
writeFileSync(join(ownerDir, "bin/docker"), STUB_DOCKER);
chmodSync(join(ownerDir, "bin/docker"), 0o755);
writeFileSync(join(ownerDir, "gnu/rm"), STUB_RM);
chmodSync(join(ownerDir, "gnu/rm"), 0o755);
writeFileSync(join(ownerDir, "gnu/stat"), STUB_STAT);
chmodSync(join(ownerDir, "gnu/stat"), 0o755);
writeFileSync(join(ownerDir, "gnu/tar"), STUB_TAR);
chmodSync(join(ownerDir, "gnu/tar"), 0o755);
// The guard that opens every scratch-folder script, as the staging script carries it.
const guardOf = (scripts: string[]) => {
  const s = scripts.find((x) => x.includes("tar -xf")) ?? "";
  const at = s.indexOf('; mkdir -p "$HOME/b1test"');
  expect(at).toBeGreaterThan(0);
  return s.slice(0, at);
};
// Runs a guard in sh against a home stand-in, with the GNU stand-ins first on PATH.
const guardRun = (guard: string, home: string, env: Record<string, string> = {}) =>
  Bun.spawnSync(["sh", "-c", `${guard}; echo passed`], {
    env: { HOME: home, PATH: `${join(ownerDir, "gnu")}:${process.env.PATH}`, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
afterAll(() => rmSync(ownerDir, { recursive: true, force: true }));
// Runs the removal's checks for real in the given home stand-in, with one container per
// working_dir given ("~" is the home). The removal opens with the guard, so the GNU
// stand-ins go first on PATH here too.
const ownership = (script: string, dirs: string[], home: string, extra: Record<string, string> = {}) => {
  const env: Record<string, string> = {
    HOME: home,
    PATH: `${join(ownerDir, "gnu")}:${join(ownerDir, "bin")}:${process.env.PATH}`,
    IDS: dirs.map((_, i) => `c${i}`).join(" "),
    ...extra,
  };
  dirs.forEach((d, i) => {
    env[`DIR_c${i}`] = d.replace(/^~/, home);
  });
  const r = Bun.spawnSync(["sh", "-c", script], { env, stdout: "pipe", stderr: "pipe" });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString().trim() };
};

// A fake analysisd for the fixture events: each gets its reply from REAL, as the staged
// rules would change it. No top-level rules file unloads the pack, and a negated 100399
// condition swaps which of its two events fires. With no stage given it answers as if
// the fixture rules stayed loaded, whatever was staged.
function analysisd(sent: string, stage?: string): string {
  const top = stage === undefined ? undefined : join(stage, "custom-rules/selftest.xml");
  const xml = top === undefined ? undefined : existsSync(top) ? readFileSync(top, "utf8") : "";
  const [pos, neg] = [at("100399/pos-powershell.json"), at("100399/neg-updater.json")];
  expect(sent.endsWith("\n")).toBe(true);
  return sent
    .slice(0, -1)
    .split("\n")
    .map((e) => {
      let i = EVENTS.indexOf(e);
      expect(i).toBeGreaterThanOrEqual(0);
      if (xml?.includes('negate="yes"') && (i === pos || i === neg)) i = i === pos ? neg : pos;
      if (xml === "" && isPack(ruleOf(REAL_REPLIES[i]))) i = neg;
      return REAL_REPLIES[i];
    })
    .join("\n");
}

interface Fake {
  transcript?: string;
  // Answer from the fake analysisd instead of a fixed transcript.
  analysisd?: "staged" | "stale";
  // The exact events stdin must carry; null skips the check for runs on other cases.
  events?: string[] | null;
  logtestCode?: number;
  inspect?: string[];
  // The id|started line the check after the cases reads.
  after?: string;
  wait?: number;
  init?: string;
  ossec?: string;
  // The exit code of the ossec.log read; 0 by default.
  ossecCode?: number;
  down?: number[];
  // The working_dir label of each b1test container the removal finds; none by default
  // is one container started from the stage.
  projectDir?: string[];
  // Folders ("~" is the home stand-in) the staging script's stat sees as mount points.
  mounts?: string[];
  loaded?: (text: string) => string;
  // The exit code of the "up" call; 0 by default.
  up?: number;
  // More of the box account's environment, as the staging script inherits it.
  boxEnv?: Record<string, string>;
}
const tmps: string[] = [];
const temp = (name: string) => {
  const d = mkdtempSync(join(tmpdir(), `logtest-${name}-`));
  tmps.push(d);
  return d;
};
afterEach(() => {
  for (const d of tmps.splice(0)) rmSync(d, { recursive: true, force: true });
});
// Runs go with the temp folder pointed at one of their own, so the stage folders another
// process makes at the same time (the suite run elsewhere) are never counted as theirs.
const ownTmp = <T>(go: () => T) => {
  const dir = temp("tmp");
  const was = process.env.TMPDIR;
  process.env.TMPDIR = dir;
  try {
    return { value: go(), left: () => readdirSync(dir) };
  } finally {
    if (was === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = was;
  }
};
const fakeBox = (f: Fake = {}) => {
  // A folder standing in for the box account's home; the staging script runs in it.
  const home = temp("box");
  const stageDir = join(home, "b1test/stage");
  // Outside the home, so the log never shows up in the listing it records.
  const seenLog = join(temp("seen"), "log");
  const calls: string[] = [];
  const owners: ReturnType<typeof ownership>[] = [];
  const downs = [...(f.down ?? [])];
  const mounts = (f.mounts ?? []).map((m) => m.replace(/^~/, home)).join(" ");
  const ok = (out = "") => ({ code: 0, out, err: "" });
  const box: Box = (_host, script, input) => {
    // SECURITY: event text is attacker-shaped, so it reaches the box on stdin only.
    for (const e of EVENTS) if (script.includes(e) || script.includes(JSON.stringify(e).slice(1, -1))) throw new Error("a remote script carries event text");
    if (script.includes("tar -xf")) {
      calls.push("stage");
      // The staging script runs for real, under a permissive default umask, so the .env
      // it writes shows the mode the script itself gives it.
      const env = { HOME: home, PATH: `${join(ownerDir, "gnu")}:${process.env.PATH}`, MOUNTS: mounts, ...f.boxEnv };
      const r = Bun.spawnSync(["sh", "-c", `umask 022; ${script}`], { stdin: input, env, stdout: "pipe", stderr: "pipe" });
      return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString().trim() };
    }
    if (script.includes("down -v")) {
      calls.push("down");
      const at = script.indexOf(" && docker compose -p b1test down");
      expect(at).toBeGreaterThan(0);
      const owner = ownership(script.slice(0, at), f.projectDir ?? ["~/b1test/stage"], home, { MOUNTS: mounts, SEEN: seenLog });
      owners.push(owner);
      if (owner.code !== 0) return owner;
      return { code: downs.shift() ?? 0, out: "", err: "" };
    }
    if (script.includes(" up -d")) return calls.push("up"), f.up ? { code: f.up, out: "", err: "no such image" } : ok();
    if (script.includes("test -S")) return calls.push("wait"), { code: f.wait ?? 0, out: "", err: "" };
    if (script.includes("not-a-file")) return calls.push("staged"), existsSync(stageDir) ? ok(`${manifest(stageDir)}\n`) : { code: 1, out: "", err: "" };
    if (script.includes("docker inspect")) {
      const inspect = f.inspect ?? INSPECT;
      if (script.includes(".Config.Image")) return calls.push("inspect"), ok(`${inspect.join("|")}\n`);
      return calls.push("recheck"), ok(`${f.after ?? inspect.slice(0, 2).join("|")}\n`);
    }
    if (script.includes("sha256sum ossec.conf")) {
      calls.push("loaded");
      const text = [
        `${h(join(stageDir, "ossec.conf"))}  ossec.conf`,
        `${h(join(stageDir, "local_logtest_winevt.xml"))}  decoders/local_logtest_winevt.xml`,
        manifest(join(stageDir, "custom-rules")),
      ].join("\n");
      return ok(`${(f.loaded ?? ((x) => x))(text)}\n`);
    }
    if (script.includes("ossec.log")) return calls.push("ossec"), { code: f.ossecCode ?? 0, out: f.ossec ?? CLEAN_BOOT, err: "" };
    if (script.includes(" logs ")) return calls.push("logs"), ok(f.init ?? "wazuh.manager-1  | [cont-init.d] 0-wazuh-init: exited 0.\n");
    if (script.includes("wazuh-logtest -d")) {
      calls.push("logtest");
      const sent = new TextDecoder().decode(input);
      // The events go in case order, one per line, the last one ended too.
      if (f.events !== null) expect(sent).toBe(`${(f.events ?? EVENTS).join("\n")}\n`);
      const out = f.analysisd ? analysisd(sent, f.analysisd === "staged" ? stageDir : undefined) : (f.transcript ?? REAL);
      return { code: f.logtestCode ?? 0, out, err: "" };
    }
    throw new Error(`the fake box has no answer for: ${script}`);
  };
  // One entry per ownership check that got as far as "docker ps": where it ran, and the
  // home's top-level names at that moment.
  const seen = () => {
    const lines = existsSync(seenLog) ? readFileSync(seenLog, "utf8").trimEnd().split("\n") : [];
    const out: { cwd: string; home: string[] }[] = [];
    for (let i = 0; i + 1 < lines.length; i += 2) out.push({ cwd: lines[i].replace(/^cwd /, ""), home: lines[i + 1].replace(/^home /, "").trim().split(" ").filter(Boolean) });
    return out;
  };
  return { box, calls, home, stageDir, owners, seen };
};
const opts = (over: Partial<RunOptions> = {}): RunOptions => ({
  host: "box",
  rules: FIX_RULES,
  cases: CASES,
  // A Sigma folder that does not exist, under a fresh temp folder so no other run can make it.
  sigma: join(temp("no-sigma"), "absent"),
  reuse: false,
  keep: false,
  ...over,
});
const VERIFY = ["staged", "inspect", "loaded", "logs", "ossec"];
// The variables every remote script that runs docker or tar clears before it does.
const UNSET =
  "unset COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PATH_SEPARATOR COMPOSE_PROJECT_NAME COMPOSE_ENV_FILES DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_TLS_VERIFY DOCKER_CERT_PATH SCRATCH_INDEXER_PASS SCRATCH_API_PASS TAR_OPTIONS TAR_READER_OPTIONS TAR_WRITER_OPTIONS";

// *--- Tests ---*

describe("scratch kit", () => {
  test("the scratch conf excludes the stock json decoders once, right after decoder_dir", () => {
    const live = readFileSync(resolve(ROOT, "deploy/soc-recon/config/wazuh_cluster/wazuh_manager.conf"), "utf8");
    const out = scratchConf(live);
    expect(out.split("0006-json_decoders.xml").length).toBe(2);
    expect(out).toContain("<decoder_dir>ruleset/decoders</decoder_dir>\n    <decoder_exclude>ruleset/decoders/0006-json_decoders.xml");
    expect(out.replace(/\n\s*<decoder_exclude>ruleset\/decoders\/0006-json_decoders.xml<\/decoder_exclude>/, "")).toBe(live);
    expect(() => scratchConf(out)).toThrow(SetupError);
    expect(() => scratchConf("<ossec_config/>")).toThrow(SetupError);
  });

  // analysisd tries decoders in file order. The port emits a Data field's text as is, so a
  // capture holding "integration":"ms-graph" would go to json-msgraph's unanchored prematch
  // if it came first, and no Windows rule would see the event, while live the C decoder
  // takes it. The shim decoder leads, and the repeated stock json decoders follow it.
  test("the kit shim's first decoder is windows_eventchannel, and each decoder is named once", () => {
    const shim = readFileSync(resolve(ROOT, "tools/logtest/local_logtest_winevt.xml"), "utf8");
    const bare = shim.replace(/<!--[\s\S]*?-->/g, " ");
    const names = [...bare.matchAll(/<decoder\b[^>]*?\bname=(["'])(.*?)\1/g)].map((m) => m[2]);
    expect(names).toHaveLength(bare.split(/<decoder\b/).length - 1);
    expect(names[0]).toBe("windows_eventchannel");
    expect(names.slice(1)).toContain("json");
    expect(new Set(names).size).toBe(names.length);
  });

  // rule_dir is not recursive. Without this element the staged rules hash right in LOADED
  // and never load, and a run whose cases touch no custom rule would still exit 0.
  test("the scratch conf refuses a live conf that does not load the custom rules once", () => {
    const live = readFileSync(resolve(ROOT, "deploy/soc-recon/config/wazuh_cluster/wazuh_manager.conf"), "utf8");
    const line = "    <rule_dir>etc/rules/custom</rule_dir>\n";
    const conf = (from: string, to: string, text = live) => {
      expect(text.split(from).length).toBe(2);
      return text.replace(from, to);
    };
    const why = (all: number, inside: number) =>
      new RegExp(
        `^deploy/soc-recon/config/wazuh_cluster/wazuh_manager\\.conf must load the custom rules: <rule_dir>etc/rules/custom</rule_dir> once inside <ruleset>, outside any comment \\(found ${all}, ${inside} inside <ruleset>\\)$`,
      );
    const refused = (text: string, reason: RegExp) => {
      let err: unknown;
      try {
        scratchConf(text);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(SetupError);
      expect((err as Error).message).toMatch(reason);
    };
    // The checked-in conf passes, its comments around the element included.
    expect(live).toContain(`did not fire. -->\n${line}  </ruleset>\n`);
    expect(() => scratchConf(live)).not.toThrow();
    // Missing, commented out on its own, or folded into the comment above it.
    const gone = conf(line, "");
    refused(gone, why(0, 0));
    refused(conf(line, "    <!-- <rule_dir>etc/rules/custom</rule_dir> -->\n"), why(0, 0));
    refused(conf(`did not fire. -->\n${line}`, `did not fire.\n${line}    -->\n`), why(0, 0));
    refused(conf(line, "    <!--\n    <rule_dir>etc/rules/custom</rule_dir>\n    -->\n"), why(0, 0));
    // Outside <ruleset>: just after it, just before it, or in another section.
    refused(conf("  </ruleset>\n", `  </ruleset>\n${line}`, gone), why(1, 0));
    refused(conf("  <ruleset>\n", `${line}  <ruleset>\n`, gone), why(1, 0));
    refused(conf("  <rule_test>\n", `  <rule_test>\n${line}`, gone), why(1, 0));
    // Between two <ruleset> blocks is inside neither.
    refused(conf("  </ruleset>\n", `  </ruleset>\n${line}  <ruleset>\n  </ruleset>\n`, gone), why(1, 0));
    // The close is searched for after the whole "<!--", so "<!-->" opens a comment and
    // never reads as one already closed.
    refused(conf(line, `    <!--> ${line.trim()} -->\n`), why(0, 0));
    // Twice inside <ruleset>, or once in and once out.
    refused(conf(line, `${line}${line}`), why(2, 2));
    refused(conf("  <rule_test>\n", `  <rule_test>\n${line}`), why(2, 1));
    // A comment never joins the text on either side into the element.
    refused(conf(line, "    <rule_dir>etc/rules/<!-- x -->custom</rule_dir>\n"), why(0, 0));
    // A comment left open, anywhere.
    refused(`${live}<!-- never closed\n`, /^deploy\/soc-recon\/config\/wazuh_cluster\/wazuh_manager\.conf has a comment that never closes$/);
    // An opener with no close of its own runs to the next comment's, swallowing the element.
    refused(conf(line, `    <!-- ${line}`), why(0, 0));
    // A "<!" or "<?" that is not a plain comment, which the manager may skip like one.
    for (const odd of ["<!- x -->", "<!DOCTYPE x>", "<? x ?>"]) {
      refused(conf(line, `    ${odd}\n${line}`), /wazuh_manager\.conf holds "<!" or "<\?" outside a comment, which the manager may skip as one$/);
    }
  });

  // The manager never reads a decoder_dir inside a comment, so the exclusion goes after the
  // one outside every comment: a conf whose only copy is commented out is refused (it was
  // put inside the comment and passed), and a commented copy beside the real one is fine.
  test("the scratch conf inserts the exclusion after the one decoder_dir outside a comment", () => {
    const live = readFileSync(resolve(ROOT, "deploy/soc-recon/config/wazuh_cluster/wazuh_manager.conf"), "utf8");
    const dir = "<decoder_dir>ruleset/decoders</decoder_dir>";
    const exclude = "<decoder_exclude>ruleset/decoders/0006-json_decoders.xml</decoder_exclude>";
    const line = `    ${dir}\n`;
    expect(live.split(line).length).toBe(2);
    expect(live.split(dir).length).toBe(2);
    const why = (n: number) =>
      new RegExp(`^deploy/soc-recon/config/wazuh_cluster/wazuh_manager\\.conf must hold ${dir.replace(/\//g, "\\/")} once outside any comment \\(found ${n}\\)$`);
    const refused = (text: string, reason: RegExp) => {
      let err: unknown;
      try {
        scratchConf(text);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(SetupError);
      expect((err as Error).message).toMatch(reason);
    };
    // Only inside a comment, on its line or across lines; or twice outside one.
    refused(live.replace(line, `    <!-- ${dir} -->\n`), why(0));
    refused(live.replace(line, `    <!--\n${line}    -->\n`), why(0));
    refused(live.replace(line, `${line}${line}`), why(2));
    // A commented copy before or after the real one: the exclusion follows the real one, and
    // the comment is left as it was.
    const commented = `    <!-- ${dir} -->\n`;
    for (const conf of [live.replace(line, `${commented}${line}`), live.replace(line, `${line}${commented}`)]) {
      expect(scratchConf(conf)).toBe(conf.replace(line, `    ${dir}\n    ${exclude}\n`));
      expect(scratchConf(conf)).toContain(commented);
    }
    // One that starts right where a comment ends is outside it.
    const after = live.replace(line, `    <!-- c -->${dir}\n`);
    expect(scratchConf(after)).toBe(live.replace(line, `    <!-- c -->${dir}\n    ${exclude}\n`));
  });

  // A compose file whose manager service runs the given image, after any text in "before".
  const withImage = (image: string, before = "") => `${before}services:\n  wazuh.manager:\n    image: ${image}\n`;

  test("the kit compose runs the live manager image", () => {
    const kit = managerImage(readFileSync(resolve(ROOT, "tools/logtest/compose.yml"), "utf8"));
    expect(kit).toBe(managerImage(LIVE));
    expect(kitImage(KIT, LIVE)).toBe(kit);
    expect(managerImage(withImage("wazuh/wazuh-manager:${WAZUH_VERSION:-4.99.1}"))).toBe("4.99.1");
    expect(managerImage(withImage("wazuh/wazuh-manager:4.99.1"))).toBe("4.99.1");
    expect(managerImage(withImage('"wazuh/wazuh-manager:${WAZUH_VERSION:-4.99.1}"'))).toBe("4.99.1");
  });

  test("a commented-out image line is not the one read", () => {
    expect(managerImage(withImage("wazuh/wazuh-manager:4.99.1", "# services:\n#   wazuh.manager:\n#     image: wazuh/wazuh-manager:1.0.0\n"))).toBe("4.99.1");
    expect(managerImage("services:\n  wazuh.manager:\n    # image: wazuh/wazuh-manager:1.0.0\n    image: wazuh/wazuh-manager:4.99.1 # was 1.0.0\n")).toBe("4.99.1");
  });

  test("the image guard refuses a kit that is not on the live compose default", () => {
    const live = withImage("wazuh/wazuh-manager:${WAZUH_VERSION:-4.99.1}");
    expect(kitImage(withImage("wazuh/wazuh-manager:4.99.1"), live)).toBe("4.99.1");
    expect(() => kitImage(withImage("wazuh/wazuh-manager:4.99.0"), live)).toThrow(/not the live compose default 4\.99\.1/);
  });

  // The repro: image-shaped text above the real service named the kit's tag, so the kit
  // passed against a live manager on another one. Compose runs the service's image key.
  test("the image is the manager service's own image key, never image-shaped text elsewhere", () => {
    const real = "wazuh/wazuh-manager:${WAZUH_VERSION:-4.15.0}";
    const decoys = [
      withImage(real, "x-note: |\n  image: wazuh/wazuh-manager:4.14.9\n"),
      withImage(real, "x-note: >-\n  image: wazuh/wazuh-manager:4.14.9\n"),
      `services:\n  old:\n    image: wazuh/wazuh-manager:4.14.9\n  wazuh.manager:\n    image: ${real}\n`,
      `services:\n  wazuh.manager:\n    labels:\n      note: "image: wazuh/wazuh-manager:4.14.9"\n    image: ${real}\n`,
    ];
    for (const live of decoys) {
      expect(managerImage(live)).toBe("4.15.0");
      expect(() => kitImage(KIT, live)).toThrow(/compose\.yml is on 4\.14\.9, not the live compose default 4\.15\.0$/);
    }
  });

  test("refuses a compose whose manager image is missing or not one plain tag", () => {
    const refuses = (compose: string, why: RegExp) => {
      let err: unknown;
      try {
        managerImage(compose, "the file");
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(SetupError);
      expect((err as Error).message).toMatch(why);
    };
    refuses("services: [a", /^the file is not YAML$/);
    // No manager service: none at all, a list, an empty file, a bare image line, another
    // name, or a service that is a string and not a mapping.
    for (const doc of [
      "- a\n- b\n",
      "",
      "image: wazuh/wazuh-manager:4.14.9\n",
      "services:\n  - wazuh.manager\n",
      "services:\n  manager:\n    image: wazuh/wazuh-manager:4.14.9\n",
      "services:\n  wazuh.manager: wazuh/wazuh-manager:4.14.9\n",
    ]) {
      refuses(doc, /^the file has no wazuh\.manager service$/);
    }
    refuses("services:\n  wazuh.manager:\n    hostname: x\n", /^the file: wazuh\.manager has no image$/);
    refuses("services:\n  wazuh.manager:\n    image:\n", /^the file: wazuh\.manager has no image$/);
    const bad = [
      // Another repository, or no tag.
      "wazuh/wazuh-indexer:4.14.9",
      "evil/wazuh-manager:4.14.9",
      "docker.io/wazuh/wazuh-manager:4.14.9",
      "wazuh/wazuh-manager-x:4.14.9",
      "wazuh/wazuh-manager",
      '"wazuh/wazuh-manager:"',
      "${REPO:-wazuh/wazuh-manager}:4.14.9",
      // Not a string.
      "4.14",
      "[wazuh/wazuh-manager:4.14.9]",
      "{tag: 4.14.9}",
      // Another interpolation form, or more than one.
      "wazuh/wazuh-manager:${WAZUH_VERSION}",
      "wazuh/wazuh-manager:$WAZUH_VERSION",
      "wazuh/wazuh-manager:${WAZUH_VERSION-4.14.9}",
      "wazuh/wazuh-manager:${WAZUH_VERSION:?4.14.9}",
      "wazuh/wazuh-manager:${WAZUH_VERSION:+4.14.9}",
      "wazuh/wazuh-manager:${WAZUH_VERSION:-}",
      "wazuh/wazuh-manager:${1V:-4.14.9}",
      "wazuh/wazuh-manager:$${WAZUH_VERSION:-4.14.9}",
      "wazuh/wazuh-manager:${A:-${B:-4.14.9}}",
      "wazuh/wazuh-manager:${A:-4.14.9}${B:-4.14.9}",
      "wazuh/wazuh-manager:4.14.9${A:-x}",
      "wazuh/wazuh-manager:${A:-4.14.9}-x",
      // A tag with whitespace, or that the reference grammar refuses.
      '"wazuh/wazuh-manager:4.14.9 "',
      '" wazuh/wazuh-manager:4.14.9"',
      "wazuh/wazuh-manager:4.14 .9",
      '"wazuh/wazuh-manager:4.14.9\\n"',
      '"wazuh/wazuh-manager:\\t4.14.9"',
      '"wazuh/wazuh-manager:${A:-4.14.9 }"',
      "wazuh/wazuh-manager:.4",
      "wazuh/wazuh-manager:-4",
      `wazuh/wazuh-manager:${"4".repeat(129)}`,
      `wazuh/wazuh-manager:4.14.9@sha256:${"0".repeat(64)}`,
    ];
    for (const image of bad) refuses(withImage(image), /^the file: wazuh\.manager image .* is not wazuh\/wazuh-manager:<tag> or wazuh\/wazuh-manager:\$\{NAME:-<tag>\}$/);
    // Each file is named in the refusal.
    expect(() => kitImage(KIT, withImage("busybox"))).toThrow(/^deploy\/soc-recon\/docker-compose\.yml: wazuh\.manager image "busybox" is not/);
    expect(() => kitImage(withImage("busybox"), LIVE)).toThrow(/^tools\/logtest\/compose\.yml: wazuh\.manager image "busybox" is not/);
  });

  const edit = (from: string, to: string) => {
    expect(KIT.split(from).length).toBe(2);
    return KIT.replace(from, to);
  };
  // The kit's environment in mapping form, carrying the two scratch passwords every kit
  // must hold (see "the kit holds no $").
  const ENV_BLOCK = / {4}environment:\n(?: {6}- .*\n)+/;
  const PASSWORDS =
    "      INDEXER_PASSWORD: ${SCRATCH_INDEXER_PASS:?logtest.ts writes .env first}\n      API_PASSWORD: ${SCRATCH_API_PASS:?logtest.ts writes .env first}\n";
  const mapped = (lines: string) => KIT.replace(ENV_BLOCK, `    environment:\n${lines}${PASSWORDS}`);

  // The kit is what "scratch only" rests on: one project, no network, its own storage.
  test("the kit compose is the scratch project with no network and only its own storage", () => {
    expect(() => checkKit(KIT)).not.toThrow();
    expect(() => checkKit(edit("\nname: b1test\n", "\nname: soc-recon\n"))).toThrow(/must name the project b1test/);
    expect(() => checkKit(edit("network_mode: none", "network_mode: bridge"))).toThrow(/network_mode: none/);
    expect(() => checkKit(edit("    network_mode: none\n", ""))).toThrow(/network_mode: none/);
    expect(() => checkKit(edit("    mem_limit: 1500m\n", '    mem_limit: 1500m\n    ports:\n      - "1514:1514"\n'))).toThrow(/must not set ports/);
    expect(() => checkKit(edit("      - etc:/var/ossec/etc\n", "      - /var/run/docker.sock:/var/run/docker.sock\n"))).toThrow(/neither its own volume nor a staged file/);
    expect(() => checkKit(edit("      - etc:/var/ossec/etc\n", "      - ../soc-recon/config:/var/ossec/etc\n"))).toThrow(/neither its own volume nor a staged file/);
    expect(() => checkKit(edit("      - etc:/var/ossec/etc\n", "      - soc-recon_etc:/var/ossec/etc\n"))).toThrow(/neither its own volume nor a staged file/);
    expect(() => checkKit(edit("  etc:\n", "  etc:\n    external: true\n"))).toThrow(/plain named volume/);
    expect(() => checkKit(`${KIT}networks:\n  live:\n    external: true\n`)).toThrow(/must not set networks/);
    expect(() => checkKit(edit("services:\n", "services:\n  other:\n    image: busybox\n"))).toThrow(/the one service/);
    expect(() => checkKit("- a\n- b\n")).toThrow(SetupError);
  });

  // An allowlist: a key the kit does not use is refused, whatever it would do.
  test("the kit service sets only the keys the kit uses", () => {
    const denied: Record<string, string> = {
      build: "    build: .\n",
      pull_policy: "    pull_policy: always\n",
      logging: "    logging:\n      driver: none\n",
      privileged: "    privileged: true\n",
      pid: "    pid: host\n",
      ipc: "    ipc: host\n",
      cap_add: "    cap_add:\n      - SYS_ADMIN\n",
      devices: "    devices:\n      - /dev/sda:/dev/sda\n",
      volumes_from: "    volumes_from:\n      - soc-recon-wazuh.manager-1\n",
      extends: "    extends:\n      file: ../../deploy/soc-recon/docker-compose.yml\n      service: wazuh.manager\n",
      env_file: "    env_file: ../.env\n",
      security_opt: "    security_opt:\n      - seccomp:unconfined\n",
      userns_mode: "    userns_mode: host\n",
      container_name: "    container_name: soc-recon-wazuh.manager-1\n",
      labels: "    labels:\n      com.docker.compose.project: soc-recon\n",
      command: "    command: sh -c 'cat /proc/1/environ'\n",
    };
    for (const [key, yaml] of Object.entries(denied)) {
      expect(() => checkKit(edit("    mem_limit: 1500m\n", `    mem_limit: 1500m\n${yaml}`))).toThrow(new RegExp(`compose\\.yml must not set ${key}$`));
    }
  });

  test("the kit mounts only its own volumes and staged files, in short form", () => {
    const mount = (line: string) => edit("      - etc:/var/ossec/etc\n", line);
    expect(() => checkKit(mount("      - type: volume\n        source: etc\n        target: /var/ossec/etc\n"))).toThrow(/short-form/);
    expect(() => checkKit(mount("      - type: bind\n        source: /\n        target: /host\n"))).toThrow(/short-form/);
    for (const src of ["./..", "./.", "./../.env", "./custom-rules/../..", "./custom-rules/x", "./.env", "~/b1test", "/", "..", "etc/x"]) {
      expect(() => checkKit(mount(`      - ${src}:/var/ossec/etc\n`))).toThrow(/neither its own volume nor a staged file/);
    }
    expect(() => checkKit(mount("      - etc:/var/ossec/etc:z\n"))).toThrow(/neither its own volume nor a staged file/);
    expect(() => checkKit(mount("      - /var/ossec/etc\n"))).toThrow(/neither its own volume nor a staged file/);
    // A volume named ".." is a path to compose, not a volume.
    expect(() => checkKit(edit("volumes:\n  etc:\n", "volumes:\n  ..:\n  etc:\n").replace("      - etc:/var/ossec/etc\n", "      - ..:/var/ossec/etc\n"))).toThrow(
      /volume \.\. is not a plain volume name/,
    );
    const mapped = KIT.replace(/ {4}volumes:\n(?: {6}- .*\n)+/, "    volumes:\n      etc: /var/ossec/etc\n");
    expect(mapped).not.toBe(KIT);
    expect(() => checkKit(mapped)).toThrow(/volumes must be a list/);
  });

  // SECURITY: a staged file or a volume mounted anywhere else, over /var/ossec/bin say,
  // would replace what the manager runs, so each goes only where the checked-in kit puts it.
  test("each kit mount goes only to the destination the checked-in kit gives it", () => {
    expect(() => checkKit(KIT)).not.toThrow();
    const mounts = [...KIT.matchAll(/^ {6}- ([^:\n]+):(\/[^:\n]*?)(:ro)?$/gm)];
    expect(mounts.map((m) => m[1])).toEqual(["etc", "logs", "queue", "./ossec.conf", "./custom-rules", "./local_logtest_winevt.xml"]);
    const dests = mounts.map((m) => m[2]);
    const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
    for (const [line, src, dest, ro = ""] of mounts) {
      for (const other of ["/var/ossec/bin", "/var/ossec/bin/wazuh-logtest", `${dest}/x`, `${dest}/`, `/${dest}`, ...dests.filter((d) => d !== dest)]) {
        const moved = edit(line, `      - ${src}:${other}${ro}`);
        expect(() => checkKit(moved)).toThrow(new RegExp(`compose\\.yml mounts ${esc(src)} at ${esc(other)}, not at ${esc(dest)}$`));
      }
    }
    // A staged file or a volume of its own that the kit never mounts goes nowhere.
    expect(() => checkKit(edit("      - etc:/var/ossec/etc\n", "      - etc:/var/ossec/etc\n      - ./compose.yml:/var/ossec/bin/x\n"))).toThrow(
      /compose\.yml mounts \.\/compose\.yml, which the kit does not mount$/,
    );
    const bin = edit("volumes:\n  etc:\n", "volumes:\n  bin:\n  etc:\n").replace("      - etc:/var/ossec/etc\n", "      - etc:/var/ossec/etc\n      - bin:/var/ossec/bin\n");
    expect(() => checkKit(bin)).toThrow(/compose\.yml mounts bin, which the kit does not mount$/);
  });

  // An environment key such as LD_PRELOAD would load code into the manager from the stage.
  test("the kit environment sets only the keys the kit uses, each value on one line", () => {
    const added = edit("      - API_USERNAME=wazuh-wui\n", "      - API_USERNAME=wazuh-wui\n      - LD_PRELOAD=/wazuh-config-mount/etc/rules/custom/x.so\n");
    expect(() => checkKit(added)).toThrow(/compose\.yml must not set environment\.LD_PRELOAD$/);
    expect(() => checkKit(edit("      - API_USERNAME=wazuh-wui\n", "      - API_USERNAME=wazuh-wui\n      - LD_PRELOAD\n"))).toThrow(/must not set environment\.LD_PRELOAD$/);
    expect(ENV_BLOCK.test(KIT)).toBe(true);
    expect(() => checkKit(mapped("      INDEXER_USERNAME: admin\n      API_USERNAME: wazuh-wui\n"))).not.toThrow();
    expect(() => checkKit(mapped("      INDEXER_USERNAME: admin\n      LD_PRELOAD: /x.so\n"))).toThrow(/must not set environment\.LD_PRELOAD$/);
    expect(() => checkKit(edit("      - INDEXER_USERNAME=admin\n", '      - "INDEXER_USERNAME=admin\\nroot"\n'))).toThrow(/environment\.INDEXER_USERNAME must be one line$/);
    expect(() => checkKit(mapped('      INDEXER_USERNAME: "admin\\rroot"\n'))).toThrow(/environment\.INDEXER_USERNAME must be one line$/);
    expect(() => checkKit(KIT.replace(ENV_BLOCK, "    environment: LD_PRELOAD=/x.so\n"))).toThrow(/environment must be a list or a mapping$/);
    expect(() => checkKit(edit("      - INDEXER_USERNAME=admin\n", "      - 7\n"))).toThrow(/environment must be a list or a mapping$/);
  });

  // Compose takes a key with no value (a bare KEY line, or KEY: with nothing) from the
  // environment it runs in, so a value the box supplies, even a multi-line one, would reach
  // the manager unchecked. An empty value is a value, and stays allowed.
  test("the kit environment refuses a key with no value, list form or mapping", () => {
    const why = (k: string) => new RegExp(`compose\\.yml environment\\.${k} has no value; compose would take it from the box's environment$`);
    expect(() => checkKit(edit("      - INDEXER_URL=https://b1test-no-indexer:9200\n", "      - INDEXER_URL\n"))).toThrow(why("INDEXER_URL"));
    expect(() => checkKit(edit("      - API_USERNAME=wazuh-wui\n", "      - API_USERNAME\n"))).toThrow(why("API_USERNAME"));
    expect(() => checkKit(edit("      - INDEXER_USERNAME=admin\n", "      - INDEXER_USERNAME=\n"))).not.toThrow();
    expect(() => checkKit(mapped("      INDEXER_USERNAME:\n      API_USERNAME: wazuh-wui\n"))).toThrow(why("INDEXER_USERNAME"));
    expect(() => checkKit(mapped("      INDEXER_USERNAME: admin\n      API_USERNAME: ~\n"))).toThrow(why("API_USERNAME"));
    expect(() => checkKit(mapped("      INDEXER_USERNAME: admin\n      API_USERNAME: null\n"))).toThrow(why("API_USERNAME"));
    expect(() => checkKit(mapped('      INDEXER_USERNAME: ""\n      API_USERNAME: wazuh-wui\n'))).not.toThrow();
    // The checked-in kit sets a value for every key it names.
    expect(() => checkKit(KIT)).not.toThrow();
  });

  // Compose fills ${VAR} and $VAR from the box's environment and reads $$ as "$", so the kit
  // holds exactly two "$": the two scratch passwords, each once, as written, on its own key.
  // The text and the parsed strings are both counted: a comment hides a "$" from the
  // parser, and an alias or an escape makes one the text does not show.
  test("the kit holds no $ but the two scratch password values, each once on its own key", () => {
    const why = /compose\.yml must hold no \$ but the two scratch password values, each once on its own key; compose would fill it from the box's environment$/;
    const pass = "      - INDEXER_PASSWORD=${SCRATCH_INDEXER_PASS:?logtest.ts writes .env first}\n";
    const api = "      - API_PASSWORD=${SCRATCH_API_PASS:?logtest.ts writes .env first}\n";
    // A third "$" anywhere: an environment value, a comment, a scalar, a block scalar, a
    // volume name, written plainly or escaped.
    const user = (v: string) => edit("      - INDEXER_USERNAME=admin\n", `      - INDEXER_USERNAME=${v}\n`);
    for (const v of ["${USER}", "$USER", "a$$b", "${SCRATCH_API_PASS:?logtest.ts writes .env first}"]) expect(() => checkKit(user(v))).toThrow(why);
    expect(() => checkKit(`# $HOME\n${KIT}`)).toThrow(why);
    expect(() => checkKit(edit("    hostname: b1test\n", "    hostname: b1test-$HOSTNAME\n"))).toThrow(why);
    expect(() => checkKit(edit("    hostname: b1test\n", "    hostname: |\n      $x\n"))).toThrow(why);
    expect(() => checkKit(edit("      - INDEXER_USERNAME=admin\n", '      - "INDEXER_USERNAME=\\x24USER"\n'))).toThrow(why);
    expect(() => checkKit(edit("  etc:\n", '  etc:\n  "\\x24v":\n'))).toThrow(why);
    // A password copied by an alias, or escaped so the text a reviewer reads shows no "$".
    const aliased = edit(pass, "      - *p\n").replace("    hostname: b1test\n", `    hostname: &p ${pass.trim().slice(2)}\n`);
    expect(() => checkKit(aliased)).toThrow(why);
    expect(() => checkKit(edit(pass, `      - "${pass.trim().slice(2).replace("$", "\\x24")}"\n`))).toThrow(why);
    // Either value altered, swapped onto the other key, missing, or given twice.
    for (const v of ["${SCRATCH_API_PASS:?logtest.ts writes .env first}", "${SCRATCH_INDEXER_PASS}", "${SCRATCH_INDEXER_PASS:?x}", "$SCRATCH_INDEXER_PASS"]) {
      expect(() => checkKit(edit(pass, `      - INDEXER_PASSWORD=${v}\n`))).toThrow(why);
    }
    for (const v of ["${SCRATCH_INDEXER_PASS:?logtest.ts writes .env first}", "${SCRATCH_API_PASS}", "${SCRATCH_API_PASS:-x}"]) {
      expect(() => checkKit(edit(api, `      - API_PASSWORD=${v}\n`))).toThrow(why);
    }
    expect(() => checkKit(edit(pass, ""))).toThrow(why);
    expect(() => checkKit(edit(api, pass))).toThrow(why);
    // The checked-in kit passes, and so do the passwords in mapping form.
    expect(() => checkKit(KIT)).not.toThrow();
    expect(() => checkKit(mapped("      INDEXER_USERNAME: admin\n"))).not.toThrow();
  });

  // Bun.YAML drops tags, so "!reset none" reads as "none" while compose removes the key.
  // Every "!" that can start a node is refused, quoted or not: telling quotes apart takes a
  // YAML tokenizer, and a naive one reads the ' in a block scalar as opening a quote that
  // hides a real tag on a later line.
  test("the kit uses no YAML tag, wherever a node can start", () => {
    const why = (tag: string) => new RegExp(`compose\\.yml must not use the YAML tag ${tag}; compose acts on tags, which this check never sees$`);
    const reset = edit("network_mode: none", "network_mode: !reset none");
    expect(Bun.YAML.parse(reset).services["wazuh.manager"].network_mode).toBe("none");
    expect(() => checkKit(reset)).toThrow(why("!reset"));
    expect(() => checkKit(edit("    volumes:\n      - etc:", "    volumes: !override\n      - etc:"))).toThrow(why("!override"));
    expect(() => checkKit(edit("    hostname: b1test\n", "    hostname: !custom b1test\n"))).toThrow(why("!custom"));
    for (const [at, tag] of [
      [`!x\n${KIT}`, "!x"],
      [edit("      - etc:/var/ossec/etc\n", "      - !x etc:/var/ossec/etc\n"), "!x"],
      [edit("      - etc:/var/ossec/etc\n", "      -!x etc:/var/ossec/etc\n"), "!x"],
      [edit("    hostname: b1test\n", "    hostname: [!x a]\n"), "!x"],
      [edit("    hostname: b1test\n", "    hostname: {!x a: b}\n"), "!x"],
      [edit("    hostname: b1test\n", "    hostname: [a,!x b]\n"), "!x"],
      [edit("    hostname: b1test\n", "    hostname: {a:!x b}\n"), "!x"],
      [edit("    hostname: b1test\n", '    hostname: {"a":!x b}\n'), "!x"],
      [edit("    hostname: b1test\n", "    hostname:\t!x b1test\n"), "!x"],
      [edit("    hostname: b1test\n", "    hostname: x\u0085!x b1test\n"), "!x"],
      [edit("    hostname: b1test\n", '    hostname: "b1 !x"\n'), "!x"],
      [edit("    hostname: b1test\n", "    hostname: >-\n      'a\n    network_mode: !reset none\n    x: b'\n").replace("    network_mode: none\n", ""), "!reset"],
    ]) {
      expect(() => checkKit(at)).toThrow(why(tag));
    }
    // A "!" inside a word starts no node.
    expect(() => checkKit(edit("    hostname: b1test\n", "    hostname: b1test!x\n"))).not.toThrow();
    expect(() => checkKit(`# scratch only!\n${KIT}`)).not.toThrow();
    expect(() => checkKit(KIT)).not.toThrow();
  });

  // Image-shaped text in another value names nothing, and the kit's key must be a literal
  // tag: the box's environment would fill a ${NAME:-tag}.
  test("the kit's image key is the image it runs, as a literal tag", () => {
    const swapped = edit("    image: wazuh/wazuh-manager:4.14.9\n    hostname: b1test\n", "    hostname: >-\n      image: wazuh/wazuh-manager:4.14.9\n    image: busybox:latest\n");
    expect(() => managerImage(swapped)).toThrow(/wazuh\.manager image "busybox:latest" is not wazuh\/wazuh-manager:<tag>/);
    expect(() => checkKit(swapped)).toThrow(/^tools\/logtest\/compose\.yml: wazuh\.manager image "busybox:latest" is not/);
    const interpolated = edit("    image: wazuh/wazuh-manager:4.14.9\n", "    image: wazuh/wazuh-manager:${WAZUH_VERSION:-4.14.9}\n");
    expect(managerImage(interpolated)).toBe("4.14.9");
    expect(() => checkKit(interpolated)).toThrow(/compose\.yml image wazuh\/wazuh-manager:\$\{WAZUH_VERSION:-4\.14\.9\} is not wazuh\/wazuh-manager:4\.14\.9$/);
  });
});

describe("manifest", () => {
  test("lists each file with its SHA-256 in path order, and a link as not-a-file", () => {
    const dir = mkdtempSync(join(tmpdir(), "logtest-man-"));
    try {
      mkdirSync(join(dir, "sub"));
      writeFileSync(join(dir, "b.xml"), "b");
      writeFileSync(join(dir, "a.xml"), "a");
      writeFileSync(join(dir, "sub/c.xml"), "c");
      symlinkSync("a.xml", join(dir, "z-link"));
      const h = (s: string) => createHash("sha256").update(s).digest("hex");
      expect(manifest(dir)).toBe([`${h("a")}  ./a.xml`, `${h("b")}  ./b.xml`, `${h("c")}  ./sub/c.xml`, "not-a-file  ./z-link"].join("\n"));
      writeFileSync(join(dir, "a b.xml"), "x");
      expect(() => manifest(dir)).toThrow(SetupError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("clean", () => {
  // A newline in a printed value would start a line of its own, such as a forged verdict.
  test("replaces every control character, tabs and line breaks included", () => {
    expect(clean("a\u001b[2Kb\tc\nd\re\u0007\u2028\u009b")).toBe("a?[2Kb?c?d?e???");
    expect(clean("x\nPASS pos 100399 forged")).toBe("x?PASS pos 100399 forged");
  });

  // A right-to-left override or isolate in event text reorders how the rest of a printed
  // line displays, so a FAIL line could be drawn to read as something else.
  test("replaces every bidirectional format character, and leaves ordinary non-ASCII text alone", () => {
    const bidi = [0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069];
    for (const c of bidi) expect([c.toString(16), clean(`a${String.fromCodePoint(c)}b`)]).toEqual([c.toString(16), "a?b"]);
    expect(clean("FAIL neg 100398 x.json: ‮dessap‬")).toBe("FAIL neg 100398 x.json: ?dessap?");
    // Their neighbours in each block are not bidi controls, and pass.
    for (const s of ["café", "Microsoft® Windows®", "؛؝", "​‍", "‐‧", " ‰", "⁠⁤"]) expect(clean(s)).toBe(s);
    // The fixture event that carries the "(R)" of Microsoft's product strings is unchanged.
    const branded = EVENTS.filter((e) => e.includes("®"));
    expect(branded.length).toBeGreaterThan(0);
    for (const e of branded) expect(clean(e)).toBe(e);
  });
});

describe("packStage", () => {
  // macOS tar writes a "._name" AppleDouble entry for any file with an extended attribute.
  // On the box that entry lands in custom-rules, analysisd reads it as a rules file and
  // exits, and the logtest socket never opens (first scratch run, 2026-11-05).
  test.skipIf(process.platform !== "darwin")("packs no AppleDouble entry for a file with an extended attribute", () => {
    const dir = mkdtempSync(join(tmpdir(), "logtest-pack-"));
    try {
      mkdirSync(join(dir, "custom-rules"));
      const file = join(dir, "custom-rules/selftest.xml");
      writeFileSync(file, "<group/>\n");
      expect(Bun.spawnSync(["xattr", "-w", "com.example.logtest", "1", file]).exitCode).toBe(0);
      // Read the raw stream: macOS tar folds a "._name" entry back into its file when it
      // lists or extracts, so "tar -t" here would hide what GNU tar on the box unpacks.
      const raw = Buffer.from(packStage(dir)).toString("latin1");
      expect(raw).toContain("./custom-rules/selftest.xml");
      expect(raw.match(/\._[\w.-]+/g) ?? []).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // GNU tar takes options from TAR_OPTIONS (a checkpoint action can run a command), and
  // macOS tar from TAR_WRITER_OPTIONS (an unknown one fails the archive). A tar first on
  // PATH that prints its environment shows what the local archive runs with.
  test("runs tar with COPYFILE_DISABLE and without any tar options variable", () => {
    const stub = temp("tar-stub");
    writeFileSync(join(stub, "tar"), "#!/bin/sh\nenv | grep -E '^(TAR_[A-Z_]*|COPYFILE_DISABLE)=' | LC_ALL=C sort\n");
    chmodSync(join(stub, "tar"), 0o755);
    const keys = ["PATH", "TAR_OPTIONS", "TAR_READER_OPTIONS", "TAR_WRITER_OPTIONS"];
    const was = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
    try {
      Object.assign(process.env, {
        PATH: `${stub}:${process.env.PATH}`,
        TAR_OPTIONS: "--checkpoint=1 --checkpoint-action=exec=true",
        TAR_READER_OPTIONS: "nonsense=1",
        TAR_WRITER_OPTIONS: "nonsense=1",
      });
      expect(Buffer.from(packStage(stub)).toString()).toBe("COPYFILE_DISABLE=1\n");
    } finally {
      for (const k of keys) {
        if (was[k] === undefined) delete process.env[k];
        else process.env[k] = was[k];
      }
    }
  });
});

describe("bootErrors", () => {
  const log = [
    "wazuh.manager-1  | [cont-init.d] 0-wazuh-init: exited 0.",
    "wazuh.manager-1  | 2026/11/06 02:00:48 wazuh-analysisd: ERROR: (1202): Configuration error at 'etc/rules/custom/._selftest.xml'.",
    "wazuh.manager-1  | 2026/11/06 02:00:48 wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/custom/._selftest.xml'.",
    "wazuh.manager-1  | 2026/11/06 02:00:48 wazuh-analysisd: ERROR: (1202): Configuration error at 'etc/rules/custom/._selftest.xml'.",
    "wazuh.manager-1  | 2026-11-06T02:00:48.129Z\tINFO\tinstance/beat.go:299\tSetup Beat: filebeat",
  ].join("\n");

  test("names each ERROR and CRITICAL line once, without the compose prefix", () => {
    expect(bootErrors(log)).toBe(
      ":\n2026/11/06 02:00:48 wazuh-analysisd: ERROR: (1202): Configuration error at 'etc/rules/custom/._selftest.xml'.\n" +
        "2026/11/06 02:00:48 wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/custom/._selftest.xml'.",
    );
  });

  test("adds nothing when the boot log holds no error", () => {
    expect(bootErrors("wazuh.manager-1  | [cont-init.d] 0-wazuh-init: exited 0.\n")).toBe("");
  });
});

describe("loadCases", () => {
  test("reads the fixture cases, decoding each capture to one line", () => {
    const cases = loadCases(CASES);
    expect(cases.map((c) => `${c.rule}/${c.kind}`)).toEqual(["100398/neg", "100398/pos", "100399/neg", "100399/pos", "92900/pos"]);
    for (const c of cases) expect(c.event.startsWith('{"win":{"system":')).toBe(true);
  });

  test("refuses a misnamed file, a non-id folder, bad JSON and an empty case", () => {
    const tmp = mkdtempSync(join(tmpdir(), "logtest-t-"));
    try {
      const bad = (setup: (d: string) => void, msg: RegExp) => {
        const d = join(tmp, String(Math.random()).slice(2));
        cpSync(CASES, d, { recursive: true });
        setup(d);
        expect(() => loadCases(d)).toThrow(msg);
      };
      bad((d) => writeFileSync(join(d, "100399/positive.json"), "{}"), /not named pos/);
      bad((d) => mkdirSync(join(d, "certutil")), /not a rule id folder/);
      bad((d) => writeFileSync(join(d, "100399/pos-x.json"), "{"), /is not JSON/);
      bad((d) => writeFileSync(join(d, "100399/neg-x.json"), "{}"), /neither a capture nor an event/);
      bad((d) => writeFileSync(join(d, "100399/neg-x.json"), JSON.stringify({ event: "" })), /neither a capture nor an event/);
      // Finder's .DS_Store is the one name skipped; any other dot name is refused.
      bad((d) => mkdirSync(join(d, ".git")), /\/\.git is not a rule id folder$/);
      bad((d) => writeFileSync(join(d, ".hidden"), ""), /\/\.hidden is not a rule id folder$/);
      bad((d) => writeFileSync(join(d, "100399/.gitkeep"), ""), /\/100399\/\.gitkeep is not named pos-<name>\.json or neg-<name>\.json$/);
      bad((d) => mkdirSync(join(d, "100399/.cache")), /\/100399\/\.cache is not named pos-<name>\.json or neg-<name>\.json$/);
      const ds = join(tmp, "ds");
      cpSync(CASES, ds, { recursive: true });
      writeFileSync(join(ds, ".DS_Store"), "");
      writeFileSync(join(ds, "100399/.DS_Store"), "");
      expect(loadCases(ds).map((c) => c.event)).toEqual(EVENTS);
      // A folder of that name is not Finder's, and skipping it would drop every case in it
      // unseen, so it is refused at either level, before the box is touched.
      const dsFolder = /\/\.DS_Store is a folder, and the case reader skips only a \.DS_Store file$/;
      for (const at of [".DS_Store", "100399/.DS_Store"]) {
        bad((d) => {
          mkdirSync(join(d, at));
          cpSync(join(d, "100399/neg-updater.json"), join(d, at, "neg-updater.json"));
        }, dsFolder);
        const d = join(tmp, String(Math.random()).slice(2));
        cpSync(CASES, d, { recursive: true });
        mkdirSync(join(d, at));
        const f = fakeBox();
        expect(() => run(opts({ cases: d }), f.box)).toThrow(dsFolder);
        expect(f.calls).toEqual([]);
      }
      bad((d) => writeFileSync(join(d, "100399/neg-x.json"), JSON.stringify({ event: "a\nb" })), /one event per line/);
      bad((d) => writeFileSync(join(d, "100399/neg-x.json"), "null"), /not a JSON object/);
      bad((d) => writeFileSync(join(d, "100399/neg-x.json"), "[]"), /not a JSON object/);
      bad((d) => writeFileSync(join(d, "100399/neg-x.json"), JSON.stringify({ capture: {} })), /does not decode/);
      for (const run of [() => loadCases(join(tmp, "missing")), () => loadCases(resolve(CASES, "100399/pos-powershell.json"))]) {
        expect(run).toThrow(SetupError);
        expect(run).toThrow(/no cases folder/);
      }
      expect(() => loadCases(join(tmp, "missing"))).toThrow(/no cases folder/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  // The shim decodes a line that opens {"win":{"system": as a Windows event without the port,
  // so a hand-written one would pass here on backslashes and quirks live never has, and one
  // the json decoder takes instead never reaches a Windows rule. Windows cases are captures.
  test("refuses an event case that holds a Windows event, however it is spelled", () => {
    const win = FIXTURES[at("100399/pos-powershell.json")].event;
    expect(win.startsWith('{"win":{"system":')).toBe(true);
    const one = (event: unknown) => {
      const d = temp("winevent");
      mkdirSync(join(d, "100399"));
      writeFileSync(join(d, "100399/neg-hand.json"), JSON.stringify({ event }));
      return () => loadCases(d);
    };
    const why = /^\S*100399\/neg-hand\.json: an event case holds a Windows event, which the shim decodes without the port; use capture for Windows events$/;
    for (const event of [
      win,
      ` ${win}`,
      win.replace('{"win":{"system":', '{ "win" :\t{ "system" : '),
      '{"win":{"system":{',
      ' {\t"win" :',
      JSON.stringify({ agent: { id: "001" }, ...JSON.parse(win) }),
      win.replace('"win"', '"\\u0077in"'),
      '{"win":"x"}',
    ]) {
      let err: unknown;
      try {
        one(event)();
      } catch (e) {
        err = e;
      }
      expect([event.slice(0, 40), err instanceof SetupError, String((err as Error | undefined)?.message)]).toEqual([event.slice(0, 40), true, expect.stringMatching(why)]);
    }
    // Other JSON, a win key below the top, an array and a plain line are events like any other.
    for (const event of ['{"timestamp":"2026-11-08T00:00:00Z","event_type":"alert"}', '{"winner":1}', '{"data":{"win":{"system":{}}}}', '[{"win":{}}]', "Nov  8 00:00:00 host sshd[1]: x"]) {
      expect(one(event)().map((c) => c.event)).toEqual([event]);
    }
  });

  // tools/README.md: a case holding both keys is read as its capture, and its event is
  // ignored, not tested, a Windows-shaped one included.
  test("a case holding both a capture and an event is read as its capture", () => {
    const { capture } = JSON.parse(readFileSync(join(CASES, "100399/pos-powershell.json"), "utf8"));
    const want = FIXTURES[at("100399/pos-powershell.json")].event;
    for (const event of ["Nov  8 00:00:00 host sshd[1]: x", '{"win":{"system":{}}}', 7]) {
      const d = temp("both");
      mkdirSync(join(d, "100399"));
      writeFileSync(join(d, "100399/pos-both.json"), JSON.stringify({ event, capture }));
      expect(loadCases(d).map((c) => c.event)).toEqual([want]);
    }
  });

  // A run with no cases would judge nothing and still exit 0.
  test("refuses a cases folder with no case in it", () => {
    const empty = temp("empty");
    expect(() => loadCases(empty)).toThrow(/no cases under/);
    mkdirSync(join(empty, "100399"));
    writeFileSync(join(empty, "100399/.DS_Store"), "");
    expect(() => loadCases(empty)).toThrow(SetupError);
    expect(() => loadCases(empty)).toThrow(/no cases under/);
  });
});

describe("parseReplies", () => {
  test("reads one result per Reply line and ignores everything else", () => {
    const out = parseReplies(transcript(reply({ id: "100399", level: 10, mitre: ["T1059.001"] }), reply(), reply({ id: "61603", level: 0 })));
    expect(out).toEqual([
      { rule: 100399, level: 10, mitre: ["T1059.001"], decoder: "windows_eventchannel", alert: true, warnings: [] },
      { rule: undefined, level: undefined, mitre: [], decoder: "windows_eventchannel", alert: false, warnings: [] },
      { rule: 61603, level: 0, mitre: [], decoder: "windows_eventchannel", alert: false, warnings: [] },
    ]);
  });

  test("keeps WARNING messages and drops the rest", () => {
    const w = "WARNING: (7000): Mitre Technique ID 'T1685' not found in database.";
    const [r] = parseReplies(transcript(reply({ id: "100399", level: 10 }, ["INFO: (7202): Session initialized", w])));
    expect(r.warnings).toEqual([w]);
  });

  test("fails closed on an error reply or one that does not parse", () => {
    const at = "2026-11-02 18:00:00,001 wazuh_logtest[DEBUG] Reply: ";
    expect(() => parseReplies(at + JSON.stringify({ error: 1, message: "socket" }))).toThrow(SetupError);
    expect(() => parseReplies(`${at}{not json}`)).toThrow(SetupError);
    expect(() => parseReplies(at + JSON.stringify({ error: 0, data: { codemsg: -1, messages: ["bad"] } }))).toThrow(/refused/);
  });

  // analysisd sets error when it could not serve the request, so whatever output rides with
  // it is no verdict: the run stops (exit 2) rather than judge a case on it.
  test("an error reply stops the run even when it carries a whole output", () => {
    const line = reply({ id: "100399", level: 10, mitre: ["T1059.001"] }).replace('{"error":0,', '{"error":2,"message":"boom",');
    expect(line).toContain('"error":2');
    expect(() => parseReplies(line)).toThrow(SetupError);
    expect(() => parseReplies(line)).toThrow(/^logtest error 2: boom$/);
    const first = REAL_REPLIES[0];
    expect(first).toContain('{"error":0,');
    const failed = REAL.replace(first, first.replace('{"error":0,', '{"error":1,'));
    expect(() => run(opts(), fakeBox({ transcript: failed }).box)).toThrow(/^logtest error 1:/);
  });

  // An event can carry any text, so a Reply line planted inside one must not count.
  // Each planted line is a whole logger line carrying the session's own token, so the
  // line anchor is the only thing that keeps it out.
  test("ignores a Reply line that is indented, quoted or mid-line", () => {
    const real = reply({ id: "61603", level: 0 });
    const fake = reply({ id: "100399", level: 10, mitre: ["T1059.001"] }).trimEnd();
    const lines = [`\t${fake}`, ` ${fake}`, `x ${fake}`, `full event: '${fake}'`];
    const out = parseReplies([real.trimEnd(), ...lines].join("\n"));
    expect(out.map((r) => r.rule)).toEqual([61603]);
  });

  test("reads a reply that carries U+2028 or U+2029 raw", () => {
    const line = reply({ id: "61603", level: 0 }).replace("windows_eventchannel", "win\u2028dows\u2029");
    expect(parseReplies(line).map((r) => r.decoder)).toEqual(["win\u2028dows\u2029"]);
  });

  test("reads the real transcript: five replies, one session token", () => {
    expect(parseReplies(REAL)).toEqual([
      { rule: 92900, level: 12, mitre: ["T1003.001"], decoder: "windows_eventchannel", alert: true, warnings: [] },
      { rule: 100398, level: 10, mitre: ["T1071"], decoder: "windows_eventchannel", alert: true, warnings: [] },
      { rule: 61603, level: 0, mitre: [], decoder: "windows_eventchannel", alert: false, warnings: [] },
      { rule: 100399, level: 10, mitre: ["T1059.001"], decoder: "windows_eventchannel", alert: true, warnings: [] },
      { rule: 92900, level: 12, mitre: ["T1003.001"], decoder: "windows_eventchannel", alert: true, warnings: [] },
    ]);
  });

  // The CLI prints a decoded field raw, so the second line of a multi-line value starts
  // at column 0 (the real transcript has many such lines). Event text can therefore hold a
  // whole logger-shaped Reply line; what it cannot hold is the session token, which
  // analysisd picks after the event is written.
  test("refuses a Reply line planted at column 0 by event text", () => {
    const real = reply({ id: "61603", level: 0 });
    const planted = reply({ id: "100399", level: 10, mitre: ["T1059.001"] }, [], "deadbeef");
    expect(() => parseReplies(transcript(real, planted))).toThrow(/token/);
    const bare = planted.replace('"token":"deadbeef",', "");
    expect(bare).not.toContain("token");
    expect(() => parseReplies(transcript(real, bare))).toThrow(/token/);
    // In the real transcript, after the first event's own text.
    const at = REAL.indexOf("\nRuleName:");
    expect(at).toBeGreaterThan(0);
    expect(() => parseReplies(`${REAL.slice(0, at)}\n${planted}${REAL.slice(at + 1)}`)).toThrow(/token/);
  });

  test("refuses a first reply with no session token", () => {
    expect(() => parseReplies(reply({ id: "61603", level: 0 }).replace('"token":"1a2b3c4d",', ""))).toThrow(SetupError);
  });
});

describe("evaluate", () => {
  test("a positive passes on its rule with the XML's level and mitre; a negative on any other", () => {
    expect(whys([kase(100399, "pos"), kase(100399, "neg"), kase(92900, "pos")], [res(100399, 10, ["T1059.001"]), res(61603, 0), res(92900, 12)])).toEqual([
      "pass",
      "pass",
      "pass",
    ]);
  });

  // ISA ISC-122, offline half: the same result judged against a flipped expectation fails.
  test("fails a flipped expectation either way", () => {
    expect(whys([kase(100399, "neg")], [res(100399, 10, ["T1059.001"])])).toEqual(["rule 100399 fired"]);
    expect(whys([kase(100399, "pos")], [res(61603, 0)])).toEqual(["expected rule 100399"]);
  });

  // A reply with no rule at all fails a positive as surely as one naming another rule.
  test("fails a positive whose reply carries no rule, pack or stock; a negative passes on it", () => {
    expect(whys([kase(100399, "pos")], [res(undefined)])).toEqual(["expected rule 100399"]);
    expect(whys([kase(92900, "pos")], [res(undefined)])).toEqual(["expected rule 92900"]);
    expect(whys([kase(100399, "neg")], [res(undefined)])).toEqual(["pass"]);
  });

  test("fails a positive whose level, mitre or warnings disagree with the XML", () => {
    expect(whys([kase(100399, "pos")], [res(100399, 3, ["T1059.001"])])).toEqual(["XML level is 10"]);
    expect(whys([kase(100399, "pos")], [res(100399, 10, [])])).toEqual(["XML mitre is [T1059.001]"]);
    expect(whys([kase(100399, "pos")], [res(100399, 10, ["T1059.001"], ["WARNING: x"])])).toEqual(["WARNING: x"]);
  });

  // A rule that fires without an alert (level 0, no_log) never reaches the indexer.
  test("fails a positive whose rule fired with no alert, pack or stock; a negative ignores alert", () => {
    const quiet = (r: Result): Result => ({ ...r, alert: false });
    expect(whys([kase(100399, "pos")], [quiet(res(100399, 10, ["T1059.001"]))])).toEqual(["rule 100399 fired with no alert"]);
    expect(whys([kase(92900, "pos")], [quiet(res(92900, 12, ["T1003.001"]))])).toEqual(["rule 92900 fired with no alert"]);
    expect(whys([kase(100399, "neg")], [quiet(res(61603, 0))])).toEqual(["pass"]);
  });

  // Stock rules pass on id and alert alone; a pack id the folder lacks came from somewhere
  // else, such as a manager kept from another tree.
  test("fails any case whose reply fired a pack rule the folder under test lacks; a stock rule still passes", () => {
    const foreign = "pack rule 100397 fired but is not in the rules folder under test";
    expect(whys([kase(100397, "pos")], [res(100397, 10, ["T1071"])])).toEqual([foreign]);
    expect(whys([kase(100399, "neg")], [res(100397, 10, ["T1071"])])).toEqual([foreign]);
    expect(whys([kase(100399, "pos")], [res(100397, 10)])).toEqual([`expected rule 100399; ${foreign}`]);
    expect(whys([kase(92900, "pos")], [res(92900, 12, ["T1003.001"])])).toEqual(["pass"]);
  });

  // An event that matched A and then a child of A ends on the child, so a negative for A
  // must also fail when the final rule descends from A through if_sid links in the folder.
  test("fails a negative whose final rule descends from its rule through if_sid links in the folder under test", () => {
    const xml = [
      '<group name="chain,">',
      '  <rule id="100397" level="10"><if_sid>61603</if_sid><description>A</description></rule>',
      '  <rule id="100396" level="10"><if_sid>100397</if_sid><description>B, child of A</description></rule>',
      '  <rule id="100395" level="10"><if_sid>61603, 100396</if_sid><description>C, child of B</description></rule>',
      '  <rule id="100394" level="10"><if_sid>100393</if_sid><description>D</description></rule>',
      '  <rule id="100393" level="10"><if_sid>100394</if_sid><description>E, a loop with D</description></rule>',
      '  <rule id="100392" level="10"><if_sid>92900</if_sid><description>F, child of a stock rule</description></rule>',
      '  <rule id="100200" level="5"><if_sid>100397</if_sid><description>G, local, outside the pack ranges</description></rule>',
      '  <rule id="100391" level="10"><if_sid>100200</if_sid><description>H, child of G</description></rule>',
      '  <rule id="100389" level="10"><if_sid>92901</if_sid><description>J, child of a stock rule outside the folder</description></rule>',
      "</group>",
    ].join("\n");
    const tree = new Map(parseRules(xml, "chain.xml").map((r) => [r.id, r]));
    const judge = (c: Case, r: Result) => evaluate([c], [r], tree).map((v) => (v.pass ? "pass" : v.why));
    expect(judge(kase(100397, "neg"), res(100396, 10))).toEqual(["rule 100397 fired (final rule 100396 descends from it)"]);
    expect(judge(kase(100397, "neg"), res(100395, 10))).toEqual(["rule 100397 fired (final rule 100395 descends from it)"]);
    expect(judge(kase(92900, "neg"), res(100392, 10))).toEqual(["rule 92900 fired (final rule 100392 descends from it)"]);
    // Every rule in the folder carries the walk, pack or not: a local child outside the
    // pack ranges, as the final rule or as a link.
    expect(judge(kase(100397, "neg"), res(100200, 5))).toEqual(["rule 100397 fired (final rule 100200 descends from it)"]);
    expect(judge(kase(100397, "neg"), res(100391, 10))).toEqual(["rule 100397 fired (final rule 100391 descends from it)"]);
    // A loop ends the walk; a stock final rule, a parent, or a stock link outside the
    // folder (whose own parents are unknown here) is not a descent.
    expect(judge(kase(100397, "neg"), res(100394, 10))).toEqual(["pass"]);
    expect(judge(kase(100397, "neg"), res(61603, 0))).toEqual(["pass"]);
    expect(judge(kase(100396, "neg"), res(100397, 10))).toEqual(["pass"]);
    expect(judge(kase(92900, "neg"), res(100389, 10))).toEqual(["pass"]);
    // A positive for A still needs A as the final rule.
    expect(judge(kase(100397, "pos"), res(100396, 10))).toEqual(["expected rule 100397"]);
  });

  // A rule hangs from another by if_sid, by if_matched_sid, and by a group the other is in
  // through if_group or if_matched_group (rules.c 988-1017, 1662-1678), so a level-0 local
  // child by any of these hides a match on its parent as well.
  test("fails a negative whose final rule descends from its rule through if_group, if_matched_sid or if_matched_group", () => {
    const xml = [
      '<group name="pack_a,">',
      '  <rule id="100397" level="10"><if_sid>61603</if_sid><description>A</description></rule>',
      "</group>",
      '<group name="local,">',
      '  <rule id="100200" level="0"><if_group>pack_a</if_group><description>child of A by group</description></rule>',
      '  <rule id="100201" level="0"><if_sid>61603</if_sid><if_matched_sid>100397</if_matched_sid><description>after A</description></rule>',
      '  <rule id="100202" level="0"><if_matched_group>pack_a</if_matched_group><description>after A by group</description></rule>',
      '  <rule id="100203" level="0"><if_group>unrelated</if_group><description>child of a group no rule here is in</description></rule>',
      '  <rule id="100204" level="0"><if_sid>100397</if_sid><group>mid,</group><description>child of A by id</description></rule>',
      '  <rule id="100205" level="0"><if_group>mid</if_group><description>child of 100204 by group</description></rule>',
      '  <rule id="100206" level="0"><if_sid>100200</if_sid><description>child of 100200 by id</description></rule>',
      '  <rule id="100207" level="0"><if_group>loop_b</if_group><group>loop_a,</group><description>a group loop</description></rule>',
      '  <rule id="100208" level="0"><if_group>loop_a</if_group><group>loop_b,</group><description>a group loop</description></rule>',
      '  <rule id="100209" level="0"><if_group>windows</if_group><description>child of stock groups, unknown here</description></rule>',
      "</group>",
    ].join("\n");
    const tree = new Map(parseRules(xml, "chain.xml").map((r) => [r.id, r]));
    const judge = (c: Case, r: Result) => evaluate([c], [r], tree).map((v) => (v.pass ? "pass" : v.why));
    const hid = (final: number) => [`rule 100397 fired (final rule ${final} descends from it)`];
    expect(judge(kase(100397, "neg"), res(100200, 0))).toEqual(hid(100200));
    expect(judge(kase(100397, "neg"), res(100201, 0))).toEqual(hid(100201));
    expect(judge(kase(100397, "neg"), res(100202, 0))).toEqual(hid(100202));
    // Mixed chains: if_sid then if_group, and if_group then if_sid.
    expect(judge(kase(100397, "neg"), res(100205, 0))).toEqual(hid(100205));
    expect(judge(kase(100397, "neg"), res(100206, 0))).toEqual(hid(100206));
    // A group no rule in the folder is in, a group loop, and a stock group (whose members are
    // not known here) are not a descent.
    expect(judge(kase(100397, "neg"), res(100203, 0))).toEqual(["pass"]);
    expect(judge(kase(100397, "neg"), res(100207, 0))).toEqual(["pass"]);
    expect(judge(kase(92900, "neg"), res(100209, 0))).toEqual(["pass"]);
    // A positive for A still needs A as the final rule.
    expect(judge(kase(100397, "pos"), res(100200, 0))).toEqual(["expected rule 100397"]);
  });

  // OS_WordMatch (os_regex_match.c 32-121) splits a group pattern on "|"; a piece that
  // starts "^" is a case-insensitive prefix of the group text, any other piece a
  // case-insensitive substring, and "$" is literal. An empty pattern links nothing, and an
  // empty piece is taken as a link, so an error fails a negative rather than passing one.
  // if_matched_group also goes through OSMatch (rules_list.c 536), where "$" may anchor.
  test("links by group as OS_WordMatch does, an empty alternative counting as a link", () => {
    const links: [number, string][] = [
      [100210, "<if_group>^pack</if_group>"],
      [100211, "<if_group>ack_a</if_group>"],
      [100212, "<if_group>PACK_A</if_group>"],
      [100213, "<if_group>other|Pack_A</if_group>"],
      [100214, "<if_group>other||nothing</if_group>"],
      [100215, "<if_group>other|</if_group>"],
      [100216, "<if_group>pack_a$</if_group>"],
      [100217, "<if_group>^ack_a</if_group>"],
      [100218, "<if_group></if_group>"],
      [100219, "<if_group>pack_b|^a</if_group>"],
      [100220, "<if_matched_group>pack_a$</if_matched_group>"],
      [100221, "<if_matched_group>^PACK</if_matched_group>"],
      [100222, "<if_matched_group>^pack_a$</if_matched_group>"],
      [100223, "<if_matched_group>pack_b$</if_matched_group>"],
      [100224, "<if_matched_group>^ck_a$</if_matched_group>"],
      [100225, "<if_matched_group>^pack$</if_matched_group>"],
    ];
    const xml = [
      '<group name="Pack_A"><rule id="100397" level="10"><if_sid>61603</if_sid><description>A</description></rule></group>',
      '<group name="local,">',
      ...links.map(([id, link]) => `  <rule id="${id}" level="0">${link}<description>x</description></rule>`),
      "</group>",
    ].join("\n");
    const tree = new Map(parseRules(xml, "groups.xml").map((r) => [r.id, r]));
    const linked = links.map(([id]) => id).filter((id) => !evaluate([kase(100397, "neg")], [res(id, 0)], tree)[0].pass);
    expect(linked).toEqual([100210, 100211, 100212, 100213, 100214, 100215, 100220, 100221, 100222]);
  });

  // rules_list.c 82-89 and 178-194 hang a rule with <if_level>N under every other rule of
  // level N or more. Levels are compared while a level-0 rule still reads as 99 (rules.c
  // 393-404), so a level-0 rule is such a parent for any N up to 99.
  test("fails a negative whose final rule descends from its rule through if_level", () => {
    const judge = (rules: string[], c: Case, final: number) => {
      const tree = new Map(parseRules(`<group name="local,">${rules.join("")}</group>`, "level.xml").map((r) => [r.id, r]));
      return evaluate([c], [res(final, 0)], tree).map((v) => (v.pass ? "pass" : v.why));
    };
    const rule = (id: number, level: number, inner: string) => `<rule id="${id}" level="${level}">${inner}<description>x</description></rule>`;
    const pack = (level: number) => rule(100397, level, "<if_sid>61603</if_sid>");
    const final = rule(100230, 0, "<if_level>10</if_level>");
    const hid = ["rule 100397 fired (final rule 100230 descends from it)"];
    expect(judge([pack(10), final], kase(100397, "neg"), 100230)).toEqual(hid);
    expect(judge([pack(16), final], kase(100397, "neg"), 100230)).toEqual(hid);
    expect(judge([pack(9), final], kase(100397, "neg"), 100230)).toEqual(["pass"]);
    // if_level then if_sid: 100231 is at level 12, a child of the level-9 pack rule.
    const mid = rule(100231, 12, "<if_sid>100397</if_sid>");
    expect(judge([pack(9), mid, final], kase(100397, "neg"), 100230)).toEqual(hid);
    // Followed beside an if_sid too, though rules_list.c places such a rule by if_sid alone.
    const both = rule(100230, 0, "<if_sid>61603</if_sid><if_level>10</if_level>");
    expect(judge([pack(10), both], kase(100397, "neg"), 100230)).toEqual(hid);
    // A level-0 rule counts as level 99 here, so a level-0 child of the pack rule is a parent.
    const quiet = rule(100232, 0, "<if_sid>100397</if_sid>");
    expect(judge([pack(9), quiet, final], kase(100397, "neg"), 100230)).toEqual(hid);
    // An if_level rule is not its own parent, and a stock rule's level is not known here.
    expect(judge([rule(100230, 12, "<if_level>10</if_level>")], kase(100397, "neg"), 100230)).toEqual(["pass"]);
    expect(judge([final], kase(92900, "neg"), 100230)).toEqual(["pass"]);
  });

  // Ruleset warnings ride on the first reply, and the first case is usually a negative.
  test("fails a negative, or a positive on a rule outside the XML, that carries a warning", () => {
    expect(whys([kase(100399, "neg")], [res(61603, 0, [], ["WARNING: x"])])).toEqual(["WARNING: x"]);
    expect(whys([kase(92900, "pos")], [res(92900, 12, [], ["WARNING: y"])])).toEqual(["WARNING: y"]);
  });

  test("refuses a reply count that does not match the cases", () => {
    expect(() => evaluate([kase(1, "pos")], [], RULES)).toThrow(/1 events sent, 0 replies/);
  });
});

describe("coverage", () => {
  // ISA ISC-121: a pack rule that never loads never fires, so it shows up here.
  test("names each pack rule with no passing positive, or no negative", () => {
    const v = evaluate([kase(100399, "pos"), kase(100399, "neg"), kase(100398, "pos")], [res(61603, 0), res(61603, 0), res(100398, 10, ["T1071"])], RULES);
    expect(coverage(v, [100399, 100398, 100397])).toEqual([
      "rule 100397: no positive case",
      "rule 100397: no negative case",
      "rule 100398: no negative case",
      "rule 100399: never fired in a positive case",
    ]);
  });

  test("is empty when every pack rule fires and has a negative", () => {
    const v = evaluate([kase(100399, "pos"), kase(100399, "neg")], [res(100399, 10, ["T1059.001"]), res(61603, 0)], RULES);
    expect(coverage(v, [100399])).toEqual([]);
  });

  // Cases for a pack id nothing under test names would judge nothing: a negative passes on
  // any other final rule, and the run would exit 0.
  test("names a case folder for a pack rule nothing under test names; a stock folder is fine", () => {
    const v = evaluate(
      [kase(100399, "pos"), kase(100399, "neg"), kase(100397, "neg", "tests/100397/neg-x.json"), kase(92900, "pos", "tests/92900/pos-x.json")],
      [res(100399, 10, ["T1059.001"]), res(61603, 0), res(61603, 0), res(92900, 12, ["T1003.001"])],
      RULES,
    );
    expect(v.every((x) => x.pass)).toBe(true);
    expect(coverage(v, [100399])).toEqual(["tests/100397: cases for pack rule 100397, which is in neither the rules folder nor the Sigma YAML"]);
  });

  // A file the manager never loads fails on its own, whatever ids it holds: a copy of a
  // loaded rule would otherwise ride on that rule's cases.
  test("names each XML file in a subfolder, even when every id it holds is covered", () => {
    const v = evaluate([kase(100399, "pos"), kase(100399, "neg")], [res(100399, 10, ["T1059.001"]), res(61603, 0)], RULES);
    expect(coverage(v, [100399], ["rules/sub/dup.xml"])).toEqual(["rules/sub/dup.xml: XML in a subfolder, which the manager never loads"]);
  });
});

describe("run against a fake box", () => {
  test("removes, stages, starts, verifies, runs, rechecks and removes, in that order", () => {
    const f = fakeBox();
    const out = run(opts(), f.box);
    expect(out.code).toBe(0);
    expect(out.verdicts.map((v) => v.pass)).toEqual([true, true, true, true, true]);
    expect(out.packRules).toBe(2);
    expect(f.calls).toEqual(["down", "stage", "up", "wait", ...VERIFY, "logtest", "recheck", "down"]);
  });

  // The fake checks stdin on every logtest call and every script for event text.
  test("sends the case events on stdin in case order, one per line, and never in a script", () => {
    const f = fakeBox();
    run(opts(), f.box);
    expect(f.calls.filter((c) => c === "logtest")).toHaveLength(1);
    expect(EVENTS).toHaveLength(5);
  });

  // ISA Constraints: scratch only. Every docker call a run makes is pinned to the project.
  test("every remote script stays in the scratch project", () => {
    const scripts: string[] = [];
    const f = fakeBox();
    run(opts(), (host, script, input) => {
      scripts.push(script);
      return f.box(host, script, input);
    });
    const pinned =
      /docker (?:compose -p b1test |inspect --format |ps -aq --filter label=com\.docker\.compose\.project=b1test\b|volume ls -q --filter label=com\.docker\.compose\.project=b1test\b)/g;
    expect(scripts.length).toBe(12);
    for (const s of scripts) {
      expect(s).not.toContain("soc-recon");
      expect(s.match(pinned)?.length ?? 0).toBe(s.match(/docker /g)?.length ?? 0);
    }
    // Removal must not depend on the stage, which a failed staging leaves missing: it
    // never reads the staged compose file or enters the stage.
    expect(scripts[0]).not.toMatch(/-f stage|cd "\$HOME|cd stage/);
    // A COMPOSE_* or DOCKER_* variable from the box account's login environment would steer
    // compose or docker (another daemon, another file, another project, an env file the
    // file-less removal reads), a SCRATCH_* one would win over the .env password, and a
    // TAR_* one hands tar options (GNU tar's TAR_OPTIONS can run a command at a checkpoint),
    // so every script that runs docker or tar clears them all, once, before the first call.
    const unset = UNSET;
    // Removal runs from a fresh empty folder inside the scratch folder, after the guard,
    // never from "/", and clears the variables once it is there.
    const guard = guardOf(scripts);
    expect(scripts[0].startsWith(`${guard}; mkdir -p "$HOME/b1test" && d=$(mktemp -d "$HOME/b1test/.down.XXXXXX" 2>/dev/null) || `)).toBe(true);
    expect(scripts[0]).toContain(`trap 'cd / && rmdir "$d" 2>/dev/null' EXIT; cd "$d" || exit 5; `);
    expect(scripts[0]).not.toMatch(/(?:^|&& |; )cd \/ (?:&&|;)/);
    expect(scripts[0].indexOf('cd "$d"')).toBeLessThan(scripts[0].indexOf(unset));
    const dockering = scripts.filter((s) => s.includes("docker "));
    expect(dockering).toHaveLength(10);
    const tooling = scripts.filter((s) => s.includes("docker ") || s.includes("tar -xf"));
    expect(tooling).toHaveLength(11);
    for (const s of tooling) {
      expect(s.split(unset)).toHaveLength(2);
      // A login profile can make one of them readonly. unset then fails and bash goes on,
      // so the script goes on only when the unset worked.
      expect(s.split(`${unset} && `)).toHaveLength(2);
      const first = Math.min(...["docker ", "tar -xf"].map((x) => s.indexOf(x)).filter((n) => n >= 0));
      expect(s.indexOf(unset)).toBeLessThan(first);
    }
    const readonly = Bun.spawnSync(["sh", "-c", `readonly TAR_OPTIONS=x; export TAR_OPTIONS; ${unset} && echo ran`], { stdout: "pipe", stderr: "pipe" });
    expect(readonly.stdout.toString()).toBe("");
    // It also has to prove nothing of the project is left: no container, no volume.
    for (const s of [scripts[0], scripts[11]]) expect(s).toMatch(/down -v --remove-orphans && \[ -z "\$\(docker ps -aq [^)]+\)" \] && \[ -z "\$\(docker volume ls -q [^)]+\)" \]$/);

    // Every script that works in the scratch folder opens with the guard, the two removals
    // included. The guard only tests and exits, so it can run here against a folder made to
    // look like the box's home.
    for (const s of scripts) if (/(?:cd|mkdir -p) "\$HOME\/b1test/.test(s)) expect(s.startsWith(guard)).toBe(true);
    expect(scripts.filter((s) => s.startsWith(guard))).toHaveLength(12);
    const home = temp("home");
    mkdirSync(join(home, "b1test"));
    const at = () => guardRun(guard, home);
    expect(at().stdout.toString()).toBe("passed\n");
    symlinkSync(join(home, "elsewhere"), join(home, "b1test/.env"));
    const linked = at();
    expect([linked.exitCode, linked.stdout.toString(), linked.stderr.toString()]).toEqual([3, "", "refusing: .env is a symlink\n"]);
    rmSync(join(home, "b1test"), { recursive: true });
    symlinkSync(home, join(home, "b1test"));
    expect(at().exitCode).toBe(3);
  });

  // rm --one-file-system skips a mount under the stage but not the stage itself, so a
  // scratch folder or stage on another device than its parent is refused outright.
  test("the guard refuses a scratch folder or stage that is a mount point, and a folder it cannot stat", () => {
    const scripts: string[] = [];
    const f = fakeBox();
    run(opts(), (host, script, input) => {
      scripts.push(script);
      return f.box(host, script, input);
    });
    const guard = guardOf(scripts);
    const home = temp("home");
    const scratch = join(home, "b1test");
    const said = (env: Record<string, string> = {}) => {
      const r = guardRun(guard, home, env);
      return [r.exitCode, r.stdout.toString(), r.stderr.toString()];
    };
    // No scratch folder yet, then one with no stage: nothing to compare, nothing refused.
    expect(said({ MOUNTS: scratch })).toEqual([0, "passed\n", ""]);
    mkdirSync(scratch);
    expect(said()).toEqual([0, "passed\n", ""]);
    expect(said({ MOUNTS: join(scratch, "stage") })).toEqual([0, "passed\n", ""]);
    expect(said({ MOUNTS: scratch })).toEqual([3, "", "refusing: b1test is a mount point\n"]);
    mkdirSync(join(scratch, "stage"));
    expect(said()).toEqual([0, "passed\n", ""]);
    expect(said({ MOUNTS: join(scratch, "stage") })).toEqual([3, "", "refusing: stage is a mount point\n"]);
    // A stat that fails is a refusal, not two empty strings that compare equal.
    expect(said({ NOSTAT: join(scratch, "stage") })).toEqual([3, "", "refusing: cannot stat stage\n"]);
    expect(said({ NOSTAT: `${scratch}/..` })).toEqual([3, "", "refusing: cannot stat b1test\n"]);
    // The real removal and staging scripts run the same guard: the first run makes the
    // stage, and the next finds it on another device and stops at the removal, before
    // anything is removed or staged.
    const g = fakeBox({ mounts: ["~/b1test/stage"] });
    expect(run(opts({ keep: true }), g.box).code).toBe(0);
    writeFileSync(join(g.stageDir, "marker"), "x");
    g.calls.length = 0;
    expect(() => run(opts({ keep: true }), g.box)).toThrow(/^removing the old scratch manager failed \(exit 3\): refusing: stage is a mount point$/);
    expect(g.calls).toEqual(["down"]);
    expect(existsSync(join(g.stageDir, "marker"))).toBe(true);
  });

  // The only thing a run deletes on the box is the stage it is about to replace.
  test("the stage script replaces the stage folder and removes nothing else", () => {
    const scripts: string[] = [];
    const f = fakeBox();
    run(opts(), (host, script, input) => {
      scripts.push(script);
      return f.box(host, script, input);
    });
    const staging = scripts.filter((s) => s.includes("tar -xf"));
    expect(staging).toHaveLength(1);
    // --one-file-system: a bind mount at the stage is not descended into (GNU rm on the box).
    expect(staging[0]).toEndWith(`; fi && ${UNSET} && rm -rf --one-file-system -- stage && mkdir stage && tar -xf - -C stage`);
    expect(staging[0]).toContain(`(umask 077 && printf 'SCRATCH_INDEXER_PASS=%s\\nSCRATCH_API_PASS=Sx9.%s\\n' "$a" "$b" >.env)`);
    expect(scripts.flatMap((s) => s.match(/\brm\b[^&;|]*/g) ?? [])).toEqual(["rm -rf --one-file-system -- stage "]);
  });

  // A login profile on the box that sets a tar options variable would reach the unpack.
  test("the staging script unpacks with no tar options variable from the box account's environment", () => {
    const marker = join(temp("checkpoint"), "ran");
    const boxEnv = { TAR_OPTIONS: `--checkpoint=1 --checkpoint-action=exec=touch ${marker}`, TAR_READER_OPTIONS: "nonsense=1", TAR_WRITER_OPTIONS: "nonsense=1" };
    const f = fakeBox({ boxEnv });
    expect(run(opts(), f.box).code).toBe(0);
    expect(f.calls.slice(0, 2)).toEqual(["down", "stage"]);
    expect(existsSync(join(f.stageDir, "custom-rules/selftest.xml"))).toBe(true);
    expect(existsSync(marker)).toBe(false);
  });

  // A manager that did not start is a setup error of its own, not a socket that never
  // opened five minutes later.
  test("a failed up stops the run with its own message before the socket wait, and the manager is removed", () => {
    const f = fakeBox({ up: 1 });
    expect(() => run(opts(), f.box)).toThrow(/^starting the scratch manager failed \(exit 1\): no such image$/);
    expect(f.calls).toEqual(["down", "stage", "up", "down"]);
  });

  // The scratch passwords are made on the box, in a file only its owner may read, even
  // where the account's default umask is permissive.
  test("the staging script writes .env owner-only, with fresh passwords, and keeps it on later runs", () => {
    const f = fakeBox();
    run(opts({ keep: true }), f.box);
    const env = join(f.home, "b1test/.env");
    expect(statSync(env).mode & 0o777).toBe(0o600);
    const first = readFileSync(env, "utf8");
    expect(first).toMatch(/^SCRATCH_INDEXER_PASS=[0-9a-f]{32}\nSCRATCH_API_PASS=Sx9\.[0-9a-f]{24}\n$/);
    run(opts({ keep: true }), f.box);
    expect(readFileSync(env, "utf8")).toBe(first);
  });

  test("--reuse skips the restart and nothing else, and refuses a stage that is not this tree's", () => {
    const f = fakeBox();
    run(opts({ keep: true }), f.box);
    f.calls.length = 0;
    expect(run(opts({ keep: true, reuse: true }), f.box).code).toBe(0);
    expect(f.calls).toEqual([...VERIFY, "logtest", "recheck"]);

    appendFileSync(join(f.stageDir, "custom-rules/selftest.xml"), "<!-- edited on the box -->\n");
    expect(() => run(opts({ keep: true, reuse: true }), f.box)).toThrow(/stage on the box is not the kit and rules under test/);
    run(opts({ keep: true }), f.box);
    symlinkSync("/etc", join(f.stageDir, "custom-rules/link"));
    expect(() => run(opts({ keep: true, reuse: true }), f.box)).toThrow(/stage on the box/);
  });

  // Same file name, other bytes: only the hash can tell.
  test("a changed decoder under the same name is caught by hash, staged or loaded", () => {
    const f = fakeBox();
    run(opts({ keep: true }), f.box);
    appendFileSync(join(f.stageDir, "local_logtest_winevt.xml"), "<!-- edited on the box -->\n");
    expect(() => run(opts({ keep: true, reuse: true }), f.box)).toThrow(/stage on the box is not the kit and rules under test/);
    const loaded = (x: string) => x.replace(/^[0-9a-f]{64}(?= {2}decoders\/local_logtest_winevt\.xml$)/m, "0".repeat(64));
    expect(loaded("a".repeat(64) + "  decoders/local_logtest_winevt.xml")).toBe("0".repeat(64) + "  decoders/local_logtest_winevt.xml");
    expect(() => run(opts(), fakeBox({ loaded }).box)).toThrow(/conf, decoder or rules differ/);
  });

  test("refuses a container on another image, with a network, stopped, in another project or with foreign storage", () => {
    const set = (i: number, v: string) => INSPECT.map((x, j) => (j === i ? v : x));
    const bad = (inspect: string[], msg: RegExp) => expect(() => run(opts(), fakeBox({ inspect }).box)).toThrow(msg);
    bad(set(2, "wazuh/wazuh-manager:4.0.0"), /not wazuh\/wazuh-manager:/);
    bad(set(3, "bridge"), /not running with no network in the scratch project/);
    bad(set(4, "false"), /not running with no network in the scratch project/);
    bad(set(5, "soc-recon"), /not running with no network in the scratch project/);
    bad(set(6, "volume soc-recon_wazuh_etc"), /storage outside the scratch project: volume soc-recon_wazuh_etc/);
    bad(set(9, "bind /opt/live/ossec.conf"), /storage outside the scratch project/);
    bad(set(9, "bind ~/b1test/stage/../../live/ossec.conf"), /storage outside the scratch project/);
    bad(INSPECT.slice(0, 6), /no mount listed/);
  });

  test("refuses loaded files that differ, an init that did not exit 0 and a ruleset line in ossec.log", () => {
    const bad = (f: Fake, msg: RegExp) => expect(() => run(opts(), fakeBox(f).box)).toThrow(msg);
    bad({ loaded: (x) => x.replace(/^[0-9a-f]{4}/, "0000") }, /conf, decoder or rules differ/);
    bad({ loaded: (x) => x.replace(/\n[0-9a-f]{64} {2}\.\/selftest\.xml/, "") }, /conf, decoder or rules differ/);
    bad({ init: "wazuh.manager-1  | [cont-init.d] 0-wazuh-init: exited 1.\n" }, /init did not exit 0/);
    bad({ ossec: `${CLEAN_BOOT}\n2026/11/06 07:27:20 wazuh-analysisd: WARNING: (7612): Rule ID '100398' is duplicated. Only the first occurrence will be considered.` }, /ruleset problems/);
    bad({ ossec: "2026/11/06 07:27:20 wazuh-testrule: ERROR: Invalid decoder name: 'x'." }, /ruleset problems/);
  });

  test("a socket that never opens is a setup error that names the boot errors, and the manager is removed", () => {
    const f = fakeBox({ wait: 1, init: "wazuh.manager-1  | 2026/11/06 02:00:48 wazuh-analysisd: CRITICAL: (1220): Error loading the rules.\n" });
    expect(() => run(opts(), f.box)).toThrow(SetupError);
    expect(() => run(opts(), fakeBox({ wait: 1 }).box)).toThrow(/the logtest socket did not open in 5 minutes$/);
    const g = fakeBox({ wait: 1, init: "wazuh.manager-1  | 2026/11/06 02:00:48 wazuh-analysisd: CRITICAL: (1220): Error loading the rules.\n" });
    expect(() => run(opts(), g.box)).toThrow(/did not open in 5 minutes:\n2026\/11\/06 02:00:48 wazuh-analysisd: CRITICAL: \(1220\)/);
    expect(g.calls).toEqual(["down", "stage", "up", "wait", "logs", "down"]);
  });

  // The saved transcript is the evidence, byte for byte; clean() is for the terminal only.
  test("--save writes the raw transcript, control characters and line breaks included", () => {
    const save = join(temp("save"), "run.txt");
    const raw = `${REAL}\u001b[2K\tafter the run\r\n`;
    expect(run(opts({ save }), fakeBox({ transcript: raw }).box).code).toBe(0);
    expect(readFileSync(save, "utf8")).toBe(raw);
  });

  test("a logtest call that exits non-zero is a setup error even with a whole transcript", () => {
    expect(() => run(opts(), fakeBox({ logtestCode: 1 }).box)).toThrow(/wazuh-logtest exited 1/);
  });

  // Another run between the check and the cases would have answered with its own tree.
  test("a manager whose id or start time changed while the cases ran stops the run", () => {
    const [id, started] = INSPECT;
    for (const after of [`${"f".repeat(64)}|${started}`, `${id}|2026-11-06T08:00:00.000000001Z`, "gone"]) {
      const f = fakeBox({ after });
      expect(() => run(opts(), f.box)).toThrow(/^the scratch manager changed while the cases ran: another run swapped it$/);
      expect(f.calls.slice(-3)).toEqual(["logtest", "recheck", "down"]);
    }
    expect(run(opts(), fakeBox({ after: `${id}|${started}` }).box).code).toBe(0);
  });

  test("a failed removal is a setup error, before the run and after it; --keep removes nothing", () => {
    expect(() => run(opts(), fakeBox({ down: [1] }).box)).toThrow(/removing the old scratch manager failed/);
    expect(() => run(opts(), fakeBox({ down: [0, 1] }).box)).toThrow(/removing the scratch manager failed \(exit 1\)/);
    const kept = fakeBox();
    expect(run(opts({ keep: true }), kept.box).code).toBe(0);
    expect(kept.calls.filter((c) => c === "down")).toEqual(["down"]);
  });

  // A local stage left behind would hold the rules under test in the temp folder. The
  // rules are read from the stage, so a refusal there must remove it too.
  test("the local stage folder is removed after a run, passed or failed", () => {
    const rules = temp("stage-bad");
    writeFileSync(join(rules, "local.xml"), '<group name="t,">\n  <rule id="abc" level="3"></rule>\n</group>\n');
    const { left } = ownTmp(() => {
      run(opts(), fakeBox().box);
      expect(() => run(opts(), fakeBox({ logtestCode: 1 }).box)).toThrow(SetupError);
      expect(() => run(opts(), fakeBox({ down: [1] }).box)).toThrow(SetupError);
      expect(() => run(opts({ rules }), fakeBox().box)).toThrow(/^reading the rules: [^\n]*local\.xml: id is not a whole number/);
    });
    expect(left().filter((n) => /^logtest-[^-]{6}$/.test(n))).toEqual([]);
  });

  // verify() pins the box to the staged copy, so the verdicts, the coverage and the descent
  // walk must read that copy and not the folder it came from. The Sigma read sits between
  // the start of a run and the staging, so a YAML parse is the hook that edits the folder.
  const editWhileRunning = (edit: () => void) => {
    const sigma = temp("hook-sigma");
    writeFileSync(join(sigma, "hook.yml"), "title: hook-marker\n");
    const parse = Bun.YAML.parse;
    let edits = 0;
    const spy = spyOn(Bun.YAML, "parse").mockImplementation((text: string) => {
      if (text.includes("hook-marker")) {
        edits++;
        edit();
      }
      return parse.call(Bun.YAML, text);
    });
    return { sigma, edits: () => edits, done: () => spy.mockRestore() };
  };

  test("a rules file changed after the run starts and before staging is judged as staged", () => {
    const rules = temp("hook-rules");
    cpSync(FIX_RULES, rules, { recursive: true });
    const before = readFileSync(join(rules, "selftest.xml"), "utf8");
    const after = before.replace('<rule id="100399" level="10">', '<rule id="100399" level="12">');
    expect(after).not.toBe(before);
    const hook = editWhileRunning(() => writeFileSync(join(rules, "selftest.xml"), after));
    const f = fakeBox();
    const out = (() => {
      try {
        return run(opts({ rules, sigma: hook.sigma }), f.box);
      } finally {
        hook.done();
      }
    })();
    expect(hook.edits()).toBe(1);
    // The box got the edited file, so the edited file is what the cases must be held to.
    expect(readFileSync(join(f.stageDir, "custom-rules/selftest.xml"), "utf8")).toBe(after);
    expect(out.verdicts.map((v) => (v.pass ? "pass" : `${v.case.file.split("/").slice(-2).join("/")}: ${v.why}`))).toEqual([
      "pass",
      "pass",
      "pass",
      "100399/pos-powershell.json: XML level is 12",
      "pass",
    ]);
    expect(out.code).toBe(1);
  });

  // No hook sits between the copy and the read inside run(), so the read is held here: a
  // source folder that moved on after the copy must not change what is judged.
  test("stagedRules judges the stage's bytes under the source folder's names", () => {
    const source = temp("src");
    cpSync(FIX_RULES, source, { recursive: true });
    mkdirSync(join(source, "sub"));
    cpSync(join(FIX_RULES, "selftest.xml"), join(source, "sub/deep.xml"));
    const dir = temp("stage");
    cpSync(source, join(dir, "custom-rules"), { recursive: true });
    const xml = readFileSync(join(source, "selftest.xml"), "utf8");
    writeFileSync(join(source, "selftest.xml"), xml.replace('<rule id="100399" level="10">', '<rule id="100399" level="12">'));
    writeFileSync(join(source, "local_new.xml"), '<group name="new,">\n  <rule id="100100" level="3">\n    <if_sid>61603</if_sid>\n    <description>n</description>\n  </rule>\n</group>\n');
    const tree = stagedRules(dir, source);
    expect(tree.rules.map((r) => [r.file, r.id, r.level])).toEqual([
      [relative(ROOT, join(source, "selftest.xml")), 100399, 10],
      [relative(ROOT, join(source, "selftest.xml")), 100398, 10],
    ]);
    expect(tree.skippedFiles).toEqual([relative(ROOT, join(source, "sub/deep.xml"))]);
  });

  // A file added or swapped for a link after the first checks reaches the stage, so the
  // checks the folder had (links, names, repeated ids) are run on the stage as well.
  test("a refusal the staged copy earns stops the run before any remote call, leaving no stage", () => {
    const plant: [string, (rules: string) => void, RegExp][] = [
      ["repeat", (r) => cpSync(join(r, "selftest.xml"), join(r, "local_copy.xml")), /^rule 100399 is defined 2 times \([^\n]*local_copy\.xml, [^\n]*selftest\.xml\)/],
      ["link", (r) => symlinkSync("/etc/hosts", join(r, "linked.xml")), /linked\.xml is a symlink, which the box cannot follow$/],
      ["early", (r) => cpSync(join(r, "selftest.xml"), join(r, "0599-x.xml")), /^reading the rules: [^\n]*0599-x\.xml: a rules file name must start with a letter/],
      // The copy leaves out a .DS_Store file but not a folder of that name, so the folder
      // reaches the stage and the staged check refuses it.
      [
        "hidden",
        (r) => {
          mkdirSync(join(r, ".DS_Store"));
          cpSync(join(r, "selftest.xml"), join(r, ".DS_Store/extra.xml"));
        },
        /^the staged rules folder [^\n]* holds the folder "\.DS_Store", a name the copy keeps off the box$/,
      ],
    ];
    for (const [name, change, msg] of plant) {
      const rules = temp(`plant-${name}`);
      cpSync(FIX_RULES, rules, { recursive: true });
      const hook = editWhileRunning(() => change(rules));
      const f = fakeBox();
      const own = ownTmp(() => {
        try {
          expect(() => run(opts({ rules, sigma: hook.sigma }), f.box)).toThrow(msg);
        } finally {
          hook.done();
        }
      });
      expect([name, hook.edits(), f.calls]).toEqual([name, 1, []]);
      expect(own.left().filter((n) => /^logtest-[^-]{6}$/.test(n))).toEqual([]);
    }
  });

  // ISA ISC-121: a pack id named only by a Sigma YAML, or only by the XML, is expected.
  test("a pack rule named by the Sigma YAML or the XML with no case fails the run on coverage alone", () => {
    const sigma = temp("sigma");
    writeFileSync(join(sigma, "x.yml"), "title: x\ncustom:\n  wazuh:\n    id: 100397\n");
    // A rule named by both its YAML and its XML is one rule under test, not two.
    writeFileSync(join(sigma, "y.yml"), "title: y\ncustom:\n  wazuh:\n    id: 100399\n");
    const a = run(opts({ sigma }), fakeBox().box);
    expect(a.verdicts.every((v) => v.pass)).toBe(true);
    expect(a.coverage).toEqual(["rule 100397: no positive case", "rule 100397: no negative case"]);
    expect(a.code).toBe(1);
    expect(a.packRules).toBe(3);

    const rules = temp("rules");
    cpSync(FIX_RULES, rules, { recursive: true });
    const xml = readFileSync(join(rules, "selftest.xml"), "utf8");
    const extra = '  <rule id="100396" level="10">\n    <if_sid>61603</if_sid>\n    <description>extra</description>\n  </rule>\n</group>';
    expect(xml.split("</group>").length).toBe(2);
    writeFileSync(join(rules, "selftest.xml"), xml.replace("</group>", extra));
    const b = run(opts({ rules }), fakeBox().box);
    expect(b.verdicts.every((v) => v.pass)).toBe(true);
    expect(b.coverage).toEqual(["rule 100396: no positive case", "rule 100396: no negative case"]);
    expect(b.code).toBe(1);
  });

  // rule_dir never reads a subfolder, so a rule there must still be held to coverage.
  test("a pack rule in a subfolder of the rules folder counts toward coverage", () => {
    const rules = temp("sub");
    cpSync(FIX_RULES, rules, { recursive: true });
    mkdirSync(join(rules, "sub"));
    writeFileSync(join(rules, "sub/extra.xml"), '<group name="extra,">\n  <rule id="100396" level="10">\n    <if_sid>61603</if_sid>\n    <description>extra</description>\n  </rule>\n</group>\n');
    const out = run(opts({ rules }), fakeBox().box);
    expect(out.verdicts.every((v) => v.pass)).toBe(true);
    expect(out.coverage).toEqual([
      `${relative(ROOT, join(rules, "sub/extra.xml"))}: XML in a subfolder, which the manager never loads`,
      "rule 100396: no positive case",
      "rule 100396: no negative case",
    ]);
    expect(out.packRules).toBe(3);
  });

  // The ids in the copy are the loaded rules' own, so only the file itself can fail.
  test("a subfolder copy of a loaded rules file fails the run though every case passes", () => {
    const rules = temp("dup");
    cpSync(FIX_RULES, rules, { recursive: true });
    mkdirSync(join(rules, "sub"));
    cpSync(join(FIX_RULES, "selftest.xml"), join(rules, "sub/dup.xml"));
    const out = run(opts({ rules }), fakeBox().box);
    expect(out.verdicts.every((v) => v.pass)).toBe(true);
    expect(out.coverage).toEqual([`${relative(ROOT, join(rules, "sub/dup.xml"))}: XML in a subfolder, which the manager never loads`]);
    expect(out.code).toBe(1);
  });

  test("a case folder for a pack rule in neither the rules folder nor the Sigma YAML fails the run, its cases passing", () => {
    const cases = temp("orphan");
    cpSync(CASES, cases, { recursive: true });
    mkdirSync(join(cases, "100397"));
    cpSync(join(CASES, "100399/neg-updater.json"), join(cases, "100397/neg-updater.json"));
    const out = run(opts({ cases }), fakeBox({ analysisd: "staged", events: null }).box);
    expect(out.verdicts.every((v) => v.pass)).toBe(true);
    expect(out.coverage).toEqual([`${relative(ROOT, join(cases, "100397"))}: cases for pack rule 100397, which is in neither the rules folder nor the Sigma YAML`]);
    expect(out.code).toBe(1);
    // Named by a Sigma YAML, the same folder is held to coverage instead.
    const sigma = temp("orphan-sigma");
    writeFileSync(join(sigma, "x.yml"), "title: x\ncustom:\n  wazuh:\n    id: 100397\n");
    expect(run(opts({ cases, sigma }), fakeBox({ analysisd: "staged", events: null }).box).coverage).toEqual(["rule 100397: no positive case"]);
  });

  // REAL fires 100398 for the svchost positive; a folder without 100398 never loaded it.
  test("a positive that fires a pack rule the folder lacks fails; the stock 92900 positive still passes", () => {
    const rules = temp("lacks");
    const xml = readFileSync(join(FIX_RULES, "selftest.xml"), "utf8");
    const block = /\n {2}<rule id="100398"[\s\S]*?<\/rule>\n/;
    expect(block.test(xml)).toBe(true);
    writeFileSync(join(rules, "selftest.xml"), xml.replace(block, "\n"));
    const out = run(opts({ rules }), fakeBox().box);
    expect(out.verdicts.map((v) => (v.pass ? "pass" : `${v.case.file.split("/").slice(-2).join("/")}: ${v.why}`))).toEqual([
      "pass",
      "100398/pos-svchost.json: pack rule 100398 fired but is not in the rules folder under test",
      "pass",
      "pass",
      "pass",
    ]);
    expect(out.verdicts[4].case.file).toEndWith("92900/pos-lsass-plant.json");
    expect(out.code).toBe(1);
  });

  test("a Sigma YAML that does not parse, or sits in a subfolder, stops the run before any remote call", () => {
    const f = fakeBox();
    const broken = temp("sigma-bad");
    writeFileSync(join(broken, "broken.yml"), "title: [unclosed\n");
    expect(() => run(opts({ sigma: broken }), f.box)).toThrow(SetupError);
    expect(() => run(opts({ sigma: broken }), f.box)).toThrow(/broken\.yml/);
    const nested = temp("sigma-sub");
    mkdirSync(join(nested, "process_creation"));
    writeFileSync(join(nested, "process_creation/nested.yml"), "title: x\ncustom:\n  wazuh:\n    id: 100397\n");
    expect(() => run(opts({ sigma: nested }), f.box)).toThrow(/nested\.yml/);
    expect(f.calls).toEqual([]);
  });

  // readSigma hands back a multi-document file as an array and an empty one as null; the
  // id path reads neither, so a pack id in either would drop out of coverage unseen.
  test("a Sigma YAML that is not one mapping, multi-document or empty, stops the run before any remote call", () => {
    const f = fakeBox();
    const multi = temp("sigma-multi");
    writeFileSync(join(multi, "multi.yml"), "title: a\n---\ntitle: b\ncustom:\n  wazuh:\n    id: 100397\n");
    expect(() => run(opts({ sigma: multi }), f.box)).toThrow(SetupError);
    expect(() => run(opts({ sigma: multi }), f.box)).toThrow(/^reading the Sigma YAML: [^\n]*multi\.yml: not one mapping \(a multi-document or empty file\)$/);
    const empty = temp("sigma-empty");
    writeFileSync(join(empty, "empty.yml"), "");
    expect(() => run(opts({ sigma: empty }), f.box)).toThrow(SetupError);
    expect(() => run(opts({ sigma: empty }), f.box)).toThrow(/^reading the Sigma YAML: [^\n]*empty\.yml: not one mapping \(a multi-document or empty file\)$/);
    expect(f.calls).toEqual([]);
  });

  // A list or a quoted id would read as a number and count, while sigma-lint refuses it.
  test("a Sigma custom.wazuh.id that is not a whole number stops the run; a plain number counts, an absent one is ignored", () => {
    const f = fakeBox();
    const cases: [string, string, string][] = [
      ["list.yml", "[100397]", "is not a number"],
      ["text.yml", '"100397"', "is not a number"],
      ["blank.yml", "", "is not a number"],
      ["half.yml", "100397.5", "is not a whole number"],
    ];
    for (const [name, id, why] of cases) {
      const sigma = temp("sigma-id");
      writeFileSync(join(sigma, name), `title: x\ncustom:\n  wazuh:\n    id: ${id}\n`);
      expect(() => run(opts({ sigma }), f.box)).toThrow(SetupError);
      expect(() => run(opts({ sigma }), f.box)).toThrow(new RegExp(`^reading the Sigma YAML: [^\\n]*${name.replace(".", "\\.")}: custom\\.wazuh\\.id ${why}$`));
    }
    expect(f.calls).toEqual([]);
    const sigma = temp("sigma-id");
    writeFileSync(join(sigma, "plain.yml"), "title: x\ncustom:\n  wazuh:\n    id: 100397\n");
    writeFileSync(join(sigma, "none.yml"), "title: y\n");
    expect(run(opts({ sigma }), fakeBox().box).coverage).toEqual(["rule 100397: no positive case", "rule 100397: no negative case"]);
  });

  test("a positive whose reply fired its rule with no alert fails that case alone", () => {
    const out = run(opts(), fakeBox({ transcript: NO_ALERT }).box);
    expect(out.code).toBe(1);
    expect(out.verdicts.map((v) => (v.pass ? "pass" : `${v.case.file.split("/").slice(-2).join("/")}: ${v.why}`))).toEqual([
      "pass",
      "pass",
      "pass",
      "100399/pos-powershell.json: rule 100399 fired with no alert",
      "pass",
    ]);
  });

  test("a warning on the first reply fails the first case, a negative", () => {
    const warned = REAL.replace('"messages":["INFO:', '"messages":["WARNING: (7612): Rule ID \'100398\' is duplicated.","INFO:');
    expect(warned).not.toBe(REAL);
    const out = run(opts(), fakeBox({ transcript: warned }).box);
    expect(out.code).toBe(1);
    expect(out.verdicts.map((v) => v.pass)).toEqual([false, true, true, true, true]);
    expect(out.verdicts[0].case.kind).toBe("neg");
    expect(out.verdicts[0].why).toContain("WARNING: (7612)");
  });

  test("refuses a missing rules folder, a symlinked one and a symlink inside one, before any remote call", () => {
    const f = fakeBox();
    const dir = temp("links");
    symlinkSync(FIX_RULES, join(dir, "rules-link"));
    cpSync(FIX_RULES, join(dir, "rules"), { recursive: true });
    symlinkSync("/etc/hosts", join(dir, "rules/extra.xml"));
    expect(() => run(opts({ rules: join(dir, "missing") }), f.box)).toThrow(/no rules folder/);
    expect(() => run(opts({ rules: join(dir, "rules-link") }), f.box)).toThrow(/is a symlink/);
    expect(() => run(opts({ rules: join(dir, "rules") }), f.box)).toThrow(/extra\.xml is a symlink/);
    for (const go of [() => run(opts({ rules: join(dir, "missing") }), f.box), () => run(opts({ rules: join(dir, "rules-link") }), f.box)]) expect(go).toThrow(SetupError);
    expect(f.calls).toEqual([]);
  });

  // Only rules files reach the box: a .so or a script beside them is refused, with the
  // file-name check, before anything on the box is touched.
  test("the rules folder may hold only .xml rules files and folders, checked before the removal", () => {
    const bad = ["evil.so", "notes.txt", ".hidden.xml", ".env", "sub/payload.so", "sub/.gitkeep2", "pipe"];
    for (const name of bad) {
      const f = fakeBox();
      const rules = temp("kinds");
      cpSync(FIX_RULES, rules, { recursive: true });
      mkdirSync(join(rules, "sub"));
      if (name === "pipe") expect(Bun.spawnSync(["mkfifo", join(rules, name)]).exitCode).toBe(0);
      else writeFileSync(join(rules, name), "x");
      const quoted = JSON.stringify(name).replace(/[.]/g, "\\.");
      expect(() => run(opts({ rules }), f.box)).toThrow(new RegExp(`^the rules folder [^\\n]* holds ${quoted}, which is not an \\.xml rules file$`));
      expect(f.calls).toEqual([]);
    }
    // A group needs a rule: rules.c fails a file holding an empty one (323-327).
    const upper = temp("upper");
    cpSync(FIX_RULES, upper, { recursive: true });
    writeFileSync(join(upper, "UPPER.XML"), '<group name="upper,">\n  <rule id="100100" level="3">\n    <if_sid>61603</if_sid>\n    <description>u</description>\n  </rule>\n</group>\n');
    expect(run(opts({ rules: upper }), fakeBox().box).code).toBe(0);
  });

  // The repo's rules folder keeps a .gitkeep; it and a Finder .DS_Store stay on the Mac.
  test("the repo's rules folder passes, and a .gitkeep or .DS_Store is never staged", () => {
    const real = resolve(ROOT, "deploy/soc-recon/wazuh/custom-rules");
    expect(existsSync(join(real, ".gitkeep"))).toBe(true);
    const f = fakeBox();
    expect(() => run(opts({ rules: real }), f.box)).not.toThrow();
    expect(readdirSync(join(f.stageDir, "custom-rules")).filter((n) => n.startsWith("."))).toEqual([]);
    const rules = temp("local");
    cpSync(FIX_RULES, rules, { recursive: true });
    writeFileSync(join(rules, ".DS_Store"), "x");
    writeFileSync(join(rules, ".gitkeep"), "");
    mkdirSync(join(rules, "sub"));
    writeFileSync(join(rules, "sub/.DS_Store"), "x");
    writeFileSync(join(rules, "sub/.gitkeep"), "");
    const g = fakeBox();
    expect(run(opts({ rules }), g.box).code).toBe(0);
    expect(readdirSync(join(g.stageDir, "custom-rules")).sort()).toEqual(["selftest.xml", "sub"]);
    expect(readdirSync(join(g.stageDir, "custom-rules/sub"))).toEqual([]);
  });

  // The copy keeps a .DS_Store or .gitkeep file on the Mac. A folder of either name would
  // have dropped out of the stage with every rules file in it, unreported, and the run exit 0.
  test("a folder named .DS_Store or .gitkeep in the rules folder is refused before any remote call", () => {
    const extra = '<group name="extra,">\n  <rule id="100396" level="10">\n    <if_sid>61603</if_sid>\n    <description>extra</description>\n  </rule>\n</group>\n';
    for (const at of [".DS_Store", ".gitkeep", "sub/.DS_Store", "sub/.gitkeep"]) {
      const f = fakeBox();
      const rules = temp("hidden");
      cpSync(FIX_RULES, rules, { recursive: true });
      mkdirSync(join(rules, at), { recursive: true });
      writeFileSync(join(rules, at, "extra.xml"), extra);
      const why = new RegExp(`^the rules folder [^\\n]* holds the folder ${JSON.stringify(at).replace(/[.]/g, "\\.")}, a name the copy keeps off the box$`);
      expect(() => run(opts({ rules }), f.box)).toThrow(SetupError);
      expect(() => run(opts({ rules }), f.box)).toThrow(why);
      expect(f.calls).toEqual([]);
    }
  });

  // SECURITY: cpSync copies a link as a link, and the box would mount whatever the link names
  // there. A kit file is staged from its own bytes, and a link or a non-file is refused.
  test("a kit file that is a symlink or not a file is refused before any remote call, leaving no stage", () => {
    const real = resolve(ROOT, "tools/logtest");
    for (const name of ["compose.yml", "local_logtest_winevt.xml"]) {
      const kit = temp("kit");
      cpSync(real, kit, { recursive: true });
      const target = join(temp("kit-target"), name);
      cpSync(join(kit, name), target);
      rmSync(join(kit, name));
      symlinkSync(target, join(kit, name));
      const f = fakeBox();
      const own = ownTmp(() => {
        expect(() => run(opts({ kit }), f.box)).toThrow(SetupError);
        expect(() => run(opts({ kit }), f.box)).toThrow(new RegExp(`^the kit file [^\\n]*${name.replace(/[.]/g, "\\.")} is a symlink, and kit files are staged from their own bytes$`));
        rmSync(join(kit, name));
        mkdirSync(join(kit, name));
        expect(() => run(opts({ kit }), f.box)).toThrow(new RegExp(`^the kit file [^\\n]*${name.replace(/[.]/g, "\\.")} is not a file$`));
      });
      expect(f.calls).toEqual([]);
      expect(own.left().filter((n) => /^logtest-[^-]{6}$/.test(n))).toEqual([]);
    }
    // A copy of the checked-in kit runs, and the staged shim is a file with the kit's bytes.
    const kit = temp("kit-copy");
    cpSync(real, kit, { recursive: true });
    const f = fakeBox();
    expect(run(opts({ kit, keep: true }), f.box).code).toBe(0);
    expect(lstatSync(join(f.stageDir, "local_logtest_winevt.xml")).isFile()).toBe(true);
    expect(readFileSync(join(f.stageDir, "local_logtest_winevt.xml"))).toEqual(readFileSync(join(real, "local_logtest_winevt.xml")));
  });

  // Opened without O_NONBLOCK, a FIFO in the kit would hold the run until something wrote to
  // it, so this runs in a child process that a timeout can end.
  test("a kit file that is a FIFO is refused, not waited on", () => {
    const kit = temp("kit-fifo");
    cpSync(resolve(ROOT, "tools/logtest"), kit, { recursive: true });
    rmSync(join(kit, "local_logtest_winevt.xml"));
    expect(Bun.spawnSync(["mkfifo", join(kit, "local_logtest_winevt.xml")]).exitCode).toBe(0);
    const o = opts({ kit });
    const script = [
      `import { run } from ${JSON.stringify(resolve(ROOT, "tools/logtest.ts"))};`,
      `try { run(${JSON.stringify(o)}, () => { throw new Error("the box was called"); }); } catch (e) { console.log(e.message); }`,
    ].join("\n");
    const r = Bun.spawnSync(["bun", "-e", script], { stdout: "pipe", stderr: "pipe", timeout: 30_000 });
    expect(r.stdout.toString()).toMatch(/^the kit file [^\n]*local_logtest_winevt\.xml is not a file\n$/);
  }, 60_000);

  // An empty id must stop the script before docker inspect, which would be handed "".
  test("the inspect script stops before docker inspect when no manager is running", () => {
    const scripts: string[] = [];
    const f = fakeBox();
    run(opts(), (host, script, input) => {
      scripts.push(script);
      return f.box(host, script, input);
    });
    const inspect = scripts.filter((s) => s.includes(".Config.Image"));
    expect(inspect).toHaveLength(1);
    const home = temp("home");
    mkdirSync(join(home, "b1test/stage"), { recursive: true });
    writeFileSync(join(home, "b1test/stage/compose.yml"), "name: b1test\n");
    const bin = temp("inspect-bin");
    writeFileSync(
      join(bin, "docker"),
      [
        "#!/bin/sh",
        'printf "%s\\n" "$1" >> "$CALLS"',
        'case "$*" in',
        '  "compose -p b1test -f stage/compose.yml --env-file .env ps -q wazuh.manager") [ -z "$CID_OUT" ] || printf "%s\\n" "$CID_OUT" ;;',
        '  "inspect --format "*) for a; do last=$a; done; echo "inspected [$last]" ;;',
        '  *) echo "stub docker: unexpected $*" >&2; exit 64 ;;',
        "esac",
        "",
      ].join("\n"),
    );
    chmodSync(join(bin, "docker"), 0o755);
    const calls = join(temp("inspect-calls"), "calls");
    const go = (cid: string) => {
      rmSync(calls, { force: true });
      const r = Bun.spawnSync(["sh", "-c", inspect[0]], {
        env: { HOME: home, PATH: `${join(ownerDir, "gnu")}:${bin}:${process.env.PATH}`, CALLS: calls, CID_OUT: cid },
        stdout: "pipe",
        stderr: "pipe",
      });
      return [r.exitCode === 0, r.stdout.toString(), readFileSync(calls, "utf8").trim().split("\n")];
    };
    expect(go("")).toEqual([false, "", ["compose"]]);
    expect(go("c0")).toEqual([true, "inspected [c0]\n", ["compose", "inspect"]]);
  });

  // grep exits 1 on a clean log and 2 when it cannot read one, so an unreadable ossec.log
  // must fail the read rather than pass for clean.
  test("the ossec.log read fails on a log it cannot read, and the run stops on it", () => {
    const scripts: string[] = [];
    const f = fakeBox();
    run(opts(), (host, script, input) => {
      scripts.push(script);
      return f.box(host, script, input);
    });
    const read = scripts.filter((s) => s.includes("ossec.log"));
    expect(read).toHaveLength(1);
    const inner = /sh -c '([^']*)'$/.exec(read[0])?.[1] ?? "";
    expect(inner.split("/var/ossec/logs/ossec.log")).toHaveLength(2);
    const dir = temp("ossec");
    const log = join(dir, "ossec.log");
    const go = () => {
      const r = Bun.spawnSync(["sh", "-c", inner.replace("/var/ossec/logs/ossec.log", log)], { stdout: "pipe", stderr: "pipe" });
      return [r.exitCode, r.stdout.toString()];
    };
    writeFileSync(log, "2026/11/06 07:27:20 wazuh-analysisd: INFO: started\n");
    expect(go()).toEqual([0, ""]);
    writeFileSync(log, "2026/11/06 07:27:20 wazuh-analysisd: INFO: started\n2026/11/06 07:27:20 wazuh-analysisd: ERROR: x\n");
    expect(go()).toEqual([0, "2026/11/06 07:27:20 wazuh-analysisd: ERROR: x\n"]);
    // Root reads a mode-000 file, so this half means nothing there; the missing file below
    // takes grep down the same exit-2 path.
    if (process.getuid?.() !== 0) {
      chmodSync(log, 0o000);
      expect(go()[0]).not.toBe(0);
    }
    rmSync(log);
    expect(go()[0]).not.toBe(0);
    expect(() => run(opts(), fakeBox({ ossecCode: 1, ossec: "" }).box)).toThrow(/^reading ossec\.log failed \(exit 1\)$/);
  });

  // Removal goes by project name alone, so a b1test project started from any folder but
  // the stage is someone else's: nothing of it is removed, and no path is printed.
  test("removal refuses a b1test container that was not started from the stage", () => {
    for (const projectDir of [["~/b1test/stage"], [], ["~/b1test/stage", "~/b1test/stage"]]) {
      const f = fakeBox({ projectDir });
      expect(run(opts(), f.box).code).toBe(0);
      expect(f.owners.map((o) => o.code)).toEqual([0, 0]);
    }
    for (const projectDir of [["/opt/elsewhere"], ["~/b1test"], ["~/b1test/stage/"], [""], ["~/b1test/stage", "/opt/elsewhere"]]) {
      const f = fakeBox({ projectDir });
      expect(() => run(opts(), f.box)).toThrow(/^the scratch project name b1test is in use by a project this tool did not stage; nothing was removed$/);
      expect(f.calls).toEqual(["down", "down"]);
      expect(f.owners).toEqual([
        { code: 4, out: "", err: "another folder" },
        { code: 4, out: "", err: "another folder" },
      ]);
    }
    // Found by the removal after the cases, it is the same refusal.
    expect(() => run(opts(), fakeBox({ down: [0, 4] }).box)).toThrow(/^the scratch project name b1test is in use by a project this tool did not stage; nothing was removed$/);
  });

  // Compose with no -f looks for a compose file in its working folder and every folder
  // above it, so removal runs from a fresh empty folder inside ~/b1test and refuses when a
  // compose file sits in any folder above it. The folder goes whatever happened.
  test("removal runs from a fresh empty folder it removes after, and refuses a compose file above it", () => {
    const downFolders = (home: string) => (existsSync(join(home, "b1test")) ? readdirSync(join(home, "b1test")).filter((n) => n.startsWith(".down.")) : []);
    const ok = fakeBox();
    expect(run(opts(), ok.box).code).toBe(0);
    expect(ok.owners.map((o) => o.code)).toEqual([0, 0]);
    expect(downFolders(ok.home)).toEqual([]);
    // Left by the ownership refusal (exit 4 from inside a loop), it is still removed.
    const foreign = fakeBox({ projectDir: ["/opt/elsewhere"] });
    expect(() => run(opts(), foreign.box)).toThrow(/did not stage/);
    expect(downFolders(foreign.home)).toEqual([]);
    // In the home, above ~/b1test, and in ~/b1test itself, which the walk passes.
    for (const at of ["", "b1test/"]) {
      for (const name of ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"]) {
        const f = fakeBox();
        mkdirSync(join(f.home, "b1test"));
        writeFileSync(join(f.home, at, name), "name: soc-recon\n");
        expect(() => run(opts(), f.box)).toThrow(/^removing the old scratch manager failed \(exit 5\): refusing: a compose file sits in a folder above the removal$/);
        expect(f.owners.map((o) => o.code)).toEqual([5, 5]);
        expect(f.calls).toEqual(["down", "down"]);
        expect(downFolders(f.home)).toEqual([]);
        expect(readdirSync(f.home).sort()).toEqual(at ? ["b1test"] : ["b1test", name].sort());
      }
    }
  });

  // The brief allows writes in ~/b1test and the b1test project only. The removal's empty
  // folder is made inside ~/b1test, so the home itself never gains an entry, not even for
  // the moment the removal runs.
  test("removal makes its empty folder inside ~/b1test, and the home gains nothing else", () => {
    const f = fakeBox();
    writeFileSync(join(f.home, "already-here"), "x");
    expect(run(opts(), f.box).code).toBe(0);
    const seen = f.seen();
    expect(seen).toHaveLength(2);
    const real = realpathSync(f.home).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    for (const s of seen) {
      expect(s.cwd).toMatch(new RegExp(`^${real}/b1test/\\.down\\.[A-Za-z0-9]{6}$`));
      expect(s.home).toEqual(["already-here", "b1test"]);
    }
    expect(readdirSync(f.home).sort()).toEqual(["already-here", "b1test"]);
    expect(readdirSync(join(f.home, "b1test")).sort()).toEqual([".env", "stage"]);
  });

  // A symlink at ~/b1test would send the mkdir and the empty folder somewhere else on the
  // box, so the removal's guard refuses it before either.
  test("a symlink at ~/b1test makes the removal refuse before it makes any folder", () => {
    const f = fakeBox();
    const elsewhere = join(f.home, "elsewhere");
    mkdirSync(elsewhere);
    symlinkSync(elsewhere, join(f.home, "b1test"));
    expect(() => run(opts(), f.box)).toThrow(/^removing the old scratch manager failed \(exit 3\): refusing: b1test is a symlink$/);
    expect(f.calls).toEqual(["down", "down"]);
    expect(f.owners.map((o) => [o.code, o.err])).toEqual([
      [3, "refusing: b1test is a symlink"],
      [3, "refusing: b1test is a symlink"],
    ]);
    expect(f.seen()).toEqual([]);
    expect(readdirSync(elsewhere)).toEqual([]);
    expect(readdirSync(f.home).sort()).toEqual(["b1test", "elsewhere"]);
  });

  // Found after the old manager was gone, this would leave the box with no manager at all.
  test("a rule file name the hash check cannot compare is refused, naming the rules folder, before the removal", () => {
    const f = fakeBox();
    const rules = temp("names");
    cpSync(FIX_RULES, rules, { recursive: true });
    writeFileSync(join(rules, "two words.xml"), "<!-- nothing -->\n");
    expect(() => run(opts({ rules }), f.box)).toThrow(SetupError);
    expect(() => run(opts({ rules }), f.box)).toThrow(/^the rules folder [^\n]*logtest-names-[^\n]* holds "two words\.xml", a name the hash check cannot compare/);
    expect(f.calls).toEqual([]);
  });

  // Wazuh keeps a repeated id where its first definition placed it and silently takes an
  // overwrite="yes" copy's group and level (rules.c 371-383, rules_list.c 294-316). The id
  // map holds the last copy, so 100352, placed under the first 100350 by if_group, no longer
  // reads as its child, and the negative below would pass on a reply that ends on 100352.
  test("refuses a rule id defined twice in the folder under test, the set sigma-lint refuses, before any remote call", () => {
    const rules = temp("twice");
    const parent = (group: string, attrs = "") =>
      `<group name="${group},">\n  <rule id="100350" level="10"${attrs}>\n    <if_sid>61603</if_sid>\n    <description>parent</description>\n  </rule>\n`;
    writeFileSync(
      join(rules, "local_a.xml"),
      `${parent("x_parent")}  <rule id="100352" level="10">\n    <if_group>x_parent</if_group>\n    <description>child</description>\n  </rule>\n</group>\n`,
    );
    writeFileSync(join(rules, "local_b.xml"), `${parent("y_other", ' overwrite="yes"')}</group>\n`);
    const cases = temp("twice-cases");
    mkdirSync(join(cases, "100350"));
    writeFileSync(join(cases, "100350/neg-child.json"), JSON.stringify({ event: "child event" }));
    const f = fakeBox({ transcript: transcript(reply({ id: "100352", level: 10 })), events: null });
    expect(() => run(opts({ rules, cases }), f.box)).toThrow(SetupError);
    expect(() => run(opts({ rules, cases }), f.box)).toThrow(/^rule 100350 is defined 2 times \([^\n]*local_a\.xml, [^\n]*local_b\.xml\)/);
    expect(f.calls).toEqual([]);
    const lint = lintPack([], readRulesDir(rules, ROOT), new Map(), new Map()).filter((x) => x.problem.startsWith("XML rule defined"));
    expect(lint.map((x) => x.rule)).toEqual([100350]);
  });

  // Wazuh loads every rule_dir's files in strcmp order of the name, and the stock ones are
  // 0NNN-*.xml, so a custom file named 0599-x.xml loads among them.
  test("refuses a rules file named to load among the stock files, before any remote call", () => {
    const f = fakeBox();
    const rules = temp("early");
    cpSync(FIX_RULES, rules, { recursive: true });
    writeFileSync(join(rules, "0599-x.xml"), '<group name="early,">\n</group>\n');
    expect(() => run(opts({ rules }), f.box)).toThrow(SetupError);
    expect(() => run(opts({ rules }), f.box)).toThrow(/^reading the rules: [^\n]*0599-x\.xml: a rules file name must start with a letter/);
    expect(f.calls).toEqual([]);
  });
});

// ISA ISC-122 through the fake box: the four scenarios, judged by a fake analysisd that
// reads what was staged, end the way they must.
describe("selfTest", () => {
  const quiet = <T>(go: () => T) => {
    const log = spyOn(console, "log").mockImplementation(() => {});
    const err = spyOn(console, "error").mockImplementation(() => {});
    try {
      const value = go();
      return { value, lines: log.mock.calls.map((c) => String(c[0])).filter((l) => l.includes(" self-test ")) };
    } finally {
      log.mockRestore();
      err.mockRestore();
    }
  };
  const SCENARIOS = [
    "A fixture pack passes",
    "B flipped expectation fails on that case only",
    "C flipped condition fails both 100399 cases",
    "D rules in a subfolder never fire",
  ];

  test("passes against an analysisd that reads the stage, and fails one that does not", () => {
    const sim = fakeBox({ analysisd: "staged", events: null });
    const own = ownTmp(() => quiet(() => selfTest("box", sim.box)));
    const a = own.value;
    expect(a.value).toBe(true);
    expect(a.lines).toEqual(SCENARIOS.map((s) => `OK   self-test ${s}`));
    // D removes its own manager, then the self-test removes whatever is left.
    expect(sim.calls.slice(-3)).toEqual(["recheck", "down", "down"]);

    const stale = quiet(() => selfTest("box", fakeBox({ analysisd: "stale", events: null }).box));
    expect(stale.value).toBe(false);
    expect(stale.lines).toEqual(SCENARIOS.map((s, i) => `${i < 2 ? "OK  " : "BAD "} self-test ${s}`));
    // The self-test's own temp folder and each run's stage are gone.
    expect(own.left().filter((n) => n.startsWith("logtest-self-") || /^logtest-[^-]{6}$/.test(n))).toEqual([]);
  });

  // A copy of the fixture pack, so a test can change it without touching the checked-in one.
  const fixtureCopy = () => {
    const fixture = temp("fixture");
    cpSync(resolve(ROOT, "tools/fixtures/logtest"), fixture, { recursive: true });
    return fixture;
  };

  // A sixth case that passes leaves A's run green, so A also counts its verdicts.
  test("A fails when the fixture pack judges any number of cases but five", () => {
    const fixture = fixtureCopy();
    cpSync(join(fixture, "cases/92900/pos-lsass-plant.json"), join(fixture, "cases/92900/pos-lsass-plant-2.json"));
    const r = quiet(() => selfTest("box", fakeBox({ analysisd: "staged", events: null }).box, fixture));
    expect(r.value).toBe(false);
    expect(r.lines).toEqual(SCENARIOS.map((s, i) => `${i === 0 ? "BAD " : "OK  "} self-test ${s}`));
  });

  // B fails on the planted case alone, coverage included: an orphan case folder that reaches
  // B's copy of the pack passes its own case but fails B's coverage, and B must say so.
  test("B fails when its run carries a coverage failure beside the planted flip", () => {
    const fixture = fixtureCopy();
    const orphan = join(fixture, "cases/100397");
    const sim = fakeBox({ analysisd: "staged", events: null });
    let runs = 0;
    const box: Box = (host, script, input) => {
      const r = sim.box(host, script, input);
      if (script.includes("wazuh-logtest -d")) {
        runs++;
        // After A has read the pack and before B copies it; gone again before C and D.
        if (runs === 1) {
          mkdirSync(orphan);
          cpSync(join(fixture, "cases/100399/neg-updater.json"), join(orphan, "neg-updater.json"));
        }
        if (runs === 2) rmSync(orphan, { recursive: true });
      }
      return r;
    };
    const r = quiet(() => selfTest("box", box, fixture));
    expect(runs).toBe(4);
    expect(r.value).toBe(false);
    expect(r.lines).toEqual(SCENARIOS.map((s, i) => `${i === 1 ? "BAD " : "OK  "} self-test ${s}`));
  });

  test("a failed removal at the end is a setup error (exit 2), not a failed check", () => {
    const sim = fakeBox({ analysisd: "staged", events: null });
    quiet(() => selfTest("box", sim.box));
    const downs = sim.calls.filter((c) => c === "down").length;
    const last = fakeBox({ analysisd: "staged", events: null, down: [...Array(downs - 1).fill(0), 1] });
    expect(() => quiet(() => selfTest("box", last.box))).toThrow(SetupError);
    const again = fakeBox({ analysisd: "staged", events: null, down: [...Array(downs - 1).fill(0), 1] });
    expect(() => quiet(() => selfTest("box", again.box))).toThrow(/^removing the scratch manager failed \(exit 1\); run --down$/);
  });
});

// The entry point, with a stub named ssh first on PATH: nothing here reaches a real host.
// Given recorded replies, the stub answers call n with the nth reply a fake box gave a run
// with the same options, so a whole run goes through the real ssh path.
describe("exit codes", () => {
  const stub = mkdtempSync(join(tmpdir(), "logtest-stub-"));
  const log = join(stub, "calls.txt");
  const replies = join(stub, "replies");
  const noSigma = join(stub, "sigma");
  mkdirSync(noSigma);
  writeFileSync(
    join(stub, "ssh"),
    [
      "#!/bin/sh",
      'd=$(dirname "$0")',
      `printf '%s\\n' "$*" >> "$d/calls.txt"`,
      'n=$(( $(cat "$d/replies/n" 2>/dev/null || echo 0) + 1 ))',
      '[ -f "$d/replies/$n.code" ] || exit 99',
      'echo "$n" > "$d/replies/n"',
      'eval "last=\\${$#}"',
      `printf '%s' "$last" > "$d/replies/$n.sent"`,
      'cat > "$d/replies/$n.in"',
      'cat "$d/replies/$n.out"',
      'cat "$d/replies/$n.err" >&2',
      'exit "$(cat "$d/replies/$n.code")"',
      "",
    ].join("\n"),
  );
  chmodSync(join(stub, "ssh"), 0o755);
  afterAll(() => rmSync(stub, { recursive: true, force: true }));

  interface Reply {
    script: string;
    code: number | null;
    out: string;
    err: string;
  }
  const ARGS = ["--host", "box", "--cases", CASES, "--rules", FIX_RULES, "--sigma", noSigma];
  // Each call a fake box answers for a run with ARGS's options (or these), in order.
  const record = (f: Fake, o: Partial<RunOptions> = {}): Reply[] => {
    const fake = fakeBox(f);
    const got: Reply[] = [];
    try {
      run(opts({ sigma: noSigma, ...o }), (host, script, input) => {
        const r = fake.box(host, script, input);
        got.push({ script, ...r });
        return r;
      });
    } catch (e) {
      if (!(e instanceof SetupError)) throw e;
    }
    return got;
  };
  const cli = (args: string[], answers: Reply[] = []) => {
    rmSync(log, { force: true });
    rmSync(replies, { recursive: true, force: true });
    mkdirSync(replies);
    answers.forEach((a, i) => {
      writeFileSync(join(replies, `${i + 1}.code`), String(a.code));
      writeFileSync(join(replies, `${i + 1}.out`), a.out);
      writeFileSync(join(replies, `${i + 1}.err`), a.err);
    });
    const r = Bun.spawnSync(["bun", "tools/logtest.ts", ...args], {
      cwd: ROOT,
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, PATH: `${stub}:${process.env.PATH}` },
    });
    const file = (n: number, ext: string) => (existsSync(join(replies, `${n}.${ext}`)) ? readFileSync(join(replies, `${n}.${ext}`), "utf8") : undefined);
    return {
      code: r.exitCode,
      out: r.stdout.toString(),
      err: r.stderr.toString().trim(),
      ssh: existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [],
      sent: answers.map((_, i) => file(i + 1, "sent")),
      stdin: answers.map((_, i) => file(i + 1, "in")),
    };
  };

  test("a setup problem exits 2 with one line and no stack trace, before any ssh", () => {
    const missing = cli(["--cases", CASES, "--rules", join(stub, "missing")]);
    expect(missing).toMatchObject({ code: 2, out: "", err: expect.stringMatching(/^logtest: no rules folder at [^\n]+$/), ssh: [] });
    const file = cli(["--cases", resolve(CASES, "100399/pos-powershell.json")]);
    expect(file).toMatchObject({ code: 2, out: "", err: expect.stringMatching(/^logtest: no cases folder at [^\n]+$/), ssh: [] });
  });

  test("a rule id defined twice, or a rules file named to load among the stock files, exits 2 before any ssh", () => {
    const twice = join(stub, "rules-twice");
    cpSync(FIX_RULES, twice, { recursive: true });
    cpSync(join(FIX_RULES, "selftest.xml"), join(twice, "selftest2.xml"));
    const a = cli(["--host", "box", "--cases", CASES, "--rules", twice, "--sigma", noSigma]);
    expect(a).toMatchObject({ code: 2, out: "", err: expect.stringMatching(/^logtest: rule 100399 is defined 2 times \([^\n]*selftest\.xml, [^\n]*selftest2\.xml\)[^\n]*$/), ssh: [] });
    const early = join(stub, "rules-early");
    cpSync(FIX_RULES, early, { recursive: true });
    cpSync(join(FIX_RULES, "selftest.xml"), join(early, "0599-selftest.xml"));
    const b = cli(["--host", "box", "--cases", CASES, "--rules", early, "--sigma", noSigma]);
    expect(b).toMatchObject({ code: 2, out: "", err: expect.stringMatching(/^logtest: reading the rules: [^\n]*0599-selftest\.xml: a rules file name must start with a letter[^\n]*$/), ssh: [] });
  });

  test("a folder named .DS_Store or .gitkeep in the rules folder exits 2 before any ssh", () => {
    for (const name of [".DS_Store", ".gitkeep"]) {
      const rules = join(stub, `rules-hidden${name}`);
      cpSync(FIX_RULES, rules, { recursive: true });
      mkdirSync(join(rules, name));
      cpSync(join(FIX_RULES, "selftest.xml"), join(rules, name, "extra.xml"));
      const r = cli(["--host", "box", "--cases", CASES, "--rules", rules, "--sigma", noSigma]);
      expect(r).toMatchObject({ code: 2, out: "", ssh: [] });
      expect(r.err).toEndWith(`holds the folder "${name}", a name the copy keeps off the box`);
    }
  });

  test("--host refuses a leading dash, and ssh gets -- before the host", () => {
    expect(cli(["--down", "--host", "-Efile"])).toMatchObject({ code: 2, err: "logtest: --host must be an ssh alias", ssh: [] });
    const down = cli(["--down", "--host", "box"]);
    expect(down.code).toBe(2);
    expect(down.err).toMatch(/^logtest: removing the scratch manager failed \(exit 99\)$/);
    expect(down.ssh).toHaveLength(1);
    expect(down.ssh[0]).toMatch(
      / -- box for p in "\$HOME\/b1test" .*; mkdir -p "\$HOME\/b1test" && d=\$\(mktemp -d "\$HOME\/b1test\/\.down\.XXXXXX" .* unset COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PATH_SEPARATOR COMPOSE_PROJECT_NAME COMPOSE_ENV_FILES DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_TLS_VERIFY DOCKER_CERT_PATH SCRATCH_INDEXER_PASS SCRATCH_API_PASS TAR_OPTIONS TAR_READER_OPTIONS TAR_WRITER_OPTIONS && for c in .* && docker compose -p b1test down -v /,
    );
  });

  // "--save --keep" would write the transcript to a file named --keep and drop the flag.
  test("--save refuses a value that starts with a dash, before any ssh", () => {
    for (const v of ["--keep", "-x"]) {
      const r = cli([...ARGS, "--save", v]);
      expect(r).toMatchObject({ code: 2, out: "", err: `logtest: --save needs a file name, and ${v} starts with - (write ./${v} for a file of that name)`, ssh: [] });
      expect(existsSync(join(ROOT, v))).toBe(false);
    }
  });

  test("a whole run through ssh exits 0 when every case passes and 1 when one fails, and never prints an event", () => {
    const pass = record({});
    const a = cli(ARGS, pass);
    expect(a.code).toBe(0);
    expect(a.sent).toEqual(pass.map((p) => p.script));
    expect(a.stdin[pass.findIndex((p) => p.script.includes("wazuh-logtest -d"))]).toBe(`${EVENTS.join("\n")}\n`);
    expect(a.out.trimEnd().split("\n").map((l) => l.split(" ")[0])).toEqual(["PASS", "PASS", "PASS", "PASS", "PASS"]);
    expect(a.err).toBe("logtest: 5 case(s), 2 pack rule(s) under test, 0 failure(s)");

    const fail = record({ transcript: NO_ALERT });
    const b = cli(ARGS, fail);
    expect(b.code).toBe(1);
    expect(b.sent).toEqual(fail.map((p) => p.script));
    expect(b.out).toMatch(/^FAIL pos 100399 \S+pos-powershell\.json: 100399 L10 \[T1059\.001\] via windows_eventchannel: rule 100399 fired with no alert$/m);
    // Its one positive failed, so the rule also never fired for coverage.
    expect(b.out).toMatch(/^FAIL coverage rule 100399: never fired in a positive case$/m);
    expect(b.err).toBe("logtest: 5 case(s), 2 pack rule(s) under test, 2 failure(s)");
    for (const text of [a.out, a.err, b.out, b.err]) expect(text).not.toContain('{"win":');
  });

  // Reply values, error text and paths can hold a line break; printed raw, one could pass
  // for a verdict line of its own.
  test("every verdict, coverage and error line stays one line when a value holds a newline", () => {
    const forged = REAL.replace('"messages":["INFO:', '"messages":["WARNING: x\\nPASS pos 100399 forged","INFO:');
    expect(forged).not.toBe(REAL);
    const a = cli(ARGS, record({ transcript: forged }));
    expect(a.code).toBe(1);
    const lines = a.out.trimEnd().split("\n");
    expect(lines).toHaveLength(5);
    expect(lines[0]).toMatch(/^FAIL neg 100398 \S+: .*: WARNING: x\?PASS pos 100399 forged$/);
    expect(lines.filter((l) => l.startsWith("PASS pos 100399 forged"))).toEqual([]);

    const ossec = ["2026/11/06 07:27:20 wazuh-analysisd: ERROR: a", "2026/11/06 07:27:20 wazuh-analysisd: ERROR: b"];
    const b = cli(ARGS, record({ ossec: ossec.join("\n") }));
    expect(b).toMatchObject({ code: 2, out: "", err: `logtest: ossec.log reports ruleset problems:?${ossec.join("?")}` });

    const odd = join(stub, "rules\nPASS pos 100399 forged");
    cpSync(FIX_RULES, odd, { recursive: true });
    mkdirSync(join(odd, "sub"), { recursive: true });
    cpSync(join(FIX_RULES, "selftest.xml"), join(odd, "sub/dup.xml"));
    const c = cli(["--host", "box", "--cases", CASES, "--rules", odd, "--sigma", noSigma], record({}, { rules: odd }));
    expect(c.code).toBe(1);
    const out = c.out.trimEnd().split("\n");
    expect(out).toHaveLength(6);
    expect(out[5]).toMatch(/^FAIL coverage \S*rules\?PASS pos 100399 forged\/sub\/dup\.xml: XML in a subfolder, which the manager never loads$/);
  });

  test("--down refuses a b1test project this tool did not stage, removing nothing", () => {
    const r = cli(["--down", "--host", "box"], [{ script: "", code: 4, out: "", err: "another folder" }]);
    expect(r).toMatchObject({ code: 2, out: "", err: "logtest: the scratch project name b1test is in use by a project this tool did not stage; nothing was removed" });
    expect(r.sent[0]).toContain("com.docker.compose.project.working_dir");
  });

  test("a run whose manager was swapped under the cases exits 2 and still removes it", () => {
    const swapped = record({ after: `${"f".repeat(64)}|${INSPECT[1]}` });
    const r = cli(ARGS, swapped);
    expect(r).toMatchObject({ code: 2, out: "", err: "logtest: the scratch manager changed while the cases ran: another run swapped it" });
    expect(r.sent).toEqual(swapped.map((s) => s.script));
    expect(r.sent.at(-1)).toContain("down -v");
  });

  // The default Sigma folder may be absent (no YAML yet); one named here may not.
  test("a --sigma folder that is missing or holds a bad YAML exits 2 before any ssh", () => {
    const base = ["--host", "box", "--cases", CASES, "--rules", FIX_RULES];
    expect(cli([...base, "--sigma", join(stub, "missing")])).toMatchObject({ code: 2, out: "", err: expect.stringMatching(/^logtest: no Sigma folder at [^\n]+$/), ssh: [] });
    const bad = join(stub, "bad-sigma");
    mkdirSync(bad, { recursive: true });
    writeFileSync(join(bad, "broken.yml"), "title: [unclosed\n");
    expect(cli([...base, "--sigma", bad])).toMatchObject({ code: 2, out: "", err: expect.stringMatching(/^logtest: reading the Sigma YAML: .*broken\.yml/s), ssh: [] });
  });
});
