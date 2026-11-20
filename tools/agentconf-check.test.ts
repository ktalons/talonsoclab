// *****************************************************************************
// *Title: agentconf-check.test*
// *Author: Kyle Versluis*
// *Description: Offline checks of the agent.conf gate through a fake box.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, afterEach, beforeAll, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import {
  boxScript,
  checkOne,
  classify,
  compareReceipt,
  findGroups,
  imageOf,
  parseReceipt,
  RECEIPT,
  readWorkingTree,
  receiptText,
  run,
  SHARED,
  selfTest,
  type Verdict,
  verdictLine,
} from "./agentconf-check.ts";
import { type Box, SetupError } from "./logtest.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const COMPOSE = "deploy/soc-recon/docker-compose.yml";
const IMAGE = imageOf(readFileSync(resolve(ROOT, COMPOSE), "utf8"));
const FIX = resolve(ROOT, "tools/fixtures/agentconf");
const PLANTED = readFileSync(join(FIX, "planted-backslash.conf"));
const CONTROL = readFileSync(join(FIX, "clean.conf"));
const GROUPS = ["phase-a-linux", "phase-a-macos", "phase-a-windows"];

// The checker's output in the shape the box printed on the first real run, 2026-11-20,
// against the pinned image: the OK line is bare, every log line opens with a timestamp.
const T = "2026/11/20 11:07:25 ";
const OK = "verify-agent-conf: OK\n";
const SCA = `${T}sca: WARNING: File 'etc/shared/cis_ubuntu26-04.yml' not found.\n`;
const rejectedOut = (staged: string) =>
  `${T}verify-agent-conf: ERROR: (1226): Error reading XML file '/t/${staged}': XMLERR: Element 'registry_ignore' not closed. (line 19).\n` +
  `${T}verify-agent-conf: ERROR: (1207): Syscheck remote configuration in '/t/${staged}' is corrupted.\n`;
const NO_DEFS =
  `${T}verify-agent-conf: ERROR: (1103): Could not open file 'etc/internal_options.conf' due to [(2)-(No such file or directory)].\n` +
  `${T}verify-agent-conf: CRITICAL: (2301): Definition not found for: 'agent.remote_conf'.\n`;

// *--- Helpers ---*

const tmps: string[] = [];
const temp = (name: string) => {
  const d = mkdtempSync(join(tmpdir(), `agentconf-test-${name}-`));
  tmps.push(d);
  return d;
};
afterEach(() => {
  for (const d of tmps.splice(0)) rmSync(d, { recursive: true, force: true });
});
const sha = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const box = (code: number | null, out = "", err = ""): ReturnType<Box> => ({ code, out, err });
// The hash line the box script prints before the checker runs, for a file whose hash is S.
const S = "a".repeat(64);
const at = (code: number | null, out = "", err = "") => box(code, `agentconf-staged ${S}\n${out}`, err);

/** A copy of the repo's compose file and shared folder, standing in for the repo root. */
function tree(): string {
  const root = temp("root");
  mkdirSync(join(root, "deploy/soc-recon"), { recursive: true });
  cpSync(resolve(ROOT, COMPOSE), join(root, COMPOSE));
  cpSync(resolve(ROOT, SHARED), join(root, SHARED), { recursive: true });
  rmSync(join(root, RECEIPT), { force: true });
  mkdirSync(join(root, "tools/fixtures"), { recursive: true });
  cpSync(FIX, join(root, "tools/fixtures/agentconf"), { recursive: true });
  return root;
}

/** Every file under the shared folder with its SHA-256, to prove what a run touched. */
function snapshot(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (d: string) => {
    for (const name of readdirSync(d).sort()) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else out[relative(root, p)] = sha(readFileSync(p));
    }
  };
  walk(join(root, SHARED));
  return out;
}

interface Call {
  script: string;
  staged: string;
  setup: boolean;
  // The files the tar stream held, by name.
  files: Record<string, Buffer>;
}

// The remote side, answered on this machine. Each call's tar is really unpacked, so the
// answer is decided from the bytes the call carried, never from the call's position.
function fakeBox(answer: (c: Call) => ReturnType<Box>): { box: Box; calls: Call[] } {
  const calls: Call[] = [];
  const b: Box = (_host, script, input) => {
    const staged = /-f \/t\/([^\s']+)'/.exec(script)?.[1] ?? "";
    const dir = temp("unpack");
    const r = Bun.spawnSync(["tar", "-xf", "-", "-C", dir], { stdin: input, stdout: "pipe", stderr: "pipe" });
    expect(r.exitCode).toBe(0);
    const files: Record<string, Buffer> = {};
    for (const name of readdirSync(dir)) files[name] = readFileSync(join(dir, name));
    const c = { script, staged, setup: script.includes("internal_options.conf /var/ossec/etc/internal_options.conf"), files };
    calls.push(c);
    return answer(c);
  };
  return { box: b, calls };
}

// What verify-agent-conf does with a file, as far as this gate relies on it: no
// internal_options.conf is CRITICAL 2301, element text ending in a backslash is the XML
// error, anything else is OK. The Linux group's sca warning rides along on its own file.
const wazuh = (c: Call): ReturnType<Box> => {
  const body = c.files[c.staged];
  if (!body) return box(1, `agentconf-staged \ncp: can't stat '/t/${c.staged}'\n`);
  const head = `agentconf-staged ${sha(body)}\n`;
  if (!c.setup) return box(1, head + NO_DEFS);
  if (/\\<\//.test(body.toString("utf8"))) return box(1, head + rejectedOut(c.staged));
  return box(0, head + (body.toString("utf8").includes("cis_ubuntu26-04.yml") ? SCA + OK : OK));
};
// Any other answer, behind the hash line the box script would print for this call.
const hashed = (c: Call, code: number, out: string) => box(code, `agentconf-staged ${sha(c.files[c.staged])}\n${out}`);

const quiet = <T>(go: () => T): { value: T; log: string[] } => {
  const log: string[] = [];
  const spy = spyOn(console, "log").mockImplementation((...a: unknown[]) => {
    log.push(a.join(" "));
  });
  try {
    return { value: go(), log };
  } finally {
    spy.mockRestore();
  }
};

// *--- Tests ---*

describe("classify", () => {
  test("a clean file passes", () => {
    expect(classify(at(0, OK), "g0.conf", S)).toEqual({ kind: "pass", warnings: [] });
  });

  test("the Linux group's sca warning does not turn a pass into a failure", () => {
    const v = classify(at(0, SCA + OK), "g0.conf", S);
    expect(v.kind).toBe("pass");
    expect(v.kind === "pass" && v.warnings).toEqual([SCA.trimEnd()]);
  });

  test("the 2026-11-14 file's output is a rejection carrying the checker's error", () => {
    const v = classify(at(1, rejectedOut("g2.conf")), "g2.conf", S);
    expect(v.kind).toBe("rejected");
    expect(v.kind === "rejected" && v.lines.join("\n")).toContain("XMLERR: Element 'registry_ignore' not closed");
  });

  test("a missing internal_options.conf is a setup failure, never a rejection or a pass", () => {
    for (const out of [NO_DEFS, "CRITICAL: (2301): Definition not found for: 'agent.remote_conf'\n"]) {
      for (const code of [0, 1]) {
        const v = classify(at(code, out), "g0.conf", S);
        expect(v.kind).toBe("setup");
        expect(v.kind === "setup" && v.why).toContain("did not start");
      }
    }
    // An OK beside the CRITICAL line changes nothing.
    expect(classify(at(0, NO_DEFS + OK), "g0.conf", S).kind).toBe("setup");
  });

  test("output for other bytes than the call sent is credited to neither verdict", () => {
    for (const [code, out] of [
      [0, OK],
      [1, rejectedOut("g0.conf")],
    ] as const) {
      const v = classify(at(code, out), "g0.conf", "b".repeat(64));
      expect(v.kind).toBe("setup");
      expect(v.kind === "setup" && v.why).toContain("other bytes than this call sent");
    }
    // No hash line at all, the hash line late, or an empty hash (sha256sum found no file).
    expect(classify(box(0, OK), "g0.conf", S).kind).toBe("setup");
    expect(classify(box(0, `${OK}agentconf-staged ${S}\n`), "g0.conf", S).kind).toBe("setup");
    expect((classify(box(0, `agentconf-staged \n${OK}`), "g0.conf", S) as { why: string }).why).toBe("the box could not hash the staged file");
    expect(classify(box(0, `agentconf-staged ${S.slice(1)}\n${OK}`), "g0.conf", S).kind).toBe("setup");
    // A second hash line is output the gate does not know.
    expect(classify(at(0, `agentconf-staged ${S}\n${OK}`), "g0.conf", S).kind).toBe("setup");
  });

  test("output that names another staged file is credited to neither verdict", () => {
    const v = classify(at(1, rejectedOut("g0.conf")), "g1.conf", S);
    expect(v.kind).toBe("setup");
    expect(v.kind === "setup" && v.why).toContain("names /t/g0.conf, not /t/g1.conf");
    expect(classify(at(0, `${T}verify-agent-conf: WARNING: '/t/g0.conf' read\n${OK}`), "g1.conf", S).kind).toBe("setup");
  });

  test("two OK lines in one call, or none, are not a pass", () => {
    expect(classify(at(0, OK + OK), "g0.conf", S).kind).toBe("setup");
    expect(classify(at(0, ""), "g0.conf", S).kind).toBe("setup");
    expect(classify(at(0, SCA), "g0.conf", S).kind).toBe("setup");
  });

  test("an exit code that disagrees with the output is a setup failure", () => {
    expect(classify(at(0, rejectedOut("g0.conf")), "g0.conf", S).kind).toBe("setup");
    expect(classify(at(1, OK), "g0.conf", S).kind).toBe("setup");
    expect(classify(at(1, rejectedOut("g0.conf") + OK), "g0.conf", S).kind).toBe("setup");
    expect(classify(at(1, ""), "g0.conf", S).kind).toBe("setup");
    expect(classify(at(2, OK), "g0.conf", S).kind).toBe("setup");
  });

  test("a rejection must name the file this call staged", () => {
    const v = classify(at(1, `${T}verify-agent-conf: ERROR: (1235): Invalid value for element 'frequency': x.\n`), "g0.conf", S);
    expect(v.kind).toBe("setup");
    expect(v.kind === "setup" && v.why).toContain("without naming /t/g0.conf");
  });

  test("output the gate does not know is a setup failure, shown to the reader", () => {
    const v = classify(at(1, "cp: can't stat '/var/ossec/data_tmp/x': No such file or directory\n"), "g0.conf", S);
    expect(v.kind).toBe("setup");
    expect(v.kind === "setup" && v.why).toContain("unrecognized checker output: cp: can't stat");
    expect(classify(at(0, `Verifying something\n${OK}`), "g0.conf", S).kind).toBe("setup");
  });

  test("the box script's own failures, docker's and ssh's are setup failures even beside an OK", () => {
    for (const code of [90, 91, 92, 125, 126, 127, 255, null]) {
      const v = classify(at(code, OK, "why"), "g0.conf", S);
      expect(v.kind).toBe("setup");
    }
    expect((classify(at(92, OK), "g0.conf", S) as { why: string }).why).toContain("was not removed");
    expect((classify(box(null, ""), "g0.conf", S) as { why: string }).why).toContain("did not finish");
    expect((classify(at(125, "docker: Error response from daemon: No such image\n"), "g0.conf", S) as { why: string }).why).toContain("docker could not run");
  });

  test("the first real run's lines, as the box printed them on 2026-11-20, read as they must", () => {
    const planted =
      "2026/11/20 11:07:25 verify-agent-conf: ERROR: (1226): Error reading XML file '/t/planted.conf': XMLERR: Element 'registry_ignore' not closed. (line 14).\n" +
      "2026/11/20 11:07:25 verify-agent-conf: ERROR: (1207): Syscheck remote configuration in '/t/planted.conf' is corrupted.\n";
    const v = classify(at(1, planted), "planted.conf", S);
    expect(v.kind).toBe("rejected");
    expect(v.kind === "rejected" && v.lines).toHaveLength(2);
    const nosetup =
      "2026/11/20 11:07:26 verify-agent-conf: ERROR: (1103): Could not open file 'etc/internal_options.conf' due to [(2)-(No such file or directory)].\n" +
      "2026/11/20 11:07:26 verify-agent-conf: CRITICAL: (2301): Definition not found for: 'agent.remote_conf'.\n";
    const w = classify(at(1, nosetup), "nosetup.conf", S);
    expect(w.kind).toBe("setup");
    expect(w.kind === "setup" && w.why).toContain("did not start");
  });

  test("a log line without the checker's timestamp is output the gate does not know", () => {
    const bare = "verify-agent-conf: ERROR: (1226): Error reading XML file '/t/g0.conf': XMLERR: Element 'registry_ignore' not closed. (line 19).\n";
    const v = classify(at(1, bare), "g0.conf", S);
    expect(v.kind).toBe("setup");
    expect(v.kind === "setup" && v.why).toContain("unrecognized checker output");
    expect(classify(at(0, `sca: WARNING: File 'etc/shared/cis_ubuntu26-04.yml' not found.\n${OK}`), "g0.conf", S).kind).toBe("setup");
    // A timestamp of the wrong shape, or one that is not at the line's start, is not one.
    expect(classify(at(1, bare.replace(/^/, "2026-11-20 11:07:25 ")), "g0.conf", S).kind).toBe("setup");
    expect(classify(at(1, bare.replace(/^/, "x 2026/11/20 11:07:25 ")), "g0.conf", S).kind).toBe("setup");
  });

  test("blank lines and a carriage return at a line end are not output", () => {
    expect(classify(at(0, `\r\n${OK.replace("\n", "\r\n")}\n`), "g0.conf", S).kind).toBe("pass");
    expect(classify(at(0, `  \t\n${SCA.replace("\n", "\r\n")}${OK}`), "g0.conf", S).kind).toBe("pass");
  });

  // Review of 2026-11-20: docker's stderr is merged into stdout on the box, but ssh and the
  // box shell keep their own, and a clean transcript beside it once read as a pass.
  test("anything on stderr beside a clean transcript is a setup failure, shown to the reader", () => {
    for (const out of [OK, SCA + OK]) {
      const v = classify(at(0, out, "tar: Ignoring unknown extended header keyword"), "g0.conf", S);
      expect(v.kind).toBe("setup");
      expect(v.kind === "setup" && v.why).toContain("stderr: tar: Ignoring unknown");
    }
    // A rejection with stray stderr is not a clean rejection either.
    expect(classify(at(1, rejectedOut("g0.conf"), "bash: warning: x"), "g0.conf", S).kind).toBe("setup");
  });

  // Same review: trimEnd() took a byte-order mark off the OK line, and a carriage return
  // inside a warning hid whatever followed it on the same record.
  test("a line that is not plain text is output the gate does not know", () => {
    const bad = [
      `verify-agent-conf: OK\ufeff\n`,
      `\ufeff${OK}`,
      `verify-agent-conf: OK\u00a0\n`,
      `${T}sca: WARNING: File 'x' not found.\rsomething else happened\n${OK}`,
      `${T}sca: WARNING: File 'x' not found.\u001b[2K\n${OK}`,
      `${OK}\u0000\n`,
      `${T}sca: WARNING: one\u2028two\n${OK}`,
    ];
    for (const out of bad) expect([JSON.stringify(out), classify(at(0, out), "g0.conf", S).kind]).toEqual([JSON.stringify(out), "setup"]);
    const v = classify(at(0, bad[3]), "g0.conf", S);
    expect(v.kind === "setup" && v.why).toContain("control character");
    // The hash line gets the same treatment.
    expect(classify(box(0, `agentconf-staged ${S}\ufeff\n${OK}`), "g0.conf", S).kind).toBe("setup");
  });
});

describe("box script", () => {
  test("runs the checker contract in a throwaway container with no network and no pull", () => {
    const s = boxScript(IMAGE, "g0.conf");
    expect(s).toContain(
      `docker run --rm --pull never --network none -w /var/ossec -v "$d:/t:ro" --entrypoint sh ${IMAGE} -c 'mkdir -p /var/ossec/etc && cp /var/ossec/data_tmp/exclusion/var/ossec/etc/internal_options.conf /var/ossec/etc/internal_options.conf && /var/ossec/bin/verify-agent-conf -f /t/g0.conf' </dev/null 2>&1`,
    );
    expect(s).toContain("unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_TLS_VERIFY DOCKER_CERT_PATH TAR_OPTIONS TAR_READER_OPTIONS TAR_WRITER_OPTIONS");
    // The hash line comes before docker, so the checker's output cannot sit ahead of it.
    expect(s.indexOf("printf 'agentconf-staged %s\\n'")).toBeGreaterThan(0);
    expect(s.indexOf("printf 'agentconf-staged")).toBeLessThan(s.indexOf("docker run"));
  });

  test("the no-setup variant leaves only the internal_options copy out", () => {
    const s = boxScript(IMAGE, "nosetup.conf", false);
    expect(s).not.toContain("internal_options.conf");
    expect(s).toContain("-c 'mkdir -p /var/ossec/etc && /var/ossec/bin/verify-agent-conf -f /t/nosetup.conf'");
  });

  test("refuses an image or staged name the shell could read as more than a word", () => {
    expect(() => boxScript("wazuh/wazuh-manager:4.14.9 ; id", "g0.conf")).toThrow(SetupError);
    expect(() => boxScript("alpine:3", "g0.conf")).toThrow(SetupError);
    for (const name of ["../g0.conf", "a b.conf", "g0.conf'", "-g0.conf", "g0", "G0.conf"]) expect(() => boxScript(IMAGE, name)).toThrow(SetupError);
  });
});

// The box script itself, run here under sh with a stand-in docker that does what the
// checker does with the mounted file. No ssh and no docker.
describe("box script, run for real", () => {
  let stub: string;
  beforeAll(() => {
    stub = mkdtempSync(join(tmpdir(), "agentconf-stub-"));
    const docker = String.raw`#!/bin/sh
[ -z "$DOCKER_HOST" ] || { echo "stub docker: DOCKER_HOST reached docker" >&2; exit 64; }
[ "$(wc -c | tr -d ' ')" = 0 ] || { echo "stub docker: stdin was not /dev/null" >&2; exit 65; }
mount=""; cmd=""
while [ $# -gt 0 ]; do
  case "$1" in
    -v) mount=$2; shift 2 ;;
    -c) cmd=$2; shift 2 ;;
    *) shift ;;
  esac
done
dir=$(printf '%s' "$mount" | sed 's#:/t:ro$##')
echo "$dir" >> "$SEEN"
[ -z "$STUB_EXIT" ] || exit "$STUB_EXIT"
file=$(printf '%s' "$cmd" | sed 's#.*-f /t/##')
case "$cmd" in *internal_options.conf*) ;; *) echo "2026/11/20 11:07:26 verify-agent-conf: CRITICAL: (2301): Definition not found for: 'agent.remote_conf'."; exit 1 ;; esac
if grep -q '\\</' "$dir/$file"; then
  echo "2026/11/20 11:07:25 verify-agent-conf: ERROR: (1226): Error reading XML file '/t/$file': XMLERR: Element 'registry_ignore' not closed. (line 19)."
  echo "2026/11/20 11:07:25 verify-agent-conf: ERROR: (1207): Syscheck remote configuration in '/t/$file' is corrupted."
  exit 1
fi
echo "verify-agent-conf: OK"
`;
    writeFileSync(join(stub, "docker"), docker);
    chmodSync(join(stub, "docker"), 0o755);
  });
  afterAll(() => rmSync(stub, { recursive: true, force: true }));

  // Runs the script the way ssh would, with the tar stream on stdin and the home a folder here.
  const local = (env: Record<string, string> = {}) => {
    const home = temp("home");
    const seen = join(temp("seen"), "log");
    const b: Box = (_host, script, input) => {
      const r = Bun.spawnSync(["sh", "-c", script], {
        stdin: input,
        env: { HOME: home, PATH: `${stub}:${process.env.PATH}`, SEEN: seen, ...env },
        stdout: "pipe",
        stderr: "pipe",
      });
      return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString().trim() };
    };
    const mounts = () => (existsSync(seen) ? readFileSync(seen, "utf8").trim().split("\n") : []);
    return { b, home, mounts };
  };

  test("the planted file is rejected, the control passes, the no-setup run is a setup failure, and no staging folder is left", () => {
    const { b, home, mounts } = local();
    const planted = checkOne(b, "box", IMAGE, "planted.conf", PLANTED);
    const control = checkOne(b, "box", IMAGE, "clean.conf", CONTROL);
    const nosetup = checkOne(b, "box", IMAGE, "nosetup.conf", CONTROL, false);
    expect(planted.kind).toBe("rejected");
    expect(control.kind).toBe("pass");
    expect(nosetup.kind).toBe("setup");
    // Each call mounted its own folder in the home, and each folder is gone.
    const used = mounts();
    expect(used).toHaveLength(3);
    expect(new Set(used).size).toBe(3);
    for (const m of used) {
      expect(m.startsWith(`${home}/.agentconf.`)).toBe(true);
      expect(existsSync(m)).toBe(false);
    }
    expect(readdirSync(home)).toEqual([]);
  });

  test("a docker failure is a setup failure and still removes the staging folder", () => {
    const { b, home, mounts } = local({ STUB_EXIT: "125" });
    const v = checkOne(b, "box", IMAGE, "clean.conf", CONTROL);
    expect(v.kind).toBe("setup");
    expect(mounts()).toHaveLength(1);
    expect(readdirSync(home)).toEqual([]);
  });

  test("a DOCKER_HOST in the box account's environment never reaches docker", () => {
    const { b } = local({ DOCKER_HOST: "tcp://<OTHER-DAEMON>:2375" });
    expect(checkOne(b, "box", IMAGE, "clean.conf", CONTROL).kind).toBe("pass");
  });

  test("a stage that will not unpack stops before docker, with nothing left behind", () => {
    const { b, home, mounts } = local();
    const r = b("box", boxScript(IMAGE, "g0.conf"), new TextEncoder().encode("not a tar stream"));
    expect(r.code).toBe(91);
    expect(classify(r, "g0.conf", S).kind).toBe("setup");
    expect(mounts()).toEqual([]);
    expect(readdirSync(home)).toEqual([]);
  });
});

describe("full run", () => {
  test("the repo holds the three groups, each with an agent.conf", () => {
    expect(findGroups().map((g) => g.group)).toEqual(GROUPS);
  });

  test("every group passing writes the receipt, and nothing else changes", () => {
    const root = tree();
    const before = snapshot(root);
    const f = fakeBox(wazuh);
    const out = run({ host: "box", root }, f.box);
    expect(out.code).toBe(0);
    expect(out.results.map((r) => [r.group, r.verdict.kind])).toEqual(GROUPS.map((g) => [g, "pass"]));
    // The Linux group's warning is carried, not failed.
    const linux = out.results[0].verdict;
    expect(linux.kind === "pass" && linux.warnings).toEqual([SCA.trimEnd()]);
    const after = snapshot(root);
    expect(Object.keys(after).filter((k) => !(k in before))).toEqual([RECEIPT]);
    for (const [k, v] of Object.entries(before)) expect(after[k]).toBe(v);
    const text = readFileSync(join(root, RECEIPT), "utf8");
    expect(text).toContain(`image ${IMAGE}\n`);
    for (const g of GROUPS) expect(text).toContain(`${sha(readFileSync(join(root, SHARED, g, "agent.conf")))}  ${g}/agent.conf\n`);
    // The receipt the run wrote is the one the offline check accepts.
    expect(compareReceipt(readWorkingTree(root))).toEqual([]);
  });

  test("stderr on one call stops the run and leaves the receipt untouched", () => {
    const root = tree();
    writeFileSync(join(root, RECEIPT), "sentinel\n");
    const before = snapshot(root);
    const f = fakeBox((c) => ({ ...wazuh(c), err: c.staged === "g1.conf" ? "unexpected diagnostic" : "" }));
    const out = run({ host: "box", root }, f.box);
    expect(out.code).toBe(2);
    expect(out.results.map((r) => r.verdict.kind)).toEqual(["pass", "setup", "pass"]);
    expect(snapshot(root)).toEqual(before);
    expect(readFileSync(join(root, RECEIPT), "utf8")).toBe("sentinel\n");
  });

  test("each call carries exactly one file, the bytes of its own group, and no tree text in the script", () => {
    const root = tree();
    const f = fakeBox(wazuh);
    run({ host: "box", root }, f.box);
    expect(f.calls).toHaveLength(3);
    f.calls.forEach((c, i) => {
      expect(c.staged).toBe(`g${i}.conf`);
      expect(Object.keys(c.files)).toEqual([c.staged]);
      expect(c.files[c.staged].equals(readFileSync(join(root, SHARED, GROUPS[i], "agent.conf")))).toBe(true);
      expect(c.setup).toBe(true);
      // SECURITY: no group name and no config text crosses into the shell. The script is
      // the constant one for its staged name and the pinned image, nothing more.
      expect(c.script).toBe(boxScript(IMAGE, c.staged));
      for (const g of GROUPS) expect(c.script).not.toContain(g);
      expect(c.script).not.toContain("agent_config");
    });
  });

  test("a rejected file exits 1, names the file and the checker's error, and leaves the receipt untouched", () => {
    const root = tree();
    writeFileSync(join(root, RECEIPT), "sentinel\n");
    writeFileSync(join(root, SHARED, "phase-a-windows/agent.conf"), PLANTED);
    const before = snapshot(root);
    const out = run({ host: "box", root }, fakeBox(wazuh).box);
    expect(out.code).toBe(1);
    const win = out.results.find((r) => r.group === "phase-a-windows");
    expect(win?.verdict.kind).toBe("rejected");
    const line = verdictLine(win?.group ?? "", win?.path ?? "", win?.verdict as Verdict);
    expect(line).toStartWith("FAIL phase-a-windows deploy/soc-recon/wazuh/shared/phase-a-windows/agent.conf: rejected by verify-agent-conf: ");
    expect(line).toContain("XMLERR: Element 'registry_ignore' not closed");
    expect(line).not.toContain("\n");
    // The other two still pass on their own bytes.
    expect(out.results.filter((r) => r.verdict.kind === "pass").map((r) => r.group)).toEqual(["phase-a-linux", "phase-a-macos"]);
    expect(snapshot(root)).toEqual(before);
    expect(readFileSync(join(root, RECEIPT), "utf8")).toBe("sentinel\n");
  });

  test("a setup failure exits 2, is not called a rejection or a pass, and writes no receipt", () => {
    const root = tree();
    const out = run({ host: "box", root }, fakeBox((c) => hashed(c, 1, NO_DEFS)).box);
    expect(out.code).toBe(2);
    expect(out.results.every((r) => r.verdict.kind === "setup")).toBe(true);
    const line = verdictLine("phase-a-linux", "x", out.results[0].verdict);
    expect(line).toStartWith("SETUP phase-a-linux x: the checker did not start: ");
    expect(line).toContain("(2301)");
    expect(existsSync(join(root, RECEIPT))).toBe(false);
  });

  test("a rejection outranks a setup failure in the exit code", () => {
    const root = tree();
    writeFileSync(join(root, SHARED, "phase-a-windows/agent.conf"), PLANTED);
    const f = fakeBox((c) => (c.staged === "g0.conf" ? box(255, "", "ssh: connect to host box: timed out") : wazuh(c)));
    const out = run({ host: "box", root }, f.box);
    expect(out.results.map((r) => r.verdict.kind)).toEqual(["setup", "pass", "rejected"]);
    expect(out.code).toBe(1);
    expect(existsSync(join(root, RECEIPT))).toBe(false);
  });

  test("an OK can never be credited to another file", () => {
    const root = tree();
    writeFileSync(join(root, SHARED, "phase-a-windows/agent.conf"), PLANTED);
    // A box that answers every call with the first call's output: the windows call gets
    // the Linux OK, which names no file at all. The hash line it opens with is the Linux
    // file's, so it passes the Linux file only.
    let first: ReturnType<Box> | undefined;
    const replay = fakeBox((c) => (first ??= wazuh(c)));
    const a = run({ host: "box", root }, replay.box);
    expect(replay.calls[2].files["g2.conf"].equals(PLANTED)).toBe(true);
    expect(a.results.map((r) => r.verdict.kind)).toEqual(["pass", "setup", "setup"]);
    expect((a.results[2].verdict as { why: string }).why).toContain("other bytes than this call sent");
    expect(a.code).toBe(2);
    expect(existsSync(join(root, RECEIPT))).toBe(false);
    // Output joined from two calls holds two OK lines, and is no pass for either.
    const joined = run({ host: "box", root: tree() }, fakeBox((c) => box(0, wazuh(c).out + OK)).box);
    expect(joined.code).toBe(2);
    expect(joined.results.every((r) => r.verdict.kind === "setup")).toBe(true);
    // A rejection that names g0 is credited to neither g1 nor g2, even behind their own hashes.
    const crossed = run({ host: "box", root: tree() }, fakeBox((c) => hashed(c, 1, rejectedOut("g0.conf"))).box);
    expect(crossed.results.map((r) => r.verdict.kind)).toEqual(["rejected", "setup", "setup"]);
  });

  test("a file saved while the run was on the box stops the receipt", () => {
    const root = tree();
    const f = fakeBox((c) => {
      if (c.staged === "g2.conf") writeFileSync(join(root, SHARED, "phase-a-windows/agent.conf"), `${CONTROL}<!-- edited -->\n`);
      return wazuh(c);
    });
    const out = run({ host: "box", root }, f.box);
    expect(out.code).toBe(2);
    expect(out.unwritten).toContain("changed while the run was on the box");
    expect(existsSync(join(root, RECEIPT))).toBe(false);
  });

  test("a group folder with no agent.conf, a symlinked agent.conf or an odd group name stops the run before the box", () => {
    const cases: [string, (root: string) => void, RegExp][] = [
      ["no agent.conf", (r) => mkdirSync(join(r, SHARED, "phase-b-new")), /phase-b-new has no agent\.conf/],
      [
        "symlink",
        (r) => {
          rmSync(join(r, SHARED, "phase-a-macos/agent.conf"));
          symlinkSync(join(r, SHARED, "phase-a-linux/agent.conf"), join(r, SHARED, "phase-a-macos/agent.conf"));
        },
        /phase-a-macos\/agent\.conf is not a regular file/,
      ],
      ["name", (r) => mkdirSync(join(r, SHARED, "bad name")), /is not a plain group name/],
    ];
    for (const [, plant, why] of cases) {
      const root = tree();
      plant(root);
      const f = fakeBox(wazuh);
      expect(() => run({ host: "box", root }, f.box)).toThrow(why);
      expect(f.calls).toHaveLength(0);
    }
  });
});

describe("self-test", () => {
  test("passes when the planted file is rejected, the control passes and the no-setup run fails as setup", () => {
    const { value, log } = quiet(() => selfTest("box", fakeBox(wazuh).box, tree()));
    expect(value).toBe(true);
    expect(log.filter((l) => l.startsWith("OK   self-test"))).toHaveLength(3);
  });

  test("fails when the checker would accept the planted backslash", () => {
    const { value, log } = quiet(() => selfTest("box", fakeBox((c) => (c.setup ? hashed(c, 0, OK) : wazuh(c))).box, tree()));
    expect(value).toBe(false);
    expect(log).toContain("BAD  self-test planted backslash is rejected with the XML error");
  });

  test("fails when the planted file is rejected for some reason other than the XML error", () => {
    const other = (c: Call) => (c.staged === "planted.conf" ? hashed(c, 1, `${T}verify-agent-conf: ERROR: (1202): Configuration error at '/t/${c.staged}'.\n`) : wazuh(c));
    const { value, log } = quiet(() => selfTest("box", fakeBox(other).box, tree()));
    expect(value).toBe(false);
    // The rejection is real, but not the one the self-test plants.
    expect(log.some((l) => l.startsWith("FAIL planted"))).toBe(true);
    expect(log).toContain("BAD  self-test planted backslash is rejected with the XML error");
  });

  test("fails when a run with no internal_options.conf passes or reads as a rejection", () => {
    const passes = quiet(() => selfTest("box", fakeBox((c) => (c.setup ? wazuh(c) : hashed(c, 0, OK))).box, tree()));
    expect(passes.value).toBe(false);
    expect(passes.log).toContain("BAD  self-test checker without internal_options.conf is a setup failure");
    const rejects = quiet(() => selfTest("box", fakeBox((c) => (c.setup ? wazuh(c) : hashed(c, 1, rejectedOut(c.staged)))).box, tree()));
    expect(rejects.value).toBe(false);
  });

  test("a setup failure for another reason than 2301 does not satisfy the setup check", () => {
    const docker = (c: Call) => (c.setup ? wazuh(c) : hashed(c, 125, "docker: Error response from daemon: No such image\n"));
    expect(quiet(() => selfTest("box", fakeBox(docker).box, tree())).value).toBe(false);
  });

  test("an unreachable box fails all three, the setup case included", () => {
    const { value, log } = quiet(() => selfTest("box", fakeBox(() => box(255, "", "ssh: no route")).box, tree()));
    expect(value).toBe(false);
    expect(log.filter((l) => l.startsWith("BAD "))).toHaveLength(3);
  });

  test("refuses fixtures edited out of their shapes before touching the box", () => {
    const root = tree();
    writeFileSync(join(root, "tools/fixtures/agentconf/planted-backslash.conf"), CONTROL);
    const f = fakeBox(wazuh);
    expect(() => selfTest("box", f.box, root)).toThrow(/has no element text ending in a backslash/);
    const root2 = tree();
    writeFileSync(join(root2, "tools/fixtures/agentconf/clean.conf"), PLANTED);
    expect(() => selfTest("box", f.box, root2)).toThrow(/clean\.conf has element text ending in a backslash/);
    expect(f.calls).toHaveLength(0);
  });
});

describe("offline receipt check", () => {
  // A tree with a receipt written for its current files.
  const verified = () => {
    const root = tree();
    const groups = findGroups(root);
    writeFileSync(join(root, RECEIPT), receiptText(IMAGE, groups));
    return root;
  };

  test("a receipt that matches every group and the pinned image is clean", () => {
    expect(compareReceipt(readWorkingTree(verified()))).toEqual([]);
  });

  test("no receipt fails and says to run the full check", () => {
    const p = compareReceipt(readWorkingTree(tree()));
    expect(p).toEqual([`${RECEIPT}: no receipt; run bun tools/agentconf-check.ts to verify every group on the box`]);
  });

  test("a changed agent.conf fails, naming the file", () => {
    const root = verified();
    writeFileSync(join(root, SHARED, "phase-a-windows/agent.conf"), PLANTED);
    const p = compareReceipt(readWorkingTree(root));
    expect(p).toHaveLength(1);
    expect(p[0]).toStartWith(`${SHARED}/phase-a-windows/agent.conf: changed since the last verified run; run bun tools/agentconf-check.ts`);
  });

  test("a group the receipt does not list fails, and so does a group folder with no agent.conf", () => {
    const root = verified();
    mkdirSync(join(root, SHARED, "phase-b-new"));
    writeFileSync(join(root, SHARED, "phase-b-new/agent.conf"), CONTROL);
    mkdirSync(join(root, SHARED, "phase-b-empty"));
    expect(compareReceipt(readWorkingTree(root))).toEqual([
      `${SHARED}/phase-b-empty: has no agent.conf`,
      `${SHARED}/phase-b-new/agent.conf: no entry in the receipt; run bun tools/agentconf-check.ts to verify every group on the box`,
    ]);
  });

  test("a receipt entry for a group that is gone fails", () => {
    const root = verified();
    rmSync(join(root, SHARED, "phase-a-macos"), { recursive: true });
    const p = compareReceipt(readWorkingTree(root));
    expect(p).toEqual([`${RECEIPT}: lists phase-a-macos, which is not a group folder in the tree; run bun tools/agentconf-check.ts to verify every group on the box`]);
  });

  test("an image change in the compose file fails", () => {
    const root = verified();
    const compose = readFileSync(join(root, COMPOSE), "utf8");
    const bumped = compose.replace("wazuh/wazuh-manager:${WAZUH_VERSION:-4.14.9}", "wazuh/wazuh-manager:${WAZUH_VERSION:-4.14.10}");
    expect(bumped).not.toBe(compose);
    writeFileSync(join(root, COMPOSE), bumped);
    const p = compareReceipt(readWorkingTree(root));
    expect(p).toHaveLength(1);
    expect(p[0]).toContain(`verified on ${IMAGE}, but ${COMPOSE} pins wazuh/wazuh-manager:4.14.10`);
  });

  test("a receipt it cannot read whole fails", () => {
    const good = receiptText(IMAGE, [{ group: "a", sha256: "0".repeat(64) }]);
    expect(parseReceipt(good).problems).toEqual([]);
    expect(parseReceipt(`${good}junk\n`).problems).toEqual(["line 5 is not an image or hash line"]);
    expect(parseReceipt(`${good}image other:1\n`).problems).toEqual(["line 5 names a second image"]);
    expect(parseReceipt(`${good}${"1".repeat(64)}  a/agent.conf\n`).problems).toEqual(["line 5 lists a a second time"]);
    expect(parseReceipt(good.replace(/^image .*\n/m, "")).problems).toEqual(["names no image"]);
    // An upper-case or short hash is not a hash line.
    expect(parseReceipt(good.replace("0".repeat(64), "A".repeat(64))).problems).toHaveLength(1);
  });

  test("the receipt lists groups in a fixed order, so a rerun on the same files changes nothing", () => {
    const g = [
      { group: "b", sha256: "1".repeat(64) },
      { group: "a", sha256: "2".repeat(64) },
    ];
    expect(receiptText(IMAGE, g)).toBe(receiptText(IMAGE, [...g].reverse()));
  });
});

// The hook end to end in a scratch repo: leakcheck first, then the offline check from the
// index whenever a commit touches the shared folder.
describe("pre-commit hook", () => {
  let scratch: string;
  let repo: string;
  let env: Record<string, string>;
  const git = (...args: string[]) => {
    const r = Bun.spawnSync(["git", ...args], { cwd: repo, env, stdout: "pipe", stderr: "pipe" });
    return { code: r.exitCode, out: `${r.stdout.toString()}${r.stderr.toString()}` };
  };
  const put = (path: string, content: string | Buffer) => {
    mkdirSync(join(repo, path, ".."), { recursive: true });
    writeFileSync(join(repo, path), content);
  };
  const compose = (tag: string) => `services:\n  wazuh.manager:\n    image: wazuh/wazuh-manager:\${WAZUH_VERSION:-${tag}}\n`;
  const receiptFor = (tag: string) => receiptText(`wazuh/wazuh-manager:${tag}`, findGroups(repo));

  beforeAll(() => {
    scratch = mkdtempSync(join(tmpdir(), "agentconf-hook-"));
    repo = join(scratch, "repo");
    mkdirSync(repo);
    writeFileSync(join(scratch, "gitconfig"), "[user]\n\tname = hook test\n\temail = test@example.test\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n");
    env = { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", GIT_CONFIG_GLOBAL: join(scratch, "gitconfig"), GIT_CONFIG_NOSYSTEM: "1" };
    // The hook and every tool it runs, kept untracked as in the leakcheck tests.
    mkdirSync(join(repo, "tools"));
    for (const f of readdirSync(resolve(ROOT, "tools"))) if (f.endsWith(".ts") && !f.endsWith(".test.ts")) cpSync(resolve(ROOT, "tools", f), join(repo, "tools", f));
    cpSync(resolve(ROOT, "tools/hooks"), join(repo, "tools/hooks"), { recursive: true });
    writeFileSync(join(repo, "tools/leak-denylist.txt"), "zq-scratch-only-literal\n");
    expect(git("init", "-q").code).toBe(0);
    const installed = Bun.spawnSync(["bash", "tools/hooks/install.sh"], { cwd: repo, env, stdout: "pipe", stderr: "pipe" });
    expect(installed.exitCode).toBe(0);
    put(".gitignore", "/tools/\n");
    put("README.md", "# scratch\n");
    put(COMPOSE, compose("4.14.9"));
  });
  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  test("a commit outside the shared folder runs leakcheck only, with no receipt anywhere", () => {
    expect(git("add", "-A").code).toBe(0);
    const r = git("commit", "-q", "-m", "initial");
    expect(r.out).toContain("leakcheck: clean");
    expect(r.out).not.toContain("agentconf-check");
    expect(r.code).toBe(0);
  });

  test("a commit that adds group configs without a receipt is blocked", () => {
    put(`${SHARED}/g-linux/agent.conf`, "<agent_config></agent_config>\n");
    put(`${SHARED}/g-windows/agent.conf`, CONTROL);
    expect(git("add", "-A").code).toBe(0);
    const r = git("commit", "-q", "-m", "add groups");
    expect(r.out).toContain(`${RECEIPT}: no receipt`);
    expect(r.code).not.toBe(0);
  });

  test("the same commit with a matching receipt goes through", () => {
    put(RECEIPT, receiptFor("4.14.9"));
    expect(git("add", "-A").code).toBe(0);
    const r = git("commit", "-q", "-m", "add groups");
    expect(r.out).toContain("the receipt covers 2 group(s) on wazuh/wazuh-manager:4.14.9");
    expect(r.code).toBe(0);
  });

  test("a staged change the receipt does not cover is blocked, even with the good file back in the working tree", () => {
    const path = `${SHARED}/g-windows/agent.conf`;
    put(path, PLANTED);
    expect(git("add", path).code).toBe(0);
    put(path, CONTROL);
    const r = git("commit", "-q", "-m", "planted");
    expect(r.out).toContain(`${path}: changed since the last verified run`);
    expect(r.code).not.toBe(0);
    expect(git("reset", "-q", "--", path).code).toBe(0);
  });

  test("a replace ref cannot pass off the staged blob as the verified one", () => {
    const path = `${SHARED}/g-windows/agent.conf`;
    const verifiedBlob = git("rev-parse", `HEAD:${path}`).out.trim();
    put(path, PLANTED);
    expect(git("add", path).code).toBe(0);
    const plantedBlob = git("rev-parse", `:${path}`).out.trim();
    expect(git("replace", plantedBlob, verifiedBlob).code).toBe(0);
    try {
      expect(git("cat-file", "blob", plantedBlob).out).toBe(CONTROL.toString("utf8"));
      const r = git("commit", "-q", "-m", "planted behind a replace ref");
      expect(r.out).toContain(`${path}: changed since the last verified run`);
      expect(r.code).not.toBe(0);
    } finally {
      expect(git("replace", "-d", plantedBlob).code).toBe(0);
      expect(git("reset", "-q", "--", path).code).toBe(0);
      put(path, CONTROL);
    }
  });

  test("an image bump staged with a shared change is blocked until the receipt names the new image", () => {
    put(COMPOSE, compose("4.14.10"));
    put(`${SHARED}/README.md`, "notes\n");
    expect(git("add", "-A").code).toBe(0);
    const r = git("commit", "-q", "-m", "bump");
    expect(r.out).toContain("verified on wazuh/wazuh-manager:4.14.9, but deploy/soc-recon/docker-compose.yml pins wazuh/wazuh-manager:4.14.10");
    expect(r.code).not.toBe(0);
    put(RECEIPT, receiptFor("4.14.10"));
    expect(git("add", "-A").code).toBe(0);
    expect(git("commit", "-q", "-m", "bump").code).toBe(0);
  });

  // Review of 2026-11-20: the index reader skipped every direct child of the shared folder
  // but the receipt, so a staged symlink to a group passed where the working tree refused it.
  test("a symlink directly under the shared folder is refused from the index and from the working tree", () => {
    const link = `${SHARED}/g-alias`;
    symlinkSync("g-linux", join(repo, link));
    try {
      expect(git("add", link).code).toBe(0);
      expect(git("ls-files", "-s", "--", link).out).toStartWith("120000 ");
      const r = git("commit", "-q", "-m", "alias");
      expect(r.out).toContain(`${SHARED}/g-alias: is a symlink`);
      expect(r.code).not.toBe(0);
      for (const args of [["--offline", "--staged"], ["--offline"]]) {
        const t = Bun.spawnSync(["bun", "tools/agentconf-check.ts", ...args], { cwd: repo, env, stdout: "pipe", stderr: "pipe" });
        expect(`${t.stdout.toString()}${t.stderr.toString()}`).toContain(`${SHARED}/g-alias: is a symlink`);
        expect(t.exitCode).toBe(1);
      }
    } finally {
      git("reset", "-q", "--", link);
      rmSync(join(repo, link), { force: true });
    }
  });

  // Same review: the hook tested only the output of the path listing, so a git failure
  // there read as "nothing staged under the shared folder" and the commit went through.
  test("a git failure while listing the staged paths blocks the commit", () => {
    const path = `${SHARED}/g-windows/agent.conf`;
    const bin = join(scratch, "fakebin");
    mkdirSync(bin, { recursive: true });
    const real = Bun.which("git") ?? "";
    expect(real).not.toBe("");
    // A git that fails only for the hook's own listing of the shared folder.
    writeFileSync(
      join(bin, "git"),
      `#!/usr/bin/env bash\nif [ "\${@: -1}" = "${SHARED}/" ]; then for a in "$@"; do if [ "$a" = "--name-only" ]; then echo "fatal: injected" >&2; exit 128; fi; done; fi\nexec "${real}" "$@"\n`,
    );
    chmodSync(join(bin, "git"), 0o755);
    const hook = (path_: string) => {
      const r = Bun.spawnSync(["bash", "tools/hooks/pre-commit"], { cwd: repo, env: { ...env, PATH: path_ }, stdout: "pipe", stderr: "pipe" });
      return { code: r.exitCode, out: `${r.stdout.toString()}${r.stderr.toString()}` };
    };
    put(path, PLANTED);
    try {
      expect(git("add", path).code).toBe(0);
      // With a working git the stale receipt blocks it.
      const ok = hook(env.PATH);
      expect(ok.out).toContain(`${path}: changed since the last verified run`);
      expect(ok.code).not.toBe(0);
      // With the listing broken it must still be blocked, and say why.
      const broken = hook(`${bin}:${env.PATH}`);
      expect(broken.out).toContain("leakcheck: clean");
      expect(broken.out).toContain("could not list the staged paths");
      expect(broken.code).not.toBe(0);
    } finally {
      git("reset", "-q", "--", path);
      put(path, CONTROL);
    }
  });
});
