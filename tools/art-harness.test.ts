// *****************************************************************************
// *Title: art-harness.test*
// *Author: Kyle Versluis*
// *Description: Offline checks of the ART harness through a fake Dell.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  ALLOWLIST_PATH,
  ATOMICS_COMMIT,
  type AllowEntry,
  type Allowlist,
  bootstrap,
  buildManifest,
  CATEGORIES,
  CMDLINE_MAX,
  checkAllowlist,
  cleanDell,
  compareListing,
  decodeAnswer,
  defenderVerdict,
  diffSnapshots,
  EXIT,
  fakeRemote,
  fill,
  gateScript,
  HarnessError,
  MANIFEST_PATH,
  type Manifest,
  MODULE_NAME,
  MODULE_VERSION,
  manifestText,
  parseAllowlist,
  PAYLOAD_MISSING,
  STDIN_WAIT_MS,
  parseGate,
  parseManifest,
  parseSnapshot,
  parseStep,
  type Remote,
  type RemoteResult,
  readCleanup,
  readPrereqs,
  readRun,
  recordFindings,
  redactName,
  remoteCommand,
  restoreScript,
  restoreVerdict,
  runSession,
  type SessionOptions,
  type Segment,
  type Snapshot,
  STAGED_ROOT,
  selectTests,
  selfTest,
  snapshotScript,
  sshRemote,
  stageFiles,
  stepScript,
  testId,
  treeDigest,
  YAML_MODULE,
  YAML_VERSION,
  deriveTests,
  fixtureCheckout,
  testReferences,
} from "./art-harness.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const ALLOW_TEXT = readFileSync(resolve(ROOT, ALLOWLIST_PATH), "utf8");
const AL = parseAllowlist(ALLOW_TEXT);
const TAG = "TSLART1 ";
const SESSION = "20261122T030000Z-abcdef";
const DESC = `talonsoclab-b4-${SESSION}`;
const DIGEST = "a".repeat(64);
const SAFE_TWO = AL.tests.filter((t) => !t.runsFetchedCode).slice(0, 2);
const OK_GIT = () => ({ head: ATOMICS_COMMIT, dirty: false });
const ARTS = join(homedir(), "code", "atomic-red-team");

// *--- Helpers ---*

const tmps: string[] = [];
const temp = (name: string) => {
  const d = mkdtempSync(join(tmpdir(), `art-harness-test-${name}-`));
  tmps.push(d);
  return d;
};
afterAll(() => {
  for (const d of tmps) rmSync(d, { recursive: true, force: true });
});

const sha = (b: string | Uint8Array) => createHash("sha256").update(b).digest("hex");
// Addresses are built at run time, as in winevt.test.ts, so none sits in the source.
const v4 = (...o: number[]) => o.join(".");
const mutate = (o: Record<string, unknown>) => JSON.stringify(o);
const allowWith = (f: (o: Record<string, any>) => void) => {
  const o = JSON.parse(ALLOW_TEXT);
  f(o);
  return mutate(o);
};
const refusedWith = (text: string, part: string) => {
  let err: unknown;
  try {
    parseAllowlist(text);
  } catch (e) {
    err = e;
  }
  expect(err).toBeInstanceOf(HarnessError);
  expect((err as HarnessError).exit).toBe(EXIT.refused);
  expect((err as HarnessError).message).toContain(part);
};

// The first allowlisted test references one file through a default input, as T1547.010 #1 does.
const REFERENCED = `atomics/${AL.tests[0].technique}/src/payload.txt`;
const REF_COMMAND = `copy "$PathToAtomicsFolder\\${AL.tests[0].technique}\\src\\payload.txt" %temp%`;

/** Write a test's command into a fixture YAML, keeping every other test as fixtureCheckout made it. */
function setCommand(checkout: string, e: AllowEntry, command: string, extra: Record<string, unknown> = {}) {
  const file = join(checkout, "atomics", e.technique, `${e.technique}.yaml`);
  const doc = JSON.parse(readFileSync(file, "utf8"));
  doc.atomic_tests[e.testNumber - 1] = { ...doc.atomic_tests[e.testNumber - 1], executor: { name: e.executor, command }, ...extra };
  writeFileSync(file, JSON.stringify(doc));
}

/** A module, a powershell-yaml module and a checkout with one YAML per technique, all in a temp tree. */
function fixtureTree(withYaml = true) {
  const dir = temp("tree");
  const mod = join(dir, "module");
  mkdirSync(join(mod, "Public"), { recursive: true });
  mkdirSync(join(mod, "_rels"), { recursive: true });
  mkdirSync(join(mod, "package", "services"), { recursive: true });
  writeFileSync(join(mod, `${MODULE_NAME}.psd1`), `@{\n  ModuleVersion = '${MODULE_VERSION}'\n}\n`);
  writeFileSync(join(mod, "PSScriptAnalyzerSettings.psd1"), "@{ Rules = @{} }\n");
  writeFileSync(join(mod, "Public", "Invoke-AtomicTest.ps1"), "function Invoke-AtomicTest {}\n");
  writeFileSync(join(mod, "_rels", ".rels"), "x");
  writeFileSync(join(mod, "package", "services", "p.psmdcp"), "x");
  writeFileSync(join(mod, "[Content_Types].xml"), "x");
  writeFileSync(join(mod, `${MODULE_NAME}.nuspec`), "x");
  const yaml = join(dir, "yaml");
  mkdirSync(yaml);
  writeFileSync(join(yaml, `${YAML_MODULE}.psd1`), `@{\n  ModuleVersion = '${YAML_VERSION}'\n}\n`);
  const checkout = join(dir, "checkout");
  fixtureCheckout(checkout, AL, { [AL.tests[0].guid]: REF_COMMAND });
  mkdirSync(join(checkout, "atomics", AL.tests[0].technique, "src"), { recursive: true });
  writeFileSync(join(checkout, ...REFERENCED.split("/")), "payload\n");
  const modules = withYaml ? [mod, yaml] : [mod];
  const m = buildManifest(AL, ALLOW_TEXT, modules, checkout, OK_GIT);
  return { dir, mod, yaml, checkout, modules, m, text: manifestText(m) };
}

const FIX = fixtureTree();

const answer = (o: unknown, code = 0): RemoteResult => ({ code, out: `${TAG}${Buffer.from(JSON.stringify(o)).toString("base64")}\n`, err: "", timedOut: false });
const stepOf = (payload: string) => /^# talonsoclab-art step=([a-z-]+)$/m.exec(payload)?.[1] ?? "";

interface Run {
  out: ReturnType<typeof runSession>;
  sent: { step: string; payload: string }[];
  written: string[];
}

/** One session through a fake Dell; override lets a test answer some steps itself. */
function session(d = cleanDell(FIX.m), extra: Partial<SessionOptions> = {}, override?: (step: string, payload: string) => RemoteResult | undefined): Run {
  const sent: { step: string; payload: string }[] = [];
  const base = fakeRemote(d, sent, AL);
  const remote: Remote = (payload, ms) => {
    const own = override?.(stepOf(payload), payload);
    if (own) {
      sent.push({ step: stepOf(payload), payload });
      return own;
    }
    return base(payload, ms);
  };
  const written: string[] = [];
  const out = runSession({
    mode: "run",
    guids: SAFE_TWO.map((t) => t.guid),
    timeoutSeconds: 120,
    allowRemoteCode: false,
    remote,
    allowlistText: ALLOW_TEXT,
    manifestText: FIX.text,
    sessionId: SESSION,
    raw: () => {},
    writeRecord: (_id, json) => {
      written.push(json);
      return "memory";
    },
    log: () => {},
    ...extra,
  });
  return { out, sent, written };
}
const count = (r: Run, step: string) => r.sent.filter((s) => s.step === step).length;

const kv = (k: string, v: string): Segment[] => [
  { m: k, c: "Cyan", n: true },
  { m: v, c: "Green", n: true },
  { m: "", c: "", n: false },
];
const E = SAFE_TWO[0];
const runSegs = (e: AllowEntry, exit = "Exit code: 0"): Segment[] => [...kv("Executing test: ", testId(e)), { m: "out", c: "", n: false }, { m: exit, c: "", n: false }, ...kv("Done executing test: ", testId(e))];

// *--- Allowlist ---*

describe("allowlist", () => {
  test("the committed allowlist loads with the 17 ruled entries and no 100344", () => {
    expect(AL.tests.length).toBe(17);
    expect(AL.tests.flatMap((t) => t.rules)).not.toContain(100344);
    expect(AL.atomicsCommit).toBe(ATOMICS_COMMIT);
  });

  test("refuses a duplicate GUID", () => refusedWith(allowWith((o) => (o.tests[1].guid = o.tests[0].guid)), "already in the allowlist"));
  test("refuses a GUID of the wrong shape", () => refusedWith(allowWith((o) => (o.tests[0].guid = "D6042746-07D4-4C92-9AD8-E644C114A231")), "lower-case GUID"));
  test("refuses a GUID carrying PowerShell", () => refusedWith(allowWith((o) => (o.tests[0].guid = "d6042746-07d4-4c92-9ad8-e644c114a231'; Remove-Item x")), "lower-case GUID"));
  test("refuses a technique of the wrong shape", () => refusedWith(allowWith((o) => (o.tests[0].technique = "T1037.1")), "technique"));
  test("refuses a rule ID outside the pack ranges", () => refusedWith(allowWith((o) => (o.tests[0].rules = [92900])), "pack ranges"));
  test("refuses a rule ID that is not a whole number", () => refusedWith(allowWith((o) => (o.tests[0].rules = ["100400"])), "pack ranges"));
  test("refuses a wrong commit", () => refusedWith(allowWith((o) => (o.atomicsCommit = "b".repeat(40))), "pinned"));
  test("refuses a wrong module version", () => refusedWith(allowWith((o) => (o.module.version = "2.2.0")), "module must be"));
  test("refuses an extra key, such as inputArgs", () => refusedWith(allowWith((o) => (o.tests[0].inputArgs = { a: "b" })), "exactly the keys"));
  test("refuses a test named twice", () => refusedWith(allowWith((o) => (o.tests[1].technique = o.tests[0].technique) && (o.tests[1].testNumber = o.tests[0].testNumber)), "a second time"));
  test("refuses fetched code with nothing fetched", () => refusedWith(allowWith((o) => (o.tests[0].runsFetchedCode = true)), "fetches"));
  test("refuses a non-https fetch", () => refusedWith(allowWith((o) => (o.tests[0].fetches = ["http://example.com/x"])), "https"));
  test("refuses an unknown executor", () => refusedWith(allowWith((o) => (o.tests[0].executor = "sh")), "executor"));
  test("refuses text that is not JSON", () => refusedWith("{", "not JSON"));
});

describe("selectTests (ISC-152)", () => {
  test("a GUID outside the allowlist is refused", () => {
    expect(() => selectTests(AL, ["00000000-0000-4000-8000-000000000000"], false)).toThrow("not in atomics/allowlist.json");
  });
  test("a GUID of the wrong shape is refused before lookup", () => {
    expect(() => selectTests(AL, ["$(calc)"], false)).toThrow("not a lower-case GUID");
  });
  test("a test that runs fetched code needs the flag", () => {
    const g = AL.tests.find((t) => t.runsFetchedCode)!.guid;
    expect(() => selectTests(AL, [g], false)).toThrow("--allow-remote-code");
    expect(selectTests(AL, [g], true).map((t) => t.guid)).toEqual([g]);
  });
  test("--all leaves out fetched-code tests unless allowed", () => {
    expect(selectTests(AL, "all", false).length).toBe(15);
    expect(selectTests(AL, "all", true).length).toBe(17);
  });
  test("a GUID named twice is refused", () => expect(() => selectTests(AL, [E.guid, E.guid], false)).toThrow("named twice"));
});

describe("checkAllowlist against a checkout", () => {
  const checkout = temp("checkout");
  const write = (e: AllowEntry, override: Record<string, unknown> = {}) => {
    const tests = Array.from({ length: e.testNumber }, (_, i) => ({ name: `filler ${i}`, auto_generated_guid: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, supported_platforms: ["windows"], executor: { name: "command_prompt" } }));
    tests[e.testNumber - 1] = {
      name: e.testName,
      auto_generated_guid: e.guid,
      supported_platforms: ["windows"],
      executor: { name: e.executor, ...(e.elevationRequired ? { elevation_required: true } : {}) },
      ...(e.inputArguments.length ? { input_arguments: Object.fromEntries(e.inputArguments.map((a) => [a, { type: "string", default: "x" }])) } : {}),
      ...override,
    } as any;
    mkdirSync(join(checkout, "atomics", e.technique), { recursive: true });
    writeFileSync(join(checkout, "atomics", e.technique, `${e.technique}.yaml`), JSON.stringify({ attack_technique: e.technique, atomic_tests: tests }));
  };
  const one: Allowlist = { ...AL, tests: [AL.tests[0]] };

  test("a matching entry passes", () => {
    write(AL.tests[0]);
    expect(checkAllowlist(one, checkout, OK_GIT)).toEqual([]);
  });
  test("a changed name, executor or elevation is reported", () => {
    write(AL.tests[0], { name: "Other", executor: { name: "powershell", elevation_required: true } });
    const bad = checkAllowlist(one, checkout, OK_GIT).join("\n");
    expect(bad).toContain("name differs");
    expect(bad).toContain("executor differs");
    expect(bad).toContain("elevationRequired differs");
  });
  test("a checkout at another commit, or dirty, is reported", () => {
    write(AL.tests[0]);
    const bad = checkAllowlist(one, checkout, () => ({ head: "c".repeat(40), dirty: true })).join("\n");
    expect(bad).toContain("not at the recorded commit");
    expect(bad).toContain("uncommitted changes");
  });
  test("a GUID at another test number is reported", () => {
    const moved = { ...AL.tests[0], testNumber: 2 };
    write(AL.tests[0]);
    expect(checkAllowlist({ ...AL, tests: [moved] }, checkout, OK_GIT).join("\n")).toContain("no test 2");
  });
  test("an input the entry does not list, or a url default not in fetches, is reported", () => {
    write(AL.tests[0], { input_arguments: { script_path: { type: "string", default: "x" }, url: { type: "url", default: "https://example.com/x" } } });
    const bad = checkAllowlist(one, checkout, OK_GIT).join("\n");
    expect(bad).toContain("inputArguments differ");
    expect(bad).toContain("not in fetches");
  });
  test.skipIf(!existsSync(join(ARTS, "atomics")))("every entry matches the pinned checkout on this Mac", () => {
    expect(checkAllowlist(AL, ARTS)).toEqual([]);
  });
});

// *--- Manifest ---*

describe("manifest (ISC-155)", () => {
  test("holds the modules, each technique's YAML and only referenced files, packaging left out", () => {
    const paths = FIX.m.files.map((f) => f.path);
    expect(paths).toContain(`${MODULE_NAME}/${MODULE_NAME}.psd1`);
    expect(paths).toContain(`${YAML_MODULE}/${YAML_MODULE}.psd1`);
    expect(paths.some((p) => /_rels|package\/|Content_Types|\.nuspec/.test(p))).toBe(false);
    const techniques = [...new Set(AL.tests.map((t) => t.technique))];
    expect(paths.filter((p) => p.startsWith("atomics/")).sort()).toEqual([...techniques.map((t) => `atomics/${t}/${t}.yaml`), REFERENCED].sort());
    expect(FIX.m.tests[0].files).toEqual([REFERENCED]);
    expect(FIX.m.tests.slice(1).every((t) => t.files.length === 0)).toBe(true);
    expect(FIX.m.owed).toEqual([]);
  });
  test("an unreferenced file in a technique folder is not staged", () => {
    expect(existsSync(join(FIX.checkout, "atomics", AL.tests[0].technique, "bin", "unused.zip"))).toBe(true);
    expect(FIX.m.files.some((f) => f.path.endsWith("unused.zip"))).toBe(false);
  });
  test("refuses a powershell-yaml of another version", () => {
    const t = fixtureTree();
    writeFileSync(join(t.yaml, `${YAML_MODULE}.psd1`), "@{\n  ModuleVersion = '0.4.7'\n}\n");
    expect(() => buildManifest(AL, ALLOW_TEXT, t.modules, t.checkout, OK_GIT)).toThrow(YAML_VERSION);
    const m = JSON.parse(FIX.text) as Manifest;
    m.modules[1].version = "0.4.7";
    expect(() => parseManifest(manifestText(m), AL, ALLOW_TEXT)).toThrow(YAML_VERSION);
  });
  test("refuses an atomics file no allowlisted test references", () => {
    const m = JSON.parse(FIX.text) as Manifest;
    const extra = { path: `atomics/${AL.tests[0].technique}/bin/unused.zip`, size: 1, sha256: "a".repeat(64) };
    const files = [...m.files, extra].sort((a, b) => (a.path < b.path ? -1 : 1));
    expect(() => parseManifest(manifestText({ ...m, files }), AL, ALLOW_TEXT)).toThrow("no allowlisted test references it");
  });
  test("refuses a test list that names a file the files list lacks, or a wrong test", () => {
    const m = JSON.parse(FIX.text) as Manifest;
    const tests = m.tests.map((t, i) => (i === 1 ? { ...t, files: [`atomics/${t.technique}/bin/unused.zip`] } : t));
    expect(() => parseManifest(manifestText({ ...m, tests }), AL, ALLOW_TEXT)).toThrow("lacks");
    const swapped = [m.tests[1], m.tests[0], ...m.tests.slice(2)];
    expect(() => parseManifest(manifestText({ ...m, tests: swapped }), AL, ALLOW_TEXT)).toThrow("not the allowlist's test");
  });
  test("owes powershell-yaml when only the module is given", () => {
    const t = fixtureTree(false);
    expect(t.m.owed).toEqual([YAML_MODULE]);
    expect(t.m.modules.length).toBe(1);
  });
  test("round-trips through parseManifest", () => {
    expect(manifestText(parseManifest(FIX.text, AL, ALLOW_TEXT))).toBe(FIX.text);
  });
  test("refuses a manifest built from another allowlist", () => {
    expect(() => parseManifest(FIX.text, AL, `${ALLOW_TEXT} `)).toThrow("another allowlist");
  });
  test("refuses files out of order, outside the roots, or under another technique", () => {
    const m = JSON.parse(FIX.text) as Manifest;
    const swap = { ...m, files: [m.files[1], m.files[0], ...m.files.slice(2)] };
    expect(() => parseManifest(manifestText(swap), AL, ALLOW_TEXT)).toThrow("out of order");
    const stray = { ...m, files: [...m.files, { path: "zz/x.ps1", size: 1, sha256: "a".repeat(64) }] };
    expect(() => parseManifest(manifestText(stray), AL, ALLOW_TEXT)).toThrow("outside every staged root");
    const other = { ...m, files: [{ path: "atomics/T9999/T9999.yaml", size: 1, sha256: "a".repeat(64) }, ...m.files].sort((a, b) => (a.path < b.path ? -1 : 1)) };
    expect(() => parseManifest(manifestText(other), AL, ALLOW_TEXT)).toThrow("no allowlisted test references it");
  });
  test("refuses an owed list that disagrees with the modules", () => {
    const m = JSON.parse(FIX.text) as Manifest;
    expect(() => parseManifest(manifestText({ ...m, owed: [YAML_MODULE] }), AL, ALLOW_TEXT)).toThrow("owed");
  });
  test("refuses a symlink in a source folder", () => {
    const t = fixtureTree();
    symlinkSync("/etc/hosts", join(t.mod, "Public", "link.ps1"));
    expect(() => buildManifest(AL, ALLOW_TEXT, t.modules, t.checkout, OK_GIT)).toThrow("symlink");
  });
  test("refuses a checkout at another commit or dirty", () => {
    expect(() => buildManifest(AL, ALLOW_TEXT, FIX.modules, FIX.checkout, () => ({ head: "c".repeat(40), dirty: false }))).toThrow("recorded commit");
    expect(() => buildManifest(AL, ALLOW_TEXT, FIX.modules, FIX.checkout, () => ({ head: ATOMICS_COMMIT, dirty: true }))).toThrow("uncommitted");
  });
  test("the committed manifest matches the committed allowlist", () => {
    const text = readFileSync(resolve(ROOT, MANIFEST_PATH), "utf8");
    const m = parseManifest(text, AL, ALLOW_TEXT);
    expect(m.owed).toEqual([]);
    expect(m.modules.map((x) => `${x.name} ${x.version}`)).toEqual([`${MODULE_NAME} ${MODULE_VERSION}`, `${YAML_MODULE} ${YAML_VERSION}`]);
    expect(m.files.some((f) => /uacme|GUP\.exe|AllTheThings|\.md$/.test(f.path) && f.path.startsWith("atomics/"))).toBe(false);
  });
});

// *--- Referenced Files ---*

describe("files a test references (ISC-155)", () => {
  const e = AL.tests[0];
  const tree = () => {
    const dir = temp("refs");
    fixtureCheckout(dir, AL);
    mkdirSync(join(dir, "atomics", e.technique, "src"), { recursive: true });
    writeFileSync(join(dir, "atomics", e.technique, "src", "a.bat"), "x");
    return dir;
  };
  const refs = (dir: string) => deriveTests({ ...AL, tests: [e] }, dir)[0];

  test("a reference in the command, the cleanup, a prerequisite or an input default is found", () => {
    const dir = tree();
    for (const extra of [
      { executor: { name: e.executor, command: "echo x", cleanup_command: `del "PathToAtomicsFolder\\${e.technique}\\src\\a.bat"` } },
      { dependencies: [{ prereq_command: `if (Test-Path $PathToAtomicsFolder/${e.technique}/src/a.bat) {exit 0}`, get_prereq_command: "exit 1" }] },
      { input_arguments: { f: { type: "path", default: `$pathtoatomicsfolder\\${e.technique}\\src\\a.bat` } } },
    ]) {
      setCommand(dir, e, "echo x", extra);
      expect(refs(dir).files).toEqual([`atomics/${e.technique}/src/a.bat`]);
      setCommand(dir, e, "echo x", { dependencies: [], input_arguments: {} });
    }
  });
  test("a reference leaving the atomics folder is recorded, not staged", () => {
    const dir = tree();
    setCommand(dir, e, "Invoke-WebRequest x -OutFile PathToAtomicsFolder\\..\\ExternalPayloads\\curl.zip");
    expect(refs(dir)).toMatchObject({ files: [], outside: ["../ExternalPayloads/curl.zip"] });
  });
  test("a referenced file missing from the checkout fails the build", () => {
    const dir = tree();
    setCommand(dir, e, `copy $PathToAtomicsFolder\\${e.technique}\\src\\gone.bat .`);
    expect(() => refs(dir)).toThrow("missing from the checkout");
  });
  test("a wildcard, a variable, a folder or the bare folder fails closed", () => {
    const dir = tree();
    for (const [cmd, why] of [
      [`copy $PathToAtomicsFolder\\${e.technique}\\src\\*.bat .`, "wildcard"],
      [`copy $PathToAtomicsFolder\\${e.technique}\\$name .`, "variable"],
      [`copy $PathToAtomicsFolder\\${e.technique}\\src\\ .`, "names a folder"],
      ["dir $PathToAtomicsFolder", "whole atomics folder"],
    ]) {
      setCommand(dir, e, cmd);
      expect(() => refs(dir)).toThrow(why);
    }
  });
  test("an input the test does not define fails closed", () => {
    const dir = tree();
    setCommand(dir, e, "type #{missing}");
    expect(() => refs(dir)).toThrow("does not define");
  });
  test("testReferences refuses a reference that is a link", () => {
    const dir = tree();
    symlinkSync("/etc/hosts", join(dir, "atomics", e.technique, "src", "l.bat"));
    expect(() => testReferences({ executor: { command: `type $PathToAtomicsFolder\\${e.technique}\\src\\l.bat` } }, dir, "t")).toThrow("not a plain file");
  });
  test.skipIf(!existsSync(join(ARTS, "atomics")))("the pinned checkout gives exactly the four referenced files", () => {
    const files = deriveTests(AL, ARTS).flatMap((t) => t.files);
    expect(files.sort()).toEqual([
      "atomics/T1105/src/T1105-download-file.vbs",
      "atomics/T1546.011/bin/T1546.011CompatDatabase.sdb",
      "atomics/T1547.001/src/batstartup.bat",
      "atomics/T1547.010/bin/PortMonitor.dll",
    ]);
  });
  test("the tree digest is order-free, and one changed byte changes it", () => {
    const files = FIX.m.files;
    expect(treeDigest([...files].reverse())).toBe(treeDigest(files));
    const lines = files.map((f) => `${f.path}\t${f.size}\t${f.sha256}\n`).sort();
    expect(treeDigest(files)).toBe(sha(lines.join("")));
    const one = files.map((f, i) => (i === 0 ? { ...f, sha256: sha("other") } : f));
    expect(treeDigest(one)).not.toBe(treeDigest(files));
  });
  test("compareListing names changed and missing files and counts extra and odd entries", () => {
    const files = FIX.m.files;
    const listing = { missingRoot: false, odd: 1, files: [{ ...files[0], sha256: sha("x") }, ...files.slice(2), { path: "privateConfig.ps1", size: 1, sha256: sha("y") }] };
    const c = compareListing(FIX.m, listing);
    expect(c.changed).toEqual([files[0].path]);
    expect(c.missing).toEqual([files[1].path]);
    expect(c.extra).toBe(1);
    expect(c.odd).toBe(1);
  });
  test("stageFiles copies exactly the manifest's files and refuses a source that changed", () => {
    const out = join(temp("stage"), "out");
    expect(stageFiles(FIX.m, FIX.modules, FIX.checkout, out)).toBe(FIX.m.files.length);
    const t = fixtureTree();
    writeFileSync(join(t.mod, "Public", "Invoke-AtomicTest.ps1"), "function Invoke-AtomicTest { 'changed' }\n");
    expect(() => stageFiles(t.m, t.modules, t.checkout, join(temp("stage2"), "out"))).toThrow("differs from the manifest");
    expect(() => stageFiles(FIX.m, FIX.modules, FIX.checkout, out)).toThrow("must not exist");
  });
});

// *--- Dell Scripts ---*

describe("Dell scripts", () => {
  const run = stepScript("run", E, AL, DIGEST, DESC, 120);
  test("the step script carries the whole allowed set and refuses outside it on the Dell (ISC-152)", () => {
    const set = /\$Allowed = @\{ (.*) \}/.exec(run)?.[1] ?? "";
    const pairs = set.split("; ").map((p) => /^'([0-9a-f-]+)' = '(T[\d.]+)'$/.exec(p)?.slice(1, 3));
    expect(pairs).toEqual(AL.tests.map((t) => [t.guid, t.technique]));
    expect(run).toContain("$Allowed.ContainsKey($Guid)");
    expect(run).toContain("$refused = 'not-allowlisted'");
    expect(run).toContain(`$Guid = '${E.guid}'`);
  });
  test("the step script checks the tree digest, Defender and the restore point before the module loads", () => {
    const order = ["staged-files-changed", "defender-gate", "restore-point-missing", "Import-Module", "Invoke-AtomicTest"].map((s) => run.indexOf(s));
    expect(order.every((x) => x > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(run).toContain(`$Expect = '${DIGEST}'`);
    expect(run).toContain(`$Desc = '${DESC}'`);
  });
  test("the module is called only in the three allowed shapes", () => {
    for (const mode of ["run", "cleanup", "prereqs"] as const) {
      const s = stepScript(mode, E, AL, DIGEST, mode === "prereqs" ? "" : DESC, 120);
      expect(s).not.toMatch(/-GetPrereqs|-InputArgs|-PromptForInputArgs|-ExecutionLogPath|-Session\b/);
      for (const line of s.split("\n").filter((l) => l.includes("Invoke-AtomicTest $Technique"))) {
        expect(line).toContain("-NoExecutionLog -Confirm:$false");
        expect(line).toContain("-PathToAtomicsFolder $atomics");
      }
    }
  });
  test("refuses a GUID outside the allowlist, a bad digest, description or timeout", () => {
    expect(() => stepScript("run", { ...E, guid: "00000000-0000-4000-8000-000000000000" }, AL, DIGEST, DESC, 120)).toThrow("not in the allowlist");
    expect(() => stepScript("run", E, AL, "zz", DESC, 120)).toThrow("digest");
    expect(() => stepScript("run", E, AL, DIGEST, "x'; calc; '", 120)).toThrow("description");
    expect(() => stepScript("prereqs", E, AL, DIGEST, DESC, 120)).toThrow("description");
    expect(() => stepScript("run", E, AL, DIGEST, DESC, 5)).toThrow("timeout");
    expect(() => restoreScript("x'; calc; '")).toThrow("description");
  });
  test("no template holds a backtick, a ${ or an unfilled placeholder", () => {
    for (const s of [gateScript(), snapshotScript(), restoreScript(DESC), run]) {
      expect(s).not.toContain("`");
      expect(s).not.toContain("${");
      expect(s).not.toMatch(/@@[A-Z]+@@/);
    }
    expect(() => fill("@@A@@ @@B@@", { A: "x" })).toThrow("unfilled");
  });
  test("the Defender gate drops null entries rather than counting them", () => {
    expect(gateScript()).toContain("if ($null -ne $x -and ([string]$x) -ne '')");
  });
  test("each step removes exactly the module's two capture files in TEMP, and nothing broader", () => {
    for (const mode of ["run", "cleanup", "prereqs"] as const) {
      const s = stepScript(mode, E, AL, DIGEST, mode === "prereqs" ? "" : DESC, 120);
      expect(s).toContain("foreach ($cap in 'art-out.txt', 'art-err.txt') {");
      expect(s).toContain("$capPath = Join-Path $env:TEMP $cap");
      const removals = s.split("\n").filter((l) => /Remove-Item/i.test(l));
      expect(removals).toEqual(["    try { if (Test-Path -LiteralPath $capPath -PathType Leaf) { Remove-Item -LiteralPath $capPath -Force } } catch { }"]);
      expect(s).not.toMatch(/Remove-Item[^\n]*(\*|-Recurse|-Path\b)/i);
      // The removal follows the module call, so it runs after the step's output exists.
      expect(s.indexOf("art-out.txt")).toBeGreaterThan(s.lastIndexOf("Invoke-AtomicTest $Technique"));
    }
    for (const s of [gateScript(), snapshotScript(), restoreScript(DESC)]) expect(s).not.toMatch(/Remove-Item/i);
  });
  test("the snapshot reads all eight categories", () => {
    for (const c of CATEGORIES) expect(snapshotScript()).toContain(`Add-Category '${c}'`);
  });
  test("the bootstrap fits the Windows command line and pins the payload hash", () => {
    const cmd = remoteCommand(run);
    expect(cmd.length).toBeLessThan(CMDLINE_MAX);
    const decoded = Buffer.from(cmd.split(" ").pop()!, "base64").toString("utf16le");
    expect(decoded).toContain(sha(run));
    expect(decoded).toContain("exit 97");
    expect(() => bootstrap("nope")).toThrow("hash");
  });
  test("the bootstrap reads one line from the raw stream with a time limit and never waits for end of input", () => {
    const b = bootstrap(sha(run));
    expect(b).not.toMatch(/ReadToEnd|\[Console\]::In\b|\$input/);
    expect(b).toContain("$r=New-Object IO.StreamReader([Console]::OpenStandardInput())");
    expect(b).toContain("$t=$r.ReadLineAsync()");
    expect(b).toContain(`if(-not $t.Wait(${STDIN_WAIT_MS})){[Environment]::Exit(${PAYLOAD_MISSING})}`);
    expect(b).toContain(`if($null -eq $b -or $b.Trim() -eq ''){[Environment]::Exit(${PAYLOAD_MISSING})}`);
    // The self-exit comes before the payload is decoded, hashed or run.
    expect(b.indexOf("Exit(96)")).toBeLessThan(b.indexOf("FromBase64String"));
    expect(b.indexOf(`'${sha(run)}'`)).toBeLessThan(b.indexOf("ScriptBlock]::Create"));
    expect(remoteCommand(run).length).toBeLessThan(2000);
  });
  test("an ssh host alias outside the pattern is refused", () => {
    expect(() => sshRemote("-oProxyCommand=calc")).toThrow("alias");
  });
});

// *--- Answers ---*

describe("answers", () => {
  test("decodeAnswer takes only the tagged last line, for the step asked", () => {
    expect(decodeAnswer(`junk\n${answer({ step: "gate" }).out}`, "gate").step).toBe("gate");
    expect(() => decodeAnswer("hello", "gate")).toThrow("expected form");
    expect(() => decodeAnswer(`${TAG}!!!`, "gate")).toThrow("expected form");
    expect(() => decodeAnswer(answer({ step: "run" }).out, "gate")).toThrow("another step");
    expect(() => decodeAnswer(`${TAG}${Buffer.from("{").toString("base64")}`, "gate")).toThrow("UTF-8 JSON");
  });

  test("defenderVerdict passes exactly one C:\\AtomicRedTeam and nothing else (ISC-150)", () => {
    const ok = { rtp: true, path: [STAGED_ROOT], process: [], extension: [], ip: [] };
    expect(defenderVerdict(ok)).toBeNull();
    expect(defenderVerdict({ ...ok, path: ["c:\\atomicredteam"] })).toBeNull();
    expect(defenderVerdict({ ...ok, rtp: false })).toContain("real-time protection is off");
    expect(defenderVerdict({ ...ok, path: [] })).toContain("0 entries");
    expect(defenderVerdict({ ...ok, path: [STAGED_ROOT, "C:\\Temp"] })).toContain("2 entries");
    expect(defenderVerdict({ ...ok, path: ["C:\\AtomicRedTeam\\"] })).toContain("another path");
    expect(defenderVerdict({ ...ok, process: ["x.exe"] })).toContain("ExclusionProcess");
    expect(defenderVerdict({ ...ok, extension: ["ps1"] })).toContain("ExclusionExtension");
  });

  test("restoreVerdict confirms one new point, and says why when there is none (ISC-157)", () => {
    expect(restoreVerdict({ existedBefore: 0, count: 1, createdUtc: "2026-11-22T03:00:00.0000000Z", error: false, frequency: 0 }, DESC)).toEqual({ createdUtc: "2026-11-22T03:00:00.0000000Z" });
    const skipped = restoreVerdict({ existedBefore: 0, count: 0, createdUtc: null, error: false, frequency: null }, DESC) as { why: string };
    expect(skipped.why).toContain("SystemRestorePointCreationFrequency is 0 (it is unset)");
    expect(skipped.why).toContain("no test was sent");
    expect((restoreVerdict({ existedBefore: 1, count: 1, createdUtc: "2026-11-22T03:00:00Z", error: false, frequency: 0 }, DESC) as { why: string }).why).toContain("already existed");
    expect((restoreVerdict({ existedBefore: 0, count: 0, createdUtc: null, error: true, frequency: 0 }, DESC) as { why: string }).why).toContain("Checkpoint-Computer failed");
  });

  test("readRun needs the module's own key segments and takes the exit code before Done", () => {
    expect(readRun(runSegs(E), E)).toEqual({ status: "exited", exitCode: 0 });
    expect(readRun(runSegs(E, "Exit code: 5"), E)).toEqual({ status: "exited", exitCode: 5 });
    // A test's stdout printing the marker text is one segment with a line end, so it never counts.
    const forged: Segment[] = [{ m: "Executing test: ", c: "", n: false }, { m: "Exit code: 0", c: "", n: false }];
    expect(readRun(forged, E).status).toBe("did-not-run-once");
    expect(readRun(runSegs(SAFE_TWO[1]), E).status).toBe("did-not-run-once");
    expect(readRun([...runSegs(E), ...runSegs(E)], E).status).toBe("did-not-run-once");
    const timed = [...kv("Executing test: ", testId(E)), { m: "Process Timed out after 120 seconds, use '-TimeoutSeconds'", c: "Red", n: false }, { m: "Exit code: -1", c: "", n: false }, ...kv("Done executing test: ", testId(E))];
    expect(readRun(timed, E).status).toBe("timed-out");
    expect(readRun([...kv("Executing test: ", testId(E)), ...kv("Done executing test: ", testId(E))], E).status).toBe("no-exit-code");
  });

  test("readCleanup and readPrereqs read their own markers", () => {
    expect(readCleanup([...kv("Executing cleanup for test: ", testId(E)), ...kv("Done executing cleanup for test: ", testId(E))], E).status).toBe("completed");
    expect(readCleanup(kv("Executing cleanup for test: ", testId(E)), E).status).toBe("did-not-run-once");
    expect(readPrereqs([...kv("CheckPrereq's for: ", testId(E)), ...kv("Prerequisites met: ", testId(E))], E)).toBe("met");
    expect(readPrereqs([...kv("CheckPrereq's for: ", testId(E)), { m: `Prerequisites not met: ${testId(E)}`, c: "Red", n: false }], E)).toBe("not-met");
    expect(readPrereqs(kv("CheckPrereq's for: ", testId(E)), E)).toBe("unknown");
  });

  test("readCleanup reads a module timeout as timed-out, and the session fails on it", () => {
    const timed = [...kv("Executing cleanup for test: ", testId(E)), { m: "Process Timed out after 120 seconds", c: "Red", n: false }, ...kv("Done executing cleanup for test: ", testId(E))];
    expect(readCleanup(timed, E).status).toBe("timed-out");
    const r = session(cleanDell(FIX.m), {}, (step) => (step === "cleanup" ? answer({ step, refused: null, start: "2026-11-22T03:00:00Z", end: "2026-11-22T03:02:00Z", threw: false, segments: timed }) : undefined));
    expect(r.out.exit).toBe(EXIT.failed);
    expect(r.out.record?.tests[0].cleanup.status).toBe("timed-out");
    expect(count(r, "run")).toBe(1);
  });

  test("parseStep refuses an unknown refusal code or a bad time", () => {
    expect(() => parseStep({ step: "run", refused: "whatever", threw: false, segments: [] }, "run")).toThrow("refused");
    expect(() => parseStep({ step: "run", refused: null, start: "yesterday", end: "x", threw: false, segments: [] }, "run")).toThrow("start");
  });
});

// *--- State Diff ---*

describe("state diff (ISC-153)", () => {
  const snap = (entries: Partial<Record<(typeof CATEGORIES)[number], [string, string][]>>): Snapshot =>
    Object.fromEntries(CATEGORIES.map((c) => [c, new Map(entries[c] ?? [])])) as Snapshot;
  test("identical snapshots differ in nothing", () => {
    expect(diffSnapshots(snap({ services: [["a", "1"]] }), snap({ services: [["a", "1"]] }))).toEqual([]);
  });
  for (const c of CATEGORIES) {
    test(`reports added, removed and changed items in ${c}`, () => {
      const d = diffSnapshots(snap({ [c]: [["gone", "1"], ["same", "1"], ["edited", "1"]] }), snap({ [c]: [["same", "1"], ["edited", "2"], ["new", "1"]] }));
      expect(d).toEqual([
        { category: c, change: "changed", item: "edited" },
        { category: c, change: "removed", item: "gone" },
        { category: c, change: "added", item: "new" },
      ]);
    });
  }
  test("a category the Dell could not read, a missing category or a repeated item stops the comparison", () => {
    const cats = Object.fromEntries(CATEGORIES.map((c) => [c, []]));
    expect(() => parseSnapshot({ step: "snapshot", categories: cats, failed: ["tasks"] })).toThrow("could not read tasks");
    const { tasks, ...short } = cats;
    expect(() => parseSnapshot({ step: "snapshot", categories: short, failed: [] })).toThrow("exactly the keys");
    expect(() => parseSnapshot({ step: "snapshot", categories: { ...cats, users: [{ k: "a", d: "1" }, { k: "a", d: "2" }] }, failed: [] })).toThrow("twice");
  });
});

// *--- Sessions ---*

describe("sessions", () => {
  test("a clean session sends gate, restore point, snapshot, run and cleanup per test, snapshot, gate", () => {
    const r = session();
    expect(r.out.exit).toBe(EXIT.ok);
    expect(r.sent.map((s) => s.step)).toEqual(["gate", "restore-point", "snapshot", "run", "cleanup", "run", "cleanup", "snapshot", "gate"]);
    expect(r.written.length).toBe(1);
  });

  test("the record holds hashes, commit, version, restore point, gate and a window per GUID (ISC-156)", () => {
    const rec = JSON.parse(session().written[0]);
    expect(rec.allowlistSha256).toBe(sha(ALLOW_TEXT));
    expect(rec.manifestSha256).toBe(sha(FIX.text));
    expect(rec.atomicsCommit).toBe(ATOMICS_COMMIT);
    expect(rec.module).toEqual({ name: MODULE_NAME, version: MODULE_VERSION });
    expect(rec.restorePoint.description).toBe(DESC);
    expect(rec.restorePoint.createdUtc).toMatch(/Z$/);
    expect(rec.defenderGate).toEqual({ realTimeProtection: true, exclusionPath: [STAGED_ROOT], pass: true });
    expect(rec.stateDiff).toEqual({ verdict: "no-difference", items: [] });
    for (const t of rec.tests) {
      expect(t.run.startUtc).toMatch(/Z$/);
      expect(t.run.endUtc).toMatch(/Z$/);
      expect(t.cleanup.startUtc).toMatch(/Z$/);
      expect(t.run.exitCode).toBe(0);
    }
    expect(rec.tests.map((t: { guid: string }) => t.guid)).toEqual(SAFE_TWO.map((t) => t.guid));
  });

  test("a GUID outside the allowlist is refused with nothing sent (ISC-152)", () => {
    const r = session(cleanDell(FIX.m), { guids: ["00000000-0000-4000-8000-000000000000"] });
    expect(r.out.exit).toBe(EXIT.refused);
    expect(r.sent.length).toBe(0);
  });

  test("a manifest that still owes powershell-yaml is refused with nothing sent", () => {
    const t = fixtureTree(false);
    const r = session(cleanDell(t.m), { manifestText: t.text });
    expect(r.out.exit).toBe(EXIT.refused);
    expect(r.out.messages.join()).toContain("owes powershell-yaml");
    expect(r.sent.length).toBe(0);
  });

  test("a changed, missing or extra staged file, a link or no root sends no test (ISC-155)", () => {
    const variants: ((d: ReturnType<typeof cleanDell>) => void)[] = [
      (d) => (d.listing.files[0] = { ...d.listing.files[0], sha256: sha("one byte") }),
      (d) => (d.listing.files[0] = { ...d.listing.files[0], size: d.listing.files[0].size + 1 }),
      (d) => d.listing.files.splice(3, 1),
      (d) => d.listing.files.push({ path: "privateConfig.ps1", size: 10, sha256: sha("x") }),
      (d) => (d.listing.odd = 1),
      (d) => (d.listing = { missingRoot: true, files: [], odd: 0 }),
    ];
    for (const v of variants) {
      const d = cleanDell(FIX.m);
      v(d);
      const r = session(d);
      expect(r.out.exit).toBe(EXIT.setup);
      expect(count(r, "run")).toBe(0);
      expect(count(r, "restore-point")).toBe(0);
    }
  });

  test("an extra file is counted, never named, since its name came from the Dell", () => {
    const d = cleanDell(FIX.m);
    d.listing.files.push({ path: "labhost-secret.ps1", size: 1, sha256: sha("x") });
    const r = session(d);
    expect(r.out.messages.join()).toContain("1 extra file");
    expect(r.out.messages.join()).not.toContain("labhost");
  });

  test("a Defender gate failure sends no test, null entries counting as none (ISC-150)", () => {
    for (const path of [[STAGED_ROOT, "C:\\Temp"], [null], [], ["C:\\Users"]]) {
      const d = cleanDell(FIX.m);
      d.defender.path = path as string[];
      const r = session(d);
      expect(r.out.exit).toBe(EXIT.setup);
      expect(count(r, "restore-point")).toBe(0);
      expect(count(r, "run")).toBe(0);
    }
    const off = cleanDell(FIX.m);
    off.defender.rtp = false;
    expect(session(off).out.exit).toBe(EXIT.setup);
  });

  test("a refused restore point sends no test and says why (ISC-157)", () => {
    const d = cleanDell(FIX.m);
    d.restore = { existedBefore: 0, count: 0, error: false, frequency: 1440 };
    const r = session(d);
    expect(r.out.exit).toBe(EXIT.setup);
    expect(count(r, "run")).toBe(0);
    expect(count(r, "snapshot")).toBe(0);
    expect(r.out.messages.join()).toContain("(it is 1440)");
  });

  test("a snapshot difference fails the session, after every cleanup ran, with names redacted (ISC-153, ISC-156)", () => {
    const d = cleanDell(FIX.m);
    d.after.tasks = [...d.after.tasks, ["\\Sync-labuser-S-1-5-21-1111111111-2222222222-3333333333-1001", "x"]];
    d.after.services = [...d.after.services, [`LABHOST-agent-${v4(10, 20, 30, 40)}`, "x"]];
    const r = session(d);
    expect(r.out.exit).toBe(EXIT.failed);
    expect(count(r, "cleanup")).toBe(2);
    const json = r.written[0];
    expect(JSON.parse(json).stateDiff.verdict).toBe("different");
    expect(json).toContain("<user>");
    expect(json).toContain("S-1-5-21-<machine>-1001");
    expect(json).toContain("<private-address>");
    expect(json).not.toMatch(/labhost|labuser|1111111111/i);
    expect(json).not.toContain(v4(10, 20, 30, 40));
  });

  test("cleanup runs when the test step times out, and the session goes on", () => {
    const timed = [...kv("Executing test: ", testId(E)), { m: "Process Timed out after 120 seconds", c: "Red", n: false }, { m: "Exit code: -1", c: "", n: false }, ...kv("Done executing test: ", testId(E))];
    let first = true;
    const logged: string[] = [];
    const r = session(cleanDell(FIX.m), { log: (l) => logged.push(l) }, (step) => {
      if (step !== "run" || !first) return undefined;
      first = false;
      return answer({ step, refused: null, start: "2026-11-22T03:00:00Z", end: "2026-11-22T03:02:00Z", threw: false, segments: timed });
    });
    expect(r.out.exit).toBe(EXIT.ok);
    expect(count(r, "cleanup")).toBe(2);
    expect(r.out.record?.tests[0].run.status).toBe("timed-out");
    // Listed and printed, not hidden: the verdict stays pass and exit stays 0.
    expect(r.out.record?.timedOut).toEqual([E.guid]);
    expect(r.out.record?.verdict).toBe("pass");
    expect(logged.filter((l) => l.startsWith("TIMEOUT "))).toEqual([`TIMEOUT ${E.technique} #${E.testNumber} ${E.guid}: the module killed the test after 120 s`]);
    expect(JSON.parse(r.written[0]).timedOut).toEqual([E.guid]);
  });

  test("a session with no timeout records an empty timedOut list and prints no TIMEOUT line", () => {
    const logged: string[] = [];
    const r = session(cleanDell(FIX.m), { log: (l) => logged.push(l) });
    expect(r.out.record?.timedOut).toEqual([]);
    expect(logged.some((l) => l.startsWith("TIMEOUT"))).toBe(false);
  });

  test("every local account but the built-ins is redacted, and users items are only a label", () => {
    const d = cleanDell(FIX.m);
    d.after.tasks = [...d.after.tasks, ["\\Sync-LabSecond-task", "x"]];
    d.after.users = [...d.after.users, ["labsecond-new", "Enabled=True"]];
    const r = session(d);
    expect(r.out.exit).toBe(EXIT.failed);
    const json = r.written[0];
    expect(json).not.toMatch(/labsecond/i);
    expect(json).toContain("\\\\Sync-<account>-task");
    const items = JSON.parse(json).stateDiff.items;
    expect(items.find((i: { category: string }) => i.category === "users").item).toBe("<local-account>");
  });

  test("a failure message or record still holding a second account name is redacted or refused", () => {
    const d = cleanDell(FIX.m);
    const gate = parseGate({ step: "gate", utc: "2026-11-22T03:00:00Z", elevated: true, ids: d.ids, defender: d.defender, listing: d.listing, frequency: 0 });
    expect(gate.ids.map((i) => i.literal)).toContain("labsecond");
    expect(redactName("the step for labsecond failed", gate.ids)).toBe("the step for <account> failed");
    expect(recordFindings(JSON.stringify({ failures: ["LabSecond left a task"] }), gate.ids)).toEqual(["the Dell's account name"]);
    // An account named like the record's own fixed text cannot be redacted out, so nothing is written.
    const fixed = cleanDell(FIX.m);
    fixed.ids = { ...fixed.ids, accounts: ["labuser", "AtomicRedTeam"] };
    const r = session(fixed);
    expect(r.out.exit).toBe(EXIT.failed);
    expect(r.written.length).toBe(0);
  });

  test("the gate script lists local accounts and leaves out the built-in RIDs", () => {
    expect(gateScript()).toContain("$builtin = @('500', '501', '503', '504')");
    expect(gateScript()).toContain("accounts = (Get-List $names)");
  });

  test("cleanup runs when the test step fails remotely; later tests are not sent", () => {
    let first = true;
    const r = session(cleanDell(FIX.m), {}, (step) => {
      if (step !== "run" || !first) return undefined;
      first = false;
      return { code: 1, out: "", err: "labhost: something", timedOut: false };
    });
    expect(r.out.exit).toBe(EXIT.failed);
    expect(count(r, "run")).toBe(1);
    expect(count(r, "cleanup")).toBe(1);
    expect(count(r, "snapshot")).toBe(2);
    expect(r.out.messages.join()).not.toContain("labhost");
    expect(r.out.record?.tests[1].run.status).toBe("not-sent");
  });

  test("a step the Dell refuses stops the session and its cleanup is still asked for", () => {
    const r = session(cleanDell(FIX.m), {}, (step) => (step === "run" ? answer({ step, refused: "staged-files-changed", start: null, end: null, threw: false, segments: [] }) : undefined));
    expect(r.out.exit).toBe(EXIT.failed);
    expect(count(r, "cleanup")).toBe(1);
    expect(r.out.messages.join()).toContain("no longer match");
  });

  test("a cleanup that did not complete fails the session", () => {
    const r = session(cleanDell(FIX.m), {}, (step) => (step === "cleanup" ? answer({ step, refused: null, start: "2026-11-22T03:00:00Z", end: "2026-11-22T03:00:01Z", threw: true, segments: [] }) : undefined));
    expect(r.out.exit).toBe(EXIT.failed);
    expect(r.out.record?.tests[0].cleanup.status).toBe("threw");
    expect(count(r, "run")).toBe(1);
  });

  test("remote failures before any test are setup failures that echo nothing remote", () => {
    const cases: RemoteResult[] = [
      { code: 255, out: "", err: "labhost: Permission denied", timedOut: false },
      { code: null, out: "", err: "", timedOut: true },
      { code: 97, out: "", err: "", timedOut: false },
      { code: 0, out: "labhost said hello", err: "", timedOut: false },
    ];
    for (const c of cases) {
      const r = session(cleanDell(FIX.m), {}, (step) => (step === "gate" ? c : undefined));
      expect(r.out.exit).toBe(EXIT.setup);
      expect(r.out.messages.join()).not.toContain("labhost");
      expect(count(r, "run")).toBe(0);
    }
  });

  // A well-formed gate answer from the clean fake, for the remote-result cases below.
  const goodGate = () => {
    const d = cleanDell(FIX.m);
    return answer({ step: "gate", utc: "2026-11-22T03:00:00Z", elevated: true, ids: d.ids, defender: d.defender, listing: d.listing, frequency: 0 });
  };

  test("a missing C:\\AtomicRedTeam is named as missing, not as a manifest difference", () => {
    const d = cleanDell(FIX.m);
    d.listing = { missingRoot: true, files: [], odd: 0 };
    const r = session(d);
    expect(r.out.exit).toBe(EXIT.setup);
    expect(r.out.messages.join()).toContain("does not exist on the Dell");
    expect(r.out.messages.join()).not.toContain("differ from");
  });

  test("null or empty exclusion entries beside C:\\AtomicRedTeam count as none, so the gate passes", () => {
    for (const path of [[null, STAGED_ROOT], ["", STAGED_ROOT]]) {
      const d = cleanDell(FIX.m);
      d.defender.path = path as string[];
      const r = session(d);
      expect(r.out.exit).toBe(EXIT.ok);
      expect(count(r, "run")).toBe(2);
    }
  });

  test("two restore points with the session's description are not confirmed", () => {
    const d = cleanDell(FIX.m);
    d.restore = { existedBefore: 0, count: 2, error: false, frequency: 0 };
    const r = session(d);
    expect(r.out.exit).toBe(EXIT.setup);
    expect(count(r, "run")).toBe(0);
    expect((restoreVerdict({ existedBefore: 0, count: 2, createdUtc: "2026-11-22T03:00:00Z", error: false, frequency: 0 }, DESC) as { why: string }).why).toContain("not confirmed");
  });

  test("an ssh timeout is reported as a timeout, even when an answer arrived", () => {
    const r = session(cleanDell(FIX.m), {}, (step) => (step === "gate" ? { ...goodGate(), timedOut: true } : undefined));
    expect(r.out.exit).toBe(EXIT.setup);
    expect(r.out.messages.join()).toContain("did not finish");
    expect(r.out.messages.join()).toContain("may still be running on the Dell");
    expect(count(r, "restore-point")).toBe(0);
  });

  const missing: RemoteResult = { code: PAYLOAD_MISSING, out: "", err: "", timedOut: false };

  test("a payload that did not arrive is sent once more, and the session goes on; each attempt is kept apart", () => {
    let misses = 0;
    const raw: string[] = [];
    const logged: string[] = [];
    const r = session(cleanDell(FIX.m), { raw: (n) => raw.push(n), log: (l) => logged.push(l) }, (step) => (step === "gate" && misses++ === 0 ? missing : undefined));
    expect(r.out.exit).toBe(EXIT.ok);
    expect(count(r, "gate")).toBe(3);
    expect(raw).toContain("01-gate.out");
    expect(raw).toContain("01-gate-attempt2.out");
    expect(raw).toContain("01-gate-attempt2.err");
    expect(logged.some((l) => l.startsWith("RETRY gate:"))).toBe(true);
  });

  test("a payload that misses twice before any test is a setup failure saying it did not arrive", () => {
    const r = session(cleanDell(FIX.m), {}, (step) => (step === "gate" ? missing : undefined));
    expect(r.out.exit).toBe(EXIT.setup);
    expect(count(r, "gate")).toBe(2);
    expect(count(r, "restore-point")).toBe(0);
    expect(r.out.messages.join()).toContain("the payload did not arrive on the Dell, twice; nothing ran");
  });

  test("a payload that misses twice after a test ran fails the session", () => {
    const r = session(cleanDell(FIX.m), {}, (step) => (step === "cleanup" ? missing : undefined));
    expect(r.out.exit).toBe(EXIT.failed);
    expect(count(r, "cleanup")).toBe(2);
    expect(count(r, "run")).toBe(1);
    expect(r.out.record?.tests[0].cleanup.status).toBe("remote-error");
    expect(r.out.messages.join()).toContain("did not arrive on the Dell, twice");
  });

  test("no other failure is retried: timeout, other exit, hash mismatch, unreadable answer", () => {
    const others: RemoteResult[] = [
      { ...missing, timedOut: true },
      { code: 1, out: "", err: "", timedOut: false },
      { code: 97, out: "", err: "", timedOut: false },
      { code: null, out: "", err: "", timedOut: false },
      { code: 0, out: "garbage", err: "", timedOut: false },
    ];
    for (const o of others) {
      const r = session(cleanDell(FIX.m), {}, (step) => (step === "gate" ? o : undefined));
      expect(r.out.exit).toBe(EXIT.setup);
      expect(count(r, "gate")).toBe(1);
    }
  });

  test("a well-formed answer from a remote that exited non-zero is not taken", () => {
    const r = session(cleanDell(FIX.m), {}, (step) => (step === "gate" ? { ...goodGate(), code: 1 } : undefined));
    expect(r.out.exit).toBe(EXIT.setup);
    expect(r.out.messages.join()).toContain("ssh exited 1");
    expect(count(r, "restore-point")).toBe(0);
  });

  test("staged files that change during the session fail it", () => {
    let gates = 0;
    const r = session(cleanDell(FIX.m), {}, (step) => {
      if (step !== "gate" || gates++ === 0) return undefined;
      const d = cleanDell(FIX.m);
      d.listing.files.push({ path: "atomics/residue.txt", size: 1, sha256: sha("x") });
      return answer({ step: "gate", utc: "2026-11-22T03:10:00Z", elevated: true, ids: d.ids, defender: d.defender, listing: d.listing, frequency: 0 });
    });
    expect(r.out.exit).toBe(EXIT.failed);
    expect(r.out.record?.stagedAfter).toEqual({ verdict: "changed", changed: 0, missing: 0, extra: 1 });
    expect(r.out.record?.verdict).toBe("fail");
    expect(r.out.messages.join()).toContain("changed during the session");
  });

  test("an unexpected answer shape is a setup failure", () => {
    const r = session(cleanDell(FIX.m), {}, (step) => (step === "gate" ? answer({ step, utc: "now" }) : undefined));
    expect(r.out.exit).toBe(EXIT.setup);
  });

  test("a non-elevated session sends nothing past the gate", () => {
    const r = session(cleanDell(FIX.m), {}, (step) => {
      if (step !== "gate") return undefined;
      const d = cleanDell(FIX.m);
      return answer({ step, utc: "2026-11-22T03:00:00Z", elevated: false, ids: d.ids, defender: d.defender, listing: d.listing, frequency: 0 });
    });
    expect(r.out.exit).toBe(EXIT.setup);
    expect(r.sent.length).toBe(1);
  });

  test("a record that still holds a Dell name after redaction is not written", () => {
    // A computer named like the staged root cannot be redacted out of the record's fixed text.
    const d = cleanDell(FIX.m);
    d.ids = { computer: "AtomicRedTeam", user: "labuser", domain: "labhost", accounts: [] };
    const r = session(d);
    expect(r.out.exit).toBe(EXIT.failed);
    expect(r.written.length).toBe(0);
    expect(r.out.messages.join()).toContain("was not written");
  });

  test("check-prereqs runs no test and needs no restore point", () => {
    const logged: string[] = [];
    const r = session(cleanDell(FIX.m), { mode: "check-prereqs", log: (l) => logged.push(l) });
    expect(r.out.exit).toBe(EXIT.ok);
    expect(r.sent.map((s) => s.step)).toEqual(["gate", "prereqs", "prereqs"]);
    expect(logged.filter((l) => l.startsWith("PREREQ met")).length).toBe(2);
  });

  test("check-prereqs exits 1 when a test's prerequisites are not met", () => {
    const logged: string[] = [];
    const notMet = [...kv("CheckPrereq's for: ", testId(E)), { m: `Prerequisites not met: ${testId(E)}`, c: "Red", n: false }];
    const r = session(cleanDell(FIX.m), { mode: "check-prereqs", log: (l) => logged.push(l) }, (step, payload) =>
      step === "prereqs" && payload.includes(`$Guid = '${E.guid}'`) ? answer({ step, refused: null, start: "2026-11-22T03:00:00Z", end: "2026-11-22T03:00:01Z", threw: false, segments: notMet }) : undefined,
    );
    expect(r.out.exit).toBe(EXIT.failed);
    expect(r.out.messages.join()).toContain("1 test did not meet its prerequisites");
    expect(logged).toContain(`PREREQ not-met ${E.technique} #${E.testNumber} ${E.guid}`);
  });
});

// *--- Record ---*

describe("record redaction (ISC-156)", () => {
  const ids = [
    { literal: "labhost", label: "<host>" },
    { literal: "labuser", label: "<user>" },
  ];
  test("redactName replaces names, SID machine parts, private addresses and control characters", () => {
    expect(redactName(`C:\\Users\\LabUser\\x-S-1-5-21-1-2-3-500 on ${v4(10, 9, 4, 5)} and ${["fd12", "3456", "", "1"].join(":")}\u001b[2J`, ids)).toBe(
      "C:\\Users\\<user>\\x-S-1-5-21-<machine>-500 on <private-address> and <private-address>?[2J",
    );
  });
  test("recordFindings catches each class a record must not hold", () => {
    expect(recordFindings('{"a":"LABHOST"}', ids)).toEqual(["the Dell's host name"]);
    expect(recordFindings('{"a":"S-1-5-21-1-2-3-500"}', ids)).toEqual(["a SID machine part"]);
    expect(recordFindings(JSON.stringify({ a: v4(10, 0, 0, 8) }), ids)).toEqual(["a private address"]);
    expect(recordFindings('{"a":"S-1-5-21-<machine>-500 <host>"}', ids)).toEqual([]);
  });
});

// *--- Self-Test and CLI ---*

describe("self-test and CLI", () => {
  test("--self-test plants every fault and catches each", () => {
    const lines: string[] = [];
    expect(selfTest((l) => lines.push(l))).toBe(true);
    expect(lines.length).toBe(7 + CATEGORIES.length);
    expect(lines.every((l) => l.startsWith("OK"))).toBe(true);
  });

  const cli = (...args: string[]) => Bun.spawnSync(["bun", resolve(ROOT, "tools/art-harness.ts"), ...args], { stdout: "pipe", stderr: "pipe", timeout: 60_000 });
  test("the CLI refuses an unknown GUID with exit 3 and no session folder", () => {
    const runs = resolve(ROOT, "Plans/b4-harness/runs");
    const before = existsSync(runs) ? readdirSync(runs).length : 0;
    const r = cli("run", "--host", "no-such-alias-for-tests", "--guid", "00000000-0000-4000-8000-000000000000");
    expect(r.exitCode).toBe(EXIT.refused);
    expect(r.stderr.toString()).toContain("not in atomics/allowlist.json");
    expect(existsSync(runs) ? readdirSync(runs).length : 0).toBe(before);
  });
  test("the CLI refuses a missing host, both --all and --guid, and an unknown argument", () => {
    expect(cli("run", "--all").exitCode).toBe(EXIT.refused);
    expect(cli("run", "--host", "x", "--all", "--guid", E.guid).exitCode).toBe(EXIT.refused);
    expect(cli("run", "--host", "x", "--bogus").exitCode).toBe(EXIT.refused);
  });
});
