// *****************************************************************************
// *Title: tier2-hold-probe.test*
// *Author: Kyle Versluis*
// *Description: Tests the Tier 2 hold probe and its rules on planted markers.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { isPack, parseRules, readRulesDir, repeatedIds } from "./wazuh-rules.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
// HOLD_PROBE points the suite at a mutated copy, to prove the cases catch each change.
const PROBE_SRC = process.env.HOLD_PROBE ?? join(ROOT, "deploy/soc-recon/wazuh/probes/soc-recon-tier2-hold.sh");
const RULES_DIR = join(ROOT, "deploy/soc-recon/wazuh/custom-rules");
const HOLD_RULES = join(RULES_DIR, "local_tier2_hold.xml");
const AGE_RULES = join(RULES_DIR, "local_tier2_age.xml");
const MANAGER_CONF = join(ROOT, "deploy/soc-recon/config/wazuh_cluster/wazuh_manager.conf");
const SHAPES = join(ROOT, "tools/fixtures/tier2-hold/shapes.json");

// The clock every case sees: the shim date answers this and nothing else.
const NOW = 1_800_000_000;
const HOUR = 3600;
const SKEW = 300;
const ALIAS = "soc-recon tier2 hold";
const AGE_ALIAS = "soc-recon tier2 age";
const isRoot = process.getuid?.() === 0;

// The tools the probe calls by name once its PATH is the shim dir; each is a link to the
// host's own, so the probe runs here as it runs in the manager image. Only date is a script.
const TOOLS = ["bash", "timeout", "head", "od", "tr", "sleep"];

let scratch = "";
let shim = "";
let bashPath = "";
let counter = 0;

interface Run {
  out: string;
  code: number;
  err: string;
  ms: number;
}

// *--- Helpers ---*

const epochText = (n: number) => String(n).padStart(10, "0");
const marker = (n: number) => `hold ${epochText(n)}\n`;
const days = (age: number) => `${Math.floor(age / 86400)}d${String(Math.floor((age % 86400) / HOUR)).padStart(2, "0")}h`;

/** Replace the one place a line sits in the probe, and fail loudly if it moved. */
function swap(text: string, from: string, to: string): string {
  const parts = text.split(from);
  if (parts.length !== 2) throw new Error(`expected exactly one ${JSON.stringify(from)} in the probe, found ${parts.length - 1}`);
  return parts.join(to);
}

/** A fresh stand-in for /srv/tier2. */
function newDir(): string {
  const d = join(scratch, `case-${++counter}`);
  mkdirSync(d);
  return d;
}

// What the probe must never change: names, kinds, modes, times, sizes, contents, link targets.
function snapshot(dir: string): string {
  // A missing directory, a plain file and a directory at mode 000 have no listing to compare.
  let names: string[];
  try {
    names = readdirSync(dir).sort();
  } catch {
    return "no listing";
  }
  const rows: string[] = [];
  for (const name of names) {
    const p = join(dir, name);
    const st = lstatSync(p);
    let body = "";
    if (st.isSymbolicLink()) body = readlinkSync(p);
    else if (st.isFile()) {
      try {
        body = readFileSync(p).toString("hex");
      } catch {
        body = "unreadable";
      }
    }
    rows.push(`${name} ${st.mode} ${st.mtimeMs} ${st.size} ${body}`);
  }
  return rows.join("\n");
}

/** The probe with its dir, PATH and (optionally) deadline pointed at the scratch tree. */
function probeCopy(dir: string, edit: (t: string) => string = (t) => t): string {
  let t = readFileSync(PROBE_SRC, "utf8");
  t = swap(t, "\nDIR=/srv/tier2\n", `\nDIR=${dir}\n`);
  t = swap(t, "\nPATH=/usr/sbin:/usr/bin\n", `\nPATH=${shim}\n`);
  t = edit(t);
  const f = join(scratch, `probe-${++counter}.sh`);
  writeFileSync(f, t);
  chmodSync(f, 0o755);
  return f;
}

function exec(probe: string, now: string): Run {
  const t0 = performance.now();
  const r = Bun.spawnSync([bashPath, probe], { env: { HOLD_TEST_NOW: now }, stdout: "pipe", stderr: "pipe" });
  return { out: r.stdout.toString(), code: r.exitCode ?? -1, err: r.stderr.toString(), ms: performance.now() - t0 };
}

// Every line the probe prints in this file, for the rule checks at the end.
const printed: string[] = [];

/** Run the probe on a dir. The interface holds for every case: one line, exit 0, nothing written. */
function probe(dir: string, o: { now?: string; edit?: (t: string) => string; secret?: string } = {}): string {
  const before = snapshot(dir);
  const r = exec(probeCopy(dir, o.edit), o.now ?? String(NOW));
  expect(r.code).toBe(0);
  expect(r.out).toMatch(/^[^\n]+\n$/);
  expect(snapshot(dir)).toBe(before);
  if (o.secret) expect(r.out).not.toContain(o.secret);
  const line = r.out.slice(0, -1);
  printed.push(line);
  return line;
}

/** A dir holding one marker file with these exact bytes. */
function withMarker(bytes: string | Buffer): string {
  const d = newDir();
  writeFileSync(join(d, "HOLD"), bytes);
  return d;
}

// *--- Rule reader ---*

// What the two rules decide for one logged event, read from the shipped XML and not copied
// into this file. wazuh-logtest on the scratch manager is the proof against the real engine;
// this reads the same text with JavaScript's regex, which agrees with PCRE2 on the small
// subset the rules use (anchors, groups, classes, \n). \z is the one PCRE2 spelling JS lacks;
// with no m flag, $ is the very end of the text, which is what \z means.
function ruleParts(file: string, id: number) {
  const xml = readFileSync(file, "utf8").replace(/<!--[\s\S]*?-->/g, "");
  const block = new RegExp(`<rule id="${id}"[\\s\\S]*?</rule>`).exec(xml)?.[0] ?? "";
  const match = /<match>([^<]*)<\/match>/.exec(block)?.[1];
  const re = /<regex type="pcre2" negate="yes">([^<]*)<\/regex>/.exec(block)?.[1];
  return { match, re };
}

function grader(file: string, first: number, second: number) {
  const m = ruleParts(file, first).match;
  const re = ruleParts(file, second).re;
  if (!m?.startsWith("^") || !re) throw new Error(`${file} lacks the match on ${first} or the negated regex on ${second}`);
  const lead = m.slice(1);
  const grade = new RegExp(re.replace(/\\z/g, "$"));
  return (event: string) => {
    const l1 = event.startsWith(lead);
    return { l1, l2: l1 && !grade.test(event) };
  };
}

const holdRules = () => grader(HOLD_RULES, 100322, 100323);
const ev = (alias: string, out: string) => `ossec: output: '${alias}':\n${out}`;

// *--- Setup ---*

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), "tier2-hold-"));
  shim = join(scratch, "bin");
  mkdirSync(shim);
  for (const name of TOOLS) {
    // Prefer Homebrew's bash (5.x, as in the manager image) over the system 3.2.
    const found = name === "bash" && existsSync("/opt/homebrew/bin/bash") ? "/opt/homebrew/bin/bash" : Bun.which(name);
    if (!found) throw new Error(`the host has no ${name}, which the probe calls`);
    symlinkSync(found, join(shim, name));
    if (name === "bash") bashPath = found;
  }
  // date answers the +%s the probe asks, from HOLD_TEST_NOW: "fail" exits 1, "junk" prints text.
  writeFileSync(
    join(shim, "date"),
    `#!${bashPath}
if [ "$1" = "+%s" ]; then
    case $HOLD_TEST_NOW in
        fail) exit 1 ;;
        junk) echo "not a number" ;;
        *) printf '%s\\n' "$HOLD_TEST_NOW" ;;
    esac
else
    exec /bin/date "$@"
fi
`,
  );
  chmodSync(join(shim, "date"), 0o755);
});

afterAll(() => {
  // A case may leave a directory at mode 000, which rm cannot enter.
  Bun.spawnSync(["chmod", "-R", "u+rwx", scratch]);
  rmSync(scratch, { recursive: true, force: true });
});

// *--- Tests: the probe ---*

describe("probe: shipped text", () => {
  test("is an executable bash script with the contract's path, fixed PATH and no stray write", () => {
    const t = readFileSync(PROBE_SRC, "utf8");
    expect(t.startsWith("#!/bin/bash\n")).toBe(true);
    expect(statSync(PROBE_SRC).mode & 0o111).not.toBe(0);
    expect(t).toContain("\nPATH=/usr/sbin:/usr/bin\n");
    expect(t).toContain("\nDIR=/srv/tier2\n");
    expect(t).toContain("\nMARKER=$DIR/HOLD\n");
    expect(t).toContain("\nexport LC_ALL=C\n");
    // Outside comments, the only redirect is stderr to /dev/null, and no command writes or deletes.
    const code = t
      .split("\n")
      .filter((l) => !l.trimStart().startsWith("#"))
      .join("\n")
      .replaceAll("2>/dev/null", "");
    expect(code).not.toContain(">");
    expect(code).not.toMatch(/\b(rm|mv|cp|touch|tee|mkdir|chmod|ln|sed|truncate)\b/);
  });

  test("never prints the marker's content: no cat, no echo of the epoch or the bytes", () => {
    const t = readFileSync(PROBE_SRC, "utf8");
    expect(t).not.toMatch(/\bcat\b/);
    expect(t).not.toMatch(/printf[^\n]*\$(\{?hex|\{?digits|\{?epoch)/);
  });
});

describe("probe: no marker, fresh and stuck", () => {
  test("no marker is OK hold=none", () => {
    expect(probe(newDir())).toBe("OK hold=none");
  });

  test("a marker one second old is OK hold=0d00h", () => {
    expect(probe(withMarker(marker(NOW - 1)))).toBe("OK hold=0d00h");
  });

  test("a marker made this second is OK hold=0d00h", () => {
    expect(probe(withMarker(marker(NOW)))).toBe("OK hold=0d00h");
  });

  test("a marker 3599 seconds old is OK hold=0d00h", () => {
    expect(probe(withMarker(marker(NOW - 3599)))).toBe("OK hold=0d00h");
  });

  test("a marker exactly one hour old is still OK hold=0d01h", () => {
    expect(probe(withMarker(marker(NOW - HOUR)))).toBe("OK hold=0d01h");
  });

  test("a marker one second past one hour is STUCK hold=0d01h", () => {
    expect(probe(withMarker(marker(NOW - HOUR - 1)))).toBe("STUCK hold=0d01h");
  });

  test("a marker days old is STUCK with the days and hours", () => {
    const age = 3 * 86400 + 5 * HOUR + 17;
    expect(probe(withMarker(marker(NOW - age)))).toBe(`STUCK hold=${days(age)}`);
    expect(days(age)).toBe("3d05h");
  });

  test("a marker over 100 days old keeps the full day count", () => {
    const age = 123 * 86400 + 23 * HOUR + 59;
    expect(probe(withMarker(marker(NOW - age)))).toBe("STUCK hold=123d23h");
  });

  test("a leading-zero epoch reads as base 10 and as a very old time, not octal", () => {
    const line = probe(withMarker("hold 0000000099\n"));
    expect(line).toBe(`STUCK hold=${days(NOW - 99)}`);
    expect(probe(withMarker("hold 0000000000\n"))).toBe(`STUCK hold=${days(NOW)}`);
    // 0000000010 is octal 8 and decimal 10; either way ancient, but 08 and 09 are not octal at all.
    expect(probe(withMarker("hold 0000000089\n"))).toBe(`STUCK hold=${days(NOW - 89)}`);
  });

  test("the marker is not touched or rewritten by any of them (probe() checks every run)", () => {
    const d = withMarker(marker(NOW - 10 * HOUR));
    const before = snapshot(d);
    probe(d);
    probe(d);
    expect(snapshot(d)).toBe(before);
  });
});

describe("probe: a clock that disagrees with the marker", () => {
  test("a marker dated ahead inside the skew counts as just made", () => {
    expect(probe(withMarker(marker(NOW + 1)))).toBe("OK hold=0d00h");
    expect(probe(withMarker(marker(NOW + SKEW)))).toBe("OK hold=0d00h");
  });

  test("a marker dated ahead beyond the skew is an error, not a pass", () => {
    expect(probe(withMarker(marker(NOW + SKEW + 1)))).toBe("ERROR the marker is dated after the clock");
    expect(probe(withMarker(marker(9_999_999_999)))).toBe("ERROR the marker is dated after the clock");
  });

  test("a clock that cannot be read is an error", () => {
    expect(probe(newDir(), { now: "fail" })).toBe("ERROR cannot read the clock");
  });

  test("a clock that prints no number is an error", () => {
    expect(probe(newDir(), { now: "junk" })).toBe("ERROR cannot read the clock");
    expect(probe(newDir(), { now: "" })).toBe("ERROR cannot read the clock");
  });
});

describe("probe: a marker that is not exactly hold, ten digits and a newline", () => {
  const bad = (name: string, bytes: string | Buffer, secret?: string) =>
    test(`${name} is an error`, () => {
      expect(probe(withMarker(bytes), { secret })).toBe("ERROR the marker is not one hold line");
    });

  bad("a 15 byte file (nine digits)", "hold 123456789\n");
  bad("a 15 byte file (no newline)", "hold 7777777777");
  bad("a 17 byte file (eleven digits)", "hold 77777777777\n");
  bad("a 17 byte file (a second newline)", `${marker(NOW - 10)}\n`);
  bad("a 17 byte file (a trailing space)", `hold ${epochText(NOW - 10)} \n`);
  bad("a 16 byte file with no newline (eleven digits)", "hold 77777777777", "77777777777");
  bad("a 16 byte file with a CR where the newline goes", `hold ${epochText(NOW - 10)}\r`);
  bad("a 16 byte file with a non-digit in the epoch", "hold 77777x7777\n", "77777");
  bad("a 16 byte file with a letter first in the epoch", "hold a777777777\n");
  // The bytes either side of 0 to 9, and the hex letter a class like [0-f] would admit.
  bad("a 16 byte file with a slash in the epoch", "hold 77777/7777\n");
  bad("a 16 byte file with a colon in the epoch", "hold 77777:7777\n");
  bad("a 16 byte file with a semicolon in the epoch", "hold 77777;7777\n");
  bad("a 16 byte file with an f in the epoch", "hold 77777f7777\n");
  bad("a 16 byte file with a space in the epoch", "hold  777777777\n");
  bad("a 16 byte file with a minus in the epoch", "hold -777777777\n");
  bad("a 16 byte file with a high byte in the epoch", Buffer.concat([Buffer.from("hold 77777"), Buffer.from([0xb5]), Buffer.from("7777\n")]));
  bad("a 16 byte file with a NUL in the epoch", Buffer.concat([Buffer.from("hold 77777"), Buffer.from([0]), Buffer.from("7777\n")]), "77777");
  bad("a 16 byte file with a NUL for the newline", Buffer.concat([Buffer.from(`hold ${epochText(NOW - 10)}`), Buffer.from([0])]));
  bad("a file of all NULs", Buffer.alloc(16));
  bad("the wrong word", `verified ${epochText(NOW - 10)}\n`.slice(0, 16));
  bad("the word in capitals", `HOLD ${epochText(NOW - 10)}\n`);
  bad("the word with a tab for the space", `hold\t${epochText(NOW - 10)}\n`);
  bad("a leading newline", `\nhold ${epochText(NOW - 10)}`);
  bad("an empty file", "");
  bad("two lines", "hold 77777\nhold 7\n");
  bad("a large file", Buffer.alloc(1 << 20, 0x61));
  bad("a large file that opens with a valid marker", Buffer.concat([Buffer.from(marker(NOW - 10)), Buffer.alloc(1 << 20, 0x61)]));
});

describe("probe: what is at the marker's path", () => {
  test("a dangling link is an error, not none", () => {
    const d = newDir();
    symlinkSync(join(d, "elsewhere"), join(d, "HOLD"));
    expect(probe(d)).toBe("ERROR the marker is a link");
  });

  test("a link to a valid marker is an error", () => {
    const d = newDir();
    writeFileSync(join(d, "real"), marker(NOW - 10));
    symlinkSync(join(d, "real"), join(d, "HOLD"));
    expect(probe(d)).toBe("ERROR the marker is a link");
  });

  test("a link to a directory is an error", () => {
    const d = newDir();
    mkdirSync(join(d, "sub"));
    symlinkSync(join(d, "sub"), join(d, "HOLD"));
    expect(probe(d)).toBe("ERROR the marker is a link");
  });

  test("a directory named HOLD is an error", () => {
    const d = newDir();
    mkdirSync(join(d, "HOLD"));
    expect(probe(d)).toBe("ERROR the marker is not a regular file");
  });

  test("a pipe named HOLD is an error and does not hang the probe", () => {
    const d = newDir();
    expect(Bun.spawnSync(["mkfifo", join(d, "HOLD")]).exitCode).toBe(0);
    expect(probe(d)).toBe("ERROR the marker is not a regular file");
  });

  test.skipIf(isRoot)("an unreadable marker is an error", () => {
    const d = withMarker(marker(NOW - 10));
    chmodSync(join(d, "HOLD"), 0o000);
    expect(probe(d)).toBe("ERROR cannot read the marker");
  });

  test("other files in the directory do not count as a hold", () => {
    const d = newDir();
    writeFileSync(join(d, "verified"), "verified 1700000000\n");
    writeFileSync(join(d, "HOLD.bak"), marker(NOW - 99 * HOUR));
    expect(probe(d)).toBe("OK hold=none");
  });
});

describe("probe: the directory", () => {
  test("a missing directory is an error, not none", () => {
    const d = newDir();
    rmSync(d, { recursive: true });
    expect(probe(d)).toBe(`ERROR cannot read ${d}`);
  });

  test("the directory as a link is an error", () => {
    const real = withMarker(marker(NOW - 10));
    const d = join(scratch, `link-${++counter}`);
    symlinkSync(real, d);
    expect(probe(d)).toBe(`ERROR ${d} is a link`);
  });

  test("a regular file where the directory should be is an error", () => {
    const d = join(scratch, `file-${++counter}`);
    writeFileSync(d, "x");
    expect(probe(d)).toBe(`ERROR cannot read ${d}`);
  });

  test.skipIf(isRoot)("an unreadable directory is an error", () => {
    const d = withMarker(marker(NOW - 10));
    chmodSync(d, 0o000);
    try {
      expect(exec(probeCopy(d), String(NOW)).out).toBe(`ERROR cannot read ${d}\n`);
    } finally {
      chmodSync(d, 0o700);
    }
  });

  test.skipIf(isRoot)("a directory that can be searched but not listed is an error", () => {
    const d = withMarker(marker(NOW - 10));
    chmodSync(d, 0o300);
    try {
      expect(exec(probeCopy(d), String(NOW)).out).toBe(`ERROR cannot read ${d}\n`);
    } finally {
      chmodSync(d, 0o700);
    }
  });

  test.skipIf(isRoot)("a directory that cannot be searched is an error", () => {
    const d = withMarker(marker(NOW - 10));
    chmodSync(d, 0o600);
    try {
      expect(exec(probeCopy(d), String(NOW)).out).toBe(`ERROR cannot read ${d}\n`);
    } finally {
      chmodSync(d, 0o700);
    }
  });
});

describe("probe: the deadline and the crash trap", () => {
  const before = "# *--- Report ---*";

  test("a probe that runs past its deadline prints one ERROR line and returns near it", () => {
    const d = withMarker(marker(NOW - 10));
    const f = probeCopy(d, (t) => swap(swap(t, "\nDEADLINE=8\n", "\nDEADLINE=1\n"), before, `sleep 30\n${before}`));
    const r = exec(f, String(NOW));
    expect(r.out).toBe("ERROR the probe ran past 1 s\n");
    expect(r.code).toBe(0);
    expect(r.ms).toBeLessThan(10_000);
    printed.push(r.out.slice(0, -1));
  });

  test("a probe that is killed prints the killed or past-deadline line", () => {
    const d = withMarker(marker(NOW - 10));
    const f = probeCopy(d, (t) => swap(t, before, `kill -9 $$\n${before}`));
    const r = exec(f, String(NOW));
    expect(r.out).toBe("ERROR the probe ran past 8 s, or was killed\n");
    printed.push(r.out.slice(0, -1));
  });

  test("a crash before the report still prints one ERROR line", () => {
    const d = withMarker(marker(NOW - 10));
    expect(probe(d, { edit: (t) => swap(t, before, `exit 7\n${before}`) })).toBe("ERROR the probe stopped before reporting");
  });

  // The OpenAI read, 2026-11-25: the case above passes without the run's own EXIT trap, because
  // the wrapper prints the same line for any early stop. This one runs the run with no wrapper.
  test("the run itself, with no wrapper, prints the ERROR line from its own trap", () => {
    const d = withMarker(marker(NOW - 10));
    const f = probeCopy(d, (t) => swap(t, before, `exit 7\n${before}`));
    const r = Bun.spawnSync([bashPath, f, "--run"], { env: { HOLD_TEST_NOW: String(NOW) }, stdout: "pipe", stderr: "pipe" });
    expect(r.stdout.toString()).toBe("ERROR the probe stopped before reporting\n");
    expect(r.exitCode).toBe(7);
  });

  test("a probe that cannot start its own run prints one ERROR line", () => {
    const d = newDir();
    const f = probeCopy(d, (t) => swap(t, 'bash -- "$0" --run', 'bash -- "$0.gone" --run'));
    const r = exec(f, String(NOW));
    expect(r.out).toBe("ERROR the probe stopped before reporting\n");
    printed.push(r.out.slice(0, -1));
  });
});

describe("probe: the age line follows the age", () => {
  test("every age from 0 to 3600 prints OK and every age past it prints STUCK", () => {
    // The ages that sit on a boundary, and a spread between: each run is a real probe run.
    const ages = [0, 1, 59, 60, 1799, 1800, 3599, 3600, 3601, 3602, 7199, 7200, 86399, 86400, 86401, 7 * 86400];
    for (const age of ages) {
      const line = probe(withMarker(marker(NOW - age)));
      expect(line).toBe(`${age <= HOUR ? "OK" : "STUCK"} hold=${days(age)}`);
    }
  });
});

// *--- Tests: the rules ---*

describe("rules file", () => {
  const rules = parseRules(readFileSync(HOLD_RULES, "utf8"), "local_tier2_hold.xml");
  const text = readFileSync(HOLD_RULES, "utf8");

  test("holds exactly rules 100322 at level 3 and 100323 at level 10", () => {
    expect(rules.map((r) => [r.id, r.level])).toEqual([
      [100322, 3],
      [100323, 10],
    ]);
  });

  test("100322 hangs off the full_command parent 530 and 100323 off 100322", () => {
    expect(rules[0].ifSid).toEqual(["530"]);
    expect(rules[1].ifSid).toEqual(["100322"]);
  });

  test("neither id is a detection pack id, and neither repeats anywhere in the rules folder", () => {
    for (const r of rules) expect(isPack(r.id)).toBe(false);
    const all = readRulesDir(RULES_DIR).rules;
    expect(repeatedIds(all)).toEqual([]);
    expect(all.filter((r) => r.id === 100322 || r.id === 100323)).toHaveLength(2);
  });

  test("100322 matches the probe's own alias and the localfile ships that alias, daily", () => {
    expect(ruleParts(HOLD_RULES, 100322).match).toBe(`^ossec: output: '${ALIAS}':`);
    const conf = readFileSync(MANAGER_CONF, "utf8").replace(/<!--[\s\S]*?-->/g, "");
    const blocks = [...conf.matchAll(/<localfile>[\s\S]*?<\/localfile>/g)].map((m) => m[0]);
    const mine = blocks.filter((b) => b.includes(`<alias>${ALIAS}</alias>`));
    expect(mine).toHaveLength(1);
    expect(mine[0]).toContain("<log_format>full_command</log_format>");
    expect(mine[0]).toContain("<command>/var/ossec/etc/probes/soc-recon-tier2-hold.sh</command>");
    expect(mine[0]).toContain("<frequency>86400</frequency>");
    // The age probe's block is still the one it was, and the two aliases are different.
    expect(blocks.filter((b) => b.includes(`<alias>${AGE_ALIAS}</alias>`))).toHaveLength(1);
  });

  test("the regex admits only the OK lines the probe can print", () => {
    expect(ruleParts(HOLD_RULES, 100323).re).toBe(`^ossec: output: '${ALIAS}':\\nOK hold=(?:none|0d0[01]h)\\n?\\z`);
  });

  test("the file says what it grades, in the age file's style, and holds no real address or host name", () => {
    expect(text).toContain('<group name="local,soc_recon,tier2_hold,">');
    expect(text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
  });
});

describe("rules: grading each line the probe can print", () => {
  const grade = holdRules();

  test("every OK shape passes 100323 and still takes 100322", () => {
    for (const out of ["OK hold=none", "OK hold=0d00h", "OK hold=0d01h", "OK hold=0d00h\n"]) {
      expect(grade(ev(ALIAS, out))).toEqual({ l1: true, l2: false });
    }
  });

  test("every STUCK and ERROR shape, an empty run and trailing junk all alert", () => {
    const loud = [
      "STUCK hold=0d01h",
      "STUCK hold=123d23h",
      "ERROR the marker is a link",
      "ERROR the marker is not a regular file",
      "ERROR cannot read the marker",
      "ERROR the marker is not one hold line",
      "ERROR the marker is dated after the clock",
      "ERROR cannot read the clock",
      "ERROR cannot read /srv/tier2",
      "ERROR /srv/tier2 is a link",
      "ERROR the probe ran past 8 s",
      "ERROR the probe ran past 8 s, or was killed",
      "ERROR the probe stopped before reporting",
      "",
      "OK",
      "OK hold=",
      "OK hold=0d02h",
      "OK hold=1d00h",
      "OK hold=0d001h",
      "OK hold=0d1h",
      "OK hold=0d01h trailing",
      "OK hold=none trailing",
      "OK hold=0d01h\nOK hold=0d01h",
      "OK hold=0d01h\nERROR something",
      "OK hold=0d01h\n\n",
      "\nOK hold=0d01h",
      " OK hold=0d01h",
      "ok hold=0d01h",
      "OK tier2=0d01h",
      "OK hold=NONE",
      "/var/ossec/etc/probes/soc-recon-tier2-hold.sh: line 3: syntax error",
    ];
    for (const out of loud) expect(grade(ev(ALIAS, out)), JSON.stringify(out)).toEqual({ l1: true, l2: true });
  });

  test("every line the probe printed in this file is graded as its first word says", () => {
    expect(printed.length).toBeGreaterThan(60);
    for (const line of printed) {
      const g = grade(ev(ALIAS, line));
      const ok = /^OK hold=(none|0d0[01]h)$/.test(line);
      expect(g, line).toEqual({ l1: true, l2: !ok });
      if (line.startsWith("OK")) expect(ok, line).toBe(true);
    }
    // The set the run printed covers every kind of line.
    expect(printed.some((l) => l === "OK hold=none")).toBe(true);
    expect(printed.some((l) => l === "OK hold=0d00h")).toBe(true);
    expect(printed.some((l) => l === "OK hold=0d01h")).toBe(true);
    expect(printed.some((l) => l.startsWith("STUCK hold="))).toBe(true);
    expect(printed.some((l) => l.startsWith("ERROR "))).toBe(true);
  });

  test("the two tier 2 probes' output never reaches each other's rules", () => {
    const age = grader(AGE_RULES, 100320, 100321);
    expect(age(ev(ALIAS, "OK hold=none"))).toEqual({ l1: false, l2: false });
    expect(age(ev(ALIAS, "STUCK hold=0d02h"))).toEqual({ l1: false, l2: false });
    expect(grade(ev(AGE_ALIAS, "OK tier2=0d01h"))).toEqual({ l1: false, l2: false });
    expect(grade(ev(AGE_ALIAS, "STALE tier2=none"))).toEqual({ l1: false, l2: false });
    expect(grade(ev("other probe", "OK hold=none"))).toEqual({ l1: false, l2: false });
    expect(grade(`ossec: output: 'x ${ALIAS}':\nOK hold=none`)).toEqual({ l1: false, l2: false });
    expect(grade(`ossec: output: '${ALIAS} x':\nOK hold=none`)).toEqual({ l1: false, l2: false });
  });
});

describe("drill shapes for wazuh-logtest on the scratch manager", () => {
  const shapes: { name: string; event: string; want: string }[] = JSON.parse(readFileSync(SHAPES, "utf8")).shapes;
  const grade = holdRules();

  test("the file names each shape once and holds a case for every outcome", () => {
    const names = shapes.map((s) => s.name);
    expect(new Set(names).size).toBe(names.length);
    expect(new Set(shapes.map((s) => s.want))).toEqual(new Set(["100322", "100323", "-"]));
  });

  // want is the id wazuh-logtest reports as the last rule to match: 100322 for a pass,
  // 100323 for an alert, and "-" where it is neither (an age rule, or the stock parent).
  test("each shape's wanted rule is what the shipped XML decides", () => {
    for (const s of shapes) {
      const g = grade(s.event);
      const got = g.l2 ? "100323" : g.l1 ? "100322" : "-";
      expect(got, s.name).toBe(s.want);
    }
  });
});
