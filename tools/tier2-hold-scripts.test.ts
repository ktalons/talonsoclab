// *****************************************************************************
// *Title: tier2-hold-scripts.test*
// *Author: Kyle Versluis*
// *Description: The backup hold in the box scripts, with docker stubbed.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const BIN = resolve(ROOT, "deploy/soc-recon/bin");
const SNAPSHOT = readFileSync(join(BIN, "tier2-snapshot"), "utf8");
const HOLD_TOOL = readFileSync(join(BIN, "tier2-hold"), "utf8");
const START = readFileSync(join(BIN, "tier2-start"), "utf8");
const PROBE = readFileSync(resolve(ROOT, "deploy/soc-recon/wazuh/probes/soc-recon-tier2-hold.sh"), "utf8");
const INIT = readFileSync(resolve(ROOT, "deploy/soc-recon/wazuh/cont-init/0-wazuh-init"), "utf8");
const made: string[] = [];

afterAll(() => {
  for (const d of made) rmSync(d, { recursive: true, force: true });
});

// *--- Helper Functions ---*

function findBash(): string {
  for (const b of ["/opt/homebrew/bin/bash", "/usr/local/bin/bash", Bun.which("bash") ?? ""]) {
    if (!b || !existsSync(b)) continue;
    const v = Bun.spawnSync([b, "-c", "echo ${BASH_VERSINFO[0]}"]).stdout.toString().trim();
    if (Number(v) >= 4) return b;
  }
  throw new Error("no bash 4 or newer on this machine; the stubbed runs need one");
}
const BASH = findBash();

/** One function's text from a script: its "name() {" line to the next "}" at column 0. */
function fn(script: string, name: string): string {
  const m = new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}$`, "m").exec(script);
  if (!m) throw new Error(`no function ${name}`);
  return m[0];
}

// The box's GNU tools, from BSD ones, inside the stubbed run only. mv keeps -T's
// meaning: a folder at the target fails the move instead of taking the file.
const GNU = `
mv() {
  local a=() t=
  for x in "$@"; do [ "$x" = -T ] && t=1 || a+=("$x"); done
  if [ -n "$t" ] && [ -d "\${a[-1]}" ] && ! [ -L "\${a[-1]}" ]; then return 1; fi
  printf 'mv\\n' >>"$W/flush"
  command mv "\${a[@]}"
}
# GNU sync FILE flushes that file or folder. Here it only leaves a trace, and fails on request.
sync() {
  [ "$1" = -- ] && shift
  case $1 in *.tmp) printf 'sync tmp\\n' >>"$W/flush"; [ -z "\${FAIL_SYNC_TMP-}" ] ;; *) printf 'sync dir %s\\n' "$1" >>"$W/flush"; [ -z "\${FAIL_SYNC_DIR-}" ] ;; esac
}
stat() { [ "$1" = -c ] && [ "$2" = %s ] && shift 3 && command stat -f %z "$@"; }
chmod() { [ "$2" = -- ] && set -- "$1" "\${@:3}"; command chmod "$@"; }
`;

// docker, retry and inputs stand in for the box. Each docker call is logged with whether
// the hold stood at that moment, which is the property under test.
const STUBS = `
say() { printf '%s\\n' "$*" >>"$W/say"; }
retry() { "$@"; }
inputs() { if [ -e "$W/inputs" ]; then cat "$W/inputs"; else printf '%s\\n' "$INPUTS"; fi; }
docker() {
  local h=no
  { [ -e "$HOLD" ] || [ -L "$HOLD" ]; } && h=yes
  printf 'docker %s hold=%s\\n' "$*" "$h" >>"$W/calls"
  case "$*" in
    "compose start wazuh.indexer")
      [ -z "\${DRIFT_AT_INDEXER-}" ] || printf 'B\\n' >"$W/inputs"
      [ -z "\${BREAK_AT_INDEXER-}" ] || mkdir "$W/inputs"
      [ -z "\${FAIL_INDEXER-}" ] ;;
    "compose up -d --no-deps --force-recreate --pull never wazuh.manager")
      [ -n "\${LOCK_STATE-}" ] && chmod 555 "$W/state/tier2"
      [ -z "\${FAIL_RECREATE-}" ] ;;
    "compose start") [ -z "\${FAIL_START-}" ] ;;
    "compose config --services") printf 'wazuh.indexer\\nwazuh.manager\\n' ;;
    "compose ps --status running --format {{.Service}}") printf 'wazuh.indexer\\nwazuh.manager\\n' ;;
    "inspect -f {{.State.Running}} "*) echo true ;;
    "start "*) [ -z "\${FAIL_IDSTART-}" ] ;;
    *) return 0 ;;
  esac
}
`;

interface Box {
  w: string;
  hold: string;
}

/** A deploy dir and a runs dir in a scratch folder, with PENDING and IDS as a run leaves them. */
function box(pending = true): Box {
  const w = realpathSync(mkdtempSync(join(tmpdir(), "tier2-hold-")));
  made.push(w);
  mkdirSync(join(w, "state/tier2"), { recursive: true });
  const want = createHash("sha256").update("A\n").digest("hex");
  if (pending) writeFileSync(join(w, ".pending-restart"), `2026-11-24T000000Z ${want}\n`);
  writeFileSync(join(w, ".restart-ids"), "wazuh.indexer aaa\nwazuh.manager bbb\n");
  return { w, hold: join(w, "state/tier2/HOLD") };
}

/** Run restart() from bin/tier2-snapshot against the stubs. */
function restart(b: Box, env: Record<string, string> = {}) {
  const script = [
    "set -u -o pipefail",
    GNU,
    STUBS,
    SNAPSHOT.match(/^HOLD_RE=.*$/m)?.[0] ?? "",
    fn(SNAPSHOT, "write_hold"),
    fn(SNAPSHOT, "unchanged"),
    fn(SNAPSHOT, "restart"),
    `PENDING=$W/.pending-restart IDS=$W/.restart-ids LOG=$W/log HOLD=$W/state/tier2/HOLD held=`,
    `restart; rc=$?; echo "rc=$rc held=$held"`,
  ].join("\n");
  writeFileSync(join(b.w, "run.sh"), script);
  const r = Bun.spawnSync([BASH, join(b.w, "run.sh")], {
    env: { PATH: "/usr/bin:/bin:/sbin", W: b.w, INPUTS: "A", LC_ALL: "C", ...env },
  });
  const read = (f: string) => (existsSync(join(b.w, f)) ? readFileSync(join(b.w, f), "utf8") : "");
  return { out: r.stdout.toString() + r.stderr.toString(), calls: read("calls"), say: read("say") };
}

/** Whether any entry stands at HOLD, a dangling link included, as the init reads it. */
function held(b: Box): boolean {
  try {
    lstatSync(b.hold);
    return true;
  } catch {
    return false;
  }
}

/** Run hold_kind() from bin/tier2-hold in a deploy dir. */
function kind(b: Box): string {
  const script = [GNU, "HOLD=state/tier2/HOLD", "HOLD_SIZE=16", fn(HOLD_TOOL, "hold_kind"), "hold_kind"].join("\n");
  writeFileSync(join(b.w, "kind.sh"), script);
  return Bun.spawnSync([BASH, join(b.w, "kind.sh")], { cwd: b.w, env: { PATH: "/usr/bin:/bin", LC_ALL: "C" } }).stdout.toString().trim();
}

// *--- Tests: restart() in bin/tier2-snapshot ---*

describe("restart() and the hold", () => {
  test("normal branch: the hold is gone before the recreate, and stays gone", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b);
    expect(r.out).toContain("rc=0 held=");
    expect(r.calls).toContain("docker compose start wazuh.indexer hold=yes");
    expect(r.calls).toContain("docker compose up -d --no-deps --force-recreate --pull never wazuh.manager hold=no");
    expect(held(b)).toBe(false);
    expect(existsSync(join(b.w, ".pending-restart"))).toBe(false);
  });

  test("normal branch, indexer start fails: the original hold stays through the recreate", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b, { FAIL_INDEXER: "1" });
    expect(r.out).toContain("rc=1");
    expect(r.calls).toContain("--force-recreate --pull never wazuh.manager hold=yes");
    expect(readFileSync(b.hold, "utf8")).toBe("hold 1764000000\n");
    expect(existsSync(join(b.w, ".pending-restart"))).toBe(true);
  });

  // Round 2: the hold is absent only after a round that fully worked.
  test("normal branch, the recreate fails after the release: a hold stands again", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b, { FAIL_RECREATE: "1" });
    expect(r.out).toContain("rc=1");
    expect(r.calls).toContain("--force-recreate --pull never wazuh.manager hold=no");
    expect(readFileSync(b.hold, "utf8")).toMatch(/^hold [0-9]{10}\n$/);
    expect(existsSync(join(b.w, ".pending-restart"))).toBe(true);
  });

  test("normal branch, the late compose start fails: a hold stands again", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b, { FAIL_START: "1" });
    expect(r.out).toContain("rc=1");
    expect(r.calls).toContain("docker compose start hold=no");
    expect(held(b)).toBe(true);
    expect(existsSync(join(b.w, ".pending-restart"))).toBe(true);
  });

  test("the next round after such a failure releases, recreates and ends with no hold", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    expect(restart(b, { FAIL_RECREATE: "1" }).out).toContain("rc=1");
    expect(held(b)).toBe(true);
    rmSync(join(b.w, "calls"));
    const r = restart(b);
    expect(r.out).toContain("rc=0");
    expect(r.calls).toContain("--force-recreate --pull never wazuh.manager hold=no");
    expect(held(b)).toBe(false);
    expect(existsSync(join(b.w, ".pending-restart"))).toBe(false);
  });

  test("a failed round whose hold cannot be written again says so in the log", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b, { FAIL_RECREATE: "1", LOCK_STATE: "1" });
    chmodSync(join(b.w, "state/tier2"), 0o755);
    expect(r.out).toContain("rc=1");
    expect(r.say).toContain("WARN: cannot write the backup hold");
    expect(held(b)).toBe(false);
  });

  test("normal branch, a folder at HOLD cannot be released: the run fails and it still holds", () => {
    const b = box();
    mkdirSync(b.hold);
    const r = restart(b);
    expect(r.out).toContain("rc=1");
    expect(r.say).toContain("WARN: cannot release the backup hold");
    expect(r.calls).toContain("wazuh.manager hold=yes");
    expect(held(b)).toBe(true);
  });

  // The OpenAI read, 2026-11-25: the release acted on a comparison made before the indexer start.
  test("normal branch, the inputs change while the indexer starts: no release, no recreate, the old manager starts", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b, { DRIFT_AT_INDEXER: "1" });
    expect(r.out).toContain("rc=0 held=1");
    expect(r.calls).toContain("docker compose start wazuh.indexer hold=yes");
    expect(r.calls).not.toContain("force-recreate");
    expect(r.calls).toContain("docker start bbb hold=yes");
    expect(readFileSync(b.hold, "utf8")).toBe("hold 1764000000\n");
    expect(r.say).toContain("WARN: the inputs changed while the indexer started");
  });

  // The second OpenAI read, 2026-11-25: a failed indexer start skipped the second comparison,
  // and the recreate that follows one applies a changed compose file, image or bind.
  test("normal branch, the indexer fails and the inputs changed meanwhile: no recreate", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b, { DRIFT_AT_INDEXER: "1", FAIL_INDEXER: "1" });
    expect(r.out).toContain("rc=1 held=1");
    expect(r.calls).not.toContain("force-recreate");
    expect(r.calls).toContain("docker start bbb hold=yes");
    expect(readFileSync(b.hold, "utf8")).toBe("hold 1764000000\n");
    expect(existsSync(join(b.w, ".pending-restart"))).toBe(true);
  });

  test("the inputs cannot be read at the first comparison: held, never a recreate", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    mkdirSync(join(b.w, "inputs"));
    const r = restart(b);
    expect(r.out).toContain("held=1");
    expect(r.calls).not.toContain("compose start wazuh.indexer");
    expect(r.calls).not.toContain("force-recreate");
    expect(held(b)).toBe(true);
  });

  test("the inputs cannot be read at the second comparison: held, never a recreate", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b, { BREAK_AT_INDEXER: "1" });
    expect(r.out).toContain("rc=0 held=1");
    expect(r.calls).toContain("docker compose start wazuh.indexer hold=yes");
    expect(r.calls).not.toContain("force-recreate");
    expect(readFileSync(b.hold, "utf8")).toBe("hold 1764000000\n");
  });

  test("held branch: the old containers start under the hold, which stays", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const before = readFileSync(b.hold, "utf8");
    const r = restart(b, { INPUTS: "B" });
    expect(r.out).toContain("rc=0 held=1");
    expect(r.calls).not.toContain("force-recreate");
    expect(r.calls).toContain("docker start bbb hold=yes");
    expect(readFileSync(b.hold, "utf8")).toBe(before);
  });

  test("held branch after an earlier try released the hold: it is written again before any start", () => {
    const b = box();
    const r = restart(b, { INPUTS: "B" });
    expect(r.out).toContain("rc=0 held=1");
    for (const line of r.calls.trim().split("\n")) expect(line).toEndWith("hold=yes");
    expect(r.calls).toContain("docker start aaa hold=yes");
    expect(readFileSync(b.hold, "utf8")).toMatch(/^hold [0-9]{10}\n$/);
  });

  // Three OpenAI reads, 2026-11-25: a held round that failed, then a change put back, let the
  // next round compare equal, release the hold and recreate.
  test("a held round that fails is held on every later round, even once the inputs match again", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    const first = restart(b, { INPUTS: "B", FAIL_IDSTART: "1" });
    expect(first.out).toContain("rc=1 held=1");
    expect(readFileSync(join(b.w, ".pending-restart"), "utf8")).toBe("2026-11-24T000000Z held\n");
    rmSync(join(b.w, "calls"));
    const r = restart(b);
    expect(r.out).toContain("rc=0 held=1");
    expect(r.calls).not.toContain("force-recreate");
    expect(r.calls).not.toContain("compose start");
    expect(r.calls).toContain("docker start bbb hold=yes");
    expect(readFileSync(b.hold, "utf8")).toBe("hold 1764000000\n");
    expect(existsSync(join(b.w, ".pending-restart"))).toBe(false);
  });

  test("a held decision that cannot be recorded is said, and the round still runs held", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    mkdirSync(join(b.w, ".pending-restart.tmp"));
    const r = restart(b, { INPUTS: "B" });
    rmSync(join(b.w, ".pending-restart.tmp"), { recursive: true, force: true });
    expect(r.out).toContain("rc=0 held=1");
    expect(r.say).toContain("WARN: cannot record the held decision");
    expect(r.calls).toContain("docker start bbb hold=yes");
  });

  test("held branch, the hold cannot be written: nothing starts and the run fails", () => {
    const b = box();
    chmodSync(join(b.w, "state/tier2"), 0o555);
    const r = restart(b, { INPUTS: "B" });
    chmodSync(join(b.w, "state/tier2"), 0o755);
    expect(r.out).toContain("rc=1 held=1");
    expect(r.calls).not.toContain("docker start");
    expect(r.say).toContain("cannot write the backup hold");
    expect(existsSync(join(b.w, ".pending-restart"))).toBe(true);
  });

  test("no PENDING: nothing runs and a hold is left as it is", () => {
    const b = box(false);
    writeFileSync(b.hold, "hold 1764000000\n");
    const r = restart(b);
    expect(r.out).toContain("rc=0");
    expect(r.calls).toBe("");
    expect(held(b)).toBe(true);
  });
});

describe("write_hold() writes the shared 16-byte marker", () => {
  const write = (b: Box, env: Record<string, string> = {}) => {
    const script = [GNU, SNAPSHOT.match(/^HOLD_RE=.*$/m)?.[0] ?? "", 'say() { printf "%s\\n" "$*" >>"$W/say"; }', fn(SNAPSHOT, "write_hold"), `HOLD=$W/state/tier2/HOLD`, 'write_hold; echo rc=$?; [ -z "${SHOW-}" ] || echo "line=${hold_line-}"'].join("\n");
    writeFileSync(join(b.w, "w.sh"), script);
    return Bun.spawnSync([BASH, join(b.w, "w.sh")], { env: { PATH: "/usr/bin:/bin", W: b.w, ...env } }).stdout.toString();
  };
  const trace = (b: Box, f: string) => (existsSync(join(b.w, f)) ? readFileSync(join(b.w, f), "utf8") : "");

  test("exactly 'hold <ten-digit epoch>' and a newline, mode 644, no temp file left", () => {
    const b = box();
    const before = Math.floor(Date.now() / 1000);
    expect(write(b)).toBe("rc=0\n");
    const text = readFileSync(b.hold, "utf8");
    expect(text).toMatch(/^hold [0-9]{10}\n$/);
    expect(Buffer.byteLength(text)).toBe(16);
    expect(Math.abs(Number(text.slice(5, 15)) - before)).toBeLessThan(5);
    expect(lstatSync(b.hold).mode & 0o777).toBe(0o644);
    expect(existsSync(`${b.hold}.tmp`)).toBe(false);
  });

  // The OpenAI read, 2026-11-25: a rename alone does not outlast a power loss.
  test("the bytes are flushed before the rename and the folder after it", () => {
    const b = box();
    expect(write(b)).toBe("rc=0\n");
    expect(trace(b, "flush")).toBe(`sync tmp\nmv\nsync dir ${join(b.w, "state/tier2")}\n`);
  });

  test("bytes that cannot be flushed publish no hold", () => {
    const b = box();
    expect(write(b, { FAIL_SYNC_TMP: "1" })).toBe("rc=1\n");
    expect(trace(b, "flush")).toBe("sync tmp\n");
    expect(existsSync(b.hold)).toBe(false);
    expect(existsSync(`${b.hold}.tmp`)).toBe(false);
  });

  test("a folder that cannot be flushed is said, and the hold stands", () => {
    const b = box();
    expect(write(b, { FAIL_SYNC_DIR: "1" })).toBe("rc=0\n");
    expect(readFileSync(b.hold, "utf8")).toMatch(/^hold [0-9]{10}\n$/);
    expect(trace(b, "say")).toContain("WARN: cannot flush");
  });

  test("the line written is kept for the log, which never reads the marker back", () => {
    const b = box();
    const out = write(b, { SHOW: "1" });
    expect(out).toBe(`rc=0\nline=${readFileSync(b.hold, "utf8")}`);
    expect(SNAPSHOT).toContain('say "backup hold written ($hold_line) for run $stamp, inputs $fp"');
    expect(SNAPSHOT).not.toContain('$(<"$HOLD")');
  });

  test("a folder at HOLD fails the write instead of taking the file", () => {
    const b = box();
    mkdirSync(b.hold);
    expect(write(b)).toBe("rc=1\n");
    expect(existsSync(join(b.hold, "HOLD.tmp"))).toBe(false);
  });

  test("the format is the one the init, the probe and tier2-hold read", () => {
    expect(SNAPSHOT).toContain("HOLD_RE='^hold [0-9]{10}$'");
    expect(HOLD_TOOL).toContain("HOLD_SIZE=16");
    expect(HOLD_TOOL).toContain("^686f6c6420(3[0-9]){10}0a$");
    expect(PROBE).toContain("MARKER_SIZE=16");
    expect(PROBE).toContain("^686f6c6420((3[0-9]){10})0a$");
    expect(INIT).toContain("if [ -e /srv/tier2/HOLD ] || [ -L /srv/tier2/HOLD ]; then");
  });
});

// *--- Tests: hold_kind() in bin/tier2-hold ---*

describe("tier2-hold types the marker before it reads it", () => {
  const cases: Record<string, [string, (p: string) => void]> = {
    "no entry": ["none", () => {}],
    "a well-formed marker": ["marker", (p) => writeFileSync(p, "hold 1764000000\n")],
    "a marker with CRLF": ["malformed", (p) => writeFileSync(p, "hold 176400000\r\n")],
    "a NUL in place of the newline": ["malformed", (p) => writeFileSync(p, "hold 1764000000\0")],
    "no newline": ["malformed", (p) => writeFileSync(p, "hold 1764000000")],
    "an empty file": ["malformed", (p) => writeFileSync(p, "")],
    "a link to a good marker": [
      "link",
      (p) => {
        writeFileSync(`${p}.real`, "hold 1764000000\n");
        symlinkSync(`${p}.real`, p);
      },
    ],
    "a dangling link": ["link", (p) => symlinkSync(`${p}.nowhere`, p)],
    "a folder": ["folder", (p) => mkdirSync(p)],
    "a FIFO, never opened": [
      "other",
      (p) => {
        if (Bun.spawnSync(["mkfifo", p]).exitCode !== 0) throw new Error("mkfifo failed");
      },
    ],
  };
  for (const [label, [want, make]] of Object.entries(cases)) {
    test(`${label} reads as ${want}`, () => {
      const b = box();
      make(b.hold);
      expect(kind(b)).toBe(want);
    });
  }
});

// *--- Tests: hold_age_min() in bin/tier2-hold ---*

describe("tier2-hold reads the epoch in base 10", () => {
  const age = (epoch: string) => {
    const r = Bun.spawnSync([BASH, "-c", `${fn(HOLD_TOOL, "hold_age_min")}\nhold_age_min "$1"`, "sh", epoch], { env: { PATH: "/usr/bin:/bin" } });
    return { out: r.stdout.toString().trim(), err: r.stderr.toString() };
  };

  // The OpenAI read, 2026-11-25: hold_kind accepts this marker, and bash reads 09... as octal.
  test("an epoch with a leading zero is a number of minutes, not an octal error", () => {
    const r = age("0999999999");
    expect(r.err).toBe("");
    expect(Number(r.out)).toBe(Math.floor((Math.floor(Date.now() / 1000) - 999999999) / 60));
  });

  test("a current epoch is zero minutes old", () => {
    expect(age(String(Math.floor(Date.now() / 1000))).out).toBe("0");
  });

});

// *--- Tests: hold_since() and release in bin/tier2-hold ---*

describe("tier2-hold status reads the marker once more, and says so when it is gone", () => {
  // GNU date -d @N, from the BSD one, inside this run only.
  const DATE = 'date() { if [ "$1" = -u ] && [ "$2" = -d ]; then command date -u -r "${3#@}" "$4"; else command date "$@"; fi; }';
  const since = (make: (p: string) => void) => {
    const b = box();
    make(b.hold);
    const script = [DATE, "HOLD=state/tier2/HOLD", fn(HOLD_TOOL, "hold_age_min"), fn(HOLD_TOOL, "hold_since"), "hold_since"].join("\n");
    const r = Bun.spawnSync([BASH, "-c", script], { cwd: b.w, env: { PATH: "/usr/bin:/bin", LC_ALL: "C" } });
    return r.stdout.toString() + r.stderr.toString();
  };

  test("a marker prints its time and its age", () => {
    expect(since((p) => writeFileSync(p, "hold 1764000000\n"))).toMatch(/^hold: since 2025-11-24T16:00:00Z, [0-9]+ min ago\n$/);
  });

  // The second OpenAI read, 2026-11-25: a marker released between the type check and this
  // read printed "hold: since ,  min ago".
  test("a marker gone since it was typed is said, with no empty time", () => {
    expect(since(() => {})).toBe("hold: the marker changed while it was read; run status again\n");
  });

  // The third OpenAI read, 2026-11-25: only the second field was checked.
  test("a line with ten digits but another first word is not a marker", () => {
    expect(since((p) => writeFileSync(p, "held 1764000000\n"))).toBe("hold: the marker changed while it was read; run status again\n");
  });

  test("a marker replaced by other bytes is said too", () => {
    expect(since((p) => writeFileSync(p, "hold soon\n"))).toBe("hold: the marker changed while it was read; run status again\n");
  });

  test("status prints a marker through it", () => {
    expect(HOLD_TOOL).toContain("        marker) hold_since ;;");
  });
});

describe("tier2-hold release looks in every runs dir, whatever the compose file names", () => {
  // The whole script, in a deploy dir with no compose file: the project name cannot be
  // rendered, which is the state a broken compose file leaves. Lock cases need flock and
  // run on scratch (hold-cmd); these are the pending record and the plain release.
  const tool = (b: Box, cmd: string) => {
    mkdirSync(join(b.w, "bin"), { recursive: true });
    writeFileSync(join(b.w, "bin/tier2-hold"), HOLD_TOOL);
    const r = Bun.spawnSync([BASH, join(b.w, "bin/tier2-hold"), cmd], { env: { HOME: join(b.w, "home"), LC_ALL: "C" } });
    return { code: r.exitCode, out: r.stdout.toString() + r.stderr.toString() };
  };
  const release = (b: Box) => tool(b, "release");

  // The third OpenAI read, 2026-11-25: release walked every dir, status only the one the
  // compose file named, and the runbook tells the operator to wait on status.
  test("status names every runs dir, and a pending restart in the one that has it", () => {
    const b = box();
    for (const p of ["alpha", "beta"]) mkdirSync(join(b.w, "home/tier2", p), { recursive: true });
    writeFileSync(join(b.w, "home/tier2/beta/.pending-restart"), "x\n");
    const r = tool(b, "status");
    expect(r.code).toBe(0);
    expect(r.out).toContain(`snapshot lock: free in ${join(b.w, "home/tier2/alpha")}\n`);
    expect(r.out).toContain(`snapshot lock: free in ${join(b.w, "home/tier2/beta")}\n`);
    expect(r.out).toContain(`pending restart: ${join(b.w, "home/tier2/beta/.pending-restart")}`);
    expect(r.out).not.toContain("alpha/.pending-restart");
  });

  test("status with no runs root says no run has used it", () => {
    const b = box();
    expect(tool(b, "status").out).toContain("snapshot lock: free, no run has used");
  });

  test("a runs root that cannot be listed: status says unknown and release refuses, the hold stays", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    mkdirSync(join(b.w, "home/tier2/alpha"), { recursive: true });
    writeFileSync(join(b.w, "home/tier2/alpha/.pending-restart"), "x\n");
    chmodSync(join(b.w, "home/tier2"), 0o000);
    const s = tool(b, "status");
    const r = release(b);
    chmodSync(join(b.w, "home/tier2"), 0o755);
    expect(s.out).toContain("snapshot lock: unknown");
    expect(r.code).toBe(1);
    expect(r.out).toContain("cannot be listed, so no snapshot lock can be checked");
    expect(held(b)).toBe(true);
  });

  test("a runs root that is a link is not walked: release refuses", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    mkdirSync(join(b.w, "home/elsewhere/alpha"), { recursive: true });
    symlinkSync(join(b.w, "home/elsewhere"), join(b.w, "home/tier2"));
    const r = release(b);
    expect(r.code).toBe(1);
    expect(held(b)).toBe(true);
  });

  // The OpenAI reads, 2026-11-25: release found the lock and the pending record through the
  // compose project name, which can change after the run that wrote the hold.
  test("a pending restart in any project's dir refuses the release, and the hold stays", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    mkdirSync(join(b.w, "home/tier2/some-other-name"), { recursive: true });
    writeFileSync(join(b.w, "home/tier2/some-other-name/.pending-restart"), "x\n");
    const r = release(b);
    expect(r.code).toBe(1);
    expect(r.out).toContain("some-other-name/.pending-restart: bring the stack back first");
    expect(held(b)).toBe(true);
  });

  test("with no run anywhere, a hold is released even when compose cannot render", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    mkdirSync(join(b.w, "home/tier2/some-other-name"), { recursive: true });
    const r = release(b);
    expect(r.code).toBe(0);
    expect(r.out).toContain("tier2-hold: released");
    expect(held(b)).toBe(false);
  });

  test("no runs dir at all: released", () => {
    const b = box();
    writeFileSync(b.hold, "hold 1764000000\n");
    expect(release(b).code).toBe(0);
    expect(held(b)).toBe(false);
  });
});

// *--- Tests: the order of the steps in each script ---*

// The parts that need the whole script on the box (docker, flock, a real stack) are drilled
// on scratch (Plans/f7). These pin the order the drills rely on.
describe("source order: where each script checks and writes the hold", () => {
  const at = (text: string, needle: string) => {
    const i = text.indexOf(needle);
    if (i < 0) throw new Error(`not found: ${needle}`);
    return i;
  };

  test("tier2-snapshot refuses a hold before its guard and before anything changes", () => {
    const refuse = at(SNAPSHOT, 'die "a backup hold is in place');
    expect(refuse).toBeLessThan(at(SNAPSHOT, "\nguard\n"));
    expect(refuse).toBeLessThan(at(SNAPSHOT, 'flock -n 9 || die "another tier2-snapshot is running"'));
    expect(refuse).toBeLessThan(at(SNAPSHOT, "docker compose config -q"));
    expect(SNAPSHOT.slice(at(SNAPSHOT, 'HOLD=$DEPLOY/state/tier2/HOLD'), refuse)).toContain('[ -e "$HOLD" ] || [ -L "$HOLD" ]');
  });

  // The OpenAI read, 2026-11-25: a run that waited at the lock never looked again.
  test("tier2-snapshot checks the hold again under its lock, before it reads PENDING or writes anything", () => {
    const again = at(SNAPSHOT, 'die "a backup hold appeared while this run started');
    expect(again).toBeGreaterThan(at(SNAPSHOT, 'flock -n 9 || die "another tier2-snapshot is running"'));
    expect(again).toBeLessThan(at(SNAPSHOT, 'if [ -e "$OUT/.pending-restart" ]; then'));
    expect(again).toBeLessThan(at(SNAPSHOT, "if ! write_hold; then"));
    expect(SNAPSHOT.slice(at(SNAPSHOT, 'flock -n 9 || die "another tier2-snapshot is running"'), again)).toContain('[ -e "$HOLD" ] || [ -L "$HOLD" ]');
  });

  test("tier2-snapshot writes the hold after PENDING and before the stop", () => {
    const write = at(SNAPSHOT, "if ! write_hold; then");
    expect(write).toBeGreaterThan(at(SNAPSHOT, 'printf \'%s %s\\n\' "$stamp" "$fp" >"$PENDING"'));
    expect(write).toBeLessThan(at(SNAPSHOT, "docker compose stop -t 120"));
  });

  test("only restart() removes the hold, and the watchdog sets HOLD before it calls restart()", () => {
    expect(SNAPSHOT.split('rm -f -- "$HOLD"').length).toBe(2);
    expect(fn(SNAPSHOT, "restart")).toContain('rm -f -- "$HOLD"');
    const watchdog = SNAPSHOT.slice(at(SNAPSHOT, 'if [ "${1-}" = --watchdog ]; then'), at(SNAPSHOT, "# *--- Preflight ---*"));
    expect(at(watchdog, "HOLD=$PWD/state/tier2/HOLD")).toBeLessThan(at(watchdog, "restart &&"));
  });

  test("tier2-start refuses a hold before compose does anything", () => {
    expect(at(START, "if [ -e state/tier2/HOLD ] || [ -L state/tier2/HOLD ]; then")).toBeLessThan(at(START, "docker compose config -q"));
  });

  test("tier2-hold release checks the lock and PENDING before it removes the hold", () => {
    const rm = at(HOLD_TOOL, 'rm -f -- "$HOLD"');
    expect(at(HOLD_TOOL, 'flock -n "$lock" || die')).toBeLessThan(rm);
    expect(at(HOLD_TOOL, 'if [ -e "$d/.pending-restart" ]; then\n        die')).toBeLessThan(rm);
    expect(at(HOLD_TOOL, "runs_readable || die")).toBeLessThan(at(HOLD_TOOL, 'flock -n "$lock" || die'));
    expect(HOLD_TOOL).not.toContain("docker compose config");
    expect(at(HOLD_TOOL, '[ "$(id -u)" -ne 0 ] || die')).toBeLessThan(rm);
  });
});
