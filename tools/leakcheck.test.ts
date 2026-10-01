// *****************************************************************************
// *Title: leakcheck.test*
// *Author: Kyle Versluis*
// *Description: Tests for leakcheck and its git hooks, run in a scratch repo.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

// *--- Configuration ---*

const REAL_ROOT = resolve(import.meta.dir, "..");
// The one literal in the scratch denylist. It is not under the fixtures directory
// here, so every class applies to the files that carry it.
const LEAK = "fixture-deny-host";
const ZERO = "0".repeat(40);

let scratch = "";
let repo = "";
let env: Record<string, string> = {};

interface Result {
  code: number;
  out: string;
  err: string;
}

// *--- Helper Functions ---*

/** Run a command in the scratch repo with a clean git environment. */
function run(args: string[], opts: { cwd?: string; stdin?: string | Buffer } = {}): Result {
  const p = Bun.spawnSync(args, {
    cwd: opts.cwd ?? repo,
    env,
    stdin: opts.stdin === undefined ? undefined : Buffer.from(opts.stdin),
  });
  return { code: p.exitCode, out: p.stdout.toString(), err: p.stderr.toString() };
}

const git = (...args: string[]) => run(["git", ...args]);
const check = (...args: string[]) => run([process.execPath, join(repo, "tools", "leakcheck.ts"), ...args]);
const output = (r: Result) => r.out + r.err;

/** Write a file under the repo and stage it. */
function stage(name: string, content: string | Buffer): void {
  writeFileSync(join(repo, name), content);
  expect(git("add", name).code).toBe(0);
}

/** Drop the index and the named working files, so the next test starts clean. */
function unstage(...names: string[]): void {
  git("reset", "-q");
  for (const n of names) rmSync(join(repo, n), { force: true });
}

/** Run the staged check against another denylist, then put the scratch one back. */
function stagedWith(denylist: string | Buffer): Result {
  const path = join(repo, "tools", "leak-denylist.txt");
  const saved = readFileSync(path);
  writeFileSync(path, denylist);
  try {
    return check("--staged");
  } finally {
    writeFileSync(path, saved);
  }
}

// *--- Setup ---*

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), "leakcheck-"));
  repo = join(scratch, "repo");
  mkdirSync(repo);
  // No global or system git config: no signing, no hooksPath, nothing from this machine.
  writeFileSync(
    join(scratch, "gitconfig"),
    "[user]\n\tname = leakcheck test\n\temail = test@example.test\n" +
      "[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
  );
  env = { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" };
  env.GIT_CONFIG_GLOBAL = join(scratch, "gitconfig");
  env.GIT_CONFIG_NOSYSTEM = "1";
  cpSync(join(REAL_ROOT, "tools", "leakcheck.ts"), join(repo, "tools", "leakcheck.ts"));
  cpSync(join(REAL_ROOT, "tools", "hooks"), join(repo, "tools", "hooks"), { recursive: true });
  writeFileSync(join(repo, "tools", "leak-denylist.txt"), `${LEAK}   # the only literal, with a trailing comment\n`);
  expect(git("init", "-q").code).toBe(0);
  const installed = run(["bash", "tools/hooks/install.sh"]);
  expect(installed.out).toContain("verified: git reaches the stubs");
  expect(installed.code).toBe(0);
  // The scanner's own source quotes the scratch literal in its self-test, so tools/
  // stays untracked here, as the denylist does in the real repo.
  writeFileSync(join(repo, ".gitignore"), "/tools/\n");
  writeFileSync(join(repo, "README.md"), "# scratch\n");
  writeFileSync(join(repo, "link.txt"), "a regular file for now\n");
  expect(git("add", "-A").code).toBe(0);
  const first = git("commit", "-q", "-m", "initial");
  expect(output(first)).toContain("leakcheck: clean");
  expect(first.code).toBe(0);
  expect(git("init", "-q", "--bare", join(scratch, "origin.git")).code).toBe(0);
  expect(git("remote", "add", "origin", join(scratch, "origin.git")).code).toBe(0);
});

afterAll(() => {
  if (scratch) rmSync(scratch, { recursive: true, force: true });
});

// *--- Tests ---*

describe("self-test and arguments", () => {
  test("the real fixtures pass", () => {
    const r = run([process.execPath, "tools/leakcheck.ts", "--self-test"], { cwd: REAL_ROOT });
    expect(r.out).toContain("self-test: pass");
    expect(r.code).toBe(0);
  });

  test("the scanner's own files pass its pattern rules, as the pre-commit hook reads them", () => {
    const own = ["tools/leakcheck.ts", "tools/leakcheck.test.ts", "tools/README.md", "tools/hooks"];
    const r = run([process.execPath, "tools/leakcheck.ts", "--no-denylist", "--paths", ...own], { cwd: REAL_ROOT });
    expect(r.out).toBe("");
    expect(r.code).toBe(0);
  });

  test.each([
    [["--bogus"], "unknown argument"],
    [["--staged", "--pushed"], "one mode at a time"],
    [["--paths"], "--paths needs"],
    [["--paths", "no-such-file"], "no such path"],
    [["--message"], "--message needs"],
    [["--message", "no-such-file"], "no such file"],
    [["--message", "."], "needs a regular file"],
    [["--message", "--staged"], "one mode at a time"],
    [["--message", "--no-denylist"], "--message needs"],
    [["--only", "bogus"], "--only takes"],
    [["--only", "denylist", "--no-denylist"], "nothing to check"],
    [["--remote"], "--remote needs"],
    [["--pushed", "--remote", "-x"], "--remote needs"],
    [["--remote", "origin"], "--remote only applies"],
  ])("%j exits 2", (args, message) => {
    const r = check(...(args as string[]));
    expect(r.err).toContain(message);
    expect(r.code).toBe(2);
  });

  test("an empty denylist is a setup error", () => {
    const r = stagedWith("# nothing but comments\n\n");
    expect(r.err).toContain("no usable entries");
    expect(r.code).toBe(2);
  });

  test("a UTF-16 denylist is decoded, not read as garbage", () => {
    stage("deny16.md", `the host ${LEAK} again\n`);
    const r = stagedWith(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`${LEAK}\n`, "utf16le")]));
    unstage("deny16.md");
    expect(r.out).toContain("deny16.md:1: denylist#1");
    expect(r.code).toBe(1);
  });

  test("a CRLF denylist keeps its trailing comment out of the entry", () => {
    stage("crlf-deny.md", `the host ${LEAK} again\n`);
    const r = stagedWith(`${LEAK}   # trailing comment\r\n`);
    unstage("crlf-deny.md");
    expect(r.out).toContain("crlf-deny.md:1: denylist#1");
    expect(r.code).toBe(1);
  });

  test("a denylist that is not text is a setup error", () => {
    const r = stagedWith(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0xff, 1]));
    expect(r.err).toContain("is not text");
    expect(r.code).toBe(2);
  });

  test("a control character in a denylist entry is a setup error", () => {
    const r = stagedWith(`${LEAK}\nbell\x07entry\n`);
    expect(r.err).toContain("line 2: control or undecodable character");
    expect(r.code).toBe(2);
  });

  test("a NUL in a denylist is a setup error, not two entries fused into one", () => {
    const r = stagedWith(Buffer.concat([Buffer.from("probe-deny-host"), Buffer.from([0]), Buffer.from("probe.lab.example\n")]));
    expect(r.err).toContain("line 1: control or undecodable character");
    expect(r.code).toBe(2);
  });

  test("a UTF-8 byte order mark does not hide the first denylist entry", () => {
    stage("bom.md", `the host ${LEAK} again\n`);
    const r = stagedWith(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`${LEAK}\n`)]));
    unstage("bom.md");
    expect(r.out).toContain("bom.md:1: denylist#1");
    expect(r.code).toBe(1);
  });
});

describe("--staged", () => {
  test("clean index", () => {
    stage("clean.md", "# nothing to see\n");
    const r = check("--staged");
    unstage("clean.md");
    // The index copy plus the author and committer identity.
    expect(r.err).toContain("clean, 2 scanned");
    expect(r.code).toBe(0);
  });

  test("a literal in the content, matched through the inline-comment denylist entry", () => {
    stage("notes.md", `# notes\n\nthe host ${LEAK} again\n`);
    const r = check("--staged");
    unstage("notes.md");
    expect(r.out).toContain("notes.md:3: denylist#1");
    expect(r.code).toBe(1);
  });

  test("a literal in a UTF-16 file", () => {
    stage("wide.txt", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`first\n${LEAK} second\n`, "utf16le")]));
    const r = check("--staged");
    unstage("wide.txt");
    expect(r.out).toContain("wide.txt:2: denylist#1");
    expect(r.code).toBe(1);
  });

  test("a stray NUL does not hide a text file from the pattern rules", () => {
    // leakcheck: allow (a test input, not a credential)
    stage("nul.sh", Buffer.concat([Buffer.from("echo start\n"), Buffer.from([0]), Buffer.from("curl -u admin:x https://a/\n")]));
    const r = check("--staged");
    unstage("nul.sh");
    expect(r.out).toContain("nul.sh:2: argv-user");
    expect(r.err).not.toContain("binary");
    expect(r.code).toBe(1);
  });

  test("a literal inside a binary body reports line 0", () => {
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49]);
    stage("blob.png", Buffer.concat([png, Buffer.from(`tEXt ${LEAK}`), Buffer.from([0, 0, 0xae, 0x42])]));
    const r = check("--staged");
    unstage("blob.png");
    expect(r.out).toContain("blob.png:0: denylist#1");
    expect(r.err).toContain("1 binary");
    expect(r.code).toBe(1);
  });

  test("a literal in the file name", () => {
    stage(`${LEAK}.md`, "# clean content\n");
    const r = check("--staged");
    unstage(`${LEAK}.md`);
    expect(r.out).toContain(`${LEAK}.md:0: denylist#1`);
    expect(r.code).toBe(1);
  });

  test("a submodule entry is counted, not scanned, and its path still meets the denylist", () => {
    const head = git("rev-parse", "HEAD").out.trim();
    expect(git("update-index", "--add", "--cacheinfo", `160000,${head},sub`).code).toBe(0);
    const r = check("--staged");
    expect(git("update-index", "--add", "--cacheinfo", `160000,${head},vendor/${LEAK}`).code).toBe(0);
    const r2 = check("--staged");
    git("reset", "-q");
    expect(r.err).toContain("1 submodule(s) not scanned");
    expect(r.code).toBe(0);
    expect(r2.out).toContain(`vendor/${LEAK}:0: denylist#1`);
    expect(r2.code).toBe(1);
  });

  test("a file turned into a symlink is scanned as its target", () => {
    rmSync(join(repo, "link.txt"));
    symlinkSync(LEAK, join(repo, "link.txt"));
    expect(git("add", "link.txt").code).toBe(0);
    const r = check("--staged");
    git("reset", "-q", "--hard");
    expect(r.out).toContain("link.txt:1: denylist#1");
    expect(r.code).toBe(1);
  });
});

describe("the tracked default", () => {
  test("a tracked file missing from the working tree is scanned from the index", () => {
    stage("gone.md", `${LEAK}\n`);
    rmSync(join(repo, "gone.md"));
    const r = check();
    git("reset", "-q");
    expect(r.out).toContain("gone.md:1: denylist#1");
    expect(r.err).toContain("index copy scanned: gone.md");
    expect(r.code).toBe(1);
  });
});

describe("parsers", () => {
  test("a flow sequence wrapped over more than 40 lines is rebuilt", () => {
    const pad = Array.from({ length: 60 }, () => '  "--verbose",');
    const body = ["command: [", '  "curl",', ...pad, '  "-u",', '  "admin:x",', '  "https://a.example.test"', "]"];
    stage("long-flow.yml", body.join("\n") + "\n");
    const r = check("--staged");
    unstage("long-flow.yml");
    expect(r.out).toContain("long-flow.yml:63: argv-user");
    expect(r.code).toBe(1);
  });

  test("an unclosed bracket on every line stays linear", () => {
    const body = Array.from({ length: 20000 }, (_, k) => `echo [step${k}`).join("\n") + "\n";
    stage("stray.sh", body);
    const t0 = performance.now();
    const r = check("--staged");
    const ms = performance.now() - t0;
    unstage("stray.sh");
    expect(r.code).toBe(0);
    expect(ms).toBeLessThan(5000);
  });

  // dotenv files hold assignments; a .env-named script is shell and gets the argv rules.
  test.each([
    [".envrc", 1],
    [".env.sh", 1],
    [".env-setup.sh", 1],
    [".environment", 1],
    [".env", 0],
    [".env.example", 0],
    [".env.production.local", 0],
  ])("%s exits %d", (name, code) => {
    const dir = mkdtempSync(join(scratch, "dotenv-"));
    // leakcheck: allow (a test input, not a credential)
    writeFileSync(join(dir, name), "curl -u admin:x https://a.example.test/\n");
    const r = check("--paths", join(dir, name));
    expect(r.code).toBe(code);
    if (code) expect(r.out).toContain(`${name}:1: argv-user`);
  });

  test.each([
    ["joined.ps1", "some-tool --token`\n  fixture-pass\n"],
    ["joined.cmd", "some-tool --password^\n  fixture-pass\n"],
  ])("%s joins a continuation mark with no space before it", (name, body) => {
    const dir = mkdtempSync(join(scratch, "join-"));
    writeFileSync(join(dir, name), body);
    const r = check("--paths", join(dir, name));
    expect(r.out).toContain(`${name}:1: argv-password-opt`);
    expect(r.code).toBe(1);
  });

  test("--paths names each entry it skips, and naming one scans it", () => {
    const dir = mkdtempSync(join(scratch, "walk-"));
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "hidden.txt"), `${LEAK}\n`);
    writeFileSync(join(dir, "seen.txt"), "clean\n");
    const r = check("--paths", dir);
    const direct = check("--paths", join(dir, "node_modules"));
    expect(r.err).toContain(`${basename(dir)}/node_modules. Name one directly to scan it.`);
    expect(r.code).toBe(0);
    expect(direct.out).toContain("hidden.txt:1: denylist#1");
    expect(direct.code).toBe(1);
  });
});

describe("--message", () => {
  test("a literal in the message", () => {
    const path = join(scratch, "msg.txt");
    writeFileSync(path, `docs: mention ${LEAK}\n`);
    const r = check("--message", path);
    expect(r.out).toContain("commit-message:1: denylist#1");
    expect(r.code).toBe(1);
  });

  test("the diff below the scissors line of a verbose commit is not the message", () => {
    const path = join(scratch, "msg-verbose.txt");
    writeFileSync(
      path,
      `docs: clean subject\n\n# ------------------------ >8 ------------------------\n` +
        `# Do not modify or remove the line above.\ndiff --git a/f b/f\n+${LEAK}\n`,
    );
    const r = check("--message", path);
    expect(r.code).toBe(0);
  });

  test("text below a scissors line that git would store is scanned", () => {
    const path = join(scratch, "msg-scissors.txt");
    writeFileSync(path, `docs: clean subject\n\n# ------------------------ >8 ------------------------\n${LEAK}\n`);
    const r = check("--message", path);
    expect(r.out).toContain("commit-message:4: denylist#1");
    expect(r.code).toBe(1);
  });
});

describe("hooks", () => {
  test("a leaky staged file blocks the commit", () => {
    stage("leak.md", `${LEAK}\n`);
    const r = git("commit", "-q", "-m", "docs: add notes");
    unstage("leak.md");
    expect(output(r)).toContain("leak.md:1: denylist#1");
    expect(r.code).not.toBe(0);
  });

  test("a leaky message blocks the commit", () => {
    stage("fine.md", "# fine\n");
    const r = git("commit", "-q", "-m", `docs: about ${LEAK}`);
    unstage("fine.md");
    expect(output(r)).toContain("commit-message:1: denylist#1");
    expect(r.code).not.toBe(0);
    expect(git("log", "-1", "--format=%s").out.trim()).toBe("initial");
  });

  test("a leaky line below a scissors line in a -F message blocks the commit", () => {
    stage("fine.md", "# fine\n");
    const path = join(scratch, "msg-f.txt");
    writeFileSync(path, `docs: fine\n\n# ------------------------ >8 ------------------------\n${LEAK}\n`);
    const r = git("commit", "-q", "-F", path);
    unstage("fine.md");
    expect(output(r)).toContain("commit-message:4: denylist#1");
    expect(r.code).not.toBe(0);
  });

  test("a leaky author identity blocks the commit", () => {
    stage("fine.md", "# fine\n");
    const r = git("-c", `user.email=kyle@${LEAK}.local`, "commit", "-q", "-m", "docs: fine");
    unstage("fine.md");
    expect(output(r)).toContain("identity:1: denylist#1");
    expect(r.code).not.toBe(0);
  });

  test("the comment lines of an editor template are not the message", () => {
    // An untracked file named for the literal is listed in the template git opens in
    // the editor. Under the strip cleanup git drops those lines, so the hook must too.
    const editor = join(scratch, "editor.sh");
    writeFileSync(editor, `#!/bin/sh\nprintf 'docs: subject\\n' | cat - "$1" > "$1.tmp" && mv "$1.tmp" "$1"\n`);
    chmodSync(editor, 0o755);
    stage("fine.md", "# fine\n");
    writeFileSync(join(repo, `${LEAK}.md`), "untracked\n");
    const r = git("-c", `core.editor=${editor}`, "commit", "-q");
    rmSync(join(repo, `${LEAK}.md`));
    expect(output(r)).toContain("leakcheck: clean");
    expect(r.code).toBe(0);
    expect(git("log", "-1", "--format=%s").out.trim()).toBe("docs: subject");
    expect(git("reset", "-q", "--hard", "HEAD~1").code).toBe(0);
  });

  test("a -m message keeps its comment lines, so a leak behind a # is still caught", () => {
    stage("fine.md", "# fine\n");
    const r = git("commit", "-q", "-m", `#42 rename ${LEAK}`);
    unstage("fine.md");
    expect(output(r)).toContain("commit-message:1: denylist#1");
    expect(r.code).not.toBe(0);
  });

  test("under core.commentChar=auto the comment character git picked is the one dropped", () => {
    // A subject that starts with # makes git comment out its template with another
    // character. The untracked file named for the literal is listed in that template.
    stage("fine.md", "# fine\n");
    writeFileSync(join(repo, `${LEAK}.md`), "untracked\n");
    const auto = ["-c", "core.commentChar=auto", "-c", "core.editor=true", "commit", "-q", "-e", "-m"];
    const kept = git(...auto, `#12 rename ${LEAK}`);
    const r = git(...auto, "#12 fix the parser");
    rmSync(join(repo, `${LEAK}.md`));
    expect(output(kept)).toContain("commit-message:1: denylist#1");
    expect(kept.code).not.toBe(0);
    expect(output(r)).toContain("leakcheck: clean");
    expect(r.code).toBe(0);
    expect(git("log", "-1", "--format=%s").out.trim()).toBe("#12 fix the parser");
    expect(git("reset", "-q", "--hard", "HEAD~1").code).toBe(0);
  });

  test("a hook that is not executable blocks instead of skipping", () => {
    stage("fine.md", "# fine\n");
    chmodSync(join(repo, "tools", "hooks", "pre-commit"), 0o644);
    const r = git("commit", "-q", "-m", "docs: fine");
    chmodSync(join(repo, "tools", "hooks", "pre-commit"), 0o755);
    unstage("fine.md");
    expect(output(r)).toContain("missing or not executable");
    expect(r.code).not.toBe(0);
  });

  test("install.sh refuses to overwrite a foreign hook and replaces its own symlink", () => {
    const stub = join(repo, ".git", "hooks", "pre-push");
    const saved = readFileSync(stub, "utf8");
    writeFileSync(stub, "#!/bin/sh\nexit 0\n");
    const refused = run(["bash", "tools/hooks/install.sh"]);
    expect(refused.err).toContain("not a leakcheck stub");
    expect(refused.code).toBe(1);
    expect(readFileSync(stub, "utf8")).toBe("#!/bin/sh\nexit 0\n");
    rmSync(stub);
    symlinkSync("../../tools/hooks/pre-push", stub);
    const replaced = run(["bash", "tools/hooks/install.sh"]);
    expect(replaced.code).toBe(0);
    expect(readFileSync(stub, "utf8")).toBe(saved);
  });

  test("install.sh refuses a repo-level core.hooksPath", () => {
    expect(git("config", "core.hooksPath", join(scratch, "elsewhere")).code).toBe(0);
    const r = run(["bash", "tools/hooks/install.sh"]);
    git("config", "--unset", "core.hooksPath");
    expect(r.err).toContain("set at local scope");
    expect(r.err).toContain("Nothing installed");
    expect(r.code).toBe(2);
  });

  test("install.sh fails when a global core.hooksPath does not chain to the stubs", () => {
    const dir = join(scratch, "global-hooks");
    const names = ["pre-commit", "commit-msg", "pre-push"];
    mkdirSync(dir, { recursive: true });
    for (const name of names) {
      writeFileSync(join(dir, name), "#!/bin/sh\nexit 0\n");
      chmodSync(join(dir, name), 0o755);
    }
    expect(git("config", "--global", "core.hooksPath", dir).code).toBe(0);
    const silent = run(["bash", "tools/hooks/install.sh"]);
    // A dispatcher that runs the stub from the repo's own git dir passes the probe.
    for (const name of names) {
      writeFileSync(
        join(dir, name),
        `#!/bin/sh\nh="$(git rev-parse --absolute-git-dir)/hooks/${name}"\n[ -x "$h" ] && exec "$h" "$@"\nexit 0\n`,
      );
    }
    const chained = run(["bash", "tools/hooks/install.sh"]);
    git("config", "--global", "--unset", "core.hooksPath");
    expect(silent.err).toContain("does not chain");
    expect(silent.err).toContain("The hooks are NOT active");
    expect(silent.code).toBe(2);
    // macOS reports the temp dir through its /private realpath, so match the tail.
    expect(chained.out).toContain("verified: git reaches the stubs through ");
    expect(chained.out).toContain(`/${basename(dir)}, and a failing stub fails git\n`);
    expect(chained.code).toBe(0);
  });

  test("install.sh fails when a global dispatcher runs the stubs but drops their exit code", () => {
    const dir = join(scratch, "swallow-hooks");
    mkdirSync(dir, { recursive: true });
    for (const name of ["pre-commit", "commit-msg", "pre-push"]) {
      writeFileSync(join(dir, name), `#!/bin/sh\nh="$(git rev-parse --absolute-git-dir)/hooks/${name}"\n"$h" "$@"\nexit 0\n`);
      chmodSync(join(dir, name), 0o755);
    }
    expect(git("config", "--global", "core.hooksPath", dir).code).toBe(0);
    const r = run(["bash", "tools/hooks/install.sh"]);
    git("config", "--global", "--unset", "core.hooksPath");
    expect(r.err).toContain("came back as exit 0");
    expect(r.err).toContain("The hooks are NOT active");
    expect(r.code).toBe(2);
  });

  test("install.sh writes stubs into a linked worktree as well", () => {
    const wt = join(scratch, "wt");
    expect(git("worktree", "add", "-q", wt, "-b", "wt-branch").code).toBe(0);
    const r = run(["bash", "tools/hooks/install.sh"]);
    const stub = join(repo, ".git", "worktrees", "wt", "hooks", "pre-commit");
    const present = existsSync(stub);
    git("worktree", "remove", "--force", wt);
    git("branch", "-q", "-D", "wt-branch");
    expect(r.out).toContain(stub);
    expect(present).toBe(true);
    expect(r.code).toBe(0);
  });

  test("a clean commit and push pass", () => {
    stage("fine.md", "# fine\n");
    const c = git("commit", "-q", "-m", "docs: fine");
    expect(c.code).toBe(0);
    const p = git("push", "-q", "origin", "main");
    expect(output(p)).toContain("across 2 commit(s)");
    expect(p.code).toBe(0);
  });

  test("a push carrying a leak in an earlier commit is blocked, even after the fix", () => {
    stage("leak.md", `${LEAK}\n`);
    expect(git("commit", "-q", "--no-verify", "-m", "docs: add").code).toBe(0);
    const sha = git("rev-parse", "--short=7", "HEAD").out.trim();
    expect(git("rm", "-q", "leak.md").code).toBe(0);
    expect(git("commit", "-q", "--no-verify", "-m", "docs: remove").code).toBe(0);
    const p = git("push", "-q", "origin", "main");
    git("reset", "-q", "--hard", "origin/main");
    expect(output(p)).toContain(`${sha}:leak.md:1: denylist#1`);
    expect(p.code).not.toBe(0);
  });

  test("a --no-verify commit that stored the text below a scissors line is blocked at push", () => {
    stage("fine2.md", "# fine\n");
    const path = join(scratch, "msg-stored.txt");
    writeFileSync(path, `docs: fine\n\n# ------------------------ >8 ------------------------\n${LEAK}\n`);
    expect(git("commit", "-q", "--no-verify", "-F", path).code).toBe(0);
    const sha = git("rev-parse", "--short=7", "HEAD").out.trim();
    const p = git("push", "-q", "origin", "main");
    git("reset", "-q", "--hard", "origin/main");
    expect(output(p)).toContain(`${sha}:message:4: denylist#1`);
    expect(p.code).not.toBe(0);
  });

  test("a --no-verify commit with a leaky author name is blocked at push", () => {
    stage("fine3.md", "# fine\n");
    expect(git("commit", "-q", "--no-verify", `--author=${LEAK} x <a@b.test>`, "-m", "docs: fine").code).toBe(0);
    const sha = git("rev-parse", "--short=7", "HEAD").out.trim();
    const p = git("push", "-q", "origin", "main");
    git("reset", "-q", "--hard", "origin/main");
    expect(output(p)).toContain(`${sha}:identity:1: denylist#1`);
    expect(p.code).not.toBe(0);
  });

  test("a replace ref does not hide a leaky commit from the push check", () => {
    const base = git("rev-parse", "origin/main").out.trim();
    stage("leak4.md", `${LEAK}\n`);
    expect(git("commit", "-q", "--no-verify", "-m", "docs: add").code).toBe(0);
    const leaky = git("rev-parse", "HEAD").out.trim();
    const sha = git("rev-parse", "--short=7", "HEAD").out.trim();
    // A stand-in with the same parent and the clean tree. Push still sends the original.
    const stand = git("commit-tree", `${base}^{tree}`, "-p", base, "-m", "docs: add").out.trim();
    expect(git("replace", leaky, stand).code).toBe(0);
    const p = git("push", "-q", "origin", "main");
    git("replace", "-d", leaky);
    git("reset", "-q", "--hard", "origin/main");
    expect(output(p)).toContain(`${sha}:leak4.md:1: denylist#1`);
    expect(p.code).not.toBe(0);
  });

  test("an annotated tag with a leaky message is blocked", () => {
    const head = git("rev-parse", "origin/main").out.trim();
    expect(git("tag", "-a", "v-leak", "-m", `release at ${LEAK}`, head).code).toBe(0);
    const tag = git("rev-parse", "v-leak").out.trim().slice(0, 7);
    const p = git("push", "-q", "origin", "v-leak");
    git("tag", "-d", "v-leak");
    expect(output(p)).toContain(`${tag}:tag:6: denylist#1`);
    expect(output(p)).toContain("across 0 commit(s) and 1 tag(s)");
    expect(p.code).not.toBe(0);
    expect(git("ls-remote", "--tags", "origin").out).toBe("");
  });

  test("a ref named for a literal is blocked before it reaches the remote", () => {
    const p = git("push", "-q", "origin", `main:fix/${LEAK}`);
    expect(output(p)).toContain(`ref:refs/heads/fix/${LEAK}:0: denylist#1`);
    expect(output(p)).toContain("across 0 commit(s)");
    expect(p.code).not.toBe(0);
    expect(git("ls-remote", "--heads", "origin", `fix/${LEAK}`).out).toBe("");
  });

  test("a clean annotated tag passes and a lightweight tag is not a tag object", () => {
    const head = git("rev-parse", "origin/main").out.trim();
    expect(git("tag", "-a", "v-clean", "-m", "release", head).code).toBe(0);
    expect(git("tag", "v-light", head).code).toBe(0);
    const a = git("push", "-q", "origin", "v-clean");
    const l = git("push", "-q", "origin", "v-light");
    expect(output(a)).toContain("and 1 tag(s)");
    expect(a.code).toBe(0);
    expect(output(l)).not.toContain("tag(s)");
    expect(l.code).toBe(0);
  });
});

describe("--pushed", () => {
  test("a deleted ref pushes nothing", () => {
    const head = git("rev-parse", "HEAD").out.trim();
    const r = check("--pushed");
    const r2 = run([process.execPath, join(repo, "tools", "leakcheck.ts"), "--pushed"], {
      stdin: `(delete) ${ZERO} refs/heads/gone ${head}\n`,
    });
    expect(r.code).toBe(0);
    expect(r2.err).toContain("across 0 commit(s)");
    expect(r2.code).toBe(0);
  });

  test("a remote sha the clone has never seen is bounded by what the destination lists", () => {
    stage("later.md", `${LEAK}\n`);
    expect(git("commit", "-q", "--no-verify", "-m", "docs: later").code).toBe(0);
    const head = git("rev-parse", "HEAD").out.trim();
    const stdin = `refs/heads/main ${head} refs/heads/main ${"f".repeat(40)}\n`;
    const scanner = [process.execPath, join(repo, "tools", "leakcheck.ts"), "--pushed"];
    const bounded = run([...scanner, "--remote", "origin"], { stdin });
    // Without the remote name, the whole history of the ref is the only safe bound.
    const whole = run(scanner, { stdin });
    git("reset", "-q", "--hard", "origin/main");
    expect(bounded.out).toContain(":later.md:1: denylist#1");
    expect(bounded.err).toContain("across 1 commit(s)");
    expect(bounded.code).toBe(1);
    expect(whole.err).not.toContain("across 1 commit(s)");
    expect(whole.code).toBe(1);
  });

  test("a pushed commit with a submodule entry passes with the entry counted", () => {
    const base = git("rev-parse", "origin/main").out.trim();
    expect(git("update-index", "--add", "--cacheinfo", `160000,${base},sub`).code).toBe(0);
    expect(git("commit", "-q", "-m", "build: add sub").code).toBe(0);
    const head = git("rev-parse", "HEAD").out.trim();
    const r = run([process.execPath, join(repo, "tools", "leakcheck.ts"), "--pushed"], {
      stdin: `refs/heads/main ${head} refs/heads/main ${base}\n`,
    });
    git("reset", "-q", "--hard", "origin/main");
    expect(r.err).toContain("across 1 commit(s), 1 submodule(s) not scanned");
    expect(r.code).toBe(0);
  });
});

describe("a second remote", () => {
  test("does not inherit what --no-verify pushed to the first", () => {
    stage("leak2.md", `${LEAK}\n`);
    expect(git("commit", "-q", "--no-verify", "-m", "docs: add").code).toBe(0);
    expect(git("push", "-q", "--no-verify", "origin", "main").code).toBe(0);
    const sha = git("rev-parse", "--short=7", "HEAD").out.trim();
    expect(git("init", "-q", "--bare", join(scratch, "mirror.git")).code).toBe(0);
    expect(git("remote", "add", "mirror", join(scratch, "mirror.git")).code).toBe(0);
    const named = git("push", "-q", "mirror", "main");
    const url = git("push", "-q", join(scratch, "mirror.git"), "main");
    expect(output(named)).toContain(`${sha}:leak2.md:1: denylist#1`);
    expect(named.code).not.toBe(0);
    expect(output(url)).toContain(`${sha}:leak2.md:1: denylist#1`);
    expect(url.code).not.toBe(0);
    expect(git("ls-remote", "--heads", "mirror").out).toBe("");
  });

  test("a remote moved to a new URL is asked what it holds, not judged by its old refs", () => {
    stage("leak3.md", `${LEAK}\n`);
    expect(git("commit", "-q", "--no-verify", "-m", "docs: add").code).toBe(0);
    expect(git("push", "-q", "--no-verify", "origin", "main").code).toBe(0);
    const sha = git("rev-parse", "--short=7", "HEAD").out.trim();
    const old = git("remote", "get-url", "origin").out.trim();
    const moved = join(scratch, "moved.git");
    expect(git("init", "-q", "--bare", moved).code).toBe(0);
    expect(git("remote", "set-url", "origin", moved).code).toBe(0);
    const p = git("push", "-q", "origin", "main");
    expect(git("remote", "set-url", "origin", old).code).toBe(0);
    expect(output(p)).toContain(`${sha}:leak3.md:1: denylist#1`);
    expect(p.code).not.toBe(0);
    expect(git("ls-remote", "--heads", moved).out).toBe("");
  });
});
