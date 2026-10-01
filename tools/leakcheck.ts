#!/usr/bin/env bun
// *****************************************************************************
// *Title: leakcheck*
// *Author: Kyle Versluis*
// *Description: Keep lab identifiers and argv secrets out of git.*
// *****************************************************************************

// *--- Imports ---*

import { existsSync, lstatSync, readdirSync, readFileSync, readlinkSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const FIXTURES = "tools/fixtures/leakcheck/";
const USAGE = `usage: bun tools/leakcheck.ts [mode] [options]

modes (one at most; default: every tracked file, as it sits in the working tree)
  --staged            the index copy of each staged file plus the author and
                      committer identity (the pre-commit hook)
  --message <file>    a commit message, identifier rules only (the commit-msg hook)
  --pushed            every commit and annotated tag named on stdin in pre-push
                      format: message, identity and changed files (the pre-push hook)
  --paths <p>...      files or directories on disk, ignored ones included
  --self-test         run the fixtures in ${FIXTURES}

options
  --remote <dest>     with --pushed: the remote being pushed to, by name or URL. A ref
                      it has not seen is bounded by the refs it lists (git ls-remote);
                      without --remote, such a ref scans its whole history
  --only <classes>    comma list of: denylist, mac, ipv4, ipv6, fingerprint, argv
  --no-denylist       skip the local denylist (a clone that has none)

denylist (tools/leak-denylist.txt, gitignored): one literal per line, # comments,
  @include <path> to pull in another list, @exclude <literal> to drop an entry
`;

const RULES = [
  "denylist",
  "mac-address",
  "private-ipv4",
  "private-ipv6",
  "ssh-fingerprint",
  "argv-user",
  "argv-header",
  "argv-body",
  "argv-env",
  "argv-agent-auth",
  "argv-secret-assign",
  "argv-password-opt",
  "argv-sshpass",
  "argv-mysql",
  "argv-net-user",
  "argv-url-userinfo",
] as const;
type Rule = (typeof RULES)[number];
type RuleClass = "denylist" | "mac" | "ipv4" | "ipv6" | "fingerprint" | "argv";
const CLASSES: RuleClass[] = ["denylist", "mac", "ipv4", "ipv6", "fingerprint", "argv"];
const DENY_ONLY = new Set<RuleClass>(["denylist"]);

// The fixture files the self-test runs. Only these are exempt from the pattern rules in
// the hooks; any other file under the fixtures directory is scanned like the rest.
const FIXTURE_FILES = new Set(["positive.md", "negative.md", "positive.yml", "negative.yml", ".env.example"]);
// Fenced blocks whose info string names prose or output. Every other fence, the
// unlabeled ones included, is read as command text.
const PROSE_FENCES = new Set(["text", "txt", "plain", "plaintext", "markdown", "md", "mermaid", "output", "log"]);
// A markdown fence is prose, but a fence nested inside it is a fence of its own.
const MARKDOWN_FENCES = new Set(["markdown", "md"]);
// A .env-named file with one of these extensions is a script, not a dotenv file.
const SHELL_EXT = /\.(?:sh|bash|zsh|ksh|fish|ps1|psm1|bat|cmd)$/i;
// Fence labels for the two shells whose continuation mark is not a backslash.
const PWSH_FENCES = new Set(["powershell", "pwsh", "ps1", "ps", "posh"]);
const CMD_FENCES = new Set(["bat", "batch", "cmd", "dosbatch", "winbatch", "batchfile"]);

// NOTE: an explicit, reviewable escape hatch for argv rules only. It goes on the
// flagged line, or in a comment on the line above, e.g. to quote an anti-pattern.
const ALLOW_MARK = /leakcheck:\s*allow(?![\w-])/i;
const ALLOW_ABOVE = /^\s*(?:>\s*)*(?:#|\/\/|<!--|;|rem\b).*leakcheck:\s*allow(?![\w-])/i;

// *--- Types ---*

interface DenyEntry {
  value: string;
  line: number;
}

interface Finding {
  path: string;
  line: number;
  rule: Rule;
  entry?: number;
}

interface Logical {
  text: string;
  starts: { offset: number; line: number }[];
  allow: boolean;
}

interface Item {
  text: string;
  line: number;
}

// PowerShell continues a line with a backtick and cmd with a caret. "" is any other
// shell, or one the file does not name.
type Shell = "pwsh" | "cmd" | "";

interface Scope {
  // Per line: inside the region the argv rules read.
  argv: boolean[];
  // Per line: the shell whose continuation mark applies.
  shell: Shell[];
}

interface Fence {
  char: string;
  len: number;
  indent: number;
  // Blockquote depth at the opener.
  depth: number;
  scan: boolean;
  // A markdown fence: a fence marker inside it opens a fence of its own.
  nested: boolean;
  yaml: boolean;
  shell: Shell;
  body: number[];
}

interface IpAllow {
  path?: RegExp;
  line: RegExp;
}

interface Source {
  label: string;
  path: string;
  read: () => Buffer | null;
  message?: boolean;
  // A submodule entry: its name meets the denylist, its contents live in another repo.
  gitlink?: boolean;
  // A ref name about to be published: only the name is checked.
  ref?: boolean;
  // Where to read from when `read` finds nothing: the index copy of a tracked file.
  fallback?: () => Buffer;
}

type Mode = "tracked" | "staged" | "message" | "pushed" | "paths" | "self-test";

interface Options {
  mode: Mode;
  paths: string[];
  message: string;
  remote: string;
  classes: Set<RuleClass>;
  denylist: boolean;
}

// *--- Class Patterns ---*

// Six octets with one separator style. The lookarounds reject windows inside longer
// colon-hex runs such as certificate fingerprints, while a label like "MAC:" may touch.
const MAC =
  /(?<![0-9a-f])(?<!(?<![0-9a-z])[0-9a-f]{2}[:-])[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}(?![:-]?[0-9a-f])/gi;
// macOS arp prints octets without their leading zero.
const MAC_SHORT = /(?<![0-9a-f:])[0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}(?![0-9a-f:])/gi;
// Cisco notation, and the Linux interface names that embed the address.
const MAC_DOTTED = /(?<![0-9a-f.])[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}(?![0-9a-f.])/gi;
const MAC_IFNAME = /\b(?:wlx|enx)([0-9a-f]{12})\b/gi;

// RFC 1918, carrier-grade NAT (also Tailscale) and link-local.
const PRIVATE_V4 =
  /(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3}(?!\d|\.\d)/g;
// The block definitions themselves are not lab addresses.
const V4_BLOCKS = new Set(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"]);
const V4_BLOCK_TEXT = new RegExp(
  String.raw`(?<![\d.])(?:${[...V4_BLOCKS].map((b) => b.replace(/[./]/g, "\\$&")).join("|")})(?!\d)`,
  "g",
);
const V4_LITERAL_ALLOW = new Set(["169.254.169.254"]);
const V4_ALLOW: IpAllow[] = [
  // The CIS benchmark's own example value, quoted in an upstream remediation.
  { path: /cis_ubuntu26-04\.yml$/, line: /Example settings: \[Upload\] URL=/ },
];
// PCI DSS requirement IDs share the dotted-quad shape. Only 10.x reaches PRIVATE_V4, and
// no requirement ID has a zero or a component above 12, so an address with either fails.
const PCI_KEY = /^(\s*)-\s*(["']?)pci_dss[\w.]*\2\s*:(.*)$/;
const PCI_ID = /^10(?:\.(?:[1-9]|1[0-2])){3}$/;

// A token that starts in link-local (fe80::/10) or unique-local (fc00::/7) space. isLabV6
// decides whether it is an address or prefix, and whether it names a network.
const PRIVATE_V6 = /(?<![\w:])(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2}):[0-9a-f:]*(?![\w:])/gi;
// The prefix each block starts with. With nothing after it, it names no network.
const V6_BLOCK_HEADS = new Set(["fe80", "fc00", "fd00"]);

// The forms ssh-keygen -l -E and the ssh client print: base64 with or without its pad,
// or colon-hex for MD5. A docker digest is lowercase. A bare digest with no prefix is out
// of reach.
const SSH_FP =
  /\b(?:SHA1:[A-Za-z0-9+/]{27}=?|SHA256:[A-Za-z0-9+/]{43}=?|SHA384:[A-Za-z0-9+/]{64}|SHA512:[A-Za-z0-9+/]{86}(?:==)?|MD5(?::[0-9a-fA-F]{2}){16})(?![A-Za-z0-9+/=:])/;

// *--- Argv Patterns ---*

// A command word may follow a path separator, so /var/ossec/bin/agent-auth counts.
const LEAD = String.raw`(?:^|[\s"'\x60(/\\])`;
const word = (w: string) => new RegExp(`${LEAD}(?:${w})(?=[\\s"']|$)`, "i");
const CMD = {
  curl: word(String.raw`curl(?:\.exe)?`),
  container: new RegExp(
    `${LEAD}(?:docker|podman|nerdctl)(?:-compose|\\.exe)?\\s(?:.*?\\s)?(?:exec|run|create|build)(?=\\s|$)`,
    "i",
  ),
  dockerLogin: new RegExp(`${LEAD}(?:docker|podman)(?:\\.exe)?\\s+login(?=\\s|$)`, "i"),
  agentAuth: word(String.raw`agent-auth(?:\.exe)?`),
  // env also matches a Dockerfile ENV; ARG is its sibling. Both bake the value into image history.
  assign: word(String.raw`sudo|env|arg|msiexec(?:\.exe)?|[\w.-]+\.msi`),
  sshpass: word("sshpass"),
  mysql: word(String.raw`(?:mysql|mariadb|mariabackup)[\w-]*(?:\.exe)?`),
  passTool: word(String.raw`hash\.sh|wazuh-passwords-tool(?:\.sh)?`),
  keystore: word("wazuh-keystore"),
  openssl: word(String.raw`openssl(?:\.exe)?`),
  netUser: new RegExp(`${LEAD}net1?(?:\\.exe)?\\s+user(?=\\s)`, "i"),
  netUse: new RegExp(`${LEAD}net1?(?:\\.exe)?\\s+use(?=\\s)`, "i"),
};

// An option and its value: attached or separated, quoted in part or in whole.
const opt = (flags: string) =>
  new RegExp(String.raw`(?:^|\s)(?:${flags})(?:\s+|=)?((?:"[^"]*"|'[^']*'|[^\s"'])+)`, "g");
// A short-flag cluster such as -skH. Only curl's no-argument flags may lead it, so an
// attached value such as -XPATCH never reads as a cluster that swallows the next flag.
const CURL_CLUSTER = "-[#0-46aBfgGiIjJklLMnNOpqRsSvVZ]*";
// -U is --proxy-user, which takes user:password the same way.
const CURL_USER = opt(String.raw`--user(?![\w-])|--proxy-user(?![\w-])|${CURL_CLUSTER}[uU]`);
const CURL_HEADER = opt(String.raw`--header|${CURL_CLUSTER}H`);
// -b NAME=VALUE sends a cookie. A value without = names a cookie file, which passes.
const CURL_COOKIE = opt(String.raw`--cookie(?![\w-])|${CURL_CLUSTER}b`);
const CURL_BEARER = /(?:^|\s)--oauth2-bearer(?:\s+|=)\S/g;
const CURL_DATA = opt(
  String.raw`--data(?:-raw|-binary|-urlencode|-ascii)?|--json|--form(?:-string)?|${CURL_CLUSTER}[dF]`,
);
const DOCKER_ENV = opt(String.raw`--env|-e`);
// A build argument is argv while the build runs and stays in the image history after it.
// --build-arg NAME alone forwards the caller's variable, and --build-arg-file names a file.
const BUILD_ARG = opt(String.raw`--build-arg(?![\w-])`);
// The boolean flags a container command commonly takes. A word after one of these, or
// after a flag=value, is the image, and every option past it belongs to the image.
const CTR_BOOL =
  /^-(?:-(?:rm|detach|interactive|tty|privileged|init|read-only|publish-all|no-cache|quiet|sig-proxy)|[dit]+|P|q)$/;
// A header whose name holds a credential word, prefixed or not: Authorization,
// X-Vault-Token, X-API-Key, Ocp-Apim-Subscription-Key, Cookie, X-Session-Id.
const SECRET_HEADER =
  /^\s*(?:[\w-]*[-_])?(?:authorization|cookie|token|secret|passw(?:or)?d|api[-_]?key|access[-_]?key|auth[-_]?key|subscription[-_]?key|session(?:[-_]?id)?|credentials?)(?:[-_][\w-]*)?\s*:\s*\S/i;
// A key such as password, client_secret or api-key, plural or not. "passive" does not
// qualify. "bypass", "compass" and the like end in "pass" but name nothing secret; a
// concatenated name such as PGPASSWORD, SSHPASS or userPassword still counts.
const SECRET_KEY = String.raw`(?:(?<!by|com|over|under|tres|sur)pass(?:word|wd|phrase)?|pwd|token|secret|api[_-]?key|credential)s?(?:[_-][\w-]*)?`;
const BODY_SECRET = new RegExp(String.raw`${SECRET_KEY}\s*[=:]\s*[^\s&,}]`, "i");
// A short option and its value, quoted or bare. The value may be separated (-p secret)
// unless attachedOnly, when only -psecret counts.
const SHORT_VAL = String.raw`(?:"[^"]+"|'[^']+'|[^\s"'-]\S*)`;
const shortOpt = (letter: string, attachedOnly = false) =>
  new RegExp(String.raw`(?:^|\s)-${letter}${attachedOnly ? "" : String.raw`\s*`}${SHORT_VAL}`, "g");
const AGENT_AUTH_P = shortOpt("P");
const SECRET_ASSIGN = new RegExp(
  String.raw`(?:^|[\s"'])-{0,2}(?=[A-Za-z_])[\w-]*${SECRET_KEY}=(?=["']?[^\s"'])`,
  "gi",
);
const BUILD_SECRET = new RegExp(String.raw`^(?=[A-Za-z_])[\w-]*${SECRET_KEY}=.`, "i");
// A long option named like a secret, with a value. --password-stdin does not
// count, and neither does a redirect such as "--with-token < file"; a <PLACEHOLDER>
// value still shows the pattern, so it does. A bare "pass" must be the whole name or
// follow a - or _, so --bypass and --passthrough stay out.
const SECRET_OPT_SEP = String.raw`(?:^|\s)--(?:[\w-]*(?:pass(?:word|wd|phrase)|pwd|token|secret|api[_-]?key|credential)s?|(?:[\w-]*[_-])?pass)(?![\w-])`;
const SECRET_OPT = new RegExp(String.raw`${SECRET_OPT_SEP}(?:=|\s+)(?![-\s>|&;)])(?!<(?![A-Z][\w-]*>))\S`, "gi");
const SECRET_OPT_EQ = new RegExp(String.raw`${SECRET_OPT_SEP}=(?![-\s])\S`, "gi");
const SHORT_P = shortOpt("p");
const SHORT_V = shortOpt("v");
// mysql reads -p only when attached; "-p name" prompts and takes name as the database.
const MYSQL_P = shortOpt("p", true);
// openssl reads a password source from -pass, -passin, -passout or -password, with one
// dash or two, and "=" or a space before it. pass: puts the password itself on the
// command line; env:, file:, fd: and stdin do not. enc -k takes the password and -K the
// raw key.
const OPENSSL_PASS = /(?:^|\s)--?pass(?:in|out|word)?(?:\s+|=)["']?pass:["']?[^\s"']/g;
const OPENSSL_K = /(?:^|\s)--?[kK](?:\s+|=)(?:"[^"]+"|'[^']+'|[^\s"'-]\S*)/g;
// `net user` takes NAME [PASSWORD | *], and `net use` takes [DEVICE | *] [REMOTE
// [PASSWORD | *]]. Switches such as /add or /user: may sit anywhere, and quotes keep a
// name with spaces in one token. The password is the first positional after the account
// name, or after a UNC or WebDAV remote. "" (an empty password or a null session) and the
// * prompt pass. A redirect, & or # ends the command.
const NET_TOKEN = /(?:"[^"]*"|'[^']*'|[^\s"'])+/g;
const NET_REMOTE = /^["']?(?:\\\\|https?:\/\/)/i;
const NET_END = /^(?:&|\d?>|<|#)/;
// The user may be empty, as a Redis URL has it. The password may not.
const URL_USERINFO = /[a-z][a-z0-9+.-]*:\/\/[^\s/:@'"]*:[^\s/@'"]+@/gi;
// auditd EXECVE records and their JSON form: one aN token per argument.
const EXECVE_ARG = /["']?\ba(\d+)["']?\s*[=:]\s*("[^"]*"|'[^']*'|[^\s,}]+)/g;

// SECURITY: a replace ref makes rev-list, log and show report a substitute object, while
// pack-objects ignores replace refs and sends the real one. A graft file bends the graph
// the same way. Every read here sees the objects as stored, which is what a push sends.
const GIT_ENV = { ...process.env, GIT_NO_REPLACE_OBJECTS: "1", GIT_GRAFT_FILE: "/dev/null" };

// *--- Helper Functions ---*

/** Run git in the repo root, with `input` on stdin, and return stdout, or exit on failure. */
function git(args: string[], input?: string): Buffer {
  const stdin = input === undefined ? undefined : Buffer.from(input);
  const proc = Bun.spawnSync(["git", ...args], { cwd: ROOT, env: GIT_ENV, stdin });
  if (proc.exitCode !== 0) {
    process.stderr.write(`leakcheck: git ${args[0]} failed\n`);
    process.exit(2);
  }
  return proc.stdout;
}

/** True when git accepts the command. */
function gitOk(args: string[]): boolean {
  return Bun.spawnSync(["git", ...args], { cwd: ROOT, env: GIT_ENV }).exitCode === 0;
}

/** Trimmed git stdout, or "" when git refuses the command. */
function gitOut(args: string[]): string {
  const proc = Bun.spawnSync(["git", ...args], { cwd: ROOT, env: GIT_ENV });
  return proc.exitCode === 0 ? proc.stdout.toString("utf8").trim() : "";
}

/** The type of a git object, or "" when the name is unknown. */
function objectType(sha: string): string {
  return gitOut(["cat-file", "-t", sha]);
}

/** NUL- or newline-separated git output as a list. */
function names(buf: Buffer, sep = "\0"): string[] {
  return buf.toString("utf8").split(sep).filter(Boolean);
}

/** The entries of a `--raw -z` diff: each new path, and whether it is a gitlink. */
function rawEntries(buf: Buffer): { path: string; gitlink: boolean }[] {
  const out = new Map<string, boolean>();
  const tokens = buf.toString("utf8").split("\0");
  for (let i = 0; i + 1 < tokens.length; i++) {
    if (!tokens[i].startsWith(":")) continue;
    // :<old mode> <new mode> <old sha> <new sha> <status>, then one path, or two for R and C.
    const fields = tokens[i].slice(1).split(" ");
    const paths = /^[RC]/.test(fields[4]) ? 2 : 1;
    out.set(tokens[i + paths], fields[1] === "160000");
    i += paths;
  }
  return [...out].map(([path, gitlink]) => ({ path, gitlink }));
}

/** The denylist beside this script, else the main worktree's copy from a linked worktree. */
function denylistPath(): string {
  const local = join(ROOT, "tools", "leak-denylist.txt");
  if (existsSync(local)) return local;
  const common = gitOut(["rev-parse", "--path-format=absolute", "--git-common-dir"]);
  return common ? join(dirname(common), "tools", "leak-denylist.txt") : local;
}

/** Parse the denylist: one literal per line, # comments, @include <path>, @exclude <literal>. */
function loadDenylist(path: string): DenyEntry[] {
  const excluded = new Set<string>();
  const entries = readDenylist(path, new Set<string>(), excluded);
  // NOTE: @exclude applies to the whole list, so it can drop an entry an include brought in.
  return entries.filter((e) => !excluded.has(e.value));
}

/** Read one denylist file, following includes and collecting excludes. */
function readDenylist(path: string, seen: Set<string>, excluded: Set<string>): DenyEntry[] {
  if (seen.has(path)) return [];
  seen.add(path);
  const out: DenyEntry[] = [];
  // SECURITY: an entry that cannot match anything is a silent hole, so a list saved in
  // another encoding is decoded or refused, never read as garbage.
  const buf = readFileSync(path);
  const { text, binary, stripped } = decode(buf);
  if (binary) {
    process.stderr.write(`leakcheck: denylist ${path} is not text. Save it as UTF-8.\n`);
    process.exit(2);
  }
  const bad = (line: number) => {
    process.stderr.write(`leakcheck: denylist line ${line}: control or undecodable character. Save it as UTF-8.\n`);
    process.exit(2);
  };
  // SECURITY: decode() drops stray NULs from a text file, which would fuse the entries on
  // either side of one into a single literal that matches neither.
  if (stripped) bad(buf.subarray(0, buf.indexOf(0)).toString("latin1").split(/\r\n|\r|\n/).length);
  text
    .replace(/^﻿/, "")
    .split(/\r\n|\r|\n/)
    .forEach((raw, i) => {
      if (/[\0-\x08\x0b\x0c\x0e-\x1f\x7f�]/.test(raw)) bad(i + 1);
      // A trailing comment needs whitespace before its #, so "#a1b2" stays a literal.
      const value = raw.replace(/\s+#.*$/, "").trim();
      if (!value || value.startsWith("#")) return;
      const inc = /^@include\s+(.+)$/.exec(value);
      if (inc) {
        // A relative include is resolved against the file that names it.
        const target = resolve(dirname(path), inc[1].trim().replace(/^~(?=\/)/, homedir()));
        if (!existsSync(target)) {
          process.stderr.write(`leakcheck: denylist line ${i + 1}: include not found\n`);
          process.exit(2);
        }
        // NOTE: included entries report under the including line's number.
        for (const e of readDenylist(target, seen, excluded)) out.push({ ...e, line: i + 1 });
        return;
      }
      const exc = /^@exclude\s+(.+)$/.exec(value);
      if (exc) {
        excluded.add(exc[1].trim().toLowerCase());
        return;
      }
      // Short literals match inside ordinary words and drown the signal.
      if (value.length < 4) {
        process.stderr.write(`leakcheck: denylist line ${i + 1} ignored: under 4 chars\n`);
        return;
      }
      out.push({ value: value.toLowerCase(), line: i + 1 });
    });
  return out;
}

const ALNUM = /[a-z0-9]/i;

/** Denylist entries found in one line, matched as whole tokens, ignoring case. */
function denyHits(line: string, deny: DenyEntry[]): number[] {
  // A LAN-prefix entry must not fire on the block definition that contains it.
  const lower = line.toLowerCase().replace(V4_BLOCK_TEXT, (m) => " ".repeat(m.length));
  const hits = new Set<number>();
  for (const d of deny) {
    const edgeStart = ALNUM.test(d.value[0]);
    const edgeEnd = ALNUM.test(d.value[d.value.length - 1]);
    let at = lower.indexOf(d.value);
    while (at !== -1) {
      const before = lower[at - 1] ?? "";
      const after = lower[at + d.value.length] ?? "";
      if (!(edgeStart && ALNUM.test(before)) && !(edgeEnd && ALNUM.test(after))) {
        hits.add(d.line);
        break;
      }
      at = lower.indexOf(d.value, at + 1);
    }
  }
  return [...hits];
}

/** True for a unicast hardware address outside the documentation block. */
function isDeviceMac(octets: string[]): boolean {
  const o = octets.map((h) => h.padStart(2, "0").toLowerCase());
  if (o.every((x) => x === "00")) return false;
  // NOTE: a set group bit means broadcast or multicast, which names no device.
  if (parseInt(o[0], 16) & 1) return false;
  return !o.join(":").startsWith("00:00:5e:00:53:");
}

/** True when the line carries a MAC address in any supported notation. */
function macHit(line: string): boolean {
  for (const m of line.matchAll(MAC)) if (isDeviceMac(m[0].split(/[:-]/))) return true;
  for (const m of line.matchAll(MAC_SHORT)) if (isDeviceMac(m[0].split(":"))) return true;
  for (const m of line.matchAll(MAC_DOTTED)) {
    if (isDeviceMac(m[0].replace(/\./g, "").match(/../g) ?? [])) return true;
  }
  for (const m of line.matchAll(MAC_IFNAME)) if (isDeviceMac(m[1].match(/../g) ?? [])) return true;
  return false;
}

/** The part of a YAML line before its comment, quotes respected. */
function yamlCode(line: string): string {
  let q = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === q) q = "";
      else if (c === "\\" && q === '"') i++;
      continue;
    }
    if (c === '"' || c === "'") q = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

/** Net open flow brackets in a YAML fragment, comments and quoted text ignored. With maps, braces count too. */
function flowDepth(text: string, maps = false): number {
  const code = yamlCode(text).replace(/"(?:\\.|[^"\\])*"|'(?:''|[^'])*'/g, "");
  const count = (re: RegExp) => code.match(re)?.length ?? 0;
  return count(/\[/g) - count(/\]/g) + (maps ? count(/\{/g) - count(/\}/g) : 0);
}

/** Per-line flag: is this line part of a `- pci_dss...:` list item's value? */
function pciScope(lines: string[]): boolean[] {
  const out = lines.map(() => false);
  for (let i = 0; i < lines.length; i++) {
    const k = PCI_KEY.exec(lines[i]);
    if (!k) continue;
    out[i] = true;
    const indent = k[1].length;
    let depth = flowDepth(k[3]);
    // An empty value continues as a block sequence on the deeper lines below.
    const block = yamlCode(k[3]).trim() === "";
    for (let j = i + 1; j < lines.length && (depth > 0 || block); j++) {
      const l = lines[j];
      if (/^\s*(?:#.*)?$/.test(l)) continue;
      if (depth <= 0 && /^\s*/.exec(l)![0].length <= indent) break;
      out[j] = true;
      depth += flowDepth(l);
      if (!block && depth <= 0) break;
      i = j;
    }
  }
  return out;
}

/** True when a private-IPv4 match is a valid address outside every allowance. */
function isLabV4(path: string, line: string, m: RegExpMatchArray, pci = false): boolean {
  if (m[0].split(".").some((o) => Number(o) > 255)) return false;
  if (V4_LITERAL_ALLOW.has(m[0])) return false;
  // SECURITY: a requirement ID passes, an address in a trailing comment never does.
  if (pci && PCI_ID.test(m[0]) && (m.index ?? 0) < yamlCode(line).length) return false;
  const cidr = /^\/\d{1,2}/.exec(line.slice((m.index ?? 0) + m[0].length));
  if (cidr && V4_BLOCKS.has(m[0] + cidr[0])) return false;
  return !V4_ALLOW.some((a) => (!a.path || a.path.test(path)) && a.line.test(line));
}

/**
 * True when a PRIVATE_V6 token is a valid address or prefix more specific than its block.
 * A bare block head (fe80::, fc00::, fd00::) names no network, and a hex word is no address.
 */
function isLabV6(token: string): boolean {
  const halves = token.toLowerCase().split("::");
  if (halves.length > 2) return false;
  const groups = halves.flatMap((h) => (h ? h.split(":") : []));
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return false;
  if (halves.length === 1 ? groups.length !== 8 : groups.length > 7) return false;
  return !(V6_BLOCK_HEADS.has(groups[0]) && groups.slice(1).every((g) => /^0+$/.test(g)));
}

/** True when the line carries a link-local or unique-local address or prefix. */
function v6Hit(line: string): boolean {
  for (const m of line.matchAll(PRIVATE_V6)) if (isLabV6(m[0])) return true;
  return false;
}

// NOTE: dotenv is .env and .env.<stage>[.<more>]. .envrc, .environment and a .env.sh or
// .env-setup.sh are shell that something executes, so the argv rules apply to them.
/** True for a dotenv file, which holds assignments and no command lines. */
function isDotenv(name: string): boolean {
  return /^\.env(?:\.[^.]+)*$/.test(name) && !SHELL_EXT.test(name);
}

/** Per line: is it inside the region argv rules apply to, and which shell does it use? */
function argvScope(path: string, lines: string[]): Scope {
  const name = basename(path);
  const each = <T>(v: T) => lines.map(() => v);
  if (isDotenv(name)) return { argv: each(false), shell: each("") };
  if (/\.(md|markdown)$/i.test(name)) return markdownScope(lines);
  if (/\.ya?ml$/i.test(name)) return { argv: yamlScope(lines), shell: each("") };
  return { argv: each(true), shell: each(/\.ps[dm]?1$/i.test(name) ? "pwsh" : /\.(?:bat|cmd)$/i.test(name) ? "cmd" : "") };
}

/** Markdown: only lines inside fences that are not prose, blockquotes and nesting included. */
function markdownScope(lines: string[]): Scope {
  const scope = lines.map(() => false);
  const shells = lines.map((): Shell => "");
  const stack: Fence[] = [];
  // Pop the fences from `from` up. A yaml body gets the compose environment: exemption,
  // with its quote markers stripped and its own indentation kept.
  const close = (from: number) => {
    for (const f of stack.splice(from)) {
      if (!f.yaml || !f.scan) continue;
      const body = f.body.map((i) => lines[i].replace(/^\s*(?:>\s?)+/, ""));
      yamlScope(body).forEach((ok, k) => {
        if (!ok) scope[f.body[k]] = false;
      });
    }
  };
  lines.forEach((raw, i) => {
    // Leading space, blockquote markers, then the indent that counts: the columns after
    // the last > or, with no >, the leading space itself.
    const lead = /^([ \t]*)((?:>[ \t]?)*)([ \t]*)/.exec(raw)!;
    const depth = (lead[2].match(/>/g) ?? []).length;
    const indent = (lead[2] ? lead[3] : lead[1] + lead[3]).replace(/\t/g, "    ").length;
    const m = /^(`{3,}|~{3,})\s*([^\s`{]*)/.exec(raw.slice(lead[0].length));
    // A line outside a quote, a blank one included, ends the fences opened in it: code
    // never continues lazily. The same line may then open a fence of its own.
    const left = stack.findIndex((f) => depth < f.depth);
    if (left !== -1) close(left);
    if (m && !m[2]) {
      // CommonMark: a closer sits at most three columns deeper than its opener, and the
      // outermost fence it can close wins, which also ends an unclosed inner fence.
      const at = stack.findIndex(
        (f) => f.char === m[1][0] && m[1].length >= f.len && depth === f.depth && indent <= f.indent + 3,
      );
      if (at !== -1) {
        close(at);
        return;
      }
    }
    const top = stack.at(-1);
    if (m && (!top || top.nested)) {
      const lang = m[2].toLowerCase();
      stack.push({
        char: m[1][0],
        len: m[1].length,
        indent,
        depth,
        nested: MARKDOWN_FENCES.has(lang),
        yaml: /^ya?ml$/.test(lang),
        shell: PWSH_FENCES.has(lang) ? "pwsh" : CMD_FENCES.has(lang) ? "cmd" : "",
        // An env fence is a .env file, and a .env file is never argv.
        scan: !PROSE_FENCES.has(lang) && !/^\.?(?:dot)?env$/.test(lang),
        body: [],
      });
      return;
    }
    if (top) {
      top.body.push(i);
      scope[i] = top.scan;
      shells[i] = top.shell;
    }
  });
  close(0);
  return { argv: scope, shell: shells };
}

/**
 * YAML: every line except a compose `environment:` value, which is not argv. The value
 * may be a block on the deeper lines, a flow map or list that runs on until its brackets
 * close, or an alias. The key may be quoted, and an anchor may follow it.
 */
function yamlScope(lines: string[]): boolean[] {
  let envIndent = -1;
  let flow = 0;
  let flowIndent = -1;
  return lines.map((line) => {
    const indent = line.search(/\S/);
    const body = line.trimStart();
    if (flow > 0) {
      // A bracket left open ends at the next line no deeper than its key, so a typo
      // cannot take the rest of the file out of scope.
      if (indent === -1 || body.startsWith("#") || indent > flowIndent || /^[\]}]/.test(body)) {
        flow += flowDepth(line, true);
        return false;
      }
      flow = 0;
    }
    if (envIndent >= 0) {
      if (indent === -1 || body.startsWith("#")) return false;
      if (indent > envIndent || (indent === envIndent && body.startsWith("- "))) return false;
      envIndent = -1;
    }
    const m = /^(\s*)(["']?)environment\2\s*:(.*)$/.exec(line);
    if (!m) return true;
    const value = yamlCode(m[3]).replace(/^\s*&\S+/, "").trim();
    if (!value) envIndent = m[1].length;
    else if (/^[{[]/.test(value)) {
      flow = Math.max(0, flowDepth(value, true));
      flowIndent = m[1].length;
    }
    return false;
  });
}

/** The line with its continuation mark turned into a space, or null when the command ends there. */
function continued(raw: string, shell: Shell): string | null {
  const body = raw.replace(/\s+$/, "");
  // A trailing backslash joins in every shell, so a script of unknown type never misses one.
  if (body.endsWith("\\")) return body.slice(0, -1) + " ";
  if (shell) {
    // The mark escapes itself, so only an odd run of them continues the line.
    const run = (shell === "pwsh" ? /`+$/ : /\^+$/).exec(body)?.[0].length ?? 0;
    return run % 2 ? body.slice(0, -1) + " " : null;
  }
  // Unknown shell: a backtick or caret after a space, so `cmd` substitution stays intact.
  return /\s[`^]$/.test(body) ? body.slice(0, -1) + " " : null;
}

/** Join backslash, PowerShell-backtick and cmd-caret continuations into logical lines. */
function logicalLines(lines: string[], scope: boolean[], shell: Shell[]): Logical[] {
  const out: Logical[] = [];
  let cur: Logical | null = null;
  for (let i = 0; i < lines.length; i++) {
    if (!scope[i]) {
      if (cur) out.push(cur);
      cur = null;
      continue;
    }
    const raw = lines[i];
    const joined = continued(raw, shell[i]);
    const more = joined !== null;
    cur ??= { text: "", starts: [], allow: ALLOW_ABOVE.test(lines[i - 1] ?? "") };
    cur.starts.push({ offset: cur.text.length, line: i + 1 });
    cur.text += joined ?? raw;
    if (ALLOW_MARK.test(raw)) cur.allow = true;
    if (!more) {
      out.push(cur);
      cur = null;
    }
  }
  if (cur) out.push(cur);
  return out;
}

/** Quote an item that holds whitespace, so it stays one argument in the flat line. */
function render(s: string): string {
  if (!/\s/.test(s)) return s;
  if (!s.includes('"')) return `"${s}"`;
  return s.includes("'") ? s : `'${s}'`;
}

/** One logical line from argv items, each mapped back to its own physical line. */
function fromItems(items: Item[], lines: string[], raw = false): Logical {
  const l: Logical = { text: "", starts: [], allow: ALLOW_ABOVE.test(lines[items[0].line - 2] ?? "") };
  for (const it of items) {
    l.starts.push({ offset: l.text.length, line: it.line });
    l.text += (l.text ? " " : "") + (raw ? it.text : render(it.text));
    if (ALLOW_MARK.test(lines[it.line - 1])) l.allow = true;
  }
  return l;
}

// NOTE: a flow sequence may wrap over any number of lines, up to the end of its fence
// or file. One that never closes is not argv, and every bracket still open when the scan
// runs out is unclosed to the same end, so it goes in `dead` and is never scanned again.
// That keeps a file full of stray brackets linear.
/** Items of the flow sequence opening at lines[i][col], or null when it never closes. */
function flowItems(
  lines: string[],
  scope: boolean[],
  i: number,
  col: number,
  dead: Set<string>,
): { items: Item[]; line: number; col: number } | null {
  const items: Item[] = [];
  const open: string[] = [];
  let depth = 0;
  let quote = "";
  let cur = "";
  let curLine = i;
  const flush = () => {
    const t = cur.trim();
    if (t) items.push({ text: t, line: curLine + 1 });
    cur = "";
  };
  for (let j = i; j < lines.length && scope[j]; j++) {
    const s = lines[j];
    for (let c = j === i ? col : 0; c < s.length; c++) {
      const ch = s[c];
      if (quote) {
        if (ch === "\\" && quote === '"') {
          cur += s[c + 1] ?? "";
          c++;
        } else if (ch === quote && quote === "'" && s[c + 1] === "'") {
          cur += "'";
          c++;
        } else if (ch === quote) {
          quote = "";
          if (cur) items.push({ text: cur, line: curLine + 1 });
          cur = "";
        } else cur += ch;
        continue;
      }
      if ((ch === '"' || ch === "'") && !cur.trim()) {
        quote = ch;
        cur = "";
        curLine = j;
      } else if (ch === "#" && (c === 0 || /\s/.test(s[c - 1]))) break;
      else if (ch === "[") {
        flush();
        depth++;
        open.push(`${j}:${c}`);
      } else if (ch === "]") {
        flush();
        open.pop();
        if (--depth === 0) return { items, line: j, col: c };
      } else if (ch === ",") flush();
      else {
        if (!cur.trim()) curLine = j;
        cur += ch;
      }
    }
    // A quoted scalar folds across lines; a plain one ends with the line.
    if (quote) cur += " ";
    else flush();
  }
  for (const o of open) dead.add(o);
  return null;
}

/** A YAML block-sequence scalar: unquoted, with any trailing comment removed. */
function scalar(s: string): string {
  const q = /^(["'])(.*)\1\s*(?:#.*)?$/.exec(s);
  if (q) return q[2];
  // A nested collection or block scalar is not one argument.
  if (/^[[{|>]/.test(s)) return "";
  return s.replace(/\s+#.*$/, "").trim();
}

// NOTE: exec form splits a command into one string per argument, so a flag and its
// value never share a line and the line rules cannot see them together.
/** Exec-form argv rebuilt as logical lines: flow sequences, block sequences, folded scalars. */
function execLines(lines: string[], scope: boolean[], yamlish: boolean): Logical[] {
  const out: Logical[] = [];
  const dead = new Set<string>();
  // Flow sequences: [command, flag, value], on one line or wrapped. Any file type.
  for (let i = 0; i < lines.length; i++) {
    if (!scope[i]) continue;
    let quote = "";
    for (let c = 0; c < lines[i].length; c++) {
      const s = lines[i];
      const ch = s[c];
      if (quote) {
        if (ch === quote && s[c - 1] !== "\\") quote = "";
      } else if ((ch === '"' || ch === "'") && !ALNUM.test(s[c - 1] ?? "")) quote = ch;
      else if (ch === "#" && (c === 0 || /\s/.test(s[c - 1]))) break;
      else if (ch === "[") {
        if (dead.has(`${i}:${c}`)) continue;
        const seq = flowItems(lines, scope, i, c, dead);
        if (!seq) continue;
        if (seq.items.length > 1) out.push(fromItems(seq.items, lines));
        i = seq.line;
        c = seq.col;
      }
    }
  }
  if (!yamlish) return out;
  // Block sequences: consecutive "- item" lines at one indent.
  for (let i = 0; i < lines.length; i++) {
    const m = scope[i] ? /^(\s*)-\s+\S/.exec(lines[i]) : null;
    if (!m) continue;
    const head = new RegExp(`^${m[1]}-\\s+(.*)$`);
    const items: Item[] = [];
    let j = i;
    for (; j < lines.length && scope[j]; j++) {
      const item = head.exec(lines[j]);
      if (!item) {
        // A blank line, like a comment, sits inside a block sequence.
        if (/^\s*(?:#|$)/.test(lines[j])) continue;
        break;
      }
      const t = scalar(item[1]);
      if (t) items.push({ text: t, line: j + 1 });
    }
    if (items.length > 1) out.push(fromItems(items, lines));
    i = Math.max(i, j - 1);
  }
  // Folded scalars: "key: >" joins the lines below it into one string. The chomping and
  // indentation indicators may come in either order: >-2 and >2- are the same header.
  for (let i = 0; i < lines.length; i++) {
    const m = scope[i] ? /^(\s*)(?:-\s+)?(?:[^\s#][^#]*:\s+)?>(?:[-+]?\d?|\d[-+])\s*(?:#.*)?$/.exec(lines[i]) : null;
    if (!m) continue;
    let items: Item[] = [];
    const flush = () => {
      if (items.length > 1) out.push(fromItems(items, lines, true));
      items = [];
    };
    let j = i + 1;
    for (; j < lines.length && scope[j]; j++) {
      const indent = lines[j].search(/\S/);
      // A blank line is a newline inside a folded scalar.
      if (indent === -1) {
        flush();
        continue;
      }
      if (indent <= m[1].length) break;
      items.push({ text: lines[j].trim(), line: j + 1 });
    }
    flush();
    i = j - 1;
  }
  return out;
}

const UTF8 = new TextDecoder("utf-8", { fatal: true });

// NOTE: the kernel hex-encodes any argument holding a space, a quote, a control byte or a
// byte above 0x7e, so every multi-line sh -c script lands here. A newline becomes " ; " so
// segments() still splits the script into its commands.
/** An auditd argument, hex-decoded when the record encoded it that way. */
function hexArg(v: string): string {
  if (!/^(?:(?:[0-9A-F]{2}){4,}|(?:[0-9a-f]{2}){4,})$/.test(v)) return v;
  let text: string;
  try {
    text = UTF8.decode(Buffer.from(v, "hex"));
  } catch {
    return v;
  }
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) return v;
  return text.replace(/\r\n|\r|\n/g, " ; ").replaceAll("\t", " ");
}

/** The hex-encoded auditd arguments on one line, decoded. */
function hexArgsOf(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(EXECVE_ARG)) {
    const raw = m[2].replace(/^(["'])(.*)\1$/, "$2");
    const t = hexArg(raw);
    if (t !== raw) out.push(t);
  }
  return out;
}

/** auditd EXECVE records, one per a0, rebuilt as logical lines. Any line, any file. */
function execveLines(lines: string[]): Logical[] {
  const out: Logical[] = [];
  let items: Item[] = [];
  const flush = () => {
    if (items.length > 1) out.push(fromItems(items, lines));
    items = [];
  };
  lines.forEach((line, i) => {
    const args = [...line.matchAll(EXECVE_ARG)];
    if (!args.length) return flush();
    for (const m of args) {
      if (m[1] === "0") flush();
      items.push({ text: hexArg(m[2].replace(/^(["'])(.*)\1$/, "$2")), line: i + 1 });
    }
  });
  flush();
  return out;
}

// NOTE: separators inside quotes do not split. A quoted command, such as a
// compose healthcheck string, stays one segment with its flags attached.
/** Split a logical line on unquoted |, ||, && and ;. */
function segments(text: string): { text: string; offset: number }[] {
  const out: { text: string; offset: number }[] = [];
  let start = 0;
  let quote = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === quote && text[i - 1] !== "\\") quote = "";
      continue;
    }
    if (c === "'" || c === '"') {
      // NOTE: a quote that never closes, such as the apostrophe in "it's", is literal.
      let j = i + 1;
      while (j < text.length && !(text[j] === c && text[j - 1] !== "\\")) j++;
      if (j < text.length) quote = c;
      continue;
    }
    const two = text.slice(i, i + 2);
    const size = two === "&&" || two === "||" ? 2 : c === "|" || c === ";" ? 1 : 0;
    if (size) {
      out.push({ text: text.slice(start, i), offset: start });
      start = i + size;
      i += size - 1;
    }
  }
  out.push({ text: text.slice(start), offset: start });
  return out;
}

/** Offsets of option values in `s` that satisfy `test`, quotes stripped. */
function optionHits(s: string, re: RegExp, test: (value: string) => boolean): number[] {
  const hits: number[] = [];
  for (const m of s.matchAll(re)) {
    if (test((m[1] ?? "").replace(/["']/g, ""))) hits.push(m.index ?? 0);
  }
  return hits;
}

/** Offsets of every match of `re` in `s`. */
function allHits(s: string, re: RegExp): number[] {
  return [...s.matchAll(re)].map((m) => m.index ?? 0);
}

/** True when the quote at s[i] opens a string: an even number of its kind precede it. */
function opensQuote(s: string, i: number): boolean {
  let n = 0;
  for (let k = 0; k < i; k++) {
    if (s[k] === "\\") k++;
    else if (s[k] === s[i]) n++;
  }
  return n % 2 === 0;
}

// NOTE: joined exec-form items are quoted, so "mysql -u root -p" "echo" puts the closing
// quote of one item right after -p. That quote is not the start of a value.
/** True when the short option at s[i] is followed by a closing quote, not a value. */
function closedValue(s: string, i: number): boolean {
  const m = /^\s*-[A-Za-z]\s*(?=["'])/.exec(s.slice(i));
  return !!m && !opensQuote(s, i + m[0].length);
}

/** Offset of the password among the arguments of `net user`, or -1 when there is none. */
function netUserPassword(s: string): number {
  let account = false;
  for (const m of s.matchAll(NET_TOKEN)) {
    const t = m[0];
    if (NET_END.test(t)) break;
    if (t.startsWith("/")) continue;
    if (!account) {
      account = true;
      continue;
    }
    const v = t.replace(/["']/g, "");
    return v === "" || v === "*" ? -1 : (m.index ?? 0);
  }
  return -1;
}

/**
 * True when the secret option at s[at] belongs to the container command that ends at
 * s[from]: no word before it reads as the image. A word that follows an option is taken
 * as that option's value unless the option is a known boolean or carries its own =.
 */
function containerSecret(s: string, from: number, at: number): boolean {
  let prev = "";
  for (const m of s.slice(from, at).matchAll(NET_TOKEN)) {
    const t = m[0];
    if (!t.startsWith("-") && (!prev.startsWith("-") || prev.includes("=") || CTR_BOOL.test(prev))) return false;
    prev = t;
  }
  return true;
}

/** Offset of the password in the arguments of a net use command, or -1 when there is none. */
function netUsePassword(s: string): number {
  let remote = false;
  for (const m of s.matchAll(NET_TOKEN)) {
    const t = m[0];
    if (NET_END.test(t)) break;
    if (t.startsWith("/")) continue;
    if (!remote) {
      remote = NET_REMOTE.test(t);
      continue;
    }
    const v = t.replace(/["']/g, "");
    return v === "" || v === "*" ? -1 : (m.index ?? 0);
  }
  return -1;
}

/** Argv findings for one segment, as offsets into the segment text. */
function segmentRules(s: string): [Rule, number][] {
  const out: [Rule, number][] = [];
  const after = (re: RegExp) => {
    const m = re.exec(s);
    return m ? (m.index ?? 0) + m[0].length : -1;
  };
  const tail = (from: number) => s.slice(from);
  // Parity is counted over the whole segment, so `from` only shifts the offset.
  const add = (rule: Rule, from: number, offsets: number[]) =>
    offsets.forEach((o) => {
      if (!closedValue(s, from + o)) out.push([rule, from + o]);
    });

  const curl = after(CMD.curl);
  if (curl >= 0) {
    add("argv-user", curl, optionHits(tail(curl), CURL_USER, (v) => /^[^:\s]*:\S/.test(v)));
    add(
      "argv-header",
      curl,
      optionHits(tail(curl), CURL_HEADER, (v) => !v.startsWith("@") && SECRET_HEADER.test(v)),
    );
    add("argv-header", curl, allHits(tail(curl), CURL_BEARER));
    add("argv-header", curl, optionHits(tail(curl), CURL_COOKIE, (v) => v.includes("=")));
    add(
      "argv-body",
      curl,
      optionHits(tail(curl), CURL_DATA, (v) => !v.startsWith("@") && BODY_SECRET.test(v)),
    );
  }
  const container = after(CMD.container);
  if (container >= 0) {
    add("argv-env", container, optionHits(tail(container), DOCKER_ENV, (v) => /^[A-Za-z_]\w*=./.test(v)));
    add("argv-secret-assign", container, optionHits(tail(container), BUILD_ARG, (v) => BUILD_SECRET.test(v)));
  }
  const login = after(CMD.dockerLogin);
  if (login >= 0) add("argv-password-opt", login, allHits(tail(login), SHORT_P));
  const agent = after(CMD.agentAuth);
  if (agent >= 0) add("argv-agent-auth", agent, allHits(tail(agent), AGENT_AUTH_P));
  const assign = after(CMD.assign);
  if (assign >= 0) add("argv-secret-assign", assign, allHits(tail(assign), SECRET_ASSIGN));
  const sshpass = after(CMD.sshpass);
  if (sshpass >= 0) add("argv-sshpass", sshpass, allHits(tail(sshpass), SHORT_P));
  const mysql = after(CMD.mysql);
  if (mysql >= 0) add("argv-mysql", mysql, allHits(tail(mysql), MYSQL_P));
  const tool = after(CMD.passTool);
  if (tool >= 0) add("argv-password-opt", tool, allHits(tail(tool), SHORT_P));
  const keystore = after(CMD.keystore);
  if (keystore >= 0) add("argv-password-opt", keystore, allHits(tail(keystore), SHORT_V));
  const ossl = after(CMD.openssl);
  if (ossl >= 0) {
    add("argv-password-opt", ossl, [...allHits(tail(ossl), OPENSSL_PASS), ...allHits(tail(ossl), OPENSSL_K)]);
  }
  // The mysql family takes "--password DBNAME" as a prompt, so only its = form counts. That
  // covers mysql's own options only: not text before the command word, and not anything
  // past a separator, with quotes counted from the command word on.
  const mysqlAt = mysql >= 0 ? (CMD.mysql.exec(s)?.index ?? 0) : -1;
  const own = (o: number) => mysql >= 0 && o >= mysqlAt && segments(s.slice(mysql, o)).length === 1;
  // A container command's own secret option names a secret to mount, not its value.
  const ownSecret = (o: number) =>
    container >= 0 && o >= container && /^\s*--secrets?(?=[=\s])/.test(s.slice(o)) && containerSecret(s, container, o);
  add("argv-password-opt", 0, allHits(s, SECRET_OPT).filter((o) => !own(o) && !ownSecret(o)));
  if (mysql >= 0) add("argv-password-opt", 0, allHits(s, SECRET_OPT_EQ));
  const net = after(CMD.netUser);
  if (net >= 0 && netUserPassword(tail(net)) >= 0) out.push(["argv-net-user", net]);
  const use = after(CMD.netUse);
  if (use >= 0) add("argv-net-user", use, [netUsePassword(tail(use))].filter((o) => o >= 0));
  return out;
}

/** Map an offset in a logical line back to its physical line number. */
function physicalLine(l: Logical, offset: number): number {
  let line = l.starts[0].line;
  for (const s of l.starts) if (s.offset <= offset) line = s.line;
  return line;
}

// *--- Core Logic ---*

/** Scan one file's text and return findings, never the matched values. */
function scanText(path: string, text: string, deny: DenyEntry[], classes: Set<RuleClass>): Finding[] {
  const found = new Map<string, Finding>();
  const add = (line: number, rule: Rule, entry?: number) =>
    found.set(`${line}:${rule}:${entry ?? ""}`, { path, line, rule, entry });
  const lines = text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/);

  const pci = pciScope(lines);
  lines.forEach((physical, i) => {
    const n = i + 1;
    // A hex-encoded auditd argument is read decoded too, at the same line.
    for (const line of [physical, ...hexArgsOf(physical)]) {
      if (classes.has("denylist")) for (const entry of denyHits(line, deny)) add(n, "denylist", entry);
      if (classes.has("mac") && macHit(line)) add(n, "mac-address");
      if (classes.has("ipv4")) {
        for (const m of line.matchAll(PRIVATE_V4)) if (isLabV4(path, line, m, pci[i])) add(n, "private-ipv4");
      }
      if (classes.has("ipv6") && v6Hit(line)) add(n, "private-ipv6");
      if (classes.has("fingerprint") && SSH_FP.test(line)) add(n, "ssh-fingerprint");
    }
  });

  if (classes.has("argv")) {
    const name = basename(path);
    const scope = argvScope(path, lines);
    const logical = [
      ...logicalLines(lines, scope.argv, scope.shell),
      ...execLines(lines, scope.argv, /\.(ya?ml|md|markdown)$/i.test(name)),
      ...execveLines(lines),
    ];
    for (const l of logical) {
      if (l.allow) continue;
      for (const seg of segments(l.text)) {
        for (const [rule, at] of segmentRules(seg.text)) add(physicalLine(l, seg.offset + at), rule);
      }
      for (const at of allHits(l.text, URL_USERINFO)) add(physicalLine(l, at), "argv-url-userinfo");
    }
  }
  return [...found.values()];
}

/**
 * Decode a buffer as text. UTF-16 is decoded, stray NULs are dropped (stripped says so);
 * what still does not read as text is binary.
 */
function decode(buf: Buffer): { text: string; binary: boolean; stripped?: boolean } {
  if (buf[0] === 0xff && buf[1] === 0xfe) {
    return { text: new TextDecoder("utf-16le").decode(buf.subarray(2)), binary: false };
  }
  if (buf[0] === 0xfe && buf[1] === 0xff) {
    const even = buf.subarray(2, 2 + Math.floor((buf.length - 2) / 2) * 2);
    return { text: Buffer.from(even).swap16().toString("utf16le"), binary: false };
  }
  const head = buf.subarray(0, 8000);
  if (!head.includes(0)) return { text: buf.toString("utf8"), binary: false };
  // NOTE: BOM-less UTF-16 puts the NUL of each ASCII character on one byte parity, which
  // a binary with NULs on both does not. The decoded text must then read as text, so a
  // binary that passes the parity check is still caught.
  let even = 0;
  let odd = 0;
  for (let i = 0; i < head.length; i++) if (head[i] === 0) i % 2 ? odd++ : even++;
  const half = head.length / 2;
  const hi = Math.max(even, odd);
  let wide: string | null = null;
  if (hi >= half * 0.1 && Math.min(even, odd) <= hi * 0.1) {
    const text = new TextDecoder(odd >= even ? "utf-16le" : "utf-16be").decode(buf.subarray(0, buf.length & ~1));
    const probe = text.slice(0, 4000);
    let bad = 0;
    for (let i = 0; i < probe.length; i++) {
      const c = probe.charCodeAt(i);
      if ((c < 32 && c !== 9 && c !== 10 && c !== 12 && c !== 13) || c === 0xfffd) bad++;
    }
    if (bad <= probe.length * 0.02) wide = text;
  }
  // A NUL beside most ASCII characters is UTF-16 even when the NUL-stripped bytes would
  // also read as text: the strip garbles every character above U+00FF.
  if (wide !== null && hi >= half * 0.3) return { text: wide, binary: false };
  // A stray NUL in a text file is still a text file. Dropping the NULs keeps every
  // newline, so line numbers hold.
  const stripped = Buffer.from(buf.filter((b) => b !== 0));
  let utf8 = true;
  try {
    // stream: a multibyte character cut at the sample boundary is not an error.
    new TextDecoder("utf-8", { fatal: true }).decode(stripped.subarray(0, 8000), { stream: true });
  } catch {
    utf8 = false;
  }
  let nul = 0;
  let printable = 0;
  for (const b of head) {
    if (b === 0) nul++;
    else if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || (utf8 && b >= 128)) printable++;
  }
  if (printable >= (head.length - nul) * 0.95) {
    return { text: stripped.toString(utf8 ? "utf8" : "latin1"), binary: false, stripped: true };
  }
  // Non-ASCII UTF-16 prose fails the strip but passes the parity check.
  if (wide !== null) return { text: wide, binary: false };
  return { text: stripped.toString("latin1"), binary: true };
}

/** Findings for one file body. Binary content gets the denylist only, at line 0. */
function scanBuffer(
  path: string,
  buf: Buffer,
  deny: DenyEntry[],
  classes: Set<RuleClass>,
): { findings: Finding[]; binary: boolean } {
  const { text, binary } = decode(buf);
  if (!binary) return { findings: scanText(path, text, deny, classes), binary };
  const use = new Set([...classes].filter((c) => DENY_ONLY.has(c)));
  const seen = new Set<number>();
  const findings = scanText(path, text, deny, use)
    .filter((f) => !seen.has(f.entry ?? 0) && seen.add(f.entry ?? 0))
    .map((f) => ({ ...f, line: 0 }));
  return { findings, binary };
}

/** A working-tree entry as bytes: a symlink is its target text, a directory is nothing. */
function readWorking(abs: string): Buffer | null {
  const st = lstatSync(abs, { throwIfNoEntry: false });
  if (!st) return null;
  if (st.isSymbolicLink()) return Buffer.from(readlinkSync(abs));
  return st.isFile() ? readFileSync(abs) : null;
}

/**
 * Every file under the given paths, and the .git, node_modules and .DS_Store entries the
 * walk passed over. Symlinks are not followed.
 */
function walk(paths: string[]): { files: string[]; skipped: string[] } {
  const files: string[] = [];
  const skipped: string[] = [];
  const visit = (p: string) => {
    const st = lstatSync(p);
    if (st.isDirectory()) {
      for (const name of readdirSync(p)) {
        if (name === ".git" || name === "node_modules" || name === ".DS_Store") skipped.push(join(p, name));
        else visit(join(p, name));
      }
    } else if (st.isFile() || st.isSymbolicLink()) files.push(p);
  };
  for (const p of paths) visit(resolve(p));
  return { files, skipped };
}

/**
 * Every index entry, read from the working tree. A file missing there is read from the
 * index instead, which is the copy the next commit records.
 */
function trackedSources(): Source[] {
  const entries = new Map<string, { gitlink: boolean; shas: string[] }>();
  for (const rec of names(git(["ls-files", "-s", "-z"]))) {
    const m = /^(\d+) ([0-9a-f]+) \d\t(.*)$/s.exec(rec);
    if (!m) {
      process.stderr.write("leakcheck: cannot parse the output of git ls-files.\n");
      process.exit(2);
    }
    // NOTE: a path in conflict has one entry per stage, and every stage gets read.
    const e = entries.get(m[3]) ?? { gitlink: false, shas: [] };
    e.gitlink ||= m[1] === "160000";
    e.shas.push(m[2]);
    entries.set(m[3], e);
  }
  return [...entries].map(([p, e]) => ({
    label: p,
    path: p,
    gitlink: e.gitlink,
    read: () => readWorking(join(ROOT, p)),
    fallback: () => Buffer.concat(e.shas.map((sha) => git(["cat-file", "blob", sha]))),
  }));
}

/** True for a self-test fixture file: fake values on purpose, so only the denylist applies. */
function isFixture(path: string): boolean {
  return path.startsWith(FIXTURES) && FIXTURE_FILES.has(path.slice(FIXTURES.length));
}

type Cleanup = "strip" | "scissors" | "whitespace" | "verbatim";

/**
 * Git's --cleanup for this commit (git-commit(1)). The default is strip when an editor
 * ran and whitespace otherwise, and git tells every commit hook which one by setting
 * GIT_EDITOR=: when no editor is launched (githooks(5)).
 */
function commitCleanup(): Cleanup {
  const cfg = gitOut(["config", "--get", "commit.cleanup"]);
  if (cfg === "strip" || cfg === "scissors" || cfg === "whitespace" || cfg === "verbatim") return cfg;
  return process.env.GIT_EDITOR === ":" ? "whitespace" : "strip";
}

/**
 * The comment string git strips from this message, or null when it cannot be told.
 * core.commentChar and core.commentString name the same setting, and the last one set
 * wins. Under "auto" git picks, per commit, a character no line of the message starts
 * with, so the template's own comment lines show which one it took.
 */
function commentChar(text: string): string | null {
  const last = gitOut(["config", "--get-regexp", "^core\\.comment(char|string)$"]).split("\n").at(-1);
  if (!last) return "#";
  const value = last.slice(last.indexOf(" ") + 1);
  if (value !== "auto") return value;
  const m = /^(\S+) -{24} >8 -{24}$/m.exec(text) ?? /^(\S+) Please enter (?:the|a) commit message/m.exec(text);
  return m ? m[1] : null;
}

/**
 * The part of a message file git will store. Under whitespace and verbatim, which -m and
 * -F get by default, every line is stored, so every line is scanned. Under strip the
 * comment lines git added (status, untracked files, branch name) are blanked, not
 * removed, so line numbers still match the file, and the diff "commit -v" appends under
 * the scissors line goes. A scissors line typed by hand is kept under strip, as git keeps
 * it, and cut only under scissors.
 */
function messageText(buf: Buffer, cleanup: Cleanup): Buffer {
  if (cleanup === "whitespace" || cleanup === "verbatim") return buf;
  const text = buf.toString("utf8");
  const cc = commentChar(text);
  // SECURITY: with no comment string known, no line is known to be dropped, so all are scanned.
  if (cc === null) return buf;
  const esc = cc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const cut = text.search(new RegExp(`^${esc} -+ >8 -+$`, "m"));
  let kept = text;
  if (cut !== -1) {
    const below = text.slice(cut).split("\n").slice(1);
    const first = below.find((l) => !l.startsWith(cc) && l.trim() !== "");
    if (cleanup === "scissors" || first === undefined || first.startsWith("diff --git ")) kept = text.slice(0, cut);
  }
  return Buffer.from(kept.split("\n").map((l) => (l.startsWith(cc) ? "" : l)).join("\n"));
}

/** The author and committer git would write now, without the timestamps. */
function identityText(): Buffer {
  const ident = (name: string) => gitOut(["var", name]).replace(/ \d+ [+-]\d{4}$/, "");
  return Buffer.from(`${ident("GIT_AUTHOR_IDENT")}\n${ident("GIT_COMMITTER_IDENT")}\n`);
}

/**
 * The commits and tags the push destination lists that this clone also holds, as rev-list
 * exclusions. `dest` is a remote name or URL; without one, nothing bounds the walk.
 */
function remoteHas(dest: string): string[] {
  if (!dest) return [];
  const proc = Bun.spawnSync(["git", "ls-remote", dest], { cwd: ROOT, env: GIT_ENV });
  if (proc.exitCode !== 0) {
    process.stderr.write("leakcheck: cannot list the refs on the push destination, so the push is blocked.\n");
    process.exit(2);
  }
  const listed = new Set(
    proc.stdout
      .toString("utf8")
      .split("\n")
      .map((l) => l.split("\t")[0])
      .filter((s) => /^[0-9a-f]{40,64}$/.test(s)),
  );
  if (!listed.size) return [];
  // NOTE: rev-list stops on a name it cannot resolve, and a ref may point at a tree or
  // a blob, so only the commits and tags present here can bound the walk.
  const types = git(["cat-file", "--batch-check=%(objectname) %(objecttype)"], [...listed].join("\n") + "\n");
  return names(types, "\n")
    .map((l) => l.split(" "))
    .filter(([, type]) => type === "commit" || type === "tag")
    .map(([sha]) => `^${sha}`);
}

/**
 * Sources for the refs a pre-push hook names on stdin: each annotated tag object, and for
 * each commit its message, its author and committer, and each changed file.
 */
function pushedSources(stdin: string, dest: string): { sources: Source[]; commits: number; tags: number } {
  const sources: Source[] = [];
  const seen = new Set<string>();
  const seenTags = new Set<string>();
  const seenRefs = new Set<string>();
  // SECURITY: a ref the remote has not seen is bounded by what the remote lists right now,
  // asked once and only when a row needs it. Tracking refs can be stale, or belong to a
  // URL the remote no longer points at, and either would hide commits it never received.
  let listed: string[] | null = null;
  for (const row of stdin.split("\n")) {
    const [, local, remoteRef, remote] = row.trim().split(/\s+/);
    // A deleted ref pushes nothing.
    if (!local || /^0+$/.test(local)) continue;
    // The ref name itself lands on the remote, so it meets the denylist like a path.
    if (remoteRef && !seenRefs.has(remoteRef)) {
      seenRefs.add(remoteRef);
      sources.push({ label: `ref:${remoteRef}`, path: remoteRef, ref: true, read: () => Buffer.alloc(0) });
    }
    // rev-list peels tags, so each tag object in the chain is read on its own.
    let target = local;
    while (objectType(target) === "tag") {
      const text = gitOut(["cat-file", "tag", target]);
      if (!seenTags.has(target)) {
        seenTags.add(target);
        sources.push({ label: `${target.slice(0, 7)}:tag`, path: "", message: true, read: () => Buffer.from(text) });
      }
      target = text.match(/^object ([0-9a-f]{40})$/m)?.[1] ?? "";
    }
    if (objectType(target) !== "commit") continue;
    const bounded = remote && !/^0+$/.test(remote) && gitOk(["cat-file", "-e", `${remote}^{commit}`]);
    const range = bounded ? [`${remote}..${target}`] : [target, ...(listed ??= remoteHas(dest))];
    for (const sha of names(git(["rev-list", "--stdin"], range.join("\n") + "\n"), "\n")) {
      if (seen.has(sha)) continue;
      seen.add(sha);
      const short = sha.slice(0, 7);
      sources.push({ label: `${short}:message`, path: "", message: true, read: () => git(["log", "-1", "--format=%B", sha]) });
      sources.push({
        label: `${short}:identity`,
        path: "",
        message: true,
        read: () => git(["log", "-1", "--format=%an <%ae>%n%cn <%ce>", sha]),
      });
      const raw = git(["diff-tree", "--no-commit-id", "--raw", "-r", "-z", "-m", "--root", "--diff-filter=ACMRT", sha]);
      for (const { path: p, gitlink } of rawEntries(raw)) {
        sources.push({ label: `${short}:${p}`, path: p, gitlink, read: () => git(["show", `${sha}:${p}`]) });
      }
    }
  }
  return { sources, commits: seen.size, tags: seenTags.size };
}

/** Run the fixtures: findings must equal each line's `expect:` markers exactly. */
function selfTest(): number {
  const covered = new Set<string>();
  let failures = 0;
  const dir = join(ROOT, FIXTURES);
  // The fixture list exercises the parser: an include and an exclude of an included entry.
  const deny = loadDenylist(join(dir, "denylist", "main.txt"));
  if (deny.map((d) => d.value).join() !== "fixture-deny-host,172.16.0.") {
    failures++;
    console.log("DENYLIST fixture parsed to the wrong entries");
  }
  const files = readdirSync(dir)
    .filter((name) => lstatSync(join(dir, name)).isFile())
    .sort();
  for (const name of files) {
    if (FIXTURE_FILES.has(name)) continue;
    failures++;
    console.log(`${name} is not in FIXTURE_FILES, so the hooks would scan it as an ordinary file`);
  }
  const keys = (found: Finding[]) => new Set(found.map((f) => `${f.line}:${f.rule}`));
  for (const name of files) {
    const path = FIXTURES + name;
    const text = readFileSync(join(dir, name), "utf8");
    const want = new Set<string>();
    text.split(/\r?\n/).forEach((line, i) => {
      const m = /expect:\s*([\w,-]+)/.exec(line);
      m?.[1].split(",").forEach((r) => {
        want.add(`${i + 1}:${r}`);
        covered.add(r);
      });
    });
    const got = keys(scanText(path, text, deny, new Set(CLASSES)));
    const report = (tag: string, a: Set<string>, b: Set<string>) => {
      for (const k of a) {
        if (b.has(k)) continue;
        failures++;
        console.log(`${tag} ${path}:${k}`);
      }
    };
    report("MISS ", want, got);
    report("EXTRA", got, want);
    console.log(`${want.size ? "positive" : "negative"}  ${path}: ${got.size} finding(s)`);
  }
  // Encodings: the same text must give the same findings however it is stored.
  const sample = readFileSync(join(dir, "positive.md"), "utf8");
  const base = [...keys(scanText("positive.md", sample, deny, new Set(CLASSES)))].sort().join();
  const le = Buffer.from(sample, "utf16le");
  const be = Buffer.from(le).swap16();
  // Non-ASCII prose must not tip BOM-less UTF-16 into binary.
  const heavy = "# Prüfung für Größe, Änderung, Rückgabe, Überprüfung\n# Проверка конфигурации агента\n".repeat(20) + sample;
  const heavyBase = [...keys(scanText("positive.md", heavy, deny, new Set(CLASSES)))].sort().join();
  const hle = Buffer.from(heavy, "utf16le");
  const encoded: [string, Buffer, string][] = [
    ["utf-16le with BOM", Buffer.concat([Buffer.from([0xff, 0xfe]), le]), base],
    ["utf-16be with BOM", Buffer.concat([Buffer.from([0xfe, 0xff]), be]), base],
    ["utf-16le without BOM", le, base],
    ["utf-16be without BOM", be, base],
    ["utf-16le without BOM, non-ASCII heavy", hle, heavyBase],
    ["utf-16be without BOM, non-ASCII heavy", Buffer.from(hle).swap16(), heavyBase],
    ["utf-8 with BOM", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(sample)]), base],
  ];
  for (const [label, buf, want] of encoded) {
    const r = scanBuffer("positive.md", buf, deny, new Set(CLASSES));
    const got = [...keys(r.findings)].sort().join();
    if (!r.binary && got === want) continue;
    failures++;
    console.log(`ENCODING ${label}: ${r.binary ? "read as binary" : "different findings"}`);
  }
  // Binary content still meets the denylist, reported at line 0.
  const bin = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 1, 7, 0]), Buffer.from("fixture-deny-host")]);
  const b = scanBuffer("blob.png", bin, deny, new Set(CLASSES));
  if (!b.binary || [...keys(b.findings)].join() !== "0:denylist") {
    failures++;
    console.log("BINARY denylist check failed");
  }
  // An array of small integers has its NULs on one parity, like UTF-16, but does not
  // decode to text.
  const ints = Buffer.from(new Uint16Array(Array.from({ length: 2000 }, (_, k) => k % 300)).buffer);
  if (!scanBuffer("ints.bin", ints, deny, new Set(CLASSES)).binary) {
    failures++;
    console.log("BINARY uint16 array read as text");
  }
  for (const r of RULES) {
    if (covered.has(r)) continue;
    failures++;
    console.log(`UNCOVERED rule ${r}`);
  }
  const total = RULES.length;
  console.log(failures ? `self-test: FAIL (${failures})` : `self-test: pass, ${total}/${total} rules`);
  return failures ? 1 : 0;
}

// *--- Entry Point ---*

/** Parse argv, or return the message for exit code 2. */
function parseArgs(argv: string[]): Options | string {
  const opts: Options = { mode: "tracked", paths: [], message: "", remote: "", classes: new Set(CLASSES), denylist: true };
  const modes: Mode[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--staged" || a === "--pushed" || a === "--self-test") modes.push(a.slice(2) as Mode);
    else if (a === "--message") {
      modes.push("message");
      // A following flag is not a file name. Leaving it for the loop reports the real error.
      if (argv[i + 1] !== undefined && !argv[i + 1].startsWith("--")) opts.message = argv[++i];
    } else if (a === "--paths") {
      modes.push("paths");
      while (argv[i + 1] !== undefined && !argv[i + 1].startsWith("--")) opts.paths.push(argv[++i]);
    } else if (a === "--remote") {
      opts.remote = argv[++i] ?? "";
      // A leading dash would reach git ls-remote as an option.
      if (!opts.remote || opts.remote.startsWith("-")) return "--remote needs a remote name or URL";
    } else if (a === "--only") {
      const picked = (argv[++i] ?? "").split(",");
      if (!picked.every((c) => (CLASSES as string[]).includes(c))) {
        return `--only takes a comma list of: ${CLASSES.join(", ")}`;
      }
      opts.classes = new Set(picked as RuleClass[]);
    } else if (a === "--no-denylist") opts.denylist = false;
    else return `unknown argument: ${a}`;
  }
  if (modes.length > 1) return "one mode at a time";
  opts.mode = modes[0] ?? "tracked";
  if (opts.mode === "message" && !opts.message) return "--message needs a file";
  if (opts.mode === "paths" && !opts.paths.length) return "--paths needs at least one path";
  if (opts.remote && opts.mode !== "pushed") return "--remote only applies to --pushed";
  if (!opts.denylist) opts.classes.delete("denylist");
  if (!opts.classes.size) return "nothing to check: --no-denylist removed the only class";
  return opts;
}

function main(argv: string[]): number {
  if (argv.includes("-h") || argv.includes("--help")) {
    process.stdout.write(USAGE);
    return 0;
  }
  const opts = parseArgs(argv);
  if (typeof opts === "string") {
    process.stderr.write(`leakcheck: ${opts}\n${USAGE}`);
    return 2;
  }
  if (opts.mode === "self-test") return selfTest();
  const { classes } = opts;

  let deny: DenyEntry[] = [];
  if (classes.has("denylist")) {
    const denylist = denylistPath();
    if (!existsSync(denylist)) {
      process.stderr.write(
        "leakcheck: tools/leak-denylist.txt is missing. Create it (gitignored),\n" +
          "or pass --no-denylist to run the class checks alone.\n",
      );
      return 2;
    }
    deny = loadDenylist(denylist);
    if (!deny.length) {
      process.stderr.write("leakcheck: tools/leak-denylist.txt has no usable entries.\n");
      return 2;
    }
  }

  // Each source yields a repo-relative path, a report label and a lazy reader.
  let sources: Source[];
  let commits = -1;
  let tags = 0;
  if (opts.mode === "paths") {
    for (const p of opts.paths) {
      if (!lstatSync(p, { throwIfNoEntry: false })) {
        process.stderr.write(`leakcheck: no such path: ${p}\n`);
        return 2;
      }
    }
    const { files, skipped } = walk(opts.paths);
    // NOTE: a skipped entry can hold anything, so name each one rather than drop it quietly.
    if (skipped.length) {
      process.stderr.write(
        `leakcheck: not scanned: ${skipped.map((abs) => relative(ROOT, abs)).join(", ")}. Name one directly to scan it.\n`,
      );
    }
    sources = files.map((abs) => {
      const path = relative(ROOT, abs);
      return { label: path, path, read: () => readWorking(abs) };
    });
  } else if (opts.mode === "message") {
    const st = statSync(opts.message, { throwIfNoEntry: false });
    if (!st) {
      process.stderr.write(`leakcheck: no such file: ${opts.message}\n`);
      return 2;
    }
    if (!st.isFile()) {
      process.stderr.write(`leakcheck: --message needs a regular file: ${opts.message}\n`);
      return 2;
    }
    const cleanup = commitCleanup();
    sources = [{ label: "commit-message", path: "", message: true, read: () => messageText(readFileSync(opts.message), cleanup) }];
  } else if (opts.mode === "pushed") {
    ({ sources, commits, tags } = pushedSources(readFileSync(0, "utf8"), opts.remote));
  } else if (opts.mode === "staged") {
    sources = rawEntries(git(["diff", "--cached", "--raw", "-z", "--diff-filter=ACMRT"])).map(({ path: p, gitlink }) => ({
      label: p,
      path: p,
      gitlink,
      read: () => git(["show", `:${p}`]),
    }));
    sources.push({ label: "identity", path: "", message: true, read: identityText });
  } else {
    sources = trackedSources();
  }

  const findings: Finding[] = [];
  let scanned = 0;
  const binaries: string[] = [];
  const fallbacks: string[] = [];
  let gitlinks = 0;
  for (const src of sources) {
    let use = classes;
    if (src.message) use = new Set([...classes].filter((c) => c !== "argv"));
    else {
      if (classes.has("denylist")) {
        for (const entry of denyHits(src.path, deny)) findings.push({ path: src.label, line: 0, rule: "denylist", entry });
      }
      // NOTE: fixture files hold fake identifiers and argv on purpose. --paths asks for them.
      if (opts.mode !== "paths" && isFixture(src.path)) use = new Set([...classes].filter((c) => DENY_ONLY.has(c)));
    }
    if (src.gitlink) gitlinks++;
    if (src.gitlink || src.ref) continue;
    let buf: Buffer | null;
    try {
      buf = src.read();
      if (!buf && src.fallback) {
        buf = src.fallback();
        fallbacks.push(src.label);
      }
    } catch (e) {
      // SECURITY: content that exists but could not be read is not clean.
      process.stderr.write(`leakcheck: cannot read ${src.label}: ${(e as NodeJS.ErrnoException).code ?? e}\n`);
      return 2;
    }
    if (!buf) {
      process.stderr.write(`leakcheck: cannot read ${src.label}: it is gone\n`);
      return 2;
    }
    const r = scanBuffer(src.path, buf, deny, use);
    if (r.binary) binaries.push(src.label);
    else scanned++;
    findings.push(...r.findings.map((f) => ({ ...f, path: src.label })));
  }

  findings.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
  for (const f of findings) {
    console.log(`${f.path}:${f.line}: ${f.rule}${f.entry ? `#${f.entry}` : ""}`);
  }
  const files = new Set(findings.map((f) => f.path)).size;
  const tally =
    `${scanned} scanned` +
    (commits >= 0 ? ` across ${commits} commit(s)` : "") +
    (tags ? ` and ${tags} tag(s)` : "") +
    (gitlinks ? `, ${gitlinks} submodule(s) not scanned` : "") +
    (binaries.length ? `, ${binaries.length} binary (denylist only)` : "") +
    (fallbacks.length ? `, ${fallbacks.length} missing from the working tree (index copy scanned)` : "");
  // NOTE: a binary file gets the denylist only, so name each one rather than hide it in a count.
  if (binaries.length) process.stderr.write(`leakcheck: binary, denylist only: ${binaries.join(", ")}\n`);
  if (fallbacks.length) {
    process.stderr.write(`leakcheck: missing from the working tree, index copy scanned: ${fallbacks.join(", ")}\n`);
  }
  if (findings.length) {
    process.stderr.write(
      `leakcheck: ${findings.length} finding(s) in ${files} file(s), ${tally}.\n` +
        "Use a placeholder such as <DELL-IP>. For an argv example quoted on purpose,\n" +
        "put `leakcheck: allow` on the line or in a comment on the line above.\n",
    );
    return 1;
  }
  process.stderr.write(`leakcheck: clean, ${tally}.\n`);
  return 0;
}

process.exit(main(process.argv.slice(2)));
