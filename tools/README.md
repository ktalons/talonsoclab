# tools

## leakcheck

`leakcheck.ts` keeps two kinds of mistake out of this repo's history:

1. **Lab identifiers.** Real hostnames, LAN addresses, MAC addresses and key
   fingerprints. Public files use placeholders such as `<DELL-IP>` instead.
2. **Secrets in argv.** Host auditd records every `execve`, and Wazuh indexes it.
   A password passed on a command line ends up searchable in the SIEM, so the
   runbooks must never show that pattern. See `deploy/soc-recon/wazuh/SECURITY.md`.

Output is one `path:line: rule` per finding. A denylist hit adds `#N`, the line
number of the entry in the denylist, and a hit on a file name reports line 0. The
matched text is never printed, with one exception: a file whose name carries a
denylist entry is reported by that name. A commit message, an author or committer
line and a tag object take the place of the path as `commit-message`,
`<sha>:message`, `<sha>:identity` and `<sha>:tag`. A branch or tag name about to
be published is checked like a path and reported as `ref:<name>`.

A file is read as UTF-8, or as UTF-16 with or without a byte-order mark, and a
stray NUL byte does not make a text file binary. A file with no NUL at all is
read as UTF-8 even where its bytes are not valid UTF-8, so every rule reads it. A
file with NULs that still does not read as text is binary: it meets the denylist
only, its hits report line 0, and stderr names every binary file the run read.

```bash
bun tools/leakcheck.ts                    # every tracked file, as it sits in the working tree
bun tools/leakcheck.ts --staged           # the next commit: index copies plus the author and committer (pre-commit)
bun tools/leakcheck.ts --message <file>   # a commit message, identifier rules only (commit-msg)
bun tools/leakcheck.ts --pushed           # the commits and annotated tags named on stdin, pre-push format (pre-push)
bun tools/leakcheck.ts --pushed --remote <dest>  # a ref <dest> has not seen is bounded by what it lists (git ls-remote)
bun tools/leakcheck.ts --paths <p>...     # files or directories on disk, ignored ones included
bun tools/leakcheck.ts --self-test        # the fixtures in tools/fixtures/leakcheck/
bun tools/leakcheck.ts --only <classes>   # only these rule classes, a comma list of denylist,mac,ipv4,ipv6,fingerprint,argv
bun tools/leakcheck.ts --no-denylist      # the pattern rules only, for a clone with no denylist
bun tools/leakcheck.ts --help
bun test tools/                           # the hooks, end to end, in a scratch repo
```

Exit code 0 is clean, 1 is findings, 2 is a usage or setup error: an unknown
argument, a missing path, a file that cannot be read, a push destination that
cannot be listed, or a denylist that is missing, empty or not text.

The default scan reads each tracked file from the working tree. A tracked file
deleted there is read from the index instead, which is the copy the next commit
records, and stderr names it. `--paths` does not descend into `.git`,
`node_modules` or `.DS_Store`, and stderr names each one it passed over. Name one
directly to scan it.

### Rules

| Rule | What it catches |
|------|-----------------|
| `denylist` | Any literal from the local denylist, in a file or in its path. Hostnames, handles, public addresses and anything else specific to this lab are caught by this rule only |
| `mac-address` | A unicast MAC in any of the usual spellings: `xx:xx:xx:xx:xx:xx`, dashes, the Cisco `xxxx.xxxx.xxxx` form, the `x:x:x:x:x:x` form macOS `arp` prints, and the `enx`/`wlx` interface names Linux derives from it. Broadcast, multicast, all-zero and the documentation block pass |
| `private-ipv4` | An RFC 1918, CGNAT (`100.64/10`) or link-local address. The block definitions, RFC 5737 documentation ranges and `169.254.169.254` pass, and so does a PCI DSS requirement ID, which shares the dotted-quad shape, inside a `- pci_dss...:` compliance list. An address in a comment there still fails |
| `private-ipv6` | A link-local (`fe80::/10`) or unique-local (`fc00::/7`) address or prefix, compressed or not, with a zone index such as `%en0` or in brackets before a port. A bare block head such as `fe80::` or `fd00::/8` names no network and passes, and so does a hex word that is not an address |
| `ssh-fingerprint` | A host or user key fingerprint as `ssh-keygen -l` or the ssh client prints it: `SHA256:` with or without its `=` pad, `SHA1:`, `SHA384:`, `SHA512:` and colon-hex `MD5:`. Lowercase `sha256:` image digests pass |
| `argv-user` | `curl -u user:pass` or `--user`, and the proxy forms `-U` and `--proxy-user`, in any quoting, inside a short-flag cluster such as `-ku` too |
| `argv-header` | A `curl -H` or `--header` value that carries credentials: Authorization, a cookie, or a header named for a token, secret, password, API, access or subscription key, session or credential, with any prefix (`X-Vault-Token`, `Ocp-Apim-Subscription-Key`). A cluster such as `-sH` counts. So does `--oauth2-bearer`, and a cookie sent with `-b` or `--cookie`. A `-b` value without `=` names a cookie file and passes |
| `argv-body` | A `curl -d`, `--data*`, `--json` or `-F` body with an inline field whose name holds a secret word. `@file` bodies pass |
| `argv-env` | `docker`, `podman` or `nerdctl` `run`, `exec`, `create` or `build` with `-e NAME=value` or `--env NAME=value`. `-e NAME` alone, which forwards the caller's variable, passes |
| `argv-agent-auth` | `agent-auth -P <password>` |
| `argv-secret-assign` | A `NAME=value` after `sudo`, `env`, `msiexec`, an `.msi`, a Dockerfile `ENV` or `ARG`, or a container `--build-arg` (each of the last three bakes the value into the image history), where the name holds a secret word. `--build-arg NAME` alone passes |
| `argv-password-opt` | A long option whose name ends in a secret word, with a value: `--password x`, `--db-pass=x`, `--api-key x`. Also `docker login -p`, the indexer `hash.sh -p`, `wazuh-keystore -v`, and `openssl` with `-pass`, `-passin`, `-passout` or `-password` set to `pass:x` or with `-k` or `-K`. A `<PLACEHOLDER>` value still counts, since the line still teaches the pattern. `--password-stdin`, `--password-file`, a `< file` redirect, the openssl `env:`, `file:`, `fd:` and `stdin` sources and the mysql family's own `--password` pass: mysql reads `--password db` as a prompt, so only `--password=x` counts there. A container command's own `--secret`, which names a secret to mount, passes too, but the same option past the image belongs to the image's command and counts |
| `argv-sshpass` | `sshpass -p <password>`. `sshpass -e` and `-f` pass |
| `argv-mysql` | Any `mysql*`, `mariadb*` or `mariabackup` command with `-p<password>` attached, quoted or not. A bare `-p` prompts and passes |
| `argv-net-user` | `net user NAME PASSWORD`, where a quoted name may hold spaces, and `net use [DEVICE] REMOTE PASSWORD` wherever `/user:` sits. A `/switch`, the `*` prompt or `""` in the password position passes |
| `argv-url-userinfo` | `scheme://user:pass@host` or `scheme://:pass@host` (an empty user, as Redis takes it) anywhere in a command |

A name holds a secret word when it contains password, passwd, passphrase, pass,
pwd, token, secret, credential or API key (`api_key`, `api-key`, `apikey`),
singular or plural, so `client_secret`, `PGPASSWORD`, `DB_PASSWORDS` and
`userPassword` count. `bypass`, `compass` and
`passive` do not, and neither does a bare `key`.

Global IPv4 and IPv6 addresses are not flagged by pattern. Put the lab's public
addresses on the denylist.

### Where the argv rules look

Identifier rules read every line of every file. The argv rules read:

- Every line of scripts, YAML and any other text file, except a compose
  `environment:` value and dotenv files, because neither one is a command line.
  The value may be a block on the deeper lines, a flow map or list that wraps
  until its brackets close, or an alias, and the key may be quoted or carry an
  anchor. A bracket left open ends at the next line no deeper than its key, so a
  typo cannot take the rest of the file out of scope. A dotenv file is `.env` or
  `.env.<stage>`, such as `.env.example`. `.envrc` and a `.env*.sh` script are
  shell, so the rules read them.
- In markdown, only fenced blocks. Every fence counts except one labeled as
  prose or output: `text`, `txt`, `plain`, `plaintext`, `markdown`, `md`,
  `mermaid`, `output`, `log`. A `markdown` fence is prose, but a fence nested
  inside it is read like any other. An `env` or `dotenv` fence is a dotenv file,
  and a `yaml` fence gets the compose `environment:` exemption. Fences inside
  blockquotes count. A closer indented more than three columns past its opener
  is content, as CommonMark has it, so the fence stays open. Inline code, tables
  and indented blocks are out of scope.
- Exec-form arrays, where a flag and its value sit in separate items. A flow
  sequence such as `["curl", "-u", "admin:pass"]` is read wherever the argv rules
  look, so a JSON array or a Dockerfile `CMD [...]` counts. It may sit on one
  line or wrap over any number of lines, up to the end of its fence or file. In
  YAML and markdown, a block sequence of `- item` lines, blank lines and
  comments inside it included, and a `>` folded scalar count too, with its
  indentation and chomping indicators in either order (`>2-` or `>-2`). Each one is
  joined back into one command before the rules run. A list that is not a
  command but whose items read as one, such as `net`, `user`, `NAME`,
  `PASSWORD`, is flagged the same way.
- auditd `EXECVE` records, in the raw `a0="..." a1="..."` form or the JSON form
  the Wazuh decoder emits. These are read on every line of every file, dotenv
  files included, so a pasted alert with a secret in it is caught even inside a
  `text` fence. The kernel hex-encodes an argument that holds a space, a quote,
  a control character or a non-ASCII byte. Such an argument is decoded, in upper
  or lower case, as UTF-8, a multi-line `sh -c` script is split into its
  commands, and the identifier rules read the decoded text as well.

Backslash, PowerShell-backtick and cmd-caret continuations join a command back
into one line. In a `.ps1`, `.psm1` or `.psd1` file or a `powershell` fence the
backtick needs no space before it, and neither does the caret in a `.cmd` or
`.bat` file or a `cmd` fence. A doubled mark escapes itself. Elsewhere a backtick
or caret continues a line only after a space, so command substitution with
backticks stays intact. The line is then split on unquoted `|`, `||`, `&&` and `;`, and
each command is checked on its own. A quote that never closes, such as the
apostrophe in `it's`, is literal, so it cannot hide the rest of the line.

To quote an anti-pattern on purpose, put `leakcheck: allow` on that line or in a
comment on the line above. The marker only silences argv rules. It never silences
an identifier.

### Set up on a new clone

The denylist holds the real values, so it is gitignored and each clone makes its
own. A linked worktree reads the main worktree's copy.

```bash
# 1. One literal per line. "#" after whitespace starts a comment.
$EDITOR tools/leak-denylist.txt

# 2. Install the three hooks.
bash tools/hooks/install.sh

# 3. Make sure the commit identity is set. Without user.email, git builds one from
#    the machine's hostname, and pre-commit blocks that when the hostname is on
#    the denylist.
git config user.email
```

The denylist also takes `@include <path>` to pull in another list (relative to
the including file, `~/` allowed) and `@exclude <literal>` to drop one entry from
the result. Entries shorter than four characters are ignored. Matching is
case-insensitive on whole tokens, so an entry `lab-host` matches `LAB-HOST.` and
not `lab-hostname`. Save the list as UTF-8 (UTF-16 decodes too, and a byte order
mark is dropped), with LF or CRLF line ends. A line with a control character, a
NUL or a byte that does not decode stops the run with exit 2, rather than becoming
an entry that can never match.

### What each hook scans

- `pre-commit` reads the index copy of every staged file, so an unstaged edit
  cannot hide a value, and the author and committer lines git will write.
- `commit-msg` reads the message file the way git will store it. When an editor
  ran, git strips the `#` comment lines of its template and the diff `git commit
  -v` appends below the scissors line, and so does the hook. A message given with
  `-m` or `-F` is stored whole, comment lines and scissors line included, so every
  line of it is scanned. `commit.cleanup` is honored, and so is
  `core.commentChar` or its alias `core.commentString`, whichever was set last.
  Under `auto` git picks a comment character per commit; the hook reads the
  choice from the template's own comment lines and, when it cannot tell, scans
  every line.
- `pre-push` reads every commit the remote does not have yet: message, identity
  and the changed files, plus every annotated tag object and the name of every ref
  being published. For a ref the remote has never seen, the bound is what the push
  destination lists right now (`git ls-remote`), by remote name or by URL alike.
  Stale tracking refs therefore hide nothing: a second remote does not inherit
  what `--no-verify` once pushed to the first, and a remote whose URL changed is
  judged by what the new URL holds. A destination that cannot be listed blocks the
  push. Replace refs and grafts are ignored, so the scan reads the same objects
  the push sends.

A submodule entry is counted and its path is checked against the denylist, but its
contents live in another repository and are not read. The fixture files are exempt
from the pattern rules by name, not by directory: the self-test lists them, fails
when another file turns up beside them, and the hooks scan any such file like the
rest of the tree.

### How the hooks fail

`install.sh` writes a small stub for `pre-commit`, `commit-msg` and `pre-push`
into `.git/hooks`. Each stub runs the matching file under `tools/hooks` and
**blocks** when that file is missing or not executable. That is the reason for
stubs instead of symlinks: git skips a hook it cannot run, so a symlink whose
target has gone would let the commit through without a word. The hook scripts in
turn block when `bun` is not on the PATH, and a missing or empty denylist is a
scanner error (exit 2) that blocks as well.

A `core.hooksPath` replaces `.git/hooks` outright, so `install.sh` refuses to run
while one is set at repo scope (exit 2, nothing written). A global one is allowed
only when it chains. After writing the stubs, the script runs each hook through
`git hook run` with the stub told to fail with exit 97, and it fails (exit 2)
unless git reached every stub and came back with that same 97. A dispatcher that
runs the stub and then exits 0 would turn every finding into a pass, and this
catches it. Exit 0 therefore means the hooks are active, not only that the files
exist.

What the stubs cannot cover:

- **A clone where `install.sh` was never run.** Hooks live outside the tree. The
  tracked scan (`bun tools/leakcheck.ts`) and the pre-push hook on a machine that
  has them are the backstops.
- **A linked worktree added after `install.sh` ran.** A global dispatcher resolves
  the worktree's own git dir, so the script writes stubs into every linked worktree
  it finds. One created later needs another run of `install.sh`.
- **`--no-verify`.** It bypasses all three hooks, `pre-push` included, and nothing
  on the server side knows this denylist. A commit made with `--no-verify` is still
  caught by the next normal push, and a push made with it is not caught at all.
  Before such a push, run the range by hand:

  ```bash
  printf 'refs/heads/main %s refs/heads/main %s\n' "$(git rev-parse HEAD)" "$(git rev-parse origin/main)" |
    bun tools/leakcheck.ts --pushed --remote origin
  ```

`git hook run pre-commit` exercises the chain without committing.

Without a denylist, `--no-denylist` still runs the pattern rules.

### What it does not catch

A string match cannot see derived identifiers, such as a hardware combination or
a traffic pattern that points at one household. Those still need a human read
before a push. The name-based rules (`argv-secret-assign`, `argv-password-opt`)
pass a variable or option whose name suggests nothing (`sudo X=hunter2 some-tool`,
`some-tool --flag hunter2`); only `argv-env` fires on any `-e NAME=value`
regardless of the name. A secret passed as a bare positional argument to a tool
the rules do not know passes too, as does the legacy Dockerfile `ENV NAME value`
form with no `=`. A bare key digest with no `SHA256:`-style prefix passes, since
a rule for any 43-character base64 run would flag far too much. The contents of a
submodule are not read. Values already in history stay there: the hooks see what
is being committed or pushed now, and rewriting history is a separate decision.

A container command's own `--secret` is told apart from one that belongs to the
image's command by finding the image: the first word that is not the value of an
option. An option the scanner does not list as a boolean is taken to have a value,
so after an unknown boolean the image reads as that value, and an image's
`--secret x` further on passes as the container's own.

Two behaviors err toward a finding, on purpose. A run of `a0="..." a1="..."`
fields is read as an auditd argv record wherever it appears, not only on a line
that says `EXECVE`, so a fragment pasted without its record header is still read.
A false hit there takes `leakcheck: allow`. A file with no NUL is read as text
even where its bytes are not valid UTF-8, so a Latin-1 file keeps every rule.
Random bytes can then look like an address, and since nothing silences an
identifier, such a file needs a human look. Narrowing either behavior could miss
a real leak.

## noise-lint

`noise-lint.ts` holds every Wazuh suppression rule to the B.0 keying rules
([`phase-b-detection/NOISE-BASELINE.md`](../phase-b-detection/NOISE-BASELINE.md)). A rule in the
noise range 100100 to 100199 must be level 0 under a listed parent (`if_sid` 80792), pin the
image path (`audit.exe` or `win.eventdata.image`), and carry at least two field constraints.
Every matcher must be `pcre2` and not negated, every field anchored `^...$`, and no matcher
may match the empty string or the lint's arbitrary probe value. A pattern that alternates outside a group fails, since its second branch
would carry no anchor and no label. An auditd rule must also pin auid, tty, cwd, uid, euid and
gid, plus the AppArmor label and `argc` in its `full_log` regex. It has exactly one regex, no
`<match>`, and no field named twice. The label is the first thing the regex matches, as plain
text, and must be `runc`, `unconfined` or one of the service profiles from
`apparmor-profiles.ts`. `docker-default` fails: every other container on the box runs under
it. Any rule that keeps an event out of the index (level below `log_alert_level`, `noalert`,
`no_log`) fails outside the range, except the Phase A Suricata rule 100200, which is pinned to
the digest of its body. CDATA fails, and so does an id used twice in the folder.

The pattern checks use JS RegExp as a stand-in for PCRE2, and the two do not read every
pattern the same way: a class that opens with `]`, a POSIX class and an XML entity each got
a label-free branch past an earlier version of this lint. So a noise-range matcher may use
only a named subset, and anything else fails as "outside the pattern subset":

- the characters `A-Z a-z 0-9`, space and `" , - / : = _`, and `.` for any character
- the escapes `\d \. \( \) \? \{ \}` and `\xHH` (so `&` is written `\x26`)
- a class of letters, digits and `. _ + -`, never negated and never empty
- a group, which is the only place `|` may appear, with no empty branch
- one of `*`, `+`, `?` or `{n}` (n up to 999) after an atom, greedy, never two in a row
- `^` as the first character and `$` as the last
- at most 1,000 characters and four levels of group, no class written `[.x.]`, and no
  `{n}` on a group (a group takes `*`, `+` or `?`): PCRE2 refuses to compile what these
  rule out, or can, and JS does not
- two known differences are left inside the subset, both on input that auditd would
  hex-encode before a rule saw it: PCRE2's `$` also matches before a final newline, and `.`
  reads a carriage return and bytes above 0x7F differently in the two engines

The sets hold what the committed rules use. Widening one is a decision to make with the
PCRE2 documentation open, not a way to get a rule through. Inside the subset, 2,000 random
patterns gave the same result in JS and in PCRE2 10.49 on 12,000 inputs, which is evidence
and not proof. The lint is a guard against mistakes. The check that a rules file does what
it should is a logtest run on a scratch manager, where Wazuh's own parser and PCRE2 read it.
A suppression rule may carry only `id` and `level`, and hold only `if_sid`, `field`, `regex`
and `description`. In any rule, `id` is 1 to 999999 and `level` 0 to 16, written as plain
numbers with no leading zero or sign, because Wazuh reads them with C integer parsing and
would take `0003` or a very large value differently from the lint. An `<options>` value must
be one the lint knows. No file may hold `&` outside a comment, a rule must be closed and not
inside another, and `lintDir` fails on any file in the folder that is not `.xml` (the
folder's `.gitkeep` excepted), since the whole folder is mounted into the manager. Every tag in a rules file must be lower-case with
double-quoted attributes and no attribute given twice. That applies to every rules file in
the folder, pack rules included, and it refuses three things Wazuh itself accepts: a
self-closing tag such as `<same_source_ip />` (write `<same_source_ip></same_source_ip>`), an
`<?xml ?>` declaration, and a tag split across lines. No rules file may hold a `<var>`
element (Wazuh substitutes it into patterns after the lint has read them), an `overwrite`
attribute (it edits a rule defined elsewhere, a stock one included), or a comment written
`<!-->` or holding `!>`. Whether Wazuh's parser really reads those differently from the
lint was not measured, so they are refused instead.

```bash
bun tools/noise-lint.ts                 # deploy/soc-recon/wazuh/custom-rules
bun tools/noise-lint.ts <dir>           # another rules folder
bun test tools/noise-lint.test.ts       # planted bad rules it must refuse
```

## apparmor-profiles

`apparmor-profiles.ts` holds each compose service to its own copy of Docker's default
AppArmor profile ([`deploy/soc-recon/apparmor/`](../deploy/soc-recon/apparmor/README.md)). A
profile must equal `docker-default.reference` with only its name changed. Every service in
`docker-compose.yml` must name exactly one profile in `security_opt`, its own, and must not
run privileged. A service with no mapped profile fails. The reference is pinned to a SHA-256
in the tool, so a weakened reference with four copies rebuilt from it fails too. The profile
names the tool exports are the labels `noise-lint.ts` accepts.

The check reads one compose file as written. What compose would resolve from elsewhere is
refused, not followed: `extends`, a top-level `include`, a variable in `security_opt`, a
`runtime`, an override file beside the compose file, a second compose file there
(`compose.yaml`, `compose.yml` or `docker-compose.yaml`, any of which makes it uncertain
which file a bare `docker compose up` reads), and any
`!` outside a comment line (the YAML parser drops tags such as `!reset`, which change what
compose builds).

```bash
bun tools/apparmor-profiles.ts           # check the profile folder and the compose file
bun tools/apparmor-profiles.ts --write   # rebuild the profiles from the reference
bun test tools/apparmor-profiles.test.ts # planted faults it must refuse
```

It cannot see a `COMPOSE_FILE` set in the box's `.env`, which profiles the kernel has
loaded, or what a running
container is confined by: `docker inspect` and `aa-status` on the box answer that.

## wazuh-init

`wazuh-init.ts` holds the manager's own `0-wazuh-init`
([`deploy/soc-recon/wazuh/cont-init/0-wazuh-init`](../deploy/soc-recon/wazuh/cont-init/0-wazuh-init))
to the stock script it shadows (ISA F7). The copy differs from stock in two marked blocks and an
added comment header, nothing else. Block 1 fixes the restart trap: on any start after a
container's first, the stock script failed to restore the always-empty `var/multigroups` and
exited before its config copy. Block 2 is the Tier 2 backup hold: while `/srv/tier2/HOLD` exists,
the copy is skipped and the script exits 75 (runbook 09, § 2).

Each block keeps the stock lines it replaced as `#|` lines. The check drops the header, puts
those lines back, and wants the result to hash to the pinned stock SHA-256 with exactly two
blocks. One changed byte outside a block, a removed line or a third block fails it.

```bash
bun tools/wazuh-init.ts check             # 0 findings, or one line per finding
bun tools/wazuh-init.ts stock             # the rebuilt stock text, to diff against a new image's
bun test tools/wazuh-init.test.ts         # the check's plants, and both scripts run in a sandbox
bun test tools/tier2-hold-scripts.test.ts # the hold in tier2-snapshot and tier2-hold, docker stubbed
bun test tools/tier2-hold-probe.test.ts   # the hold probe on planted markers, graded by rules 100322 and 100323
```

The sandbox runs the stock and the owned text on the Mac, every absolute path moved under a
scratch folder and GNU-only options mapped to BSD ones. It shows the trap on the stock text, the
fix and the hold on the owned text, and the owned text equal to stock wherever neither applies.
What only the box can show (s6 running the bound script, the image's real `permanent_data.env`,
docker, `flock`, a reboot) is left to the scratch-stack drills.

## agentconf-check

`agentconf-check.ts` runs every shared agent group config
(`deploy/soc-recon/wazuh/shared/*/agent.conf`) through Wazuh's own parser,
`verify-agent-conf`, before a commit that changes one (ISA ISC-105). On 2026-11-14 the
Windows group shipped a `registry_ignore` whose text ended in a backslash. Wazuh's XML reader
takes a backslash before `<` as an escape, so the element never closed and the agent rejected
the whole file. Five review rounds read that line. None ran it through the parser.

```bash
bun tools/agentconf-check.ts                     # every group on the box; writes the receipt on a full pass
bun tools/agentconf-check.ts --offline           # the receipt against the working tree, no network
bun tools/agentconf-check.ts --offline --staged  # the same against the index (the pre-commit hook)
bun tools/agentconf-check.ts --self-test         # proves on the box that the gate can fail
bun tools/agentconf-check.ts --host <ssh alias>  # another box than talonsoc, with or without --self-test
bun test tools/agentconf-check.test.ts           # every mode through a fake box
```

The full check needs no running stack. For each group it sends that one file over ssh as a
tar stream, unpacks it into a fresh folder under the box account's home, and runs the checker
in a throwaway container of the manager image the compose file pins (`docker run --rm --pull
never --network none`, the folder mounted read-only at `/t`). The image is the default tag of
`wazuh.manager` in `docker-compose.yml`, read the way `logtest.ts` reads it, so a
`WAZUH_VERSION` override on the box is not seen. With `--pull never`, an image the box does
not hold is a setup failure, not a download. The folder is removed whether the check passed or
failed, and a removal that leaves it behind is a setup failure. Nothing from a config file
reaches the shell: the box script carries its own constants, the image tag and a staged name
the tool makes (`g0.conf`, `g1.conf` and so on), and the file itself goes on stdin. Docker gets
`/dev/null` as stdin, since in an ssh one-liner it would otherwise read the stream.

Each file gets one of three results, one line per group:

- `PASS`: exit 0, exactly one `verify-agent-conf: OK` line, and nothing beside it but warning
  lines, which are shown. The Linux group's `sca` warning that
  `etc/shared/cis_ubuntu26-04.yml` is not found is expected: the policy sits beside the group
  file, not where the checker looks for it.
- `FAIL`: exit 1 and an `ERROR: (NNNN)` line naming the staged file. The line carries the
  checker's error.
- `SETUP`: anything else. A checker started without its `internal_options.conf` stops with
  `CRITICAL: (2301)` for every file, and that reads as setup, never as a verdict on the file.
  So do an ssh or docker failure, an exit code that disagrees with the output, and any line
  the tool does not know. The checker opens every error and warning line with a
  `YYYY/MM/DD HH:MM:SS` timestamp, and a level line without one counts as unknown. Anything on
  stderr is setup as well: docker's stderr is merged into stdout on the box, so what arrives
  there came from ssh or the box shell, and a verdict beside it is not a clean one. So is a
  line that is not plain text. A line ends at LF or CRLF and only spaces and tabs are trimmed
  from it, so a carriage return inside a line, a byte-order mark, a no-break space or any
  control character other than tab makes the whole reply unknown.

Output counts for a file only when it opens with the SHA-256 of that file as the box unpacked
it, which the box script prints before docker runs. A reply meant for another call, or two
calls' output run together, is a setup failure, so an OK is never credited to a file it was not
run on. Exit 0 means every group passed, 1 that the parser rejected at least one file, and 2
that some check could not run and none was rejected. A rejection outranks a setup failure in
the exit code because it is a verdict on a file either way.

On a full pass the tool writes `deploy/soc-recon/wazuh/shared/agentconf.verified`: the image,
then the SHA-256 of each group's `agent.conf` in a fixed order, so a rerun on the same files
writes the same bytes. It is tracked. It sits beside the group folders and never in one,
because a file in a group folder ships to every agent in the group. On any failure the existing
receipt is left as it was, and a file saved while the run is on the box stops the receipt too.
A group folder with no `agent.conf`, a symlinked `agent.conf`, or a group name outside letters,
digits, dot, dash and underscore stops the run before the box is touched. The tool never writes
inside a group folder.

`--offline` needs no network. It fails when the receipt is missing or cannot be read whole,
names another image than the compose file pins, lacks a group, lists a group that is gone, or
holds another hash for a group's `agent.conf`. Each message names the file and says to run the
full check. A symlink directly under the shared folder fails too, from the working tree and
from the index alike: the manager would read it as a group folder no run has checked.
`--staged` reads the shared folder, the compose file and the receipt from the
index, so an edit left unstaged cannot hide what the commit holds. The pre-commit hook runs
`--offline --staged` after leakcheck whenever the commit touches a file under
`deploy/soc-recon/wazuh/shared/`. It asks git for the staged paths there, and a git failure on
that question blocks the commit instead of reading as "nothing staged". The order of work is: edit the config, run the full check,
stage the config with the new receipt, commit. A commit that changes only the compose file does
not trigger it; a receipt left on an old image is caught by the next commit to the shared
folder.

`--self-test` proves on the box that the gate can fail. It sends
`tools/fixtures/agentconf/planted-backslash.conf`, the 2026-11-14 shape, which must come back
`FAIL` with the XML error (`XMLERR: Element '...' not closed`); `clean.conf`, the corrected
shape, which must pass; and `clean.conf` again with the `internal_options.conf` copy left out,
which must come back `SETUP` with the 2301 error. It exits 0 only when all three do. A fixture
edited out of its shape stops the self-test before the box is touched.

What it does not catch:

- The checker is the manager's Linux build. It proves the XML and the settings every platform
  shares. It skips the content of Windows-only elements such as `registry_ignore`, so a pass
  says nothing about those.
- The receipt shows a run happened on these bytes, not who ran it. A hand-written receipt with
  the right hashes passes the offline check, and `--no-verify` skips the hook as it skips
  leakcheck. It is a guard against forgetting, not against someone who means to skip it.
- It checks files before they ship. The check on the live manager after the recreate that
  delivers them is the manual step in
  [`deploy/soc-recon/wazuh/shared/README.md`](../deploy/soc-recon/wazuh/shared/README.md#verify).
- The output shapes it accepts are the ones the box printed on 2026-11-15 from
  `wazuh/wazuh-manager:4.14.9`. A new image that words them differently reads as a setup
  failure until the patterns change, which fails closed.
- A remote shell killed outright leaves its `~/.agentconf.*` folder on the box, holding the
  one config it was sent. A pass, a failure, and a hangup, interrupt or terminate signal each
  remove it; the tests prove the first two, not the signal trap.

## B.1 rule pipeline

A pack rule goes Sigma YAML, then hand-ported XML, then logtest, then live. These four tools
cover the steps before live. Stock `wazuh-logtest` cannot reach a Windows rule at all: the
`windows_eventchannel` decoder is C code that runs only for events off an agent's eventchannel
queue, and logtest runs XML decoders only. So Windows cases go through a port of that decoder
and a shim on a scratch manager, never the live one.

### winevt and winevt-capture

`winevt-capture.ts` pulls events off the Windows endpoint over ssh with `Get-WinEvent`, keeping each
event's `Message` and `ToXml()`, the two things the agent sends. The JSON crosses the wire as
base64 of UTF-8, because the console code page turns the `®` in Microsoft's product strings
into an `r` on the way out.

Redaction is the same across the whole capture, so decoded fields stay comparable:

- Private IPv4 and IPv6 addresses become RFC 5737 and RFC 3849 documentation addresses, in
  each form the tool knows: plain, before a sentence period, a full `in-addr.arpa` or
  `ip6.arpa` name, IPv4-mapped IPv6, and NAT64 (`64:ff9b::/96`, hex or dotted), each
  embedded IPv4 address taking its plain form's alias. A zone index is dropped from every redacted IPv6
  form, a dotted IPv4 tail included (`::ffff:<v4>%12` loses its `%12`), except on a hex form
  with a colon after the zone (`%eth0:445`, a host-and-port form), where the match backtracks
  and part or all of the zone stays; after a bare IPv4
  address a `%` suffix is not a zone and stays. A zone takes any RFC 6874 character (letters,
  digits, `-._~` and `%XX` escapes). An IPv6 address with a dotted tail is read as one address:
  a private one takes the same alias as its hex spelling, and a global one (`2000::/3`) is left
  whole even when its tail looks like a private IPv4 address. The deprecated IPv4-compatible
  form (`::/96`) is known in its dotted spelling only: `::` before a dotted private address is
  redacted, `::` before the same address in hex is not a form the tool reads and passes
  unchanged. Windows does not write that form.
- The machine part of an account SID becomes `0-0-n`, with or without a RID, in either case.
  Its parts are keyed by value, so `0123` and `123` are one machine and share one alias.
  A SID whose first two sub-authorities after `S-1-5-21-` are each exactly `0` is taken as one
  this tool already wrote: it passes unchanged and `n` is reserved so no new alias reuses it.
  That assumes no real machine or domain identifier begins `0-0`; Windows draws those
  sub-authorities at random from 32 bits, so a real one is vanishingly unlikely, and a padded
  `00-0` is not exempt.
- The first field of Sysmon's process and logon GUIDs becomes `00000000`. Sysmon derives it
  from the machine's GUID. It is learned only from an XML `<Data>` field named ProcessGuid,
  ParentProcessGuid, SourceProcessGuid, TargetProcessGuid or LogonGuid (whole name, any case,
  and `Name` the element's only attribute, which is how `ToXml()` writes it, with ASCII
  whitespace allowed around the GUID), never from message text. Once learned, those eight hex digits are replaced wherever they
  appear followed by a dash and not preceded by a letter or digit, in a GUID or not (a
  `<prefix>-error` in a command line is rewritten too: it errs toward replacing). A prefix is
  learned from the field's opening `{xxxxxxxx-` alone, whatever provider wrote it, so a
  truncated GUID or a same-named field from another provider teaches one too; that
  over-redacts and never leaks.
- Hostnames and user names go through `--redact`, which also matches the XML-escaped form.
  Its alias may hold only letters, digits, dot, dash and underscore, so it goes in unescaped,
  and may not look like anything a later pass rewrites (a private address in any form the
  tool redacts, an `S-1-5-21` SID, `0-0-n` included, or eight hex digits before a dash); such
  an alias is refused at parse, by its position.
  A source that would rewrite a tag, an attribute name, a `<Data>` attribute value (a field
  name) or part of an entity reference such as `&amp;` refuses the capture, naming the
  `--redact` by its position and alias (a match that holds a whole entity, the escaped form
  of a source, is fine). No source may
  equal another source, no two mappings may share an alias, and no alias may equal a source or
  contain one anywhere, even inside a longer word, whatever the case or the order; that is
  refused at parse, naming the two mappings by position. Mappings are applied longest source
  first whatever their order on the command line, so a host and its domain (`wkstn.lab.internal`
  and `lab.internal`, both redacted) come out as two aliases, never as the host label beside the
  domain's alias. After every pass has run on a record, any source that still matches the
  redacted text refuses the capture, naming the mapping; that is what stops an alias from
  rebuilding a source with the text around it (`wkstn=host` beside `host.lab.internal=zz`
  would otherwise print the second source). An alias must begin and end with a letter `g` to
  `z` in either case, refused at parse by position: a digit or `a` to `f` at its edge would
  change how a later pass reads an address beside it, so `wkstn=labhost1` on
  `wkstn.<private v4>` would leave the address unredacted. As a second line of defence the tool
  records where each alias was written and carries those spans through every later pass: a
  later rewrite that overlaps an alias, or glues text onto it so it stops being a whole token,
  refuses the capture (`taken into text a later pass rewrote`), and so does a whole-token copy
  of an alias that no span accounts for (`appears in text a later pass wrote`). Not covered:
  two sources whose meeting edges are both punctuation (`$wk$` directly before `.lab`, each
  mapped): once one is replaced the other is no longer a whole token, so it prints and nothing
  refuses. Give such a pair one mapping for the whole string.
- No alias is one the capture already holds: a generated alias skips any already present, and
  a `--redact` alias found as a whole token anywhere in a record refuses the capture. When a
  range runs out the capture is refused, not numbered past the range.
- A base64 run that decodes to text any rule above would change refuses the whole capture.
  Each run of 16 characters or more is decoded at each of the four character offsets, as
  UTF-8, as UTF-16LE and UTF-16BE, each from an even and an odd byte; runs separated only by
  whitespace are also decoded joined the same ways, so a blob wrapped at 76 columns (as .NET
  writes one with line breaks) is checked whole even with a word such as `-EncodedCommand` in
  front of it. The check runs on each record before redaction as well as after, so an alias
  that replaces a source sitting inside a blob (between `+` and `/`) cannot shift or split the
  rest of the blob out of the check's reach. Every two or three pieces next to each other that
join to 16 characters or more, and each run of equal-length lines with and without the piece
after it and without its first or last piece, are read too, so words glued to either end of a
wrapped blob, at any wrap width, cannot hide a source on its first or last line (24,000 random
uneven wraps and every fixed width from 4 to 43 found no leak). Still missed: a blob wrapped at uneven widths whose source spans four or more
pieces with words glued after it (reading every span would be quadratic). Character
references for a line break, tab or space (`&#xD;`, `&#10;`, `&#x20;`, any case, leading
zeros) count as whitespace. That can refuse ordinary text when a `--redact`
  source is very short: across 4.8 MB of markdown, a two-letter source caused 11 false refusals
  and a six-letter one none. A refusal never leaks; use a longer source if it bites. No pattern
  reads inside a blob otherwise.
- A private IPv6 address run together with a colon or a hex digit before it refuses the
  capture, unless the whole run is a valid global (`2000::/3`) address. No pattern can tell
  where such a run begins, and `leakcheck` does not catch the glued form either.
- A private IPv4 address left inside an IPv4-mapped or NAT64 form refuses the capture: one run
  together with a hex digit or colon before it, a `::ffff:0:` (translated) form written in hex,
  a dotted one with a zero-padded octet, and any other form under `64:ff9b:` (the local-use
  `64:ff9b:1::/48` included), which is checked but not redacted. A translated form with a
  dotted private tail is a dotted tail like any other: redacted, zone dropped. A plain `::ffff:`
  form is redacted as before, and a valid global (`2000::/3`) address passes.
- A private IPv4 address followed by a port (`.80`), on its own, as a dotted tail, or embedded
  in hex in an IPv4-mapped or NAT64 form, refuses the capture: no pass redacts the
  `address.port` form and `leakcheck` does not catch it for IPv4. So does a five-part dotted
  run that starts with a private quad (`10.1.2.3.4`), which cannot be told from one. Still
  passing: a private quad that does not start its dotted run (`1.10.1.2.3.80`), a last octet
  over 255 before the port, and a zero-padded first octet (below).

`--raw` keeps private addresses and nothing else.

When ssh fails, or cannot start, the capture exits 2 and prints the exit code or the error's
name only, never ssh's or the remote
shell's error text, which can hold event text, the endpoint's name or an address; run the
ssh by hand to see why.

Not redacted: public addresses, MACs, other devices' hostnames, the 8.3 short name of a
redacted user, Azure AD SIDs (`S-1-12-1-...`), a partial reverse zone such as
`0.0.10.in-addr.arpa`, an IPv6 `address.port` form (`leakcheck` flags a private one), a
private IPv4 address with a zero-padded
first octet (`010.`) or a zero-padded second octet in 172.16/12 or 100.64/10 (plain or in an
`in-addr.arpa` name; inside an IPv4-mapped or NAT64 form it refuses the capture instead; padding
elsewhere is redacted and shares the plain form's alias), base64 shorter than 16 characters, a
literal that sits beside `-` or `_`,
and base64 that is URL-safe, nested, compressed (PowerShell's usual gzip wrapper) or glued to
other text. Address-shaped text inside a
private prefix is replaced even
when it is not a valid address (an octet above 255), and a four-part version string that starts
with `10.` and whose other parts are at most three digits each (`10.0.19045.1`, not
`10.0.26100.9818`) is rewritten as if it were an address: both err toward replacing. So does
a private address or an account SID glued to a letter before it (a letter directly before
`10.` and the rest of an address, or `id` directly before `S-1-5-21-...`):
the automatic passes bound a match on the right and against a digit on the left, not against a
letter, unlike `--redact`, which matches whole tokens only. A `--redact` token boundary is
anything but an ASCII letter, digit, `_` or `-`, so a source glued to a non-ASCII letter
(`alice` inside `éalice`) is replaced as well: over-redaction, never a leak. The automatic passes also read
attribute values, so a `<Data Name>` shaped like a private address or beginning with a learned
GUID prefix and a dash would be renamed; no Windows field name has either shape.

`winevt.ts` turns a capture into the JSON that analysisd's `DecodeWinevt` builds, including
its quirks: values taken from the XML keep cJSON's escaping (a backslash in a path arrives
doubled), `(NULL)`, `-` and empty values are dropped, and the message is the capture's
decoded text wrapped in quotes, so the same backslash is doubled in an EventData field and
single in `system.message`. A control character in the message comes out as cJSON printed it
and `wstr_unescape_json` left it: tab, line feed, carriage return, backspace and form feed
come back raw, every other one below 32 stays as the six characters `\u00XX` (lower-case
hex, `cJSON.c` `print_string_ptr`). An empty `<Channel>` still gives `channel: ""`. Trailing whitespace is
trimmed after that escaping and only as the C locale sees it, so trailing spaces go, a trailing
tab stays as `\t`, a trailing no-break space stays, and an all-blank value keeps one space. A
`Data` with attributes is keyed by each attribute's value, `Keywords` is read as hex with or
without `0x`, and the severity is set only when Level and Keywords are both present. `Security`
adds `securityUserID: "UserID"`, and `Channel` adds `userID: "UserID"` after `channel`, only
when the element's first attribute's *value* is the text `UserID`, which no Windows event
produces; `Correlation` is not read at all. The port does the same, so a real event's
`<Security UserID='...'/>` and `<Correlation .../>` leave no field (the live alert fixture
shows neither). Those
facts come from the 4.14.9 source (`winevtchannel.c`); the rest of the quirks are pinned to
the port's own behavior, and all of them wait on live alerts to confirm them.

It refuses what it does not port instead of emitting part of an event: an attribute value in
double quotes or no quotes (the manager's XML reader sees cJSON's `\"` and errors), an
`<Event>` that never closes or has text after it, a comment, declaration or CDATA section, a
second `<System>` or `<EventData>`, any Event child but `<System>` and `<EventData>`
(`TODO-2`), `<EventData>` with attributes, markup inside a field, two EventData values that
land on one key, two System values that land on one key (a repeated child, two children equal
after the first letter is lowered, a repeated Provider or Execution attribute, or a child named
like a computed field such as `SeverityValue` or `Message`), a `Data` named `categoryId`,
`subcategoryId` or `auditPolicyChanges`
(`TODO-1`, the audit-policy translation), and a Level that is not decimal or a Keywords that
is not hex on its own (analysisd would read the leading digits and carry on; a capture like
that is a mistake). It refuses a NUL (U+0000) anywhere in the XML or the message, and so does
the capture: the agent hands analysisd a C string, so live the event stops at the NUL and only
a truncated message survives, while every later field would decode here (registry key names
with an embedded NUL are a known way to hide a key). It also refuses what `os_xml` rejects or
reads as another shape: a closing
tag with a space before its `>`, a tab, line break or non-ASCII space inside a tag, a `>`
inside an attribute value, an attribute repeated on one element (case-sensitive, as
`strcmp`), an element or attribute named `var` in any case (`os_xml` takes it as a variable),
and a 50th attribute on one element, or a 49th followed by a space (`XML_MAX_ATTR_DEPTH`; 49
directly followed by `>` decodes, as in `os_xml`). `Provider`, `TimeCreated` or `Execution` with no
attributes but some text land, as in the C's generic branch, under `provider`, `timeCreated`
or `execution` holding that text.

The size limit is the manager's: `os_xml` gives up on the whole event when any element name,
text run (counted afresh after each child) or attribute name or value reaches `XML_MAXSIZE`,
20480 bytes at 4.14.9, counted on cJSON's print of the event (a backslash, quote, tab or line
break is 2 bytes, another control character 6, a non-ASCII character its UTF-8 length). Then
`DecodeWinevt` keeps only `system.message`, and so does the port: a positive on a field that
long fails here as its rule would never fire live. Its test holds it to one live alert (Sysmon
EID 10) field for field.

```bash
bun tools/winevt-capture.ts <ssh-host> --id 3 --max 5 --redact <hostname>=labhost --redact <user>=labuser > cap.json
bun tools/winevt.ts cap.json             # one decoded event per line
bun test tools/winevt.test.ts            # the live-alert match, the quirks, the redaction rules, the capture CLI through a stub ssh
```

TODO list for the port, numbered as in `winevt.ts`:

- `TODO-1`: port the audit-policy translation for `Data` named `categoryId`, `subcategoryId`
  and `auditPolicyChanges` (`winevtchannel.c` 370-677). Refused until then.
- `TODO-2`: port the decoding of Event children other than `System` and `EventData`
  (`winevtchannel.c` 294-321, 716-718). Refused until then.

A capture that will be committed is read by eye first, for the things above that no rule
catches, and then goes through `bun tools/leakcheck.ts --paths`.

### logtest

`logtest.ts` runs every case under `phase-b-detection/tests/<rule id>/` through `wazuh-logtest`
on the scratch manager `b1test` on the box. A case is `pos.json` or `pos-<name>.json`
(the rule must fire) or `neg.json` or `neg-<name>.json` (it must not), holding either `{"capture": ...}`
from winevt-capture or `{"event": "<one log line>"}`. A case holding both keys is read as its
capture and the `event` is ignored, not tested; keep one key per case. An `event` shaped as a
Windows event (starting `{"win":` once whitespace is removed, or a JSON object with a
top-level `win` key) is refused: the shim would decode it without the port, so its
backslashes would differ from live. Use a capture for a Windows event. A folder named
`.DS_Store` in the cases tree is refused, as in the rules folder; a `.DS_Store` file is
skipped, and any other dot name in the cases tree is refused.

Each run stages the kit in `tools/logtest/` (compose file, shim decoder) with the live manager
conf, the stock json decoders excluded so the shim decodes first, and the rules folder under
test. It refuses a kit compose that is anything but the `b1test` project with no network: the
service keys are an allowlist of what the kit uses, mounts are short-form only, onto the kit's
own plain-named volumes or a `./<file>` staged beside the compose file, each at the
destination the checked-in kit gives it (so a staged file cannot land over `/var/ossec/bin`),
the environment keys
are an allowlist of the six the kit sets with each value given in the file and on one line (a
bare key, which compose fills from the box's environment, is refused). Any YAML tag (`!reset`,
`!override`, which the parser here would drop but compose obeys) and any `$` (compose
interpolation from the box's environment) other than the two password references the kit
reads from `~/b1test/.env` refuse the kit before it is read (those two variables are also
cleared from the account's environment, which would otherwise override the file), and the image key must
be the tag the live-default check reads. It refuses a rules folder that is a symlink or holds
one, a rules file name outside letters, digits, dot, dash and underscore, and any file but an
`.xml` rules file not starting with a dot (a `.DS_Store` or the repo's `.gitkeep` file is
allowed and never staged, so only rules files reach the box; a folder of either name is
refused, since its contents would never be staged), all before the old manager is removed.
The same checks run again on the staged copy. The kit's compose file and shim are read through
`O_NOFOLLOW` and must be regular files: a symlink or anything else is refused, and the stage
gets their bytes, never a link. The live conf must hold exactly one `decoder_dir` outside
comments; the json exclusion goes after that one.
It then removes the old scratch manager and its volumes, with the variables that steer compose and docker (`COMPOSE_FILE`, `COMPOSE_PROFILES`, `COMPOSE_PATH_SEPARATOR`, `COMPOSE_PROJECT_NAME`, `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`, `COMPOSE_ENV_FILES`, and for tar `TAR_OPTIONS`, `TAR_READER_OPTIONS` and `TAR_WRITER_OPTIONS`, which can name a checkpoint command; other `COMPOSE_*` settings survive and fail closed through the leftover-container check) cleared from the box account's environment first, in every script that runs docker, and run from a fresh empty folder inside `~/b1test` (made after the symlink and mount checks, removed whatever happens unless the remote shell is killed by a signal, which leaves an empty `.down.*` inside `~/b1test`), refusing, with nothing removed, when a compose file (`compose.yaml`, `compose.yml`, `docker-compose.yaml` or `docker-compose.yml`) sits in that folder or any folder above it, since compose with no file named looks upward for one (refusing, with nothing removed, when
a `b1test` container was started from any folder but `~/b1test/stage`: the name is then
someone else's), stages, and starts the manager. A Sigma YAML that does not parse, one in a
subfolder, or a `custom.wazuh.id` that is present but not a plain whole number stops the run
before it touches the box.

Before any case runs, every run checks that what will answer is this tree:

- the stage on the box matches the local one by SHA-256, file for file
- the container runs the kit's image with no network, in the scratch project, and mounts
  nothing but the project's volumes and the staged files
- the conf, the shim and the rule files the manager loaded match the stage by SHA-256
- the init exited 0, and `ossec.log` holds no ruleset error or warning

It also records the manager's container id and start time there, reads them again after the
cases, and treats any change, or no manager left, as exit 2: another run swapped it.

`--reuse` skips the restart and nothing else: without `--keep` the manager is still removed at the end. The image check compares the kit's tag to the
default tag of the live compose file's `wazuh.manager` service (read from the parsed file,
not from the first image-shaped line), not an image id. The live conf must hold exactly one
`<rule_dir>etc/rules/custom</rule_dir>` in its `<ruleset>`, outside comments, or the run
stops before staging, since without it the staged rules would hash as loaded and never load.
Ownership before a removal is checked on the project's containers; its volumes are matched by
the project name alone, so a `b1test` project someone started from another folder and left
with volumes but no container would lose those volumes (that takes the box account). The tool never reads the live project,
so a `WAZUH_VERSION` override on the box is something it cannot see.

The verdicts come from analysisd's own reply (the `-d` transcript), not the formatted phases,
and `wazuh-logtest` must exit 0. The transcript also echoes event text, and a multi-line field
can put a line of its own at column 0, so every reply must carry the session token of the first
one. Event text cannot know that token, and a planted reply line stops the run as a setup
problem. Every verdict, coverage and error line prints on one line: a control character in a
reply value or a message, tab and line break included, prints as `?`, and so does a Unicode
bidirectional format character, which could otherwise reorder the line on screen. `--save`
keeps the transcript raw; a `--save` value starting with `-` is refused, so `--save --keep`
cannot quietly swallow the flag.

A positive passes when its rule is the final one and its reply alerted. A negative fails when
its rule is the final one, or when the final rule descends from it among the rules in the
folder under test through any parent link Wazuh has: `if_sid` and `if_matched_sid` by id,
`if_group` and `if_matched_group` by Wazuh's own group match (`OS_WordMatch`: `|`
alternatives, one starting `^` a prefix, any other a substring, case-insensitive, against the
ancestor's whole group text; for `if_matched_group` a trailing `$` also anchors the end, and
an empty alternative counts as a link), and `if_level` by any ancestor at that level or above
(a level-0 rule counts as 99 there, the way `rules.c` holds it while placing rules), pack or not (a stock rule outside the folder ends the
chain): the event matched the rule, then a child of it fired. For a rule in the XML
under test, the level and MITRE IDs must also be what the XML says; a stock rule (outside the
pack ranges, like the `92900` anchor case in the fixtures) passes on rule id and alert alone. A
pack-range rule the folder under test does not hold fails any case it fires on, positive or
negative: it was loaded from somewhere else, such as a manager kept with `--reuse`. A logtest
warning fails the case it arrives on, positive or negative: that catches an ID `mitre.db`
silently drops, and ruleset warnings, which ride on the first reply. Every pack rule named in
the XML or the Sigma YAML must fire in a passing positive and have a negative, and every XML
file in a subfolder of the rules folder (copied, never loaded) fails the run on its own, even
when a top-level file holds the same ids. A case folder for a pack-range id that neither the
rules folder nor the Sigma YAML names fails the run too, even when its cases pass; a stock-rule
folder such as `92900` needs no rule in the folder. The summary line counts the pack rules
held to that coverage.

```bash
bun tools/logtest.ts                     # the repo's rules and phase-b-detection/tests
bun tools/logtest.ts --rules <dir> --cases <dir>
bun tools/logtest.ts --keep              # leave the manager up; --reuse runs cases on it again
bun tools/logtest.ts --save run.txt      # keep the raw transcript
bun tools/logtest.ts --self-test         # four scenarios on tools/fixtures/logtest
bun tools/logtest.ts --down              # remove the scratch manager and its volumes (refuses a b1test project the tool did not stage)
bun test tools/logtest.test.ts           # the offline half: run() and the self-test against a fake box, the entry point through a stub ssh
```

`--self-test` runs the fixture pack (must pass with exactly its five verdicts), a planted copy
of a positive filed as a negative (must fail on that case alone, with no coverage failure
beside it), the same rule with its condition negated (must fail
both of its cases), and the rules file moved into a subfolder (must report the subfolder file
and both rules never fired, with no reply naming either rule). A scratch manager it cannot
remove at the end is exit 2, not a failed check.

Exit code 0 is pass and 1 is a failing case, a coverage gap or a `--self-test` check that does
not hold. 2 is everything else: a setup
problem, a folder or file the tool cannot read or write, a `--sigma` folder named on the
command line that does not exist (the default may be absent), a Sigma YAML that does not parse,
sits in a subfolder or is not one mapping (a multi-document or empty file), a rules folder
holding a file that is not an `.xml` rules file, a `b1test` project the tool did not stage, a
manager swapped while the cases ran, a scratch manager it could not remove.

What it does not cover:

- Two runs at once. Nothing locks `~/b1test` on the box, so run one at a time. A run whose
  manager was replaced while its cases ran stops with exit 2 instead of reporting another
  tree's replies.
- Someone who already holds the box account. The checks for a symlink at `~/b1test`, its
  `.env` or its `stage`, and for `~/b1test` or `stage` being a mount point, stop an accident,
  not a race. A mount under the stage is skipped (the old stage is removed with
  `rm -rf --one-file-system`); a mount at the stage or at the scratch folder is refused when
  it is another filesystem (the check compares device numbers with the parent, which is also
  all `--one-file-system` sees), and so is a folder the box cannot stat. A bind mount of a
  folder on the same filesystem passes both, and the stage's removal would then reach the
  bound folder; placing one takes root on the box, which is past the account this list is
  about. The account's `HOME` is trusted as it is. Under `--reuse`
  the hashes prove the staged and loaded files, not what analysisd holds in memory: rules
  swapped under a kept manager by that account, without a restart, pass the hashes and answer
  from the old ruleset. A local edit cannot do that; `--reuse` skips the deploy, so a changed
  tree fails the stage hash and exits 2.
- State between cases. They share one logtest session, so a rule that counts events sees the
  cases before it.
- The decoder. A negative passes whatever decoded it, and it need not reach its rule's parent.
- What live keeps in its `wazuh_etc` volume. The scratch manager loads the image's own
  `etc/rules/local_rules.xml`, `etc/decoders/local_decoder.xml` and `etc/lists/`, while live
  loads whatever its persistent volume holds, edits made from the dashboard included. A live
  child of a pack rule added there (say `<if_sid>100340</if_sid>` in live `local_rules.xml`)
  is invisible here: a positive passes and live alerts on the child; no negative can see it.
- A non-default docker context, or a container someone else built. The scripts clear
  `DOCKER_CONTEXT` and `DOCKER_CONFIG`, so docker then reads the account's own config; if that
  selects another context, the removal and everything after it run against that daemon. Under
  `--reuse` the running container's mount destinations are not inspected, so a `b1test`
  container built by hand could carry an extra project-named volume over `/var/ossec/bin`. Both
  take the box account.
- Stock decoders. Every other stock `0NNN-` decoder file (the json one is excluded in scratch)
  loads before the shim, and a verdict ignores
  which decoder answered, so a stock decoder with an unanchored prematch on event text could
  take a Windows line in scratch. Unverified: the stock decoders are not in this repo.
- Limits on the agent's side. An event over `OS_MAXSTR` is cut by the agent and fails to parse
  live, and the joined unnamed `data` is truncated at `OS_MAXSTR` (`winevtchannel.c` 279); the
  port does neither.
- A case folder whose all-digit name is longer than any rule id. It reads as a number outside
  the pack ranges, so a negative in it passes for nothing; coverage still requires real cases
  for each pack rule.
- What `--down` leaves behind: `~/b1test/.env` (scratch-only passwords, mode 600) and the
  `stage/` folder stay on the box until the next run replaces them. On a box with no
  `~/b1test`, `--down` creates it empty (the removal's temp folder lives inside it) and leaves
  it.

Relative option paths resolve against the current folder here, and against the repo root in
sigma-lint.

Every scratch run is SIEM noise: the manager's init and each `docker exec` are host execs that
auditd records and agent 002 ships.

### Open test gaps

Found by the round 3 review (both vendor legs, 2026-11-06). Each is a mutation the offline
tests would not catch; the guard itself exists and the live runs exercise it. Numbered so a
later change can close one by number.

1. `logtest.test.ts`: the fake box answers the loaded-files hash from the local stage, so a
   `LOADED` script that hashed the stage on the box instead of the files inside the container
   would pass.
2. `logtest.test.ts`: the symlink guard's `stage` member has no probe; only `~/b1test` and its
   `.env` are planted as symlinks.
3. `logtest.test.ts`: nothing asserts that the three staged files are mounted at their container
   destinations; the fake supplies the mount list.
4. `logtest.test.ts`: a `null` exit code from a killed process is untested, and the stub `ssh`
   logs `$*`, so `--` and the host passed as one argument would look the same.
5. `logtest.test.ts`: a reply with no `alert` key and more replies than cases are
   untested.
6. `winevt.test.ts`: the Level saturation test needs a value that tells the clamp apart (such as
   `LONG_MAX` plus 4); the capture CLI's `--log`, `--id`, `--record`, `--since` and `--max` are
   not decoded back out of the stub's argv.
7. `sigma-lint.test.ts`: `critical` mapping to 15 is never exercised, and relative option paths
   resolving against the repo root is untested.
8. `winevt.test.ts`: the Provider `EventSourceName` attribute has no fixture or synthetic test,
   so removing its handling would pass.
9. `logtest.test.ts`: the scratch-project tests do not assert the remote working directory in
   which `.env` and `stage` are created, and nothing proves `run()` stages `scratchConf`'s
   result rather than the live conf.
10. `logtest.test.ts`: the `grep -qx 'name: b1test' stage/compose.yml` guard in every scratch
    script, the coverage id dedupe, and `--max 0` in the capture are untested; `--save` writes
    the transcript before the swap recheck, so a swapped run's saved file can be another tree's
    (the exit code says so).
11. `wazuh-rules.test.ts`: the `!>` comment terminator (an `os_xml` quirk) is untested.
12. `logtest.test.ts`: the fake box answers any script holding `wazuh-logtest -d` from a
    recorded transcript, so the static script audit constrains the docker, compose, guard and
    removal text but not every other command or path a script could carry.
13. Closed: `<name/ >` is now read as `os_xml` reads it (the `>` belongs to the tag), and
    anything but spaces between the `/` and the `>` is refused (2026-11-08).
14. `logtest.test.ts`: the staged compose-file operand (`-f stage/compose.yml`) is not asserted
    on its own, and the kit allowlist tests could be satisfied by a narrower denylist; the
    multi-document Sigma test in `sigma-lint.test.ts` asserts the finding text only.
15. Unpinned by any test (a loosened guard would pass): `SAFE_LOG` on the capture's `--log`
    value, `remote()`'s ssh options beyond `--` and the host, self-test check C's two-case
    requirement, an empty `<Level></Level>` beside Keywords, TimeCreated's first-attribute
    rule, level 3 and 5 names, IP-shaped `--redact` aliases counted as taken, the lint's
    odd-argument usage refusal, the `rules*` folder set and the one-id-in-two-files refusal
    of `--refresh-sigmahq`, the 5-minute socket wait, a second positional host and the ssh
    timeout branch of the capture.
16. `logtest.test.ts`: the kit allowlist tests deny named keys but do not pin the allowlist
    itself (a key added to `KIT_KEYS` or `KIT_ENV` would pass); the level and MITRE checks are
    tested in one direction only (a higher level or an extra technique beside the expected one
    would pass a weakened comparison).
17. `logtest.test.ts`: the fake box hashes whatever was staged, so staging the live `ossec.conf`
    unmodified instead of `scratchConf(live)` would pass (the `scratchConf` unit tests still
    hold); the `stage` member of the symlink guard has no probe (only `~/b1test` and `.env` do,
    as item 2 says); the event-to-stdin check searches scripts for the whole fixture event, so
    a regression interpolating part of an event into a script would pass, and no case event
    with shell metacharacters is tried; `--self-test` is tested as a function, never through
    the command line, so the exit-code wiring at the end of the file is unpinned.
18. `logtest.test.ts`: the reply-count check is tested with fewer replies than cases, not more;
    the kit allowlist tests try `LD_PRELOAD` as the one unknown environment key and never
    `entrypoint` as a service key (item 16's allowlist pin would cover both).
19. `sigma-lint.test.ts`: the multi-document test hands `lintPack` a ready-made array instead
    of writing a two-document file through `readSigma`, so a reader that kept only the first
    document would pass it.
20. `sigma-lint.test.ts`: the level compare is pinned in one direction only (flagging only a
    lower YAML level would pass), and a YAML with no `level:` key is never linted (the lint
    flags it; a lint that skipped it would pass). The `if_sid` compare is now pinned both ways.
21. `winevt.test.ts`: the `0-0-n` SID exemption has no SID whose first sub-authority is `0` and
    second is not, so a check weakened to the first `0` alone would pass that SID unredacted;
    a capture holding only the `in-addr.arpa` name of an alias is never tried, so dropping the
    reversed form from the taken set would pass; an unnamed `<Data>-</Data>` or
    `<Data>(NULL)</Data>` joined into `data` is untested. `logtest.test.ts`: no negative case
    has a rule that fires without `alert`, so a negative check weakened to alerting replies
    only would pass.
22. `logtest.test.ts`: the scratch-only tests check the scripts for `docker` counts, the live
    project name, the one `rm` and named fragments, so an extra write added to a script
    (`: > "$HOME/outside"`, `mkdir`, `mv`, `find -delete`) would survive them, and the fake
    home is deleted whole at the end; an event base64-encoded into a script and decoded there
    would pass the stdin check, which looks for the fixture event and its JSON-escaped form
    only; an inspect answer with an empty id or start time is never tried, so dropping that
    refusal would pass; the `ossec.log` query's exit status is never nonzero in the fake, so a
    call site that stopped checking it would pass.
23. Guards a weakened copy would ship: no 16-character base64 run is tried, so raising the blob
    floor to 17 would pass; the `--max` upper bound of 500 is unpinned; the capture's `fail()`
    branch for an unexpected (non-`CaptureError`) throw, which prints the error's name and not
    its message so no captured value reaches stderr, is untested; the decoder's refusal of a
    non-string `message` is untested; `OWN_MOUNT` widened to any bind under the home would pass
    (the tests try `/opt/...` and a `..` path, never `~/elsewhere/x`).
24. `winevt.test.ts`: the ssh stub answers with a canned capture whatever script it is sent,
    so the generated PowerShell (UTF-8 encoding, `Message` plus `ToXml()`, the JSON shape) is
    pinned only by its XPath substring. `sigma-lint.test.ts`: the set comparison of technique
    tags is tried with duplicates, never with the same techniques in another order.
25. `logtest.test.ts`: the mount check is never tried with a sibling sharing the stage's
    prefix (`~/b1test/stage-other/...`), so a boundary weakened to a bare prefix would pass; the
    session-token check is tried only with a wholly different planted token, never one that
    differs in its last character; the C0 and C1 ranges in `clean()` are sampled, not walked;
    the top-level key allowlist is never tried with `include`. `sigma-lint.test.ts`: "the
    checked-in tree is clean" holds trivially while the pack is empty (it pins no inventory),
    and `custom.wazuh.id: 0` is reported as "not a whole number" rather than outside the pack
    ranges (a finding either way).
26. Weakened copies the suite would ship: the removal's compose-file walk stopped at the home
    (no test plants a file above it); `--reuse` without `--keep` no longer removing the manager;
    self-test B's "that case only" loosened to "includes"; the case-file line-break check
    narrowed to `\n`; attribute values not cJSON-escaped; an empty message dropped; a GUID
    prefix learned from a `<Data>` with extra attributes; a prefix after a `g` to `z` letter
    zeroed; a signal-killed ssh (exit code `null`) treated as success; the duplicate Sigma id
    tried upper-then-lower only; technique tags that are a strict subset of
    `custom.wazuh.mitre` passing.
27. Also unpinned: the `checkKit` and `kitImage` calls inside `stage()` (the helpers are tested,
    their call sites are not; see item 17 for `scratchConf`); the capture's process-level ssh
    timeout (every stub exits at once); the
    SigmaHQ refresh reading `rules-*` folders other than `rules/`; duplicate XML ids sent
    through `readRulesDir` and the CLI rather than two concatenated parses.
28. Also unpinned: `::` standing for zero groups in the IPv6 reader; a Provider attribute named
    `constructor` and the `system` object's prototype (only EventData has a `__proto__` test);
    a 3-byte character counted as 2 at the 20480 limit; the ssh alias grammar beyond a leading
    dash; a truncated GUID or a foreign provider's `ProcessGuid` in the learning tests; the same
    `if_sid` or MITRE values in another order; a single-character alias from `a` to `f` (only
    `0` is tried); the third distinct private IPv4 taking the third documentation alias (the
    tests stop at two). The `chmod 000` case is skipped when the suite runs as root.

### sigma-lint

`sigma-lint.ts` holds each YAML in `phase-b-detection/sigma/` to its XML rule. It reads `.yml`
and `.yaml` in any letter case. A YAML in a subfolder, or one that does not parse, stops the
lint (exit 2) and stops logtest; a file that is empty or holds more than one document is a
finding. A mapping that repeats a key is read with the last value only (the YAML parser keeps
the last; YAML itself forbids repeats), so a first `if_sid:` that disagrees with the XML is
never seen: keep each key once. When the default folder is absent the lint prints one notice line and checks only the
XML. The YAML carries the Wazuh side in `custom.wazuh` (`id`, `if_sid`, `level`, `mitre`). The
id must be in a pack range and the level must be what the Sigma level maps to (medium 10, high
12, critical 15). Each field the lint compares must have its type: `id`, `level` and every
`tags`, `mitre` and `related` id entry a string; `custom.wazuh.id` and `custom.wazuh.level`
numbers; `custom.wazuh.if_sid` a number or a comma string such as `"61603, 61605"`. A field of
another type, a one-element list included, is a finding naming the field, and logtest refuses
a `custom.wazuh.id` that is not a number. The XML rule must exist once, at the top of the rules folder, with the same
level, `if_sid` and MITRE IDs (read from every `<mitre>` block), and with one `<if_sid>` and
one `<mitre>` element. Each MITRE ID must be in `phase-b-detection/mitre-db-ids.txt`, neither
revoked nor deprecated there, and written as `TNNNN` or `TNNNN.NNN` exactly (a padded,
lower-case or otherwise non-canonical id is a finding), because Wazuh drops an ID its
`mitre.db` lacks, stores the element's text as written, and whether it trims at alert time is
not known. The YAML also needs a UUID,
a `detection` that is a mapping with a non-empty string `condition`, every `related` entry a mapping with a string `type` and a string `id`
whatever its type, one of them of type `derived` whose id is in
`phase-b-detection/sigmahq-ids.txt` and not deprecated there, and technique tags that name the
same techniques as `custom.wazuh.mitre`, compared without regard to case; any tag that starts
`attack.t`, in any case, and is not `attack.tNNNN` or `attack.tNNNN.NNN` is a finding. A pack
XML rule with no YAML fails, and so do
any XML in a subfolder and any rule id defined twice in the folder, pack or not. logtest
refuses the same repeated id with exit 2 before it touches the box: Wazuh keeps a rule where
its first copy was placed and takes an `overwrite` copy's group and level, which a single id
map cannot model.

A Sigma `id` used by two YAMLs fails like a reused Wazuh id (compared without regard to case).
What the lint does not check: the contents of a `<rule>` beyond
its structure and attributes (a missing `<description>`, an element Wazuh does not know).
The manager refuses such a rule at boot (`rules.c`: "No such description", "Invalid option"),
and logtest then stops on the ruleset error in `ossec.log` with exit 2, so a rule the lint
passed but Wazuh would not load never reaches a verdict.

The rule reader walks every element in the file the way `os_xml` does, and takes element and
attribute names in any letter case, as Wazuh does (`strcasecmp` in `rules.c`). A start tag must
read as `name="value"` or `name='value'` pairs, with space allowed after `=` but not before it;
as in Wazuh, a backslash makes the next `<` text, but `<!` still opens a comment and the
backslash still applies to the first character after it; attributes on `<id>` inside `<mitre>`
are ignored. A file it cannot read whole stops the lint and logtest, because a rule they
skipped would pass every check: a start tag that does not read as pairs, an attribute given
twice, a `<rule>` attribute Wazuh does not know (it knows `id`, `level`, `maxsize`, `timeframe`,
`frequency`, `accuracy`, `noalert`, `ignore` and `overwrite`), a `<group>` attribute other than
`name`, an id that is not a whole number of at most 6 digits (leading zeros count), a level
that is not a whole number from 0 to 16, an
unclosed or mismatched element, an unclosed comment, a `<rule>` outside any `<group>`, a child
of `<group>` that is not a `<rule>` (a nested `<group>`, a `<decoder/>`), an `if_sid` that
is not digits, commas and spaces (Wazuh skips such a rule and decodes no character references),
an element with no name, an unquoted attribute value, a child element inside any element read
as text (`if_sid`, `if_group`, `if_matched_sid`, `if_matched_group`, `if_level`, a rule's
`group`, `description`, `<mitre><id>`: os_xml keeps only the text after the last child, so
the two sides would read differently), an `if_sid` part or the standing `if_matched_sid` above
999999 or an `if_level` above 16 (Wazuh reads them with `atoi`, which wraps; 17 to 99 is
legal in Wazuh, refused here as the narrower choice), and a top-level rules file whose name
does not begin with a letter (Wazuh loads every rule file in basename order across all
`rule_dir`s, and a name such as `0599-x.xml` would load among the stock files). An `if_sid`
ending in a comma or space, or naming parent 0, is refused: Wazuh reads the empty last part as
0 and hangs the rule under a stock template rule as well (`rules_list.c` 136-160). Sizes are
checked as `os_xml` counts them on the file's bytes (invalid UTF-8 is counted after decoding,
3 bytes per replacement character, so the count never runs low): an element name (the `/` of a closed
element included), an attribute name or value, or a text run reaching 20480 bytes stops the
read; a comment inside a text run neither adds to the run nor restarts it, as in `os_xml`. The reader does not check `os_xml`'s 48-attribute or 1024-level nesting limits.
It also refuses a non-ASCII space where a tag needs a space (`os_xml` splits on the six ASCII
spaces only), a `>` inside an attribute value, an empty `<group>` (which fails the whole file
in Wazuh), and a `<mitre>` child other than `id`, `tacticID` or `techniqueID`. A `<mitre>`
block is read as `rules.c` reads it: one that mixes `<id>` with the tactic and technique form,
holds a lone tactic or technique, more than one of either, or an empty child is dropped, so the
lint then reports the YAML and XML disagreeing; a valid tactic and technique pair throws away
every `<id>` in the rule, and the lint reports a pair on a pack rule as a finding, since the ID
list holds techniques only. The reader passes a rule child Wazuh does not know (a typo such as
`<descripton>`), which fails the whole file in `rules.c`: the lint is clean on it, and logtest
stops at the ruleset error in `ossec.log` with exit 2. logtest judges the staged copy of the
rules folder, read after staging, so the rules it judges are the ones it verified on the box.
Several `<if_sid>` elements are joined the way Wazuh joins them, text to text with no
separator, so a second element only adds a parent when the first ends in a comma; a repeated
`<if_sid>` is a finding on pack rules only.

```bash
bun tools/sigma-lint.ts                  # phase-b-detection/sigma against the custom rules
bun tools/sigma-lint.ts --sigma <dir> --rules <dir> --mitre <ids file> --sigmahq <ids file>
bun tools/sigma-lint.ts --refresh-mitre <mitre.db> "wazuh/wazuh-manager:<tag>" [--out <file>]
bun tools/sigma-lint.ts --refresh-sigmahq <path to a SigmaHQ/sigma checkout> "SigmaHQ/sigma <short hash>, <date>" [--out <file>]
bun test tools/sigma-lint.test.ts        # planted disagreements, the level mismatch among them, both refresh commands
```

Exit code 0 is clean and 1 is lint findings. 2 means the lint could not run: no rules folder,
a `--sigma`, `--mitre` or `--sigmahq` path that does not exist (the default MITRE and SigmaHQ
lists included), a rule the reader cannot read, a YAML that stops the read, an ID listed twice
in either list, or a list line holding anything but an id and the one status word its refresh
command writes. A `tags:` that is a single string rather than a list is a finding.

Refresh the MITRE ID list after every manager image change. A database that returns an id
twice stops the refresh (exit 2) and nothing is written, because the lint would refuse that
list. Copy the database out of a stopped
container with `docker cp <container>:/var/ossec/var/db/mitre.db <folder>`, which runs nothing
inside it. Nothing compares the image named in the list's header to the compose tag, so that
check is by eye.

Refresh the SigmaHQ list from a checkout of `SigmaHQ/sigma` (a shallow clone is enough). The
command parses every `.yml` under `rules*/` and `deprecated/` and takes the id of its root
mapping (an indented rule or a quoted id still reads; a rule that does not parse, is not a
single mapping or has no UUID id stops the refresh, naming the file), marks the deprecated
ones, and records the checkout's `HEAD` in the header; the checkout must be clean, untracked
and ignored files included (SigmaHQ's own `.gitignore` ignores `build/`, `lib/` and `var/`
anywhere, so a stray YAML under one of those would otherwise be read and not reported), so
that `HEAD` names exactly the files read, else the refresh stops (exit 2) and writes nothing.
The check runs once, before the read; a file changed by another process between the two is
not caught, so refresh from a checkout nothing else is writing to. The walk follows a tracked
symlink like any folder, so a checkout where someone committed a `rules-*` link to a folder
outside it would read that folder as part of `HEAD`; upstream tracks no symlink, and such a
checkout is one the operator altered on purpose. Ids are read in lower case,
so the same id listed twice in different cases stops the lint (exit 2). `unsupported/` and `other/`
are not read, so a pack rule derived from a rule there is told its id is not a SigmaHQ rule id;
that is deliberate. Relative paths on both refresh commands resolve against the repo root, and
a label holding a line break is refused (exit 2), because it would write extra lines into the
list.

## art-harness

`art-harness.ts` runs a fixed list of Atomic Red Team tests on the Dell over ssh, so that B.5
can show which pack rules fired on a real run (ISA F5). It runs on the Mac and drives the Dell
the way `winevt-capture.ts` does: one `powershell -NoProfile -NonInteractive -EncodedCommand`
per step, through the same `sshArgv`. Its Dell-side scripts first ran on the Dell on
2026-11-22; what that showed and what it did not is under Limits.

```bash
bun tools/art-harness.ts check-allowlist --atomics ~/code/atomic-red-team
bun tools/art-harness.ts build-manifest --module <Invoke-AtomicRedTeam dir> [--module <powershell-yaml dir>] --atomics ~/code/atomic-red-team [--check]
bun tools/art-harness.ts stage --module <dir> [--module <dir>] --atomics ~/code/atomic-red-team --out <new dir>
bun tools/art-harness.ts check-prereqs --host <ssh alias> (--guid <guid>... | --all)
bun tools/art-harness.ts run --host <ssh alias> (--guid <guid>... | --all) [--timeout <s>] [--allow-remote-code]
bun tools/art-harness.ts --self-test       # every planted fault through a fake Dell, offline
bun test tools/art-harness.test.ts         # the same and more, offline
```

Exit 0 is a pass. 1 is a failed check or a failed session (a test may have run), and for
`check-prereqs` a test whose prerequisites are not met or could not be read. 2 is a setup
failure: something on the Dell did not meet a gate, or a remote call failed, and no test was
sent. 3 is a refusal: the input was not allowed and nothing was sent.

A session's `pass` verdict means it met every gate and left the Dell as it found it: each test
ran once and was cleaned up, and neither the state snapshot nor the staged tree changed. It says
nothing about detection; whether a test fired its rule is B.5's question, read from the alert
index against the record's windows. A test the module killed at `--timeout` is data, not a
failure: the session goes on and can still pass, but the test is listed in the record's
`timedOut` and printed as a `TIMEOUT` line, never hidden.

### The two files it reads

`atomics/allowlist.json` is the only source of test GUIDs. It records the atomics commit, the
module version and, per test, the technique, the test number and name as the atomics YAML has
them, the GUID, the executor, whether elevation is required, the input names whose defaults the
test runs with, the URLs its defaults fetch, whether it runs what it fetches, and the pack rules
it is meant to fire. Kyle's ruling of 2026-11-15 is GUID only, never `-InputArgs`, so every test
runs with its defaults. Rule 100344 has no entry: its only test, `T1105 #18`, needs a
non-default `curl_path`, so it is a classified miss in B.5 unless that ruling changes. The tool
refuses to load an allowlist with a repeated GUID or test, a GUID, technique, rule ID or URL of
the wrong shape, an unknown key, or a commit or module version other than the ones pinned in
the tool. `check-allowlist` holds each entry to the checkout: the commit (`git -C <dir>
rev-parse HEAD`), no uncommitted change under a named technique folder, the GUID at that test
number and nowhere else in the file, the name, executor, elevation, Windows support, the input
names, and every `url` input's default in `fetches`.

`atomics/manifest.json` pins what is staged on the Dell under `C:\AtomicRedTeam`, by SHA-256 and
size: every file of two modules (nupkg packaging left out: `_rels`, `package`,
`[Content_Types].xml`, the `.nuspec`), `Invoke-AtomicRedTeam` 2.3.0 and the `powershell-yaml`
0.4.12 it requires, both versions pinned in the tool; each allowlisted technique's YAML; and
only the files one of the tests references. Nothing else from a technique folder is staged, so
no `uacme.zip`, `GUP.exe` or unused DLL. Today that is 72 files, 1,895,184 bytes: 40 module
files, 14 `powershell-yaml` files, 14 YAMLs and 4 referenced files. It carries the allowlist's
hash, so an allowlist change needs a rebuild. `build-manifest --check` compares the file with
what the sources give now. `stage` copies exactly the manifest's files into a new folder,
checking every hash, for transport to the Dell.

The referenced files are derived from the pinned YAML, never typed in. For each test the tool
fills the default inputs into its command, cleanup command and each dependency's prerequisite
and get-prerequisite command, then reads every `PathToAtomicsFolder` (with or without `$`, any
case, as the module's `Merge-InputArgs` does) in those and in the defaults themselves. The
manifest's `tests` list shows, per GUID, the files each one brought in and any reference that
leaves the atomics folder (only `T1614 #1`'s get-prerequisite download into
`..\ExternalPayloads`, which the harness never runs). `build-manifest` fails when a referenced
file is missing from the checkout or is a link, and fails closed rather than staging a folder
when a reference cannot be resolved for certain: a wildcard, a variable, a folder, the bare
folder, an input whose default holds another input, or an input the test does not define. When
loading a manifest, the tool refuses any atomics file that is neither a YAML nor in some test's
list.

| Test | Files it brings in |
|---|---|
| `T1547.010 #1` (100401) | `atomics/T1547.010/bin/PortMonitor.dll` |
| `T1546.011 #2` (100405) | `atomics/T1546.011/bin/T1546.011CompatDatabase.sdb` |
| `T1547.001 #6` (100406) | `atomics/T1547.001/src/batstartup.bat` |
| `T1105 #26` (100343) | `atomics/T1105/src/T1105-download-file.vbs` |
| the other 13 | none beyond their YAML |

`powershell-yaml` 0.4.12 loads `lib/net47/YamlDotNet.dll` and `PowerShellYamlSerializer.dll`
with `[Reflection.Assembly]::LoadFile` when it is imported under Windows PowerShell 5.1. At
import it does nothing else: it defines an enum, compiles a regex and exports
`ConvertFrom-Yaml` and `ConvertTo-Yaml` with their aliases. A DLL with a mark of the web can
fail to load under .NET Framework; `scp` sets none.

### A session

1. **Refusals, before ssh.** A GUID not in the allowlist, a test that runs fetched code without
   `--allow-remote-code`, a manifest that does not match the allowlist or still owes a module,
   and a bad timeout each stop the run with exit 3 (ISC-152).
2. **Gate.** The Dell lists every file under `C:\AtomicRedTeam` with its size and SHA-256, and
   counts links and reparse points. One changed, missing or extra file, a link, or no folder
   means no test is sent (ISC-155). Changed and missing files are named from the manifest; an
   extra file is counted, never named, since its name came from the Dell. The same check refuses
   a `privateConfig.ps1` in `C:\AtomicRedTeam`, which the module's `config.ps1` would otherwise
   run. Defender must report real-time protection on, `ExclusionPath` exactly `C:\AtomicRedTeam`
   (one entry, compared without regard to case), and no process, extension or address
   exclusion; a null or empty entry counts as none, on the Dell and on the Mac, so PowerShell's
   `@($null).Count` of 1 never passes as one exclusion (ISC-150). The ssh token must be elevated.
3. **Restore point.** `Checkpoint-Computer` with a description unique to the session, then the
   tool confirms exactly one restore point of that description exists and none did before. When
   Windows skips it (a second one inside 24 hours, unless `SystemRestorePointCreationFrequency`
   is 0) or the call fails, no test starts and the message says why and what the value is
   (ISC-154, ISC-157).
4. **Snapshot.** The Dell returns definitions in eight categories: services (start mode,
   account, binary path, delayed start, type; never whether it runs), scheduled tasks (actions,
   triggers, principal, enabled and hidden flags; never last or next run, state or result), Run
   and RunOnce under HKLM and HKCU in both registry views, WMI filters, consumers and bindings in
   `root\subscription`, local users (last logon left out), Administrators members by SID, every
   Defender preference, and `watched`: the registry keys and folders the 17 tests write to
   (`HKCU\Environment`, the print monitors, the two AppCompatFlags keys, the LanmanServer
   parameters, `Policies\System`, both Startup folders and `apppatch\Custom`). The last
   category is mine, beyond ISC-153's list, so a residue such as `EnableLUA` left at 0 fails the
   session.
5. **Per test.** A run step, then a cleanup step whatever the run step did: a timeout, a
   refusal or a remote error included. Each step re-checks on the Dell, before the module
   loads: the GUID against the allowed set the script carries, the elevated token, the staged
   tree's digest against the manifest's, the Defender gate, and the session's restore point.
   Then it imports `powershell-yaml` and the module from `C:\AtomicRedTeam` by path and checks
   each one's loaded version (0.4.12 and 2.3.0) and folder, takes the UTC time from the Dell's clock, runs
   `Invoke-AtomicTest <technique> -TestGuids <guid> -PathToAtomicsFolder C:\AtomicRedTeam\atomics
   -TimeoutSeconds <n> -NoExecutionLog -Confirm:$false` (with `-Cleanup` for cleanup), and takes
   the time again. The tool never passes `-GetPrereqs`, `-InputArgs` or `-PromptForInputArgs`.
   A test counts as run when the module printed its `Executing test:` key once, naming that
   test, and its `Done` key once; the exit code is the line before `Done`. A test that exits
   non-zero, or that the module kills at the timeout, is a result, not a failure. A step that
   did not run once, threw, was refused or failed remotely fails the session, its cleanup is
   still sent, and no later test is sent. After the module returns, each step removes
   `%TEMP%\art-out.txt` and `%TEMP%\art-err.txt` if present, the two capture files
   `Invoke-ExecuteCommand` names, and nothing else. Module 2.3.0 keeps a test's output in memory
   and never writes them (the file branch of `Invoke-Process` is only reached for an interactive
   test, which the harness never asks for), so the removal is a guard against a later version
   leaving account or credential listings on disk.
6. **After.** A second snapshot, diffed on the Mac by a pure function, and the staged tree
   listed again. Any difference in either fails the session.
7. **Record.** One JSON file per session in `phase-b-detection/art-runs/<session>.json`: the
   allowlist and manifest hashes, the atomics commit, the module version, the restore point's
   description and creation time, the Defender gate, per GUID the UTC start and end and status of
   each step with the run's exit code, the GUIDs whose run timed out (`timedOut`), the diff's
   verdict with every item named, and the staged tree's verdict.

`check-prereqs` runs the gate, then `Invoke-AtomicTest -CheckPrereqs` per test, with no restore
point and no snapshot. It executes no test, but it does run each test's `prereq_command`; for
the 17 tests those are `Test-Path` checks or nothing.

### What the record never holds

Diff items are named from the Dell, and a task or service name can hold a SID, a user name or an
address. Before the record is written, every item name has each SID's machine part replaced
(`S-1-5-21-<machine>-1001`), the Dell's computer, user and domain names (read in the gate)
replaced with `<host>`, `<user>` and `<domain>`, the name of every other local account replaced
with `<account>` (the gate lists them all but the well-known built-ins, RIDs 500, 501, 503 and
504), private IPv4 and IPv6 addresses replaced, and control characters replaced. An item in the
`users` category is an account name, so it never reaches the record at all: it is written as
`<local-account>`. The finished JSON is then searched for those names, any
`S-1-5-21-a-b-c`, and any private address, and is not written if one is found; a Dell name that
also occurs in the record's own text (a computer named `AtomicRedTeam`) stops it the same way.
Last, `leakcheck.ts --paths` runs on a scratch copy with the local denylist, and the file is
written only if that passes. Raw remote output, every decoded answer, both snapshots and an
unchecked copy of the record go to `Plans/b4-harness/runs/<session>/`, which is gitignored.
Messages never print remote text: a failed ssh call says its exit code and where the output is
saved.

### How the payload gets there

A step's script is larger than the 8,191-character Windows command line allows once encoded.
The command line carries only a bootstrap of 1,546 characters encoded. The script goes on
stdin as one line of base64. The bootstrap reads exactly that one line from the raw
standard-input stream (`[Console]::OpenStandardInput()` through a `StreamReader`, with
`ReadLineAsync()` and a 60-second `Wait`), checks that the bytes hash to the SHA-256 it was
built with (exit 97 if not), and runs them. When no line arrives in time it exits 96 by itself,
having run nothing. So a payload altered or cut short on the way is refused before any of it
runs, and a payload that never arrives ends the remote process instead of leaving it behind.

On the Mac, exit 96 means the payload did not reach the Dell and nothing ran, so that call, for
any step, is sent once more and each attempt's raw output is kept under its own name
(`NN-<step>` and `NN-<step>-attempt2`). A second miss is a setup failure before any test has run
and a failed session after one, and the message says the payload did not arrive. Nothing else is
ever retried: not an ssh timeout, not another non-zero exit, not a payload-hash mismatch, not an
answer that cannot be read. Each of those may mean something ran.

### Limits and what is not proven

- Shown on the Dell as of 2026-11-22: `check-prereqs --all` (15 of 15 met), and one session of
  two read-only tests, `T1003.005 #1` and `T1033 #8`. That session exercised the stdin
  bootstrap, the gate, the restore point, both snapshots (744 items in eight categories, no
  difference), run and cleanup for each test, and the record. Not shown there: a test that
  changes state and its cleanup, the timeout path, and every refusal branch of the Dell-side
  scripts. Those run only against the fake Dell in the tests, which prove the Mac side: what
  is sent, how answers are read, and that every planted fault stops the session.
- Staging is proven as of 2026-11-22: a plain `scp -r` of the `stage` folder to
  `<dell-alias>:C:/AtomicRedTeam/` put all 72 files on the Dell, each matching the
  manifest by SHA-256, none with a mark of the web.
- What the module's output looks like was read from its 2.3.0 source and then matched live on
  2026-11-22 for a run, a cleanup and a prerequisite check: the `Write-KeyValue` key segments
  and `Exit code: <n>` before the `Done` key. The timeout line has not been seen live. Output
  the harness cannot read as one run makes the step "did not run once" and the session fails
  closed.
- `Invoke-AtomicTest` 2.3.0 never prints the cleanup command's exit code, so a cleanup counts
  as completed when the module ran it to its `Done` line without a timeout. The snapshot diff
  is what proves the cleanup worked.
- Two tests, `T1218.010 #2` (100341) and `T1218.011 #1` (100342), download a scriptlet from the
  atomics repo's `master` branch at run time and execute it. The commit pin does not cover that
  file, so they run only with `--allow-remote-code`, and `--all` leaves them out without it.
  Three more fetch from the internet with their defaults and run nothing they fetch:
  `T1614 #1` (ipinfo.io), and `T1105 #7` and `#26` (the repo's `LICENSE.txt`; `#26`'s URL sits
  in its VBScript, not in an input, so `check-allowlist` cannot hold it to the YAML).
- The snapshot does not see processes. Tests that start `calc.exe` or `notepad.exe` can leave
  them running, and `T1218.011 #1`'s cleanup kills every `notepad.exe`, not only its own.
- A diff item that only Windows changed (a maintenance task rewriting its triggers, a service
  start mode toggled by servicing, a per-user service instance) fails the session. That is
  deliberate: it errs toward reporting. The raw snapshots show which item it was.
- The staged-tree check lists files only. It does not see an empty directory, and it hashes each
  file's main data stream, so an alternate data stream added to a staged file is not seen.
- Each step checks the tree's digest, then imports the module from the same files. Someone
  with admin rights on the Dell could swap a file in that gap; such a person is out of scope,
  since they could change the harness's own checks just as easily.
- Only the module's information, error and output streams are captured. Its warning stream is
  not, so a module warning is neither recorded nor reported.
- Windows sshd keeps a child's stdin open after the ssh client is gone, so a remote reader that
  waits for end of input outlives the harness. The first live run (2026-11-22) saw 2 of about 45
  deliveries block for ever in `[Console]::In.ReadToEnd()`, left as orphan processes on the Dell.
  The bootstrap must therefore never wait for end of input. `[Console]::In` cannot be given a time
  limit either: it is a synchronized reader whose async methods run synchronously, which is why
  the bootstrap reads the raw stream.
- The 60-second read limit and the one retry cover only a payload that never arrives. A remote
  script that hangs for any other reason, a step or a module call, still outlives the harness's
  ssh timeout: the harness says so and cannot end it, and the process stays on the Dell until
  someone kills it there.
- The bootstrap sets `$ErrorActionPreference` to `Stop` globally, so it applies to module code
  too: a non-terminating module error throws and the step reads as "threw". That fails safe,
  but live it may show up as a false failure.
- Each step is one ssh session, so a full run of 15 tests opens about 35 of them, and each
  raises the stock PowerShell alerts noted on 2026-11-12 (92151, 92213). None is a pack rule.
- The restore point check trusts `Get-ComputerRestorePoint`. That a restore point can actually
  restore the Dell is not tested.

## coverage

`coverage.ts` turns the detection pack and the live-alert evidence into two ATT&CK Navigator
layers, one summary file and the results section of the writeup, for B.5. It runs offline on the Mac. The one command that touches
the network is `fetch`, a read-only query of the alerts index. It has run against the live index
for every session record checked in under `art-runs/`.

```bash
bun tools/coverage.ts build                          # read everything, write the four outputs
bun tools/coverage.ts check [--final]                # rebuild in memory; fail on any difference
bun tools/coverage.ts claims [--against <lab root>] <file.md>...   # refuse a typed count or percentage
bun tools/coverage.ts fetch --host <ssh alias>       # write one evidence file per session record
bun tools/coverage.ts refresh-attack <STIX bundle> [--sha256 <hex>] [--out <path>]
bun tools/coverage.ts --self-test                    # each planted refusal, through the real entry points
bun test tools/coverage.test.ts
```

Exit 0 is ok. 1 is a failed check (`check` found an output or the results section that differs). 2 is a setup problem: an
input is missing, ssh did not answer, or the leak scan `fetch` runs did not (`leak-scan-setup`). 3 is a refusal. A refusal is always a thrown, typed
error that names the offending item, a non-zero exit and no output file written or changed.

`build`, `check`, `claims`, `fetch` and `refresh-attack` check each path before they read or write
it. Under the lab root every folder from the root down is looked at without being followed, and
every entry under the rules folder is checked, subfolders included. A path outside the root, such
as a file given to `claims` or the bundle and `--out` of `refresh-attack`, is checked at its last
component only, and the root itself is taken as given. A path that is a symbolic link, dangling
or not, is refused as `path-symlink` and names the path. `build` and `refresh-attack` refuse
before they write anything when an output path is neither absent nor a regular file
(`path-not-file`). A file this tool reads itself (the writeup, the records, the evidence, the
miss list, the literals list, the crosswalk, the technique list and the files `claims` is given) that is not valid UTF-8 is refused as `bad-utf8` and is never
decoded with replacement characters; the ATT&CK bundle is refused as `bundle-json`. The rule XML is
the exception: `wazuh-rules.ts` reads it, and it decodes a stray byte as a replacement
character without a refusal.

### What it will not overstate

The pack is the rules whose ID is in the pack ranges of `wazuh-rules.ts` (100340 to 100399 and
100400 to 100499), read from `deploy/soc-recon/wazuh/custom-rules/`. Today that is 18 rules.
A pack rule is **validated** when an alert it raised from agent `001` has an event time inside
the run window of a test whose `rules` list names that rule, in a session whose verdict is
`pass`. Logtest output never counts, and the tool refuses a logtest transcript given as a session
record, evidence, the miss list, the crosswalk, the literals list or the technique list. The
writeup and the files `claims` reads are prose, and are not checked for one.

The match is on the event time: the Sysmon `utcTime` when the alert has one, else the system
time. The index time lags the event by about a second, so an alert indexed inside a window for
an event that happened after it does not count, and an event inside a window that was indexed
after it does. Times are compared as exact instants. The records carry seven decimals; a Sysmon event time
carries three, so it stands for a whole millisecond, and that whole millisecond has to be inside
the window for the alert to count. A Sysmon event time with other than three decimals is
refused as `evidence-time`. On any other channel the event time has to equal the system time of
that alert, and a difference is refused the same way.

Everything else is listed in `coverage.json` with a reason: outside the run window (cleanup and
gaps included), rule not in the test's `rules`, or session verdict not `pass`. A pack alert for
a pack-range rule that is not in the XML and fired inside a run window is a refusal.

A not-validated rule is either classified in `phase-b-detection/validation/misses.json` or
unclassified. An unclassified rule is not a refusal, but it keeps `complete` false, and `check
--final` refuses while `complete` is false. A miss entry has a rule, a class, evidence text and,
where the class needs them, a session and test:

| class | needs | refused when |
|---|---|---|
| `blocked-by-defender` | session, test, `alertId` | the cited alert is not a rule 62123 or 62124 alert with an event time inside that test's run window |
| `sensor-gap`, `rule-gap`, `prerequisite-failed` | session, test | the test does not list the rule |
| `not-run` | `ruling` | the ruling is empty |

An entry is also refused for a validated rule, a rule outside the pack, an unknown class, empty
evidence, a second entry for one rule, or a field its class does not carry.

### The inputs

| file | what it is |
|---|---|
| `phase-b-detection/attack/enterprise-19.2-techniques.tsv` | every Enterprise 19.2 technique with its status, successor and tactics, written by `refresh-attack` from the pinned bundle |
| `phase-b-detection/attack/crosswalk.json` | one entry for every ATT&CK ID a pack rule uses, mapping it to its 19.2 ID as `unchanged` or `revoked-by` |
| `phase-b-detection/art-runs/*.json` | the session records of `art-harness.ts`; a step that was not sent carries no times (`record-step`), and every time a record carries has seven decimals (`record-time`) |
| `phase-b-detection/validation/<session>.alerts.json` | the evidence `fetch` writes, one file per session |
| `phase-b-detection/validation/misses.json` | the hand-kept miss list |

`refresh-attack` checks the bundle's SHA-256 against the pinned value
(`dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`, the 19.2 file at
`mitre-attack/attack-stix-data`) and refuses a mismatch. The crosswalk is refused when a pack
rule's ID has no entry, when a target is absent, revoked or deprecated, when `unchanged` names an
ID that is not active or maps elsewhere, or when `revoked-by` names anything but the successor
the bundle records.

### The outputs

`phase-b-detection/coverage/` holds `layer-rule-exists.json`, `layer-validated.json` and
`coverage.json`, and the writeup holds the results section (below). They are deterministic: sorted, no wall-clock time, byte-identical on a rebuild,
and `check` is the gate that says so. The pre-commit hook runs it whenever a commit stages a
change under the pack rules folder, under `art-runs/`, `attack/`, `validation/` or `coverage/`
in `phase-b-detection/`, or to the tool itself. It makes a copy of the index that holds the
staged inputs and outputs and the staged copies of `coverage.ts` and the four files it imports
(`wazuh-rules.ts`, `art-harness.ts`, `winevt-capture.ts` and `winevt.ts`), and it runs that copy of
the tool on that copy of the tree. A good file or a good tool in the working tree cannot stand in
for a stale or bad one in the commit, so a tool change staged without the outputs it now
rebuilds differently is blocked, and so is a bad staged tool beside a good one on disk. A tool
that the index does not hold as a regular file blocks the commit. Every git call in the hook,
and every one the tool makes, runs with replace refs off, so a replace ref on HEAD or on a staged blob cannot show the hook other bytes
than the commit will hold. A failure to list or copy the index blocks the commit. A layer staged
as a link is refused as `path-symlink`. The hook runs plain `check`; `--final` is for the ship. After `check` it runs `claims` on the
writeup inside the same copy, with the literals list copied beside it, so a count typed outside
the results section cannot land either. A commit that stages `phase-b-detection/README.md` runs it too.

The pre-push hook runs the same two commands on the tree of each tip being pushed, because a
merge, a cherry-pick or a rebase that git finishes without a pre-commit hook would otherwise
reach the remote unchecked. `leakcheck` runs first, with the exit status it always had, and the
check gets the same ref lines. For each tip the hook copies that tree's inputs, outputs, literals
and the five tool files through a private index, with replace refs off, and runs the tip's own
copy of `coverage.ts` on the copy: `check`, then `claims` on the writeup. A tip whose tree has
no `tools/coverage.ts` is named in one line and not blocked, and a deleted ref pushes as before.
A failure to read or copy a tip's tree, or a tool file that is not a regular file in it, blocks the push.

Each layer scores a technique by the number of pack rules
(or validated pack rules) that map to it, with the rule IDs and `art:<technique> #<n> <session>`
in the comment. A scored sub-technique also emits its parent with `showSubtechniques` on and no
score, unless the parent is itself mapped. No entry names a tactic. `coverage.json` carries the
pack size, the validated rule IDs, the ratio as two integers, `complete`, the unclassified rule
IDs, one row per rule (level, ATT&CK IDs as written and as 19.2, status, the validating alert or
the miss entry) and the pack alerts that did not count.

### The writeup number gate

The fourth output is a section of `phase-b-detection/README.md`. It runs from the heading
`## Validation results` to a last line of the form `Source: \`coverage.json\`, SHA-256 <64 hex>.`,
and the hash is of the bytes of `coverage.json`. It holds the totals as sentences (validated over
pack size with the percentage to one decimal, rounded to nearest in integer arithmetic so 12 of 18 reads 66.7 percent, the misses by class, how many techniques each layer scores) and
one table row per pack rule, sorted by rule ID: level, ATT&CK IDs as mapped to 19.2, status, the
ART test that validated it or its miss class, and the session. Every value comes from the same
in-memory build that writes `coverage.json`. It is plain ASCII with no wall-clock time, so a
rebuild is byte-identical. `build` replaces the section and leaves every byte outside it as it
was; with no section in the file it appends one. `check` compares the section with the rebuild.
A missing file is refused as `writeup-missing`, a missing section as `section-missing`, two as
`section-duplicate` and one with no source line before the next heading as
`section-unterminated`. A heading inside a fenced block is not a section. The pre-commit hook
holds the staged writeup to the same rebuild.

The prose around the section never types a number that counts something. `claims` takes any
Markdown files and refuses every digit-bearing token outside the section that is not an
identifier or a listed literal, naming file, line and token. A spelled-out ratio ("twelve of
eighteen", "twelve out of eighteen") or percentage ("twelve percent") is refused too, as
`claim-number-word`, with emphasis marks (`*` or `_`) or `&nbsp;` and `&#160;` between its words, with a determiner ("the twelve of the eighteen"), a hyphen
("twelve-of-eighteen") or a line break inside the ratio, and with "hundred" or "thousand" in the
spelled percentage. Fenced and inline code are scanned like any other text. A fence closes only
on the same character at least as long as the one that opened it, so a shorter fence line inside a longer fence does not end it. A file with no
section is still checked as prose. A decimal digit outside ASCII (fullwidth, Arabic-Indic and
the like) is refused as `claim-number`, because it reads as a number to a person and matches no
pattern here. Digits inside an `http://` or `https://` URL, in a link destination or bare, are an
address and are not refused; the text of a link is scanned like any prose, so `[13 of 18](https://example.org/)`
is refused on the text. The URL ends at whitespace, and trailing punctuation and an unbalanced closing bracket are not
part of it, so a number touching the closing bracket of a link, as in `[s](https://example.org/)13%`, is reported.

```bash
bun tools/coverage.ts claims phase-b-detection/README.md
bun tools/coverage.ts claims --against <lab root> <post.md> <page.md>   # files in another repo
```

A copy of the section in another file, at any heading level, has to equal the lab's current
section byte for byte, apart from the heading line; any other copy is refused as
`claim-section-differs`. `--against` names the lab root whose pack, records and section the files
are held to, and defaults to `--root`. A post is compared with a rebuild from that root's inputs, not with the section its writeup
holds, so a stale writeup there does not excuse a stale copy. The lab's own writeup is held to its section the same way.

What counts as an identifier, by pattern, and where a registry exists the identifier has to be in it:

| identifier | pattern | must be |
|---|---|---|
| rule ID | five or six digits in a pack range or one of the tool's Defender rules (62123, 62124) | a pack rule in the XML, else `claim-rule-unknown`; any other five or six digit number is a count |
| technique ID | `T` and four digits, with an optional `.` and three | in the pinned 19.2 list, else `claim-technique-unknown` |
| ART test | a technique ID, a space, `#` and digits | the technique in the pinned list |
| session ID | `<date>T<time>Z-<six hex>` | a record under `phase-b-detection/art-runs/`, else `claim-session-unknown` |
| date, clock time | ISO dates with an optional time and zone offset, and `hh:mm` forms | a real day, a real time and a real offset (up to 14:00, in quarter hours; `+99:99` is a count) |
| tactic ID | `TA` and four digits | by pattern only |
| digest | 40 or 64 hex digits | by pattern only |
| version | a `v` and digits with up to three more dotted parts (a bare `v2` is accepted), or exactly three dotted parts | by pattern only |
| list marker | a number and `.` or `)` opening a list item | by pattern only |

A bare `19.2` is a decimal number, not a version, so it needs a literal. Literals live in
`phase-b-detection/claims-literals.json`, as `{"format": "talonsoclab-claims-literals/1",
"literals": [{"text": "...", "source": "..."}]}`. Each literal is a phrase of single-spaced ASCII
tokens ("event 3", "Sysmon 15.21", "level 12", "port 443", "ATT&CK 19.2"): one token is a word with a
letter and no digit, and one has a digit in it. It is matched as a whole phrase at token boundaries, so only the
digits inside a matched phrase are excused: with "event 3" listed, "Sysmon event 3 fired and 3 rules did not" is
refused on the second 3. A literal that is only a number, or has no word, is `literals-shape`. Each carries a
non-empty source. A literal with no source is `literal-source`, a repeat is
`literal-duplicate`, a malformed file is `literals-shape`, and a literal no file used is
`literal-unused`. Use is judged only when the lab's own writeup is among the files given, so a
blog post checked alone cannot mark a literal unused.

### Fetch

`fetch` needs `tools/leak-denylist.txt`, because it scans the evidence with `leakcheck.ts`. The file is gitignored, so a fresh clone has none, and then the scan does not run and `fetch` exits 2.

`fetch` sends one `_msearch` over `ssh -o BatchMode=yes <alias> 'cd ~/talonsoclab/deploy/soc-recon
&& bin/idx "/_msearch" --data-binary @-'` per session record, with the NDJSON on stdin and the
command as an argv array. The alias is held to a strict pattern first. The first query asks for
agent `001` alerts of every pack rule and of Defender rules 62123 and 62124, by index time from
60 seconds before the session's first run start to 60 seconds after its last cleanup end; the
second counts all agent `001` alerts in the same span as a control. The padding is for fetch
only, and matching never uses it. Each evidence file records the format, the session, the
SHA-256 of the record file it was taken against, the query, the shard counts, the control count
and, per alert, only the index name, document ID, rule ID and level, `rule.mitre.id`, agent,
index time, event time, system time, event ID, channel and image file name. Fetch refuses to
write when any shard failed, when the answer was truncated or a count is only a lower bound,
and when the repo leak scan (`leakcheck.ts --paths`, as `art-harness.ts` runs it) flags the text.
A record that carries no run or cleanup times has no window to ask for: `fetch` skips it and prints a line naming the session. Every session is fetched and checked before the first file is written.

### Limits

- `claims` refuses a spelled-out ratio or percentage, but other number words ("three rules",
  "a dozen") pass: no pattern separates a count from ordinary prose. A listed literal's source is
  only checked to be non-empty, not to be true.
- A count that happens to equal a known rule ID ("62123 alerts") passes as an identifier, because
  the pattern cannot tell a rule from a count. A `v`-prefixed number passes by pattern, whatever
  it counts.
- `fetch` has run against the live index for every session record checked in. The evidence
  files under `phase-b-detection/validation/` hold Sysmon alerts, Defender alerts (rules 62123 and
  62124, whose event time comes from `systemTime`) and alerts that did not count, so the query's
  field names, the date `format` and the document-ID pattern have been seen live for each.
  Not yet seen live: a failed shard. The fixtures under `tools/fixtures/coverage/` carry
  placeholder document IDs; their control and shard counts are synthetic.
- Identifier kinds still let a count through, because each is a pattern and no pattern knows what
  it counts: a clock time ("12:18 rules"), a three-part version ("12.6.0 rules"), digits attached to a
  URL with no space ("https://example.org/x,13"), a number written in a glyph that is not a
  decimal digit (a Roman numeral, a circled digit, a vulgar fraction), and a fraction in words
  ("one half").
- The tool is built to catch an honest mistake: a stale output, a typed count, a tool or a rule
  changed without a rebuild. It is not built to hold against someone who edits its inputs by hand
  to mislead it. Known ways to do that, each found in review and left as it is: a link address
  with an escaped bracket hides a number written right after it; a second heading spelled with
  closing hashes is not read as a second results section, and `build` appends its section inside
  a code fence left open; a record whose step says `refused` but still carries times opens a run
  window, and a gate time that is not a time is not refused; an alert outside the Sysmon channel
  whose time is spelled with fewer decimals is read as a wider instant; a `--root` that is itself
  a link is followed; a rule file with an invalid byte in a comment is read with a replacement
  character.
- A workflow on GitHub, `.github/workflows/coverage-gate.yml`, runs `check --final` and `claims`
  again on every push to `main`. It cannot stop a push. It marks the commit, so a push that went
  around the hooks shows as a failed check. It holds no copy of the leak denylist, so it says
  nothing about what `leakcheck` guards.
- A local hook cannot stop an author who does not run it: `git commit --no-verify` skips the
  pre-commit hook, `git push --no-verify` skips the pre-push hook, and an author can change either
  hook or the tools it runs. The hook also runs code from the working tree on the author's own
  machine, and these are the ways that code, or the bytes it reads, can be made to give the wrong
  answer. A `bunfig.toml` in the working tree is read by Bun when the hook runs the staged tool, so an
  untracked one can load code into the check. A staged `coverage.ts` that judges itself can return
  success without checking anything, because the hook only holds it to be a regular file. On a
  case-insensitive disk, a path that differs from a built path only in letter case names the same
  file there but a different path in git, and the hook's path patterns are not made to treat the
  two as one. A checkout filter, below,
  changes the bytes the check reads.
- A checkout filter configured in the repo (a smudge filter or a line-ending conversion) changes
  the bytes of the copy the hook makes, and the hook does not switch it off. It is outside the
  hook's reach.
- The Navigator app version in the layers is a named constant in `coverage.ts` (5.3.2, the hosted
  app; the 4.5 layer spec requires at least 4.9.0). Both layers were opened in the hosted app on
  2026-11-23, as committed in `d492869`: it reports v5.3.2, loads the ATT&CK 19.2 bundle from the
  layer's `"attack": "19"` with no upgrade prompt, and colors every scored technique in each of
  its tactics and nothing else (16 techniques in 22 cells, and 11 in 17). A layer rebuilt since
  then has not been opened until someone opens it. The hosted app is a moving target: when it drops 19.2 or
  changes version, this check is stale.
- The tool does not check that a test's ART technique agrees with the `<mitre>` ID of the rule
  it is meant to fire.
- Evidence is joined to a rule by its ID, not by what the rule matches. A rule that validated stays
  validated when its pattern is edited later, as long as its ID, level and ATT&CK mapping stay the
  same and the record and evidence files are unchanged: the old alert still counts. A change to
  the level or the mapping changes the outputs, and `check` says so; a change to the pattern
  does not. Editing a validated rule's pattern means running its test and `fetch` again by hand.
- An evidence file is tied to a record by the record's SHA-256, so any edit to a record makes its
  evidence stale until `fetch` is run again. The fixtures carry the SHA-256 of the two real
  records, so they go stale the same way.
- Rule 100344 has no allowlisted test, so 17 of 18 is the most a validation run can show.
