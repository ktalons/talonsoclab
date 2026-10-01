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
bun tools/leakcheck.ts --paths <p>...     # files or directories on disk, ignored ones included
bun tools/leakcheck.ts --self-test        # the fixtures in tools/fixtures/leakcheck/
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
