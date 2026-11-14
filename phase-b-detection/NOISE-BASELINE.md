# B.0 Noise Baseline

Phase B adds detections, and a new alert only means something if the alerts already arriving
are understood. This page records what the lab alerted on before Phase B, which of it was the
stack watching itself, how that was suppressed, and what is still left.

**Status:** live since 2026-10-25 20:33 UTC, with every container rule pinned to the shared
`docker-default` label. The per-service labels described below were added in 2026-11: the
profiles are loaded on the box, and the rules that pin them take effect at the stack recreate
that follows this commit. No live measurement of them is in this document yet. The 7-day
measurement covers 2026-10-27 to 11-02 UTC. 10-26 is left out: a test session on the box that day carried 6,145 alerts, and test days
are not a baseline.

**Target:** a 7-day mean of 3,000 alerts a day or fewer. **Measured: 2,663.**

## Before

A quiet day, 2026-10-24 UTC, with no test runs on the box: **20,708 alerts**. One stock rule
made up 19,973 of them, 96%:

| Rule | Level | What it is | Alerts |
|---|:--:|---|--:|
| 80792 | 3 | `Audit: Command`, one alert per `execve` on the SOC box | 19,973 |
| everything else | | Windows Sysmon, FIM, SCA, the macOS agent's port changes | 735 |

Almost every 80792 alert had no login session behind it (`auid` unset). The SOC box audits
every `execve` on its kernel ([`talonsoclab.rules`](../deploy/soc-recon/wazuh/audit/talonsoclab.rules)),
and the containers run on that kernel, so the stack was alerting on its own healthchecks and its
own monitoring jobs.

The earlier S0.1 baseline (about 34,000 a day, 2026-09-23 to 09-30) predates the healthcheck
rework that removed the shell wrapper and the password from the indexer healthcheck. Days with
test runs on the box (10-13, 10-16, 10-19 to 10-21) reached 400,000 and are not a baseline.

## How the suppressions are keyed

Every suppression is a level-0 child of 80792 in
[`local_noise_baseline.xml`](../deploy/soc-recon/wazuh/custom-rules/local_noise_baseline.xml),
IDs 100100 to 100199. They sit at the Wazuh rule layer, never in auditd, so every event still
reaches the manager and is evaluated. A suppressed event is not stored there, though: `logall` is
off, so its only copy is the SOC box's own `/var/log/audit/audit.log`. Each rule requires all of
these:

- **No login session and no tty.** Anything a person runs, on the host or through
  `docker exec -it`, still alerts. A `docker exec` without `-t` runs with no session and no tty
  inside the container; its trail is the host-side `docker` command, which alerts with its full
  argv.
- **The full exe path and the working directory.**
- **The uid, euid and gid the shape really runs as.** The gid separates the two copies of the
  Wazuh monitors: 999 is the manager container's wazuh group, 108 the host's.
- **The AppArmor label** from the audit record: the service's own profile for a container
  (`soc-recon-indexer`, `soc-recon-manager`, `soc-recon-suricata`), `runc` for runc,
  `unconfined` for the host. Each service in `docker-compose.yml` runs under its own copy of
  Docker's default profile ([`deploy/soc-recon/apparmor/`](../deploy/soc-recon/apparmor/README.md)),
  so the label names one service. No rule pins `docker-default`, the label every other
  container on the box gets. `/var/ossec` is the working directory of both the manager
  container and the box's own Wazuh agent, and the label is what tells them apart.
- **The exact argv.** The auditd decoder stops at the eighth argument and leaves hex-encoded
  arguments undecoded, so each rule matches the full EXECVE record in `full_log`, with the
  argument count pinned. Seven rules leave named slots open: the pid in the liveness checks
  (100110, 100111, 100120, 100121), the package name and query format in 100116, the
  deserialize fd in 100130, and the missed binary's name in 100118, which pins no argv because
  nothing executed.

`bun tools/noise-lint.ts` enforces the shape. A rule in the range must be level 0 under a listed
parent (only 80792 today), with every matcher `pcre2` and never negated, every field anchored
at both ends, and no matcher that matches the empty string or an arbitrary probe value. A
pattern that alternates outside a group fails. An auditd rule
must pin all seven fields above plus the label and `argc` in `full_log`, in one regex with no
`<match>` beside it and no field named twice. The label comes first in the regex as plain text
and must be `runc`, `unconfined` or a service profile; `docker-default` fails.

Wazuh runs these patterns with PCRE2 and the lint reads them with JavaScript's regex engine,
and the two do not read every pattern the same way. Two review rounds in 2026-11 each found a
pattern that passed the lint and matched a `docker-default` record under PCRE2: a class
opening with `]`, then a POSIX class. So a suppression may only use a small pattern subset,
and the lint refuses everything outside it: plain characters, `.`, eight named escapes,
simple classes that are never negated, groups with `|` inside them, one greedy quantifier
after an atom, `^` first and `$` last, with caps on length and nesting. The 23 rules here
fit it as they stand. Inside the subset the two engines agreed on 12,000 random pattern and
input pairs (PCRE2 10.49). Reviews found two differences there, both on input auditd would
hex-encode before a rule saw it: PCRE2's `$` also matches just before a final newline, and
`.` reads a carriage return and bytes above 0x7F differently in the two engines. That is evidence, not proof. The lint catches mistakes; what proves
a rules file is the scratch manager, which runs the real parser and the real engine, so a
new suppression goes through both and still gets read by a person. A rule may hold
only its parent, its fields, its regex and a description. Every tag in a rules file must be
lower-case with double-quoted attributes on one line, which also rules out a self-closing
tag such as `<same_user />` (write `<same_user></same_user>`) and an `<?xml ?>` line, and no file may use `<var>`, `overwrite`, or a
comment that ends in an unusual way: each is a place where Wazuh's parser might read the
file differently from the lint, which was not measured, so each is refused. For the same
reason a rule's id and level must be plain numbers, no file may hold `&` outside a comment,
and the rules folder may hold nothing but `.xml` files and its `.gitkeep`. Any rule that keeps an event out of the index, by a level below
`log_alert_level`, `noalert` or `no_log`, fails anywhere outside the range, except the Phase A
Suricata ethertype rule 100200. CDATA in a rules file fails.

## What these rules cannot see

A cross-vendor audit (Forge, OpenAI and Anthropic legs, 2026-10-25) found no way to forge a
matching record: any value with a space or quote is hex-encoded by auditd, so text planted in a
path or argument cannot imitate the record structure. It did find four things an honest match
can hide, and the hardening work in 2026-11 added a fifth.

- **The parent.** EXECVE has no parent process, so anything that repeats a shape exactly, in
  the same directory as the same user, is suppressed.
- **The environment.** EXECVE carries no environment. An exact argv can still load other code
  through `LD_PRELOAD`, read a planted `.curlrc` or rpm macro file, or source an edited file.
  The argv being exact does not make the behavior exact.
- **The binary.** The exe and cwd are paths inside the process's own mount namespace. Root in a
  container that can write `/usr/bin` can put its own binary at a suppressed path and run it
  under one of that same service's shapes. The first version of these rules pinned
  `docker-default`, which every container shares, so any container could do it under any
  container's shape. With each service under its own profile, a shape run from a different
  container alerts as plain 80792.
- **The label's owner.** A label names a profile, not a container. Whoever can start a
  container can start it under a service's profile. That takes Docker access on the box, which
  is already root.
- **The record afterwards.** A suppressed event is not archived at the manager.

Every one of these needs code execution on the box or in a container first. They are residual
risk, accepted for now. Per-service labels close the cross-container half of the binary swap.
A read-only root filesystem closes the rest of it for one service, Suricata; the next section
says what stops the other three. A sensor that sees the environment and the parent (eBPF) is
the follow-up after Phase B. All of it is tracked in the ISA.

## Read-only root filesystems

A service that cannot write its own root filesystem cannot swap a binary under `/usr/bin`.
Each service was started on a scratch stack with `read_only: true` and nothing else changed
(2026-11-14 UTC):

| Service | With a read-only root | What blocks it |
|---|---|---|
| wazuh.manager | exits at start | the s6 init cannot create `/var/run/s6` |
| wazuh.indexer | exits at start | the JVM's temp folder under `/tmp`. The running service also writes `config/opensearch.keystore`, its logs under `/var/log/wazuh-indexer` and a JNA cache |
| wazuh.dashboard | exits at start | `config/opensearch_dashboards.keystore`, then `data/uuid` |
| suricata | starts and stays healthy | nothing at start. Its two nightly jobs fail: `logrotate` cannot write `/var/lib/logrotate/logrotate.status`, and `suricata-update` finds no temp folder |

Suricata is the one adopted. Its compose entry sets `read_only: true` with a tmpfs on `/tmp`
and one on `/var/lib/logrotate`. With those two, a rotation, a full rule update (53,492 rules
staged, tested, promoted and reloaded) and the healthcheck all passed on scratch under the
service's own profile. Without them the healthcheck stays green while both jobs fail, so a
healthy container was not the test. The other three stay writable, and for them the same-service
binary swap above stands.

## The suppressions

Counts are what each rule removes from the 2026-10-24 replay. "Blind to" names the argv each rule
hides; the five limits above apply to every row.

| ID | Source | Removed | Blind to |
|---|---|--:|---|
| **Tier 1** | **container healthchecks** | | |
| 100100 | `runc init`, first exec of every healthcheck and `docker exec` | 4,328 | runc init itself; the exec'd child still alerts |
| 100101 | indexer healthcheck `curl`, all 15 arguments | 2,871 | that exact curl |
| 100102 | Suricata healthcheck shell | 1,439 | that exact shell line |
| 100103 | `suricatasc -c uptime` | 1,439 | `suricatasc -c uptime` as root; the same command as the suricata user still alerts |
| **Tier 2a** | **manager container's own monitors** | | |
| 100110 | daemon liveness `ps -p <pid>` | 536 | a ps of one pid |
| 100111 | the shell around it | 536 | that shell line |
| 100112 | shells for the `df`, `last` and `netstat` command monitors | 718 | those three command lines |
| 100113 | the netstat pipeline's three `sed` stages | 706 | those three sed scripts |
| 100114 | its `sort -k 4 -g` | 237 | that sort |
| 100115 | `df -P` | 237 | `df -P` |
| 100116 | SCA and syscollector `rpm` queries | 360 | those rpm query argvs |
| 100117 | syscollector `xargs -I {} rpm -ql {}` | 24 | that xargs line |
| 100118 | PATH-search misses (SCA looking for CIS tools the container lacks) | 2,014 | modulesd or xargs failing to find a binary |
| **Tier 2b** | **the box's own agent** | | |
| 100120 | daemon liveness `ps -p <pid>` | 252 | a ps of one pid |
| 100121 | the shell around it | 251 | that shell line |
| 100122 | shells for the same three command monitors | 719 | those three command lines |
| 100123 | the three `sed` stages | 670 | those three sed scripts |
| 100124 | `sort -k 4 -g` | 223 | that sort |
| 100125 | `df -P` | 236 | `df -P` |
| **Tier 3** | **host housekeeping** | | |
| 100130 | systemd's exec helper, once per unit start | 335 | the helper; the unit's command still alerts |
| 100131 | sysstat's enabled check | 144 | that shell line, which sources `/etc/default/sysstat` |
| 100132 | sysstat `sa1` | 144 | `sa1 1 1`, which sources `/etc/sysstat/sysstat` |
| 100133 | sysstat `sadc` | 144 | that sadc sample |

Total removed: 18,563 of 19,973.

The two sysstat files those rules source are the tier-3 weak point: an edit to either runs every
10 minutes under a suppressed shape. The box agent's FIM covers `/etc` on its scheduled scan (89
FIM alerts under `/etc` in the last 30 days), so the edit itself alerts, within a scan cycle
rather than at once.

## After

| | 2026-10-24 before | Replay after | Live 7-day mean |
|---|--:|--:|--:|
| 80792 | 19,973 | 1,410 | 1,656 |
| everything else | 735 | 735 | 1,007 |
| **All alerts** | **20,708** | **2,145** | **2,663** |

The live mean is 18,643 alerts over the seven days. Daily totals ran from 2,241 to 3,192. No
suppressed event reached the index: a count of rule IDs 100100 to 100199 over the week is 0.

Live sits above the replay for two reasons. About 204 of the 80792 alerts a day are truncated
records the replay never had (below). And the Windows endpoint's activity changes by day: its
vendor update service ran on 10-28 and 10-31 and added about 300 alerts each time.

## What is left, and why it stays

The five largest remaining (rule, image) pairs over the measured week. None is suppressed.

| Rule | Image | Per day | Why it stays |
|---|---|--:|---|
| 80792 | `/usr/bin/coreutils` (containers) | 243 | the lab's own job-age probe in the manager container (169), `timeout` and staging-directory moves from the three daily maintenance jobs (54), and truncated `df` and `sort` records (20). Low volume, and the jobs are ours |
| 80792 | `/usr/bin/bash` (manager container) | 180 | the job-age probe's shells, syscollector's `rpm -qa` pipelines, and `zcat` over rotated alerts |
| 80792 | `/usr/bin/sed` (manager container and box agent) | 147 | the port monitor's `sed` stages, arriving truncated. 989 of the week's 1,031 had no working-directory record, so no suppression can match them |
| 750 | n/a (Windows endpoint) | 136 | registry values changed under FIM. 790 of the week's 955 are Volume Shadow Copy diagnostic values under `Services\VSS\Diag`, rewritten on every shadow copy operation. Real changes that say little. A registry ignore for the keys under it was added to the shared Windows agent config in 2026-11 and is judged by the next week's count |
| 80792 | `/usr/bin/dash` (SOC box) | 96 | host shells: root's hourly cron job, the daily apt and `cron.daily` runs, and the login banner scripts on each ssh session |

The replay's second pair, the macOS agent's port-change rule 533, fell from 189 a day to 52 and
left the top five. `/usr/bin/gawk` in the manager container is sixth at 84.

Truncated audit events that arrive without their working-directory record fail every suppression
and keep alerting. That's deliberate: a rule that can't see all of its fields doesn't fire. In
the measured week 1,428 of the 11,593 alerts from rule 80792 arrived that way, about 204 a day,
most of them `sed`, `df` and `sort` from the command monitors' pipelines.

Container restarts are loud by design. A manager start runs about 2,000 s6 init execs, and an
`apt upgrade` run through `sudo` carries a login session, so it alerts in full.

## Planted true positives

The suppressions must never hide what they look like. These run through the same test, and each
was planted on the live stack after deployment:

- A `curl` to `_cluster/health` from an interactive host shell: alerts as 80792.
- The same query through `bin/idx` inside the indexer container: alerts as 80792. It runs in the
  same directory under the same user as the healthcheck, and only the argv tells them apart.
- Lsass access (Sysmon EID 10) from an image not on the allowlist: no Windows rule is suppressed
  here. A real Sysmon event written with `New-WinEvent` on the Windows endpoint alerted as rule
  92900, level 12, two seconds later. A live `OpenProcess` on lsass could not be the plant: LSA
  protection refuses it before Sysmon logs anything.

## Testing

A scratch suite logtested 309 cases on a throwaway manager running the lab's image (4.14.9).
There were 34 real captured events, one per shape, plus eight mutants of each that must fall back
to plain 80792: login session, tty, working directory, AppArmor label, argv, uid, euid and gid.
The indexer healthcheck has a ninth, a pinned dot changed to another byte. Then the two planted
curls. Result: 309 of 309.

The per-service labels (2026-11) grew that suite to 559 cases. Each container shape was run
under every other service's profile, under `docker-default`, under `unconfined` and under
four labels that only contain the right name (a suffix, a prefix, and stacked either way), and
each host shape under every service profile. All must fall back to plain 80792. Result: 559 of
559, and the earlier rules fail exactly the 40 cases they should. The labels in those cases
were written into captured records.

So the rules were then run against records that carry real labels. The four profiles were
loaded on the box, a scratch stack ran once with each service under its own profile and once
with the services under each other's, and every exec from both runs was taken from the index:
5,445 audit records. The earlier rules decided which shape each record was. Under the new
rules, 1,389 records of a shape under its own service's label were suppressed by the same rule
(all twelve container rules), 1,390 records of a shape under another service's label alerted
as plain 80792 (eleven of the twelve; the syscollector `xargs` did not run in that pass), and
the other 2,666 came out as they did before. No record disagreed.

The suite and its fixtures are not in this repo yet. The lint and the profile check are:

```bash
bun tools/noise-lint.ts                 # keying rules on every suppression
bun test tools/noise-lint.test.ts       # the lint refuses each planted bad rule
bun tools/apparmor-profiles.ts          # one profile per service, each a copy of the default
```
