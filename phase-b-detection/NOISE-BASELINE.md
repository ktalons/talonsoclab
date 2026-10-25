# B.0 Noise Baseline

Phase B adds detections, and a new alert only means something if the alerts already arriving
are understood. This page records what the lab alerted on before Phase B, which of it was the
stack watching itself, how that was suppressed, and what is still left.

**Status:** rules written and replay-tested on a scratch manager. Live deployment and the 7-day
measurement are pending, so every "after" number below is a projection from replaying one real day
through the new rules. It gets replaced by the live number when the 7 days are in.

**Target:** a 7-day mean of 3,000 alerts a day or fewer.

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
- **The AppArmor label** from the audit record: `docker-default` for a container, `runc` for runc,
  `unconfined` for the host. `/var/ossec` is the working directory of both the manager container
  and the box's own Wazuh agent, and the label is what tells them apart.
- **The exact argv.** The auditd decoder stops at the eighth argument and leaves hex-encoded
  arguments undecoded, so each rule matches the full EXECVE record in `full_log`, with the
  argument count pinned. Eight rules leave named slots open: the pid in the liveness checks
  (100110, 100111, 100120, 100121), the package name and query format in 100116, the
  deserialize fd in 100130, and the missed binary's name in 100118, which pins no argv because
  nothing executed.

`bun tools/noise-lint.ts` enforces the shape. A rule in the range must be level 0 under a listed
parent (only 80792 today), with every matcher `pcre2`, never negated, anchored, and unable to
match an empty or arbitrary value. An auditd rule must pin all seven fields above plus the label
and `argc` in `full_log`. Any rule that keeps an event out of the index, by a level below
`log_alert_level`, `noalert` or `no_log`, fails anywhere outside the range, except the Phase A
Suricata ethertype rule 100200. CDATA in a rules file fails.

## What these rules cannot see

A cross-vendor audit (Forge, OpenAI and Anthropic legs, 2026-10-25) found no way to forge a
matching record: any value with a space or quote is hex-encoded by auditd, so text planted in a
path or argument cannot imitate the record structure. It did find four things an honest match
can hide.

- **The parent.** EXECVE has no parent process, so anything that repeats a shape exactly, in
  the same directory as the same user, is suppressed.
- **The environment.** EXECVE carries no environment. An exact argv can still load other code
  through `LD_PRELOAD`, read a planted `.curlrc` or rpm macro file, or source an edited file.
  The argv being exact does not make the behavior exact.
- **The binary.** The exe and cwd are paths inside the process's own mount namespace, and every
  container shares the `docker-default` label. Root in a container that can write `/usr/bin`
  can put its own binary at a suppressed path and run it under that shape.
- **The record afterwards.** A suppressed event is not archived at the manager.

Every one of these needs code execution on the box or in a container first. They are residual
risk, accepted for now. The fixes are per-service AppArmor profiles pinned in place of
`docker-default`, read-only root filesystems where the images allow, and in time a sensor that
sees the environment and the parent (eBPF). They are tracked in the ISA.

## The suppressions

Counts are what each rule removes from the 2026-10-24 replay. "Blind to" names the argv each rule
hides; the four limits above apply to every row.

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
| 80792 | 19,973 | 1,410 | pending |
| everything else | 735 | 735 | pending |
| **All alerts** | **20,708** | **2,145** | **pending** |

## What is left, and why it stays

The five largest remaining (rule, image) pairs in the replay. None is suppressed: each one is
real activity, reported correctly.

| Rule | Image | Per day | Why it stays |
|---|---|--:|---|
| 80792 | `/usr/bin/coreutils` (manager container) | 225 | the lab's own job-age probe, alert-archive reads, and PATH misses when `timeout` looks up bash. Low volume, and the probe is ours |
| 533 | n/a (macOS agent) | 189 | listening ports opened or closed on the laptop. A real change each time |
| 80792 | `/usr/bin/bash` (manager container) | 176 | the job-age probe's shells, syscollector's `rpm -qa` pipelines, and `zcat` over rotated alerts |
| 750 | n/a (Windows endpoint) | 83 | registry values changed under FIM. Real changes, and exactly what FIM is for |
| 80792 | `/usr/bin/gawk` (manager container) | 82 | the job-age probe's parsing |

Truncated audit events that arrive without their working-directory record fail every suppression
and keep alerting. That's deliberate: a rule that can't see all of its fields doesn't fire.

Container restarts are loud by design. A manager start runs about 2,000 s6 init execs, and an
`apt upgrade` run through `sudo` carries a login session, so it alerts in full.

## Planted true positives

The suppressions must never hide what they look like. These run through the same test:

- A `curl` to `_cluster/health` from an interactive host shell: alerts as 80792.
- The same query through `bin/idx` inside the indexer container: alerts as 80792. It runs in the
  same directory under the same user as the healthcheck, and only the argv tells them apart.
- Lsass access (Sysmon EID 10) from an image not on the allowlist: no Windows rule is suppressed
  here. The live plant on the Windows endpoint is pending.

## Testing

A scratch suite logtested 309 cases on a throwaway manager running the lab's image (4.14.9).
There were 34 real captured events, one per shape, plus eight mutants of each that must fall back
to plain 80792: login session, tty, working directory, AppArmor label, argv, uid, euid and gid.
The indexer healthcheck has a ninth, a pinned dot changed to another byte. Then the two planted
curls. Result: 309 of 309. The suite and its fixtures move into this repo with B.1's
logtest harness. Until then, the lint runs from here:

```bash
bun tools/noise-lint.ts                 # keying rules on every suppression
bun test tools/noise-lint.test.ts       # the lint refuses each planted bad rule
```
