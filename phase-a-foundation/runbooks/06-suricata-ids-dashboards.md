# Suricata IDS on the host NIC + the SOC Overview dashboard

> **What this does:** stands up Suricata 8.0.7 as a container on the SOC host's physical NIC
> (`eno1`), feeds its `eve.json` into Wazuh through the existing `phase-a-linux` agent, tunes the
> local L2 noise floor out of the indexer, and builds the custom dashboard that Phase A ships as
> its deliverable.
>
> **Completed 2026-08-09.** Closes ISC-26 and ISC-27, the last two Phase A build criteria.
>
> **Revised 2026-10-01.** Bumped from 8.0.6 to 8.0.7. Log rotation and rule updates moved to host
> systemd timers after the in-container cron job turned out never to have run (section 6). The
> positive control no longer depends on a third-party site (section 4).
>
> **Why it matters for a SOC:** the three endpoint agents see what happens *on hosts*. Nothing
> until now saw what happens *on the wire*. Suricata is the network-visibility half, and its
> alerts land in the same indexer as Sysmon and auditd, so one query surfaces host and network
> evidence for the same event.
>
> **The load-bearing lesson in this runbook is section 3.** A Wazuh manager restart does NOT
> apply git-shipped configuration. It looks like it does (the container reports Up, all ten
> daemons run, every agent stays Active) and the config silently never lands. Read it before
> changing anything under `deploy/soc-recon/wazuh/`.
>
> Steps are tagged **[BOX]** (SOC host) or **[API]** (dashboard saved-objects API). Nothing here
> takes a password as an argument.

---

## 0. Orient — [BOX]

```bash
cd ~/talonsoclab/deploy/soc-recon
docker compose ps
ip -br link                      # confirm the physical NIC name; the compose default is eno1
free -h                          # Suricata adds ~2 GB to the always-on ceiling
```

The interface name matters more than it looks. Suricata runs with `network_mode: host`
specifically so the name in `SURICATA_IFACE` resolves to the same interface `ip -br link` shows.
Point it at a docker bridge and the sensor comes up **healthy and blind**: it captures the
bridge, sees nothing real, and reports no error.

## 1. Fetch the ET Open ruleset — [BOX]

The image ships **zero** signatures. This is the single most important step to not skip:
Suricata with no rules starts cleanly, writes flow/dns/tls records all day, and never alerts.
Green and blind.

```bash
docker compose run --rm suricata suricata-update
```

Expect `Loaded 68186 rules`, `enabled: 52245` (the 2026-08-09 counts; they move as ET Open
changes), written to `/var/lib/suricata/rules/suricata.rules`, then `Testing with suricata -T`.
The trailing `Reload command failed: ... suricata-command.socket: No such file or directory` is
**expected and harmless**: nothing is running yet, so there is no socket to reload. The rules
persist in the `suricata_rules` named volume.

This is the only manual fetch. From here on, the `soc-recon-suricata-update` timer (section 6)
re-runs `suricata-update` daily and live-reloads the engine. Without it the ruleset freezes at
whatever this command fetched. This lab's sat unchanged from 2026-08-09 until 2026-10-01.

## 2. Start the sensor — [BOX]

```bash
docker compose up -d suricata
docker compose ps suricata                    # want: Up (healthy)
docker compose logs suricata | head -5
```

The startup log must show `Checking for capability sys_nice: yes` and `net_admin: yes`. If
either says `no`, the entrypoint **silently drops its `--user`/`--group` arguments and runs
Suricata as root** rather than failing. The container still works, so the only place this shows
up is that line.

Confirm it is actually capturing, from the host:

```bash
grep -E "rules successfully loaded" /var/log/suricata/suricata.log
grep -o '"event_type":"[a-z_0-9]*"' /var/log/suricata/eve.json | sort | uniq -c | sort -rn
grep -o '"in_iface":"[a-z0-9]*"' /var/log/suricata/eve.json | head -1     # must be the real NIC
```

## 3. Wire eve.json into Wazuh — [BOX]

The `<localfile>` lives in git at `deploy/soc-recon/wazuh/shared/phase-a-linux/agent.conf` and
reaches the agent as group config. It is **not** edited on a running manager.

> ### The manager restart trap — read this
>
> `docker compose restart wazuh.manager` **does not apply this file.** Neither does
> `stop` + `start`. Only a **new container** does:
>
> ```bash
> docker compose up -d --force-recreate wazuh.manager
> ```
>
> **Why.** The image's init script (`/etc/cont-init.d/0-wazuh-init`) runs `main()` in a fixed
> order: `mount_permanent_data` first, `mount_files` (the step that copies
> `/wazuh-config-mount` into `/var/ossec`) much later. `mount_permanent_data` walks the
> `PERMANENT_DATA` list, and for any path that is **empty** it restores a baked-in backup from
> `/var/ossec/data_tmp`. `main()` deletes `data_tmp` at the end of its first successful run, and
> a container's filesystem survives `restart`/`stop`+`start`. So on every subsequent init:
> `/var/ossec/var/multigroups` is still empty (it only fills when an agent belongs to 2+ groups,
> and none here do), the restore source is gone, `cp` fails, and the script's
> `error_and_exit` kills it **before `mount_files` ever runs**.
>
> s6 logs `0-wazuh-init: exited 1` and starts the daemons anyway. The result is a manager that
> is Up, has all ten daemons running, keeps every agent Active, and is running last month's
> configuration. There is no error anywhere that says so.
>
> **Always verify the copy landed rather than trusting the restart:**
> ```bash
> docker compose logs --since 3m wazuh.manager | grep -E "Identified Wazuh|cont-init.d\] 0-wazuh-init"
> ```
> Want `Identified Wazuh configuration files to mount...`, the per-file `'/wazuh-config-mount/...' -> '/var/ossec/...'`
> lines, and `0-wazuh-init: exited 0`. An `exited 1` means nothing was applied.

Then confirm the group config actually reached the agent: compare the manager's `merged.mg`
hash against what the agent reports, which is the only check that proves delivery rather than
staging.

```bash
docker compose exec -T wazuh.manager md5sum /var/ossec/etc/shared/phase-a-linux/merged.mg
docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -i 002 | grep "Shared file hash"
```

The two must match.

## 4. Prove the alert path with a positive control — [BOX]

**"Suricata is running" is not acceptance.** Only `event_type: alert` survives to the indexer:
ruleset rule `86601` is level 3, while `86602`/`86603`/`86604` (http/dns/tls) are **level 0** and
the manager drops them at `log_alert_level 3`. A sensor generating flow and DNS records all day
produces exactly zero indexer documents. This is the same trap ISC-23.5 hit with Sysmon Event
ID 3: the observation channel has to be checked before a criterion is bound to it.

Trigger a real ET Open signature. Sid 2100498 (`GPL ATTACK_RESPONSE id check returned root`)
matches the bytes `uid=0(root)` in any IP payload, in either direction. One UDP datagram to
`192.0.2.1`, a TEST-NET-1 documentation address (RFC 5737) that no real host answers, puts those
bytes on the wire through `eno1`. `/dev/udp/` is a bash feature, so run this from bash, not sh:

```bash
printf 'uid=0(root) gid=0(root) groups=0(root)\n' > /dev/udp/192.0.2.1/9
grep "id check returned root" /var/log/suricata/fast.log | tail -1
```

> **Why not `curl testmynids.org`.** This step used to fetch `http://testmynids.org/uid/index.html`,
> which serves that same string. On 2026-10-01 the domain returned NXDOMAIN from 1.1.1.1, 8.8.8.8
> and 9.9.9.9 alike, and `curl -s` failed silently: an empty body, no error on screen, no alert.
> A positive control that depends on someone else's server can fail exactly the way the system
> under test fails. This one needs nothing outside the box.

Then confirm it reached the indexer (this is the collapsing probe: it cannot be true unless
capture, ruleset, eve.json, group config, agent tail, decoder, level floor and filebeat are all
simultaneously correct):

```bash
bin/idx '/wazuh-alerts-*/_search?size=1' \
  -d '{"query":{"term":{"data.alert.signature_id":"2100498"}}}'
```

> **Field-name note:** Wazuh decodes eve.json with its generic JSON decoder, so the fields are
> `data.alert.signature`, `data.src_ip`, `data.in_iface`, **not** `data.suricata.*`. That prefix
> belongs to Elastic's Filebeat Suricata module, which this stack does not use.

## 5. Tune the local noise floor — [BOX]

Two problems show up within minutes of a live sensor, and both are fixed in git.

**(a) Decoder-event flood.** `SURICATA Ethertype unknown` (sid 2200121) fires on every L2 frame
carrying an ethertype Suricata doesn't parse. On this LAN that is the TL-SG108E smart switch
broadcasting Realtek RRCP (`0x8899`) plus the router's LLDP/IEEE-1905 chatter, measured at
~66/min, ~95k alerts/day. In the first 11 minutes it put **214 documents** in the indexer against
**1** real signature hit.

Suppression is at the **manager**, not the sensor: `wazuh/custom-rules/local_suricata_tuning.xml`
scores it level 0. That keeps every frame in `eve.json` on disk (the full-fidelity network
archive) while stopping the indexer write. Disabling it in `suricata-update`'s `disable.conf`
would have erased the record along with the alert.

This requires one more thing, and it is easy to miss:

```xml
<rule_dir>etc/rules/custom</rule_dir>     <!-- in config/wazuh_cluster/wazuh_manager.conf -->
```

`rule_dir` is **not recursive**. Compose mounts `wazuh/custom-rules` to `etc/rules/custom`, and
without that explicit entry every rule in it is silently ignored: the mount exists, the XML is
on disk, `analysisd` never reads it, nothing reports a problem.

**(b) `ERROR: Too many fields for JSON decoder`.** Suricata's `stats` records carry several
hundred counters and blow through Wazuh's JSON-decoder field-count ceiling: one every 8 seconds,
~10k error lines/day, burying any real decoder error. The compose `--set` drops **only** stats
from the eve output; global `stats.enabled` stays on, so `stats.log` still answers "is the sensor
dropping packets?" via `capture.kernel_drops`.

> **`types.32` is a list index, not a name.** It is coupled to the pinned image tag. After any
> `SURICATA_VERSION` bump, re-derive it and confirm:
> ```bash
> docker run --rm --entrypoint /usr/bin/suricata jasonish/suricata:<ver> \
>   --set outputs.1.eve-log.types.32.stats.enabled=no --dump-config | grep types.32
> ```
> A wrong index silently sets the option on a different output type and the errors keep coming.
>
> Re-derived for 8.0.7 on 2026-10-01: the eve-log `types` list is identical to 8.0.6's (index 32
> is `stats`, 33 is `flow`), so the index carried over unchanged.

Verify both by measurement rather than inspection. Record a count, wait, record it again:

```bash
grep -c '"event_type":"stats"' /var/log/suricata/eve.json          # must stop increasing
docker compose logs --since 2m wazuh.manager | grep -c "Too many fields"   # must be 0
```

## 6. Log rotation — [BOX]

The image ships `/etc/logrotate.d/suricata` (daily, 3 rotations) and **nothing ever runs it**,
while the logs grow ~240 MB/day against a 256 GB NVMe. This is not a mistake by anyone. It is
the standard container seam, and it is worth understanding rather than pattern-matching to
"misconfigured". Verified against a pristine container 2026-08-09:

| Link in the chain | State in the image |
|---|---|
| `/etc/logrotate.d/suricata` | present, and **owned by no RPM**, so the image author added it, not the distro |
| what normally executes it on AlmaLinux 9 | `logrotate.timer` + `logrotate.service`; the logrotate RPM ships **only** systemd units, no `/etc/cron.daily/logrotate` |
| systemd in the container | binary present (`/sbin/init -> systemd`) but **never PID 1**; the entrypoint execs suricata, so the timer is never loaded |
| `/etc/cron.d/0hourly` | present → `run-parts /etc/cron.hourly` |
| `/etc/cron.hourly/0anacron` | present, `cronie-anacron` installed |
| `/etc/cron.daily/` | **EMPTY** ← the chain dead-ends here |

So the policy and its executor were packaged by different parties for different runtimes: RHEL
family moved logrotate to a systemd timer, and containers don't run systemd. Debian-based images
would not show this, because there logrotate still ships `/etc/cron.daily/logrotate`.

Note the consequence for the obvious shortcut: **`ENABLE_CRON=yes` on its own rotates nothing.**
crond would start, `0hourly` would fire, anacron would run `run-parts /etc/cron.daily` over an
empty directory. The flag supplies the scheduler; a cron entry still has to supply the job.

### The first fix never ran

Until 2026-10-01 compose tried exactly that pairing: `ENABLE_CRON=yes` started `crond`, and
`suricata/logrotate.cron` was bind-mounted to `/etc/cron.d/suricata-logrotate` with an explicit
04:00 entry. The job never ran once.

A bind mount keeps the host file's owner and mode, so inside the container the cron file was
uid 1000, mode 664. cronie skips any `/etc/cron.d` file that is not owned by root or is writable
by group or others, and nothing in this stack reported it. The check this section used to
prescribe was `ps ax | grep crond`. It passed the whole time, because a running scheduler says
nothing about whether it loaded the job. The forced `logrotate -f` that proved the policy on
2026-08-09 was the only rotation that ever happened. By 2026-10-01 `eve.json` had reached 2.5 GB,
`fast.log` 1.2 GB and `stats.log` 5.6 GB.

### The fix: host systemd timers

The host runs systemd as PID 1, and there a failed run shows up in `systemctl --failed`, in the
journal, and through the host's own Wazuh agent on the dashboard. `deploy/soc-recon/systemd/`
holds two oneshot services, their timers, and the two scripts the services run. The scripts do
the work and the checking; the units only schedule them.

| Unit | Daily at (UTC) | Script | What it does |
|---|---|---|---|
| `soc-recon-suricata-logrotate` | 04:00 | `soc-recon-suricata-logrotate.sh` | runs the image's own `/etc/logrotate.d/suricata` inside the container, then proves the engine reopened `eve.json` |
| `soc-recon-suricata-update` | 04:30 | `soc-recon-suricata-update.sh` | builds and tests the new ruleset in a stage beside the live one, promotes it, reloads, then proves the engine swapped to it |

Install them as root-owned copies, the scripts included, not as links into the checkout. A linked
unit or script would change with every `git pull`, with no install step where anyone looks at
what root is about to run:

```bash
cd ~/talonsoclab/deploy/soc-recon
sudo install -o root -g root -m 0755 systemd/*.sh /usr/local/sbin/
sudo install -o root -g root -m 0644 systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-recon-suricata-logrotate.timer soc-recon-suricata-update.timer
systemctl list-timers 'soc-recon-*'      # both timers, each with a NEXT time
```

`list-timers` proves the schedule, not the job. Run each service once by hand. A hand rotation
costs one generation of retention (see the note after the anti-tests), so the rotation can wait
for its first scheduled run instead:

```bash
sudo systemctl start soc-recon-suricata-update.service
systemctl show -p Result,ExecMainStatus,ExecMainExitTimestamp soc-recon-suricata-update.service
journalctl -u soc-recon-suricata-update.service -n 40 --no-pager
sudo systemctl start soc-recon-suricata-logrotate.service
systemctl show -p Result,ExecMainStatus,ExecMainExitTimestamp soc-recon-suricata-logrotate.service
journalctl -u soc-recon-suricata-logrotate.service -n 5 --no-pager    # the "rotated:" line
```

`Result=success` on its own proves nothing. systemd prints it for a unit that has never run, and
for a unit name that does not exist. The evidence is `ExecMainStatus=0` with an
`ExecMainExitTimestamp` from just now, and the journal lines below.

The update's journal shows `Writing rules to /var/lib/suricata/.stage.<random>/suricata.rules`,
`Testing with suricata -T`, `promoted <n> rules`, the engine's `{"message":"done","return":"OK"}`
reply, `engine swapped: last_reload <before> -> <after>`, a `ruleset-stats` line, and
`update complete: <n> rules loaded`. The rotation's journal ends with `rotated: eve.json.1 holds
inode <old>, the new eve.json is inode <new>`. Then prove detection survived both, with the
section 4 positive control.

Then the anti-tests. With the engine stopped, the rotation must fail rather than report success,
and the failure must reach Wazuh. This costs about a minute of sensor downtime. Use `stop` and
`start`, not `up`, so the container is not recreated, and not `docker kill` (see the recovery
bullets below):

```bash
t=$(date -u +%FT%TZ)
docker compose stop suricata
sudo systemctl start soc-recon-suricata-logrotate.service    # must fail
systemctl show -p Result,ExecMainStatus soc-recon-suricata-logrotate.service    # exit-code, 1
docker compose start suricata
sudo systemctl reset-failed soc-recon-suricata-logrotate.service
q='{"query":{"bool":{"filter":[{"term":{"rule.id":"40704"}},
  {"match_phrase":{"full_log":"soc-recon-suricata-logrotate"}},
  {"range":{"timestamp":{"gte":"'"$t"'"}}}]}}}'
sleep 30; bin/idx '/wazuh-alerts-*/_count' -d "$q" | jq -r .count    # want 1
```

And the update's floor must fail closed, before anything goes live. This builds and tests a full
ruleset, so it costs about 40 s:

```bash
sudo env MIN_RULES=999999 /usr/local/sbin/soc-recon-suricata-update.sh; echo "rc=$?"
# want rc=1 and "only <n> rules staged, the floor is 999999; live rules untouched"
```

A hand run needs `sudo`. The script's lock lives in `/run`, where only root can create files, so
a run as any other user stops at the lock. The unit unsets `MIN_RULES`, so
`systemctl set-environment` cannot lower the floor for the timer. A hand run can still set it,
which is how this test works.

Every successful rotation is a forced one, and `rotate 3` deletes whatever is pushed past `.3`.
Copy anything worth keeping out of `/var/log/suricata/` before the timers age it out.

### Why the scripts look the way they do

- **`logrotate -f`.** logrotate keeps its state file in the container's writable layer, so every
  recreate loses it. On a run with no state entry, logrotate 3.18 records the log and rotates
  nothing. Forcing makes the timer the only schedule, and every run a rotation, so a second run
  on the same day shifts every generation by one.
- **The `uptime` gate.** logrotate renames first and asks the engine to reopen second. If the
  engine is not answering, the rename still happens, the reopen fails, and the engine keeps
  writing into `eve.json.1`, which the Wazuh agent no longer reads. The script asks the engine
  socket for its uptime before touching anything.
- **The `eve.json` proof is two inode checks.** `reopen-log-files` replies OK whether or not
  anything reopened, so the script checks the disk the agent reads. `eve.json.1` must carry the
  inode `eve.json` had before the run, which fails a logrotate that exits 0 without renaming.
  Then a new, non-empty `eve.json` on a different inode must appear within two minutes, which
  fails a reopen that never came. The sensor wrote `eve.json` in each of 600 sampled seconds on
  2026-10-02, and logged events in all 120 seconds from 04:00 to 04:02 UTC on each night from
  2026-09-29 to 2026-10-02, so two quiet minutes mean trouble, not a quiet network. The new
  `eve.json` must be a regular file, not a link: `stat` reads a link itself and `[ -s ]` reads
  its target, so a link planted in place of `eve.json` passed both checks until this one was
  added (R8).
- **The recovery trap.** A run that stops between the rename and the reopen, because the
  postrotate failed or hung or the unit was killed, leaves the engine writing into `eve.json.1`
  while the agent waits for an `eve.json` that never comes. So on any failure after the rename,
  if `eve.json` is missing, the exit trap sends the engine `SIGHUP`. Suricata reopens its logs on
  `SIGHUP` through its main loop, a path that needs neither the socket nor the postrotate step,
  and the new `eve.json` appears on the engine's next write. The trap can look too early, though.
  `docker exec` does not forward signals, so a unit stopped before logrotate's rename leaves
  logrotate running in the container, and the rename lands after the trap has found `eve.json`
  still in place. If the postrotate then fails, nothing reopens the log. So the shell that runs
  logrotate in the container makes the same check whenever logrotate fails, and that shell
  outlives the unit (R10). When both checks send `SIGHUP`, the second one is harmless: the engine
  reopens `eve.json` in append mode, so it just opens the same file again.
- **`SIGHUP` from inside the container, never `docker kill`.** On an image that sets no
  `STOPSIGNAL`, Docker handles a `docker kill` as a stop, whatever the signal, and cancels the
  restart policy. Measured on 2026-10-02: after `docker compose kill -s HUP` the engine kept
  running, but its next clean exit was not restarted, where the same exit just before had been.
  The trap runs `kill -s HUP 1` through `docker compose exec`, which Docker never sees as a kill.
- **The stage.** `suricata-update` writes into a fresh directory beside `rules/` on the same
  volume (`--output`), and its `suricata -T` tests that staged file, failing on any rule the
  engine cannot parse. The stage must hold exactly `classification.config` and `suricata.rules`,
  and at least `MIN_RULES` rules, before `suricata.rules` is renamed into `rules/`. The live
  ruleset changes in that one rename, and a run that fails or is killed before then leaves it
  exactly as it was. `classification.config` stays behind: the engine and its `-T` both read
  `/etc/suricata/classification.config`, so the copy an earlier version promoted into `rules/`
  is never read. An empty stage never matches "No changes detected", so every run is tested
  without `--force`. Each run first deletes any stage an earlier run left, under the build lock
  (below), so never one a build is still writing. A feed that starts shipping datasets or Lua
  files fails the contents check, and alerts, until the script learns to promote them. That beats
  promoting an output whose shape has changed. The exit trap deletes the run's own stage, and a
  run whose cleanup fails exits 1 even after a good update (C2). The next run would clear the
  stage, but a docker call that fails there is worth an alert.
- **The rule floor, checked twice.** Fewer than 40,000 rules (`MIN_RULES`) fails the run. The
  staged count is checked before the promote, so an empty or gutted ruleset, from a bad
  `disable.conf` for example, never reaches the engine. After the reload, `rules_loaded` must
  clear the floor again and `rules_failed` must be 0. The staged count is the file's non-comment
  lines, which matched `rules_loaded` exactly on 2026-10-02: 53,073, the number ET Open had
  enabled on 2026-10-01. The script does not demand that the two counts match, because a rule
  the engine skips would then fail a good run.
- **The reload is checked by the engine's own clock.** `suricata-update` logs a failed reload
  and still exits 0, hence `--no-reload`. And `reload-rules` replies OK once the reload finishes,
  even when the new engine failed to build and the old one kept running. So the script reads the
  engine's `last_reload` before and after, and fails unless it moved.
- **And by the engine's own log.** A worker thread that fails to take the new engine logs an
  error, and the engine still logs `rule reload complete` and moves `last_reload`. So the script
  reads the engine's console log from just before the reload, waits up to 10 s for the exact line
  `i: detect: rule reload complete`, and fails on any `E: ` line in that window. Matching the
  whole line also proves the log is still in the default console format, the one where errors
  start with `E: `. If the format ever changes, the run fails on the missing line instead of
  missing the errors. The live engine had never logged an `E:` line as of 2026-10-02, so a false
  alarm is unlikely.
- **No rollback.** Once `suricata.rules` is promoted, a failed reload leaves it in place. It
  passed `suricata -T`, which fails on any rule that does not parse, so a failure past the
  promote lies in the reload or the checks around it, not in the rules. The engine keeps running
  the old ruleset, and the new file loads at the next restart. The failed run alerts, so nobody
  restarts into it blind.
- **`--fail`.** Without it, a failed download falls back to the cached archive, rebuilds the same
  rules and exits 0. Every night of a dead feed would look like a good one.
- **The `suricata` user.** Everything the scripts run in the container runs as `suricata`, above
  all `suricata-update`, which unpacks an archive fetched from the internet. logrotate and the
  recovery `SIGHUP` run as container root: the image's policy file is readable only by root, and
  the `SIGHUP` is a fixed `kill -s HUP 1` with nothing from the container in it. Whether it is
  sent does depend on the container: both checks test for `eve.json` in a directory the engine's
  user owns, so that user can trigger the signal or suppress it. Neither gains anything. The same
  user can signal its own engine directly, and the repair only runs on a run that has already
  failed and alerted. The policy has no `create`, so root only renames and deletes, and neither
  follows a link. Its postrotate does run `suricatasc` as container root against the engine's
  socket, so root parses a reply the engine's user controls (the threat-model line under Known
  gaps).
- **Every failure exits 1, short of a few signals.** Wazuh rule 40704 (level 5) alerts on a failed
  unit only when the journal says `status=1/FAILURE`. A timeout's 124 or a signal's 143 lands on
  level-0 rule 40700 instead, and fails in silence. Both scripts trap `EXIT` and leave with 1.
  dash dies of an untrapped signal without running that trap, so `HUP`, `INT`, `QUIT` and `TERM`
  each get a trap of their own: the previous update script, sent `SIGHUP` mid-build, ended
  `status=1/HUP` and raised nothing in 150 s (G1a). A start timeout sends `SIGTERM`, then
  `SIGKILL` once `TimeoutStopSec` runs out, and a killed script ends `status=9/KILL`, which rule
  40704 does not match (T1). The trap needs up to 35 s, so both units pin `TimeoutStopSec` at 2
  minutes rather than trust the system default, 90 s on this box. On 2026-10-02 a start timeout
  forced on each script in a scratch stack ran the trap, ended `status=1/FAILURE`, and raised
  rule 40704 within 10 s. So did `SIGHUP`, `SIGQUIT` (G1a, G1b) and the docker check below.
  `SIGKILL` cannot be trapped, and `USR1`, `USR2` and `ALRM` have no trap (Known gaps).
- **Timeouts inside the container.** Killing the docker CLI does not stop what it started in the
  container, so the build, the socket queries and logrotate each run under `timeout -k` in there.
  Their worst case adds up to about 23 minutes for the update and 5.5 for the rotation, under the
  units' `TimeoutStartSec` of 30 and 8. The log read and the docker calls in the exit trap carry
  a limit on the host. The quick calls, `mktemp`, `find`, `grep` and `mv` on the rules volume,
  carry none. A call that hangs anyway, in the daemon or on the volume, is what `TimeoutStartSec`
  is for: systemd stops the script, and the trap still exits 1. That path is expected, not
  tested. Every test ran against a healthy daemon, and a docker call stuck on a dead one could
  outlast `TimeoutStopSec` and end in `SIGKILL`.
- **The docker check, not `Requisite=`.** `docker.socket` is enabled on Ubuntu, so any `docker`
  command while the daemon is stopped for maintenance would start it again, and every
  `unless-stopped` container with it. So each script checks `systemctl is-active docker.service`
  before its first docker command, and fails if the daemon is down. The units used to say
  `Requisite=docker.service`, which looks like the same thing and is not. An inactive requisite
  skips the start job: the script never runs, nothing exits 1, the unit never shows in
  `systemctl --failed`, and Wazuh gets no `status=1/FAILURE` line. The units keep
  `After=docker.service` for ordering only.
- **Two locks.** Two builds at once would load two extra rulesets into one memory cap. One can
  come from a hand run that overlaps the timer, and one from a killed run whose builder is still
  going. So the update takes a lock on the host, `/run/soc-recon-suricata-update.lock`, and fails
  at once when another run holds it. Inside the container it takes a second lock around the
  stage cleanup and the build. A builder orphaned by a killed run keeps holding that one until it
  ends, so the next run fails with `another build holds the lock, nothing changed` instead of
  racing it. The host lock lives in `/run`, where only root can create files. A lock file
  another user left in the sticky `/run/lock` would refuse root, because of
  `fs.protected_regular=2`.
- **A fixed `PATH`.** The scripts set `PATH=/usr/sbin:/usr/bin`, so root never resolves `docker`
  or `jq` through `/usr/local`. The docker CLI finds `compose` in its own plugin directories, not
  through `PATH`: first root's own under `/root`, then any listed in its `config.json`, then
  four system directories. Of those four, only `/usr/libexec/docker/cli-plugins` exists on the box,
  and it is root-owned.
- **Host tools.** The scripts need `jq` on the host, and three GNU options: `timeout -k`,
  `stat -c` and `date +%N`. Ubuntu 26.04 ships uutils 0.10, the Rust rewrite of coreutils, which
  has all three. The unit headers say the same.
- **The memory cap.** The update runs inside the sensor's container, and its `suricata -T` loads
  a second full ruleset beside the live engine. That is why `mem_limit` is 2g (see the comment in
  `docker-compose.yml`). The staged update sampled a 1.51 GB peak on 2026-10-02. Processes
  started through `docker exec` inherit the engine's `oom_score_adj` of -400, so the build raises
  its own to 1000. If the two outgrow the cap together, the kernel kills the build, not the
  engine.
- **No `Persistent=`.** A catch-up run at boot would fire before the container is up and fail.
  A missed night costs one day of rules, or one rotation that carries two days.

### Known gaps

- **Nothing pages.** A failed run raises a level 5 alert (rule 40704) on the dashboard and shows
  in `systemctl --failed` and the journal, but nobody is told. Check them at the start of a
  session. A run killed by `SIGKILL` never reaches its trap and lands on level 0. That happens
  when an operator sends it, or when a stop outlasts `TimeoutStopSec` (T1), which the 2-minute
  pin makes unlikely. Two ways would catch it, neither built: an `OnFailure=` unit that itself
  exits 1, or a local Wazuh rule on `status=9/KILL`.
- **Signals with no trap.** `USR1`, `USR2` and `ALRM` kill the script without its exit trap, the
  same as `SIGKILL`. Nothing in the stack sends them, so it takes an operator who picks one. A
  write to stderr that fails inside the trap would end the run with 2, and a second signal in the
  instant before the trap disarms them ends it with that signal's code. systemd signals once and
  ignores `SIGPIPE` for both units. A local Wazuh rule on systemd's `Failed with result` line
  for these two units would catch every case, `SIGKILL` included.
- **A partial rotation can strand the other logs.** The policy renames the `*.log` files before
  `eve.json`. If a rename fails in between, logrotate skips the reopen, and both repairs send
  `SIGHUP` only when `eve.json` is missing. The run still fails its inode proof and alerts, but
  `fast.log`, `stats.log` and `suricata.log` go on into their renamed files until the next
  reopen. Wazuh reads only `eve.json`. The planned fix is a `SIGHUP` on any failed rotation.
- **A killed update leaves its builder running.** `docker exec` does not forward signals, so
  `suricata-update` runs on inside the container until it finishes or hits its own 900 s limit
  (U4). The exit trap deletes the stage, though a builder that has not yet written its output
  makes it again. The builder never touches the live rules, and it holds the build lock the
  whole time, so a run that starts meanwhile fails and alerts instead of racing it (M2a). Once
  it ends, the next run completes (M2b), and first deletes any stage left behind (S1), as it does
  one left by a run killed with `SIGKILL`.
- **The Hyperscan cache is shared.** The test and the live engine both use
  `/var/lib/suricata/cache/sgh`. The test warms it, which is why a reload takes about 15 s
  instead of 30, but the stage does not isolate it.
- **The log directory must stay `755`.** logrotate refuses a parent directory that is group- or
  world-writable ("parent directory has insecure permissions"), so the run fails and alerts. The
  first scratch run below hit this by accident: its log directory was `775`, every rotation
  failed with exit 1, and the one under systemd raised rule 40704.
- **Back-to-back runs test the same archive.** `suricata-update` skips the download within 15
  minutes of the last one, and when the remote checksum has not changed.
- **The log directory belongs to the engine's uid.** On the host, `/var/log/suricata` is owned by
  uid 998, the engine's user in the container and `systemd-network` on the host. Whoever holds
  that uid can replace `eve.json` with a link, and the Wazuh agent, which runs as root, follows
  the path it is given. This predates the timers. It is a threat-model line, not fixed here. The
  rotation proof refuses a link (R8) but cannot tell a decoy regular file from the engine's own
  (R9). The same uid also writes everything root parses from the engine: the socket replies that
  `suricatasc` and `jq` read, and the console log the update searches for `E: ` lines. It owns
  `/var/run/suricata`, so it could answer those queries itself, with an `uptime` from a dead
  engine or a `last_reload` that moves without a reload. Whoever holds the uid can already blind
  the sensor outright. Forging a check adds one thing: the failed run passes, so no alert fires.
  A stronger proof would confirm from the host that the engine process holds the new `eve.json`
  open, through `/proc/<pid>/fd`, which neither a decoy file nor a forged reply would pass.
- **The rotation has no lock.** A hand rotation that overlaps the timer's can rotate twice, or
  fail its proof and alert. The update needs its locks because two builds can exhaust the memory
  cap. Two rotations only shift files.
- **A version bump never refreshes `/etc/suricata`.** The image declares `/etc/suricata` a
  volume, and recreating the container keeps the old one. On 2026-10-02 the sensor still ran
  8.0.6's `suricata.yaml` under 8.0.7. Apart from comments, the diff between the two was one
  empty `cache:` key under `thresholds`, which leaves the engine's default in place. Diff them
  on every bump. `docker compose up -d -V` renews the image's anonymous volumes and keeps the
  named rules volume (V1), so it refreshes `/etc/suricata` and discards anything changed in it.

### Proven on a scratch stack, then on the sensor

Each failure path below ran on 2026-10-02 against `s03test`, a throwaway copy of the sensor on the
same box with its own container, rules volume and log directory. The tests ran the production
scripts, retargeted with `sed` at that project, log path and lock file, and a guard refused any
copy that still named the live ones. The rotation tests other than R5 and R10 shortened the
logrotate limit to 15 s and the wait to 20 s. D1, G1a, G1b, R5, R10, T1, C2 and U4 ran as
transient systemd units, so their failures reached Wazuh through the journal. K1, K2 and V1
tested Docker, and T1 tested systemd, not the scripts. Every row that tests the scripts ran
again on the final ones in a single pass. R4 needs 20 quiet seconds, a stray write broke them in
that pass, and it passed when run again on its own.

| Test | Injected | Result |
|---|---|---|
| D1 | the docker check fails, in each script | exit 1 before any docker command, `status=1/FAILURE`, rule 40704 in 10 s |
| G1a | `SIGHUP` to every process in the update unit, mid-build | `status=1/FAILURE`, rule 40704; the trap deleted the stage and the builder, still running, wrote it again. The previous script ended `status=1/HUP` and raised nothing in 150 s |
| G1b | `SIGQUIT` to the rotation script while it waits for a reopen that never comes | `status=1/FAILURE`, `SIGHUP` sent, a new `eve.json` within 4 s, rule 40704 |
| T1 | `TimeoutStartSec=3s` on a stand-in script whose `TERM` trap takes 8 s | with `TimeoutStopSec=3s`, `status=9/KILL` and no rule 40704 in 150 s; with `15s`, `status=1/FAILURE` and rule 40704 in 15 s |
| C2 | the stage cleanup fails after a good update | exit 1, `rules updated, but the run left its stage behind`, `last_reload` moved, rule 40704 in 10 s |
| R1 | nothing | exit 0, rotated |
| R2 | postrotate exits 1 | exit 1, `SIGHUP` sent, a new `eve.json` within 4 s |
| R3 | postrotate hangs (`sleep 600`) | `timeout` killed it (124), exit 1, `SIGHUP`, recovered, no orphaned `sleep` |
| R4 | quiet sensor, no write in the 20 s after the rotation | exit 1, `SIGHUP`, recovered once traffic returned |
| R5 | `TimeoutStartSec=20s` while postrotate hangs | the trap ran on `SIGTERM` and sent `SIGHUP`, `status=1/FAILURE`, rule 40704 in 10 s, recovered |
| R6 | engine stopped | exit 1, `engine not answering`, nothing renamed, no `SIGHUP` |
| R8 | postrotate plants a link at `eve.json` | exit 1 when the wait ran out, where the previous script exited 0 |
| R9 | postrotate writes a decoy `eve.json` | exit 0 while the engine kept writing `eve.json.1`, the residual under Known gaps |
| R10 | `TimeoutStartSec=4s` stops the unit in an 8 s prerotate, then postrotate exits 1 | `status=1/FAILURE`, rule 40704; after the late rename the container shell sent `SIGHUP`, and a new `eve.json` was in place 12 s later. The previous script left the engine writing `eve.json.1` with no `eve.json` |
| U1 | nothing | exit 0, 53,073 promoted and loaded, 0 failed, no stage left; the build ran at `oom_score_adj` 1000, the engine at -400 |
| U2 | `MIN_RULES=999999` | exit 1 before the promote, rules and `last_reload` unchanged |
| U3 | an extra file in the stage | exit 1, `unexpected stage contents`, rules unchanged |
| U4 | `TimeoutStartSec=6s`, inside the build | `status=1/FAILURE`, rule 40704 in 5 s, rules unchanged, the builder still running |
| M2a | a run while U4's builder is still going | exit 1 at once, `another build holds the lock, nothing changed`, still one builder |
| M2b | the next run, after the builder ended | exit 0, 53,073 promoted and loaded |
| H1 | another run holds the host lock | exit 1 at once, `another rule update is running` |
| C1 | the build lock held in the container | exit 1 at once, `another build holds the lock, nothing changed` |
| S1 | two stale stages | both deleted under the build lock |
| N1 | a hand run without `sudo`, real lock path | exit 1 at the `/run` lock, nothing ran |
| F7a | a synthetic `E:` line in the reload window | exit 1, `the engine logged errors during the reload` |
| F7b | the exact completion line never appears | exit 1 after 10 s of polling |
| K1, K2 | a clean engine exit, before and after `docker compose kill -s HUP` | restarted before, not restarted after |
| V1 | a marker file in `/etc/suricata`, then a recreate without `-V` and one with it | kept without `-V`; with it, a new `/etc/suricata` volume and no marker, the rules volume and its sha256 unchanged, 53,073 loaded |

Before the locks existed (a run now needs root), the update also ran by hand on the live sensor
under `sh` as the docker-group user. It exited 0 in 35 s, `last_reload` moved from 06:15:48 to
08:04:10 UTC, 53,073 rules were staged and 53,073 loaded with 0 failed, the engine logged no `E:`
or `W:` line, and no stage was left. The floor run exited 1 in 20 s with the live file's sha256
and `last_reload` unchanged. The positive control indexed 15 s after it.

### Prove rotation end to end, not just that the unit succeeded

Verified twice on 2026-10-01, both times before the root install. The first unit design, run
under a user manager, moved the 2.5 GB backlog into `eve.json.1`. Then the scripts themselves,
run by hand on the box, printed `rotated: eve.json.1 holds inode 12487985, the new eve.json is
inode 12488389` and exited 0 in a second. Five minutes later `eve.json`, `fast.log` and
`stats.log` were all growing on new inodes while their `.1` files sat still, so the engine had
reopened all three, not just the file the script checks.

> **The trap in verifying this.** After rotation the indexer's Suricata doc count sat unchanged,
> which looks exactly like "the agent lost the file". It is not evidence either way: the L2 noise
> is suppressed at level 0 by rule 100200, so only a genuine signature can move that counter. The
> discriminating test is to trigger a real one *after* the rotation, with the section 4 datagram.
> On 2026-10-01 sid 2100498 reached the indexer within 10 s of the first rotation and 35 s of the
> second, proving the Wazuh agent re-followed the new inode both times. This is the same "no
> alerts is not evidence of no ingestion" trap as ISC-23.5; a static counter on a
> deliberately-silenced channel proves nothing.

Minor, benign: `suricata.log` is rotated but not immediately recreated. Suricata only writes it
on engine events, so it reappears at the next one.

## 7. The SOC Overview dashboard — [API]

`dashboards/talonsoclab-soc-overview.ndjson` holds the dashboard plus five visualizations:
alerts over time by endpoint, severity distribution, MITRE ATT&CK tactics, top firing rules, and
Suricata IDS signatures.

Import it from the box, so the password never leaves it. It reaches curl on stdin as a config
line, never as an argument (see `deploy/soc-recon/wazuh/SECURITY.md`):

```bash
docker cp ../../dashboards/talonsoclab-soc-overview.ndjson soc-recon-wazuh.dashboard-1:/tmp/d.ndjson
PASS=$(grep -E '^WAZUH_INDEXER_PASS=' .env | cut -d= -f2-)
printf 'user = "admin:%s"\n' "$PASS" | docker compose exec -T wazuh.dashboard \
  curl -sk -K - -H "osd-xsrf: true" -X POST \
  "https://localhost:5601/api/saved_objects/_import?overwrite=true" --form file=@/tmp/d.ndjson
unset PASS
```

> **Refresh the index-pattern field list first, or the Suricata panel will fail.** OpenSearch
> Dashboards stores `wazuh-alerts-*`'s field list as a **cached snapshot** on the saved object.
> It does not follow the mapping. Any field that appears later (`data.alert.*` the moment
> Suricata starts shipping) is absent, and the panel renders
> `Could not locate that index-pattern-field (id: data.alert.signature)` **even though the
> aggregation is valid and the data is queryable**. The import reports success either way.
>
> Fix: Dashboards → Stack Management → Index patterns → `wazuh-alerts-*` → the refresh button;
> or `PUT /api/saved_objects/index-pattern/wazuh-alerts-*` with the `fields` array from
> `GET /api/index_patterns/_fields_for_wildcard?pattern=wazuh-alerts-*`. This lab's refresh took
> the pattern to 855 fields.
>
> The committed ndjson deliberately **excludes** the index-pattern object: it is 139 KB of
> derived, stale-on-arrival field cache. Refresh it on the live stack instead.

**Data-table gotcha:** OpenSearch Dashboards orders table columns by agg **id**, not by array
position. A metric at id `1` always renders as the leading column, producing a table of bare
numbers with the labels scrolled off. The bucket agg takes id `1` in both tables here, the metric
takes id `2`, and each terms agg's `orderBy` points at `2` to match.

## Acceptance

- [x] Suricata 8.0.6 `Up (healthy)` on `eno1`, `52245 rules successfully loaded, 0 rules failed`
- [x] `eve.json` on the host carries `in_iface: eno1` and multiple event types
- [x] `merged.mg` md5 on the manager matches agent 002's reported *Shared file hash*
- [x] Positive control: `GPL ATTACK_RESPONSE id check returned root` (sid 2100498) queryable in
      `wazuh-alerts-*` as `rule.id 86601`, level 3, from agent `talonsoclab`
- [x] Noise suppressed: ethertype documents frozen across 120s of live traffic while a repeat
      positive control still landed (sid 2100498 count 1 → 2): surgical, not a blanket break
- [x] `Too many fields for JSON decoder` errors 5952 → 0
- [x] `crond` running; logrotate policy parses. **Insufficient, found 2026-10-01:** both held
      while the cron job never loaded (section 6). Superseded by the host-timer criteria below.
- [x] Dashboard renders all five panels with live data, verified in real Chrome, not by import
      status. The Suricata panel failed on the first render despite a clean import; only the
      visual check caught it.

### Revision 2026-10-01

- [x] Suricata 8.0.7 `Up (healthy)`, startup log shows `sys_nice: yes`, `types.32` re-derived and
      held: `Too many fields for JSON decoder` stayed at 0 through the first hour
- [x] Staged update run by hand on the sensor (2026-10-02, under `sh`): `suricata -T` passed on
      the stage, 53,073 promoted, `last_reload` moved, `ruleset-stats` 53,073 loaded and 0
      failed, no `E:` line, no stage left, exit 0 in 35 s
- [x] Floor anti-test on the sensor: with `MIN_RULES=999999` the update exits 1 before the promote
      with `only 53073 rules staged, the floor is 999999; live rules untouched`, and the live
      file's sha256 and `last_reload` are unchanged
- [x] Rotation script run by hand (2026-10-01, before the recovery trap): `eve.json.1` took the old
      inode, a new `eve.json` was written within a second, and `fast.log` and `stats.log`
      reopened too
- [x] Positive control reached the indexer as `rule.id 86601` after each rotation (10 s, then
      35 s), after the rule reload, and after the staged update (15 s)
- [x] The update fits the cap with a reloaded engine: `memory.peak` 1.62 GB against `mem_limit: 2g`,
      no swap, zero `high`, `max` or `oom` events; the staged update sampled 1.51 GB
- [x] The failure paths in the section 6 table proven on a scratch stack. A forced start timeout
      on each script, and the docker check failing in each, ended `status=1/FAILURE` and raised
      rule 40704 within 10 s
- [x] Units pass `systemd-analyze verify` on the box (systemd 259), and both calendars resolve to
      the next 04:00 and 04:30 UTC
- [x] Scripts and units installed root-owned (2026-10-02 22:49 UTC): all six match their
      sha256, scripts `root:root 755`, units `root:root 644`, `TimeoutStopUSec=2min` on both
      services, both timers enabled with NEXT at 04:00 and 04:30 UTC
- [x] The update ends `ExecMainStatus=0` with a fresh `ExecMainExitTimestamp` as a root system
      unit, run by hand: exit at 22:50:28 UTC, `engine swapped`, 53,098 loaded and 0 failed, no
      stage left, the host lock `root:root 600`, no rule 40704, and the positive control indexed
      10 s later
- [x] The rotation ends `ExecMainStatus=0` with a fresh `ExecMainExitTimestamp` at its first
      scheduled run (a hand run would cost one more generation of retention): exit at 04:00:02
      UTC on 2026-10-03, no rule 40704, and the positive control indexed 15 s after a probe at
      05:17 UTC
- [x] Anti-test (2026-10-02, on the previous revision of the scripts): with the container
      stopped, the rotation unit ended `Result=exit-code` and Wazuh raised rule 40704 at 11:13:15
      UTC. The final scripts take the same path (R6)
- [x] First scheduled runs confirmed from the journal with no manual action: the rotation's
      `rotated:` line with `eve.json.1` under 26 h old, and the update's `engine swapped` line
      with a `last_reload` after 04:30 UTC. On 2026-10-03 the rotation moved the old inode to
      `eve.json.1` at 04:00:01, and the update swapped the engine at 04:30:38 with 53,098 loaded
      and 0 failed
