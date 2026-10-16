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
> **Revised 2026-10-14 (round 6).** Both services name an `OnFailure=` handler, so a kill or an
> exec error still raises rule 40704. Both scripts trap the signals systemd or an operator is
> likely to send, and a failed rotation sends the engine `SIGHUP` whether or not `eve.json` is
> missing (section 6).
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
the work and the checking; the units only schedule them. The same directory also holds the
manager's log retention unit, timer and script (runbook 08) and the `OnFailure=` handler,
`soc-recon-unit-failed@.service`.

| Unit | Daily at (UTC) | Script | What it does |
|---|---|---|---|
| `soc-recon-suricata-logrotate` | 04:00 | `soc-recon-suricata-logrotate.sh` | runs the image's own `/etc/logrotate.d/suricata` inside the container, then proves the engine reopened `eve.json` |
| `soc-recon-suricata-update` | 04:30 | `soc-recon-suricata-update.sh` | builds and tests the new ruleset in a stage beside the live one, promotes it, reloads, then proves the engine swapped to it |

Install them as root-owned copies, the scripts included, not as links into the checkout. A linked
unit or script would change with every `git pull`, with no install step where anyone looks at
what root is about to run:

```bash
cd ~/talonsoclab/deploy/soc-recon
sudo install -o root -g root -m 0755 systemd/soc-recon-suricata-*.sh /usr/local/sbin/
sudo install -o root -g root -m 0644 systemd/soc-recon-suricata-*.service \
  systemd/soc-recon-suricata-*.timer 'systemd/soc-recon-unit-failed@.service' \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-recon-suricata-logrotate.timer soc-recon-suricata-update.timer
systemctl list-timers 'soc-recon-suricata-*'      # both timers, each with a NEXT time
systemctl show -p OnFailure,IgnoreSIGPIPE soc-recon-suricata-logrotate.service \
  soc-recon-suricata-update.service
```

Both services name `soc-recon-unit-failed@%n.service` as their `OnFailure=` handler, the one
runbook 08 installs and drills (its step 1). `show` prints the name even when the file is
missing, so run that drill once on a box that has never had it.

`LAST` shows `-` after a reboot. Without `Persistent=`, systemd keeps the last trigger in memory
only, so the column is no evidence either way; the journal is.

`list-timers` proves the schedule, not the job. Run each service once by hand. A hand rotation
costs one generation of retention (see the note after the anti-tests), so the rotation can wait
for its first scheduled run instead:

```bash
sudo systemctl start soc-recon-suricata-update.service
journalctl -u soc-recon-suricata-update.service -n 40 --no-pager
sudo systemctl start soc-recon-suricata-logrotate.service
journalctl -u soc-recon-suricata-logrotate.service -n 5 --no-pager    # the "rotated:" line
```

`systemctl show` is no evidence here. `Result=success` and `ExecMainStatus=0` print for a unit
that has never run, and for a unit name that does not exist, and `ExecMainExitTimestamp` came
back empty for a oneshot that had just finished (runbook 08, 2026-10-13). The evidence is the
journal: `Starting` and `Finished` lines from just now, with the script's lines below between
them.

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
sudo systemctl reset-failed soc-recon-suricata-logrotate.service \
  'soc-recon-unit-failed@soc-recon-suricata-logrotate.service.service'
# NOTE: full unit names. The indexer reads `logrotate.service` as one word, so a
# phrase ending in `-logrotate` matches neither line.
u=soc-recon-suricata-logrotate.service
q='{"query":{"bool":{"filter":[{"term":{"rule.id":"40704"}},
  {"bool":{"should":[{"match_phrase":{"full_log":"'"$u"'"}},
    {"match_phrase":{"full_log":"soc-recon-unit-failed@'"$u"'.service"}}],
   "minimum_should_match":1}},
  {"range":{"timestamp":{"gte":"'"$t"'"}}}]}}}'
sleep 30; bin/idx '/wazuh-alerts-*/_count' -d "$q" | jq -r .count    # want 2
```

Two, because the `OnFailure=` handler logs its own `status=1/FAILURE` line under its instance
name, `soc-recon-unit-failed@soc-recon-suricata-logrotate.service.service`. Both units need the
`reset-failed`. Until 2026-10-14 this query used the phrase `soc-recon-suricata-logrotate`,
which returns 0 even for the alert the 2026-10-02 anti-test raised.

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
  while the agent waits for an `eve.json` that never comes. The policy also renames the `*.log`
  files before `eve.json`, so a rename that fails in between leaves `fast.log` and `stats.log`
  going into their `.1` files with `eve.json` still in place. So on any failure once the
  rotation has begun, the exit trap sends the engine `SIGHUP`, whether or not `eve.json` is
  missing. Suricata reopens its logs on `SIGHUP` through its main loop, a path that needs
  neither the socket nor the postrotate step, and each new file appears on the engine's next
  write to it. The trap can fire too early, though. `docker exec` does not forward signals, so a
  unit stopped before logrotate's rename leaves logrotate running in the container, and the
  rename lands after the trap's `SIGHUP`. So the shell that runs logrotate in the container also
  sends `SIGHUP` whenever logrotate fails, and that shell outlives the unit (R10). Extra `SIGHUP`s
  are harmless: the engine reopens each log in append mode, so with nothing renamed it just opens
  the same files again. Until round 6 both repairs fired only when `eve.json` was missing, and a
  policy that failed after renaming `stats.log` left it stranded (X1).
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
  alarm is unlikely. Each read has a 10 s limit, and a read that fails or times out counts as
  "not yet" inside the wait, so one slow `docker compose logs` call cannot fail a good update on
  its own (X3). Only a wait that ends on a failed read reports `could not read the engine log`.
- **No rollback.** Once `suricata.rules` is promoted, a failed reload leaves it in place. It
  passed `suricata -T`, which fails on any rule that does not parse, so a failure past the
  promote lies in the reload or the checks around it, not in the rules. The engine keeps running
  the old ruleset, and the new file loads at the next restart. The failed run alerts, so nobody
  restarts into it blind.
- **`--fail`.** Without it, a failed download falls back to the cached archive, rebuilds the same
  rules and exits 0. Every night of a dead feed would look like a good one.
- **The `suricata` user.** Everything the update script runs in the container runs as `suricata`,
  above all `suricata-update`, which unpacks an archive fetched from the internet, and so does the
  rotation's uptime check. Only logrotate and the recovery `SIGHUP` run as container root: the
  image's policy file is readable only by root, and the `SIGHUP` is a fixed `kill -s HUP 1` with
  nothing from the container in it. Since round 6 neither repair reads anything from the
  container before it fires, so the engine's user cannot suppress the signal. It can still cause
  one, by making a run fail, and gains nothing: it can signal its own engine directly, and the
  repair only runs on a run that has already failed, which alerts once the repair returns and the
  unit exits. The policy has no `create`, so root only renames and deletes, and neither follows a
  link. Its postrotate does run `suricatasc` as container root against the engine's
  socket, so root parses a reply the engine's user controls (the threat-model line under Known
  gaps).
- **Every failure exits 1, and the handler catches the rest.** Wazuh rule 40704 (level 5) alerts
  on a failed unit only when the journal says `status=1/FAILURE`. A timeout's 124 or a signal's
  143 lands on level-0 rule 40700 instead, and fails in silence. Both scripts trap `EXIT` and
  leave with 1, and the trap runs without `set -e`, so a failed write to stderr inside it cannot
  change that code. dash dies of an untrapped signal without running the `EXIT` trap, so each
  signal systemd or an operator is likely to send, `HUP`, `INT`, `QUIT`, `TERM`, `USR1`, `USR2`
  and `ALRM`, gets a trap of its own: the previous update script, sent `SIGHUP` mid-build, ended
  `status=1/HUP` and raised nothing in 150 s (G1a), and the round 5 rotation script died of
  `USR1` with 138 (X2). `SIGPIPE` cannot end either script. Both units pin `IgnoreSIGPIPE=yes`,
  and dash can neither trap nor restore a signal ignored on entry, so one that is sent is dropped
  and a write to a closed journal stream fails with `EPIPE` instead: a transient unit that
  trapped `PIPE` and sent itself one ran on and never ran the trap. The rarer ones, `XCPU` or
  `SYS` for example, need a limit or a filter neither unit sets, and the handler below reports
  them anyway. A start timeout sends `SIGTERM`, then `SIGKILL` once `TimeoutStopSec` runs out,
  and a killed script ends `status=9/KILL`, which rule 40704 does not match (T1). The trap
  needs up to 35 s, so both units pin `TimeoutStopSec` at 2 minutes rather than trust the system
  default, 90 s on this box. What no trap can catch, `SIGKILL` or an `ExecStart` that cannot run
  (`203/EXEC`), goes to `OnFailure=soc-recon-unit-failed@%n.service`, which fails on purpose with
  exit 1 and logs the `status=1/FAILURE` line naming the unit (runbook 08 proved both cases raise
  40704 within a second). On 2026-10-02 a start timeout forced on each script in a scratch stack
  ran the trap, ended `status=1/FAILURE`, and raised rule 40704 within 10 s. So did `SIGHUP`,
  `SIGQUIT` (G1a, G1b) and the docker check below.
- **Timeouts inside the container.** Killing the docker CLI does not stop what it started in the
  container, so the build, the socket queries and logrotate each run under `timeout -k` in there.
  Their worst case adds up to about 23 minutes for the update and 5.5 for the rotation, under the
  units' `TimeoutStartSec` of 30 and 8. The log read and the docker calls in the exit trap carry
  a limit on the host. The quick calls, `mktemp`, `find`, `grep` and `mv` on the rules volume,
  carry none. A call that hangs anyway, in the daemon or on the volume, is what `TimeoutStartSec`
  is for: systemd stops the script, and the trap still exits 1. Round 6 tested it against a
  daemon that accepts and never answers (X9, X10), each script run as a transient unit with a
  20 s or 45 s `TimeoutStartSec` rather than through the installed units. Both ended
  `Result=timeout` with `status=1/FAILURE`, the update's after its trap spent 30 s on a stage
  cleanup that could not reach the daemon. The trap's docker calls stop within 35 s, well inside
  the 2-minute `TimeoutStopSec`, and anything that outlasts it anyway ends in `SIGKILL`, which
  the `OnFailure=` handler reports.
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
  session. A failure the script sees raises two alerts, its own `status=1/FAILURE` line and the
  `OnFailure=` handler's; a kill or an exec error raises the handler's alone.
- **A timer that never fires.** `OnFailure=` covers a run that fails, not a run that never
  starts because a timer was disabled or masked. The job age probe below raises rule 100311 at
  level 7 about two hours after a missed daily run. Until it is installed, only
  `systemctl list-timers` shows it.
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
- **Never pipe a hand run.** The unit starts each script with `SIGPIPE` ignored, a terminal does
  not, and neither script traps it. The update writes `promoted <n> rules` to stdout between the
  promote and the reload, so `sudo ... | head` can kill it there without its exit trap: new rules
  on disk, the old ones still loaded, the stage left behind, and no alert. The next timer run
  repairs all three. Redirect to a file instead, as in `> /tmp/upd.log 2>&1`.
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

Round 6 ran on 2026-10-14 against a rebuilt `s03test`, the same way: the round 6 scripts, and as
controls the installed round 5 ones, each retargeted with `sed` and refused if a copy still named
the live project, log path or lock. A control has to fail where the fix passes, so a test that
cannot tell the two apart shows up as a failed control. The first X1 control did pass for the
wrong reason: a `SIGHUP` sent to get `stats.log` back before the run left a reopen pending, and
the engine applied it after the rename. Each X1 run now waits for one write after any `SIGHUP`.
The hung-daemon rows put a `socat` container between the script and the Docker socket and
paused it, so the script saw a daemon that accepted and never answered, while the real daemon
kept serving the live stack.

| Test | Injected | Result |
|---|---|---|
| X1 | a policy that renames `stats.log`, then fails before `eve.json` | exit 1, `SIGHUP` sent, a new `stats.log` within 20 s; the round 5 script left it stranded |
| X2 | `USR1`, `USR2`, `ALRM` to the rotation script before its rename | exit 1 for each; the round 5 script died of `USR1` with 138. The update script's traps are the same lines and were not sent these three |
| X3 | the first engine-log read fails | exit 0, update complete; the round 5 script exited 1, `could not read the engine log` |
| X4 | every engine-log read fails | exit 1 after the full wait, `could not read the engine log` |
| X5 | the build lock held in the container | exit 1 at once, `another build holds the lock, nothing changed` (exit code 200 inside) |
| X6 | stderr on `/dev/full`, project missing, each script | exit 1; the round 5 scripts also exit 1, so `set +e` in the trap guards a case dash already survives |
| X7 | a broken `compose.yml` in the working directory | exit 0, rotated |
| X8 | nothing, round 6 update script | exit 0, 53,154 loaded, no stage left |
| X9 | the daemon hangs before the rotation's first call, `TimeoutStartSec=20s` | `Result=timeout`, `status=1/FAILURE`, nothing renamed |
| X10 | the daemon hangs once the build has started, `TimeoutStartSec=45s` | `Result=timeout`; the trap's stage cleanup timed out after 30 s, `could not remove`, then `status=1/FAILURE`; the builder ran on in the container and left its stage, the case S1 covers |

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

### Job age probe

The units above alert when a run fails. When no run happens, they say nothing. A timer that is
disabled, masked or never loaded, a box that was down at 04:00, and an agent that stopped
forwarding the journal all look like silence. The probe turns that silence into an alert, for
both Suricata timers and runbook 08's retention timer (ISC-48).

It has two halves. The first is a success alert per job. Each script prints one line when its
work succeeded (the update prints it just before its exit trap; see the gaps below). That line
already reaches the manager through agent 002's journald localfile, and three level 3 rules in `deploy/soc-recon/wazuh/custom-rules/local_job_age.xml` now match them:

| Rule | Job | Matches, with the script name as journald tags it |
|---|---|---|
| 100300 | rotation | `rotated: eve.json.1 holds inode <n>, the new eve.json is inode <n>` |
| 100301 | update | `update complete: <n> rules loaded` |
| 100302 | retention | `kept <n> newer dated files; alerts.json in place` |

Each regex is anchored at both ends, so no failure line can match. The scratch logtest ran every
line the three scripts can print, plus near misses and the right phrase under the wrong program
name: the six success lines matched, and none of the other 69 did.

The second half is the probe, `deploy/soc-recon/wazuh/probes/soc-recon-job-age.sh`. The manager's
logcollector runs it as root every hour (a `full_command` localfile in the manager's `ossec.conf`,
alias `soc-recon job age`), and once at boot. It reads the manager's own `logs/alerts` for the
newest success of each job. That means today's `alerts.json` plus any dated
`ossec-alerts-<dd>.json[.gz]` last written inside the 26 h window. It also reads the age of every
regular file below the top of `logs/alerts` and `logs/archives`, whatever its name. Then it
prints one line:

| Line | Rule | Level | Means |
|---|---|---|---|
| `OK rotation=<h>h<mm>m update=... retention=... oldest_dated=<d>d<hh>h` | 100310 | 3 | every job succeeded within 26 h and no dated file is past 16 days. This is the hourly heartbeat |
| `STALE <the same fields> stale=<job>,...` | 100311 | 7 | a job has no success in 26 h (`<job>=none` means none in the files it reads), or a dated file is past 16 days, or there is no dated file at all (`stale=dated`, the last as `oldest_dated=none`). Today's dated name is a hard link to `alerts.json`, so a live manager always has one |
| `ERROR <reason>` | 100311 | 7 | it could not trust what it read: a missing or unreadable tree, a file that will not decompress, a success alert cut short, with a time that is not a real one, or whose two journal times or program disagree with its rule (all three reported as a timestamp that does not parse), a success or a dated file dated after the clock, an `alerts.json` or a tree replaced by a link. Or the run itself failed: it stopped before reporting, ran past 8 s, or was killed |
| anything else | 100311 | 7 | 100311 takes every output that is not exactly the OK line, one newline after the header and at most one after it, no blank line or space around it |
| nothing | none | | logcollector sends no event for an empty output. The probe prints `ERROR` on any exit before its report and on a run past its limit, so only a `SIGKILL` of the probe itself leaves it silent |

The limits and levels are Kyle's (2026-10-16). 26 h after a job's last success alerts about two
hours after one missed daily run. Retention keeps 14 days and the oldest dated file normally
peaks near 14 d 5 h, so 16 days means about two missed retention runs, or a file under a name the
retention pattern does not know. Level 7 sits above 40704's 5, because a job that went silent is
worse than one that failed loudly. Nothing pages, so the level only sets dashboard sort and
filter weight.

Only the three success alerts count, and every other line is another alert, skipped whatever it
holds. A success alert has to be whole: one that does not end with its `location` field is
`cut short`, an `ERROR`. The one exception is the file's last line with no newline yet, which the
manager may still be writing; the next run reads it whole. It has to come from agent 002's
`journald` input. The rules fire for any agent, so a success line forged on another endpoint
still shows as its own 100300 to 100302 alert, but it never makes a job here look fresh.

A job's age runs from the time the job printed its line, the journal's own `predecoder.timestamp`
(`Oct 16 04:31:17`), not from when the manager received it. A line the agent sends again later
keeps its old time and reads old, and a line delivered late still reads from when the job ran.
Both times have to be real ones. gawk's `mktime` would roll 30 February into 2 March and hour 24
into the next day, so each must print back unchanged, and an alert offset past 14:00 is an
`ERROR` too. The journal time is written twice, in `predecoder` and at the start of `full_log`,
and the two must agree, as must `program_name` and the job the rule id names; one damaged field
cannot move a success or hand it to another job.

The probe only reads. It writes no file, makes no network call and touches neither docker nor a
secret. Reading does update the access time of the files it reads, as every reader of them does
(the logs volume is `relatime`); nothing on the manager keys on access time. It finished in 0.5 s on a 69 MB `alerts.json` on the scratch stack. The whole run has an
8 s limit: the probe starts itself again under `timeout`, which signals the run's whole process
group, so a hung read ends in `ERROR the probe ran past 8 s` with no reader left behind (one
stuck inside the kernel is the exception; see the gaps). Run it by its path. Piped into `bash -s`, it cannot find itself and says `ERROR`.

The probe's own record is `rule.id` 100310 or 100311, one document an hour:

```bash
cd ~/talonsoclab/deploy/soc-recon
q='{"size":30,"sort":[{"timestamp":"desc"}],"_source":["timestamp","rule.id","full_log"],
  "query":{"bool":{"filter":[{"terms":{"rule.id":["100310","100311"]}},
  {"range":{"timestamp":{"gte":"now-1d"}}}]}}}'
bin/idx '/wazuh-alerts-*/_search' -d "$q" |
  jq -r '.hits.hits[]._source | "\(.timestamp) \(.rule.id) \(.full_log | split("\n") | last)"'
```

**Install.** The probe, its rules and the localfile ride `/wazuh-config-mount`, so they apply only
on a new container (section 3). No sudo. A recreate also copies every other config-mount file,
so check first what else it would change. The loop is one line in single quotes, so every `$`
expands inside the container and a paste cannot split it:

```bash
cd ~/talonsoclab/deploy/soc-recon
git pull --ff-only
docker compose exec -T wazuh.manager bash -c 'cd /wazuh-config-mount && find . -type f | sort | while read -r f; do t=/var/ossec/${f#./}; if [ ! -e "$t" ]; then echo "new  $f"; elif [ "$(md5sum <"$f")" != "$(md5sum <"$t")" ]; then echo "diff $f"; fi; done'
docker compose exec -T wazuh.manager cat /var/ossec/etc/ossec.conf | diff - config/wazuh_cluster/wazuh_manager.conf
docker compose up -d --force-recreate wazuh.manager
docker compose logs --since 3m wazuh.manager | grep -E "Identified Wazuh|cont-init.d\] 0-wazuh-init|probes"
docker compose exec -T wazuh.manager stat -c '%U:%G %a %n' /var/ossec/etc/probes/soc-recon-job-age.sh
docker compose exec -T wazuh.manager grep 'soc-recon-job-age' /var/ossec/logs/ossec.log
```

The loop runs inside the running container, so it has two blind spots. It sees only the mounts
that container started with, so a route the compose file adds (here `etc/probes`) is missing
until the recreate; read the compose diff for those. And a single-file bind keeps the file it
started with, because git replaces a file rather than rewriting it, so `ossec.conf` shows no
change after a pull; the host-side `diff` line covers it. On 2026-10-16, before this install,
the loop listed `new ./etc/rules/custom/local_job_age.xml` and `diff ./etc/shared/README.md`,
and the host `diff` showed only the new `<localfile>` block.

After the recreate, the boot log needs `Identified Wazuh configuration files to mount...`, a
`'/wazuh-config-mount/etc/probes/soc-recon-job-age.sh' -> '/var/ossec/etc/probes/soc-recon-job-age.sh'`
line and `0-wazuh-init: exited 0`. The probe should be `root:root 755`: the init copies it as
root under umask 022, so the checkout's 775 lands as 755. `ossec.log` should show
`Monitoring full output of command(3600): /var/ossec/etc/probes/soc-recon-job-age.sh`.

The first line after an install is `STALE rotation=none update=none retention=none`, as a level 7
100311 within a minute of the boot. That is correct, not a fault. The day's runs printed their
success lines before these rules existed, so no success alert exists yet, and that first alert is
the live proof of the STALE path. The first 100310 comes at the first hourly run after all three
jobs have run under the new rules: after the next 05:00 UTC retention run, or after a hand run of
all three units.

**How it was proven.** A scratch manager on the box (`Plans/isc48-tests/`, project `isc48test`,
its own network and volumes, the live image) booted with the same mounts. Its boot log copied the
probe in (`root:root 755` from a 775 source), and its logcollector ran the probe 15 s after boot,
raising a real 100311. Three success alerts and a logcollector restart then gave a real 100310,
and a success with a broken timestamp gave a real `ERROR`. Each output shape went through the
manager's logtest: 23 shapes reached 100310 or 100311 as they should, and two other localfiles
reached neither. 58 planted trees ran the probe, among them all fresh, one job 27 h old, one job
with no success, the successes only in yesterday's `.json.gz`, a 17-day file under an unknown
name, no dated file at all, a tree that is unreadable, missing or corrupted, a success cut short,
impossible times and offsets, a success sent again or delayed, one from another agent or input,
one whose two journal times or whose program disagree, an `alerts.json` or a tree replaced by a
link, an `alerts.json` that is a FIFO, a dated file ahead of the clock, and both limits
approached from either side. Each compared the tree before and after the run. A probe made to
hang ended at 8 s, and one that also ignored `SIGTERM` at 9 s, both with `ERROR` and nothing left
running. A targeted mutation set on the STALE and ERROR branches checked that the cases catch
what they claim (see `Plans/isc48-tests/RESULTS.md`).

**The probe's own gaps.**

- **A probe that never runs, or prints nothing, raises nothing.** Only the missing hourly
  100310 or 100311 document shows it. A manager that is down shows in every other panel first.
- **The journal time has no year and no zone.** The probe takes the alert's year, or the year
  before when that would land more than 5 minutes after the alert arrived, and reads the time
  as UTC, the box's zone. A box set to another zone shifts every age: west of UTC every job
  reads older and goes STALE early; east of it every journal time lands after its alert, so it
  falls back a year and reads STALE too. The same 5 minutes is the clock skew allowed between
  the agent and the manager, which share the box's clock today. A line replayed from the same
  month and day of an earlier year would read fresh. That needs the agent to re-read a journal
  more than a year old; the box's journal starts 2026-07-11, so not before 2027-07-11, and
  `MaxRetentionSec=` under a year in `journald.conf` would rule it out for good.
- **A success line can be forged on the box.** Anything that can write the host's journal under
  a script's name raises the success alert, for example `logger -t soc-recon-suricata-update.sh
  'update complete: 1 rules loaded'`, and keeps the probe quiet for 26 h. The journal records
  the real unit in `_SYSTEMD_UNIT`, but the agent's journald reader does not forward it. It
  takes a login on the box, which today means talon, whose docker group is root already. The
  same line on another endpoint changes nothing here.
- **A success alert is checked at its edges, not in full.** The probe has no JSON parser. It
  checks the start of the line, its agent, its journal time and its end. A line garbled in
  between could still count, but an appended write does not garble a middle; only something
  that can write `alerts.json` can, and it could write a valid line as easily.
- **The agent id is fixed.** A box enrolled again gets a new id, and every job reads `none`,
  STALE every hour, until `AGENT` in the probe follows it.
- **The update's line prints before its exit trap.** A run whose stage cleanup then fails exits 1
  and raises 40704, and still counts as a success here. The rules did update.
- **A run that races the midnight rotation can say ERROR once.** The manager compresses
  yesterday's file at 00:00 UTC, and a file listed before that can be gone by the time it is read.
  The next hour's run passes.
- **Root ignores file modes.** On the live manager, "unreadable" means an I/O error, a missing
  file or the wrong file type, never a mode. The suite drops root's read override in one
  container to test the mode case anyway.
- **The clock is trusted.** A success dated more than 5 minutes ahead of the clock is an `ERROR`,
  but a clock that runs slow is not detected. A clock stepped back more than 5 minutes, say by
  a large NTP correction at boot, leaves the newest success, and any dated file written inside
  the step, ahead of it: an hourly `ERROR` until the clock catches up, at most the size of the
  step.
- **A read stuck inside the kernel outlives the limit.** A process in uninterruptible I/O ignores
  even `SIGKILL`, and `timeout` waits for it. The hourly document then goes missing, as in the
  first gap.
- **The probe knows the manager's alert line and file names.** It reads a success only from a
  line that starts with `timestamp`, then `rule` with `level`, `description` and `id` in that
  order, carries `predecoder` with `program_name` then `timestamp`, and ends with `location`. A
  manager upgrade that moves those keys turns every job to `none` and STALE, or, if the line
  stops ending with `location`, every hour to `ERROR ... cut short`. It reads only the dated
  names `ossec-alerts-<dd>.json[.gz]`; size rotation (`ossec-alerts-<dd>-001.json.gz`) is off
  here. A renamed dated file hides yesterday's successes, so the line is STALE from 00:00 UTC
  until each job runs again. It also needs `full_log` to open with the journal time, and its
  three script names to match the rules' `program_name`s; a manager that changes the first, or a
  script renamed in the rules but not in the probe, gives `ERROR ... does not parse` every hour.
  Each case is loud, not silent.
- **The success rules must stay at level 3 or above.** The manager writes `alerts.json` from
  `log_alert_level` 3, and the probe reads its successes from there. Renumber a rule, or lower it
  below 3, and its job reads `none`, then STALE.

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

### Revision 2026-10-14 (round 6)

- [x] Scratch suite on the round 6 scripts: the ten X rows above, 20 cases in all. X1 to X3 have
      controls that fail where the fix passes; X6's controls pass as well, and the rest have none
      *(run on sha256 a3518ccf and d156d9d0; the shipped e7d777f5 and d21dfe26 differ from them
      in comment lines only, and the comment-stripped files are byte-identical)*
- [x] Round 6 scripts and units installed root-owned and byte-equal to the repo; `OnFailure`
      names `soc-recon-unit-failed@%n.service` and `IgnoreSIGPIPE` is `yes` on both services;
      `systemd-analyze verify` rc 0 and silent about both units (it still warns about stock
      `xfs_scrub` units) *(installed 2026-10-14 about 07:00Z from f679926: scripts e7d777f5
      and d21dfe26 at 755, units 0cdc82e6 and a829f8dd at 644, all root:root and equal to the
      repo; both services show their own `soc-recon-unit-failed@<unit>.service`)*
- [x] Rotation anti-test on the installed units, with the section 6 query: the rotation ended
      `Result=exit-code` and `ExecMainStatus=1` with `engine not answering, nothing rotated`, the
      handler logged its own `status=1/FAILURE` line, and the query returned 2 *(2026-10-14
      07:03:36 UTC; the sensor came back healthy and `eve.json` was growing again within 3 min)*
- [x] First scheduled runs after the install confirmed from the journal: the rotation's
      `rotated:` line and the update's `engine swapped` line, no rule 40704 *(2026-10-15: the
      rotation moved the old inode to `eve.json.1` at 04:00:23 UTC; the update promoted 53,158
      rules and swapped the engine at 04:30:56, `last_reload` 2026-10-14T07:04:06 to
      2026-10-15T04:30:55, 53,158 loaded and 0 failed. No handler instance started, and rule
      40704 counted 0 since 03:55 UTC for both units and overall, with the 2026-10-14 anti-test
      window still returning its alert as a control)*

### Revision 2026-10-16 (ISC-48 job age probe)

- [x] Scratch proof on `isc48test`: `mount_files` copies the new `etc/probes` folder, the probe
      lands `root:root 755` from a 775 source, and the logcollector runs it at boot; logtest on
      every line the three scripts print (75 lines) and on 25 probe output shapes; 58 planted
      trees, a timed day-sized tree, two hung runs cut at the 8 s limit and 3 real-pipeline runs;
      targeted mutants of the STALE and ERROR branches, all caught *(Plans/isc48-tests/RESULTS.md)*
- [x] Two-leg delta audit on the pinned final tree, no unaddressed High or Medium *(2026-10-16:
      six rounds; on the final pin Max READY, and codex's last High and Medium fall under Kyle's
      rulings: whole-record JSON validation is a standing dispute, and access-time updates on read
      are documented above)*
- [ ] Installed by one force-recreate: the boot log copies the probe and ends
      `0-wazuh-init: exited 0`, the probe is `root:root 755`, and the first probe alert reaches
      the indexer within 65 min
- [ ] First 100310 heartbeat in the indexer after all three jobs have run under the new rules,
      and one each of 100300, 100301 and 100302 from the scheduled runs
