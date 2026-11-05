# Suricata IDS on the host NIC + the SOC Overview dashboard

> Condensed public version. The full build log with dated evidence stays private, and the acceptance list is consolidated from 29 items to 23.

> **What this does:** stands up Suricata 8.0.7 as a container on the SOC host's physical NIC
> (`eno1`), feeds its `eve.json` into Wazuh through the existing `phase-a-linux` agent, tunes the
> local L2 noise floor out of the indexer, and builds the dashboard Phase A ships as its
> deliverable.
>
> **Completed 2026-08-09.** Closes ISC-26 and ISC-27, the last two Phase A build criteria.
>
> **Why it matters for a SOC:** the endpoint agents see the hosts; Suricata sees the *wire*. Its
> alerts land beside Sysmon and auditd, so one query shows host and network evidence together.
>
> **The load-bearing lesson is section 3:** a Wazuh manager restart does NOT apply git-shipped
> configuration, and nothing says so. Read it before changing anything under
> `deploy/soc-recon/wazuh/`.
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

Suricata runs with `network_mode: host` so the name in `SURICATA_IFACE` resolves to the same
interface `ip -br link` shows. Point it at a docker bridge and the sensor comes up **healthy and
blind**: it captures the bridge, sees nothing real, and reports no error.

## 1. Fetch the ET Open ruleset — [BOX]

The image ships **zero** signatures. Suricata with no rules starts cleanly, logs flows all day,
and never alerts.

```bash
docker compose run --rm suricata suricata-update
```

Expect `Loaded <n> rules` and an `enabled:` count, written to
`/var/lib/suricata/rules/suricata.rules`, then `Testing with suricata -T`. The trailing
`Reload command failed: ... suricata-command.socket: No such file or directory` is **expected and
harmless**: nothing is running yet. The rules persist in the `suricata_rules` named volume.

This is the only manual fetch. From here on the `soc-recon-suricata-update` timer (section 6)
re-runs it daily and live-reloads the engine.

## 2. Start the sensor — [BOX]

```bash
docker compose up -d suricata
docker compose ps suricata                    # want: Up (healthy)
docker compose logs suricata | head -5
```

The startup log must show `Checking for capability sys_nice: yes` and `net_admin: yes`. If
either says `no`, the entrypoint **silently drops its `--user`/`--group` arguments and runs
Suricata as root**, and that line is the only place it shows.

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
> **Why.** The init script (`/etc/cont-init.d/0-wazuh-init`) restores any empty
> `PERMANENT_DATA` path from `/var/ossec/data_tmp`, then deletes that backup after its first run.
> A restarted container keeps its filesystem, so on the next init the still-empty
> `/var/ossec/var/multigroups` has no restore source, and the script exits **before
> `mount_files` copies `/wazuh-config-mount` into `/var/ossec`**. s6 logs
> `0-wazuh-init: exited 1` and starts the daemons anyway: the manager is Up, every agent stays
> Active, and it runs the old configuration.
>
> **Always verify the copy landed rather than trusting the restart:**
> ```bash
> docker compose logs --since 3m wazuh.manager | grep -E "Identified Wazuh|cont-init.d\] 0-wazuh-init"
> ```
> Want `Identified Wazuh configuration files to mount...`, the per-file `'/wazuh-config-mount/...' -> '/var/ossec/...'`
> lines, and `0-wazuh-init: exited 0`. An `exited 1` means nothing was applied.

Then prove delivery, not staging: the manager's `merged.mg` md5 must match the hash the agent
reports.

```bash
docker compose exec -T wazuh.manager md5sum /var/ossec/etc/shared/phase-a-linux/merged.mg
docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -i 002 | grep "Shared file hash"
```

## 4. Prove the alert path with a positive control — [BOX]

**"Suricata is running" is not acceptance.** Only `event_type: alert` reaches the indexer: rule
`86601` is level 3, while `86602`/`86603`/`86604` (http/dns/tls) are **level 0** and dropped at
`log_alert_level 3`. A sensor logging flows all day produces zero indexer documents, the same
trap ISC-23.5 hit with Sysmon Event ID 3.

Trigger a real ET Open signature. Sid 2100498 (`GPL ATTACK_RESPONSE id check returned root`)
matches `uid=0(root)` in any IP payload. One UDP datagram to `192.0.2.1`, a TEST-NET-1
documentation address (RFC 5737), puts it on the wire through `eno1` with nothing outside the box
involved. `/dev/udp/` is a bash feature, so run this from bash:

```bash
printf 'uid=0(root) gid=0(root) groups=0(root)\n' > /dev/udp/192.0.2.1/9
grep "id check returned root" /var/log/suricata/fast.log | tail -1
```

Then confirm it reached the indexer, which proves capture, ruleset, eve.json, group config, agent
tail, decoder, level floor and filebeat at once:

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
with an ethertype Suricata doesn't parse: here the managed switch's Realtek RRCP (`0x8899`) and
the router's LLDP/IEEE-1905 chatter, about 95k alerts a day.

`wazuh/custom-rules/local_suricata_tuning.xml` scores it level 0 at the **manager**, so every
frame stays in `eve.json` on disk and only the indexer write stops. Disabling it in
`disable.conf` would erase the record too. It also needs this easily missed line, because
`rule_dir` is **not recursive** and without it `analysisd` silently ignores the mounted rules:

```xml
<rule_dir>etc/rules/custom</rule_dir>     <!-- in config/wazuh_cluster/wazuh_manager.conf -->
```

**(b) `ERROR: Too many fields for JSON decoder`.** Suricata's `stats` records carry several
hundred counters, past Wazuh's JSON-decoder field limit. The compose `--set` drops **only** stats
from the eve output, and `stats.log` still reports `capture.kernel_drops`.

> **`types.32` is a list index, not a name.** It is coupled to the pinned image tag. After any
> `SURICATA_VERSION` bump, re-derive it and confirm:
> ```bash
> docker run --rm --entrypoint /usr/bin/suricata jasonish/suricata:<ver> \
>   --set outputs.1.eve-log.types.32.stats.enabled=no --dump-config | grep types.32
> ```
> A wrong index silently sets the option on a different output type. On 8.0.7 it is `stats`.

Verify both by measurement. Record a count, wait, record it again:

```bash
grep -c '"event_type":"stats"' /var/log/suricata/eve.json          # must stop increasing
docker compose logs --since 2m wazuh.manager | grep -c "Too many fields"   # must be 0
```

## 6. Log rotation — [BOX]

The image ships `/etc/logrotate.d/suricata` (daily, 3 rotations) and **nothing ever runs it**,
while the logs grow about 240 MB a day. On AlmaLinux 9 logrotate ships only a systemd timer,
systemd is never PID 1 in the container, and `/etc/cron.daily/` is empty. So
**`ENABLE_CRON=yes` on its own rotates nothing**: it supplies a scheduler, not a job.

### The first fix never ran

Compose once paired `ENABLE_CRON=yes` with a cron entry bind-mounted into `/etc/cron.d`. It never
ran: the bind mount kept the host file's owner and mode, and cronie silently skips an
`/etc/cron.d` file not owned by root or writable by group or others. The prescribed check,
`ps ax | grep crond`, passed throughout, because a running scheduler says nothing about whether
it loaded the job.

### The fix: host systemd timers

On the host a failed run shows in `systemctl --failed`, the journal, and through the host's
Wazuh agent. `deploy/soc-recon/systemd/` holds the two oneshot services, their timers and
scripts, runbook 08's retention unit, and the `OnFailure=` handler,
`soc-recon-unit-failed@.service`.

| Unit | Daily at (UTC) | Script | What it does |
|---|---|---|---|
| `soc-recon-suricata-logrotate` | 04:00 | `soc-recon-suricata-logrotate.sh` | runs the image's own `/etc/logrotate.d/suricata` inside the container, then proves the engine reopened `eve.json` |
| `soc-recon-suricata-update` | 04:30 | `soc-recon-suricata-update.sh` | tests the new ruleset in a stage, promotes it, reloads, then proves the engine swapped |

Install them as root-owned copies, not links into the checkout, so a `git pull` never changes
what root runs without an install step:

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

Both name `soc-recon-unit-failed@%n.service`, which runbook 08 installs and drills (its step 1).
`show` prints the name even if the file is missing, so run that drill on a fresh box. `LAST`
reads `-` after a reboot: the timers set no `Persistent=`, as a catch-up run at boot would beat
the container up.

`list-timers` proves the schedule, not the job. Run each service once by hand. A hand rotation
costs one generation of retention, so the rotation can wait for its first scheduled run instead:

```bash
sudo systemctl start soc-recon-suricata-update.service
journalctl -u soc-recon-suricata-update.service -n 40 --no-pager
sudo systemctl start soc-recon-suricata-logrotate.service
journalctl -u soc-recon-suricata-logrotate.service -n 5 --no-pager    # the "rotated:" line
```

`systemctl show` is no evidence: it prints `Result=success` for a unit that never ran. Want
fresh `Starting` and `Finished` journal lines around the script's own: `promoted <n> rules`,
`engine swapped: last_reload <before> -> <after>` and `update complete: <n> rules loaded`, or
`rotated: eve.json.1 holds inode <old>, the new eve.json is inode <new>`. Then rerun the section
4 positive control. After a rotation, `eve.json`, `fast.log` and `stats.log` grow on new inodes,
and only that alert proves the agent re-followed `eve.json`: the L2 noise is level 0 (rule
100200), so a static indexer count proves nothing.

Then the anti-tests. With the engine stopped, the rotation must fail and reach Wazuh, at about a
minute of sensor downtime. Use `stop` and `start`, not `up`, and never `docker kill`, which Docker
handles as a stop that cancels the restart policy:

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

Two, because the `OnFailure=` handler logs its own `status=1/FAILURE` line. Then the update's
floor must fail closed before anything goes live (about 40 s):

```bash
sudo env MIN_RULES=999999 /usr/local/sbin/soc-recon-suricata-update.sh; echo "rc=$?"
# want rc=1 and "only <n> rules staged, the floor is 999999; live rules untouched"
```

A hand run needs `sudo`, because the lock lives in `/run`. The unit unsets `MIN_RULES`, so the
timer's floor cannot be lowered. Every rotation is forced, and `rotate 3` deletes anything pushed
past `.3`, so copy out of `/var/log/suricata/` whatever is worth keeping.

### Why the scripts look the way they do

Every check exists because a wrapped tool can report success when nothing succeeded:
`reopen-log-files` and `reload-rules` reply OK either way, and `suricata-update` exits 0 after a
failed reload or download. So the rotation proves the reopen on disk by inode, and the update
proves the swap by the engine's own `last_reload` and console log. The update tests the new
ruleset in a stage, checks a 40,000-rule floor (`MIN_RULES`) before the promote and after the
reload, and changes the live ruleset in one rename. Every failure exits 1, because Wazuh rule
40704 matches only `status=1/FAILURE`, and the `OnFailure=` handler reports what no trap can
catch. Each script checks `docker.service` itself, because `Requisite=` would skip the run with
nothing for Wazuh to see.

### Known gaps

- **Nothing pages.** A failed run raises level 5 rule 40704 and nobody is told. Check at the
  start of a session.
- **A killed update leaves its builder running** in the container until its 900 s limit. It
  holds the build lock and never touches the live rules, so a run meanwhile fails and alerts.
- **The log directory must stay `755`**, or logrotate refuses it.
- **The log directory belongs to the engine's uid.** Whoever holds it can plant a decoy
  `eve.json` or forge the replies the scripts trust. This is a threat-model line, not fixed here.
- **Never pipe a hand run.** `sudo ... | head` can kill the update between the promote and the
  reload with no alert. Redirect to a file instead, as in `> /tmp/upd.log 2>&1`.
- **A version bump never refreshes `/etc/suricata`.** It is an image volume. Diff it on every
  bump; `docker compose up -d -V` renews it and keeps the named rules volume.

### Job age probe

The units alert when a run fails, not when no run happens: a disabled timer, a box down at
04:00, or an agent that stopped forwarding the journal all look like silence. This probe turns
that silence into an alert, for both Suricata timers and runbook 08's retention timer (ISC-48).

Each script prints one success line, which reaches the manager through agent 002's journald
localfile. Three level 3 rules in `deploy/soc-recon/wazuh/custom-rules/local_job_age.xml`, each
anchored at both ends, match them:

| Rule | Job | Matches, with the script name as journald tags it |
|---|---|---|
| 100300 | rotation | `rotated: eve.json.1 holds inode <n>, the new eve.json is inode <n>` |
| 100301 | update | `update complete: <n> rules loaded` |
| 100302 | retention | `kept <n> newer dated files; alerts.json in place` |

The probe, `deploy/soc-recon/wazuh/probes/soc-recon-job-age.sh`, runs as root at boot and hourly
from the manager's logcollector (a `full_command` localfile, alias `soc-recon job age`). It finds
each job's newest success in the manager's `logs/alerts`, checks the age of the dated files under
`logs/alerts` and `logs/archives`, and prints one line:

| Line | Rule | Level | Means |
|---|---|---|---|
| `OK rotation=<h>h<mm>m update=... retention=... oldest_dated=<d>d<hh>h` | 100310 | 3 | every job succeeded within 26 h and no dated file is past 16 days |
| `STALE <the same fields> stale=<job>,...` | 100311 | 7 | a job has no success in 26 h, a dated file is past 16 days, or there is none |
| `ERROR <reason>` | 100311 | 7 | it could not trust what it read, or it failed or ran past 8 s |
| anything else | 100311 | 7 | every output that is not exactly the OK line |

26 h alerts about two hours after one missed daily run, and 16 days means about two missed
retention runs. Level 7 outranks 40704's 5: a job gone silent is worse than one that failed
loudly. Only agent 002's `journald` successes count, aged from the journal time. The probe only
reads. Run it by its path; piped into `bash -s` it says `ERROR`.

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

The loop sees only the running container's mounts, so read the compose diff for new ones such as
`etc/probes`. The host-side `diff` covers `ossec.conf`, a single-file bind that keeps its old copy
after a pull. After the recreate, the boot log needs the probe's copy line and
`0-wazuh-init: exited 0`, the probe should be `root:root 755`, and `ossec.log` should show
`Monitoring full output of command(3600): /var/ossec/etc/probes/soc-recon-job-age.sh`.

The first alert is `STALE rotation=none update=none retention=none` (100311, level 7), and that
is correct: no success alert exists yet. The first 100310 follows once all three jobs have run.

**The probe's own gaps.**

- **A probe that never runs raises nothing**; only the missing hourly document shows it.
- **Journal times are read as UTC**, the box's zone; another zone shifts every age.
- **A success line can be forged** by a login on the box that writes the journal under a
  script's name. The login user's docker group is root already.
- **It assumes the agent id, the alert format and success rules at level 3 or above.** Break
  one and it goes STALE or ERROR, loud rather than silent.

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
> Dashboards stores `wazuh-alerts-*`'s field list as a **cached snapshot**, so a field that
> appears later (`data.alert.*`) is absent, and the panel renders
> `Could not locate that index-pattern-field (id: data.alert.signature)` **even though the data
> is queryable**. The import reports success either way.
>
> Fix: Dashboards → Stack Management → Index patterns → `wazuh-alerts-*` → the refresh button;
> or `PUT /api/saved_objects/index-pattern/wazuh-alerts-*` with the `fields` array from
> `GET /api/index_patterns/_fields_for_wildcard?pattern=wazuh-alerts-*`. The committed ndjson
> deliberately **excludes** the index-pattern object, a stale-on-arrival field cache.

**Data-table gotcha:** columns order by agg **id**, not array position, so both tables give the
bucket agg id `1`, the metric id `2`, and point each terms agg's `orderBy` at `2`.

## Acceptance

- [x] Suricata `Up (healthy)` on `eno1` (8.0.6, then 8.0.7), 0 rules failed, `sys_nice: yes`
- [x] `eve.json` on the host carries `in_iface: eno1` and multiple event types
- [x] `merged.mg` md5 on the manager matches agent 002's reported *Shared file hash*
- [x] Positive control sid 2100498 queryable in `wazuh-alerts-*` as `rule.id 86601`, level 3
- [x] Ethertype documents frozen over 120 s of live traffic while a repeat positive control landed
- [x] `Too many fields for JSON decoder` errors at 0, still 0 after `types.32` was re-derived
- [x] `crond` running, policy parses. Superseded: the job never loaded (section 6)
- [x] All five dashboard panels render live data, verified in real Chrome, not by import status
- [x] Staged update by hand: `suricata -T` passed on the stage, `last_reload` moved, 0 failed
- [x] Floor anti-test: `MIN_RULES=999999` exits 1 before the promote, live rules unchanged
- [x] Hand rotation: `eve.json.1` took the old inode; `eve.json`, `fast.log`, `stats.log` reopened
- [x] Positive control indexed after each rotation, the rule reload and the staged update
- [x] The update fits `mem_limit: 2g` with a reloaded engine: no swap, no `oom` events
- [x] Failure paths proven on a scratch sensor: each ends `status=1/FAILURE`, rule 40704
- [x] Units pass `systemd-analyze verify`; calendars resolve to the next 04:00 and 04:30 UTC
- [x] Scripts and units root-owned, byte-equal to the repo, `OnFailure` and `IgnoreSIGPIPE=yes` set
- [x] The update as a root system unit: `engine swapped`, 0 failed, host lock `root:root 600`
- [x] Anti-test on the installed units: `Result=exit-code`, and the section 6 query returns 2
- [x] First scheduled runs confirmed from the journal: `rotated:` and `engine swapped`, no 40704
- [x] Probe proven on a scratch manager: logtest on every line and shape, hung runs cut at 8 s
- [x] Two-leg delta audit on the final tree, no unaddressed High or Medium
- [x] Probe installed by one force-recreate: `exited 0`, `root:root 755`, first alert within 65 min
- [x] First 100310 heartbeat after all three jobs ran, and one each of 100300, 100301 and 100302
