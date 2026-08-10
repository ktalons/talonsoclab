# Suricata IDS on the host NIC + the SOC Overview dashboard

> **What this does:** stands up Suricata 8.0.6 as a container on the SOC host's physical NIC
> (`eno1`), feeds its `eve.json` into Wazuh through the existing `phase-a-linux` agent, tunes the
> local L2 noise floor out of the indexer, and builds the custom dashboard that Phase A ships as
> its deliverable.
>
> **Completed 2026-08-09.** Closes ISC-26 and ISC-27 — the last two Phase A build criteria.
>
> **Why it matters for a SOC:** the three endpoint agents see what happens *on hosts*. Nothing
> until now saw what happens *on the wire*. Suricata is the network-visibility half, and its
> alerts land in the same indexer as Sysmon and auditd, so one query surfaces host and network
> evidence for the same event.
>
> **The load-bearing lesson in this runbook is section 3.** A Wazuh manager restart does NOT
> apply git-shipped configuration. It looks like it does — the container reports Up, all ten
> daemons run, every agent stays Active — and the config silently never lands. Read it before
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
free -h                          # Suricata adds ~1.5 GB to the always-on ceiling
```

The interface name matters more than it looks. Suricata runs with `network_mode: host`
specifically so the name in `SURICATA_IFACE` resolves to the same interface `ip -br link` shows.
Point it at a docker bridge and the sensor comes up **healthy and blind** — it captures the
bridge, sees nothing real, and reports no error.

## 1. Fetch the ET Open ruleset — [BOX]

The image ships **zero** signatures. This is the single most important step to not skip:
Suricata with no rules starts cleanly, writes flow/dns/tls records all day, and never alerts.
Green and blind.

```bash
docker compose run --rm suricata suricata-update
```

Expect `Loaded 68186 rules`, `enabled: 52245`, written to `/var/lib/suricata/rules/suricata.rules`,
then `Testing with suricata -T`. The trailing
`Reload command failed: ... suricata-command.socket: No such file or directory` is **expected and
harmless** — nothing is running yet, so there is no socket to reload. The rules persist in the
`suricata_rules` named volume.

## 2. Start the sensor — [BOX]

```bash
docker compose up -d suricata
docker compose ps suricata                    # want: Up (healthy)
docker compose logs suricata | head -5
```

The startup log must show `Checking for capability sys_nice: yes` and `net_admin: yes`. If
either says `no`, the entrypoint **silently drops its `--user`/`--group` arguments and runs
Suricata as root** rather than failing — the container still works, so the only place this shows
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
> order: `mount_permanent_data` first, `mount_files` — the step that copies
> `/wazuh-config-mount` into `/var/ossec` — much later. `mount_permanent_data` walks the
> `PERMANENT_DATA` list, and for any path that is **empty** it restores a baked-in backup from
> `/var/ossec/data_tmp`. `main()` deletes `data_tmp` at the end of its first successful run, and
> a container's filesystem survives `restart`/`stop`+`start`. So on every subsequent init:
> `/var/ossec/var/multigroups` is still empty (it only fills when an agent belongs to 2+ groups,
> and none here do), the restore source is gone, `cp` fails, and the script's
> `error_and_exit` kills it **before `mount_files` ever runs**.
>
> s6 logs `0-wazuh-init: exited 1` and starts the daemons anyway. The result is a manager that
> is Up, has all ten daemons running, keeps every agent Active — and is running last month's
> configuration. There is no error anywhere that says so.
>
> **Always verify the copy landed rather than trusting the restart:**
> ```bash
> docker compose logs --since 3m wazuh.manager | grep -E "Identified Wazuh|cont-init.d\] 0-wazuh-init"
> ```
> Want `Identified Wazuh configuration files to mount...`, the per-file `'/wazuh-config-mount/...' -> '/var/ossec/...'`
> lines, and `0-wazuh-init: exited 0`. An `exited 1` means nothing was applied.

Then confirm the group config actually reached the agent — compare the manager's `merged.mg`
hash against what the agent reports, which is the only check that proves delivery rather than
staging:

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
ID 3 — the observation channel has to be checked before a criterion is bound to it.

Trigger a real ET Open signature:

```bash
curl -s http://testmynids.org/uid/index.html      # returns: uid=0(root) gid=0(root) groups=0(root)
grep "id check returned root" /var/log/suricata/fast.log | tail -1
```

Then confirm it reached the indexer (this is the collapsing probe — it cannot be true unless
capture, ruleset, eve.json, group config, agent tail, decoder, level floor and filebeat are all
simultaneously correct):

```bash
PASS=$(grep -E '^WAZUH_INDEXER_PASS=' .env | cut -d= -f2-)
docker compose exec -T -e P="$PASS" wazuh.indexer sh -c \
  'curl -sk -u "admin:$P" -H "Content-Type: application/json" \
   "https://localhost:9200/wazuh-alerts-*/_search?size=1" \
   -d "{\"query\":{\"term\":{\"data.alert.signature_id\":\"2100498\"}}}"'
```

> **Field-name note:** Wazuh decodes eve.json with its generic JSON decoder, so the fields are
> `data.alert.signature`, `data.src_ip`, `data.in_iface` — **not** `data.suricata.*`. That prefix
> belongs to Elastic's Filebeat Suricata module, which this stack does not use.

## 5. Tune the local noise floor — [BOX]

Two problems show up within minutes of a live sensor, and both are fixed in git.

**(a) Decoder-event flood.** `SURICATA Ethertype unknown` (sid 2200121) fires on every L2 frame
carrying an ethertype Suricata doesn't parse. On this LAN that is the TL-SG108E smart switch
broadcasting Realtek RRCP (`0x8899`) plus the router's LLDP/IEEE-1905 chatter — measured at
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
without that explicit entry every rule in it is silently ignored — the mount exists, the XML is
on disk, `analysisd` never reads it, nothing reports a problem.

**(b) `ERROR: Too many fields for JSON decoder`.** Suricata's `stats` records carry several
hundred counters and blow through Wazuh's JSON-decoder field-count ceiling — one every 8 seconds,
~10k error lines/day, burying any real decoder error. The compose `--set` drops **only** stats
from the eve output; global `stats.enabled` stays on, so `stats.log` still answers "is the sensor
dropping packets?" via `capture.kernel_drops`.

> **`types.32` is a list index, not a name** — it is coupled to the pinned image tag. After any
> `SURICATA_VERSION` bump, re-derive it and confirm:
> ```bash
> docker run --rm --entrypoint /usr/bin/suricata jasonish/suricata:<ver> \
>   --set outputs.1.eve-log.types.32.stats.enabled=no --dump-config | grep types.32
> ```
> A wrong index silently sets the option on a different output type and the errors keep coming.

Verify both, by measurement rather than inspection — record a count, wait, record it again:

```bash
grep -c '"event_type":"stats"' /var/log/suricata/eve.json          # must stop increasing
docker compose logs --since 2m wazuh.manager | grep -c "Too many fields"   # must be 0
```

## 6. Log rotation — [BOX]

The image ships `/etc/logrotate.d/suricata` (daily, 3 rotations) and **nothing ever runs it**,
while the logs grow ~240 MB/day against a 256 GB NVMe. This is not a mistake by anyone — it is
the standard container seam, and it is worth understanding rather than pattern-matching to
"misconfigured". Verified against a pristine container 2026-08-09:

| Link in the chain | State in the image |
|---|---|
| `/etc/logrotate.d/suricata` | present — and **owned by no RPM**, so the image author added it, not the distro |
| what normally executes it on AlmaLinux 9 | `logrotate.timer` + `logrotate.service` — the logrotate RPM ships **only** systemd units, no `/etc/cron.daily/logrotate` |
| systemd in the container | binary present (`/sbin/init -> systemd`) but **never PID 1** — the entrypoint execs suricata, so the timer is never loaded |
| `/etc/cron.d/0hourly` | present → `run-parts /etc/cron.hourly` |
| `/etc/cron.hourly/0anacron` | present, `cronie-anacron` installed |
| `/etc/cron.daily/` | **EMPTY** ← the chain dead-ends here |

So the policy and its executor were packaged by different parties for different runtimes: RHEL
family moved logrotate to a systemd timer, and containers don't run systemd. Debian-based images
would not show this, because there logrotate still ships `/etc/cron.daily/logrotate`.

Note the consequence for the obvious shortcut: **`ENABLE_CRON=yes` on its own rotates nothing.**
crond would start, `0hourly` would fire, anacron would run `run-parts /etc/cron.daily` — over an
empty directory. The flag supplies the scheduler; a cron entry still has to supply the job.

Compose fixes both halves without touching the host: `ENABLE_CRON=yes` starts `crond`, and
`suricata/logrotate.cron` is mounted to `/etc/cron.d/suricata-logrotate` (an explicit 04:00 entry,
chosen over dropping a script in `/etc/cron.daily/` so the schedule is deterministic rather than
dependent on anacron's catch-up semantics in a container that restarts).

```bash
docker compose exec -T suricata ps ax | grep crond           # must be running
docker compose exec -T suricata /usr/sbin/logrotate -d /etc/logrotate.d/suricata
```

### Prove rotation end to end, not just that the config parses

A parsed config is not a working rotation. Force one and watch the whole chain:

```bash
docker compose exec -T suricata /usr/sbin/logrotate -f -v /etc/logrotate.d/suricata
```

Verified 2026-08-09: `eve.json` → `eve.json.1`, the `postrotate suricatasc -c reopen-log-files`
fired, and Suricata recreated `eve.json` on a **new inode** and resumed writing within ~25 s.

> **The trap in verifying this.** After rotation the indexer's Suricata doc count sat unchanged,
> which looks exactly like "the agent lost the file". It is not evidence either way — the L2 noise
> is suppressed at level 0 by rule 100200, so only a genuine signature can move that counter. The
> discriminating test is to trigger a real one *after* the rotation:
> `curl http://testmynids.org/uid/index.html` → sid 2100498 count went **3 → 4**, proving the
> Wazuh agent re-followed the new inode. This is the same "no alerts is not evidence of no
> ingestion" trap as ISC-23.5; a static counter on a deliberately-silenced channel proves nothing.

Minor, benign: `suricata.log` is rotated but not immediately recreated — Suricata only writes it
on engine events, so it reappears at the next one.

## 7. The SOC Overview dashboard — [API]

`dashboards/talonsoclab-soc-overview.ndjson` holds the dashboard plus five visualizations:
alerts over time by endpoint, severity distribution, MITRE ATT&CK tactics, top firing rules, and
Suricata IDS signatures.

Import it (from the box, so the password never leaves it):

```bash
docker cp dashboards/talonsoclab-soc-overview.ndjson soc-recon-wazuh.dashboard-1:/tmp/d.ndjson
PASS=$(grep -E '^WAZUH_INDEXER_PASS=' deploy/soc-recon/.env | cut -d= -f2-)
docker compose exec -T -e P="$PASS" wazuh.dashboard sh -c \
  'curl -sk -u "admin:$P" -H "osd-xsrf: true" -X POST \
     "https://localhost:5601/api/saved_objects/_import?overwrite=true" --form file=@/tmp/d.ndjson'
```

> **Refresh the index-pattern field list first, or the Suricata panel will fail.** OpenSearch
> Dashboards stores `wazuh-alerts-*`'s field list as a **cached snapshot** on the saved object.
> It does not follow the mapping. Any field that appears later — `data.alert.*` the moment
> Suricata starts shipping — is absent, and the panel renders
> `Could not locate that index-pattern-field (id: data.alert.signature)` **even though the
> aggregation is valid and the data is queryable**. The import reports success either way.
>
> Fix: Dashboards → Stack Management → Index patterns → `wazuh-alerts-*` → the refresh button;
> or `PUT /api/saved_objects/index-pattern/wazuh-alerts-*` with the `fields` array from
> `GET /api/index_patterns/_fields_for_wildcard?pattern=wazuh-alerts-*`. This lab's refresh took
> the pattern to 855 fields.
>
> The committed ndjson deliberately **excludes** the index-pattern object — it is 139 KB of
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
      positive control still landed (sid 2100498 count 1 → 2) — surgical, not a blanket break
- [x] `Too many fields for JSON decoder` errors 5952 → 0
- [x] `crond` running; logrotate policy parses
- [x] Dashboard renders all five panels with live data — verified in real Chrome, not by import
      status. The Suricata panel failed on the first render despite a clean import; only the
      visual check caught it.
