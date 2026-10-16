# Wazuh manager log retention: 14 days of dated files on disk

> **What this does:** gives the manager's dated alert and archive files a 14-day retention,
> enforced by a root-owned host systemd timer that deletes what has aged out and then proves the
> delete did only that.
>
> **Why it matters for a SOC:** the manager rotates `alerts.json` into a dated file every night
> and never deletes one. Left alone, the files grow without bound, and they keep every alert body
> forever, including anything sensitive a misbehaving tool ever logged. The indexer already
> keeps 45 days through its ISM policy (`deploy/soc-recon/wazuh/ism/`), so the files on disk are
> a short replay buffer, not the record. Two weeks of buffer is plenty.
>
> Steps are tagged **[BOX]** (SOC host). Nothing here takes a password as an argument.

---

## 0. Orient: what the manager keeps, and where — [BOX]

Inside the manager container, under `/var/ossec/logs`:

| Path | What it is |
|---|---|
| `alerts/alerts.json`, `alerts/alerts.log` | today's alerts, the file filebeat reads |
| `alerts/<yyyy>/<Mon>/ossec-alerts-<dd>.{json,log}` | today's dated file, a **hard link** to `alerts.json` (link count 2) |
| `alerts/<yyyy>/<Mon>/ossec-alerts-<dd>.{json,log}.gz` and `.sum` | earlier days, compressed at the midnight rotation, plus checksums |
| `archives/...` | the same layout for `ossec-archive-<dd>`; near-empty unless `logall` is on |

Measure before changing anything:

```bash
docker exec soc-recon-wazuh.manager-1 sh -c '
  for t in alerts archives; do
    echo "$t: $(find /var/ossec/logs/$t -mindepth 3 -type f | wc -l) dated files, $(du -sh /var/ossec/logs/$t | cut -f1)"
  done'
```

The hard link is the detail that shapes the script. Today's dated file sits in the same tree the
timer cleans, so the script never deletes a file whose link count is above 1.

## 1. Install, without enabling — [BOX]

`deploy/soc-recon/systemd/` holds the script, a oneshot service and its timer:

| Unit | Daily at (UTC) | Script | What it does |
|---|---|---|---|
| `soc-recon-wazuh-retention` | 05:00 | `soc-recon-wazuh-retention.sh` | deletes dated files last written more than 14 days ago, then proves none remain, nothing younger went missing and `alerts.json` is intact |
| `soc-recon-unit-failed@` | on failure | none | started by `OnFailure=`; logs a `status=1/FAILURE` line naming the unit that failed, so kills and exec errors alert too |

Install root-owned copies, not links into the checkout, for the same reason as runbook 06
section 6: a linked script changes with every `git pull`, with no step where anyone looks at what
root is about to run.

```bash
cd ~/talonsoclab/deploy/soc-recon
sudo install -o root -g root -m 0755 systemd/soc-recon-wazuh-retention.sh /usr/local/sbin/
sudo install -o root -g root -m 0644 systemd/soc-recon-wazuh-retention.service \
  systemd/soc-recon-wazuh-retention.timer 'systemd/soc-recon-unit-failed@.service' \
  /etc/systemd/system/
sudo systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/soc-recon-wazuh-retention.service \
  /etc/systemd/system/soc-recon-wazuh-retention.timer    # silent when both parse
systemctl show -p UnsetEnvironment,OnFailure soc-recon-wazuh-retention.service
systemd-analyze verify '/etc/systemd/system/soc-recon-unit-failed@.service'
```

`show -p OnFailure` prints the handler's name even when its file is missing, so drill it once.
The drill unit fails on purpose, and its `status=1/FAILURE` line must reach the indexer:

```bash
t=$(date -u +%FT%TZ)
sudo systemctl start soc-recon-unit-failed@drill.service    # fails, by design
systemctl show -p LoadState 'soc-recon-unit-failed@soc-recon-wazuh-retention.service.service'
sleep 15    # the alert takes a few seconds to reach the indexer
# NOTE: the full unit name. The indexer reads `drill.service` as one word, so a
# phrase ending in `@drill` never matches.
printf '{"query":{"bool":{"filter":[{"term":{"rule.id":"40704"}},{"match_phrase":{"full_log":"soc-recon-unit-failed@drill.service"}},{"range":{"timestamp":{"gte":"%s"}}}]}}}' "$t" |
  bin/idx '/wazuh-alerts-*/_count' --data-binary @- | jq -r .count    # want 1
sudo systemctl reset-failed 'soc-recon-unit-failed@drill.service'
```

## 2. Dry run, and read it — [BOX]

The first real run deletes everything past 14 days in one go. Read what it would delete first:

```bash
sudo /usr/local/sbin/soc-recon-wazuh-retention.sh --dry-run
```

It prints one line per month with file counts and bytes, a total, how many newer dated files it
keeps, and how many older `ossec-*` files match no known name. That last number should be 0. A
manager upgrade that changes the nightly names shows up there first, because those files are
kept, not deleted. Nothing is deleted, and the output never carries file contents. Copy anything
worth keeping out of the container before step 3.

## 3. First run and proof — [BOX]

Count alerts indexed per 10 minutes first, so the run can be compared against a baseline:

```bash
for w in "now-30m now-20m" "now-20m now-10m" "now-10m now"; do
  set -- $w
  printf '{"query":{"range":{"timestamp":{"gte":"%s","lt":"%s"}}}}' "$1" "$2" |
    bin/idx '/wazuh-alerts-*/_count' --data-binary @- | jq -r .count
done
```

Then run the service once and read what it did:

```bash
sudo systemctl start soc-recon-wazuh-retention.service
systemctl show -p Result,ExecMainStatus,ExecMainExitTimestamp soc-recon-wazuh-retention.service
journalctl -u soc-recon-wazuh-retention.service -n 20 --no-pager
```

`Result=success` and `ExecMainStatus=0` alone prove nothing: systemd prints both for a unit
that never ran, and `ExecMainExitTimestamp` comes back empty once this oneshot has finished
(observed 2026-10-13). The evidence is the journal: `Starting` and `Finished` lines from just
now, with the script's `deleted dated files ...` summary between them, ending in
`kept <n> newer dated files; alerts.json in place`. Re-run the step 0 count and the
indexing count; the indexing rate should match the baseline.

## 4. Enable the timer — [BOX]

```bash
sudo systemctl enable --now soc-recon-wazuh-retention.timer
systemctl list-timers 'soc-recon-*'      # three timers, each with a NEXT time
```

`LAST` shows `-` after a reboot. Without `Persistent=`, systemd keeps the last trigger in memory
only, so the column is no evidence either way; the journal is:
`journalctl -u soc-recon-wazuh-retention.service --since yesterday`.

### Why the script looks the way it does

- **One cutoff per run.** The script fixes `start - 14 days` once and uses it, through
  `find -newermt`, for the listing, the delete and the proof. With `-mtime` each `find` would
  judge its own moment, and a file crossing the line mid-run would fail the proof.
- **The exact names only.** A strict pattern matches `ossec-alerts-<dd>` under `alerts/` and
  `ossec-archive-<dd>` under `archives/`, plain, `.gz` or `.sum`, three levels down. A link, a
  stray name, the live top-level files and `ossec.log` never match.
- **`find -delete`, as root inside the container.** The logs belong to the container's `wazuh`
  user. `-delete` removes each entry relative to its open directory, so a directory swapped for a
  link mid-run cannot steer it outside the tree.
- **Exit 1 on any failure.** Wazuh rule 40704 alerts on a failed unit only when the journal says
  `status=1/FAILURE`, so the script maps timeouts and signals to exit 1, the same trap as the
  Suricata scripts. It checks `docker.service` itself rather than relying on `Requisite=`.
- **Every failure alerts, including the ones the script never sees.** A run killed at the stop
  timeout ends in `status=9/KILL` and a missing script in `203/EXEC`, and rule 40704 matches
  neither. `OnFailure=` starts `soc-recon-unit-failed@`, which exits 1 on purpose and logs the
  `status=1/FAILURE` line the rule does match. Both cases were proven to raise 40704 within a
  second, under a user manager with test units.
- **The record is of the delete, not the listing.** `-printf` after `-delete` prints only what
  was actually unlinked, so a run that fails partway still says what it removed.
- **The clock has to be right.** The cutoff comes from the host clock, and the proof reads the
  same clock, so a host that booted days ahead would pass its own check. A delete run refuses
  unless `timedatectl` reports NTP-synchronized. A dry run only reports, so it skips the check.
- **It starts in `/`.** Compose 5.6 ignores the working directory's compose file and `.env`
  for `-p ... exec`; a broken file and a failing `${VAR:?}` both ran clean. Other versions may
  not, and a hand run starts in the checkout, so the script runs `cd /` first, as the unit does.
- **A delete on the live project needs root.** The script takes three overrides for its
  scratch-stack tests (`RETENTION_PROJECT`, `RETENTION_DOCKER_UNIT`, `RETENTION_LOCK`), and the
  unit unsets all three. On 2026-10-13 the first suite run set the lock override but not the
  project, and its first case ran the delete against the live manager as the docker-group user.
  It removed exactly the set the dry run would have shown, but before anyone had read that dry
  run. Since then the suite refuses any project but its scratch ones, and the script refuses a
  non-dry-run delete on `soc-recon` from anyone but root.

### Known gaps

- **Empty month folders stay.** The script never removes directories, so nothing it does can
  race the manager's own rotation into a missing folder. That leaves about twelve empty folders a
  year.
- **A run near midnight UTC can fail its proof.** The rotation compresses yesterday's file into a
  new `.gz` name, and a run straddling that sees a young file go missing. It fails loud with exit
  1 and the next run passes. The timer runs at 05:00 to stay clear.
- **Age is the file's last write.** A restore that resets modification times keeps restored files
  for 14 more days.
- **No `Persistent=`.** A day missed while the box was down is skipped, and the next run deletes
  two days' files.
- **A timer that never fires.** `OnFailure=` covers a run that fails, not a run that never
  starts because the timer was disabled or masked. The job age probe (runbook 06, section 6,
  "Job age probe") covers it twice: no `kept <n> newer dated files; alerts.json in place` line
  in 26 h, or a dated tree with a file past 16 days whatever its name, or with no file at all,
  raises rule 100311 at level 7. The second also catches a manager upgrade that renames the
  dated files, which this script would then keep forever. Until the probe is installed, only
  `systemctl list-timers` shows it.
- **A killed run can leave its `find` running.** `docker exec` does not forward signals, so the
  in-container `find` can run up to 125 s past a kill. A run started in that window can fail
  loud on a file that vanished. It cannot delete the wrong file.
- **The cutoff is inclusive.** A file whose last write equals the cutoff to the nanosecond goes
  too, which is why the output says "14 or more days".
- **Entries can change between the checks and the unlink.** `-delete` does not re-check type,
  link count or age at the moment it unlinks. Only the manager's `wazuh` user or root can change
  entries in those folders, and either could delete them directly anyway, so this gives nobody
  anything new.

## Acceptance

- [x] Script, service, timer and handler installed root-owned; timer enabled at 05:00 UTC
      *(2026-10-13)*
- [x] Dry run read before the first delete *(0 files: the 2026-10-13 test suite had already
      deleted the backlog, see "A delete on the live project needs root" above)*
- [x] First run: the journal shows the run, no dated file past 14 days left, the young-file
      count unchanged (87), indexing at the baseline rate *(2026-10-13 22:52Z, deleted 0)*
- [x] First scheduled run that deletes: the 05:00 UTC journal shows a nonzero total
      *(2026-10-14 05:00:09Z: 6 September files, 7,529,504 bytes; 0 unknown `ossec-*` names;
      87 kept; `alerts.json` in place; 100, then 189 and 103 alerts per 10 min after it)*
- [x] `systemd-analyze verify` silent on all three units; `UnsetEnvironment` lists the three
      overrides; the handler shows `LoadState=loaded`; the drill raised one 40704
      *(2026-10-13 22:48Z)*
- [ ] 46 days after the first run, `_count` on `wazuh-alerts-*` with `timestamp` older than
      `now-46d` is 0, and a `min` aggregation on `timestamp` puts the oldest alert 45 to 46 days
      back. The second check is the positive control: a count of 0 also comes from an unmapped
      field or from there being no old data at all
- [x] Scratch-stack suite passes (15 cases), including the read-only month, a symlinked month
      folder, the TERM signal, a broken compose file in the working directory and the non-root
      live refusal
- [x] `OnFailure=` proven: an exec error and a kill each raised rule 40704 within a second
