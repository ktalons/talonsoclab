# Tier 2 backups: encrypted volume snapshots on an external drive

> **What this does:** takes a snapshot of the four Docker volumes that hold the SOC's state,
> encrypts each archive with `age` on the box before it leaves, copies the set to an external
> drive on the Mac, proves every archive decrypts and matches the live manager, and only then
> marks the backup as good. A daily probe on the manager reads that mark, and the SIEM raises a
> level 10 alert when the newest good backup is over a week old.
>
> **Why it matters for a SOC:** git rebuilds the stack, but not its state. Agent keys, file
> integrity baselines, alert history and the indexer's security config live only in volumes. A
> backup that nobody checks lapses quietly, and an earlier version of this one did exactly that.
> So the backup is verified on every run, and the SIEM watches its age like any other control.
>
> Steps are tagged **[MAC]** (the workstation with the drive) and **[BOX]** (SOC host). The box
> never holds the key that opens the archives, and no plaintext archive is written to any disk.

---

## 0. What gets backed up, and what does not

| Volume | Why it is in the set |
|---|---|
| `indexer_data` | alert history, saved dashboards, the indexer's security index and ISM policies |
| `wazuh_etc` | `client.keys`, `authd.pass`, the manager's config as installed, shared agent-group configs |
| `wazuh_queue` | agent databases, `rids` counters, FIM baselines, syscollector, keystore |
| `wazuh_api_configuration` | the manager API's config and certs |

The queue leaves out `vd`, `vd_updater`, `indexer` and `harvester`: about 12 GB of CVE data
and spools that rebuild themselves, where a restored copy would be stale. Every other volume is
image payload, generated at start, refetched (`suricata_rules`, rebuilt by the update job), or
already in the indexer (`wazuh_logs`, which runbook 08 trims to 14 days anyway).

Measured 2026-10-16: the four archives come to about 1.1 GB. Reading `indexer_data` dominates,
so **a run stops the stack for about 3 to 4 minutes**, the indexer's start included.

## 1. Setup, once — [MAC] then [BOX]

Make the key pair on the Mac. The private half never leaves it:

```bash
mkdir -p -m 700 ~/.config/talon
age-keygen -o ~/.config/talon/tier2-identity.txt
chmod 600 ~/.config/talon/tier2-identity.txt
age-keygen -y ~/.config/talon/tier2-identity.txt        # the public key, age1...
```

Put a copy of the identity file in the password manager (Tier 3 in PHOENIX). Losing it means
every archive is unreadable, which is the point of the encryption and the risk of it.

On the box, install `age` (one sudo line) and give the deploy dir the public key:

```bash
sudo apt install -y age
```

```bash
cd ~/talonsoclab/deploy/soc-recon
cp tier2.recipient.example tier2.recipient
# replace the age1<recipient> line with the public key printed on the Mac
```

`tier2.recipient` is gitignored. The script refuses a file with no key, more than one key, or
anything that is not an `age1` public key.

The probe, its rules, its localfile and the read-only `/srv/tier2` bind ride the manager's
config mount, so they apply on a new container. Install them the way runbook 06 section 3
installs anything (check what the recreate would change, recreate, read the boot log), then:

```bash
docker compose exec -T wazuh.manager stat -c '%U:%G %a %n' /var/ossec/etc/probes/soc-recon-tier2-age.sh
docker compose exec -T wazuh.manager /var/ossec/etc/probes/soc-recon-tier2-age.sh
```

Want `root:root 755`, then `STALE tier2=none` until the first backup verifies.

## 2. Take a backup — [MAC]

The drive must be mounted at `/Volumes/<drive>`; the script's `VOLUME` names it. Then:

```bash
cd ~/Projects/talonsoclab
tools/tier2-backup.sh
```

It runs in this order, and stops at the first failure:

1. **Before the box is touched:** the identity is yours, mode 600, and opens what the box
   encrypts to; the drive is a mounted volume, not a folder on the boot disk, and no directory
   on the way to the destination is a link; 4 GB are free. The drive check runs again before
   each write, because the drive can go away during the 3 to 4 minutes.
2. **On the box** (`deploy/soc-recon/bin/tier2-snapshot`): refuses unless every service is
   running and the running manager matches the checkout (next section). Then it starts its
   watchdog, stops the stack (each service gets 2 minutes to stop cleanly), streams each volume
   through the manager image's own `tar` into `age`, and brings the stack back: the indexer,
   then a **new** manager container, then the rest. Each restart step is tried up to three
   times. It waits for `0-wazuh-init: exited 0` and every health check, then checks the
   restarted stack against the checkout again, before it reports. A held restart (below)
   reports at once instead.
3. **Copy and verify:** `rsync` to `<drive>/talonsoclab/tier2/<project>/<stamp>/`, the box's
   `MANIFEST` checked, exactly four archives. Each archive must fail `tar -tzf` on its raw bytes
   and pass `age -d | tar -tzf -`.
4. **Restore test:** the `wazuh_etc` archive's `ossec.conf`, every file under `rules/custom/` at
   any depth and each `shared/*/agent.conf` must hash the same as the live manager's copies.
5. **Mark and prune:** only now does the box get its marker. The drive keeps the newest three
   snapshots and the box keeps the newest one. Only stamp-named directories holding the box's
   `MANIFEST` are pruned; anything else is left alone. A delete that fails, on the drive or on
   the box, leaves the marker written, since the backup verified, and the run exits 3.

The box script's progress goes to stderr and to `~/tier2/<project>/last-run.log`, so if the
Mac's session drops mid-run the box still finishes or unwinds, and the log says which.

### A backup is never an install

The restart recreates the manager, and a recreate installs whatever the checkout holds. So the
box script compares four things before it stops anything, and refuses on any difference:

- the manager's compose definition (`docker compose config --hash` against the running
  container's label);
- the image, by ID: the tag the compose file names must still be the image the manager runs. A
  `docker compose pull` or a retag moves the tag without changing the compose hash. The
  recreate runs with `--pull never`, and the archives use the same image ID;
- every config-mount file against the copy the manager's init made (runbook 06's loop); a
  directory the manager does not have (an empty one too) or has as a file, anything that is
  neither a file nor a directory, such as a symlink, on either side, count as differences;
- every single-file bind of every service (the manager, the indexer, the dashboard) against
  what its container sees, and the manager's against what the init copied. A git pull replaces
  a file, a single-file bind keeps the old one, and the restart's start would load the new one.
  Every bind source must also exist, be no link, and be the same kind (file or directory) the
  container sees: a start cannot mount a directory onto a file, and the service would stay down.

The refusal lists what differs. Install it first (the manager: runbook 06 section 3; another
service: `docker compose up -d --force-recreate <service>`), or revert it, then run the backup
again. It also refuses a recipient `age` cannot encrypt to, and a
`.pending-restart` an earlier run left behind.

The guard runs before the stop, and the 3 to 4 minutes after it are a window: a `git pull`, an
edit, a compose change or a `docker compose pull` in that time would go live on the recreate.
So the run hashes everything a recreate reads (the compose definition, the image ID, every bind
source's files and directories) before the stop, and again at the restart. If the hash changed,
it starts the old containers instead of recreating the manager, by the container IDs it saved
before the stop, so even a compose file that no longer parses cannot stop them coming back.
With `wazuh-manager:4.14.6` that installs
no config-mount file: the init then exits 1 before its config copy, and every daemon runs the
old config, as after a dockerd restart. The run fails and says why. Install the change (the
manager: runbook 06 section 3; another service: `docker compose up -d --force-recreate
<service>`) or revert it, then back up.

The held path does not cover single-file binds that land straight in live paths: the manager's
Filebeat cert files and `wazuh/cont-init/1-config-filebeat` (which s6 runs at boot), and every
indexer and dashboard bind (their certs, `wazuh.indexer.yml`, `internal_users.yml`,
`opensearch_dashboards.yml`, `wazuh.yml`). Docker re-reads every bind source when it starts a
container, so a change to one of those during a run goes live on the restart, held or not, and
a deleted one leaves its service down until `git checkout` puts it back (measured on Docker
29.9.1, 2026-10-20). The guard covers a change made before the run, including one written in
place (`cp` onto the file, an editor), which keeps the inode so the container already sees the
new bytes: a single-file bind whose ctime is newer than its service's start is refused,
because the running service never loaded it. Install it as above (the manager: runbook 06
section 3, never a plain restart, whose init exits 1; another service:
`docker compose up -d --force-recreate <service>`), then back up. A change during the run
fails it, with no marker: one made before the restart's check is held there, and one made
after it is caught once every service is back and healthy, by a second hash of the checkout and
by the guard run again against the restarted containers. That matters for the dashboard, which
compose starts only once the indexer is healthy, minutes after the check. The second guard also
catches most changes loaded during the restart and reverted on the host, because the containers
keep what they loaded: a file swapped and put back the way git does it, a config-mount file
edited back, the compose file, or the image tag moved and moved back. Last, a ctime check
catches what is put back in place: a direct single-file bind edited and restored in place
keeps its inode and bytes, and a config-mount file added and removed leaves no trace in the
checkout, but every write, rename, mode change, and entry added to or removed from a
directory moves an inode's ctime. Any bind source, config-mount entry, the compose file or
`.env` whose ctime is newer than the run's start fails it and is named. No service touches its
own bind sources at start (measured on the live stack, 2026-10-20), so a normal run lists
nothing; a stray `chmod` or `touch` there during a run fails it too.

**Change nothing on the box while a backup runs.** A failed run is the most the script can do:
by the time a change is seen it may already be live. The direct single-file binds go live on any
start, and the last hash check and the recreate are separate commands, so a `git pull` or
`docker compose pull` landing after the check goes live unreviewed. Preventing that, not just
reporting it, would take a lock every git and docker command on the box honors, so the rule is
the guard: one operator, and no changes until the run has finished.

The held path's guarantee is a measured property of 4.14.6's init, not something the script can
enforce. After a manager image change, prove it again on scratch before the first backup on the
new image (runbook 02, § 5).

The config-mount comparison is content and new files only, on purpose. The init copies with
`cp -r` (GNU coreutils 8.32 in `wazuh-manager:4.14.6`, measured 2026-10-19): onto an existing
file it replaces the content and keeps the file's mode, and it never deletes a file the
checkout dropped. So a recreate can install a changed or new file, which the loop catches, but
never a mode change or a deletion.

### When a run dies

A run that is stopped normally, by an error, Ctrl-C or the ssh session dropping, brings the
stack back from its exit trap. For what no trap can catch, SIGKILL or the kernel's OOM killer,
the run starts a watchdog before it stops anything: a detached copy of the script, in its own
session, that waits for the run's lock and restarts the stack if the run left
`~/tier2/<project>/.pending-restart` behind. That file goes only when every restart step
worked, so a restart that failed is retried once more by the watchdog. Both write to
`last-run.log`.

A signal waits for the archive in progress: up to about 100 s on `indexer_data` before the
restart begins.

A box reboot mid-run kills the watchdog too, and `restart: unless-stopped` honours the stop, so
the stack stays down. After a reboot, or when `last-run.log` ends in
`WARN: the stack is not fully back`, bring it back by hand on the box. If the log also says the
old manager was started because the checkout changed, review that change first: the recreate
below installs it.

```bash
cd ~/talonsoclab/deploy/soc-recon
docker compose start wazuh.indexer
docker compose up -d --no-deps --force-recreate --pull never wazuh.manager
docker compose start
docker compose logs wazuh.manager | grep '0-wazuh-init: exited'     # want exited 0
rm -f ~/tier2/soc-recon/.pending-restart ~/tier2/soc-recon/.restart-ids
```

When the restart fails after all four archives are written, or the run dies after that point, the
run or its watchdog keeps them, with their
`MANIFEST` and `INFO`, as `~/tier2/<project>/.<stamp>.failed`. No prune, watchdog or Mac run
touches that name, and the Mac writes no marker for it. It is the freshest copy of the state
you are about to recover by hand. Once the stack is back, take a normal backup, then delete it.
If the recovery goes badly first, copy it to the drive and restore from it (§ 4):

```bash
rsync -a <box>:tier2/soc-recon/.<stamp>.failed/ <drive>/talonsoclab/tier2/soc-recon/<stamp>/
```

The watchdog survives the ssh session ending because logind leaves talon's processes alone
(`KillUserProcesses` unset, so `no`, on the box as of 2026-10-19). Changing that setting would
take the watchdog down with the session.

## 3. The SIEM watches its own backup — [BOX]

`tools/tier2-backup.sh` writes `deploy/soc-recon/state/tier2/verified` on the box after a
backup verifies: one line, `verified <epoch>`, in the box's clock, replaced by rename. The
manager sees that directory read-only at `/srv/tier2`. It is a directory bind, because a
single-file bind would keep the inode the rename replaced.

Once a day the manager's logcollector runs `soc-recon-tier2-age.sh`, which prints one line:

| Output | Rule | Level | Means |
|---|---|---|---|
| `OK tier2=<d>d<hh>h` | 100320 | 3 | the newest verified backup is at most 7 days old (`0d00h` to `7d00h`, the only OK ages the probe prints; any other OK alerts as 100321). The daily heartbeat |
| `STALE tier2=<d>d<hh>h` | 100321 | 10 | it is over 7 days old |
| `STALE tier2=none` | 100321 | 10 | no backup has verified since the marker was cleared |
| `ERROR <reason>` | 100321 | 10 | it cannot trust the marker: a link, not a regular file, unreadable, not exactly one `verified` line, or dated after the clock. Or the probe failed or ran past 8 s |
| anything else | 100321 | 10 | 100321 takes every output that is not exactly the OK line |

The probe reads the marker's own time, never its mtime, and never prints its content. It
writes nothing. The probe's record, one document a day:

```bash
cd ~/talonsoclab/deploy/soc-recon
q='{"size":10,"sort":[{"timestamp":"desc"}],"_source":["timestamp","rule.id","full_log"],
  "query":{"bool":{"filter":[{"terms":{"rule.id":["100320","100321"]}},
  {"range":{"timestamp":{"gte":"now-8d"}}}]}}}'
bin/idx '/wazuh-alerts-*/_search' -d "$q" |
  jq -r '.hits.hits[]._source | "\(.timestamp) \(.rule.id) \(.full_log | split("\n") | last)"'
```

The daily cadence is runs, not a calendar: the probe runs when the manager starts, then every
24 h. A backup recreates the manager, so the next document lands within a minute of it.

## 4. Restore — [MAC] and [BOX]

Restores stream too: decrypt on the Mac, pipe over ssh into a new volume on the box. Run this
from PHOENIX Stage 2 Path A, after Stage 1 has the repo and the images (`docker compose pull`):

```bash
cd ~/Projects/talonsoclab
tools/tier2-restore.sh <drive>/talonsoclab/tier2/soc-recon/<stamp>
```

It stops at the first failure, and checks before it writes anything:

1. **The snapshot:** `MANIFEST` matches, exactly the four archives, each decrypts and lists.
2. **The box:** its compose project is the snapshot's, the stack has no containers, none of
   the four volumes exists, and the manager image is already there. Nothing is pulled.
3. **The restore:** each volume is created with compose's project and volume labels, so
   compose adopts it, plus a `tier2.restore` label with this run's token, pinned by a stopped
   holder container (`tier2.holder=<token>`) before its label is read back, and filled by the
   manager image's `tar`. Docker refuses to remove a volume a container references, so no other
   volume can be swapped in under the same name while the restore uses it. A failed or
   interrupted run that can still reach the box removes its holders and the volumes it
   created, so the next try starts clean. It warns when the snapshot's `INFO` names
   another image than the box's.
4. **The record:** once all four are filled, it writes `state/tier2-restored` on the box,
   `restored <stamp> <token>`. A failed write fails the run and removes the volumes.

It refuses a volume that already exists rather than writing into it. Removing a volume is the
one step that destroys state, so it stays a deliberate `docker volume rm` by hand.

Then, on the box, start the stack through the guard and check the init:

```bash
cd ~/talonsoclab/deploy/soc-recon
bin/tier2-start
docker compose logs wazuh.manager | grep '0-wazuh-init: exited'     # want exited 0
```

`bin/tier2-start` runs `docker compose up -d --force-recreate --pull never` only when all four
volumes exist and carry the record's token, and it pins each with its own holder container from
that check until compose has created the stack's containers. A run cut off from the box
(SIGKILL, a Mac that lost power, ssh down through the cleanup) leaves half-filled volumes that
carry compose's labels and no record for their token, plus their holders, so the guard refuses
and names them. Remove the holders first (`docker rm -f` with the IDs it prints), then the
volumes with `docker volume rm`, then restore again. **Never start a restored stack with plain
`docker compose up`:** it adopts whatever volumes carry compose's labels, finished or not.

Carry on with PHOENIX. Expect the vulnerability dashboard to be empty for the first several
minutes while `vd` refetches.

### Why it looks the way it does

- **`age` on the box, with only the public key there.** Encryption happens before the bytes
  leave, so the drive, the network and the Mac's disk only ever see ciphertext. A stolen drive
  or a stolen box gives up nothing that opens the archives.
- **Verify on every run, not once.** The marker means "a restorable copy is on the drive", not
  "a snapshot was taken". A run that cannot decrypt, list or match leaves the old marker, so the
  alert keeps counting.
- **gzip, not zstd.** Reading the volume is the bottleneck: plain `tar` took 90 s on
  `indexer_data`, gzip 104 s, `zstd -T0` 87 s. gzip keeps `tar -tzf` as the check everywhere.
- **The manager image's `tar`, read-only, no network.** Nothing is pulled at backup time, and
  nothing in the archive step can change the data.
- **Stamps, not dates.** `<YYYY-MM-DD>T<HHMMSS>Z` in UTC, so two runs in one day do not collide
  and the names sort in time order. The box runs UTC and the Mac does not.

### Known gaps

- **A run stops the stack for about 3 to 4 minutes.** Nothing is collected while it is down;
  agents buffer and resend. Snapshotting the indexer live (its snapshot API) would avoid that
  and is not built.
- **The drive and the Mac are one site.** Tier 2 protects against the box dying, not the house.
- **A probe that never runs raises nothing.** Only the missing daily 100320 shows it, the same
  limit as the job age probe.
- **The marker is as trustworthy as the talon account.** talon can write it, and talon is in
  the `docker` group, which is root on the box anyway.
- **The marker lives in the checkout.** `state/tier2/verified` is gitignored, so a
  `git clean -x` in the deploy dir deletes it. The probe then says `STALE tier2=none`.
- **A box snapshot can outlive a failed run.** When a run fails after its archives are complete
  (a held restart, a failed init, a stack that does not come back healthy, the second hash
  or second guard, or the ctime check),
  the box keeps the snapshot and skips its prune, but the Mac writes no marker. Both fail toward
  STALE.
- **A touch or chmod on a single-file bind refuses every backup until its service starts
  again.** The ctime check cannot tell a mode change or a rewrite with the same bytes from an
  edit, so it names the file as not loaded. Install it as in section 2, then back up.
- **A change before the restart's check leaves the old manager running.** The run then fails,
  and the manager runs its old config with `0-wazuh-init: exited 1` until the change is
  installed. A change after the check fails the run at the second hash, the second guard or the ctime
  check instead.
- **A restore that is killed or loses the box leaves its volumes.** SIGKILL, a Mac that loses
  power, or an ssh link that stays down through the cleanup's three tries skips the removal.
  The volumes carry a `tier2.restore` label and no record names their token: `bin/tier2-start`
  and the next restore both refuse and name them and their holder containers, and
  `docker rm -f` on the holders, then `docker volume rm`, clears them. Plain
  `docker compose up` does not check, which is why section 4 starts through the guard.
- **Change nothing on the box during a backup.** A change during the run fails it (no marker),
  but it may be live by then: a direct single-file bind (certs, the cont-init script, the
  indexer and dashboard configs) changed before its service starts, or a pull landing before
  the recreate reads the checkout. The run fails for it, including a change made and put back
  inside the restart, which the second guard or the ctime check sees (section 2). Only that
  rule, not a lock, keeps any of it from happening.
- **Holder containers outlive a killed restore or `bin/tier2-start`.** They are stopped
  containers labelled `tier2.holder` or `tier2.startholder`, and they keep their volumes from
  being removed, `docker compose down -v` included. Both refusals name them; `docker rm -f` on
  them comes first. `docker container prune` removes them too, which also lifts the pin.
- **Only single-file binds are compared for services other than the manager.** Their directory
  binds (Suricata's log directory) are data. A future config directory bound into the indexer
  or dashboard would not be covered.
- **One Mac run at a time.** The tool holds `~/.config/talon/tier2-backup.lock` from before the
  snapshot to the end. A run killed with SIGKILL leaves it behind; the next run says so, and
  `rmdir` clears it.
- **Profiled services are not checked.** `docker compose config --services` leaves out services
  behind a profile (`recon-runner`). Setting `COMPOSE_PROFILES=recon` in `.env` would make every
  backup refuse until that service runs.
- **Config file names must not contain a tab, a newline or a backslash.** Spaces compare fine.
  The Mac's `tar` and the box's `sha256sum` escape those characters, so such a file fails the
  restore test (no marker), never passes it.
- **A restore owns only what it labelled.** Each run labels the volumes it creates with its own
  random token, pins each with a holder container, writes into a volume only after reading that
  token back, and removes only volumes that carry it. A volume another process made in the
  meantime is refused, never written into or removed, and once pinned it cannot be swapped.
  The same holds for `bin/tier2-start`, which pins all four until compose has created the
  stack's containers.
- **Manual runs.** The 7-day alert is the reminder. Automating it would mean 3 to 4 minutes of
  downtime with nobody watching.

## Acceptance

- [ ] Refusals leave the stack untouched: missing, doubled or malformed recipient, a stopped
      service, a changed config-mount file, a replaced single-file bind, a changed compose
      definition, a moved or missing image tag, a second run holding the lock
- [ ] A run writes exactly four `.tar.gz.age` archives, no plaintext archive on any disk, and the
      stack comes back with `0-wazuh-init: exited 0`, also when the run is killed mid-archive,
      SIGKILL included; restart steps that keep failing are retried, reported, and left to the
      watchdog
- [ ] On the drive, every archive fails `tar -tzf` raw and passes `age -d | tar -tzf -`; a link
      on the way or a drive that goes away mid-run stops the run before it writes
- [ ] The restore test matches; a planted difference fails the run and leaves the marker, also
      one level down in `rules/custom/`
- [ ] The marker moves only after a verified run; the drive keeps three snapshots, the box one;
      only stamp directories holding a `MANIFEST` are pruned, and a failed delete exits 3
- [ ] `tools/tier2-restore.sh` refuses a bad snapshot, a running stack or an existing volume,
      cleans up after an interrupted run, and a restore plus `bin/tier2-start` brings back the
      planted state with a clean init
- [ ] `bin/tier2-start` refuses, and starts nothing, after a restore killed mid-stream: with no
      record, a stale record, its own token with a volume missing, a malformed record, or an
      unlabelled volume; a restore whose record cannot be written removes its volumes
- [ ] 100320 on a fresh marker; 100321 level 10 on none, over 7 days, and every ERROR shape; a
      back-dated marker alerts within one probe interval
- [ ] No age identity anywhere on the box or in the repo
- [ ] Installed by one force-recreate; the first real backup verifies; the first 100320 reaches
      the indexer
