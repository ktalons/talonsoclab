# Tier 2 backups: encrypted volume snapshots on an external drive

> Condensed public version. The full build log with dated evidence stays private.

> **What this does:** snapshots the four Docker volumes that hold the SOC's state, encrypts each
> archive with `age` on the box, copies the set to an external drive on the Mac, and proves every
> archive decrypts and matches the live manager before marking the backup good. The SIEM raises
> a level 10 alert when the newest good backup is over a week old.
>
> **Why it matters for a SOC:** git rebuilds the stack, not its state. Agent keys, FIM baselines,
> alert history and the indexer's security config live only in volumes, and a backup nobody
> checks lapses quietly.
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

The queue leaves out `vd`, `vd_updater`, `indexer` and `harvester`, about 12 GB that rebuilds
itself. Every other volume is image payload, generated at start, refetched, or already in the
indexer. The archives come to about 1.1 GB, and **a run stops the stack for about 3 to 4
minutes**.

## 1. Setup, once — [MAC] then [BOX]

Make the key pair on the Mac. The private half never leaves it:

```bash
mkdir -p -m 700 ~/.config/talon
age-keygen -o ~/.config/talon/tier2-identity.txt
chmod 600 ~/.config/talon/tier2-identity.txt
age-keygen -y ~/.config/talon/tier2-identity.txt        # the public key, age1...
```

Put a copy of the identity in the password manager (Tier 3 in PHOENIX). Losing it makes every
archive unreadable.

Then the seal key, also Mac only. The `age` recipient is public, so anyone who can write the
drive could encrypt a snapshot of their own. The backup signs what it verified, and the restore
reads nothing unsigned:

```bash
ssh-keygen -t ed25519 -N '' -C tier2 -f ~/.config/talon/tier2-sign
printf 'tier2 namespaces="tier2" %s\n' "$(cat ~/.config/talon/tier2-sign.pub)" >~/.config/talon/tier2-allowed-signers
```

Put the `tier2-allowed-signers` line in the password manager too; a restore on a new Mac needs
it. Neither key has a passphrase, and both rest on the Mac login. The tools refuse a seal key
with a passphrase, and a signers file that is not yours or that others can write.

**Re-keying the seal.** For a key retired or lost but never read, append the new line with `>>`
and drop the old one once its three snapshots are pruned. For a key that may have been read,
remove the old line at once and take a new backup, because a signature carries no trusted time.
Either way, replace the password-manager copy the same day.

Each backup also appends a line to `~/.config/talon/tier2-sealed.log`, which the restore reads to
say whether a snapshot is the newest sealed. Copy it to the password manager now and then.

On the box, install `age` and give the deploy dir the public key:

```bash
sudo apt install -y age
```

```bash
cd ~/talonsoclab/deploy/soc-recon
cp tier2.recipient.example tier2.recipient
# replace the age1<recipient> line with the public key printed on the Mac
```

`tier2.recipient` is gitignored, and the script refuses anything but exactly one `age1` public
key.

The probe, its rules, its localfile and the read-only `/srv/tier2` bind ride the manager's config
mount. Install them the way runbook 06 section 3 installs anything, then:

```bash
docker compose exec -T wazuh.manager stat -c '%U:%G %a %n' /var/ossec/etc/probes/soc-recon-tier2-age.sh
docker compose exec -T wazuh.manager /var/ossec/etc/probes/soc-recon-tier2-age.sh
```

Want `root:root 755`, then `STALE tier2=none` until the first backup verifies.

## 2. Take a backup — [MAC]

The drive must be mounted at `/Volumes/<drive>`; the script's `VOLUME` names it. The box is
reached through the ssh alias `soc-host`: add a `Host soc-host` entry to `~/.ssh/config`, or
export `TIER2_BOX=<your alias>` before running either script. Then:

```bash
cd ~/Projects/talonsoclab
tools/tier2-backup.sh
```

It stops at the first failure:

1. **Mac checks:** both keys are yours, mode 600, and match the box's recipient and the
   restore's signer. The drive is a real mounted volume with no link on the path and 4 GB free,
   rechecked before each write.
2. **On the box** (`deploy/soc-recon/bin/tier2-snapshot`): it refuses unless every service runs
   and matches the checkout (next section), starts its watchdog, stops the stack, and streams each
   volume through the manager image's `tar` into `age`. Then it brings the stack back with a
   **new** manager container, waits for `0-wazuh-init: exited 0`, and checks it again.
3. **Copy and verify:** `rsync` to `<drive>/talonsoclab/tier2/<project>/<stamp>/`, check
   `MANIFEST`, and require each of the four archives to fail `tar -tzf` raw and pass
   `age -d | tar -tzf -`.
4. **Restore test and seal:** the archived `ossec.conf`, `rules/custom/` and
   `shared/*/agent.conf` must hash the same as the live manager's. Then `VERIFIED` and
   `VERIFIED.sig` are written, signed in memory with `~/.config/talon/tier2-sign` over the box's
   own hashes.
5. **Mark and prune:** only now does the box get its marker. The drive keeps three snapshots and
   the box one. A failed delete exits 3.

Progress also goes to `~/tier2/<project>/last-run.log` on the box, so a dropped Mac session loses
nothing.

### A backup is never an install

The restart recreates the manager, and a recreate installs whatever the checkout holds. So before
the stop, the box script refuses on any difference between the running stack and the checkout:
the compose hash, the image ID behind the tag, every config-mount file against the init's copy
(runbook 06's loop), and every single-file bind against what its container sees, with a ctime
check for in-place edits. It names what differs. Install it (the manager: runbook 06 section 3;
another service: `docker compose up -d --force-recreate <service>`) or revert it, then back up
again. It also refuses a bad recipient and a leftover `.pending-restart`.

If the checkout changes during the run, the restart starts the old containers by saved ID instead
of recreating them, and the run fails, leaving the old manager on its old config
(`0-wazuh-init: exited 1`) until the change is installed. A second hash, a second guard run and
a ctime check catch later changes but cannot stop them: certs, the cont-init script and the
indexer and dashboard configs are single-file binds re-read on any start. **Change nothing on the
box while a backup runs.**

The held path relies on the measured behaviour of the `wazuh-manager:4.14.6` init, so prove it
again on scratch after a manager image change (runbook 02, § 5). The config-mount check covers
content and new files only, because the init's `cp -r` installs nothing else.

### When a run dies (Recovery)

An error, Ctrl-C or a dropped ssh session brings the stack back from the exit trap. For SIGKILL
or the OOM killer, a detached watchdog started before the stop restarts the stack if the run left
`~/tier2/<project>/.pending-restart` behind. A signal waits for the archive in progress, up to
about 100 s.

A box reboot mid-run kills the watchdog too, and the stack stays down. After a reboot, or when
`last-run.log` ends in `WARN: the stack is not fully back`, bring it back by hand. If the log says
the old manager was started because the checkout changed, review that change first, because the
recreate installs it:

```bash
cd ~/talonsoclab/deploy/soc-recon
docker compose start wazuh.indexer
docker compose up -d --no-deps --force-recreate --pull never wazuh.manager
docker compose start
docker compose logs wazuh.manager | grep '0-wazuh-init: exited'     # want exited 0
rm -f ~/tier2/soc-recon/.pending-restart ~/tier2/soc-recon/.restart-ids
```

If the restart failed after all four archives were written, they stay on the box as
`~/tier2/<project>/.<stamp>.failed`, unpruned and unmarked: the freshest copy of the state. Take
a normal backup once the stack is back, then delete it. If recovery goes badly first, copy it to
the drive and restore from it (§ 4):

```bash
rsync -a <box>:tier2/soc-recon/.<stamp>.failed/ <drive>/talonsoclab/tier2/soc-recon/<stamp>/
```

The watchdog outlives the ssh session only while logind's `KillUserProcesses` stays unset.

## 3. The SIEM watches its own backup — [BOX]

After a verified backup, `tools/tier2-backup.sh` writes `deploy/soc-recon/state/tier2/verified`
on the box: `verified <epoch>`, replaced by rename. The manager sees it read-only through a
directory bind at `/srv/tier2`, because a single-file bind would keep the replaced inode.

Once a day the manager's logcollector runs `soc-recon-tier2-age.sh`, which prints one line:

| Output | Rule | Level | Means |
|---|---|---|---|
| `OK tier2=<d>d<hh>h` | 100320 | 3 | the newest verified backup is at most 7 days old |
| `STALE tier2=<d>d<hh>h` | 100321 | 10 | it is over 7 days old |
| `STALE tier2=none` | 100321 | 10 | no backup has verified since the marker was cleared |
| `ERROR <reason>` | 100321 | 10 | the marker cannot be trusted, or the probe failed or ran past 8 s |
| anything else | 100321 | 10 | every output that is not exactly the OK line |

The probe reads the marker's own time, never its mtime, and writes nothing. Its record:

```bash
cd ~/talonsoclab/deploy/soc-recon
q='{"size":10,"sort":[{"timestamp":"desc"}],"_source":["timestamp","rule.id","full_log"],
  "query":{"bool":{"filter":[{"terms":{"rule.id":["100320","100321"]}},
  {"range":{"timestamp":{"gte":"now-8d"}}}]}}}'
bin/idx '/wazuh-alerts-*/_search' -d "$q" |
  jq -r '.hits.hits[]._source | "\(.timestamp) \(.rule.id) \(.full_log | split("\n") | last)"'
```

It runs at manager start, then every 24 h, so a backup brings the next document within a minute.

## 4. Restore — [MAC] and [BOX]

Restores stream too: decrypt on the Mac, pipe over ssh into a new volume on the box. Run this
from PHOENIX Stage 2 Path A, after Stage 1 has the repo and the images (`docker compose pull`):

```bash
cd ~/Projects/talonsoclab
tools/tier2-restore.sh <drive>/talonsoclab/tier2/soc-recon/<stamp>
```

It stops at the first failure, and checks before it writes anything:

1. **The seal:** the snapshot is copied to a private `$TMPDIR` dir on the Mac (its size plus
   512 MB free), seal files first.
   `VERIFIED.sig` must verify against `~/.config/talon/tier2-allowed-signers`, and `VERIFIED`
   must name this project, this stamp and the hashes of this `MANIFEST` and `INFO`.
2. **The snapshot:** `MANIFEST` matches, and the four archives decrypt and list.
3. **The box:** the same compose project, no containers, none of the four volumes, and the
   manager image present. Nothing is pulled.
4. **The restore:** each volume gets compose's labels plus a `tier2.restore` token label, is
   pinned by a stopped holder container, and is filled by the manager image's `tar`. A failed
   run that can still reach the box removes what it made.
5. **The record:** `state/tier2-restored` on the box, `restored <stamp> <token>`.

It never writes into an existing volume. Removing one destroys state, so it stays a deliberate
`docker volume rm` by hand.

Then, on the box, start the stack through the guard and check the init. On a rebuilt box,
load the four AppArmor profiles first: every service names one, and a service whose profile
is not in the kernel does not start
([`deploy/soc-recon/apparmor/README.md`](../../deploy/soc-recon/apparmor/README.md)).

```bash
cd ~/talonsoclab/deploy/soc-recon
sudo install -m 0644 apparmor/soc-recon-* /etc/apparmor.d/   # rebuilt box only
sudo apparmor_parser -r /etc/apparmor.d/soc-recon-*          # rebuilt box only
bin/tier2-start
docker compose logs wazuh.manager | grep '0-wazuh-init: exited'     # want exited 0
```

`bin/tier2-start` runs `docker compose up -d --force-recreate --pull never` only when all four
volumes carry the record's token. After a restore cut off from the box, it refuses and names the
half-filled volumes and their holders: `docker rm -f` the holders, `docker volume rm` the
volumes, then restore again. **Never start a restored stack with plain `docker compose up`:** it
adopts any volume with compose's labels, finished or not.

Carry on with PHOENIX. The vulnerability dashboard stays empty until `vd` refetches.

### Why it looks the way it does

Encryption happens on the box with only the public key there, so the drive, the network and the
Mac's disk see only ciphertext. The marker means a restorable copy exists, so every run verifies
before moving it. gzip keeps `tar -tzf` as the check everywhere, and reading the volume,
not compressing it, is the bottleneck. Stamps are UTC `<YYYY-MM-DD>T<HHMMSS>Z`, so runs never
collide and sort in time order.

### Known gaps

- **Downtime.** A run stops the stack for 3 to 4 minutes. Agents buffer and resend.
- **One site.** The drive and the Mac protect against the box dying, not the house.
- **A probe that never runs raises nothing.** Only the missing daily 100320 shows it.
- **The marker** is as trustworthy as the login user, whose docker group is root on the box, and
  a `git clean -x` deletes it.
- **Root on the Mac** can read both keys, forge a seal and decrypt every archive. Guard the Mac
  account.
- **The seal proves origin, not freshness.** The restore warns when `tier2-sealed.log` has no
  record of the seal or names a newer stamp.
- **Drive ownership.** Check `mount` shows no `noowners`. To turn ownership on, run
  `sudo diskutil enableOwnership /Volumes/<drive>`.
- **A touch or chmod on a single-file bind** refuses every backup until its service restarts.
- **Only single-file binds are compared** for the indexer and dashboard.
- **One Mac run at a time.** SIGKILL leaves `~/.config/talon/tier2-backup.lock`; `rmdir` clears it.
- **Config file names** must not contain a tab, a newline or a backslash.
- **Manual runs.** The 7-day alert is the reminder.

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
