# PHOENIX — TalonSocLab Recovery Runbook (docker edition)

> **What this is:** the runbook that earns its keep when the EliteDesk dies, gets
> reimaged, or a `docker compose down -v` nukes the volumes. Every TalonSocLab artifact
> must survive a total box loss through one of three tiers.
>
> **Target rebuild time:** ≤ 1 hour from git + volume snapshots; ≤ 2 hours from git alone.
>
> **What changed from the Proxmox edition** ([archived](archive-proxmox/PHOENIX.md)): the box
> is now **owned**, so this is recovery from *my* hardware failure, not a shared-host wipe I
> can't predict. Substrate is Ubuntu + Docker, so Tier 2 is docker-volume snapshots, not vzdump.

---

## Defense-in-depth, three tiers

### Tier 1 — Source of truth in git
Everything that *describes* how the lab is built lives in this repo, pushed to
`github.com/ktalons/talonsoclab`. The blueprint to rebuild from scratch.

- `phase-a-foundation/architecture.mmd` — container topology, single source of truth
- `phase-a-foundation/README.md` — the deployment outline
- `deploy/soc-recon/` — the compose stack, Dockerfile, recon + digest, `.env.example`
- `deploy/soc-recon/wazuh/custom-rules/` — Sigma-converted detection content (Phase B+)

**Cadence:** end of every build session, `git add . && git commit && git push`.

### Tier 2 — Docker volume snapshots on the external drive
Named-volume tarballs so a known-good Wazuh state restores without re-enrolling everything.

- **Location:** `/Volumes/MacbookXD/talonsoclab/volumes/YYYY-MM-DD/`
- **Cadence:** after every session that flips an acceptance box; before any risky change.
- **Retention:** keep last 3 snapshots; delete older to manage disk.

```bash
# On the EliteDesk — snapshot the stateful Wazuh volumes.
# (manager state is split across etc/queue/api volumes — there is no "manager_data")
# Stop the stack first so the tarballs are consistent; ~1 min of downtime.
# DATE is UTC on purpose — see "Date convention" below.
DATE=$(date -u +%Y-%m-%d); mkdir -p ~/vol-snap
cd ~/talonsoclab/deploy/soc-recon && docker compose stop

# wazuh_queue needs exclusions — see "What NOT to snapshot" below.
QUEUE_EXCLUDES="--exclude=./vd --exclude=./vd_updater --exclude=./indexer --exclude=./harvester"

for v in soc-recon_indexer_data soc-recon_wazuh_etc soc-recon_wazuh_queue soc-recon_wazuh_api_configuration; do
  EX=""; [ "$v" = "soc-recon_wazuh_queue" ] && EX="$QUEUE_EXCLUDES"
  docker run --rm -v "$v":/from -v ~/vol-snap:/to alpine \
    tar czf "/to/${v}_${DATE}.tar.gz" -C /from $EX .
done
docker compose start

# Verify before trusting. A tarball that won't list is not a backup.
for f in ~/vol-snap/*_${DATE}.tar.gz; do tar -tzf "$f" >/dev/null && echo "OK $f"; done
# Then rsync ~/vol-snap/*_$DATE.tar.gz to /Volumes/MacbookXD/talonsoclab/volumes/$DATE/ from the Mac,
# using the SAME UTC date for the directory name.
```

> `tar: ./alerts/execq: socket ignored` is expected and harmless — those are Unix domain
> sockets in the alerts queue, not data.

#### What NOT to snapshot (found 2026-07-27)

`/var/ossec/queue/vd` is the **Vulnerability Detection CVE database — 12 GB on disk**, and it
dominated every snapshot taken before this was caught: the `wazuh_queue` tarball was 819 MB with
*zero agents enrolled*, and 1.3 GB after A.1. Excluding the four directories below takes it to
**5.5 MB**, and the whole snapshot set from ~1.3 GB to ~7.7 MB.

| Excluded | Size on disk | Why |
|---|---|---|
| `vd` | 12 G | CVE database, re-downloaded from Wazuh CTI on start. A restored copy is *stale* — worse than refetching. |
| `vd_updater` | 40 M | Updater working state for the above |
| `indexer` | 264 M | Spool of documents pending write to the indexer — transient; restoring it replays stale docs |
| `harvester` | 75 M | Transient collection buffer |

What remains is the state that actually matters, ~31 MB total: `db` (agent databases), `rids`
(agent counters — needed so agents aren't seen as replaying), `fim` (file-integrity baselines),
`syscollector`, `keystore`, `tasks`.

**Restore consequence:** the vulnerability database rebuilds itself on first start. Expect the
vulnerability dashboard to be empty for the first several minutes after a Phoenix restore. That is
the correct trade — 12 GB of re-fetchable reference data does not belong in a backup set whose
whole purpose is fast recovery.

#### Date convention

**Use UTC (`date -u`) for both the tarball names and the directory name.** The box runs UTC while
the Mac runs MST, so `date +%Y-%m-%d` on each gives different answers for ~7 hours a day. That
already bit us: `volumes/2026-07-25/` contains tarballs named `..._2026-07-26.tar.gz`, because the
directory was created Mac-side and the tarballs box-side. UTC also matches the index naming
(`wazuh-alerts-4.x-2026.07.27`), which is what you'd be correlating against during a restore.

### Tier 3 — Secrets in password manager
- Wazuh `admin`, `kyle-admin`, `kyle-analyst` passwords; `WAZUH_INDEXER_PASS` for the digest
- `WAZUH_DASHBOARD_PASS` (kibanaserver) and `WAZUH_API_PASS` (wazuh-wui) — all three `.env`
  passwords, since `.env` is gitignored and nothing else holds them
- Any API keys (AbuseIPDB, VirusTotal — Phase D)

> Losing these means a full credential reset, not just a restore: the live indexer
> credentials live in the `.opendistro_security` index inside the `indexer_data` volume,
> and the bcrypt hashes in `internal_users.yml` are one-way. A Tier 2 snapshot restores
> the *hashes*, never the passwords.

**Never** in repo. **Never** baked into images. `.env` is gitignored; the password manager
is the only authority.

---

## The Phoenix sequence (when the box is gone or wiped)

### Stage 0 — Rebuild the host (20 min)
1. Install Ubuntu Server LTS (26.04 as of 2026-07) on the EliteDesk (see `runbooks/00-host-ubuntu-docker.md`).
2. `sudo sysctl -w vm.max_map_count=262144` and persist it in `/etc/sysctl.conf`.
3. Install Docker Engine + the compose plugin; add your user to the `docker` group.
4. UFW: allow `443/1514/1515/55000` from the LAN, SSH key-only, deny the rest inbound.

### Stage 1 — Restore the repo (5 min)
```bash
git clone https://github.com/ktalons/talonsoclab.git ~/talonsoclab
cd ~/talonsoclab/deploy/soc-recon
cp .env.example .env        # set WAZUH_VERSION, INDEXER_HEAP, WAZUH_INDEXER_PASS (from pw manager)
# internal_users.yml is gitignored (it holds real bcrypt hashes). Restore it:
cp config/wazuh_indexer/internal_users.yml.example config/wazuh_indexer/internal_users.yml
# then regenerate both hashes from the password-manager passwords and re-run
# securityadmin — see deploy/soc-recon/wazuh/SECURITY.md. Leaving the .example
# hashes in place means running Wazuh's PUBLISHED demo credentials.
cp scope/domains.txt.example scope/domains.txt
mkdir -p data && sudo chown -R 10001 data
docker compose -f generate-indexer-certs.yml run --rm generator
# generator writes a root-owned 500 dir — container uids can't read it without this:
sudo chmod 755 config/wazuh_indexer_ssl_certs && sudo chmod 644 config/wazuh_indexer_ssl_certs/*
```

### Stage 2 — Restore state, or start clean (10–30 min)
**Path A — restore from Tier 2 snapshot (fast, keeps history):**
```bash
for v in soc-recon_indexer_data soc-recon_wazuh_etc soc-recon_wazuh_queue soc-recon_wazuh_api_configuration; do
  docker volume create "$v"
  docker run --rm -v "$v":/to -v /Volumes/MacbookXD/talonsoclab/volumes/<DATE>:/from alpine \
    sh -c "tar xzf /from/${v}_<DATE>.tar.gz -C /to"
done
docker compose up -d
```
**Path B — fresh start (no snapshot / corrupted volume):**
```bash
docker compose up -d        # clean Wazuh; re-import dashboards from configs/, re-enroll agents
```

**Either path — re-apply the two things that live only inside volumes.** Both were found the
hard way during the Phase 0.5 rebuild; neither errors when missing, they just silently don't work.

```bash
# 1. ISM retention — see deploy/soc-recon/wazuh/ism/README.md
#    Without it the 256 GB NVMe fills and takes the indexer down.

# 2. Shared agent-group ownership. The entrypoint creates group dirs as root:root,
#    but wazuh-remoted (user `wazuh`) must write merged.mg there or agents never
#    receive their group config. One-time per volume lifetime.
for g in phase-a-windows; do
  docker compose exec wazuh.manager chown -R wazuh:wazuh "/var/ossec/etc/shared/$g"
  docker compose exec wazuh.manager chmod 770 "/var/ossec/etc/shared/$g"
done
docker compose exec wazuh.manager ls -la /var/ossec/etc/shared/phase-a-windows/  # want merged.mg
```

### Stage 3 — Re-enroll endpoints (15 min)
Reinstall / re-point the Wazuh agents on the Windows box, Mac, and host at the manager
(`<host-ip>:1514`, enroll on `:1515`). Confirm all three show `active` in the inventory.

### Stage 4 — Re-validate acceptance (15 min)
Walk the acceptance boxes in [`README.md`](README.md). Confirm dashboard green, agents active,
Suricata events flowing, retention policy re-applied.

### Stage 5 — Resume (5 min)
```bash
git commit -m "phoenix: recovered from box loss YYYY-MM-DD" --allow-empty && git push
```
Carry on with whatever phase you were in.

---

## Failure modes and escape hatches

| Failure | Cause | Escape hatch |
|---|---|---|
| Indexer won't start | `vm.max_map_count` not set after reimage | `sysctl -w vm.max_map_count=262144` |
| Dashboard red after restore | indexer volume corruption | Path B fresh start; re-import dashboards from `configs/` |
| Agents won't enroll | UFW dropped `1514/1515` | re-apply firewall rules from Stage 0 |
| Disk full mid-rebuild | indices restored without retention | re-apply ISM policy; prune old indices |
| Repo unreachable | GitHub down | local clones on Mac + the box; volume snapshots also carry `/etc` state |

## What this runbook does NOT cover

- **Phase D honeynet / OpenCTI** — runs in cloud, not on this box; its own backup story lives
  in `phase-d-intel/` when it ships.
- **CASA** — a separate repo (`casa-ai-agent`) with its own recovery; TalonSocLab only needs
  to keep emitting clean intake artifacts.
