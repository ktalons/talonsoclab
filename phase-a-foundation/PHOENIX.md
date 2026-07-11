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
# On the EliteDesk — snapshot the always-on Wazuh volumes:
DATE=$(date +%Y-%m-%d); mkdir -p ~/vol-snap
for v in soc-recon_indexer_data soc-recon_manager_data; do
  docker run --rm -v "$v":/from -v ~/vol-snap:/to alpine \
    tar czf "/to/${v}_${DATE}.tar.gz" -C /from .
done
# Then copy ~/vol-snap/*.tar.gz to /Volumes/MacbookXD/talonsoclab/volumes/$DATE/ (scp/rsync).
```

### Tier 3 — Secrets in password manager
- Wazuh `admin`, `kyle-admin`, `kyle-analyst` passwords; `WAZUH_INDEXER_PASS` for the digest
- Any API keys (AbuseIPDB, VirusTotal — Phase D)

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
cp scope/domains.txt.example scope/domains.txt
mkdir -p data && sudo chown -R 10001 data
```

### Stage 2 — Restore state, or start clean (10–30 min)
**Path A — restore from Tier 2 snapshot (fast, keeps history):**
```bash
for v in soc-recon_indexer_data soc-recon_manager_data; do
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
