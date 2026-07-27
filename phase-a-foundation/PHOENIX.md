# PHOENIX — TalonSocLab recovery runbook

> **What this is:** the runbook that earns its keep when the box dies, gets reimaged, or a
> `docker compose down -v` nukes the volumes. Every TalonSocLab artifact must survive a total
> box loss through one of three tiers.
>
> **Target rebuild time:** ≤ 1 hour from git + volume snapshots; ≤ 2 hours from git alone.

---

## Three tiers

### Tier 1 — Source of truth in git

Everything that *describes* how the lab is built lives in this repo. The blueprint to rebuild
from scratch: `deploy/soc-recon/` (compose stack, configs, ISM policy, agent group config),
`phase-a-foundation/` (architecture, runbooks).

**Cadence:** end of every build session.

### Tier 2 — Docker volume snapshots on the external drive

Named-volume tarballs, so a known-good Wazuh state restores without re-enrolling everything.

- **Location:** `/Volumes/<drive>/talonsoclab/volumes/YYYY-MM-DD/`
- **Cadence:** after any session that flips an acceptance box; before any risky change
- **Retention:** keep the last 3

```bash
# On the box. Stop the stack first so tarballs are consistent -- ~1 min downtime.
# DATE is UTC on purpose (see Findings).
DATE=$(date -u +%Y-%m-%d); mkdir -p ~/vol-snap
cd ~/talonsoclab/deploy/soc-recon && docker compose stop

QUEUE_EXCLUDES="--exclude=./vd --exclude=./vd_updater --exclude=./indexer --exclude=./harvester"

for v in soc-recon_indexer_data soc-recon_wazuh_etc soc-recon_wazuh_queue soc-recon_wazuh_api_configuration; do
  EX=""; [ "$v" = "soc-recon_wazuh_queue" ] && EX="$QUEUE_EXCLUDES"
  docker run --rm -v "$v":/from -v ~/vol-snap:/to alpine \
    tar czf "/to/${v}_${DATE}.tar.gz" -C /from $EX .
done
docker compose start

# Verify before trusting. A tarball that won't list is not a backup.
for f in ~/vol-snap/*_${DATE}.tar.gz; do tar -tzf "$f" >/dev/null && echo "OK $f"; done
```

Then from the Mac, using the **same UTC date** for the directory:

```bash
DATE=$(TZ=UTC date +%Y-%m-%d)
mkdir -p "/Volumes/<drive>/talonsoclab/volumes/$DATE"
rsync -avh talonsoc:"~/vol-snap/*_$DATE.tar.gz" "/Volumes/<drive>/talonsoclab/volumes/$DATE/"

# local-only docs are gitignored, so Tier 1 does not cover them
rsync -avh ~/talonsoclab/internal/ "/Volumes/<drive>/talonsoclab/internal/"
```

`tar: ./alerts/execq: socket ignored` is expected and harmless.

### Tier 3 — Secrets in a password manager

The `.env` passwords (indexer, dashboard, API), the agent enrollment password, and any Phase D
API keys. **Never** in the repo, never baked into images.

> Losing these means a full credential reset, not a restore. The live indexer credentials live
> in the `.opendistro_security` index inside the `indexer_data` volume, and the bcrypt hashes in
> `internal_users.yml` are one-way. A Tier 2 snapshot restores the *hashes*, never the passwords.

---

## The Phoenix sequence

**Stage 0 — rebuild the host (20 min).** Ubuntu Server, `vm.max_map_count`, Docker, UFW. See
[`runbooks/00-host-ubuntu-docker.md`](runbooks/00-host-ubuntu-docker.md).

**Stage 1 — restore the repo (5 min).** Clone, then restore the gitignored files from Tier 3:
`.env`, `internal_users.yml` (regenerate both hashes from the password manager and re-run
`securityadmin` — leaving the `.example` hashes in place means running Wazuh's **published demo
credentials**), and `wazuh/authd.pass`. Generate certs, then:

```bash
# the generator writes a root-owned 0500 dir container UIDs cannot read
sudo chmod 755 config/wazuh_indexer_ssl_certs && sudo chmod 644 config/wazuh_indexer_ssl_certs/*
```

**Stage 2 — restore state, or start clean (10–30 min).** Restore the Tier 2 tarballs into fresh
volumes, or `docker compose up -d` for a clean start and re-enroll.

**Either path — re-apply the two things that live only inside volumes.** Neither errors when
missing; they just silently don't work.

```bash
# 1. ISM retention -- see deploy/soc-recon/wazuh/ism/README.md
#    Without it the NVMe fills and takes the indexer down.

# 2. Shared agent-group ownership. The entrypoint creates group dirs root:root,
#    but wazuh-remoted (user `wazuh`) must write merged.mg there or agents
#    receive nothing. One-time per volume lifetime.
for g in phase-a-windows; do
  docker compose exec wazuh.manager chown -R wazuh:wazuh "/var/ossec/etc/shared/$g"
done
docker compose exec wazuh.manager ls -la /var/ossec/etc/shared/phase-a-windows/   # want merged.mg
```

**Stage 3 — re-enroll endpoints (15 min).** Point the agents at the manager, confirm all show
`Active`. See [`runbooks/04-windows-agent-sysmon.md`](runbooks/04-windows-agent-sysmon.md).

**Stage 4 — re-validate acceptance (15 min).** Walk the acceptance boxes in each runbook.

## Failure modes

| Failure | Cause | Escape hatch |
|---|---|---|
| Indexer won't start | `vm.max_map_count` not set after reimage | `sysctl -w vm.max_map_count=262144` |
| Indexer won't start | cert dir left root-owned `0500` | the `chmod` in Stage 1 |
| Agents enroll but get no config | group dir owned `root:root`, no `merged.mg` | the `chown` in Stage 2 |
| Dashboard red after restore | indexer volume corruption | clean start; re-import dashboards |
| Agents won't enroll | UFW dropped `1514/1515` | re-apply Stage 0 firewall rules |
| Disk full mid-rebuild | indices restored without retention | re-apply ISM policy; prune old indices |

---

## Findings

**Most of what was being backed up was re-downloadable.** `/var/ossec/queue/vd` is the
Vulnerability Detection CVE database — **12 GB on disk**. It dominated every snapshot: the
`wazuh_queue` tarball was 819 MB *with zero agents enrolled*, and 1.3 GB after the first agent.
Excluding it and three transient directories takes that tarball to **5.5 MB**, and the whole
snapshot set from ~1.3 GB to ~7.7 MB.

| Excluded | On disk | Why |
|---|---|---|
| `vd` | 12 G | Refetched from Wazuh CTI on start. A restored copy is *stale* — worse than refetching. |
| `vd_updater` | 40 M | Updater working state |
| `indexer` | 264 M | Spool of documents pending write; restoring it replays stale docs |
| `harvester` | 75 M | Transient collection buffer |

What remains is ~31 MB of actual state: `db`, `rids`, `fim`, `syscollector`, `keystore`,
`tasks`. Restore consequence: the vulnerability dashboard is empty for the first few minutes
while the database rebuilds. That's the correct trade for a runbook targeting a one-hour
recovery.

**Snapshot dates must be UTC.** The box runs UTC and the workstation runs local time, so plain
`date` disagrees for several hours a day. It had already happened silently: a `volumes/07-25/`
directory holding tarballs named `_07-26`, because the directory was created workstation-side
and the tarballs box-side. UTC also matches index naming, which is what a restore correlates
against.

**Nothing verified the backups.** The original procedure created tarballs and never listed one.
A `tar -tzf` loop is one line and turns "files exist" into "files are readable archives."

**A backup story has to cover the gitignored files too.** Tier 1 protects everything in git by
definition, which makes it easy to forget that the local-only notes and `.env` are outside it.
Those are exactly the files whose loss is unrecoverable rather than merely inconvenient.
