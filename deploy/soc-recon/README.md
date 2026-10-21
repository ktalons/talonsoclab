# soc-recon

The compose stack. Three workloads on one 16 GB box, unequal priority:

- **Wazuh SOC stack:** always-on, memory reservation + OOM protection.
- **Suricata sensor:** always-on on the host network, protected, but killed before Wazuh
  under memory pressure.
- **Recon pipeline:** cron-launched, ephemeral, hard memory cap. Yields to Wazuh. Not
  deployed yet; the compose service and cron entry are the plan.

Endpoints are Wazuh agents on real devices, so no endpoint VMs run here and the RAM budget
stays clear. Recon points at my own assets only.

## Layout

```
docker-compose.yml       resource limits, recon profile, indexer healthcheck
.env.example             WAZUH_VERSION, INDEXER_HEAP, passwords, digest config
generate-indexer-certs.yml  one-shot TLS cert generator, run once before the first `up`
crontab.example          planned schedule for the recon run and the digest (not installed)
recon_pipeline_architecture.png  diagram of the recon pipeline
bin/idx                  indexer API helper: admin client certificate (--cacert/--cert/--key), never a password in argv
bin/tier2-snapshot       stops the stack and archives its four state volumes through age (runbook 09; run by tools/tier2-backup.sh)
bin/tier2-start          starts the stack after tools/tier2-restore.sh, only on a finished restore's volumes (runbook 09 section 4)
config/                  indexer, dashboard and manager config; *.example templates for the two gitignored secret files
systemd/                 host timers plus the scripts they run, installed root-owned: Suricata log rotation, daily ET Open
                         updates, manager log retention (runbook 08), and the OnFailure handler that makes a failed run alert
recon/                   subfinder + httpx + nuclei + diff, one slim image (not deployed)
scope/                   in-scope targets (domains.txt is gitignored)
state/tier2/             the Tier 2 backup marker, read-only to the manager at /srv/tier2 (the marker itself is gitignored)
tier2.recipient.example  the age public key Tier 2 archives are encrypted to (tier2.recipient is gitignored)
triage/                  human-review queue (not deployed)
digest/                  daily digest + CASA intake builder (not deployed)
wazuh/SECURITY.md        credential rotation and keeping secrets out of argv
wazuh/authd.pass.example placeholder for the agent enrollment password (wazuh/authd.pass is gitignored)
wazuh/audit/             auditd execve rules for phase-a-linux endpoints
wazuh/cont-init/         filebeat init override that keeps the indexer password out of argv
wazuh/ism/               retention policy (version-controlled on purpose)
wazuh/shared/            per-group agent config pushed to endpoints
wazuh/custom-rules/      local Suricata tuning, job age and Tier 2 age rules (live); Sigma-converted XML lands here in Phase B
wazuh/probes/            the probes the manager runs: hourly job age (runbook 06, section 6), daily Tier 2 backup age (runbook 09)
```

## Resource budget

| Service | heap | reservation | hard cap |
|---|---|---|---|
| wazuh.indexer | 2g | 2g | 4g |
| wazuh.manager | — | 1g | 1.5g |
| wazuh.dashboard | — | 512m | 1g |
| suricata | — | 512m | 2g |
| recon-runner | — | — | 2g |

Always-on hard ceiling ≈ 8.5 GB + ~1.5 GB OS, leaving headroom for the 2 GB recon burst. Suricata's cap is sized for the
nightly rule update, not the idle engine: see the `mem_limit` comment in `docker-compose.yml`. Raise `INDEXER_HEAP` only after a RAM
upgrade. **Disk is the tighter limit** — see [`wazuh/ism/`](wazuh/ism/).

## Run

```bash
cp .env.example .env                              # set version, heap, passwords
cp scope/domains.txt.example scope/domains.txt    # your own assets only
# gitignored files compose bind-mounts, from their tracked templates (see below)
cp config/wazuh_indexer/internal_users.yml.example config/wazuh_indexer/internal_users.yml
cp config/wazuh_dashboard/wazuh.yml.example config/wazuh_dashboard/wazuh.yml
cp wazuh/authd.pass.example wazuh/authd.pass
cp tier2.recipient.example tier2.recipient      # a public key; runbook 09 section 1
mkdir -p data && chown -R 10001 data

# certs, once
docker compose -f generate-indexer-certs.yml run --rm generator
sudo chmod 755 config/wazuh_indexer_ssl_certs && sudo chmod 644 config/wazuh_indexer_ssl_certs/*

docker compose up -d                              # dashboard at https://<host>

# Planned, not deployed: the recon run and the digest. crontab.example has the schedule.
docker compose run --rm recon-runner              # recon, one-shot
python3 digest/generate_digest.py                 # daily digest + CASA intake
```

Host prerequisite: `vm.max_map_count=262144`.

Compose refuses to start unless `.env` sets all three passwords (`WAZUH_INDEXER_PASS`,
`WAZUH_DASHBOARD_PASS`, `WAZUH_API_PASS`). The three copied files hold the demo hashes, the demo
API password and a placeholder enrollment password. Replace them before the box is reachable:
[`wazuh/SECURITY.md`](wazuh/SECURITY.md) has the steps for each.

Nothing auto-submits anywhere. Once deployed, recon writes deltas to `triage/` and the digest
collects and cites. You review and decide.

## Credentials

`.env.example` ships Wazuh's **published** demo passwords. Change them before this box is
reachable from anywhere it shouldn't be. The change is two-sided — new values in `.env`, plus
regenerated bcrypt hashes applied with `securityadmin.sh`. Procedure in
[`wazuh/SECURITY.md`](wazuh/SECURITY.md).

## CASA

This bundle is the **data plane** and is deterministic on purpose: it collects, filters, cites,
and emits `digest/{date}-intake.json`. It does not analyze.
**[CASA](https://github.com/ktalons/casa-ai-agent)** is the separate reasoning plane that
consumes that artifact. The `--alerts-file` offline mode is the eval harness: feed CASA recorded
attack data and measure its reasoning against ground truth.
