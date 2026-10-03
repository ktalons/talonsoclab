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
bin/idx                  indexer API helper: admin client certificate (--cacert/--cert/--key), never a password in argv
systemd/                 Suricata log rotation and daily ET Open updates: host timers plus the scripts they run, installed root-owned
recon/                   subfinder + httpx + nuclei + diff, one slim image (not deployed)
scope/                   in-scope targets (domains.txt is gitignored)
triage/                  human-review queue (not deployed)
digest/                  daily digest + CASA intake builder (not deployed)
wazuh/ism/               retention policy (version-controlled on purpose)
wazuh/shared/            per-group agent config pushed to endpoints
wazuh/custom-rules/      local Suricata tuning rules (live); Sigma-converted XML lands here in Phase B
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
