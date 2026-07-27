# soc-recon

The compose stack. Two workloads on one 16 GB box, unequal priority:

- **Wazuh SOC stack** — always-on, memory reservation + OOM protection.
- **Recon pipeline** — cron-launched, ephemeral, hard memory cap. Yields to Wazuh.

Endpoints are Wazuh agents on real devices, so no endpoint VMs run here and the RAM budget
stays clear. Recon points at my own assets only.

## Layout

```
docker-compose.yml       resource limits, recon profile, indexer healthcheck
.env.example             WAZUH_VERSION, INDEXER_HEAP, passwords, digest config
recon/                   subfinder + httpx + nuclei + diff, one slim image
scope/                   in-scope targets (domains.txt is gitignored)
triage/                  human-review queue
digest/                  daily digest + CASA intake builder
wazuh/ism/               retention policy (version-controlled on purpose)
wazuh/shared/            per-group agent config pushed to endpoints
wazuh/custom-rules/      Sigma-converted rule XML (Phase B)
```

## Resource budget

| Service | heap | reservation | hard cap |
|---|---|---|---|
| wazuh.indexer | 2g | 2g | 4g |
| wazuh.manager | — | 1g | 1.5g |
| wazuh.dashboard | — | 512m | 1g |
| recon-runner | — | — | 2g |

Always-on ≈ 6.5 GB + ~1.5 GB OS, leaving ~8 GB headroom. Raise `INDEXER_HEAP` only after a RAM
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
docker compose run --rm recon-runner              # recon, one-shot; this is what cron runs
python3 digest/generate_digest.py                 # daily digest + CASA intake
```

Host prerequisite: `vm.max_map_count=262144`.

Nothing auto-submits anywhere. Recon writes deltas to `triage/`; the digest collects and cites.
You review and decide.

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
