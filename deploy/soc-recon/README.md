# soc-recon

The compose stack. Two workloads on one 16 GB box, unequal priority:

- **Wazuh SOC stack:** always-on, memory reservation + OOM protection.
- **Suricata sensor:** always-on on the host network, protected, but killed before Wazuh
  under memory pressure.

Endpoints are Wazuh agents on real devices, so no endpoint VMs run here and the RAM budget
stays clear. The name is historical: an attack-surface recon pipeline was planned for this
box and never deployed, and its plan now lives outside the public repo.

## Layout

```
docker-compose.yml       resource limits, indexer healthcheck
.env.example             WAZUH_VERSION, INDEXER_HEAP, passwords
generate-indexer-certs.yml  one-shot TLS cert generator, run once before the first `up`
bin/idx                  indexer API helper: admin client certificate (--cacert/--cert/--key), never a password in argv
bin/tier2-snapshot       stops the stack and archives its four state volumes through age (runbook 09; run by tools/tier2-backup.sh)
bin/tier2-start          starts the stack after tools/tier2-restore.sh, only on a finished restore's volumes (runbook 09 section 4)
config/                  indexer, dashboard and manager config; *.example templates for the two gitignored secret files
systemd/                 host timers plus the scripts they run, installed root-owned: Suricata log rotation, daily ET Open
                         updates, manager log retention (runbook 08), and the OnFailure handler that makes a failed run alert
state/tier2/             the Tier 2 backup marker, read-only to the manager at /srv/tier2 (the marker itself is gitignored)
tier2.recipient.example  the age public key Tier 2 archives are encrypted to (tier2.recipient is gitignored)
apparmor/                one AppArmor profile per service, a copy of docker-default under the service's name (apparmor/README.md)
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

Always-on hard ceiling ≈ 8.5 GB + ~1.5 GB OS. Suricata's cap is sized for the
nightly rule update, not the idle engine: see the `mem_limit` comment in `docker-compose.yml`. Raise `INDEXER_HEAP` only after a RAM
upgrade. **Disk is the tighter limit** — see [`wazuh/ism/`](wazuh/ism/).

## Run

```bash
cp .env.example .env                              # set version, heap, passwords
# gitignored files compose bind-mounts, from their tracked templates (see below)
cp config/wazuh_indexer/internal_users.yml.example config/wazuh_indexer/internal_users.yml
cp config/wazuh_dashboard/wazuh.yml.example config/wazuh_dashboard/wazuh.yml
cp wazuh/authd.pass.example wazuh/authd.pass
cp tier2.recipient.example tier2.recipient      # a public key; runbook 09 section 1

# certs, once
docker compose -f generate-indexer-certs.yml run --rm generator
sudo chmod 755 config/wazuh_indexer_ssl_certs && sudo chmod 644 config/wazuh_indexer_ssl_certs/*

# AppArmor profiles, before the first up and after any change to apparmor/
sudo install -m 0644 apparmor/soc-recon-* /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/soc-recon-*

docker compose up -d                              # dashboard at https://<host>
```

Host prerequisites: `vm.max_map_count=262144`, and the four AppArmor profiles in
[`apparmor/`](apparmor/) loaded. A service whose profile is not loaded does not start. The
noise suppressions name those profiles. Loading a profile changes nothing by itself. On a
running stack, the label each container runs under and the rules that name it change
together, in one bare `docker compose up -d --force-recreate`
([`apparmor/README.md`](apparmor/README.md)).

Compose refuses to start unless `.env` sets all three passwords (`WAZUH_INDEXER_PASS`,
`WAZUH_DASHBOARD_PASS`, `WAZUH_API_PASS`). The three copied files hold the demo hashes, the demo
API password and a placeholder enrollment password. Replace them before the box is reachable:
[`wazuh/SECURITY.md`](wazuh/SECURITY.md) has the steps for each.

## Credentials

`.env.example` ships Wazuh's **published** demo passwords. Change them before this box is
reachable from anywhere it shouldn't be. The change is two-sided — new values in `.env`, plus
regenerated bcrypt hashes applied with `securityadmin.sh`. Procedure in
[`wazuh/SECURITY.md`](wazuh/SECURITY.md).

## CASA

This bundle is the **data plane**: it collects, stores and alerts, and it does not analyze.
**[CASA](https://github.com/ktalons/casa-ai-agent)** is the separate reasoning plane. Its
`--alerts-file` offline mode is the eval harness: feed it recorded attack data and measure its
reasoning against ground truth. The handoff from this stack to CASA is not built yet.
