# Phase 0.5 — Wazuh 4.9.2 → 4.14.6 (clean rebuild)

> **What this does:** moves the central stack (manager, indexer, dashboard) from 4.9.2 to
> 4.14.6. Nothing was enrolled yet and no detections had been written, so this is a **clean
> rebuild** — volumes destroyed and recreated rather than migrated.
>
> **Why it matters for a SOC:** the manager must always be at or above the version of every
> agent reporting to it. Doing this *before* Phase A enrollment sets the version floor once, at
> the top. Do it after enrolling Windows, macOS and the host, and all three have to be
> re-touched. This is the cheapest possible moment.
>
> Steps are tagged **[MAC]** = repo work, **[BOX]** = SOC host over SSH.
>
> **Completed 2026-07-25.** Every change was diffed against
> [`wazuh/wazuh-docker` at `v4.14.6`](https://github.com/wazuh/wazuh-docker/tree/v4.14.6/single-node),
> not inferred from docs.

---

## 0. Why a clean rebuild

The documented Docker upgrade path keeps the volumes and lets OpenSearch migrate index metadata
forward. That's right when you have data. Here the indexer held about two weeks of alerts the
manager generated **about itself** — no agent telemetry, because no agent had ever enrolled.

So the trade was: carry OpenSearch index metadata across five minor versions in one jump (the
single most likely thing to break) in exchange for keeping data with no value. Clean rebuild
removes that risk for a cost of zero.

**This is not a version bump.** Between 4.9 and 4.14 the indexer's config root moved from
`/usr/share/wazuh-indexer/` to `/usr/share/wazuh-indexer/config/`. Changing `WAZUH_VERSION`
alone leaves the 4.14 indexer unable to find its certs or `opensearch.yml`, and it fails to
start rather than degrade. Seven mount paths and six config paths move with it — and those
edits are required whether or not you keep the volumes.

## 1. Pre-flight — [BOX]

Confirm the assumption the plan rests on. If anything other than agent `000` comes back, stop
and re-plan.

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/agents?select=id,name,version,status" | jq '.data.affected_items'
```

Then take a volume snapshot. `down -v` qualifies as a risky change. It isn't protecting the
data — we chose the rebuild because the volumes hold nothing of value — it's protecting the
**rollback path**.

## 2. The change set — [MAC]

| File | Change |
|---|---|
| `docker-compose.yml` | 3 image tags → `4.14.6`; **7 indexer mount paths** gain `/config` |
| `config/wazuh_indexer/wazuh.indexer.yml` | 6 `pemcert_filepath` paths gain `/config`; adds `cluster.name`, ECDHE cipher allowlist, TLS protocol pin |
| `generate-indexer-certs.yml` | generator `0.0.2` → `0.0.4`; adds `CERT_TOOL_VERSION=4.14` |
| `config/wazuh_dashboard/opensearch_dashboards.yml` | 15-min session + cookie TTL with keepalive |
| `config/wazuh_cluster/wazuh_manager.conf` | syscollector `<ports all>` → `yes`; adds 3 malicious-IOC CDB lists |
| `.env` *(untracked)* | `WAZUH_VERSION` → `4.14.6` |

The **malicious-IOC lists** (`malicious-ip`, `malicious-domains`, `malware-hashes`) are new in
4.14 and a real detection gain, not housekeeping. CDB lists are Wazuh's O(1) lookup structure
for matching field values against large sets, so they give IOC matching on every event with no
rule authoring.

## 3. Execute — [BOX]

```bash
cd ~/talonsoclab/deploy/soc-recon && git pull
sed -i 's/^WAZUH_VERSION=.*/WAZUH_VERSION=4.14.6/' .env

docker compose down -v

# the cert tool will NOT overwrite an existing set
rm -rf config/wazuh_indexer_ssl_certs/*
docker compose -f generate-indexer-certs.yml run --rm generator

# REQUIRED — generator writes a root-owned 0500 dir container UIDs cannot traverse
sudo chmod 755 config/wazuh_indexer_ssl_certs
sudo chmod 644 config/wazuh_indexer_ssl_certs/*

docker compose pull && docker compose up -d
```

The indexer takes noticeably longer than 4.9 on first boot — it initialises the security index
from scratch. Healthcheck `start_period` is 120s; give it that.

## 4. Verify — [BOX]

> **Indexer API calls must run inside a container.** `9200` is not host-published by design, so
> `curl https://localhost:9200` from the host reaches nothing — and with `-s` it fails
> *silently*, which reads as an empty result rather than an error.

```bash
docker compose ps
docker compose exec -T wazuh.indexer curl -sk -u admin:"$PASS" https://localhost:9200/_cluster/health
docker compose exec wazuh.manager /var/ossec/bin/wazuh-control status
docker compose exec wazuh.manager filebeat test output
curl -skI https://localhost:443 | head -1
```

## Acceptance — Phase 0.5

- [x] 3/3 containers up, indexer `(healthy)`, all images `:4.14.6`
- [x] `_cluster/health` returns yellow over TLS — **correct** single-node (the 3 unassigned
      shards are replicas, which cannot be placed on the same node as their primaries)
- [x] `wazuh-control status` — 10 daemons running
- [x] `filebeat test output` — handshake OK (TLS **1.2** now, not 1.3)
- [x] Dashboard 443 login OK; API card reads Online v4.14.6
- [x] Indexer `:9200` still not host-published
- [x] ISM retention policy re-applied and **version-controlled**

Next: [`03-windows-ssh-access.md`](03-windows-ssh-access.md).
