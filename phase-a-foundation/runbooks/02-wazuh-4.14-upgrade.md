# Phase 0.5 — Wazuh 4.9.2 → 4.14.6 (clean rebuild)

> **What this does:** moves the whole central stack (manager, indexer, dashboard) from
> **4.9.2** to **4.14.6**, the current stable. Because nothing is enrolled yet and no
> detections have been written, this is done as a **clean rebuild** — volumes are destroyed
> and recreated rather than migrated.
>
> **Why it matters for a SOC:** the manager must always be at or above the version of every
> agent that reports to it. Doing this *before* Phase A enrollment means the version floor is
> set once, at the top. Do it after enrolling Windows + macOS + host and every one of those
> endpoints has to be re-touched. This is the cheapest possible moment to take the jump.
>
> **This is not a version bump.** Between 4.9 and 4.14 the indexer's config root moved from
> `/usr/share/wazuh-indexer/` to `/usr/share/wazuh-indexer/config/`. Changing `WAZUH_VERSION`
> alone leaves the 4.14 indexer unable to find its certs or its `opensearch.yml`, and it will
> fail to start rather than degrade. Seven mount paths and six config paths move with it.
>
> Steps are tagged **[MAC]** = local repo work, **[BOX]** = run on the SOC host over SSH.
> Capture real output back into this file as you go — don't trust a step until you've seen it
> succeed.

**Source of truth:** every change below was diffed against
[`wazuh/wazuh-docker` at tag `v4.14.6`](https://github.com/wazuh/wazuh-docker/tree/v4.14.6/single-node),
not inferred from the docs. The upstream single-node deploy is the reference topology this
stack is a resource-tuned fork of.

---

## 0. Why a clean rebuild and not an in-place migration

The [documented Docker upgrade path](https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html)
keeps the volumes and lets OpenSearch migrate its index metadata forward. That's the right
call when you have data. Here the indexer volume holds roughly two weeks of alerts the
manager generated **about itself** — no agent telemetry, because no agent has ever enrolled.

So the trade is: carry OpenSearch index metadata across five minor versions in one jump (the
single most likely thing to break) in exchange for keeping data that has no value. Clean
rebuild removes that risk entirely for a cost of zero.

**The file edits in section 2 are required either way.** They're about the 4.14 image layout,
not about the volumes. The only thing the rebuild decision changes is whether step 3 uses
`down -v` or `down`.

---

## 1. Pre-flight — [BOX]

Confirm the assumption this whole plan rests on. If anything other than agent `000` (the
manager itself) comes back, **stop** and re-plan — enrolled agents change the sequencing.

```bash
cd ~/talonsoclab/deploy/soc-recon

TOKEN=$(curl -sk -u wazuh-wui:"$(grep ^WAZUH_API_PASS .env | cut -d= -f2 | awk '{print $1}')" \
  -X POST https://localhost:55000/security/user/authenticate | jq -r .data.token)

curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/agents?select=id,name,version,status" | jq '.data.affected_items'
```

Then take a **PHOENIX Tier 2 snapshot** ([`PHOENIX.md`](../PHOENIX.md) § Tier 2). Its stated
cadence is "before any risky change," and `down -v` qualifies.

Be clear about what this snapshot is for. It is **not** protecting the data — we chose the
clean rebuild precisely because these volumes hold nothing but manager self-alerts. It's
protecting the **rollback path**: if 4.14.6 misbehaves, this is what lets you get a working
4.9.2 stack back (see § 7). Two minutes for a known-good escape hatch.

```bash
DATE=$(date +%Y-%m-%d); mkdir -p ~/vol-snap
cd ~/talonsoclab/deploy/soc-recon && sudo docker compose stop
for v in soc-recon_indexer_data soc-recon_wazuh_etc soc-recon_wazuh_queue soc-recon_wazuh_api_configuration; do
  sudo docker run --rm -v "$v":/from -v ~/vol-snap:/to alpine \
    tar czf "/to/${v}_${DATE}.tar.gz" -C /from .
done
sudo docker compose start
ls -lh ~/vol-snap/
```

Then pull them to the external drive — run this **from the Mac**, not the box:

```bash
DATE=$(date +%Y-%m-%d)
mkdir -p "/Volumes/MacbookXD/talonsoclab/volumes/$DATE"
rsync -avh talon@talonsoclab:~/vol-snap/ "/Volumes/MacbookXD/talonsoclab/volumes/$DATE/"
```

Four tarballs on the external drive before you proceed. Not three.

---

## 2. The change set — [MAC]

Five tracked files plus the untracked `.env`. All five are already committed; on the box you
only need `git pull`.

| File | Change |
|---|---|
| `docker-compose.yml` | 3 image tags → `4.14.6`; **7 indexer mount paths** gain `/config` |
| `config/wazuh_indexer/wazuh.indexer.yml` | 6 `pemcert_filepath` paths gain `/config`; adds `cluster.name`, ECDHE cipher allowlist, TLS protocol pin |
| `generate-indexer-certs.yml` | generator `0.0.2` → `0.0.4`; adds `CERT_TOOL_VERSION=4.14` |
| `config/wazuh_dashboard/opensearch_dashboards.yml` | adds 15-min session + cookie TTL with keepalive |
| `config/wazuh_cluster/wazuh_manager.conf` | syscollector `<ports all>` → `yes`; adds 3 malicious-IOC CDB lists |
| `.env` *(untracked, edit on box)* | `WAZUH_VERSION=4.9.2` → `4.14.6` |

Two of these are worth understanding rather than just applying:

**The malicious-IOC lists** (`malicious-ip`, `malicious-domains`, `malware-hashes`) are new
CDB lists shipped in 4.14. They're a real detection gain, not housekeeping — CDB lists are
Wazuh's O(1) lookup structure for matching field values against large sets, so these give you
IOC matching on every event with no rule-authoring effort.

**The TLS protocol pin.** Upstream 4.14 ships `enabled_protocols: ["TLSv1.2"]`, which
*disables* TLS 1.3. This stack negotiated 1.3 fine at 4.9 (recorded in `ISA.md` ISC-19,
filebeat test output). It's kept as upstream ships it so 4.14 comes up on a known-good
baseline — but it's a downgrade on paper and worth revisiting once the stack is verified
green. One line to change back.

---

## 3. Execute — [BOX]

```bash
cd ~/talonsoclab/deploy/soc-recon
git pull

# .env is gitignored — bump it by hand
sed -i 's/^WAZUH_VERSION=.*/WAZUH_VERSION=4.14.6/' .env
grep WAZUH_VERSION .env

# tear down, volumes included
sudo docker compose down -v

# the cert tool will NOT overwrite an existing set — clear it first
rm -rf config/wazuh_indexer_ssl_certs/*

# regenerate certs with the 4.14 cert tool
sudo docker compose -f generate-indexer-certs.yml run --rm generator

# REQUIRED — the generator writes a root-owned 0500 dir that container UIDs
# cannot traverse. Skip this and the indexer dies on unreadable certs.
# (This is the same trap recorded in PHOENIX.md Stage 1.)
sudo chmod 755 config/wazuh_indexer_ssl_certs
sudo chmod 644 config/wazuh_indexer_ssl_certs/*
ls -la config/wazuh_indexer_ssl_certs/

# pull 4.14.6 images, then bring it up
sudo docker compose pull
sudo docker compose up -d
```

The indexer takes noticeably longer than 4.9 on first boot — it initialises the security
index from scratch. `start_period` in the healthcheck is 120s; give it that before worrying.

---

## 4. Verify — [BOX]

Don't mark this done on `up -d` returning cleanly. Work the list:

> **Indexer API calls must run inside a container.** `9200` is not host-published by design,
> so `curl https://localhost:9200` from the host reaches nothing — and with `-s` it fails
> *silently*, which reads as an empty result rather than an error. Route them through
> `docker compose exec`.

```bash
PASS=$(grep ^WAZUH_INDEXER_PASS .env | cut -d= -f2 | awk '{print $1}')

# 1. all three containers up, indexer healthy, versions correct
sudo docker compose ps

# 2. indexer answers over TLS and reports green/yellow (yellow is fine single-node)
sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" https://localhost:9200/_cluster/health | jq

# 3. manager daemons — expect 10 running, with clusterd/maild/agentlessd off
sudo docker compose exec wazuh.manager /var/ossec/bin/wazuh-control status

# 4. filebeat can still reach the indexer after the cipher/protocol change
sudo docker compose exec wazuh.manager filebeat test output

# 5. dashboard answers on 443
curl -skI https://localhost:443 | head -1
```

Then in the browser: log in, confirm the API card reads **Online v4.14.6**, and confirm the
new session TTL by leaving it idle 15 minutes and watching it bounce you to login.

**Acceptance checklist:**

- [ ] `docker compose ps` — 3/3 up, indexer `(healthy)`, all images `:4.14.6`
- [ ] `_cluster/health` returns `green` or `yellow` over TLS
- [ ] `wazuh-control status` — 10 daemons running
- [ ] `filebeat test output` — TLS handshake + "talk to server" OK (expect **TLS 1.2** now, not 1.3)
- [ ] Dashboard 443 login OK; API card reads Online **v4.14.6**
- [ ] Indexer `:9200` still **not** host-published (absent from the `ps` port map)
- [ ] ISM retention policy re-applied — **the clean rebuild wiped it**

---

## 5. The thing that will bite you

`down -v` destroyed the indexer volume, and the **ISM retention policy lived in that volume**.
`ISA.md` records it as verified via the explain API back at Phase 0.2 — that verification is
now void. On a 256 GB NVMe with no retention policy, the indexer will happily fill the disk.

The policy is now captured in git at
[`deploy/soc-recon/wazuh/ism/`](../../deploy/soc-recon/wazuh/ism/) — it wasn't before, which is
how it managed to disappear without anything noticing. Apply and verify per that README.

Re-apply it before enrolling any agent, and re-verify with the explain API rather than assuming
the PUT took. Note that on a freshly rebuilt stack the explain call returns empty because no
`wazuh-alerts-*` index exists yet — `ism_template` attaches to indices as they're created, so
the meaningful check is *after* the first agent reports.

---

## 6. After

Phase 0.5 closes and A.1 opens with the version floor set correctly. Install agents at
**4.14.6** directly — do not install 4.9.2 and upgrade. The
[Linux agent upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/wazuh-agent/linux.html)
only becomes relevant for the *next* jump, once these agents exist.

Post-session checklist: secrets scrubbed, acceptance boxes updated in `README.md`, PHOENIX
snapshot of the newly-green 4.14.6 stack, commit + push.

---

## 7. Rollback — if 4.14.6 won't come up

This is what the § 1 snapshot bought. Rolling back is **two moves, not one** — the volumes and
the config have to go back together, because the 4.9.2 volumes only work with 4.9.2's mount
paths. Restore one without the other and you get the same cert-not-found failure from the
opposite direction.

```bash
cd ~/talonsoclab/deploy/soc-recon

# 1. config back to 4.9.2
git revert --no-edit a796f31
sed -i 's/^WAZUH_VERSION=.*/WAZUH_VERSION=4.9.2/' .env

# 2. volumes back to the snapshot
sudo docker compose down -v
DATE=<the snapshot date>
for v in soc-recon_indexer_data soc-recon_wazuh_etc soc-recon_wazuh_queue soc-recon_wazuh_api_configuration; do
  sudo docker volume create "$v"
  sudo docker run --rm -v "$v":/to -v ~/vol-snap:/from alpine \
    sh -c "tar xzf /from/${v}_${DATE}.tar.gz -C /to"
done

# 3. certs must go back to the 0.0.2 / 4.9 set too
rm -rf config/wazuh_indexer_ssl_certs/*
sudo docker compose -f generate-indexer-certs.yml run --rm generator
sudo chmod 755 config/wazuh_indexer_ssl_certs && sudo chmod 644 config/wazuh_indexer_ssl_certs/*

sudo docker compose up -d
```

**Before reaching for this**, check the likely failure first — most 4.14 boot failures on this
stack will be the cert permissions from § 3, not the version:

```bash
sudo docker compose logs wazuh.indexer | tail -40
```

If you see permission or "file not found" errors on anything under
`/usr/share/wazuh-indexer/config/certs/`, that's the chmod, not a reason to roll back.
