# ISM retention policies

Index State Management policies for the Wazuh indexer, kept in git because **they live inside
the indexer volume and do not survive `docker compose down -v`.**

That's not hypothetical. The 4.9.2 → 4.14.6 rebuild (Phase 0.5, 2026-07-25) destroyed the
retention policy set back in Phase 0.2, and it had never been captured anywhere — the repo
asserted it was active (`README.md` acceptance box) while the only copy sat in a volume that
was about to be deleted. A config that exists only in a running service isn't configured,
it's remembered.

## Why this one matters

256 GB NVMe. `wazuh-alerts-*` grows without bound once agents start reporting. No retention
policy means a disk-full incident on a schedule, and a full disk takes the indexer down hard.
This is the single cheapest piece of insurance in the stack.

## Apply

> **Run every indexer API call from inside a container.** `9200` is deliberately **not**
> host-published (see `docker-compose.yml` — the indexer exposes no `0.0.0.0` binding), so
> `curl https://localhost:9200` from the host connects to nothing. With `curl -s` that failure
> is silent and `jq` prints nothing on empty input, so a call that never left the host looks
> identical to one that returned an empty result. Use `docker compose exec`.

```bash
cd ~/talonsoclab/deploy/soc-recon
PASS=$(grep ^WAZUH_INDEXER_PASS .env | cut -d= -f2 | awk '{print $1}')

sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" \
  -H 'Content-Type: application/json' \
  -X PUT "https://localhost:9200/_plugins/_ism/policies/wazuh-alerts-retention" \
  -d @- < wazuh/ism/wazuh-alerts-retention.json | jq
```

`-d @-` reads the policy from stdin; `exec -T` is what pipes the host-side file through.

`ism_template` auto-attaches the policy to **newly created** indices matching
`wazuh-alerts-*`. Indices that already exist when you apply it need attaching by hand:

```bash
sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" \
  -H 'Content-Type: application/json' \
  -X POST "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*" \
  -d '{"policy_id":"wazuh-alerts-retention"}' | jq
```

That second call returns `no indices found` on a freshly rebuilt stack. Expected — nothing has
been indexed yet. Re-run it after the first agent enrolls and alerts start landing.

## Verify

Don't trust the PUT. Check that the policy is registered:

```bash
sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" \
  "https://localhost:9200/_plugins/_ism/policies/wazuh-alerts-retention" | jq '.policy.states'
```

And once indices exist, confirm the policy is actually managing them — this is the explain API,
the check `ISA.md` refers to:

```bash
sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" \
  "https://localhost:9200/_plugins/_ism/explain/wazuh-alerts-*" | jq
```

A managed index reports `index.plugins.index_state_management.policy_id` and a non-null
`policy_id`. `"total_managed_indices": 0` with indices present means the policy registered but
never attached — go back and run the `add` call.

## Watch the disk regardless

```bash
df -h /
docker system df -v | grep indexer_data
```
