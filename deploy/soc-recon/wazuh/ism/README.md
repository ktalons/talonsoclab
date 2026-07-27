# ISM retention policies

Index State Management policies for the Wazuh indexer, kept in git because **they live inside
the indexer volume and do not survive `docker compose down -v`**. The 4.9.2 → 4.14.6 rebuild
destroyed the original policy, which had never been captured anywhere.

On a 256 GB NVMe, `wazuh-alerts-*` grows without bound once agents report. No retention policy
is a disk-full incident on a schedule, and a full disk takes the indexer down hard.

## Apply

> Run every indexer API call **from inside a container**. `9200` is deliberately not
> host-published, so `curl https://localhost:9200` from the host connects to nothing — and with
> `-s` that failure is silent, so it looks identical to an empty result.

```bash
PASS=$(grep ^WAZUH_INDEXER_PASS .env | cut -d= -f2 | awk '{print $1}')

docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" -H 'Content-Type: application/json' \
  -X PUT "https://localhost:9200/_plugins/_ism/policies/wazuh-alerts-retention" \
  -d @- < wazuh/ism/wazuh-alerts-retention.json
```

> **Always give `exec -T` an stdin source.** Without one the session waits for an EOF that never
> arrives and looks like a hung request. Use `< file` or `< /dev/null`.

`ism_template` auto-attaches the policy to **newly created** indices. Indices that already exist
need attaching by hand:

```bash
docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" -H 'Content-Type: application/json' \
  -X POST "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*" \
  -d '{"policy_id":"wazuh-alerts-retention"}' < /dev/null
```

## Verify

```bash
docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" \
  "https://localhost:9200/_plugins/_ism/explain/wazuh-alerts-*" < /dev/null
```

Want a non-null `policy_id` and `total_managed_indices` matching your index count.

## Reading the status

A correctly working policy looks like a job that never finishes.

| What you see | What it means |
|---|---|
| Job Status **Running** | Steady state, for the policy's whole lifetime |
| `Evaluating transition conditions` | Attached and working — checking `min_index_age >= 45d`, getting no |
| State `hot` on a young index | Correct. `delete` is entered only at 45 days |

**The failure signal is `"total_managed_indices": 0`** while `wazuh-alerts-*` indices exist —
the policy registered but never attached. Run the `add` call above.
