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

> **Always give `exec -T` an stdin source.** With `-T` and stdin still attached to your
> terminal, the exec session won't close after curl exits — it sits waiting for an EOF that
> never arrives, and looks exactly like a hung request. The command already ran; only the
> session is stuck. Here `< wazuh/ism/...json` supplies the EOF. Every call below that doesn't
> need stdin gets `< /dev/null` for the same reason. Ctrl-C is safe — it kills your client, not
> the server-side work.

`ism_template` auto-attaches the policy to **newly created** indices matching
`wazuh-alerts-*`. Indices that already exist when you apply it need attaching by hand:

```bash
sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" \
  -H 'Content-Type: application/json' \
  -X POST "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*" \
  -d '{"policy_id":"wazuh-alerts-retention"}' < /dev/null | jq
```

That second call returns `no indices found` on a freshly rebuilt stack. Expected — nothing has
been indexed yet. Re-run it after the first agent enrolls and alerts start landing.

## Verify

Don't trust the PUT. Check that the policy is registered:

```bash
sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" \
  "https://localhost:9200/_plugins/_ism/policies/wazuh-alerts-retention" \
  < /dev/null | jq '.policy.states'
```

And once indices exist, confirm the policy is actually managing them — this is the explain API,
the check `ISA.md` refers to:

```bash
sudo docker compose exec -T wazuh.indexer \
  curl -sk -u admin:"$PASS" \
  "https://localhost:9200/_plugins/_ism/explain/wazuh-alerts-*" < /dev/null | jq
```

A managed index reports `index.plugins.index_state_management.policy_id` and a non-null
`policy_id`. `"total_managed_indices": 0` with indices present means the policy registered but
never attached — go back and run the `add` call.

## What healthy looks like

ISM's UI is easy to misread, because a correctly working policy looks like a job that never
finishes.

| What you see | What it means |
|---|---|
| Job Status: **Running** | Steady state. The index is under active management. It reads `Running` for the policy's whole lifetime, not just while something is happening. |
| `Evaluating transition conditions [index=wazuh-alerts-4.x-YYYY.MM.DD]` | The policy is attached and doing its job — checking `min_index_age >= 45d`, getting "no", and leaving the index in `hot`. Expect this same message on every job interval for 45 days. |
| State: `hot` on a young index | Correct. `delete` is only entered once the index is genuinely 45 days old. |

ISM evaluates on its own schedule (~5 min interval, jittered) entirely server-side. Nothing
about it is tied to the shell that applied the policy — closing or interrupting a `curl` has no
effect on a job already registered.

**The failure signal isn't a long-running job.** It's `"total_managed_indices": 0` while
`wazuh-alerts-*` indices exist, which means the policy registered but never attached. That's
what the `_ism/add` call above is for.

## Watch the disk regardless

```bash
df -h /
docker system df -v | grep indexer_data
```
