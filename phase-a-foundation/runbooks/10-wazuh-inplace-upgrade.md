# Wazuh in-place upgrade: 4.14.6 to 4.14.9, volumes kept

> **What this does:** moves the central stack (manager, indexer, dashboard) and then all three
> agents to a newer Wazuh patch release **without** destroying any volume. Agent keys, FIM
> baselines, alert history and the indexer's security config all carry across.
>
> **Why it matters for a SOC:** [runbook 02](02-wazuh-4.14-upgrade.md) got to 4.14.6 by
> `docker compose down -v`, which was only safe because nothing had enrolled yet. Doing that now
> would wipe three agents' worth of telemetry. Patch releases also carry security fixes for the
> SIEM itself (4.14.7 fixed an active-response argument injection on the manager and every
> agent), so "never upgrade" is not an option either. This is the procedure for every later
> 4.x patch bump.
>
> Steps are tagged **[MAC]** (the workstation with the backup drive) and **[BOX]** (SOC host).
> Written 2026-10-22 for 4.14.6 to 4.14.9; § 1 proven on scratch the same day.

---

## 0. Why in place, and what can't be undone

Wazuh's documented Docker upgrade keeps the volumes: stop the stack, change the image tags,
start it again. The new manager runs its init on the old volumes, and the new indexer opens the
old index data.

The indexer is the one-way step. 4.14.6 runs OpenSearch 2.19.5 and 4.14.9 runs 2.19.6, and
OpenSearch refuses to start on data a newer version has written, even across a patch. So once
the new indexer has opened `indexer_data`, setting the old tag back does not roll back. **The
rollback is a Tier 2 restore** ([runbook 09](09-tier2-backups.md) § 4), and the backup taken in
§ 2 is the restore point. Anything indexed between that backup and a rollback is lost.

The manager and dashboard volumes have no such check, but they ride the same restore.

## 1. Pre-flight — [MAC] then [BOX]

**Diff upstream, not the docs.** Compare `wazuh/wazuh-docker`'s `single-node/` at the running
tag and the target tag, then our deploy against the running tag:

```bash
git clone -q --depth 1 --branch v4.14.6 https://github.com/wazuh/wazuh-docker.git up-old
git clone -q --depth 1 --branch v4.14.9 https://github.com/wazuh/wazuh-docker.git up-new
diff -ru up-old/single-node up-new/single-node
```

For 4.14.6 to 4.14.9 the only difference is the three image tags. Every config file is
byte-identical, so our local changes (28 lines in `wazuh_manager.conf`, the indexer TLS pins,
the dashboard session TTL, the cert generator) carry over with nothing to merge. The official
guide's step that **replaces** `wazuh_manager.conf` with upstream's would delete ours and add
nothing; skip it. Its certificate regeneration step is skipped too: the generator is already
`0.0.4` and every cert is valid to 2036 (`openssl x509 -noout -enddate`).

**Pull the images first.** This does not touch the running containers:

```bash
for i in manager indexer dashboard; do docker pull -q wazuh/wazuh-$i:4.14.9; done
```

**Diff what the image runs, not just what the repo ships.** Three things in this deploy depend on
the manager image's contents:

| What | Check | 4.14.9 result |
|---|---|---|
| `wazuh/cont-init/1-config-filebeat` shadows the stock script | `sha256sum` of the stock `/etc/cont-init.d/1-config-filebeat` against the hash in our copy's header | same hash, override unchanged |
| The Tier 2 held path depends on `0-wazuh-init` exiting early on a second start | runbook 02 § 5 on scratch | 27/27 over three modes; all three cont-init scripts byte-identical |
| `cis_ubuntu26-04.yml` is derived from the image's `cis_ubuntu24-04.yml` | `diff` the source between images, re-derive with the header's transform | five `c:` checks now run under `sh -c`; re-derived |

To read a file from an image without starting it:

```bash
c=$(docker create wazuh/wazuh-manager:4.14.9); docker cp -q $c:/etc/cont-init.d ./ci-4.14.9; docker rm $c
```

**Record the baseline** on the box, before anything changes:

```bash
cd ~/talonsoclab/deploy/soc-recon
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control info | head -1
docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l
bin/idx '/_cat/indices/wazuh-alerts-*?h=index,docs.count&s=index' | tail -4
bin/idx /wazuh-alerts-4.x-<two-days-ago>/_count
```

Pick an index two days old for the count: yesterday's can still take late, buffered events.

## 2. Take the restore point — [MAC]

Run a Tier 2 backup **on the old version, before the box pulls the new commit**. The backup's
guard refuses when the running manager differs from the checkout, so after the pull it would
refuse until the upgrade's recreate:

```bash
cd ~/Projects/talonsoclab
tools/tier2-backup.sh
```

Want exit 0, `sealed`, and the restore test's config files matching. Note the stamp. It is the
only way back (§ 0).

## 3. Upgrade the stack — [BOX]

```bash
cd ~/talonsoclab/deploy/soc-recon && git pull --ff-only
docker compose config -q
sed -i 's/^WAZUH_VERSION=.*/WAZUH_VERSION=4.14.9/' .env
docker compose stop wazuh.dashboard wazuh.manager
bin/idx /_flush -X POST
docker compose up -d
```

`stop` first, so the manager's filebeat is not writing while the indexer goes down, and the
flush puts every in-memory segment on disk before the indexer stops. `up -d` then recreates
exactly the three services whose image changed. Suricata keeps running, and its `eve.json`
lines buffer at agent 002 until the manager is back. **There is no `down -v` anywhere in this
runbook.** Do not add one.

The indexer opens the old data first, so give it its 120 s `start_period`.

## 4. Verify the stack — [BOX]

```bash
docker compose ps
docker compose logs wazuh.manager | grep -E "Identified Wazuh|0-wazuh-init: exited"
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control info | head -1
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control status
bin/idx /_cluster/health
bin/idx /wazuh-alerts-4.x-<two-days-ago>/_count
docker compose exec -T wazuh.manager filebeat test output
docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l
```

Want: four containers up and the indexer `(healthy)`; `0-wazuh-init: exited 0` (a new
container, so the config-mount copy ran); `WAZUH_VERSION="v4.14.9"`; ten daemons; health
yellow (the replicas a single node cannot place); **the same doc count as the baseline**; the
filebeat handshake; agents 001 to 003 Active.

Then the detection path. A real Suricata decoder event from `eve.json` must still hit our
suppression rule:

```bash
l=$(tail -n 20000 /var/log/suricata/eve.json | grep -m1 '"signature":"SURICATA Ethertype unknown"')
printf '%s\n' "$l" | docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-logtest | grep -E "id: '|level: "
```

Want `id: '100200'` and `level: '0'`.

## 5. Upgrade the agents — [BOX]

The manager must be at or above every agent ([runbook 05](05-wazuh-agent-update.md)), so agents
go only after § 4 passes. One at a time, the Linux host first, because it is the one on the box:

```bash
docker compose exec -T wazuh.manager /var/ossec/bin/agent_upgrade -l
docker compose exec -T wazuh.manager /var/ossec/bin/agent_upgrade -a 002 -v 4.14.9
docker compose exec -T wazuh.manager /var/ossec/bin/agent_upgrade -a 001 -v 4.14.9
docker compose exec -T wazuh.manager /var/ossec/bin/agent_upgrade -a 003 -v 4.14.9
for a in 001 002 003; do
  docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -i $a | grep -E "Agent ID|Status|Client version"
done
```

Want each `Active` with `Client version: Wazuh v4.14.9`. Alerts carry no agent version field, so
this, the manager's own record, is the place to read it.

No `-F`. Without it the manager refuses a target that is not newer than the agent, which is the
check you want. Each agent downloads its signed WPK from `packages.wazuh.com`, so the endpoint
needs outbound HTTPS. Before 001, check the Dell has no pending reboot: 4.14.9 fixed an MSI
upgrade that left the agent broken after the next reboot when a restart was pending, but the
fix ships in the new installer and the Dell's state is what decides it.

On the Ubuntu host, `apt-mark showhold` keeps listing `wazuh-agent`. The WPK path does not go
through apt, so the hold stays and keeps `apt upgrade` from moving the agent past the manager.

## 6. Prove it from the data — [BOX] then a browser

```bash
bin/idx '/wazuh-alerts-*/_search?size=0' --data-binary @- <<'EOF'
{"query":{"range":{"@timestamp":{"gte":"now-1h"}}},
 "aggs":{"a":{"terms":{"field":"agent.id"}}}}
EOF
bin/idx '/wazuh-alerts-*/_search?size=0' --data-binary @- <<'EOF'
{"query":{"bool":{"filter":[{"term":{"agent.id":"001"}},{"range":{"@timestamp":{"gte":"now-24h"}}}]}},
 "aggs":{"eid":{"terms":{"field":"data.win.system.eventID","size":30}}}}
EOF
```

Want every agent with documents in the last hour. The Sysmon event ID histogram for the Dell
should include IDs outside {1, 2, 5, 6}, the same spread as before the upgrade.

In the browser: log in to the dashboard, the API card reads **Online v4.14.9**, and the SOC
Overview dashboard renders with data.

## 7. Take a backup on the new version — [MAC]

`tools/tier2-backup.sh` again. The held-path proof in § 1 is what allows a backup on a new image
(runbook 02 § 5). This snapshot is the new restore point; the § 2 one stays on the drive until
the backup prunes it as the fourth newest.

## Rollback

Only if § 4 or § 6 fails and the cause cannot be fixed forward. A tag flip is not a rollback
(§ 0). Restore the § 2 snapshot with [runbook 09](09-tier2-backups.md) § 4 and set `.env` back to
the old version before `bin/tier2-start`. The restore refuses while any of the four volumes
exists, so removing them is a deliberate step by hand, after you are sure. Agents already
upgraded stay ahead of a rolled-back manager, so roll back before § 5 or plan to re-upgrade the
manager forward.

## Known gaps

- **Removed config-mount files stay installed.** `mount_files` copies `wazuh/custom-rules/` and
  the other config-mount trees into the volume and never deletes. A rule file deleted from git
  keeps loading from `wazuh_etc` until it is removed from the volume by hand. Found on scratch
  2026-10-22: a test file planted on 10-21 broke analysisd on the next boot.
- **A plain restart still skips the config copy.** All three cont-init scripts are unchanged in
  4.14.9, so the multigroups trap in [runbook 06](06-suricata-ids-dashboards.md) § 3 still applies.
  The upgrade itself is safe because `up -d` makes new containers.

## Acceptance

- [ ] Upstream `single-node/` diffed between the two tags; our config needs no merge
- [ ] Image-dependent files re-checked: filebeat override hash, held path on scratch (runbook
      02 § 5), the derived CIS policy re-derived
- [ ] Tier 2 backup on the old version sealed, stamp recorded, before the pull
- [ ] All three services report 4.14.9; init `exited 0`; ten daemons; health yellow
- [ ] The two-day-old index has the same doc count before and after
- [ ] Logtest: the real Ethertype line still hits 100200 at level 0
- [ ] Agents 001 to 003 on 4.14.9, Active, with documents in the last hour
- [ ] The Dell's 24 h Sysmon event ID histogram includes IDs outside {1, 2, 5, 6}
- [ ] Dashboard API card reads Online v4.14.9; SOC Overview renders
- [ ] Tier 2 backup on the new version sealed
- [ ] No `down -v` was run

Next: Phase B.
