# Shared agent-group configs

Config the manager pushes to agents by group. Mounted at
`/wazuh-config-mount/etc/shared` so the entrypoint syncs it into `/var/ossec/etc/shared` on
every boot.

Kept in git because `/var/ossec/etc/shared/` lives inside the `wazuh_etc` Docker volume and
does not survive `docker compose down -v` — the same failure class as the ISM retention policy
lost in the Phase 0.5 rebuild (see [`../ism/README.md`](../ism/README.md)).

## Groups

| Group | Purpose |
|---|---|
| `phase-a-windows` | Windows endpoints. Adds the Sysmon eventchannel collector on top of the agent's default Security/System/Application channels. |

## How it reaches an agent

The manager merges every file in a group directory into **`merged.mg`**, and that is what
agents actually download. Agents pull it within ~5 minutes of a change, or immediately on
agent restart.

Two consequences worth knowing:

- **Comments ship too.** `merged.mg` is built from the raw file contents, so anything you write
  in `agent.conf` is distributed to every endpoint in the group. Keep operational notes in this
  README, not in the config.
- **No `merged.mg` means no config.** If the merged file is missing, agents enroll into the
  group perfectly happily and silently receive nothing. There is no error anywhere.

## Required one-time chown after any `down -v`

The entrypoint's sync **creates** a group directory as `root:root 755`. `wazuh-remoted` runs as
the `wazuh` user and needs write access there to generate `merged.mg`. It can read the config
but not produce the merged file, so the group appears correctly configured and does nothing.

```bash
docker compose exec wazuh.manager \
  chown -R wazuh:wazuh /var/ossec/etc/shared/phase-a-windows
docker compose exec wazuh.manager \
  chmod 770 /var/ossec/etc/shared/phase-a-windows
```

Verified 2026-07-25 — the manager's own `default` group is `wazuh:wazuh 770`, and a
freshly-synced group landed `root:root 755` with no merged file. After the chown, `merged.mg`
appeared within 30 seconds.

**One-time per volume lifetime, not per boot.** The entrypoint leaves an existing directory's
ownership alone; confirmed across a `docker compose restart wazuh.manager`. It only recurs
after the volume is destroyed, which is why it's also recorded in
[`PHOENIX.md`](../../../../phase-a-foundation/PHOENIX.md) Stage 2.

## Verify

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -l
docker compose exec wazuh.manager ls -la /var/ossec/etc/shared/phase-a-windows/
```

Want the group listed, and both `agent.conf` and `merged.mg` present as `wazuh:wazuh`.
