# Shared agent-group configs

Config the manager pushes to agents by group. Mounted at `/wazuh-config-mount/etc/shared` so
the entrypoint syncs it into `/var/ossec/etc/shared` on every boot.

Kept in git because `/var/ossec/etc/shared/` lives inside the `wazuh_etc` volume and does not
survive `docker compose down -v` — same failure class as the ISM policy
(see [`../ism/README.md`](../ism/README.md)).

| Group | Purpose |
|---|---|
| `phase-a-windows` | Windows endpoints. Adds the Sysmon eventchannel collector on top of the agent's default Security/System/Application channels. |

## How it reaches an agent

The manager merges every file in a group directory into **`merged.mg`**, and that is what
agents download — within ~5 minutes of a change, or immediately on agent restart.

- **Comments ship too.** `merged.mg` is built from raw file contents, so anything in
  `agent.conf` reaches every endpoint in the group. Keep notes here, not in the config.
- **No `merged.mg` means no config.** Agents enroll into the group happily and silently receive
  nothing. There is no error anywhere.

## Required one-time chown after any `down -v`

The entrypoint creates a new group directory as `root:root 755`, but `wazuh-remoted` runs as
`wazuh` and needs write access to generate `merged.mg`. Without it the group looks correctly
configured and does nothing.

```bash
docker compose exec wazuh.manager chown -R wazuh:wazuh /var/ossec/etc/shared/phase-a-windows
docker compose exec wazuh.manager chmod 770 /var/ossec/etc/shared/phase-a-windows
```

One-time per volume lifetime, not per boot — an existing directory's ownership is left alone.

## Verify

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -l
docker compose exec wazuh.manager ls -la /var/ossec/etc/shared/phase-a-windows/
```

Want the group listed, and both `agent.conf` and `merged.mg` present as `wazuh:wazuh`.
