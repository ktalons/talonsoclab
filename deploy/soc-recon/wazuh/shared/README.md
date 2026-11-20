# Shared agent-group configs

Config the manager pushes to agents by group. Mounted at `/wazuh-config-mount/etc/shared` so
the entrypoint syncs it into `/var/ossec/etc/shared` when the container is created
(`docker compose up -d --force-recreate wazuh.manager`). A plain restart does not sync; see
GOTCHA 2 in `../../docker-compose.yml` and runbook 06 § 3.

Kept in git because `/var/ossec/etc/shared/` lives inside the `wazuh_etc` volume and does not
survive `docker compose down -v` — same failure class as the ISM policy
(see [`../ism/README.md`](../ism/README.md)).

| Group | Purpose |
|---|---|
| `phase-a-windows` | Windows endpoints. Adds the Sysmon eventchannel collector on top of the agent's default Security/System/Application channels, and one registry ignore for the keys under Volume Shadow Copy's `Services\VSS\Diag`, which change on every shadow copy and made most of the registry alerts. |
| `phase-a-linux` | Linux endpoints. Adds `/var/log/audit/audit.log`; the default config collects syslog and auth.log but not audit. Rules in [`../audit/`](../audit/). Also tails Suricata's `/var/log/suricata/eve.json` (only the SOC host has it) and ships `cis_ubuntu26-04.yml`, the CIS SCA policy adapted to Ubuntu 26.04. |
| `phase-a-macos` | macOS endpoints. Adds a filtered unified-log collector. The default `/var/log/system.log` carries almost nothing on modern macOS. |

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
for g in phase-a-linux phase-a-macos phase-a-windows; do
  docker compose exec wazuh.manager chown -R wazuh:wazuh "/var/ossec/etc/shared/$g"
  docker compose exec wazuh.manager chmod 770 "/var/ossec/etc/shared/$g"
done
```

One-time per volume lifetime, not per boot — an existing directory's ownership is left alone.

## Verify

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -l
docker compose exec wazuh.manager ls -la /var/ossec/etc/shared/phase-a-{linux,macos,windows}/
```

Want each group listed, and `agent.conf` and `merged.mg` present as `wazuh:wazuh` in each
directory. `phase-a-linux` also holds `cis_ubuntu26-04.yml`.

Then have Wazuh parse every group's `agent.conf`:

```bash
docker compose exec wazuh.manager /var/ossec/bin/verify-agent-conf
```

Want `verify-agent-conf: OK` under each group and exit 0. The `sca` warning that
`etc/shared/cis_ubuntu26-04.yml` is not found is expected: the checker looks for the policy
beside the group folders. This is the manager's Linux build: it reads the XML and the
settings every platform shares, and skips the content of Windows-only elements such as
`registry_ignore`.

The manager serves a file that fails this check anyway. An agent that receives one raises
rule 220, `Invalid remote configuration`, and keeps its running settings, but only until
its service next restarts: the bad file is on its disk, and by Wazuh's source a restarted
agent then loads nothing from it, without a message. For the Windows group that means no
Sysmon. The 2026-11-14 registry ignore shipped that way: its pattern ended in a backslash,
which Wazuh's XML reader takes as an escape for the closing tag. It was corrected the next
day.

So a file is checked before it is committed as well. Run `bun tools/agentconf-check.ts` from
the repo root after changing any `agent.conf`: it runs this same checker on each group's file
in a throwaway container of the pinned manager image on the box, and on a full pass writes
`agentconf.verified` in this folder. The pre-commit hook blocks a commit to this folder when
that receipt does not match the staged files. It does not replace the check above, which is
the step after the recreate. Details and limits:
[`tools/README.md`](../../../../tools/README.md#agentconf-check).
