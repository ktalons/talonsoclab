# Wazuh agent version management — Ubuntu host agent

> **What this does:** changes the version of the native (apt-installed) `wazuh-agent` on the
> SOC host itself: agent `002 talonsoclab`, group `phase-a-linux`, self-monitoring the box the
> Wazuh stack runs on. Unlike runbooks 00-04, this isn't a one-time build step. It's the
> procedure to reach for every time the agent's version needs to change.
>
> **First used 2026-07-31**, to roll the agent back from `4.14.7-1` to `4.14.6-1` after a
> manual apt override broke the version floor. See Acceptance below for the confirmed result.
>
> **Why it matters for a SOC:** the manager must always be at or above the version of every
> agent reporting to it. [Wazuh's own upgrade guide states this outright](https://documentation.wazuh.com/current/upgrade-guide/wazuh-agent/index.html),
> not just a policy this lab invented. `wazuh-agent` is `apt-mark hold`'d specifically because
> the box also runs `unattended-upgrades` (runbook 00), which would otherwise bump it past the
> manager with no warning.
>
> **Use Wazuh's own remote upgrade module, not raw apt.** The manager ships a tool that pushes
> a signed WPK package to the agent over the existing connection (port 1514): no SSH, no sudo,
> no dpkg conffile prompts. It validates versions against the manager by default; going
> backward requires deliberately passing `-F`/`--force`. Internal runbook 02 flagged this exact
> doc as the next relevant step once agents existed. This is that step.
>
> Steps are tagged **[BOX]** (SOC host, either directly or via `docker compose exec` into the
> manager container). Nothing here ever takes a password as an argument or environment
> variable. Sudo prompts happen interactively, same rule as everywhere else in this lab.

---

## 0. Orient before touching anything — [BOX]

```bash
apt-mark showhold                                  # is wazuh-agent currently held?
dpkg-query -W -f='${Version}\n' wazuh-agent         # currently-installed version
```

```bash
cd ~/talonsoclab/deploy/soc-recon   # or wherever this checkout actually lives on the box
docker compose exec -T wazuh.manager ls -la /var/ossec/bin/agent_upgrade
docker compose exec -T wazuh.manager /var/ossec/bin/agent_upgrade -h
docker compose exec -T wazuh.manager /var/ossec/bin/agent_upgrade -l
```

The `-h` output is ground truth for this exact build. Confirm the flags below against it
before running anything that changes state. `-l` lists outdated/mismatched agents; worth
seeing how it characterizes an agent that's *ahead* of the manager before acting on one.

## 1. Routine upgrade (agent behind the manager)

```bash
docker compose exec -T wazuh.manager /var/ossec/bin/agent_upgrade -a 002 -v <manager-version>
```

Always pass `-v` explicitly, read from the manager's own version (`docker compose exec -T
wazuh.manager /var/ossec/bin/wazuh-control info`, or `WAZUH_VERSION` in `.env`). Don't rely
on the bare default (`-v` omitted defaults to "latest Wazuh version," which isn't confirmed to
be capped at the manager's own version). No `-F` needed here; the tool's own version
validation is the safety net, confirmed live 2026-07-31: a target that isn't strictly newer
than what's already installed fails cleanly with `Error 1822 - Current agent version is
greater or equal` rather than silently doing nothing or erroring unclearly.

## 2. Forcing a specific version (rollback, or reinstalling the same version)

```bash
docker compose exec -T wazuh.manager /var/ossec/bin/agent_upgrade -a 002 -v <target-version> -F
```

`-F`/`--force` **"forces the agent to upgrade, ignoring version validations"**. That's a
broad override, not a downgrade-specific flag. It's exactly as capable of pushing an agent
*past* the manager as it is of pulling one back down. Only reach for it with a specific,
already-checked-safe `-v` value in hand, never routinely.

## Manual apt path — why it's not the recommended one

Working through this by hand (raw `apt-get install wazuh-agent`) is what caused the incident
this runbook exists to prevent: an unheld/held-override install can silently jump the agent
past the manager, and it hits real friction along the way.

| Mistake | Why it breaks | Fix, if you ever do need the apt path |
|---|---|---|
| `sudo echo "…" \| tee -a wazuh.list` | `sudo` only elevates `echo`; `tee` still runs unprivileged against a root-owned path → `Permission denied` | `echo "…" \| sudo tee wazuh.list > /dev/null` |
| Plain `apt-get install -y wazuh-agent` | `-y` answers "continue?" prompts, not dpkg conffile prompts; a missing/modified conffile still blocks on Y/I/N/O/D/Z | `sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confmiss" …` |
| `apt-get install` against a **held** package | apt will override an explicit hold with a confirmation prompt, with no guarantee the hold state you expect afterward is the one you get | leave the hold alone; use `agent_upgrade` instead |

## Acceptance

- [x] `agent_upgrade -l` no longer lists `002` as mismatched: `All agents are updated.`
- [x] `dpkg-query -W wazuh-agent` reports the intended version: `4.14.6-1`
- [x] `wazuh-control info` agrees: `WAZUH_VERSION="v4.14.6"` (independent of dpkg's package DB)
- [x] `systemctl is-active wazuh-agent` → `active`; `is-enabled` → `enabled`
- [x] `apt-mark showhold` still lists `wazuh-agent`. This tool doesn't change that policy, and
      didn't need to reapply it after the upgrade this time either (see internal runbook: the
      hold did not survive the *original* override and had to be set fresh, once, by hand)
- [x] Verified **from the manager**, not the endpoint's own report:
      `agent_control -l` → `002 talonsoclab ... Active`
- [x] Manager version unchanged, still ≥ the agent (`.env` untouched, still `4.14.6`)

Raising the *manager's* version first is the only legitimate way to let the agent go higher
than today's ceiling, but **don't reach for runbook 02 to do it.** That runbook's
`docker compose down -v` clean-rebuild was only safe because no agent had enrolled yet;
repeating it now would destroy live auditd/Sysmon/FIM data from all three enrolled agents. A
volume-preserving manager upgrade procedure doesn't exist in this repo yet. See
`ISA.md` ISC-25.2.
