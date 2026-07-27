# Build Schedule

> Phase plan for the docker-compose build. The old Proxmox session plan is archived under
> [`archive-proxmox/BUILD-SCHEDULE.md`](archive-proxmox/BUILD-SCHEDULE.md).
>
> Constraint that shapes everything below: **16 GB RAM and a 256 GB NVMe**. Indexer heap is
> capped at 2g, always-on footprint at roughly 6.5 GB, and retention is set day one.

## Phases

| Phase | Deliverable | Status |
|---|---|---|
| **0 — Substrate** | Ubuntu + Docker on the EliteDesk; Wazuh stack green; ISM retention; backups verified | ✅ complete |
| **A — Foundation** | Wazuh ingesting real telemetry from Windows + Mac + host; Suricata; dashboards | 🚧 in progress |
| **B — Detection Engineering** | Sigma pack → Wazuh rules; Atomic Red Team validation; ATT&CK coverage map | 🔴 not started |
| **C — AD Attack & Defense** | Mini-AD, top-5 AD detection chain, purple-team report | 🔴 not started |
| **D — Honeynet + Threat Intel** | T-Pot → Wazuh; OpenCTI; AbuseIPDB + VT enrichment | 🔴 not started |

**CASA integration** threads from Phase B onward: TalonSocLab emits `intake.json`,
[CASA](https://github.com/ktalons/casa-ai-agent) reasons over it, and the evaluation writeup is
the capstone.

## Phase 0 — Substrate ✅

| # | Deliverable | Runbook |
|---|---|---|
| 0.1 | Ubuntu Server + Docker + UFW; SSH key-only | [00](runbooks/00-host-ubuntu-docker.md) |
| 0.2 | `deploy/soc-recon` stack up; indexer healthy; dashboard reachable; ISM retention set | [deploy README](../deploy/soc-recon/README.md) |
| 0.3 | Volume snapshots verified onto external storage | [PHOENIX](PHOENIX.md) |
| 0.4 | Wired cutover through the smart switch; DHCP reservation; BIOS power posture | [01](runbooks/01-network-switch-cutover.md) |
| 0.5 | Wazuh 4.9.2 → **4.14.6** clean rebuild; certs regenerated; ISM version-controlled | [02](runbooks/02-wazuh-4.14-upgrade.md) |

The version jump landed here deliberately: the manager must be at or above every agent that
reports to it, and the floor is cheapest to set when nothing is enrolled yet.

## Phase A — Foundation 🚧

| # | Deliverable | Status |
|---|---|---|
| A.0 | SSH access to the Windows endpoint; key-only login | ✅ [03](runbooks/03-windows-ssh-access.md) |
| A.1 | Wazuh agent + Sysmon on Windows, enrolled and verified from the manager | ✅ [04](runbooks/04-windows-agent-sysmon.md) |
| A.2 | Agents on the Mac and the Ubuntu host (auditd); all three endpoints active | ⬜ |
| A.3 | Suricata on the host NIC; `data.suricata.*` in the dashboard; 3 dashboards exported | ⬜ |
| A.4 | Walkthrough recording; README status green; blog post | ⬜ |

## Slip plan

1. If endpoints lag, ship with 2 of 3 agents and add the third later. The stack being live
   matters more than the third agent.
2. If Suricata fights the host NIC, drop it to a Phase B opener. It isn't core to "live SOC."
3. Health and study blocks come first. The lab slips before they do.

## Session checklist

**Before:** `git pull`; confirm the box is reachable and `docker compose ps` is green.

**After:** config changes captured in `deploy/soc-recon/` or a runbook; secrets and real IPs
scrubbed; acceptance boxes updated; PHOENIX snapshot if an acceptance box flipped; commit and
push.
