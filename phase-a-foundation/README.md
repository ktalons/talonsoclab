# Phase A — Foundation SOC Stack

Wazuh SIEM ingesting real telemetry from real devices, with custom dashboards and a Suricata
IDS, in containers on a small box I own outright.

**Substrate:** HP EliteDesk 800 G4 Mini (i5-8500T, 16 GB, 256 GB NVMe) · Ubuntu Server 26.04 ·
Docker. **Stack:** [`deploy/soc-recon/`](../deploy/soc-recon/).

## Runbooks

| # | Step | Status |
|---|---|:--:|
| [00](runbooks/00-host-ubuntu-docker.md) | Ubuntu Server + Docker + UFW | ✅ |
| [01](runbooks/01-network-switch-cutover.md) | Wired cutover through the smart switch | ✅ |
| [02](runbooks/02-wazuh-4.14-upgrade.md) | Wazuh 4.9.2 → 4.14.6 clean rebuild | ✅ |
| [03](runbooks/03-windows-ssh-access.md) | SSH access to the Windows endpoint | ✅ |
| [04](runbooks/04-windows-agent-sysmon.md) | Wazuh agent + Sysmon on Windows | ✅ |
| [05](runbooks/05-wazuh-agent-update.md) | Native agent version management (Wazuh remote upgrade) | ✅ |
| [06](runbooks/06-suricata-ids-dashboards.md) | Suricata IDS on the host NIC + SOC Overview dashboard | ✅ |
| [07](runbooks/07-sca-ubuntu-26-04.md) | SCA coverage on Ubuntu 26.04 (adapted CIS policy) | ✅ |

## Acceptance

- [x] Stack green; dashboard reachable *(4.14.6)*
- [x] ISM retention policy active and version-controlled
- [x] All 3 endpoint agents active — Windows, Linux, macOS
- [x] Suricata events visible in the dashboard *(Suricata 8.0.6 on `eno1`, ET Open 52,245 rules;
      proven with a live `GPL ATTACK_RESPONSE id check returned root` hit, not just "sensor up")*
- [x] ≥1 custom dashboard with ≥3 visualizations exported —
      [`dashboards/talonsoclab-soc-overview.ndjson`](../dashboards/talonsoclab-soc-overview.ndjson)
      (5 panels: alerts over time by endpoint, severity, MITRE ATT&CK tactics, top rules,
      Suricata signatures)
- [ ] Walkthrough recording; blog post

## Not in Phase A

Sigma rule pack (B), Active Directory (C), honeynet (D), pfSense/VLANs (dropped in the docker
pivot), HA and SOAR (out of scope).

## Feeding CASA

The digest collector emits a deterministic `{date}-intake.json`. That artifact is the seam for
**[CASA](https://github.com/ktalons/casa-ai-agent)**, the multi-agent reasoning layer and my
capstone. TalonSocLab is the data plane; CASA does the analysis.

## History

Phase A originally ran as Proxmox VMs on a shared university host. That host died in May 2026,
so I bought a small SFF and pivoted to docker-compose.
