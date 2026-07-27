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

## Acceptance

- [x] Stack green; dashboard reachable *(4.14.6)*
- [x] ISM retention policy active and version-controlled
- [ ] All 3 endpoint agents active *(1 of 3: Windows)*
- [ ] Suricata events visible in the dashboard
- [ ] ≥1 custom dashboard with ≥3 visualizations exported
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
so I bought a small SFF and pivoted to docker-compose. The original topology and six VM
runbooks are preserved in [`archive-proxmox/`](archive-proxmox/).
