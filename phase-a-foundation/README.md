# Phase A — Foundation SOC Stack (docker-compose edition)

> Working Wazuh SIEM ingesting real telemetry from real devices, with custom dashboards
> and a Suricata IDS — all in containers on a small box I own outright. The structural
> floor every later phase builds on.

**Substrate:** HP EliteDesk 800 G4 Mini (i5-8500T, 16 GB RAM, 256 GB NVMe), Ubuntu Server
22.04 LTS bare-metal + Docker.
**Status:** 🟡 Rebuilding on owned hardware after the shared-Proxmox pivot (see below).
**Deploy bundle:** [`deploy/soc-recon/`](../deploy/soc-recon/) — the actual compose stack.

---

## Why this looks different from the runbooks in `archive-proxmox/`

Phase A originally ran as Proxmox VMs (pfSense + VLANs + Windows endpoint VMs) on a shared
University of Arizona Saguaros host. That host died (PSU + Processor VRD fault, ~May 29 2026)
with no remote-hands access. Rather than wait on a repair I don't control, I bought a small
SFF and **pivoted to docker-compose** — the lab is now portable and mine.

The trade is deliberate and documented:

| Dropped (archived) | Replaced with | Net effect |
|---|---|---|
| pfSense edge + 2 VLANs | host firewall (UFW) + Docker network isolation | less network realism |
| Windows / Server endpoint VMs | **Wazuh agents on real devices** | real multi-OS telemetry, 0 extra RAM |
| Proxmox + vzdump recovery | Docker + volume-snapshot recovery | simpler, owned, faster rebuild |

Network realism is the one real loss; it can return later as a libvirt pfSense VM **if** I
upgrade past 16 GB. The portfolio value moves to detection breadth + analyst workflow —
which is where it should be anyway. The full original topology and six VM runbooks are
preserved in [`archive-proxmox/`](archive-proxmox/) as provenance for the pivot.

## What ships at the end of Phase A

- **Wazuh single-node stack** (Manager + Indexer + Dashboard) in Docker, tuned for 16 GB
  (see [`deploy/soc-recon/README.md`](../deploy/soc-recon/README.md) → Resource budget).
- **3 real endpoints** generating live telemetry via Wazuh agents:
  - Windows daily driver — Sysmon (Olaf Hartong modular config) + Wazuh agent
  - macOS — Wazuh agent
  - the Ubuntu host itself — Wazuh agent + auditd
- **Suricata** as a container sniffing the host NIC, `eve.json` shipped to Wazuh.
- **Custom dashboards**: top alerts, MITRE ATT&CK coverage, endpoint health → exported ndjson.
- **2-minute screen recording** walking the stack end-to-end.

## Deployment outline

Detailed per-component runbooks get written *as each step is executed on the real box*
(no fabricating steps for hardware that isn't here yet). The sequence:

1. **Host** — Ubuntu Server 22.04, `vm.max_map_count=262144`, Docker Engine + compose plugin,
   UFW (allow 443/1514/1515/55000 from LAN, SSH key-only), unattended-upgrades.
2. **Stack** — `cd deploy/soc-recon && cp .env.example .env` (set `WAZUH_INDEXER_PASS`),
   `docker compose up -d`. Confirm indexer healthcheck green, dashboard at `https://<host>`.
3. **Retention** — set a Wazuh ISM policy (delete `wazuh-alerts-*` > ~45 days) *day one*;
   256 GB fills fast.
4. **Endpoints** — install the Wazuh agent on the Windows box (+ Sysmon), the Mac, and the
   host; enroll to the manager; confirm all three `active` in the agent inventory.
5. **Suricata** — bring up the suricata container on the host NIC; confirm `data.suricata.*`
   events in the dashboard.
6. **Dashboards** — build the three visualizations, export to `dashboards/*.ndjson`.

## Acceptance criteria

- [ ] `docker compose up -d` brings the stack green; dashboard reachable at `https://<host>`
- [ ] All 3 endpoint agents visible in Wazuh inventory, status = active
- [ ] Suricata `eve.json` events visible in the dashboard (filter `data.suricata.*`)
- [ ] ≥1 custom dashboard with ≥3 visualizations exported to `dashboards/*.ndjson`
- [ ] ISM retention policy active; `df -h` headroom confirmed
- [ ] Screen recording in `screenshots/walkthrough.mp4`
- [ ] Top-level README Phase A status flipped to 🟢
- [ ] Portfolio site card updated to "Live"; blog post #1 published; LinkedIn post

## What Phase A explicitly does NOT do

- No Sigma rule pack — Phase B
- No Active Directory — Phase C
- No internet-exposed honeynet — Phase D (and it lives in cloud, not on this box)
- No pfSense / VLAN segmentation — dropped in the docker pivot (see table above)
- No HA / clustering, no SOAR — out of scope for the portfolio piece

## How this feeds CASA

The digest collector ([`deploy/soc-recon/digest/generate_digest.py`](../deploy/soc-recon/digest/generate_digest.py))
emits a deterministic `{date}-intake.json`. That artifact is the integration seam for
**[CASA](https://github.com/ktalons/casa-ai-agent)** — the PAI-based multi-agent reasoning
layer (the capstone). TalonSocLab is the data plane; CASA does the analysis. The two stay
cleanly separated on purpose.

## Risks tracked

| Risk | Mitigation |
|---|---|
| 256 GB NVMe fills with indices | ISM retention day one; watch `df -h`; 1 TB SSD is a cheap fix |
| 16 GB caps Phases C/D | A/B fit fine; budget 64 GB + 1 TB (~$150) as a Phase-C unlock, or cloud-burst |
| Single owned box = single point of failure | [PHOENIX](PHOENIX.md): git source-of-truth + volume snapshots to external drive |
| Network realism lost | Documented trade; revisit libvirt pfSense after a RAM upgrade |

## Once Phase A ships

Phase B (Detection Engineering) starts immediately — the same Wazuh stack becomes the
substrate Sigma rules + Atomic Red Team tests fire into. No rebuild. See [BUILD-SCHEDULE.md](BUILD-SCHEDULE.md).
