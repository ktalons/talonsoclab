# Phase A — Foundation SOC Stack

> Working Wazuh SIEM ingesting from real endpoints with custom dashboards, fronted by pfSense + Suricata. The structural floor every later phase builds on.

**Window:** May 20 – Jun 9, 2026 (3 weeks)
**Ship date:** Jun 9, 2026
**Status:** 🟡 Scaffolded — build sessions begin Wed May 27
**Host:** University of Arizona Saguaros Cyber Range (Proxmox)

---

## What ships at the end of Phase A

A live SOC stack on Proxmox with:

- **pfSense** edge firewall + router (2 internal VLANs: Endpoints, SOC)
- **Suricata** IDS on the pfSense WAN, eve.json shipped to Wazuh
- **Wazuh** single-node stack (Manager + Indexer + Dashboard)
- **3 endpoints** generating real telemetry:
  - Windows 10 (workstation) — Sysmon + Wazuh agent
  - Windows Server 2022 — Sysmon + Wazuh agent (+ WEF collector role)
  - Ubuntu 22.04 — Wazuh agent + auditd
- **Custom dashboards** in Wazuh: top alerts, MITRE ATT&CK coverage, endpoint health
- **2-minute screen recording** walking the stack end-to-end

## Acceptance criteria (Jun 9)

- [x] Architecture diagram (`architecture.mmd`) renders cleanly on GitHub
- [ ] All 3 endpoints visible in Wazuh agent inventory, status = active
- [ ] Suricata eve.json events visible in Wazuh dashboard (filter `data.suricata.*`)
- [ ] At least one custom dashboard with ≥3 visualizations exported to `dashboards/*.ndjson`
- [ ] Screen recording (mp4 or webm) in `screenshots/walkthrough.mp4`
- [ ] Top-level repo README status row for Phase A flipped from 🟠 → 🟢
- [ ] Portfolio site card (`ktalons.github.io/projects/talonsoclab/`) updated to "Live"
- [ ] Blog post #1 published on `ktalons.github.io/blog/`
- [ ] LinkedIn post linking the blog + screenshot

## Folder layout

```
phase-a-foundation/
├── README.md                 # this file
├── architecture.mmd          # mermaid topology — single source of truth for IPs/VLANs
├── BUILD-SCHEDULE.md         # day-by-day plan through Jun 9
├── deployment/               # runbooks, one per VM/component
│   ├── 01-pfsense-edge.md
│   ├── 02-wazuh-stack.md
│   ├── 03-windows-endpoints.md
│   ├── 04-linux-endpoint.md
│   ├── 05-wef-collector.md
│   └── 06-suricata-ids.md
├── scripts/                  # automation that survives a rebuild
├── dashboards/               # exported Wazuh dashboard ndjson
└── screenshots/              # diagrams, dashboard caps, walkthrough recording
```

## Design choices worth flagging

- **Single-node Wazuh** for Phase A — production-style cluster split is out of scope; the goal is detection breadth, not HA.
- **WEF + agent on Windows endpoints, not WEF-only** — agent for richness, WEF as a documented secondary path because real SOCs run both.
- **Suricata on pfSense WAN, not inline IPS** — visibility first; IPS tuning is a Phase B concern.
- **Two VLANs minimum** — Endpoints (clients) and SOC (Wazuh + future Sigma stack). Mirrors how detection traffic is actually segregated.

## What Phase A explicitly does NOT do

- No Sigma rule pack — that's Phase B
- No Active Directory — that's Phase C
- No internet-exposed honeynet — that's Phase D
- No HA / clustering — out of scope for portfolio piece
- No SOAR / case management — out of scope

## Risks tracked

| Risk | Mitigation |
|---|---|
| Saguaros tenancy access ends post-grad | Export all VM configs + Wazuh ndjson weekly to this repo so the artifact survives even if the live lab doesn't |
| Wazuh single-node performance with 3 endpoints + Suricata | Acceptable for Phase A traffic volume; revisit before Phase D honeynet |
| Time slippage from interview/app sprints | Sun + Wed PM blocks are protected; slip ship date to Jun 16 before cutting scope |

## Once Phase A ships

Phase B (Detection Engineering) starts the day after — the Wazuh stack from A becomes the substrate that Sigma rules + Atomic Red Team tests fire into. No rebuild needed.
