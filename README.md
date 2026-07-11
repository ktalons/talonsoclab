# TalonSocLab

**Personal SOC home lab** — flagship portfolio project by [Kyle Versluis](https://ktalons.github.io/).

A single coherent home SOC built in four phases. Each phase ships independently with its own
folder, README, architecture diagram, and lessons-learned write-up. By the end this is a working
end-to-end example of "I can run a small SOC" — and the **data plane** that feeds
[CASA](https://github.com/ktalons/casa-ai-agent), my PAI-based agentic-SOC capstone.

## Status

🟢 **Pivot resolved → rebuilding on owned hardware** *(updated 2026-06-20)*.
I **bought a dedicated SFF** (HP EliteDesk 800 G4 Mini — i5-8500T, 16 GB, 256 GB NVMe)
and **pivoted from Proxmox VMs to docker-compose**.

| Phase | Deliverable | Substrate |
|---|---|---|
| **A — Foundation SOC Stack** | Wazuh + Sysmon + Suricata in Docker, real-device agents, custom dashboards | EliteDesk (16 GB) |
| **B — Detection Engineering & Threat Hunting** | Sigma rule pack validated against Atomic Red Team + MITRE ATT&CK coverage map | EliteDesk |
| **C — AD Attack & Defense** | Mini-AD (on-box) or cloud-burst GOAD + top-5 AD detection chain + purple-team report | EliteDesk / cloud |
| **D — Honeynet + Threat Intel** | T-Pot → OpenCTI with AbuseIPDB + VirusTotal enrichment | cloud (by design) |

> **16 GB note:** Phases A + B run comfortably on the box. C and D are RAM/disk-hungry —
> they're scoped to cloud-burst or a planned 64 GB + 1 TB upgrade. Honest constraints, planned for.

## Architecture

The build splits cleanly into two planes:

- **Data plane (this repo)** — Wazuh SIEM, Suricata IDS, an ephemeral recon pipeline, and a
  deterministic digest collector. It collects, filters, and cites. It does **not** reason.
  The deploy bundle lives in [`deploy/soc-recon/`](deploy/soc-recon/).
- **Reasoning plane ([CASA](https://github.com/ktalons/casa-ai-agent))** — a separate PAI-based
  multi-agent system on Claude that consumes this repo's structured `intake.json` and produces
  explainable, NIST-aligned, human-in-the-loop analysis. That's the capstone.

Keeping them separate is the whole point: deterministic infra below, agentic reasoning above.

## Why

I learn by building the thing, not reading about it. TalonSocLab is me standing up a small SOC
end to end — collection, detection, triage — so I actually understand how the pieces fit, and
keeping it public so it's useful to someone coming up behind me. It also doubles as the live
environment my [CASA](https://github.com/ktalons/casa-ai-agent) capstone reasons over.

## Follow along

- 🌐 Project page: <https://ktalons.github.io/projects/talonsoclab/>
- 📝 Blog posts as each phase ships: <https://ktalons.github.io/blog/>
- 🤖 CASA (reasoning layer / capstone): <https://github.com/ktalons/casa-ai-agent>
- 💼 LinkedIn: <https://www.linkedin.com/in/ta1ons/>
