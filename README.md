# TalonSocLab

**Personal SOC home lab** — flagship portfolio project by [Kyle Versluis](https://ktalons.github.io/).

A single coherent home SOC built in four phases over 10 weeks. Each phase ships independently with its own folder, README, architecture diagram, and lessons-learned write-up. By the end this will be a working end-to-end example of "I can run a small SOC."

## Status

🟡 **Phase A in pivot** *(updated 2026-06-09)* — the cyber-range Proxmox host that ran Phase A's VMs went hardware-dead since approximately May 29 (PSU failure + Processor VRD critical fault, no physical access for remote-hands repair). Phase A is now in a 27-day wait window with a hard substrate decision day of **2026-07-06**: either resume on the recovered host (RECOVER) or stand the lab up on a small owned SFF (BUY). Active build work has shifted to Phase B paper deliverables — Sigma rule pack + ATT&CK coverage skeleton + Atomic Red Team mappings — on a single Ubuntu VM, all of which land cleanly into Phase B's live confirmation sprint once Wazuh is back. Full story: [TalonSocLab Phase A — schedule update](https://ktalons.github.io/blog/talonsoclab-phase-a-schedule-update/).

## Phases *(revised schedule, 2026-06-09)*

| Phase | Window | Deliverable |
|---|---|---|
| **A — Foundation SOC Stack** | May 20 – **Aug 4 (recover) / Aug 11 (buy)** | Wazuh + Sysmon + Suricata + pfSense on Proxmox with custom dashboards |
| **B — Detection Engineering & Threat Hunting** | Jun 9 – **Aug 18 (R) / Aug 25 (B)** | Sigma rule pack validated against Atomic Red Team + MITRE ATT&CK coverage map (paper prep underway during the Phase A wait window) |
| **C — AD Attack & Defense** | post-Phase B → **mid-late Sep** | GOAD-style AD lab + top-5 AD attack detection chain + purple-team report |
| **D — Honeynet + Threat Intel Pipeline** | post-Phase C → **early-mid Oct** | T-Pot → OpenCTI with automated AbuseIPDB + VirusTotal enrichment |

> Original schedule was May 20 – Aug 4. The pivot pushes program completion by ~6 weeks; phase ordering and scope are unchanged.

## Why I'm building it

Strong CTF and OT SOC experience, but no public home-lab artifact a hiring manager can click on. TalonSocLab fixes that — particularly relevant for senior SOC and federal detection-engineering roles where end-to-end SOC capability needs to be visibly demonstrated, not just described.

## Follow along

- 🌐 Project page: <https://ktalons.github.io/projects/talonsoclab/>
- 📝 Blog posts as each phase ships: <https://ktalons.github.io/blog/>
- 💼 LinkedIn: <https://www.linkedin.com/in/ta1ons/>
