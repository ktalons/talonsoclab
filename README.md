![TalonSocLab: personal SOC home lab](assets/talon-waveform.png)

[![Phase](https://img.shields.io/badge/phase-B%20%C2%B7%20Detection-89b4fa)](https://ktalons.github.io/projects/talonsoclab/)
[![Last commit](https://img.shields.io/github/last-commit/ktalons/talonsoclab)](https://github.com/ktalons/talonsoclab/commits/main)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14-blue)](https://wazuh.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)

## Status

| Phase<img src="assets/spacer.png" width="260" height="1" alt=""> | Deliverable<img src="assets/spacer.png" width="700" height="1" alt=""> | |
|---|---|:---:|
| **A — Foundation SOC Stack** | Wazuh + Sysmon + Suricata, real-device agents, custom dashboards | <img src="assets/talon-glyph-64.png" width="20" align="top" alt=""> |
| **A+ — Hardening** | Host timers with failure alerts, log retention, secrets out of argv, credential rotation, encrypted Tier 2 backups | <img src="assets/talon-glyph-64.png" width="20" align="top" alt=""> |
| **B — Detection Engineering** | Sigma rule pack validated against MITRE ATT&CK | 🚧 |
| **C — AD Attack & Defense** | Mini-AD, top-5 detection chain, purple-team report | ⏭ |
| **D — Honeynet + Threat Intel** | T-Pot into OpenCTI with threat-intel enrichment | 🔴 |

<img src="assets/talon-glyph-64.png" width="20" align="top" alt=""> complete &nbsp;·&nbsp; 🚧 in progress &nbsp;·&nbsp; ⏭ next &nbsp;·&nbsp; 🔴 not started

Phase A closed on 2026-10-25 with the stack hardened: host timers with failure alerts, 14-day log retention, no secret in any process's arguments, credentials rotated, and age-encrypted backups the SIEM itself watches. Phase B is detection engineering. The noise baseline is measured first, so every rule that follows is judged against what the lab actually looks like when nothing is happening. Then a Sigma rule pack, each rule converted to Wazuh, mapped to MITRE ATT&CK and proven with a positive control on the live manager.

## Why

This is my first home lab. I learn by building the thing instead of reading about it, so I'm standing up a small SOC end to end and keeping it public for anyone coming up behind me.

## Follow along

<img src="assets/talon-glyph-64.png" width="20" align="top" alt=""> Project page: <https://ktalons.github.io/projects/talonsoclab/><br>
<img src="assets/talon-glyph-64.png" width="20" align="top" alt=""> Blog posts as each phase ships: <https://ktalons.github.io/blog/><br>
<img src="assets/talon-glyph-64.png" width="20" align="top" alt=""> CASA (reasoning layer): <https://github.com/ktalons/casa-ai-agent><br>
<img src="assets/talon-glyph-64.png" width="20" align="top" alt=""> Main site: <https://ktalons.github.io/><br>
<img src="assets/talon-glyph-64.png" width="20" align="top" alt=""> LinkedIn: <https://www.linkedin.com/in/ta1ons/>
