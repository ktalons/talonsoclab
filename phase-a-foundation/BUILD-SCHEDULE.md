# Phase A — Build Schedule

> Five build sessions across May 25 → Jun 9. Sun + Wed PM blocks per PRD time budget. Each session ends with a commit so progress is visible in `git log`.

| # | Date | Block | Goal | Commit at end |
|---|---|---|---|---|
| 0 | **Sun May 25** | Kickoff | Scaffold repo + architecture + schedule lock | `phase-a: scaffold + architecture` |
| 1 | **Wed May 27 PM** | 2–3 hrs | pfSense VM up + base config (WAN/LAN VLANs 10+20) + Wazuh Manager VM created from Ubuntu 22.04 ISO | `phase-a: pfsense edge + wazuh vm provisioned` |
| 2 | **Sun Jun 1** | 4–6 hrs | Wazuh Manager + Indexer + Dashboard installed (single-node script) + Ubuntu endpoint joined as first agent | `phase-a: wazuh single-node live + ubuntu agent enrolled` |
| 3 | **Wed Jun 4 PM** | 2–3 hrs | Win10 + WinServer2022 deployed + Sysmon (SwiftOnSecurity config) + Wazuh agent on both | `phase-a: windows endpoints + sysmon + agent` |
| 4 | **Sun Jun 8** | 6–8 hrs | WEF collector role on WinSrv + Suricata on pfSense WAN + Filebeat to Wazuh + 3 custom dashboards exported to ndjson + screen recording + README polish + dashboard screenshots | `phase-a: suricata + wef + dashboards + recording` |
| 5 | **Mon Jun 9** | Ship | Final review + push tag `phase-a-v1.0` + portfolio site card flip + blog post #1 + LinkedIn post | `phase-a: ship v1.0` + site/blog/LinkedIn |

## Slip plan

If Session 2 (Jun 1) doesn't get Wazuh fully alive, the schedule absorbs as follows:

1. **Add Tue Jun 3 evening recovery block** (2 hrs) — Sec+ Tue AM stays sacred, recovery is evening.
2. **If still slipping after Jun 4:** drop Suricata from Phase A acceptance (becomes Phase B opener), ship the rest on Jun 9.
3. **Hard slip ceiling:** Jun 16. Beyond that, Phase B start gets pushed and the cascade hurts the Aug 12 finish.

## Pre-session checklist (run before each block)

- [x] Confirm Saguaros Proxmox access live
- [x] Pull latest `talonsoclab` from origin
- [x] Open `architecture.mmd` and `deployment/<runbook>.md` for the session's work

## Post-session checklist

- [ ] All config changes captured either in `scripts/` or as a runbook diff
- [ ] Anything sensitive (passwords, API tokens, real WAN IPs) scrubbed before commit
- [ ] Update `README.md` status badge / checklist for the acceptance criteria items satisfied
- [ ] `git commit -m "phase-a: <what changed>"` + push
- [ ] If memory-worthy: note for tNexus to record in `project-talonsoclab.md`
