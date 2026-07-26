# Build Schedule — docker-compose edition

> Rebuilt after the BUY + docker-compose pivot (2026-06-20). The old Proxmox session
> plan is archived under [`archive-proxmox/BUILD-SCHEDULE.md`](archive-proxmox/BUILD-SCHEDULE.md).
> Windows are anchored to **hardware arrival** (the EliteDesk), since that gates Phase 0.
> Sun + Wed PM blocks per the time budget; each session ends with a commit.

## Phase map

| Phase | Window (T = box arrives) | Deliverable | Fits 16 GB? |
|---|---|---|---|
| **0 — Substrate cutover** | T → T+1 weekend | Ubuntu + Docker on the EliteDesk; `deploy/soc-recon` stack green; ISM retention set; PHOENIX backups live | ✅ |
| **A — Foundation (docker edition)** | T+1 → T+2 wk | Wazuh ingesting real telemetry from Win + Mac + host agents; Suricata container; 3 dashboards; walkthrough | ✅ |
| **B — Detection Engineering** | A+1 → A+3 wk | Sigma pack → Wazuh XML; Atomic Red Team validation; ATT&CK coverage map; purple-team writeup | ✅ |
| **CASA integration** *(threads B→D)* | from B onward | TalonSocLab emits `intake.json`; CASA (separate repo) reasons over it; eval writeup = capstone | ✅ |
| **C — AD Attack & Defense** | post-B → ~Sep | Mini-AD (on-box, non-concurrent) **or** cloud-burst GOAD; top-5 AD detection chain; purple-team report | ⚠️ trim/cloud |
| **D — Honeynet + Threat Intel** | post-C → ~Oct | T-Pot on a VPS → home Wazuh; OpenCTI (cloud/trimmed); AbuseIPDB + VT enrichment → CASA | ⚠️ cloud (correct) |

## Phase 0 — Substrate cutover (the unblock)

| # | Block | Goal | Commit |
|---|---|---|---|
| 0.1 | on arrival | Ubuntu Server 26.04 installed ✅; `vm.max_map_count` ✅; Docker + compose ✅; UFW ✅; SSH key-only ✅ — **complete 2026-07-11** | `phase-0: host base + docker` |
| 0.2 | +1 day | `deploy/soc-recon` up ✅; indexer healthcheck green ✅; dashboard reachable ✅; ISM retention set ✅ — **complete 2026-07-11** | `phase-0: wazuh stack live on owned box` |
| 0.3 | +1 day | PHOENIX Tier 2 volume-snapshot script run ✅ + copied to external drive ✅ (integrity-checked) — **complete 2026-07-11** | `phase-0: phoenix backups verified` |
| 0.4 | cable arrival | Wired cutover: box on TL-SG108E @1000Mb/s ✅; `eno1` DHCP fixed + reserved ✅; interim WiFi stripped ✅; BIOS After-Power-Loss=On ✅; stack re-verified green ✅ — **complete 2026-07-24** | `phase-0.4: switch cutover + wired` |
| 0.5 | before A.1 | Stack 4.9.2 → **4.14.6** clean rebuild ✅; certs regenerated w/ cert-tool 4.14 ✅; 10 daemons ✅; filebeat→indexer TLS1.2 ✅; health yellow (correct single-node) ✅; ISM retention re-applied, version-controlled, `total_managed_indices: 1` ✅ — **complete 2026-07-25. PHASE 0 DONE.** [runbook](runbooks/02-wazuh-4.14-upgrade.md) | `phase-0.5: wazuh 4.14.6 upgrade` |

## Phase A — Foundation (docker edition)

| # | Block | Goal | Commit |
|---|---|---|---|
| A.0 | before A.1 | SSH access to the **Dell OptiPlex 7070** (`talondellbox`): OpenSSH Server ✅; StartType Automatic ✅; `NetworkCategory` Public→Private (silently voided the firewall rule) ✅; dedicated lab keypair ✅; `administrators_authorized_keys` + ACL ✅; key-only login proven under `BatchMode` ✅; DefaultShell→PowerShell ✅ — **complete 2026-07-26.** [runbook](runbooks/03-windows-ssh-access.md) | `phase-a.0: ssh access to windows endpoint` |
| A.1 | Sun | Wazuh agent + Sysmon (Hartong) on the **Dell OptiPlex 7070** (`talondellbox`, Win 11 Pro 26200, bare metal); enrolled into `phase-a-windows`, status active | `phase-a: windows agent + sysmon` |
| A.2 | Wed PM | Wazuh agents on the Mac + the Ubuntu host (auditd); all 3 endpoints active | `phase-a: mac + host agents` |
| A.3 | Sun | Suricata container on host NIC; `data.suricata.*` in dashboard; 3 dashboards → ndjson | `phase-a: suricata + dashboards` |
| A.4 | Mon | Walkthrough recording; README status 🟢; portfolio card "Live"; blog #1; LinkedIn | `phase-a: ship v1.0` |

## Slip plan

1. If endpoints lag, ship with 2 of 3 agents and add the third in a recovery block — the
   stack being live matters more than the third agent.
2. If Suricata fights the host NIC, drop it to a Phase B opener (it's not core to "live SOC").
3. Hard rule: protect health and the Sec+ / interview blocks. The lab slips before they do.

## Pre-session checklist
- [ ] `git pull` latest `talonsoclab`
- [ ] Open `architecture.mmd` + the relevant section of `README.md`
- [ ] Confirm the box is reachable and the stack is green (`docker compose ps`)

## Post-session checklist
- [ ] Config changes captured in `deploy/soc-recon/` or a runbook diff
- [ ] Secrets scrubbed (no passwords/keys/real IPs) before commit
- [ ] Acceptance checklist updated in `README.md`
- [ ] PHOENIX volume snapshot if an acceptance box flipped
- [ ] `git commit && git push`
