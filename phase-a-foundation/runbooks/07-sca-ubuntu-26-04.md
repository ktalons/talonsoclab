# SCA coverage on Ubuntu 26.04 — adapting the shipped CIS policy

> **What this does:** gives the Ubuntu 26.04 SOC host a working Security Configuration Assessment
> benchmark, on a release Wazuh has no policy for yet. Ships the 24.04 CIS policy with only its
> applicability gate rewritten, distributed from git through the `phase-a-linux` agent group.
>
> **Completed 2026-08-09.** Closes ISC-25.1.
>
> **Why it matters for a SOC:** SCA is the "is this host built correctly" half of endpoint
> coverage, next to "what is happening on this host" (auditd/Sysmon). Before this, the Windows
> endpoint was assessed against `cis_win11_enterprise.yml` and the Linux host was assessed
> against **nothing** — an asymmetric blind spot that no alert would ever surface, because
> *absence* of assessment produces no events.

---

## 0. Confirm the gap from the manager, not the agent — [BOX]

```bash
cd ~/talonsoclab/deploy/soc-recon
APASS=$(grep -E '^WAZUH_API_PASS=' .env | cut -d= -f2-)
docker compose exec -T -e A="$APASS" wazuh.manager sh -c \
  'TOKEN=$(curl -sk -u "wazuh-wui:$A" -X POST "https://localhost:55000/security/user/authenticate?raw=true");
   curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:55000/sca/002?pretty=true"'
```

Before this runbook that returned `"No SCA information was returned"`. Read it server-side: the
agent's own log needs root, and the manager's answer is the one that matters anyway.

## 1. Understand the gate before touching it — [BOX]

```bash
docker compose exec -T wazuh.manager ls /var/ossec/ruleset/sca/ | grep -i ubuntu
```

4.14.6 ships **14.04, 16.04, 18.04, 20.04, 22.04 and 24.04**. (An earlier note in this project
claimed 20.04/22.04 only — that was generalised from one log line, never from the directory.)
Every policy is gated by the same shape:

```yaml
requirements:
  title: "Check Ubuntu version."
  condition: all
  rules:
    - "f:/etc/os-release -> r:Ubuntu 24.04"
    - "f:/proc/sys/kernel/ostype -> Linux"
```

This host reports `PRETTY_NAME="Ubuntu 26.04 LTS"`, so it matches **none** of the six and all of
them are skipped. That is the whole gap — not a missing feature, one unmatched string.

## 2. Derive the 26.04 policy — [BOX]

Change the **gate only**. Do not rewrite check bodies: that is authoring a benchmark, it is
unbounded and unaudited, and it destroys traceability back to CIS. Preserving all 279 upstream
check IDs means every finding still maps to a published control, and swapping in a real upstream
26.04 policy later is a delete-and-replace.

Four substitutions, each asserted present **before** rewriting and re-asserted after:

| From | To |
|---|---|
| `id: "cis_ubuntu24-04"` | `id: "cis_ubuntu26-04"` |
| `file: "cis_ubuntu24-04.yml"` | `file: "cis_ubuntu26-04.yml"` |
| `name: "... Benchmark v1.0.0."` | `... (adapted to Ubuntu 26.04).` |
| `f:/etc/os-release -> r:Ubuntu 24.04` | `... r:Ubuntu 26.04` |

> **Assert the version rule occurs exactly once** before rewriting. If a substitution silently
> matched nothing, the resulting policy loads, skips on the gate, and the API returns
> `"No SCA information was returned"` — **identical to the state you started in.** Success and
> failure are indistinguishable from the outside, so the check has to happen at transform time.

The committed artifact is `deploy/soc-recon/wazuh/shared/phase-a-linux/cis_ubuntu26-04.yml`; its
header records the source, the exact transform, and the caveat.

## 3. Distribute it — [BOX]

The policy lives in the group folder, so the group push puts it on the agent under
`/var/ossec/etc/shared/`. The group `agent.conf` references it relative to `/var/ossec`:

```xml
<sca>
  <policies>
    <policy>etc/shared/cis_ubuntu26-04.yml</policy>
  </policies>
</sca>
```

```bash
docker compose up -d --force-recreate wazuh.manager    # NOT restart — see runbook 06 § 3
```

Verify delivery by hash, not by "Active" — a 590 KB file that staged but never shipped looks the
same from `agent_control -l`:

```bash
docker compose exec -T wazuh.manager md5sum /var/ossec/etc/shared/phase-a-linux/merged.mg
docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -i 002 | grep "Shared file hash"
```

The agent restarts its modules when `merged.mg` changes and scans on start — results appeared
within ~20 s.

## 4. Read the results correctly — [BOX]

```
total_checks 279 | pass 23 | fail 56 | invalid 200 | score 29
```

Two things about those numbers:

- **`invalid: 200` is misleading.** The per-check API reports **192 explicitly
  `not applicable`**; the policy summary lumps not-applicable in with invalid. Query
  `/sca/002/checks/cis_ubuntu26-04` for the real distribution.
- **`score 29` is against applicable checks only** — 23/(23+56), not 23/279.

A large not-applicable count is normal for a minimal server: absent services, and no separate
`/tmp` partition (this box uses plain partitions). Some of it is *probably* not genuine — the
kernel-module block's first rule is `c:modprobe -n -v cramfs`, which is consistent with `modprobe`
not resolving on the scanner's PATH. That has not been characterised; don't claim it either way.

## 5. Confirm a finding by hand before acting on it — [BOX]

This is the standing rule for an adapted policy, and the first check tried proves why.

**35659 "Ensure sshd PermitRootLogin is disabled" reports FAIL on a host where it is correctly
set.** Its rules are `condition: all` over:

```
c:sshd -T -> r:^permitrootlogin no
f:/etc/ssh/sshd_config -> r:^\s*\t*PermitRootLogin\s*\t*no
```

This host sets `PermitRootLogin no` in `/etc/ssh/sshd_config.d/99-hardening.conf`. `sshd -T`
resolves the `Include` and would pass; the raw-file grep does not read drop-ins and fails; `all`
requires both, so the check fails.

**This is an upstream CIS-policy limitation, not an artifact of the 24.04→26.04 adaptation** —
the identical false positive occurs on a real 24.04 host hardened through drop-ins, which is
modern Ubuntu's default layout. Worth stating precisely: the wrong lesson to draw is "the adapted
policy is unreliable."

## Acceptance

- [x] Baseline `"No SCA information was returned"` captured from the manager before any change
- [x] Transform asserts each target string before and after; version rule confirmed to occur once
- [x] All 279 checks and upstream IDs preserved
- [x] `merged.mg` md5 matches agent 002's reported *Shared file hash* (590 KB delivered)
- [x] Scan runs: `policy_id: cis_ubuntu26-04`, 23 pass / 56 fail / 192 not applicable
- [x] One failure hand-verified and correctly classified as an upstream false positive (35659)
- [ ] The 25 audit-rule failures (35725–35749) worked into the auditd ruleset — **Phase B**
