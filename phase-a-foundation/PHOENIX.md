# PHOENIX — TalonSocLab Recovery Runbook

> **What this is:** the runbook that earns its keep when the Saguaros test server (`test-0`) gets wiped without notice. Cyber-hub admin policy reserves the right to wipe at any time, so every TalonSocLab artifact must survive a wipe through one of three tiers.
>
> **Target rebuild time:** ≤ 4 hours if Phase A has shipped, ≤ 1 hour if mid-Phase-A.

---

## Defense-in-depth, three tiers

### Tier 1 — Source of truth in git
Everything that *describes* how the lab is built lives in this repo and is pushed to `github.com/ktalons/talonsoclab`. This is the blueprint to rebuild from scratch.

- `phase-a-foundation/architecture.mmd` — single source of truth for VLANs, IPs, bridges
- `phase-a-foundation/deployment/*.md` — six runbooks for foundation buildout
- `phase-a-foundation/configs/` — exported configs (see `configs/README.md` for what lands where)
- `phase-a-foundation/scripts/` — automation (backup, smoke tests)

**Cadence:** end of every build session, `git add . && git commit && git push`.

### Tier 2 — VM image backups on MacbookXD
Per-VM `vzdump` images on the external drive so a known-good VM can be restored without rebuilding from ISO.

- **Location:** `/Volumes/MacbookXD/talonsoclab/vzdumps/YYYY-MM-DD/`
- **Cadence:** after every session that flips an acceptance box; before any risky change
- **Retention:** keep last 3 dumps per VM; older ones deleted to manage disk

### Tier 3 — Secrets in password manager
- pfSense admin password
- Wazuh `admin`, `kyle-admin`, `kyle-analyst` passwords
- Any API keys (AbuseIPDB, VirusTotal, etc. — Phase D)

**Never** in repo. **Never** baked into scripts. Password manager is the only authority.

---

## Pre-flight (run this before you ever need PHOENIX)

These commands assume `test-0` is up and your VMs exist. Run them after each meaningful session.

```bash
# On Proxmox node `test-0` (SSH or node Shell):

# 1. Export every TalonSocLab VM's config to a file you can put in the repo
for vmid in $(qm list | awk '$2 ~ /^kv-/ {print $1}'); do
  qm config "$vmid" > "/tmp/vm-config-${vmid}.conf"
done
ls /tmp/vm-config-*.conf

# 2. From your Mac, pull configs into the repo (configs/vm-configs/)
# scp root@<test-0-ip>:/tmp/vm-config-*.conf \
#     ~/Projects/talonsoclab/phase-a-foundation/configs/vm-configs/
# Then: cd ~/Projects/talonsoclab && git add . && git commit -m "session N: vm configs" && git push
```

VZDump cadence (after each session that ships acceptance):

```bash
# On Proxmox node:
mkdir -p /tmp/talon-dumps
for vmid in $(qm list | awk '$2 ~ /^kv-/ {print $1}'); do
  vzdump "$vmid" --dumpdir /tmp/talon-dumps --mode snapshot --compress zstd
done

# On Mac:
DATE=$(date +%Y-%m-%d)
mkdir -p "/Volumes/MacbookXD/talonsoclab/vzdumps/${DATE}"
scp root@<test-0-ip>:/tmp/talon-dumps/vzdump-qemu-*.vma.zst \
    "/Volumes/MacbookXD/talonsoclab/vzdumps/${DATE}/"

# Clean up node:
ssh root@<test-0-ip> 'rm /tmp/talon-dumps/vzdump-qemu-*.vma.zst'
```

---

## The Phoenix sequence (when test-0 has been wiped)

### Stage 0 — Confirm the wipe and re-establish baseline (15 min)

1. Log into Proxmox web UI at `test-0` — confirm access still works
2. Datacenter → Permissions → confirm your user still has Administrator (or what role you ended up with)
3. Datacenter → Pools → does `talonsoclab` exist? If not, recreate it (Datacenter → Pools → Create → Name: `talonsoclab`)
4. Node → System → Network → does `vmbrtalon` exist? If not, recreate per `deployment/01-pfsense-edge.md` (Network → Create Linux Bridge → name `vmbrtalon`, no ports, VLAN aware ☑, autostart ☑, then Apply Configuration)
5. Confirm `vmbr0` is still the shared uplink (it almost certainly is — it's the cyber hub's primary bridge)

If any of 2–4 are broken, message the cyber hub admin before continuing.

### Stage 1 — Restore VMs from vzdump (45–90 min depending on count)

For each `kv-*` VM, in this order: **pfsense-edge first (600), then wazuh-soc (601), then endpoints (602+).**

```bash
# On Proxmox node, for each VM:
# 1. Copy the latest vzdump from MacbookXD up to the node
#    (from your Mac: scp /Volumes/MacbookXD/talonsoclab/vzdumps/<latest>/vzdump-qemu-600-*.vma.zst root@<test-0>:/var/lib/vz/dump/)

# 2. Restore:
qmrestore /var/lib/vz/dump/vzdump-qemu-600-<timestamp>.vma.zst 600 --pool talonsoclab
qmrestore /var/lib/vz/dump/vzdump-qemu-601-<timestamp>.vma.zst 601 --pool talonsoclab
# ...etc for each VMID
```

### Stage 2 — Re-wire NICs to current bridges (5 min per VM)

The restored VM configs reference `vmbrtalon` by name. If you recreated `vmbrtalon` cleanly in Stage 0, NICs should bind automatically. Verify:

```bash
qm config 600 | grep ^net
qm config 601 | grep ^net
# Expected: net0=...bridge=vmbr0..., net1=...bridge=vmbrtalon... (for pfSense)
# Expected: net0=...bridge=vmbrtalon,tag=20...                   (for Wazuh)
```

If a NIC line shows a bridge that no longer exists, edit it via web UI or `qm set <vmid> --net0 <new-spec>`.

### Stage 3 — Boot in dependency order (15 min)

1. **pfSense (600)** first. Wait for WAN DHCP, confirm web UI at LAN IP. If WAN doesn't come up, check that NIC1 is on `vmbr0`.
2. **Wazuh (601)** second. Wait for `https://10.10.20.10` to load. Confirm Manager + Indexer + Dashboard all green.
3. **Endpoints (602+)** last. Confirm they pull DHCP from pfSense on VLAN 10 and that their Wazuh agents check in to the manager.

### Stage 4 — Re-validate acceptance criteria (15 min)

Walk the acceptance boxes in the most recently shipped runbook (e.g., `deployment/01-pfsense-edge.md` "Acceptance" section). If any fail, fix before declaring recovery complete.

### Stage 5 — Resume from the next-session brief (5 min)

- Update `MEMORY/project-talonsoclab-next-session` if dates slipped
- Push a Phoenix-recovery note to the repo: `git commit -m "phoenix: recovered from wipe YYYY-MM-DD"`
- Carry on with whatever phase you were in

---

## Total time estimate

| Stage | Time | Notes |
|---|---|---|
| 0. Baseline | 15 min | Pool + bridge recreation |
| 1. VM restore | 45–90 min | Depends on vzdump size + count |
| 2. NIC verification | 10 min | 2–5 VMs |
| 3. Boot sequence | 15 min | pfSense → Wazuh → endpoints |
| 4. Acceptance | 15 min | Re-walk last-shipped runbook |
| 5. Resume | 5 min | Note + commit |
| **TOTAL** | **~2.5 hrs for full Phase A** | Under the 4-hour target |

---

## Failure modes and escape hatches

| Failure | Cause | Escape hatch |
|---|---|---|
| Pool can't be recreated | Permission revoked post-wipe | Message admin — likely a one-line ACL restoration |
| `vmbrtalon` create fails | Name collision (someone else took it) | Pick `vmbrtalonk` or `talonbr` — update repo across all 5 files via `find -exec sed` |
| vzdump won't restore | Disk format mismatch on new storage pool | `qmrestore --storage local-zfs ...` to target a different pool |
| Wazuh dashboard won't load after restore | Indexer state corruption | Reinstall Wazuh from scratch using `deployment/02-wazuh-stack.md` — keep dashboards JSON from `configs/wazuh/` for fast re-import |
| Endpoints can't enroll | pfSense firewall rules dropped | Re-import pfSense config XML from `configs/pfsense/` |

---

## What this runbook does NOT cover

- **Phase D honeynet** — runs on a cloud VM, not `test-0`. Its own backup story lives in `phase-d-intel/` when it ships.
- **Repo corruption** — if `github.com/ktalons/talonsoclab` itself is unavailable, you have local clones at `~/Projects/talonsoclab/` (Mac) and the vzdumps include `/etc` from the Wazuh VM which itself has installed runbooks via Ansible (Phase B+). Multi-clone redundancy is the answer.
- **Saguaros server hardware loss** — if `test-0` is decommissioned permanently, this becomes a migration not a recovery. Re-target to whichever Proxmox host the cyber hub provisions, update the IP/hostname in this PHOENIX runbook, otherwise the sequence is identical.
