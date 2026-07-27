# Phase 0.1 — Host: Windows → Ubuntu Server + Docker

> **What this does:** wipes the OEM Windows install off the HP EliteDesk 800 G4 Mini, puts
> Ubuntu Server on it, and preps the host for the Wazuh stack — Docker, the kernel parameter
> the indexer needs, and a LAN-only firewall.
>
> **Why it matters:** everything after this is driven over SSH. This is the only step that
> requires standing at the box, so it ends by handing control to a key-based SSH session.
>
> Steps are tagged **[KEYBOARD]** (no OS = no SSH yet) and **[SSH]**.
>
> **Completed 2026-07-11.** Target: EliteDesk 800 G4 Mini · i5-8500T · 16 GB · 256 GB NVMe →
> hostname `talonsoclab`, user `talon`. As installed: Ubuntu Server **26.04 LTS**.

---

## 1. BIOS — [KEYBOARD]

The box lives on a UPS, so set the always-on posture while you're in here:

- **Advanced → Boot Options → After Power Loss → Power On**
- Disable **S5 Maximum Power Savings** (it can power down the NIC PHY)

Secure Boot can stay on; Ubuntu supports it.

## 2. Ubuntu Server installer — [KEYBOARD]

Guided install, wiping the whole disk. Three choices that matter:

| Screen | Choice | Why |
|---|---|---|
| Storage | Entire disk, guided | **Then edit `ubuntu-lv` to the max size.** Guided LVM only allocates ~half the disk by default, and the indexer needs all 256 GB. |
| SSH Setup | ✅ Install OpenSSH server | This is the step that makes the rest of the build remote. Import your key from GitHub here. |
| Featured snaps | None | Keep it lean. Docker comes from apt. |

Record the interface MAC from the network screen — you need it for the DHCP reservation later.

## 3. Host prep — [SSH]

```bash
# Kernel parameter the Wazuh indexer requires
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
sudo sysctl --system && sysctl vm.max_map_count      # expect >= 262144

# Docker Engine + compose plugin, official apt repo
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt update && sudo apt -y install docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker talon                        # log out/in to take effect

# UFW — deny inbound by default, Wazuh ports from the LAN only
sudo ufw default deny incoming
sudo ufw default allow outgoing
for p in 22 443 1514 1515 55000; do
  sudo ufw allow from 192.168.x.0/24 to any port $p proto tcp
done
sudo ufw enable && sudo ufw status verbose
```

Port roles: `443` dashboard, `1514` agent data, `1515` agent enrollment, `55000` Wazuh API.

## 4. Pin the IP — [SSH]

DHCP reservation on the router against the interface MAC. Everything downstream references
this address, so a moving IP means stale `known_hosts` entries and re-touching every doc.

## Acceptance — Phase 0.1

- [x] Ubuntu Server 26.04 LTS booting, Windows gone
- [x] `ssh talon@<box-ip>` logs in with key, no password prompt
- [x] `sysctl vm.max_map_count` ≥ `262144` (26.04 defaults to 1048576)
- [x] `docker compose version` succeeds; `talon` in the `docker` group
- [x] `ufw status` → deny incoming, LAN-only allows on 22/443/1514/1515/55000
- [x] Box IP pinned by DHCP reservation and recorded

Next: [`01-network-switch-cutover.md`](01-network-switch-cutover.md), then the stack itself
(`deploy/soc-recon/README.md`).
