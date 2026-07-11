# Phase 0.1 — Host: Windows → Ubuntu Server 24.04 + Docker

> **RESUME (2026-07-10):** last attempt stalled at installer step C.3 — "all interfaces
> disabled," DHCPv4 autoconfiguration failed. The recovery path is **section C2** below.
> ISO recommendation is now **24.04 LTS**: 22.04 hits end of standard support 2027-04,
> and 24.04's newer kernel improves I219-LM NIC support — it may fix the failure outright.

> The EliteDesk 800 G4 Mini ships with Windows 10/11 Home preinstalled. Phase 0.1 wipes it
> for **Ubuntu Server 24.04 LTS** and ends with the box reachable over SSH so the rest of
> the build is driven remotely. Steps are split: **[KEYBOARD]** = done at the box (no OS = no
> SSH yet); **[SSH]** = run after the box is reachable. Capture real output back into this
> file as you go — don't trust a step until you've seen it succeed.

**Target:** HP EliteDesk 800 G4 Mini · i5-8500T · 16 GB · 256 GB NVMe → hostname `talonsoc`.

---

## A. Before you start — [KEYBOARD]

- [ ] A spare USB stick ≥ 4 GB (it gets wiped).
- [ ] Download **Ubuntu Server 24.04.x LTS** ISO (the `live-server` amd64 image). If the
      USB is still flashed with 22.04 from last time, re-flash — 15 minutes buys support
      to 2029 plus a kernel that handles the I219 NIC better.
- [ ] Write it to USB with **balenaEtcher** (Mac/Win) or `dd`. Nothing on the EliteDesk's
      Windows install needs saving — it's fresh OEM.
- [ ] **Note your LAN subnet from the Mac** (needed if DHCP fails again):
      `netstat -nr -f inet | grep '^default'` → gateway = the BE550 (e.g. `192.168.0.1`);
      static fallback = same subnet, high host number (e.g. `192.168.0.250/24`).
- [ ] **Cable the box directly into a BE550 LAN port** — NOT through the TL-SG108E until
      that switch is configured. An unconfigured managed switch in line is a classic
      silent DHCP killer.
- [ ] Samsung monitor + UGREEN KVM are racked now — put the EliteDesk on a KVM port so
      keyboard work doesn't mean re-cabling. **Don't switch KVM channels mid-install** —
      composite-HID re-enumeration can drop keyboard input at GRUB/installer; keep a
      direct keyboard within reach as fallback.
- [ ] When racking after the install: the BE550 and SG108E belong on the UPS with the box —
      a power blip that drops the LAN also drops SSH and any in-flight agent enrollments.
- [ ] Decide a username (e.g. `kyle`) and have your SSH **public** key ready
      (`~/.ssh/id_ed25519.pub` on this Mac — `cat` it, or import from GitHub during install).

> If you don't have a key on this Mac yet: `ssh-keygen -t ed25519 -C "talonsoc"` (accept defaults).

## B. BIOS + boot from USB — [KEYBOARD]

1. Insert the USB. Power on, tap **F10** to enter BIOS (HP) — or **F9** for the one-time boot menu.
2. While you're in BIOS, set the always-on posture (the box lives on the UPS now):
   - **Advanced → Power Management Options → After Power Loss → Power On**
   - Disable **S5 Maximum Power Savings** / deep-sleep options (they can power down the NIC PHY)
3. (Optional) Secure Boot can stay **on** — Ubuntu supports it. If the USB won't boot, disable it.
4. Boot the USB → choose **Try or Install Ubuntu Server**.

## C. Ubuntu Server installer — [KEYBOARD]

Walk the guided installer:

1. **Language / keyboard** → English / your layout.
2. **Installer type** → Ubuntu Server (not minimized).
3. **Network** → if DHCP works, **write the IP down** — you'll SSH to it. Also record the
   MAC shown next to the interface (for the router DHCP reservation in step F).
   **If it shows "all interfaces disabled" or DHCP fails → section C2 below.** Don't
   fight this screen — C2 is the 30-second triage, and the install can finish on a
   manual IP or with no network at all.
4. **Proxy** → blank. **Mirror** → default.
5. **Storage** → **Use an entire disk** (this wipes Windows), guided, with LVM is fine.
   **Gotcha:** guided LVM only allocates ~half the disk to `ubuntu-lv`. On the summary
   screen, edit `ubuntu-lv` → set size to the maximum — the indexer needs the full
   256 GB. Confirm the destructive write when prompted.
6. **Profile** →
   - Your name: `Kyle`
   - Server name (hostname): `talonsoc`
   - Username: `kyle`
   - Password: a strong one (you'll mostly use the SSH key after this).
7. **SSH Setup** → ✅ **Install OpenSSH server** — *this is the step that lets me take over.*
   - ✅ Import SSH identity → **from GitHub** (`ktalons`) if your key is there, or skip and we
     add the key in step E.
8. **Featured server snaps** → select **none** (keep it lean; Docker comes from apt).
9. Let it install → **Reboot**, remove the USB.

## C2. If the network step fails — recovery [KEYBOARD]

> June 27 failure mode: "all interfaces disabled," DHCPv4 autoconfiguration failed.
> Triage order: physical → shell probes → manual IP → skip network. Every path ends
> with the install finishing.

**First, physical (the most likely cause):** reseat the cable, confirm it runs straight
to a BE550 LAN port, and look for link LEDs at both ends. No LEDs = cable/port problem,
full stop.

**Then split the problem in 30 seconds** — from the installer: `Help → Enter shell`
(or `Ctrl+Alt+F2`):

```bash
ip -br link                        # interface name: eno1 or enp0s31f6
ip link set eno1 up; sleep 5
cat /sys/class/net/eno1/carrier    # 1 = link up → DHCP problem, go to (B)
                                   # 0 / NO-CARRIER → link problem, go to (A)
```

### (A) No carrier — the link never comes up

```bash
lspci -nnk | grep -iA3 ethernet    # NIC on the bus? "Kernel driver in use: e1000e"?
dmesg | grep -iE 'e1000e|nvm|unit hang|phy reset'
```

| Evidence | Meaning | Fix |
|---|---|---|
| NIC missing from `lspci` | LAN disabled in BIOS | F10 → Advanced → enable LAN controller |
| `NVM Checksum Is Not Valid` | NIC firmware quirk | `modprobe -r e1000e && modprobe e1000e`; durable fix = HP BIOS update |
| `Detected Hardware Unit Hang` | driver/offload quirk | `ethtool -K eno1 tso off gso off sg off`, retry |
| `PHY reset is blocked due to SOL/IDER` | Intel AMT interference | MEBx (`Ctrl+P` at boot) → disable AMT → **cold** power-off 30 s |
| Clean logs, still no carrier | cable/port/negotiation | swap cable + router port; last resort `ethtool -s eno1 speed 100 duplex full autoneg off` |

### (B) Carrier = 1 but DHCP fails

```bash
dhclient -v eno1                   # watch: OFFERs received, or silence?
```

- **Silence (no OFFERs):** wait 60 s, retry once — spanning-tree on a switch port can eat
  the first DHCP window. Still nothing → back in the installer UI, set IPv4 to **Manual**
  using the subnet noted in step A (e.g. address `192.168.0.250/24`, gateway
  `192.168.0.1`, DNS `192.168.0.1` or `1.1.1.1`). Manual is fine forever — the IP gets
  pinned in step F anyway.
- **OFFERs arrive but never bind:** `ethtool -K eno1 rx off tx off`, retry `dhclient`.

**Either way, record the MAC:** `cat /sys/class/net/eno1/address` → needed for the router
reservation in step F.

### (C) Escape hatch — nothing works

Choose **Continue without network** in the installer. The install completes fine offline;
fix networking post-boot (step D0) from a full OS where `tcpdump` and friends exist.

## D. First boot + updates — [KEYBOARD]

**D0 — only if you installed without network:** create `/etc/netplan/01-lan.yaml`:

```yaml
network:
  version: 2
  ethernets:
    eno1:                # your interface name from `ip -br link`
      dhcp4: true        # or a static block matching your C2(B) manual config
```

then `sudo netplan apply && ip -br addr`. Diagnose from the full OS if it still fights you.

```bash
ip a                                   # confirm the IP (note the interface name, e.g. enp1s0)
sudo apt update && sudo apt -y upgrade
sudo reboot                            # if a kernel updated
```

## E. Confirm SSH from the Mac — [SSH] (from this Mac)

```bash
# If you imported the key during install, this just works:
ssh kyle@<box-ip>

# If you skipped key import, copy it now (one-time, uses your password):
ssh-copy-id kyle@<box-ip>
ssh kyle@<box-ip>                      # should NOT prompt for a password now
```

Once `ssh kyle@<box-ip>` logs in with the key and no password → **the box is mine to drive.**
Give me `kyle@<box-ip>` and I take it from step F.

> Harden SSH (disable password login) only **after** key login is confirmed working:
> in `/etc/ssh/sshd_config.d/99-hardening.conf` set `PasswordAuthentication no` and
> `PermitRootLogin no`, then `sudo systemctl restart ssh`.

---

## F. Host prep — [SSH] (I run these once the box is reachable)

The plan I'll execute over SSH (recorded here so it's reviewable; real output gets pasted back):

```bash
# 1. Stable IP — DHCP reservation on the router (preferred) OR a static netplan.

# 2. Kernel param the Wazuh indexer requires:
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
sudo sysctl --system && sysctl vm.max_map_count    # expect 262144

# 3. Docker Engine + compose plugin (official apt repo):
sudo apt -y install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt update
sudo apt -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker kyle           # log out/in so `docker` works without sudo
docker --version && docker compose version

# 4. UFW — default deny in, SSH + Wazuh ports from the LAN only (adjust 192.168.x.0/24):
sudo apt -y install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.x.0/24 to any port 22 proto tcp     # SSH (LAN only)
sudo ufw allow from 192.168.x.0/24 to any port 443 proto tcp    # dashboard
sudo ufw allow from 192.168.x.0/24 to any port 1514 proto tcp   # agent data
sudo ufw allow from 192.168.x.0/24 to any port 1515 proto tcp   # agent enrollment
sudo ufw allow from 192.168.x.0/24 to any port 55000 proto tcp  # Wazuh API
sudo ufw enable && sudo ufw status verbose

# 5. unattended-upgrades (security patches):
sudo apt -y install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
```

Then Phase 0.2 = clone the repo on the box, `cd deploy/soc-recon`, generate certs, `docker compose up -d`
(see `deploy/soc-recon/README.md` → Run). Phase 0.3 = PHOENIX volume snapshot.

## Acceptance — Phase 0.1

- [ ] Ubuntu Server 24.04 LTS booting on the EliteDesk; Windows gone
- [ ] `ssh kyle@<box-ip>` logs in with key, no password prompt
- [ ] `sysctl vm.max_map_count` → `262144`
- [ ] `docker compose version` succeeds; `kyle` in the `docker` group
- [ ] `sudo ufw status` → deny incoming, LAN-only allows for 22/443/1514/1515/55000
- [ ] Box IP pinned (reservation or static) and recorded here: `__________`
