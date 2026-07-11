# Phase 0.1 — Host: Windows → Ubuntu Server 24.04 + Docker

> **STATUS (2026-07-11, verified over SSH):** install CONFIRMED — Ubuntu Server **26.04
> LTS** ("resolute"), kernel 7.0.0-27-generic, hostname `talonsoclab`, user `talon`,
> online via USB-WiFi adapter with a DHCP lease; GitHub key import worked (key-based SSH
> from the Mac verified live). Wired `eno1` is healthy but cable-less (`NO-CARRIER`) —
> June's "all interfaces disabled" was almost certainly just the missing cable.
> **Current blocker: forgotten login password** → section **R** at the keyboard. sudo is
> gated on it; SSH is not. After R, continue at step **F** (Docker, UFW, IP reservation).

> The EliteDesk 800 G4 Mini ships with Windows 10/11 Home preinstalled. Phase 0.1 wipes it
> for **Ubuntu Server LTS** (26.04 "resolute" as installed) and ends with the box reachable over SSH so the rest of
> the build is driven remotely. Steps are split: **[KEYBOARD]** = done at the box (no OS = no
> SSH yet); **[SSH]** = run after the box is reachable. Capture real output back into this
> file as you go — don't trust a step until you've seen it succeed.

**Target:** HP EliteDesk 800 G4 Mini · i5-8500T · 16 GB · 256 GB NVMe → hostname `talonsoclab` (as installed).

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
      silent DHCP killer. No cable long enough to reach the rack? → **section W**
      (WiFi interim), or park the box next to the router for the install and rack it after.
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
6. **Profile** → as installed (2026-07-11):
   - Server name (hostname): `talonsoclab`
   - Username: `talon`
   - Password: a strong one, **stored in the password manager** (PHOENIX Tier 3 —
     see §R for what happens when it isn't).
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

## W. Interim network — WiFi until the switch uplink exists [KEYBOARD]

> The rack's TL-SG108E needs a long ethernet run to the BE550 that doesn't exist yet, so
> the box rides **WiFi temporarily**. Wired through the switch supersedes this the day the
> cable arrives — WiFi is a bring-up convenience, not a SOC posture. (Wazuh agent traffic
> at Phase A volume is fine over WPA2; Suricata/SPAN work later requires wired.)

> **Reality check (2026-07-11):** no internal WLAN card, but a USB adapter (`wlx…`,
> in-kernel driver) came up fine with a DHCP lease — the dongle warning below proved too
> pessimistic. Optional stability tweak once sudo works:
> `sudo apt install iw && sudo iw dev <wlan> set power_save off`. Wired `eno1` verified
> healthy and waiting on the long cable — the wired cutover still supersedes WiFi.

1. **Does the box even have a WiFi card?** The 800 G4 Mini's WLAN module is *optional*
   hardware — many business units shipped without one. At the keyboard:
   `ip -br link` → look for `wlp*`/`wlo*`, or `lspci -nn | grep -i net`.
   **No card** → the WiFi plan is off: park the box next to the BE550 on a short cable
   (SSH doesn't care where the box physically sits), and rack it when the long cable
   arrives. Avoid USB WiFi dongles — Realtek driver roulette on a server isn't worth it.
2. **Fresh install, card present:** the installer's network screen can join WPA2 — select
   the wlan device, choose the SSID, enter the passphrase, continue as normal.
3. **Already installed, card present:** configure netplan (`wpasupplicant` ships with
   24.04 server):

   ```yaml
   # /etc/netplan/02-wifi.yaml   (sudo chmod 600 — contains the PSK; NEVER in git)
   network:
     version: 2
     wifis:
       wlp2s0:                    # your device name from `ip -br link`
         dhcp4: true
         access-points:
           "<SSID>":
             password: "<PSK>"
   ```

   `sudo netplan apply && ip -br addr` → note the IP; SSH from the Mac takes over from
   there (step E).
4. **Record the WiFi MAC** (`cat /sys/class/net/<wlan>/address`) and give it a DHCP
   reservation in the BE550 so the interim IP holds still.
5. **When the long cable arrives:** BE550 → SG108E uplink, box onto the switch wired,
   delete `02-wifi.yaml`, `sudo netplan apply`. The step-F UFW rules stay valid (same
   subnet).

## R. Forgot the login password — reset at the keyboard [KEYBOARD]

> SSH key login still works (`talon`), but tty login and **sudo** need the password.
> Reset takes ~3 minutes at the console:

1. Reboot the box. Hold **Esc** (or **Shift**) during boot for the GRUB menu.
2. **Advanced options for Ubuntu** → the top kernel's **(recovery mode)** entry.
3. Recovery menu → **root — Drop to root shell prompt**.
4. At the `#` prompt:
   ```bash
   mount -o remount,rw /
   passwd talon        # set the new password, twice
   reboot
   ```
5. If recovery mode won't cooperate: at GRUB press `e` on the default entry, append
   ` init=/bin/bash` to the `linux` line, **Ctrl+X** to boot, run the same
   `mount -o remount,rw / && passwd talon`, then `exec /sbin/init`.
6. Put it in the password manager this time — PHOENIX Tier 3 exists for exactly this.

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
# Key was imported from GitHub during install — verified working 2026-07-11:
ssh talon@<box-ip>

# (If a future rebuild skips key import, copy it with: ssh-copy-id talon@<box-ip>)
```

Once `ssh talon@<box-ip>` logs in with the key and no password → **the box is mine to drive.**
Give me `talon@<box-ip>` and I take it from step F.

> Harden SSH (disable password login) only **after** key login is confirmed working:
> in `/etc/ssh/sshd_config.d/99-hardening.conf` set `PasswordAuthentication no` and
> `PermitRootLogin no`, then `sudo systemctl restart ssh`.

---

## F. Host prep — [SSH] (I run these once the box is reachable)

The plan I'll execute over SSH (recorded here so it's reviewable; real output gets pasted back):

```bash
# 1. Stable IP — DHCP reservation on the router (preferred) OR a static netplan.

# 2. Kernel param the Wazuh indexer requires — 26.04 already defaults to 1048576
#    (≥ 262144), so this is belt-and-suspenders for PHOENIX rebuild determinism:
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
sudo sysctl --system && sysctl vm.max_map_count    # expect ≥ 262144

# 3. Docker Engine + compose plugin (official apt repo). If Docker hasn't published
#    the "resolute" (26.04) suite yet, apt update will 404 on docker.list —
#    substitute the previous LTS codename in that file and it works fine:
sudo apt -y install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt update
sudo apt -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker talon          # log out/in so `docker` works without sudo
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

- [x] Ubuntu Server 26.04 LTS booting on the EliteDesk; Windows gone *(verified over SSH 2026-07-11)*
- [x] `ssh talon@<box-ip>` logs in with key, no password prompt *(verified 2026-07-11)*
- [x] `sysctl vm.max_map_count` ≥ `262144` *(26.04 default: 1048576)*
- [ ] `docker compose version` succeeds; `talon` in the `docker` group
- [ ] `sudo ufw status` → deny incoming, LAN-only allows for 22/443/1514/1515/55000
- [ ] Box IP pinned (reservation or static) and recorded here: `__________`
