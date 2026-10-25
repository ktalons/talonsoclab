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

## 5. Updates and reboots — [SSH]

*Added 2026-10-23 (S0.7).* Ubuntu's `unattended-upgrades` runs daily from
`apt-daily-upgrade.timer` (06:00 UTC plus up to an hour of random delay). It installs security
updates, kernels included, and **never reboots the box**: `Unattended-Upgrade::Automatic-Reboot`
stays at its default of off. `wazuh-agent` is on its `Package-Blacklist` and held with
`apt-mark hold` (runbook 05).

Reboots stay manual on purpose. Every reboot brings the manager back by a plain start, whose
init stops before its config copy (the multigroups trap, `docker-compose.yml` GOTCHA 2). S0.5's
backup relies on that stop, so the trap stays in Phase A and its fix moves to Phase B together
with an explicit hold for the backup. An automatic reboot could also land in the middle of a
Tier 2 run (runbook 09).

A manual policy goes stale without telling you. In September unattended-upgrades moved the
kernel from -27 to -34, and only a project review noticed. So a daily check turns a pending
reboot into an alert:

| Piece | What it does |
|---|---|
| `systemd/soc-recon-reboot-check.sh` | Reads `/run/reboot-required` (written by `update-notifier-common`) and compares the running kernel with the newest `/boot/vmlinuz-*`. Prints one line, writes nothing. |
| `systemd/soc-recon-reboot-check.timer` | 08:00 UTC, after unattended-upgrades, and 5 min after every boot. |
| Rule 100330, level 3 | `no reboot required: running=<release>`, the daily all-clear. |
| Rule 100331, level 7 | `reboot required: running=... newest=... flag=... pkgs=...` |
| Rule 40704 | The unit failed. `OnFailure=` covers a kill or an exec error. |

The line reaches the manager through agent 002's journald localfile, the same path as the job
age rules (runbook 06, section 6).

### Install

Pull first, then install the new rule file on the manager the way every config change goes in
(runbook 06, section 3, a force-recreate, never a plain restart). Then, from `deploy/soc-recon`:

```bash
sudo install -o root -g root -m 0755 systemd/soc-recon-reboot-check.sh /usr/local/sbin/
sudo install -o root -g root -m 0644 systemd/soc-recon-reboot-check.service \
  systemd/soc-recon-reboot-check.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start soc-recon-reboot-check.service
journalctl -u soc-recon-reboot-check.service -n 3 --no-pager   # the one line
sudo systemctl enable --now soc-recon-reboot-check.timer
systemctl list-timers 'soc-recon-*'      # four timers, each with a NEXT time
```

`soc-recon-unit-failed@.service` is already installed (runbook 08, section 1).

A manual `apt upgrade` that takes `docker-ce` or `containerd.io` restarts the Docker daemon, and
every container comes back by a plain start, the same as after a reboot. Treat it like one: no
Tier 2 run going, then the init check below. Both come from Docker's own repo, which
unattended-upgrades does not track by default, so only a manual upgrade does this.

### A controlled reboot

When 100331 fires, reboot when no Tier 2 run is going and you can watch it come back:

```bash
sudo reboot
# then, about 10 min later:
uname -r                                  # the newest kernel
docker compose ps                         # four containers, healthy
docker compose logs -t --since 15m wazuh.manager | sed -n '/0-wazuh-init: executing/,/0-wazuh-init: exited/p'
```

The manager's init says `exited 1`, and the only error before it is the multigroups copy from
`data_tmp`: `Error executing command: 'cp -ar /var/ossec/data_tmp/permanent/var/ossec/var/multigroups/. /var/ossec/var/multigroups'`,
with every other permanent path reported as already mounted. That is the accepted trap. Any other error is a real failure. Check that all three
agents are Active in the dashboard, and that 100330 fires about 5 min after boot.

## Acceptance — Phase 0.1

- [x] Ubuntu Server 26.04 LTS booting, Windows gone
- [x] `ssh talon@<box-ip>` logs in with key, no password prompt
- [x] `sysctl vm.max_map_count` ≥ `262144` (26.04 defaults to 1048576)
- [x] `docker compose version` succeeds; `talon` in the `docker` group
- [x] `ufw status` → deny incoming, LAN-only allows on 22/443/1514/1515/55000
- [x] Box IP pinned by DHCP reservation and recorded

Next: [`01-network-switch-cutover.md`](01-network-switch-cutover.md), then the stack itself
(`deploy/soc-recon/README.md`).
