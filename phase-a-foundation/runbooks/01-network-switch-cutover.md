# Phase 0.4 — Network cutover: WiFi → wired through the smart switch

> **What this does:** moves the SOC box off its interim USB-WiFi link onto a wired connection
> through the rack's TP-Link TL-SG108E, pins the address with a DHCP reservation, and removes
> the temporary WiFi config.
>
> **Why it matters for a SOC:** wired is the correct posture for a sensor host, but the real
> reason is **port mirroring**. A passive IDS has to see traffic it isn't the destination for,
> and only a switch SPAN port delivers that. WiFi cannot mirror. The switch is a prerequisite
> for network detection, not just tidier cabling.
>
> Steps are tagged **[HANDS]**, **[BOX]**, **[ROUTER]**.
>
> **Completed 2026-07-24.**

**Kit:** TP-Link Archer BE550 (router, the only Layer 3 device here — DHCP, DNS, gateway) ·
TP-Link TL-SG108E (8-port Easy Smart switch, Layer 2 frame forwarding, VLAN- and SPAN-capable
but works with zero configuration on a flat network) · HP EliteDesk 800 G4 Mini (`eno1`).

---

## 1. Wiring — [HANDS]

Router and switch both go on the UPS. A power blip that drops the LAN also drops SSH and any
in-flight agent enrollments.

1. Uplink: **one** cable, BE550 LAN port → any SG108E port. All 8 ports are equal; there's no
   dedicated uplink.
2. SOC host: `eno1` → another SG108E port.
3. Confirm link LEDs at **both** ends of every run. No LED means bad cable or bad port, and
   nothing else is worth checking until it lights.
4. **Exactly one cable between router and switch.** A second one is a loop, and loop
   prevention is off by default on this switch.
5. Cat5e or better, or the port negotiates at 100 Mb.

## 2. Confirm the wired link — [BOX]

```bash
ip -br link                        # eno1 should read UP, not NO-CARRIER
cat /sys/class/net/eno1/carrier    # 1 = link up
ip -br addr | grep -v '127.0.0'    # does eno1 hold a lease alongside the wlx one?
ethtool eno1 | grep -i speed       # expect 1000Mb/s
```

Seeing an IP on both `eno1` and the WiFi adapter means the box is briefly dual-homed. That's
the safe state to cut over from.

## 3. Remove the interim WiFi — [BOX]

> **Don't cut the branch you're sitting on.** SSH to the *new wired IP* first, or do this at
> the console. Tearing down the interface carrying your session drops it.

```bash
sudo cp /etc/netplan/00-installer-config.yaml ~/netplan-installer.yaml.bak
sudo sed -i '/wifis:/,$d' /etc/netplan/00-installer-config.yaml
sudo grep -n wifis /etc/netplan/00-installer-config.yaml    # prints nothing
sudo netplan apply
sudo ip addr flush dev <wlx-name> && sudo ip link set <wlx-name> down
ip -br addr | grep -v '127.0.0'                             # only eno1 holds a LAN inet
```

Restore from the backup if the edit goes wrong. Then unplug the dongle.

Verify the stack survived the address change — the containers bind to all interfaces, so a new
host IP is fine:

```bash
cd ~/talonsoclab/deploy/soc-recon && docker compose ps
```

UFW rules allow the whole `192.168.x.0/24` and the wired IP is in the same subnet, so no
firewall change is needed.

## 4. Pin the address — [ROUTER]

Reserve the lease against `eno1`'s MAC (`cat /sys/class/net/eno1/address`) in
**Advanced → Network → DHCP Server → Address Reservation**. Reserve the address it already
holds. Then confirm the binding sticks:

```bash
sudo networkctl renew eno1 && ip -br addr show eno1
```

A reservation beats a static IP: centrally managed, survives an OS reinstall, and nothing is
hard-coded on the box.

## Acceptance — Phase 0.4

- [x] Switch racked and powered on the UPS; single uplink, no loop
- [x] `eno1` UP with carrier, negotiated at 1000Mb/s, holding a lease
- [x] Interim WiFi removed; box is wired-only
- [x] Stack green on the new wired IP; dashboard reachable
- [x] DHCP reservation set; IP survives renew and a full reboot
- [x] BIOS After Power Loss = Power On; deep sleep disabled
- [ ] Switch mgmt IP moved onto the LAN + admin password changed *(deferred to Phase C, with VLANs)*

Left unconfigured on purpose: **802.1Q VLANs** (segmenting management / victim / sensor —
Phase C) and **SPAN** (Phase A.3, once there's a sensor to mirror to). Flat L2 is the correct
Phase 0 state.

---

## Findings

**A declared interface is not a leasing interface.** `eno1` came up at gigabit with carrier and
had no IPv4 at all. The installer's `00-installer-config.yaml` declared it properly — a `match:`
plus `set-name:` block — but the only `dhcp4: true` in the file sat under the **`wifis:`**
block. A fully declared interface with no `dhcp4` of its own never asks for an address. It
presents as a link problem and isn't one. Fix is `dhcp4: true` plus `optional: true` under
`eno1`.

**The WiFi config wasn't in its own file.** The plan said "delete `02-wifi.yaml`." That file
never existed. Ubuntu's installer folds the WPA join, SSID and PSK included, into a `wifis:`
block inside the same installer netplan file. The teardown is removing a block, not deleting a
file — and since that block is the tail of the file, `sed '/wifis:/,$d'` does it cleanly.

**Use `netplan`, not `dhclient`.** Ubuntu 26.04 ships `systemd-networkd`, not the ISC client.
`netplan apply` and `networkctl renew` are the right tools; reaching for `dhclient` out of habit
produces confusing errors.

**Terminal type breaks remote editors.** SSHing from Ghostty, remote `nano` dies with
`cannot initialize terminal type ($TERM="xterm-ghostty")` — the box's ncurses has no terminfo
for it. Another argument for `sed` over an interactive editor in a runbook. Workaround:
`sudo TERM=xterm nano <file>`.

**Default credentials on the management plane.** The SG108E pulled its own DHCP lease and
appeared as a wired client, still on `admin`/`admin`. A managed switch is a management plane
sitting inside the network it manages — exactly the anti-pattern this lab is meant to teach.
Flagged and deferred to Phase C rather than left unnoticed.
