# Phase 0.4 — Network cutover: WiFi → wired through the smart switch

> **What this does:** moves the SOC box off its interim USB-WiFi link onto a wired
> connection through the rack's **TP-Link TL-SG108E** switch, pins its address with a DHCP
> reservation, and removes the temporary WiFi config. This is the last open item of the
> substrate phase (the box has been riding WiFi only because no long ethernet run existed).
>
> **Why it matters for a SOC:** wired is the correct posture for a sensor host — stable
> throughput, no WPA renegotiation dropping agent traffic, and (critically) the switch's
> **port-mirroring / SPAN** capability is what later lets a passive IDS (Suricata/Zeek) see
> traffic it isn't the destination for. WiFi can't mirror. The switch is a prerequisite for
> real network detection, not just tidier cabling.
>
> Steps are tagged **[HANDS]** = physical/at-the-keyboard, **[BOX]** = run on the SOC host,
> **[ROUTER]** = the BE550 web UI. Capture real output back into this file as you go — don't
> trust a step until you've seen it succeed.

**Kit involved:**
- **TP-Link Archer BE550** — the router. Acts as the **Layer 3 gateway**: it hands out DHCP
  leases, does DNS, routes to the internet, and is the WiFi AP. Gateway = `.1` on the LAN.
- **TP-Link TL-SG108E** — an 8-port **"Easy Smart"** switch. A **Layer 2** device: it fans
  one router port out to many wired hosts and forwards frames by MAC address. Gigabit,
  fanless, auto-MDI/MDIX (cable direction doesn't matter). VLAN- and SPAN-capable via a web
  UI, but forwards traffic fine with **zero configuration** on a flat network.
- **HP EliteDesk 800 G4 Mini** — the SOC host. Wired NIC is `eno1`; it's been dark
  (`NO-CARRIER`) only because nothing was plugged into it.

---

## 0. Concepts first (30-second orientation)

If any of this is new, read it once — it's the mental model the rest of the doc assumes, and
it's the knowledge this exercise is meant to build.

- **Router vs. switch.** The router is the *edge* — one WAN side (internet), one LAN side
  (your network), and it's the only device here doing Layer 3 (IP routing, DHCP, NAT). The
  switch is *interior* — pure Layer 2, no IP routing, it just moves Ethernet frames between
  the ports of the same network. You uplink the switch to one router LAN port, and now every
  switch port is on the same LAN as the router.
- **Broadcast domain / flat network.** Everything here shares one subnet
  (`192.168.x.0/24`) and one broadcast domain. That's fine for now. Splitting it into
  isolated segments (management / victim / sensor) is **VLANs — Phase C**, and the SG108E
  can do it. Today we stay flat.
- **Uplink.** Just the cable from a router LAN port to any switch port. The SG108E has no
  dedicated uplink port — all 8 are equal. **Use exactly one cable between the router and
  the switch.** A second one makes a loop that can broadcast-storm the LAN (the SG108E has
  loop prevention, but it's off by default — don't rely on it).
- **DHCP reservation vs. static IP.** A reservation lives on the router: "MAC `X` always
  gets IP `Y`." The host still does normal DHCP, so nothing is hard-coded on the box, but the
  address never changes. Preferred over a static IP because it's centrally managed and
  survives an OS reinstall. Keyed on the **MAC of `eno1`** (the wired NIC), which is why the
  reservation follows the interface, not the WiFi dongle.

---

## 1. Physical wiring — [HANDS]

Do this at the rack. The router and switch should both be on the UPS (a power blip that drops
the LAN also drops SSH and any in-flight agent enrollments).

1. **Seat the switch** in the rack and power it (UPS-protected outlet). No config needed — it
   forwards on boot.
2. **Uplink:** one cable from a **BE550 LAN port** → **any SG108E port** (say port 1). Watch
   for link LEDs at *both* ends. A solid/blinking LED = link negotiated. No LED = bad cable,
   bad port, or a dead run — swap the cable before anything else.
3. **SOC host:** cable the EliteDesk's **`eno1`** port → **another SG108E port** (say port 2).
   Confirm the link LED for that port lights.
4. **Sanity check the loop rule:** exactly **one** cable between router and switch; every other
   device hangs off its own switch port. Trace the cables with your finger if unsure.
5. **Cable grade:** any run must be **Cat5e or better** for gigabit. If a port negotiates at
   100 Mb, suspect the cable (see Step 3 verification).

> **While you're at the box (BIOS power posture, if not already set):** tap **F10** at boot →
> Advanced → Power Management → **After Power Loss = Power On**, and disable **S5 Maximum Power
> Savings / deep sleep** (it can power down the NIC PHY). This makes the box come back by
> itself after a UPS-covered outage. (Runbook 00 §B covers this; confirm it's set.)

---

## 2. Confirm the wired link came up — [BOX]

Check at the KVM console (WiFi may already be dropping its lease) that `eno1` now has carrier
and whether it pulled a DHCP lease:

> **Real-world gotcha (hit on this build):** carrier came up at gigabit but `eno1` had **no
> IPv4** — only a link-local. Cause: the installer's `00-installer-config.yaml` *declared*
> `eno1` (a `match:` + `set-name:` block) but the only `dhcp4: true` in the file sat under the
> **`wifis:`** block, not under `eno1`. A declared interface with no `dhcp4` never requests an
> address. Fix = add `dhcp4: true` (and `optional: true`) under the `eno1:` block, same
> indentation as `set-name:`, then `sudo netplan apply`. Don't reach for `dhclient` — 26.04
> ships `systemd-networkd`, not the ISC client; `netplan apply` / `networkctl renew eno1` is
> the right tool.

```bash
ip -br link                        # eno1 should now read UP (not NO-CARRIER)
cat /sys/class/net/eno1/carrier    # 1 = link is up
ip -br addr | grep -v '127.0.0'    # do you see an eno1 inet lease alongside the wlx WiFi one?
ethtool eno1 | grep -i speed       # expect 1000Mb/s — 100Mb/s means a Cat5/older cable
```

- **`eno1` shows an IP already** → the box is briefly **dual-homed** (wired + WiFi). Good —
  that's the safe state to cut over from. Go to Step 3.
- **`eno1` UP but no IP** → apply the netplan fix in the gotcha box above (`dhcp4: true` under
  `eno1`), then `sudo netplan apply`. If still nothing, check the switch port LED and the
  uplink; re-run Step 1.

> **Note the new wired IP** — it will differ from the WiFi IP until we reserve it in Step 4.

---

## 3. Cut over cleanly — remove the interim WiFi — [BOX]

> ⚠️ **Don't cut the branch you're sitting on.** If you're SSH'd in over WiFi, tearing down
> WiFi drops your session. Two safe ways:
> - **Preferred:** SSH to the **new wired IP** first (from Step 2). Once you're on the wired
>   session, removing WiFi won't disconnect you.
> - **Fallback:** do this step at the **KVM console**, where there's no network session to lose.

With the wired link confirmed and you connected over it:

> **Real-world gotcha (hit on this build):** there was no separate `02-wifi.yaml` to delete.
> The Ubuntu installer (subiquity) folds the WPA join into a **`wifis:` block inside the same
> `00-installer-config.yaml`** — SSID and PSK and all. So the teardown is "remove the `wifis:`
> block," not "delete a file." Since that block is the tail of the file, one non-interactive
> command does it cleanly (and dodges the editor entirely — see the Ghostty note below):

```bash
sudo cp /etc/netplan/00-installer-config.yaml ~/netplan-installer.yaml.bak   # safety net
sudo sed -i '/wifis:/,$d' /etc/netplan/00-installer-config.yaml              # strip wifis→EOF
sudo grep -n wifis /etc/netplan/00-installer-config.yaml                     # → prints nothing
sudo netplan apply
sudo ip addr flush dev wlxfc221c200528     # your wlx name from `ip -br link`
sudo ip link set wlxfc221c200528 down
ip -br addr | grep -v '127.0.0'            # only eno1 holds a LAN inet; wlx DOWN, no inet
```

Restore instantly if the edit goes wrong: `sudo cp ~/netplan-installer.yaml.bak
/etc/netplan/00-installer-config.yaml && sudo netplan apply`.

Then physically unplug the USB-WiFi dongle — it's no longer used.

> **Ghostty / `$TERM` gotcha:** SSHing from Ghostty, remote `nano` dies with
> `cannot initialize terminal type ($TERM="xterm-ghostty")` — the box's ncurses has no
> terminfo for it. That's why `sed` is the better tool here. If you *must* use an editor:
> `sudo TERM=xterm nano <file>` (or install Ghostty's terminfo on the box).

**Verify the stack survived the address change** (the containers bind to all interfaces, so a
new host IP is fine):

```bash
cd ~/talonsoclab/deploy/soc-recon        # adjust to your clone path
docker compose ps                        # indexer/manager/dashboard Up (healthy)
```

From the Mac, hit the dashboard at the **new wired IP**: `https://<wired-ip>` → login page.

> **UFW still valid:** the firewall rules allow the whole `192.168.x.0/24`, and the wired IP
> is in that same subnet — no rule change needed. (If you ever move the box to a *different*
> subnet, revisit the UFW allows.)

---

## 4. Pin the address — DHCP reservation — [ROUTER]

So the wired IP never moves (agents, dashboards, and SSH all target it), reserve it on the
BE550 keyed to `eno1`'s MAC.

1. Grab the wired NIC's MAC on the box: `cat /sys/class/net/eno1/address`.
2. In the **BE550 web UI** (`http://192.168.x.1`, or the TP-Link app):
   **Advanced → Network → DHCP Server → Address Reservation** (wording varies by firmware).
3. **Add a reservation:** MAC = `eno1`'s address, IP = the address it currently holds (keep it
   simple — reserve the lease it already has). Save.
4. On the box, renew to confirm the binding sticks:
   ```bash
   sudo dhclient -r eno1 && sudo dhclient -v eno1     # release + renew
   ip -br addr show eno1                              # same IP, now reserved
   ```

> Record the reserved IP in the (git-ignored) hardware/ISA notes, not in this committed file.

---

## 5. (Optional) Tour the switch's management UI — [HANDS]

You don't need this for a working flat network, but understanding it is the point of using a
*smart* switch — and it's where VLANs and SPAN live.

- **Default management address:** `192.168.0.1` (subnet `255.255.255.0`), login `admin`/`admin`.
  Note this is on a **different subnet** from your `192.168.1.x` LAN, so you can't reach it by
  default. Two ways in:
  - Temporarily give a laptop NIC a `192.168.0.x/24` address, plug into the switch, browse to
    `192.168.0.1`; **or**
  - From the web UI, change the switch's management IP to a free address on *your* LAN
    (e.g. `192.168.x.5`) or set it to DHCP, then reserve it on the BE550 like Step 4.
- **First things to change:** admin password (default creds on a management plane is exactly
  the anti-pattern this lab teaches), and set a static/reserved mgmt IP so you can always find
  it.
- **What's in there for later phases:**
  - **802.1Q VLANs** — segment management / victim / sensor networks (**Phase C**).
  - **Port Mirroring (SPAN)** — copy traffic from one/all ports to a sensor port so
    Suricata/Zeek can inspect it passively (**Phase A.3 / B**). This is the switch's payoff
    for the SOC.
  - **Loop prevention**, cable diagnostics, QoS, IGMP snooping.

Leave VLANs/SPAN unconfigured for now — flat L2 is the correct Phase 0 state.

---

## Acceptance — Phase 0.4 (network cutover)

- [ ] Switch racked and powered on the UPS; single uplink BE550 → SG108E (no loop)
- [ ] `eno1` **UP** with carrier, negotiated at **1000Mb/s**, holding a DHCP lease
- [ ] Interim `02-wifi.yaml` removed; box is **wired-only** (`ip -br addr` shows no `wlx`)
- [ ] Stack green over the **new wired IP**; dashboard reachable at `https://<wired-ip>`
- [ ] DHCP **reservation** for `eno1`'s MAC set on the BE550; IP survives release/renew
- [ ] BIOS **After Power Loss = Power On** confirmed; deep-sleep disabled
- [ ] (Optional) switch mgmt IP moved onto the LAN + admin password changed
- [ ] Reserved wired IP recorded in the git-ignored notes (not this file)

---

## What I learned (portfolio notes)

- **L2 vs L3, concretely.** The router is the only L3 device (routing, DHCP, DNS, NAT); the
  switch is pure L2 frame-forwarding. Uplinking the switch to one router port extends the same
  broadcast domain across all switch ports — no addressing changes, hosts just appear on the
  LAN.
- **Smart vs. managed vs. unmanaged.** The SG108E is "smart/Easy Smart" — it works unmanaged
  out of the box but exposes a web UI for VLANs, SPAN, QoS. Cheaper than fully-managed, enough
  for a home SOC lab, and the SPAN port is what makes passive IDS possible.
- **DHCP reservation over static.** Central, MAC-keyed, survives OS reinstalls; the address
  follows the *wired NIC*, which is why cutting over from WiFi to `eno1` needed a fresh
  reservation on `eno1`'s MAC.
- **Wired supersedes WiFi for a sensor host.** Stability and throughput, but the real reason
  is mirroring: an IDS must see traffic it isn't addressed to, and only a switch SPAN port
  delivers that.
- **Loop discipline.** Exactly one path between any two switches/router; a second cable is a
  broadcast-storm risk unless STP/loop-prevention is deliberately configured.
- **Don't cut the branch you're on.** Tearing down the interface carrying your SSH session
  drops it — cut over from the new link or the local console, a Layer-1 habit that saves
  remote-hands trips.
