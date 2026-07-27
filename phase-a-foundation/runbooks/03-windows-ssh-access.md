# Phase A.0 — SSH access to the Windows endpoint

> **What this does:** stands up OpenSSH Server on the Dell OptiPlex 7070 and configures
> key-only login from the Mac, so the rest of Phase A can be driven from one terminal.
>
> **Why it matters for a SOC:** A.1 is a paste-the-output job. Doing it from the Dell's own
> keyboard means retyping or screenshotting every result, and transcription errors in a
> *verification* step defeat the point of verifying. There's a second payoff: SSH logons
> generate Security-channel events and, once Sysmon is in, process-creation events. Your own
> logins become free verification traffic.
>
> Steps are tagged **[MAC]** and **[BOX]**. Real addresses are `<DELL-IP>` per the repo's
> no-real-IPs rule.
>
> **Completed 2026-07-26.** Prerequisite: a DHCP reservation for the Dell.

---

## 1. Install the server capability — [BOX]

Windows ships the OpenSSH **Client** enabled and the **Server** not installed. These are
independent capabilities, and the distinction is the first place to go wrong — most guides say
"install OpenSSH Client" because the common case is Windows connecting *out*. This lab is the
reverse direction, so **Server** is the one to add.

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
Get-Service sshd | Select-Object Name, Status, StartType
```

**`StartType` must be `Automatic`.** `Add-WindowsCapability` leaves it `Manual`, which works
until the first reboot and then silently doesn't.

## 2. Fix the network profile — [BOX]

```powershell
Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory Private
```

A firewall rule only applies to the profiles it is scoped to. Windows classifies a new wired
connection as **Public**, so the OpenSSH rule reads `Enabled: True` and is simultaneously not in
effect — connections time out rather than being refused. Private is also correct for a lab LAN
regardless, and it matters again for agent↔manager traffic in A.1.

## 3. Key generation — [MAC]

A **dedicated** lab keypair, not the everyday key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_talonlab -N "" -C "talonsoclab-mac-to-dell"
```

The Dell becomes the Phase C victim network. Authorising the key that also reaches GitHub into
an Administrators account on a box you intend to deliberately compromise is the wrong habit.
No passphrase is a deliberate tradeoff, not an oversight: it allows scripted verification
without prompts, the key's entire reach is one lab host behind a firewall, and it's revocable
in one line.

```
Host talondell
  HostName <DELL-IP>
  User ktalo
  IdentityFile ~/.ssh/id_ed25519_talonlab
  IdentitiesOnly yes
```

**Put specific host blocks above `Host *`.**

## 4. Authorize the key — [BOX]

```powershell
Get-LocalGroupMember -Group Administrators | Select-Object Name
```

If the login account is in that list, the default Windows `sshd_config` ends with:

```
Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
```

**`~/.ssh/authorized_keys` is ignored entirely for admin accounts.** The key goes in the
machine-wide file, with restricted ACLs:

```powershell
$f = 'C:\ProgramData\ssh\administrators_authorized_keys'
Add-Content -Path $f -Value '<PUBLIC-KEY-LINE>' -Encoding ascii
icacls $f /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
```

No `sshd` restart needed — `authorized_keys` is read per connection. **Leave password auth
enabled until key login is proven.** Hardening auth before the key works is how you lock
yourself out of a box you're treating as headless.

## 5. Verify — [MAC]

```bash
ssh -o BatchMode=yes talondell "hostname && whoami"
```

`BatchMode=yes` disables every interactive prompt, so success **proves the key did the work**
and no password fallback occurred. Without it you've confirmed only that you can log in
somehow. Also confirm the host key fingerprint out-of-band rather than trusting first-connect.

## 6. Harden — [BOX], after A.1

```powershell
# both directives required, both ABOVE the Match block
PasswordAuthentication no
KbdInteractiveAuthentication no
```

```powershell
& 'C:\Windows\System32\OpenSSH\sshd.exe' -T > effective.txt 2>&1   # validate BEFORE restart
Restart-Service sshd
```

Acceptance is the **refusal message**, not the config file:

```bash
ssh -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=0 talondell true
# want exactly: Permission denied (publickey).
```

Any additional method listed in those parentheses is a remaining password path.

## Acceptance

- [x] `sshd` Running, StartType Automatic — survives reboot
- [x] Inbound rule enabled **and** in an active profile (`NetworkCategory: Private`)
- [x] Key-only login confirmed under `BatchMode=yes`
- [x] `administrators_authorized_keys` ACL = SYSTEM + Administrators only
- [x] Host key fingerprint verified out-of-band
- [x] Default shell = PowerShell (PS7)
- [x] Password authentication disabled *(completed after A.1)*

## Parked decision — Phase C

When the Dell becomes the victim network, SSH is either **disabled** or **kept as intentional
attack surface**. Decide deliberately and write it down. The failure mode is letting an
admin-authorized key on a deliberately-vulnerable host persist by accident.
