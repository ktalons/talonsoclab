# Phase A.0 — SSH access to the Windows endpoint (`talondellbox`)

> **What this does:** stands up OpenSSH Server on the Dell OptiPlex 7070 and configures
> key-only login from the Mac, so the rest of Phase A can be driven from one terminal.
>
> **Why it matters for a SOC:** A.1 (agent + Sysmon enrollment) is a paste-the-output job.
> Doing it from the Dell's own keyboard means retyping or screenshotting every result, and
> transcription errors in a verification step defeat the point of verifying. There's a second
> payoff: SSH logons generate Security-channel logon events and, once Sysmon is in, process
> creation events. Your own logins become **free verification traffic** — watching your
> session land in the dashboard proves the pipeline works, rather than waiting for something
> to happen unprompted.
>
> Steps are tagged **[MAC]** = local workstation, **[BOX]** = Administrator PowerShell on the
> Dell. Real IPs are `<DELL-IP>` / `<MAC-IP>` here per the repo's no-real-IPs rule; the actual
> values live in the local-only access note, not in git.
>
> **Completed 2026-07-26.**

**Prerequisite:** the Dell has a DHCP reservation on the BE550. Without it the address moves,
the `known_hosts` entry goes stale, and every doc referencing the host has to be re-touched.

---

## 1. Install the server capability — [BOX]

Windows 10/11 ship the OpenSSH **Client** enabled by default and the **Server** not installed.
These are independent capabilities and the distinction is the first place to go wrong:

| Capability | Binary | Direction | Needed here? |
|---|---|---|---|
| OpenSSH Client | `ssh.exe` | Dell reaches **out** | No — already present |
| OpenSSH Server | `sshd` service, listens :22 | Dell accepts **in** | **Yes** |

Most tutorials say "install OpenSSH Client" because the common case is a Windows workstation
connecting out to Linux. This lab is the reverse direction — Mac in to Windows — so **Server**
is the one to add. Either the Optional Features GUI or:

```powershell
Get-WindowsCapability -Online -Name OpenSSH.Server* | Select-Object Name, State
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

Get-Service sshd | Select-Object Name, Status, StartType
Get-NetFirewallRule -Name *OpenSSH*Server* | Select-Object DisplayName, Enabled, Direction
```

**`StartType` must be `Automatic`.** `Add-WindowsCapability` leaves it `Manual`, which works
until the first reboot and then silently doesn't — you lose remote access to a box you were
treating as headless and won't know why.

Captured:

```
Name: sshd   Status: Running   StartType: Automatic
DisplayName: OpenSSH Server (sshd)   Enabled: True   Direction: Inbound
```

---

## 2. The network profile trap — [BOX]

With `sshd` Running and an inbound firewall rule reporting `Enabled: True`, the connection
still failed:

```
[MAC] nc -vz <DELL-IP> 22   → Operation timed out
[MAC] ping <DELL-IP>        → 100% packet loss
```

Read those two results carefully, because the diagnosis is in the *kind* of failure:

- **Ping silence means nothing.** Windows Defender blocks inbound ICMP echo by default. This
  is a red herring and will send you looking at the wrong layer.
- **"Timed out" ≠ "connection refused."** *Refused* means the packet reached the host and
  something actively declined — nothing listening. *Timed out* means packets are being
  **dropped silently**, which is firewall-shaped behaviour. Combined with `sshd` confirmed
  Running, that points away from the service and at what sits in front of it.

The cause: a firewall rule only applies to the **profiles** it is scoped to. Windows had
classified the wired connection as **Public**, so the rule was simultaneously enabled and
not in effect.

```powershell
Get-NetTCPConnection -LocalPort 22 -State Listen | Select-Object LocalAddress, LocalPort, State
Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory
Get-NetFirewallRule -Name *OpenSSH*Server* | Select-Object Name, Enabled, Direction, Action, Profile
```

`NetworkCategory: Public` → fix it. Private is correct for a lab LAN regardless, and it
matters again for agent↔manager traffic in A.1:

```powershell
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory Private
```

Retest immediately: `nc -vz <DELL-IP> 22` → `open`.

> **Generalise this.** "Service running + rule enabled + still unreachable" on Windows is the
> network profile roughly every time. Check `NetworkCategory` before touching anything else.

---

## 3. Key generation — [MAC]

A **dedicated** lab keypair, not the everyday key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_talonlab -N "" -C "talonsoclab-mac-to-dell"
```

Two deliberate decisions:

- **Separate from the primary key.** The Dell becomes the Phase C victim network. Authorising
  the key that also reaches GitHub into an Administrators account on a box you intend to
  deliberately compromise is the wrong habit. This keeps blast radius inside the lab.
- **No passphrase.** A tradeoff, not an oversight: it allows scripted verification against the
  box without prompts. Acceptable because the key's entire reach is one lab host on a
  UFW-protected LAN, and it is revocable in one line.

Client config, `~/.ssh/config`:

```
Host talondell
  HostName <DELL-IP>
  User ktalo
  IdentityFile ~/.ssh/id_ed25519_talonlab
  IdentitiesOnly yes
  ServerAliveInterval 60
  ServerAliveCountMax 3
```

**Put specific host blocks above `Host *`.** `IdentityFile` directives *accumulate* rather
than first-match-wins, so a `Host *` block at the top of the file gets its key offered first
on every connection — one **failed publickey attempt logged per login**. In a lab whose whole
purpose is alerting on failed logons, that is self-inflicted false-positive noise. `IdentitiesOnly yes`
plus block ordering keeps each connection to a single offered key.

---

## 4. The administrators_authorized_keys trap — [BOX]

The single most likely thing to cost you an hour. Check group membership first:

```powershell
Get-LocalGroupMember -Group Administrators | Select-Object Name
```

If the login account is in that list — it is here (`TALONDELLBOX\ktalo`) — then the default
Windows `sshd_config` ends with:

```
Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
```

**`~/.ssh/authorized_keys` is ignored entirely for admin accounts.** The key goes in the
machine-wide file, with restricted ACLs:

```powershell
$key = '<PUBLIC-KEY-LINE>'
$f = 'C:\ProgramData\ssh\administrators_authorized_keys'

Add-Content -Path $f -Value $key -Encoding ascii

icacls $f /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
icacls $f
```

Two silent failures live in those four lines:

1. **`-Encoding ascii` is mandatory.** Windows PowerShell 5.1's `-Encoding utf8` writes a
   **BOM**, and `sshd` cannot parse the first key in a BOM'd file. `>` or `Out-File` is worse
   — UTF-16LE, nothing works. Both failure modes present as a password prompt with no useful
   log line. (PowerShell 7's `utf8NoBOM` default is fine, but don't rely on which shell you're
   in.)
2. **`/inheritance:r` is mandatory.** `sshd` refuses the file if any account beyond
   Administrators and SYSTEM can write it, and again says nothing useful about why.

Verified ACL — these two entries and nothing else:

```
NT AUTHORITY\SYSTEM:(F)
BUILTIN\Administrators:(F)
```

No `sshd` restart needed. `authorized_keys` is read per connection.

**Leave password authentication enabled until key login is proven.** Hardening auth before
the key works is how you lock yourself out of a box you're treating as headless.

---

## 5. Verify — [MAC]

```bash
ssh -o BatchMode=yes talondell "hostname && whoami && ver"
```

`BatchMode=yes` disables every interactive prompt, so a success here **proves the key did the
work** and no password fallback occurred. That distinction is the whole verification; without
it you've confirmed only that you can log in somehow.

```
talondellbox
talondellbox\ktalo
Microsoft Windows [Version 10.0.26200.8894]
```

Also confirm the host key fingerprint out-of-band rather than trusting first-connect. On the
Dell: `ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub`, and compare against the
value recorded in the local-only access note.

---

## 6. Default shell → PowerShell — [BOX]

The default remote shell is `cmd.exe`, where `;` is **not** a command separator. Sending
`hostname; whoami` passes `;` and `whoami` as *arguments* to `hostname.exe`, which fails with
a misleading message about the Network Control Panel Applet. The connection is fine; the
syntax isn't. Every PowerShell command otherwise needs `powershell -NoProfile -Command "..."`
wrapping with escaped quotes for the rest of Phase A.

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
  -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -PropertyType String -Force
```

Applies to the next new session; no service restart.

---

## Acceptance

- [x] `sshd` Running, StartType Automatic — survives reboot
- [x] Inbound rule enabled **and** in an active profile (`NetworkCategory: Private`)
- [x] Key-only login confirmed under `BatchMode=yes`
- [x] `administrators_authorized_keys` ACL = SYSTEM + Administrators only
- [x] Host key fingerprint verified out-of-band
- [x] Default shell = PowerShell — **corrected 2026-07-27.** This box was ticked in error: the
  `New-ItemProperty` above never took, `HKLM\SOFTWARE\OpenSSH` had no `DefaultShell` value, and
  the remote shell stayed `cmd.exe`. It surfaced when a `|` in a remote command was interpreted by
  cmd instead of PowerShell (`'PubkeyAuthentication' is not recognized`). Now set, and pointed at
  `C:\Program Files\PowerShell\7\pwsh.exe` rather than Windows PowerShell 5.1. Verified by
  `ssh talondell '$PSVersionTable.PSVersion.ToString()'` → `7.6.4`, and `scp` re-tested afterwards
  (unaffected — OpenSSH 9.5 runs scp over the SFTP subsystem, not the login shell).
- [x] Password authentication disabled — **completed 2026-07-27, after A.1.**

### Closing password auth — the part most guides miss

`PasswordAuthentication no` **is not sufficient on Windows.** With only that set, the refusal reads:

```
Permission denied (publickey,keyboard-interactive).
```

`KbdInteractiveAuthentication` is a *separate* method, defaults to `yes`, and on Microsoft's
OpenSSH port it performs password validation — handing back the exact login path you meant to
close. Both directives are required:

```
PasswordAuthentication no
KbdInteractiveAuthentication no
```

**Placement matters more than the values.** `sshd_config` ends with a `Match Group administrators`
block, and **`Match` scopes everything after it until the next `Match` or EOF** — so appending to
the end of the file silently scopes your hardening to that one group. That happened here: an
`Add-Content` landed the directive below the `Match` line and `sshd -T` kept reporting
`kbdinteractiveauthentication yes`, because `sshd -T` without `-C` prints only the global config.
The line has to go **above** the `Match` block. Verify by line number, not by assumption:

```powershell
Select-String -Path C:\ProgramData\ssh\sshd_config -Pattern '^\s*(PasswordAuthentication|KbdInteractiveAuthentication|Match)'
# want both directives at lower line numbers than the Match line
```

Always validate before restarting — a bad config means sshd doesn't come back:

```powershell
& 'C:\Windows\System32\OpenSSH\sshd.exe' -T > C:\lab\install\sshd-effective.txt 2>&1
"config valid: " + ($LASTEXITCODE -eq 0)
```

Edit with **PowerShell 7**, not 5.1 — `Set-Content -Encoding utf8NoBOM` matters here, since 5.1's
`utf8` writes a BOM that sshd cannot parse past. Same trap as `administrators_authorized_keys`.

**Acceptance is the refusal message, not the config file.** From the Mac:

```bash
ssh -o BatchMode=yes talondell hostname                                    # key auth still works
ssh -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=0 talondell true # want: Permission denied (publickey).
```

The second must list **`(publickey)` only**. Any additional method in those parentheses is a
remaining password path. Note that `NumberOfPasswordPrompts=0` makes the client give up before
attempting, so a bare "Permission denied" from that flag alone proves nothing — it's the *method
list* that carries the evidence.

## Parked decision — Phase C

When the Dell becomes the Phase C victim network, SSH is either **disabled** or **kept as
intentional attack surface**. Decide deliberately and write it down. The failure mode is
letting an admin-authorized key on a deliberately-vulnerable host persist by accident.

## State at handoff

Neither the Wazuh agent nor Sysmon is installed yet (`Get-Service WazuhSvc,Sysmon*` returns
nothing). That is A.1, and it is now drivable over SSH.
