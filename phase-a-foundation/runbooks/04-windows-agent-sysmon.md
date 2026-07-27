# Phase A.1 — Wazuh agent + Sysmon on the Windows endpoint (`talondellbox`)

> **What this does:** installs Sysmon with the sysmon-modular ruleset and the Wazuh 4.14.6 agent
> on the Dell OptiPlex 7070, enrolls it into the `phase-a-windows` group against a passworded
> `authd`, and verifies the result from the **manager**, not from the endpoint.
>
> **Why it matters for a SOC:** this is the first real telemetry in the lab. It's also the step
> where almost every failure is *silent* — an agent that reads `Active` can still be in the wrong
> group, running a stock four-event Sysmon config, or forwarding over a protocol the manager isn't
> listening on. Every check below exists because the naive version of it can pass while the
> pipeline is broken.
>
> Steps are tagged **[MAC]** = local workstation, **[BOX]** = PowerShell on the Dell. Real
> addresses are `<MANAGER-IP>` / `<DELL-IP>` per the repo's no-real-IPs rule.
>
> **Completed 2026-07-26.** Prerequisite: [`03-windows-ssh-access.md`](03-windows-ssh-access.md).

---

## 0. Preflight — gate before you install anything

Run these **before** the MSI, in this order, because each one fails before the one it would
otherwise mask.

### Manager side — [MAC → EliteDesk]

```bash
cd ~/talonsoclab/deploy/soc-recon

# 1. authd.pass is a FILE, not a directory, and non-empty
ls -l wazuh/authd.pass

# 2. what authd ACTUALLY loaded -- byte-level, not visual
docker compose exec -T wazuh.manager od -c /var/ossec/etc/authd.pass | tail -3

# 3. group dir has agent.conf AND merged.mg, both wazuh:wazuh
docker compose exec -T wazuh.manager ls -la /var/ossec/etc/shared/phase-a-windows/

# 4. exact group spelling you will pass to the MSI
docker compose exec -T wazuh.manager /var/ossec/bin/agent_groups -l
```

Why each one:

| Check | The silent failure it catches |
|---|---|
| `authd.pass` is a file | The compose bind-mounts `./wazuh/authd.pass`. **If that path doesn't exist on the host, Docker creates a _directory_ there.** authd then can't read a password and — per its documented behaviour — **generates a random one and carries on**. Manager reads perfectly healthy; every agent gets `Invalid password`. |
| `od -c` byte dump | A CRLF, a trailing space, or a UTF-8 BOM produces `Invalid password` against a password that looks correct on screen. Expect exactly `<N> chars` + one `\n`. |
| `merged.mg` exists, `wazuh:wazuh` | The entrypoint creates a fresh group dir `root:root`, but `wazuh-remoted` runs as `wazuh` — it can read the config and **cannot write the merged file**. Agents then enroll into the group happily and receive **nothing**, with no error anywhere. |
| `agent_groups -l` | A typo in `WAZUH_AGENT_GROUP` is **not rejected**. The agent silently lands in `default`, never gets the group's `agent.conf`, and collects no Sysmon channel while showing healthy. |

### Endpoint side — [BOX]

```powershell
Get-Date -Format o
"1514: " + (Test-NetConnection <MANAGER-IP> -Port 1514 -WarningAction SilentlyContinue).TcpTestSucceeded
"1515: " + (Test-NetConnection <MANAGER-IP> -Port 1515 -WarningAction SilentlyContinue).TcpTestSucceeded
"Admin: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")
"HVCI:  " + ((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning -join ",")
Get-Service Sysmon64,SysmonDrv,WazuhSvc -ErrorAction SilentlyContinue
```

**Test both ports.** 1515 is enrollment, 1514 is the data path. A green 1515 with a dead 1514
registers the agent and parks it at **`Never connected`** forever — and the naive one-port check
cannot tell the two apart.

> **PowerShell trap:** `Test-Connection` in Windows PowerShell 5.1 is **ICMP-only and has no
> `-Port` parameter**. `Test-NetConnection` is the one that does TCP. Getting these confused
> silently leaves a port untested — it did here, on the first attempt.

`HVCI` non-zero means Memory Integrity is on; that's the first suspect if `SysmonDrv` later fails
to start. On this box it returned `0`. Empty output from `Get-Service` = clean slate.

---

## 1. PowerShell 7 — [BOX]

Not just ergonomics. PS 5.1's `-Encoding utf8` writes a **BOM**, and section 4 places a
credential file where a BOM means silent rejection. The same trap cost time on
`administrators_authorized_keys` in A.0.

```powershell
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path C:\lab\install | Out-Null
$msi = 'C:\lab\install\PowerShell-7.6.4-win-x64.msi'

Invoke-WebRequest -UseBasicParsing -OutFile $msi `
  -Uri 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.4/PowerShell-7.6.4-win-x64.msi'

Get-AuthenticodeSignature $msi | Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject.Split(',')[0]}}

(Start-Process msiexec.exe -Wait -PassThru -ArgumentList `
  '/i', $msi, '/qn', '/norestart', 'REGISTER_MANIFEST=1', 'ENABLE_PSREMOTING=0', `
  '/l*v', 'C:\lab\install\ps7-install.log').ExitCode
```

Verify the **signature**, not a hash fetched from the same host as the file — a hash proves
transfer integrity, a signature proves provenance. Want `Status: Valid`, `ExitCode: 0` (`3010` =
success pending reboot, also fine). `REGISTER_MANIFEST=1` registers PS7's event log manifest so
pwsh activity is loggable, which is the point on a monitored endpoint.

**Reconnect your SSH session afterward.** `PATH` doesn't refresh inside a session that predates
the install, so `pwsh` won't resolve until you get a new one.

---

## 2. Sysmon — [BOX]

### Which config

Use the **prebuilt `sysmonconfig.xml`** from `olafhartong/sysmon-modular`.

Worth knowing: that prebuilt file was last regenerated by the repo's CI on **2023-09-20**, while
the fragment tree keeps merging PRs. That looks alarming and mostly isn't — the prebuilt covers
**all 22 Sysmon event types**, and the real delta since is 8 non-merge commits amounting to one
file extension, one image-load rule, and some syntax fixes.

Merging the fragments yourself with `Merge-SysmonXml.ps1` is a Phase B job, for two reasons: the
gain is marginal today, and at the step whose entire purpose is *proving the pipeline carries
telemetry*, a self-merged config nobody's CI has ever run becomes a **competing suspect** the
moment the channel reads empty. Swapping config later is one command — `Sysmon64.exe -c <new>.xml`,
no reinstall, no re-enrollment — so there is no cost to deferring it.

### Install

```powershell
$ErrorActionPreference = 'Stop'
Set-Location C:\lab\install

Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile 'Sysmon.zip'
Expand-Archive -Path 'Sysmon.zip' -DestinationPath 'C:\lab\install\Sysmon' -Force
$sysmon = 'C:\lab\install\Sysmon\Sysmon64.exe'
"Sysmon version: " + (Get-Item $sysmon).VersionInfo.ProductVersion
"Sysmon signature: " + (Get-AuthenticodeSignature $sysmon).Status

Invoke-WebRequest -UseBasicParsing -OutFile 'C:\lab\install\sysmonconfig.xml' `
  -Uri 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml'

$want = '4516404FA30EE87CEA558567820CDC78863CC4AB07889519E49EAC3CCA92E0D2'
$got  = (Get-FileHash 'C:\lab\install\sysmonconfig.xml' -Algorithm SHA256).Hash
if ($got -ne $want) { throw "CONFIG HASH MISMATCH - not installing. got=$got want=$want" }
"hash gate: PASS"

& $sysmon -accepteula -i 'C:\lab\install\sysmonconfig.xml'
```

Pinned artifact: `sysmonconfig.xml`, schemaversion **4.90**, commit `a9ff298f`, sha256
`4516404fa30ee87cea558567820cdc78863cc4ab07889519e49eac3cca92e0d2`.

The `throw` is the point of the block — if GitHub returns anything other than the reviewed file,
the sensor never loads unreviewed rules. Expect `Loading configuration file with schema version
4.90 / Sysmon schema version: 4.91 / Configuration file validated` — the binary's schema being
*newer* is fine and backward compatible. An **older** binary against a newer schema hard-fails,
so Sysmon must be ≥ 15.0 for a 4.90 config. (Installed here: 15.21.)

### Verify — by what it EMITS, not what it says

**This is the largest silent failure in the whole block.** `Sysmon64.exe -i` with a missing or
bad config still installs, still starts, still populates the channel — running a **default config
with four event types**. Process/network/registry/DNS coverage you think you have is simply
absent, and you find out in Phase B when a Sigma rule never fires and you debug the *rule*.

```powershell
Get-Service Sysmon64,SysmonDrv | Format-Table Name,Status,StartType -AutoSize
"driver loaded: " + [bool](fltmc filters | Select-String SysmonDrv)

Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 2000 |
  Group-Object Id | Sort-Object {[int]$_.Name} |
  Select-Object @{n='EventID';e={$_.Name}}, Count | Format-Table -AutoSize
```

| Config | Event IDs produced |
|---|---|
| **Stock default** | 1, 2, 5, 6 only |
| **sysmon-modular** | + 3, 7, 10, 11, 13, 15, 17, 22 … |

Observed on this box within minutes on an idle desktop: `1`(10) `3`(85) `4`(1) `5`(2) `7`(69)
`10`(57) `11`(18) `13`(137) `15`(19) `16`(1) `17`(3) `22`(6). Any of 3/7/10/11/13/15/17/22 proves
rules exist that the default cannot produce.

Check `fltmc` for the **driver**, not just the service — `Sysmon64` can read `Running` with
`SysmonDrv` failed to load, which yields a healthy-looking service and an empty channel.

> **Do NOT verify via `Sysmon64.exe -c`.** It emits **UTF-16LE**, which PowerShell captures as raw
> bytes with a null between every character, so *no* ASCII pattern match against it can ever
> succeed. It looks exactly like a failed config load on a perfectly healthy sensor. Two probes
> were burned learning this. If you want it anyway: `($c -replace "\0","")` first.

---

## 3. Wazuh agent — install without the password, on purpose

Sysmon is now live and recording **Event ID 1 with full command lines**. An `msiexec` line
carrying `WAZUH_REGISTRATION_PASSWORD` would be captured by the sensor you just installed and
indexed into your own SIEM as searchable event data — plus `ConsoleHost_history.txt` and the
Mac's shell history. So the password never goes on a command line.

Installing without it first is also a **negative control**: it proves `authd` is genuinely
*enforcing* the password rather than accepting anything.

```powershell
$msi = 'C:\lab\install\wazuh-agent-4.14.6-1.msi'
Invoke-WebRequest -UseBasicParsing -OutFile $msi `
  -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi'
Get-AuthenticodeSignature $msi | Select-Object Status

# NOTE: no WAZUH_REGISTRATION_PASSWORD, deliberately
(Start-Process msiexec.exe -Wait -PassThru -ArgumentList `
  '/i', $msi, '/qn', '/norestart', `
  'WAZUH_MANAGER=<MANAGER-IP>', `
  'WAZUH_REGISTRATION_SERVER=<MANAGER-IP>', `
  'WAZUH_AGENT_NAME=talondellbox', `
  'WAZUH_AGENT_GROUP=phase-a-windows', `
  'WAZUH_PROTOCOL=tcp', `
  '/l*v', 'C:\lab\install\wazuh-install.log').ExitCode

# read the properties BACK -- do not trust the command you typed
Select-String -Path 'C:\Program Files (x86)\ossec-agent\ossec.conf' `
  -Pattern '<address>|<port>|<protocol>|<agent_name>|<groups>'
```

**MSI properties are case-sensitive and a mistyped one is silently dropped — msiexec still returns
0.** Reading `ossec.conf` back is the only way to know they landed. `<protocol>tcp</protocol>`
matters specifically: the manager listens **TCP-only** on 1514, and a UDP agent against it is
total silence with no error on either side.

`/l*v` is not optional. Without it, a failed MSI gives you an exit code and nothing else.

`/qn` installs the service **without starting it** (`Stopped`/`Automatic`). Start it to see the
rejection:

```powershell
$dir = 'C:\Program Files (x86)\ossec-agent'
"client.keys bytes: " + (Get-Item "$dir\client.keys").Length   # expect 0
Start-Service WazuhSvc; Start-Sleep -Seconds 20
Get-Content "$dir\ossec.log" -Tail 20
```

Expected — **learn this signature by sight**:

```
INFO:  No authentication password provided
INFO:  Using agent name as: talondellbox
ERROR: Invalid password. Unable to add agent (from manager)
```

`(from manager)` is the important half: the refusal came from `authd`, not a client-side check.
If enrollment **succeeds** here, stop — `use_password` is not being enforced and anything on the
LAN can register into the SIEM.

`client.keys` staying at 0 bytes is why the retry loop keeps firing. **Enrollment only fires when
`client.keys` is empty** — if a failed attempt ever leaves partial content there, later attempts
silently skip enrollment no matter how correct the parameters are. Recovery is both halves:
remove the agent on the manager **and** delete `client.keys` on the endpoint.

---

## 4. Move the password as a file — [MAC]

Stream it host-to-host so it never touches the workstation's disk, never renders as text, and
never enters a command line:

```bash
scp -3 talonsoc:'~/talonsoclab/deploy/soc-recon/wazuh/authd.pass' \
       talondell:'C:/lab/install/authd.pass'
```

Verify **bytes**, without printing content:

```bash
ssh talondell 'pwsh -NoProfile -Command "$f=Get-Item C:\lab\install\authd.pass; $f.Length; $b=[IO.File]::ReadAllBytes($f.FullName); $b[0] -eq 0xEF; (Get-FileHash $f.FullName -Algorithm SHA256).Hash"'
```

Compare that sha256 against **both** the git-tracked source and the copy `authd` actually loaded
in-container. All three matching eliminates the entire "Invalid password against a
correct-looking password" class — BOM, CRLF, truncation, wrong file.

Then place it and enroll — [BOX]:

```powershell
$dir = 'C:\Program Files (x86)\ossec-agent'
Stop-Service WazuhSvc -Force
Move-Item 'C:\lab\install\authd.pass' "$dir\authd.pass" -Force
Rename-Item "$dir\ossec.log" 'ossec.log.preauth' -Force   # keep the rejection signature
Start-Service WazuhSvc; Start-Sleep -Seconds 25
"client.keys bytes: " + (Get-Item "$dir\client.keys").Length
```

`Move-Item` not `Copy-Item` — the staging copy is cleared in the same step. **`client.keys` going
non-zero is the success signal**, better than anything in the log, because its emptiness is what
was driving the retry loop.

---

## 5. Verify from the MANAGER — [MAC]

The endpoint reporting itself healthy is precisely what must not be trusted.

```bash
cd ~/talonsoclab/deploy/soc-recon
docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l
docker compose exec -T wazuh.manager /var/ossec/bin/agent_groups -l
```

Want `ID: 001, Name: talondellbox, Active` and `phase-a-windows (1)`. Then confirm telemetry
actually landed in the indexer (indexer `:9200` is deliberately not host-published, so query from
inside the container):

```bash
set -a; . ./.env; set +a
docker compose exec -T -e P="$WAZUH_INDEXER_PASS" wazuh.indexer sh -c \
  'curl -sk -u admin:$P "https://localhost:9200/wazuh-alerts-*/_count?q=agent.name:talondellbox+AND+data.win.system.providerName:*Sysmon*"'
```

A non-zero count here is the **collapsing probe** — it cannot be true unless enrollment, group
assignment, `merged.mg` delivery, the Sysmon config, and the TCP protocol are *simultaneously*
correct. The eventchannel `<localfile>` that produces these docs exists only in the group's
`agent.conf`, so their arrival independently proves the group config was delivered and applied.

### Then remove the password

```powershell
Remove-Item 'C:\Program Files (x86)\ossec-agent\authd.pass' -Force
Restart-Service WazuhSvc
```

It's used **once**, at enrollment, never per-message — and default ACLs leave it readable by local
users on a host destined to be the Phase C victim network. The restart is the actual test: the
agent should reconnect with **no** `Requesting a key from server` line, confirming enrollment
doesn't re-fire once `client.keys` is populated.

---

## Acceptance

- [x] Agent `001 talondellbox` **Active** from `agent_control -l`
- [x] Data path confirmed: `(4102): Connected to the server ([<MANAGER-IP>]:1514/tcp)` — not just 1515
- [x] Group `phase-a-windows (1)` read **server-side**, `default (0)`
- [x] Sysmon 15.21 + sysmon-modular — proven by 9 event IDs the stock config cannot emit
- [x] `SysmonDrv` loaded (`fltmc`), services Running/Automatic and Running/Boot
- [x] Sysmon-provider docs queryable in the indexer
- [x] Anti: no indexed command line contains `REGISTRATION_PASSWORD` (count 0)
- [x] Anti: `authd.pass` removed post-enrollment; agent still Active, ingest continuing
- [x] ISM manages the **newly rolled** daily index via `ism_template`, no manual `_ism/add`

## Findings worth carrying forward

**The alert-level floor discards most Sysmon telemetry.** `wazuh-alerts-*` holds **alerts, not
events**. With `log_alert_level 3` and `logall_json: no`, anything not matching a rule scoring ≥3
is dropped at the manager and archived nowhere. Sysmon generated 85 network-connection events
here; **zero** reached the indexer, because no default rule scores EID 3 that high. Only IDs 1, 7
and 11 cleared the floor. Observed rule levels: 7(351), 3(149), 9(11), 4(2).

So *"the SIEM shows Sysmon data"* and *"the SIEM retains the Sysmon data you care about"* are
different claims, and only the first is true at the end of A.1. **"No alerts in the dashboard" is
not evidence of no ingestion** — a distinction worth internalising before it costs an hour
debugging a working pipeline.

→ **Phase B decision:** close the gap with `logall_json` archives (full fidelity, real disk cost
on a 256 GB NVMe, needs its own ISM policy) or with custom rules scoring the Sysmon IDs worth
alerting on. Rules are the better default; archives are the better lab.

**Wazuh does not inherit the `ProductName` registry lie.** `Get-ComputerInfo` reports
`WindowsProductName: Windows 10 Pro` on every Windows 11 host, because Microsoft deliberately
never updated that registry value for app-compat. Wazuh syscollector gets it right:
`os.name: Microsoft Windows 11 Pro`, `os.build: 26200.8894`, `os.display_version: 25H2`. One
nuance — `os.version` reads `10.0.26200.8894`, and that `10.0` NT-kernel prefix is identical on
Win 10 and Win 11, so a rule matching on version *prefix* still misclassifies. Build number is the
discriminator. The agent's SCA module independently agreed, auto-selecting `cis_win11_enterprise.yml`.

## State at handoff

One of three endpoints live. Next: **A.2** — Wazuh agents on the Mac and on the Ubuntu host
(auditd), all three Active. The deferred item from A.0 (disable password authentication on `sshd`)
is now unblocked, since console access is no longer needed to drive this box.
