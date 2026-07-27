# Phase A.1 — Wazuh agent + Sysmon on the Windows endpoint

> **What this does:** installs Sysmon with the sysmon-modular ruleset and the Wazuh 4.14.6
> agent on the Dell OptiPlex 7070, enrolls it into the `phase-a-windows` group against a
> passworded `authd`, and verifies the result from the **manager**, not from the endpoint.
>
> **Why it matters for a SOC:** this is the first real telemetry in the lab. It's also the step
> where almost every failure is *silent* — an agent reading `Active` can still be in the wrong
> group, running a stock four-event Sysmon config, or forwarding over a protocol the manager
> isn't listening on. Every check below exists because the naive version of it can pass while
> the pipeline is broken.
>
> Steps are tagged **[MAC]** and **[BOX]**. Addresses are `<MANAGER-IP>` per the no-real-IPs rule.
>
> **Completed 2026-07-26.** Prerequisite: [`03-windows-ssh-access.md`](03-windows-ssh-access.md).

---

## 0. Preflight

Each check fails before the one it would otherwise mask.

**Manager side — [MAC]:**

```bash
ls -l wazuh/authd.pass                                              # a FILE, not a directory
docker compose exec -T wazuh.manager od -c /var/ossec/etc/authd.pass | tail -3
docker compose exec -T wazuh.manager ls -la /var/ossec/etc/shared/phase-a-windows/
docker compose exec -T wazuh.manager /var/ossec/bin/agent_groups -l
```

| Check | The silent failure it catches |
|---|---|
| `authd.pass` is a file | Compose bind-mounts `./wazuh/authd.pass`. **If that path doesn't exist on the host, Docker creates a _directory_.** authd then generates a random password and carries on. Manager reads healthy; every agent gets `Invalid password`. |
| `od -c` byte dump | A CRLF, trailing space, or BOM produces `Invalid password` against a password that looks correct on screen. |
| `merged.mg` present, `wazuh:wazuh` | The entrypoint creates group dirs `root:root`, but `wazuh-remoted` runs as `wazuh` — it can read the config and cannot write the merged file. Agents enroll happily and receive **nothing**, with no error anywhere. |
| `agent_groups -l` | A typo in `WAZUH_AGENT_GROUP` is **not rejected**. The agent silently lands in `default`. |

**Endpoint side — [BOX]:**

```powershell
"1514: " + (Test-NetConnection <MANAGER-IP> -Port 1514).TcpTestSucceeded
"1515: " + (Test-NetConnection <MANAGER-IP> -Port 1515).TcpTestSucceeded
"Admin: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")
Get-Service Sysmon64,SysmonDrv,WazuhSvc -ErrorAction SilentlyContinue   # want empty
```

**Test both ports.** 1515 is enrollment, 1514 is the data path. A green 1515 with a dead 1514
registers the agent and parks it at `Never connected` forever.

## 1. PowerShell 7 — [BOX]

Not just ergonomics: PS 5.1's `-Encoding utf8` writes a BOM, and section 3 places a credential
file where a BOM means silent rejection. Verify the **signature** rather than a hash fetched
from the same host as the file — a hash proves transfer integrity, a signature proves
provenance. Reconnect your SSH session afterward; `PATH` doesn't refresh in a session that
predates the install.

## 2. Sysmon — [BOX]

Use the **prebuilt `sysmonconfig.xml`** from `olafhartong/sysmon-modular`.

```powershell
& $sysmon -accepteula -i 'C:\lab\install\sysmonconfig.xml'
```

Pin and hash-gate it first, so an unreviewed ruleset can never load:

```powershell
$want = '4516404FA30EE87CEA558567820CDC78863CC4AB07889519E49EAC3CCA92E0D2'
$got  = (Get-FileHash 'C:\lab\install\sysmonconfig.xml' -Algorithm SHA256).Hash
if ($got -ne $want) { throw "CONFIG HASH MISMATCH - not installing." }
```

Expect `Loading configuration file with schema version 4.90 / Sysmon schema version: 4.91 /
Configuration file validated`. The binary's schema being *newer* is fine; an **older** binary
against a newer schema hard-fails, so Sysmon must be ≥ 15.0 for a 4.90 config.

### Verify by what it emits

```powershell
"driver loaded: " + [bool](fltmc filters | Select-String SysmonDrv)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 2000 |
  Group-Object Id | Sort-Object {[int]$_.Name}
```

| Config | Event IDs produced |
|---|---|
| **Stock default** | 1, 2, 5, 6 only |
| **sysmon-modular** | + 3, 7, 10, 11, 13, 15, 17, 22 … |

Observed within minutes on an idle desktop: `1`(10) `3`(85) `7`(69) `10`(57) `11`(18)
`13`(137) `15`(19) `17`(3) `22`(6). Check `fltmc` for the **driver**, not just the service —
`Sysmon64` can read `Running` with `SysmonDrv` failed to load, giving a healthy-looking service
and an empty channel.

## 3. Agent — install without the password, on purpose

Sysmon is now live and recording Event ID 1 with full command lines, so a `msiexec` line
carrying `WAZUH_REGISTRATION_PASSWORD` would be captured by the sensor you just installed and
indexed into your own SIEM as searchable data. Installing without it first is also a **negative
control**: it proves authd is genuinely enforcing.

```powershell
Start-Process msiexec.exe -Wait -ArgumentList '/i', $msi, '/qn', '/norestart', `
  'WAZUH_MANAGER=<MANAGER-IP>', 'WAZUH_AGENT_NAME=talondellbox', `
  'WAZUH_AGENT_GROUP=phase-a-windows', 'WAZUH_PROTOCOL=tcp', `
  '/l*v', 'C:\lab\install\wazuh-install.log'

# read the properties BACK -- do not trust the command you typed
Select-String -Path 'C:\Program Files (x86)\ossec-agent\ossec.conf' `
  -Pattern '<address>|<port>|<protocol>|<agent_name>|<groups>'
```

**MSI properties are case-sensitive and a mistyped one is silently dropped — msiexec still
returns 0.** `<protocol>tcp</protocol>` matters specifically: the manager listens TCP-only on
1514, and a UDP agent against it is total silence with no error on either side.

`/qn` installs the service **without starting it**. Start it and learn the rejection signature:

```
INFO:  No authentication password provided
ERROR: Invalid password. Unable to add agent (from manager)
```

`(from manager)` is the important half — the refusal came from authd, not a client-side check.
If enrollment **succeeds** here, stop: anything on the LAN can register into the SIEM.

## 4. Move the password as a file — [MAC]

```bash
scp -3 talonsoc:'~/.../wazuh/authd.pass' talondell:'C:/lab/install/authd.pass'
```

Streams host-to-host, so it never touches the workstation's disk, renders as text, or enters a
command line. Verify **bytes** without printing content, and compare the sha256 against both
the git-tracked source and the copy authd actually loaded in-container. All three matching
eliminates the whole "Invalid password against a correct-looking password" class.

Then place it, restart, and watch `client.keys`:

```powershell
Move-Item 'C:\lab\install\authd.pass' "$dir\authd.pass" -Force
Start-Service WazuhSvc
"client.keys bytes: " + (Get-Item "$dir\client.keys").Length
```

**`client.keys` going non-zero is the success signal** — better than anything in the log,
because its emptiness is what was driving the retry loop. Enrollment only fires when that file
is empty, so a partial write means later attempts silently skip enrollment no matter how
correct the parameters are.

## 5. Verify from the MANAGER — [MAC]

The endpoint reporting itself healthy is precisely what must not be trusted.

```bash
docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l    # want 001 ... Active
docker compose exec -T wazuh.manager /var/ossec/bin/agent_groups -l     # want phase-a-windows (1)

docker compose exec -T -e P="$WAZUH_INDEXER_PASS" wazuh.indexer sh -c \
  'curl -sk -u admin:$P "https://localhost:9200/wazuh-alerts-*/_count?q=agent.name:talondellbox+AND+data.win.system.providerName:*Sysmon*"'
```

A non-zero count is the **collapsing probe** — it cannot be true unless enrollment, group
assignment, `merged.mg` delivery, the Sysmon config and the TCP protocol are *simultaneously*
correct. The eventchannel `<localfile>` producing those docs exists only in the group's
`agent.conf`, so their arrival independently proves the group config was delivered.

Then remove `authd.pass`. It's used once, at enrollment, never per-message, and default ACLs
leave it readable by local users on a host destined to be the Phase C victim network.

## Acceptance

- [x] Agent `001 talondellbox` **Active** from `agent_control -l`
- [x] Data path confirmed: `(4102): Connected to the server ([<MANAGER-IP>]:1514/tcp)`
- [x] Group `phase-a-windows (1)` read **server-side**
- [x] Sysmon 15.21 + sysmon-modular — 9 event IDs the stock config cannot emit
- [x] `SysmonDrv` loaded; services Running/Automatic and Running/Boot
- [x] Sysmon-provider docs queryable in the indexer
- [x] Anti: no indexed command line contains `REGISTRATION_PASSWORD`
- [x] Anti: `authd.pass` removed post-enrollment; agent still Active, ingest continuing
- [x] ISM manages the newly-rolled daily index via `ism_template`

---

## Findings

**The alert-level floor discards most Sysmon telemetry.** `wazuh-alerts-*` holds **alerts, not
events**. With `log_alert_level 3` and `logall_json: no`, anything not matching a rule scoring
≥3 is dropped at the manager and archived nowhere. Sysmon generated 85 network-connection
events here; **zero** reached the indexer, because no default rule scores Event ID 3 that high.
Only IDs 1, 7 and 11 cleared the floor. Observed rule levels: 7(351), 3(149), 9(11), 4(2).

So *"the SIEM shows Sysmon data"* and *"the SIEM retains the Sysmon data you care about"* are
different claims, and only the first is true at the end of A.1. **"No alerts in the dashboard"
is not evidence of no ingestion.** Closing the gap is a Phase B decision between `logall_json`
archives (full fidelity, real disk cost) and custom rules scoring the Sysmon IDs worth alerting
on. Rules are the better default; archives are the better lab.

**Prove a sensor by what it emits, not what it says about itself.** Verifying the Sysmon config
via `Sysmon64.exe -c` failed twice on a perfectly healthy sensor. That command emits
**UTF-16LE**, which PowerShell captures as raw bytes with a null between every character
(`425,582 ≈ 2 ×` the config size), so no ASCII pattern can ever match. It presents identically
to a failed config load. The emitted-event distribution needs no parsing, survives version and
format changes, and is a better portfolio artifact besides.

**Pair every self-report probe with an independent behavioural one.** The block that contained
the broken `-c` check also forced an Event ID 3 as a positive control. The two disagreeing is
what exposed the bad probe rather than the good sensor. When they conflict, observed behaviour
wins.

**The prebuilt sysmon-modular config is fine, and its staleness is misleading.** Its CI stopped
regenerating the pre-merged file in 2023, which looks alarming — but it already covers all 22
event types, and the real delta since is eight non-merge commits amounting to one file
extension, one image-load rule and some syntax fixes. Merging fragments locally at the step
whose purpose is *proving the pipeline works* would add a competing suspect for no gain. Config
swaps are one command (`Sysmon64.exe -c <new>.xml`), so deferring enrichment to Phase B costs
nothing.

**Wazuh does not inherit the `ProductName` registry lie.** `Get-ComputerInfo` reports
`WindowsProductName: Windows 10 Pro` on every Windows 11 host, because Microsoft deliberately
never updated that registry value for app-compat. Syscollector gets it right:
`os.name: Microsoft Windows 11 Pro`, `os.build: 26200.8894`, `25H2`. One nuance — `os.version`
reads `10.0.26200.8894`, and that `10.0` NT-kernel prefix is identical on Windows 10 and 11, so
a rule matching on version *prefix* still misclassifies. The build number is the discriminator.
