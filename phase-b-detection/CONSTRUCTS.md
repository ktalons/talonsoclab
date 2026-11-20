# Sigma Constructs

Phase B ports Sigma rules to Wazuh by hand before deciding whether a compiler is worth building.
This page records every Sigma construct the 18 ports met, how each one is written in Wazuh XML,
and what could not be written at all. It is the evidence for that decision.

**Scope:** 18 rules from SigmaHQ `rules/windows` at commit `53423dac`. The Sigma YAML is in
[`sigma/`](sigma/) and the test cases are in [`tests/`](tests/). Two rule sets:

- The first five, from `network_connection`, are in
  [`local_eid3_pack.xml`](../deploy/soc-recon/wazuh/custom-rules/local_eid3_pack.xml) as IDs 100340
  to 100344.
- Thirteen more are in four packs, as IDs 100400 to 100412:
  [`local_eid13_pack.xml`](../deploy/soc-recon/wazuh/custom-rules/local_eid13_pack.xml) (100400 to
  100404, from `registry/registry_set`),
  [`local_eid11_pack.xml`](../deploy/soc-recon/wazuh/custom-rules/local_eid11_pack.xml) (100405 to
  100407, from `file/file_event`),
  [`local_eid1_pack.xml`](../deploy/soc-recon/wazuh/custom-rules/local_eid1_pack.xml) (100408 to
  100411, from `process_creation`) and
  [`local_eid22_pack.xml`](../deploy/soc-recon/wazuh/custom-rules/local_eid22_pack.xml) (100412,
  from `dns_query`).

Everything here was checked on Wazuh 4.14.9 with `tools/logtest.ts`, which runs each case through a
real `wazuh-analysisd` on a scratch manager. The 2026-11-20 runs covered all 431 cases with no
failures. What that run did not exercise is marked "not checked".

| ID | Level | Upstream rule | Ported |
|---|:--:|---|---|
| 100340 | 12 | `net_connection_win_certutil_initiated_connection` | in full |
| 100341 | 10 | `net_connection_win_regsvr32_network_activity` | in full |
| 100342 | 10 | `net_connection_win_rundll32_net_connections` | in part, two filters dropped |
| 100343 | 12 | `net_connection_win_wscript_cscript_outbound_connection` | in full |
| 100344 | 12 | `net_connection_win_susp_initiated_uncommon_or_suspicious_locations` | in part, one filter left out on purpose |
| 100400 | 10 | `registry_set_persistence_logon_scripts_userinitmprlogonscript` | in full |
| 100401 | 10 | `registry_set_add_port_monitor` | in part, one four-field filter dropped |
| 100402 | 10 | `registry_set_persistence_shim_database` | in full, filters inverted |
| 100403 | 10 | `registry_set_disable_administrative_share` | in full |
| 100404 | 10 | `registry_set_uac_disable` | in full |
| 100405 | 10 | `file_event_win_creation_new_shim_database` | in full, ATT&CK id changed |
| 100406 | 12 | `file_event_win_susp_startup_folder_persistence` | in full |
| 100407 | 12 | `file_event_win_powershell_startup_shortcuts` | in full |
| 100408 | 10 | `proc_creation_win_certutil_encode` | in part, Image branch only |
| 100409 | 12 | `proc_creation_win_schtasks_system` | in full |
| 100410 | 12 | `proc_creation_win_cmdkey_recon` | in part, Image branch only |
| 100411 | 10 | `proc_creation_win_whoami_all_execution` | in part, Image branch only |
| 100412 | 10 | `dns_query_win_susp_external_ip_lookup` | in full |

## Parent per logsource

A Sigma `logsource` becomes the `if_sid` parent. Each one is a stock Sysmon rule, and each parent
has to be checked for level-0 children before the first rule is written.

| Sigma logsource (`product: windows`) | Stock parent | Level-0 stock children | Parents in the pack rules |
|---|---|---|---|
| `network_connection` | 61605, event 3 | 92101, 92108 | `61605, 92101, 92108` |
| `registry_set` | 61615, event 13 | 92300 | `61615, 92300` |
| `file_event` | 61613, event 11 | 92216 | `61613, 92216` |
| `process_creation` | 61603, event 1 | 92025, 92028, 92042, 92069 | `61603, 92025, 92028, 92042, 92069` |
| `dns_query` | 61650, event 22 | none | `61650` |

One parent was not enough. A level-0 child that matches ends the event with no alert, even when a
pack rule at level 10 also matches. Naming the level-0 child as an extra parent tries the pack rule
as its child too. Stock rule 92110 uses the same idiom. Each second parent has a case that proves
it, and the 2026-11-20 run passed them all.

A new logsource needs the same check before its first rule: read the stock children of the parent
and find the level-0 ones.

**Event 3.** Stock rules 92101 (`powershell.exe` over TCP) and 92108 (any connection to port 3389)
are level-0 children of 61605. `regsvr32.exe` to port 3389 ended at 92108, and a binary named
`powershell.exe` in `C:\Users\Public` ended at 92101.

**Event 13.** 92300 is the only level-0 child of 61615. It matches any value under a Run, RunOnce
or Terminal Server Run key. None of the five registry rules matches a Run path unless a value is
named for the pattern, so for these five the second parent is the idiom only. 100400 has a case
for it (`pos-run-key-value`, a Run value called `UserInitMprLogonScript`).

**Event 11.** 92216 is `powershell.exe` writing a `.tmp` file under `Windows\Temp` or `Users`. It
matches on `.tmp` anywhere in the path, so `powershell.exe` writing `calc.tmp.lnk` into a Startup
folder ends at 92216 with no alert unless the pack rule hangs from it as well. 100405 can never
reach 92216, since a path under `Windows\apppatch` is not under `Windows\Temp` or `Users`, so for
100405 the second parent is the idiom only. `tests/100406/pos-tmp-level0-parent` and
`tests/100407/pos-tmp-level0-parent` prove it for the other two.

**Event 1.** Four level-0 children, all in `0800-sysmon_id_1.xml`:

| Stock rule | Matches | Realistic for the four pack rules? |
|---|---|---|
| 92025 | `originalFileName` holding `reg.EXE` | only for a renamed reg.exe |
| 92028 | `originalFileName` powershell.exe and a script extension on the command line | only for a renamed powershell.exe |
| 92042 | `originalFileName` holding `netsh.EXE` | only for a renamed netsh.exe |
| 92069 | `parentImage` holding `WmiPrvSE.exe` | yes, any process started over WMI |

92069 is the one an attack meets in practice: `Invoke-CimMethod Win32_Process Create` or a WMI
lateral-movement tool starts the process under WmiPrvSE.exe. Each rule has a case for each of the
four (`pos-parent-wmiprvse`, `pos-stock-92025-reg`, `pos-stock-92028-powershell`,
`pos-stock-92042-netsh`).

**Event 22.** No rule names 61650 as a parent and none attaches to `sysmon_event_22` on 4.14.9, so
the one parent is enough. If a later ruleset adds a level-0 child there, the pack rule needs it as
a second parent.

### Group names

A stock rule that attaches by `if_group` becomes a child of every rule that carries that group. A
pack rule must not carry a `sysmon_event*` group, or those stock rules turn into its children and
can take the final match. Each pack uses its own group, and no stock `if_group` value matches it.

| Pack group | Stock group it must not carry | Stock rules attached to that group on 4.14.9 |
|---|---|---|
| `local,eid3_pack,` | `sysmon_event3` | 5: 92101, 92104, 92105, 92107, 92108 |
| `local,eid13_pack,` | `sysmon_event_13` | 3: 92300, 92304, 92307 |
| `local,eid11_pack,` | `sysmon_event_11` | 20: 19 in `0830-sysmon_id_11.xml` and 91001 in `0910-ms-exchange-proxylogon_rules.xml` |
| `local,eid1_pack,` | `sysmon_event1` | 71: 42 in `0800-sysmon_id_1.xml`, 13 in `0595-win-sysmon_rules.xml`, 3 in `0910-ms-exchange-proxylogon_rules.xml`, 13 in `0330-sysmon_rules.xml` |
| `local,eid22_pack,` | `sysmon_event_22` | 0 |

The 13 in `0330-sysmon_rules.xml` read the old `sysmon.*` fields and never match an eventchannel
event. The `sysmon_eid1_detections` group on the four level-0 event 1 rules is not an `if_group`
target in the stock set either. The counts are from the stock 4.14.9 files with comments stripped.

## Which rule ends an event

The final rule is decided by the walk, not by the highest level anywhere in the ruleset. Wazuh
tries the rules under one parent in this order: level 0 first, then highest level to lowest. It
takes the first match and goes on only into that rule's children. Rules under a sibling that was
never reached are never tried.

Two things follow.

- A stock rule at a level above the pack rule wins only if it is a sibling of the pack rule, or
  sits under a rule the walk takes. At the same level the rule loaded first wins. Stock files
  load before the pack, so a stock rule beside a pack rule wins a tie. The engine showed it:
  `100406/neg-mshta-all-users-vbs` ends at stock 92215, level 12 against 12.
- A stock rule under a lower-level sibling is hidden by any pack rule that matches first. The
  higher level of the stock rule does not help it.

Stock 92226 (level 14, `powershell.exe` writing a launchable file into the all-users Startup
folder, `C:\ProgramData\...\StartUp`) is the case that matters. It is a child of 92203 and 92225,
both level 6. Pack rules 100406 and 100407 are level 12 and are tried first under 61613. They end
the event, and 92226 is never reached. The cost, stated plainly: such a write alerted at level 14
before the pack, and alerts at level 12 under the pack rule now. The case is
`tests/100406/pos-powershell-all-users-bat`, and the 2026-11-20 run confirms it.

The same walk governs the stock rules that do outrank the pack:

| Event | Stock rule | Why it ends the event |
|---|---|---|
| 3 | 92104 (level 15, U+202E in the image path) and 92109 (level 15, port 3389 with loopback at both ends) | outrank the pack rules. Test cases pin both |
| 13 | 92301 (level 12, `.lnk`, `.vbs` or `.vba` in Details under a Run key) over a level 10 pack rule | shares the parent 92300 and is higher. `100400/neg-run-key-vbs` ends at 92301 |
| 13 | 92303 (level 12, VNC or tvnserver in Details) | same position as 92301. `100400/neg-run-key-vnc` ends at 92303 |
| 11 | 92211 (level 14, `rundll32.exe` writing a launchable file) and 92212 (level 14, `powershell.exe` writing a name with `.7z`, `.zip` or `.rar` in it) | sit beside the pack rules under 61613 and are higher. `100406/neg-rundll32-all-users-dll` and `100407/neg-powershell-zip-lnk` pin them |
| 11 | 92215 (level 12, `mshta.exe` writing a launchable file) and 91001 (level 12, `UMWorkerProcess.exe`, in the Exchange ProxyLogon file) | tie with 100406 and 100407 and win it, loaded first. `100406/neg-mshta-all-users-vbs` pins 92215. No case covers 91001 |
| 1 | 92016 (level 13, a renamed certutil.exe) and 92018 (level 13, `certutil -decode` of a file into an `.exe`) | outrank 100408. Test cases pin both |
| 1 | 92057 (level 12, a `powershell.exe` parent and an encoded PowerShell flag on the command line) | ties with 100409 and wins it. PowerShell starting `schtasks.exe` to create a SYSTEM task that runs an encoded PowerShell command alerts under 92057 and does not carry T1053.005. `100409/neg-powershell-encoded-payload` pins it |

One stock rule does the opposite and hides an alert. 92069 (level 0, parent `WmiPrvSE.exe`) takes
every process started over WMI before any sibling is tried. The pack rules hang from it and still
fire. A stock sibling does not: a renamed `certutil.exe` started over WMI never reaches 92016 and
raises nothing (`100408/neg-renamed-binary-wmi`).

The stock rules below a lower-level sibling cannot take the final match from a pack rule on the
same event: 92305 and 92306 (level 12) under 92304 (level 6), and 92309 (level 15) under 92308
(level 3). No case covers an event that matches both a pack rule and one of those chains.

## Field mapping

Sysmon fields arrive under `win.eventdata` with a lower-case first letter.

| Sigma field | Wazuh field | Note |
|---|---|---|
| `Image` | `win.eventdata.image` | events 1, 3, 11, 13 and 22. Each backslash arrives doubled. The real capture of `pwsh.exe` has a lower-case path |
| `CommandLine` | `win.eventdata.commandLine` | event 1 only. Backslashes arrive doubled and each double quote arrives as `\"` |
| `ParentImage`, `ParentCommandLine` | `win.eventdata.parentImage`, `.parentCommandLine` | event 1 only. `parentImage` is absent when Sysmon logs `-` (a WmiPrvSE.exe start on the endpoint did). The command line is as `CommandLine` |
| `OriginalFileName` | `win.eventdata.originalFileName` | event 1 |
| `Initiated` | `win.eventdata.initiated` | event 3. `true` or `false` |
| `DestinationPort` | `win.eventdata.destinationPort` | event 3 |
| `DestinationIp` | `win.eventdata.destinationIp` | event 3. IPv6 is written in full, never compressed |
| `DestinationHostname`, `SourceHostname` | `win.eventdata.destinationHostname`, `.sourceHostname` | event 3. Absent when Sysmon logs `-` |
| `TargetFilename` | `win.eventdata.targetFilename` | event 11. Each backslash arrives doubled |
| `TargetObject` | `win.eventdata.targetObject` | event 13. Each backslash arrives doubled. Sysmon writes `HKLM\...` and `HKU\<SID>\...`, never `HKCU` |
| `Details` | `win.eventdata.details` | event 13. Absent when Sysmon logs nothing, `-` or `(NULL)`. `(Empty)` stays as text. A DWORD reads `DWORD (0x00000000)` |
| `QueryName` | `win.eventdata.queryName` | event 22 |
| `CommandLine`, `ParentImage` | none | event 3 does not carry them |
| `EventType`, `User`, `ProcessGuid`, `QueryStatus`, `QueryResults` | `win.eventdata.eventType`, `.user`, `.processGuid`, `.queryStatus`, `.queryResults` | not used by any of the 18 rules |

The event 22 names `queryName` and `image` were not proven before the run, because no stock rule
reads a Sysmon DNS event. The 2026-11-20 run decoded both on 4.14.9.

Wazuh drops an EventData value of `-`, `(NULL)` or an empty string, so a field that Sysmon left
empty is not an empty string in the rule. It is missing. On the lab's Windows endpoint both
hostname fields were `-` in every event 3 sampled. Whether a live Sysmon event ever carries `-` or
`(NULL)` in `Details` is not established. The cases feed those values to the decoder directly.

The event 1 quote comes from the same step as the doubled backslash: the agent prints the event
as a JSON string before the decoder reads it, and nothing undoes either escape. The same holds for
XML entities. `ToXml()` writes `&` as `&amp;`, and the decoder decodes no entities, so a field
holds `&amp;` where the command line held `&`. None of the four event 1 patterns contains `&`, `<`
or `>`. The source for both is the port's reading of the decoder (`tools/winevt.ts`, the comment
on `cjsonEscaped`). Not checked on a live event.

## Constructs met

| Sigma construct | Wazuh XML | Met in |
|---|---|---|
| plain string match | `type="pcre2"` with `(?i)`, anchored at both ends | 100340 to 100344, 100403, 100404, 100412 |
| `\|endswith` | `(?i)\\name\.exe$` | 100340 to 100344 and the rest |
| `\|contains` | unanchored pattern | 100344, 100404, 100412 and the rest |
| `\|startswith` | the pattern starts with `^` | 100412 |
| `\|contains` and `\|endswith` on one field | one ordered pattern: the folder or key, anything or nothing, then the name and `$` | 100403, 100406, 100407 |
| list of values on one field | one alternation | 100340, 100343, 100344 |
| list of extensions on `\|endswith` | one alternation inside `\.(?:...)$`, with `jse?` for `js` and `jse` | 100406 |
| several fields in one selection (AND) | one `<field>` each | all 18 |
| several selections on one field, all required | one `<field>` per selection, same name | 100409 |
| selection that is a list of two maps (one exact, one `\|contains`) | one alternation of the two forms: the exact names anchored at both ends, the contains values bare | 100412 |
| exact path that exists as `Program Files` and `Program Files (x86)` | `Program Files(?: \(x86\))?` | 100412 |
| exact match on a typed value (`DWORD (0x00000000)`) | `^DWORD \(0x00000000\)$` | 100403, 100404 |
| `\|contains` on a value name, no anchor | no `$`, so a longer name still matches, as upstream | 100404 |
| `\|windash` | a character class in front of the flag, with the pattern in UTF mode | 100408, 100410, 100411 |
| `\|contains\|all` | one lookahead per needle behind `^`, so the needles match in any order | 100401, 100409 |
| `\|cidr` | an address-prefix pattern | 100342, 100343 |
| Image OR OriginalFileName in one selection | the Image branch only | 100408, 100410, 100411 |
| `not 1 of filter_*`, one field per filter | one negated `<field>` per field, the values of every filter on that field joined | 100342, 100343, 100409, 100412 |
| several filters that all test the same field | one negated `<field>`, every value joined | 100342, 100343, 100412 (twelve filters on `Image`) |
| filter whose value is a list of maps (`Image\|startswith`, `Image\|endswith`, `Image`) | one alternation, one branch per map | 100412 `filter_optional_edge_1` |
| filter with `\|startswith` and `\|endswith` on the same field | one ordered pattern, `^folder\\+(?:.*\\)?name$` | 100412 `filter_optional_edge_2` |
| `\|contains\|all` inside a filter | lookaheads anchored at the start, `^(?=.*a)(?=.*b)` | 100401, 100409 |
| a value that is a filter and also a selection value on the same field | the positive field and one negated field of the same name, both on the rule | 100401 |
| filter on a field that can be absent | a negated `<regex>` over the whole log line | 100342 |
| `Details: null`, `''`, `'(Empty)'` as filters | a positive test that the field is present and not `(Empty)`: `^(?!\(Empty\)\z).+` | 100402 |
| `tags` with `attack.t....` | `<mitre><id>` | all 18 |
| `level` | medium 10, high 12, critical 15 | all 18 |

The `Image OR OriginalFileName` row is met in part. The OriginalFileName branch is lost, which is
recorded under "Constructs that did not port".

### `|cidr`

A dynamic field has no CIDR type in a Wazuh rule, so each range becomes a prefix pattern:

| Range | Pattern |
|---|---|
| `127.0.0.0/8`, `10.0.0.0/8`, `20.0.0.0/8` | `^127\.`, `^10\.`, `^20\.` |
| `192.168.0.0/16`, `169.254.0.0/16`, `51.103.0.0/16` to `51.105.0.0/16` | `^192\.168\.`, `^169\.254\.`, `^51\.10[345]\.` |
| `172.16.0.0/12` | `^172\.(?:1[6-9]\|2\d\|3[01])\.` |
| `20.0.0.0/11` | `^20\.(?:\d\|[12]\d\|3[01])\.` |
| `::1/128` | `^(?:::1\|0:0:0:0:0:0:0:1)$` |
| `fe80::/10` | `^fe[89ab][0-9a-f]:` |
| `fc00::/7` | `^f[cd][0-9a-f]{2}:` |

A prefix length on an octet boundary is one literal octet. Any other length needs the octet
written out as a range by hand, which is where a mistake is most likely. Sysmon writes IPv6 in
full (`0:0:0:0:0:0:0:1`), so the loopback pattern carries both forms.

A prefix pattern is a text match, where Sigma parses the address. `10.not-an-address` matches
`^10\.` and would be filtered. The port relies on Sysmon writing a real address in the field.

### `|windash`

pySigma expands a `-` or `/` at the start of a word into five characters: hyphen, slash, en dash
(U+2013), em dash (U+2014) and horizontal bar (U+2015). The port writes that as one class in
front of the flag:

```xml
<field name="win.eventdata.commandLine" type="pcre2">(*UTF)(?i)[-/\x{2013}\x{2014}\x{2015}]encode</field>
```

The three code points need UTF mode, so a windash pattern starts with `(*UTF)`, ahead of `(?i)`.
Stock rules 92060 and 92064 start the same way (`(*UTF)\N{U+202E}`), and so does stock 92104. The
2026-11-20 run passed every windash case on 4.14.9, so Wazuh hands the pattern to PCRE2 as written
and does not refuse UTF mode. Two ways to get this wrong:

- `\x{2013}` without `(*UTF)` is a compile error in PCRE2's 8-bit library (a code point above 255
  in non-UTF mode). The rule would not load, and logtest stops on the ruleset error.
- A raw en dash pasted into the class, without UTF mode, is three bytes, and a class of them
  matches any one of those bytes. The rule would load and match the wrong text.

Upstream's value keeps its leading space where it has one (`' -l'`, `' -all'`), so the port does
too: `cmdkey host-lab` holds `-l` and does not match. That space also means a flag written straight
after a quoted program path (`"C:\...\whoami.exe"/all`) is missed, by upstream and port alike. A
case records it.

Not checked: a command line that is not valid UTF-8. A UTF-mode match on one would return an
error, which Wazuh reads as no match.

### Several conditions on one field

Several `<field>` tags with the same name are ANDed. Each is matched on its own, so the order of
the arguments is free, as in Sigma. This was a question until the 2026-11-20 run. Stock 92043
carries two positive `commandLine` fields and stock 92151 four negated `image` fields, which only
showed that the loader accepts them. The run showed that every tag is enforced and not just the
last:

- 100409 holds four `commandLine` fields, three positive and one negated. Its negatives that drop
  exactly one selection (`neg-no-create-or-change`, `neg-no-ru`, `neg-user-not-system`) do not
  match.
- 100401 holds a positive and a negated `targetObject` together, and passes.

Sigma lets a selection hold `TargetObject|contains` and `TargetObject|endswith` at once. The two
can share the one backslash between them (`...\Parameters\AutoShareWks` satisfies `\Parameters\`
and `\AutoShareWks`), so two separate patterns would be right and so would one ordered pattern.
100403 uses one ordered pattern,
`\\+Services\\+LanmanServer\\+Parameters\\+(?:.*\\+)?AutoShare(?:Wks|Server)$`, which also allows a
subkey in between. A tool that generated these would have to choose. A hand port should prefer the
single pattern when the two conditions are ordered.

`filter_optional_edge_2` in 100412 is the one place Sigma's startswith and endswith can overlap,
because the folder ends in a backslash and the file name starts with one. `EdgeCore\msedge.exe` is
startswith `...\EdgeCore\` and endswith `\msedge.exe` at once, so Sigma filters it. The pattern
`EdgeCore\\+(?:.*\\)?(?:msedge|msedgewebview2)\.exe$` keeps that: the optional group is skipped
and the separator is shared. A pattern that demanded `.*\\` after the folder would have lost it.
`tests/100412/neg-filter-edgecore-direct` pins it.

### `|contains|all` as lookaheads

`TargetObject|contains|all: [A, B, C]` is `^(?=.*A)(?=.*B)(?=.*C)`. Each lookahead scans from the
start, so the needles can come in any order and can overlap.

In 100401 it sits inside the one negated `targetObject`, joined to the MONVNC alternative with `|`.
The first alternative has no `^`, so the alternation reads `A|^(?=...)(?=...)(?=...)`, and the `^`
binds to the second branch only. A case for the needles in another order pins it
(`neg-vnc-printer-reordered`).

In 100409 the same form sits inside a filter on `CommandLine`. See the next section.

### Filters

`selection and not 1 of filter_*` means "none of the filters match". When every filter tests one
field, that is one negated `<field>` per field. Two or more filters on the same field join into
one alternation.

**100412.** All twelve filters test `Image` and nothing else, so they join into one negated
`<field>`. The pattern is long, and a hand-typed alternation is where a typo hides. The cases walk
every value in every filter, one negative each, and add one positive for each boundary: a Chrome
under a Temp folder, a Chrome on `D:`, `msedge.exe` in Downloads, a file under `EdgeCore` with
another name, `EdgeWebView` under `Program Files` where the filter names only
`Program Files (x86)`, and `notbrave.exe`.

**100409.** All three filters test `CommandLine`, so they join into one negated field. (TeamViewer's
filter also tests `Image`, which the selection already holds to `schtasks.exe`, so that test is
dropped with no loss.) `contains|all` inside a filter is a set of lookaheads anchored at the start,
so the strings can come in any order:

```text
(?is)^(?=.*/TN TVInstallRestore)(?=.*\\TeamViewer_\.exe)|...|/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\\?" /RL HIGHEST
```

`(?s)` lets `.` cross a line break, as Sigma's contains does. Upstream's Avira value holds a
double quote, which arrives as `\"`, so the pattern is `\\?"`. It matches with or without the
backslash, in case a live event differs from the port. `CommandLine` is present on every event 1,
so this negated field does not meet the absent-field problem below.

**A field that can be absent.** A negated `<field>` only works on a field every event carries.
100342 first carried a negated `win.eventdata.sourceHostname`, and it never fired: the field was
absent, and a rule with a negated test on an absent field does not match. The filter is now a
negated `<regex>` over the log line, `"sourceHostname":"[^"]*\.internal\.cloudapp\.net"`, which is
simply false when the key is missing.

This filter is proven on the scratch manager only, where the log line comes from the test decoder.
If the live log line were shaped differently the filter would stop excluding anything and the rule
would still alert. It cannot hide a detection. The same holds for a host name with a JSON-escaped
quote in it, which `[^"]*` stops at.

The other direction is a real gap. 100342 and 100343 keep a negated `win.eventdata.destinationIp`,
so an event with no `DestinationIp` matches neither rule, where the Sigma rule would alert. Sysmon
writes the field on every event 3, so the gap needs a malformed event to open. A test case in each
rule records it (`neg-no-destination-ip`). 100412 has the same gap on `Image`: it is silent on an
event 22 with no `Image`, where the Sigma rule would alert. Every event 22 the lab endpoint logged
had one.

**A filter on a field that can be absent, inverted.** 100402's three filters (`Details: ''`,
`'(Empty)'`, `null`) say "Details is empty, absent or `(Empty)`". Negated, that is "Details is
present and is not `(Empty)`", and a positive test says exactly that: `^(?!\(Empty\)\z).+`. The XML
needs no negated field and no negated regex. It works because Wazuh drops an empty `Details`, so
an empty one is absent, and an absent field fails a positive test.

The filter on `(Empty)` is case-insensitive, as Sigma's is. A `Details` of `(Empty) value` is not
`(Empty)` and alerts. Cases pin both.

The lookahead ends in `\z`, not `$`. The loader reads a dollar sign as a variable, and the event 3
pack writes `\x24` for a literal one. Nothing in the repo or the stock ruleset puts a `$` directly
before a `)`, so `\z` avoids the question. The run showed that 4.14.9 accepts `\z` and loads the
rule.

### A space at the end of a pattern

Sigma values such as `'/ru '` and `' SYSTEM '` end in a space. The port writes a final space as
`\x20` (`(?i)/ru\x20`), so a reader that trims element text cannot turn `/ru ` into `/ru` and
match `/run`. Whether Wazuh's XML reader trims is not checked. The escape costs nothing either way.

## Constructs that did not port

| Construct | Where | Why |
|---|---|---|
| a filter that needs two fields at once | 100342 `filter_main_svchost_update_processes` | `not (A and B)` is `not A or not B`, and one Wazuh rule holds no OR across fields |
| a filter that needs four fields at once | 100401 `filter_optional_cutepdf` (Image, TargetObject, Details, User) | the same reason: `not (A and B and C and D)` holds an OR across fields |
| a filter on `CommandLine` or `ParentImage` | 100342 `filter_main_app_sdb` and the one above | event 3 carries neither field |
| OR across fields in a selection (Image OR OriginalFileName) | 100408, 100410, 100411 | one rule holds no OR across fields, and the pack has no room for a level-0 helper. Each keeps the Image branch |
| OR across fields in a selection (`1 of selection_*`) | not met in these 18 | would need one rule per branch |
| `\|re`, `\|base64offset`, `fieldref` | not met | see the last section. They are not in the 18 ports' Sigma |

The usual Wazuh answer to a two-field filter is a level-0 helper rule that matches the benign case
first. The pack has no room for one: `tools/sigma-lint.ts` requires every pack rule to have a Sigma
YAML and a level of medium or higher.

What the drops cost, by rule.

**100342** alerts on whatever the two filters would have dropped, which is `rundll32.exe` started
by `svchost.exe` on port 443, and the `PcaSvc.dll` compatibility task. Event 3 alone cannot say
which events those are. The endpoint's Sysmon log held one SYSTEM `rundll32.exe` event to a
Microsoft address on 443, outside the listed ranges, when the pack was written. It is kept as a
positive case, [`tests/100342/pos-real.json`](tests/100342/pos-real.json), so the cost stays
visible.

The event 1 for the same process, one record earlier, names it: `PcaSvc.dll,PcaPatchSdbTask`,
started by `svchost.exe` for Task Scheduler. Both upstream filters would have dropped it. In the
five days of log on hand the task ran eleven times and opened a connection once, and no other
`rundll32.exe` process logged an event 3. The expected cost is well under one alert a day.

**100344** leaves out upstream's file-sharing domain filter on purpose. Upstream has it so a
sibling rule can own those domains. This pack does not carry that sibling, so the filter would
only hide them.

**100401** alerts when CutePDF Writer registers its monitor, which is `spoolsv.exe` as SYSTEM
writing `cpwmon64_v40.dll`. That happens at install, once per machine. Narrowing the filter to its
`TargetObject` alone would hide any DLL written under the key `CutePDF Writer Monitor v4.0`, a name
an attacker can choose, so the port does not do that. `tests/100401/pos-cutepdf.json` keeps it
visible.

**100408, 100410, 100411** lose a renamed binary. For `certutil.exe` the event still alerts,
because stock 92016 (level 13) fires on any process whose `originalFileName` is CertUtil.exe and
whose image name is not (`tests/100408/neg-renamed-binary.json`). The exception is a renamed copy
started over WMI: stock 92069 (level 0) takes that event first, 92016 is never reached, and nothing
alerts (`tests/100408/neg-renamed-binary-wmi.json`). Nothing covers a renamed
`cmdkey.exe` or `whoami.exe` (`neg-renamed-binary` in 100410 and 100411). 100409's upstream has no
OriginalFileName branch.

The other route is untested and not shipped: a positive `<regex>` over the whole log line that
holds both keys, in place of the `image` field:

```text
(?i)"image":"[^"]*\\\\certutil\.exe"|"originalFileName":"certutil\.exe"
```

In the log line every value is escaped once more, so a path separator is four backslashes and a
quote inside a value is `\\\"`. A value cannot forge the `"key":"` shape. No stock rule matches a
Windows eventchannel event with a `<regex>` at all, and the one stock `<regex>` keyed on a JSON
field name is a negated one on Microsoft Graph events (99503). To ship it, a run would have to
show:

1. a positive with the real image and another `originalFileName` fires (the Image branch)
2. a positive with another image and `originalFileName` CertUtil.exe fires (the renamed branch)
3. a negative whose command line holds the text `"originalFileName":"CertUtil.exe"` does not
4. a negative with `parentImage` ending `\certutil.exe` does not (the `"image"` key must not match
   inside `"parentImage"`)

and then a live event would have to show the same log line shape, the caveat 100342's negated
regex already carries.

## Wazuh behaviour that is not in the Sigma

| Behaviour | What the port does |
|---|---|
| Each backslash in a decoded path arrives doubled | a trailing `\\name\.exe$` still matches. A separator inside a path is `\\+`, which also accepts a repeated separator that Sigma would not |
| The rule loader reads `$` as a variable | a literal dollar sign is `\x24` (`\x24Recycle\.bin`). Before a `)` the pattern uses `\z` (100402) |
| An EventData value of `-`, `(NULL)` or empty is absent, not empty | 100402 asks for a present `Details`, so these never match. `neg-details-blank`, `-dash` and `-null` pin it |
| A level-0 sibling ends the event with no alert | extra parents, one per level-0 stock child. See "Parent per logsource" |
| Stock rules attach by `if_group` | the pack groups carry no `sysmon_event*` name |
| The walk decides the final rule | see "Which rule ends an event". 92226 is never reached under 100406 and 100407, and the event alerts at level 12 |
| Two pack rules can match one event | the higher level is final, and at the same level the rule loaded first. `regsvr32.exe` or `rundll32.exe` in a listed folder ends at 100344 (12 over 10). `certutil.exe`, `wscript.exe` or `cscript.exe` in a listed folder ends at its own rule (same level, loaded first). `powershell.exe` writing a script into a Startup folder ends at 100406 and writing a `.lnk` ends at 100407. Those two extension sets do not overlap, so no event matches both. Test cases pin each |
| Stock rules at a lower level also match | the pack rule is final: 100340 over stock 92105 (ports 135 and 445), 100343 over stock 92107, 100342 over stock 92110 (port 5985), 100405 to 100407 over stock 92200, 92201, 92203, 92204 and 92225 (levels 6 to 9), 100400 over stock 92302 (level 6). A 100343 negative still ends at 92107, level 4 |
| Stock rules at a higher level also match | the stock rule is final and the event still alerts, under it. Event 3: 92104 and 92109. Event 13: 92301 and 92303. Event 11: 92211 and 92212. Event 1: 92016 and 92018. Test cases pin each |
| Stock rules at the same level also match | the stock rule is final, loaded first, and the event still alerts under it. Event 11: 92215 and 91001 against 100406 and 100407. Event 1: 92057 against 100409. Test cases pin 92215 and 92057 |
| Every command_prompt atomic runs under `cmd.exe /c`, which stock 92032 (level 3, a child of 61603) matches | the pack rule is higher and final. Each event 1 rule's `pos` case pins it |
| The 92028 case also matches stock 92005 (level 4) and 92029 (level 6) | the pack rule is higher and final |
| The WOW6432Node view | 100402 misses `\SOFTWARE\WOW6432Node\Microsoft\Windows NT\...`, as upstream does. 100404 matches it, because its needle starts at `\Microsoft`. Cases pin both |

## Test limits

| Event | Rules | Cases | Real captures |
|---|--:|--:|--:|
| 3 | 5 | 124 | 7 |
| 13 | 5 | 64 | 5 |
| 11 and 22 | 4 | 147 | 4 |
| 1 | 4 | 96 | 5 |
| All | 18 | 431 | 21 |

Of the 21 real captures, 20 are negatives and one is a positive (100342 `pos-real`). The other 410
cases are built from the real ones with fields changed, and each case's `note` names the fields.
`203.0.113.10` and `203.0.113.5` in a case are documentation addresses standing in for public
ones. The 2026-11-20 runs covered all 431 on Wazuh 4.14.9 with no failures. It checks patterns,
parent chains, finality and decoding of the test lines. It does not check the shape of a live log
line.

**Event 3.**

- The repo's leak check refuses private addresses in committed files, so the `10.0.0.0/8`,
  `172.16.0.0/12` and `192.168.0.0/16` branches have no case inside the range. Each has a positive
  case just below and just above it. Link-local and unique-local are tested with the few addresses
  the leak check allows (`169.254.169.254`, and the first address of `fe80::/10`, `fc00::/7` and
  its `fd` half). Loopback and the Microsoft ranges have cases on both sides.
- The endpoint's Sysmon config logs event 3 only for a named set of programs and folders. No
  browser is in it, so the browser negative is a synthetic event, and Defender's update traffic
  stands in for Windows Update.
- Every one of the 17 folders in 100344 has a positive case.
- The live test of 100340 (2026-11-12) did not use the best-known download form. On the lab's
  Windows endpoint Defender blocked `certutil -urlcache -split -f`: the process did not start and
  100340 raised no alert. The test used `certutil -generateSSTFromWU`, which raised 100340 within
  seconds. This is one dated observation. The block is a signature that can change with a
  definitions update, and it does not apply where Defender is off or excluded.

**Event 13.**

- The endpoint's real event 13 captures are three Task Scheduler Index writes by `svchost.exe`.
  None is near any of the five rules, so each rule has one real case and it is a negative
  (`neg-real-taskcache`). Every positive is built from the first capture with Image, TargetObject,
  Details and User changed.
- Positives use what the named Atomic Red Team test writes: T1037.001 test 1 (100400), T1547.010
  test 1 (100401), T1546.011 test 3 (100402), T1070.005 test 4 (100403) and T1548.002 test 8
  (100404). The Sysmon records for those tests were not captured on the endpoint. The
  `TargetObject` is the one Sysmon would log for the command in the test (a `HKCU` path becomes
  `HKU\<SID>`), and the SID is the placeholder `S-1-5-21-0-0-0-1001`.
- Not tested: a `Details` over the length Sysmon truncates, and a binary value (`Binary Data`),
  which none of the five rules reads.

**Events 11 and 22.**

- The endpoint's Sysmon config logs event 11 for a named set of programs and folders. The capture
  file holds three records: `svchost.exe` as SYSTEM writing under `Windows\appcompat`, and
  `powershell.exe` and `pwsh.exe` writing `__PSScriptPolicyTest_*.ps1` under the user's Temp
  folder. It holds three event 22 records, two of them the same lookup. No case is a real shim,
  Startup or IP-lookup event.
- Every positive writes what the Atomic Red Team test for it writes where one exists: T1546.011
  test 2 for 100405, T1547.001 test 7 (a `.lnk` in the user Startup folder) for 100407, T1614 test
  1 for 100412.
- Event 11 cases use `svchost.exe` as SYSTEM as the base, with no user path, and the all-users
  Startup folder where a Startup path is needed. The user Startup folder needs a user name, so
  those cases use `labuser`.
- 100406 has one positive for each of its 17 extensions. 100412 has one positive for each of its 43
  names (2 exact, 41 contains) and one negative for each filter value.
- Stock 92211, 92212 (level 14) and 92215 (level 12, a tie) each end a pack event, and a case
  pins each. Not tested: a tie with stock 92207 or 91001, and stock 92214 (level 15). Stock
  92213 (level 15, a Temp drop) ends the real `powershell.exe` Temp capture in `tests/100407`,
  where no pack rule matches.

**Event 1.**

- The five real captures are all negatives: the WmiPrvSE.exe start in each rule's folder, and in
  100408 the capture session's own `powershell.exe -EncodedCommand`, whose command line holds the
  text `-Encode` (the image test is what stops 100408). The rest are built from the WmiPrvSE.exe
  capture (record 939560) with fields changed.
- `labuser`'s logon fields come from the PowerShell capture (record 939655). The version strings
  (`Description`, `OriginalFileName`) are what Windows ships for each binary, not captured on the
  endpoint. `Hashes` are zeroed stand-ins. No rule reads them.
- The parent of an atomic's process is written as `"C:\Windows\system32\cmd.exe" /c "<lines joined
  by &>"`, how Invoke-AtomicTest runs a command_prompt test. Assumed, not captured. The child's
  command line is the atomic's line as written, with `%temp%` expanded.
- The en dash, em dash, horizontal bar and figure dash in the cases are written as JSON escapes,
  so no committed file holds a raw dash look-alike. The figure dash (U+2012) is the neighbour below
  the class's first code point, and each windash rule has a negative on it.
- Not checked: the quote and entity escapes on a live event 1, and whether Wazuh's XML reader trims
  a trailing space in a pattern.

## The folders as a whole

The same commit holds 51 `network_connection` rules. Counted with a YAML parser:

| | Rules |
|---|--:|
| `condition: selection`, no filter | 19 |
| `selection and not 1 of filter_*` (one or two filter groups) | 29 |
| `all of selection_*` | 2 |
| `selection and filter` | 1 |
| at least one filter that needs two fields at once | 8 |
| uses `CommandLine` or `ParentImage` | 4 |
| filters on `SourceHostname` or `DestinationHostname` | 4 |

So 8 of 51 rules cannot be carried by one Wazuh rule without a helper, and 13 use `|cidr`, where
every range that is not on an octet boundary is written by hand.

Modifier use across the five folders the pack draws on, counted from a reference checkout at the
same commit. `|re` includes `|re|i`.

| Folder | Rules | `\|endswith` | `\|contains` | `\|startswith` | `\|contains\|all` | `\|windash` | `\|re` |
|---|--:|--:|--:|--:|--:|--:|--:|
| `network_connection` | 51 | 149 | 38 | 38 | 5 | 0 | 0 |
| `registry/registry_set` | 206 | 247 | 270 | 53 | 45 | 0 | 1 |
| `file/file_event` | 167 | 249 | 125 | 56 | 36 | 0 | 9 |
| `dns_query` | 23 | 64 | 25 | 25 | 1 | 0 | 0 |
| `process_creation` | 1193 | 1338 | 1359 | 52 | 547 | 104 | 67 |

`|cidr` is 25 in `network_connection` and was not counted elsewhere. `process_creation` also holds
4 `|base64offset|contains` and one `fieldref`, which no port has met.

Two things stand out. `|contains|all` and `|windash` are now met, and they are the modifiers
`process_creation` leans on hardest. `|re` is the one with real weight left: it is 67 uses in
`process_creation` and 9 in `file_event`, and no port has needed it.
