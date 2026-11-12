# B.2 Sigma Constructs

Phase B ports Sigma rules to Wazuh by hand before deciding whether a compiler is worth building.
This page records every Sigma construct the first five ports met, how each one is written in
Wazuh XML, and what could not be written at all. It is the evidence for that decision.

**Scope:** five rules from SigmaHQ `rules/windows/network_connection` at commit `53423dac`, ported
to [`local_eid3_pack.xml`](../deploy/soc-recon/wazuh/custom-rules/local_eid3_pack.xml) as IDs
100340 to 100344. The Sigma YAML is in [`sigma/`](sigma/) and the test cases are in
[`tests/`](tests/). Everything here was checked on Wazuh 4.14.9 with `tools/logtest.ts`, which
runs each case through a real `wazuh-analysisd` on a scratch manager.

| ID | Level | Upstream rule | Ported |
|---|:--:|---|---|
| 100340 | 12 | `net_connection_win_certutil_initiated_connection` | in full |
| 100341 | 10 | `net_connection_win_regsvr32_network_activity` | in full |
| 100342 | 10 | `net_connection_win_rundll32_net_connections` | in part, two filters dropped |
| 100343 | 12 | `net_connection_win_wscript_cscript_outbound_connection` | in full |
| 100344 | 12 | `net_connection_win_susp_initiated_uncommon_or_suspicious_locations` | in part, one filter left out on purpose |

## Parent per logsource

A Sigma `logsource` becomes the `if_sid` parent. For `category: network_connection` with
`product: windows` that is stock rule 61605, Sysmon event 3.

One parent was not enough. Stock rules 92101 (`powershell.exe` over TCP) and 92108 (any
connection to port 3389) are level-0 children of 61605. On 4.14.9 an event that matched one of
them ended there with no alert, even when a pack rule at level 10 also matched: `regsvr32.exe` to
port 3389 ended at 92108, and a binary named `powershell.exe` in `C:\Users\Public` ended at 92101.
Every pack rule therefore names three parents, `61605, 92101, 92108`, so it is also tried as a
child of the two level-0 rules. Stock rule 92110 uses the same idiom.

A new logsource needs the same check before its first rule: read the stock children of the parent
and find the level-0 ones.

The pack's group is `local,eid3_pack,`. It must not carry `sysmon_event3`: five stock rules
(92101, 92104, 92105, 92107, 92108) attach by `if_group`, so they would become children of the
pack rules and take the final match.

## Field mapping

Sysmon event 3 fields arrive under `win.eventdata` with a lower-case first letter.

| Sigma field | Wazuh field | Note |
|---|---|---|
| `Image` | `win.eventdata.image` | each backslash arrives doubled |
| `Initiated` | `win.eventdata.initiated` | `true` or `false` |
| `DestinationPort` | `win.eventdata.destinationPort` | |
| `DestinationIp` | `win.eventdata.destinationIp` | IPv6 is written in full, never compressed |
| `DestinationHostname` | `win.eventdata.destinationHostname` | absent when Sysmon logs `-` |
| `SourceHostname` | `win.eventdata.sourceHostname` | absent when Sysmon logs `-` |
| `CommandLine`, `ParentImage` | none | event 3 does not carry them |

Wazuh drops an EventData value of `-`, so a field that Sysmon left empty is not an empty string
in the rule. It is missing. On the lab's Windows endpoint both hostname fields were `-` in every
event sampled.

## Constructs met

| Sigma construct | Wazuh XML | Met in |
|---|---|---|
| plain string match | `type="pcre2"` with `(?i)`, anchored at both ends | all five |
| `\|endswith` | `(?i)\\name\.exe$` | all five |
| `\|contains` | unanchored pattern | 100344 |
| list of values on one field | one alternation | 100340, 100343, 100344 |
| several fields in one selection (AND) | one `<field>` each | all five |
| `\|cidr` | an address-prefix pattern | 100342, 100343 |
| `not 1 of filter_*`, one field per filter | one negated `<field>` per field, the values of every filter on that field joined | 100342, 100343 |
| filter on a field that can be absent | a negated `<regex>` over the whole log line | 100342 |
| `tags` with `attack.t....` | `<mitre><id>` | all five |
| `level` | medium 10, high 12, critical 15 | all five |

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

### Filters

`selection and not 1 of filter_*` means "none of the filters match". When every filter tests one
field, that is one negated `<field>` per field. Two filters on the same field join into one
alternation.

A negated `<field>` only works on a field every event carries. 100342 first carried a negated
`win.eventdata.sourceHostname`, and it never fired: the field was absent, and a rule with a
negated test on an absent field does not match. The filter is now a negated `<regex>` over the
log line, `"sourceHostname":"[^"]*\.internal\.cloudapp\.net"`, which is simply false when the key
is missing.

This filter is proven on the scratch manager only, where the log line comes from the test
decoder. If the live log line were shaped differently the filter would stop excluding anything
and the rule would still alert. It cannot hide a detection. The same holds for a host name with
a JSON-escaped quote in it, which `[^"]*` stops at.

The other direction is a real gap. 100342 and 100343 keep a negated `win.eventdata.destinationIp`,
so an event with no `DestinationIp` matches neither rule, where the Sigma rule would alert. Sysmon
writes the field on every event 3, so the gap needs a malformed event to open. A test case in
each rule records it (`neg-no-destination-ip`).

## Constructs that did not port

| Construct | Where | Why |
|---|---|---|
| a filter that needs two fields at once | 100342 `filter_main_svchost_update_processes` | `not (A and B)` is `not A or not B`, and one Wazuh rule holds no OR across fields |
| a filter on `CommandLine` or `ParentImage` | 100342 `filter_main_app_sdb` and the one above | event 3 carries neither field |
| OR across fields in a selection (`1 of selection_*`) | not met in these five | would need one rule per branch |
| `\|windash` | not met | the folder does not use it. It belongs to `CommandLine`, so it first appears in `process_creation` |

The usual Wazuh answer to a two-field filter is a level-0 helper rule that matches the benign
case first. The pack has no room for one: `tools/sigma-lint.ts` requires every pack rule to have
a Sigma YAML and a level of medium or higher.

What the drops cost: 100342 alerts on whatever the two filters would have dropped, which is
`rundll32.exe` started by `svchost.exe` on port 443, and the `PcaSvc.dll` compatibility task.
Event 3 alone cannot say which events those are. The endpoint's Sysmon log held one SYSTEM
`rundll32.exe` event to a Microsoft address on 443, outside the listed ranges, when the pack was
written. It is kept as a positive case, [`tests/100342/pos-real.json`](tests/100342/pos-real.json),
so the cost stays visible.

The event 1 for the same process, one record earlier, names it: `PcaSvc.dll,PcaPatchSdbTask`,
started by `svchost.exe` for Task Scheduler. Both upstream filters would have dropped it. In the
five days of log on hand the task ran eleven times and opened a connection once, and no other
`rundll32.exe` process logged an event 3. The expected cost is well under one alert a day.

100344 leaves out upstream's file-sharing domain filter on purpose. Upstream has it so a sibling
rule can own those domains. This pack does not carry that sibling, so the filter would only hide
them.

## Wazuh behaviour that is not in the Sigma

| Behaviour | What the port does |
|---|---|
| Each backslash in a decoded path arrives doubled | a trailing `\\name\.exe$` still matches. A separator inside a path is `\\+`, which also accepts a repeated separator that Sigma would not |
| The rule loader reads `$` as a variable | a literal dollar sign is `\x24` (`\x24Recycle\.bin`) |
| A level-0 sibling ends the event with no alert | three parents, as above |
| Two pack rules can match one event | the higher level is final, and at the same level the rule loaded first. `regsvr32.exe` or `rundll32.exe` in a listed folder ends at 100344 (12 over 10). `certutil.exe`, `wscript.exe` or `cscript.exe` in a listed folder ends at its own rule (same level, loaded first). Test cases pin each |
| Stock rules at a lower level also match | the pack rule is final: 100340 over stock 92105 (ports 135 and 445), 100343 over stock 92107, 100342 over stock 92110 (port 5985). A 100343 negative still ends at 92107, level 4 |
| Two stock rules are level 15 | 92104 (U+202E, the right-to-left override, in the image path) and 92109 (port 3389 with loopback at both ends) are final over any pack rule. The event still alerts, under the stock rule. Test cases pin both |

## Test limits

- The repo's leak check refuses private addresses in committed files, so the `10.0.0.0/8`,
  `172.16.0.0/12` and `192.168.0.0/16` branches have no case inside the range. Each has a
  positive case just below and just above it. Link-local and unique-local are tested with the
  few addresses the leak check allows (`169.254.169.254`, and the first address of `fe80::/10`,
  `fc00::/7` and its `fd` half). Loopback and the Microsoft ranges have cases on both sides.
- The endpoint's Sysmon config logs event 3 only for a named set of programs and folders. No
  browser is in it, so the browser negative is a synthetic event, and Defender's update traffic
  stands in for Windows Update.
- Of 124 cases, seven are real captures, six negatives and one positive, from five events. The
  other 117 are built from one real capture with fields changed, and each case's `note` names
  the fields. `203.0.113.10` in a case is a documentation address standing in for a public one.
- Every one of the 17 folders in 100344 has a positive case.
- The live test of 100340 (2026-11-12) did not use the best-known download form. On the lab's
  Windows endpoint Defender blocked `certutil -urlcache -split -f`: the process did not start
  and 100340 raised no alert. The test used `certutil -generateSSTFromWU`, which raised 100340
  within seconds. This is one dated observation. The block is a signature that can change with
  a definitions update, and it does not apply where Defender is off or excluded.

## The folder as a whole

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

Modifier use across the folder: `|endswith` 149, `|contains` 38, `|startswith` 38, `|cidr` 25,
`|contains|all` 5, `|windash` 0, `|re` 0.

So 8 of 51 rules cannot be carried by one Wazuh rule without a helper, and 13 use `|cidr`, where
every range that is not on an octet boundary is written by hand.
