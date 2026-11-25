# Phase B: a detection pack, validated against ATT&CK

This writeup is in draft. Every number in it comes from the generated results section below.

Phase B asks one question of every rule in the pack. Did it fire on the real thing? A rule
counts as validated only when it raised a live alert from the Windows endpoint inside the
window of an Atomic Red Team test run. A rule that only passes in logtest is not validated.
It is in the pack, and that is all I claim for it.

The pack is small on purpose. Each rule starts as a Sigma rule, becomes a Wazuh rule by hand,
gets pinned by planted cases, and then has to earn its place on the coverage map with a real
run. This page follows one rule through all of that, then shows the results, the misses, and
how to recompute every number here.

## One rule, end to end

The rule is 100407. It catches PowerShell writing a shortcut into a Startup folder, which is
ATT&CK technique T1547.001. A shortcut there runs at the next logon, so it is a cheap way to
persist.

### The Sigma source

The source is the SigmaHQ rule `file_event_win_powershell_startup_shortcuts.yml`. My copy is
[`sigma/100407-powershell-startup-shortcut.yml`](sigma/100407-powershell-startup-shortcut.yml).
It keeps the upstream detection, names the upstream commit it was copied from, and adds a
`custom.wazuh` block with the rule ID, the parent rules, the level and the technique.

The detection reads the Sysmon file-create event. It wants three things at once. The writing
process is `powershell.exe` or `pwsh.exe`. The file path contains the Startup folder. The file
name ends in `.lnk`.

Sigma calls this rule high. In this pack a high rule is a Wazuh level 12 rule.

### The Wazuh rule

The port is by hand. The rule lives in
[`deploy/soc-recon/wazuh/custom-rules/`](../deploy/soc-recon/wazuh/custom-rules/), in the pack
file for file-create events. Nothing from the Sigma detection is dropped. The two conditions
on the file path become one ordered pattern, the folder and then the extension.

The port differs from upstream in one way. Wazuh's decoder doubles each backslash, so the rule
accepts one or more backslashes at each separator. A path with a repeated separator matches
here where Sigma would not.

A hand port can drift from its source. `tools/sigma-lint.ts` holds each YAML to its XML rule:
the ID, the level, the parents and the technique have to agree, or the lint fails.

### The planted cases

A rule that fires is half the test. The other half is what it must not fire on. The cases
live in [`tests/100407/`](tests/100407/), and `tools/logtest.ts` runs each one through
`wazuh-logtest` on a scratch manager that has no network.

Every case starts from a real Sysmon event captured on the Dell, with the host and user names
replaced. A few fields are then edited to make the point of the case, and the case's note
says which.

The positive cases say the rule must fire on the shortcut the Atomic Red Team test writes, on
the same write from `pwsh.exe`, on an upper case path, on a subfolder of Startup, and on the
all-users Startup folder.

The negative cases say where the rule stops. A folder whose name only begins with `Startup`
is not the Startup folder. A shortcut on the Desktop is not persistence. A file named
`calc.lnk.txt` is not a shortcut. An image named `mypowershell.exe` is not PowerShell, and
neither is `svchost.exe`.

Some cases pin which rule gets the last word, because Wazuh ends an event at one rule. A
stock rule matches PowerShell writing any `.tmp` name under a user folder and scores it level 0.
A shortcut named with `.tmp` in it would have ended there in silence. So 100407 hangs from that
stock rule too, and a case holds it.

### The ART run

The test is `T1547.001 #7`, "Add Executable Shortcut Link to User Startup Folder". It uses
PowerShell to create a shortcut to the calculator in the user's Startup folder, and its cleanup
removes the shortcut.

`tools/art-harness.ts` ran it on the Dell in session `20261122T035737Z-cb8eb2`. The harness is
strict about what it will run and what it leaves behind:

- It runs only tests on [`atomics/allowlist.json`](../atomics/allowlist.json).
- The test files on the Dell are a staged copy of atomics commit
  `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`. Every file is hashed in
  [`atomics/manifest.json`](../atomics/manifest.json) and hashed again on the Dell before the
  session.
- Defender real-time protection has to be on, with the staged folder as the only exclusion.
- Each session makes its own restore point first.
- It snapshots the Dell's state before and after: services, scheduled tasks, Run keys, WMI
  subscriptions, local users, administrators, Defender preferences, and the keys and folders
  the tests write to. Any difference fails the session.

This session passed. Both of its tests exited clean, cleanup completed, and the snapshots
were equal. The record is
[`art-runs/20261122T035737Z-cb8eb2.json`](art-runs/20261122T035737Z-cb8eb2.json). It holds
the start and end of each test in UTC, from the Dell's clock.

### The alert

The test ran from `2026-11-22T03:58:04.900Z` to `2026-11-22T03:58:06.548Z`. Sysmon stamped
the file-create event at `2026-11-22T03:58:06.455Z`, inside that window. Rule 100407 alerted on
it at level 12 from agent 001, with `powershell.exe` as the image. The alert reached the index
about a second later.

`tools/coverage.ts fetch` asks the live index for the endpoint's alerts around each session
and writes what it finds to
[`validation/20261122T035737Z-cb8eb2.alerts.json`](validation/20261122T035737Z-cb8eb2.alerts.json).
That file carries a hash of its session record, so editing a record makes its evidence
stale.

The match is on the event's own time, not on when the alert was indexed. There is no lag
allowance. An event stamped outside its test's window does not count, however close it is.

### The layer

`tools/coverage.ts build` reads the pack, the session records and the evidence, and writes two
ATT&CK Navigator layers:

- [`coverage/layer-rule-exists.json`](coverage/layer-rule-exists.json) scores a technique by
  the pack rules that map to it.
- [`coverage/layer-validated.json`](coverage/layer-validated.json) scores a technique by the
  pack rules that a live alert validated.

In the validated layer, T1547.001 carries rule 100407 and names the test and the session that
earned it. Rule 100406 sits on the same technique with its own test.

To see the validated layer, open it in the
[hosted Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fktalons%2Ftalonsoclab%2Fmain%2Fphase-b-detection%2Fcoverage%2Flayer-validated.json).
The layers are pinned to ATT&CK 19.2.

## Validation results

14 of 18 pack rules are validated (77.8 percent) by a live alert from an ART test run.

Misses by class: 3 blocked by Defender, 1 not run.

Every rule that is not validated has a miss class.

The rule-exists layer scores 16 techniques and the validated layer scores 13 techniques.

| Rule | Level | ATT&CK 19.2 | Status | ART test or miss class | Session |
|---|---|---|---|---|---|
| 100340 | 12 | T1105 | not validated | blocked-by-defender | 20261123T051200Z-b4e336 |
| 100341 | 10 | T1218.010, T1559.001 | not validated | blocked-by-defender | 20261125T182727Z-90da90 |
| 100342 | 10 | T1218.011 | not validated | blocked-by-defender | 20261125T182914Z-6ca13f |
| 100343 | 12 | T1105 | validated | T1105 #26 | 20261123T090325Z-4b506a |
| 100344 | 12 | T1105 | not validated | not-run | none |
| 100400 | 10 | T1037.001 | validated | T1037.001 #1 | 20261122T035737Z-cb8eb2 |
| 100401 | 10 | T1547.010 | validated | T1547.010 #1 | 20261123T051536Z-245b00 |
| 100402 | 10 | T1546.011 | validated | T1546.011 #3 | 20261123T051536Z-245b00 |
| 100403 | 10 | T1070.005 | validated | T1070.005 #4 | 20261123T051536Z-245b00 |
| 100404 | 10 | T1548.002 | validated | T1548.002 #8 | 20261123T051536Z-245b00 |
| 100405 | 10 | T1546.011 | validated | T1546.011 #2 | 20261123T051536Z-245b00 |
| 100406 | 12 | T1204.002, T1547.001 | validated | T1547.001 #6 | 20261123T051536Z-245b00 |
| 100407 | 12 | T1547.001 | validated | T1547.001 #7 | 20261122T035737Z-cb8eb2 |
| 100408 | 10 | T1027 | validated | T1140 #1 | 20261123T051536Z-245b00 |
| 100409 | 12 | T1053.005 | validated | T1053.005 #1 | 20261123T051536Z-245b00 |
| 100410 | 12 | T1003.005 | validated | T1003.005 #1 | 20261122T035219Z-95651d |
| 100411 | 10 | T1033 | validated | T1033 #8 | 20261122T035219Z-95651d |
| 100412 | 10 | T1590 | validated | T1614 #1 | 20261123T090325Z-4b506a |

Source: `coverage.json`, SHA-256 09f3d4cb9a461654b3832e4899b6f272e79eaee384f18b35a5e78d6710e1a9ce.

## The misses and what each showed

A miss is worth as much as a hit if it has a cause. Every rule that is not validated carries a
miss class in [`validation/misses.json`](validation/misses.json), with its evidence.

### Blocked by Defender: 100340, 100341 and 100342

Rule 100340 looks for `certutil.exe` opening a network connection. Its test, `T1105 #7`,
downloads a file with certutil. Defender stopped the command before it connected, in session
`20261123T051200Z-b4e336`, as it had on 2026-11-12.

Rule 100341 looks for a regsvr32.exe image opening a network connection, and rule 100342 for
a rundll32.exe image connecting to a public address. Their tests, `T1218.010 #2` and `T1218.011 #1`,
each fetch a scriptlet from the atomics `master` branch at run time and run it. That code is
outside the commit pin, so I held these tests back at first.

I ran them on 2026-11-25. Right before each run I fetched the scriptlet myself and compared it
with the copy in the pinned commit. Each matched byte for byte, and each only starts
`calc.exe` or `notepad.exe`. Defender stopped the commands anyway, in sessions
`20261125T182727Z-90da90` and `20261125T182914Z-6ca13f`.

The lab did see every one of these. Defender logged event 1116 inside each test's window, and
stock rule 62123 alerted on it through the Defender channel. So the behavior was caught, by
Defender and not by my rules. The rules stay in the pack and stay unvalidated.

### Not run: 100344

Rule 100344 looks for a process in an unusual folder opening a network connection. No test
in the pinned atomics does that with its default inputs, and I chose not to override inputs.
It has no test.

### Two misses that turned out to be the sensor

Rules 100343 and 100412 missed on the first run and validated on a later one, in session
`20261123T090325Z-4b506a`. Nothing about the rules changed in between. The Dell was rebooted.

The cause is the clock. The Dell's clock is stepped forward once a day. Sysmon's times on
network and DNS events, event 3 and event 22, do not follow the step. They keep the time base
Sysmon started with, so they fall behind by every correction since boot.

That offset does more than put a timestamp outside a window. When Sysmon's network times trail
the clock, it cannot name a process younger than the offset. My Sysmon config includes network
events by process image, so an unnamed process means the event is dropped. The same test from
the same config left no event 3 with the offset in place, and left one a few minutes after a
reboot. That is one test each way, not a series.

So these two rules validate only between a boot and the next clock step. It is also a gap in
the lab as it runs, not only in validation: from the first clock step after a boot, the sensor
loses the connections of short-lived processes. Fixing the time sync is planned for a later phase.

## Recompute every number

Everything in the results section is built from files in this repo. With
[Bun](https://bun.sh/) installed, from the repo root:

```bash
bun tools/coverage.ts check --final
```

That rebuilds both layers, `coverage.json` and the results section in memory from the rule
XML, the session records, the evidence files and the misses. It fails if any checked-in copy
differs by a byte, or if any rule is neither validated nor classified.

```bash
bun tools/coverage.ts claims phase-b-detection/README.md
```

That refuses any count or percentage typed in this page outside the results section. The
prose here may name rules, techniques, tests, sessions and dates. It may not count them. The
pre-commit hook runs both checks on a copy of the staged files.

Two steps need the lab and cannot be rerun from a clone. `tools/logtest.ts` needs the scratch
manager, and `tools/coverage.ts fetch` needs the live index. Their inputs and outputs are all
checked in: the cases, the session records and the evidence files.

## Limits

- **One endpoint, one run.** Every validation is one test, run once, on one Windows machine. A
  rule that fired once on a test's default inputs is validated. That does not show it catches
  every variant. The planted cases cover variants, and only in logtest.
- **Validated is not tuned.** A live alert shows the rule fires on the behavior. It says
  nothing about how often it would fire on benign work in another environment.
- **The port is by hand.** The lint holds the IDs, levels, parents and techniques together. It
  does not prove the XML pattern means what the Sigma detection means. The cases do that work.
- **Time comes from the endpoint.** A test's window and its event's time both come from the
  Dell. The clock finding above shows how that can go wrong.
- **A status read proves the switch, not the protection.** The harness checks that Defender
  real-time protection reads on before every session. On this Dell the standard EICAR test
  file still sat untouched for over a minute after it was written. That held from an ssh
  session and from the Dell's own console, in the temp folder and on the Desktop, through a
  .NET call and through `Set-Content`. An on-demand scan of the same file detected it at
  once, and the alert reached the lab through the Defender channel. I do not know why the
  write was left alone. It does not depend on how the harness reaches the Dell, so the class
  "blocked by Defender" does not either.
- **ATT&CK is pinned.** The crosswalk and the layers use ATT&CK 19.2. A newer release exists,
  and moving to it is a rebuild.
- **Some rules are not validated.** The results table says which, and the section above says
  why. I would rather show them than cut the pack to the rules that passed.
