# Phase B detection writeup

This writeup is in draft. Every number in it comes from the generated results section below.

## Validation results

14 of 18 pack rules are validated (77.8 percent) by a live alert from an ART test run.

Misses by class: 1 blocked by Defender, 3 not run.

Every rule that is not validated has a miss class.

The rule-exists layer scores 16 techniques and the validated layer scores 13 techniques.

| Rule | Level | ATT&CK 19.2 | Status | ART test or miss class | Session |
|---|---|---|---|---|---|
| 100340 | 12 | T1105 | not validated | blocked-by-defender | 20261123T051200Z-b4e336 |
| 100341 | 10 | T1218.010, T1559.001 | not validated | not-run | none |
| 100342 | 10 | T1218.011 | not validated | not-run | none |
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

Source: `coverage.json`, SHA-256 724ccfb0481206535683dcae10dc8b861ed5ec5f5033baf4e46f0cc67cfa7da8.
