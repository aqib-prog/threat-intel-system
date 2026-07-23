# Card 5 step-5 pre-Layer-2 baseline

sbousseaden/macOS-ATTACK-DATASET commit: `0315ec88d1f4b338c07315223bc6a53619465472`

## Primary strict metrics

Sample-level predictions are compared to metadata ATT&CK IDs using exact IDs. Micro scores aggregate TP/FP/FN across all 54 captures.

| Rule set | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Current runtime | 0.400 | 0.127 | 0.193 | 8 | 12 | 55 |
| Layer-1 preview | 0.144 | 0.222 | 0.175 | 14 | 83 | 49 |

## Layer-1 preview confidence thresholds

| Threshold | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| high only | 0.429 | 0.095 | 0.156 | 6 | 8 | 57 |
| high and medium | 0.458 | 0.175 | 0.253 | 11 | 13 | 52 |
| all confidences | 0.144 | 0.222 | 0.175 | 14 | 83 | 49 |

## Per-tactic Layer-1 preview

| Tactic | Samples | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| collection | 3 | 0.286 | 0.667 | 0.400 | 2 | 5 | 1 |
| credential_access | 9 | 0.176 | 0.300 | 0.222 | 3 | 14 | 7 |
| defense_evasion | 8 | 0.083 | 0.111 | 0.095 | 1 | 11 | 8 |
| discovery | 2 | 0.400 | 0.667 | 0.500 | 2 | 3 | 1 |
| execution | 6 | 0.111 | 0.091 | 0.100 | 1 | 8 | 10 |
| lateral_movement | 2 | 0.000 | 0.000 | 0.000 | 0 | 2 | 2 |
| persistence | 16 | 0.161 | 0.294 | 0.208 | 5 | 26 | 12 |
| privileges_elevation | 8 | 0.000 | 0.000 | 0.000 | 0 | 14 | 8 |

## Checkpoint verdict and failure analysis

The Layer-1 preview clears the proposed recall bar (22.2% versus 60%) but fails the proposed precision bar (14.4% versus 80%). It raises recall by +9.5 percentage points from the current runtime, while precision changes by -25.6 percentage points.

The preview emits a mean of 1.8 distinct technique IDs per capture (minimum 1, maximum 4). Parent/sub-technique-family scoring improves the result only to 17.5% precision and 27.4% recall, so ID granularity is not the main cause of the precision failure.

Most frequent strict false-positive technique IDs:

- `T1036.006` in 54/54 captures
- `T1087.001` in 14/54 captures
- `T1059.002` in 6/54 captures
- `T1685` in 2/54 captures
- `T1136.001` in 2/54 captures
- `T1647` in 1/54 captures
- `T1105` in 1/54 captures
- `T1543.001` in 1/54 captures
- `T1569.001` in 1/54 captures
- `T1078.003` in 1/54 captures

Most frequent contributing sources (one count per affected capture):

- `Sigma: proc_creation_macos_space_after_filename.yml` in 54/54 captures
- `Sigma: proc_creation_macos_local_account.yml` in 14/54 captures
- `Atomic Red Team T1059.002` in 5/54 captures
- `Sigma: macos_tcc_database_tampering` in 2/54 captures
- `Sigma: proc_creation_macos_create_account.yml` in 2/54 captures
- `MITRE ATT&CK T1647` in 1/54 captures
- `Sigma: proc_creation_macos_applescript.yml` in 1/54 captures
- `Atomic Red Team T1105` in 1/54 captures
- `Atomic Red Team T1543.001` in 1/54 captures
- `GTFOBins-style LOLBin: launchctl` in 1/54 captures

The dominant failure is field erasure in the pre-Layer-2 raw-text projection. The generated regexes preserve Boolean structure but not which JSON field a literal belongs to.

## Method and limitations

- This is the existing raw-text detector/parser/regex approach; no canonical field extraction is used.
- The primary metric is sample-level exact ATT&CK-ID matching. A parent/sub-technique family diagnostic is included in JSON but is not used as the headline result.
- Each capture contains attack activity plus surrounding host telemetry. Predictions outside the metadata labels count as false positives, even when they may describe real secondary behavior present in the capture.
- This attack-only corpus cannot establish a benign-log false-positive rate; that requires the separate benign batch described in Card 5 Layer 3.
- A conservative mandatory-literal prefilter skips lines that cannot satisfy a regex, then the original Python regex decides every candidate. This changes performance, not matching semantics.
- The upstream README links GNU GPL v3. Corpus telemetry remains in the external pinned checkout and is not redistributed in this repository.

## Case details

| Dataset | Tactic | Ground truth | Runtime predictions | Layer-1 predictions | Seconds |
|---|---|---|---|---|---:|
| MACOS-ATTACK-001 | collection | T1115 | T1059.002 | T1036.006, T1059.002 | 0.008 |
| MACOS-ATTACK-002 | collection | T1552.003 | T1552.003 | T1036.006, T1087.001, T1552.003 | 0.003 |
| MACOS-ATTACK-003 | collection | T1113 | T1113 | T1036.006, T1113 | 0.002 |
| MACOS-ATTACK-004 | credential_access | T1539 | — | T1036.006, T1087.001 | 0.003 |
| MACOS-ATTACK-005 | credential_access | T1539 | — | T1036.006, T1087.001 | 0.003 |
| MACOS-ATTACK-006 | credential_access | T1558.005 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-007 | credential_access | T1555.001 | T1555.001 | T1036.006, T1555.001 | 0.001 |
| MACOS-ATTACK-008 | credential_access | T1555.001 | T1555.001 | T1036.006, T1555.001 | 0.001 |
| MACOS-ATTACK-009 | credential_access | T1056.002 | T1059.002 | T1036.006, T1056.002, T1059.002 | 0.002 |
| MACOS-ATTACK-010 | credential_access | T1003 | — | T1036.006 | 0.002 |
| MACOS-ATTACK-011 | credential_access | T1539, T1548.006 | — | T1036.006, T1087.001 | 0.003 |
| MACOS-ATTACK-012 | credential_access | T1003 | — | T1036.006, T1087.001 | 0.002 |
| MACOS-ATTACK-013 | defense_evasion | T1553.001 | T1553.001 | T1036.006, T1553.001 | 0.001 |
| MACOS-ATTACK-014 | defense_evasion | T1685 | T1647 | T1036.006, T1647 | 0.001 |
| MACOS-ATTACK-015 | defense_evasion | T1574.006 | — | T1036.006 | 0.004 |
| MACOS-ATTACK-016 | defense_evasion | T1059.007, T1548.006 | — | T1036.006 | 0.002 |
| MACOS-ATTACK-017 | defense_evasion | T1553.004 | — | T1036.006 | 0.002 |
| MACOS-ATTACK-018 | defense_evasion | T1556.003 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-019 | defense_evasion | T1548.006 | T1685 | T1036.006, T1087.001, T1685 | 0.002 |
| MACOS-ATTACK-020 | defense_evasion | T1685 | — | T1036.006 | 0.002 |
| MACOS-ATTACK-021 | discovery | T1518.001 | — | T1036.006, T1518.001 | 0.002 |
| MACOS-ATTACK-022 | discovery | T1069.002, T1087.001 | — | T1036.006, T1087.001, T1136.001 | 0.003 |
| MACOS-ATTACK-023 | execution | T1059.004, T1059.007, T1105 | T1105 | T1036.006, T1105 | 0.004 |
| MACOS-ATTACK-024 | execution | T1036, T1564.001 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-025 | execution | T1546.016 | T1059.002 | T1036.006, T1059.002 | 0.004 |
| MACOS-ATTACK-026 | execution | T1059.007, T1105 | — | T1036.006, T1059.002 | 0.002 |
| MACOS-ATTACK-027 | execution | T1027, T1059.006 | — | T1036.006 | 0.004 |
| MACOS-ATTACK-028 | execution | T1036 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-029 | lateral_movement | T1059.004 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-030 | lateral_movement | T1021.004 | — | T1036.006 | 0.002 |
| MACOS-ATTACK-031 | persistence | T1546.004 | — | T1036.006, T1087.001 | 0.001 |
| MACOS-ATTACK-032 | persistence | T1564.002 | — | T1036.006, T1087.001, T1136.001, T1564.002 | 0.002 |
| MACOS-ATTACK-033 | persistence | T1053.003 | — | T1036.006, T1053.003 | 0.001 |
| MACOS-ATTACK-034 | persistence | T1053.003 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-035 | persistence | T1647 | — | T1036.006, T1087.001 | 0.001 |
| MACOS-ATTACK-036 | persistence | T1546.014 | T1105 | T1036.006, T1105 | 0.010 |
| MACOS-ATTACK-037 | persistence | T1546.014 | — | T1036.006, T1546.014 | 0.005 |
| MACOS-ATTACK-038 | persistence | T1564.001 | — | T1036.006 | 0.002 |
| MACOS-ATTACK-039 | persistence | T1547.015 | T1059.002 | T1036.006, T1059.002 | 0.001 |
| MACOS-ATTACK-040 | persistence | T1543.001, T1564.001 | T1543.001 | T1036.006, T1087.001, T1543.001 | 0.002 |
| MACOS-ATTACK-041 | persistence | T1543.004 | T1543.004 | T1036.006, T1543.004 | 0.001 |
| MACOS-ATTACK-042 | persistence | T1037.002 | — | T1036.006, T1087.001 | 0.002 |
| MACOS-ATTACK-043 | persistence | T1037.002 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-044 | persistence | T1053 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-045 | persistence | T1098.004 | — | T1036.006, T1087.001 | 0.002 |
| MACOS-ATTACK-046 | persistence | T1546 | — | T1036.006, T1087.001 | 0.002 |
| MACOS-ATTACK-047 | privileges_elevation | T1548.006 | T1685 | T1036.006, T1685 | 0.005 |
| MACOS-ATTACK-048 | privileges_elevation | T1548.003 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-049 | privileges_elevation | T1548.006 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-050 | privileges_elevation | T1098 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-051 | privileges_elevation | T1548.001 | — | T1036.006 | 0.001 |
| MACOS-ATTACK-052 | privileges_elevation | T1548.004 | T1059.002 | T1036.006, T1059.002 | 0.001 |
| MACOS-ATTACK-053 | privileges_elevation | T1548.004 | T1543.001, T1569.001 | T1036.006, T1087.001, T1543.001, T1569.001 | 0.002 |
| MACOS-ATTACK-054 | privileges_elevation | T1098.007 | T1078.003 | T1036.006, T1078.003 | 0.002 |
