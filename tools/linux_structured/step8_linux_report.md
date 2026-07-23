# Card 5 structured-field pilot: Linux

Security-Datasets commit: `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`

## Primary strict metrics

Sample-level predictions are compared to metadata ATT&CK IDs using exact IDs. Micro scores aggregate TP/FP/FN across all 2 captures.

| Rule set | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Current runtime | 0.000 | 0.000 | 0.000 | 0 | 0 | 2 |
| Layer-1 preview | 0.222 | 1.000 | 0.364 | 2 | 7 | 0 |
| Layer-2 Linux preview | 0.667 | 1.000 | 0.800 | 2 | 1 | 0 |

## Layer-2 Linux preview confidence thresholds

| Threshold | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| high only | 1.000 | 0.500 | 0.667 | 1 | 0 | 1 |
| high and medium | 1.000 | 0.500 | 0.667 | 1 | 0 | 1 |
| all confidences | 0.667 | 1.000 | 0.800 | 2 | 1 | 0 |

## Per-tactic Layer-2 Linux preview

| Tactic | Samples | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| defense_evasion | 1 | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 |
| discovery | 1 | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 |

## Checkpoint verdict and failure analysis

The Linux structured pilot changes strict precision from 22.2% to 66.7% (+44.4 percentage points) and recall from 100.0% to 100.0% (+0.0 percentage points).

The field-authoritative preview emits a mean of 1.5 distinct technique IDs per capture (minimum 1, maximum 2). Parent/sub-technique-family scoring is 66.7% precision and 100.0% recall.

Most frequent strict false-positive technique IDs:

- `T1485` in 1/2 captures

Most frequent contributing sources (one count per affected capture):

- `Sigma: lnx_auditd_dd_delete_file.yml` in 1/2 captures

Structured Sigma predicates are evaluated against their original source fields, so unrelated values elsewhere in an event cannot satisfy a field-specific condition.

## Method and limitations

- Linux records use field-authoritative Sigma matching; partial records retain per-rule raw fallback until a complete positive field branch is extracted. Raw-only and non-Linux rules are unchanged.
- The primary metric is sample-level exact ATT&CK-ID matching. A parent/sub-technique family diagnostic is included in JSON but is not used as the headline result.
- Each capture contains attack activity plus surrounding host telemetry. Predictions outside the metadata labels count as false positives, even when they may describe real secondary behavior present in the capture.
- This attack-only corpus cannot establish a benign-log false-positive rate; that requires the separate benign batch described in Card 5 Layer 3.
- A conservative mandatory-literal prefilter skips lines that cannot satisfy a regex, then the original Python regex decides every candidate. This changes performance, not matching semantics.
- The external fixture is not committed. The pinned LICENSE is MIT, while the pinned README contains a contradictory GPL-3.0 sentence.

## Case details

| Dataset | Tactic | Ground truth | Runtime predictions | Layer-1 predictions | Layer-2 predictions | Seconds |
|---|---|---|---|---|---|---:|
| SDLIN-201110081941 | defense_evasion | T1027.001 | — | T1027.001, T1033, T1049, T1485, T1505.003 | T1027.001, T1485 | 0.035 |
| SDLIN-201110074812 | discovery | T1018 | — | T1018, T1033, T1049, T1505.003 | T1018 | 0.005 |
