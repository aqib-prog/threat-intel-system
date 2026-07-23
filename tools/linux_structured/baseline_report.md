# Card 5 step-5 pre-Layer-2 baseline

Security-Datasets commit: `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`

## Primary strict metrics

Sample-level predictions are compared to metadata ATT&CK IDs using exact IDs. Micro scores aggregate TP/FP/FN across all 2 captures.

| Rule set | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Current runtime | 0.000 | 0.000 | 0.000 | 0 | 0 | 2 |
| Layer-1 preview | 0.222 | 1.000 | 0.364 | 2 | 7 | 0 |

## Layer-1 preview confidence thresholds

| Threshold | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| high only | 0.333 | 0.500 | 0.400 | 1 | 2 | 1 |
| high and medium | 0.333 | 0.500 | 0.400 | 1 | 2 | 1 |
| all confidences | 0.222 | 1.000 | 0.364 | 2 | 7 | 0 |

## Per-tactic Layer-1 preview

| Tactic | Samples | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| defense_evasion | 1 | 0.200 | 1.000 | 0.333 | 1 | 4 | 0 |
| discovery | 1 | 0.250 | 1.000 | 0.400 | 1 | 3 | 0 |

## Checkpoint verdict and failure analysis

The Layer-1 preview clears the proposed recall bar (100.0% versus 60%) but fails the proposed precision bar (22.2% versus 80%). It raises recall by +100.0 percentage points from the current runtime, while precision changes by +22.2 percentage points.

The preview emits a mean of 4.5 distinct technique IDs per capture (minimum 4, maximum 5). Parent/sub-technique-family scoring improves the result only to 22.2% precision and 100.0% recall, so ID granularity is not the main cause of the precision failure.

Most frequent strict false-positive technique IDs:

- `T1033` in 2/2 captures
- `T1049` in 2/2 captures
- `T1505.003` in 2/2 captures
- `T1485` in 1/2 captures

Most frequent contributing sources (one count per affected capture):

- `Sigma: lnx_auditd_user_discovery.yml` in 2/2 captures
- `Sigma: proc_creation_lnx_system_network_connections_discovery.yml` in 2/2 captures
- `Sigma: lnx_auditd_web_rce.yml` in 2/2 captures
- `Sigma: lnx_auditd_dd_delete_file.yml` in 1/2 captures

The dominant failure is field erasure in the pre-Layer-2 raw-text projection. The generated regexes preserve Boolean structure but not which JSON field a literal belongs to.

## Method and limitations

- This is the existing raw-text detector/parser/regex approach; no canonical field extraction is used.
- The primary metric is sample-level exact ATT&CK-ID matching. A parent/sub-technique family diagnostic is included in JSON but is not used as the headline result.
- Each capture contains attack activity plus surrounding host telemetry. Predictions outside the metadata labels count as false positives, even when they may describe real secondary behavior present in the capture.
- This attack-only corpus cannot establish a benign-log false-positive rate; that requires the separate benign batch described in Card 5 Layer 3.
- A conservative mandatory-literal prefilter skips lines that cannot satisfy a regex, then the original Python regex decides every candidate. This changes performance, not matching semantics.
- The external fixture is not committed. The pinned LICENSE is MIT, while the pinned README contains a contradictory GPL-3.0 sentence.

## Case details

| Dataset | Tactic | Ground truth | Runtime predictions | Layer-1 predictions | Seconds |
|---|---|---|---|---|---:|
| SDLIN-201110081941 | defense_evasion | T1027.001 | — | T1027.001, T1033, T1049, T1485, T1505.003 | 0.028 |
| SDLIN-201110074812 | discovery | T1018 | — | T1018, T1033, T1049, T1505.003 | 0.005 |
