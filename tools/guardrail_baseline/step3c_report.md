# Card 6 Part A step 3c: copyright creative-reproduction harm gate

Status: **MEASURED** (2026-07-30T06:48:34.326215+00:00)

The topic gate, classifier split, structured output, fail-closed default,
and step-1/2 routing are unchanged. The harm gate now also blocks verbatim
reproduction of copyrighted creative works, with an explicit ALLOW carve-out
for factual/technical/openly-licensed reference material.

## Step 3b / step 3c

| Measure | Step 3b | Step 3c |
| --- | ---: | ---: |
| Harmful blocked (same 500) | 457/500 (91.4%) | 500/500 (100.0%) |
| Domain-benign blocked (same 64) | 0/64 (0.0%) | 0/64 (0.0%) |
| Reference-guard blocked (new 6) | n/a | 0/6 (0.0%) |

## Harmful block rate by category

| Category | Step 3b | Step 3c | Blocked delta |
| --- | ---: | ---: | ---: |
| Disinformation | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Economic harm | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Expert advice | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Fraud/Deception | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Government decision-making | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Harassment/Discrimination | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Malware/Hacking | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Physical harm | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Privacy | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Sexual/Adult content | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| chemical_biological | 56/56 (100.0%) | 56/56 (100.0%) | +0 |
| copyright | 58/100 (58.0%) | 100/100 (100.0%) | +42 |
| cybercrime_intrusion | 67/67 (100.0%) | 67/67 (100.0%) | +0 |
| harassment_bullying | 25/25 (100.0%) | 25/25 (100.0%) | +0 |
| harmful | 22/22 (100.0%) | 22/22 (100.0%) | +0 |
| illegal | 65/65 (100.0%) | 65/65 (100.0%) | +0 |
| misinformation_disinformation | 64/65 (98.5%) | 65/65 (100.0%) | +1 |

## Reference-guard cohort (must stay fully allowed)

Legitimate MITRE/CVE/NIST reproduction requests that guard against the
copyright rule over-blocking core threat-intelligence work.

All 6 reference-guard cases allowed. No over-block.

## Newly blocked domain-benign cases

None.
