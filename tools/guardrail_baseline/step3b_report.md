# Card 6 Part A step 3b: general-harm harm gate

Status: **MEASURED** (2026-07-17T13:50:16.953741+00:00)

The topic prompt, classifier split, structured output, fail-closed
default, and step-1/2 routing are all unchanged. Only the harm gate's
BLOCK taxonomy is widened to cover clearly-harmful non-cyber content.

## Step 3 / step 3b

| Measure | Step 3 | Step 3b |
| --- | ---: | ---: |
| Harmful blocked (same 500) | 418/500 (83.6%) | 457/500 (91.4%) |
| Domain-benign blocked (same 64) | 0/64 (0.0%) | 0/64 (0.0%) |
| Topic fail-open / parse default | 0 / 0 | 0 / 0 |
| Harm fail-open / parse default | 0 / 0 | 0 / 0 |

## Harmful block rate by category

| Category | Step 3 | Step 3b | Blocked delta |
| --- | ---: | ---: | ---: |
| Disinformation | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Economic harm | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Expert advice | 9/10 (90.0%) | 10/10 (100.0%) | +1 |
| Fraud/Deception | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Government decision-making | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Harassment/Discrimination | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Malware/Hacking | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Physical harm | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Privacy | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Sexual/Adult content | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| chemical_biological | 55/56 (98.2%) | 56/56 (100.0%) | +1 |
| copyright | 32/100 (32.0%) | 58/100 (58.0%) | +26 |
| cybercrime_intrusion | 67/67 (100.0%) | 67/67 (100.0%) | +0 |
| harassment_bullying | 25/25 (100.0%) | 25/25 (100.0%) | +0 |
| harmful | 22/22 (100.0%) | 22/22 (100.0%) | +0 |
| illegal | 65/65 (100.0%) | 65/65 (100.0%) | +0 |
| misinformation_disinformation | 53/65 (81.5%) | 64/65 (98.5%) | +11 |

## Newly blocked domain-benign cases

None.

The three historical JBB-benign fast-allows remain routing probes only
and are excluded from both headline rates.
