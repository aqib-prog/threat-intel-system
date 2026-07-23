# Card 6 Part A step 3: defensive-vs-offensive-uplift harm gate

Status: **MEASURED** (2026-07-17T12:16:57.560885+00:00)

The topic prompt and step-1/2 routing are unchanged. The harm seam now has
a distinct taxonomy for operational offensive uplift.

## Step 2 / step 3

| Measure | Step 2 | Step 3 |
| --- | ---: | ---: |
| Harmful blocked (same 500) | 236/500 (47.2%) | 418/500 (83.6%) |
| Domain-benign blocked (same 64) | 0/64 (0.0%) | 0/64 (0.0%) |
| Topic fail-open / parse default | 0 / 0 | 0 / 0 |
| Harm fail-open / parse default | 0 / 0 | 0 / 0 |

## Harmful block rate by category

| Category | Step 2 | Step 3 | Blocked delta |
| --- | ---: | ---: | ---: |
| Disinformation | 4/10 (40.0%) | 10/10 (100.0%) | +6 |
| Economic harm | 7/10 (70.0%) | 10/10 (100.0%) | +3 |
| Expert advice | 8/10 (80.0%) | 9/10 (90.0%) | +1 |
| Fraud/Deception | 5/10 (50.0%) | 10/10 (100.0%) | +5 |
| Government decision-making | 3/10 (30.0%) | 10/10 (100.0%) | +7 |
| Harassment/Discrimination | 9/10 (90.0%) | 10/10 (100.0%) | +1 |
| Malware/Hacking | 1/10 (10.0%) | 10/10 (100.0%) | +9 |
| Physical harm | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| Privacy | 4/10 (40.0%) | 10/10 (100.0%) | +6 |
| Sexual/Adult content | 10/10 (100.0%) | 10/10 (100.0%) | +0 |
| chemical_biological | 39/56 (69.6%) | 55/56 (98.2%) | +16 |
| copyright | 13/100 (13.0%) | 32/100 (32.0%) | +19 |
| cybercrime_intrusion | 5/67 (7.5%) | 67/67 (100.0%) | +62 |
| harassment_bullying | 24/25 (96.0%) | 25/25 (100.0%) | +1 |
| harmful | 19/22 (86.4%) | 22/22 (100.0%) | +3 |
| illegal | 52/65 (80.0%) | 65/65 (100.0%) | +13 |
| misinformation_disinformation | 23/65 (35.4%) | 53/65 (81.5%) | +30 |

## Newly blocked domain-benign cases

None.

The three historical JBB-benign fast-allows remain routing probes only and
are excluded from both headline rates.
