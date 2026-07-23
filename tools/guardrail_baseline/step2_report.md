# Card 6 Part A step 2: structured output and fail-closed parsing

Status: **MEASURED** (2026-07-17T11:32:09.999408+00:00)

The classifier prompt/taxonomy and step-1 routing are unchanged. This
checkpoint changes only Ollama output framing and the parse-failure default.

## Step 1 / step 2

| Measure | Step 1 | Step 2 |
| --- | ---: | ---: |
| Topic fail-open | 338 | 0 |
| Harm-seam fail-open | 390 | 0 |
| Harmful blocked (same 500) | 17/500 (3.4%) | 236/500 (47.2%) |
| Domain-benign blocked (same 64) | 0/64 (0.0%) | 0/64 (0.0%) |

## Parse reliability

- Topic LLM calls: **468**; fail-open: **0**; fail-closed parse defaults: **0**.
- Harm-seam calls: **343**; fail-open: **0**; fail-closed parse defaults: **0**.
- Historical fast-allow probes reaching the harm seam: **51/51**.
- Total evaluation time: **1297.470s**; p50/p95 per case: **2.121s / 4.347s**.

The three historical JBB-benign fast-allows remain routing probes only and
are excluded from both headline rates.
