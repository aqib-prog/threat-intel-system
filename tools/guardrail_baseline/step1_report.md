# Card 6 Part A step 1: topic/harm structural separation

Status: **MEASURED** (2026-07-17T10:57:17.614754+00:00)

Step 1 changes routing only. The provisional harm seam intentionally uses
the unchanged topic-oriented classifier taxonomy; JSON-mode, fail-closed
behavior, and the real harm taxonomy remain later checkpoints.

## Before / after

| Measure | Before | After |
| --- | ---: | ---: |
| Harmful blocked (same 500) | 16/500 (3.2%) | 17/500 (3.4%) |
| Domain-benign blocked (same 64) | 0/64 (0.0%) | 0/64 (0.0%) |
| Historical cybersecurity fast-allows reaching harm seam | 0/51 | 51/51 |

## Routing and reliability observations

- Topic LLM calls: **468**; fail-open: **338**.
- Harm-seam calls: **551**; fail-open: **390**.
- Historical fast-allow probes replayed: **51**; blocked by provisional seam: **1**.
- Total evaluation time: **1661.940s**; p50/p95 per case: **2.950s / 4.427s**.

The three historical JBB-benign fast-allows are routing probes only. They
are excluded from both the 500-case harmful catch rate and the 64-case
domain-specific benign block rate.
