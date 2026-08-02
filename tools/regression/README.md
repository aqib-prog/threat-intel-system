# Card 5 Layer-4 regression gate

This is the permanent regression entry point for the log-analysis compiler,
mapping, parser, hybrid matching, and measured precision artifacts.

The offline gate needs no external fixtures:

```bash
backend/venv/bin/python tools/regression/run.py --mode artifacts
```

The full gate is the CI authority. It requires four clean checkouts at the
pinned commits and fails if any required environment variable is absent, any
checkout is dirty, generated compiler output changes, corpus membership
changes, detector routing changes, prediction sets change, or the measured
Windows/Linux/macOS precision reports stop reproducing.

The Windows and Linux baseline JSON files are deliberately frozen pre-extractor
measurements; full mode reproduces the current structured reports against those
immutable fixtures. The macOS baseline is reproducible because its corpus
adapter and corrected schema routing predate both macOS measurements.

```bash
export SIGMA_ROOT=/private/tmp/card5-sigma
export FALCO_ROOT=/private/tmp/card5-falco-plugins
export SECURITY_DATASETS_ROOT=/private/tmp/card5-security-datasets
export MACOS_ATTACK_DATASET_ROOT=/private/tmp/card5-macos-attack-dataset
backend/venv/bin/python tools/regression/run.py --mode full
```

Full mode defaults to four evaluation workers. Set
`CARD5_REGRESSION_WORKERS=1` only when diagnosing ordering or platform-specific
process-pool limitations; prediction and operation-count comparisons remain
deterministic across worker counts.

External telemetry stays outside the repository. Kubernetes has no labeled
corpus gate and remains raw-regex-only; Falco parser/compiler semantics and its
reviewed mapping artifacts are still covered by synthetic and pinned-source
tests.

## Runtime integration benchmark

Each platform promotion is measured against deterministic platform telemetry
in the same process. For the Windows checkpoint:

```bash
backend/venv/bin/python tools/regression/benchmark_log_analysis.py \
  --variant compare --repetitions 9 --warmups 2
```

The largest scenario is 250 complete Sysmon-style JSON events (under the API's
100,000-character paste limit). The report separates raw regex searches from
field-authoritative structured evaluations and reports median/p95 parse,
analysis, and end-to-end latency for both the legacy and integrated rule sets.

Select `--platform linux` to benchmark grouped auditd records with the same
10/50/250-event, nine-repetition protocol.

Select `--platform macos` to benchmark complete Elastic ECS process records
with that same protocol.

## Backend behavior tests

Do not use one repository-wide `unittest discover` invocation as the authority:
several backend test directories are intentionally not Python packages and
would be silently skipped. This runner loads every `test*.py` file by path and
prints every test result:

```bash
backend/venv/bin/python tools/regression/run_backend_behavior_tests.py \
  --list-files
```

## Comprehensive live production suite

The live suite calls the running `/query` API and exercises Ollama, Neo4j,
guardrails, retrieval, generation, orchestration, citation grounding, raw-log
analysis, and the exact response contract consumed by the frontend. Its 270
cases comprise:

- 156 independently verified golden questions across all 13 relationship
  types (52 original, 52 typo, and 52 reworded);
- 24 multi-intent, noise, invalid-input, and raw-log scenarios;
- 20 adversarial mixed-log and frontend-contract scenarios;
- 64 defensive cybersecurity questions and 6 technical-reference requests
  that must remain allowed.

For golden answers, the report distinguishes missing expected ATT&CK IDs,
unexpected IDs, ungrounded/possibly fabricated IDs, missing entity names,
negative-polarity drift, missing sources, routing failures, and response-schema
failures. Complete API responses and provenance are retained in JSON; a shorter
failure review is written to Markdown. Both artifacts are atomically
checkpointed after every request. The terminal shows a progress bar with
PASS/FAIL/ERROR counts, elapsed time, and ETA.

A resumed run first revalidates every saved raw response using the current
validator, then reuses completed PASS and validation-FAIL cases. Interrupted
ERROR and pending cases rerun. Use `--rerun-failures` with `--resume` after a
product fix when prior validation failures should also be queried again.
Transient HTTP 429/500/502/503/504, connection, and timeout failures retry with
backoff. If infrastructure remains unavailable, the suite stops after
checkpointing instead of converting all remaining cases into errors.

```bash
backend/venv/bin/python tools/regression/run_live_production_suite.py \
  --api-base http://localhost:8000 \
  --report /tmp/live-production-suite-report.json \
  --markdown-report /tmp/live-production-suite-report.md
```

If interrupted, rerun the same command with `--resume`. The API's configured
rate limit remains active; the runner respects HTTP 429 `Retry-After` responses
instead of bypassing production behavior.

## Targeted repeatability suite

This smaller live gate runs three Malware-to-Technique phrasings three times
each, then repeats a comprehensive mixed turn that combines authoritative
GraphRAG facts, did-you-mean, off-topic handling, a harmful segment, and a
Sysmon event containing instruction-like telemetry data. Six additional
profile scenarios cover interrogative/copula/auxiliary typo combinations
across APT29, FIN7, Lazarus Group, and Sandworm Team. Their validators require
the complete deterministic profile shape, frontend subsections, grounding,
and clean Markdown (no leaked ``**`` markers or operating-system misrouting).
The suite also follows the returned did-you-mean action and repeats the
corrected query three times.

The comparison includes answers, cards, sources, grounding, filters,
suggestions/actions, and answer presentation. Only `latency_ms` is excluded.

```bash
LANGFUSE_ENABLED=false backend/venv/bin/python \
  tools/regression/run_repeatability_suite.py \
  --api-base http://localhost:8000 \
  --repeats 3 \
  --report /tmp/live-repeatability-suite-report.json
```

For the pre-production stability matrix, use `--profile production`. It repeats
118 non-duplicative scenarios three times: all 52 original semantic golden
cases, every mixed-log contract, every routable multi-intent case, a balanced
defensive/reference guardrail sample, the extra Malware phrasings, and the
comprehensive mixed turn plus the six typo/profile/Markdown scenarios. The
emitted did-you-mean action is also executed three times, for 357 live requests
in total.

```bash
LANGFUSE_ENABLED=false backend/venv/bin/python -u \
  tools/regression/run_repeatability_suite.py \
  --profile production \
  --api-base http://localhost:8000 \
  --repeats 3 \
  --report /tmp/live-repeatability-production-report.json
```

The report is atomically checkpointed after every live response. If the
backend, Ollama, Neo4j, or the terminal is interrupted, rerun the identical
command with `--resume`; completed repetitions are revalidated and reused.
