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
