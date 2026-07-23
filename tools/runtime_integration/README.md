# Card 5 runtime integration checkpoints

This directory promotes reviewed offline compiler output into dependency-free
runtime bundles, one platform at a time. A bundle is generated only from the
approved `mapping_candidate` partition; `needs_review` rows fail the build if
they overlap the runtime input.

## Windows checkpoint

Rebuild the deterministic gzip/JSON bundle:

```bash
backend/venv/bin/python tools/runtime_integration/build_windows.py
```

The runtime replaces 60 exact legacy overlaps rather than retaining both raw
and structured copies. The resulting Windows inventory is 1,682 rules: 1,587
field-authoritative structured rules and 95 raw-only rules (84 untouched legacy
rules plus 11 reviewed candidates whose structured projection failed closed).

Re-run the controlled same-process benchmark:

```bash
backend/venv/bin/python tools/regression/benchmark_log_analysis.py \
  --variant compare --repetitions 9 --warmups 2 \
  --output tools/runtime_integration/windows_performance_report.json
```

On the recorded Apple arm64 / Python 3.13.11 run, median end-to-end latency
improved by 8.56–8.82% across 10, 50, and 250 complete Windows JSON events.
The largest input is 97,225 bytes, below the API's 100,000-character limit.
At that size, raw regex evaluations fell from 36,000 to 23,750 while 396,750
field-aware evaluations supplied the expanded coverage.

The report is a measured checkpoint, not a cross-machine latency threshold.
Correctness and deterministic evaluation counts are enforced by the permanent
regression suite; repeat timings on the deployment class before changing a
performance budget.

## Linux checkpoint

Rebuild the Linux bundle:

```bash
backend/venv/bin/python tools/runtime_integration/build_linux.py
```

The runtime replaces 20 exact legacy overlaps. The resulting Linux inventory
is 189 rules: 131 field-aware structured rules and 58 raw evaluations (34
untouched legacy rules plus 24 reviewed candidates whose structured projection
failed closed).

The Linux benchmark uses grouped auditd `SYSCALL`/`EXECVE`/`CWD` records and
one genuine `arp -a` positive per scenario:

```bash
backend/venv/bin/python tools/regression/benchmark_log_analysis.py \
  --platform linux --variant compare --repetitions 9 --warmups 2 \
  --output tools/runtime_integration/linux_performance_report.json
```

On the recorded Apple arm64 / Python 3.13.11 run, median end-to-end latency
improved by 18.45–19.63% across 10, 50, and 250 events. The 250-event input is
87,205 bytes. Raw evaluations rise from 13,500 to 21,000 because structured
rules whose required fields are absent retain conservative raw fallback; the
additional 26,250 field-aware evaluations are cheap enough that median latency
still falls from 860.3 ms to 691.4 ms and p95 falls from 883.4 ms to 712.9 ms.

## macOS checkpoint

Rebuild the macOS bundle:

```bash
backend/venv/bin/python tools/runtime_integration/build_macos.py
```

The runtime replaces 12 exact legacy overlaps. The resulting macOS inventory
is 67 rules: all 47 reviewed Sigma candidates use field-authoritative
structured matching, while the remaining 20 untouched legacy rules stay raw.
No reviewed macOS candidate requires raw fallback.

The macOS benchmark uses complete Elastic ECS process events, matching the
schema of the pinned sbousseaden/macOS-ATTACK-DATASET corpus, with one genuine
`/usr/bin/base64 -d` positive per scenario:

```bash
backend/venv/bin/python tools/regression/benchmark_log_analysis.py \
  --platform macos --variant compare --repetitions 9 --warmups 2 \
  --output tools/runtime_integration/macos_performance_report.json
```

On the recorded Apple arm64 / Python 3.13.11 run, median end-to-end latency
improved by 20.65–20.87%. The 250-event input is 74,758 bytes. Raw regex
evaluations fall from 8,000 to 5,000 while 11,750 structured evaluations add
coverage; median latency falls from 267.1 ms to 211.3 ms and p95 falls from
279.3 ms to 212.3 ms.
