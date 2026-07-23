# Linux structured-field pilot (Card 5, Part 1, step 8)

The offline compiler reloads the approved Linux candidates from the pinned
Sigma checkout and serializes pySigma's field-aware condition trees as plain
Python data. The running application does not depend on pySigma.

Linux auditd lines sharing one `msg=audit(...)` identifier are grouped into a
single event. Native audit fields (`type`, `a0`...`a7`, `exe`, `comm`,
`name`) are retained, while `Image`, `CommandLine`, and `TargetFilename` aliases
are populated only from those extracted values. A structured predicate becomes
authoritative once its complete positive field branch is present; otherwise the
group retains per-rule raw fallback.

The pinned Security-Datasets revision contains only two labeled Linux host
captures. Both are used; their paths and computed results are committed, but
the captures remain in the external sparse checkout.

```bash
env SIGMA_ROOT=/private/tmp/card5-sigma \
  backend/venv/bin/python tools/linux_structured/compiler.py \
  --sigma-root /private/tmp/card5-sigma

backend/venv/bin/python -u tools/security_datasets_baseline/evaluate.py \
  --datasets-root /private/tmp/card5-security-datasets \
  --manifest tools/linux_structured/corpus_manifest.json \
  --structured-specs tools/linux_structured/linux_structured_rule_specs.py \
  --comparison-baseline-report tools/linux_structured/baseline_report.json \
  --report-json tools/linux_structured/step8_linux_report.json \
  --report-md tools/linux_structured/step8_linux_report.md
```
