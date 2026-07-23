# Security-Datasets baseline (Card 5, Part 1, step 5)

This harness measures the current raw-text detector/parser/regex approach on a
fixed, external 40-capture Windows corpus. It evaluates both the currently
imported 288 rules and the Layer-1 preview consisting of those rules plus the
approved Sigma and Falco generated candidates. It does not import the preview
rules into `backend/log_analysis/mappings.py` and does not use Layer 2 fields.

The capture ZIPs remain in a sparse checkout outside this repository. At the
pinned Security-Datasets commit, `LICENSE` contains MIT text while `README.md`
still says GPL-3.0, so this directory redistributes only paths and computed
results, never dataset content.

Run:

```bash
backend/venv/bin/python -u tools/security_datasets_baseline/evaluate.py \
  --datasets-root /path/to/OTRF/Security-Datasets \
  --workers 4

backend/venv/bin/python -m unittest discover \
  -s tools/security_datasets_baseline -v
```

The headline metric is sample-level micro precision/recall/F1 using strict
ATT&CK-ID equality. The JSON report also contains macro scores, a clearly
separated parent/sub-technique-family diagnostic, confidence buckets,
cumulative confidence thresholds, and per-tactic results.

The mandatory-literal prefilter exists only to make the unchanged regex
semantics tractable on large captures: it fails open when no safe literal can
be derived, and the original compiled Python regex still decides every
candidate line.
