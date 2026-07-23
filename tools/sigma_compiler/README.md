# pySigma offline compiler (Card 5, Part 1, steps 1–2)

This directory contains the checkpoint-gated pySigma work for:

- step 1: compile 10–20 selected Windows rules and validate them against
  pinned Security-Datasets captures;
- step 2: compile the targeted Windows, Linux, macOS, and AWS CloudTrail rule
  trees from one pinned Sigma commit.

Both commands produce review artifacts without changing
`backend/log_analysis/mappings.py`.

## Reproduce

Use an external checkout of SigmaHQ/sigma and, optionally, OTRF/Security-Datasets:

```bash
backend/venv/bin/pip install -r tools/sigma_compiler/requirements.txt
backend/venv/bin/python tools/sigma_compiler/prototype.py \
  --sigma-root /path/to/SigmaHQ/sigma \
  --techniques backend/data/parsed/techniques.json \
  --security-datasets-root /path/to/OTRF/Security-Datasets \
  --report tools/sigma_compiler/prototype_report.json

backend/venv/bin/python tools/sigma_compiler/full_recompile.py \
  --sigma-root /path/to/SigmaHQ/sigma \
  --sigma-commit 65b39fa48afc2739ed01df03ef61c68be995bb36 \
  --techniques backend/data/parsed/techniques.json \
  --relationships backend/data/parsed/relationships.json

SIGMA_ROOT=/path/to/SigmaHQ/sigma \
SECURITY_DATASETS_ROOT=/path/to/OTRF/Security-Datasets \
  backend/venv/bin/python -m unittest discover -s tools/sigma_compiler -v
```

The compiler reads pySigma's parsed condition tree. It projects each leaf onto
the existing raw-full-event matching model, then composes boolean predicates as
anchored lookaheads. Field identity is intentionally not claimed here: Layer 2
of Card 5 is the structured-field work. Unsupported pySigma value types fail
closed instead of being approximated silently.

Technique-tag policy:

- one ATT&CK technique tag: emit a mapping candidate;
- a parent plus exactly one of its sub-techniques: drop the parent and emit the
  more specific sub-technique, recording the automatic resolution;
- any genuinely multi-technique rule: compile its regex, but withhold it from
  mapping candidates and place it in `needs_review`;
- no ATT&CK technique tag: likewise place it in `needs_review`.

Each report is a review boundary; the following roadmap step must not start
until the current checkpoint is approved.

Step 2 emits two additional review artifacts:

- `full_recompile_report.json`: complete input inventory, semantic diff against
  the current generated Sigma sections, mapping candidates, and every withheld
  rule with its review reason;
- `full_recompile_rule_specs.py`: pure generated data that proves every
  candidate can be constructed in the current `MappingRule` format. It is not
  imported by the runtime.

Projection deliberately fails closed for null, CIDR, field-reference, and
empty/all-wildcard predicates because flattening those into raw-text regexes
would change their field-aware semantics. Those rules remain reviewable in the
report rather than being discarded.
