# Falco offline compiler (Card 5, Part 1, steps 3–4)

This directory contains the five-rule parser prototype from step 3 and the
review-only 70-rule compilation and manual ATT&CK mapping pass from step 4.
Neither command modifies `backend/log_analysis/mappings.py`.

## Reproduce

Use a checkout containing these two files:

- `plugins/k8saudit/rules/k8s_audit_rules.yaml`
- `plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml`

Then run:

```bash
backend/venv/bin/pip install -r tools/falco_compiler/requirements.txt
backend/venv/bin/python tools/falco_compiler/prototype.py \
  --falco-root /path/to/falcosecurity/plugins

backend/venv/bin/python tools/falco_compiler/full_recompile.py \
  --falco-root /path/to/falcosecurity/plugins \
  --techniques backend/data/parsed/techniques.json \
  --relationships backend/data/parsed/relationships.json

FALCO_ROOT=/path/to/falcosecurity/plugins \
  backend/venv/bin/python -m unittest discover -s tools/falco_compiler -v
```

The parser uses a recursive-descent boolean grammar and expands source macros
and lists before projecting supported field predicates onto raw JSON regexes.
Unknown syntax, fields, macros, operators, and cycles fail closed.

The sample covers:

- macro and nested-list expansion;
- `and`, `or`, `not`, and parentheses;
- `=`, `!=`, `exists`, `in`, `intersects`, and `startswith`;
- trusted-image exceptions with Falco's set-containment semantics;
- case-sensitive Falco literals inside the current runtime's case-insensitive
  regex wrapper.

Step 4 accounts for all 48 Kubernetes and 22 CloudTrail rules. Rules disabled
by Falco source configuration retain compiled output but never become runtime
candidates. Ambiguous or low-confidence ATT&CK mappings remain review items.

Step-4 review artifacts:

- `full_mapping_table.md`: the complete 70-row Falco → ATT&CK decision table;
- `full_recompile_report.json`: conditions, expanded trees, regexes, mapping
  metadata, validation results, and Sigma+Falco coverage deltas;
- `full_rule_specs.py`: the conservative `MappingRule` candidates as pure
  generated data; it is not imported by the runtime.
- `medium_fit_mitre_audit.md`: the direct official-MITRE-page cross-check of
  the 14 medium-fit rows, including three rejected candidates and the explicit
  limitations on the 11 retained candidates.

These files are the step-4 review boundary. Step 5 does not begin until the
mapping table is approved.
