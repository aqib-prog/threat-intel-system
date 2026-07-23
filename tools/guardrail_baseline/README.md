# Card 6 guardrail baseline

This is the Part A step-1 measurement harness. It calls the unchanged
production guardrail layers against pinned HarmBench and JailbreakBench
behavior sets and writes aggregate reports without redistributing prompt text.

```bash
HARMBENCH_ROOT=$HOME/.cache/threat-intel-guardrail-datasets/harmbench \
JAILBREAKBENCH_ROOT=$HOME/.cache/threat-intel-guardrail-datasets/jailbreakbench \
JBB_BEHAVIORS_ROOT=$HOME/.cache/threat-intel-guardrail-datasets/jbb-behaviors \
backend/venv/bin/python tools/guardrail_baseline/test_evaluate.py -v

backend/venv/bin/python tools/guardrail_baseline/evaluate.py \
  --harmbench-root $HOME/.cache/threat-intel-guardrail-datasets/harmbench \
  --jailbreakbench-root $HOME/.cache/threat-intel-guardrail-datasets/jailbreakbench \
  --jbb-behaviors-root $HOME/.cache/threat-intel-guardrail-datasets/jbb-behaviors
```

The evaluation is sequential because it measures the same local Ollama
`llama3.1` classifier used by production. A partial JSON checkpoint is written
every ten cases and removed only after the final reports are complete.

## Step 1: topic/harm separation

`domain_benign_set.json` contains 64 balanced, reviewable defensive-security
questions. The pre-step-1 result is recorded in
`domain_benign_before_step1.json`; it must remain separate from JBB's generic
benign split.

Run the structural checkpoint with:

```bash
backend/venv/bin/python tools/guardrail_baseline/test_step1_flow.py -v
backend/venv/bin/python tools/guardrail_baseline/test_step1_evaluate.py -v

backend/venv/bin/python -u tools/guardrail_baseline/evaluate_step1.py \
  --harmbench-root $HOME/.cache/threat-intel-guardrail-datasets/harmbench \
  --jailbreakbench-root $HOME/.cache/threat-intel-guardrail-datasets/jailbreakbench \
  --jbb-behaviors-root $HOME/.cache/threat-intel-guardrail-datasets/jbb-behaviors
```

The step-1 evaluator replays the same 500 harmful prompts, all 64 domain-benign
questions, and three JBB-benign routing probes needed to account for every one
of the historical 51 cybersecurity fast-allows. The probes are excluded from
both headline rates.

## Step 2: structured output and fail-closed parsing

Run the reliability checkpoint against the identical cohorts with:

```bash
backend/venv/bin/python tools/guardrail_baseline/test_step2_reliability.py -v
backend/venv/bin/python tools/guardrail_baseline/test_step2_evaluate.py -v

backend/venv/bin/python -u tools/guardrail_baseline/evaluate_step2.py \
  --harmbench-root $HOME/.cache/threat-intel-guardrail-datasets/harmbench \
  --jailbreakbench-root $HOME/.cache/threat-intel-guardrail-datasets/jailbreakbench \
  --jbb-behaviors-root $HOME/.cache/threat-intel-guardrail-datasets/jbb-behaviors
```

`step2_report.json` and `step2_report.md` compare against the immutable step-1
report. In addition to fail-open counts, they record fail-closed parse defaults
separately so JSON framing cannot appear reliable merely because parsing errors
now block instead of allow.

## Step 3: defensive-vs-offensive-uplift harm gate

Run the classifier-split and taxonomy checkpoint with:

```bash
backend/venv/bin/python tools/guardrail_baseline/test_step3_taxonomy.py -v
backend/venv/bin/python tools/guardrail_baseline/test_step3_evaluate.py -v

backend/venv/bin/python -u tools/guardrail_baseline/evaluate_step3.py \
  --harmbench-root $HOME/.cache/threat-intel-guardrail-datasets/harmbench \
  --jailbreakbench-root $HOME/.cache/threat-intel-guardrail-datasets/jailbreakbench \
  --jbb-behaviors-root $HOME/.cache/threat-intel-guardrail-datasets/jbb-behaviors
```

The report compares all harmful categories with step 2 and lists each newly
blocked domain-benign case by review ID, category, gate, and classifier reason.
It never retains classifier reasons for external harmful cases, because a model
could echo source prompt text into that field.
