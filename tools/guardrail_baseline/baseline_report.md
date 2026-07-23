# Card 6 Part A step 1: current-guardrail baseline

Status: **MEASURED** (2026-07-17T09:45:16.749079+00:00)

No guardrail behavior was changed for this measurement. The harness calls the
production blacklist, cybersecurity fast-allow, and Ollama `llama3.1` classifier
in the same order as `guardrail()`.

## Headline results

| Measure | Blocked | Total | Rate |
| --- | ---: | ---: | ---: |
| Harmful prompts, source-weighted | 16 | 500 | 3.2% |
| Harmful prompts, exact-text deduplicated | 16 | 491 | 3.3% |
| JailbreakBench benign rejection | 1 | 100 | 1.0% |

JailbreakBench benign rejection is **not** treated as a product false-positive
rate: its benign split contains many general-domain requests that this
cybersecurity-only assistant intentionally rejects.

## Corpus results

| Corpus / split | Blocked | Total | Rate |
| --- | ---: | ---: | ---: |
| harmbench / harmful | 15 | 400 | 3.8% |
| jailbreakbench / benign | 1 | 100 | 1.0% |
| jailbreakbench / harmful | 1 | 100 | 1.0% |

## Layer and reliability observations

- Decision layers: `{"blacklist": 2, "cybersecurity_fast_allow": 51, "llm_classifier": 162, "llm_fail_open": 385}`
- Ollama classifier calls: **547**
- Classifier fail-open results: **385**
- Total measured guardrail time: **876.906s**
- LLM-call p50 / p95: **1.427s / 3.103s**

## Scope and provenance

- HarmBench input: all 400 canonical text behaviors. Contextual rows use
  HarmBench's own DirectRequest context/separator/behavior construction.
- JailbreakBench input: all 100 harmful and 100 benign `Goal` strings verbatim.
- Reports contain prompt hashes and benchmark identifiers, not prompt text.
- Source commits and file hashes are pinned in `source_manifest.json`.

This is a behavior-rejection baseline, not a guarantee of jailbreak robustness:
these files are direct-request behavior sets, not every generated adversarial
suffix or submitted jailbreak artifact supported by the full frameworks.
