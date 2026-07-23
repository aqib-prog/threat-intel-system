# RAG Accuracy — Step 8a local Ragas prototype

- Cases: 15
- Judge: `ChatOllama/llama3.1:latest`
- Embeddings: `OllamaEmbeddings/nomic-embed-text:latest`
- OPENAI_API_KEY present: `False`
- OpenAI host attempted: `False`
- Blocked external hosts: `[]`

## Independently derived aggregate scores

| Metric | Mean | Scored |
|---|---:|---:|
| faithfulness | 0.7390 | 15/15 |
| context_precision | 0.9974 | 15/15 |
| context_recall | 0.8400 | 15/15 |

## Per-case raw scores

| Relationship | Case | Faithfulness | Context precision | Context recall | Sources |
|---|---|---:|---:|---:|---:|
| technique_mitigation | enterprise-mitigations-t1078 | 0.6000 | 1.0000 | 1.0000 | 1 |
| technique_mitigation | enterprise-mitigations-t1053 | 1.0000 | 1.0000 | 1.0000 | 1 |
| technique_tactic | enterprise-tactics-t1053 | 0.6471 | 1.0000 | 1.0000 | 1 |
| technique_tactic | enterprise-tactics-t1001 | 1.0000 | 1.0000 | 1.0000 | 1 |
| group_technique | group-uses-techniques-g0002 | 1.0000 | 1.0000 | 0.5000 | 1 |
| group_technique | group-uses-techniques-g0003 | 0.6000 | 1.0000 | 0.6000 | 1 |
| software_technique | software-uses-techniques-s0002 | 0.4706 | 1.0000 | 1.0000 | 8 |
| software_technique | software-uses-techniques-s0003 | 0.5000 | 0.9617 | 1.0000 | 8 |
| group_software | group-uses-software-g0002 | 1.0000 | 1.0000 | 1.0000 | 1 |
| group_software | group-uses-software-g0003 | 0.6667 | 1.0000 | 0.5000 | 1 |
| technique_detection_strategy | technique-detection-strategy-t1078 | 1.0000 | 1.0000 | 0.5000 | 1 |
| technique_detection_strategy | technique-detection-components-t1059.001 | 0.3333 | 1.0000 | 1.0000 | 1 |
| campaign_group | campaign-attributed-groups-c0011 | 0.8000 | 1.0000 | 0.5000 | 1 |
| campaign_group | campaign-attributed-groups-c0052 | 0.8000 | 1.0000 | 1.0000 | 1 |
| campaign_group | campaign-has-no-attributed-group-c0001 | 0.6667 | 1.0000 | 1.0000 | 1 |

Contexts come directly from `PipelineResult.retrieved_contexts`, using the same `generation.generate.format_context()` field serialization as the production answer path, one context document per retrieved node.
