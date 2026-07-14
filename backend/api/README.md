# Backend API

The backend API powers the Threat Intel GraphRAG assistant.

It receives user questions, runs the retrieval and generation pipeline, and
returns grounded answers with source nodes from the threat intelligence graph.

## What it provides

- Question answering over MITRE ATT&CK data
- Guardrails for irrelevant or unsupported requests
- Entity and filter extraction
- Semantic retrieval and graph traversal
- Reranking for more relevant context
- Grounded answer generation
- Security-log analysis and ATT&CK mapping
- API responses for the frontend

## Role in the project

The backend is responsible for the core intelligence workflow. It connects the
knowledge graph, retrieval logic, log-analysis rules, and response generation
into one API that the frontend can use.
