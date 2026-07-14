# Backend

The backend powers the intelligence workflow for Threat Intel GraphRAG.

It receives questions from the frontend, retrieves relevant threat intelligence
from the knowledge graph, expands related context, ranks the results, and
generates grounded answers.

## What it provides

- MITRE ATT&CK question answering
- Guardrails for unsupported requests
- Entity and filter extraction
- Semantic search
- Graph relationship traversal
- Reranking for better context
- Grounded response generation
- Security-log analysis and ATT&CK technique mapping
- API responses for the frontend

## Role in the project

The backend connects the knowledge graph, retrieval pipeline, log-analysis
rules, and generation layer into one service used by the web interface.
