# Threat Intel GraphRAG

Threat Intel GraphRAG is an AI-powered cybersecurity research assistant built
around the MITRE ATT&CK knowledge base.

The system helps users ask questions about threat actors, attack techniques,
tactics, tools, malware, campaigns, detections, mitigations, and security logs.

It combines graph-based threat intelligence with retrieval-augmented generation
so answers can be grounded in structured ATT&CK relationships instead of relying
only on a language model.

## Key capabilities

- Answers MITRE ATT&CK-focused questions
- Explains techniques, tactics, and related entities
- Retrieves supporting source nodes from a Neo4j knowledge graph
- Maps security log evidence to likely ATT&CK techniques
- Provides detections, mitigations, platforms, tools, and strongest evidence
- Presents results through an interactive web interface

## Purpose

The goal of this project is to make threat intelligence easier to explore,
validate, and explain by combining:

- a cybersecurity knowledge graph
- semantic retrieval
- graph relationship traversal
- reranking
- grounded answer generation
- deterministic log-analysis rules

MITRE ATT&CK is a registered trademark of The MITRE Corporation.
