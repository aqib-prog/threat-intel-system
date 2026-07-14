# Frontend

The frontend is the web interface for Threat Intel GraphRAG.

It allows users to ask cybersecurity questions, review AI-generated answers,
inspect source nodes, and view visual breakdowns of the retrieved threat
intelligence.

## What it provides

- Chat interface for threat intelligence questions
- Visual category breakdowns for answers
- Source cards showing where the answer came from
- MITRE ATT&CK ID highlighting
- Security-log analysis display
- Clean session behavior for browser refreshes

## Role in the project

The frontend is focused on presenting the intelligence clearly. It does not
store secrets or perform the core retrieval logic. Questions are sent to the
backend API, and the frontend displays the returned answer, sources, and
visual context.
