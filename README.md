# Threat Intel GraphRAG

Threat Intel GraphRAG is a MITRE ATT&CK-focused retrieval and generation system.
It uses Neo4j as the knowledge graph, embedding search for semantic retrieval,
graph traversal for relationship expansion, reranking for accuracy, and a
FastAPI + React interface for querying the system.

## Current architecture

```text
user query
  -> guardrail
  -> filter/entity extraction
  -> semantic search
  -> graph traversal
  -> reranker
  -> grounded generation
  -> API response
  -> frontend visualization
```

The backend also has deterministic telemetry/log handling for common security
signals. The long-term direction is a dedicated `log_analysis` branch that
parses raw telemetry, maps evidence to ATT&CK techniques, then fetches exact
Neo4j context.

## Main components

- `backend/ingestion/` — MITRE graph loading, contextualization, embedding, and indexes.
- `backend/retrieval/` — guardrails, semantic search, graph traversal, and reranking.
- `backend/generation/` — grounded response generation and structured summaries.
- `backend/orchestration/` — end-to-end pipeline wiring.
- `backend/api/` — FastAPI REST API.
- `backend/security/` — API key auth, rate limiting, security headers, sanitized errors.
- `frontend/` — Vite/React threat-intel UI with graph stats, chat, source views, and visual sections.

## Backend setup

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements-api.txt
pip install -r requirements-reranker.txt
cp .env.example .env
```

Start Neo4j and Ollama locally, then run:

```bash
uvicorn api.app:app --reload --host 127.0.0.1 --port 8000
```

Useful endpoints:

- `GET /health`
- `GET /stats`
- `GET /filters`
- `POST /query`

See [backend/api/README.md](backend/api/README.md) for endpoint and security details.

## Frontend setup

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

By default the frontend calls:

```text
http://localhost:8000
```

Set `VITE_API_BASE` and `VITE_API_KEY` in `frontend/.env` when needed.

See [frontend/README.md](frontend/README.md) for frontend details.

## Environment files

Use the example files as templates:

- `backend/.env.example`
- `backend/.env.development.example`
- `backend/.env.staging.example`
- `backend/.env.production.example`
- `frontend/.env.example`
- `frontend/.env.staging.example`
- `frontend/.env.production.example`

Real `.env` files are ignored by git.

## Validation

Backend syntax check:

```bash
cd backend
venv/bin/python -m py_compile api/app.py orchestration/pipeline.py generation/generate.py
```

Frontend checks:

```bash
cd frontend
npm run build
npm run lint
```

Git whitespace check:

```bash
git diff --check
```


