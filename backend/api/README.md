# Threat Intel GraphRAG API

FastAPI REST API for the full retrieval + generation pipeline.

## Run locally

```bash
cd backend
cp .env.example .env
venv/bin/pip install -r requirements-api.txt
venv/bin/uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload
```

## Endpoints

- `GET /health` — API + Neo4j health.
- `GET /stats` — live node/relationship/tactic counts from Neo4j (cached in-process
  for `STATS_CACHE_SECONDS`). Powers the frontend landing page - never hardcode
  these numbers client-side.
- `GET /filters?query=...` — supported filters and active filters for an optional query.
- `POST /query` — runs the full pipeline and returns answer, filters, source nodes, and counts.
  `relevance_score` on returned nodes is on a `[0, 10]` scale (see
  `retrieval/reranker.py`'s `clipped_score`), not 0-1.

Example:

```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"query":"Tell me about T1078","top_k":8,"candidate_k":30}'
```

## Security

- **CORS** fails closed: an unset `CORS_ORIGINS` blocks all cross-origin browser
  requests rather than allowing every origin. Set it explicitly per environment.
- **Rate limiting** (`backend/security/rate_limit.py`) is per-client-IP on
  `/query`, `/filters`, and `/stats` (`RATE_LIMIT_*` env vars). The default
  in-memory store only rate-limits correctly with a single worker process -
  set `RATE_LIMIT_STORAGE_URI` (e.g. a Redis URL) before running multiple
  workers or instances.
- **API key auth** (`backend/security/auth.py`) gates `/query` and `/filters`
  via a required `X-API-Key` header, checked with a constant-time comparison.
  Set via `API_KEYS` (comma-separated for multiple/rotation). **This is a
  single-shared-secret scheme, not per-user auth** - a key baked into the
  frontend build (`VITE_API_KEY`) is visible to anyone who inspects that
  frontend's network requests or JS bundle. It stops anonymous internet
  scanners and casual abuse of a discovered API URL; it does **not** stop a
  determined user of your own frontend from extracting the key and calling
  the API directly. For real per-user access control, put a session/JWT auth
  provider in front of this instead. Unset `API_KEYS` disables auth entirely
  (fine for local dev only) - `GET /health`'s `auth` field reports
  `"MISCONFIGURED"` if staging/production is running without a key set.
- **Error responses are sanitized** (`backend/security/errors.py`): internal
  exception detail (Neo4j connection errors, LLM provider errors) is logged
  server-side only, never returned to the client.
- Neo4j should never be directly internet-reachable - only this API should
  have network access to it. The local dev password in `backend/.env`
  (`password123`) is a placeholder; use a strong, unique secret in any shared
  or production environment.

## Environment portability

All deployment-specific settings are environment variables. Use `.env.example`
as the template for local, staging, and production `.env` files. Do not commit
real secrets.

