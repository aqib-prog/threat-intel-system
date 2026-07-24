# Langfuse — local, self-hosted LLM observability

Traces every `/query` request through the RAG pipeline so you can see, per
request: the input, the final answer, whether it was answered or **blocked**
(and by which guardrail), how many nodes were retrieved, latency, and — on a
pipeline error — exactly **which stage failed**. Everything runs on
`localhost`; no data leaves the machine (consistent with the project's
loopback-only stance).

## Prerequisites

- A Docker runtime. This project uses **OrbStack** (its `docker` CLI lives at
  `~/.orbstack/bin/docker`). Plain `docker` works too if it's on your PATH.

## Start / stop the stack

```bash
cd tools/langfuse
~/.orbstack/bin/docker compose up -d      # start (first run pulls ~2-3 GB)
~/.orbstack/bin/docker compose ps         # check 6 services are healthy
~/.orbstack/bin/docker compose down       # stop (data persists in volumes)
~/.orbstack/bin/docker compose down -v    # stop AND wipe all trace data
```

Six containers: `langfuse-web`, `langfuse-worker`, `postgres`, `clickhouse`,
`redis`, `minio`.

## Dashboard

- URL: **http://localhost:3000**
- Login: see `LANGFUSE_INIT_USER_EMAIL` / `LANGFUSE_INIT_USER_PASSWORD` in
  `tools/langfuse/.env` (git-ignored; generated on first setup).
- Traces live under project **GraphRAG Pipeline**, trace name **`rag_query`**.

## How the backend is wired

- `backend/observability/langfuse_tracing.py` — a gated, fail-open helper.
  - **Off by default.** Every function is a no-op unless `LANGFUSE_ENABLED` is
    truthy, so production behaviour is unchanged when it's off.
  - **Never breaks the request.** Any tracing/SDK error is swallowed; the
    pipeline always continues.
- `backend/api/app.py`'s `/query` handler opens one `rag_query` trace per
  request (no protected files were modified).
- Config lives in `backend/.env` (git-ignored):

  ```
  LANGFUSE_ENABLED=true
  LANGFUSE_HOST=http://localhost:3000
  LANGFUSE_PUBLIC_KEY=pk-lf-...
  LANGFUSE_SECRET_KEY=sk-lf-...
  ```

  Set `LANGFUSE_ENABLED=false` (or remove it) to turn tracing off with zero
  overhead. Restart the backend after changing it.

## Using it

1. Start the stack (above) and make sure the backend was started with the
   Langfuse env vars set.
2. Send queries through the frontend/chat as usual.
3. Open http://localhost:3000 → the `rag_query` traces appear in real time.
   Blocked queries are flagged WARNING with the guardrail category; pipeline
   errors are flagged ERROR with the failing stage — so you can see where a
   failure happened at a glance.

## What gets traced

- **Live `/query` requests** — one `rag_query` trace per request with a nested
  **per-stage latency waterfall**: `guardrail`, `filter_extraction`,
  `retrieval`, `graph_traversal`, `reranking`, `generation`. Blocked queries are
  flagged WARNING with the guardrail category; pipeline errors are flagged ERROR
  with the failing stage. Use the waterfall to see which stage dominates
  latency (typically guardrail + reranking) when optimizing.
- **RAGAS evaluation runs** — `tools/rag_accuracy/evaluate_rag.py` emits one
  `ragas_eval_case` trace per scored case with the faithfulness / context
  precision / context recall scores attached, filterable by relationship type
  and variant kind. (The eval's own 156 pipeline-collection calls have stage
  tracing suppressed so they don't flood the dashboard.)
- **Flush on shutdown** — the API flushes pending traces on clean shutdown so
  the last few requests aren't lost.

## Notes / future work

- Deliberately **not** done (fine for this local/trial setup): sampling &
  retention policy (every query is traced), and PII controls (traces store full
  query + answer text — safe because everything is local; rotate secrets and add
  controls before exposing any port beyond localhost).
- The `.env` in this folder holds generated local secrets and is git-ignored.
