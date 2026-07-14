# Backend API

This is the FastAPI service used by the frontend.

It receives user questions, runs the threat intelligence pipeline, and returns
the answer with source nodes.

## Run locally

From the `backend` folder:

```bash
cp .env.example .env
uvicorn api.app:app --reload --host 127.0.0.1 --port 8000
```

## Main routes

- `GET /health` — checks if the API is running
- `GET /stats` — returns graph statistics for the frontend
- `GET /filters` — returns detected filters for a query
- `POST /query` — runs the full question-answering pipeline

## Example query

```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"query":"Tell me about T1078"}'
```

## Environment

Use `.env.example` as the template.

Do not commit real secrets, passwords, or API keys.
