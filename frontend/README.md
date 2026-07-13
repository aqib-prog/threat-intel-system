# Threat Intel AI — Frontend

React + Vite + Tailwind + Framer Motion frontend for a Graph RAG threat-intelligence
assistant over a MITRE ATT&CK knowledge graph in Neo4j.

- **Landing (`/`)** — animated particle network, matrix rain, a decorative Three.js
  globe, and live graph stats pulled from the backend's `GET /stats`.
- **Chat (`/chat`)** — queries `POST /query` on the FastAPI backend
  (`../backend/api/app.py`), with MITRE ID highlighting, category visualizations,
  expandable source cards, a D3 source graph view, and an active-filters panel.
  Falls back to a clearly-labeled mock response if the backend is unreachable.

## Setup

```bash
npm install
cp .env.example .env   # only needed if your backend isn't on localhost:8000
npm run dev
```

Requires the backend running (see `../backend/README.md` / `../backend/api/README.md`)
for real data — without it, the app still runs against mock data with an
"offline" indicator.

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `VITE_API_BASE` | `http://localhost:8000` | Backend API origin. Must also be reflected in `index.html`'s CSP `connect-src` if changed. |
| `VITE_API_KEY` | empty | Optional API key sent as `X-API-Key` to authenticated backend endpoints. |

## Scripts

- `npm run dev` — dev server (Vite + HMR)
- `npm run build` — type-check (`tsc -b`) + production build
- `npm run preview` — preview a production build locally
- `npm run lint` — run oxlint

## Notes

- Real backend response schema (`QueryResponse`, `NodeSource`, `StatsResponse`) is
  mirrored in `src/lib/types.ts` — keep both in sync if the API changes.
  `relevance_score` is on a `[0, 10]` scale (see `MAX_RELEVANCE_SCORE`), not 0–1.
- Chat history is intentionally in-memory only (`useChatHistory`). Refreshing
  the page starts a clean session.
- After one hour in the chat view, the UI shows a refresh warning and disables
  new submissions so long browser sessions do not keep loading the backend/model.
- No secrets live in this app — all backend credentials (Neo4j, etc.) stay
  server-side in `../backend/.env` (gitignored).
