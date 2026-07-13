# Deployment / environment promotion

Both apps are fully environment-variable driven — no code changes are needed
to move between dev, staging, and production. Only configuration changes.

## Backend (`backend/`)

Settings load from environment variables (`backend/api/settings.py`,
`backend/config.py`) with `.env` as the local convenience mechanism
(`python-dotenv`). Per-environment templates:

| Environment | Template | Copy to |
|---|---|---|
| Development | `backend/.env.development.example` | `backend/.env` |
| Staging | `backend/.env.staging.example` | secret manager / CI env, not a file |
| Production | `backend/.env.production.example` | secret manager / CI env, not a file |

```bash
# Local dev
cd backend
cp .env.development.example .env   # then fill in real values
venv/bin/pip install -r requirements-api.txt
venv/bin/uvicorn api.app:app --host 127.0.0.1 --port 8000 --reload
```

For staging/production, **do not put real secrets in a `.env` file on disk** —
inject them as process environment variables from whatever your host provides
(e.g. platform env var settings, AWS Secrets Manager, Doppler, Vault). The
`.env.staging.example` / `.env.production.example` files document which
variables exist and what changes between environments; they intentionally
contain placeholders, not values.

What actually differs per environment:

- `CORS_ORIGINS` — must exactly match the frontend origin(s) for that
  environment. CORS fails closed if unset (see `backend/api/README.md`).
- `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` — point at that environment's
  Neo4j instance. Neo4j itself should never be publicly reachable in any
  environment — only this API should have network access to it.
- `RATE_LIMIT_*` — dev can be generous (you're the only caller); staging/prod
  should reflect expected real traffic.
- `RATE_LIMIT_STORAGE_URI` — leave empty for a single-process dev server.
  **Required** once staging/production run more than one worker/instance, or
  each process enforces its own independent limit (see
  `backend/security/rate_limit.py`).
- `API_KEYS` — empty/unset disables auth on `/query` and `/filters` (dev
  only). **Required** in staging/production - `GET /health`'s `auth` field
  reports `"MISCONFIGURED"` if it's missing there. Must match `VITE_API_KEY`
  on the frontend for that environment.
- `APP_ENV` — also gates the `API_KEYS` check above; doesn't otherwise change
  behavior.

Deploy as a standard ASGI app (`api.app:app`) behind a process manager /
container orchestrator of your choice, fronted by a reverse proxy or load
balancer that terminates TLS and forwards HTTPS traffic. TLS/HSTS and
`frame-ancestors` should be configured at that layer, not in the app.

## Frontend (`frontend/`)

Vite's built-in mode system picks the right file automatically — no manual
env-var wiring needed:

| Environment | Command | Loads |
|---|---|---|
| Development | `npm run dev` | `.env` / `.env.development` |
| Staging | `npm run build -- --mode staging` | `.env.staging` |
| Production | `npm run build` (mode defaults to `production`) | `.env.production` |

Copy the matching `.example` file and fill in the real backend origin before
building:

```bash
cp .env.staging.example .env.staging       # then edit VITE_API_BASE
npm run build -- --mode staging
```

`VITE_API_BASE` must be an `https://` origin in staging/production. If you
change it, also update the CSP `connect-src` directive in `index.html` to
match — a static meta tag can't read the env var at request time.

`VITE_API_KEY` must match the backend's `API_KEYS` for that environment.
**Note this key ships inside the public JS bundle** — see the auth caveat in
`backend/api/README.md` before relying on it for anything beyond
bot/scanner deterrence.

## Promotion checklist

Before promoting a build to a new environment, confirm:

- [ ] `CORS_ORIGINS` (backend) lists exactly that environment's frontend origin(s)
- [ ] `VITE_API_BASE` (frontend) points at that environment's backend
- [ ] `index.html` CSP `connect-src` matches `VITE_API_BASE`
- [ ] `API_KEYS` (backend) is set and matches `VITE_API_KEY` (frontend) - check
      `GET /health` doesn't report `"auth": "MISCONFIGURED"`
- [ ] Neo4j password is unique to that environment (never reused from dev)
- [ ] Neo4j is not publicly reachable from that environment's network
- [ ] `RATE_LIMIT_STORAGE_URI` is set if running >1 backend worker/instance
- [ ] No `.env*` files (other than `.example` templates) are committed
- [ ] `og:image`/`twitter:image` in `index.html` point to an absolute
      `https://` URL on the real domain (relative paths are unreliable for
      link-preview scrapers on most platforms)
