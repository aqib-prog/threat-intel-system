# Frontend

This is the web interface for the Threat Intel GraphRAG assistant.

Users can open the chat page, ask cyber threat intelligence questions, and view
answers with source cards and visual sections.

## Run locally

```bash
npm install
cp .env.example .env
npm run dev
```

Open the URL shown in the terminal, usually:

```text
http://localhost:5174/chat
```

## Settings

Set these in `frontend/.env`:

```text
VITE_API_BASE=http://localhost:8000
VITE_API_KEY=
```

`VITE_API_KEY` must match the backend API key if backend authentication is enabled.

## Checks

```bash
npm run lint
npm run build
```

Do not commit real `.env` files or build output.
