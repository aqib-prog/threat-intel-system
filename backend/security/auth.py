"""Shared-secret API key authentication for LLM- and Neo4j-backed endpoints.

This is a pragmatic single-frontend-client scheme, not per-user auth. A key
baked into a browser-built frontend bundle (VITE_API_KEY) is visible to
anyone who opens devtools on that frontend - it stops anonymous internet
scanners and casual abuse of the raw API URL, it does not stop a determined
user of your own app from extracting the key and calling the API directly.
For real per-user access control, put a session/JWT auth provider in front
of this instead.

Auth is opt-in via API_KEYS/API_KEY: unset means disabled (so local dev
keeps working with zero config). Staging/production should always set it -
see is_auth_misconfigured() and how api/app.py surfaces that via /health.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status


def _load_keys() -> set[str]:
    raw = os.getenv("API_KEYS", "") or os.getenv("API_KEY", "")
    return {key.strip() for key in raw.split(",") if key.strip()}


_API_KEYS = _load_keys()
AUTH_ENABLED = bool(_API_KEYS)


def _matches_any(candidate: str, keys: set[str]) -> bool:
    # Constant-time compare per key to avoid leaking key length/prefix via
    # response timing.
    return any(hmac.compare_digest(candidate, key) for key in keys)


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not AUTH_ENABLED:
        return
    if not x_api_key or not _matches_any(x_api_key, _API_KEYS):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key",
        )


def is_auth_misconfigured(environment: str) -> bool:
    """True if running in a non-local environment with no key configured -
    a real production security gap, surfaced via /health rather than
    silently allowed."""
    return environment.lower() in {"staging", "production"} and not AUTH_ENABLED
