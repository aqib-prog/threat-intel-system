"""The route gate: reject any request without a live server-side session.

This is the real enforcement layer. The frontend's redirect to /login is UX
politeness - a user who bypasses it, or scripts the API directly, must still be
refused here, on every request.

It composes with (does not replace) the existing shared API-key check. The API
key identifies the frontend build; the session identifies the human. Requiring
both means a leaked key alone grants nothing, and a stolen session cookie
replayed from outside the app still fails the key check.
"""

from __future__ import annotations

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session as OrmSession

from auth import service
from auth.models import User
from auth.routes import get_db
from auth.settings import SETTINGS


# Escape hatch for local development and for the offline evaluation harnesses,
# which call the pipeline directly and have no browser to hold a cookie.
# Defaults to ENFORCED: an auth gate that is off unless someone remembers to
# switch it on is how unprotected endpoints reach production.
SESSION_REQUIRED = SETTINGS.require_session


def require_session(
    ti_session: str | None = Cookie(default=None),
    db: OrmSession = Depends(get_db),
) -> User | None:
    if not SESSION_REQUIRED:
        return None
    user = service.resolve_session(db, ti_session)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    return user
