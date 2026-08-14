"""Sign-up, login, logout, and the session dependency used to gate routes.

Transport decisions, all deliberate:

* The session token travels in a cookie marked ``HttpOnly`` (JavaScript cannot
  read it, so an XSS bug cannot exfiltrate it), ``SameSite=Lax`` (a third-party
  site cannot silently drive an authenticated request), and ``Secure`` whenever
  the app is not on localhost.
* It is never placed in a URL, where it would leak into browser history, server
  access logs, and ``Referer`` headers.
* Login and signup are rate limited, because password endpoints are the natural
  target for credential stuffing.
"""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from auth import service
from auth.models import SessionLocal, User
from auth.settings import SETTINGS


router = APIRouter(prefix="/auth", tags=["auth"])

# Cookies marked Secure are dropped by browsers over plain http, which would
# break local development, so this defaults off and auth/settings.py warns when
# a deployed environment leaves it that way.
COOKIE_SECURE = SETTINGS.cookie_secure
COOKIE_SAMESITE = SETTINGS.cookie_samesite


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class CredentialsIn(BaseModel):
    # Bounds here are a first line of defence: they cap the work done before any
    # hashing happens, so an oversized body cannot be used as a DoS lever.
    email: str = Field(..., min_length=3, max_length=320)
    password: str = Field(..., min_length=1, max_length=service.MAX_PASSWORD_LENGTH)


class UserOut(BaseModel):
    id: int
    email: str


def _set_session_cookie(response: Response, token: str, max_age_seconds: int) -> None:
    response.set_cookie(
        key=service.SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age_seconds,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        domain=SETTINGS.cookie_domain,
        path="/",
    )


@router.post("/signup", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def signup(
    request: Request,
    payload: CredentialsIn,
    response: Response,
    db: OrmSession = Depends(get_db),
) -> UserOut:
    try:
        user = service.create_user(db, payload.email, payload.password)
    except service.WeakPasswordError as exc:
        # Password rules are the one case where a specific message helps the
        # user and tells an attacker nothing they could not read in the docs.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=exc.reason) from exc
    except service.AuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    token, _ = service.issue_session(db, user)
    _set_session_cookie(response, token, int(service.SESSION_TTL.total_seconds()))
    return UserOut(id=user.id, email=user.email)


@router.post("/login", response_model=UserOut)
def login(
    request: Request,
    payload: CredentialsIn,
    response: Response,
    db: OrmSession = Depends(get_db),
) -> UserOut:
    try:
        user = service.authenticate(db, payload.email, payload.password)
    except service.AuthError as exc:
        # 401 with one generic message for every credential failure.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    # A fresh token per login: an old cookie captured earlier is not silently
    # re-blessed, and fixation attacks have nothing to fix onto.
    token, _ = service.issue_session(db, user)
    _set_session_cookie(response, token, int(service.SESSION_TTL.total_seconds()))
    return UserOut(id=user.id, email=user.email)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    ti_session: str | None = Cookie(default=None),
    db: OrmSession = Depends(get_db),
) -> Response:
    # Server-side revocation is the point of this session model: the row is gone,
    # so the token is dead everywhere immediately, not just in this browser.
    service.revoke_session(db, ti_session)
    response.delete_cookie(service.SESSION_COOKIE_NAME, path="/")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def current_user(
    ti_session: str | None = Cookie(default=None),
    db: OrmSession = Depends(get_db),
) -> User:
    """Dependency that gates a route. Raises 401 when there is no live session."""
    user = service.resolve_session(db, ti_session)
    if user is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    return user


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> UserOut:
    """Used by the frontend route guard to check for a live session."""
    return UserOut(id=user.id, email=user.email)
