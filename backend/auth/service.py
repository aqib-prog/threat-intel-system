"""Credential and session operations.

Every function here is written so that the failure modes are boring: the same
error for a wrong email as for a wrong password, constant-ish work whether or not
an account exists, and no secret ever returned to a caller that did not just
create it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from email_validator import EmailNotValidError, validate_email
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from auth.models import Session, User, utcnow
from auth.settings import SETTINGS


# Argon2id defaults from argon2-cffi are already sensible (memory-hard, tuned to
# the RFC 9106 recommendations). Left explicit so the cost is visible and can be
# raised as hardware improves.
_hasher = PasswordHasher(
    time_cost=SETTINGS.argon2_time_cost,
    memory_cost=SETTINGS.argon2_memory_cost_kib,
    parallelism=SETTINGS.argon2_parallelism,
)

SESSION_TTL = dt.timedelta(hours=SETTINGS.session_ttl_hours)
SESSION_COOKIE_NAME = SETTINGS.session_cookie_name

# Long enough that guessing is infeasible; url-safe so it survives a cookie
# round trip without encoding surprises.
_TOKEN_BYTES = 32

MIN_PASSWORD_LENGTH = SETTINGS.min_password_length
# Argon2 is memory-hard; unbounded input is a DoS lever.
MAX_PASSWORD_LENGTH = SETTINGS.max_password_length

# A dummy hash to verify against when the email doesn't exist. Without this,
# "no such user" returns fast and "wrong password" returns slow, and that timing
# difference alone tells an attacker which emails are registered.
_DUMMY_HASH = _hasher.hash("not-a-real-password-placeholder")


class AuthError(Exception):
    """Raised for any credential failure. Deliberately carries no detail about
    WHICH part failed - the caller turns this into one generic message."""


class WeakPasswordError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def normalize_email(raw: str) -> str:
    """Validate shape and return the normalized address, or raise AuthError.

    Uses email-validator rather than a regex: address syntax is genuinely harder
    than it looks, and a homemade pattern both rejects valid addresses and
    accepts invalid ones. Deliverability is NOT checked (no DNS lookup) so this
    stays offline and free.
    """
    try:
        result = validate_email(raw.strip(), check_deliverability=False)
    except EmailNotValidError as exc:
        raise AuthError("Enter a valid email address.") from exc
    return result.normalized.lower()


def validate_password_strength(password: str) -> None:
    """Length-first policy. Length dominates entropy far more than mandatory
    character classes, which mostly push people toward 'P@ssw0rd!' patterns."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
        )
    if password.strip() == "":
        raise WeakPasswordError("Password cannot be only whitespace.")


def hash_token(token: str) -> str:
    """SHA-256 of a session token. Fast on purpose: this is a high-entropy random
    value, not a human password, so key stretching buys nothing and would only
    slow every authenticated request."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_user(db: OrmSession, email: str, password: str) -> User:
    normalized = normalize_email(email)
    validate_password_strength(password)

    user = User(email=normalized, password_hash=_hasher.hash(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        # The unique index is the real guard against a duplicate created by two
        # simultaneous signups; a pre-check SELECT alone would race.
        db.rollback()
        raise AuthError("That email is already registered.") from exc
    db.refresh(user)
    return user


def authenticate(db: OrmSession, email: str, password: str) -> User:
    """Return the user, or raise AuthError. Never reveals which field was wrong."""
    try:
        normalized = normalize_email(email)
    except AuthError:
        # Still do the dummy verify so a malformed email costs the same as a
        # well-formed unknown one.
        _verify_dummy()
        raise AuthError("Incorrect email or password.")

    user = db.execute(select(User).where(User.email == normalized)).scalar_one_or_none()
    if user is None:
        _verify_dummy()
        raise AuthError("Incorrect email or password.")

    try:
        _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        raise AuthError("Incorrect email or password.")

    # Transparent upgrade if the cost parameters have since been raised.
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = _hasher.hash(password)
        db.commit()

    user.last_login_at = utcnow()
    db.commit()
    return user


def _verify_dummy() -> None:
    try:
        _hasher.verify(_DUMMY_HASH, "wrong")
    except Exception:
        pass


def issue_session(db: OrmSession, user: User) -> tuple[str, dt.datetime]:
    """Create a session and return (raw_token, expires_at).

    The raw token is returned exactly once, to be placed in the cookie. Only its
    hash is persisted, so it cannot be recovered from the database later.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    expires_at = utcnow() + SESSION_TTL
    db.add(Session(token_hash=hash_token(token), user_id=user.id, expires_at=expires_at))
    db.commit()
    return token, expires_at


def resolve_session(db: OrmSession, token: str | None) -> User | None:
    """Return the user for a valid, unexpired session token, else None."""
    if not token:
        return None
    record = db.execute(
        select(Session).where(Session.token_hash == hash_token(token))
    ).scalar_one_or_none()
    if record is None:
        return None

    expires_at = record.expires_at
    # SQLite hands back naive datetimes; compare in UTC either way.
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=dt.timezone.utc)
    if expires_at <= utcnow():
        db.delete(record)
        db.commit()
        return None

    return record.user


def revoke_session(db: OrmSession, token: str | None) -> None:
    """Delete one session. Idempotent - logging out twice is not an error."""
    if not token:
        return
    db.execute(delete(Session).where(Session.token_hash == hash_token(token)))
    db.commit()


def purge_expired_sessions(db: OrmSession) -> int:
    """Housekeeping so the table cannot grow without bound."""
    result = db.execute(delete(Session).where(Session.expires_at <= utcnow()))
    db.commit()
    return int(result.rowcount or 0)
