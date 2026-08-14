"""User and session storage for per-user authentication.

Storage is SQLite through SQLAlchemy: no new infrastructure, ACID, and a
connection-string change away from Postgres if this ever runs multi-instance.
Neo4j deliberately does NOT hold credentials - a graph database is the wrong
shape for auth records, and keeping user secrets out of the threat-intel store
means a read path into the graph can never expose them.

Two security decisions are encoded in the schema itself:

* ``User.password_hash`` stores an Argon2id hash. Argon2id won the Password
  Hashing Competition and is memory-hard, so GPU/ASIC cracking is far more
  expensive than it is against bcrypt. The plaintext password is never written
  anywhere - not to a column, not to a log.
* ``Session.token_hash`` stores a SHA-256 hash of the session token, never the
  token itself. The raw token exists only in the user's cookie. If this database
  file is ever stolen, the attacker still cannot mint a usable session from it,
  because the stored value is not what the cookie must present.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from auth.settings import SETTINGS


# All auth configuration lives in auth/settings.py - see that module for the
# full list of environment variables and their production guidance.
DATABASE_URL = SETTINGS.database_url


class Base(DeclarativeBase):
    pass


def utcnow() -> dt.datetime:
    """Timezone-aware UTC. Naive datetimes silently compare wrong across DST and
    would make expiry checks unreliable."""
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Stored lowercased and stripped so "A@b.com" and "a@b.com " are one account
    # and cannot be registered twice. Uniqueness is enforced by the database, not
    # only by an application-level check that could race.
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    """A server-side session. Revocable by deleting the row - which is exactly
    why this was chosen over a stateless JWT."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    # SHA-256 of the cookie value. See module docstring: never the token itself.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped[User] = relationship(back_populates="sessions")


Index("ix_sessions_expires_at", Session.expires_at)


# check_same_thread=False because FastAPI serves requests from a thread pool;
# each request still takes its own Session object from the factory below.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_db() -> None:
    """Create tables if absent. Safe to call on every startup."""
    Base.metadata.create_all(engine)
