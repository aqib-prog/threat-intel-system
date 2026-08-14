"""Environment-driven authentication settings.

Single source of truth for every auth knob. Previously these were scattered as
raw ``os.getenv`` calls across four modules, which meant no one place showed
what was configurable, and a production deployment could silently miss one.

Follows the same convention as :mod:`api.settings`: read once at import, expose
a frozen dataclass, and validate values rather than trusting them.

Production hardening is enforced here rather than left to a checklist - see
:func:`production_warnings`, which the app surfaces at startup when ``APP_ENV``
is a deployed environment and a setting is unsafe for it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from api.settings import env_int, env_str


BACKEND_DIR = Path(__file__).resolve().parents[1]

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}
_DEPLOYED_ENVS = {"production", "prod", "staging"}
_VALID_SAMESITE = {"lax", "strict", "none"}


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    return default


@dataclass(frozen=True)
class AuthSettings:
    # --- storage ---
    database_url: str

    # --- session lifetime ---
    session_ttl_hours: int
    session_cookie_name: str

    # --- cookie transport ---
    cookie_secure: bool
    cookie_samesite: str
    cookie_domain: str | None

    # --- password policy ---
    min_password_length: int
    max_password_length: int

    # --- hashing cost (raise as hardware improves) ---
    argon2_time_cost: int
    argon2_memory_cost_kib: int
    argon2_parallelism: int

    # --- enforcement ---
    require_session: bool

    # --- housekeeping ---
    session_cleanup_interval_seconds: int

    # --- abuse limits on credential endpoints ---
    rate_limit_login: str
    rate_limit_signup: str

    environment: str

    @property
    def is_deployed(self) -> bool:
        return self.environment.strip().lower() in _DEPLOYED_ENVS


def load_auth_settings() -> AuthSettings:
    samesite = env_str("AUTH_COOKIE_SAMESITE", "lax").lower()
    if samesite not in _VALID_SAMESITE:
        samesite = "lax"

    # SameSite=None is only meaningful on a Secure cookie; browsers reject the
    # combination otherwise, which would silently drop the session entirely.
    cookie_secure = env_bool("AUTH_COOKIE_SECURE", False)
    if samesite == "none":
        cookie_secure = True

    min_length = env_int("AUTH_MIN_PASSWORD_LENGTH", 12, minimum=8, maximum=128)
    max_length = env_int("AUTH_MAX_PASSWORD_LENGTH", 128, minimum=min_length, maximum=1024)

    domain = env_str("AUTH_COOKIE_DOMAIN", "")

    return AuthSettings(
        database_url=env_str("AUTH_DATABASE_URL", f"sqlite:///{BACKEND_DIR / 'auth.db'}"),
        # Two hours. Short by design: this is a security tool, and the window in
        # which a stolen cookie is useful should be measured in hours, not days.
        # Expiry is ABSOLUTE from login, not idle-based, so an attacker cannot
        # keep a captured session alive indefinitely just by using it.
        session_ttl_hours=env_int("AUTH_SESSION_TTL_HOURS", 2, minimum=1, maximum=720),
        session_cookie_name=env_str("AUTH_COOKIE_NAME", "ti_session"),
        cookie_secure=cookie_secure,
        cookie_samesite=samesite,
        cookie_domain=domain or None,
        min_password_length=min_length,
        max_password_length=max_length,
        # RFC 9106 second-recommended profile: 64 MiB, 3 passes, 4 lanes.
        argon2_time_cost=env_int("AUTH_ARGON2_TIME_COST", 3, minimum=1, maximum=10),
        argon2_memory_cost_kib=env_int(
            "AUTH_ARGON2_MEMORY_KIB", 64 * 1024, minimum=8 * 1024, maximum=1024 * 1024
        ),
        argon2_parallelism=env_int("AUTH_ARGON2_PARALLELISM", 4, minimum=1, maximum=16),
        # Enforced unless explicitly disabled: a gate that is off by default is
        # how unprotected endpoints reach production.
        require_session=env_bool("AUTH_REQUIRE_SESSION", True),
        # Hourly. Expired sessions are already refused at authentication, so
        # this only reclaims storage - sweeping aggressively would add database
        # churn for no security benefit. Floored at 60s in cleanup.py so a
        # mistaken 0 cannot become a busy loop.
        session_cleanup_interval_seconds=env_int(
            "AUTH_SESSION_CLEANUP_INTERVAL_SECONDS", 3600, minimum=60, maximum=86_400
        ),
        rate_limit_login=env_str("AUTH_RATE_LIMIT_LOGIN", "10/minute"),
        rate_limit_signup=env_str("AUTH_RATE_LIMIT_SIGNUP", "5/minute"),
        environment=env_str("APP_ENV", "local"),
    )


def production_warnings(settings: AuthSettings) -> list[str]:
    """Configuration that is acceptable locally but unsafe once deployed.

    Returned rather than raised so the caller decides whether to log loudly or
    refuse to boot; the app logs them at startup.
    """
    problems: list[str] = []
    if not settings.is_deployed:
        return problems

    if not settings.cookie_secure:
        problems.append(
            "AUTH_COOKIE_SECURE is off - the session cookie will be sent over "
            "plain HTTP and can be intercepted. Set AUTH_COOKIE_SECURE=1."
        )
    if not settings.require_session:
        problems.append(
            "AUTH_REQUIRE_SESSION is off - chat endpoints are UNAUTHENTICATED. "
            "Unset it or set AUTH_REQUIRE_SESSION=1."
        )
    if settings.cookie_samesite == "none":
        problems.append(
            "AUTH_COOKIE_SAMESITE=none allows the cookie on cross-site requests, "
            "which weakens CSRF protection. Prefer 'lax' unless a separate "
            "frontend origin genuinely requires it."
        )
    if settings.database_url.startswith("sqlite"):
        problems.append(
            "AUTH_DATABASE_URL points at SQLite. Fine for a single instance, but "
            "it cannot be shared across replicas - move to Postgres before "
            "scaling out."
        )
    if settings.min_password_length < 12:
        problems.append(
            f"AUTH_MIN_PASSWORD_LENGTH is {settings.min_password_length}; 12 or "
            "more is recommended."
        )
    return problems


SETTINGS = load_auth_settings()
