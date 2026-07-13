"""Environment-driven API settings.

Keep deployment-specific values in environment variables or `.env` files, not
in application code. This makes the same code runnable in local, staging, and
production environments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def env_str(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


def env_int(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw is not None else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(value, minimum)
    if maximum is not None:
        value = min(value, maximum)
    return value


def env_list(name: str, default: str = "*") -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class ApiSettings:
    title: str
    version: str
    environment: str
    cors_origins: list[str]
    default_top_k: int
    default_candidate_k: int
    max_top_k: int
    max_candidate_k: int
    max_query_chars: int
    rate_limit_query: str
    rate_limit_filters: str
    rate_limit_stats: str
    stats_cache_seconds: int


def load_settings() -> ApiSettings:
    max_top_k = env_int("API_MAX_TOP_K", 25, minimum=1)
    max_candidate_k = env_int("API_MAX_CANDIDATE_K", 100, minimum=1)
    default_top_k = env_int("PIPELINE_TOP_K", 8, minimum=1, maximum=max_top_k)
    default_candidate_k = env_int(
        "PIPELINE_CANDIDATE_K",
        30,
        minimum=default_top_k,
        maximum=max_candidate_k,
    )
    return ApiSettings(
        title=env_str("API_TITLE", "Threat Intel GraphRAG API"),
        version=env_str("API_VERSION", "1.0.0"),
        environment=env_str("APP_ENV", "local"),
        # Fail closed: an unset CORS_ORIGINS blocks all cross-origin browser
        # requests rather than allowing every origin. Set it explicitly per
        # environment (see .env.example).
        cors_origins=env_list("CORS_ORIGINS", ""),
        default_top_k=default_top_k,
        default_candidate_k=default_candidate_k,
        max_top_k=max_top_k,
        max_candidate_k=max_candidate_k,
        max_query_chars=env_int("MAX_QUERY_CHARS", 8000, minimum=1),
        # LLM- and Neo4j-backed endpoints get tighter limits than the
        # read-only stats endpoint.
        rate_limit_query=env_str("RATE_LIMIT_QUERY", "20/minute"),
        rate_limit_filters=env_str("RATE_LIMIT_FILTERS", "30/minute"),
        rate_limit_stats=env_str("RATE_LIMIT_STATS", "60/minute"),
        stats_cache_seconds=env_int("STATS_CACHE_SECONDS", 60, minimum=0),
    )

