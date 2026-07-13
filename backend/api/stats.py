"""Live graph statistics for the frontend landing page.

Counts are queried directly from Neo4j on each request (with a short
in-memory cache) rather than hardcoded, so the UI never displays stale or
fabricated numbers. The cache is per-process; it exists to smooth bursts of
landing-page traffic, not to serve as a source of truth.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel


class StatsResponse(BaseModel):
    node_count: int
    relationship_count: int
    tactic_count: int
    generated_at: float
    cached: bool


@dataclass
class _CacheEntry:
    payload: dict[str, Any]
    expires_at: float


_cache: _CacheEntry | None = None


def get_stats(driver, ttl_seconds: int) -> StatsResponse:
    global _cache
    now = time.time()
    if _cache is not None and now < _cache.expires_at:
        return StatsResponse(**_cache.payload, cached=True)

    with driver.session() as session:
        node_count = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        relationship_count = session.run(
            "MATCH ()-[r]->() RETURN count(r) AS c"
        ).single()["c"]
        tactic_count = session.run("MATCH (t:Tactic) RETURN count(t) AS c").single()["c"]

    payload = {
        "node_count": node_count,
        "relationship_count": relationship_count,
        "tactic_count": tactic_count,
        "generated_at": now,
    }
    if ttl_seconds > 0:
        _cache = _CacheEntry(payload=payload, expires_at=now + ttl_seconds)
    return StatsResponse(**payload, cached=False)
