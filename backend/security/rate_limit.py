"""Rate limiting for LLM-backed and database-backed endpoints.

/query and /filters both trigger LLM calls and Neo4j traversals per request,
so an unauthenticated client could otherwise drive unbounded cost and load.
Limits are enforced per client IP and are configurable via environment
variables so they can be tuned per deployment without a code change.

In-memory storage (the default) only rate-limits correctly within a single
process. Set RATE_LIMIT_STORAGE_URI (e.g. redis://host:6379) before running
with multiple workers or multiple instances behind a load balancer, or every
process will enforce its own independent limit.
"""

from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_storage_uri = os.getenv("RATE_LIMIT_STORAGE_URI") or None

limiter = Limiter(key_func=get_remote_address, storage_uri=_storage_uri)
