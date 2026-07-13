"""Sanitized error responses.

Internal exception details (Neo4j URIs/credentials in connection errors,
stack frames, LLM provider errors) must never reach the client. They're
logged server-side with full detail and replaced with a generic, stable
message before leaving the process.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("threat_intel_api")

GENERIC_MESSAGE = "The request could not be completed. Please try again."


def log_and_sanitize(exc: Exception, *, stage: str | None = None) -> str:
    logger.error(
        "Unhandled error%s: %s",
        f" during {stage}" if stage else "",
        exc,
        exc_info=exc,
    )
    return GENERIC_MESSAGE
