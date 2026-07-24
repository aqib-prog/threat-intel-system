"""Gated, fail-open Langfuse tracing for the RAG pipeline.

Design rules (both non-negotiable):
  1. **Off by default, zero overhead.** Unless ``LANGFUSE_ENABLED`` is truthy
     every function here is a no-op, so production behaviour is byte-identical
     to running without this module. Same opt-in philosophy as
     ``run_pipeline(include_contexts=...)``.
  2. **Observability must never break the pipeline.** Every call into the
     Langfuse SDK is wrapped so a tracing failure (server down, bad key,
     network blip) is swallowed and the request continues normally. Tracing is
     a side channel, never on the critical path.

The self-hosted Langfuse server is local-only (http://localhost:3000), so
enabling this keeps every byte on the machine - consistent with the project's
loopback-only stance. The SDK reads LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY /
LANGFUSE_HOST from the environment.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any, Iterator

_TRUTHY = {"1", "true", "yes", "on"}


def enabled() -> bool:
    """True only when tracing is explicitly switched on via env."""
    return os.getenv("LANGFUSE_ENABLED", "false").strip().lower() in _TRUTHY


_client = None


def _get_client():
    global _client
    if _client is None:
        from langfuse import get_client  # imported lazily so a disabled

        # deployment never even imports the SDK
        _client = get_client()
    return _client


class _Span:
    """Uniform span handle. Every method is safe to call and never raises,
    whether it wraps a real Langfuse span or nothing at all."""

    __slots__ = ("_real",)

    def __init__(self, real: Any = None) -> None:
        self._real = real

    def update(self, **kwargs: Any) -> None:
        if self._real is None:
            return
        try:
            self._real.update(**kwargs)
        except Exception:
            pass

    def update_trace(self, **kwargs: Any) -> None:
        if self._real is None:
            return
        try:
            self._real.update_trace(**kwargs)
        except Exception:
            pass

    def event(self, **kwargs: Any) -> None:
        if self._real is None:
            return
        try:
            self._real.create_event(**kwargs)
        except Exception:
            pass


@contextlib.contextmanager
def span(name: str, **create_kwargs: Any) -> Iterator[_Span]:
    """Open a tracing span (a nested observation, or the trace root if it's the
    outermost span). No-op and yields an inert handle when disabled or on any
    SDK error."""
    if not enabled():
        yield _Span(None)
        return
    try:
        client = _get_client()
        with client.start_as_current_span(name=name, **create_kwargs) as real:
            yield _Span(real)
    except Exception:
        yield _Span(None)


@contextlib.contextmanager
def generation(name: str, **create_kwargs: Any) -> Iterator[_Span]:
    """Like :func:`span` but records an LLM generation (model/usage aware)."""
    if not enabled():
        yield _Span(None)
        return
    try:
        client = _get_client()
        with client.start_as_current_generation(name=name, **create_kwargs) as real:
            yield _Span(real)
    except Exception:
        yield _Span(None)


def flush() -> None:
    """Force-flush buffered traces (call at process end / after a batch)."""
    if not enabled():
        return
    try:
        _get_client().flush()
    except Exception:
        pass


def auth_check() -> bool:
    """Verify the SDK can reach the configured Langfuse server. For diagnostics
    only - never called on the request path."""
    if not enabled():
        return False
    try:
        return bool(_get_client().auth_check())
    except Exception:
        return False
