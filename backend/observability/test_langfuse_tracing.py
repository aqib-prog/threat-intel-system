"""Tests for the gated, fail-open Langfuse tracing helper.

These assert the two non-negotiable guarantees without needing a live Langfuse
server: (1) disabled == true no-op that never touches the SDK, and (2) a tracing
error never propagates out to break the request path.
"""

from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _reload_with(enabled: str):
    os.environ["LANGFUSE_ENABLED"] = enabled
    from observability import langfuse_tracing as obs

    return importlib.reload(obs)


class LangfuseTracingTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("LANGFUSE_ENABLED", None)

    def test_disabled_is_noop_and_never_creates_client(self):
        obs = _reload_with("false")
        self.assertFalse(obs.enabled())
        # spans/generations yield an inert handle; no method raises
        with obs.span("q") as s:
            s.update(input="a", output="b", level="ERROR")
            s.update_trace(input="a", output="b")
            s.event(name="x")
        with obs.generation("g", model="llama3.1") as g:
            g.update(output="c")
        obs.flush()
        # the SDK client must never have been instantiated when disabled
        self.assertIsNone(obs._client)

    def test_enabled_but_client_error_does_not_raise(self):
        obs = _reload_with("true")

        def boom():
            raise RuntimeError("langfuse unreachable")

        original = obs._get_client
        obs._get_client = boom
        try:
            # span() must swallow the client error and still yield a usable handle
            with obs.span("q") as s:
                s.update(input="a", output="b")
            with obs.generation("g") as g:
                g.update(output="c")
            self.assertFalse(obs.auth_check())  # also swallows, returns False
        finally:
            obs._get_client = original

    def test_truthy_parsing(self):
        for value, expected in [
            ("true", True), ("1", True), ("YES", True), ("on", True),
            ("false", False), ("0", False), ("", False), ("nope", False),
        ]:
            obs = _reload_with(value)
            self.assertEqual(obs.enabled(), expected, value)


if __name__ == "__main__":
    unittest.main()
