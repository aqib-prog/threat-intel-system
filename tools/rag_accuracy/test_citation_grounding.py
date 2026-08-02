from __future__ import annotations

import asyncio
import inspect
import re
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from starlette.requests import Request


ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import app as api_app  # noqa: E402


class _FakeResult:
    def __init__(self, ids: list[str]) -> None:
        self._ids = ids

    def single(self) -> dict[str, list[str]]:
        return {"ids": self._ids}


class _FakeSession:
    def __init__(self, ids: list[str]) -> None:
        self._ids = ids

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def run(self, _query: str) -> _FakeResult:
        return _FakeResult(self._ids)


class _FakeDriver:
    def __init__(self, ids: list[str]) -> None:
        self._ids = ids
        self.closed = False

    def session(self) -> _FakeSession:
        return _FakeSession(self._ids)

    def close(self) -> None:
        self.closed = True


class CitationGroundingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._original_ids = api_app._ALL_EXTERNAL_IDS
        self._original_expiry = api_app._ALL_EXTERNAL_IDS_EXPIRES_AT
        self._original_settings = api_app.SETTINGS
        api_app._ALL_EXTERNAL_IDS = {"T1078", "G0016", "M1036", "DET0094", "AN1543"}
        api_app._ALL_EXTERNAL_IDS_EXPIRES_AT = float("inf")

    def tearDown(self) -> None:
        api_app._ALL_EXTERNAL_IDS = self._original_ids
        api_app._ALL_EXTERNAL_IDS_EXPIRES_AT = self._original_expiry
        api_app.SETTINGS = self._original_settings

    def test_real_id_is_grounded(self) -> None:
        self.assertEqual(api_app.grounded_mitre_ids("Valid Accounts (T1078)"), ["T1078"])

    def test_fake_id_is_not_grounded(self) -> None:
        self.assertEqual(api_app.grounded_mitre_ids("Fabricated group G9999"), [])

    def test_mixed_real_and_fake_ids_keep_only_real(self) -> None:
        answer = "G9999 is fake; M1036 and T1078 are real."
        self.assertEqual(api_app.grounded_mitre_ids(answer), ["M1036", "T1078"])

    def test_id_inside_markdown_url_is_grounded(self) -> None:
        answer = "[Valid Accounts](https://attack.mitre.org/techniques/T1078/)"
        self.assertEqual(api_app.grounded_mitre_ids(answer), ["T1078"])

    def test_matching_is_case_insensitive_and_normalized(self) -> None:
        self.assertEqual(api_app.grounded_mitre_ids("See det0094 and t1078."), ["DET0094", "T1078"])

    def test_empty_answer_and_answer_without_ids_skip_database_lookup(self) -> None:
        api_app._ALL_EXTERNAL_IDS = None
        api_app._ALL_EXTERNAL_IDS_EXPIRES_AT = 0.0
        with mock.patch.object(api_app, "get_driver") as get_driver:
            self.assertEqual(api_app.grounded_mitre_ids(""), [])
            self.assertEqual(api_app.grounded_mitre_ids("No ATT&CK identifier here."), [])
        get_driver.assert_not_called()

    def test_expired_cache_refreshes_and_exposes_new_graph_id(self) -> None:
        first_driver = _FakeDriver(["T1078"])
        second_driver = _FakeDriver(["T1078", "T1059"])
        api_app._ALL_EXTERNAL_IDS = None
        api_app._ALL_EXTERNAL_IDS_EXPIRES_AT = 0.0
        api_app.SETTINGS = replace(api_app.SETTINGS, citation_cache_seconds=10)

        with (
            mock.patch.object(api_app.time, "time", side_effect=[100.0, 105.0, 111.0]),
            mock.patch.object(
                api_app, "get_driver", side_effect=[first_driver, second_driver]
            ) as get_driver,
        ):
            self.assertEqual(api_app.grounded_mitre_ids("T1078 and T1059"), ["T1078"])
            self.assertEqual(api_app.grounded_mitre_ids("T1059"), [])
            self.assertEqual(api_app.grounded_mitre_ids("T1059"), ["T1059"])

        self.assertEqual(get_driver.call_count, 2)
        self.assertTrue(first_driver.closed)
        self.assertTrue(second_driver.closed)

    def test_database_failure_keeps_query_answer_and_returns_no_grounded_ids(self) -> None:
        answer = "Valid Accounts (T1078) is the relevant technique."
        pipeline_result = SimpleNamespace(
            query="What is T1078?",
            answer=answer,
            sources=[],
            filters={},
            allowed=True,
            guardrail_category=None,
            retrieved_count=1,
            context_count=1,
            answer_source="rag",
            log_evidence=[],
            retrieved_contexts=[],
            suggestions=[],
            suggestion_actions=[],
            segments=[],
        )
        api_app._ALL_EXTERNAL_IDS = {"T1078"}
        api_app._ALL_EXTERNAL_IDS_EXPIRES_AT = 0.0
        request = Request({"type": "http", "method": "POST", "path": "/query", "headers": []})
        payload = api_app.QueryRequest(query=pipeline_result.query)
        endpoint = inspect.unwrap(api_app.query)

        with (
            mock.patch.object(
                api_app, "run_multi_pipeline", return_value=pipeline_result
            ),
            mock.patch.object(api_app, "get_driver", side_effect=RuntimeError("neo4j unavailable")),
            mock.patch.object(api_app, "log_and_sanitize", return_value="sanitized") as log_error,
        ):
            response = asyncio.run(endpoint(request, payload))

        self.assertEqual(response.answer, answer)
        self.assertTrue(response.allowed)
        self.assertEqual(response.grounded_ids, [])
        log_error.assert_called_once()
        self.assertEqual(log_error.call_args.kwargs["stage"], "citation grounding refresh")


class FrontendCitationContractTests(unittest.TestCase):
    def test_backend_and_frontend_recognize_identical_prefixes(self) -> None:
        frontend_source = (ROOT / "frontend/src/lib/mitre.ts").read_text(encoding="utf-8")
        frontend_match = re.search(r"\(\?:([^)]*)\)\\d\{4\}", frontend_source)
        backend_match = re.search(r"\(\?:([^)]*)\)\\d\{4\}", api_app._MITRE_ID_RE.pattern)
        self.assertIsNotNone(frontend_match)
        self.assertIsNotNone(backend_match)
        self.assertEqual(frontend_match.group(1), backend_match.group(1))

    def test_every_recognized_prefix_except_analytic_has_a_public_page_mapping(self) -> None:
        frontend_source = (ROOT / "frontend/src/lib/mitre.ts").read_text(encoding="utf-8")
        prefix_match = re.search(r"\(\?:([^)]*)\)\\d\{4\}", api_app._MITRE_ID_RE.pattern)
        path_block = re.search(
            r"const PREFIX_PATH:[^{]+\{(?P<body>.*?)\n\};", frontend_source, re.DOTALL
        )
        self.assertIsNotNone(prefix_match)
        self.assertIsNotNone(path_block)
        recognized = set(prefix_match.group(1).split("|"))
        linkable = set(re.findall(r"^\s*([A-Z]+):\s*\"", path_block.group("body"), re.MULTILINE))

        self.assertNotIn("AN", linkable)
        self.assertEqual(linkable, recognized - {"AN"})


if __name__ == "__main__":
    unittest.main()
