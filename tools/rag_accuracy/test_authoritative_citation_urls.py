from __future__ import annotations

import asyncio
import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from starlette.requests import Request


ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import app as api_app  # noqa: E402
from orchestration import pipeline  # noqa: E402
from retrieval import graph_traversal  # noqa: E402


class _SingleRecordResult:
    def __init__(self, record: dict) -> None:
        self._record = record

    def single(self) -> dict:
        return self._record


class _Session:
    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _Driver:
    def __init__(self) -> None:
        self.closed = False

    def session(self) -> _Session:
        return _Session()

    def close(self) -> None:
        self.closed = True


TRAVERSAL_CASES = {
    "Technique": ("t", "T1566.001", "https://attack.mitre.org/techniques/T1566/001"),
    "Actor": ("a", "G0016", "https://attack.mitre.org/groups/G0016"),
    "Malware": ("mal", "S0003", "https://attack.mitre.org/software/S0003"),
    "Tool": ("tool", "S0002", "https://attack.mitre.org/software/S0002"),
    "Mitigation": ("m", "M1024", "https://attack.mitre.org/mitigations/M1024"),
    "Tactic": ("tac", "TA0003", "https://attack.mitre.org/tactics/TA0003"),
    "Campaign": ("c", "C0024", "https://attack.mitre.org/campaigns/C0024"),
    "DetectionStrategy": (
        "ds",
        "DET0094",
        "https://attack.mitre.org/detectionstrategies/DET0094",
    ),
    "Analytic": (
        "an",
        "AN0110",
        "https://attack.mitre.org/detectionstrategies/DET0039#AN0110",
    ),
    "DataComponent": (
        "dc",
        "DC0008",
        "https://attack.mitre.org/datacomponents/DC0008",
    ),
    "Other": ("n", "DS0001", "https://attack.mitre.org/datasources/DS0001"),
}


class GraphTraversalUrlTests(unittest.TestCase):
    def test_every_node_type_query_returns_its_stored_url(self) -> None:
        driver = _Driver()

        for node_type, (alias, external_id, expected_url) in TRAVERSAL_CASES.items():
            captured_queries: list[str] = []

            def fake_run_query(_session: object, cypher: str, **_parameters: object):
                captured_queries.append(cypher)
                return _SingleRecordResult(
                    {"name": node_type, "id": external_id, "url": expected_url}
                )

            with self.subTest(node_type=node_type), mock.patch.object(
                graph_traversal, "run_query", side_effect=fake_run_query
            ):
                result = graph_traversal.traverse_node(driver, "stix-id", node_type)

                self.assertEqual(result["url"], expected_url)
                self.assertEqual(len(captured_queries), 1)
                self.assertIn(f"{alias}.external_id as id", captured_queries[0])
                self.assertIn(f"{alias}.url as url", captured_queries[0])

    def test_authoritative_regression_url_shapes_are_preserved_exactly(self) -> None:
        expected = {
            "T1566.001": "https://attack.mitre.org/techniques/T1566/001",
            "C0024": "https://attack.mitre.org/campaigns/C0024",
            "M1024": "https://attack.mitre.org/mitigations/M1024",
            "DET0094": "https://attack.mitre.org/detectionstrategies/DET0094",
            "DC0008": "https://attack.mitre.org/datacomponents/DC0008",
            "AN0110": "https://attack.mitre.org/detectionstrategies/DET0039#AN0110",
        }
        actual = {external_id: url for _, external_id, url in TRAVERSAL_CASES.values()}

        for external_id, url in expected.items():
            with self.subTest(external_id=external_id):
                self.assertEqual(actual[external_id], url)
                self.assertFalse(url.endswith("/"))
        self.assertNotIn("/analytics/", actual["AN0110"])
        self.assertIn("#AN0110", actual["AN0110"])


class PipelineUrlTests(unittest.TestCase):
    def test_run_pipeline_carries_ranked_node_url_into_sources(self) -> None:
        driver = _Driver()
        authoritative_url = "https://attack.mitre.org/techniques/T1566/001"
        context = {
            "id": "attack-pattern--test",
            "name": "Spearphishing Attachment",
            "external_id": "T1566.001",
            "url": authoritative_url,
            "node_type": "Technique",
            "relevance_score": 9.0,
        }

        with (
            mock.patch.object(
                pipeline.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=False),
            ),
            mock.patch.object(pipeline, "guardrail", return_value={"allowed": True}),
            mock.patch.object(pipeline, "is_low_signal_query", return_value=False),
            mock.patch.object(pipeline, "get_driver", return_value=driver),
            mock.patch.object(pipeline, "explicit_ids_exist", return_value=True),
            mock.patch.object(pipeline, "extract_filters", return_value={}),
            mock.patch.object(pipeline, "fetch_telemetry_seed_nodes", return_value=[]),
            mock.patch.object(pipeline, "fetch_filter_seed_nodes", return_value=[]),
            mock.patch.object(
                pipeline,
                "search",
                return_value=[{"id": context["id"], "type": "Technique"}],
            ),
            mock.patch.object(pipeline, "traverse_nodes", return_value=[context]),
            mock.patch.object(pipeline, "rerank", return_value=[context]),
            mock.patch.object(
                pipeline,
                "generate",
                return_value="Spearphishing Attachment is T1566.001.",
            ),
        ):
            result = pipeline.run_pipeline("Explain spearphishing attachments")

        self.assertEqual(len(result.sources), 1)
        self.assertEqual(result.sources[0].url, authoritative_url)
        self.assertTrue(driver.closed)

    def test_log_analysis_source_also_carries_traversed_url(self) -> None:
        authoritative_url = "https://attack.mitre.org/techniques/T1033"
        match = SimpleNamespace(
            technique_name="System Owner/User Discovery",
            matched_line="whoami.exe /all",
            confidence="high",
        )
        context = {
            "name": match.technique_name,
            "external_id": "T1033",
            "url": authoritative_url,
            "node_type": "Technique",
        }

        with (
            mock.patch.object(pipeline, "parse_log", return_value=[object()]),
            mock.patch.object(pipeline, "analyze_log_evidence", return_value=[match]),
            mock.patch.object(
                pipeline,
                "fetch_nodes_by_names",
                return_value=[{"id": "attack-pattern--test", "type": "Technique"}],
            ),
            mock.patch.object(pipeline, "traverse_nodes", return_value=[context]),
            mock.patch.object(pipeline, "format_log_analysis_answer", return_value="T1033"),
        ):
            result = pipeline.run_log_analysis_pipeline("raw log", _Driver(), "windows")

        self.assertEqual(result.sources[0].url, authoritative_url)


class ApiUrlTests(unittest.TestCase):
    def test_query_response_serializes_source_url_in_nodes_and_sources(self) -> None:
        authoritative_url = "https://attack.mitre.org/detectionstrategies/DET0039#AN0110"
        source = pipeline.Source(
            name="Analytic for test",
            external_id="AN0110",
            url=authoritative_url,
            node_type="Analytic",
            relevance_score=10.0,
        )
        pipeline_result = pipeline.PipelineResult(
            query="Explain AN0110",
            answer="AN0110 detects the behavior.",
            allowed=True,
            guardrail_category=None,
            filters={},
            sources=[source],
            retrieved_count=1,
            context_count=1,
        )
        request = Request({"type": "http", "method": "POST", "path": "/query", "headers": []})
        payload = api_app.QueryRequest(query=pipeline_result.query)
        endpoint = inspect.unwrap(api_app.query)

        with (
            mock.patch.object(api_app, "run_pipeline", return_value=pipeline_result),
            mock.patch.object(api_app, "grounded_mitre_ids", return_value=["AN0110"]),
        ):
            response = asyncio.run(endpoint(request, payload))

        self.assertEqual(response.nodes[0].url, authoritative_url)
        self.assertEqual(response.sources[0].url, authoritative_url)
        self.assertEqual(response.model_dump()["nodes"][0]["url"], authoritative_url)


class FrontendAuthoritativeUrlContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.types_source = (ROOT / "frontend/src/lib/types.ts").read_text(encoding="utf-8")
        cls.markdown_source = (
            ROOT / "frontend/src/components/chat/MarkdownMessage.tsx"
        ).read_text(encoding="utf-8")
        cls.mitre_id_source = (
            ROOT / "frontend/src/components/chat/MitreId.tsx"
        ).read_text(encoding="utf-8")
        cls.mitre_source = (ROOT / "frontend/src/lib/mitre.ts").read_text(encoding="utf-8")
        cls.bubble_source = (
            ROOT / "frontend/src/components/chat/MessageBubble.tsx"
        ).read_text(encoding="utf-8")

    def test_node_url_map_is_uppercase_and_authoritative_url_precedes_fallback(self) -> None:
        self.assertIn("url: string | null;", self.types_source)
        self.assertIn("nodes={message.nodes}", self.bubble_source)
        self.assertIn("urls.set(node.external_id.toUpperCase(), node.url)", self.markdown_source)

        citation_function = self.markdown_source[
            self.markdown_source.index("function makeCitationLink"):
            self.markdown_source.index("const baseComponents")
        ]
        grounding_gate = citation_function.index("grounded.has(id)")
        authoritative_then_fallback = citation_function.index(
            "authoritativeId ? nodeUrls.get(authoritativeId) : mitreCitationUrl(href)"
        )
        self.assertLess(grounding_gate, authoritative_then_fallback)

    def test_analytic_links_only_when_an_authoritative_node_url_is_available(self) -> None:
        self.assertIn("authoritativeUrl || mitreUrl(id)", self.mitre_id_source)
        self.assertIn(
            "authoritativeUrl={nodeUrls.get(id.toUpperCase())}",
            self.markdown_source,
        )
        self.assertIn("const hrefIds = extractMitreIds(href)", self.markdown_source)
        self.assertIn("[...hrefIds].reverse().find", self.markdown_source)
        prefix_path = self.mitre_source[
            self.mitre_source.index("const PREFIX_PATH"):
            self.mitre_source.index("export function mitreUrl")
        ]
        self.assertNotIn("AN:", prefix_path)

    def test_visible_citation_badge_and_chip_labels_are_unchanged(self) -> None:
        self.assertIn(">\n          cite ↗\n        </a>", self.markdown_source)
        self.assertIn("href={cite}", self.markdown_source)
        self.assertNotIn(">{cite}<", self.markdown_source)
        self.assertIn("{id}", self.mitre_id_source)


if __name__ == "__main__":
    unittest.main()
