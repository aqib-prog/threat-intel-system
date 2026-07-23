from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from orchestration import pipeline  # noqa: E402


class _Driver:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


CONTEXT = {
    "id": "attack-pattern--valid-accounts",
    "name": "Valid Accounts",
    "external_id": "T1078",
    "url": "https://attack.mitre.org/techniques/T1078",
    "node_type": "Technique",
    "description": (
        "Adversaries may obtain and abuse credentials of existing accounts "
        "as a means of gaining access."
    ),
    "tactics": ["Initial Access", "Persistence"],
    "mitigations": ["Multi-factor Authentication"],
    "relevance_score": 9.0,
}


class PipelineRetrievedContextTests(unittest.TestCase):
    def run_success(
        self,
        *,
        include_contexts: bool | None,
        generated_answer: str = "Valid Accounts is mitigated by Multi-factor Authentication.",
    ) -> pipeline.PipelineResult:
        driver = _Driver()
        kwargs = {} if include_contexts is None else {"include_contexts": include_contexts}
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
            mock.patch.object(
                pipeline, "has_unresolved_explicit_id", return_value=False
            ),
            mock.patch.object(pipeline, "fetch_telemetry_seed_nodes", return_value=[]),
            mock.patch.object(pipeline, "fetch_filter_seed_nodes", return_value=[]),
            mock.patch.object(
                pipeline,
                "search",
                return_value=[{"id": CONTEXT["id"], "type": "Technique"}],
            ),
            mock.patch.object(pipeline, "traverse_nodes", return_value=[CONTEXT]),
            mock.patch.object(pipeline, "rerank", return_value=[CONTEXT]),
            mock.patch.object(pipeline, "generate", return_value=generated_answer),
        ):
            result = pipeline.run_pipeline("What mitigates T1078?", **kwargs)
        self.assertTrue(driver.closed)
        return result

    def test_default_and_explicit_false_preserve_every_legacy_field(self) -> None:
        implicit = self.run_success(include_contexts=None)
        explicit = self.run_success(include_contexts=False)

        self.assertEqual(implicit.to_dict(), explicit.to_dict())
        self.assertEqual(implicit.retrieved_contexts, [])

        legacy = implicit.to_dict()
        legacy.pop("retrieved_contexts")
        actual = json.dumps(
            legacy, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        expected = json.dumps(
            {
                "query": "What mitigates T1078?",
                "answer": "Valid Accounts is mitigated by Multi-factor Authentication.",
                "allowed": True,
                "guardrail_category": None,
                "filters": {},
                "sources": [
                    {
                        "name": "Valid Accounts",
                        "external_id": "T1078",
                        "node_type": "Technique",
                        "relevance_score": 9.0,
                        "url": "https://attack.mitre.org/techniques/T1078",
                    }
                ],
                "retrieved_count": 1,
                "context_count": 1,
                "answer_source": "rag",
                "log_evidence": [],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(actual, expected)

    def test_default_false_does_not_format_or_export_contexts(self) -> None:
        with mock.patch.object(
            pipeline,
            "format_context",
            side_effect=AssertionError("format_context must not run without opt-in"),
        ):
            result = self.run_success(include_contexts=False)
        self.assertEqual(result.retrieved_contexts, [])

    def test_opt_in_exports_real_description_and_relationship_facts(self) -> None:
        result = self.run_success(include_contexts=True)

        self.assertEqual(len(result.retrieved_contexts), 1)
        context = result.retrieved_contexts[0]
        self.assertIn("Adversaries may obtain and abuse credentials", context)
        self.assertIn("Mitigations: Multi-factor Authentication", context)
        self.assertIn("Tactics: Initial Access, Persistence", context)

    def test_opt_in_keeps_context_used_even_when_generation_returns_fallback(self) -> None:
        result = self.run_success(
            include_contexts=True,
            generated_answer=pipeline.FALLBACK,
        )

        self.assertEqual(result.sources, [])
        self.assertEqual(len(result.retrieved_contexts), 1)
        self.assertIn("Valid Accounts", result.retrieved_contexts[0])

    def _run_main_path(
        self,
        *,
        explicit_ids_exist: bool = True,
        ambiguous: bool = False,
        unresolved: bool = False,
        retrieved: list[dict] | None = None,
        contexts: list[dict] | None = None,
        ranked: list[dict] | None = None,
    ) -> pipeline.PipelineResult:
        driver = _Driver()
        retrieved = (
            [{"id": CONTEXT["id"], "type": "Technique"}]
            if retrieved is None
            else retrieved
        )
        contexts = [CONTEXT] if contexts is None else contexts
        ranked = [CONTEXT] if ranked is None else ranked
        with (
            mock.patch.object(
                pipeline.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=False),
            ),
            mock.patch.object(pipeline, "guardrail", return_value={"allowed": True}),
            mock.patch.object(pipeline, "is_low_signal_query", return_value=False),
            mock.patch.object(pipeline, "get_driver", return_value=driver),
            mock.patch.object(
                pipeline, "explicit_ids_exist", return_value=explicit_ids_exist
            ),
            mock.patch.object(pipeline, "extract_filters", return_value={}),
            mock.patch.object(
                pipeline, "is_ambiguous_short_reference", return_value=ambiguous
            ),
            mock.patch.object(
                pipeline, "has_unresolved_explicit_id", return_value=unresolved
            ),
            mock.patch.object(pipeline, "fetch_telemetry_seed_nodes", return_value=[]),
            mock.patch.object(pipeline, "fetch_filter_seed_nodes", return_value=[]),
            mock.patch.object(pipeline, "search", return_value=retrieved),
            mock.patch.object(pipeline, "traverse_nodes", return_value=contexts),
            mock.patch.object(pipeline, "rerank", return_value=ranked),
            mock.patch.object(pipeline, "generate", return_value="answer"),
        ):
            result = pipeline.run_pipeline(
                "Explain Valid Accounts", include_contexts=True
            )
        self.assertTrue(driver.closed)
        return result

    def test_every_rag_early_return_has_an_empty_context_list(self) -> None:
        immediate_results = [
            pipeline.run_pipeline("", include_contexts=True),
            pipeline.run_pipeline("How many techniques exist?", include_contexts=True),
        ]
        for result in immediate_results:
            self.assertEqual(result.retrieved_contexts, [])

        with (
            mock.patch.object(
                pipeline.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=False),
            ),
            mock.patch.object(
                pipeline, "guardrail", return_value={"allowed": False, "category": "blocked"}
            ),
        ):
            blocked = pipeline.run_pipeline("blocked query", include_contexts=True)
        self.assertEqual(blocked.retrieved_contexts, [])

        with (
            mock.patch.object(
                pipeline.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=False),
            ),
            mock.patch.object(pipeline, "guardrail", return_value={"allowed": True}),
            mock.patch.object(pipeline, "is_low_signal_query", return_value=True),
        ):
            low_signal = pipeline.run_pipeline("low signal", include_contexts=True)
        self.assertEqual(low_signal.retrieved_contexts, [])

        staged_results = {
            "unresolved_explicit_id": self._run_main_path(explicit_ids_exist=False),
            "ambiguous_reference": self._run_main_path(ambiguous=True),
            "unresolved_filter_id": self._run_main_path(unresolved=True),
            "no_retrieved_nodes": self._run_main_path(retrieved=[]),
            "no_graph_context": self._run_main_path(contexts=[]),
            "no_ranked_context": self._run_main_path(ranked=[]),
            "low_relevance": self._run_main_path(
                ranked=[{**CONTEXT, "relevance_score": 0.1}]
            ),
        }
        for stage, result in staged_results.items():
            with self.subTest(stage=stage):
                self.assertIsInstance(result.retrieved_contexts, list)
                self.assertEqual(result.retrieved_contexts, [])

    def test_raw_log_guardrail_early_returns_have_empty_context_lists(self) -> None:
        raw = SimpleNamespace(is_raw_log=True, platform="windows")
        with (
            mock.patch.object(pipeline.log_analysis_detector, "detect", return_value=raw),
            mock.patch.object(
                pipeline, "check_blacklist", return_value={"allowed": False, "category": "blocked"}
            ),
        ):
            blacklist = pipeline.run_pipeline("raw log", include_contexts=True)
        self.assertEqual(blacklist.retrieved_contexts, [])

        with (
            mock.patch.object(pipeline.log_analysis_detector, "detect", return_value=raw),
            mock.patch.object(pipeline, "check_blacklist", return_value={"allowed": True}),
            mock.patch.object(pipeline, "check_llm_guardrail", return_value={"allowed": False}),
        ):
            harm = pipeline.run_pipeline("raw log", include_contexts=True)
        self.assertEqual(harm.retrieved_contexts, [])

    def test_raw_log_branch_forwards_the_context_opt_in(self) -> None:
        raw = SimpleNamespace(is_raw_log=True, platform="windows")
        driver = _Driver()
        expected = pipeline.fallback_result("raw log")
        expected.retrieved_contexts = ["full log-analysis context"]
        with (
            mock.patch.object(pipeline.log_analysis_detector, "detect", return_value=raw),
            mock.patch.object(pipeline, "check_blacklist", return_value={"allowed": True}),
            mock.patch.object(pipeline, "check_llm_guardrail", return_value={"allowed": True}),
            mock.patch.object(pipeline, "get_driver", return_value=driver),
            mock.patch.object(
                pipeline,
                "run_log_analysis_pipeline",
                return_value=expected,
            ) as run_log_analysis,
        ):
            result = pipeline.run_pipeline("raw log", include_contexts=True)

        run_log_analysis.assert_called_once_with(
            "raw log", driver, "windows", include_contexts=True
        )
        self.assertEqual(result.retrieved_contexts, ["full log-analysis context"])
        self.assertTrue(driver.closed)

    def test_log_analysis_early_returns_and_success_are_well_formed(self) -> None:
        match = SimpleNamespace(
            technique_name="System Owner/User Discovery",
            matched_line="whoami.exe /all",
            reason="The command enumerates the current user.",
            confidence="high",
        )
        node = {
            "id": "attack-pattern--system-owner-user-discovery",
            "name": match.technique_name,
            "external_id": "T1033",
            "node_type": "Technique",
            "description": "Adversaries may attempt to identify the primary user.",
            "tactics": ["Discovery"],
        }

        with (
            mock.patch.object(pipeline, "parse_log", return_value=[object()]),
            mock.patch.object(pipeline, "analyze_log_evidence", return_value=[]),
        ):
            no_matches = pipeline.run_log_analysis_pipeline(
                "raw log", _Driver(), "windows", include_contexts=True
            )
        self.assertEqual(no_matches.retrieved_contexts, [])

        with (
            mock.patch.object(pipeline, "parse_log", return_value=[object()]),
            mock.patch.object(pipeline, "analyze_log_evidence", return_value=[match]),
            mock.patch.object(pipeline, "fetch_nodes_by_names", return_value=[]),
        ):
            no_seeds = pipeline.run_log_analysis_pipeline(
                "raw log", _Driver(), "windows", include_contexts=True
            )
        self.assertEqual(no_seeds.retrieved_contexts, [])

        with (
            mock.patch.object(pipeline, "parse_log", return_value=[object()]),
            mock.patch.object(pipeline, "analyze_log_evidence", return_value=[match]),
            mock.patch.object(
                pipeline,
                "fetch_nodes_by_names",
                return_value=[{"id": node["id"], "type": "Technique"}],
            ),
            mock.patch.object(pipeline, "traverse_nodes", return_value=[]),
        ):
            no_graph_context = pipeline.run_log_analysis_pipeline(
                "raw log", _Driver(), "windows", include_contexts=True
            )
        self.assertEqual(no_graph_context.retrieved_contexts, [])

        with (
            mock.patch.object(pipeline, "parse_log", return_value=[object()]),
            mock.patch.object(pipeline, "analyze_log_evidence", return_value=[match]),
            mock.patch.object(
                pipeline,
                "fetch_nodes_by_names",
                return_value=[{"id": node["id"], "type": "Technique"}],
            ),
            mock.patch.object(pipeline, "traverse_nodes", return_value=[node]),
            mock.patch.object(
                pipeline, "format_log_analysis_answer", return_value="T1033"
            ),
        ):
            success = pipeline.run_log_analysis_pipeline(
                "raw log", _Driver(), "windows", include_contexts=True
            )
        self.assertEqual(len(success.retrieved_contexts), 1)
        self.assertIn("identify the primary user", success.retrieved_contexts[0])
        self.assertIn("Matched Line: whoami.exe /all", success.retrieved_contexts[0])
        self.assertIn("Match Reason: The command enumerates", success.retrieved_contexts[0])


if __name__ == "__main__":
    unittest.main()
