"""Hermetic API-contract regressions for structured suggestion actions."""

from __future__ import annotations

import asyncio
import inspect
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from starlette.requests import Request


BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

os.environ.setdefault("API_KEYS", "test-key")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:5173")
os.environ.setdefault("LANGFUSE_ENABLED", "false")

from api import app as api_app  # noqa: E402
from orchestration import multi_intent, pipeline  # noqa: E402


class QueryResponseSuggestionTests(unittest.TestCase):
    @staticmethod
    def _pipeline_result(query: str, answer: str) -> pipeline.PipelineResult:
        return pipeline.PipelineResult(
            query=query,
            answer=answer,
            allowed=True,
            guardrail_category=None,
            filters={},
            sources=[],
            retrieved_count=0,
            context_count=0,
        )

    def test_exact_suggestion_action_is_serialized_without_changing_label(self):
        action = pipeline.SuggestionAction(
            label="APT2",
            query="Compare APT29 and APT2 techniques",
            original="APT20",
        )
        result = pipeline.PipelineResult(
            query="Compare APT29 and APT20 techniques",
            answer="APT20 is not in the knowledge base.",
            allowed=True,
            guardrail_category=None,
            filters={},
            sources=[],
            retrieved_count=0,
            context_count=0,
            suggestions=[action.label],
            suggestion_actions=[action],
        )
        request = Request(
            {"type": "http", "method": "POST", "path": "/query", "headers": []}
        )
        payload = api_app.QueryRequest(query=result.query)
        endpoint = inspect.unwrap(api_app.query)

        with (
            mock.patch.object(
                api_app,
                "run_multi_pipeline",
                return_value=multi_intent._as_single(result),
            ),
            mock.patch.object(api_app, "grounded_mitre_ids", return_value=[]),
        ):
            response = asyncio.run(endpoint(request, payload))

        self.assertEqual(response.suggestions, ["APT2"])
        self.assertEqual(
            response.suggestion_actions[0].model_dump(),
            {
                "label": "APT2",
                "query": "Compare APT29 and APT2 techniques",
                "original": "APT20",
            },
        )

    def test_answer_presentation_is_serialized_from_backend_sections(self):
        result = pipeline.PipelineResult(
            query="What is APT34?",
            answer=(
                "OilRig (G0049)\n"
                "Description: OilRig is a suspected Iranian threat group.\n\n"
                "Tactics explicitly connected to OilRig:\n"
                "- Execution\n- Persistence\n"
            ),
            allowed=True,
            guardrail_category=None,
            filters={"threat_actor": ["OilRig"]},
            sources=[],
            retrieved_count=1,
            context_count=1,
        )
        request = Request(
            {"type": "http", "method": "POST", "path": "/query", "headers": []}
        )
        payload = api_app.QueryRequest(query=result.query)
        endpoint = inspect.unwrap(api_app.query)

        with (
            mock.patch.object(
                api_app,
                "run_multi_pipeline",
                return_value=multi_intent._as_single(result),
            ),
            mock.patch.object(api_app, "grounded_mitre_ids", return_value=["G0049"]),
        ):
            response = asyncio.run(endpoint(request, payload))

        self.assertIsNotNone(response.answer_presentation)
        self.assertEqual(response.answer_presentation.preamble, "OilRig (G0049)")
        self.assertEqual(
            [block.label for block in response.answer_presentation.blocks],
            ["Description", "Tactics"],
        )
        self.assertEqual(response.answer_sections[0].label, "Tactics")

    def test_mixed_log_segment_identity_is_serialized_authoritatively(self):
        log_result = self._pipeline_result('{"EventID":1}', "Log answer")
        log_result.answer_source = "log_analysis"
        question_result = self._pipeline_result("What is T1055?", "Technique answer")
        segments = [
            multi_intent._answer_segment(
                log_result.query,
                log_result,
                display_title="Log Analysis",
                segment_kind="log_analysis",
            ),
            multi_intent._answer_segment(question_result.query, question_result),
        ]
        result = multi_intent._as_multi(
            f"{log_result.query}\n{question_result.query}",
            segments,
        )
        request = Request(
            {"type": "http", "method": "POST", "path": "/query", "headers": []}
        )
        payload = api_app.QueryRequest(query=result.query)
        endpoint = inspect.unwrap(api_app.query)

        with (
            mock.patch.object(api_app, "run_multi_pipeline", return_value=result),
            mock.patch.object(api_app, "grounded_mitre_ids", return_value=[]),
        ):
            response = asyncio.run(endpoint(request, payload))

        self.assertEqual(len(response.segments), 2)
        self.assertEqual(response.segments[0].display_title, "Log Analysis")
        self.assertEqual(response.segments[0].segment_kind, "log_analysis")
        self.assertEqual(response.segments[1].segment_kind, "question")

    def test_correction_gate_is_offered_only_after_corrected_query_resolves(self):
        original = self._pipeline_result(
            "waht tacktics does APT29 use?",
            api_app.FALLBACK_ERROR,
        )
        corrected = self._pipeline_result(
            "what tactics does APT29 use?",
            "Tactics explicitly connected to APT29:\n- Persistence",
        )
        request = Request(
            {"type": "http", "method": "POST", "path": "/query", "headers": []}
        )
        payload = api_app.QueryRequest(query=original.query)
        endpoint = inspect.unwrap(api_app.query)

        with (
            mock.patch.object(
                api_app,
                "run_multi_pipeline",
                side_effect=[
                    multi_intent._as_single(original),
                    multi_intent._as_single(corrected),
                ],
            ) as run_multi,
            mock.patch.object(
                api_app,
                "normalize_query",
                return_value=corrected.query,
            ),
            mock.patch.object(
                api_app,
                "has_cybersecurity_signal",
                return_value=True,
            ),
            mock.patch.object(api_app, "grounded_mitre_ids", return_value=[]),
        ):
            response = asyncio.run(endpoint(request, payload))

        self.assertEqual(run_multi.call_count, 2)
        self.assertEqual(response.correction.original, original.query)
        self.assertEqual(response.correction.suggested, corrected.query)

    def test_correction_gate_is_not_offered_when_probe_still_has_no_answer(self):
        original = self._pipeline_result(
            "waht tacktics does FAKEGROUP use?",
            api_app.FALLBACK_ERROR,
        )
        corrected = self._pipeline_result(
            "what tactics does FAKEGROUP use?",
            api_app.FALLBACK_ERROR,
        )
        request = Request(
            {"type": "http", "method": "POST", "path": "/query", "headers": []}
        )
        payload = api_app.QueryRequest(query=original.query)
        endpoint = inspect.unwrap(api_app.query)

        with (
            mock.patch.object(
                api_app,
                "run_multi_pipeline",
                side_effect=[
                    multi_intent._as_single(original),
                    multi_intent._as_single(corrected),
                ],
            ),
            mock.patch.object(
                api_app,
                "normalize_query",
                return_value=corrected.query,
            ),
            mock.patch.object(
                api_app,
                "has_cybersecurity_signal",
                return_value=True,
            ),
            mock.patch.object(api_app, "grounded_mitre_ids", return_value=[]),
        ):
            response = asyncio.run(endpoint(request, payload))

        self.assertIsNone(response.correction)

    def test_skip_correction_prevents_probe_and_repeated_gate(self):
        original = self._pipeline_result(
            "waht tacktics does APT29 use?",
            api_app.FALLBACK_ERROR,
        )
        request = Request(
            {"type": "http", "method": "POST", "path": "/query", "headers": []}
        )
        payload = api_app.QueryRequest(
            query=original.query,
            skip_correction=True,
        )
        endpoint = inspect.unwrap(api_app.query)

        with (
            mock.patch.object(
                api_app,
                "run_multi_pipeline",
                return_value=multi_intent._as_single(original),
            ) as run_multi,
            mock.patch.object(api_app, "normalize_query") as normalize,
            mock.patch.object(api_app, "grounded_mitre_ids", return_value=[]),
        ):
            response = asyncio.run(endpoint(request, payload))

        run_multi.assert_called_once()
        normalize.assert_not_called()
        self.assertIsNone(response.correction)


if __name__ == "__main__":
    unittest.main()
