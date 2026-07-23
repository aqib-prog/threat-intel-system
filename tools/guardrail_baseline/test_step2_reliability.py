from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from retrieval import guardrail as production


class Step2ReliabilityTests(unittest.TestCase):
    def response(self, content: str):
        return {"message": {"content": content}}

    def test_classifier_requests_json_mode_without_changing_taxonomy(self):
        with patch.object(
            production.OLLAMA_CLIENT,
            "chat",
            return_value=self.response('{"allowed": true, "reason": "in scope"}'),
        ) as chat:
            result = production._check_llm_topic_classifier("test query")
        self.assertTrue(result["allowed"])
        kwargs = chat.call_args.kwargs
        self.assertEqual(kwargs["format"], "json")
        self.assertEqual(kwargs["options"], {"temperature": 0})
        prompt = kwargs["messages"][0]["content"]
        self.assertIn("ALWAYS ALLOW if there is even the slightest cybersecurity connection.", prompt)
        self.assertIn("Everything else -> ALLOW", prompt)

    def test_unparseable_output_fails_closed(self):
        with patch.object(
            production.OLLAMA_CLIENT,
            "chat",
            return_value=self.response("I cannot comply with that request."),
        ):
            result = production._check_llm_topic_classifier("test query")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "Could not parse, blocking by default")

    def test_invalid_json_shape_fails_closed(self):
        for content in ('[]', '{"allowed": "true"}', '{"reason": "missing verdict"}'):
            with self.subTest(content=content), patch.object(
                production.OLLAMA_CLIENT, "chat", return_value=self.response(content)
            ):
                result = production._check_llm_topic_classifier("test query")
            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason"], "Could not parse, blocking by default")

    def test_ollama_exception_fails_closed(self):
        with patch.object(
            production.OLLAMA_CLIENT, "chat", side_effect=RuntimeError("local model unavailable")
        ):
            result = production._check_llm_topic_classifier("test query")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "Could not parse, blocking by default")

    def test_topic_gate_still_uses_the_step2_classifier(self):
        verdict = {"allowed": True, "reason": "topic"}
        with patch.object(
            production, "_check_llm_topic_classifier", return_value=verdict
        ) as shared:
            self.assertIs(production.check_llm_topic_guardrail("topic"), verdict)
        shared.assert_called_once_with("topic")


if __name__ == "__main__":
    unittest.main()
