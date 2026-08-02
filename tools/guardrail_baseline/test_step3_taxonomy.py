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


class Step3TaxonomyTests(unittest.TestCase):
    def response(self, content: str):
        return {"message": {"content": content}}

    def test_harm_gate_has_distinct_taxonomy_and_preserves_json_reliability(self):
        query = "Explain how a credential dumping technique works conceptually."
        with patch.object(
            production.OLLAMA_CLIENT,
            "chat",
            return_value=self.response(
                '{"allowed": true, "reason": "Conceptual threat intelligence"}'
            ),
        ) as chat:
            result = production._classify_harm(query)

        self.assertTrue(result["allowed"])
        kwargs = chat.call_args.kwargs
        self.assertEqual(kwargs["format"], "json")
        self.assertEqual(kwargs["options"], {"temperature": 0})
        self.assertEqual([message["role"] for message in kwargs["messages"]], ["system", "user"])
        taxonomy = kwargs["messages"][0]["content"]
        submitted_query = kwargs["messages"][1]["content"]
        for required in (
            "Conceptual explanations of attack techniques",
            "Historical campaigns, threat actors, IOCs, MITRE ATT&CK mappings",
            "Detection engineering",
            "Functional exploit code",
            "Ready-to-run attack payloads",
            "specific real system",
            "Producing or improving an operational capability",
        ):
            self.assertIn(required, taxonomy)
        self.assertNotIn(query, taxonomy)
        self.assertIn(query, submitted_query)

    def test_topic_and_harm_gates_no_longer_share_the_topic_classifier(self):
        topic_verdict = {"allowed": True, "reason": "topic"}
        with patch.object(
            production, "_check_llm_topic_classifier", return_value=topic_verdict
        ) as topic_classifier, patch.object(
            production.OLLAMA_CLIENT,
            "chat",
            return_value=self.response(
                '{"allowed": false, "reason": "Operational offensive uplift"}'
            ),
        ) as chat:
            self.assertIs(
                production.check_llm_topic_guardrail("topic query"), topic_verdict
            )
            harm_verdict = production.check_llm_guardrail("harm query")

        topic_classifier.assert_called_once_with("topic query")
        chat.assert_called_once()
        self.assertFalse(harm_verdict["allowed"])

    def test_harm_gate_preserves_fail_closed_parse_behavior(self):
        invalid_outputs = (
            "I cannot classify that request.",
            "[]",
            '{"allowed": "false"}',
            '{"reason": "missing verdict"}',
        )
        for content in invalid_outputs:
            with self.subTest(content=content), patch.object(
                production.OLLAMA_CLIENT, "chat", return_value=self.response(content)
            ):
                result = production.check_llm_guardrail("test query")
            self.assertEqual(
                result,
                {"allowed": False, "reason": "Could not parse, blocking by default"},
            )

    def test_harm_gate_fails_closed_when_ollama_is_unavailable(self):
        with patch.object(
            production.OLLAMA_CLIENT, "chat", side_effect=RuntimeError("unavailable")
        ):
            result = production.check_llm_guardrail("test query")
        self.assertEqual(
            result,
            {"allowed": False, "reason": "Could not parse, blocking by default"},
        )

    def test_step1_control_flow_functions_are_unchanged(self):
        with patch.object(
            production, "has_cybersecurity_signal", return_value=True
        ), patch.object(production, "check_llm_topic_guardrail") as topic:
            result = production.check_topic_guardrail("query")
        self.assertEqual(result, {"allowed": True, "waived_by_cybersecurity_signal": True})
        topic.assert_not_called()


if __name__ == "__main__":
    unittest.main()
