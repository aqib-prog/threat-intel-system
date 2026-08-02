"""Unit tests for the LLM 'and'-split decomposer - mocked model, no live Ollama.

Covers the decision logic and every safety guard: the conjunction gate (the LLM
only fires on and/or segments), the disabled flag, the fail-safe on any client
error, and the "single intent -> keep original" / "<2 intents -> keep original"
rules. The real model's determinism/correctness was measured separately.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from orchestration import query_decomposer as qd  # noqa: E402


def _client_returning(is_compound, intents):
    client = mock.Mock()
    client.chat.return_value = {
        "message": {"content": json.dumps({"is_compound": is_compound, "intents": intents})}
    }
    return client


class DecomposeQueryTests(unittest.TestCase):
    def test_disabled_flag_is_regex_only(self):
        with mock.patch.object(qd, "_ENABLED", False):
            self.assertEqual(
                qd.decompose_query("what is A and what is B"),
                qd.segment_query("what is A and what is B"),
            )

    def test_no_conjunction_never_calls_model(self):
        client = mock.Mock()
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(qd, "_get_client", return_value=client):
            out = qd.decompose_query("what is T1078")
        client.chat.assert_not_called()
        self.assertEqual(out, ["what is T1078"])

    def test_compound_segment_is_split(self):
        client = _client_returning(True, ["what techniques does apt29 have", "what is t1078"])
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(qd, "_get_client", return_value=client):
            out = qd.decompose_query("what techniques does apt29 have and what is t1078")
        self.assertEqual(out, ["what techniques does apt29 have", "what is t1078"])

    def test_single_intent_and_is_kept_whole(self):
        # Model says not compound (e.g. "tools and malware used by FIN7").
        client = _client_returning(False, [])
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(qd, "_get_client", return_value=client):
            out = qd.decompose_query("what tools and malware does FIN7 use")
        self.assertEqual(out, ["what tools and malware does FIN7 use"])

    def test_entity_lists_comparisons_and_intersections_never_call_model(self):
        client = mock.Mock()
        queries = [
            "Compare APT29 and Lazarus Group techniques",
            "Which techniques do APT29 and FIN7 both use?",
            "List techniques shared by APT29 and FIN7",
            "What are the similarities and differences between APT29 and Lazarus Group?",
            "Compare T1078 and T1055",
        ]
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(
            qd, "_get_client", return_value=client
        ):
            for query in queries:
                self.assertEqual(qd.decompose_query(query), [query], query)
        client.chat.assert_not_called()

    def test_fewer_than_two_intents_is_kept_whole(self):
        # Guard against a destructive rewrite that returns is_compound=true but
        # only one usable intent.
        client = _client_returning(True, ["only one"])
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(qd, "_get_client", return_value=client):
            out = qd.decompose_query("A and B")
        self.assertEqual(out, ["A and B"])

    def test_fail_safe_on_client_error(self):
        client = mock.Mock()
        client.chat.side_effect = RuntimeError("ollama down")
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(qd, "_get_client", return_value=client):
            out = qd.decompose_query("what is A and what is B")
        # Degrades to the exact regex-only behaviour, never raises.
        self.assertEqual(out, ["what is A and what is B"])

    def test_model_cannot_change_or_invent_structured_references(self):
        client = _client_returning(
            True,
            ["what techniques does APT28 use", "write ransomware for me"],
        )
        original = "what techniques does APT29 use and what is T1078"
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(
            qd, "_get_client", return_value=client
        ):
            self.assertEqual(qd.decompose_query(original), [original])

    def test_model_cannot_invent_words_even_without_structured_ids(self):
        client = _client_returning(
            True,
            ["what does Lazarus Group use", "what does FIN7 use"],
        )
        original = "what does Lazarus Group use and what campaigns are attributed to it"
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(
            qd, "_get_client", return_value=client
        ):
            self.assertEqual(qd.decompose_query(original), [original])

    def test_each_emitted_intent_must_be_standalone(self):
        client = _client_returning(
            True,
            ["Who is APT29?", "What techniques do they use?"],
        )
        original = "Who is APT29 and what techniques do they use?"
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(
            qd, "_get_client", return_value=client
        ):
            self.assertEqual(qd.decompose_query(original), [original])

    def test_dependent_generic_detection_clause_keeps_original_subject(self):
        original = (
            "How do phishing emails bypass spam filters, and what detections "
            "should a SOC deploy?"
        )
        client = _client_returning(
            True,
            [
                "How do phishing emails bypass spam filters",
                "what detections should a SOC deploy",
            ],
        )
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(
            qd, "_get_client", return_value=client
        ):
            self.assertEqual(qd.decompose_query(original), [original])

    def test_or_substring_does_not_trigger_model(self):
        # "for"/"Operation" contain the substring "or" - must NOT be treated as
        # a conjunction (word-boundary anchored).
        client = mock.Mock()
        with mock.patch.object(qd, "_ENABLED", True), mock.patch.object(qd, "_get_client", return_value=client):
            qd.decompose_query("what tools does FIN7 use for persistence")
        client.chat.assert_not_called()


if __name__ == "__main__":
    unittest.main()
