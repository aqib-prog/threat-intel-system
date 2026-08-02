"""Regression tests for reproducible semantic-search planning."""

from __future__ import annotations

import unittest
from unittest import mock

from retrieval import semantic_search


class SemanticSearchDeterminismTests(unittest.TestCase):
    def test_query_expansion_never_calls_a_generative_model(self):
        with mock.patch.object(
            semantic_search.OLLAMA_CLIENT,
            "chat",
            side_effect=AssertionError("generative expansion must not run"),
        ):
            self.assertEqual(
                semantic_search.expand_query(
                    "Investigate Windows Event 4624 network logon"
                ),
                [
                    "Investigate Windows Event 4624 network logon",
                    "Valid Accounts Remote Services Windows logon session authentication",
                ],
            )

    def test_rrf_ties_are_ordered_by_authoritative_id(self):
        results = semantic_search.rrf_fusion(
            [
                {"id": "b", "external_id": "T1002", "score": 0.9},
                {"id": "a", "external_id": "T1001", "score": 0.9},
            ],
            [
                {"id": "a", "external_id": "T1001", "score": 0.9},
                {"id": "b", "external_id": "T1002", "score": 0.9},
            ],
        )
        self.assertEqual(
            [item["external_id"] for item in results],
            ["T1001", "T1002"],
        )


if __name__ == "__main__":
    unittest.main()
