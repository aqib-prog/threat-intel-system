"""Regression tests for deterministic retrieval on validated entity lookups."""

from __future__ import annotations

import unittest

from orchestration.pipeline import (
    add_named_detection_filters,
    filter_relevant_ranked_nodes,
    focus_ranked_nodes_on_explicit_terms,
    should_resolve_named_detection_entity,
    should_skip_semantic_search,
)


class RetrievalStabilityTests(unittest.TestCase):
    def setUp(self):
        self.seed = [
            {
                "id": "stix-object",
                "name": "Resolved entity",
                "source": "validated_filter",
            }
        ]

    def test_every_validated_entity_family_uses_authoritative_seed_context(self):
        for field, value in (
            ("mitre_id", "T1001"),
            ("malware", "Trojan.Mebromi"),
            ("tool", "Mimikatz"),
            ("campaign", "Frankenstein"),
            ("mitigation", "Software Configuration"),
            ("tactic", "Persistence"),
            ("analytic", "Analytic 0717"),
            ("detection_strategy", "Detection Strategy for Phishing"),
            ("data_component", "Process Creation"),
        ):
            with self.subTest(field=field):
                self.assertTrue(
                    should_skip_semantic_search(
                        "relationship lookup",
                        {field: [value]},
                        self.seed,
                    )
                )

    def test_actor_lookup_uses_seed_unless_platform_relationship_needs_candidates(self):
        self.assertTrue(
            should_skip_semantic_search(
                "What techniques does APT29 use?",
                {"threat_actor": ["APT29"], "node_type": ["Technique"]},
                self.seed,
            )
        )
        self.assertFalse(
            should_skip_semantic_search(
                "What Windows techniques does APT29 use?",
                {
                    "threat_actor": ["APT29"],
                    "platform": ["Windows"],
                    "node_type": ["Technique"],
                },
                self.seed,
            )
        )

    def test_no_validated_seed_still_uses_semantic_search(self):
        self.assertFalse(
            should_skip_semantic_search(
                "Explain credential theft",
                {"node_type": ["Technique"]},
                [],
            )
        )

    def test_telemetry_seed_always_skips_semantic_search(self):
        telemetry_seed = [{"id": "technique", "source": "telemetry_seed"}]
        self.assertTrue(
            should_skip_semantic_search("raw telemetry", {}, telemetry_seed)
        )

    def test_exact_detection_name_seed_is_authoritative_and_typed(self):
        seed = [{
            "name": "Process Creation",
            "type": "DataComponent",
            "source": "exact_detection_name",
        }]
        self.assertTrue(should_skip_semantic_search("definition", {}, seed))
        self.assertEqual(
            add_named_detection_filters({}, seed),
            {"data_component": ["Process Creation"]},
        )
        self.assertTrue(
            should_resolve_named_detection_entity(
                "Quote the data source definition for Process Creation."
            )
        )
        self.assertFalse(
            should_resolve_named_detection_entity("Explain Valid Accounts.")
        )

    def test_every_generated_context_must_clear_relevance_threshold(self):
        nodes = [
            {"external_id": "AN0717", "relevance_score": 3.4},
            {"external_id": "DET9999", "relevance_score": 0.49},
            {"external_id": "T9999", "relevance_score": None},
        ]
        self.assertEqual(
            [node["external_id"] for node in filter_relevant_ranked_nodes(nodes, 0.5)],
            ["AN0717"],
        )

    def test_explicit_api_term_excludes_semantically_related_noise(self):
        nodes = [
            {"external_id": "AN0717", "description": "Unusual AssumeRole API calls"},
            {"external_id": "AN1105", "description": "PassRole and AssumeRole activity"},
            {"external_id": "AN1594", "description": "Cloud object enumeration"},
        ]
        focused = focus_ranked_nodes_on_explicit_terms(
            "Which signals identify anomalous AssumeRole activity?",
            nodes,
        )
        self.assertEqual(
            [node["external_id"] for node in focused],
            ["AN0717", "AN1105"],
        )

    def test_explicit_mixed_case_entity_never_discards_validated_anchors(self):
        nodes = [
            {"external_id": "C0001", "name": "Frankenstein"},
            {"external_id": "S0029", "name": "PsExec"},
        ]
        focused = focus_ranked_nodes_on_explicit_terms(
            "Does C0001 (Frankenstein) use Tool S0029 (PsExec)?",
            nodes,
            has_authoritative_seeds=True,
        )
        self.assertEqual(focused, nodes)


if __name__ == "__main__":
    unittest.main()
