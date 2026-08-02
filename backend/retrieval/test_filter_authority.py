"""Regression tests for authoritative identifiers and conservative name typos."""

from __future__ import annotations

import unittest
from unittest import mock

from rapidfuzz import fuzz

from retrieval import guardrail


class FilterAuthorityTests(unittest.TestCase):
    def test_exact_id_rejects_fuzzy_sibling_id(self):
        with (
            mock.patch.object(guardrail, "ensure_entity_indexes"),
            mock.patch.object(
                guardrail,
                "extract_entities_regex",
                return_value={"mitre_id": ["T1007"]},
            ),
            mock.patch.object(
                guardrail,
                "generate_dynamic_hint_entities",
                return_value={
                    "mitre_id": [
                        {
                            "value": "T1569",
                            "source_text": "System Service Discvoery",
                            "score": 88,
                        }
                    ]
                },
            ),
            mock.patch.object(
                guardrail,
                "validate_all_entities",
                side_effect=lambda entities, _driver, _query: entities,
            ),
        ):
            filters = guardrail.extract_filters(
                "What mitigates T1007 (System Service Discvoery)?",
                object(),
            )
        self.assertEqual(filters["mitre_id"], ["T1007"])

    def test_exact_ids_preserve_other_named_entity_families(self):
        with (
            mock.patch.object(guardrail, "ensure_entity_indexes"),
            mock.patch.object(
                guardrail,
                "extract_entities_regex",
                return_value={"mitre_id": ["T1001"]},
            ),
            mock.patch.object(
                guardrail,
                "generate_dynamic_hint_entities",
                return_value={
                    "mitre_id": [
                        {
                            "value": "T1005",
                            "source_text": "Data Obfuscation",
                            "score": 85,
                        }
                    ],
                    "campaign": [
                        {
                            "value": "Frankenstein",
                            "source_text": "Frankenstein",
                            "score": 100,
                        }
                    ],
                },
            ),
            mock.patch.object(
                guardrail,
                "validate_all_entities",
                side_effect=lambda entities, _driver, _query: entities,
            ),
        ):
            filters = guardrail.extract_filters(
                "Does Frankenstein use T1001?",
                object(),
            )
        self.assertEqual(filters["mitre_id"], ["T1001"])
        self.assertEqual(filters["campaign"], ["Frankenstein"])

    def test_unique_adjacent_transposition_is_confident(self):
        self.assertEqual(
            guardrail.best_entity_match(
                "axoim",
                ["axiom", "apt29"],
                scorer=fuzz.ratio,
                threshold=82,
            ),
            ("axiom", 80.0),
        )

    def test_arbitrary_low_similarity_stays_rejected(self):
        self.assertIsNone(
            guardrail.best_entity_match(
                "axiom",
                ["axion"],
                scorer=fuzz.ratio,
                threshold=82,
            )
        )

    def test_exact_canonical_name_suppresses_overlapping_fuzzy_sibling(self):
        index = {
            "system service discovery": {
                "real_name": "T1007",
                "type": "mitre_id",
            },
            "system services": {
                "real_name": "T1569",
                "type": "mitre_id",
            },
        }
        with (
            mock.patch.object(guardrail, "GLOBAL_INDEX", index),
            mock.patch.object(guardrail, "MITRE_TACTICS", []),
            mock.patch.object(guardrail, "TACTIC_CONTEXT_INDEX", {}),
        ):
            hints = guardrail.extract_database_entity_hints(
                "What measures prevent System Service Discovery?"
            )
        self.assertEqual(
            [item["value"] for item in hints.get("mitre_id", [])],
            ["T1007"],
        )

    def test_internal_entity_punctuation_is_preserved_for_exact_matching(self):
        index = {
            "trojan.mebromi": {
                "real_name": "Trojan.Mebromi",
                "type": "malware",
            },
            "threat group-3390": {
                "real_name": "Threat Group-3390",
                "type": "threat_actor",
            },
        }
        with (
            mock.patch.object(guardrail, "GLOBAL_INDEX", index),
            mock.patch.object(guardrail, "MITRE_TACTICS", []),
            mock.patch.object(guardrail, "TACTIC_CONTEXT_INDEX", {}),
            mock.patch.object(
                guardrail,
                "GENERIC_ENTITY_CATEGORY_WORDS",
                {"trojan", "mebromi", "threat", "group"},
            ),
        ):
            malware = guardrail.extract_database_entity_hints(
                "What techniques does Trojan.Mebromi use?"
            )
            actor = guardrail.extract_database_entity_hints(
                "What techniques does Threat Group-3390 use?"
            )
        self.assertEqual(
            [item["value"] for item in malware.get("malware", [])],
            ["Trojan.Mebromi"],
        )
        self.assertEqual(
            [item["value"] for item in actor.get("threat_actor", [])],
            ["Threat Group-3390"],
        )

    def test_newer_detection_entity_name_is_an_authoritative_hint(self):
        index = {
            "process creation": {
                "real_name": "Process Creation",
                "type": "data_component",
            }
        }
        with (
            mock.patch.object(guardrail, "GLOBAL_INDEX", index),
            mock.patch.object(guardrail, "MITRE_TACTICS", []),
            mock.patch.object(guardrail, "TACTIC_CONTEXT_INDEX", {}),
        ):
            hints = guardrail.extract_database_entity_hints(
                "Quote the MITRE definition for Process Creation."
            )
        self.assertEqual(
            [item["value"] for item in hints.get("data_component", [])],
            ["Process Creation"],
        )


if __name__ == "__main__":
    unittest.main()
