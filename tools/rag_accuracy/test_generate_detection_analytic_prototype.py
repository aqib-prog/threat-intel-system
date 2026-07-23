from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
GENERATOR_PATH = HERE / "generate_detection_analytic_prototype.py"
PROTOTYPE_PATH = HERE / "golden_set_detection_analytic_prototype.json"
FULL_PATH = HERE / "golden_set_detection_analytic.json"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_detection_analytic", GENERATOR_PATH
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


class DetectionAnalyticExtractionTests(unittest.TestCase):
    def setUp(self):
        self.linked = {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--linked",
            "name": "Linked Analytic",
            "external_references": external("AN0001"),
            "x_mitre_platforms": ["Linux", "Linux"],
        }
        self.orphan = {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--orphan",
            "name": "Orphan Analytic",
            "external_references": external("AN0002"),
            "x_mitre_platforms": ["Windows"],
        }
        self.strategy = {
            "type": "x-mitre-detection-strategy",
            "id": "x-mitre-detection-strategy--one",
            "name": "Example Strategy",
            "external_references": external("DET0001"),
            "x_mitre_analytic_refs": [self.linked["id"]],
        }

    def test_extracts_embedded_link_parent_orphan_and_linux_property(self):
        extracted = module.extract_detection_analytic_scope(
            {"type": "bundle", "objects": [self.strategy, self.linked, self.orphan]}
        )
        self.assertEqual(
            extracted["paths"],
            [
                {
                    "detection_strategy_ref": self.strategy["id"],
                    "detection_strategy_external_id": "DET0001",
                    "analytic_ref": self.linked["id"],
                    "analytic_external_id": "AN0001",
                    "source_field": "x_mitre_analytic_refs",
                    "source_field_index": 0,
                }
            ],
        )
        self.assertEqual(
            [item["external_id"] for item in extracted["orphans"]], ["AN0002"]
        )
        self.assertEqual(
            extracted["global_coverage"],
            {
                "active_detection_strategy_count": 1,
                "active_analytic_count": 2,
                "active_strategy_analytic_link_count": 1,
                "active_linked_analytic_count": 1,
                "active_orphan_analytic_count": 1,
                "analytics_with_multiple_parents": 0,
                "strategies_with_one_or_more_analytics": 1,
                "strategies_with_zero_analytics": 0,
                "strategies_with_one_or_more_linux_analytics": 1,
                "strategies_with_zero_linux_analytics": 0,
                "linux_strategy_analytic_link_count": 1,
            },
        )
        linked = module.analytic_catalog(extracted)["AN0001"]
        self.assertEqual(linked["platforms"], ["Linux"])

    def test_rejects_one_analytic_referenced_by_two_strategies(self):
        second = {
            **self.strategy,
            "id": "x-mitre-detection-strategy--two",
            "name": "Second Strategy",
            "external_references": external("DET0002"),
        }
        with self.assertRaises(module.DetectionAnalyticParserError):
            module.extract_detection_analytic_scope(
                {
                    "type": "bundle",
                    "objects": [self.strategy, second, self.linked, self.orphan],
                }
            )

    def test_rejects_duplicate_embedded_analytic_reference(self):
        strategy = {
            **self.strategy,
            "x_mitre_analytic_refs": [self.linked["id"], self.linked["id"]],
        }
        with self.assertRaises(module.DetectionAnalyticParserError):
            module.extract_detection_analytic_scope(
                {"type": "bundle", "objects": [strategy, self.linked]}
            )

    def test_negative_constructor_rejects_real_link(self):
        extracted = module.extract_detection_analytic_scope(
            {"type": "bundle", "objects": [self.strategy, self.linked, self.orphan]}
        )
        source = {
            "repository": "repo",
            "commit": "commit",
            "path": "bundle.json",
            "sha256": "hash",
        }
        with self.assertRaises(module.DetectionAnalyticParserError):
            module.negative_relationship_pair(
                extracted["strategies"][0],
                module.analytic_catalog(extracted)["AN0001"],
                extracted,
                source,
            )

    def test_orphan_constructor_rejects_linked_analytic(self):
        extracted = module.extract_detection_analytic_scope(
            {"type": "bundle", "objects": [self.strategy, self.linked, self.orphan]}
        )
        source = {
            "repository": "repo",
            "commit": "commit",
            "path": "bundle.json",
            "sha256": "hash",
        }
        with self.assertRaises(module.DetectionAnalyticParserError):
            module.orphan_parent_identification_pair(
                module.analytic_catalog(extracted)["AN0001"], extracted, source
            )


class DetectionAnalyticPrototypeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(PROTOTYPE_PATH.read_text())
        cls.pairs = cls.artifact["pairs"]

    def test_schema_and_all_adapted_intent_families(self):
        self.assertEqual(self.artifact["schema_version"], "1.0")
        self.assertEqual(
            self.artifact["scope"]["relationship_type"],
            "x_mitre_analytic_refs",
        )
        selection = self.artifact["selection"]
        self.assertEqual(selection["pair_count"], 30)
        self.assertEqual(selection["linked_parent_identification_pairs"], 5)
        self.assertEqual(selection["orphan_parent_identification_pairs"], 5)
        self.assertEqual(selection["strategy_aggregate_pairs"], 5)
        self.assertEqual(selection["positive_relationship_pairs"], 5)
        self.assertEqual(selection["negative_relationship_pairs"], 5)
        self.assertEqual(selection["platform_constrained_pairs"], 5)
        self.assertEqual(
            {pair["case_type"] for pair in self.pairs},
            {
                "identify_analytic_detection_strategy",
                "identify_analytic_no_detection_strategy",
                "aggregate_detection_strategy_analytics",
                "positive_detection_strategy_analytic_relationship",
                "negative_detection_strategy_analytic_relationship",
                "aggregate_detection_strategy_platform_analytics",
                "aggregate_detection_strategy_no_platform_analytics",
            },
        )

    def test_an0110_parent_is_det0039(self):
        pair = next(
            pair
            for pair in self.pairs
            if pair["case_type"] == "identify_analytic_detection_strategy"
            and pair["analytic"]["external_id"] == "AN0110"
        )
        self.assertEqual(
            pair["expected_detection_strategy"]["external_id"], "DET0039"
        )
        self.assertEqual(len(pair["provenance"]["strategy_analytic_paths"]), 1)
        self.assertEqual(
            pair["provenance"]["strategy_analytic_paths"][0]["source_field"],
            "x_mitre_analytic_refs",
        )

    def test_prototype_orphans_are_deterministic_and_explicit(self):
        self.assertEqual(
            self.artifact["selection"]["orphan_sample_external_ids"],
            ["AN0667", "AN0670", "AN0888", "AN0891", "AN0894"],
        )
        pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "identify_analytic_no_detection_strategy"
        ]
        self.assertEqual(len(pairs), 5)
        for pair in pairs:
            self.assertIsNone(pair["expected_detection_strategy"])
            self.assertEqual(pair["provenance"]["strategy_analytic_paths"], [])

    def test_linux_filter_uses_child_analytic_platforms(self):
        pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"]
            in {
                "aggregate_detection_strategy_platform_analytics",
                "aggregate_detection_strategy_no_platform_analytics",
            }
        ]
        self.assertEqual(len(pairs), 5)
        for pair in pairs:
            self.assertEqual(
                pair["provenance"]["platform_applies_to"], "child_analytic"
            )
            self.assertTrue(
                all("Linux" in item["platforms"] for item in pair["expected_analytics"])
            )

    def test_prototype_negatives_are_graph_verified(self):
        path_keys = {
            (path["detection_strategy_ref"], path["analytic_ref"])
            for row in self.artifact["parsed_data"]["detection_strategies"].values()
            for path in row["strategy_analytic_paths"]
        }
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"]
            == "negative_detection_strategy_analytic_relationship"
        ]
        self.assertEqual(len(negatives), 5)
        for pair in negatives:
            key = (
                pair["detection_strategy"]["stix_id"],
                pair["candidate_analytic"]["stix_id"],
            )
            self.assertNotIn(key, path_keys)
            self.assertFalse(pair["relationship_exists"])
            self.assertEqual(pair["provenance"]["strategy_analytic_paths"], [])


class DetectionAnalyticFullArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(FULL_PATH.read_text())
        cls.pairs = cls.artifact["pairs"]

    def test_real_snapshot_counts_and_total_case_count(self):
        self.assertEqual(
            self.artifact["global_coverage"],
            {
                "active_detection_strategy_count": 697,
                "active_analytic_count": 1758,
                "active_strategy_analytic_link_count": 1745,
                "active_linked_analytic_count": 1745,
                "active_orphan_analytic_count": 13,
                "analytics_with_multiple_parents": 0,
                "strategies_with_one_or_more_analytics": 697,
                "strategies_with_zero_analytics": 0,
                "strategies_with_one_or_more_linux_analytics": 356,
                "strategies_with_zero_linux_analytics": 341,
                "linux_strategy_analytic_link_count": 356,
            },
        )
        selection = self.artifact["selection"]
        self.assertEqual(selection["pair_count"], 3981)
        self.assertEqual(len(self.pairs), 3981)
        self.assertEqual(selection["embedded_parent_identification_fact_count"], 1745)
        self.assertEqual(selection["embedded_strategy_aggregate_fact_count"], 1745)
        self.assertEqual(selection["embedded_platform_constrained_fact_count"], 356)

    def test_parent_lookup_is_exhaustive_for_links_and_samples_orphans(self):
        linked = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "identify_analytic_detection_strategy"
        ]
        orphans = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "identify_analytic_no_detection_strategy"
        ]
        self.assertEqual(len(linked), 1745)
        self.assertEqual(len({pair["analytic"]["external_id"] for pair in linked}), 1745)
        self.assertEqual(len(orphans), 5)
        self.assertEqual(
            [pair["analytic"]["external_id"] for pair in orphans],
            self.artifact["orphan_selection"]["selected_external_ids"],
        )
        self.assertIn("evenly spaced", self.artifact["scope"]["orphan_sampling_note"])

    def test_strategy_aggregates_are_exhaustive(self):
        pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_detection_strategy_analytics"
        ]
        self.assertEqual(len(pairs), 697)
        self.assertEqual(
            len({pair["detection_strategy"]["external_id"] for pair in pairs}),
            697,
        )
        self.assertEqual(sum(len(pair["expected_analytics"]) for pair in pairs), 1745)

    def test_boolean_cases_have_full_strategy_coverage_and_target_ratio(self):
        positives = [
            pair
            for pair in self.pairs
            if pair["case_type"]
            == "positive_detection_strategy_analytic_relationship"
        ]
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"]
            == "negative_detection_strategy_analytic_relationship"
        ]
        self.assertEqual(len(positives), 697)
        self.assertEqual(
            len({pair["detection_strategy"]["external_id"] for pair in positives}),
            697,
        )
        self.assertEqual(len(negatives), 140)
        ratio = self.artifact["selection"]["explicit_boolean_negative_ratio"]
        self.assertAlmostEqual(ratio, 140 / 837)
        self.assertGreaterEqual(ratio, 0.15)
        self.assertLessEqual(ratio, 0.20)
        path_keys = {
            (path["detection_strategy_ref"], path["analytic_ref"])
            for row in self.artifact["parsed_data"]["detection_strategies"].values()
            for path in row["strategy_analytic_paths"]
        }
        for pair in negatives:
            self.assertNotIn(
                (
                    pair["detection_strategy"]["stix_id"],
                    pair["candidate_analytic"]["stix_id"],
                ),
                path_keys,
            )

    def test_linux_filter_is_exhaustive_across_all_strategies(self):
        pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"]
            in {
                "aggregate_detection_strategy_platform_analytics",
                "aggregate_detection_strategy_no_platform_analytics",
            }
        ]
        self.assertEqual(len(pairs), 697)
        self.assertEqual(sum(bool(pair["expected_analytics"]) for pair in pairs), 356)
        self.assertEqual(sum(not pair["expected_analytics"] for pair in pairs), 341)
        self.assertEqual(sum(len(pair["expected_analytics"]) for pair in pairs), 356)
        for pair in pairs:
            self.assertTrue(
                all("Linux" in item["platforms"] for item in pair["expected_analytics"])
            )

    def test_every_pair_has_exact_pinned_embedded_link_provenance(self):
        source = self.artifact["source"]
        self.assertEqual(
            source["commit"], "a6c366439edee3a87b79cf90dc0b93f5d7975956"
        )
        self.assertEqual(
            source["sha256"],
            "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3",
        )
        for pair in self.pairs:
            provenance = pair["provenance"]
            self.assertEqual(provenance["source_commit"], source["commit"])
            self.assertEqual(provenance["source_bundle_sha256"], source["sha256"])
            self.assertEqual(
                provenance["source_field"],
                "x-mitre-detection-strategy.x_mitre_analytic_refs",
            )
            for path in provenance["strategy_analytic_paths"]:
                self.assertEqual(path["source_field"], "x_mitre_analytic_refs")


class DetectionAnalyticNoLlmTests(unittest.TestCase):
    def test_generator_has_no_llm_or_network_client_imports(self):
        source = GENERATOR_PATH.read_text().lower()
        for forbidden in (
            "import ollama",
            "from ollama",
            "import openai",
            "from openai",
            "langchain",
            "requests.",
            "httpx.",
        ):
            self.assertNotIn(forbidden, source)

    def test_answers_are_materialized_strings_not_runtime_prompts(self):
        for artifact_path in (PROTOTYPE_PATH, FULL_PATH):
            artifact = json.loads(artifact_path.read_text())
            self.assertTrue(artifact["pairs"])
            self.assertTrue(
                all(isinstance(pair["question"], str) for pair in artifact["pairs"])
            )
            self.assertTrue(
                all(
                    isinstance(pair["expected_answer"], str)
                    for pair in artifact["pairs"]
                )
            )


if __name__ == "__main__":
    unittest.main()
