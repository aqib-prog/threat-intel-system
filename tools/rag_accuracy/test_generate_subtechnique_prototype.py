from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
GENERATOR_PATH = HERE / "generate_subtechnique_prototype.py"
PROTOTYPE_PATH = HERE / "golden_set_subtechnique_prototype.json"
FULL_PATH = HERE / "golden_set_subtechnique.json"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_subtechnique", GENERATOR_PATH
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


class SubtechniqueExtractionTests(unittest.TestCase):
    def setUp(self):
        self.parent = {
            "type": "attack-pattern",
            "id": "attack-pattern--parent",
            "name": "Example Parent",
            "external_references": external("T1000"),
            "x_mitre_platforms": ["Linux", "Windows"],
        }
        self.child = {
            "type": "attack-pattern",
            "id": "attack-pattern--child",
            "name": "Example Child",
            "external_references": external("T1000.001"),
            "x_mitre_is_subtechnique": True,
            "x_mitre_platforms": ["Linux", "Linux"],
        }
        self.leaf = {
            "type": "attack-pattern",
            "id": "attack-pattern--leaf",
            "name": "Example Leaf",
            "external_references": external("T1001"),
            "x_mitre_platforms": ["macOS"],
        }
        self.relationship = {
            "type": "relationship",
            "id": "relationship--subtechnique",
            "relationship_type": "subtechnique-of",
            "source_ref": self.child["id"],
            "target_ref": self.parent["id"],
        }

    def test_extracts_active_child_to_parent_and_validates_fixed_cardinality(self):
        bundle = {
            "type": "bundle",
            "objects": [
                self.parent,
                self.child,
                self.leaf,
                self.relationship,
                {
                    **self.relationship,
                    "id": "relationship--revoked",
                    "revoked": True,
                },
                {
                    **self.relationship,
                    "id": "relationship--uses",
                    "relationship_type": "uses",
                },
            ],
        }
        extracted = module.extract_subtechnique_scope(bundle)
        self.assertEqual(extracted["paths"], [{
            "subtechnique_ref": self.child["id"],
            "parent_technique_ref": self.parent["id"],
            "subtechnique_of_relationship_stix_id": self.relationship["id"],
        }])
        self.assertEqual(
            [item["external_id"] for item in extracted["parents"]], ["T1000"]
        )
        self.assertEqual(
            [item["external_id"] for item in extracted["subtechniques"]],
            ["T1000.001"],
        )
        self.assertEqual(
            [item["external_id"] for item in extracted["top_level_leaves"]],
            ["T1001"],
        )
        child = extracted["subtechniques"][0]
        self.assertEqual(child["platforms"], ["Linux"])
        self.assertEqual(
            extracted["global_coverage"],
            {
                "active_technique_count": 3,
                "active_subtechnique_of_edge_count": 1,
                "active_subtechnique_count": 1,
                "active_parent_technique_count": 1,
                "active_top_level_leaf_technique_count": 1,
                "active_nonparent_technique_count": 2,
                "subtechniques_with_exactly_one_parent": 1,
                "parent_techniques_that_are_subtechniques": 0,
                "parents_with_one_or_more_linux_subtechniques": 1,
                "parents_with_zero_linux_subtechniques": 0,
                "linux_subtechnique_edge_count": 1,
            },
        )

    def test_rejects_subtechnique_with_two_active_parents(self):
        other_parent = {
            **self.parent,
            "id": "attack-pattern--other-parent",
            "name": "Other Parent",
            "external_references": external("T1002"),
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.parent,
                other_parent,
                self.child,
                self.relationship,
                {
                    **self.relationship,
                    "id": "relationship--second-parent",
                    "target_ref": other_parent["id"],
                },
            ],
        }
        with self.assertRaises(module.SubtechniqueParserError):
            module.extract_subtechnique_scope(bundle)

    def test_rejects_flag_and_relationship_disagreement(self):
        bundle = {
            "type": "bundle",
            "objects": [
                self.parent,
                {**self.child, "x_mitre_is_subtechnique": False},
                self.relationship,
            ],
        }
        with self.assertRaises(module.SubtechniqueParserError):
            module.extract_subtechnique_scope(bundle)

    def test_zero_case_constructor_rejects_real_parent(self):
        bundle = {
            "type": "bundle",
            "objects": [self.parent, self.child, self.leaf, self.relationship],
        }
        extracted = module.extract_subtechnique_scope(bundle)
        source = {
            "repository": "repo",
            "commit": "commit",
            "path": "bundle.json",
            "sha256": "hash",
        }
        with self.assertRaises(module.SubtechniqueParserError):
            module.zero_subtechniques_pair(
                extracted["parents"][0], extracted, source
            )


class SubtechniquePrototypeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(PROTOTYPE_PATH.read_text())
        cls.pairs = cls.artifact["pairs"]

    def test_schema_and_adapted_intent_families(self):
        self.assertEqual(self.artifact["schema_version"], "1.0")
        self.assertEqual(
            self.artifact["scope"]["relationship_type"], "subtechnique-of"
        )
        selection = self.artifact["selection"]
        self.assertEqual(selection["pair_count"], 30)
        self.assertEqual(selection["parent_identification_pairs"], 5)
        self.assertEqual(selection["parent_aggregate_pairs"], 5)
        self.assertEqual(selection["positive_relationship_pairs"], 5)
        self.assertEqual(selection["negative_relationship_pairs"], 5)
        self.assertEqual(selection["platform_constrained_pairs"], 5)
        self.assertEqual(selection["zero_path_aggregate_pairs"], 5)
        self.assertEqual(
            {pair["case_type"] for pair in self.pairs},
            {
                "identify_subtechnique_parent",
                "aggregate_parent_subtechniques",
                "positive_subtechnique_relationship",
                "negative_subtechnique_relationship",
                "aggregate_parent_platform_subtechniques",
                "aggregate_technique_no_subtechniques",
            },
        )

    def test_dynamic_link_library_injection_parent_is_process_injection(self):
        pair = next(
            pair
            for pair in self.pairs
            if pair["case_type"] == "identify_subtechnique_parent"
            and pair["subtechnique"]["external_id"] == "T1055.001"
        )
        self.assertEqual(pair["expected_parent"]["external_id"], "T1055")
        self.assertEqual(len(pair["provenance"]["relationship_paths"]), 1)
        self.assertEqual(
            pair["provenance"]["relationship_paths"][0]["subtechnique_ref"],
            pair["subtechnique"]["stix_id"],
        )

    def test_platform_filter_uses_each_child_own_platforms(self):
        pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_parent_platform_subtechniques"
        ]
        self.assertEqual(len(pairs), 5)
        for pair in pairs:
            self.assertEqual(pair["platform_filter"], "Linux")
            self.assertEqual(
                pair["provenance"]["platform_applies_to"],
                "child_subtechnique",
            )
            self.assertTrue(
                all(
                    "Linux" in child["platforms"]
                    for child in pair["expected_subtechniques"]
                )
            )

    def test_prototype_negatives_and_zero_paths_are_graph_verified(self):
        path_keys = {
            (
                path["subtechnique_ref"],
                path["parent_technique_ref"],
            )
            for row in self.artifact["parsed_data"]["parents"].values()
            for path in row["relationship_paths"]
        }
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "negative_subtechnique_relationship"
        ]
        for pair in negatives:
            key = (
                pair["candidate_subtechnique"]["stix_id"],
                pair["queried_parent"]["stix_id"],
            )
            self.assertNotIn(key, path_keys)
            self.assertFalse(pair["relationship_exists"])
            self.assertEqual(pair["provenance"]["relationship_paths"], [])
        zero_paths = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_technique_no_subtechniques"
        ]
        parent_stix_ids = {
            row["parent_technique"]["stix_id"]
            for row in self.artifact["parsed_data"]["parents"].values()
        }
        self.assertEqual(len(zero_paths), 5)
        for pair in zero_paths:
            self.assertNotIn(pair["parent_candidate"]["stix_id"], parent_stix_ids)
            self.assertEqual(pair["expected_subtechniques"], [])
            self.assertEqual(pair["provenance"]["relationship_paths"], [])

    def test_every_pair_has_exact_pinned_relationship_provenance(self):
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
                provenance["subtechnique_of_relationship_stix_ids"],
                [
                    path["subtechnique_of_relationship_stix_id"]
                    for path in provenance["relationship_paths"]
                ],
            )


class SubtechniqueFullArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(FULL_PATH.read_text())
        cls.pairs = cls.artifact["pairs"]

    def test_real_snapshot_counts_and_total_case_count(self):
        self.assertEqual(
            self.artifact["global_coverage"],
            {
                "active_technique_count": 697,
                "active_subtechnique_of_edge_count": 475,
                "active_subtechnique_count": 475,
                "active_parent_technique_count": 101,
                "active_top_level_leaf_technique_count": 121,
                "active_nonparent_technique_count": 596,
                "subtechniques_with_exactly_one_parent": 475,
                "parent_techniques_that_are_subtechniques": 0,
                "parents_with_one_or_more_linux_subtechniques": 69,
                "parents_with_zero_linux_subtechniques": 32,
                "linux_subtechnique_edge_count": 200,
            },
        )
        selection = self.artifact["selection"]
        self.assertEqual(selection["pair_count"], 818)
        self.assertEqual(len(self.pairs), 818)
        self.assertEqual(selection["embedded_parent_identification_fact_count"], 475)
        self.assertEqual(selection["embedded_parent_aggregate_fact_count"], 475)
        self.assertEqual(selection["embedded_platform_constrained_fact_count"], 200)

    def test_parent_identification_is_exhaustive_and_one_to_one(self):
        pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "identify_subtechnique_parent"
        ]
        self.assertEqual(len(pairs), 475)
        self.assertEqual(
            len({pair["subtechnique"]["external_id"] for pair in pairs}), 475
        )
        for pair in pairs:
            self.assertTrue(pair["subtechnique"]["is_subtechnique"])
            self.assertFalse(pair["expected_parent"]["is_subtechnique"])
            self.assertEqual(len(pair["provenance"]["relationship_paths"]), 1)

    def test_parent_aggregates_cover_all_parents_and_all_edges(self):
        pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_parent_subtechniques"
        ]
        self.assertEqual(len(pairs), 101)
        self.assertEqual(
            len({pair["parent_technique"]["external_id"] for pair in pairs}), 101
        )
        self.assertEqual(
            sum(len(pair["expected_subtechniques"]) for pair in pairs), 475
        )

    def test_zero_path_sample_is_documented_stratified_and_deterministic(self):
        selection = self.artifact["selection"]
        self.assertEqual(selection["zero_path_aggregate_pairs"], 20)
        self.assertEqual(selection["zero_path_top_level_leaf_pairs"], 10)
        self.assertEqual(selection["zero_path_subtechnique_pairs"], 10)
        self.assertIn(
            "10 top-level leaf techniques and 10 subtechniques",
            self.artifact["scope"]["zero_path_sampling_note"],
        )
        selected = self.artifact["zero_path_selection"]["selected_external_ids"]
        self.assertEqual(selected, sorted(selected))
        self.assertEqual(len(selected), len(set(selected)))
        for item in module.PROTOTYPE_ZERO_PATH_TECHNIQUE_IDS:
            self.assertIn(item, selected)
        zero_pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_technique_no_subtechniques"
        ]
        self.assertEqual(
            {pair["parent_candidate"]["external_id"] for pair in zero_pairs},
            set(selected),
        )
        self.assertTrue(
            all(not pair["provenance"]["relationship_paths"] for pair in zero_pairs)
        )

    def test_boolean_cases_have_natural_parent_coverage_and_negative_ratio(self):
        positives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "positive_subtechnique_relationship"
        ]
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "negative_subtechnique_relationship"
        ]
        self.assertEqual(len(positives), 101)
        self.assertEqual(
            len({pair["queried_parent"]["external_id"] for pair in positives}), 101
        )
        self.assertEqual(len(negatives), 20)
        self.assertAlmostEqual(
            self.artifact["selection"]["explicit_boolean_negative_ratio"],
            20 / 121,
        )
        self.assertGreaterEqual(
            self.artifact["selection"]["explicit_boolean_negative_ratio"], 0.15
        )
        self.assertLessEqual(
            self.artifact["selection"]["explicit_boolean_negative_ratio"], 0.20
        )
        for pair in negatives:
            self.assertFalse(pair["relationship_exists"])
            self.assertEqual(pair["provenance"]["relationship_paths"], [])

    def test_linux_filter_is_exhaustive_across_all_parents(self):
        pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"] in {
                "aggregate_parent_platform_subtechniques",
                "aggregate_parent_no_platform_subtechniques",
            }
        ]
        self.assertEqual(len(pairs), 101)
        self.assertEqual(
            sum(bool(pair["expected_subtechniques"]) for pair in pairs), 69
        )
        self.assertEqual(
            sum(not pair["expected_subtechniques"] for pair in pairs), 32
        )
        self.assertEqual(
            sum(len(pair["expected_subtechniques"]) for pair in pairs), 200
        )
        for pair in pairs:
            self.assertTrue(
                all(
                    "Linux" in child["platforms"]
                    for child in pair["expected_subtechniques"]
                )
            )


class SubtechniqueNoLlmTests(unittest.TestCase):
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
