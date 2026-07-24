from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
GENERATOR_PATH = HERE / "generate_campaign_technique_prototype.py"
PROTOTYPE_PATH = HERE / "golden_set_campaign_technique_prototype.json"
FULL_PATH = HERE / "golden_set_campaign_technique.json"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_campaign_technique", GENERATOR_PATH
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


class CampaignTechniqueExtractionTests(unittest.TestCase):
    def setUp(self):
        self.campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
            "first_seen": "2024-01-01T00:00:00.000Z",
            "last_seen": "2024-02-01T00:00:00.000Z",
        }
        self.other_campaign = {
            "type": "campaign",
            "id": "campaign--two",
            "name": "Other Campaign",
            "external_references": external("C0002"),
        }
        self.technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--one",
            "name": "Example Technique",
            "external_references": external("T1000"),
            "x_mitre_platforms": ["Linux", "Windows", "Windows"],
        }
        self.other_technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--two",
            "name": "Other Technique",
            "external_references": external("T1001"),
            "x_mitre_platforms": ["macOS"],
        }
        self.uses = {
            "type": "relationship",
            "id": "relationship--uses",
            "relationship_type": "uses",
            "source_ref": self.campaign["id"],
            "target_ref": self.technique["id"],
        }

    def test_extracts_only_active_direct_campaign_to_technique_uses(self):
        bundle = {
            "type": "bundle",
            "objects": [
                self.campaign,
                self.other_campaign,
                self.technique,
                self.other_technique,
                self.uses,
                {**self.uses, "id": "relationship--revoked", "revoked": True},
                {
                    **self.uses,
                    "id": "relationship--wrong-source",
                    "source_ref": "intrusion-set--one",
                },
                {
                    **self.uses,
                    "id": "relationship--wrong-target",
                    "target_ref": "malware--one",
                },
            ],
        }
        extracted = module.extract_campaign_technique_scope(bundle, ("C0001",))
        self.assertEqual(extracted["paths"], [{
            "campaign_ref": "campaign--one",
            "technique_ref": "attack-pattern--one",
            "uses_relationship_stix_id": "relationship--uses",
        }])
        compact = next(
            item
            for item in extracted["active_technique_catalog"]
            if item["external_id"] == "T1000"
        )
        self.assertEqual(compact["platforms"], ["Linux", "Windows"])
        self.assertEqual(
            extracted["global_coverage"],
            {
                "active_campaign_count": 2,
                "active_technique_count": 2,
                "active_direct_campaign_technique_uses_edge_count": 1,
                "campaigns_with_one_or_more_techniques": 1,
                "campaigns_with_zero_techniques": 1,
                "techniques_with_one_or_more_campaigns": 1,
                "techniques_with_zero_campaigns": 1,
            },
        )

    def test_global_paths_make_reverse_answers_complete_in_prototype_mode(self):
        second_edge = {
            **self.uses,
            "id": "relationship--other-uses",
            "source_ref": self.other_campaign["id"],
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.campaign,
                self.other_campaign,
                self.technique,
                self.uses,
                second_edge,
            ],
        }
        extracted = module.extract_campaign_technique_scope(bundle, ("C0001",))
        technique = extracted["active_technique_catalog"][0]
        campaigns, paths = module.paths_for_technique(technique, extracted)
        self.assertEqual(
            [item["external_id"] for item in campaigns], ["C0001", "C0002"]
        )
        self.assertEqual(len(paths), 2)
        self.assertEqual(
            extracted["extraction_audit"]["selected_campaign_path_count"], 1
        )

    def test_rejects_missing_or_inactive_selected_campaign(self):
        bundle = {
            "type": "bundle",
            "objects": [
                {**self.campaign, "x_mitre_deprecated": True},
                self.technique,
            ],
        }
        with self.assertRaises(module.CampaignTechniqueParserError):
            module.extract_campaign_technique_scope(bundle, ("C0001",))

    def test_rejects_duplicate_active_relationship_for_same_pair(self):
        bundle = {
            "type": "bundle",
            "objects": [
                self.campaign,
                self.technique,
                self.uses,
                {**self.uses, "id": "relationship--duplicate"},
            ],
        }
        with self.assertRaises(module.CampaignTechniqueParserError):
            module.extract_campaign_technique_scope(bundle, ("C0001",))


class CampaignTechniquePrototypeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(PROTOTYPE_PATH.read_text())

    def test_schema_and_all_four_intent_families(self):
        artifact = self.artifact
        self.assertEqual(artifact["schema_version"], "1.0")
        self.assertEqual(
            artifact["scope"]["relationship_type"], "uses"
        )
        self.assertEqual(artifact["selection"]["campaign_count"], 5)
        self.assertEqual(artifact["selection"]["pair_count"], 25)
        self.assertEqual(artifact["selection"]["forward_aggregate_pairs"], 5)
        self.assertEqual(artifact["selection"]["focused_positive_pairs"], 5)
        self.assertEqual(artifact["selection"]["reverse_aggregate_pairs"], 5)
        self.assertEqual(artifact["selection"]["platform_constrained_pairs"], 5)
        self.assertEqual(artifact["selection"]["negative_existence_pairs"], 5)
        case_types = {pair["case_type"] for pair in artifact["pairs"]}
        self.assertTrue({
            "aggregate_campaign_techniques",
            "focused_campaign_technique",
            "aggregate_technique_campaigns",
            "aggregate_campaign_platform_techniques",
            "negative_campaign_technique",
        }.issubset(case_types))

    def test_reverse_pairs_are_complete_global_answers(self):
        paths = {
            technique_id: set()
            for technique_id in module.FOCUSED_TECHNIQUE_BY_CAMPAIGN.values()
        }
        techniques = {
            pair["technique"]["external_id"]: pair
            for pair in self.artifact["pairs"]
            if pair["case_type"] == "aggregate_technique_campaigns"
        }
        for technique_id, pair in techniques.items():
            expected_campaign_stix = {
                item["stix_id"] for item in pair["expected_campaigns"]
            }
            provenance_campaign_stix = set(
                pair["provenance"]["campaign_stix_ids"]
            )
            self.assertEqual(expected_campaign_stix, provenance_campaign_stix)
            for path in pair["provenance"]["relationship_paths"]:
                paths[technique_id].add(path["campaign_ref"])
                self.assertEqual(path["technique_ref"], pair["technique"]["stix_id"])
            self.assertEqual(paths[technique_id], expected_campaign_stix)

    def test_platform_constrained_pairs_use_authoritative_technique_platforms(self):
        pairs = [
            pair
            for pair in self.artifact["pairs"]
            if pair["case_type"] == "aggregate_campaign_platform_techniques"
        ]
        self.assertEqual(len(pairs), 5)
        for pair in pairs:
            self.assertEqual(pair["platform_filter"], "Windows")
            self.assertEqual(pair["provenance"]["platform_filter"], "Windows")
            self.assertEqual(
                pair["provenance"]["platform_source_field"],
                "attack-pattern.x_mitre_platforms",
            )
            self.assertTrue(pair["expected_techniques"])
            self.assertTrue(
                all(
                    "Windows" in item["platforms"]
                    for item in pair["expected_techniques"]
                )
            )

    def test_negative_cases_are_honest_and_have_empty_edge_provenance(self):
        path_keys = {
            (path["campaign_ref"], path["technique_ref"])
            for row in self.artifact["parsed_data"].values()
            for path in row["relationship_paths"]
        }
        negatives = [
            pair
            for pair in self.artifact["pairs"]
            if pair["case_type"] == "negative_campaign_technique"
        ]
        self.assertEqual(len(negatives), 5)
        for pair in negatives:
            key = (
                pair["campaign"]["stix_id"],
                pair["queried_technique"]["stix_id"],
            )
            self.assertNotIn(key, path_keys)
            self.assertEqual(pair["expected_techniques"], [])
            self.assertEqual(pair["provenance"]["relationship_paths"], [])
            self.assertIn("No active direct uses relationship", pair["expected_answer"])

    def test_every_pair_has_exact_pinned_source_provenance(self):
        source = self.artifact["source"]
        self.assertEqual(
            source["commit"], "a6c366439edee3a87b79cf90dc0b93f5d7975956"
        )
        self.assertEqual(
            source["sha256"],
            "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3",
        )
        for pair in self.artifact["pairs"]:
            provenance = pair["provenance"]
            self.assertEqual(provenance["source_repository"], source["repository"])
            self.assertEqual(provenance["source_commit"], source["commit"])
            self.assertEqual(provenance["source_bundle_path"], source["path"])
            self.assertEqual(provenance["source_bundle_sha256"], source["sha256"])
            relationship_ids = provenance["uses_relationship_stix_ids"]
            path_ids = [
                path["uses_relationship_stix_id"]
                for path in provenance["relationship_paths"]
            ]
            self.assertEqual(relationship_ids, path_ids)


class CampaignTechniqueFullArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(FULL_PATH.read_text())
        cls.pairs = cls.artifact["pairs"]

    def test_real_snapshot_counts_and_total_case_count(self):
        self.assertEqual(self.artifact["global_coverage"], {
            "active_campaign_count": 56,
            "active_technique_count": 697,
            "active_direct_campaign_technique_uses_edge_count": 1146,
            "campaigns_with_one_or_more_techniques": 55,
            "campaigns_with_zero_techniques": 1,
            "techniques_with_one_or_more_campaigns": 320,
            "techniques_with_zero_campaigns": 377,
        })
        selection = self.artifact["selection"]
        self.assertEqual(selection["pair_count"], 960)
        self.assertEqual(len(self.pairs), 960)
        self.assertEqual(selection["embedded_forward_fact_count"], 1146)
        self.assertEqual(selection["embedded_reverse_fact_count"], 1146)

    def test_one_case_per_forward_reverse_and_platform_anchor(self):
        forward = [
            pair
            for pair in self.pairs
            if pair["case_type"] in {
                "aggregate_campaign_techniques",
                "aggregate_campaign_no_techniques",
            }
        ]
        reverse = [
            pair
            for pair in self.pairs
            if pair["case_type"] in {
                "aggregate_technique_campaigns",
                "aggregate_technique_no_campaigns",
            }
        ]
        platform = [
            pair
            for pair in self.pairs
            if pair["case_type"] in {
                "aggregate_campaign_platform_techniques",
                "aggregate_campaign_no_platform_techniques",
            }
        ]
        self.assertEqual(len(forward), 56)
        self.assertEqual(len({pair["campaign"]["external_id"] for pair in forward}), 56)
        self.assertEqual(len(reverse), 697)
        self.assertEqual(
            len({pair["technique"]["external_id"] for pair in reverse}), 697
        )
        self.assertEqual(len(platform), 56)
        self.assertEqual(
            len({pair["campaign"]["external_id"] for pair in platform}), 56
        )

    def test_zero_path_anchors_are_explicit_not_dropped(self):
        forward_zero = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_campaign_no_techniques"
        ]
        platform_zero = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_campaign_no_platform_techniques"
        ]
        reverse_zero = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_technique_no_campaigns"
        ]
        self.assertEqual(
            [pair["campaign"]["external_id"] for pair in forward_zero], ["C0033"]
        )
        self.assertEqual(
            [pair["campaign"]["external_id"] for pair in platform_zero], ["C0033"]
        )
        self.assertEqual(len(reverse_zero), 377)
        for pair in forward_zero + platform_zero + reverse_zero:
            self.assertEqual(pair["provenance"]["relationship_paths"], [])

    def test_full_negative_selection_matches_existing_ratio_convention(self):
        selection = self.artifact["selection"]
        self.assertEqual(selection["focused_positive_pairs"], 55)
        self.assertEqual(selection["negative_existence_pairs"], 10)
        self.assertEqual(selection["adversarial_negative_pairs"], 86)
        self.assertEqual(selection["total_negative_pairs"], 96)
        self.assertGreaterEqual(selection["total_negative_ratio"], 0.08)
        self.assertLessEqual(selection["total_negative_ratio"], 0.15)
        self.assertAlmostEqual(
            selection["explicit_point_negative_ratio"], 10 / 65
        )
        self.assertGreaterEqual(selection["explicit_point_negative_ratio"], 0.15)
        self.assertLessEqual(selection["explicit_point_negative_ratio"], 0.20)
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "negative_campaign_technique"
        ]
        self.assertEqual(
            len({pair["campaign"]["external_id"] for pair in negatives}), 10
        )
        for campaign_id, technique_id in module.NEGATIVE_TECHNIQUE_BY_CAMPAIGN.items():
            self.assertTrue(any(
                pair["campaign"]["external_id"] == campaign_id
                and pair["queried_technique"]["external_id"] == technique_id
                for pair in negatives
            ))

    def test_adversarial_negatives_use_real_same_actor_sibling_context(self):
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"]
            == "adversarial_negative_campaign_technique"
        ]
        self.assertEqual(len(negatives), 86)
        sample = negatives[0]
        context = sample["provenance"]["adversarial_context"]
        self.assertFalse(sample["relationship_exists"])
        self.assertEqual(
            context["method"],
            "different_campaign_same_attributed_actor",
        )
        self.assertTrue(context["campaign_attribution_paths"])
        self.assertTrue(context["sibling_attribution_paths"])
        self.assertTrue(context["sibling_technique_paths"])
        shared_group_id = context["shared_group"]["stix_id"]
        self.assertTrue(
            all(
                path["group_ref"] == shared_group_id
                for path in context["campaign_attribution_paths"]
                + context["sibling_attribution_paths"]
            )
        )
        queried_technique_id = sample["queried_technique"]["stix_id"]
        self.assertTrue(
            all(
                path["technique_ref"] == queried_technique_id
                for path in context["sibling_technique_paths"]
            )
        )
        anchor = next(
            pair
            for pair in self.pairs
            if pair.get("campaign", {}).get("stix_id")
            == sample["campaign"]["stix_id"]
            and pair["case_type"]
            in {
                "aggregate_campaign_techniques",
                "aggregate_campaign_no_techniques",
            }
        )
        sibling = next(
            pair
            for pair in self.pairs
            if pair.get("campaign", {}).get("stix_id")
            == context["sibling_campaign"]["stix_id"]
            and pair["case_type"]
            in {
                "aggregate_campaign_techniques",
                "aggregate_campaign_no_techniques",
            }
        )
        self.assertNotIn(
            queried_technique_id,
            {item["stix_id"] for item in anchor["expected_techniques"]},
        )
        self.assertIn(
            queried_technique_id,
            {item["stix_id"] for item in sibling["expected_techniques"]},
        )

    def test_relationship_paths_exactly_support_every_embedded_fact(self):
        for pair in self.pairs:
            provenance = pair["provenance"]
            paths = provenance["relationship_paths"]
            if "expected_techniques" in pair:
                expected = {item["stix_id"] for item in pair["expected_techniques"]}
                path_targets = {path["technique_ref"] for path in paths}
                self.assertEqual(expected, path_targets)
            if "expected_campaigns" in pair:
                expected = {item["stix_id"] for item in pair["expected_campaigns"]}
                path_sources = {path["campaign_ref"] for path in paths}
                self.assertEqual(expected, path_sources)

    def test_questions_answers_and_pair_ids_are_unique_and_deterministic(self):
        ids = [pair["id"] for pair in self.pairs]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(pair["question"] for pair in self.pairs))
        self.assertTrue(all(pair["expected_answer"] for pair in self.pairs))


class CampaignTechniqueNoLlmTests(unittest.TestCase):
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
