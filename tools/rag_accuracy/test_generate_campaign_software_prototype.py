from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
GENERATOR_PATH = HERE / "generate_campaign_software_prototype.py"
PROTOTYPE_PATH = HERE / "golden_set_campaign_software_prototype.json"
FULL_PATH = HERE / "golden_set_campaign_software.json"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_campaign_software", GENERATOR_PATH
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


class CampaignSoftwareExtractionTests(unittest.TestCase):
    def setUp(self):
        self.campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
        }
        self.other_campaign = {
            "type": "campaign",
            "id": "campaign--two",
            "name": "Other Campaign",
            "external_references": external("C0002"),
        }
        self.malware = {
            "type": "malware",
            "id": "malware--one",
            "name": "Example Malware",
            "external_references": external("S0001"),
            "x_mitre_platforms": ["Linux", "Windows", "Windows"],
        }
        self.tool = {
            "type": "tool",
            "id": "tool--one",
            "name": "Example Tool",
            "external_references": external("S0002"),
            "x_mitre_platforms": ["macOS"],
        }
        self.malware_edge = {
            "type": "relationship",
            "id": "relationship--malware",
            "relationship_type": "uses",
            "source_ref": self.campaign["id"],
            "target_ref": self.malware["id"],
        }
        self.tool_edge = {
            "type": "relationship",
            "id": "relationship--tool",
            "relationship_type": "uses",
            "source_ref": self.campaign["id"],
            "target_ref": self.tool["id"],
        }

    def test_unifies_only_active_direct_campaign_malware_and_tool_edges(self):
        technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--one",
            "name": "Technique",
            "external_references": external("T1000"),
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.campaign,
                self.other_campaign,
                self.malware,
                self.tool,
                technique,
                self.malware_edge,
                self.tool_edge,
                {**self.malware_edge, "id": "relationship--revoked", "revoked": True},
                {
                    **self.malware_edge,
                    "id": "relationship--technique",
                    "target_ref": technique["id"],
                },
                {
                    **self.malware_edge,
                    "id": "relationship--wrong-source",
                    "source_ref": "intrusion-set--one",
                },
            ],
        }
        extracted = module.extract_campaign_software_scope(bundle, ("C0001",))
        self.assertEqual(len(extracted["paths"]), 2)
        self.assertEqual(
            extracted["software_counts_by_campaign"]["C0001"],
            {"total": 2, "malware": 1, "tools": 1},
        )
        compact = {
            item["external_id"]: item
            for item in extracted["active_software_catalog"]
        }
        self.assertEqual(compact["S0001"]["stix_type"], "malware")
        self.assertEqual(compact["S0001"]["platforms"], ["Linux", "Windows"])
        self.assertEqual(compact["S0002"]["stix_type"], "tool")
        self.assertEqual(
            extracted["global_coverage"],
            {
                "active_campaign_count": 2,
                "active_software_count": 2,
                "active_malware_count": 1,
                "active_tool_count": 1,
                "active_direct_campaign_software_uses_edge_count": 2,
                "active_direct_campaign_malware_uses_edge_count": 1,
                "active_direct_campaign_tool_uses_edge_count": 1,
                "campaigns_with_one_or_more_software": 1,
                "campaigns_with_zero_software": 1,
                "software_with_one_or_more_campaigns": 2,
                "software_with_zero_campaigns": 0,
                "malware_with_one_or_more_campaigns": 1,
                "tools_with_one_or_more_campaigns": 1,
            },
        )

    def test_global_paths_make_reverse_answers_complete_in_prototype_mode(self):
        second_edge = {
            **self.malware_edge,
            "id": "relationship--other-malware",
            "source_ref": self.other_campaign["id"],
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.campaign,
                self.other_campaign,
                self.malware,
                self.malware_edge,
                second_edge,
            ],
        }
        extracted = module.extract_campaign_software_scope(bundle, ("C0001",))
        software = extracted["active_software_catalog"][0]
        campaigns, paths = module.paths_for_software(software, extracted)
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
                self.malware,
            ],
        }
        with self.assertRaises(module.CampaignSoftwareParserError):
            module.extract_campaign_software_scope(bundle, ("C0001",))

    def test_rejects_duplicate_active_relationship_for_same_pair(self):
        bundle = {
            "type": "bundle",
            "objects": [
                self.campaign,
                self.malware,
                self.malware_edge,
                {**self.malware_edge, "id": "relationship--duplicate"},
            ],
        }
        with self.assertRaises(module.CampaignSoftwareParserError):
            module.extract_campaign_software_scope(bundle, ("C0001",))


class CampaignSoftwarePrototypeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(PROTOTYPE_PATH.read_text())

    def test_schema_and_all_four_intent_families(self):
        artifact = self.artifact
        self.assertEqual(artifact["schema_version"], "1.0")
        self.assertEqual(artifact["scope"]["target_types"], ["malware", "tool"])
        self.assertEqual(artifact["scope"]["relationship_type"], "uses")
        self.assertEqual(artifact["selection"]["campaign_count"], 5)
        self.assertEqual(artifact["selection"]["pair_count"], 25)
        self.assertEqual(artifact["selection"]["forward_aggregate_pairs"], 5)
        self.assertEqual(artifact["selection"]["focused_positive_pairs"], 5)
        self.assertEqual(artifact["selection"]["reverse_aggregate_pairs"], 5)
        self.assertEqual(artifact["selection"]["platform_constrained_pairs"], 5)
        self.assertEqual(artifact["selection"]["negative_existence_pairs"], 5)
        case_types = {pair["case_type"] for pair in artifact["pairs"]}
        self.assertTrue(
            {
                "aggregate_campaign_software",
                "focused_campaign_software",
                "aggregate_software_campaigns",
                "aggregate_campaign_platform_software",
                "negative_campaign_software",
            }.issubset(case_types)
        )

    def test_reverse_prototype_covers_both_malware_and_tool_anchors(self):
        reverse = [
            pair
            for pair in self.artifact["pairs"]
            if pair["case_type"] == "aggregate_software_campaigns"
        ]
        self.assertEqual(len(reverse), 5)
        self.assertEqual(
            {pair["software"]["stix_type"] for pair in reverse},
            {"malware", "tool"},
        )
        for pair in reverse:
            type_name = module.software_type_name(pair["software"])
            self.assertIn(type_name, pair["question"])
            self.assertIn(type_name, pair["expected_answer"])
            self.assertEqual(
                set(pair["provenance"]["campaign_stix_ids"]),
                {item["stix_id"] for item in pair["expected_campaigns"]},
            )

    def test_aggregate_answers_always_separate_malware_from_tools(self):
        pairs = [
            pair
            for pair in self.artifact["pairs"]
            if pair["case_type"] in {
                "aggregate_campaign_software",
                "aggregate_campaign_platform_software",
            }
        ]
        self.assertEqual(len(pairs), 10)
        for pair in pairs:
            self.assertIn("Malware:", pair["expected_answer"])
            self.assertIn("Tools:", pair["expected_answer"])
            self.assertTrue(
                all(
                    item["stix_type"] in {"malware", "tool"}
                    for item in pair["expected_software"]
                )
            )

    def test_platform_cases_use_authoritative_software_platforms(self):
        pairs = [
            pair
            for pair in self.artifact["pairs"]
            if pair["case_type"] == "aggregate_campaign_platform_software"
        ]
        self.assertEqual(len(pairs), 5)
        for pair in pairs:
            self.assertEqual(pair["platform_filter"], "Windows")
            self.assertEqual(pair["provenance"]["platform_filter"], "Windows")
            self.assertEqual(
                pair["provenance"]["platform_source_field"],
                "malware/tool.x_mitre_platforms",
            )
            self.assertTrue(
                all(
                    "Windows" in item["platforms"]
                    for item in pair["expected_software"]
                )
            )

    def test_negative_cases_are_graph_verified_and_typed(self):
        path_keys = {
            (path["campaign_ref"], path["software_ref"])
            for row in self.artifact["parsed_data"].values()
            for path in row["relationship_paths"]
        }
        negatives = [
            pair
            for pair in self.artifact["pairs"]
            if pair["case_type"] == "negative_campaign_software"
        ]
        self.assertEqual(len(negatives), 5)
        for pair in negatives:
            key = (
                pair["campaign"]["stix_id"],
                pair["queried_software"]["stix_id"],
            )
            self.assertNotIn(key, path_keys)
            self.assertEqual(pair["expected_software"], [])
            self.assertEqual(pair["provenance"]["relationship_paths"], [])
            self.assertIn(
                module.software_type_name(pair["queried_software"]),
                pair["expected_answer"],
            )

    def test_every_pair_has_exact_pinned_relationship_provenance(self):
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
            self.assertEqual(provenance["source_commit"], source["commit"])
            self.assertEqual(provenance["source_bundle_sha256"], source["sha256"])
            self.assertEqual(
                provenance["uses_relationship_stix_ids"],
                [
                    path["uses_relationship_stix_id"]
                    for path in provenance["relationship_paths"]
                ],
            )


class CampaignSoftwareFullArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(FULL_PATH.read_text())
        cls.pairs = cls.artifact["pairs"]

    def test_real_snapshot_counts_and_total_case_count(self):
        self.assertEqual(
            self.artifact["global_coverage"],
            {
                "active_campaign_count": 56,
                "active_software_count": 821,
                "active_malware_count": 726,
                "active_tool_count": 95,
                "active_direct_campaign_software_uses_edge_count": 172,
                "active_direct_campaign_malware_uses_edge_count": 91,
                "active_direct_campaign_tool_uses_edge_count": 81,
                "campaigns_with_one_or_more_software": 50,
                "campaigns_with_zero_software": 6,
                "software_with_one_or_more_campaigns": 121,
                "software_with_zero_campaigns": 700,
                "malware_with_one_or_more_campaigns": 84,
                "tools_with_one_or_more_campaigns": 37,
            },
        )
        selection = self.artifact["selection"]
        self.assertEqual(selection["pair_count"], 993)
        self.assertEqual(len(self.pairs), 993)
        self.assertEqual(selection["embedded_forward_fact_count"], 172)
        self.assertEqual(selection["embedded_reverse_fact_count"], 172)

    def test_one_case_per_forward_reverse_and_platform_anchor(self):
        forward = [
            pair
            for pair in self.pairs
            if pair["case_type"] in {
                "aggregate_campaign_software",
                "aggregate_campaign_no_qualifying_software",
            }
        ]
        reverse = [
            pair
            for pair in self.pairs
            if pair["case_type"] in {
                "aggregate_software_campaigns",
                "aggregate_software_no_campaigns",
            }
        ]
        platform = [
            pair
            for pair in self.pairs
            if pair["case_type"] in {
                "aggregate_campaign_platform_software",
                "aggregate_campaign_no_platform_software",
            }
        ]
        self.assertEqual(len(forward), 56)
        self.assertEqual(
            len({pair["campaign"]["external_id"] for pair in forward}), 56
        )
        self.assertEqual(len(reverse), 821)
        self.assertEqual(
            len({pair["software"]["external_id"] for pair in reverse}), 821
        )
        self.assertEqual(len(platform), 56)

    def test_reverse_has_complete_malware_and_tool_coverage(self):
        reverse = [
            pair
            for pair in self.pairs
            if pair["case_type"].startswith("aggregate_software_")
        ]
        malware = [
            pair
            for pair in reverse
            if pair["software"]["stix_type"] == "malware"
        ]
        tools = [pair for pair in reverse if pair["software"]["stix_type"] == "tool"]
        self.assertEqual(len(malware), 726)
        self.assertEqual(len(tools), 95)
        self.assertEqual(
            sum(bool(pair["expected_campaigns"]) for pair in malware), 84
        )
        self.assertEqual(sum(bool(pair["expected_campaigns"]) for pair in tools), 37)

    def test_zero_path_anchors_are_explicit_not_dropped(self):
        forward_zero = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_campaign_no_qualifying_software"
        ]
        reverse_zero = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_software_no_campaigns"
        ]
        platform_zero = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_campaign_no_platform_software"
        ]
        self.assertEqual(
            {pair["campaign"]["external_id"] for pair in forward_zero},
            {"C0035", "C0041", "C0045", "C0049", "C0052", "C0062"},
        )
        self.assertEqual(len(reverse_zero), 700)
        self.assertEqual(len(platform_zero), 11)
        for pair in forward_zero + reverse_zero + platform_zero:
            self.assertEqual(pair["provenance"]["relationship_paths"], [])

    def test_full_negative_selection_matches_existing_ratio_convention(self):
        selection = self.artifact["selection"]
        self.assertEqual(selection["focused_positive_pairs"], 50)
        self.assertEqual(selection["negative_existence_pairs"], 10)
        self.assertAlmostEqual(
            selection["explicit_point_negative_ratio"], 10 / 60
        )
        self.assertGreaterEqual(selection["explicit_point_negative_ratio"], 0.15)
        self.assertLessEqual(selection["explicit_point_negative_ratio"], 0.20)
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "negative_campaign_software"
        ]
        self.assertEqual(
            len({pair["campaign"]["external_id"] for pair in negatives}), 10
        )
        for campaign_id, software_id in module.NEGATIVE_SOFTWARE_BY_CAMPAIGN.items():
            self.assertTrue(
                any(
                    pair["campaign"]["external_id"] == campaign_id
                    and pair["queried_software"]["external_id"] == software_id
                    for pair in negatives
                )
            )

    def test_relationship_paths_exactly_support_every_embedded_fact(self):
        for pair in self.pairs:
            paths = pair["provenance"]["relationship_paths"]
            if "expected_software" in pair:
                self.assertEqual(
                    {item["stix_id"] for item in pair["expected_software"]},
                    {path["software_ref"] for path in paths},
                )
            if "expected_campaigns" in pair:
                self.assertEqual(
                    {item["stix_id"] for item in pair["expected_campaigns"]},
                    {path["campaign_ref"] for path in paths},
                )


class CampaignSoftwareNoLlmTests(unittest.TestCase):
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
