from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_campaign_group",
    HERE / "generate_campaign_group_prototype.py",
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


class CampaignGroupPrototypeTests(unittest.TestCase):
    def setUp(self):
        self.campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
            "first_seen": "2024-01-01T00:00:00.000Z",
            "last_seen": "2024-02-01T00:00:00.000Z",
        }
        self.group = {
            "type": "intrusion-set",
            "id": "intrusion-set--one",
            "name": "Example Group",
            "aliases": ["Example Group"],
            "external_references": external("G0001"),
        }
        self.attribution = {
            "type": "relationship",
            "id": "relationship--attribution",
            "relationship_type": "attributed-to",
            "source_ref": self.campaign["id"],
            "target_ref": self.group["id"],
        }

    def test_extracts_only_active_campaign_to_group_attributions(self):
        zero_campaign = {
            "type": "campaign",
            "id": "campaign--zero",
            "name": "Zero Campaign",
            "external_references": external("C0002"),
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.campaign,
                zero_campaign,
                self.group,
                self.attribution,
                {
                    **self.attribution,
                    "id": "relationship--revoked",
                    "revoked": True,
                },
                {
                    **self.attribution,
                    "id": "relationship--uses",
                    "relationship_type": "uses",
                },
            ],
        }
        extracted = module.extract_campaign_group_scope(bundle, ("C0001",))
        self.assertEqual(len(extracted["paths"]), 1)
        self.assertEqual(
            extracted["paths"][0]["attributed_to_relationship_stix_id"],
            "relationship--attribution",
        )
        self.assertEqual(extracted["group_counts_by_campaign"]["C0001"], 1)
        self.assertEqual(
            extracted["global_coverage"]["campaigns_with_zero_attributed_groups"],
            1,
        )
        self.assertEqual(
            extracted["extraction_audit"][
                "inactive_or_dangling_attributed_to_relationship_count"
            ],
            1,
        )

    def test_rejects_missing_or_inactive_selected_campaign(self):
        bundle = {
            "type": "bundle",
            "objects": [
                {**self.campaign, "x_mitre_deprecated": True},
                self.group,
            ],
        }
        with self.assertRaises(module.CampaignGroupParserError):
            module.extract_campaign_group_scope(bundle, ("C0001",))

    def test_artifact_has_five_aggregates_four_positives_and_honest_negative(self):
        artifact = json.loads(
            (HERE / "golden_set_campaign_group_prototype.json").read_text()
        )
        selection = artifact["selection"]
        self.assertEqual(selection["campaign_count"], 5)
        self.assertEqual(selection["pair_count"], 10)
        self.assertEqual(selection["aggregate_pairs"], 5)
        self.assertEqual(selection["focused_positive_pairs"], 4)
        self.assertEqual(selection["negative_existence_pairs"], 1)
        negative = next(
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "negative_campaign_group"
        )
        self.assertEqual(negative["campaign"]["external_id"], "C0024")
        self.assertEqual(negative["queried_group"]["external_id"], "G0007")
        self.assertEqual(negative["expected_groups"], [])
        self.assertEqual(
            negative["provenance"]["attributed_to_relationship_stix_ids"],
            [],
        )
        self.assertIn(
            "No active attributed-to relationship",
            negative["expected_answer"],
        )

    def test_every_pair_has_complete_pinned_relationship_provenance(self):
        artifact = json.loads(
            (HERE / "golden_set_campaign_group_prototype.json").read_text()
        )
        source = artifact["source"]
        for pair in artifact["pairs"]:
            provenance = pair["provenance"]
            self.assertEqual(provenance["source_commit"], source["commit"])
            self.assertEqual(
                provenance["source_bundle_sha256"], source["sha256"]
            )
            self.assertEqual(provenance["scope"], module.SCOPE)
            self.assertEqual(
                provenance["campaign_stix_id"], pair["campaign"]["stix_id"]
            )
            self.assertEqual(
                set(provenance["group_stix_ids"]),
                {group["stix_id"] for group in pair["expected_groups"]},
            )
            self.assertEqual(
                provenance["attributed_to_relationship_stix_ids"],
                [
                    path["attributed_to_relationship_stix_id"]
                    for path in provenance["relationship_paths"]
                ],
            )

    def test_full_artifact_has_all_campaigns_zero_paths_multi_group_and_negatives(self):
        artifact = json.loads(
            (HERE / "golden_set_campaign_group.json").read_text()
        )
        selection = artifact["selection"]
        self.assertEqual(selection["active_campaign_count"], 56)
        self.assertEqual(selection["pair_count"], 250)
        self.assertEqual(selection["original_pair_count"], 66)
        self.assertEqual(selection["reverse_aggregate_pairs"], 174)
        self.assertEqual(selection["reverse_zero_path_pairs"], 155)
        self.assertEqual(selection["reverse_negative_existence_pairs"], 10)
        self.assertEqual(selection["positive_aggregate_pairs"], 25)
        self.assertEqual(selection["zero_path_aggregate_pairs"], 31)
        self.assertEqual(selection["negative_existence_pairs"], 10)
        self.assertEqual(
            selection["negative_existence_distinct_campaign_count"], 10
        )
        self.assertEqual(selection["multi_group_aggregate_pairs"], 1)
        self.assertEqual(selection["embedded_campaign_group_fact_count"], 26)
        aggregates = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"].startswith("aggregate_campaign_")
        ]
        positive = [
            pair
            for pair in aggregates
            if pair["case_type"] == "aggregate_campaign_groups"
        ]
        zero_paths = [
            pair
            for pair in aggregates
            if pair["case_type"] == "aggregate_campaign_no_attributed_group"
        ]
        negatives = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "negative_campaign_group"
        ]
        self.assertEqual(len(aggregates), 56)
        self.assertEqual(
            len({pair["campaign"]["external_id"] for pair in aggregates}),
            56,
        )
        self.assertEqual(len(positive), 25)
        self.assertEqual(len(zero_paths), 31)
        self.assertTrue(all(not pair["expected_groups"] for pair in zero_paths))
        self.assertTrue(
            all(not pair["provenance"]["relationship_paths"] for pair in zero_paths)
        )
        multi = [pair for pair in positive if len(pair["expected_groups"]) > 1]
        self.assertEqual(len(multi), 1)
        self.assertEqual(multi[0]["campaign"]["external_id"], "C0052")
        self.assertEqual(
            {group["external_id"] for group in multi[0]["expected_groups"]},
            {"G0004", "G1023"},
        )
        self.assertEqual(len(negatives), 10)
        self.assertEqual(
            len({pair["campaign"]["external_id"] for pair in negatives}),
            10,
        )
        self.assertTrue(all(not pair["expected_groups"] for pair in negatives))
        self.assertTrue(
            all(not pair["provenance"]["relationship_paths"] for pair in negatives)
        )
        preserved = next(
            pair
            for pair in negatives
            if pair["campaign"]["external_id"] == "C0024"
        )
        self.assertEqual(preserved["queried_group"]["external_id"], "G0007")


if __name__ == "__main__":
    unittest.main()
