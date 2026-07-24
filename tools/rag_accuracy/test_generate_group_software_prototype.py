from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_group_software",
    HERE / "generate_group_software_prototype.py",
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def relationship(stix_id: str, source_ref: str, target_ref: str, **extra):
    return {
        "type": "relationship",
        "id": stix_id,
        "relationship_type": "uses",
        "source_ref": source_ref,
        "target_ref": target_ref,
        **extra,
    }


class GroupSoftwarePrototypeTests(unittest.TestCase):
    def setUp(self):
        self.group = {
            "type": "intrusion-set",
            "id": "intrusion-set--one",
            "name": "Example Group",
            "aliases": ["Example Group"],
            "external_references": external("G0001"),
        }
        self.software = {
            "type": "malware",
            "id": "malware--one",
            "name": "Example Malware",
            "external_references": external("S0001"),
            "x_mitre_platforms": ["Windows"],
        }

    def test_unions_active_direct_and_campaign_attributed_software_paths(self):
        technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--one",
            "name": "Example Technique",
            "external_references": external("T1001"),
        }
        campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
        }
        campaign_software = {
            "type": "tool",
            "id": "tool--campaign",
            "name": "Campaign Tool",
            "external_references": external("S0002"),
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.group,
                self.software,
                campaign,
                campaign_software,
                technique,
                relationship("relationship--kept", self.group["id"], self.software["id"]),
                relationship("relationship--revoked", self.group["id"], self.software["id"], revoked=True),
                relationship("relationship--technique", self.group["id"], technique["id"]),
                relationship("relationship--reverse", self.software["id"], technique["id"]),
                {
                    **relationship(
                        "relationship--attribution",
                        campaign["id"],
                        self.group["id"],
                    ),
                    "relationship_type": "attributed-to",
                },
                relationship(
                    "relationship--campaign-use",
                    campaign["id"],
                    campaign_software["id"],
                ),
            ],
        }
        result = module.extract_group_software_scope(bundle, ("G0001",))
        self.assertEqual(len(result["paths"]), 2)
        direct = next(path for path in result["paths"] if path["path_type"] == "direct")
        campaign_path = next(
            path for path in result["paths"]
            if path["path_type"] == "campaign_attributed"
        )
        self.assertEqual(
            direct["direct_uses_relationship_stix_id"], "relationship--kept"
        )
        self.assertEqual(
            campaign_path["attributed_to_relationship_stix_id"],
            "relationship--attribution",
        )
        self.assertEqual(
            campaign_path["campaign_uses_relationship_stix_id"],
            "relationship--campaign-use",
        )
        self.assertEqual(result["software_counts_by_group"]["G0001"]["malware"], 1)
        self.assertEqual(result["software_counts_by_group"]["G0001"]["tools"], 1)
        self.assertEqual(result["software_counts_by_group"]["G0001"]["total"], 2)
        self.assertEqual(result["extraction_audit"]["inactive_uses_relationship_count"], 1)

    def test_rejects_missing_or_inactive_selected_group(self):
        bundle = {
            "type": "bundle",
            "objects": [{**self.group, "revoked": True}, self.software],
        }
        with self.assertRaises(module.GroupSoftwareParserError):
            module.extract_group_software_scope(bundle, ("G0001",))

    def test_all_group_summary_counts_zero_path_distributions(self):
        empty_group = {
            "type": "intrusion-set",
            "id": "intrusion-set--empty",
            "name": "Empty Group",
            "external_references": external("G0002"),
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.group,
                empty_group,
                self.software,
                relationship(
                    "relationship--direct",
                    self.group["id"],
                    self.software["id"],
                ),
            ],
        }
        extracted = module.extract_group_software_scope(bundle, group_ids=None)
        summary = module.all_group_scope_summary(extracted)
        self.assertEqual(summary["active_group_count"], 2)
        self.assertEqual(summary["merged_group_software_pair_count"], 1)
        self.assertEqual(summary["groups_with_zero_direct_software"], 1)
        self.assertEqual(
            summary["groups_with_zero_campaign_attributed_software"], 2
        )
        self.assertEqual(
            summary["groups_with_zero_direct_and_zero_campaign_software"], 1
        )

    def test_artifact_has_ten_pairs_and_honest_negative(self):
        artifact = json.loads(
            (HERE / "golden_set_group_software_prototype.json").read_text()
        )
        self.assertEqual(artifact["selection"]["group_count"], 5)
        self.assertEqual(artifact["selection"]["pair_count"], 10)
        self.assertEqual(artifact["selection"]["aggregate_pairs"], 5)
        self.assertEqual(artifact["selection"]["focused_edge_pairs"], 4)
        self.assertEqual(artifact["selection"]["negative_edge_pairs"], 1)
        negative = next(
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "negative_group_software"
        )
        self.assertEqual(negative["group"]["external_id"], "G0032")
        self.assertEqual(negative["queried_software"]["external_id"], "S0266")
        self.assertEqual(negative["expected_software"], [])
        self.assertEqual(negative["provenance"]["direct_uses_relationship_stix_ids"], [])
        self.assertEqual(negative["provenance"]["campaign_uses_relationship_stix_ids"], [])
        self.assertIn("No active direct or campaign-attributed", negative["expected_answer"])

    def test_every_pair_has_pinned_source_and_path_provenance(self):
        artifact = json.loads(
            (HERE / "golden_set_group_software_prototype.json").read_text()
        )
        source = artifact["source"]
        for pair in artifact["pairs"]:
            provenance = pair["provenance"]
            self.assertEqual(provenance["source_commit"], source["commit"])
            self.assertEqual(provenance["source_bundle_sha256"], source["sha256"])
            self.assertEqual(provenance["scope"], module.SCOPE)
            self.assertEqual(
                provenance["direct_uses_relationship_stix_ids"],
                sorted(
                    path["direct_uses_relationship_stix_id"]
                    for path in provenance["relationship_paths"]
                    if path["path_type"] == "direct"
                ),
            )
            self.assertEqual(
                provenance["campaign_uses_relationship_stix_ids"],
                sorted(
                    path["campaign_uses_relationship_stix_id"]
                    for path in provenance["relationship_paths"]
                    if path["path_type"] == "campaign_attributed"
                ),
            )

    def test_full_artifact_has_all_groups_zero_paths_and_honest_negatives(self):
        artifact = json.loads(
            (HERE / "golden_set_group_software.json").read_text()
        )
        selection = artifact["selection"]
        self.assertEqual(selection["active_group_count"], 174)
        self.assertEqual(selection["pair_count"], 1106)
        self.assertEqual(selection["original_pair_count"], 194)
        self.assertEqual(selection["reverse_aggregate_pairs"], 821)
        self.assertEqual(selection["reverse_zero_path_pairs"], 210)
        self.assertEqual(selection["reverse_negative_existence_pairs"], 20)
        self.assertEqual(selection["positive_aggregate_pairs"], 161)
        self.assertEqual(selection["zero_path_aggregate_pairs"], 13)
        self.assertEqual(selection["negative_existence_pairs"], 20)
        self.assertEqual(selection["adversarial_negative_pairs"], 71)
        self.assertEqual(selection["negative_existence_distinct_group_count"], 20)
        self.assertEqual(selection["embedded_group_software_fact_count"], 1164)
        positives = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "aggregate_group_software"
        ]
        zero_paths = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "aggregate_group_no_qualifying_software"
        ]
        negatives = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "negative_group_software"
        ]
        self.assertEqual(len(positives), 161)
        self.assertTrue(all(pair["expected_software"] for pair in positives))
        self.assertEqual(len(zero_paths), 13)
        self.assertTrue(all(not pair["expected_software"] for pair in zero_paths))
        self.assertTrue(
            all(not pair["provenance"]["relationship_paths"] for pair in zero_paths)
        )
        self.assertEqual(len(negatives), 20)
        self.assertEqual(
            len({pair["group"]["external_id"] for pair in negatives}),
            20,
        )
        self.assertTrue(all(not pair["expected_software"] for pair in negatives))
        self.assertTrue(
            all(not pair["provenance"]["relationship_paths"] for pair in negatives)
        )
        preserved = next(
            pair
            for pair in negatives
            if pair["group"]["external_id"] == "G0032"
        )
        self.assertEqual(preserved["queried_software"]["external_id"], "S0266")


if __name__ == "__main__":
    unittest.main()
