from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_software_technique",
    HERE / "generate_software_technique_prototype.py",
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


class SoftwareTechniquePrototypeTests(unittest.TestCase):
    def setUp(self):
        self.software = {
            "type": "tool",
            "id": "tool--one",
            "name": "Example Tool",
            "external_references": external("S0001"),
            "x_mitre_platforms": ["Windows"],
        }
        self.technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--one",
            "name": "Example Technique",
            "external_references": external("T1001"),
        }

    def test_extracts_only_active_direct_software_to_active_technique_edges(self):
        group = {
            "type": "intrusion-set",
            "id": "intrusion-set--one",
            "name": "Example Group",
            "external_references": external("G0001"),
        }
        other_software = {
            "type": "malware",
            "id": "malware--other",
            "name": "Other Malware",
            "external_references": external("S0002"),
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.software,
                other_software,
                group,
                self.technique,
                relationship("relationship--kept", self.software["id"], self.technique["id"]),
                relationship("relationship--revoked", self.software["id"], self.technique["id"], revoked=True),
                relationship("relationship--group", group["id"], self.technique["id"]),
                relationship("relationship--software-target", self.software["id"], other_software["id"]),
            ],
        }
        result = module.extract_software_technique_scope(bundle, ("S0001",))
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(
            result["paths"][0]["uses_relationship_stix_id"],
            "relationship--kept",
        )
        self.assertEqual(result["extraction_audit"]["inactive_uses_relationship_count"], 1)

    def test_rejects_missing_or_inactive_selected_software(self):
        bundle = {
            "type": "bundle",
            "objects": [{**self.software, "revoked": True}, self.technique],
        }
        with self.assertRaises(module.SoftwareTechniqueParserError):
            module.extract_software_technique_scope(bundle, ("S0001",))

    def test_all_software_summary_keeps_zero_edge_software(self):
        empty = {
            "type": "malware",
            "id": "malware--empty",
            "name": "Empty Malware",
            "external_references": external("S0002"),
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.software,
                empty,
                self.technique,
                relationship(
                    "relationship--one",
                    self.software["id"],
                    self.technique["id"],
                ),
            ],
        }
        extracted = module.extract_software_technique_scope(
            bundle, software_ids=None
        )
        summary = module.all_software_scope_summary(extracted)
        self.assertEqual(summary["active_software_count"], 2)
        self.assertEqual(summary["software_technique_pair_count"], 1)
        self.assertEqual(summary["software_with_at_least_one_technique"], 1)
        self.assertEqual(summary["software_with_zero_techniques"], 1)

    def test_artifact_has_ten_pairs_and_honest_negative(self):
        artifact = json.loads(
            (HERE / "golden_set_software_technique_prototype.json").read_text()
        )
        self.assertEqual(artifact["selection"]["software_count"], 5)
        self.assertEqual(artifact["selection"]["pair_count"], 10)
        self.assertEqual(artifact["selection"]["aggregate_pairs"], 5)
        self.assertEqual(artifact["selection"]["focused_edge_pairs"], 4)
        self.assertEqual(artifact["selection"]["negative_edge_pairs"], 1)
        negative = next(
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "negative_software_technique"
        )
        self.assertEqual(negative["software"]["external_id"], "S0266")
        self.assertEqual(negative["queried_technique"]["external_id"], "T1496")
        self.assertEqual(negative["expected_techniques"], [])
        self.assertEqual(negative["provenance"]["uses_relationship_stix_ids"], [])
        self.assertIn("No active direct uses relationship", negative["expected_answer"])

    def test_every_pair_has_pinned_source_and_relationship_provenance(self):
        artifact = json.loads(
            (HERE / "golden_set_software_technique_prototype.json").read_text()
        )
        source = artifact["source"]
        for pair in artifact["pairs"]:
            provenance = pair["provenance"]
            self.assertEqual(provenance["source_commit"], source["commit"])
            self.assertEqual(provenance["source_bundle_sha256"], source["sha256"])
            self.assertEqual(provenance["scope"], module.SCOPE)
            self.assertEqual(
                provenance["uses_relationship_stix_ids"],
                [
                    path["uses_relationship_stix_id"]
                    for path in provenance["relationship_paths"]
                ],
            )

    def test_full_artifact_has_all_software_and_distinct_honest_negatives(self):
        artifact = json.loads(
            (HERE / "golden_set_software_technique.json").read_text()
        )
        selection = artifact["selection"]
        self.assertEqual(selection["active_software_count"], 821)
        self.assertEqual(selection["pair_count"], 846)
        self.assertEqual(selection["positive_aggregate_pairs"], 821)
        self.assertEqual(selection["zero_path_aggregate_pairs"], 0)
        self.assertEqual(selection["negative_existence_pairs"], 25)
        self.assertEqual(
            selection["negative_existence_distinct_software_count"], 25
        )
        self.assertEqual(
            selection["embedded_software_technique_fact_count"], 11211
        )
        aggregates = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "aggregate_software_techniques"
        ]
        negatives = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"] == "negative_software_technique"
        ]
        self.assertEqual(len(aggregates), 821)
        self.assertTrue(all(pair["expected_techniques"] for pair in aggregates))
        self.assertEqual(len(negatives), 25)
        self.assertEqual(
            len({pair["software"]["external_id"] for pair in negatives}),
            25,
        )
        self.assertTrue(
            all(not pair["expected_techniques"] for pair in negatives)
        )
        self.assertTrue(
            all(
                not pair["provenance"]["uses_relationship_stix_ids"]
                for pair in negatives
            )
        )
        preserved = next(
            pair
            for pair in negatives
            if pair["software"]["external_id"] == "S0266"
        )
        self.assertEqual(preserved["queried_technique"]["external_id"], "T1496")


if __name__ == "__main__":
    unittest.main()
