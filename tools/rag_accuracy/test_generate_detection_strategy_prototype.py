from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_detection_strategy",
    HERE / "generate_detection_strategy_prototype.py",
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


class DetectionStrategyPrototypeTests(unittest.TestCase):
    def setUp(self):
        self.technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--one",
            "name": "Example Technique",
            "external_references": external("T1001"),
            "x_mitre_platforms": ["Windows"],
        }
        self.component = {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--one",
            "name": "Process Creation",
            "external_references": external("DC0032"),
        }
        self.analytic = {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--one",
            "name": "Analytic 0001",
            "description": "Detect example activity.",
            "external_references": external("AN0001"),
            "x_mitre_platforms": ["Windows"],
            "x_mitre_log_source_references": [
                {
                    "x_mitre_data_component_ref": self.component["id"],
                    "name": "WinEventLog:Sysmon",
                    "channel": "EventCode=1",
                }
            ],
        }
        self.strategy = {
            "type": "x-mitre-detection-strategy",
            "id": "x-mitre-detection-strategy--one",
            "name": "Example Detection Strategy",
            "external_references": external("DET0001"),
            "x_mitre_analytic_refs": [self.analytic["id"]],
        }
        self.detects = {
            "type": "relationship",
            "id": "relationship--detects",
            "relationship_type": "detects",
            "source_ref": self.strategy["id"],
            "target_ref": self.technique["id"],
        }

    def test_extracts_detects_analytics_and_log_source_components(self):
        bundle = {
            "type": "bundle",
            "objects": [
                self.technique,
                self.strategy,
                self.analytic,
                self.component,
                self.detects,
                {**self.detects, "id": "relationship--revoked", "revoked": True},
            ],
        }
        extracted = module.extract_detection_strategy_scope(bundle, ("T1001",))
        fact = extracted["facts_by_technique"]["T1001"]
        self.assertEqual(
            fact["detection_strategy"]["external_id"], "DET0001"
        )
        self.assertEqual(
            [row["external_id"] for row in fact["analytics"]], ["AN0001"]
        )
        self.assertEqual(
            [row["external_id"] for row in fact["data_components"]],
            ["DC0032"],
        )
        self.assertEqual(
            fact["analytic_data_component_links"][0]["log_source_channel"],
            "EventCode=1",
        )
        self.assertEqual(
            extracted["extraction_audit"][
                "inactive_or_dangling_detects_relationship_count"
            ],
            1,
        )

    def test_rejects_missing_or_inactive_embedded_references(self):
        bundle = {
            "type": "bundle",
            "objects": [
                self.technique,
                self.strategy,
                {**self.analytic, "x_mitre_deprecated": True},
                self.component,
                self.detects,
            ],
        }
        with self.assertRaises(module.DetectionStrategyParserError):
            module.extract_detection_strategy_scope(bundle, ("T1001",))

    def test_artifact_preserves_ten_pairs_and_adds_five_reverse_pairs(self):
        artifact = json.loads(
            (
                HERE
                / "golden_set_technique_detection_strategy_prototype.json"
            ).read_text()
        )
        selection = artifact["selection"]
        self.assertEqual(selection["technique_count"], 5)
        self.assertEqual(selection["pair_count"], 15)
        self.assertEqual(selection["original_pair_count"], 10)
        self.assertEqual(selection["strategy_and_analytic_pairs"], 5)
        self.assertEqual(selection["data_component_pairs"], 5)
        self.assertEqual(selection["reverse_detection_strategy_pairs"], 5)
        self.assertFalse(selection["negative_zero_strategy_pair_included"])
        self.assertEqual(
            artifact["global_coverage"][
                "techniques_with_zero_detection_strategies"
            ],
            0,
        )
        self.assertEqual(
            {
                pair["technique"]["external_id"]
                for pair in artifact["pairs"][:10]
            },
            set(module.SELECTED_TECHNIQUE_IDS),
        )
        self.assertTrue(
            all(pair["expected_analytics"] for pair in artifact["pairs"])
        )
        self.assertTrue(
            all(pair["expected_data_components"] for pair in artifact["pairs"])
        )

    def test_every_pair_has_complete_pinned_path_provenance(self):
        artifact = json.loads(
            (
                HERE
                / "golden_set_technique_detection_strategy_prototype.json"
            ).read_text()
        )
        source = artifact["source"]
        for pair in artifact["pairs"]:
            provenance = pair["provenance"]
            technique = pair.get("technique", pair.get("expected_technique"))
            strategy = pair.get(
                "expected_detection_strategy", pair.get("detection_strategy")
            )
            self.assertEqual(provenance["source_commit"], source["commit"])
            self.assertEqual(
                provenance["source_bundle_sha256"], source["sha256"]
            )
            self.assertEqual(provenance["scope"], module.SCOPE)
            self.assertEqual(
                provenance["technique_stix_id"],
                technique["stix_id"],
            )
            self.assertEqual(
                provenance["detection_strategy_stix_id"],
                strategy["stix_id"],
            )
            self.assertEqual(
                set(provenance["analytic_stix_ids"]),
                {row["stix_id"] for row in pair["expected_analytics"]},
            )
            self.assertEqual(
                set(provenance["data_component_stix_ids"]),
                {row["stix_id"] for row in pair["expected_data_components"]},
            )
            self.assertEqual(
                set(provenance["analytic_stix_ids"]),
                {
                    row["analytic_ref"]
                    for row in provenance["strategy_analytic_links"]
                },
            )
            self.assertEqual(
                set(provenance["data_component_stix_ids"]),
                {
                    row["data_component_ref"]
                    for row in provenance["analytic_data_component_links"]
                },
            )

    def test_full_artifact_covers_all_detects_edges_in_both_directions(self):
        artifact = json.loads(
            (
                HERE / "golden_set_technique_detection_strategy.json"
            ).read_text()
        )
        selection = artifact["selection"]
        self.assertEqual(selection["active_technique_count"], 697)
        self.assertEqual(selection["active_detection_strategy_count"], 697)
        self.assertEqual(selection["strategy_and_analytic_pairs"], 697)
        self.assertEqual(selection["data_component_pairs"], 652)
        self.assertEqual(selection["zero_data_component_pairs"], 45)
        self.assertEqual(selection["reverse_detection_strategy_pairs"], 697)
        self.assertEqual(selection["pair_count"], 2324)
        self.assertEqual(selection["adversarial_negative_pairs"], 233)
        self.assertEqual(selection["total_negative_pairs"], 233)
        self.assertGreaterEqual(selection["total_negative_ratio"], 0.08)
        self.assertLessEqual(selection["total_negative_ratio"], 0.15)
        reverse = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"]
            == "aggregate_detection_strategy_technique"
        ]
        self.assertEqual(len(reverse), 697)
        self.assertEqual(
            len(
                {
                    pair["detection_strategy"]["external_id"]
                    for pair in reverse
                }
            ),
            697,
        )
        for pair in reverse:
            self.assertEqual(
                pair["provenance"]["detection_strategy_stix_id"],
                pair["detection_strategy"]["stix_id"],
            )
            self.assertEqual(
                pair["provenance"]["technique_stix_id"],
                pair["expected_technique"]["stix_id"],
            )

    def test_adversarial_strategy_mismatches_are_same_tactic_non_edges(self):
        artifact = json.loads(
            (
                HERE / "golden_set_technique_detection_strategy.json"
            ).read_text()
        )
        negatives = [
            pair
            for pair in artifact["pairs"]
            if pair["case_type"]
            == "adversarial_negative_detection_strategy_technique"
        ]
        self.assertEqual(len(negatives), 233)
        strategy_targets = {
            pair["detection_strategy"]["stix_id"]:
            pair["expected_technique"]["stix_id"]
            for pair in artifact["pairs"]
            if pair["case_type"]
            == "aggregate_detection_strategy_technique"
        }
        sample = negatives[0]
        context = sample["provenance"]["adversarial_context"]
        self.assertFalse(sample["relationship_exists"])
        self.assertTrue(context["anchor_tactic_links"])
        self.assertTrue(context["sibling_tactic_links"])
        self.assertEqual(
            context["anchor_tactic_links"][0]["tactic_ref"],
            context["shared_tactic"]["stix_id"],
        )
        self.assertEqual(
            context["sibling_tactic_links"][0]["tactic_ref"],
            context["shared_tactic"]["stix_id"],
        )
        self.assertEqual(
            strategy_targets[sample["detection_strategy"]["stix_id"]],
            context["sibling_technique"]["stix_id"],
        )
        self.assertNotEqual(
            strategy_targets[sample["detection_strategy"]["stix_id"]],
            sample["queried_technique"]["stix_id"],
        )
if __name__ == "__main__":
    unittest.main()
