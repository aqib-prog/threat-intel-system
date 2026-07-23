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

    def test_artifact_has_five_techniques_and_ten_grounded_pairs(self):
        artifact = json.loads(
            (
                HERE
                / "golden_set_technique_detection_strategy_prototype.json"
            ).read_text()
        )
        selection = artifact["selection"]
        self.assertEqual(selection["technique_count"], 5)
        self.assertEqual(selection["pair_count"], 10)
        self.assertEqual(selection["strategy_and_analytic_pairs"], 5)
        self.assertEqual(selection["data_component_pairs"], 5)
        self.assertFalse(selection["negative_zero_strategy_pair_included"])
        self.assertEqual(
            artifact["global_coverage"][
                "techniques_with_zero_detection_strategies"
            ],
            0,
        )
        self.assertEqual(
            {pair["technique"]["external_id"] for pair in artifact["pairs"]},
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
            self.assertEqual(provenance["source_commit"], source["commit"])
            self.assertEqual(
                provenance["source_bundle_sha256"], source["sha256"]
            )
            self.assertEqual(provenance["scope"], module.SCOPE)
            self.assertEqual(
                provenance["technique_stix_id"],
                pair["technique"]["stix_id"],
            )
            self.assertEqual(
                provenance["detection_strategy_stix_id"],
                pair["expected_detection_strategy"]["stix_id"],
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


if __name__ == "__main__":
    unittest.main()
