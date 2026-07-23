from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
GENERATOR_PATH = HERE / "generate_analytic_datacomponent_prototype.py"
PROTOTYPE_PATH = HERE / "golden_set_analytic_datacomponent_prototype.json"
FULL_PATH = HERE / "golden_set_analytic_datacomponent.json"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_analytic_datacomponent", GENERATOR_PATH
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


class AnalyticDataComponentExtractionTests(unittest.TestCase):
    def setUp(self):
        self.windows_component = {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--windows",
            "name": "Windows Component",
            "external_references": external("DC0001"),
            "x_mitre_log_sources": [
                {"name": "WinEventLog:Security", "channel": "EventCode=1"},
                {"name": "AWS:CloudTrail", "channel": "CreateThing"},
            ],
        }
        self.cloud_component = {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--cloud",
            "name": "Cloud Component",
            "external_references": external("DC0002"),
            "x_mitre_log_sources": [
                {"name": "AWS:CloudTrail", "channel": "DeleteThing"}
            ],
        }
        self.orphan_component = {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--orphan",
            "name": "Orphan Component",
            "external_references": external("DC0003"),
        }
        self.linked_analytic = {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--linked",
            "name": "Linked Analytic",
            "external_references": external("AN0001"),
            "x_mitre_platforms": ["Windows"],
            "x_mitre_log_source_references": [
                {
                    "x_mitre_data_component_ref": self.windows_component["id"],
                    "name": "WinEventLog:Security",
                    "channel": "EventCode=1",
                },
                {
                    "x_mitre_data_component_ref": self.windows_component["id"],
                    "name": "WinEventLog:Sysmon",
                    "channel": "EventCode=1",
                },
                {
                    "x_mitre_data_component_ref": self.cloud_component["id"],
                    "name": "AWS:CloudTrail",
                    "channel": "DeleteThing",
                },
            ],
        }
        self.zero_analytic = {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--zero",
            "name": "Zero Analytic",
            "external_references": external("AN0002"),
        }

    def bundle(self):
        return {
            "type": "bundle",
            "objects": [
                self.windows_component,
                self.cloud_component,
                self.orphan_component,
                self.linked_analytic,
                self.zero_analytic,
            ],
        }

    def test_extracts_distinct_edges_preserves_rows_and_zero_paths(self):
        extracted = module.extract_analytic_datacomponent_scope(self.bundle())
        self.assertEqual(
            extracted["global_coverage"],
            {
                "active_analytic_count": 2,
                "active_data_component_count": 3,
                "analytic_log_source_reference_row_count": 3,
                "distinct_analytic_data_component_edge_count": 2,
                "duplicate_reference_rows_beyond_distinct_edges": 1,
                "analytics_with_one_or_more_data_components": 1,
                "analytics_with_zero_data_components": 1,
                "data_components_with_one_or_more_analytics": 2,
                "orphan_data_component_count": 1,
                "maximum_data_components_per_analytic": 2,
                "maximum_analytics_per_data_component": 1,
                "data_components_at_or_below_reverse_enumeration_threshold": 2,
                "data_components_above_reverse_enumeration_threshold": 0,
                "active_data_component_log_source_row_count": 3,
                "data_components_with_windows_event_log_source": 1,
                "analytic_data_component_edges_matching_windows_event_log_property": 1,
                "analytics_with_one_or_more_windows_event_log_components": 1,
                "analytics_with_zero_windows_event_log_components": 1,
            },
        )
        self.assertEqual(
            extracted["extraction_audit"]["endpoint_pairs_with_multiple_source_rows"],
            1,
        )
        self.assertEqual(
            extracted["extraction_audit"]["maximum_source_rows_for_one_endpoint_pair"],
            2,
        )
        self.assertEqual(
            [item["external_id"] for item in extracted["zero_analytics"]],
            ["AN0002"],
        )
        self.assertEqual(
            [item["external_id"] for item in extracted["orphan_data_components"]],
            ["DC0003"],
        )

    def test_property_filter_reads_component_own_structured_log_sources(self):
        extracted = module.extract_analytic_datacomponent_scope(self.bundle())
        analytic = module.analytic_catalog(extracted)["AN0001"]
        source = {
            "repository": "repo",
            "commit": "commit",
            "path": "bundle.json",
            "sha256": "hash",
        }
        pair = module.property_constrained_pair(analytic, extracted, source)
        self.assertEqual(
            [item["external_id"] for item in pair["expected_data_components"]],
            ["DC0001"],
        )
        evidence = pair["provenance"]["data_component_property_evidence"]
        self.assertEqual(len(evidence), 1)
        self.assertTrue(evidence[0]["log_source_name"].startswith("WinEventLog:"))

    def test_rejects_missing_or_inactive_component_reference(self):
        analytic = {
            **self.linked_analytic,
            "x_mitre_log_source_references": [
                {
                    "x_mitre_data_component_ref": "x-mitre-data-component--missing",
                    "name": "missing",
                    "channel": "missing",
                }
            ],
        }
        with self.assertRaises(module.DetectionStrategyParserError):
            module.extract_analytic_datacomponent_scope(
                {
                    "type": "bundle",
                    "objects": [self.windows_component, analytic],
                }
            )

    def test_rejects_non_list_component_log_sources(self):
        component = {**self.windows_component, "x_mitre_log_sources": "invalid"}
        with self.assertRaises(module.AnalyticDataComponentParserError):
            module.extract_analytic_datacomponent_scope(
                {
                    "type": "bundle",
                    "objects": [component, self.linked_analytic],
                }
            )

    def test_negative_constructor_rejects_real_edge(self):
        extracted = module.extract_analytic_datacomponent_scope(self.bundle())
        source = {
            "repository": "repo",
            "commit": "commit",
            "path": "bundle.json",
            "sha256": "hash",
        }
        with self.assertRaises(module.AnalyticDataComponentParserError):
            module.negative_relationship_pair(
                module.analytic_catalog(extracted)["AN0001"],
                module.component_catalog(extracted)["DC0001"],
                extracted,
                source,
            )


class AnalyticDataComponentPrototypeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(PROTOTYPE_PATH.read_text())
        cls.pairs = cls.artifact["pairs"]

    def test_schema_and_all_adapted_intent_families(self):
        self.assertEqual(self.artifact["schema_version"], "1.0")
        self.assertEqual(
            self.artifact["scope"]["relationship_type"],
            "x_mitre_log_source_references",
        )
        selection = self.artifact["selection"]
        self.assertEqual(selection["pair_count"], 30)
        self.assertEqual(selection["forward_positive_pairs"], 5)
        self.assertEqual(selection["forward_zero_path_pairs"], 5)
        self.assertEqual(selection["reverse_enumerated_pairs"], 2)
        self.assertEqual(selection["reverse_capped_pairs"], 2)
        self.assertEqual(selection["reverse_zero_path_pairs"], 1)
        self.assertEqual(selection["positive_relationship_pairs"], 5)
        self.assertEqual(selection["negative_relationship_pairs"], 5)
        self.assertEqual(selection["property_constrained_pairs"], 5)

    def test_forward_max_fanout_and_duplicate_source_rows_are_preserved(self):
        max_pair = next(
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_analytic_data_components"
            and pair["analytic"]["external_id"] == "AN1551"
        )
        self.assertEqual(len(max_pair["expected_data_components"]), 10)
        duplicate_pair = next(
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_analytic_data_components"
            and pair["analytic"]["external_id"] == "AN0872"
        )
        self.assertEqual(len(duplicate_pair["expected_data_components"]), 4)
        self.assertEqual(
            duplicate_pair["provenance"]["distinct_supported_edge_count"], 4
        )
        self.assertEqual(
            duplicate_pair["provenance"]["supporting_source_row_count"], 5
        )

    def test_reverse_cap_boundary_and_858_case_are_exact(self):
        boundary = next(
            pair
            for pair in self.pairs
            if pair.get("data_component", {}).get("external_id") == "DC0004"
        )
        self.assertEqual(boundary["expected_analytic_total_count"], 15)
        self.assertTrue(boundary["expected_analytics_complete"])
        self.assertEqual(len(boundary["expected_analytics"]), 15)

        over_boundary = next(
            pair
            for pair in self.pairs
            if pair.get("data_component", {}).get("external_id") == "DC0079"
        )
        self.assertEqual(over_boundary["expected_analytic_total_count"], 16)
        self.assertFalse(over_boundary["expected_analytics_complete"])
        self.assertEqual(len(over_boundary["expected_analytics"]), 10)

        maximum = next(
            pair
            for pair in self.pairs
            if pair.get("data_component", {}).get("external_id") == "DC0032"
        )
        self.assertEqual(maximum["expected_analytic_total_count"], 858)
        self.assertEqual(len(maximum["expected_analytics"]), 10)
        self.assertFalse(maximum["expected_analytics_complete"])
        self.assertIn("858 active Analytics", maximum["expected_answer"])
        self.assertIn("10 shown; 858 total", maximum["expected_answer"])
        self.assertEqual(
            len(set(maximum["provenance"]["analytic_stix_ids"])), 858
        )
        self.assertEqual(
            maximum["provenance"]["distinct_supported_edge_count"], 858
        )

    def test_zero_samples_and_reverse_orphan_are_explicit(self):
        self.assertEqual(
            self.artifact["selection"]["zero_analytic_sample_external_ids"],
            ["AN1937", "AN1951", "AN1979", "AN2009", "AN2062"],
        )
        reverse_orphan = next(
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_data_component_no_analytics"
        )
        self.assertEqual(reverse_orphan["data_component"]["external_id"], "DC0026")
        self.assertEqual(reverse_orphan["expected_analytic_total_count"], 0)
        self.assertEqual(reverse_orphan["provenance"]["analytic_data_component_paths"], [])

    def test_property_cases_use_exact_prefix_and_deterministic_evidence(self):
        positive = next(
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_analytic_property_data_components"
            and pair["analytic"]["external_id"] == "AN0001"
        )
        self.assertEqual(
            [item["external_id"] for item in positive["expected_data_components"]],
            ["DC0082", "DC0085"],
        )
        evidence = positive["provenance"]["data_component_property_evidence"]
        self.assertEqual(len(evidence), 2)
        self.assertTrue(
            all(row["log_source_name"].startswith("WinEventLog:") for row in evidence)
        )
        zero = next(
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_analytic_no_property_data_components"
            and pair["analytic"]["external_id"] == "AN0234"
        )
        self.assertEqual(zero["expected_data_components"], [])
        self.assertEqual(zero["provenance"]["data_component_property_evidence"], [])

    def test_prototype_negatives_are_graph_verified(self):
        path_keys = {
            (path["analytic_ref"], path["data_component_ref"])
            for row in self.artifact["parsed_data"]["analytics"].values()
            for path in row["analytic_data_component_paths"]
        }
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "negative_analytic_data_component_relationship"
        ]
        self.assertEqual(len(negatives), 5)
        for pair in negatives:
            self.assertNotIn(
                (
                    pair["analytic"]["stix_id"],
                    pair["candidate_data_component"]["stix_id"],
                ),
                path_keys,
            )
            self.assertFalse(pair["relationship_exists"])


class AnalyticDataComponentFullArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(FULL_PATH.read_text())
        cls.pairs = cls.artifact["pairs"]

    def test_real_snapshot_counts_and_total_case_count(self):
        self.assertEqual(
            self.artifact["global_coverage"],
            {
                "active_analytic_count": 1758,
                "active_data_component_count": 106,
                "analytic_log_source_reference_row_count": 4182,
                "distinct_analytic_data_component_edge_count": 4170,
                "duplicate_reference_rows_beyond_distinct_edges": 12,
                "analytics_with_one_or_more_data_components": 1713,
                "analytics_with_zero_data_components": 45,
                "data_components_with_one_or_more_analytics": 98,
                "orphan_data_component_count": 8,
                "maximum_data_components_per_analytic": 10,
                "maximum_analytics_per_data_component": 858,
                "data_components_at_or_below_reverse_enumeration_threshold": 64,
                "data_components_above_reverse_enumeration_threshold": 34,
                "active_data_component_log_source_row_count": 2993,
                "data_components_with_windows_event_log_source": 52,
                "analytic_data_component_edges_matching_windows_event_log_property": 3933,
                "analytics_with_one_or_more_windows_event_log_components": 1641,
                "analytics_with_zero_windows_event_log_components": 117,
            },
        )
        selection = self.artifact["selection"]
        self.assertEqual(selection["pair_count"], 5638)
        self.assertEqual(len(self.pairs), 5638)
        self.assertEqual(selection["embedded_forward_distinct_edge_fact_count"], 4170)
        self.assertEqual(selection["embedded_reverse_total_fact_count"], 4170)
        self.assertEqual(selection["embedded_property_distinct_edge_fact_count"], 3933)

    def test_forward_coverage_and_bounded_zero_sample(self):
        positives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_analytic_data_components"
        ]
        zeros = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "aggregate_analytic_no_data_components"
        ]
        self.assertEqual(len(positives), 1713)
        self.assertEqual(sum(len(pair["expected_data_components"]) for pair in positives), 4170)
        self.assertEqual(len(zeros), 5)
        self.assertEqual(
            [pair["analytic"]["external_id"] for pair in zeros],
            self.artifact["zero_analytic_selection"]["selected_external_ids"],
        )
        self.assertEqual(
            self.artifact["zero_analytic_selection"]["total_active_zero_path_count"],
            45,
        )

    def test_reverse_coverage_is_complete_and_cap_is_deterministic(self):
        reverse = [
            pair
            for pair in self.pairs
            if pair["case_type"]
            in {
                "aggregate_data_component_analytics",
                "aggregate_data_component_analytics_capped",
                "aggregate_data_component_no_analytics",
            }
        ]
        self.assertEqual(len(reverse), 106)
        self.assertEqual(sum(pair["expected_analytic_total_count"] for pair in reverse), 4170)
        self.assertEqual(sum(pair["case_type"] == "aggregate_data_component_analytics" for pair in reverse), 64)
        self.assertEqual(sum(pair["case_type"] == "aggregate_data_component_analytics_capped" for pair in reverse), 34)
        self.assertEqual(sum(pair["case_type"] == "aggregate_data_component_no_analytics" for pair in reverse), 8)
        for pair in reverse:
            total = pair["expected_analytic_total_count"]
            all_ids = pair["provenance"]["analytic_stix_ids"]
            self.assertEqual(total, len(set(all_ids)))
            self.assertEqual(total, pair["provenance"]["distinct_supported_edge_count"])
            if total > 15:
                self.assertEqual(len(pair["expected_analytics"]), 10)
                self.assertFalse(pair["expected_analytics_complete"])
                expected_first = sorted(
                    self.artifact["parsed_data"]["data_components"][
                        pair["data_component"]["external_id"]
                    ]["analytic_external_ids"]
                )[:10]
                self.assertEqual(
                    [item["external_id"] for item in pair["expected_analytics"]],
                    expected_first,
                )
            else:
                self.assertEqual(len(pair["expected_analytics"]), total)
                self.assertTrue(pair["expected_analytics_complete"])

    def test_all_eight_orphan_components_are_explicit(self):
        orphan_ids = {
            pair["data_component"]["external_id"]
            for pair in self.pairs
            if pair["case_type"] == "aggregate_data_component_no_analytics"
        }
        self.assertEqual(
            orphan_ids,
            {
                "DC0026",
                "DC0030",
                "DC0044",
                "DC0045",
                "DC0047",
                "DC0053",
                "DC0095",
                "DC0100",
            },
        )

    def test_boolean_cases_have_natural_coverage_and_verified_negatives(self):
        positives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "positive_analytic_data_component_relationship"
        ]
        negatives = [
            pair
            for pair in self.pairs
            if pair["case_type"] == "negative_analytic_data_component_relationship"
        ]
        self.assertEqual(len(positives), 1713)
        self.assertEqual(len(negatives), 343)
        ratio = self.artifact["selection"]["explicit_boolean_negative_ratio"]
        self.assertAlmostEqual(ratio, 343 / 2056)
        self.assertGreaterEqual(ratio, 0.15)
        self.assertLessEqual(ratio, 0.20)
        path_keys = {
            (path["analytic_ref"], path["data_component_ref"])
            for row in self.artifact["parsed_data"]["analytics"].values()
            for path in row["analytic_data_component_paths"]
        }
        for pair in negatives:
            self.assertNotIn(
                (
                    pair["analytic"]["stix_id"],
                    pair["candidate_data_component"]["stix_id"],
                ),
                path_keys,
            )

    def test_property_filter_is_complete_and_evidence_is_structured(self):
        property_pairs = [
            pair
            for pair in self.pairs
            if pair["case_type"]
            in {
                "aggregate_analytic_property_data_components",
                "aggregate_analytic_no_property_data_components",
            }
        ]
        self.assertEqual(len(property_pairs), 1758)
        self.assertEqual(sum(bool(pair["expected_data_components"]) for pair in property_pairs), 1641)
        self.assertEqual(sum(not pair["expected_data_components"] for pair in property_pairs), 117)
        self.assertEqual(sum(len(pair["expected_data_components"]) for pair in property_pairs), 3933)
        for pair in property_pairs:
            evidence = pair["provenance"]["data_component_property_evidence"]
            self.assertEqual(len(evidence), len(pair["expected_data_components"]))
            self.assertTrue(
                all(row["log_source_name"].startswith("WinEventLog:") for row in evidence)
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
                "x-mitre-analytic.x_mitre_log_source_references",
            )
            self.assertEqual(
                provenance["supporting_source_row_count"],
                len(provenance["analytic_data_component_paths"]),
            )


class AnalyticDataComponentNoLlmTests(unittest.TestCase):
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
