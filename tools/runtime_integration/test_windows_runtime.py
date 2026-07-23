from __future__ import annotations

import gzip
import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from build_windows import build_payload, load_module, render
from log_analysis.analyzer import analyze
from log_analysis.mappings import RULES_BY_PLATFORM
from log_analysis.parser import parse_log
from log_analysis.runtime_rules import RUNTIME_BUNDLES, load_runtime_rule_bundle


STEP2_REPORT = REPO / "tools/sigma_compiler/full_recompile_report.json"
SIGMA_SPECS = REPO / "tools/sigma_compiler/full_recompile_rule_specs.py"
STRUCTURED_SPECS = (
    REPO / "tools/windows_structured/windows_structured_rule_specs.py"
)
BUNDLE = RUNTIME_BUNDLES["windows"]
PERFORMANCE_REPORT = HERE / "windows_performance_report.json"


class WindowsRuntimeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = load_runtime_rule_bundle("windows")
        cls.rules = RULES_BY_PLATFORM["windows"]

    def test_bundle_is_mapping_candidate_only_and_reconciles(self):
        self.assertEqual(self.payload["decision_policy"], "mapping_candidate_only")
        self.assertEqual(
            self.payload["inventory"],
            {
                "mapping_candidate_count": 1598,
                "structured_condition_count": 1587,
                "raw_fallback_only_count": 11,
            },
        )
        self.assertEqual(len(self.payload["rules"]), 1598)

    def test_bundle_reproduces_byte_for_byte_from_reviewed_artifacts(self):
        report = json.loads(STEP2_REPORT.read_text(encoding="utf-8"))
        sigma = load_module(SIGMA_SPECS, "test_runtime_sigma_specs")
        structured = load_module(STRUCTURED_SPECS, "test_runtime_structured_specs")
        self.assertEqual(BUNDLE.read_bytes(), render(build_payload(report, sigma, structured)))

    def test_no_needs_review_source_is_present(self):
        report = json.loads(STEP2_REPORT.read_text(encoding="utf-8"))
        review_paths = {
            item["source_path"]
            for item in report["needs_review"]
            if item["platform"] == "windows"
        }
        runtime_paths = {item["source_path"] for item in self.payload["rules"]}
        self.assertTrue(runtime_paths.isdisjoint(review_paths))

    def test_all_candidates_are_live_and_structured_counts_match(self):
        # 144 prior runtime rules - 60 exact overlaps + 1,598 reviewed rules.
        self.assertEqual(len(self.rules), 1682)
        self.assertEqual(
            sum(rule.structured_condition is not None for rule in self.rules), 1587
        )
        self.assertEqual(
            sum(rule.structured_condition is None for rule in self.rules), 95
        )

    def test_existing_overlap_is_replaced_not_duplicated(self):
        matches = [
            rule
            for rule in self.rules
            if rule.source == "Sigma: proc_creation_win_registry_logon_script.yml"
            and rule.technique_name == "Logon Script (Windows)"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIsNotNone(matches[0].structured_condition)

    def test_structured_candidate_runs_through_production_analyzer(self):
        event = parse_log(
            json.dumps({"EventID": 8, "StartAddress": "0000000000000B80"}),
            "windows",
        )[0]
        nearby = parse_log(
            json.dumps({"EventID": 8, "StartAddress": "0000000000000B81"}),
            "windows",
        )[0]
        matched = {item.technique_name for item in analyze([event], "windows")}
        nearby_matched = {item.technique_name for item in analyze([nearby], "windows")}
        self.assertIn("Dynamic-link Library Injection", matched)
        self.assertNotIn("Dynamic-link Library Injection", nearby_matched)

    def test_bundle_is_gzip_json_not_executable_code(self):
        decoded = gzip.decompress(BUNDLE.read_bytes()).decode("utf-8")
        self.assertEqual(json.loads(decoded)["platform"], "windows")
        self.assertNotIn("import ", decoded)

    def test_recorded_performance_checkpoint_is_complete_and_improved(self):
        report = json.loads(PERFORMANCE_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(report["protocol"]["repetitions"], 9)
        self.assertEqual(report["protocol"]["warmups"], 2)
        legacy = report["variants"]["legacy"]["scenarios"]
        integrated = report["variants"]["integrated"]["scenarios"]
        self.assertEqual([item["event_count"] for item in legacy], [10, 50, 250])
        self.assertLessEqual(integrated[-1]["input_bytes"], 100_000)
        for before, after in zip(legacy, integrated, strict=True):
            self.assertLess(
                after["end_to_end_ms"]["median"],
                before["end_to_end_ms"]["median"],
            )
        self.assertTrue(
            all(item["raw_regex_evaluation_delta"] < 0 for item in report["comparison"])
        )


if __name__ == "__main__":
    unittest.main()
