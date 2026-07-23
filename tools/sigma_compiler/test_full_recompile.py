from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPORT = HERE / "full_recompile_report.json"
SPECS = HERE / "full_recompile_rule_specs.py"


@unittest.skipUnless(REPORT.is_file() and SPECS.is_file(), "generate full step-2 artifacts first")
class FullRecompileArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))
        spec = importlib.util.spec_from_file_location("full_recompile_rule_specs", SPECS)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        cls.specs = module.RULE_SPECS_BY_PLATFORM

    def test_all_four_platforms_are_present(self):
        self.assertEqual(set(self.specs), {"windows", "linux", "macos", "aws"})
        self.assertTrue(all(self.specs[platform] for platform in self.specs))

    def test_spec_count_matches_report(self):
        count = sum(len(items) for items in self.specs.values())
        self.assertEqual(count, self.report["mapping_candidate_count"])

    def test_every_generated_pattern_compiles(self):
        for platform, items in self.specs.items():
            for item in items:
                kwargs = item["rule_kwargs"]
                self.assertEqual(kwargs["platform"], platform)
                re.compile(kwargs["pattern"], re.IGNORECASE)

    def test_review_list_preserves_every_non_candidate(self):
        inventory = self.report["inventory"]
        self.assertEqual(
            inventory["input_rule_count"],
            self.report["mapping_candidate_count"] + self.report["needs_review_count"],
        )

    def test_semantic_diff_partitions_old_and_proposed_sigma_rules(self):
        diff = self.report["diff_against_current_mappings"]
        self.assertEqual(
            diff["current_generated_sigma_section_count"],
            diff["retained_source_technique_mapping_count"]
            + diff["removed_source_technique_mapping_count"],
        )
        self.assertEqual(
            diff["proposed_generated_sigma_rule_count"],
            diff["retained_source_technique_mapping_count"]
            + diff["new_source_technique_mapping_count"],
        )
        self.assertEqual(
            len(diff["new_source_technique_mappings"]),
            diff["new_source_technique_mapping_count"],
        )
        self.assertEqual(
            len(diff["removed_source_technique_mappings"]),
            diff["removed_source_technique_mapping_count"],
        )
        self.assertEqual(
            len(diff["retained_mapping_regex_changes"]),
            diff["retained_mapping_regex_changed_count"],
        )

    def test_parent_hints_exist_for_duplicate_names(self):
        candidates = self.report["mapping_candidates"]
        by_name: dict[str, set[str]] = {}
        for item in candidates:
            by_name.setdefault(item["technique_name"], set()).add(item["technique_id"])
        duplicate_names = {name for name, ids in by_name.items() if len(ids) > 1}
        for item in candidates:
            if item["technique_name"] in duplicate_names:
                self.assertIsNotNone(item["parent_hint"], item["source"])

    def test_runtime_mapping_rules_can_be_constructed(self):
        backend = Path(__file__).resolve().parents[2] / "backend"
        sys.path.insert(0, str(backend))
        from log_analysis.mappings import _rule

        constructed = [
            _rule(**item["rule_kwargs"])
            for items in self.specs.values()
            for item in items
        ]
        self.assertEqual(len(constructed), self.report["mapping_candidate_count"])

    def test_new_cross_platform_rules_match_positive_not_nearby_negative(self):
        """Hand-check one newly generated rule per target platform."""
        cases = {
            "create_remote_thread_win_hktl_cobaltstrike.yml": {
                "technique_id": "T1055.001",
                "positive": "StartAddress=0000000000000B80 TargetImage=C:\\Windows\\System32\\notepad.exe",
                "negative": "StartAddress=0000000000000B81 TargetImage=C:\\Windows\\System32\\notepad.exe",
            },
            "file_event_lnx_doas_conf_creation.yml": {
                "technique_id": "T1548",
                "positive": 'TargetFilename="/etc/doas.conf" action=CREATE',
                "negative": 'TargetFilename="/etc/sudoers" action=CREATE',
            },
            "file_event_macos_emond_launch_daemon.yml": {
                "technique_id": "T1546.014",
                "positive": 'TargetFilename="/etc/emond.d/rules/persist.plist" action=create',
                "negative": 'TargetFilename="/etc/emond.d/rules/persist.txt" action=create',
            },
            "aws_cloudtrail_console_login_success_without_mfa.yml": {
                "technique_id": "T1078.004",
                "positive": (
                    '{"eventName":"ConsoleLogin","additionalEventData":{"MFAUsed":"NO"},'
                    '"responseElements":{"ConsoleLogin":"Success"}}'
                ),
                "negative": (
                    '{"eventName":"ConsoleLogin","additionalEventData":{"MFAUsed":"YES"},'
                    '"responseElements":{"ConsoleLogin":"Success"}}'
                ),
            },
        }
        candidates = {item["source"]: item for item in self.report["mapping_candidates"]}
        for source, case in cases.items():
            with self.subTest(source=source):
                item = candidates[source]
                self.assertEqual(item["technique_id"], case["technique_id"])
                pattern = re.compile(item["pattern"], re.IGNORECASE)
                self.assertIsNotNone(pattern.search(case["positive"]))
                self.assertIsNone(pattern.search(case["negative"]))


if __name__ == "__main__":
    unittest.main()
