from __future__ import annotations

import gzip
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

from build_linux import build_payload, load_module, render
from log_analysis.analyzer import analyze
from log_analysis.mappings import RULES_BY_PLATFORM
from log_analysis.parser import parse_log
from log_analysis.runtime_rules import RUNTIME_BUNDLES, load_runtime_rule_bundle


STEP2_REPORT = REPO / "tools/sigma_compiler/full_recompile_report.json"
SIGMA_SPECS = REPO / "tools/sigma_compiler/full_recompile_rule_specs.py"
STRUCTURED_SPECS = REPO / "tools/linux_structured/linux_structured_rule_specs.py"
BUNDLE = RUNTIME_BUNDLES["linux"]
PERFORMANCE_REPORT = HERE / "linux_performance_report.json"


def audit_event(executable: str, command: str, argument: str) -> str:
    message = "1721152801.001:10000"
    return "\n".join(
        (
            f'type=SYSCALL msg=audit({message}): arch=c000003e syscall=59 success=yes '
            f'exit=0 pid=4100 ppid=1 auid=1000 uid=1000 comm="{command}" '
            f'exe="{executable}" key="process_exec"',
            f'type=EXECVE msg=audit({message}): argc=2 a0="{command}" a1="{argument}"',
            f'type=CWD msg=audit({message}): cwd="/opt/example"',
        )
    )


class LinuxRuntimeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = load_runtime_rule_bundle("linux")
        cls.rules = RULES_BY_PLATFORM["linux"]

    def test_bundle_is_mapping_candidate_only_and_reconciles(self):
        self.assertEqual(self.payload["decision_policy"], "mapping_candidate_only")
        self.assertEqual(
            self.payload["inventory"],
            {
                "mapping_candidate_count": 155,
                "structured_condition_count": 131,
                "raw_fallback_only_count": 24,
            },
        )
        self.assertEqual(len(self.payload["rules"]), 155)

    def test_bundle_reproduces_byte_for_byte_from_reviewed_artifacts(self):
        report = json.loads(STEP2_REPORT.read_text(encoding="utf-8"))
        sigma = load_module(SIGMA_SPECS, "test_runtime_linux_sigma_specs")
        structured = load_module(STRUCTURED_SPECS, "test_runtime_linux_structured_specs")
        self.assertEqual(BUNDLE.read_bytes(), render(build_payload(report, sigma, structured)))

    def test_no_needs_review_source_is_present(self):
        report = json.loads(STEP2_REPORT.read_text(encoding="utf-8"))
        review_paths = {
            item["source_path"]
            for item in report["needs_review"]
            if item["platform"] == "linux"
        }
        runtime_paths = {item["source_path"] for item in self.payload["rules"]}
        self.assertTrue(runtime_paths.isdisjoint(review_paths))

    def test_all_candidates_are_live_and_structured_counts_match(self):
        # 54 prior runtime rules - 20 exact overlaps + 155 reviewed rules.
        self.assertEqual(len(self.rules), 189)
        self.assertEqual(sum(rule.structured_condition is not None for rule in self.rules), 131)
        self.assertEqual(sum(rule.structured_condition is None for rule in self.rules), 58)

    def test_existing_overlap_is_replaced_not_duplicated(self):
        matches = [
            rule
            for rule in self.rules
            if rule.source == "Sigma: proc_creation_lnx_base64_decode.yml"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIsNotNone(matches[0].structured_condition)

    def test_structured_candidate_runs_through_production_analyzer(self):
        positive = parse_log(audit_event("/usr/sbin/arp", "arp", "-a"), "linux")
        nearby = parse_log(audit_event("/usr/sbin/arp", "arp", "--help"), "linux")
        matched = {item.technique_name for item in analyze(positive, "linux")}
        nearby_matched = {item.technique_name for item in analyze(nearby, "linux")}
        self.assertIn("Remote System Discovery", matched)
        self.assertNotIn("Remote System Discovery", nearby_matched)

    def test_bundle_is_gzip_json_not_executable_code(self):
        decoded = gzip.decompress(BUNDLE.read_bytes()).decode("utf-8")
        self.assertEqual(json.loads(decoded)["platform"], "linux")
        self.assertNotIn("import ", decoded)

    def test_recorded_performance_checkpoint_is_complete(self):
        report = json.loads(PERFORMANCE_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(report["protocol"]["platform"], "linux")
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
            all(
                item["structured_evaluation_delta"] > 0
                for item in report["comparison"]
            )
        )


if __name__ == "__main__":
    unittest.main()
