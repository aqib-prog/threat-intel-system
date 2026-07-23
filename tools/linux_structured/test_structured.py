from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
SIGMA_TOOLS = REPO / "tools/sigma_compiler"
for path in (str(BACKEND), str(SIGMA_TOOLS), str(HERE)):
    if path not in sys.path:
        sys.path.insert(0, path)

from compiler import compile_linux_structured
from log_analysis.parser import parse_log
from log_analysis.structured import StructuredCondition


SPECS_PATH = HERE / "linux_structured_rule_specs.py"
COMPILE_REPORT = HERE / "compile_report.json"
STEP2_REPORT = SIGMA_TOOLS / "full_recompile_report.json"
BASELINE_REPORT = HERE / "baseline_report.json"
STEP8_REPORT = HERE / "step8_linux_report.json"


def load_specs():
    spec = importlib.util.spec_from_file_location("step8_linux_specs", SPECS_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_fixture(name: str) -> str:
    root = Path(os.environ["SECURITY_DATASETS_ROOT"])
    capture = next((root / "datasets/atomic/linux").rglob(name))
    with ZipFile(capture) as archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        if len(members) != 1:
            raise AssertionError(f"expected one fixture member: {capture}")
        return archive.read(members[0]).decode("utf-8", errors="replace")


@unittest.skipUnless(SPECS_PATH.is_file(), "generate the Linux specs first")
class LinuxStructuredArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.specs = load_specs().STRUCTURED_BY_SOURCE_TECHNIQUE

    def condition(self, source: str, technique_id: str) -> StructuredCondition:
        return StructuredCondition.from_dict(self.specs[(source, technique_id)])

    def test_every_generated_tree_constructs(self):
        self.assertEqual(len(self.specs), 131)
        for key, tree in self.specs.items():
            with self.subTest(key=key):
                self.assertTrue(StructuredCondition.from_dict(tree).positive_fields)

    def test_step8_report_proves_precision_improvement_without_recall_loss(self):
        report = json.loads(STEP8_REPORT.read_text(encoding="utf-8"))
        baseline = report["comparison_step5_baseline"][
            "layer1_micro_strict_exact_id"
        ]
        layer2 = report["metrics"]["layer2_linux_preview"][
            "micro_strict_exact_id"
        ]
        compiler = json.loads(COMPILE_REPORT.read_text(encoding="utf-8"))

        self.assertEqual(
            report["checkpoint"],
            "Card 5 Part 1 roadmap step 8 Linux pilot only",
        )
        self.assertEqual(report["corpus"]["sample_count"], 2)
        self.assertEqual(report["corpus"]["detector_gate_pass_count"], 2)
        self.assertEqual(report["rule_inventory"]["linux_structured_rule_count"], 131)
        self.assertEqual(
            compiler["inventory"]["raw_fallback_only_candidates"], 24
        )
        self.assertEqual(
            (baseline["tp"], baseline["fp"], baseline["fn"]),
            (2, 7, 0),
        )
        self.assertEqual((layer2["tp"], layer2["fp"], layer2["fn"]), (2, 1, 0))
        self.assertGreater(layer2["precision"], baseline["precision"])
        self.assertEqual(layer2["recall"], baseline["recall"])
        self.assertEqual(report["performance"]["raw_fallback_searches"], 3)
        self.assertNotIn(
            "evidence_excerpt", STEP8_REPORT.read_text(encoding="utf-8")
        )


@unittest.skipUnless(
    os.environ.get("SECURITY_DATASETS_ROOT"),
    "set SECURITY_DATASETS_ROOT for fixture-backed extractor tests",
)
class LinuxFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.specs = load_specs().STRUCTURED_BY_SOURCE_TECHNIQUE

    def condition(self, source: str, technique_id: str) -> StructuredCondition:
        return StructuredCondition.from_dict(self.specs[(source, technique_id)])

    def test_audit_lines_group_by_message_id_and_preserve_fields(self):
        events = parse_log(read_fixture("sh_binary_padding_dd.zip"), "linux")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertFalse(event.structured_complete)
        self.assertIn("EXECVE", event.source_fields["type"])
        self.assertIn("/bin/dd", event.source_fields["image"])
        self.assertIn("dd if=/dev/zero bs=1 count=1", event.source_fields["commandline"])
        self.assertNotIn("558e25052c70 558e251641a0", event.source_fields["commandline"])

    def test_arp_rule_matches_arp_record_but_not_piped_grep_record(self):
        events = parse_log(read_fixture("sh_arp_cache.zip"), "linux")
        condition = self.condition(
            "Sigma: proc_creation_lnx_remote_system_discovery.yml", "T1018"
        )
        self.assertEqual(len(events), 2)
        self.assertTrue(condition.matches(events[0]))
        self.assertFalse(condition.matches(events[1]))

    def test_raw_cross_field_false_positives_are_rejected(self):
        events = parse_log(read_fixture("sh_binary_padding_dd.zip"), "linux")
        for source, technique_id in (
            ("Sigma: lnx_auditd_user_discovery.yml", "T1033"),
            ("Sigma: proc_creation_lnx_system_network_connections_discovery.yml", "T1049"),
            ("Sigma: lnx_auditd_web_rce.yml", "T1505.003"),
        ):
            with self.subTest(source=source):
                self.assertFalse(
                    any(self.condition(source, technique_id).matches(event) for event in events)
                )

    def test_remaining_strict_false_positive_is_a_real_secondary_match(self):
        event = parse_log(read_fixture("sh_binary_padding_dd.zip"), "linux")[0]
        condition = self.condition("Sigma: lnx_auditd_dd_delete_file.yml", "T1485")
        self.assertTrue(condition.matches(event))


@unittest.skipUnless(os.environ.get("SIGMA_ROOT"), "set SIGMA_ROOT for source tests")
class SourceBackedCompilerTests(unittest.TestCase):
    def test_generated_inventory_reproduces(self):
        step2 = json.loads(STEP2_REPORT.read_text(encoding="utf-8"))
        specs, review, inventory = compile_linux_structured(
            Path(os.environ["SIGMA_ROOT"]), step2
        )
        artifact = json.loads(COMPILE_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(inventory, artifact["inventory"])
        self.assertEqual(len(specs), inventory["structured_linux_candidates"])
        self.assertEqual(len(review), inventory["raw_fallback_only_candidates"])


if __name__ == "__main__":
    unittest.main()
