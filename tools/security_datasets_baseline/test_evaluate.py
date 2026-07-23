from __future__ import annotations

import json
import re
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from evaluate import build_prefilter, load_rules, read_capture, score_cases


HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "corpus_manifest.json"
REPORT = HERE / "baseline_report.json"


class BaselineHarnessTests(unittest.TestCase):
    def test_manifest_is_exactly_40_unique_stratified_cases(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cases = manifest["cases"]
        self.assertEqual(len(cases), 40)
        self.assertEqual(len({item["metadata"] for item in cases}), 40)
        self.assertEqual(len({item["capture"] for item in cases}), 40)
        self.assertEqual(
            Counter(item["tactic"] for item in cases),
            Counter(manifest["tactic_quotas"]),
        )

    def test_rule_overlay_inventory_is_complete(self):
        _, inventory = load_rules()
        self.assertEqual(inventory["total"], 2156)
        self.assertEqual(
            inventory["by_origin"],
            {"falco_preview": 38, "runtime": 288, "sigma_preview": 1830},
        )

    def test_prefilter_accepts_every_representative_true_match(self):
        cases = {
            r"(?=.*(?:\\ssh\.exe))(?=.*(?:\ \-R\ )).+":
                r'Image=C:\Windows\System32\OpenSSH\ssh.exe CommandLine="ssh.exe -R 9000:localhost:80"',
            r"\b(?:rar|7z|winrar)(?:\.exe)?\b.{0,80}\s+a\b|\bcompress-archive\b":
                "powershell Compress-Archive secrets.zip",
            r"(?=.*(?:rundll32\.exe))(?=.*(?:Execute))(?=.*(?:RegRead))(?=.*(?:window\.close)).+":
                "rundll32.exe javascript Execute RegRead window.close",
            r"\A(?:(?=[\s\S]*(?:19))|(?=[\s\S]*(?:20))|(?=[\s\S]*(?:21)))[\s\S]*\Z":
                '{"UtcTime":"2020-10-20"}',
            r"\A(?=[\s\S]*(?:(?-i:\"eventName\")\s*:\s*(?-i:\")(?-i:StopLogging)(?-i:\")))[\s\S]*\Z":
                '{"eventName":"StopLogging"}',
        }
        for pattern, text in cases.items():
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(re.compile(pattern, re.IGNORECASE).search(text))
                self.assertTrue(build_prefilter(pattern).matches(text.lower()))

    def test_regex_without_mandatory_literal_fails_open(self):
        self.assertEqual(build_prefilter(r"\A\d+\Z").kind, "true")

    def test_capture_reader_accepts_linux_log_member(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "linux.zip"
            with ZipFile(archive_path, "w") as archive:
                archive.writestr("audit.log", "type=EXECVE a0=arp a1=-a\n")
            text, member, size = read_capture(archive_path)
        self.assertEqual(text, "type=EXECVE a0=arp a1=-a\n")
        self.assertEqual(member, "audit.log")
        self.assertEqual(size, len(text))

    def test_strict_scoring_does_not_auto_credit_parent_child_overlap(self):
        cases = [
            {
                "tactic": "test",
                "ground_truth": ["T1055"],
                "predictions": {
                    "T1055.001": {"confidence": "high"},
                    "T1003": {"confidence": "medium"},
                },
            }
        ]
        score = score_cases(cases, "predictions")
        self.assertEqual(score["micro_strict_exact_id"]["tp"], 0)
        self.assertEqual(score["family_aware_diagnostic"]["tp"], 1)


@unittest.skipUnless(REPORT.is_file(), "generate the full baseline report first")
class BaselineArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_report_accounts_for_the_full_corpus(self):
        self.assertEqual(self.report["corpus"]["sample_count"], 40)
        self.assertEqual(len(self.report["cases"]), 40)
        self.assertEqual(self.report["corpus"]["detector_gate_pass_count"], 40)

    def test_metrics_reconcile(self):
        for view in ("runtime_current", "layer1_preview"):
            metric = self.report["metrics"][view]["micro_strict_exact_id"]
            self.assertEqual(metric["tp"] + metric["fn"], 40)
            self.assertGreaterEqual(metric["fp"], 0)

    def test_prefilter_only_reduces_full_regex_work(self):
        performance = self.report["performance"]
        self.assertGreater(performance["prefilter_rejections"], 0)
        self.assertGreater(performance["regex_searches"], 0)

    def test_report_does_not_redistribute_event_excerpts(self):
        self.assertNotIn("evidence_excerpt", REPORT.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
