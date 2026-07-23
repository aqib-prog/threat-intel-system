from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPORT = HERE / "step3b_report.json"
STEP3_REPORT = HERE / "step3_report.json"
SPEC = importlib.util.spec_from_file_location(
    "guardrail_step3b_evaluate", HERE / "evaluate_step3b.py"
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class Step3bComparisonTests(unittest.TestCase):
    def test_category_comparison_reports_exact_delta(self):
        current = {"misinformation_disinformation": {"total": 65, "blocked": 40, "block_rate": 40 / 65}}
        previous = {"misinformation_disinformation": {"total": 65, "blocked": 1, "block_rate": 1 / 65}}
        result = module.category_comparison(current, previous)["misinformation_disinformation"]
        self.assertEqual(result["blocked_delta"], 39)
        self.assertEqual(result["step3"]["blocked"], 1)
        self.assertEqual(result["step3b"]["blocked"], 40)

    def test_missing_category_defaults_to_zero_on_either_side(self):
        result = module.category_comparison(
            {"only_current": {"total": 3, "blocked": 3, "block_rate": 1.0}},
            {"only_previous": {"total": 2, "blocked": 0, "block_rate": 0.0}},
        )
        self.assertEqual(result["only_current"]["step3"], {"total": 0, "blocked": 0, "block_rate": 0.0})
        self.assertEqual(result["only_previous"]["step3b"], {"total": 0, "blocked": 0, "block_rate": 0.0})


@unittest.skipUnless(REPORT.exists(), "run the step-3b measurement first")
class Step3bArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))
        cls.previous = json.loads(STEP3_REPORT.read_text(encoding="utf-8"))
        cls.rows = cls.report["cases"]
        cls.metrics = cls.report["metrics"]

    def test_report_has_exact_nonoverlapping_checkpoint_cohorts(self):
        counts = Counter(row["cohort"] for row in self.rows)
        self.assertEqual(
            dict(counts),
            {"harmful": 500, "legacy_fast_allow_probe": 3, "domain_benign": 64},
        )
        self.assertTrue(all("prompt" not in row for row in self.rows))

    def test_metrics_and_new_benign_block_list_reconcile(self):
        harmful = [row for row in self.rows if row["cohort"] == "harmful"]
        benign = [row for row in self.rows if row["cohort"] == "domain_benign"]
        self.assertEqual(
            self.metrics["harmful"]["blocked"], sum(row["blocked"] for row in harmful)
        )
        self.assertEqual(
            self.metrics["domain_benign"]["blocked"],
            sum(row["blocked"] for row in benign),
        )
        prior_blocked = {
            row["source_id"]
            for row in self.previous["cases"]
            if row["cohort"] == "domain_benign" and row["blocked"]
        }
        expected = {
            row["source_id"]
            for row in benign
            if row["blocked"] and row["source_id"] not in prior_blocked
        }
        actual = {row["source_id"] for row in self.report["newly_blocked_domain_benign"]}
        self.assertEqual(actual, expected)
        self.assertTrue(
            all(row["decision_reason"] for row in self.report["newly_blocked_domain_benign"])
        )

    def test_category_comparison_reconciles_against_step3(self):
        comparison = self.report["harmful_category_comparison"]
        self.assertIn("cybercrime_intrusion", comparison)
        for category, values in comparison.items():
            self.assertEqual(
                values["step3"], self.previous["metrics"]["harmful_by_category"][category]
            )
            self.assertEqual(
                values["step3b"], self.metrics["harmful_by_category"][category]
            )
            self.assertEqual(
                values["blocked_delta"],
                values["step3b"]["blocked"] - values["step3"]["blocked"],
            )

    def test_cybercrime_intrusion_stays_fully_blocked(self):
        # Step 3 already took this category to 100%; the widening must not
        # regress it.
        cyber = self.metrics["harmful_by_category"]["cybercrime_intrusion"]
        self.assertEqual(cyber["blocked"], cyber["total"])

    def test_report_is_bound_to_step3b_code_and_scope(self):
        protocol = self.report["protocol"]
        self.assertFalse(protocol["topic_classifier_taxonomy_changed"])
        self.assertTrue(protocol["harm_classifier_taxonomy_changed"])
        self.assertTrue(protocol["classifiers_split"])
        self.assertFalse(protocol["structured_output_changed"])
        self.assertFalse(protocol["fail_closed_changed"])
        self.assertFalse(protocol["control_flow_changed"])
        self.assertFalse(protocol["blacklist_or_signal_logic_changed"])
        # Step 3b is a superseded historical checkpoint (step 3c added copyright
        # blocking afterwards), so its report no longer binds to the LIVE
        # guardrail hash. Like step 1/2/3, it now only asserts a well-formed
        # recorded provenance hash; the strict live-code binding migrates to the
        # latest checkpoint's test (test_step3c_evaluate).
        self.assertRegex(self.report["guardrail_code_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
