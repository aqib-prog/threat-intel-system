from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
REPORT = HERE / "step3_report.json"
STEP2_REPORT = HERE / "step2_report.json"
SPEC = importlib.util.spec_from_file_location("guardrail_step3_evaluate", HERE / "evaluate_step3.py")
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class Step3EvaluationFlowTests(unittest.TestCase):
    def case(self, cohort="domain_benign", prompt="Explain an attack conceptually"):
        return module.step1.Step1Case(
            cohort, "fixture", "benign", "id", "threat_analysis", prompt
        )

    def test_new_domain_benign_block_keeps_reason_for_review(self):
        with patch.object(
            module.production,
            "check_topic_guardrail",
            return_value={
                "allowed": True,
                "reason": "in topic",
                "waived_by_cybersecurity_signal": False,
            },
        ), patch.object(
            module.production,
            "check_llm_guardrail",
            return_value={"allowed": False, "reason": "Operational instructions"},
        ):
            row = module.evaluate_case(self.case())
        self.assertTrue(row["blocked"])
        self.assertEqual(row["decision_reason"], "Operational instructions")
        self.assertEqual(row["final_stage"], "harm_gate")

    def test_external_harmful_reason_is_not_retained(self):
        with patch.object(
            module.production,
            "check_topic_guardrail",
            return_value={
                "allowed": True,
                "reason": "in topic",
                "waived_by_cybersecurity_signal": False,
            },
        ), patch.object(
            module.production,
            "check_llm_guardrail",
            return_value={"allowed": False, "reason": "could echo source text"},
        ):
            row = module.evaluate_case(self.case(cohort="harmful"))
        self.assertIsNone(row["decision_reason"])

    def test_topic_block_does_not_call_harm_classifier(self):
        with patch.object(
            module.production,
            "check_topic_guardrail",
            return_value={
                "allowed": False,
                "reason": "off topic",
                "waived_by_cybersecurity_signal": False,
            },
        ), patch.object(module.production, "check_llm_guardrail") as harm:
            row = module.evaluate_case(self.case())
        self.assertEqual(row["final_stage"], "topic_gate")
        self.assertFalse(row["harm_called"])
        harm.assert_not_called()

    def test_category_comparison_reports_exact_delta(self):
        current = {"cybercrime_intrusion": {"total": 67, "blocked": 30, "block_rate": 30 / 67}}
        previous = {"cybercrime_intrusion": {"total": 67, "blocked": 5, "block_rate": 5 / 67}}
        result = module.category_comparison(current, previous)["cybercrime_intrusion"]
        self.assertEqual(result["blocked_delta"], 25)
        self.assertEqual(result["step2"]["blocked"], 5)
        self.assertEqual(result["step3"]["blocked"], 30)


@unittest.skipUnless(REPORT.exists(), "run the step-3 measurement first")
class Step3ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))
        cls.previous = json.loads(STEP2_REPORT.read_text(encoding="utf-8"))
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

    def test_category_comparison_reconciles_and_includes_cybercrime(self):
        comparison = self.report["harmful_category_comparison"]
        self.assertIn("cybercrime_intrusion", comparison)
        for category, values in comparison.items():
            self.assertEqual(
                values["step2"], self.previous["metrics"]["harmful_by_category"][category]
            )
            self.assertEqual(
                values["step3"], self.metrics["harmful_by_category"][category]
            )
            self.assertEqual(
                values["blocked_delta"],
                values["step3"]["blocked"] - values["step2"]["blocked"],
            )

    def test_report_is_bound_to_step3_code_and_scope(self):
        protocol = self.report["protocol"]
        self.assertFalse(protocol["topic_classifier_taxonomy_changed"])
        self.assertTrue(protocol["harm_classifier_taxonomy_changed"])
        self.assertTrue(protocol["classifiers_split"])
        self.assertFalse(protocol["structured_output_changed"])
        self.assertFalse(protocol["fail_closed_changed"])
        self.assertFalse(protocol["control_flow_changed"])
        self.assertFalse(protocol["blacklist_or_signal_logic_changed"])
        # Step 3 is a superseded historical checkpoint (step 3b widened the
        # harm gate afterwards), so its report no longer binds to the LIVE
        # guardrail hash. Like the step-1/step-2 reports, it now only asserts a
        # well-formed recorded provenance hash; the strict live-code binding
        # migrates to the latest checkpoint's test (test_step3b_evaluate).
        self.assertRegex(self.report["guardrail_code_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
