"""Hermetic tests for the targeted live repeatability gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "regression" / "run_repeatability_suite.py"
SPEC = importlib.util.spec_from_file_location("repeatability_suite", SCRIPT)
repeatability = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = repeatability
SPEC.loader.exec_module(repeatability)


def mebromi_response(*, latency_ms: int = 1):
    answer = (
        "Techniques explicitly connected to Trojan.Mebromi (S0001):\n"
        "- System Firmware (T1542.001)"
    )
    source = {
        "name": "Trojan.Mebromi",
        "external_id": "S0001",
        "node_type": "Malware",
        "url": "https://attack.mitre.org/software/S0001",
    }
    return {
        "query": "What techniques does Trojan.Mebromi use?",
        "answer": answer,
        "response": answer,
        "filters": {"malware": ["Trojan.Mebromi"]},
        "allowed": True,
        "guardrail_category": None,
        "retrieved_count": 1,
        "context_count": 1,
        "latency_ms": latency_ms,
        "answer_source": "rag",
        "nodes": [source],
        "sources": [source],
        "answer_sections": [],
        "answer_presentation": None,
        "log_evidence": [],
        "segments": [],
        "grounded_ids": ["S0001", "T1542.001"],
        "suggestions": [],
        "suggestion_actions": [],
        "correction": None,
    }


class RepeatabilitySuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = repeatability.live.load_entity_catalog()

    def test_matrix_has_lookup_mixed_and_typo_profile_coverage(self):
        scenarios = repeatability.scenarios("core")
        self.assertEqual(len(scenarios), 10)
        self.assertEqual(
            [item.id for item in scenarios[:3]],
            ["mebromi-canonical", "mebromi-natural", "mebromi-id"],
        )
        mixed_query = scenarios[3].query
        for marker in (
            "Trojan.Mebromi",
            "T1001",
            repeatability.TYPO_ID,
            "capital of France",
            "credential-stealing",
            '"EventID": 1',
            "ignore previous instructions",
        ):
            self.assertIn(marker, mixed_query)
        self.assertEqual(
            [item.id for item in scenarios[4:]],
            [
                "typo-profile-apt29-os",
                "typo-profile-apt29-markdown-wrapped",
                "typo-profile-fin7-iz",
                "typo-profile-lazarus-double-scaffold",
                "typo-profile-sandworm-polite",
                "typo-profile-apt29-auxiliary",
            ],
        )

    def test_production_matrix_covers_verified_semantic_layers(self):
        scenarios = repeatability.scenarios("production")
        ids = [item.id for item in scenarios]
        self.assertEqual(len(ids), 118)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            sum(item.startswith("matrix::golden::") for item in ids),
            52,
        )
        self.assertEqual(
            sum(item.startswith("matrix::mixed::") for item in ids),
            20,
        )
        self.assertEqual(
            sum(item.startswith("matrix::multi::") for item in ids),
            23,
        )
        self.assertEqual(
            sum(item.startswith("matrix::guardrail::") for item in ids),
            14,
        )
        self.assertIn("mebromi-natural", ids)
        self.assertIn("typo-profile-apt29-os", ids)
        self.assertIn("typo-profile-apt29-markdown-wrapped", ids)
        self.assertIn("typo-profile-apt29-auxiliary", ids)
        self.assertIn("mebromi-id", ids)
        self.assertIn("comprehensive-mixed-turn", ids)

    def test_command_gate_profile_is_focused_and_distinct(self):
        scenarios = repeatability.scenarios("command-gate")
        self.assertEqual(
            [item.id for item in scenarios],
            [
                "command-gate-ragas-multiline",
                "command-gate-powershell-prompt",
                "command-gate-project-cli",
            ],
        )
        self.assertIn("evaluate_rag.py", scenarios[0].query)
        self.assertIn("Get-Process", scenarios[1].query)
        self.assertIn("--input", scenarios[2].query)

    def test_command_gate_validator_rejects_any_factual_payload(self):
        response = mebromi_response()
        response.update(
            {
                "answer": repeatability.OPERATIONAL_BLOCK_MESSAGE,
                "response": repeatability.OPERATIONAL_BLOCK_MESSAGE,
                "allowed": False,
                "guardrail_category": "unsupported_operational_command",
                "retrieved_count": 0,
                "context_count": 0,
                "nodes": [],
                "sources": [],
                "segments": [],
                "grounded_ids": [],
            }
        )
        self.assertEqual(
            repeatability.validate_operational_command_block(
                response, self.catalog
            ),
            [],
        )
        response["nodes"] = [{"external_id": "T1055"}]
        errors = repeatability.validate_operational_command_block(
            response, self.catalog
        )
        self.assertTrue(any("non-empty nodes" in item for item in errors))

    def test_stability_ignores_latency_but_not_source_drift(self):
        first = mebromi_response(latency_ms=10)
        second = mebromi_response(latency_ms=999)
        self.assertEqual(
            repeatability.stable_hash(first),
            repeatability.stable_hash(second),
        )
        second["sources"][0]["external_id"] = "S9999"
        self.assertNotEqual(
            repeatability.stable_hash(first),
            repeatability.stable_hash(second),
        )
        self.assertIn(
            "$.sources[0].external_id",
            repeatability.differing_paths(
                repeatability.stable_projection(first),
                repeatability.stable_projection(second),
            ),
        )

    def test_mebromi_validator_checks_pinned_answer_and_grounding(self):
        response = mebromi_response()
        self.assertEqual(
            repeatability.validate_mebromi(response, self.catalog),
            [],
        )
        response["answer"] = response["answer"].replace("T1542.001", "T1055")
        errors = repeatability.validate_mebromi(response, self.catalog)
        self.assertTrue(any("missing pinned IDs" in item for item in errors))
        self.assertTrue(any("unexpected ATT&CK IDs" in item for item in errors))

    def test_pinned_reference_guard_fact_accepts_only_process_creation(self):
        response = mebromi_response()
        response["answer"] = "Process Creation (DC0032) records process starts."
        response["sources"] = [{"external_id": "DC0032"}]
        response["nodes"] = []
        self.assertEqual(
            repeatability._pinned_guardrail_fact_errors(
                "guardrail::reference_guard::ref-04",
                response,
                self.catalog,
            ),
            [],
        )

    def test_pinned_reference_guard_fact_rejects_old_wrong_answer(self):
        response = mebromi_response()
        response["answer"] = "Process Injection (T1055)"
        response["sources"] = [{"external_id": "T1055"}]
        response["nodes"] = []
        errors = repeatability._pinned_guardrail_fact_errors(
            "guardrail::reference_guard::ref-04",
            response,
            self.catalog,
        )
        self.assertTrue(any("missing ATT&CK IDs" in item for item in errors))
        self.assertTrue(any("unrelated source IDs" in item for item in errors))
        self.assertTrue(any("forbidden IDs" in item for item in errors))

    def test_pinned_cloud_fact_rejects_unrelated_analytic(self):
        response = mebromi_response()
        response["answer"] = (
            "AssumeRole detections use AN0717, AN1105, and AN1594."
        )
        response["sources"] = [
            {"external_id": "AN0717"},
            {"external_id": "AN1105"},
            {"external_id": "AN1594"},
        ]
        response["nodes"] = []
        errors = repeatability._pinned_guardrail_fact_errors(
            "guardrail::domain_benign::cloud-01",
            response,
            self.catalog,
        )
        self.assertTrue(any("unrelated source IDs" in item for item in errors))
        self.assertTrue(any("forbidden IDs" in item for item in errors))

    def test_corrected_action_must_be_unique_across_response_units(self):
        response = mebromi_response()
        response["suggestion_actions"] = [
            {
                "label": "Adversary-in-the-Middle (T1557)",
                "query": "What is T1557?",
                "original": "T10557",
                "replacement": "T1557",
            },
            {
                "label": "T1055 (Process Injection)",
                "query": "What is T1055?",
                "original": "T10557",
                "replacement": "T1055",
            }
        ]
        self.assertEqual(
            repeatability.corrected_suggestion_query(response),
            "What is T1055?",
        )
        response["suggestion_actions"].append(
            {
                "label": "T1055",
                "query": "Explain T1055",
                "original": "T10557",
                "replacement": "T1055",
            }
        )
        self.assertIsNone(
            repeatability.corrected_suggestion_query(response)
        )

    def test_partial_checkpoint_is_pending_and_complete_resume_makes_no_call(self):
        scenario = repeatability.scenarios("core")[0]
        first = {
            "repeat": 1,
            "elapsed_seconds": 0.1,
            "retry_count": 0,
            "stable_sha256": repeatability.stable_hash(mebromi_response()),
            "validation_errors": [],
            "response": mebromi_response(),
        }
        partial = repeatability.summarize_attempts(scenario, [first], 3)
        self.assertEqual(partial["status"], "PENDING")

        completed = [
            {**first, "repeat": index}
            for index in range(1, 4)
        ]
        with mock.patch.object(
            repeatability.live,
            "request_with_rate_limit_retry",
            side_effect=AssertionError("completed resume must not call API"),
        ):
            result = repeatability.run_repeated(
                scenario=scenario,
                repeats=3,
                base="http://localhost:8000",
                api_key="",
                timeout=1,
                max_retries=0,
                catalog=self.catalog,
                existing_attempts=completed,
            )
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["identical"])

    def test_plan_fingerprint_binds_profile_repeats_and_queries(self):
        planned = repeatability.scenarios("core")
        baseline = repeatability.plan_fingerprint(
            planned, profile="core", repeats=3
        )
        self.assertNotEqual(
            baseline,
            repeatability.plan_fingerprint(
                planned, profile="core", repeats=2
            ),
        )
        changed = list(planned)
        changed[0] = repeatability.Scenario(
            id=planned[0].id,
            query=planned[0].query + " changed",
            purpose=planned[0].purpose,
            validator=planned[0].validator,
        )
        self.assertNotEqual(
            baseline,
            repeatability.plan_fingerprint(
                changed, profile="core", repeats=3
            ),
        )


if __name__ == "__main__":
    unittest.main()
