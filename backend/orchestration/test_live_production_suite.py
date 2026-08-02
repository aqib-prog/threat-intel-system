"""Tests for the comprehensive live suite's truth-comparison logic."""

from __future__ import annotations

from collections import Counter
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest import mock
import urllib.error


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "regression" / "run_live_production_suite.py"
SPEC = importlib.util.spec_from_file_location("live_production_suite", SCRIPT)
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)


def fake_unit(answer: str, *, grounded_ids: list[str] | None = None):
    return {
        "answer": answer,
        "allowed": True,
        "guardrail_category": None,
        "answer_source": "rag",
        "grounded_ids": grounded_ids or sorted(suite.extract_mitre_ids(answer)),
        "nodes": [
            {
                "name": "fixture source",
                "external_id": "T1001",
                "node_type": "Technique",
                "url": "https://attack.mitre.org/techniques/T1001",
            }
        ],
    }


def fake_response(answer: str, *, grounded_ids: list[str] | None = None):
    unit = fake_unit(answer, grounded_ids=grounded_ids)
    return {
        "query": "What mitigates T1001 (Data Obfuscation)?",
        **unit,
        "response": answer,
        "filters": {},
        "sources": list(unit["nodes"]),
        "retrieved_count": 1,
        "context_count": 1,
        "latency_ms": 1,
        "answer_sections": [],
        "answer_presentation": None,
        "log_evidence": [],
        "segments": [],
        "suggestions": [],
        "suggestion_actions": [],
        "correction": None,
    }


class ComprehensiveLiveSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = suite.load_entity_catalog()
        cls.golden_cases, cls.golden_index = suite.load_golden_index()

    def test_comprehensive_matrix_has_all_four_layers_and_270_cases(self):
        cases = suite.build_cases("comprehensive")
        self.assertEqual(len(cases), 270)
        self.assertEqual(
            Counter(case["suite"] for case in cases),
            {
                "golden": 156,
                "multi-intent": 24,
                "mixed": 20,
                "guardrail": 70,
            },
        )

    def test_guardrail_layer_contains_all_committed_allow_cases(self):
        cases = suite.load_guardrail_allow_cases()
        self.assertEqual(
            Counter(case["cohort"] for case in cases),
            {"domain_benign": 64, "reference_guard": 6},
        )
        self.assertTrue(all(case["expected_allowed"] for case in cases))
        self.assertTrue(all(len(case["artifact_sha256"]) == 64 for case in cases))

    def test_golden_layer_covers_13_relationships_and_all_variants(self):
        self.assertEqual(
            len({case["relationship_type"] for case in self.golden_cases}),
            13,
        )
        self.assertEqual(
            Counter(case["variant_kind"] for case in self.golden_cases),
            {"original": 52, "typo": 52, "reworded": 52},
        )

    def test_every_expected_id_exists_in_pinned_entity_catalog(self):
        expected_ids = {
            external_id
            for case in self.golden_cases
            for external_id in suite.extract_mitre_ids(case["reference"])
        }
        self.assertEqual(len(expected_ids), 267)
        self.assertEqual(expected_ids - set(self.catalog), set())

    def test_ta_actor_name_is_not_mistaken_for_a_tactic_id(self):
        extracted = suite.extract_catalogued_mitre_ids(
            "Actors: TA2541. Tactics: TA0011 (Command and Control). "
            "Unknown technique T9999.",
            self.catalog,
        )
        self.assertNotIn("TA2541", extracted)
        self.assertIn("TA0011", extracted)
        self.assertIn("T9999", extracted)

    def test_exact_golden_answer_passes(self):
        case = self.golden_index["enterprise-mitigations-t1001::original"]
        expected_ids = sorted(suite.extract_mitre_ids(case["reference"]))
        comparison, errors = suite.compare_golden_answer(
            fake_unit(case["reference"], grounded_ids=expected_ids),
            case,
            self.catalog,
        )
        self.assertEqual(errors, [])
        self.assertEqual(comparison["missing_expected_ids"], [])
        self.assertEqual(comparison["unexpected_answer_ids"], [])
        self.assertEqual(comparison["ungrounded_answer_ids"], [])

    def test_missing_extra_and_ungrounded_ids_are_separate_failures(self):
        case = self.golden_index["enterprise-mitigations-t1001::original"]
        wrong = "T1001 (Data Obfuscation) is mitigated by T9999 (Invented)."
        comparison, errors = suite.compare_golden_answer(
            fake_unit(wrong, grounded_ids=["T1001"]),
            case,
            self.catalog,
        )
        codes = {item["code"] for item in errors}
        self.assertIn("missing_expected_ids", codes)
        self.assertIn("unexpected_answer_ids", codes)
        self.assertIn("ungrounded_answer_ids", codes)
        self.assertEqual(comparison["missing_expected_ids"], ["M1031"])
        self.assertEqual(comparison["unexpected_answer_ids"], ["T9999"])
        self.assertEqual(comparison["ungrounded_answer_ids"], ["T9999"])

    def test_correct_ids_are_sufficient_without_repeating_entity_names(self):
        case = self.golden_index["enterprise-mitigations-t1001::original"]
        answer = "T1001 is mitigated by M1031."
        comparison, errors = suite.compare_golden_answer(
            fake_unit(answer),
            case,
            self.catalog,
        )
        self.assertEqual(errors, [])
        self.assertEqual(comparison["missing_expected_ids"], [])

    def test_canonical_names_are_sufficient_without_repeating_ids(self):
        case = self.golden_index["enterprise-mitigations-t1001::original"]
        answer = (
            "Data Obfuscation is mitigated by Network Intrusion Prevention."
        )
        comparison, errors = suite.compare_golden_answer(
            fake_unit(answer, grounded_ids=[]),
            case,
            self.catalog,
        )
        self.assertEqual(errors, [])
        self.assertEqual(comparison["missing_expected_ids"], [])

    def test_adversarial_contrast_entities_are_not_mandatory(self):
        case = self.golden_index[
            "enterprise-technique-tactic-adversarial-negative-t1001-ta0003::original"
        ]
        answer = (
            "No active relationship exists between T1001 (Data Obfuscation) "
            "and TA0003 (Persistence) in the pinned snapshot."
        )
        comparison, errors = suite.compare_golden_answer(
            fake_unit(answer),
            case,
            self.catalog,
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            set(comparison["expected_ids"]),
            {"T1001", "TA0003"},
        )

    def test_negative_relationship_cannot_flip_to_positive(self):
        case = {
            "reference": (
                "No active relationship exists between G0001 (Axiom) and "
                "T1496 (Resource Hijacking) in the pinned snapshot."
            )
        }
        answer = "G0001 (Axiom) uses T1496 (Resource Hijacking)."
        _, errors = suite.compare_golden_answer(
            fake_unit(answer),
            case,
            self.catalog,
        )
        self.assertIn(
            "negative_polarity_lost",
            {item["code"] for item in errors},
        )

    def test_empty_public_api_turn_expects_validation_422(self):
        case = next(
            item
            for item in suite.build_cases("multi-intent")
            if item["id"] == "multi::empty-turn"
        )
        self.assertEqual(case["expected_http_status"], 422)
        saved = {
            "id": case["id"],
            "suite": case["suite"],
            "category": case["category"],
            "status": "PASS",
            "errors": [],
            "response": {"http_status": 422, "body": "{}"},
        }
        revalidated = suite.revalidate_saved_row(
            case, saved, self.catalog
        )
        self.assertIsNotNone(revalidated)
        assert revalidated is not None
        self.assertEqual(revalidated["status"], "PASS")

    def test_offtopic_segment_may_use_the_committed_soft_refusal(self):
        scenario = next(
            item
            for item in suite.load_multi_intent_scenarios()[0]
            if item["id"] == "multi-offtopic-plus-question"
        )
        cyber_case = self.golden_index[
            "campaign-attributed-groups-c0022::original"
        ]
        cyber_ids = sorted(suite.extract_mitre_ids(cyber_case["reference"]))
        response = fake_response("combined")
        response["segments"] = [
            fake_unit(
                "I don't have enough information about this in my knowledge base.",
                grounded_ids=[],
            ),
            fake_unit(cyber_case["reference"], grounded_ids=cyber_ids),
        ]
        comparison, errors = suite.validate_multi_intent_case(
            scenario,
            response,
            self.golden_index,
            self.catalog,
        )
        self.assertEqual(errors, [])
        self.assertEqual(len(comparison["segment_comparisons"]), 1)

    def test_frontend_contract_rejects_alias_and_source_url_drift(self):
        response = {
            "query": "What is T1001?",
            "answer": "answer",
            "response": "different",
            "filters": {},
            "allowed": True,
            "guardrail_category": None,
            "retrieved_count": 1,
            "context_count": 1,
            "latency_ms": 1,
            "answer_source": "rag",
            "nodes": [{"name": "one", "node_type": "Technique"}],
            "sources": [
                {
                    "name": "one",
                    "node_type": "Technique",
                    "external_id": "T1001",
                    "url": "https://example.com/not-mitre",
                }
            ],
            "answer_sections": [],
            "answer_presentation": None,
            "log_evidence": [],
            "segments": [],
            "grounded_ids": [],
            "suggestions": [],
            "suggestion_actions": [],
            "correction": None,
        }
        codes = {
            item["code"] for item in suite.validate_api_contract(response)
        }
        self.assertIn("schema_answer_alias_mismatch", codes)
        self.assertIn("schema_source_alias_mismatch", codes)
        self.assertIn("non_authoritative_mitre_url", codes)

    def test_summary_exposes_fact_and_hallucination_failure_counts(self):
        results = [
            {
                "suite": "golden",
                "category": "one",
                "status": "FAIL",
                "errors": [
                    {"code": "missing_expected_ids"},
                    {"code": "unexpected_answer_ids"},
                    {"code": "ungrounded_answer_ids"},
                ],
            },
            {
                "suite": "mixed",
                "category": "two",
                "status": "PASS",
                "errors": [],
            },
        ]
        summary = suite.derive_summary(results)
        self.assertEqual(summary["missing_fact_cases"], 1)
        self.assertEqual(summary["unexpected_fact_cases"], 1)
        self.assertEqual(summary["possible_hallucination_cases"], 1)

    def test_resume_revalidates_saved_response_instead_of_trusting_old_status(self):
        case = next(
            item
            for item in suite.build_cases("golden")
            if item["id"] == "golden::enterprise-mitigations-t1001::original"
        )
        expected = case["golden"]["reference"]
        expected_ids = sorted(suite.extract_mitre_ids(expected))
        saved = {
            "id": case["id"],
            "suite": "golden",
            "category": case["category"],
            "purpose": case["purpose"],
            "query": case["query"],
            "status": "FAIL",
            "errors": [{"code": "stale_validator_error"}],
            "response": fake_response(expected, grounded_ids=expected_ids),
        }
        revalidated = suite.revalidate_saved_row(
            case, saved, self.catalog
        )
        self.assertIsNotNone(revalidated)
        assert revalidated is not None
        self.assertEqual(revalidated["status"], "PASS")
        self.assertEqual(revalidated["errors"], [])
        self.assertTrue(revalidated["resumed_revalidated"])

    def test_transient_503_is_retried(self):
        transient = urllib.error.HTTPError(
            "http://localhost/query",
            503,
            "unavailable",
            {},
            None,
        )
        with mock.patch.object(
            suite.mixed,
            "_request_json",
            side_effect=[transient, {"answer": "ok"}],
        ), mock.patch.object(suite.time, "sleep") as sleep:
            response, retries = suite.request_with_rate_limit_retry(
                "http://localhost/query",
                api_key="",
                query="test",
                timeout=1,
                max_retries=2,
            )
        self.assertEqual(response, {"answer": "ok"})
        self.assertEqual(retries, 1)
        sleep.assert_called_once_with(2.0)

    def test_progress_bar_shows_counts_and_eta(self):
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            suite.print_progress(
                completed=2,
                total=4,
                results=[
                    {
                        "status": "PASS",
                        "elapsed_seconds": 2.0,
                    },
                    {
                        "status": "FAIL",
                        "elapsed_seconds": 2.0,
                    },
                ],
                session_started=suite.time.perf_counter(),
            )
        rendered = output.getvalue()
        self.assertIn("2/4 ( 50.0%)", rendered)
        self.assertIn("PASS=1 FAIL=1 ERROR=0", rendered)
        self.assertIn("ETA=", rendered)


if __name__ == "__main__":
    unittest.main()
