from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_evaluator",
    HERE / "evaluate_rag.py",
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class RagasPrototypeHarnessTests(unittest.TestCase):
    def test_fixed_sample_has_fifteen_cases_across_all_relationship_types(self):
        cases = module.load_sample_cases()
        self.assertEqual(len(cases), 15)
        self.assertEqual(len({case["case_id"] for case in cases}), 15)
        self.assertEqual(
            {case["relationship_type"] for case in cases},
            {
                "campaign_group",
                "group_software",
                "group_technique",
                "software_technique",
                "technique_detection_strategy",
                "technique_mitigation",
                "technique_tactic",
            },
        )

    def test_every_selected_case_has_pinned_artifact_hash_and_reference(self):
        for case in module.load_sample_cases():
            self.assertEqual(len(case["golden_artifact_sha256"]), 64)
            self.assertTrue(case["question"])
            self.assertTrue(case["reference"])

    def test_pipeline_worker_requests_and_preserves_full_retrieved_contexts(self):
        calls = []
        full_context = (
            "[1] Technique - Valid Accounts\nID: T1078\n"
            "Description: Adversaries may obtain and abuse credentials.\n"
            "Mitigations: Multi-factor Authentication"
        )

        def fake_run_pipeline(question, **kwargs):
            calls.append((question, kwargs))
            result = SimpleNamespace(
                answer="answer",
                allowed=True,
                guardrail_category=None,
                retrieved_contexts=[full_context],
                retrieved_count=1,
                context_count=1,
                answer_source="rag",
            )
            result.to_dict = lambda: {
                "sources": [
                    {
                        "name": "Valid Accounts",
                        "external_id": "T1078",
                        "node_type": "Technique",
                        "relevance_score": 9.0,
                    }
                ]
            }
            return result

        fake_package = ModuleType("orchestration")
        fake_package.__path__ = []
        fake_pipeline = ModuleType("orchestration.pipeline")
        fake_pipeline.run_pipeline = fake_run_pipeline
        case = {
            "case_id": "case",
            "question": "What mitigates T1078?",
            "reference": "Multi-factor Authentication",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "input.json"
            output_path = Path(temp_dir) / "output.json"
            input_path.write_text(json.dumps([case]), encoding="utf-8")
            with mock.patch.dict(
                sys.modules,
                {
                    "orchestration": fake_package,
                    "orchestration.pipeline": fake_pipeline,
                },
            ), mock.patch.object(
                module,
                "verify_local_ollama",
                return_value=[module.JUDGE_MODEL],
            ):
                self.assertEqual(module.run_pipeline_worker(input_path, output_path), 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(calls, [(case["question"], {"include_contexts": True})])
        self.assertEqual(payload["context_serialization"], module.CONTEXT_SERIALIZATION)
        self.assertEqual(payload["rows"][0]["contexts"], [full_context])
        self.assertIn("Adversaries may obtain", payload["rows"][0]["contexts"][0])

    def test_loopback_policy_accepts_only_local_hosts(self):
        for host in ("localhost", "127.0.0.1", "::1", b"127.0.0.1"):
            self.assertTrue(module.is_loopback_host(host))
        for host in ("openai.com", "api.openai.com", "8.8.8.8"):
            self.assertFalse(module.is_loopback_host(host))

    def test_aggregate_is_rederived_from_raw_case_scores(self):
        rows = [
            {
                "relationship_type": "one",
                "scores": {
                    "faithfulness": 1.0,
                    "context_precision": 0.5,
                    "context_recall": 0.0,
                },
            },
            {
                "relationship_type": "one",
                "scores": {
                    "faithfulness": 0.0,
                    "context_precision": 1.0,
                    "context_recall": 1.0,
                },
            },
        ]
        aggregate = module.derive_aggregates(rows)["overall"]
        self.assertEqual(aggregate["faithfulness"]["mean"], 0.5)
        self.assertEqual(aggregate["context_precision"]["mean"], 0.75)
        self.assertEqual(aggregate["context_recall"]["mean"], 0.5)

    def test_saved_pipeline_raw_matches_the_fixed_sample_when_present(self):
        raw_path = HERE / "rag_pipeline_prototype_raw.json"
        if not raw_path.exists():
            self.skipTest("raw pipeline artifact is created by the live Step-8a run")
        raw_payload = json.loads(raw_path.read_text(encoding="utf-8"))
        if raw_payload.get("context_serialization") != module.CONTEXT_SERIALIZATION:
            with self.assertRaises(module.EvaluationError):
                module.load_reusable_pipeline_rows(
                    module.load_sample_cases(), raw_path
                )
            return
        cases = module.load_sample_cases()
        raw_rows = raw_payload.get("rows", [])
        hashes_match = len(raw_rows) == len(cases) and all(
            actual.get("golden_artifact_sha256")
            == expected.get("golden_artifact_sha256")
            for expected, actual in zip(cases, raw_rows, strict=True)
        )
        if not hashes_match:
            with self.assertRaises(module.EvaluationError):
                module.load_reusable_pipeline_rows(cases, raw_path)
            return
        payload = module.load_reusable_pipeline_rows(cases, raw_path)
        self.assertEqual(len(payload["rows"]), 15)
        self.assertTrue(all(row["sources"] for row in payload["rows"]))

    def test_final_loader_has_all_156_cases_and_variant_provenance(self):
        cases = module.load_final_golden_set_cases()
        self.assertEqual(len(cases), 156)
        self.assertEqual(len({case["case_id"] for case in cases}), 156)
        self.assertEqual(
            {
                variant: sum(
                    case["variant_kind"] == variant for case in cases
                )
                for variant in ("original", "typo", "reworded")
            },
            {"original": 52, "typo": 52, "reworded": 52},
        )
        self.assertEqual(
            len({case["relationship_type"] for case in cases}), 13
        )
        self.assertTrue(
            all(case["source_case_id"] for case in cases)
        )

    def test_final_set_covers_every_relationship_variant_and_polarity(self):
        cases = module.load_final_golden_set_cases()
        relationships = sorted({case["relationship_type"] for case in cases})
        self.assertEqual(len(relationships), 13)
        self.assertEqual(
            {
                polarity: sum(
                    module.case_polarity(case) == polarity for case in cases
                )
                for polarity in ("positive", "negative")
            },
            {"positive": 90, "negative": 66},
        )
        for relationship in relationships:
            selected = [
                case
                for case in cases
                if case["relationship_type"] == relationship
            ]
            with self.subTest(relationship=relationship):
                self.assertEqual(len(selected), 12)
                self.assertEqual(
                    {case["variant_kind"] for case in selected},
                    {"original", "typo", "reworded"},
                )
                self.assertEqual(
                    {module.case_polarity(case) for case in selected},
                    {"positive", "negative"},
                )

    def test_variant_aggregation_is_parallel_to_relationship_aggregation(self):
        rows = [
            {
                "relationship_type": "one",
                "variant_kind": "original",
                "scores": {
                    "faithfulness": 1.0,
                    "context_precision": 0.5,
                    "context_recall": 0.0,
                },
            },
            {
                "relationship_type": "one",
                "variant_kind": "typo",
                "scores": {
                    "faithfulness": 0.0,
                    "context_precision": 1.0,
                    "context_recall": 1.0,
                },
            },
        ]
        aggregates = module.derive_aggregates(rows)
        self.assertEqual(
            aggregates["by_variant_kind"]["original"]["faithfulness"],
            {"mean": 1.0, "scored_count": 1, "total_count": 1},
        )
        self.assertEqual(
            aggregates["by_variant_kind"]["typo"]["context_recall"],
            {"mean": 1.0, "scored_count": 1, "total_count": 1},
        )

    def test_positive_and_negative_aggregates_are_reported_separately(self):
        rows = [
            {
                "relationship_type": "one",
                "variant_kind": "original",
                "sampling_slot": "forward_positive",
                "scores": {
                    "faithfulness": 1.0,
                    "context_precision": 1.0,
                    "context_recall": 1.0,
                },
            },
            {
                "relationship_type": "one",
                "variant_kind": "typo",
                "sampling_slot": "zero_path",
                "scores": {
                    "faithfulness": 0.25,
                    "context_precision": 0.0,
                    "context_recall": 0.5,
                },
            },
        ]
        by_polarity = module.derive_aggregates(rows)["by_case_polarity"]
        self.assertEqual(
            by_polarity["positive"]["faithfulness"],
            {"mean": 1.0, "scored_count": 1, "total_count": 1},
        )
        self.assertEqual(
            by_polarity["negative"]["context_precision"],
            {"mean": 0.0, "scored_count": 1, "total_count": 1},
        )

    def test_scored_row_requires_every_metric_to_be_finite(self):
        expected = self._fake_scoring_row("case")
        complete = {
            **expected,
            "scores": {
                "faithfulness": 1.0,
                "context_precision": 0.5,
                "context_recall": 0.25,
            },
        }
        self.assertTrue(module.valid_scored_row(complete, expected))
        for invalid in (None, float("nan"), float("inf"), True):
            with self.subTest(invalid=invalid):
                candidate = json.loads(json.dumps(complete))
                candidate["scores"]["faithfulness"] = invalid
                self.assertFalse(
                    module.valid_scored_row(candidate, expected)
                )

    def test_scoring_fingerprint_binds_seeded_judge_configuration(self):
        rows = [self._fake_scoring_row("case")]
        baseline = module.scoring_input_fingerprint(rows)
        self.assertEqual(
            module.scoring_configuration()["judge_seed"],
            module.RAGAS_JUDGE_SEED,
        )
        with mock.patch.object(
            module,
            "RAGAS_JUDGE_SEED",
            module.RAGAS_JUDGE_SEED + 1,
        ):
            self.assertNotEqual(
                baseline,
                module.scoring_input_fingerprint(rows),
            )

    def test_scoring_fingerprint_binds_domain_prompt_semantics(self):
        rows = [self._fake_scoring_row("case")]
        baseline = module.scoring_input_fingerprint(rows)
        configuration = module.scoring_configuration()
        self.assertEqual(
            configuration["faithfulness_prompt_version"],
            module.FAITHFULNESS_PROMPT_VERSION,
        )
        self.assertTrue(
            configuration["faithfulness_verdict_cardinality_required"]
        )
        with mock.patch.object(
            module,
            "FAITHFULNESS_PROMPT_VERSION",
            module.FAITHFULNESS_PROMPT_VERSION + "-changed",
        ):
            self.assertNotEqual(
                baseline,
                module.scoring_input_fingerprint(rows),
            )

    def test_negative_case_is_deterministic_and_ragas_is_not_applicable(self):
        reference = (
            "No active relationship exists between T1001 (Data Obfuscation) "
            "and T1027 (Obfuscated Files or Information)."
        )
        row = {
            **self._fake_scoring_row("negative"),
            "sampling_slot": "negative_relationship",
            "source_case_id": "source-negative",
            "golden_artifact": "fixture.json",
            "golden_artifact_sha256": "a" * 64,
            "question": "Is T1027 a child of T1001?",
            "reference": reference,
            "answer": (
                "No. Obfuscated Files or Information (T1027) is not a child "
                "of Data Obfuscation (T1001)."
            ),
            "answer_source": "rag",
            "contexts": ["Technique T1001\nTechnique T1027"],
            "sources": [
                {
                    "name": "Data Obfuscation",
                    "external_id": "T1001",
                },
                {
                    "name": "Obfuscated Files or Information",
                    "external_id": "T1027",
                },
            ],
        }
        source_pair = {
            "id": "source-negative",
            "case_type": "negative_subtechnique_relationship",
            "relationship_exists": False,
            "question": "Is T1027 a child of T1001?",
            "expected_answer": reference,
            "expected_subtechniques": [],
            "candidate_subtechnique": {
                "external_id": "T1027",
                "name": "Obfuscated Files or Information",
            },
            "queried_parent": {
                "external_id": "T1001",
                "name": "Data Obfuscation",
            },
            "provenance": {"relationship_paths": []},
        }
        with mock.patch.object(module, "load_source_pair", return_value=source_pair):
            rows = module.build_negative_validation_rows(
                [row],
                catalog={
                    "T1001": "Data Obfuscation",
                    "T1027": "Obfuscated Files or Information",
                },
            )
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["ragas_metrics_applicable"])
        self.assertEqual(
            rows[0]["scores"],
            {metric: None for metric in module.REQUIRED_SCORE_METRICS},
        )
        self.assertTrue(rows[0]["deterministic_validation"]["passed"])

    def test_negative_validation_rejects_lost_polarity(self):
        row = {
            **self._fake_scoring_row("negative"),
            "sampling_slot": "zero_path",
            "source_case_id": "source-negative",
            "golden_artifact": "fixture.json",
            "golden_artifact_sha256": "a" * 64,
            "question": "What mitigates T1007?",
            "reference": "No active mitigation is recorded for T1007.",
            "answer": "T1007 is System Service Discovery.",
            "answer_source": "rag",
            "contexts": ["Technique T1007"],
        }
        source_pair = {
            "id": "source-negative",
            "case_type": "negative",
            "question": "What mitigates T1007?",
            "expected_answer": row["reference"],
            "expected_mitigations": [],
            "provenance": {"relationship_ids": []},
        }
        with mock.patch.object(module, "load_source_pair", return_value=source_pair):
            with self.assertRaisesRegex(
                module.EvaluationError, "lost the golden negative polarity"
            ):
                module.build_negative_validation_rows(
                    [row], catalog={"T1007": "System Service Discovery"}
                )

    def test_set_operation_is_validated_by_exact_algebra_not_ragas(self):
        source_pair, row = self._fake_set_operation_case()
        with mock.patch.object(module, "load_source_pair", return_value=source_pair):
            rows = module.build_set_operation_validation_rows([row], catalog={})
        self.assertEqual(len(rows), 1)
        result = rows[0]["deterministic_validation"]
        self.assertTrue(result["passed"])
        self.assertTrue(result["answer_exact_match"])
        self.assertTrue(result["context_operands_exact_match"])
        self.assertEqual(result["expected_result_count"], 2)
        self.assertFalse(rows[0]["ragas_metrics_applicable"])
        self.assertEqual(
            rows[0]["scores"],
            {metric: None for metric in module.REQUIRED_SCORE_METRICS},
        )

    def test_set_operation_validation_rejects_missing_result(self):
        source_pair, row = self._fake_set_operation_case()
        row["answer"] = "Toolbox (S0001) but not Operation One (C0001): Alpha (T0001)."
        with mock.patch.object(module, "load_source_pair", return_value=source_pair):
            with self.assertRaisesRegex(
                module.EvaluationError, "answer is missing result IDs"
            ):
                module.build_set_operation_validation_rows([row], catalog={})

    def test_set_operation_validation_rejects_incomplete_operand_context(self):
        source_pair, row = self._fake_set_operation_case()
        row["contexts"][1] = row["contexts"][1].replace(
            "- Beta (T0002)\n", ""
        )
        with mock.patch.object(module, "load_source_pair", return_value=source_pair):
            with self.assertRaisesRegex(
                module.EvaluationError, "software context operand differs"
            ):
                module.build_set_operation_validation_rows([row], catalog={})

    def test_final_metric_applicability_has_three_distinct_claim_shapes(self):
        cases = module.load_final_golden_set_cases()
        self.assertEqual(
            {
                kind: sum(module.case_evaluation_kind(case) == kind for case in cases)
                for kind in (
                    "ragas_open_world",
                    "graph_absence",
                    "set_operation",
                )
            },
            {
                "ragas_open_world": 87,
                "graph_absence": 66,
                "set_operation": 3,
            },
        )

    def test_v2_checkpoint_migration_retains_only_positive_scores(self):
        positive = self._fake_scoring_row("positive")
        negative = {
            **self._fake_scoring_row("negative"),
            "sampling_slot": "zero_path",
        }
        all_rows = [positive, negative]
        scored_rows = [
            {
                **row,
                "scores": {
                    "faithfulness": 1.0,
                    "context_precision": 0.5,
                    "context_recall": 0.25,
                },
            }
            for row in all_rows
        ]
        legacy_configuration = module.legacy_scoring_configuration_v2()
        payload = {
            "checkpoint_schema": module.LEGACY_SCORING_CHECKPOINT_SCHEMA,
            "scoring_input_fingerprint": module._scoring_input_fingerprint(
                all_rows, legacy_configuration
            ),
            "scoring_configuration": legacy_configuration,
            "network_audit": {
                "observed_hosts": ["127.0.0.1"],
                "blocked_hosts": [],
                "openai_host_attempted": False,
            },
            "rows": scored_rows,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            checkpoint = Path(temp_dir) / "v2.json"
            checkpoint.write_text(json.dumps(payload), encoding="utf-8")
            migrated = module._load_scoring_checkpoint(
                checkpoint,
                [positive],
                legacy_all_rows=all_rows,
            )
        self.assertEqual(
            migrated["checkpoint_schema"], module.SCORING_CHECKPOINT_SCHEMA
        )
        self.assertEqual(
            [row["case_id"] for row in migrated["rows"]], ["positive"]
        )
        self.assertEqual(migrated["completed_count"], 1)
        self.assertEqual(migrated["remaining_count"], 0)
        self.assertEqual(
            migrated["migration"]["discarded_inapplicable_negative_rows"], 1
        )

    def test_v7_checkpoint_migration_drops_closed_world_set_scores(self):
        ordinary = self._fake_scoring_row("ordinary")
        set_operation = {
            **self._fake_scoring_row("set-operation"),
            "sampling_slot": "path_divergence",
            "contexts": ["new complete operand context"],
        }
        prior_positive_rows = [ordinary, set_operation]
        old_set_operation = {
            **set_operation,
            "contexts": ["old incomplete operand context"],
        }
        scored_rows = [
            {
                **row,
                "scores": {
                    "faithfulness": 1.0,
                    "context_precision": 1.0,
                    "context_recall": 1.0,
                },
            }
            for row in (ordinary, old_set_operation)
        ]
        previous_configuration = module.previous_scoring_configuration_v7()
        payload = {
            "checkpoint_schema": module.PREVIOUS_SCORING_CHECKPOINT_SCHEMA,
            "scoring_input_fingerprint": module._scoring_input_fingerprint(
                [ordinary, old_set_operation], previous_configuration
            ),
            "scoring_configuration": previous_configuration,
            "network_audit": {
                "observed_hosts": ["127.0.0.1"],
                "blocked_hosts": [],
                "openai_host_attempted": False,
            },
            "rows": scored_rows,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            checkpoint = Path(temp_dir) / "v7.json"
            checkpoint.write_text(json.dumps(payload), encoding="utf-8")
            migrated = module._load_scoring_checkpoint(
                checkpoint,
                [ordinary],
                legacy_all_rows=prior_positive_rows,
            )
        self.assertEqual(
            migrated["checkpoint_schema"], module.SCORING_CHECKPOINT_SCHEMA
        )
        self.assertEqual(
            [row["case_id"] for row in migrated["rows"]], ["ordinary"]
        )
        self.assertEqual(
            migrated["migration"]["discarded_set_operation_rows"], 1
        )

    def test_incomplete_cases_are_retried_individually(self):
        rows = [self._fake_scoring_row(f"case-{index}") for index in range(3)]
        calls = []
        attempts = {row["case_id"]: 0 for row in rows}
        models = {"judge": "local", "judge_seed": 7}

        def fake_score(batch):
            calls.append([row["case_id"] for row in batch])
            scored = []
            for row in batch:
                case_id = row["case_id"]
                attempts[case_id] += 1
                scores = {
                    "faithfulness": 1.0,
                    "context_precision": 0.5,
                    "context_recall": 0.25,
                }
                if case_id == "case-1" and attempts[case_id] == 1:
                    scores["faithfulness"] = None
                if case_id == "case-2" and attempts[case_id] < 3:
                    scores["context_recall"] = None
                scored.append({**row, "scores": scores})
            return scored, models

        with mock.patch.object(module, "score_with_ragas", fake_score):
            complete, unresolved, returned_models = (
                module.score_batch_with_incomplete_retries(
                    rows,
                    max_incomplete_retries=2,
                )
            )
        self.assertEqual(
            calls,
            [
                ["case-0", "case-1", "case-2"],
                ["case-1"],
                ["case-2"],
                ["case-2"],
            ],
        )
        self.assertEqual([row["case_id"] for row in complete], [
            "case-0",
            "case-1",
            "case-2",
        ])
        self.assertEqual(unresolved, [])
        self.assertEqual(returned_models, models)

    def test_persistently_incomplete_case_is_not_checkpointed_as_complete(self):
        rows = [self._fake_scoring_row("complete"), self._fake_scoring_row("timeout")]
        models = {"judge": "local", "judge_seed": 7}

        def fake_score(batch):
            scored = []
            for row in batch:
                scores = {
                    "faithfulness": 1.0,
                    "context_precision": 0.5,
                    "context_recall": 0.25,
                }
                if row["case_id"] == "timeout":
                    scores["faithfulness"] = None
                scored.append({**row, "scores": scores})
            return scored, models

        with tempfile.TemporaryDirectory() as temp_dir:
            checkpoint = Path(temp_dir) / "scoring.json"
            with mock.patch.object(module, "score_with_ragas", fake_score):
                with self.assertRaisesRegex(
                    module.EvaluationError,
                    "measurement is incomplete",
                ):
                    module.score_with_ragas_checkpointed(
                        rows,
                        checkpoint,
                        batch_size=2,
                        incomplete_score_retries=1,
                    )
            payload = json.loads(checkpoint.read_text(encoding="utf-8"))

        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["completed_count"], 1)
        self.assertEqual(payload["remaining_count"], 1)
        self.assertEqual(
            [row["case_id"] for row in payload["rows"]],
            ["complete"],
        )
        self.assertEqual(
            payload["last_error"]["cases"],
            [{"case_id": "timeout", "missing_metrics": ["faithfulness"]}],
        )

    def test_pipeline_checkpoint_resumes_only_missing_valid_rows(self):
        cases = [
            {
                "case_id": f"case-{index}",
                "relationship_type": "test",
                "question": f"question {index}",
                "reference": f"reference {index}",
            }
            for index in range(3)
        ]
        first_calls = []

        def first_run(question, **kwargs):
            first_calls.append((question, kwargs))
            if len(first_calls) == 2:
                raise RuntimeError("deliberate interruption")
            return self._fake_pipeline_result(question)

        second_calls = []

        def second_run(question, **kwargs):
            second_calls.append((question, kwargs))
            return self._fake_pipeline_result(question)

        fake_package = ModuleType("orchestration")
        fake_package.__path__ = []
        fake_pipeline = ModuleType("orchestration.pipeline")

        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "input.json"
            checkpoint_path = Path(temp_dir) / "checkpoint.json"
            input_path.write_text(json.dumps(cases), encoding="utf-8")

            fake_pipeline.run_pipeline = first_run
            with mock.patch.dict(
                sys.modules,
                {
                    "orchestration": fake_package,
                    "orchestration.pipeline": fake_pipeline,
                },
            ), mock.patch.object(
                module,
                "verify_local_ollama",
                return_value=[module.JUDGE_MODEL],
            ):
                with self.assertRaises(RuntimeError):
                    module.run_pipeline_worker(input_path, checkpoint_path)
            interrupted = json.loads(
                checkpoint_path.read_text(encoding="utf-8")
            )
            self.assertEqual(interrupted["completed_count"], 1)
            self.assertEqual(interrupted["remaining_count"], 2)
            self.assertEqual(interrupted["status"], "failed")

            fake_pipeline.run_pipeline = second_run
            with mock.patch.dict(
                sys.modules,
                {
                    "orchestration": fake_package,
                    "orchestration.pipeline": fake_pipeline,
                },
            ), mock.patch.object(
                module,
                "verify_local_ollama",
                return_value=[module.JUDGE_MODEL],
            ):
                self.assertEqual(
                    module.run_pipeline_worker(input_path, checkpoint_path), 0
                )
            resumed = json.loads(
                checkpoint_path.read_text(encoding="utf-8")
            )

        self.assertEqual(
            first_calls,
            [
                ("question 0", {"include_contexts": True}),
                ("question 1", {"include_contexts": True}),
            ],
        )
        self.assertEqual(
            second_calls,
            [
                ("question 1", {"include_contexts": True}),
                ("question 2", {"include_contexts": True}),
            ],
        )
        self.assertEqual(resumed["completed_count"], 3)
        self.assertEqual(resumed["remaining_count"], 0)
        self.assertEqual(resumed["status"], "complete")

    def test_v4_pipeline_checkpoint_refreshes_only_set_operation_rows(self):
        ordinary = {
            "case_id": "ordinary",
            "relationship_type": "test",
            "variant_kind": "original",
            "sampling_slot": "forward_positive",
            "question": "ordinary question",
            "reference": "ordinary reference",
        }
        set_operation = {
            "case_id": "set-operation",
            "relationship_type": "test",
            "variant_kind": "original",
            "sampling_slot": "path_divergence",
            "question": "set question",
            "reference": "set reference",
        }
        cases = [ordinary, set_operation]
        rows = [
            {
                **case,
                "answer": "answer",
                "contexts": ["old context"],
                "sources": [],
                "allowed": True,
            }
            for case in cases
        ]
        payload = {
            "checkpoint_schema": module.PIPELINE_CHECKPOINT_SCHEMA,
            "dataset_fingerprint": module.dataset_fingerprint(cases),
            "context_serialization": module.PREVIOUS_CONTEXT_SERIALIZATION,
            "network_audit": {
                "blocked_hosts": [],
                "openai_host_attempted": False,
            },
            "rows": rows,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            checkpoint = Path(temp_dir) / "pipeline.json"
            checkpoint.write_text(json.dumps(payload), encoding="utf-8")
            migrated = module._load_pipeline_checkpoint(checkpoint, cases)
        self.assertEqual(
            migrated["context_serialization"], module.CONTEXT_SERIALIZATION
        )
        self.assertEqual(
            [row["case_id"] for row in migrated["rows"]], ["ordinary"]
        )
        self.assertEqual(migrated["completed_count"], 1)
        self.assertEqual(migrated["remaining_count"], 1)
        self.assertEqual(
            migrated["migration"]["discarded_set_operation_rows"], 1
        )

    def test_blocked_benign_query_is_never_checkpointed_as_complete(self):
        case = {
            "case_id": "benign",
            "relationship_type": "test",
            "question": "What mitigates T1078?",
            "reference": "M1032",
        }
        blocked = SimpleNamespace(
            answer="fallback",
            allowed=False,
            guardrail_category="llm_harm_blocked",
            retrieved_contexts=[],
            retrieved_count=0,
            context_count=0,
            answer_source="fallback",
        )
        fake_package = ModuleType("orchestration")
        fake_package.__path__ = []
        fake_pipeline = ModuleType("orchestration.pipeline")
        fake_pipeline.run_pipeline = lambda *_args, **_kwargs: blocked
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "input.json"
            checkpoint = Path(temp_dir) / "pipeline.json"
            input_path.write_text(json.dumps([case]), encoding="utf-8")
            with mock.patch.dict(
                sys.modules,
                {
                    "orchestration": fake_package,
                    "orchestration.pipeline": fake_pipeline,
                },
            ), mock.patch.object(
                module,
                "verify_local_ollama",
                return_value=[module.JUDGE_MODEL],
            ):
                with self.assertRaisesRegex(
                    module.EvaluationError, "benign golden query was blocked"
                ):
                    module.run_pipeline_worker(input_path, checkpoint)
            payload = json.loads(checkpoint.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["completed_count"], 0)
        self.assertEqual(payload["remaining_count"], 1)
        self.assertEqual(payload["rows"], [])

    def test_scoring_checkpoint_resumes_only_missing_valid_rows(self):
        rows = [
            {
                "case_id": f"case-{index}",
                "relationship_type": "test",
                "variant_kind": "original",
                "question": f"question {index}",
                "reference": f"reference {index}",
                "answer": f"answer {index}",
                "contexts": [f"context {index}"],
                "sources": [],
                "allowed": True,
            }
            for index in range(3)
        ]
        calls = []
        interrupted_once = {"value": False}
        model_metadata = {
            "judge": "local",
            "embeddings": "local",
        }

        def fake_score(batch):
            calls.append([row["case_id"] for row in batch])
            if len(calls) == 2 and not interrupted_once["value"]:
                interrupted_once["value"] = True
                raise RuntimeError("deliberate scoring interruption")
            return [
                {
                    **row,
                    "scores": {
                        "faithfulness": 1.0,
                        "context_precision": 0.5,
                        "context_recall": 0.25,
                    },
                }
                for row in batch
            ], model_metadata

        with tempfile.TemporaryDirectory() as temp_dir:
            checkpoint = Path(temp_dir) / "scoring.json"
            with mock.patch.object(module, "score_with_ragas", fake_score):
                with self.assertRaises(RuntimeError):
                    module.score_with_ragas_checkpointed(
                        rows, checkpoint, batch_size=1
                    )
            interrupted = json.loads(checkpoint.read_text(encoding="utf-8"))
            self.assertEqual(interrupted["completed_count"], 1)
            self.assertEqual(interrupted["status"], "failed")

            calls.clear()
            with mock.patch.object(module, "score_with_ragas", fake_score):
                scored, models, audit = module.score_with_ragas_checkpointed(
                    rows, checkpoint, batch_size=1
                )

        self.assertEqual(calls, [["case-1"], ["case-2"]])
        self.assertEqual([row["case_id"] for row in scored], [
            "case-0",
            "case-1",
            "case-2",
        ])
        self.assertEqual(models, model_metadata)
        self.assertEqual(audit["blocked_hosts"], [])

    @staticmethod
    def _fake_pipeline_result(question):
        result = SimpleNamespace(
            answer=f"answer for {question}",
            allowed=True,
            guardrail_category=None,
            retrieved_contexts=[f"context for {question}"],
            retrieved_count=1,
            context_count=1,
            answer_source="rag",
        )
        result.to_dict = lambda: {
            "sources": [
                {
                    "name": "Test",
                    "external_id": "T0000",
                    "node_type": "Technique",
                    "relevance_score": 1.0,
                }
            ]
        }
        return result

    @staticmethod
    def _fake_scoring_row(case_id):
        return {
            "case_id": case_id,
            "relationship_type": "test",
            "variant_kind": "original",
            "sampling_slot": "forward_positive",
            "question": f"question {case_id}",
            "reference": f"reference {case_id}",
            "answer": f"answer {case_id}",
            "contexts": [f"context {case_id}"],
            "sources": [],
            "allowed": True,
        }

    @staticmethod
    def _fake_set_operation_case():
        campaign = {"external_id": "C0001", "name": "Operation One"}
        software = {
            "external_id": "S0001",
            "name": "Toolbox",
            "stix_type": "tool",
        }
        records = {
            "T0001": {"external_id": "T0001", "name": "Alpha"},
            "T0002": {"external_id": "T0002", "name": "Beta"},
            "T0003": {"external_id": "T0003", "name": "Shared"},
            "T0004": {"external_id": "T0004", "name": "Campaign Only"},
        }
        reference = (
            "Tool S0001 has T0001 and T0002 but campaign C0001 does not."
        )
        source_pair = {
            "id": "set-source",
            "case_type": "campaign_software_technique_divergence",
            "question": "Which Toolbox techniques are absent from Operation One?",
            "expected_answer": reference,
            "campaign": campaign,
            "software": software,
            "expected_campaign_direct_techniques": [
                records["T0003"],
                records["T0004"],
            ],
            "expected_software_techniques": [
                records["T0001"],
                records["T0002"],
                records["T0003"],
            ],
            "expected_software_only_techniques": [
                records["T0001"],
                records["T0002"],
            ],
            "expected_shared_techniques": [records["T0003"]],
            "expected_campaign_only_techniques": [records["T0004"]],
            "provenance": {
                "set_operation": (
                    "software_direct_techniques minus "
                    "campaign_direct_techniques"
                )
            },
        }
        row = {
            **RagasPrototypeHarnessTests._fake_scoring_row("set-case"),
            "sampling_slot": "path_divergence",
            "source_case_id": "set-source",
            "golden_artifact": "fixture.json",
            "golden_artifact_sha256": "a" * 64,
            "reference": reference,
            "answer": (
                "Techniques used by Toolbox (S0001) but absent from "
                "Operation One (C0001): Alpha (T0001), Beta (T0002)."
            ),
            "answer_source": "rag",
            "contexts": [
                "[1] Campaign - Operation One\n"
                "ID: C0001\n"
                "Techniques directly used by this Campaign:\n"
                "- Shared (T0003)\n"
                "- Campaign Only (T0004)\n",
                "[1] Tool - Toolbox\n"
                "ID: S0001\n"
                "Techniques directly used by this Tool:\n"
                "- Alpha (T0001)\n"
                "- Beta (T0002)\n"
                "- Shared (T0003)\n"
                "Campaigns directly using this Tool:\n"
                "- Operation One (C0001)\n",
            ],
            "sources": [campaign, software],
        }
        return source_pair, row


if __name__ == "__main__":
    unittest.main()
