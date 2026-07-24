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


if __name__ == "__main__":
    unittest.main()
