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
        payload = module.load_reusable_pipeline_rows(module.load_sample_cases(), raw_path)
        self.assertEqual(len(payload["rows"]), 15)
        self.assertTrue(all(row["sources"] for row in payload["rows"]))


if __name__ == "__main__":
    unittest.main()
