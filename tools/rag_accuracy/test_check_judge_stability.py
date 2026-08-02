from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "ragas_judge_stability",
    HERE / "check_judge_stability.py",
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def scored(case_id: str, faithfulness: float = 1.0) -> dict:
    return {
        "case_id": case_id,
        "scores": {
            "faithfulness": faithfulness,
            "context_precision": 0.5,
            "context_recall": 0.25,
        },
    }


class JudgeStabilityTests(unittest.TestCase):
    def test_default_probe_has_positive_negative_and_long_timeout_case(self):
        self.assertEqual(len(module.DEFAULT_CASE_IDS), 3)
        self.assertIn(
            "enterprise-mitigations-t1001::original",
            module.DEFAULT_CASE_IDS,
        )
        self.assertIn(
            "group-has-no-qualifying-techniques-g0017::original",
            module.DEFAULT_CASE_IDS,
        )
        self.assertIn(
            "campaign-software-techniques-c0001-s0363::original",
            module.DEFAULT_CASE_IDS,
        )

    def test_identical_metric_vectors_are_stable(self):
        runs = [
            [scored("positive"), scored("negative", 0.25)]
            for _ in range(3)
        ]
        result = module.derive_stability(runs, tolerance=1e-12)
        self.assertTrue(result["stable"])
        self.assertEqual(result["case_count"], 2)
        self.assertEqual(result["repeat_count"], 3)
        self.assertEqual(
            result["cases"]["positive"]["score_ranges"]["faithfulness"],
            0.0,
        )

    def test_changed_metric_vector_is_reported_unstable(self):
        runs = [
            [scored("case", 1.0)],
            [scored("case", 0.0)],
            [scored("case", 1.0)],
        ]
        result = module.derive_stability(runs, tolerance=1e-12)
        self.assertFalse(result["stable"])
        self.assertEqual(
            result["cases"]["case"]["score_ranges"]["faithfulness"],
            1.0,
        )

    def test_incomplete_metric_is_rejected(self):
        row = scored("case")
        row["scores"]["context_recall"] = None
        with self.assertRaisesRegex(
            module.evaluator.EvaluationError,
            "incomplete stability score",
        ):
            module.derive_stability([[row], [row]], tolerance=1e-12)

    def test_case_order_must_match_across_repeats(self):
        with self.assertRaisesRegex(
            module.evaluator.EvaluationError,
            "same ordered cases",
        ):
            module.derive_stability(
                [
                    [scored("one"), scored("two")],
                    [scored("two"), scored("one")],
                ],
                tolerance=1e-12,
            )

    def test_probe_checkpoints_each_repeat_and_resumes_without_rescoring(self):
        rows = [
            {
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
            for case_id in ("positive", "negative")
        ]
        calls = []

        def fake_score(selected, **kwargs):
            calls.append([row["case_id"] for row in selected])
            return (
                [{**row, "scores": scored(row["case_id"])["scores"]} for row in selected],
                [],
                {"judge": "local", "judge_seed": 7},
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            report = Path(temp_dir) / "stability.json"
            with (
                mock.patch.object(module, "select_probe_rows", return_value=rows),
                mock.patch.object(
                    module.evaluator,
                    "score_batch_with_incomplete_retries",
                    side_effect=fake_score,
                ),
            ):
                result = module.run_probe(
                    pipeline_checkpoint=Path("unused.json"),
                    report_path=report,
                    case_ids=["positive", "negative"],
                    repeats=3,
                    tolerance=1e-12,
                    incomplete_score_retries=2,
                )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(result, 0)
            self.assertEqual(len(calls), 3)
            self.assertEqual(payload["status"], "complete")
            self.assertEqual(payload["completed_repeats"], 3)

            with (
                mock.patch.object(module, "select_probe_rows", return_value=rows),
                mock.patch.object(
                    module.evaluator,
                    "score_batch_with_incomplete_retries",
                    side_effect=AssertionError("resume must not rescore"),
                ),
            ):
                resumed = module.run_probe(
                    pipeline_checkpoint=Path("unused.json"),
                    report_path=report,
                    case_ids=["positive", "negative"],
                    repeats=3,
                    tolerance=1e-12,
                    incomplete_score_retries=2,
                )
            self.assertEqual(resumed, 0)


if __name__ == "__main__":
    unittest.main()
