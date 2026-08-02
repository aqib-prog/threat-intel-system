from __future__ import annotations

import unittest
from unittest import mock

from orchestration import pipeline
from retrieval.test_input_shape import EXACT_RAGAS_COMMAND


class OperationalInputPipelineBoundaryTests(unittest.TestCase):
    def test_command_is_blocked_before_log_detection_or_database(self):
        with mock.patch.object(pipeline.log_analysis_detector, "detect") as detector, mock.patch.object(
            pipeline, "get_driver"
        ) as driver, mock.patch.object(pipeline, "guardrail") as full_guardrail:
            result = pipeline.run_pipeline(EXACT_RAGAS_COMMAND)

        self.assertFalse(result.allowed)
        self.assertEqual(result.guardrail_category, "unsupported_operational_command")
        self.assertIn("can't execute", result.answer)
        self.assertEqual(result.sources, [])
        detector.assert_not_called()
        driver.assert_not_called()
        full_guardrail.assert_not_called()

    def test_question_about_command_is_not_shape_blocked(self):
        query = "Explain what this command does: curl -s http://localhost:11434/api/tags"
        self.assertFalse(pipeline.is_bare_operational_command(query))
        with mock.patch.object(
            pipeline, "is_unsupported_count_query", return_value=False
        ), mock.patch.object(
            pipeline.log_analysis_detector,
            "detect",
            return_value=mock.Mock(is_raw_log=False),
        ), mock.patch.object(
            pipeline,
            "guardrail",
            return_value={"allowed": False, "category": "test_stop"},
        ):
            result = pipeline.run_pipeline(query)

        self.assertEqual(result.guardrail_category, "test_stop")


if __name__ == "__main__":
    unittest.main()
