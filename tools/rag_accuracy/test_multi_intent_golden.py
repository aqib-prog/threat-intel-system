"""Deterministic regression for the multi-intent golden scenarios.

For every scenario in ``golden_set_multi_intent.json`` this asserts the
orchestration layer splits and routes the turn exactly as declared - the right
questions survive, the noise is dropped, off-topic questions still route (to be
softly refused), a raw-log paste is recognized and never split, and the
card-vs-single-fallback decision matches. No Neo4j / Ollama: it exercises only
``segment_query``, ``_segment_disposition`` (driver=None), and the log detector.

Answer quality per routed segment is NOT scored here - that is the RAGAS run
against each segment's golden ``expected_answer`` and needs the live stack.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from log_analysis import detector as log_detector  # noqa: E402
from log_analysis.analyzer import analyze as analyze_log  # noqa: E402
from log_analysis.parser import parse_log  # noqa: E402
from orchestration.multi_intent import _segment_disposition  # noqa: E402
from orchestration.query_splitter import segment_query  # noqa: E402

SCENARIOS = json.loads((HERE / "golden_set_multi_intent.json").read_text())["scenarios"]


class MultiIntentGoldenTests(unittest.TestCase):
    def test_scenarios_present(self):
        self.assertGreaterEqual(len(SCENARIOS), 12)

    def test_each_scenario_routes_as_declared(self):
        for sc in SCENARIOS:
            with self.subTest(scenario=sc["id"]):
                if sc["raw_log"]:
                    # A raw log must be recognized as a log so run_multi_pipeline
                    # sends the whole turn to the deterministic log branch
                    # (never splitting it into per-line fragments).
                    self.assertTrue(
                        log_detector.detect(sc["input"]).is_raw_log,
                        f"{sc['id']}: expected raw-log detection",
                    )
                    self.assertTrue(sc["single_fallback"])
                    self.assertFalse(sc["expects_cards"])
                    continue

                candidates = segment_query(sc["input"])
                routed = [c for c in candidates if _segment_disposition(c, None) == "route"]

                # Count of routed sub-questions matches the golden expectation.
                self.assertEqual(
                    len(routed), sc["expected_routed_count"],
                    f"{sc['id']}: routed {routed!r}",
                )

                # Every segment declared as a route (real question OR off-topic)
                # actually survives as a routed candidate.
                for seg in sc["segments"]:
                    if seg["disposition"] == "route":
                        self.assertIn(
                            seg["text"], routed,
                            f"{sc['id']}: expected routed segment {seg['text']!r}",
                        )

                # Card vs single-fallback flags are consistent with the routing.
                self.assertEqual(sc["expects_cards"], len(routed) >= 2, sc["id"])
                self.assertEqual(sc["single_fallback"], len(routed) <= 1, sc["id"])

    def test_golden_answers_are_populated(self):
        # Every routed real-question segment must carry a golden id + answer so
        # the RAGAS harness has ground truth to score against.
        for sc in SCENARIOS:
            for seg in sc["segments"]:
                if seg.get("golden_id"):
                    self.assertTrue(seg["expected_answer"], f"{sc['id']}: empty golden answer")

    def test_per_os_logs_detect_and_map_to_techniques(self):
        # Windows / Linux / macOS / AWS logs must each (a) be recognized as a
        # raw log, (b) resolve to the expected platform, and (c) map to their
        # expected high-confidence ATT&CK techniques. This runs the real
        # deterministic log engine (detect -> parse -> analyze); no DB needed.
        checked = 0
        for sc in SCENARIOS:
            if "expected_techniques" not in sc:
                continue
            checked += 1
            text = sc["input"]
            with self.subTest(scenario=sc["id"]):
                result = log_detector.detect(text)
                self.assertTrue(result.is_raw_log, f"{sc['id']}: not detected as raw log")
                self.assertEqual(
                    result.platform, sc["expected_platform"],
                    f"{sc['id']}: platform {result.platform!r}",
                )
                got = {m.technique_name for m in analyze_log(parse_log(text, result.platform), result.platform)}
                for tech in sc["expected_techniques"]:
                    self.assertIn(tech, got, f"{sc['id']}: expected technique {tech!r} not mapped")
        self.assertGreaterEqual(checked, 4, "expected at least 4 per-OS log scenarios")


if __name__ == "__main__":
    unittest.main()
