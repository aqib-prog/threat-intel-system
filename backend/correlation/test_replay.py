from __future__ import annotations

import unittest
from dataclasses import replace

from correlation.heuristics import HeuristicPolicy
from correlation.models import EntityKey
from correlation.replay import (
    CorrelationReplayReport,
    CorrelationReplayRunner,
    ReplayLimitError,
    ReplayPolicy,
)
from correlation.test_heuristics import _event


class _Source:
    def __init__(self, events):
        self._events = tuple(events)
        self.calls = 0

    def events(self):
        self.calls += 1
        yield from self._events


def _with_activity(event, activity_id: str):
    return replace(
        event,
        entity_keys=(
            *event.entity_keys,
            EntityKey("activity_id", activity_id, "host:boot"),
        ),
    )


class CorrelationReplayRunnerTests(unittest.TestCase):
    def test_default_replay_is_deterministic_only_and_reads_source_once(self):
        source = _Source(
            [
                _event("parent", pid="100"),
                _event("child", pid="200", ppid="100", seconds=1),
            ]
        )

        result = CorrelationReplayRunner().run(source)
        report = result.report.to_dict()

        self.assertEqual(source.calls, 1)
        self.assertEqual(result.heuristic_edges.edges, ())
        self.assertEqual(result.shadow_comparison.components, ())
        self.assertEqual(report["heuristic_validation_status"], "disabled")
        self.assertFalse(report["ground_truth_supplied"])
        self.assertFalse(report["accuracy_measured"])
        self.assertTrue(report["deterministic_incident_membership_only"])
        self.assertFalse(report["heuristic_promotion_eligible"])
        self.assertEqual(
            CorrelationReplayReport.from_dict(report),
            result.report,
        )

    def test_enabled_heuristic_is_reported_without_changing_membership(self):
        events = [
            _with_activity(_event("parent", pid="100"), "parent-activity"),
            _with_activity(
                _event("child", pid="200", ppid="100", seconds=1),
                "child-activity",
            ),
        ]
        policy = ReplayPolicy(
            heuristic=HeuristicPolicy.pid_lineage_shadow(
                max_parent_pid_gap_seconds=10
            )
        )

        result = CorrelationReplayRunner(policy).run(_Source(events))
        report = result.report.to_dict()

        self.assertEqual(len(result.deterministic_snapshot.incidents), 2)
        self.assertEqual(len(result.heuristic_edges.edges), 1)
        self.assertEqual(
            result.shadow_comparison.coverage.would_merge_edge_count,
            1,
        )
        self.assertEqual(report["heuristic_validation_status"], "unmeasured")
        self.assertEqual(
            report["deterministic_snapshot_id"],
            result.deterministic_snapshot.snapshot_id,
        )
        self.assertFalse(
            result.shadow_comparison.components[0].promotion_eligible
        )

    def test_report_is_order_independent_and_content_addressed(self):
        events = [
            _event("parent", pid="100"),
            _event("child", pid="200", ppid="100", seconds=1),
        ]
        policy = ReplayPolicy(
            heuristic=HeuristicPolicy.pid_lineage_shadow(
                max_parent_pid_gap_seconds=10
            )
        )

        first = CorrelationReplayRunner(policy).run(_Source(events)).report
        second = CorrelationReplayRunner(policy).run(
            _Source(reversed(events))
        ).report

        self.assertEqual(first.report_id, second.report_id)
        self.assertEqual(first.canonical_payload, second.canonical_payload)

    def test_report_rejects_tampering(self):
        report = CorrelationReplayRunner().run(
            _Source([_event("one", pid="100")])
        ).report
        tampered = report.canonical_payload.replace(
            b'"accuracy_measured":false',
            b'"accuracy_measured":true',
        )

        with self.assertRaises(ValueError):
            CorrelationReplayReport(report.report_id, tampered)

    def test_input_limit_and_source_contract_fail_closed(self):
        runner = CorrelationReplayRunner(
            ReplayPolicy(max_input_events=1, max_unique_events=1)
        )

        with self.assertRaises(ReplayLimitError):
            runner.run(
                _Source(
                    [
                        _event("one", pid="100"),
                        _event("two", pid="200"),
                    ]
                )
            )
        with self.assertRaises(TypeError):
            CorrelationReplayRunner().run(object())
        with self.assertRaises(ValueError):
            ReplayPolicy(max_report_samples=1_001)

    def test_durable_report_samples_are_bounded_without_dropping_results(self):
        events = [
            _event("parent-one", pid="100", seconds=0),
            _event("child-one", pid="200", ppid="100", seconds=1),
            _event("parent-two", pid="300", seconds=2),
            _event("child-two", pid="400", ppid="300", seconds=3),
        ]
        policy = ReplayPolicy(
            max_report_samples=1,
            heuristic=HeuristicPolicy.pid_lineage_shadow(
                max_parent_pid_gap_seconds=10
            ),
        )

        result = CorrelationReplayRunner(policy).run(_Source(events))
        report = result.report.to_dict()

        self.assertEqual(len(result.heuristic_edges.edges), 2)
        self.assertEqual(report["artifacts"]["heuristic_edges"]["count"], 2)
        self.assertEqual(len(report["review_samples"]["heuristic_edges"]), 1)

    def test_duplicate_events_remain_idempotent_but_are_counted(self):
        event = _event("one", pid="100")

        result = CorrelationReplayRunner().run(_Source([event, event]))

        coverage = result.deterministic_edges.coverage
        self.assertEqual(coverage.input_event_count, 2)
        self.assertEqual(coverage.unique_event_count, 1)
        self.assertEqual(coverage.duplicate_event_count, 1)
        self.assertEqual(
            len(result.deterministic_snapshot.unassigned_events),
            1,
        )


if __name__ == "__main__":
    unittest.main()
