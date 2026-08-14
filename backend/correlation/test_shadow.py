from __future__ import annotations

import unittest
from dataclasses import replace

from correlation.edges import DeterministicEdgeBuilder
from correlation.heuristics import HeuristicEdgeBuilder, HeuristicPolicy
from correlation.incidents import IncidentBuilder
from correlation.models import EntityKey, Platform
from correlation.shadow import (
    ShadowComparator,
    ShadowComparisonPolicy,
    ShadowEdgeEffect,
    ShadowInputConflictError,
    ShadowLimitError,
)
from correlation.test_heuristics import _event


def _add_activity(event, activity_id: str):
    return replace(
        event,
        entity_keys=(
            *event.entity_keys,
            EntityKey("activity_id", activity_id, "host:boot"),
        ),
    )


def _artifacts(events):
    deterministic_edges = DeterministicEdgeBuilder().build(events).edges
    snapshot = IncidentBuilder().build(events, deterministic_edges)
    heuristic_edges = HeuristicEdgeBuilder(
        HeuristicPolicy.pid_lineage_shadow(max_parent_pid_gap_seconds=10)
    ).build(events).edges
    return snapshot, heuristic_edges


class ShadowComparatorTests(unittest.TestCase):
    def test_two_deterministic_incidents_are_reported_as_would_merge(self) -> None:
        events = [
            _add_activity(_event("parent", pid="100"), "activity-parent"),
            _add_activity(
                _event("child", pid="200", ppid="100", seconds=1),
                "activity-child",
            ),
        ]
        snapshot, heuristic_edges = _artifacts(events)
        original = snapshot.to_dict()

        result = ShadowComparator().compare(snapshot, heuristic_edges)

        self.assertEqual(len(snapshot.incidents), 2)
        self.assertEqual(result.coverage.would_merge_edge_count, 1)
        self.assertEqual(
            result.assessments[0].effect,
            ShadowEdgeEffect.WOULD_MERGE_INCIDENTS,
        )
        self.assertEqual(len(result.components[0].incident_ids), 2)
        self.assertFalse(result.components[0].promotion_eligible)
        self.assertIn("unmeasured_rule", result.components[0].suppression_reasons)
        self.assertEqual(snapshot.to_dict(), original)

    def test_same_incident_edge_is_redundant(self) -> None:
        shared = "shared-activity"
        events = [
            _add_activity(_event("parent", pid="100"), shared),
            _add_activity(
                _event("child", pid="200", ppid="100", seconds=1),
                shared,
            ),
        ]
        snapshot, heuristic_edges = _artifacts(events)

        result = ShadowComparator().compare(snapshot, heuristic_edges)

        self.assertEqual(len(snapshot.incidents), 1)
        self.assertEqual(result.coverage.redundant_edge_count, 1)
        self.assertEqual(result.assessments[0].effect, ShadowEdgeEffect.REDUNDANT)

    def test_assigned_to_unassigned_edge_is_reported_as_attach(self) -> None:
        events = [
            _add_activity(_event("parent", pid="100"), "activity-parent"),
            _event("child", pid="200", ppid="100", seconds=1),
        ]
        snapshot, heuristic_edges = _artifacts(events)

        result = ShadowComparator().compare(snapshot, heuristic_edges)

        self.assertEqual(len(snapshot.incidents), 1)
        self.assertEqual(len(snapshot.unassigned_events), 1)
        self.assertEqual(result.coverage.would_attach_edge_count, 1)
        self.assertEqual(
            result.assessments[0].effect,
            ShadowEdgeEffect.WOULD_ATTACH_UNASSIGNED,
        )

    def test_two_unassigned_events_are_reported_as_new_component(self) -> None:
        events = [
            _event("parent", pid="100"),
            _event("child", pid="200", ppid="100", seconds=1),
        ]
        snapshot, heuristic_edges = _artifacts(events)

        result = ShadowComparator().compare(snapshot, heuristic_edges)

        self.assertEqual(snapshot.incidents, ())
        self.assertEqual(result.coverage.would_create_edge_count, 1)
        self.assertEqual(len(result.components[0].unassigned_event_refs), 2)

    def test_transitive_blast_radius_is_suppressed_by_component_limits(self) -> None:
        events = [
            _add_activity(_event("one", pid="100"), "activity-1"),
            _add_activity(
                _event("two", pid="200", ppid="100", seconds=1),
                "activity-2",
            ),
            _add_activity(
                _event("three", pid="300", ppid="200", seconds=2),
                "activity-3",
            ),
        ]
        snapshot, heuristic_edges = _artifacts(events)
        comparator = ShadowComparator(
            ShadowComparisonPolicy(max_incidents_per_component=2)
        )

        result = comparator.compare(snapshot, heuristic_edges)

        self.assertEqual(len(result.components), 1)
        self.assertEqual(result.coverage.maximum_incidents_in_component, 3)
        self.assertEqual(result.coverage.suppressed_component_count, 1)
        self.assertFalse(result.components[0].within_cardinality_bounds)
        self.assertIn(
            "cardinality:incident_limit_exceeded",
            result.components[0].suppression_reasons,
        )

    def test_missing_or_platform_mismatched_snapshot_events_are_rejected(self) -> None:
        windows_events = [
            _event("parent", pid="100"),
            _event("child", pid="200", ppid="100", seconds=1),
        ]
        _, heuristic_edges = _artifacts(windows_events)
        parent_only, _ = _artifacts([windows_events[0]])
        with self.assertRaises(ShadowInputConflictError):
            ShadowComparator().compare(parent_only, heuristic_edges)

        linux_events = [
            _event(
                "parent",
                pid="100",
                platform=Platform.LINUX,
                action="execve",
            ),
            _event(
                "child",
                pid="200",
                ppid="100",
                seconds=1,
                platform=Platform.LINUX,
                action="execve",
            ),
        ]
        linux_snapshot, _ = _artifacts(linux_events)
        with self.assertRaises(ShadowInputConflictError):
            ShadowComparator().compare(linux_snapshot, heuristic_edges)

    def test_edge_limit_duplicates_and_delivery_order_are_deterministic(self) -> None:
        events = [
            _add_activity(_event("one", pid="100"), "activity-1"),
            _add_activity(
                _event("two", pid="200", ppid="100", seconds=1),
                "activity-2",
            ),
            _add_activity(
                _event("three", pid="300", ppid="200", seconds=2),
                "activity-3",
            ),
        ]
        snapshot, heuristic_edges = _artifacts(events)
        first = ShadowComparator().compare(snapshot, heuristic_edges)
        second = ShadowComparator().compare(
            snapshot,
            reversed((*heuristic_edges, heuristic_edges[0])),
        )
        self.assertEqual(first, second)

        with self.assertRaises(ShadowLimitError):
            ShadowComparator(ShadowComparisonPolicy(max_edges=1)).compare(
                snapshot,
                heuristic_edges,
            )


if __name__ == "__main__":
    unittest.main()
