from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from correlation.edges import DeterministicEdgeBuilder
from correlation.incidents import (
    IncidentBuilder,
    IncidentChangeKind,
    IncidentHistory,
    IncidentInputConflictError,
    IncidentLimitError,
    IncidentRevision,
    IncidentSnapshot,
)
from correlation.models import (
    EntityKey,
    EventTimeQuality,
    NormalizedEvent,
    ParseStatus,
    Platform,
    RawEvidenceRef,
)


NOW = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)
RAW = RawEvidenceRef.for_bytes(
    b"incident-test",
    uri="memory://incident-test",
    media_type="application/json",
    collected_at=NOW,
)


def _event(
    event_id: str,
    *keys: EntityKey,
    tenant_id: str = "tenant-a",
    platform: Platform = Platform.WINDOWS,
    seconds: int = 0,
    parse_status: ParseStatus = ParseStatus.PARSED,
    raw: RawEvidenceRef = RAW,
    ingested_at: datetime = NOW,
) -> NormalizedEvent:
    warnings = () if parse_status is ParseStatus.PARSED else ("fixture warning",)
    return NormalizedEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        platform=platform,
        source_type="test_fixture",
        source_instance_id="source-1",
        adapter_version="1.0.0",
        ingested_at=ingested_at,
        observed_at=NOW + timedelta(seconds=seconds),
        event_time_quality=EventTimeQuality.SOURCE_REPORTED,
        parse_status=parse_status,
        raw_evidence=raw,
        entity_keys=keys,
        attributes=(
            {} if parse_status is ParseStatus.UNPARSEABLE else {"sequence": seconds}
        ),
        parse_warnings=warnings,
    )


def _snapshot(events: list[NormalizedEvent], *, excluded_event_ids=()):
    edge_result = DeterministicEdgeBuilder().build(events)
    excluded = set(excluded_event_ids)
    edges = [edge for edge in edge_result.edges if edge.event_id not in excluded]
    return IncidentBuilder().build(events, edges)


class IncidentBuilderTests(unittest.TestCase):
    def test_shared_correlation_key_forms_one_time_ordered_incident(self) -> None:
        key = EntityKey("process_guid", "process-1", "host:boot")
        later = _event("event-a", key, seconds=20)
        earlier = _event("event-z", key, seconds=10)

        snapshot = _snapshot([later, earlier])

        self.assertEqual(len(snapshot.incidents), 1)
        incident = snapshot.incidents[0]
        self.assertEqual(incident.event_ids, ("event-z", "event-a"))
        self.assertEqual(len(incident.correlation_edge_ids), 2)
        self.assertEqual(incident.context_edge_ids, ())
        self.assertEqual(incident.first_event_time, NOW + timedelta(seconds=10))
        self.assertEqual(incident.last_event_time, NOW + timedelta(seconds=20))
        self.assertEqual(snapshot.unassigned_events, ())

    def test_context_edges_enrich_but_never_merge_components(self) -> None:
        shared_principal = EntityKey(
            "aws_principal_arn",
            "arn:aws:iam::123:role/shared",
            "aws:123",
        )
        left = _event(
            "aws-left",
            EntityKey("cloudtrail_event_id", "left", "aws"),
            shared_principal,
            platform=Platform.AWS,
        )
        right = _event(
            "aws-right",
            EntityKey("cloudtrail_event_id", "right", "aws"),
            shared_principal,
            platform=Platform.AWS,
        )

        snapshot = _snapshot([left, right])

        self.assertEqual(len(snapshot.incidents), 2)
        self.assertTrue(
            all(
                shared_principal in item.context_entity_keys
                for item in snapshot.incidents
            )
        )
        self.assertTrue(
            all(len(item.context_edge_ids) == 1 for item in snapshot.incidents)
        )

    def test_events_without_correlation_edges_remain_explicitly_unassigned(
        self,
    ) -> None:
        context_only = _event(
            "context-only",
            EntityKey("login_uid", "1000", "host:boot"),
            platform=Platform.LINUX,
        )
        unstable_only = _event(
            "pid-only",
            EntityKey("process_pid", "77", "host:boot"),
            platform=Platform.LINUX,
        )

        snapshot = _snapshot([context_only, unstable_only])

        self.assertEqual(snapshot.incidents, ())
        self.assertEqual(
            {event.event_id for event in snapshot.unassigned_events},
            {"context-only", "pid-only"},
        )
        self.assertEqual(len(snapshot.unassigned_context_edge_ids), 1)

    def test_tenant_and_platform_boundaries_prevent_accidental_joins(self) -> None:
        key = EntityKey("process_guid", "same", "same-host:boot")
        events = [
            _event("a", key, tenant_id="tenant-a", platform=Platform.WINDOWS),
            _event("b", key, tenant_id="tenant-b", platform=Platform.WINDOWS),
            _event("c", key, tenant_id="tenant-a", platform=Platform.LINUX),
        ]

        snapshot = _snapshot(events)

        self.assertEqual(len(snapshot.incidents), 3)
        self.assertTrue(all(len(item.events) == 1 for item in snapshot.incidents))

    def test_delivery_order_does_not_change_incident_or_snapshot_ids(self) -> None:
        key = EntityKey("kubernetes_audit_id", "audit-1", "cluster-1")
        events = [
            _event("stage-1", key, platform=Platform.KUBERNETES, seconds=1),
            _event("stage-2", key, platform=Platform.KUBERNETES, seconds=2),
        ]
        edge_result = DeterministicEdgeBuilder().build(events)

        first = IncidentBuilder().build(events, edge_result.edges)
        second = IncidentBuilder().build(
            reversed(events),
            reversed(edge_result.edges),
        )

        self.assertEqual(first, second)

    def test_replay_storage_location_does_not_change_snapshot_identity(self) -> None:
        replay_raw = RawEvidenceRef(
            sha256=RAW.sha256,
            uri="file:///different-environment/evidence.raw",
            byte_length=RAW.byte_length,
            media_type=RAW.media_type,
            collected_at=NOW + timedelta(days=1),
        )
        key = EntityKey("activity_id", "activity-1", "host:boot")
        original = _event("event-1", key, raw=RAW, ingested_at=NOW)
        replay = _event(
            "event-1",
            key,
            raw=replay_raw,
            ingested_at=NOW + timedelta(days=1),
        )

        original_snapshot = _snapshot([original])
        replay_snapshot = _snapshot([replay])

        self.assertEqual(original_snapshot.snapshot_id, replay_snapshot.snapshot_id)
        self.assertEqual(
            original_snapshot.incidents[0].incident_id,
            replay_snapshot.incidents[0].incident_id,
        )

    def test_snapshot_serialization_round_trip_rejects_tampered_provenance(
        self,
    ) -> None:
        snapshot = _snapshot(
            [
                _event(
                    "event-1",
                    EntityKey("activity_id", "activity-1", "host:boot"),
                )
            ]
        )
        payload = snapshot.to_dict()

        self.assertEqual(IncidentSnapshot.from_dict(payload), snapshot)
        payload["incidents"][0]["correlation_edge_ids"][0] = "edge:tampered"
        with self.assertRaises(ValueError):
            IncidentSnapshot.from_dict(payload)

    def test_orphan_platform_mismatch_and_unparseable_edges_are_rejected(self) -> None:
        key = EntityKey("process_guid", "process-1", "host:boot")
        parsed = _event("event-1", key)
        edge = DeterministicEdgeBuilder().build([parsed]).edges[0]

        with self.assertRaises(IncidentInputConflictError):
            IncidentBuilder().build([], [edge])

        wrong_platform = _event("event-1", key, platform=Platform.LINUX)
        with self.assertRaises(IncidentInputConflictError):
            IncidentBuilder().build([wrong_platform], [edge])

        unparseable = _event(
            "event-1",
            key,
            parse_status=ParseStatus.UNPARSEABLE,
        )
        with self.assertRaises(IncidentInputConflictError):
            IncidentBuilder().build([unparseable], [edge])

    def test_limits_bound_events_edges_and_incidents(self) -> None:
        events = [
            _event(
                f"event-{index}",
                EntityKey("activity_id", f"activity-{index}", "host:boot"),
            )
            for index in range(2)
        ]
        edges = DeterministicEdgeBuilder().build(events).edges

        with self.assertRaises(IncidentLimitError):
            IncidentBuilder(max_events=1).build(events, edges)
        with self.assertRaises(IncidentLimitError):
            IncidentBuilder(max_edges=1).build(events, edges)
        with self.assertRaises(IncidentLimitError):
            IncidentBuilder(max_incidents=1).build(events, edges)


class IncidentRevisionTests(unittest.TestCase):
    def test_expansion_contraction_and_assignment_deltas_are_explicit(self) -> None:
        key = EntityKey("process_guid", "process-1", "host:boot")
        first_event = _event("event-1", key)
        second_event = _event("event-2", key, seconds=1)
        first = _snapshot([first_event])
        expanded = _snapshot([first_event, second_event])

        history = IncidentHistory()
        created = history.append(first)
        expansion = history.append(expanded)
        contraction = history.append(first)

        self.assertIsNotNone(created)
        self.assertEqual(created.changes[0].kind, IncidentChangeKind.CREATED)
        self.assertEqual(expansion.changes[0].kind, IncidentChangeKind.EXPANDED)
        self.assertEqual(
            expansion.newly_assigned_event_refs,
            (("tenant-a", "event-2"),),
        )
        self.assertEqual(expansion.added_event_refs, (("tenant-a", "event-2"),))
        self.assertEqual(contraction.changes[0].kind, IncidentChangeKind.CONTRACTED)
        self.assertEqual(contraction.newly_unassigned_event_refs, ())
        self.assertEqual(contraction.removed_event_refs, (("tenant-a", "event-2"),))
        self.assertEqual(
            IncidentRevision.from_dict(expansion.to_dict()),
            expansion,
        )

    def test_bridge_event_merge_and_removal_split_are_reversible(self) -> None:
        left_key = EntityKey("process_guid", "left", "host:boot")
        right_key = EntityKey("process_guid", "right", "host:boot")
        left = _event("left", left_key)
        right = _event("right", right_key)
        bridge = _event("bridge", left_key, right_key)
        events = [left, right, bridge]
        split = _snapshot(events, excluded_event_ids={"bridge"})
        merged = _snapshot(events)

        history = IncidentHistory()
        history.append(split)
        merge_revision = history.append(merged)
        split_revision = history.rollback(split.snapshot_id)

        self.assertEqual(len(split.incidents), 2)
        self.assertEqual(len(merged.incidents), 1)
        self.assertEqual(merge_revision.changes[0].kind, IncidentChangeKind.MERGED)
        self.assertEqual(split_revision.changes[0].kind, IncidentChangeKind.SPLIT)
        self.assertEqual(
            split_revision.newly_unassigned_event_refs,
            (("tenant-a", "bridge"),),
        )
        self.assertEqual(split_revision.removed_event_refs, ())
        self.assertEqual(
            history.timeline,
            (split.snapshot_id, merged.snapshot_id, split.snapshot_id),
        )
        self.assertIs(history.current_snapshot, split)

    def test_context_change_is_updated_not_merge_or_split(self) -> None:
        process = EntityKey("process_guid", "process-1", "host:boot")
        without_context = _event("event-1", process)
        with_context = _event(
            "event-1",
            process,
            EntityKey("login_uid", "1000", "host:boot"),
        )
        first = _snapshot([without_context])
        second = _snapshot([with_context])

        history = IncidentHistory()
        history.append(first)
        revision = history.append(second)

        self.assertEqual(revision.changes[0].kind, IncidentChangeKind.UPDATED)
        self.assertEqual(revision.newly_assigned_event_refs, ())
        self.assertEqual(revision.newly_unassigned_event_refs, ())

    def test_appending_identical_snapshot_is_idempotent(self) -> None:
        snapshot = _snapshot(
            [
                _event(
                    "event-1",
                    EntityKey("kubernetes_audit_id", "audit-1", "cluster-1"),
                    platform=Platform.KUBERNETES,
                )
            ]
        )
        history = IncidentHistory()

        self.assertIsNotNone(history.append(snapshot))
        self.assertIsNone(history.append(snapshot))
        self.assertEqual(len(history.revisions), 1)


if __name__ == "__main__":
    unittest.main()
