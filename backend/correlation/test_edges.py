from __future__ import annotations

import unittest
from datetime import datetime, timezone

from correlation.edges import (
    KEY_RULES,
    DeterministicEdgeBuilder,
    EdgeFamily,
    EdgeLimitError,
    EdgeRole,
    EdgeUsage,
    EventConflictError,
    DeterministicEdge,
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
    b"deterministic-edge-test",
    uri="memory://deterministic-edge-test",
    media_type="application/json",
    collected_at=NOW,
)


def _event(
    event_id: str,
    *keys: EntityKey,
    tenant_id: str = "tenant-a",
    platform: Platform = Platform.WINDOWS,
    parse_status: ParseStatus = ParseStatus.PARSED,
    attributes: dict | None = None,
) -> NormalizedEvent:
    warnings = () if parse_status is ParseStatus.PARSED else ("fixture warning",)
    return NormalizedEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        platform=platform,
        source_type="test_fixture",
        source_instance_id="source-1",
        adapter_version="1.0.0",
        ingested_at=NOW,
        observed_at=NOW,
        event_time_quality=EventTimeQuality.SOURCE_REPORTED,
        parse_status=parse_status,
        raw_evidence=RAW,
        entity_keys=keys,
        attributes=(
            {} if parse_status is ParseStatus.UNPARSEABLE else (attributes or {})
        ),
        parse_warnings=warnings,
    )


class DeterministicEdgeBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = DeterministicEdgeBuilder()

    def test_windows_parent_and_child_guids_share_canonical_kind_with_roles(
        self,
    ) -> None:
        event = _event(
            "windows-1",
            EntityKey("process_guid", "child-guid", "host-a:boot-1"),
            EntityKey("parent_process_guid", "parent-guid", "host-a:boot-1"),
            EntityKey("process_pid", "4242", "host-a:boot-1"),
        )
        result = self.builder.build([event])

        self.assertEqual(len(result.edges), 2)
        self.assertEqual(
            {(edge.entity_key.kind, edge.role) for edge in result.edges},
            {
                ("process_guid", EdgeRole.SUBJECT),
                ("process_guid", EdgeRole.PARENT),
            },
        )
        self.assertTrue(
            all(edge.usage is EdgeUsage.CORRELATION for edge in result.edges)
        )
        self.assertEqual(result.coverage.excluded_key_count, 1)
        self.assertEqual(dict(result.coverage.excluded_key_counts), {"process_pid": 1})

    def test_linux_request_session_and_identity_have_distinct_usage(self) -> None:
        event = _event(
            "linux-1",
            EntityKey("audit_event_serial", "1700000000.123:77", "host-a:boot-1"),
            EntityKey("audit_session", "42", "host-a:boot-1"),
            EntityKey("login_uid", "1000", "host-a:boot-1"),
            platform=Platform.LINUX,
        )
        result = self.builder.build([event])

        by_kind = {edge.source_key_kind: edge for edge in result.edges}
        self.assertIs(by_kind["audit_event_serial"].family, EdgeFamily.REQUEST)
        self.assertIs(by_kind["audit_session"].family, EdgeFamily.SESSION)
        self.assertIs(by_kind["login_uid"].usage, EdgeUsage.CONTEXT)
        self.assertEqual(result.coverage.correlation_edge_count, 2)
        self.assertEqual(result.coverage.context_edge_count, 1)

    def test_macos_pidversions_canonicalize_but_bare_pids_are_excluded(self) -> None:
        event = _event(
            "macos-1",
            EntityKey("process_pidversion", "100:8", "mac-a:boot-1"),
            EntityKey("initiator_process_pidversion", "100:7", "mac-a:boot-1"),
            EntityKey("responsible_process_pidversion", "40:3", "mac-a:boot-1"),
            EntityKey("parent_process_pid", "1", "mac-a:boot-1"),
            platform=Platform.MACOS,
        )
        result = self.builder.build([event])

        self.assertEqual(
            {edge.entity_key.kind for edge in result.edges}, {"process_pidversion"}
        )
        self.assertEqual(
            {edge.role for edge in result.edges},
            {EdgeRole.SUBJECT, EdgeRole.INITIATOR, EdgeRole.RESPONSIBLE},
        )
        self.assertEqual(result.coverage.excluded_key_count, 1)

    def test_aws_original_ids_join_current_ids_while_context_stays_non_driving(
        self,
    ) -> None:
        event = _event(
            "aws-1",
            EntityKey("cloudtrail_event_id", "event-current", "aws"),
            EntityKey("cloudtrail_original_event_id", "event-original", "aws"),
            EntityKey("cloud_request_id", "request-current", "aws:123:us-east-1"),
            EntityKey(
                "cloud_original_request_id",
                "request-original",
                "aws:123:us-east-1",
            ),
            EntityKey("aws_principal_arn", "arn:aws:iam::123:role/test", "aws:123"),
            EntityKey("aws_resource_arn", "arn:aws:s3:::bucket", "aws"),
            platform=Platform.AWS,
        )
        result = self.builder.build([event])

        by_source = {edge.source_key_kind: edge for edge in result.edges}
        self.assertEqual(
            by_source["cloudtrail_original_event_id"].entity_key.kind,
            "cloudtrail_event_id",
        )
        self.assertIs(
            by_source["cloudtrail_original_event_id"].role, EdgeRole.ORIGINAL
        )
        self.assertEqual(
            by_source["cloud_original_request_id"].entity_key.kind,
            "cloud_request_id",
        )
        self.assertIs(by_source["aws_principal_arn"].usage, EdgeUsage.CONTEXT)
        self.assertIs(by_source["aws_resource_arn"].usage, EdgeUsage.CONTEXT)
        self.assertEqual(result.coverage.correlation_edge_count, 4)
        self.assertEqual(result.coverage.context_edge_count, 2)
        self.assertEqual(result.coverage.events_without_correlation_edges, 0)

    def test_kubernetes_audit_id_drives_correlation_but_names_do_not(self) -> None:
        event = _event(
            "kubernetes-1",
            EntityKey("kubernetes_audit_id", "audit-1", "cluster-1"),
            EntityKey("kubernetes_user_uid", "uid-1", "cluster-1"),
            EntityKey("kubernetes_user_name", "system:serviceaccount:a:b", "cluster-1"),
            EntityKey("kubernetes_object_uid", "object-1", "cluster-1"),
            platform=Platform.KUBERNETES,
        )
        result = self.builder.build([event])

        by_source = {edge.source_key_kind: edge for edge in result.edges}
        self.assertIs(by_source["kubernetes_audit_id"].usage, EdgeUsage.CORRELATION)
        self.assertIs(by_source["kubernetes_user_uid"].usage, EdgeUsage.CONTEXT)
        self.assertIs(by_source["kubernetes_object_uid"].role, EdgeRole.RESOURCE)
        self.assertNotIn("kubernetes_user_name", by_source)
        self.assertEqual(result.coverage.excluded_key_count, 1)

    def test_unknown_future_key_fails_closed_and_is_visible_in_coverage(self) -> None:
        result = self.builder.build(
            [_event("future-1", EntityKey("future_magic_join", "value", "scope"))]
        )

        self.assertEqual(result.edges, ())
        self.assertEqual(result.coverage.unknown_key_count, 1)
        self.assertEqual(
            dict(result.coverage.unknown_key_counts), {"future_magic_join": 1}
        )
        self.assertEqual(result.coverage.events_without_emitted_edges, 1)
        self.assertEqual(result.coverage.events_without_correlation_edges, 1)
        self.assertEqual(
            result.coverage.to_dict()["platform_counts"]["windows"]["unknown_keys"],
            1,
        )

    def test_unparseable_event_never_emits_even_if_keys_are_attached(self) -> None:
        result = self.builder.build(
            [
                _event(
                    "bad-1",
                    EntityKey("process_guid", "must-not-join", "host:boot"),
                    parse_status=ParseStatus.UNPARSEABLE,
                )
            ]
        )

        self.assertEqual(result.edges, ())
        self.assertEqual(result.coverage.unparseable_event_count, 1)
        self.assertEqual(result.coverage.events_without_emitted_edges, 1)

    def test_same_native_key_is_tenant_isolated(self) -> None:
        key = EntityKey("process_guid", "same-guid", "host:boot")
        result = self.builder.build(
            [
                _event("event-1", key, tenant_id="tenant-a"),
                _event("event-1", key, tenant_id="tenant-b"),
            ]
        )

        self.assertEqual(len(result.edges), 2)
        self.assertNotEqual(result.edges[0].edge_id, result.edges[1].edge_id)
        self.assertEqual(
            {edge.tenant_id for edge in result.edges}, {"tenant-a", "tenant-b"}
        )

    def test_exact_redelivery_is_idempotent_but_conflicting_redelivery_fails(
        self,
    ) -> None:
        original = _event(
            "duplicate-1", EntityKey("process_guid", "guid-1", "host:boot")
        )
        result = self.builder.build([original, original])
        self.assertEqual(len(result.edges), 1)
        self.assertEqual(result.coverage.input_event_count, 2)
        self.assertEqual(result.coverage.unique_event_count, 1)
        self.assertEqual(result.coverage.duplicate_event_count, 1)

        conflicting = _event(
            "duplicate-1", EntityKey("process_guid", "guid-2", "host:boot")
        )
        with self.assertRaises(EventConflictError):
            self.builder.build([original, conflicting])

    def test_limits_are_enforced_before_unbounded_growth(self) -> None:
        with self.assertRaises(EdgeLimitError):
            DeterministicEdgeBuilder(max_unique_events=1).build(
                [_event("event-1"), _event("event-2")]
            )
        with self.assertRaises(EdgeLimitError):
            DeterministicEdgeBuilder(max_edges=1).build(
                [
                    _event(
                        "event-1",
                        EntityKey("process_guid", "guid-1", "host:boot"),
                        EntityKey("logon_id", "99", "host:boot"),
                    )
                ]
            )

    def test_serialization_and_edge_ids_are_deterministic(self) -> None:
        first_event = _event(
            "stable-1", EntityKey("activity_id", "activity-1", "host:boot")
        )
        second_event = _event(
            "stable-2", EntityKey("logon_id", "99", "host:boot")
        )
        first = self.builder.build([first_event, second_event])
        second = self.builder.build([second_event, first_event])

        self.assertEqual(first, second)
        self.assertEqual(first.edges[0].to_dict(), second.edges[0].to_dict())
        self.assertEqual(
            DeterministicEdge.from_dict(first.edges[0].to_dict()),
            first.edges[0],
        )
        self.assertEqual(first.coverage.to_dict(), second.coverage.to_dict())

    def test_forged_or_policy_mismatched_edges_are_rejected(self) -> None:
        event = _event(
            "stable-1", EntityKey("activity_id", "activity-1", "host:boot")
        )
        edge = self.builder.build([event]).edges[0]
        forged = edge.to_dict()
        forged["edge_id"] = "edge:" + ("0" * 64)
        with self.assertRaises(ValueError):
            DeterministicEdge.from_dict(forged)

        mismatched = edge.to_dict()
        mismatched["usage"] = "context"
        with self.assertRaises(ValueError):
            DeterministicEdge.from_dict(mismatched)

    def test_registry_covers_every_key_kind_emitted_by_current_adapters(self) -> None:
        emitted_key_kinds = {
            "process_guid",
            "parent_process_guid",
            "process_entity_id",
            "parent_process_entity_id",
            "process_pidversion",
            "parent_process_pidversion",
            "initiator_process_pidversion",
            "responsible_process_pidversion",
            "process_pid",
            "parent_process_pid",
            "initiator_process_pid",
            "responsible_process_pid",
            "audit_event_serial",
            "audit_session",
            "login_uid",
            "logon_guid",
            "logon_id",
            "activity_id",
            "related_activity_id",
            "cloudtrail_event_id",
            "cloudtrail_original_event_id",
            "cloudtrail_shared_event_id",
            "cloudtrail_insight_id",
            "cloud_request_id",
            "cloud_original_request_id",
            "aws_principal_id",
            "aws_principal_arn",
            "aws_access_key_id",
            "aws_identity_center_user_id",
            "aws_delegated_provider_account_id",
            "aws_signin_session_arn",
            "aws_session_issuer_arn",
            "aws_attributed_principal_arn",
            "aws_resource_arn",
            "aws_vpc_endpoint_id",
            "kubernetes_audit_id",
            "kubernetes_user_uid",
            "kubernetes_user_name",
            "kubernetes_impersonated_user_uid",
            "kubernetes_impersonated_user_name",
            "kubernetes_object_uid",
        }
        self.assertEqual(set(KEY_RULES), emitted_key_kinds)


if __name__ == "__main__":
    unittest.main()
