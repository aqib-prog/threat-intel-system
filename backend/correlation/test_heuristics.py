from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from correlation.linux import LinuxAdapter
from correlation.local import LocalRawEvidenceStore
from correlation.macos import MacOSAdapter
from correlation.heuristics import (
    HeuristicEdge,
    HeuristicEdgeBuilder,
    HeuristicInputConflictError,
    HeuristicLimitError,
    HeuristicPolicy,
)
from correlation.models import (
    EntityKey,
    EventTimeQuality,
    NormalizedEvent,
    ParseStatus,
    Platform,
    RawEvidenceRef,
)
from correlation.windows import WindowsAdapter


NOW = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)
RAW = RawEvidenceRef.for_bytes(
    b"heuristic-test",
    uri="memory://heuristic-test",
    media_type="application/json",
    collected_at=NOW,
)


def _event(
    event_id: str,
    *,
    pid: str | None,
    ppid: str | None = None,
    scope: str = "host:boot",
    seconds: float = 0,
    tenant_id: str = "tenant-a",
    platform: Platform = Platform.WINDOWS,
    action: str = "process_start",
    time_quality: EventTimeQuality = EventTimeQuality.SOURCE_REPORTED,
    parse_status: ParseStatus = ParseStatus.PARSED,
    stable_parent: EntityKey | None = None,
) -> NormalizedEvent:
    keys: list[EntityKey] = []
    if pid is not None:
        keys.append(EntityKey("process_pid", pid, scope))
    if ppid is not None:
        keys.append(EntityKey("parent_process_pid", ppid, scope))
    if stable_parent is not None:
        keys.append(stable_parent)
    warnings = () if parse_status is ParseStatus.PARSED else ("fixture warning",)
    observed_at = NOW + timedelta(seconds=seconds)
    return NormalizedEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        platform=platform,
        source_type="test_fixture",
        source_instance_id="source-1",
        adapter_version="1.0.0",
        ingested_at=observed_at,
        observed_at=observed_at,
        event_time_quality=time_quality,
        parse_status=parse_status,
        raw_evidence=RAW,
        entity_keys=tuple(keys),
        attributes=(
            {}
            if parse_status is ParseStatus.UNPARSEABLE
            else {"event": {"action": action}}
        ),
        parse_warnings=warnings,
    )


def _builder(*, gap: float = 10, **kwargs) -> HeuristicEdgeBuilder:
    return HeuristicEdgeBuilder(
        HeuristicPolicy.pid_lineage_shadow(
            max_parent_pid_gap_seconds=gap,
            **kwargs,
        )
    )


class HeuristicEdgeBuilderTests(unittest.TestCase):
    def test_disabled_by_default_and_one_shot_iterators_are_supported(self) -> None:
        events = (
            event
            for event in (
                _event("parent", pid="100"),
                _event("child", pid="200", ppid="100", seconds=1),
            )
        )

        result = HeuristicEdgeBuilder().build(events)

        self.assertEqual(result.edges, ())
        self.assertFalse(result.coverage.enabled)
        self.assertEqual(result.coverage.unique_event_count, 2)

    def test_one_unique_prior_parent_observation_emits_shadow_edge(self) -> None:
        parent = _event("parent", pid="100")
        child = _event("child", pid="200", ppid="100", seconds=1)

        result = _builder().build([child, parent])

        self.assertEqual(len(result.edges), 1)
        edge = result.edges[0]
        self.assertEqual(edge.parent_event_id, "parent")
        self.assertEqual(edge.child_event_id, "child")
        self.assertEqual(edge.gap_milliseconds, 1000)
        self.assertEqual(result.coverage.emitted_edge_count, 1)
        self.assertEqual(HeuristicEdge.from_dict(edge.to_dict()), edge)
        self.assertEqual(result.policy.to_dict()["max_parent_pid_gap_seconds"], 10)

    def test_multiple_live_candidates_are_ambiguous_and_fail_closed(self) -> None:
        events = [
            _event("parent-old", pid="100", seconds=0),
            _event("parent-new", pid="100", seconds=1),
            _event("child", pid="200", ppid="100", seconds=2),
        ]

        result = _builder().build(events)

        self.assertEqual(result.edges, ())
        self.assertEqual(result.coverage.ambiguous_candidate_count, 1)

    def test_pid_reuse_outside_window_does_not_create_ambiguity(self) -> None:
        events = [
            _event("expired-parent", pid="100", seconds=0),
            _event("current-parent", pid="100", seconds=100),
            _event("child", pid="200", ppid="100", seconds=105),
        ]

        result = _builder(gap=10).build(events)

        self.assertEqual(len(result.edges), 1)
        self.assertEqual(result.edges[0].parent_event_id, "current-parent")

    def test_equal_timestamp_and_outside_window_candidates_are_rejected(self) -> None:
        equal = _builder().build(
            [
                _event("parent", pid="100"),
                _event("child", pid="200", ppid="100"),
            ]
        )
        outside = _builder(gap=1).build(
            [
                _event("parent", pid="100"),
                _event("child", pid="200", ppid="100", seconds=2),
            ]
        )

        self.assertEqual(equal.edges, ())
        self.assertEqual(equal.coverage.equal_timestamp_candidate_count, 1)
        self.assertEqual(outside.edges, ())
        self.assertEqual(outside.coverage.outside_window_count, 1)

    def test_stable_parent_identifier_supersedes_pid_heuristic(self) -> None:
        parent = _event("parent", pid="100")
        child = _event(
            "child",
            pid="200",
            ppid="100",
            seconds=1,
            stable_parent=EntityKey(
                "parent_process_guid",
                "{11111111-1111-1111-1111-111111111111}",
                "host:boot",
            ),
        )

        result = _builder().build([parent, child])

        self.assertEqual(result.edges, ())
        self.assertEqual(result.coverage.stable_parent_key_count, 1)

    def test_tenant_platform_and_scope_are_hard_boundaries(self) -> None:
        parent = _event("parent", pid="100")
        children = [
            _event(
                "other-tenant",
                pid="200",
                ppid="100",
                seconds=1,
                tenant_id="tenant-b",
            ),
            _event(
                "other-platform",
                pid="201",
                ppid="100",
                seconds=1,
                platform=Platform.LINUX,
            ),
            _event(
                "other-scope",
                pid="202",
                ppid="100",
                seconds=1,
                scope="host-2:boot",
            ),
        ]

        result = _builder().build([parent, *children])

        self.assertEqual(result.edges, ())
        self.assertEqual(result.coverage.no_candidate_count, 3)

    def test_aws_kubernetes_bad_time_action_and_unparseable_are_ineligible(
        self,
    ) -> None:
        events = [
            _event("aws", pid="1", platform=Platform.AWS),
            _event("k8s", pid="1", platform=Platform.KUBERNETES),
            _event(
                "collector-time",
                pid="1",
                time_quality=EventTimeQuality.COLLECTOR_ASSIGNED,
            ),
            _event("network", pid="1", action="network_connection"),
            _event("broken", pid="1", parse_status=ParseStatus.UNPARSEABLE),
        ]

        result = _builder().build(events)

        self.assertEqual(result.edges, ())
        self.assertEqual(result.coverage.unsupported_platform_count, 2)
        self.assertEqual(result.coverage.non_source_time_count, 1)
        self.assertEqual(result.coverage.ineligible_action_count, 1)
        self.assertEqual(result.coverage.unparseable_event_count, 1)

    def test_redelivery_is_idempotent_and_conflicting_event_reuse_fails(self) -> None:
        parent = _event("parent", pid="100")
        child = _event("child", pid="200", ppid="100", seconds=1)
        result = _builder().build(iter([parent, child, child]))

        self.assertEqual(len(result.edges), 1)
        self.assertEqual(result.coverage.duplicate_event_count, 1)

        conflicting = _event("child", pid="201", ppid="100", seconds=1)
        with self.assertRaises(HeuristicInputConflictError):
            _builder().build([child, conflicting])

    def test_delivery_order_is_deterministic(self) -> None:
        events = [
            _event("parent", pid="100"),
            _event("child", pid="200", ppid="100", seconds=1),
        ]

        first = _builder().build(events)
        second = _builder().build(reversed(events))

        self.assertEqual(first, second)

    def test_limits_and_policy_ceiling_are_enforced(self) -> None:
        with self.assertRaises(ValueError):
            HeuristicPolicy.pid_lineage_shadow(max_parent_pid_gap_seconds=301)
        with self.assertRaises(ValueError):
            HeuristicPolicy(enabled=False, max_parent_pid_gap_seconds=1)

        events = [
            _event("parent", pid="100"),
            _event("child", pid="200", ppid="100", seconds=1),
        ]
        with self.assertRaises(HeuristicLimitError):
            _builder(max_unique_events=1).build(events)
        with self.assertRaises(HeuristicLimitError):
            _builder(max_pid_index_keys=1).build(events)

        two_children = [
            _event("parent-a", pid="100"),
            _event("child-a", pid="200", ppid="100", seconds=1),
            _event("parent-b", pid="300", seconds=2),
            _event("child-b", pid="400", ppid="300", seconds=3),
        ]
        with self.assertRaises(HeuristicLimitError):
            _builder(max_edges=1).build(two_children)

    def test_tampered_serialized_edge_is_rejected(self) -> None:
        edge = _builder().build(
            [
                _event("parent", pid="100"),
                _event("child", pid="200", ppid="100", seconds=1),
            ]
        ).edges[0]
        payload = edge.to_dict()
        payload["gap_milliseconds"] = 9999

        with self.assertRaises(ValueError):
            HeuristicEdge.from_dict(payload)

    def test_real_windows_linux_and_macos_adapter_outputs_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = LocalRawEvidenceStore(Path(temporary) / "evidence")
            windows = WindowsAdapter(
                store,
                tenant_id="tenant-a",
                source_instance_id="windows-host",
                boot_id="boot-1",
            )
            windows_records = [
                {
                    "System": {
                        "Provider": {
                            "Name": "Microsoft-Windows-Security-Auditing"
                        },
                        "EventID": "4688",
                        "EventRecordID": str(100 + index),
                        "TimeCreated": {
                            "SystemTime": f"2026-08-11T12:00:0{index}Z"
                        },
                    },
                    "EventData": {
                        "NewProcessId": new_pid,
                        "ProcessId": parent_pid,
                        "NewProcessName": executable,
                    },
                }
                for index, (new_pid, parent_pid, executable) in enumerate(
                    (
                        ("0x64", "0x4", r"C:\Windows\System32\cmd.exe"),
                        ("0xc8", "0x64", r"C:\Windows\System32\whoami.exe"),
                    )
                )
            ]
            windows_events = windows.ingest(
                json.dumps(windows_records).encode(),
                media_type="application/json",
                collected_at=NOW,
            )

            linux = LinuxAdapter(
                store,
                tenant_id="tenant-a",
                source_instance_id="linux-host",
                boot_id="boot-1",
            )
            linux_payload = (
                'type=EXECVE msg=audit(1786449600.000:1): pid=100 ppid=1 '
                'argc=1 a0="bash"\n'
                'type=EXECVE msg=audit(1786449601.000:2): pid=200 ppid=100 '
                'argc=1 a0="whoami"\n'
            ).encode()
            linux_events = linux.ingest(
                linux_payload,
                media_type="text/plain",
                collected_at=NOW,
            )

            macos = MacOSAdapter(
                store,
                tenant_id="tenant-a",
                source_instance_id="mac-host",
                boot_id="boot-1",
                collector_instance_id="elastic-1",
            )
            macos_records = [
                {
                    "_source": {
                        "@timestamp": f"2026-08-11T12:00:0{index}Z",
                        "host": {"os": {"platform": "macos"}},
                        "event": {
                            "id": f"mac-{index}",
                            "action": "start",
                            "category": ["process"],
                            "dataset": "endpoint.events.process",
                        },
                        "process": {
                            "pid": pid,
                            "ppid": ppid,
                            "name": name,
                        },
                    },
                }
                for index, (pid, ppid, name) in enumerate(
                    ((100, 1, "zsh"), (200, 100, "whoami"))
                )
            ]
            macos_events = macos.ingest(
                json.dumps(macos_records).encode(),
                media_type="application/json",
                collected_at=NOW,
            )

        results = [
            _builder().build(windows_events),
            _builder().build(linux_events),
            _builder().build(macos_events),
        ]
        self.assertEqual([len(result.edges) for result in results], [1, 1, 1])
        self.assertEqual(
            [result.edges[0].platform for result in results],
            [Platform.WINDOWS, Platform.LINUX, Platform.MACOS],
        )


if __name__ == "__main__":
    unittest.main()
