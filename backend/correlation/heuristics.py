"""Fail-closed, shadow-only heuristic correlation candidates.

Heuristic edges are deliberately a different type from deterministic edges and
cannot be consumed by ``IncidentBuilder``. The first rule proposes temporal
parent-PID lineage only when one unique prior process observation exists in an
explicitly configured window. It remains unmeasured and disabled by default.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from correlation.models import (
    EntityKey,
    EventTimeQuality,
    NormalizedEvent,
    ParseStatus,
    Platform,
)


HEURISTIC_EDGE_SCHEMA_VERSION = "1.0.0"
PID_PARENT_LINEAGE_RULE_ID = "pid_parent_lineage.v1"
ABSOLUTE_MAX_PARENT_PID_GAP_SECONDS = 300.0
DEFAULT_MAX_HEURISTIC_EVENTS = 1_000_000
DEFAULT_MAX_HEURISTIC_EDGES = 1_000_000
DEFAULT_MAX_PID_INDEX_KEYS = 1_000_000


class HeuristicBuildError(RuntimeError):
    pass


class HeuristicInputConflictError(HeuristicBuildError):
    pass


class HeuristicLimitError(HeuristicBuildError):
    pass


class HeuristicMode(str, Enum):
    SHADOW = "shadow"


class HeuristicValidationStatus(str, Enum):
    UNMEASURED = "unmeasured"


_ELIGIBLE_ACTIONS: dict[Platform, frozenset[str]] = {
    Platform.WINDOWS: frozenset({"process_start"}),
    Platform.LINUX: frozenset({"process_start", "execve"}),
    Platform.MACOS: frozenset({"exec", "fork", "process_start", "start"}),
}
_STABLE_PARENT_KEY_KINDS = frozenset(
    {
        "parent_process_guid",
        "parent_process_entity_id",
        "parent_process_pidversion",
    }
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _event_fingerprint(event: NormalizedEvent) -> bytes:
    return _canonical_json(event.to_dict())


def _event_action(event: NormalizedEvent) -> str | None:
    event_attributes = event.attributes.get("event")
    if not isinstance(event_attributes, Mapping):
        return None
    action = event_attributes.get("action")
    rendered = str(action or "").strip().casefold()
    return rendered or None


def _keys(event: NormalizedEvent, kind: str) -> tuple[EntityKey, ...]:
    return tuple(key for key in event.entity_keys if key.kind == kind)


@dataclass(frozen=True, slots=True)
class HeuristicPolicy:
    enabled: bool = False
    max_parent_pid_gap_seconds: float = 0.0
    max_unique_events: int = DEFAULT_MAX_HEURISTIC_EVENTS
    max_edges: int = DEFAULT_MAX_HEURISTIC_EDGES
    max_pid_index_keys: int = DEFAULT_MAX_PID_INDEX_KEYS
    max_candidates_per_pid: int = 2
    mode: HeuristicMode = HeuristicMode.SHADOW

    def __post_init__(self) -> None:
        if (
            not isinstance(self.mode, HeuristicMode)
            or self.mode is not HeuristicMode.SHADOW
        ):
            raise ValueError("heuristic correlation is shadow-only")
        if min(
            self.max_unique_events,
            self.max_edges,
            self.max_pid_index_keys,
            self.max_candidates_per_pid,
        ) < 1:
            raise ValueError("heuristic limits must be positive")
        if self.max_candidates_per_pid < 2:
            raise ValueError("at least two candidates are required to detect ambiguity")
        if self.enabled and not (
            0 < self.max_parent_pid_gap_seconds
            <= ABSOLUTE_MAX_PARENT_PID_GAP_SECONDS
        ):
            raise ValueError(
                "enabled parent-PID shadowing requires an explicit gap no greater "
                f"than {ABSOLUTE_MAX_PARENT_PID_GAP_SECONDS:g} seconds"
            )
        if not self.enabled and self.max_parent_pid_gap_seconds != 0:
            raise ValueError("disabled heuristic policy must not carry an active gap")

    @classmethod
    def pid_lineage_shadow(
        cls,
        *,
        max_parent_pid_gap_seconds: float,
        max_unique_events: int = DEFAULT_MAX_HEURISTIC_EVENTS,
        max_edges: int = DEFAULT_MAX_HEURISTIC_EDGES,
        max_pid_index_keys: int = DEFAULT_MAX_PID_INDEX_KEYS,
        max_candidates_per_pid: int = 2,
    ) -> HeuristicPolicy:
        return cls(
            enabled=True,
            max_parent_pid_gap_seconds=max_parent_pid_gap_seconds,
            max_unique_events=max_unique_events,
            max_edges=max_edges,
            max_pid_index_keys=max_pid_index_keys,
            max_candidates_per_pid=max_candidates_per_pid,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode.value,
            "max_parent_pid_gap_seconds": self.max_parent_pid_gap_seconds,
            "max_unique_events": self.max_unique_events,
            "max_edges": self.max_edges,
            "max_pid_index_keys": self.max_pid_index_keys,
            "max_candidates_per_pid": self.max_candidates_per_pid,
        }


def _heuristic_edge_payload(
    *,
    tenant_id: str,
    platform: Platform,
    parent_event_id: str,
    child_event_id: str,
    process_pid_key: EntityKey,
    parent_pid_key: EntityKey,
    gap_milliseconds: int,
) -> dict[str, Any]:
    return {
        "schema_version": HEURISTIC_EDGE_SCHEMA_VERSION,
        "rule_id": PID_PARENT_LINEAGE_RULE_ID,
        "mode": HeuristicMode.SHADOW.value,
        "validation_status": HeuristicValidationStatus.UNMEASURED.value,
        "tenant_id": tenant_id,
        "platform": platform.value,
        "parent_event_id": parent_event_id,
        "child_event_id": child_event_id,
        "process_pid_key": process_pid_key.to_dict(),
        "parent_pid_key": parent_pid_key.to_dict(),
        "gap_milliseconds": gap_milliseconds,
    }


@dataclass(frozen=True, slots=True)
class HeuristicEdge:
    edge_id: str
    tenant_id: str
    platform: Platform
    parent_event_id: str
    child_event_id: str
    process_pid_key: EntityKey
    parent_pid_key: EntityKey
    gap_milliseconds: int
    rule_id: str = PID_PARENT_LINEAGE_RULE_ID
    mode: HeuristicMode = HeuristicMode.SHADOW
    validation_status: HeuristicValidationStatus = (
        HeuristicValidationStatus.UNMEASURED
    )
    schema_version: str = HEURISTIC_EDGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for field_name in ("tenant_id", "parent_event_id", "child_event_id"):
            if not str(getattr(self, field_name) or "").strip():
                raise ValueError(f"{field_name} must not be empty")
        if self.parent_event_id == self.child_event_id:
            raise ValueError("a heuristic edge cannot connect an event to itself")
        if not isinstance(self.platform, Platform):
            raise TypeError("platform must be a Platform")
        if self.platform not in _ELIGIBLE_ACTIONS:
            raise ValueError("platform is not eligible for parent-PID shadowing")
        if self.rule_id != PID_PARENT_LINEAGE_RULE_ID:
            raise ValueError("unsupported heuristic rule")
        if self.mode is not HeuristicMode.SHADOW:
            raise ValueError("heuristic edges must remain shadow-only")
        if self.validation_status is not HeuristicValidationStatus.UNMEASURED:
            raise ValueError("unmeasured heuristic cannot claim validation")
        if self.schema_version != HEURISTIC_EDGE_SCHEMA_VERSION:
            raise ValueError("unsupported heuristic edge schema version")
        if self.process_pid_key.kind != "process_pid":
            raise ValueError("process_pid_key must use process_pid")
        if self.parent_pid_key.kind != "parent_process_pid":
            raise ValueError("parent_pid_key must use parent_process_pid")
        if (
            self.process_pid_key.value != self.parent_pid_key.value
            or self.process_pid_key.scope != self.parent_pid_key.scope
        ):
            raise ValueError("PID heuristic keys must match in value and scope")
        if self.gap_milliseconds <= 0:
            raise ValueError("PID heuristic gap must be strictly positive")
        if self.gap_milliseconds > ABSOLUTE_MAX_PARENT_PID_GAP_SECONDS * 1000:
            raise ValueError("PID heuristic gap exceeds the absolute safety ceiling")
        payload = _heuristic_edge_payload(
            tenant_id=self.tenant_id,
            platform=self.platform,
            parent_event_id=self.parent_event_id,
            child_event_id=self.child_event_id,
            process_pid_key=self.process_pid_key,
            parent_pid_key=self.parent_pid_key,
            gap_milliseconds=self.gap_milliseconds,
        )
        expected_id = "heuristic-edge:" + hashlib.sha256(
            _canonical_json(payload)
        ).hexdigest()
        if self.edge_id != expected_id:
            raise ValueError("edge_id does not match heuristic edge content")

    @classmethod
    def create(
        cls,
        *,
        tenant_id: str,
        platform: Platform,
        parent_event_id: str,
        child_event_id: str,
        process_pid_key: EntityKey,
        parent_pid_key: EntityKey,
        gap_milliseconds: int,
    ) -> HeuristicEdge:
        payload = _heuristic_edge_payload(
            tenant_id=tenant_id,
            platform=platform,
            parent_event_id=parent_event_id,
            child_event_id=child_event_id,
            process_pid_key=process_pid_key,
            parent_pid_key=parent_pid_key,
            gap_milliseconds=gap_milliseconds,
        )
        return cls(
            edge_id="heuristic-edge:"
            + hashlib.sha256(_canonical_json(payload)).hexdigest(),
            tenant_id=tenant_id,
            platform=platform,
            parent_event_id=parent_event_id,
            child_event_id=child_event_id,
            process_pid_key=process_pid_key,
            parent_pid_key=parent_pid_key,
            gap_milliseconds=gap_milliseconds,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_heuristic_edge_payload(
                tenant_id=self.tenant_id,
                platform=self.platform,
                parent_event_id=self.parent_event_id,
                child_event_id=self.child_event_id,
                process_pid_key=self.process_pid_key,
                parent_pid_key=self.parent_pid_key,
                gap_milliseconds=self.gap_milliseconds,
            ),
            "edge_id": self.edge_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> HeuristicEdge:
        return cls(
            edge_id=str(value.get("edge_id") or ""),
            tenant_id=str(value.get("tenant_id") or ""),
            platform=Platform(str(value.get("platform") or "")),
            parent_event_id=str(value.get("parent_event_id") or ""),
            child_event_id=str(value.get("child_event_id") or ""),
            process_pid_key=EntityKey.from_dict(value.get("process_pid_key") or {}),
            parent_pid_key=EntityKey.from_dict(value.get("parent_pid_key") or {}),
            gap_milliseconds=int(value.get("gap_milliseconds", 0)),
            rule_id=str(value.get("rule_id") or ""),
            mode=HeuristicMode(str(value.get("mode") or "")),
            validation_status=HeuristicValidationStatus(
                str(value.get("validation_status") or "")
            ),
            schema_version=str(value.get("schema_version") or ""),
        )


@dataclass(frozen=True, slots=True)
class HeuristicCoverage:
    enabled: bool
    input_event_count: int
    unique_event_count: int
    duplicate_event_count: int
    eligible_observation_count: int
    eligible_child_count: int
    emitted_edge_count: int
    unsupported_platform_count: int
    unparseable_event_count: int
    non_source_time_count: int
    ineligible_action_count: int
    missing_process_pid_count: int
    missing_parent_pid_count: int
    stable_parent_key_count: int
    ambiguous_candidate_count: int
    equal_timestamp_candidate_count: int
    outside_window_count: int
    no_candidate_count: int
    platform_counts: tuple[tuple[str, tuple[tuple[str, int], ...]], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "input_event_count": self.input_event_count,
            "unique_event_count": self.unique_event_count,
            "duplicate_event_count": self.duplicate_event_count,
            "eligible_observation_count": self.eligible_observation_count,
            "eligible_child_count": self.eligible_child_count,
            "emitted_edge_count": self.emitted_edge_count,
            "unsupported_platform_count": self.unsupported_platform_count,
            "unparseable_event_count": self.unparseable_event_count,
            "non_source_time_count": self.non_source_time_count,
            "ineligible_action_count": self.ineligible_action_count,
            "missing_process_pid_count": self.missing_process_pid_count,
            "missing_parent_pid_count": self.missing_parent_pid_count,
            "stable_parent_key_count": self.stable_parent_key_count,
            "ambiguous_candidate_count": self.ambiguous_candidate_count,
            "equal_timestamp_candidate_count": self.equal_timestamp_candidate_count,
            "outside_window_count": self.outside_window_count,
            "no_candidate_count": self.no_candidate_count,
            "platform_counts": {
                platform: dict(counts) for platform, counts in self.platform_counts
            },
        }


@dataclass(frozen=True, slots=True)
class HeuristicBuildResult:
    edges: tuple[HeuristicEdge, ...]
    coverage: HeuristicCoverage
    policy: HeuristicPolicy


@dataclass(frozen=True, slots=True)
class _Observation:
    event_id: str
    event_time_seconds: float
    process_pid_key: EntityKey


class HeuristicEdgeBuilder:
    def __init__(self, policy: HeuristicPolicy | None = None) -> None:
        self.policy = policy or HeuristicPolicy()

    def build(self, events: Iterable[NormalizedEvent]) -> HeuristicBuildResult:
        seen: dict[tuple[str, str], bytes] = {}
        event_by_ref: dict[tuple[str, str], NormalizedEvent] = {}
        input_count = 0
        duplicate_count = 0
        for event in events:
            input_count += 1
            if not isinstance(event, NormalizedEvent):
                raise TypeError("events must contain only NormalizedEvent values")
            ref = (event.tenant_id, event.event_id)
            fingerprint = _event_fingerprint(event)
            previous = seen.get(ref)
            if previous is not None:
                if previous != fingerprint:
                    raise HeuristicInputConflictError(
                        "the same tenant/event ID has conflicting normalized content"
                    )
                duplicate_count += 1
                continue
            if len(seen) >= self.policy.max_unique_events:
                raise HeuristicLimitError("heuristic event limit exceeded")
            seen[ref] = fingerprint
            event_by_ref[ref] = event

        ordered_events = sorted(
            event_by_ref.values(),
            key=lambda item: (
                item.effective_event_time,
                item.tenant_id,
                item.platform.value,
                item.event_id,
            ),
        )
        return self._build_unique(
            ordered_events,
            input_count=input_count,
            duplicate_count=duplicate_count,
        )

    def _build_unique(
        self,
        events: list[NormalizedEvent],
        *,
        input_count: int,
        duplicate_count: int,
    ) -> HeuristicBuildResult:
        counters: Counter[str] = Counter()
        platform_counts: dict[str, Counter[str]] = {}
        edges: list[HeuristicEdge] = []
        index: dict[
            tuple[str, Platform, str, str],
            deque[_Observation],
        ] = {}

        if not self.policy.enabled:
            coverage = self._coverage(
                counters,
                platform_counts,
                input_count=input_count,
                unique_count=len(events),
                duplicate_count=duplicate_count,
                edge_count=0,
            )
            return HeuristicBuildResult((), coverage, self.policy)

        observation_times: dict[
            tuple[str, Platform, str, str],
            set[float],
        ] = {}
        for event in events:
            if (
                event.platform not in _ELIGIBLE_ACTIONS
                or event.parse_status is ParseStatus.UNPARSEABLE
                or event.event_time_quality is not EventTimeQuality.SOURCE_REPORTED
                or _event_action(event) not in _ELIGIBLE_ACTIONS[event.platform]
            ):
                continue
            process_keys = _keys(event, "process_pid")
            if len(process_keys) != 1:
                continue
            process_key = process_keys[0]
            index_key = (
                event.tenant_id,
                event.platform,
                process_key.scope,
                process_key.value,
            )
            if (
                index_key not in observation_times
                and len(observation_times) >= self.policy.max_pid_index_keys
            ):
                raise HeuristicLimitError(
                    "heuristic PID timestamp index limit exceeded"
                )
            observation_times.setdefault(index_key, set()).add(
                event.effective_event_time.timestamp()
            )

        for event in events:
            platform = platform_counts.setdefault(event.platform.value, Counter())
            platform["events"] += 1
            if event.platform not in _ELIGIBLE_ACTIONS:
                counters["unsupported_platform"] += 1
                platform["unsupported_platform"] += 1
                continue
            if event.parse_status is ParseStatus.UNPARSEABLE:
                counters["unparseable"] += 1
                platform["unparseable"] += 1
                continue
            if event.event_time_quality is not EventTimeQuality.SOURCE_REPORTED:
                counters["non_source_time"] += 1
                platform["non_source_time"] += 1
                continue
            action = _event_action(event)
            if action not in _ELIGIBLE_ACTIONS[event.platform]:
                counters["ineligible_action"] += 1
                platform["ineligible_action"] += 1
                continue

            process_keys = _keys(event, "process_pid")
            parent_keys = _keys(event, "parent_process_pid")
            if len(process_keys) != 1:
                counters["missing_process_pid"] += 1
                platform["missing_process_pid"] += 1
                continue
            counters["eligible_observation"] += 1
            platform["eligible_observation"] += 1

            has_stable_parent = any(
                key.kind in _STABLE_PARENT_KEY_KINDS for key in event.entity_keys
            )
            if has_stable_parent:
                counters["stable_parent_key"] += 1
                platform["stable_parent_key"] += 1
            elif len(parent_keys) != 1:
                counters["missing_parent_pid"] += 1
                platform["missing_parent_pid"] += 1
            else:
                counters["eligible_child"] += 1
                platform["eligible_child"] += 1
                edge = self._match_parent(
                    event,
                    parent_keys[0],
                    index,
                    observation_times,
                    counters,
                    platform,
                )
                if edge is not None:
                    if len(edges) >= self.policy.max_edges:
                        raise HeuristicLimitError("heuristic edge limit exceeded")
                    edges.append(edge)

            process_key = process_keys[0]
            index_key = (
                event.tenant_id,
                event.platform,
                process_key.scope,
                process_key.value,
            )
            if index_key not in index and len(index) >= self.policy.max_pid_index_keys:
                raise HeuristicLimitError("heuristic PID index key limit exceeded")
            observations = index.setdefault(index_key, deque())
            observations.append(
                _Observation(
                    event_id=event.event_id,
                    event_time_seconds=event.effective_event_time.timestamp(),
                    process_pid_key=process_key,
                )
            )
            while len(observations) > self.policy.max_candidates_per_pid:
                observations.popleft()

        coverage = self._coverage(
            counters,
            platform_counts,
            input_count=input_count,
            unique_count=len(events),
            duplicate_count=duplicate_count,
            edge_count=len(edges),
        )
        return HeuristicBuildResult(
            tuple(sorted(edges, key=lambda edge: edge.edge_id)),
            coverage,
            self.policy,
        )

    def _match_parent(
        self,
        child: NormalizedEvent,
        parent_key: EntityKey,
        index: dict[tuple[str, Platform, str, str], deque[_Observation]],
        observation_times: dict[
            tuple[str, Platform, str, str],
            set[float],
        ],
        counters: Counter[str],
        platform: Counter[str],
    ) -> HeuristicEdge | None:
        index_key = (
            child.tenant_id,
            child.platform,
            parent_key.scope,
            parent_key.value,
        )
        observations = index.get(index_key)
        child_seconds = child.effective_event_time.timestamp()
        if not observations:
            if child_seconds in observation_times.get(index_key, set()):
                counters["equal_timestamp"] += 1
                platform["equal_timestamp"] += 1
            else:
                counters["no_candidate"] += 1
                platform["no_candidate"] += 1
            return None
        cutoff = child_seconds - self.policy.max_parent_pid_gap_seconds
        positive = [
            item
            for item in observations
            if cutoff <= item.event_time_seconds < child_seconds
        ]
        if not positive:
            if child_seconds in observation_times.get(index_key, set()):
                counters["equal_timestamp"] += 1
                platform["equal_timestamp"] += 1
            else:
                counters["outside_window"] += 1
                platform["outside_window"] += 1
            return None
        if len(positive) != 1:
            counters["ambiguous_candidate"] += 1
            platform["ambiguous_candidate"] += 1
            return None
        parent = positive[0]
        gap_milliseconds = max(
            1,
            round((child_seconds - parent.event_time_seconds) * 1000),
        )
        return HeuristicEdge.create(
            tenant_id=child.tenant_id,
            platform=child.platform,
            parent_event_id=parent.event_id,
            child_event_id=child.event_id,
            process_pid_key=parent.process_pid_key,
            parent_pid_key=parent_key,
            gap_milliseconds=gap_milliseconds,
        )

    def _coverage(
        self,
        counters: Counter[str],
        platform_counts: dict[str, Counter[str]],
        *,
        input_count: int,
        unique_count: int,
        duplicate_count: int,
        edge_count: int,
    ) -> HeuristicCoverage:
        return HeuristicCoverage(
            enabled=self.policy.enabled,
            input_event_count=input_count,
            unique_event_count=unique_count,
            duplicate_event_count=duplicate_count,
            eligible_observation_count=counters["eligible_observation"],
            eligible_child_count=counters["eligible_child"],
            emitted_edge_count=edge_count,
            unsupported_platform_count=counters["unsupported_platform"],
            unparseable_event_count=counters["unparseable"],
            non_source_time_count=counters["non_source_time"],
            ineligible_action_count=counters["ineligible_action"],
            missing_process_pid_count=counters["missing_process_pid"],
            missing_parent_pid_count=counters["missing_parent_pid"],
            stable_parent_key_count=counters["stable_parent_key"],
            ambiguous_candidate_count=counters["ambiguous_candidate"],
            equal_timestamp_candidate_count=counters["equal_timestamp"],
            outside_window_count=counters["outside_window"],
            no_candidate_count=counters["no_candidate"],
            platform_counts=tuple(
                (name, tuple(sorted(values.items())))
                for name, values in sorted(platform_counts.items())
            ),
        )
