"""Bounded, read-only replay orchestration for correlation measurement.

The runner applies the exact deterministic builders used by the domain layer,
then evaluates any explicitly enabled heuristic policy in shadow mode. It does
not persist incidents, mutate live state, or claim accuracy without an
independent ground-truth manifest.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from correlation.edges import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_UNIQUE_EVENTS,
    DeterministicEdgeBuilder,
    EdgeBuildResult,
)
from correlation.heuristics import HeuristicBuildResult, HeuristicEdgeBuilder
from correlation.heuristics import HeuristicPolicy
from correlation.incidents import IncidentBuilder, IncidentSnapshot
from correlation.ports import EventReplaySource
from correlation.shadow import (
    ShadowComparator,
    ShadowComparisonPolicy,
    ShadowComparisonResult,
)


CORRELATION_REPLAY_REPORT_SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_REPLAY_INPUT_EVENTS = 2_000_000
DEFAULT_MAX_REPORT_SAMPLES = 100
ABSOLUTE_MAX_REPORT_SAMPLES = 1_000


class ReplayError(RuntimeError):
    pass


class ReplayLimitError(ReplayError):
    pass


@dataclass(frozen=True, slots=True)
class ReplayPolicy:
    max_input_events: int = DEFAULT_MAX_REPLAY_INPUT_EVENTS
    max_unique_events: int = DEFAULT_MAX_UNIQUE_EVENTS
    max_deterministic_edges: int = DEFAULT_MAX_EDGES
    max_incidents: int = DEFAULT_MAX_UNIQUE_EVENTS
    max_report_samples: int = DEFAULT_MAX_REPORT_SAMPLES
    heuristic: HeuristicPolicy = field(default_factory=HeuristicPolicy)
    shadow: ShadowComparisonPolicy = field(
        default_factory=ShadowComparisonPolicy
    )

    def __post_init__(self) -> None:
        if min(
            self.max_input_events,
            self.max_unique_events,
            self.max_deterministic_edges,
            self.max_incidents,
            self.max_report_samples,
        ) < 1:
            raise ValueError("replay limits must be positive")
        if self.max_unique_events > self.max_input_events:
            raise ValueError(
                "max_unique_events cannot exceed max_input_events"
            )
        if self.max_report_samples > ABSOLUTE_MAX_REPORT_SAMPLES:
            raise ValueError(
                "max_report_samples exceeds the absolute safety ceiling"
            )
        if not isinstance(self.heuristic, HeuristicPolicy):
            raise TypeError("heuristic must be a HeuristicPolicy")
        if not isinstance(self.shadow, ShadowComparisonPolicy):
            raise TypeError("shadow must be a ShadowComparisonPolicy")

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_input_events": self.max_input_events,
            "max_unique_events": self.max_unique_events,
            "max_deterministic_edges": self.max_deterministic_edges,
            "max_incidents": self.max_incidents,
            "max_report_samples": self.max_report_samples,
            "heuristic": self.heuristic.to_dict(),
            "shadow": self.shadow.to_dict(),
        }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _artifact_manifest(values: Iterable[Any]) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    for value in values:
        encoded = _canonical_json(value)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    return {"count": count, "sha256": digest.hexdigest()}


def _report_payload(
    *,
    policy: ReplayPolicy,
    edge_result: EdgeBuildResult,
    snapshot: IncidentSnapshot,
    heuristic_result: HeuristicBuildResult,
    shadow_result: ShadowComparisonResult,
) -> dict[str, Any]:
    return {
        "schema_version": CORRELATION_REPLAY_REPORT_SCHEMA_VERSION,
        "policy": policy.to_dict(),
        "ground_truth_supplied": False,
        "accuracy_measured": False,
        "heuristic_validation_status": (
            "unmeasured" if policy.heuristic.enabled else "disabled"
        ),
        "deterministic_incident_membership_only": True,
        "heuristic_promotion_eligible": False,
        "deterministic_snapshot_id": snapshot.snapshot_id,
        "artifacts": {
            "deterministic_edges": _artifact_manifest(
                edge.to_dict() for edge in edge_result.edges
            ),
            "incidents": _artifact_manifest(
                {"incident_id": incident.incident_id}
                for incident in snapshot.incidents
            ),
            "unassigned_events": _artifact_manifest(
                event.to_dict() for event in snapshot.unassigned_events
            ),
            "heuristic_edges": _artifact_manifest(
                edge.to_dict() for edge in heuristic_result.edges
            ),
            "shadow_assessments": _artifact_manifest(
                assessment.to_dict()
                for assessment in shadow_result.assessments
            ),
            "shadow_components": _artifact_manifest(
                component.to_dict() for component in shadow_result.components
            ),
        },
        "review_samples": {
            "heuristic_edges": [
                edge.to_dict()
                for edge in heuristic_result.edges[: policy.max_report_samples]
            ],
            "shadow_assessments": [
                assessment.to_dict()
                for assessment in shadow_result.assessments[
                    : policy.max_report_samples
                ]
            ],
            "shadow_components": [
                component.to_dict()
                for component in shadow_result.components[
                    : policy.max_report_samples
                ]
            ],
        },
        "coverage": {
            "deterministic_edges": edge_result.coverage.to_dict(),
            "heuristics": heuristic_result.coverage.to_dict(),
            "shadow": shadow_result.coverage.to_dict(),
        },
    }


@dataclass(frozen=True, slots=True)
class CorrelationReplayReport:
    report_id: str
    canonical_payload: bytes

    def __post_init__(self) -> None:
        try:
            payload = json.loads(self.canonical_payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("canonical_payload must contain JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("replay report payload must be an object")
        if _canonical_json(payload) != self.canonical_payload:
            raise ValueError("replay report payload must use canonical JSON")
        if payload.get("schema_version") != (
            CORRELATION_REPLAY_REPORT_SCHEMA_VERSION
        ):
            raise ValueError("unsupported replay report schema version")
        if payload.get("ground_truth_supplied") is not False:
            raise ValueError("unlabeled replay cannot claim ground truth")
        if payload.get("accuracy_measured") is not False:
            raise ValueError("unlabeled replay cannot claim measured accuracy")
        if payload.get("deterministic_incident_membership_only") is not True:
            raise ValueError("replay cannot replace deterministic membership")
        if payload.get("heuristic_promotion_eligible") is not False:
            raise ValueError("unmeasured heuristics cannot be promotion eligible")
        expected = "correlation-replay:" + hashlib.sha256(
            self.canonical_payload
        ).hexdigest()
        if self.report_id != expected:
            raise ValueError("report_id does not match replay report content")

    @classmethod
    def create(
        cls,
        *,
        policy: ReplayPolicy,
        edge_result: EdgeBuildResult,
        snapshot: IncidentSnapshot,
        heuristic_result: HeuristicBuildResult,
        shadow_result: ShadowComparisonResult,
    ) -> CorrelationReplayReport:
        payload = _report_payload(
            policy=policy,
            edge_result=edge_result,
            snapshot=snapshot,
            heuristic_result=heuristic_result,
            shadow_result=shadow_result,
        )
        return cls(
            report_id="correlation-replay:"
            + hashlib.sha256(_canonical_json(payload)).hexdigest(),
            canonical_payload=_canonical_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = json.loads(self.canonical_payload)
        return {**payload, "report_id": self.report_id}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CorrelationReplayReport:
        if not isinstance(value, dict):
            raise TypeError("replay report must be an object")
        payload = dict(value)
        report_id = str(payload.pop("report_id", ""))
        return cls(
            report_id=report_id,
            canonical_payload=_canonical_json(payload),
        )


@dataclass(frozen=True, slots=True)
class CorrelationReplayResult:
    policy: ReplayPolicy
    deterministic_edges: EdgeBuildResult
    deterministic_snapshot: IncidentSnapshot
    heuristic_edges: HeuristicBuildResult
    shadow_comparison: ShadowComparisonResult
    report: CorrelationReplayReport


class CorrelationReplayRunner:
    def __init__(self, policy: ReplayPolicy | None = None) -> None:
        self.policy = policy or ReplayPolicy()

    def run(self, source: EventReplaySource) -> CorrelationReplayResult:
        events_method = getattr(source, "events", None)
        if not callable(events_method):
            raise TypeError("source must implement EventReplaySource.events()")

        events = []
        for event in events_method():
            if len(events) >= self.policy.max_input_events:
                raise ReplayLimitError("replay input event limit exceeded")
            events.append(event)
        frozen_events = tuple(events)

        edge_result = DeterministicEdgeBuilder(
            max_unique_events=self.policy.max_unique_events,
            max_edges=self.policy.max_deterministic_edges,
        ).build(frozen_events)
        snapshot = IncidentBuilder(
            max_events=self.policy.max_unique_events,
            max_edges=self.policy.max_deterministic_edges,
            max_incidents=self.policy.max_incidents,
        ).build(frozen_events, edge_result.edges)
        heuristic_result = HeuristicEdgeBuilder(
            self.policy.heuristic
        ).build(frozen_events)
        shadow_result = ShadowComparator(self.policy.shadow).compare(
            snapshot,
            heuristic_result.edges,
        )
        if shadow_result.deterministic_snapshot_id != snapshot.snapshot_id:
            raise ReplayError("shadow comparison changed deterministic snapshot")

        report = CorrelationReplayReport.create(
            policy=self.policy,
            edge_result=edge_result,
            snapshot=snapshot,
            heuristic_result=heuristic_result,
            shadow_result=shadow_result,
        )
        return CorrelationReplayResult(
            policy=self.policy,
            deterministic_edges=edge_result,
            deterministic_snapshot=snapshot,
            heuristic_edges=heuristic_result,
            shadow_comparison=shadow_result,
            report=report,
        )
