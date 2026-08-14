"""Independent component ground truth and exact correlation scoring.

This module does not infer labels from detector output. A manifest assigns
every replay event to an expected component and records how those assignments
were produced. Only capture-orchestrator labels with deterministic event joins,
mixed benign activity, and exhaustive assignment qualify as promotion evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from math import comb
from typing import Any, Iterable, Mapping

from correlation.incidents import IncidentSnapshot
from correlation.shadow import ShadowComparisonResult


GROUND_TRUTH_SCHEMA_VERSION = "1.0.0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


class GroundTruthError(RuntimeError):
    pass


class GroundTruthCoverageError(GroundTruthError):
    pass


class LabelMethod(str, Enum):
    CAPTURE_ORCHESTRATOR = "capture_orchestrator"
    POSTHOC_ANALYST = "posthoc_analyst"
    DETECTOR_DERIVED = "detector_derived"


class EventJoinMethod(str, Enum):
    NATIVE_EVENT_ID = "native_event_id"
    INJECTED_CAPTURE_MARKER = "injected_capture_marker"
    TIME_WINDOW = "time_window"


class ComponentKind(str, Enum):
    ATTACK = "attack"
    BENIGN = "benign"
    MIXED = "mixed"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class TruthComponent:
    component_key: str
    tenant_id: str
    event_refs: tuple[tuple[str, str], ...]
    kind: ComponentKind
    run_id: str
    step_ids: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("component_key", "tenant_id", "run_id"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"{name} must not be empty")
        if not isinstance(self.kind, ComponentKind):
            raise TypeError("kind must be a ComponentKind")
        if not self.event_refs:
            raise ValueError("truth component must contain at least one event")
        if tuple(sorted(set(self.event_refs))) != self.event_refs:
            raise ValueError("event_refs must be unique and sorted")
        if any(ref[0] != self.tenant_id for ref in self.event_refs):
            raise ValueError("truth component cannot cross tenant boundaries")
        for name in ("step_ids", "technique_ids"):
            values = getattr(self, name)
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{name} must be unique and sorted")
        if any(_TECHNIQUE_ID.fullmatch(value) is None for value in self.technique_ids):
            raise ValueError("technique_ids must contain MITRE ATT&CK IDs")

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_key": self.component_key,
            "tenant_id": self.tenant_id,
            "event_refs": [list(ref) for ref in self.event_refs],
            "kind": self.kind.value,
            "run_id": self.run_id,
            "step_ids": list(self.step_ids),
            "technique_ids": list(self.technique_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> TruthComponent:
        refs = value.get("event_refs")
        if not isinstance(refs, list) or any(
            not isinstance(ref, list) or len(ref) != 2 for ref in refs
        ):
            raise ValueError("event_refs must be two-item lists")
        step_ids = value.get("step_ids", [])
        technique_ids = value.get("technique_ids", [])
        if not isinstance(step_ids, list) or not isinstance(technique_ids, list):
            raise ValueError("step_ids and technique_ids must be lists")
        return cls(
            component_key=str(value.get("component_key") or ""),
            tenant_id=str(value.get("tenant_id") or ""),
            event_refs=tuple((str(ref[0]), str(ref[1])) for ref in refs),
            kind=ComponentKind(str(value.get("kind") or "")),
            run_id=str(value.get("run_id") or ""),
            step_ids=tuple(str(item) for item in step_ids),
            technique_ids=tuple(str(item) for item in technique_ids),
        )


def _manifest_payload(
    *,
    source_name: str,
    source_uri: str,
    source_sha256: str,
    license_name: str,
    label_method: LabelMethod,
    event_join_method: EventJoinMethod,
    benign_background_included: bool,
    exhaustive_event_assignment: bool,
    components: tuple[TruthComponent, ...],
) -> dict[str, Any]:
    return {
        "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
        "source_name": source_name,
        "source_uri": source_uri,
        "source_sha256": source_sha256,
        "license": license_name,
        "label_method": label_method.value,
        "event_join_method": event_join_method.value,
        "benign_background_included": benign_background_included,
        "exhaustive_event_assignment": exhaustive_event_assignment,
        "components": [component.to_dict() for component in components],
    }


@dataclass(frozen=True, slots=True)
class GroundTruthManifest:
    manifest_id: str
    source_name: str
    source_uri: str
    source_sha256: str
    license_name: str
    label_method: LabelMethod
    event_join_method: EventJoinMethod
    benign_background_included: bool
    exhaustive_event_assignment: bool
    components: tuple[TruthComponent, ...]
    schema_version: str = GROUND_TRUTH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != GROUND_TRUTH_SCHEMA_VERSION:
            raise ValueError("unsupported ground-truth schema version")
        for name in ("source_name", "source_uri", "license_name"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"{name} must not be empty")
        if _SHA256.fullmatch(self.source_sha256) is None:
            raise ValueError("source_sha256 must be a lowercase SHA-256 digest")
        if not isinstance(self.label_method, LabelMethod):
            raise TypeError("label_method must be a LabelMethod")
        if not isinstance(self.event_join_method, EventJoinMethod):
            raise TypeError("event_join_method must be an EventJoinMethod")
        if not isinstance(self.benign_background_included, bool) or not isinstance(
            self.exhaustive_event_assignment, bool
        ):
            raise TypeError("ground-truth qualification fields must be booleans")
        if not self.components:
            raise ValueError("ground-truth manifest must contain components")
        if tuple(
            sorted(self.components, key=lambda item: item.component_key)
        ) != self.components:
            raise ValueError("components must be sorted by component_key")
        keys = [component.component_key for component in self.components]
        if len(keys) != len(set(keys)):
            raise ValueError("component keys must be unique")
        refs = [
            ref for component in self.components for ref in component.event_refs
        ]
        if len(refs) != len(set(refs)):
            raise ValueError("an event cannot belong to multiple truth components")
        payload = _manifest_payload(
            source_name=self.source_name,
            source_uri=self.source_uri,
            source_sha256=self.source_sha256,
            license_name=self.license_name,
            label_method=self.label_method,
            event_join_method=self.event_join_method,
            benign_background_included=self.benign_background_included,
            exhaustive_event_assignment=self.exhaustive_event_assignment,
            components=self.components,
        )
        expected = "correlation-truth:" + hashlib.sha256(
            _canonical_json(payload)
        ).hexdigest()
        if self.manifest_id != expected:
            raise ValueError("manifest_id does not match ground-truth content")

    @property
    def promotion_evidence_qualified(self) -> bool:
        return (
            self.label_method is LabelMethod.CAPTURE_ORCHESTRATOR
            and self.event_join_method
            in {
                EventJoinMethod.NATIVE_EVENT_ID,
                EventJoinMethod.INJECTED_CAPTURE_MARKER,
            }
            and self.benign_background_included
            and self.exhaustive_event_assignment
        )

    @classmethod
    def create(
        cls,
        *,
        source_name: str,
        source_uri: str,
        source_sha256: str,
        license_name: str,
        label_method: LabelMethod,
        event_join_method: EventJoinMethod,
        benign_background_included: bool,
        exhaustive_event_assignment: bool,
        components: Iterable[TruthComponent],
    ) -> GroundTruthManifest:
        ordered = tuple(sorted(components, key=lambda item: item.component_key))
        payload = _manifest_payload(
            source_name=source_name,
            source_uri=source_uri,
            source_sha256=source_sha256,
            license_name=license_name,
            label_method=label_method,
            event_join_method=event_join_method,
            benign_background_included=benign_background_included,
            exhaustive_event_assignment=exhaustive_event_assignment,
            components=ordered,
        )
        return cls(
            manifest_id="correlation-truth:"
            + hashlib.sha256(_canonical_json(payload)).hexdigest(),
            source_name=source_name,
            source_uri=source_uri,
            source_sha256=source_sha256,
            license_name=license_name,
            label_method=label_method,
            event_join_method=event_join_method,
            benign_background_included=benign_background_included,
            exhaustive_event_assignment=exhaustive_event_assignment,
            components=ordered,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_manifest_payload(
                source_name=self.source_name,
                source_uri=self.source_uri,
                source_sha256=self.source_sha256,
                license_name=self.license_name,
                label_method=self.label_method,
                event_join_method=self.event_join_method,
                benign_background_included=self.benign_background_included,
                exhaustive_event_assignment=self.exhaustive_event_assignment,
                components=self.components,
            ),
            "manifest_id": self.manifest_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> GroundTruthManifest:
        components = value.get("components")
        if not isinstance(components, list):
            raise ValueError("components must be a list")
        return cls(
            manifest_id=str(value.get("manifest_id") or ""),
            source_name=str(value.get("source_name") or ""),
            source_uri=str(value.get("source_uri") or ""),
            source_sha256=str(value.get("source_sha256") or ""),
            license_name=str(value.get("license") or ""),
            label_method=LabelMethod(str(value.get("label_method") or "")),
            event_join_method=EventJoinMethod(
                str(value.get("event_join_method") or "")
            ),
            benign_background_included=(
                value.get("benign_background_included") is True
            ),
            exhaustive_event_assignment=(
                value.get("exhaustive_event_assignment") is True
            ),
            components=tuple(
                TruthComponent.from_dict(item) for item in components
            ),
            schema_version=str(value.get("schema_version") or ""),
        )


@dataclass(frozen=True, slots=True)
class PairwiseComponentMetrics:
    event_count: int
    expected_component_count: int
    predicted_component_count: int
    true_positive_pairs: int
    false_positive_pairs: int
    false_negative_pairs: int
    true_negative_pairs: int
    precision: float
    recall: float
    f1: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "expected_component_count": self.expected_component_count,
            "predicted_component_count": self.predicted_component_count,
            "true_positive_pairs": self.true_positive_pairs,
            "false_positive_pairs": self.false_positive_pairs,
            "false_negative_pairs": self.false_negative_pairs,
            "true_negative_pairs": self.true_negative_pairs,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


@dataclass(frozen=True, slots=True)
class GroundTruthEvaluation:
    manifest_id: str
    deterministic_snapshot_id: str
    promotion_evidence_qualified: bool
    baseline: PairwiseComponentMetrics
    shadow: PairwiseComponentMetrics

    @property
    def precision_delta(self) -> float:
        return self.shadow.precision - self.baseline.precision

    @property
    def recall_delta(self) -> float:
        return self.shadow.recall - self.baseline.recall

    @property
    def f1_delta(self) -> float:
        return self.shadow.f1 - self.baseline.f1

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "deterministic_snapshot_id": self.deterministic_snapshot_id,
            "accuracy_measured": True,
            "promotion_evidence_qualified": self.promotion_evidence_qualified,
            "baseline": self.baseline.to_dict(),
            "shadow": self.shadow.to_dict(),
            "delta": {
                "precision": self.precision_delta,
                "recall": self.recall_delta,
                "f1": self.f1_delta,
            },
        }


class _UnionFind:
    def __init__(self, values: Iterable[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        while parent != self.parent[parent]:
            parent = self.parent[parent]
        while value != parent:
            next_value = self.parent[value]
            self.parent[value] = parent
            value = next_value
        return parent

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            low, high = sorted((left_root, right_root))
            self.parent[high] = low


def _snapshot_assignments(
    snapshot: IncidentSnapshot,
) -> dict[tuple[str, str], str]:
    assignments = {
        event.ref: incident.incident_id
        for incident in snapshot.incidents
        for event in incident.events
    }
    assignments.update(
        {
            event.ref: f"unassigned:{event.tenant_id}:{event.event_id}"
            for event in snapshot.unassigned_events
        }
    )
    return assignments


def _shadow_assignments(
    snapshot: IncidentSnapshot,
    shadow: ShadowComparisonResult,
) -> dict[tuple[str, str], str]:
    if shadow.deterministic_snapshot_id != snapshot.snapshot_id:
        raise GroundTruthCoverageError(
            "shadow comparison belongs to a different deterministic snapshot"
        )
    baseline = _snapshot_assignments(snapshot)
    union_find = _UnionFind(set(baseline.values()))
    for component in shadow.components:
        member_labels = list(component.incident_ids)
        member_labels.extend(
            f"unassigned:{tenant_id}:{event_id}"
            for tenant_id, event_id in component.unassigned_event_refs
        )
        if any(label not in union_find.parent for label in member_labels):
            raise GroundTruthCoverageError(
                "shadow component references unknown deterministic membership"
            )
        for label in member_labels[1:]:
            union_find.union(member_labels[0], label)
    return {
        ref: union_find.find(label) for ref, label in baseline.items()
    }


def _score(
    truth: Mapping[tuple[str, str], str],
    predicted: Mapping[tuple[str, str], str],
) -> PairwiseComponentMetrics:
    if set(truth) != set(predicted):
        raise GroundTruthCoverageError(
            "truth and predicted event sets must match exactly"
        )
    truth_sizes = Counter(truth.values())
    predicted_sizes = Counter(predicted.values())
    intersections = Counter(
        (truth[ref], predicted[ref]) for ref in truth
    )
    true_positive = sum(comb(size, 2) for size in intersections.values())
    predicted_positive = sum(comb(size, 2) for size in predicted_sizes.values())
    expected_positive = sum(comb(size, 2) for size in truth_sizes.values())
    false_positive = predicted_positive - true_positive
    false_negative = expected_positive - true_positive
    total_pairs = comb(len(truth), 2)
    true_negative = total_pairs - true_positive - false_positive - false_negative
    precision = (
        true_positive / predicted_positive
        if predicted_positive
        else (1.0 if expected_positive == 0 else 0.0)
    )
    recall = (
        true_positive / expected_positive
        if expected_positive
        else 1.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return PairwiseComponentMetrics(
        event_count=len(truth),
        expected_component_count=len(truth_sizes),
        predicted_component_count=len(predicted_sizes),
        true_positive_pairs=true_positive,
        false_positive_pairs=false_positive,
        false_negative_pairs=false_negative,
        true_negative_pairs=true_negative,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def evaluate_components(
    manifest: GroundTruthManifest,
    snapshot: IncidentSnapshot,
    shadow: ShadowComparisonResult,
) -> GroundTruthEvaluation:
    if not isinstance(manifest, GroundTruthManifest):
        raise TypeError("manifest must be a GroundTruthManifest")
    if not manifest.exhaustive_event_assignment:
        raise GroundTruthCoverageError(
            "pairwise scoring requires exhaustive event assignment"
        )
    truth = {
        ref: component.component_key
        for component in manifest.components
        for ref in component.event_refs
    }
    baseline = _snapshot_assignments(snapshot)
    if set(truth) != set(baseline):
        missing = sorted(set(baseline) - set(truth))
        extra = sorted(set(truth) - set(baseline))
        raise GroundTruthCoverageError(
            f"manifest/snapshot event mismatch: missing={missing!r}, extra={extra!r}"
        )
    return GroundTruthEvaluation(
        manifest_id=manifest.manifest_id,
        deterministic_snapshot_id=snapshot.snapshot_id,
        promotion_evidence_qualified=manifest.promotion_evidence_qualified,
        baseline=_score(truth, baseline),
        shadow=_score(truth, _shadow_assignments(snapshot, shadow)),
    )
