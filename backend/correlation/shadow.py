"""Read-only comparison of heuristic proposals to deterministic incidents.

This module never returns a replacement ``IncidentSnapshot``. It reports what
unmeasured heuristic edges *would* change, along with component blast-radius
bounds, while leaving deterministic production membership untouched.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from correlation.heuristics import HeuristicEdge, HeuristicValidationStatus
from correlation.incidents import IncidentSnapshot


SHADOW_COMPARISON_SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_SHADOW_EDGES = 1_000_000
DEFAULT_MAX_INCIDENTS_PER_SHADOW_COMPONENT = 10
DEFAULT_MAX_EVENTS_PER_SHADOW_COMPONENT = 1_000


class ShadowComparisonError(RuntimeError):
    pass


class ShadowInputConflictError(ShadowComparisonError):
    pass


class ShadowLimitError(ShadowComparisonError):
    pass


class ShadowEdgeEffect(str, Enum):
    REDUNDANT = "redundant"
    WOULD_MERGE_INCIDENTS = "would_merge_incidents"
    WOULD_ATTACH_UNASSIGNED = "would_attach_unassigned"
    WOULD_CREATE_COMPONENT = "would_create_component"


@dataclass(frozen=True, slots=True)
class ShadowComparisonPolicy:
    max_edges: int = DEFAULT_MAX_SHADOW_EDGES
    max_incidents_per_component: int = (
        DEFAULT_MAX_INCIDENTS_PER_SHADOW_COMPONENT
    )
    max_events_per_component: int = DEFAULT_MAX_EVENTS_PER_SHADOW_COMPONENT

    def __post_init__(self) -> None:
        if min(
            self.max_edges,
            self.max_incidents_per_component,
            self.max_events_per_component,
        ) < 1:
            raise ValueError("shadow comparison limits must be positive")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_edges": self.max_edges,
            "max_incidents_per_component": self.max_incidents_per_component,
            "max_events_per_component": self.max_events_per_component,
        }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class ShadowEdgeAssessment:
    heuristic_edge_id: str
    effect: ShadowEdgeEffect
    parent_incident_id: str | None
    child_incident_id: str | None
    parent_was_unassigned: bool
    child_was_unassigned: bool

    def __post_init__(self) -> None:
        if not str(self.heuristic_edge_id or "").strip():
            raise ValueError("heuristic_edge_id must not be empty")
        if not isinstance(self.effect, ShadowEdgeEffect):
            raise TypeError("effect must be a ShadowEdgeEffect")

    def to_dict(self) -> dict[str, Any]:
        return {
            "heuristic_edge_id": self.heuristic_edge_id,
            "effect": self.effect.value,
            "parent_incident_id": self.parent_incident_id,
            "child_incident_id": self.child_incident_id,
            "parent_was_unassigned": self.parent_was_unassigned,
            "child_was_unassigned": self.child_was_unassigned,
        }


def _component_payload(
    tenant_id: str,
    incident_ids: tuple[str, ...],
    unassigned_event_refs: tuple[tuple[str, str], ...],
    heuristic_edge_ids: tuple[str, ...],
    deterministic_event_count: int,
    total_event_count: int,
    within_cardinality_bounds: bool,
    suppression_reasons: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "schema_version": SHADOW_COMPARISON_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "incident_ids": list(incident_ids),
        "unassigned_event_refs": [list(ref) for ref in unassigned_event_refs],
        "heuristic_edge_ids": list(heuristic_edge_ids),
        "deterministic_event_count": deterministic_event_count,
        "total_event_count": total_event_count,
        "within_cardinality_bounds": within_cardinality_bounds,
        "promotion_eligible": False,
        "suppression_reasons": list(suppression_reasons),
    }


@dataclass(frozen=True, slots=True)
class ShadowComponentProposal:
    component_id: str
    tenant_id: str
    incident_ids: tuple[str, ...]
    unassigned_event_refs: tuple[tuple[str, str], ...]
    heuristic_edge_ids: tuple[str, ...]
    deterministic_event_count: int
    total_event_count: int
    within_cardinality_bounds: bool
    suppression_reasons: tuple[str, ...]
    promotion_eligible: bool = False
    schema_version: str = SHADOW_COMPARISON_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SHADOW_COMPARISON_SCHEMA_VERSION:
            raise ValueError("unsupported shadow comparison schema version")
        if not str(self.tenant_id or "").strip():
            raise ValueError("tenant_id must not be empty")
        if self.promotion_eligible:
            raise ValueError(
                "unmeasured shadow components cannot be promotion eligible"
            )
        for field_name in (
            "incident_ids",
            "unassigned_event_refs",
            "heuristic_edge_ids",
            "suppression_reasons",
        ):
            values = getattr(self, field_name)
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} must be unique and sorted")
        if self.total_event_count < self.deterministic_event_count:
            raise ValueError(
                "total event count cannot be smaller than deterministic count"
            )
        if self.within_cardinality_bounds != (
            not any(
                reason.startswith("cardinality:")
                for reason in self.suppression_reasons
            )
        ):
            raise ValueError("cardinality status does not match suppression reasons")
        payload = _component_payload(
            self.tenant_id,
            self.incident_ids,
            self.unassigned_event_refs,
            self.heuristic_edge_ids,
            self.deterministic_event_count,
            self.total_event_count,
            self.within_cardinality_bounds,
            self.suppression_reasons,
        )
        expected_id = "shadow-component:" + hashlib.sha256(
            _canonical_json(payload)
        ).hexdigest()
        if self.component_id != expected_id:
            raise ValueError("component_id does not match shadow proposal content")

    @classmethod
    def create(
        cls,
        *,
        tenant_id: str,
        incident_ids: Iterable[str],
        unassigned_event_refs: Iterable[tuple[str, str]],
        heuristic_edge_ids: Iterable[str],
        deterministic_event_count: int,
        total_event_count: int,
        policy: ShadowComparisonPolicy,
    ) -> ShadowComponentProposal:
        ordered_incidents = tuple(sorted(set(incident_ids)))
        ordered_unassigned = tuple(sorted(set(unassigned_event_refs)))
        ordered_edges = tuple(sorted(set(heuristic_edge_ids)))
        reasons = ["unmeasured_rule"]
        if len(ordered_incidents) > policy.max_incidents_per_component:
            reasons.append("cardinality:incident_limit_exceeded")
        if total_event_count > policy.max_events_per_component:
            reasons.append("cardinality:event_limit_exceeded")
        ordered_reasons = tuple(sorted(reasons))
        within_bounds = not any(
            reason.startswith("cardinality:") for reason in ordered_reasons
        )
        payload = _component_payload(
            tenant_id,
            ordered_incidents,
            ordered_unassigned,
            ordered_edges,
            deterministic_event_count,
            total_event_count,
            within_bounds,
            ordered_reasons,
        )
        return cls(
            component_id="shadow-component:"
            + hashlib.sha256(_canonical_json(payload)).hexdigest(),
            tenant_id=tenant_id,
            incident_ids=ordered_incidents,
            unassigned_event_refs=ordered_unassigned,
            heuristic_edge_ids=ordered_edges,
            deterministic_event_count=deterministic_event_count,
            total_event_count=total_event_count,
            within_cardinality_bounds=within_bounds,
            suppression_reasons=ordered_reasons,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_component_payload(
                self.tenant_id,
                self.incident_ids,
                self.unassigned_event_refs,
                self.heuristic_edge_ids,
                self.deterministic_event_count,
                self.total_event_count,
                self.within_cardinality_bounds,
                self.suppression_reasons,
            ),
            "component_id": self.component_id,
        }


@dataclass(frozen=True, slots=True)
class ShadowComparisonCoverage:
    heuristic_edge_count: int
    redundant_edge_count: int
    would_merge_edge_count: int
    would_attach_edge_count: int
    would_create_edge_count: int
    component_count: int
    bounded_component_count: int
    suppressed_component_count: int
    maximum_incidents_in_component: int
    maximum_events_in_component: int

    def to_dict(self) -> dict[str, int]:
        return {
            "heuristic_edge_count": self.heuristic_edge_count,
            "redundant_edge_count": self.redundant_edge_count,
            "would_merge_edge_count": self.would_merge_edge_count,
            "would_attach_edge_count": self.would_attach_edge_count,
            "would_create_edge_count": self.would_create_edge_count,
            "component_count": self.component_count,
            "bounded_component_count": self.bounded_component_count,
            "suppressed_component_count": self.suppressed_component_count,
            "maximum_incidents_in_component": self.maximum_incidents_in_component,
            "maximum_events_in_component": self.maximum_events_in_component,
        }


@dataclass(frozen=True, slots=True)
class ShadowComparisonResult:
    deterministic_snapshot_id: str
    assessments: tuple[ShadowEdgeAssessment, ...]
    components: tuple[ShadowComponentProposal, ...]
    coverage: ShadowComparisonCoverage
    policy: ShadowComparisonPolicy


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[tuple[str, str], tuple[str, str]] = {}

    def add(self, item: tuple[str, str]) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: tuple[str, str]) -> tuple[str, str]:
        parent = self.parent[item]
        while parent != self.parent[parent]:
            parent = self.parent[parent]
        while item != parent:
            next_item = self.parent[item]
            self.parent[item] = parent
            item = next_item
        return parent

    def union(self, left: tuple[str, str], right: tuple[str, str]) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            low, high = sorted((left_root, right_root))
            self.parent[high] = low


def _effect(
    parent_incident_id: str | None,
    child_incident_id: str | None,
) -> ShadowEdgeEffect:
    if parent_incident_id is not None and parent_incident_id == child_incident_id:
        return ShadowEdgeEffect.REDUNDANT
    if parent_incident_id is not None and child_incident_id is not None:
        return ShadowEdgeEffect.WOULD_MERGE_INCIDENTS
    if parent_incident_id is not None or child_incident_id is not None:
        return ShadowEdgeEffect.WOULD_ATTACH_UNASSIGNED
    return ShadowEdgeEffect.WOULD_CREATE_COMPONENT


class ShadowComparator:
    def __init__(self, policy: ShadowComparisonPolicy | None = None) -> None:
        self.policy = policy or ShadowComparisonPolicy()

    def compare(
        self,
        snapshot: IncidentSnapshot,
        heuristic_edges: Iterable[HeuristicEdge],
    ) -> ShadowComparisonResult:
        if not isinstance(snapshot, IncidentSnapshot):
            raise TypeError("snapshot must be an IncidentSnapshot")

        incident_by_event: dict[tuple[str, str], str] = {}
        event_platform: dict[tuple[str, str], str] = {}
        incident_event_counts: dict[str, int] = {}
        for incident in snapshot.incidents:
            incident_event_counts[incident.incident_id] = len(incident.events)
            for event in incident.events:
                incident_by_event[event.ref] = incident.incident_id
                event_platform[event.ref] = event.platform.value
        for event in snapshot.unassigned_events:
            event_platform[event.ref] = event.platform.value

        edges_by_id: dict[str, HeuristicEdge] = {}
        for edge in heuristic_edges:
            if not isinstance(edge, HeuristicEdge):
                raise TypeError("heuristic_edges must contain HeuristicEdge values")
            if edge.validation_status is not HeuristicValidationStatus.UNMEASURED:
                raise ShadowInputConflictError(
                    "shadow comparator received an unsupported validation status"
                )
            existing = edges_by_id.get(edge.edge_id)
            if existing is not None:
                if existing != edge:
                    raise ShadowInputConflictError(
                        "heuristic edge ID has conflicting content"
                    )
                continue
            if len(edges_by_id) >= self.policy.max_edges:
                raise ShadowLimitError("shadow heuristic edge limit exceeded")
            for event_id in (edge.parent_event_id, edge.child_event_id):
                ref = (edge.tenant_id, event_id)
                platform = event_platform.get(ref)
                if platform is None:
                    raise ShadowInputConflictError(
                        "heuristic edge references an event absent from the snapshot"
                    )
                if platform != edge.platform.value:
                    raise ShadowInputConflictError(
                        "heuristic edge platform does not match snapshot event"
                    )
            edges_by_id[edge.edge_id] = edge

        assessments: list[ShadowEdgeAssessment] = []
        union_find = _UnionFind()
        edge_nodes: dict[str, tuple[tuple[str, str], tuple[str, str]]] = {}

        def node_for(ref: tuple[str, str]) -> tuple[str, str]:
            incident_id = incident_by_event.get(ref)
            if incident_id is not None:
                return "incident", incident_id
            return "event", f"{ref[0]}\x00{ref[1]}"

        for edge in sorted(edges_by_id.values(), key=lambda item: item.edge_id):
            parent_ref = (edge.tenant_id, edge.parent_event_id)
            child_ref = (edge.tenant_id, edge.child_event_id)
            parent_incident = incident_by_event.get(parent_ref)
            child_incident = incident_by_event.get(child_ref)
            effect = _effect(parent_incident, child_incident)
            assessments.append(
                ShadowEdgeAssessment(
                    heuristic_edge_id=edge.edge_id,
                    effect=effect,
                    parent_incident_id=parent_incident,
                    child_incident_id=child_incident,
                    parent_was_unassigned=parent_incident is None,
                    child_was_unassigned=child_incident is None,
                )
            )
            left = node_for(parent_ref)
            right = node_for(child_ref)
            union_find.add(left)
            union_find.add(right)
            union_find.union(left, right)
            edge_nodes[edge.edge_id] = (left, right)

        nodes_by_root: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for node in union_find.parent:
            nodes_by_root.setdefault(union_find.find(node), set()).add(node)
        edges_by_root: dict[tuple[str, str], set[str]] = {}
        for edge_id, (left, _) in edge_nodes.items():
            edges_by_root.setdefault(union_find.find(left), set()).add(edge_id)

        components: list[ShadowComponentProposal] = []
        for root, nodes in nodes_by_root.items():
            incident_ids = {
                value for node_type, value in nodes if node_type == "incident"
            }
            unassigned_refs = {
                tuple(value.split("\x00", 1))
                for node_type, value in nodes
                if node_type == "event"
            }
            edge_ids = edges_by_root.get(root, set())
            tenants = {ref[0] for ref in unassigned_refs}
            tenants.update(edges_by_id[edge_id].tenant_id for edge_id in edge_ids)
            if len(tenants) != 1:
                raise ShadowInputConflictError(
                    "shadow component crossed tenant boundaries"
                )
            deterministic_event_count = sum(
                incident_event_counts[incident_id] for incident_id in incident_ids
            )
            total_event_count = deterministic_event_count + len(unassigned_refs)
            components.append(
                ShadowComponentProposal.create(
                    tenant_id=next(iter(tenants)),
                    incident_ids=incident_ids,
                    unassigned_event_refs=unassigned_refs,
                    heuristic_edge_ids=edge_ids,
                    deterministic_event_count=deterministic_event_count,
                    total_event_count=total_event_count,
                    policy=self.policy,
                )
            )

        ordered_assessments = tuple(
            sorted(assessments, key=lambda item: item.heuristic_edge_id)
        )
        ordered_components = tuple(
            sorted(components, key=lambda item: item.component_id)
        )
        effect_counts = {
            effect: sum(item.effect is effect for item in ordered_assessments)
            for effect in ShadowEdgeEffect
        }
        coverage = ShadowComparisonCoverage(
            heuristic_edge_count=len(ordered_assessments),
            redundant_edge_count=effect_counts[ShadowEdgeEffect.REDUNDANT],
            would_merge_edge_count=effect_counts[
                ShadowEdgeEffect.WOULD_MERGE_INCIDENTS
            ],
            would_attach_edge_count=effect_counts[
                ShadowEdgeEffect.WOULD_ATTACH_UNASSIGNED
            ],
            would_create_edge_count=effect_counts[
                ShadowEdgeEffect.WOULD_CREATE_COMPONENT
            ],
            component_count=len(ordered_components),
            bounded_component_count=sum(
                item.within_cardinality_bounds for item in ordered_components
            ),
            suppressed_component_count=sum(
                not item.within_cardinality_bounds for item in ordered_components
            ),
            maximum_incidents_in_component=max(
                (len(item.incident_ids) for item in ordered_components),
                default=0,
            ),
            maximum_events_in_component=max(
                (item.total_event_count for item in ordered_components),
                default=0,
            ),
        )
        return ShadowComparisonResult(
            deterministic_snapshot_id=snapshot.snapshot_id,
            assessments=ordered_assessments,
            components=ordered_components,
            coverage=coverage,
            policy=self.policy,
        )
