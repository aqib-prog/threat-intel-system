"""Versioned, reversible incidents built from deterministic edges only.

An incident in this module is a correlation component, not a declaration that
an attack occurred. Only ``EdgeUsage.CORRELATION`` edges can connect events.
Context edges are attached after components are formed and never merge them.

Snapshots and incidents are immutable and content-addressed. ``IncidentHistory``
is an in-memory reference implementation: appending an earlier snapshot creates
a new rollback revision instead of deleting or rewriting later history.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping

from correlation.edges import (
    DETERMINISTIC_EDGE_SCHEMA_VERSION,
    DeterministicEdge,
    EdgeUsage,
)
from correlation.models import EntityKey, NormalizedEvent, ParseStatus, Platform


INCIDENT_SCHEMA_VERSION = "1.0.0"
INCIDENT_SNAPSHOT_SCHEMA_VERSION = "1.0.0"
INCIDENT_REVISION_SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_INCIDENT_EVENTS = 1_000_000
DEFAULT_MAX_INCIDENT_EDGES = 10_000_000
DEFAULT_MAX_INCIDENTS = 1_000_000


class IncidentBuildError(RuntimeError):
    pass


class IncidentInputConflictError(IncidentBuildError):
    pass


class IncidentLimitError(IncidentBuildError):
    pass


class IncidentRevisionError(RuntimeError):
    pass


class IncidentChangeKind(str, Enum):
    CREATED = "created"
    REMOVED = "removed"
    EXPANDED = "expanded"
    CONTRACTED = "contracted"
    UPDATED = "updated"
    MERGED = "merged"
    SPLIT = "split"
    RECOMPOSED = "recomposed"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _content_id(prefix: str, value: Any) -> str:
    return f"{prefix}:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _event_digest(event: NormalizedEvent) -> str:
    # Storage URIs, collection timestamps, and ingestion timestamps can differ
    # when the same immutable evidence is replayed in another environment. The
    # digest covers the normalized assertion and raw content hash instead.
    payload = {
        "schema_version": event.schema_version,
        "event_id": event.event_id,
        "tenant_id": event.tenant_id,
        "platform": event.platform.value,
        "source_type": event.source_type,
        "source_instance_id": event.source_instance_id,
        "adapter_version": event.adapter_version,
        "observed_at": event.observed_at.isoformat() if event.observed_at else None,
        "event_time_quality": event.event_time_quality.value,
        "parse_status": event.parse_status.value,
        "raw_evidence_sha256": event.raw_evidence.sha256,
        "native_event_id": event.native_event_id,
        "native_sequence": event.native_sequence,
        "entity_keys": [key.to_dict() for key in event.entity_keys],
        "attributes": event.to_dict()["attributes"],
        "parse_warnings": list(event.parse_warnings),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True, slots=True, order=True)
class IncidentEvent:
    tenant_id: str
    event_id: str
    event_digest: str
    platform: Platform
    effective_event_time: datetime

    def __post_init__(self) -> None:
        for field_name in ("tenant_id", "event_id"):
            rendered = str(getattr(self, field_name) or "").strip()
            if not rendered:
                raise ValueError(f"{field_name} must not be empty")
            object.__setattr__(self, field_name, rendered)
        digest = str(self.event_digest or "").strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("event_digest must be a lowercase SHA-256 digest")
        object.__setattr__(self, "event_digest", digest)
        if not isinstance(self.platform, Platform):
            raise TypeError("platform must be a Platform")
        if (
            self.effective_event_time.tzinfo is None
            or self.effective_event_time.utcoffset() is None
        ):
            raise ValueError("effective_event_time must be timezone-aware")
        object.__setattr__(
            self,
            "effective_event_time",
            self.effective_event_time.astimezone(timezone.utc),
        )

    @property
    def ref(self) -> tuple[str, str]:
        return self.tenant_id, self.event_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "event_id": self.event_id,
            "event_digest": self.event_digest,
            "platform": self.platform.value,
            "effective_event_time": self.effective_event_time.isoformat(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> IncidentEvent:
        try:
            event_time = datetime.fromisoformat(str(value.get("effective_event_time")))
        except (TypeError, ValueError) as exc:
            raise ValueError("effective_event_time must be ISO-8601") from exc
        return cls(
            tenant_id=str(value.get("tenant_id") or ""),
            event_id=str(value.get("event_id") or ""),
            event_digest=str(value.get("event_digest") or ""),
            platform=Platform(str(value.get("platform") or "")),
            effective_event_time=event_time,
        )


def _incident_event_sort_key(event: IncidentEvent) -> tuple[Any, ...]:
    return (
        event.effective_event_time,
        event.event_id,
        event.event_digest,
        event.platform.value,
    )


def _unassigned_event_sort_key(event: IncidentEvent) -> tuple[Any, ...]:
    return (event.tenant_id, *_incident_event_sort_key(event))


def _incident_payload(
    tenant_id: str,
    events: tuple[IncidentEvent, ...],
    correlation_edge_ids: tuple[str, ...],
    context_edge_ids: tuple[str, ...],
    correlation_entity_keys: tuple[EntityKey, ...],
    context_entity_keys: tuple[EntityKey, ...],
) -> dict[str, Any]:
    return {
        "schema_version": INCIDENT_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "events": [event.to_dict() for event in events],
        "correlation_edge_ids": list(correlation_edge_ids),
        "context_edge_ids": list(context_edge_ids),
        "correlation_entity_keys": [
            key.to_dict() for key in correlation_entity_keys
        ],
        "context_entity_keys": [key.to_dict() for key in context_entity_keys],
    }


@dataclass(frozen=True, slots=True)
class CorrelationIncident:
    incident_id: str
    tenant_id: str
    events: tuple[IncidentEvent, ...]
    correlation_edge_ids: tuple[str, ...]
    context_edge_ids: tuple[str, ...]
    correlation_entity_keys: tuple[EntityKey, ...]
    context_entity_keys: tuple[EntityKey, ...]
    schema_version: str = INCIDENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != INCIDENT_SCHEMA_VERSION:
            raise ValueError("unsupported incident schema version")
        tenant_id = str(self.tenant_id or "").strip()
        if not tenant_id:
            raise ValueError("tenant_id must not be empty")
        object.__setattr__(self, "tenant_id", tenant_id)
        if not self.events:
            raise ValueError("an incident must contain at least one event")
        if not self.correlation_edge_ids or not self.correlation_entity_keys:
            raise ValueError("an incident must contain correlation provenance")
        if tuple(sorted(set(self.events), key=_incident_event_sort_key)) != self.events:
            raise ValueError("incident events must be unique and sorted")
        if len({event.ref for event in self.events}) != len(self.events):
            raise ValueError("incident event references must be unique")
        if any(event.tenant_id != self.tenant_id for event in self.events):
            raise ValueError("incident events must belong to the incident tenant")
        if tuple(sorted(set(self.correlation_edge_ids))) != self.correlation_edge_ids:
            raise ValueError("correlation edge IDs must be unique and sorted")
        if tuple(sorted(set(self.context_edge_ids))) != self.context_edge_ids:
            raise ValueError("context edge IDs must be unique and sorted")
        if (
            tuple(sorted(set(self.correlation_entity_keys)))
            != self.correlation_entity_keys
        ):
            raise ValueError("correlation entity keys must be unique and sorted")
        if tuple(sorted(set(self.context_entity_keys))) != self.context_entity_keys:
            raise ValueError("context entity keys must be unique and sorted")
        expected_id = _content_id(
            "incident",
            _incident_payload(
                self.tenant_id,
                self.events,
                self.correlation_edge_ids,
                self.context_edge_ids,
                self.correlation_entity_keys,
                self.context_entity_keys,
            ),
        )
        if self.incident_id != expected_id:
            raise ValueError("incident_id does not match incident content")

    @classmethod
    def create(
        cls,
        *,
        tenant_id: str,
        events: Iterable[IncidentEvent],
        correlation_edge_ids: Iterable[str],
        context_edge_ids: Iterable[str],
        correlation_entity_keys: Iterable[EntityKey],
        context_entity_keys: Iterable[EntityKey],
    ) -> CorrelationIncident:
        ordered_events = tuple(sorted(set(events), key=_incident_event_sort_key))
        ordered_correlation_edges = tuple(sorted(set(correlation_edge_ids)))
        ordered_context_edges = tuple(sorted(set(context_edge_ids)))
        ordered_correlation = tuple(sorted(set(correlation_entity_keys)))
        ordered_context = tuple(sorted(set(context_entity_keys)))
        payload = _incident_payload(
            tenant_id,
            ordered_events,
            ordered_correlation_edges,
            ordered_context_edges,
            ordered_correlation,
            ordered_context,
        )
        return cls(
            incident_id=_content_id("incident", payload),
            tenant_id=tenant_id,
            events=ordered_events,
            correlation_edge_ids=ordered_correlation_edges,
            context_edge_ids=ordered_context_edges,
            correlation_entity_keys=ordered_correlation,
            context_entity_keys=ordered_context,
        )

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(event.event_id for event in self.events)

    @property
    def platforms(self) -> tuple[Platform, ...]:
        return tuple(
            sorted(
                {event.platform for event in self.events},
                key=lambda item: item.value,
            )
        )

    @property
    def first_event_time(self) -> datetime:
        return min(event.effective_event_time for event in self.events)

    @property
    def last_event_time(self) -> datetime:
        return max(event.effective_event_time for event in self.events)

    def to_dict(self) -> dict[str, Any]:
        payload = _incident_payload(
            self.tenant_id,
            self.events,
            self.correlation_edge_ids,
            self.context_edge_ids,
            self.correlation_entity_keys,
            self.context_entity_keys,
        )
        return {
            **payload,
            "incident_id": self.incident_id,
            "platforms": [platform.value for platform in self.platforms],
            "first_event_time": self.first_event_time.isoformat(),
            "last_event_time": self.last_event_time.isoformat(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CorrelationIncident:
        events = value.get("events")
        correlation_edges = value.get("correlation_edge_ids")
        context_edges = value.get("context_edge_ids")
        correlation_keys = value.get("correlation_entity_keys")
        context_keys = value.get("context_entity_keys")
        if not isinstance(events, list):
            raise ValueError("incident events must be a list")
        if not isinstance(correlation_edges, list) or not isinstance(
            context_edges, list
        ):
            raise ValueError("incident edge IDs must be lists")
        if not isinstance(correlation_keys, list) or not isinstance(context_keys, list):
            raise ValueError("incident entity keys must be lists")
        return cls(
            incident_id=str(value.get("incident_id") or ""),
            tenant_id=str(value.get("tenant_id") or ""),
            events=tuple(IncidentEvent.from_dict(item) for item in events),
            correlation_edge_ids=tuple(str(item) for item in correlation_edges),
            context_edge_ids=tuple(str(item) for item in context_edges),
            correlation_entity_keys=tuple(
                EntityKey.from_dict(item) for item in correlation_keys
            ),
            context_entity_keys=tuple(
                EntityKey.from_dict(item) for item in context_keys
            ),
            schema_version=str(value.get("schema_version") or ""),
        )


def _snapshot_payload(
    incidents: tuple[CorrelationIncident, ...],
    unassigned_events: tuple[IncidentEvent, ...],
    unassigned_context_edge_ids: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "schema_version": INCIDENT_SNAPSHOT_SCHEMA_VERSION,
        "edge_schema_version": DETERMINISTIC_EDGE_SCHEMA_VERSION,
        "incident_ids": [incident.incident_id for incident in incidents],
        "unassigned_events": [event.to_dict() for event in unassigned_events],
        "unassigned_context_edge_ids": list(unassigned_context_edge_ids),
    }


@dataclass(frozen=True, slots=True)
class IncidentSnapshot:
    snapshot_id: str
    incidents: tuple[CorrelationIncident, ...]
    unassigned_events: tuple[IncidentEvent, ...]
    unassigned_context_edge_ids: tuple[str, ...]
    schema_version: str = INCIDENT_SNAPSHOT_SCHEMA_VERSION
    edge_schema_version: str = DETERMINISTIC_EDGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != INCIDENT_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("unsupported incident snapshot schema version")
        if self.edge_schema_version != DETERMINISTIC_EDGE_SCHEMA_VERSION:
            raise ValueError("unsupported edge schema version")
        if (
            tuple(sorted(self.incidents, key=lambda item: item.incident_id))
            != self.incidents
        ):
            raise ValueError("incidents must be sorted by incident_id")
        if len({item.incident_id for item in self.incidents}) != len(self.incidents):
            raise ValueError("incident IDs must be unique")
        if (
            tuple(sorted(set(self.unassigned_events), key=_unassigned_event_sort_key))
            != self.unassigned_events
        ):
            raise ValueError("unassigned events must be unique and sorted")
        if len({event.ref for event in self.unassigned_events}) != len(
            self.unassigned_events
        ):
            raise ValueError("unassigned event references must be unique")
        if (
            tuple(sorted(set(self.unassigned_context_edge_ids)))
            != self.unassigned_context_edge_ids
        ):
            raise ValueError("unassigned context edge IDs must be unique and sorted")

        assigned = [
            event.ref for incident in self.incidents for event in incident.events
        ]
        if len(assigned) != len(set(assigned)):
            raise ValueError("an event cannot belong to multiple incidents")
        if set(assigned).intersection(event.ref for event in self.unassigned_events):
            raise ValueError("an event cannot be both assigned and unassigned")
        expected_id = _content_id(
            "incident-snapshot",
            _snapshot_payload(
                self.incidents,
                self.unassigned_events,
                self.unassigned_context_edge_ids,
            ),
        )
        if self.snapshot_id != expected_id:
            raise ValueError("snapshot_id does not match snapshot content")

    @classmethod
    def create(
        cls,
        *,
        incidents: Iterable[CorrelationIncident],
        unassigned_events: Iterable[IncidentEvent],
        unassigned_context_edge_ids: Iterable[str],
    ) -> IncidentSnapshot:
        ordered_incidents = tuple(sorted(incidents, key=lambda item: item.incident_id))
        ordered_unassigned = tuple(
            sorted(set(unassigned_events), key=_unassigned_event_sort_key)
        )
        ordered_unassigned_context_edges = tuple(
            sorted(set(unassigned_context_edge_ids))
        )
        payload = _snapshot_payload(
            ordered_incidents,
            ordered_unassigned,
            ordered_unassigned_context_edges,
        )
        return cls(
            snapshot_id=_content_id("incident-snapshot", payload),
            incidents=ordered_incidents,
            unassigned_events=ordered_unassigned,
            unassigned_context_edge_ids=ordered_unassigned_context_edges,
        )

    @property
    def assigned_event_refs(self) -> frozenset[tuple[str, str]]:
        return frozenset(
            event.ref for incident in self.incidents for event in incident.events
        )

    @property
    def unassigned_event_refs(self) -> frozenset[tuple[str, str]]:
        return frozenset(event.ref for event in self.unassigned_events)

    @property
    def all_event_refs(self) -> frozenset[tuple[str, str]]:
        return self.assigned_event_refs.union(self.unassigned_event_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "edge_schema_version": self.edge_schema_version,
            "snapshot_id": self.snapshot_id,
            "incidents": [incident.to_dict() for incident in self.incidents],
            "unassigned_events": [event.to_dict() for event in self.unassigned_events],
            "unassigned_context_edge_ids": list(self.unassigned_context_edge_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> IncidentSnapshot:
        incidents = value.get("incidents")
        unassigned = value.get("unassigned_events")
        unassigned_context_edges = value.get("unassigned_context_edge_ids")
        if not isinstance(incidents, list) or not isinstance(unassigned, list):
            raise ValueError("snapshot incidents and unassigned_events must be lists")
        if not isinstance(unassigned_context_edges, list):
            raise ValueError("unassigned_context_edge_ids must be a list")
        return cls(
            snapshot_id=str(value.get("snapshot_id") or ""),
            incidents=tuple(CorrelationIncident.from_dict(item) for item in incidents),
            unassigned_events=tuple(
                IncidentEvent.from_dict(item) for item in unassigned
            ),
            unassigned_context_edge_ids=tuple(
                str(item) for item in unassigned_context_edges
            ),
            schema_version=str(value.get("schema_version") or ""),
            edge_schema_version=str(value.get("edge_schema_version") or ""),
        )


class _UnionFind:
    def __init__(self) -> None:
        self._parent: dict[tuple[str, str], tuple[str, str]] = {}

    def add(self, item: tuple[str, str]) -> None:
        self._parent.setdefault(item, item)

    def find(self, item: tuple[str, str]) -> tuple[str, str]:
        parent = self._parent[item]
        while parent != self._parent[parent]:
            parent = self._parent[parent]
        while item != parent:
            next_item = self._parent[item]
            self._parent[item] = parent
            item = next_item
        return parent

    def union(self, left: tuple[str, str], right: tuple[str, str]) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        # Stable root selection makes internal state independent of delivery order.
        low, high = sorted((left_root, right_root))
        self._parent[high] = low

    @property
    def items(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._parent)


class IncidentBuilder:
    def __init__(
        self,
        *,
        max_events: int = DEFAULT_MAX_INCIDENT_EVENTS,
        max_edges: int = DEFAULT_MAX_INCIDENT_EDGES,
        max_incidents: int = DEFAULT_MAX_INCIDENTS,
    ) -> None:
        if min(max_events, max_edges, max_incidents) < 1:
            raise ValueError("incident builder limits must be positive")
        self.max_events = max_events
        self.max_edges = max_edges
        self.max_incidents = max_incidents

    def build(
        self,
        events: Iterable[NormalizedEvent],
        edges: Iterable[DeterministicEdge],
    ) -> IncidentSnapshot:
        event_by_ref: dict[tuple[str, str], NormalizedEvent] = {}
        digest_by_ref: dict[tuple[str, str], str] = {}
        for event in events:
            if not isinstance(event, NormalizedEvent):
                raise TypeError("events must contain only NormalizedEvent values")
            ref = (event.tenant_id, event.event_id)
            digest = _event_digest(event)
            previous = digest_by_ref.get(ref)
            if previous is not None:
                if previous != digest:
                    raise IncidentInputConflictError(
                        "the same tenant/event ID has conflicting normalized content"
                    )
                continue
            if len(event_by_ref) >= self.max_events:
                raise IncidentLimitError("incident event limit exceeded")
            event_by_ref[ref] = event
            digest_by_ref[ref] = digest

        edge_by_id: dict[str, DeterministicEdge] = {}
        for edge in edges:
            if not isinstance(edge, DeterministicEdge):
                raise TypeError("edges must contain only DeterministicEdge values")
            existing = edge_by_id.get(edge.edge_id)
            if existing is not None:
                if existing != edge:
                    raise IncidentInputConflictError(
                        "the same edge ID has conflicting deterministic content"
                    )
                continue
            if len(edge_by_id) >= self.max_edges:
                raise IncidentLimitError("incident edge limit exceeded")
            ref = (edge.tenant_id, edge.event_id)
            event = event_by_ref.get(ref)
            if event is None:
                raise IncidentInputConflictError("edge references an unknown event")
            if event.platform is not edge.platform:
                raise IncidentInputConflictError(
                    "edge platform does not match its event"
                )
            if event.parse_status is ParseStatus.UNPARSEABLE:
                raise IncidentInputConflictError(
                    "unparseable events cannot carry edges"
                )
            edge_by_id[edge.edge_id] = edge

        union_find = _UnionFind()
        entity_owner: dict[tuple[str, Platform, EntityKey], tuple[str, str]] = {}
        correlation_keys_by_event: dict[tuple[str, str], set[EntityKey]] = {}
        context_keys_by_event: dict[tuple[str, str], set[EntityKey]] = {}
        correlation_edges_by_event: dict[tuple[str, str], set[str]] = {}
        context_edges_by_event: dict[tuple[str, str], set[str]] = {}

        for edge in sorted(edge_by_id.values(), key=lambda item: item.edge_id):
            ref = (edge.tenant_id, edge.event_id)
            if edge.usage is EdgeUsage.CONTEXT:
                context_keys_by_event.setdefault(ref, set()).add(edge.entity_key)
                context_edges_by_event.setdefault(ref, set()).add(edge.edge_id)
                continue
            union_find.add(ref)
            correlation_keys_by_event.setdefault(ref, set()).add(edge.entity_key)
            correlation_edges_by_event.setdefault(ref, set()).add(edge.edge_id)
            # Platform is part of the namespace. Windows and Linux can both
            # emit process_guid, and a configuration collision must not join
            # two operating systems into one deterministic component.
            entity_ref = (edge.tenant_id, edge.platform, edge.entity_key)
            owner = entity_owner.setdefault(entity_ref, ref)
            union_find.union(owner, ref)

        component_events: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for ref in union_find.items:
            component_events.setdefault(union_find.find(ref), set()).add(ref)

        incidents: list[CorrelationIncident] = []
        assigned_refs: set[tuple[str, str]] = set()
        for refs in component_events.values():
            if len(incidents) >= self.max_incidents:
                raise IncidentLimitError("incident count limit exceeded")
            tenant_ids = {tenant_id for tenant_id, _ in refs}
            if len(tenant_ids) != 1:
                raise IncidentInputConflictError(
                    "one incident crossed tenant boundaries"
                )
            tenant_id = next(iter(tenant_ids))
            incident_events = tuple(
                IncidentEvent(
                    tenant_id=ref[0],
                    event_id=ref[1],
                    event_digest=digest_by_ref[ref],
                    platform=event_by_ref[ref].platform,
                    effective_event_time=event_by_ref[ref].effective_event_time,
                )
                for ref in refs
            )
            correlation_keys = {
                key for ref in refs for key in correlation_keys_by_event.get(ref, set())
            }
            context_keys = {
                key for ref in refs for key in context_keys_by_event.get(ref, set())
            }
            correlation_edge_ids = {
                edge_id
                for ref in refs
                for edge_id in correlation_edges_by_event.get(ref, set())
            }
            context_edge_ids = {
                edge_id
                for ref in refs
                for edge_id in context_edges_by_event.get(ref, set())
            }
            incidents.append(
                CorrelationIncident.create(
                    tenant_id=tenant_id,
                    events=incident_events,
                    correlation_edge_ids=correlation_edge_ids,
                    context_edge_ids=context_edge_ids,
                    correlation_entity_keys=correlation_keys,
                    context_entity_keys=context_keys,
                )
            )
            assigned_refs.update(refs)

        unassigned_refs = set(event_by_ref) - assigned_refs
        unassigned = (
            IncidentEvent(
                tenant_id=ref[0],
                event_id=ref[1],
                event_digest=digest_by_ref[ref],
                platform=event.platform,
                effective_event_time=event.effective_event_time,
            )
            for ref, event in event_by_ref.items()
            if ref in unassigned_refs
        )
        unassigned_context_edge_ids = {
            edge_id
            for ref in unassigned_refs
            for edge_id in context_edges_by_event.get(ref, set())
        }
        return IncidentSnapshot.create(
            incidents=incidents,
            unassigned_events=unassigned,
            unassigned_context_edge_ids=unassigned_context_edge_ids,
        )


@dataclass(frozen=True, slots=True)
class IncidentChange:
    kind: IncidentChangeKind
    previous_incident_ids: tuple[str, ...]
    current_incident_ids: tuple[str, ...]
    overlapping_event_refs: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.kind, IncidentChangeKind):
            raise TypeError("kind must be an IncidentChangeKind")
        if tuple(sorted(set(self.previous_incident_ids))) != self.previous_incident_ids:
            raise ValueError("previous incident IDs must be unique and sorted")
        if tuple(sorted(set(self.current_incident_ids))) != self.current_incident_ids:
            raise ValueError("current incident IDs must be unique and sorted")
        if (
            tuple(sorted(set(self.overlapping_event_refs)))
            != self.overlapping_event_refs
        ):
            raise ValueError("overlapping event refs must be unique and sorted")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "previous_incident_ids": list(self.previous_incident_ids),
            "current_incident_ids": list(self.current_incident_ids),
            "overlapping_event_refs": [
                list(ref) for ref in self.overlapping_event_refs
            ],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> IncidentChange:
        def _ids(field_name: str) -> tuple[str, ...]:
            raw = value.get(field_name)
            if not isinstance(raw, list):
                raise ValueError(f"{field_name} must be a list")
            return tuple(str(item) for item in raw)

        refs = value.get("overlapping_event_refs")
        if not isinstance(refs, list):
            raise ValueError("overlapping_event_refs must be a list")
        if any(not isinstance(item, list) or len(item) != 2 for item in refs):
            raise ValueError("overlapping_event_refs entries must be two-item lists")
        return cls(
            kind=IncidentChangeKind(str(value.get("kind") or "")),
            previous_incident_ids=_ids("previous_incident_ids"),
            current_incident_ids=_ids("current_incident_ids"),
            overlapping_event_refs=tuple(
                (str(item[0]), str(item[1])) for item in refs
            ),
        )


def _change_kind(
    previous: tuple[CorrelationIncident, ...],
    current: tuple[CorrelationIncident, ...],
) -> IncidentChangeKind:
    if not previous:
        return IncidentChangeKind.CREATED
    if not current:
        return IncidentChangeKind.REMOVED
    if len(previous) > 1 and len(current) > 1:
        return IncidentChangeKind.RECOMPOSED
    previous_refs = {
        event.ref for incident in previous for event in incident.events
    }
    current_refs = {event.ref for incident in current for event in incident.events}
    if len(previous) > 1:
        return (
            IncidentChangeKind.MERGED
            if previous_refs.issubset(current_refs)
            else IncidentChangeKind.RECOMPOSED
        )
    if len(current) > 1:
        return (
            IncidentChangeKind.SPLIT
            if current_refs.issubset(previous_refs)
            else IncidentChangeKind.RECOMPOSED
        )
    if previous_refs < current_refs:
        return IncidentChangeKind.EXPANDED
    if current_refs < previous_refs:
        return IncidentChangeKind.CONTRACTED
    return IncidentChangeKind.UPDATED


def _snapshot_changes(
    previous: IncidentSnapshot | None,
    current: IncidentSnapshot,
) -> tuple[tuple[IncidentChange, ...], tuple[str, ...]]:
    if previous is None:
        return (
            tuple(
                IncidentChange(
                    IncidentChangeKind.CREATED,
                    (),
                    (incident.incident_id,),
                    (),
                )
                for incident in current.incidents
            ),
            (),
        )

    previous_by_id = {incident.incident_id: incident for incident in previous.incidents}
    current_by_id = {incident.incident_id: incident for incident in current.incidents}
    unchanged_ids = tuple(sorted(set(previous_by_id).intersection(current_by_id)))
    changed_previous = {
        incident_id: incident
        for incident_id, incident in previous_by_id.items()
        if incident_id not in unchanged_ids
    }
    changed_current = {
        incident_id: incident
        for incident_id, incident in current_by_id.items()
        if incident_id not in unchanged_ids
    }

    previous_by_event: dict[tuple[str, str], set[str]] = {}
    current_by_event: dict[tuple[str, str], set[str]] = {}
    for incident_id, incident in changed_previous.items():
        for event in incident.events:
            previous_by_event.setdefault(event.ref, set()).add(incident_id)
    for incident_id, incident in changed_current.items():
        for event in incident.events:
            current_by_event.setdefault(event.ref, set()).add(incident_id)

    adjacency: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for event_ref in set(previous_by_event).intersection(current_by_event):
        for previous_id in previous_by_event[event_ref]:
            previous_node = ("previous", previous_id)
            adjacency.setdefault(previous_node, set())
            for current_id in current_by_event[event_ref]:
                current_node = ("current", current_id)
                adjacency.setdefault(current_node, set())
                adjacency[previous_node].add(current_node)
                adjacency[current_node].add(previous_node)

    changes: list[IncidentChange] = []
    visited: set[tuple[str, str]] = set()
    for start in sorted(adjacency):
        if start in visited:
            continue
        pending = [start]
        component: set[tuple[str, str]] = set()
        while pending:
            node = pending.pop()
            if node in component:
                continue
            component.add(node)
            pending.extend(adjacency[node] - component)
        visited.update(component)
        previous_ids = tuple(
            sorted(node_id for side, node_id in component if side == "previous")
        )
        current_ids = tuple(
            sorted(node_id for side, node_id in component if side == "current")
        )
        previous_incidents = tuple(changed_previous[item] for item in previous_ids)
        current_incidents = tuple(changed_current[item] for item in current_ids)
        previous_refs = {
            event.ref for incident in previous_incidents for event in incident.events
        }
        current_refs = {
            event.ref for incident in current_incidents for event in incident.events
        }
        changes.append(
            IncidentChange(
                _change_kind(previous_incidents, current_incidents),
                previous_ids,
                current_ids,
                tuple(sorted(previous_refs.intersection(current_refs))),
            )
        )

    linked_previous = {
        item for change in changes for item in change.previous_incident_ids
    }
    linked_current = {
        item for change in changes for item in change.current_incident_ids
    }
    for incident_id in sorted(set(changed_previous) - linked_previous):
        changes.append(
            IncidentChange(IncidentChangeKind.REMOVED, (incident_id,), (), ())
        )
    for incident_id in sorted(set(changed_current) - linked_current):
        changes.append(
            IncidentChange(IncidentChangeKind.CREATED, (), (incident_id,), ())
        )
    ordered_changes = tuple(
        sorted(changes, key=lambda change: _canonical_json(change.to_dict()))
    )
    return ordered_changes, unchanged_ids


def _revision_payload(
    ordinal: int,
    previous_snapshot_id: str | None,
    current_snapshot_id: str,
    changes: tuple[IncidentChange, ...],
    unchanged_incident_ids: tuple[str, ...],
    newly_assigned_event_refs: tuple[tuple[str, str], ...],
    newly_unassigned_event_refs: tuple[tuple[str, str], ...],
    added_event_refs: tuple[tuple[str, str], ...],
    removed_event_refs: tuple[tuple[str, str], ...],
) -> dict[str, Any]:
    return {
        "schema_version": INCIDENT_REVISION_SCHEMA_VERSION,
        "ordinal": ordinal,
        "previous_snapshot_id": previous_snapshot_id,
        "current_snapshot_id": current_snapshot_id,
        "changes": [change.to_dict() for change in changes],
        "unchanged_incident_ids": list(unchanged_incident_ids),
        "newly_assigned_event_refs": [list(ref) for ref in newly_assigned_event_refs],
        "newly_unassigned_event_refs": [
            list(ref) for ref in newly_unassigned_event_refs
        ],
        "added_event_refs": [list(ref) for ref in added_event_refs],
        "removed_event_refs": [list(ref) for ref in removed_event_refs],
    }


@dataclass(frozen=True, slots=True)
class IncidentRevision:
    revision_id: str
    ordinal: int
    previous_snapshot_id: str | None
    current_snapshot_id: str
    changes: tuple[IncidentChange, ...]
    unchanged_incident_ids: tuple[str, ...]
    newly_assigned_event_refs: tuple[tuple[str, str], ...]
    newly_unassigned_event_refs: tuple[tuple[str, str], ...]
    added_event_refs: tuple[tuple[str, str], ...]
    removed_event_refs: tuple[tuple[str, str], ...]
    schema_version: str = INCIDENT_REVISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != INCIDENT_REVISION_SCHEMA_VERSION:
            raise ValueError("unsupported incident revision schema version")
        if self.ordinal < 1:
            raise ValueError("revision ordinal must be positive")
        if not str(self.current_snapshot_id or "").strip():
            raise ValueError("current_snapshot_id must not be empty")
        if any(not isinstance(change, IncidentChange) for change in self.changes):
            raise TypeError("changes must contain IncidentChange values")
        for field_name in (
            "unchanged_incident_ids",
            "newly_assigned_event_refs",
            "newly_unassigned_event_refs",
            "added_event_refs",
            "removed_event_refs",
        ):
            values = getattr(self, field_name)
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} must be unique and sorted")
        expected_id = _content_id(
            "incident-revision",
            _revision_payload(
                self.ordinal,
                self.previous_snapshot_id,
                self.current_snapshot_id,
                self.changes,
                self.unchanged_incident_ids,
                self.newly_assigned_event_refs,
                self.newly_unassigned_event_refs,
                self.added_event_refs,
                self.removed_event_refs,
            ),
        )
        if self.revision_id != expected_id:
            raise ValueError("revision_id does not match revision content")

    @classmethod
    def create(
        cls,
        *,
        ordinal: int,
        previous: IncidentSnapshot | None,
        current: IncidentSnapshot,
    ) -> IncidentRevision:
        changes, unchanged_ids = _snapshot_changes(previous, current)
        previous_assigned = previous.assigned_event_refs if previous else frozenset()
        previous_unassigned = (
            previous.unassigned_event_refs if previous else frozenset()
        )
        previous_all = previous.all_event_refs if previous else frozenset()
        current_assigned = current.assigned_event_refs
        current_unassigned = current.unassigned_event_refs
        current_all = current.all_event_refs
        newly_assigned = tuple(sorted(current_assigned - previous_assigned))
        newly_unassigned = tuple(sorted(current_unassigned - previous_unassigned))
        added_events = tuple(sorted(current_all - previous_all))
        removed_events = tuple(sorted(previous_all - current_all))
        payload = _revision_payload(
            ordinal,
            previous.snapshot_id if previous else None,
            current.snapshot_id,
            changes,
            unchanged_ids,
            newly_assigned,
            newly_unassigned,
            added_events,
            removed_events,
        )
        return cls(
            revision_id=_content_id("incident-revision", payload),
            ordinal=ordinal,
            previous_snapshot_id=previous.snapshot_id if previous else None,
            current_snapshot_id=current.snapshot_id,
            changes=changes,
            unchanged_incident_ids=unchanged_ids,
            newly_assigned_event_refs=newly_assigned,
            newly_unassigned_event_refs=newly_unassigned,
            added_event_refs=added_events,
            removed_event_refs=removed_events,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_revision_payload(
                self.ordinal,
                self.previous_snapshot_id,
                self.current_snapshot_id,
                self.changes,
                self.unchanged_incident_ids,
                self.newly_assigned_event_refs,
                self.newly_unassigned_event_refs,
                self.added_event_refs,
                self.removed_event_refs,
            ),
            "revision_id": self.revision_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> IncidentRevision:
        def _refs(field_name: str) -> tuple[tuple[str, str], ...]:
            raw = value.get(field_name)
            if not isinstance(raw, list):
                raise ValueError(f"{field_name} must be a list")
            if any(not isinstance(item, list) or len(item) != 2 for item in raw):
                raise ValueError(f"{field_name} entries must be two-item lists")
            return tuple((str(item[0]), str(item[1])) for item in raw)

        changes = value.get("changes")
        unchanged = value.get("unchanged_incident_ids")
        if not isinstance(changes, list) or not isinstance(unchanged, list):
            raise ValueError("revision changes and unchanged IDs must be lists")
        previous_id = value.get("previous_snapshot_id")
        return cls(
            revision_id=str(value.get("revision_id") or ""),
            ordinal=int(value.get("ordinal", 0)),
            previous_snapshot_id=(
                str(previous_id) if previous_id is not None else None
            ),
            current_snapshot_id=str(value.get("current_snapshot_id") or ""),
            changes=tuple(IncidentChange.from_dict(item) for item in changes),
            unchanged_incident_ids=tuple(str(item) for item in unchanged),
            newly_assigned_event_refs=_refs("newly_assigned_event_refs"),
            newly_unassigned_event_refs=_refs("newly_unassigned_event_refs"),
            added_event_refs=_refs("added_event_refs"),
            removed_event_refs=_refs("removed_event_refs"),
            schema_version=str(value.get("schema_version") or ""),
        )


class IncidentHistory:
    """Thread-safe immutable snapshot history with explicit rollback revisions."""

    def __init__(self) -> None:
        self._snapshots: dict[str, IncidentSnapshot] = {}
        self._timeline: list[str] = []
        self._revisions: list[IncidentRevision] = []
        self._lock = threading.RLock()

    @property
    def current_snapshot(self) -> IncidentSnapshot | None:
        with self._lock:
            return self._snapshots[self._timeline[-1]] if self._timeline else None

    @property
    def revisions(self) -> tuple[IncidentRevision, ...]:
        with self._lock:
            return tuple(self._revisions)

    @property
    def timeline(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._timeline)

    def get_snapshot(self, snapshot_id: str) -> IncidentSnapshot:
        with self._lock:
            try:
                return self._snapshots[snapshot_id]
            except KeyError as exc:
                raise IncidentRevisionError("unknown incident snapshot") from exc

    def append(self, snapshot: IncidentSnapshot) -> IncidentRevision | None:
        if not isinstance(snapshot, IncidentSnapshot):
            raise TypeError("snapshot must be an IncidentSnapshot")
        with self._lock:
            previous = self.current_snapshot
            if previous is not None and previous.snapshot_id == snapshot.snapshot_id:
                return None
            stored = self._snapshots.get(snapshot.snapshot_id)
            if stored is not None and stored != snapshot:
                raise IncidentRevisionError(
                    "snapshot ID collision with different content"
                )
            self._snapshots[snapshot.snapshot_id] = snapshot
            revision = IncidentRevision.create(
                ordinal=len(self._revisions) + 1,
                previous=previous,
                current=snapshot,
            )
            self._timeline.append(snapshot.snapshot_id)
            self._revisions.append(revision)
            return revision

    def rollback(self, snapshot_id: str) -> IncidentRevision | None:
        return self.append(self.get_snapshot(snapshot_id))
