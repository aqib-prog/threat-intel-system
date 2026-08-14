"""Deterministic event-to-entity edges and correlation coverage accounting.

Edges are bipartite: each normalized event links to a canonical, scoped native
entity key. We never materialize all event-to-event pairs for a shared key;
that would grow quadratically for common principals and resources.

Only lifetime-stable request, process, session, and activity identifiers are
eligible to drive deterministic incident correlation. Exact but long-lived
identity/resource associations are retained as context-only edges. PID-only
and mutable-name keys are counted but excluded. Unknown future key kinds fail
closed and are surfaced in coverage.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from correlation.models import EntityKey, NormalizedEvent, ParseStatus, Platform


DETERMINISTIC_EDGE_SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_UNIQUE_EVENTS = 1_000_000
DEFAULT_MAX_EDGES = 10_000_000


class EdgeBuildError(RuntimeError):
    pass


class EventConflictError(EdgeBuildError):
    pass


class EdgeLimitError(EdgeBuildError):
    pass


class EdgeFamily(str, Enum):
    REQUEST = "request"
    PROCESS = "process"
    SESSION = "session"
    ACTIVITY = "activity"
    IDENTITY = "identity"
    RESOURCE = "resource"


class EdgeUsage(str, Enum):
    CORRELATION = "correlation"
    CONTEXT = "context"


class EdgeRole(str, Enum):
    SUBJECT = "subject"
    PARENT = "parent"
    INITIATOR = "initiator"
    RESPONSIBLE = "responsible"
    ORIGINAL = "original"
    ISSUER = "issuer"
    ATTRIBUTED = "attributed"
    IMPERSONATED = "impersonated"
    RESOURCE = "resource"
    RELATED = "related"


class KeyPolicy(str, Enum):
    CORRELATION = "correlation"
    CONTEXT = "context"
    EXCLUDED_UNSTABLE = "excluded_unstable"


@dataclass(frozen=True, slots=True)
class KeyRule:
    policy: KeyPolicy
    canonical_kind: str | None = None
    family: EdgeFamily | None = None
    role: EdgeRole = EdgeRole.SUBJECT
    exclusion_reason: str | None = None

    def __post_init__(self) -> None:
        emits = self.policy in {KeyPolicy.CORRELATION, KeyPolicy.CONTEXT}
        if emits and (self.canonical_kind is None or self.family is None):
            raise ValueError("emitted key rules require canonical kind and family")
        if not emits and not self.exclusion_reason:
            raise ValueError("excluded key rules require an exclusion reason")


def _correlation(
    canonical_kind: str,
    family: EdgeFamily,
    role: EdgeRole = EdgeRole.SUBJECT,
) -> KeyRule:
    return KeyRule(KeyPolicy.CORRELATION, canonical_kind, family, role)


def _context(
    canonical_kind: str,
    family: EdgeFamily,
    role: EdgeRole = EdgeRole.SUBJECT,
) -> KeyRule:
    return KeyRule(KeyPolicy.CONTEXT, canonical_kind, family, role)


def _excluded(reason: str) -> KeyRule:
    return KeyRule(KeyPolicy.EXCLUDED_UNSTABLE, exclusion_reason=reason)


# This registry is intentionally explicit. Adding an adapter key without a
# reviewed rule produces no edge and increments unknown_key_counts.
KEY_RULES: dict[str, KeyRule] = {
    # Windows, Linux, and macOS process identity.
    "process_guid": _correlation("process_guid", EdgeFamily.PROCESS),
    "parent_process_guid": _correlation(
        "process_guid", EdgeFamily.PROCESS, EdgeRole.PARENT
    ),
    "process_entity_id": _correlation("process_entity_id", EdgeFamily.PROCESS),
    "parent_process_entity_id": _correlation(
        "process_entity_id", EdgeFamily.PROCESS, EdgeRole.PARENT
    ),
    "process_pidversion": _correlation("process_pidversion", EdgeFamily.PROCESS),
    "parent_process_pidversion": _correlation(
        "process_pidversion", EdgeFamily.PROCESS, EdgeRole.PARENT
    ),
    "initiator_process_pidversion": _correlation(
        "process_pidversion", EdgeFamily.PROCESS, EdgeRole.INITIATOR
    ),
    "responsible_process_pidversion": _correlation(
        "process_pidversion", EdgeFamily.PROCESS, EdgeRole.RESPONSIBLE
    ),
    # A PID can be reused during one boot, so it cannot deterministically name
    # a process lifetime without an additional validated lifetime boundary.
    "process_pid": _excluded("pid_is_reused_within_boot"),
    "parent_process_pid": _excluded("pid_is_reused_within_boot"),
    "initiator_process_pid": _excluded("pid_is_reused_within_boot"),
    "responsible_process_pid": _excluded("pid_is_reused_within_boot"),
    # Compound audit events, login sessions, and Windows activity chains.
    "audit_event_serial": _correlation(
        "audit_event_serial", EdgeFamily.REQUEST
    ),
    "audit_session": _correlation("audit_session", EdgeFamily.SESSION),
    "login_uid": _context("login_uid", EdgeFamily.IDENTITY),
    "logon_guid": _correlation("logon_guid", EdgeFamily.SESSION),
    "logon_id": _correlation("logon_id", EdgeFamily.SESSION),
    "activity_id": _correlation("activity_id", EdgeFamily.ACTIVITY),
    "related_activity_id": _correlation(
        "activity_id", EdgeFamily.ACTIVITY, EdgeRole.RELATED
    ),
    # CloudTrail request/action identity.
    "cloudtrail_event_id": _correlation(
        "cloudtrail_event_id", EdgeFamily.REQUEST
    ),
    "cloudtrail_original_event_id": _correlation(
        "cloudtrail_event_id", EdgeFamily.REQUEST, EdgeRole.ORIGINAL
    ),
    "cloudtrail_shared_event_id": _correlation(
        "cloudtrail_shared_event_id", EdgeFamily.REQUEST
    ),
    "cloudtrail_insight_id": _correlation(
        "cloudtrail_insight_id", EdgeFamily.REQUEST
    ),
    "cloud_request_id": _correlation("cloud_request_id", EdgeFamily.REQUEST),
    "cloud_original_request_id": _correlation(
        "cloud_request_id", EdgeFamily.REQUEST, EdgeRole.ORIGINAL
    ),
    "aws_signin_session_arn": _correlation(
        "aws_signin_session_arn", EdgeFamily.SESSION
    ),
    # Long-lived AWS principals/resources are exact associations, but they
    # must not merge every action by one account or role into one incident.
    "aws_principal_id": _context("aws_principal_id", EdgeFamily.IDENTITY),
    "aws_principal_arn": _context("aws_principal_arn", EdgeFamily.IDENTITY),
    "aws_access_key_id": _context("aws_access_key_id", EdgeFamily.IDENTITY),
    "aws_identity_center_user_id": _context(
        "aws_identity_center_user_id", EdgeFamily.IDENTITY
    ),
    "aws_delegated_provider_account_id": _context(
        "aws_delegated_provider_account_id", EdgeFamily.IDENTITY
    ),
    "aws_session_issuer_arn": _context(
        "aws_principal_arn", EdgeFamily.IDENTITY, EdgeRole.ISSUER
    ),
    "aws_attributed_principal_arn": _context(
        "aws_principal_arn", EdgeFamily.IDENTITY, EdgeRole.ATTRIBUTED
    ),
    "aws_resource_arn": _context(
        "aws_resource_arn", EdgeFamily.RESOURCE, EdgeRole.RESOURCE
    ),
    "aws_vpc_endpoint_id": _context(
        "aws_vpc_endpoint_id", EdgeFamily.RESOURCE, EdgeRole.RESOURCE
    ),
    # Kubernetes request, identity, and resource associations.
    "kubernetes_audit_id": _correlation(
        "kubernetes_audit_id", EdgeFamily.REQUEST
    ),
    "kubernetes_user_uid": _context(
        "kubernetes_user_uid", EdgeFamily.IDENTITY
    ),
    "kubernetes_impersonated_user_uid": _context(
        "kubernetes_user_uid", EdgeFamily.IDENTITY, EdgeRole.IMPERSONATED
    ),
    "kubernetes_object_uid": _context(
        "kubernetes_object_uid", EdgeFamily.RESOURCE, EdgeRole.RESOURCE
    ),
    "kubernetes_user_name": _excluded("username_is_mutable"),
    "kubernetes_impersonated_user_name": _excluded("username_is_mutable"),
}


def _edge_identifier(
    *,
    tenant_id: str,
    event_id: str,
    source_key_kind: str,
    canonical_key: EntityKey,
    family: EdgeFamily,
    usage: EdgeUsage,
    role: EdgeRole,
) -> str:
    material = json.dumps(
        [
            DETERMINISTIC_EDGE_SCHEMA_VERSION,
            tenant_id,
            event_id,
            source_key_kind,
            canonical_key.kind,
            canonical_key.value,
            canonical_key.scope,
            family.value,
            usage.value,
            role.value,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "edge:" + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True, slots=True)
class DeterministicEdge:
    edge_id: str
    tenant_id: str
    event_id: str
    platform: Platform
    source_key_kind: str
    entity_key: EntityKey
    family: EdgeFamily
    usage: EdgeUsage
    role: EdgeRole
    schema_version: str = DETERMINISTIC_EDGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("edge_id", "tenant_id", "event_id", "source_key_kind"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"{name} must not be empty")
        if not isinstance(self.platform, Platform):
            raise TypeError("platform must be a Platform")
        if not isinstance(self.entity_key, EntityKey):
            raise TypeError("entity_key must be an EntityKey")
        if not isinstance(self.family, EdgeFamily):
            raise TypeError("family must be an EdgeFamily")
        if not isinstance(self.usage, EdgeUsage):
            raise TypeError("usage must be an EdgeUsage")
        if not isinstance(self.role, EdgeRole):
            raise TypeError("role must be an EdgeRole")
        if self.schema_version != DETERMINISTIC_EDGE_SCHEMA_VERSION:
            raise ValueError("unsupported deterministic edge schema version")
        rule = KEY_RULES.get(self.source_key_kind)
        if rule is None or rule.policy is KeyPolicy.EXCLUDED_UNSTABLE:
            raise ValueError("source_key_kind is not eligible to emit an edge")
        expected_usage = (
            EdgeUsage.CORRELATION
            if rule.policy is KeyPolicy.CORRELATION
            else EdgeUsage.CONTEXT
        )
        if (
            self.entity_key.kind != rule.canonical_kind
            or self.family is not rule.family
            or self.usage is not expected_usage
            or self.role is not rule.role
        ):
            raise ValueError("edge fields do not match the registered key policy")
        expected_id = _edge_identifier(
            tenant_id=self.tenant_id,
            event_id=self.event_id,
            source_key_kind=self.source_key_kind,
            canonical_key=self.entity_key,
            family=self.family,
            usage=self.usage,
            role=self.role,
        )
        if self.edge_id != expected_id:
            raise ValueError("edge_id does not match deterministic edge content")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "edge_id": self.edge_id,
            "tenant_id": self.tenant_id,
            "event_id": self.event_id,
            "platform": self.platform.value,
            "source_key_kind": self.source_key_kind,
            "entity_key": self.entity_key.to_dict(),
            "family": self.family.value,
            "usage": self.usage.value,
            "role": self.role.value,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> DeterministicEdge:
        return cls(
            edge_id=str(value.get("edge_id") or ""),
            tenant_id=str(value.get("tenant_id") or ""),
            event_id=str(value.get("event_id") or ""),
            platform=Platform(str(value.get("platform") or "")),
            source_key_kind=str(value.get("source_key_kind") or ""),
            entity_key=EntityKey.from_dict(value.get("entity_key") or {}),
            family=EdgeFamily(str(value.get("family") or "")),
            usage=EdgeUsage(str(value.get("usage") or "")),
            role=EdgeRole(str(value.get("role") or "")),
            schema_version=str(value.get("schema_version") or ""),
        )


@dataclass(frozen=True, slots=True)
class EdgeCoverage:
    input_event_count: int
    unique_event_count: int
    duplicate_event_count: int
    parsed_event_count: int
    partial_event_count: int
    unparseable_event_count: int
    source_key_count: int
    emitted_edge_count: int
    correlation_edge_count: int
    context_edge_count: int
    excluded_key_count: int
    unknown_key_count: int
    events_with_correlation_edges: int
    events_with_context_edges: int
    events_without_correlation_edges: int
    events_without_source_keys: int
    events_without_emitted_edges: int
    source_key_counts: tuple[tuple[str, int], ...]
    canonical_key_counts: tuple[tuple[str, int], ...]
    excluded_key_counts: tuple[tuple[str, int], ...]
    unknown_key_counts: tuple[tuple[str, int], ...]
    platform_counts: tuple[tuple[str, tuple[tuple[str, int], ...]], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_event_count": self.input_event_count,
            "unique_event_count": self.unique_event_count,
            "duplicate_event_count": self.duplicate_event_count,
            "parse_status": {
                "parsed": self.parsed_event_count,
                "partial": self.partial_event_count,
                "unparseable": self.unparseable_event_count,
            },
            "source_key_count": self.source_key_count,
            "emitted_edge_count": self.emitted_edge_count,
            "correlation_edge_count": self.correlation_edge_count,
            "context_edge_count": self.context_edge_count,
            "excluded_key_count": self.excluded_key_count,
            "unknown_key_count": self.unknown_key_count,
            "events_with_correlation_edges": self.events_with_correlation_edges,
            "events_with_context_edges": self.events_with_context_edges,
            "events_without_correlation_edges": self.events_without_correlation_edges,
            "events_without_source_keys": self.events_without_source_keys,
            "events_without_emitted_edges": self.events_without_emitted_edges,
            "source_key_counts": dict(self.source_key_counts),
            "canonical_key_counts": dict(self.canonical_key_counts),
            "excluded_key_counts": dict(self.excluded_key_counts),
            "unknown_key_counts": dict(self.unknown_key_counts),
            "platform_counts": {
                platform: dict(values) for platform, values in self.platform_counts
            },
        }


@dataclass(frozen=True, slots=True)
class EdgeBuildResult:
    edges: tuple[DeterministicEdge, ...]
    coverage: EdgeCoverage


def _event_fingerprint(event: NormalizedEvent) -> bytes:
    return json.dumps(
        event.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _edge_id(
    event: NormalizedEvent,
    source_key: EntityKey,
    canonical_key: EntityKey,
    rule: KeyRule,
) -> str:
    if rule.family is None:
        raise ValueError("an emitted edge rule must have a family")
    usage = (
        EdgeUsage.CORRELATION
        if rule.policy is KeyPolicy.CORRELATION
        else EdgeUsage.CONTEXT
    )
    return _edge_identifier(
        tenant_id=event.tenant_id,
        event_id=event.event_id,
        source_key_kind=source_key.kind,
        canonical_key=canonical_key,
        family=rule.family,
        usage=usage,
        role=rule.role,
    )


class DeterministicEdgeBuilder:
    def __init__(
        self,
        *,
        max_unique_events: int = DEFAULT_MAX_UNIQUE_EVENTS,
        max_edges: int = DEFAULT_MAX_EDGES,
    ) -> None:
        if max_unique_events < 1 or max_edges < 1:
            raise ValueError("edge builder limits must be positive")
        self.max_unique_events = max_unique_events
        self.max_edges = max_edges

    def edges_for_event(self, event: NormalizedEvent) -> tuple[DeterministicEdge, ...]:
        if not isinstance(event, NormalizedEvent):
            raise TypeError("event must be a NormalizedEvent")
        # An unparseable envelope preserves evidence but carries no trusted
        # normalized assertions. Fail closed even if a faulty/future adapter
        # accidentally attaches entity keys to it.
        if event.parse_status is ParseStatus.UNPARSEABLE:
            return ()
        edges: list[DeterministicEdge] = []
        for source_key in event.entity_keys:
            rule = KEY_RULES.get(source_key.kind)
            if rule is None or rule.policy is KeyPolicy.EXCLUDED_UNSTABLE:
                continue
            canonical_key = EntityKey(
                rule.canonical_kind or "",
                source_key.value,
                source_key.scope,
            )
            usage = (
                EdgeUsage.CORRELATION
                if rule.policy is KeyPolicy.CORRELATION
                else EdgeUsage.CONTEXT
            )
            edges.append(
                DeterministicEdge(
                    edge_id=_edge_id(event, source_key, canonical_key, rule),
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    platform=event.platform,
                    source_key_kind=source_key.kind,
                    entity_key=canonical_key,
                    family=rule.family or EdgeFamily.RESOURCE,
                    usage=usage,
                    role=rule.role,
                )
            )
        return tuple(edges)

    def build(self, events: Iterable[NormalizedEvent]) -> EdgeBuildResult:
        seen_events: dict[tuple[str, str], bytes] = {}
        seen_edges: set[str] = set()
        edges: list[DeterministicEdge] = []
        input_count = 0
        duplicate_count = 0
        status_counts: Counter[str] = Counter()
        source_counts: Counter[str] = Counter()
        canonical_counts: Counter[str] = Counter()
        excluded_counts: Counter[str] = Counter()
        unknown_counts: Counter[str] = Counter()
        platform_counts: dict[str, Counter[str]] = {}
        events_with_correlation = 0
        events_with_context = 0
        events_without_source_keys = 0
        events_without_emitted_edges = 0

        for event in events:
            input_count += 1
            if not isinstance(event, NormalizedEvent):
                raise TypeError("events must contain only NormalizedEvent values")
            event_key = (event.tenant_id, event.event_id)
            fingerprint = _event_fingerprint(event)
            previous = seen_events.get(event_key)
            if previous is not None:
                if previous != fingerprint:
                    raise EventConflictError(
                        "the same tenant/event ID has conflicting normalized content"
                    )
                duplicate_count += 1
                continue
            if len(seen_events) >= self.max_unique_events:
                raise EdgeLimitError("unique event limit exceeded")
            seen_events[event_key] = fingerprint

            status_counts[event.parse_status.value] += 1
            platform = platform_counts.setdefault(event.platform.value, Counter())
            platform["events"] += 1
            platform[f"parse_status_{event.parse_status.value}"] += 1
            if not event.entity_keys:
                events_without_source_keys += 1
                platform["events_without_source_keys"] += 1

            for key in event.entity_keys:
                source_counts[key.kind] += 1
                platform["source_keys"] += 1
                rule = KEY_RULES.get(key.kind)
                if rule is None:
                    unknown_counts[key.kind] += 1
                    platform["unknown_keys"] += 1
                elif rule.policy is KeyPolicy.EXCLUDED_UNSTABLE:
                    excluded_counts[key.kind] += 1
                    platform["excluded_keys"] += 1

            event_edges = self.edges_for_event(event)
            has_correlation = any(
                edge.usage is EdgeUsage.CORRELATION for edge in event_edges
            )
            has_context = any(edge.usage is EdgeUsage.CONTEXT for edge in event_edges)
            if has_correlation:
                events_with_correlation += 1
                platform["events_with_correlation_edges"] += 1
            else:
                platform["events_without_correlation_edges"] += 1
            if has_context:
                events_with_context += 1
                platform["events_with_context_edges"] += 1
            if not event_edges:
                events_without_emitted_edges += 1
                platform["events_without_emitted_edges"] += 1

            for edge in event_edges:
                if edge.edge_id in seen_edges:
                    continue
                if len(edges) >= self.max_edges:
                    raise EdgeLimitError("deterministic edge limit exceeded")
                seen_edges.add(edge.edge_id)
                edges.append(edge)
                canonical_counts[edge.entity_key.kind] += 1
                platform[f"{edge.usage.value}_edges"] += 1

        correlation_count = sum(
            edge.usage is EdgeUsage.CORRELATION for edge in edges
        )
        context_count = len(edges) - correlation_count
        coverage = EdgeCoverage(
            input_event_count=input_count,
            unique_event_count=len(seen_events),
            duplicate_event_count=duplicate_count,
            parsed_event_count=status_counts[ParseStatus.PARSED.value],
            partial_event_count=status_counts[ParseStatus.PARTIAL.value],
            unparseable_event_count=status_counts[ParseStatus.UNPARSEABLE.value],
            source_key_count=sum(source_counts.values()),
            emitted_edge_count=len(edges),
            correlation_edge_count=correlation_count,
            context_edge_count=context_count,
            excluded_key_count=sum(excluded_counts.values()),
            unknown_key_count=sum(unknown_counts.values()),
            events_with_correlation_edges=events_with_correlation,
            events_with_context_edges=events_with_context,
            events_without_correlation_edges=(
                len(seen_events) - events_with_correlation
            ),
            events_without_source_keys=events_without_source_keys,
            events_without_emitted_edges=events_without_emitted_edges,
            source_key_counts=tuple(sorted(source_counts.items())),
            canonical_key_counts=tuple(sorted(canonical_counts.items())),
            excluded_key_counts=tuple(sorted(excluded_counts.items())),
            unknown_key_counts=tuple(sorted(unknown_counts.items())),
            platform_counts=tuple(
                (name, tuple(sorted(counts.items())))
                for name, counts in sorted(platform_counts.items())
            ),
        )
        ordered_edges = tuple(sorted(edges, key=lambda edge: edge.edge_id))
        return EdgeBuildResult(ordered_edges, coverage)
