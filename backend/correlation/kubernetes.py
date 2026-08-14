"""Normalize Kubernetes API audit events without exposing embedded bodies.

One API request can emit several stage events. They remain distinct evidence
occurrences and share a trusted-cluster-scoped ``auditID`` correlation key.
Request/response bodies and arbitrary identity extras/annotations remain only
in immutable raw evidence because they can contain credentials or attacker-
controlled data.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from correlation.models import (
    EntityKey,
    EventTimeQuality,
    NormalizedEvent,
    ParseStatus,
    Platform,
    RawEvidenceRef,
)
from correlation.ports import RawEvidenceStore


KUBERNETES_AUDIT_ADAPTER_VERSION = "1.0.0"
DEFAULT_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSED_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_EVENTS_PER_PAYLOAD = 10_000
MAX_JSON_NESTING_DEPTH = 64
MAX_SOURCE_IPS = 64
MAX_USER_GROUPS = 512
MAX_TEXT_BYTES = 8 * 1024
MAX_IDENTIFIER_BYTES = 1_024
SUPPORTED_API_VERSION = "audit.k8s.io/v1"
SUPPORTED_STAGES = frozenset(
    {"RequestReceived", "ResponseStarted", "ResponseComplete", "Panic"}
)
SUPPORTED_LEVELS = frozenset({"None", "Metadata", "Request", "RequestResponse"})
SAFE_AUDIT_ANNOTATIONS = frozenset(
    {"authorization.k8s.io/decision", "authorization.k8s.io/reason"}
)


@dataclass(frozen=True, slots=True)
class _InvalidRecord:
    reason: str


def _mapping_get(value: Mapping[str, Any], name: str) -> Any:
    wanted = name.casefold()
    for key, child in value.items():
        if str(key).casefold() == wanted:
            return child
    return None


def _text(value: Any, *, max_bytes: int = MAX_TEXT_BYTES) -> str | None:
    if not isinstance(value, str):
        return None
    rendered = value.strip()
    if not rendered or len(rendered.encode("utf-8")) > max_bytes:
        return None
    return rendered


def _identifier(value: Any) -> str | None:
    rendered = _text(value, max_bytes=MAX_IDENTIFIER_BYTES)
    if rendered is None or any(ord(character) < 32 for character in rendered):
        return None
    return rendered


def _timestamp(value: Any) -> datetime | None:
    rendered = _text(value, max_bytes=128)
    if rendered is None:
        return None
    try:
        parsed = datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        normalized = str(key).casefold()
        if normalized in seen:
            raise ValueError(f"duplicate or case-ambiguous JSON key: {key}")
        seen.add(normalized)
        result[str(key)] = value
    return result


def _loads(value: str) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_strict_json_object,
        parse_constant=_reject_json_constant,
    )


def _expand(value: Any) -> list[Mapping[str, Any] | _InvalidRecord]:
    if isinstance(value, Mapping):
        if _text(_mapping_get(value, "kind"), max_bytes=64) == "EventList":
            if (
                _text(_mapping_get(value, "apiVersion"), max_bytes=128)
                != SUPPORTED_API_VERSION
            ):
                return [_InvalidRecord("unsupported Kubernetes audit EventList version")]
            items = _mapping_get(value, "items")
            if not isinstance(items, list):
                return [_InvalidRecord("Kubernetes EventList items is not an array")]
            return [
                item
                if isinstance(item, Mapping)
                else _InvalidRecord("audit event is not a JSON object")
                for item in items
            ]
        return [value]
    if isinstance(value, list):
        return [
            item
            if isinstance(item, Mapping)
            else _InvalidRecord("audit event is not a JSON object")
            for item in value
        ]
    return [_InvalidRecord("audit event is not a JSON object")]


def _json_items(payload: bytes) -> list[Mapping[str, Any] | _InvalidRecord]:
    decoded = payload.decode("utf-8-sig")
    try:
        return _expand(_loads(decoded))
    except (json.JSONDecodeError, ValueError):
        items: list[Mapping[str, Any] | _InvalidRecord] = []
        for line in decoded.splitlines():
            if not line.strip():
                continue
            try:
                items.extend(_expand(_loads(line)))
            except (json.JSONDecodeError, ValueError) as exc:
                items.append(_InvalidRecord(str(exc)))
        if not items:
            raise
        return items


def _json_depth_is_safe(value: Any) -> bool:
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_JSON_NESTING_DEPTH:
            return False
        if isinstance(current, Mapping):
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current)
    return True


def _bounded_strings(value: Any, *, limit: int) -> tuple[list[str], bool]:
    if value is None:
        return [], False
    if not isinstance(value, list):
        return [], True
    invalid_or_truncated = len(value) > limit
    output: list[str] = []
    for item in value[:limit]:
        rendered = _identifier(item)
        if rendered is None:
            invalid_or_truncated = True
        else:
            output.append(rendered)
    return output, invalid_or_truncated


def _metadata_uid(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    metadata = _mapping_get(value, "metadata")
    if not isinstance(metadata, Mapping):
        return None
    return _identifier(_mapping_get(metadata, "uid"))


def _safe_annotations(value: Any) -> tuple[dict[str, str], bool]:
    if value is None:
        return {}, False
    if not isinstance(value, Mapping):
        return {}, True
    kept: dict[str, str] = {}
    omitted = False
    for key, child in value.items():
        name = _text(key, max_bytes=256)
        rendered = _text(child)
        if name in SAFE_AUDIT_ANNOTATIONS and rendered is not None:
            kept[name] = rendered
        else:
            omitted = True
    return kept, omitted


@dataclass(frozen=True, slots=True)
class KubernetesAuditAdapter:
    evidence_store: RawEvidenceStore
    tenant_id: str
    source_instance_id: str
    cluster_uid: str
    adapter_version: str = KUBERNETES_AUDIT_ADAPTER_VERSION
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES
    max_events_per_payload: int = DEFAULT_MAX_EVENTS_PER_PAYLOAD

    def __post_init__(self) -> None:
        for name in ("tenant_id", "source_instance_id", "cluster_uid", "adapter_version"):
            rendered = _identifier(getattr(self, name))
            if rendered is None:
                raise ValueError(f"{name} must be a bounded non-empty identifier")
            object.__setattr__(self, name, rendered)
        if min(
            self.max_payload_bytes,
            self.max_decompressed_bytes,
            self.max_events_per_payload,
        ) < 1:
            raise ValueError("payload and event limits must be positive")

    def ingest(
        self,
        payload: bytes,
        *,
        media_type: str,
        collected_at: datetime,
        ingested_at: datetime | None = None,
        content_encoding: str | None = None,
    ) -> tuple[NormalizedEvent, ...]:
        raw = self.evidence_store.put(
            payload,
            tenant_id=self.tenant_id,
            platform=Platform.KUBERNETES,
            source_instance_id=self.source_instance_id,
            media_type=media_type,
            collected_at=collected_at,
            content_encoding=content_encoding,
        )
        arrival = ingested_at or collected_at
        if len(payload) > self.max_payload_bytes:
            return (
                self._unparseable(
                    raw,
                    arrival,
                    0,
                    f"payload exceeds configured {self.max_payload_bytes}-byte raw limit",
                ),
            )
        try:
            decoded = self._decode(payload, media_type, content_encoding)
            items = _json_items(decoded)
        except (
            gzip.BadGzipFile,
            EOFError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            return (self._unparseable(raw, arrival, 0, str(exc)),)
        if len(items) > self.max_events_per_payload:
            return (
                self._unparseable(
                    raw,
                    arrival,
                    0,
                    f"payload contains more than {self.max_events_per_payload} audit events",
                ),
            )

        events: list[NormalizedEvent] = []
        for ordinal, item in enumerate(items):
            if isinstance(item, _InvalidRecord):
                events.append(self._unparseable(raw, arrival, ordinal, item.reason))
            elif not _json_depth_is_safe(item):
                events.append(
                    self._unparseable(
                        raw,
                        arrival,
                        ordinal,
                        f"record exceeds {MAX_JSON_NESTING_DEPTH}-level JSON depth limit",
                    )
                )
            else:
                events.append(self._normalize(raw, item, ordinal, arrival))
        return tuple(events) or (
            self._unparseable(raw, arrival, 0, "payload contains no audit events"),
        )

    def _decode(
        self, payload: bytes, media_type: str, content_encoding: str | None
    ) -> bytes:
        encoding = (_text(content_encoding, max_bytes=64) or "").casefold()
        media = (_text(media_type, max_bytes=128) or "").casefold()
        compressed = payload.startswith(b"\x1f\x8b") or encoding in {
            "gzip",
            "x-gzip",
        } or media in {"application/gzip", "application/x-gzip"}
        if not compressed:
            return payload
        with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as archive:
            decoded = archive.read(self.max_decompressed_bytes + 1)
        if len(decoded) > self.max_decompressed_bytes:
            raise ValueError(
                "gzip payload exceeds configured "
                f"{self.max_decompressed_bytes}-byte decompressed limit"
            )
        return decoded

    def _event_id(self, identity: str) -> str:
        material = f"{self.tenant_id}\x00{self.source_instance_id}\x00{identity}"
        return "k8s:" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _unparseable(
        self,
        raw: RawEvidenceRef,
        ingested_at: datetime,
        ordinal: int,
        warning: str,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=self._event_id(f"raw:{raw.sha256}:{ordinal}"),
            tenant_id=self.tenant_id,
            platform=Platform.KUBERNETES,
            source_type="kubernetes_audit",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            ingested_at=ingested_at,
            event_time_quality=EventTimeQuality.UNKNOWN,
            parse_status=ParseStatus.UNPARSEABLE,
            raw_evidence=raw,
            attributes={},
            parse_warnings=(warning,),
        )

    def _normalize(
        self,
        raw: RawEvidenceRef,
        record: Mapping[str, Any],
        ordinal: int,
        ingested_at: datetime,
    ) -> NormalizedEvent:
        api_version = _text(_mapping_get(record, "apiVersion"), max_bytes=128)
        kind = _text(_mapping_get(record, "kind"), max_bytes=64)
        if api_version != SUPPORTED_API_VERSION or kind != "Event":
            return self._unparseable(
                raw,
                ingested_at,
                ordinal,
                "record is not a supported audit.k8s.io/v1 Event",
            )

        warnings: list[str] = []
        audit_id = _identifier(_mapping_get(record, "auditID"))
        if audit_id is None:
            warnings.append("auditID is missing, invalid, or too long")
        stage = _text(_mapping_get(record, "stage"), max_bytes=64)
        if stage not in SUPPORTED_STAGES:
            warnings.append("audit stage is missing or unsupported")
        level = _text(_mapping_get(record, "level"), max_bytes=64)
        if level not in SUPPORTED_LEVELS:
            warnings.append("audit level is missing or unsupported")

        received_at = _timestamp(_mapping_get(record, "requestReceivedTimestamp"))
        stage_at = _timestamp(_mapping_get(record, "stageTimestamp"))
        observed_at = stage_at or received_at
        if observed_at is None:
            observed_at = ingested_at
            time_quality = EventTimeQuality.COLLECTOR_ASSIGNED
            warnings.append("audit timestamps are missing or invalid")
        else:
            time_quality = EventTimeQuality.SOURCE_REPORTED
        if received_at is None:
            warnings.append("requestReceivedTimestamp is missing or invalid")
        if stage_at is None:
            warnings.append("stageTimestamp is missing or invalid")
        elif received_at is not None and stage_at < received_at:
            warnings.append("stageTimestamp precedes requestReceivedTimestamp")

        verb = _text(_mapping_get(record, "verb"), max_bytes=256)
        if verb is None:
            warnings.append("verb is missing or invalid")
        raw_uri = _text(_mapping_get(record, "requestURI"))
        request_path: str | None = None
        query_present = False
        if raw_uri is None:
            warnings.append("requestURI is missing, invalid, or too long")
        else:
            try:
                parsed_uri = urlsplit(raw_uri)
            except ValueError:
                warnings.append("requestURI cannot be parsed safely")
            else:
                if parsed_uri.scheme or parsed_uri.netloc:
                    warnings.append("requestURI is not relative to the API server")
                request_path = parsed_uri.path or "/"
                query_present = bool(parsed_uri.query)

        user = _mapping_get(record, "user")
        user = user if isinstance(user, Mapping) else {}
        username = _identifier(_mapping_get(user, "username"))
        user_uid = _identifier(_mapping_get(user, "uid"))
        if username is None:
            warnings.append("authenticated user name is missing or invalid")
        groups, groups_limited = _bounded_strings(
            _mapping_get(user, "groups"), limit=MAX_USER_GROUPS
        )
        if groups_limited:
            warnings.append("authenticated user groups are invalid or truncated")

        impersonated = _mapping_get(record, "impersonatedUser")
        impersonated = impersonated if isinstance(impersonated, Mapping) else {}
        impersonated_name = _identifier(_mapping_get(impersonated, "username"))
        impersonated_uid = _identifier(_mapping_get(impersonated, "uid"))
        impersonated_groups, impersonated_groups_limited = _bounded_strings(
            _mapping_get(impersonated, "groups"), limit=MAX_USER_GROUPS
        )
        if impersonated_groups_limited:
            warnings.append("impersonated user groups are invalid or truncated")

        source_ips, source_ips_limited = _bounded_strings(
            _mapping_get(record, "sourceIPs"), limit=MAX_SOURCE_IPS
        )
        if source_ips_limited:
            warnings.append("source IPs are invalid or truncated")
        transport_peer = source_ips[-1] if source_ips else None
        forwarded_source_ips = source_ips[:-1]

        object_ref = _mapping_get(record, "objectRef")
        object_ref = object_ref if isinstance(object_ref, Mapping) else {}
        raw_object_uid = _mapping_get(object_ref, "uid")
        object_uid = _identifier(raw_object_uid)
        object_uid_source = "objectRef" if object_uid else None
        if raw_object_uid is not None and object_uid is None:
            warnings.append("objectRef.uid is invalid or too long")
        if object_uid is None:
            object_uid = _metadata_uid(_mapping_get(record, "responseObject"))
            if object_uid:
                object_uid_source = "responseObject.metadata"

        response_status = _mapping_get(record, "responseStatus")
        response_status = response_status if isinstance(response_status, Mapping) else {}
        response_code = _integer(_mapping_get(response_status, "code"))
        if response_code is not None and not 100 <= response_code <= 599:
            warnings.append("responseStatus.code is outside the HTTP status range")
            response_code = None
        outcome = "unknown"
        if stage == "Panic":
            outcome = "failure"
        elif response_code is not None:
            outcome = "success" if 200 <= response_code < 400 else "failure"

        annotations, annotations_omitted = _safe_annotations(
            _mapping_get(record, "annotations")
        )
        authentication_metadata = _mapping_get(record, "authenticationMetadata")
        authentication_metadata = (
            authentication_metadata
            if isinstance(authentication_metadata, Mapping)
            else {}
        )

        keys: list[EntityKey] = []
        for key_kind, key_value in (
            ("kubernetes_audit_id", audit_id),
            ("kubernetes_user_uid", user_uid),
            ("kubernetes_user_name", username),
            ("kubernetes_impersonated_user_uid", impersonated_uid),
            ("kubernetes_impersonated_user_name", impersonated_name),
            ("kubernetes_object_uid", object_uid),
        ):
            if key_value:
                keys.append(EntityKey(key_kind, key_value, self.cluster_uid))

        request_body_present = _mapping_get(record, "requestObject") is not None
        response_body_present = _mapping_get(record, "responseObject") is not None
        attributes = {
            "event": {
                "provider": "kubernetes_audit",
                "api_version": api_version,
                "audit_id": audit_id,
                "stage": stage,
                "level": level,
                "outcome": outcome,
                "request_received_at": received_at.isoformat() if received_at else None,
                "stage_at": stage_at.isoformat() if stage_at else None,
            },
            "cluster": {
                "uid": self.cluster_uid,
                "source_instance_id": self.source_instance_id,
            },
            "request": {
                "verb": verb,
                "path": request_path,
                "query_present": query_present,
                "body_present": request_body_present,
            },
            "response": {
                "code": response_code,
                "status": _text(_mapping_get(response_status, "status"), max_bytes=256),
                "reason": _text(_mapping_get(response_status, "reason"), max_bytes=512),
                "body_present": response_body_present,
            },
            "identity": {
                "user_name": username,
                "user_uid": user_uid,
                "groups": groups,
                "extra_present_but_omitted": _mapping_get(user, "extra") is not None,
                "impersonated_user_name": impersonated_name,
                "impersonated_user_uid": impersonated_uid,
                "impersonated_groups": impersonated_groups,
                "impersonation_constraint": _text(
                    _mapping_get(authentication_metadata, "impersonationConstraint"),
                    max_bytes=256,
                ),
            },
            "network": {
                "transport_peer": transport_peer,
                "forwarded_source_ips_untrusted": forwarded_source_ips,
                "user_agent_untrusted": _text(_mapping_get(record, "userAgent")),
            },
            "object": {
                "api_group": _text(_mapping_get(object_ref, "apiGroup"), max_bytes=512),
                "api_version": _text(
                    _mapping_get(object_ref, "apiVersion"), max_bytes=512
                ),
                "resource": _text(_mapping_get(object_ref, "resource"), max_bytes=512),
                "subresource": _text(
                    _mapping_get(object_ref, "subresource"), max_bytes=512
                ),
                "namespace": _text(
                    _mapping_get(object_ref, "namespace"),
                    max_bytes=MAX_IDENTIFIER_BYTES,
                ),
                "name": _text(
                    _mapping_get(object_ref, "name"), max_bytes=MAX_IDENTIFIER_BYTES
                ),
                "uid": object_uid,
                "uid_source": object_uid_source,
                "resource_version": _identifier(
                    _mapping_get(object_ref, "resourceVersion")
                ),
            },
            "authorization": annotations,
            "evidence": {
                "request_body_omitted": request_body_present,
                "response_body_omitted": response_body_present,
                "other_annotations_omitted": annotations_omitted,
            },
        }
        fingerprint = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        identity = (
            f"audit:{audit_id or 'missing'}:{stage or 'missing'}:"
            f"{stage_at.isoformat() if stage_at else 'missing'}:{fingerprint}:"
            f"raw:{raw.sha256}:{ordinal}"
        )
        return NormalizedEvent(
            event_id=self._event_id(identity),
            tenant_id=self.tenant_id,
            platform=Platform.KUBERNETES,
            source_type="kubernetes_audit",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            observed_at=observed_at,
            ingested_at=ingested_at,
            event_time_quality=time_quality,
            parse_status=ParseStatus.PARTIAL if warnings else ParseStatus.PARSED,
            raw_evidence=raw,
            native_event_id=audit_id,
            native_sequence=None,
            entity_keys=tuple(keys),
            attributes=attributes,
            parse_warnings=tuple(warnings),
        )
