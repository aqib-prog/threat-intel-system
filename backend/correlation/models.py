"""Versioned contracts shared by replay and live correlation.

The contracts deliberately contain no Kafka, Kinesis, Redis, RocksDB, or
filesystem assumptions.  Local development and production transports must
carry the same envelope unchanged.

Raw telemetry is never embedded in a :class:`NormalizedEvent`.  It must be
durably written first and referenced by content hash so parser failures cannot
erase the original evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


CORRELATION_EVENT_SCHEMA_VERSION = "1.0.0"
_SHA256_HEX_LENGTH = 64


class Platform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    AWS = "aws"
    KUBERNETES = "kubernetes"


class EventTimeQuality(str, Enum):
    """How trustworthy the event's occurrence timestamp is.

    This is separate from correlation confidence. A source-reported timestamp
    can still be skewed; a collector timestamp is an explicit fallback, not a
    fabricated source timestamp.
    """

    SOURCE_REPORTED = "source_reported"
    COLLECTOR_ASSIGNED = "collector_assigned"
    UNKNOWN = "unknown"


class ParseStatus(str, Enum):
    PARSED = "parsed"
    PARTIAL = "partial"
    UNPARSEABLE = "unparseable"


def _required_text(value: str, field_name: str) -> str:
    rendered = str(value or "").strip()
    if not rendered:
        raise ValueError(f"{field_name} must not be empty")
    return rendered


def _utc_datetime(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _parse_datetime(value: Any, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 datetime") from exc
    return _utc_datetime(parsed, field_name)


def _validate_sha256(value: str) -> str:
    digest = str(value or "").strip().lower()
    if len(digest) != _SHA256_HEX_LENGTH or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ValueError("sha256 must be a 64-character lowercase hex digest")
    return digest


def _freeze_json(value: Any) -> Any:
    """Copy JSON-like values into immutable containers.

    Adapters may reuse and mutate their input dictionaries after publishing an
    event.  Copying here prevents those mutations from silently changing an
    already accepted event.
    """

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_json(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    raise TypeError(
        "normalized attributes must contain only JSON-compatible values; "
        f"got {type(value).__name__}"
    )


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


@dataclass(frozen=True, slots=True)
class RawEvidenceRef:
    """Content-addressed pointer to the exact bytes received from a sensor."""

    sha256: str
    uri: str
    byte_length: int
    media_type: str
    collected_at: datetime
    content_encoding: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "sha256", _validate_sha256(self.sha256))
        object.__setattr__(self, "uri", _required_text(self.uri, "uri"))
        object.__setattr__(
            self, "media_type", _required_text(self.media_type, "media_type")
        )
        if self.byte_length < 0:
            raise ValueError("byte_length must be non-negative")
        object.__setattr__(
            self,
            "collected_at",
            _utc_datetime(self.collected_at, "collected_at"),
        )
        if self.content_encoding is not None:
            object.__setattr__(
                self,
                "content_encoding",
                _required_text(self.content_encoding, "content_encoding"),
            )

    @property
    def evidence_id(self) -> str:
        return f"sha256:{self.sha256}"

    @classmethod
    def for_bytes(
        cls,
        payload: bytes,
        *,
        uri: str,
        media_type: str,
        collected_at: datetime,
        content_encoding: str | None = None,
    ) -> RawEvidenceRef:
        return cls(
            sha256=hashlib.sha256(payload).hexdigest(),
            uri=uri,
            byte_length=len(payload),
            media_type=media_type,
            collected_at=collected_at,
            content_encoding=content_encoding,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "sha256": self.sha256,
            "uri": self.uri,
            "byte_length": self.byte_length,
            "media_type": self.media_type,
            "collected_at": self.collected_at.isoformat(),
            "content_encoding": self.content_encoding,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RawEvidenceRef:
        reference = cls(
            sha256=str(value.get("sha256") or ""),
            uri=str(value.get("uri") or ""),
            byte_length=int(value.get("byte_length", -1)),
            media_type=str(value.get("media_type") or ""),
            collected_at=_parse_datetime(value.get("collected_at"), "collected_at"),
            content_encoding=(
                str(value["content_encoding"])
                if value.get("content_encoding") is not None
                else None
            ),
        )
        claimed_id = value.get("evidence_id")
        if claimed_id is not None and str(claimed_id) != reference.evidence_id:
            raise ValueError("evidence_id does not match sha256")
        return reference


@dataclass(frozen=True, slots=True, order=True)
class EntityKey:
    """A tenant-scoped, platform-native correlation key.

    ``kind`` names the semantic key (for example ``process_guid``,
    ``cloud_request_id`` or ``kubernetes_audit_id``). ``scope`` prevents a
    locally unique value from being treated as globally unique; examples are a
    host boot identifier, AWS account/region, or Kubernetes cluster UID.

    Secret bearer tokens and credentials are forbidden as entity keys. Where a
    sensitive value is genuinely required, an adapter must publish a keyed HMAC
    and use a kind that explicitly ends in ``_hmac``.
    """

    kind: str
    value: str
    scope: str

    def __post_init__(self) -> None:
        kind = _required_text(self.kind, "entity key kind").casefold()
        value = _required_text(self.value, "entity key value")
        scope = _required_text(self.scope, "entity key scope")
        if any(token in kind for token in ("password", "secret", "bearer_token")):
            raise ValueError("secret material must not be stored as an entity key")
        # macOS ``audit_token`` is a kernel process identity structure, not an
        # authentication credential. Restrict this policy to credential/session
        # token kinds instead of rejecting every legitimate field containing
        # the word "token".
        if kind in {"access_token", "auth_token", "session_token"} and not kind.endswith(
            "_hmac"
        ):
            raise ValueError("token-derived entity keys must use a keyed HMAC")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "scope", scope)

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value, "scope": self.scope}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> EntityKey:
        return cls(
            kind=str(value.get("kind") or ""),
            value=str(value.get("value") or ""),
            scope=str(value.get("scope") or ""),
        )


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """Immutable production event envelope emitted by every platform adapter."""

    event_id: str
    tenant_id: str
    platform: Platform
    source_type: str
    source_instance_id: str
    adapter_version: str
    ingested_at: datetime
    event_time_quality: EventTimeQuality
    parse_status: ParseStatus
    raw_evidence: RawEvidenceRef
    observed_at: datetime | None = None
    native_event_id: str | None = None
    native_sequence: str | None = None
    entity_keys: tuple[EntityKey, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)
    parse_warnings: tuple[str, ...] = ()
    schema_version: str = CORRELATION_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for field_name in (
            "event_id",
            "tenant_id",
            "source_type",
            "source_instance_id",
            "adapter_version",
            "schema_version",
        ):
            object.__setattr__(
                self,
                field_name,
                _required_text(getattr(self, field_name), field_name),
            )
        if self.schema_version != CORRELATION_EVENT_SCHEMA_VERSION:
            raise ValueError(
                "unsupported correlation event schema_version: "
                f"{self.schema_version!r}"
            )
        if not isinstance(self.platform, Platform):
            raise TypeError("platform must be a Platform")
        if not isinstance(self.event_time_quality, EventTimeQuality):
            raise TypeError("event_time_quality must be an EventTimeQuality")
        if not isinstance(self.parse_status, ParseStatus):
            raise TypeError("parse_status must be a ParseStatus")
        if not isinstance(self.raw_evidence, RawEvidenceRef):
            raise TypeError("raw_evidence must be a RawEvidenceRef")
        object.__setattr__(
            self, "ingested_at", _utc_datetime(self.ingested_at, "ingested_at")
        )
        if self.observed_at is not None:
            object.__setattr__(
                self,
                "observed_at",
                _utc_datetime(self.observed_at, "observed_at"),
            )
        if self.event_time_quality is EventTimeQuality.SOURCE_REPORTED and (
            self.observed_at is None
        ):
            raise ValueError("source-reported event time requires observed_at")
        if self.event_time_quality is EventTimeQuality.UNKNOWN and (
            self.observed_at is not None
        ):
            raise ValueError("unknown event time must not carry observed_at")

        entity_keys = tuple(dict.fromkeys(self.entity_keys))
        if any(not isinstance(key, EntityKey) for key in entity_keys):
            raise TypeError("entity_keys must contain EntityKey values")
        object.__setattr__(self, "entity_keys", entity_keys)
        object.__setattr__(self, "attributes", _freeze_json(self.attributes))
        object.__setattr__(
            self,
            "parse_warnings",
            tuple(str(item).strip() for item in self.parse_warnings if str(item).strip()),
        )

        if self.parse_status is ParseStatus.PARSED and self.parse_warnings:
            raise ValueError("a fully parsed event cannot carry parse warnings")
        if self.parse_status is ParseStatus.UNPARSEABLE and self.attributes:
            raise ValueError("an unparseable event cannot claim normalized attributes")

        for optional_name in ("native_event_id", "native_sequence"):
            value = getattr(self, optional_name)
            if value is not None:
                object.__setattr__(
                    self,
                    optional_name,
                    _required_text(value, optional_name),
                )

    @property
    def effective_event_time(self) -> datetime:
        """Timestamp used for event-time processing without hiding fallback."""

        return self.observed_at or self.ingested_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "platform": self.platform.value,
            "source_type": self.source_type,
            "source_instance_id": self.source_instance_id,
            "adapter_version": self.adapter_version,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "ingested_at": self.ingested_at.isoformat(),
            "event_time_quality": self.event_time_quality.value,
            "parse_status": self.parse_status.value,
            "raw_evidence": self.raw_evidence.to_dict(),
            "native_event_id": self.native_event_id,
            "native_sequence": self.native_sequence,
            "entity_keys": [key.to_dict() for key in self.entity_keys],
            "attributes": _thaw_json(self.attributes),
            "parse_warnings": list(self.parse_warnings),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> NormalizedEvent:
        schema_version = str(value.get("schema_version") or "")
        if schema_version != CORRELATION_EVENT_SCHEMA_VERSION:
            raise ValueError(
                "unsupported correlation event schema_version: "
                f"{schema_version!r}"
            )
        raw_value = value.get("raw_evidence")
        if not isinstance(raw_value, Mapping):
            raise ValueError("raw_evidence must be an object")
        raw_keys = value.get("entity_keys", ())
        if not isinstance(raw_keys, (list, tuple)):
            raise ValueError("entity_keys must be a list")
        if any(not isinstance(item, Mapping) for item in raw_keys):
            raise ValueError("every entity_keys entry must be an object")
        attributes = value.get("attributes", {})
        if not isinstance(attributes, Mapping):
            raise ValueError("attributes must be an object")
        warnings = value.get("parse_warnings", ())
        if not isinstance(warnings, (list, tuple)):
            raise ValueError("parse_warnings must be a list")

        observed_at = value.get("observed_at")
        return cls(
            schema_version=schema_version,
            event_id=str(value.get("event_id") or ""),
            tenant_id=str(value.get("tenant_id") or ""),
            platform=Platform(str(value.get("platform") or "")),
            source_type=str(value.get("source_type") or ""),
            source_instance_id=str(value.get("source_instance_id") or ""),
            adapter_version=str(value.get("adapter_version") or ""),
            observed_at=(
                _parse_datetime(observed_at, "observed_at")
                if observed_at is not None
                else None
            ),
            ingested_at=_parse_datetime(value.get("ingested_at"), "ingested_at"),
            event_time_quality=EventTimeQuality(
                str(value.get("event_time_quality") or "")
            ),
            parse_status=ParseStatus(str(value.get("parse_status") or "")),
            raw_evidence=RawEvidenceRef.from_dict(raw_value),
            native_event_id=(
                str(value["native_event_id"])
                if value.get("native_event_id") is not None
                else None
            ),
            native_sequence=(
                str(value["native_sequence"])
                if value.get("native_sequence") is not None
                else None
            ),
            entity_keys=tuple(
                EntityKey.from_dict(item)
                for item in raw_keys
            ),
            attributes=attributes,
            parse_warnings=tuple(str(item) for item in warnings),
        )
