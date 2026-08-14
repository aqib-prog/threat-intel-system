"""macOS Endpoint Security and Elastic ECS normalization adapter.

The adapter accepts two deliberately separate source contracts:

* JSON Lines produced by Apple's ``eslogger`` prototype collector. Apple
  explicitly documents that this JSON is not a stable API, so parsing is
  conservative, records the JSON ``schema_version`` and Endpoint Security
  message ``version``, and gates fields by the message version documented in
  ``ESMessage.h``.
* Elastic Common Schema endpoint events, including the real Elastic Endpoint
  telemetry used by this project's macOS validation corpus.

Endpoint Security process identity is the boot-scoped ``(pid, pidversion)``
tuple decoded from an audit token. Sequence numbers are collector-loss
signals, not entity identities, and are scoped to an explicit collector
instance so a restart cannot create false continuity.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from correlation.models import (
    EntityKey,
    EventTimeQuality,
    NormalizedEvent,
    ParseStatus,
    Platform,
    RawEvidenceRef,
)
from correlation.ports import RawEvidenceStore


MACOS_ADAPTER_VERSION = "1.0.0"
DEFAULT_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024


def _text(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered if rendered and rendered != "-" else None


def _integer(value: Any) -> int | None:
    rendered = _text(value)
    if rendered is None:
        return None
    try:
        return int(rendered, 0)
    except ValueError:
        return None


def _mapping_get(value: Mapping[str, Any], name: str) -> Any:
    wanted = name.casefold()
    for key, child in value.items():
        if str(key).casefold() == wanted:
            return child
    return None


def _path(value: Mapping[str, Any], dotted: str) -> Any:
    current: Any = value
    for part in dotted.split("."):
        if not isinstance(current, Mapping):
            return None
        current = _mapping_get(current, part)
    return current


def _first(record: Mapping[str, Any], *paths: str) -> Any:
    for candidate in paths:
        value = _path(record, candidate)
        if value is not None and _text(value) is not None:
            return value
    return None


def _compact(value: Any) -> Any:
    if isinstance(value, Mapping):
        result = {
            str(key): _compact(child)
            for key, child in value.items()
            if child is not None
        }
        return {key: child for key, child in result.items() if child not in ({}, [])}
    if isinstance(value, (list, tuple)):
        result = [_compact(child) for child in value if child is not None]
        return [child for child in result if child not in ({}, [])]
    return value


def _iso_timestamp(value: Any) -> datetime | None:
    rendered = _text(value)
    if rendered is None:
        return None
    try:
        parsed = datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _es_timestamp(value: Any) -> datetime | None:
    parsed = _iso_timestamp(value)
    if parsed is not None:
        return parsed
    if not isinstance(value, Mapping):
        return None
    seconds = _integer(
        _mapping_get(value, "sec")
        if _mapping_get(value, "sec") is not None
        else _mapping_get(value, "seconds")
    )
    nanoseconds = _integer(
        _mapping_get(value, "nsec")
        if _mapping_get(value, "nsec") is not None
        else _mapping_get(value, "nanoseconds")
    )
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds + (nanoseconds or 0) / 1_000_000_000, timezone.utc)


def _json_items(payload: bytes) -> list[Mapping[str, Any] | None]:
    decoded = payload.decode("utf-8")
    try:
        parsed = json.loads(decoded)
    except json.JSONDecodeError:
        items: list[Mapping[str, Any] | None] = []
        for line in decoded.splitlines():
            if not line.strip():
                continue
            try:
                child = json.loads(line)
            except json.JSONDecodeError:
                items.append(None)
                continue
            items.append(child if isinstance(child, Mapping) else None)
        if not items:
            raise
        return items
    if isinstance(parsed, Mapping):
        for key in ("events", "Events", "records", "Records"):
            children = _mapping_get(parsed, key)
            if isinstance(children, list):
                return [child if isinstance(child, Mapping) else None for child in children]
        return [parsed]
    if isinstance(parsed, list):
        return [child if isinstance(child, Mapping) else None for child in parsed]
    return [None]


def _audit_token(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    pid = _integer(_mapping_get(value, "pid"))
    pidversion = _integer(_mapping_get(value, "pidversion"))
    if pid is None or pidversion is None or pid < 0 or pidversion < 0:
        return None
    return str(pid), str(pidversion)


def _es_event_name(record: Mapping[str, Any]) -> str | None:
    event = _path(record, "event")
    if isinstance(event, Mapping):
        names = [str(key).casefold() for key in event if str(key).strip()]
        if len(names) == 1:
            return names[0]
    rendered = _text(_mapping_get(record, "event_type"))
    if rendered is None:
        return None
    normalized = rendered.casefold()
    for prefix in ("es_event_type_notify_", "notify_"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
    return normalized


def _es_event_payload(record: Mapping[str, Any], event_name: str | None) -> Mapping[str, Any]:
    event = _path(record, "event")
    if not isinstance(event, Mapping) or event_name is None:
        return {}
    child = _mapping_get(event, event_name)
    return child if isinstance(child, Mapping) else {}


def _es_process_view(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    token = _audit_token(_mapping_get(value, "audit_token"))
    executable = _path(value, "executable.path")
    result: dict[str, Any] = {
        "pid": token[0] if token else None,
        "pidversion": token[1] if token else None,
        "ppid": _integer(_mapping_get(value, "ppid")),
        "original_ppid": _integer(_mapping_get(value, "original_ppid")),
        "executable": _text(executable),
        "signing_id": _text(_mapping_get(value, "signing_id")),
        "team_id": _text(_mapping_get(value, "team_id")),
        "is_platform_binary": _mapping_get(value, "is_platform_binary"),
    }
    return _compact(result)


@dataclass(frozen=True, slots=True)
class MacOSAdapter:
    evidence_store: RawEvidenceStore
    tenant_id: str
    source_instance_id: str
    boot_id: str
    collector_instance_id: str
    adapter_version: str = MACOS_ADAPTER_VERSION
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "source_instance_id",
            "boot_id",
            "collector_instance_id",
            "adapter_version",
        ):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"{name} must not be empty")
        if self.max_payload_bytes < 1:
            raise ValueError("max_payload_bytes must be positive")

    @property
    def _host_scope(self) -> str:
        return f"{self.source_instance_id}:{self.boot_id}"

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
            platform=Platform.MACOS,
            source_instance_id=self.source_instance_id,
            media_type=media_type,
            collected_at=collected_at,
            content_encoding=content_encoding,
        )
        accepted_at = ingested_at or collected_at
        if len(payload) > self.max_payload_bytes:
            return (
                self._unparseable(
                    raw,
                    accepted_at,
                    0,
                    f"payload exceeds configured {self.max_payload_bytes}-byte parse limit",
                ),
            )
        try:
            items = _json_items(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return (self._unparseable(raw, accepted_at, 0, str(exc)),)

        events: list[NormalizedEvent] = []
        for ordinal, item in enumerate(items):
            if item is None:
                events.append(
                    self._unparseable(raw, accepted_at, ordinal, "record is not an object")
                )
            elif self._is_eslogger(item):
                events.append(self._normalize_eslogger(raw, item, ordinal, accepted_at))
            elif self._is_elastic_ecs(item):
                events.append(self._normalize_ecs(raw, item, ordinal, accepted_at))
            else:
                events.append(
                    self._unparseable(
                        raw,
                        accepted_at,
                        ordinal,
                        "record is neither Endpoint Security eslogger nor macOS Elastic ECS telemetry",
                    )
                )
        return tuple(events) or (
            self._unparseable(raw, accepted_at, 0, "payload contains no event records"),
        )

    @staticmethod
    def _is_eslogger(record: Mapping[str, Any]) -> bool:
        return (
            _mapping_get(record, "schema_version") is not None
            and isinstance(_path(record, "process.audit_token"), Mapping)
            and isinstance(_mapping_get(record, "event"), Mapping)
        )

    @staticmethod
    def _is_elastic_ecs(record: Mapping[str, Any]) -> bool:
        source = _mapping_get(record, "_source")
        candidate = source if isinstance(source, Mapping) else record
        platform = _text(_first(candidate, "host.os.platform", "host.os.family"))
        dataset = _text(_first(candidate, "event.dataset", "data_stream.dataset"))
        has_event = isinstance(_mapping_get(candidate, "event"), Mapping)
        has_process = isinstance(_mapping_get(candidate, "process"), Mapping)
        return (
            platform is not None
            and platform.casefold() in {"macos", "darwin"}
            and dataset is not None
            and has_event
            and has_process
        )

    def _event_id(self, identity: str) -> str:
        material = f"{self.tenant_id}\x00{self.source_instance_id}\x00{identity}"
        return "macos:" + hashlib.sha256(material.encode()).hexdigest()

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
            platform=Platform.MACOS,
            source_type="macos_telemetry",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            ingested_at=ingested_at,
            event_time_quality=EventTimeQuality.UNKNOWN,
            parse_status=ParseStatus.UNPARSEABLE,
            raw_evidence=raw,
            attributes={},
            parse_warnings=(warning,),
        )

    def _process_keys(
        self,
        process: Mapping[str, Any],
        *,
        prefix: str = "process",
    ) -> list[EntityKey]:
        pid = _text(process.get("pid"))
        pidversion = _text(process.get("pidversion"))
        if pid is None:
            return []
        keys = [EntityKey(f"{prefix}_pid", pid, self._host_scope)]
        if pidversion is not None:
            keys.insert(
                0,
                EntityKey(
                    f"{prefix}_pidversion",
                    f"{pid}:{pidversion}",
                    self._host_scope,
                ),
            )
        return keys

    def _normalize_eslogger(
        self,
        raw: RawEvidenceRef,
        record: Mapping[str, Any],
        ordinal: int,
        ingested_at: datetime,
    ) -> NormalizedEvent:
        warnings: list[str] = []
        message_version = _integer(_mapping_get(record, "version"))
        schema_version = _text(_mapping_get(record, "schema_version"))
        if message_version is None:
            warnings.append("Endpoint Security message version is missing or invalid")
        if schema_version is None:
            warnings.append("eslogger JSON schema_version is missing")

        event_name = _es_event_name(record)
        event_payload = _es_event_payload(record, event_name)
        actor_source = _mapping_get(record, "process")
        actor_source = actor_source if isinstance(actor_source, Mapping) else {}
        actor = _es_process_view(actor_source)
        subject = actor
        subject_source = actor_source
        if event_name == "exec":
            target_source = _mapping_get(event_payload, "target")
            target_source = target_source if isinstance(target_source, Mapping) else {}
            target = _es_process_view(target_source)
            if target:
                subject = target
                subject_source = target_source
            else:
                warnings.append("exec event target process is missing or invalid")
        elif event_name == "fork":
            child_source = _mapping_get(event_payload, "child")
            child_source = child_source if isinstance(child_source, Mapping) else {}
            child = _es_process_view(child_source)
            if child:
                subject = child
                subject_source = child_source
            else:
                warnings.append("fork event child process is missing or invalid")

        seq_num: int | None = None
        global_seq_num: int | None = None
        if message_version is not None and message_version >= 2:
            seq_num = _integer(_mapping_get(record, "seq_num"))
            if seq_num is None:
                warnings.append("message version permits seq_num but it is missing")
        elif _mapping_get(record, "seq_num") is not None:
            warnings.append("ignored seq_num because message version is below 2")
        if message_version is not None and message_version >= 4:
            global_seq_num = _integer(_mapping_get(record, "global_seq_num"))
            if global_seq_num is None:
                warnings.append("message version permits global_seq_num but it is missing")
        elif _mapping_get(record, "global_seq_num") is not None:
            warnings.append("ignored global_seq_num because message version is below 4")

        parent: dict[str, Any] = {}
        responsible: dict[str, Any] = {}
        if message_version is not None and message_version >= 4:
            parent_token = _audit_token(_mapping_get(subject_source, "parent_audit_token"))
            responsible_token = _audit_token(
                _mapping_get(subject_source, "responsible_audit_token")
            )
            if parent_token:
                parent = {"pid": parent_token[0], "pidversion": parent_token[1]}
            if responsible_token:
                responsible = {
                    "pid": responsible_token[0],
                    "pidversion": responsible_token[1],
                }
        elif any(
            _mapping_get(subject_source, name) is not None
            for name in ("parent_audit_token", "responsible_audit_token")
        ):
            warnings.append(
                "ignored parent/responsible audit tokens because message version is below 4"
            )

        observed_at = _es_timestamp(_mapping_get(record, "time"))
        if observed_at is None:
            observed_at = ingested_at
            quality = EventTimeQuality.COLLECTOR_ASSIGNED
            warnings.append("source event timestamp is missing or invalid")
        else:
            quality = EventTimeQuality.SOURCE_REPORTED
        if event_name is None:
            warnings.append("Endpoint Security event name is missing or ambiguous")

        arguments = _mapping_get(event_payload, "args")
        command_line = None
        if isinstance(arguments, list):
            command_line = " ".join(str(value) for value in arguments)
        file_path = _text(
            _first(
                event_payload,
                "file.path",
                "target.path",
                "source.path",
                "destination.existing_file.path",
            )
        )
        attributes = _compact(
            {
                "event": {
                    "provider": "apple_endpoint_security",
                    "action": event_name,
                    "message_version": message_version,
                    "schema_version": schema_version,
                },
                "host": {"id": self.source_instance_id, "boot_id": self.boot_id},
                "collector": {
                    "instance_id": self.collector_instance_id,
                    "seq_num": seq_num,
                    "global_seq_num": global_seq_num,
                },
                "process": {
                    **subject,
                    "command_line": command_line,
                    "parent": parent,
                    "responsible": responsible,
                },
                "initiator": actor if subject != actor else None,
                "file": {"path": file_path},
                # UIPC and XPC are retained as their actual IPC types. They are
                # intentionally not promoted to TCP/UDP network telemetry.
                "ipc": {
                    "type": event_name if event_name in {"uipc_bind", "uipc_connect", "xpc_connect"} else None,
                    "service_name": _text(_mapping_get(event_payload, "service_name")),
                },
            }
        )
        keys = self._process_keys(subject)
        if subject != actor:
            keys.extend(self._process_keys(actor, prefix="initiator_process"))
        keys.extend(self._process_keys(parent, prefix="parent_process"))
        keys.extend(self._process_keys(responsible, prefix="responsible_process"))
        fingerprint = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        native_sequence = (
            str(global_seq_num) if global_seq_num is not None else str(seq_num) if seq_num is not None else None
        )
        identity = (
            f"es:{self.collector_instance_id}:{event_name or 'unknown'}:"
            f"{native_sequence or 'missing'}:{fingerprint}:raw:{raw.sha256}"
        )
        return NormalizedEvent(
            event_id=self._event_id(identity),
            tenant_id=self.tenant_id,
            platform=Platform.MACOS,
            source_type="endpoint_security_eslogger",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            observed_at=observed_at,
            ingested_at=ingested_at,
            event_time_quality=quality,
            parse_status=ParseStatus.PARTIAL if warnings else ParseStatus.PARSED,
            raw_evidence=raw,
            native_event_id=event_name,
            native_sequence=native_sequence,
            entity_keys=tuple(keys),
            attributes=attributes,
            parse_warnings=tuple(warnings),
        )

    def _normalize_ecs(
        self,
        raw: RawEvidenceRef,
        record: Mapping[str, Any],
        ordinal: int,
        ingested_at: datetime,
    ) -> NormalizedEvent:
        source = _mapping_get(record, "_source")
        event = source if isinstance(source, Mapping) else record
        warnings: list[str] = []
        observed_at = _iso_timestamp(_first(event, "@timestamp", "event.created"))
        if observed_at is None:
            observed_at = ingested_at
            quality = EventTimeQuality.COLLECTOR_ASSIGNED
            warnings.append("source event timestamp is missing or invalid")
        else:
            quality = EventTimeQuality.SOURCE_REPORTED

        process_entity_id = _text(_first(event, "process.entity_id"))
        parent_entity_id = _text(_first(event, "process.parent.entity_id"))
        pid = _integer(_first(event, "process.pid"))
        ppid = _integer(_first(event, "process.parent.pid", "process.ppid"))
        action = _text(_first(event, "event.action"))
        event_id = _text(_first(event, "event.id"))
        sequence = _text(_first(event, "event.sequence"))
        if process_entity_id is None:
            warnings.append("ECS process.entity_id is missing")
        args = _path(event, "process.args")
        command_line = _text(_first(event, "process.command_line"))
        if command_line is None and isinstance(args, list):
            command_line = " ".join(str(value) for value in args)

        attributes = _compact(
            {
                "event": {
                    "provider": _text(_first(event, "event.provider", "event.module")),
                    "dataset": _text(_first(event, "event.dataset", "data_stream.dataset")),
                    "category": _path(event, "event.category"),
                    "type": _path(event, "event.type"),
                    "action": action,
                    "outcome": _text(_first(event, "event.outcome")),
                },
                "host": {"id": self.source_instance_id, "boot_id": self.boot_id},
                "process": {
                    "entity_id": process_entity_id,
                    "pid": str(pid) if pid is not None else None,
                    "name": _text(_first(event, "process.name")),
                    "executable": _text(_first(event, "process.executable")),
                    "command_line": command_line,
                    "parent": {
                        "entity_id": parent_entity_id,
                        "pid": str(ppid) if ppid is not None else None,
                        "name": _text(_first(event, "process.parent.name")),
                        "executable": _text(_first(event, "process.parent.executable")),
                    },
                },
                "user": {
                    "id": _text(_first(event, "user.id")),
                    "name": _text(_first(event, "user.name")),
                },
                "file": {"path": _text(_first(event, "file.path"))},
                "network": {
                    "transport": _text(_first(event, "network.transport")),
                    "direction": _text(_first(event, "network.direction")),
                    "source": {
                        "ip": _text(_first(event, "source.ip")),
                        "port": _integer(_first(event, "source.port")),
                    },
                    "destination": {
                        "ip": _text(_first(event, "destination.ip")),
                        "port": _integer(_first(event, "destination.port")),
                    },
                },
            }
        )
        keys: list[EntityKey] = []
        if process_entity_id:
            keys.append(EntityKey("process_entity_id", process_entity_id, self._host_scope))
        if parent_entity_id:
            keys.append(
                EntityKey("parent_process_entity_id", parent_entity_id, self._host_scope)
            )
        if pid is not None:
            keys.append(EntityKey("process_pid", str(pid), self._host_scope))
        if ppid is not None:
            keys.append(EntityKey("parent_process_pid", str(ppid), self._host_scope))

        fingerprint = hashlib.sha256(
            json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        identity = (
            f"ecs:{event_id or 'missing'}:{sequence or 'missing'}:"
            f"{fingerprint}:raw:{raw.sha256}"
        )
        return NormalizedEvent(
            event_id=self._event_id(identity),
            tenant_id=self.tenant_id,
            platform=Platform.MACOS,
            source_type="elastic_endpoint",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            observed_at=observed_at,
            ingested_at=ingested_at,
            event_time_quality=quality,
            parse_status=ParseStatus.PARTIAL if warnings else ParseStatus.PARSED,
            raw_evidence=raw,
            native_event_id=event_id,
            native_sequence=sequence,
            entity_keys=tuple(keys),
            attributes=attributes,
            parse_warnings=tuple(warnings),
        )
