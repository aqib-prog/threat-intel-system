"""Linux audit and Sysmon for Linux normalization adapter.

Linux Audit compound events are deliberately emitted one record at a time.
Records with the same audit timestamp/serial receive the same
``audit_event_serial`` entity key so the production correlation engine—not a
batch-only parser—can assemble them consistently during both replay and live
streaming. The serial is never treated as a persistent process identity.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from correlation.models import (
    EntityKey,
    EventTimeQuality,
    NormalizedEvent,
    ParseStatus,
    Platform,
    RawEvidenceRef,
)
from correlation.ports import RawEvidenceStore
from correlation.sysmon import SYSMON_ACTIONS


LINUX_ADAPTER_VERSION = "1.0.0"
DEFAULT_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
_AUDIT_HEADER_RE = re.compile(
    r"^(?:node=\S+\s+)?type=(?P<record_type>[A-Z0-9_]+)\s+"
    r"msg=audit\((?P<timestamp>\d+(?:\.\d+)?):(?P<serial>\d+)\)"
    r"\s*:?[ ]*(?P<body>.*)$"
)
_AUDIT_FIELD_RE = re.compile(
    r"(?<!\S)(?P<key>[A-Za-z_][A-Za-z0-9_]*)="
    r"(?P<value>\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s]+)"
)
_GUID_RE = re.compile(
    r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$",
    re.IGNORECASE,
)
_UNSET_AUDIT_IDS = {"-1", "4294967295", "unset"}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    if len(rendered) >= 2 and rendered[0] == rendered[-1] and rendered[0] in "\"'":
        rendered = rendered[1:-1]
    return rendered if rendered and rendered != "-" else None


def _integer(value: Any) -> str | None:
    rendered = _text(value)
    if rendered is None:
        return None
    try:
        return str(int(rendered, 0))
    except ValueError:
        return None


def _guid(value: Any) -> str | None:
    rendered = _text(value)
    return rendered.casefold() if rendered and _GUID_RE.match(rendered) else None


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
    if isinstance(value, list):
        result = [_compact(child) for child in value if child is not None]
        return [child for child in result if child not in ({}, [])]
    return value


def _iso_timestamp(value: Any, *, utc_without_offset: bool = False) -> datetime | None:
    rendered = _text(value)
    if rendered is None:
        return None
    try:
        parsed = datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        if not utc_without_offset:
            return None
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _audit_timestamp(value: str) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _decode_hex_text(value: str | None) -> str | None:
    rendered = _text(value)
    if rendered is None or len(rendered) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", rendered):
        return rendered
    try:
        decoded = bytes.fromhex(rendered).replace(b"\x00", b" ").decode(
            "utf-8", errors="strict"
        )
    except (ValueError, UnicodeDecodeError):
        return rendered
    decoded = " ".join(decoded.split())
    return decoded if decoded and decoded.isprintable() else rendered


def _audit_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in _AUDIT_FIELD_RE.finditer(line):
        key = match.group("key")
        value = _text(match.group("value"))
        if value is not None:
            fields[key] = value
    return fields


def _audit_command(record_type: str, fields: Mapping[str, str]) -> str | None:
    if record_type == "PROCTITLE":
        return _decode_hex_text(fields.get("proctitle"))
    if record_type != "EXECVE":
        return None
    arguments: list[tuple[int, str]] = []
    for key, value in fields.items():
        match = re.fullmatch(r"a(\d+)", key)
        if match:
            arguments.append((int(match.group(1)), _decode_hex_text(value) or value))
    return " ".join(value for _, value in sorted(arguments)) or None


def _parse_xml_records(payload: bytes) -> list[dict[str, Any]]:
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("XML document types and entities are not allowed")
    # Sysmon for Linux commonly prefixes the XML with a syslog header.
    start = payload.find(b"<Event")
    if start < 0:
        raise ValueError("XML contains no Event element")
    root = ET.fromstring(payload[start:])
    events = [root] if root.tag.rsplit("}", 1)[-1] == "Event" else [
        item for item in root.iter() if item.tag.rsplit("}", 1)[-1] == "Event"
    ]
    records: list[dict[str, Any]] = []
    for event in events:
        system: dict[str, Any] = {}
        event_data: dict[str, Any] = {}
        for child in event:
            local = child.tag.rsplit("}", 1)[-1]
            if local == "System":
                for item in child:
                    name = item.tag.rsplit("}", 1)[-1]
                    system[name] = dict(item.attrib) if item.attrib else item.text
            elif local == "EventData":
                unnamed = 0
                for item in child:
                    if item.tag.rsplit("}", 1)[-1] != "Data":
                        continue
                    name = item.attrib.get("Name") or f"unnamed_{unnamed}"
                    unnamed += 1
                    event_data[name] = item.text or ""
        records.append({"System": system, "EventData": event_data})
    return records


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
                item = json.loads(line)
            except json.JSONDecodeError:
                items.append(None)
                continue
            items.append(item if isinstance(item, Mapping) else None)
        if not items:
            raise
        return items
    if isinstance(parsed, Mapping):
        for key in ("records", "Records", "events", "Events"):
            children = _mapping_get(parsed, key)
            if isinstance(children, list):
                return [item if isinstance(item, Mapping) else None for item in children]
        return [parsed]
    if isinstance(parsed, list):
        return [item if isinstance(item, Mapping) else None for item in parsed]
    return [None]


@dataclass(frozen=True, slots=True)
class LinuxAdapter:
    evidence_store: RawEvidenceStore
    tenant_id: str
    source_instance_id: str
    boot_id: str
    adapter_version: str = LINUX_ADAPTER_VERSION
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES

    def __post_init__(self) -> None:
        for name in ("tenant_id", "source_instance_id", "boot_id", "adapter_version"):
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
            platform=Platform.LINUX,
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
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            return (self._unparseable(raw, accepted_at, 0, str(exc)),)

        stripped = text.strip()
        if "<Event" in stripped:
            try:
                records: Sequence[Mapping[str, Any] | None] = _parse_xml_records(payload)
            except (ET.ParseError, ValueError) as exc:
                return (self._unparseable(raw, accepted_at, 0, str(exc)),)
            return tuple(
                self._normalize_sysmon(raw, record, ordinal, accepted_at)
                for ordinal, record in enumerate(records)
                if record is not None
            )

        # Native audit.log is line-oriented. Keeping one envelope per record
        # avoids batch-only grouping behavior and permits interlaced records.
        native_lines = [line.strip() for line in text.splitlines() if line.strip()]
        if native_lines and any(_AUDIT_HEADER_RE.search(line) for line in native_lines):
            events: list[NormalizedEvent] = []
            for ordinal, line in enumerate(native_lines):
                events.append(
                    self._normalize_audit_line(raw, line, ordinal, accepted_at)
                    if _AUDIT_HEADER_RE.search(line)
                    else self._unparseable(
                        raw, accepted_at, ordinal, "line is not a Linux Audit record"
                    )
                )
            return tuple(events)

        try:
            items = _json_items(payload)
        except json.JSONDecodeError as exc:
            return (self._unparseable(raw, accepted_at, 0, str(exc)),)
        events = []
        for ordinal, item in enumerate(items):
            if item is None:
                events.append(
                    self._unparseable(raw, accepted_at, ordinal, "record is not an object")
                )
                continue
            message = _text(_first(item, "MESSAGE", "message"))
            if message and _AUDIT_HEADER_RE.search(message):
                events.append(self._normalize_audit_line(raw, message, ordinal, accepted_at))
            elif self._is_sysmon(item):
                events.append(self._normalize_sysmon(raw, item, ordinal, accepted_at))
            elif _path(item, "auditd") is not None:
                events.append(self._normalize_audit_json(raw, item, ordinal, accepted_at))
            else:
                events.append(
                    self._unparseable(
                        raw,
                        accepted_at,
                        ordinal,
                        "record is neither Linux Audit nor Sysmon for Linux telemetry",
                    )
                )
        return tuple(events) or (
            self._unparseable(raw, accepted_at, 0, "payload contains no event records"),
        )

    def _event_id(self, identity: str) -> str:
        material = f"{self.tenant_id}\x00{self.source_instance_id}\x00{identity}"
        return "linux:" + hashlib.sha256(material.encode()).hexdigest()

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
            platform=Platform.LINUX,
            source_type="linux_telemetry",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            ingested_at=ingested_at,
            event_time_quality=EventTimeQuality.UNKNOWN,
            parse_status=ParseStatus.UNPARSEABLE,
            raw_evidence=raw,
            attributes={},
            parse_warnings=(warning,),
        )

    def _normalize_audit_line(
        self,
        raw: RawEvidenceRef,
        line: str,
        ordinal: int,
        ingested_at: datetime,
    ) -> NormalizedEvent:
        header = _AUDIT_HEADER_RE.search(line)
        if header is None:
            return self._unparseable(raw, ingested_at, ordinal, "invalid audit header")
        record_type = header.group("record_type")
        serial = header.group("serial")
        fields = _audit_fields(line)
        observed_at = _audit_timestamp(header.group("timestamp"))
        pid = _integer(fields.get("pid"))
        ppid = _integer(fields.get("ppid"))
        session = _text(fields.get("ses"))
        login_uid = _text(fields.get("auid"))
        if session in _UNSET_AUDIT_IDS:
            session = None
        if login_uid in _UNSET_AUDIT_IDS:
            login_uid = None
        command_line = _audit_command(record_type, fields)
        success = _text(fields.get("success") or fields.get("res"))

        attributes = _compact(
            {
                "event": {
                    "provider": "linux_audit",
                    "action": record_type.casefold(),
                    "outcome": success,
                },
                "host": {"id": self.source_instance_id, "boot_id": self.boot_id},
                "process": {
                    "pid": pid,
                    "ppid": ppid,
                    "name": _text(fields.get("comm")),
                    "executable": _text(fields.get("exe")),
                    "command_line": command_line,
                    "working_directory": _text(fields.get("cwd")),
                },
                "user": {
                    "id": _text(fields.get("uid")),
                    "effective_id": _text(fields.get("euid")),
                    "login_uid": login_uid,
                    "session_id": session,
                },
                "file": {"path": _text(fields.get("name"))},
                "network": {
                    "address": _text(fields.get("addr")),
                    "hostname": _text(fields.get("hostname")),
                },
                "audit": {
                    "record_type": record_type,
                    "serial": serial,
                    "syscall": _text(fields.get("syscall")),
                    "architecture": _text(fields.get("arch")),
                    "rule_key": _text(fields.get("key")),
                    "terminal": _text(fields.get("tty")),
                },
            }
        )
        keys = [EntityKey("audit_event_serial", serial, self._host_scope)]
        if pid:
            keys.append(EntityKey("process_pid", pid, self._host_scope))
        if ppid:
            keys.append(EntityKey("parent_process_pid", ppid, self._host_scope))
        if session:
            keys.append(EntityKey("audit_session", session, self._host_scope))
        if login_uid:
            keys.append(EntityKey("login_uid", login_uid, self._host_scope))

        fingerprint = hashlib.sha256(line.encode()).hexdigest()
        identity = f"audit:{serial}:{record_type}:{fingerprint}:raw:{raw.sha256}"
        return NormalizedEvent(
            event_id=self._event_id(identity),
            tenant_id=self.tenant_id,
            platform=Platform.LINUX,
            source_type="auditd",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            observed_at=observed_at,
            ingested_at=ingested_at,
            event_time_quality=EventTimeQuality.SOURCE_REPORTED,
            parse_status=ParseStatus.PARSED,
            raw_evidence=raw,
            native_event_id=serial,
            native_sequence=serial,
            entity_keys=tuple(keys),
            attributes=attributes,
        )

    @staticmethod
    def _is_sysmon(record: Mapping[str, Any]) -> bool:
        provider = _text(
            _first(
                record,
                "winlog.provider_name",
                "System.Provider.Name",
                "ProviderName",
            )
        )
        channel = _text(_first(record, "winlog.channel", "System.Channel", "Channel"))
        return "sysmon" in f"{provider or ''} {channel or ''}".casefold()

    def _normalize_sysmon(
        self,
        raw: RawEvidenceRef,
        record: Mapping[str, Any],
        ordinal: int,
        ingested_at: datetime,
    ) -> NormalizedEvent:
        data = _path(record, "winlog.event_data") or _path(record, "EventData") or {}
        data = data if isinstance(data, Mapping) else {}

        def data_value(*names: str) -> Any:
            for name in names:
                value = _mapping_get(data, name)
                if value is not None and _text(value) is not None:
                    return value
                value = _mapping_get(record, name)
                if value is not None and _text(value) is not None:
                    return value
            return None

        provider_value = _first(
            record, "winlog.provider_name", "System.Provider.Name", "ProviderName"
        )
        provider = _text(provider_value)
        event_code = _integer(
            _first(record, "winlog.event_id", "event.code", "System.EventID", "EventID")
        )
        record_id = _text(
            _first(record, "winlog.record_id", "System.EventRecordID", "EventRecordID")
        )
        channel = _text(_first(record, "winlog.channel", "System.Channel", "Channel"))
        observed_at = _iso_timestamp(
            _first(record, "@timestamp", "winlog.time_created", "System.TimeCreated.SystemTime")
        ) or _iso_timestamp(data_value("UtcTime"), utc_without_offset=True)
        warnings: list[str] = []
        if observed_at is None:
            observed_at = ingested_at
            quality = EventTimeQuality.COLLECTOR_ASSIGNED
            warnings.append("source event timestamp is missing or invalid")
        else:
            quality = EventTimeQuality.SOURCE_REPORTED
        if event_code is None:
            warnings.append("event code is missing")
        if provider is None:
            warnings.append("event provider is missing")

        process_guid = _guid(data_value("ProcessGuid"))
        parent_guid = _guid(data_value("ParentProcessGuid"))
        pid = _integer(data_value("ProcessId"))
        ppid = _integer(data_value("ParentProcessId"))
        attributes = _compact(
            {
                "event": {
                    "provider": provider,
                    "channel": channel,
                    "code": event_code,
                    "record_id": record_id,
                    "action": SYSMON_ACTIONS.get(event_code or ""),
                },
                "host": {"id": self.source_instance_id, "boot_id": self.boot_id},
                "process": {
                    "guid": process_guid,
                    "pid": pid,
                    "executable": _text(data_value("Image")),
                    "command_line": _text(data_value("CommandLine")),
                    "working_directory": _text(data_value("CurrentDirectory")),
                    "parent": {
                        "guid": parent_guid,
                        "pid": ppid,
                        "executable": _text(data_value("ParentImage")),
                        "command_line": _text(data_value("ParentCommandLine")),
                    },
                },
                "user": {"name": _text(data_value("User"))},
                "file": {"path": _text(data_value("TargetFilename", "ImageLoaded"))},
                "network": {
                    "protocol": _text(data_value("Protocol")),
                    "source": {
                        "ip": _text(data_value("SourceIp")),
                        "port": _integer(data_value("SourcePort")),
                    },
                    "destination": {
                        "ip": _text(data_value("DestinationIp")),
                        "port": _integer(data_value("DestinationPort")),
                    },
                },
                "dns": {"query": _text(data_value("QueryName"))},
            }
        )
        keys: list[EntityKey] = []
        if process_guid:
            keys.append(EntityKey("process_guid", process_guid, self._host_scope))
        if parent_guid:
            keys.append(EntityKey("parent_process_guid", parent_guid, self._host_scope))
        if pid:
            keys.append(EntityKey("process_pid", pid, self._host_scope))
        if ppid:
            keys.append(EntityKey("parent_process_pid", ppid, self._host_scope))
        fingerprint = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        identity = (
            f"sysmon:{provider}:{channel}:{record_id or 'missing'}:"
            f"{fingerprint}:raw:{raw.sha256}"
        )
        return NormalizedEvent(
            event_id=self._event_id(identity),
            tenant_id=self.tenant_id,
            platform=Platform.LINUX,
            source_type="sysmon_linux",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            observed_at=observed_at,
            ingested_at=ingested_at,
            event_time_quality=quality,
            parse_status=ParseStatus.PARTIAL if warnings else ParseStatus.PARSED,
            raw_evidence=raw,
            native_event_id=record_id,
            entity_keys=tuple(keys),
            attributes=attributes,
            parse_warnings=tuple(warnings),
        )

    def _normalize_audit_json(
        self,
        raw: RawEvidenceRef,
        record: Mapping[str, Any],
        ordinal: int,
        ingested_at: datetime,
    ) -> NormalizedEvent:
        auditd = _path(record, "auditd")
        auditd = auditd if isinstance(auditd, Mapping) else {}
        data = _mapping_get(auditd, "data")
        data = data if isinstance(data, Mapping) else {}
        serial = _text(
            _first(record, "auditd.sequence", "auditd.serial", "event.sequence")
        )
        record_type = _text(
            _first(record, "auditd.message_type", "event.action")
        ) or "UNKNOWN"
        observed_at = _iso_timestamp(_first(record, "@timestamp", "event.created"))
        warnings: list[str] = []
        if observed_at is None:
            observed_at = ingested_at
            quality = EventTimeQuality.COLLECTOR_ASSIGNED
            warnings.append("source event timestamp is missing or invalid")
        else:
            quality = EventTimeQuality.SOURCE_REPORTED
        if serial is None:
            warnings.append("audit serial is missing")

        pid = _integer(_first(record, "process.pid", "auditd.data.pid"))
        ppid = _integer(_first(record, "process.ppid", "auditd.data.ppid"))
        session = _text(_first(record, "auditd.data.ses", "user.session"))
        login_uid = _text(_first(record, "user.audit.id", "auditd.data.auid"))
        if session in _UNSET_AUDIT_IDS:
            session = None
        if login_uid in _UNSET_AUDIT_IDS:
            login_uid = None
        args = _path(record, "process.args")
        command_line = " ".join(str(item) for item in args) if isinstance(args, list) else None
        attributes = _compact(
            {
                "event": {
                    "provider": "linux_audit",
                    "action": record_type.casefold(),
                    "outcome": _text(_first(record, "event.outcome", "auditd.result")),
                },
                "host": {"id": self.source_instance_id, "boot_id": self.boot_id},
                "process": {
                    "pid": pid,
                    "ppid": ppid,
                    "name": _text(_first(record, "process.name")),
                    "executable": _text(_first(record, "process.executable")),
                    "command_line": command_line,
                    "working_directory": _text(_first(record, "process.working_directory")),
                },
                "user": {
                    "id": _text(_first(record, "user.id")),
                    "login_uid": login_uid,
                    "session_id": session,
                },
                "file": {"path": _text(_first(record, "file.path"))},
                "audit": {
                    "record_type": record_type,
                    "serial": serial,
                    "syscall": _text(_mapping_get(data, "syscall")),
                    "rule_key": _text(_mapping_get(data, "key")),
                },
            }
        )
        keys: list[EntityKey] = []
        if serial:
            keys.append(EntityKey("audit_event_serial", serial, self._host_scope))
        if pid:
            keys.append(EntityKey("process_pid", pid, self._host_scope))
        if ppid:
            keys.append(EntityKey("parent_process_pid", ppid, self._host_scope))
        if session:
            keys.append(EntityKey("audit_session", session, self._host_scope))
        if login_uid:
            keys.append(EntityKey("login_uid", login_uid, self._host_scope))
        fingerprint = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        identity = (
            f"audit-json:{serial or 'missing'}:{record_type}:"
            f"{fingerprint}:raw:{raw.sha256}"
        )
        return NormalizedEvent(
            event_id=self._event_id(identity),
            tenant_id=self.tenant_id,
            platform=Platform.LINUX,
            source_type="auditd",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            observed_at=observed_at,
            ingested_at=ingested_at,
            event_time_quality=quality,
            parse_status=ParseStatus.PARTIAL if warnings else ParseStatus.PARSED,
            raw_evidence=raw,
            native_event_id=serial,
            native_sequence=serial,
            entity_keys=tuple(keys),
            attributes=attributes,
            parse_warnings=tuple(warnings),
        )
