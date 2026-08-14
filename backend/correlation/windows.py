"""Windows Event Log and Sysmon normalization adapter.

Supported production inputs are structured JSON/NDJSON emitted by a trusted
Windows collector and exported Windows Event XML. Native binary EVTX is always
stored, but decoding belongs in the collection tier; this adapter emits an
explicit unparseable envelope rather than pretending binary bytes were parsed.

Microsoft documents Sysmon ``ProcessGuid`` as the stable process-correlation
identifier and Windows Event ``EventRecordID`` as the record number assigned
when an event is logged. PID-only keys remain distinguishable from GUID keys so
the correlation engine can apply reuse-aware temporal rules later.
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


WINDOWS_ADAPTER_VERSION = "1.0.0"
DEFAULT_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
_EVTX_MAGIC = b"ElfFile\x00"
_WINDOWS_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_GUID_RE = re.compile(
    r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$",
    re.IGNORECASE,
)


_SECURITY_ACTIONS = {
    "4624": "logon_success",
    "4625": "logon_failure",
    "4634": "logoff",
    "4647": "user_logoff",
    "4648": "explicit_credentials_logon",
    "4672": "privileged_logon",
    "4688": "process_start",
    "4689": "process_end",
    "4697": "service_install",
    "4698": "scheduled_task_create",
    "4702": "scheduled_task_update",
    "4768": "kerberos_tgt_request",
    "4769": "kerberos_service_ticket_request",
    "4771": "kerberos_preauthentication_failure",
}


class WindowsAdapterError(RuntimeError):
    pass


def _text(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered if rendered and rendered != "-" else None


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


def _normalize_guid(value: Any) -> str | None:
    rendered = _text(value)
    if rendered is None or not _GUID_RE.match(rendered):
        return None
    return rendered.casefold()


def _normalize_integer(value: Any) -> str | None:
    rendered = _text(value)
    if rendered is None:
        return None
    try:
        return str(int(rendered, 0))
    except ValueError:
        try:
            return str(int(rendered))
        except ValueError:
            return None


def _parse_timestamp(value: Any, *, utc_without_offset: bool = False) -> datetime | None:
    rendered = _text(value)
    if rendered is None:
        return None
    candidate = rendered.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        if not utc_without_offset:
            return None
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_data(record: Mapping[str, Any]) -> dict[str, Any]:
    for candidate in (
        _path(record, "winlog.event_data"),
        _path(record, "EventData"),
        _path(record, "event_data"),
    ):
        if isinstance(candidate, Mapping):
            return {str(key): value for key, value in candidate.items()}
    return {}


def _record_value(
    record: Mapping[str, Any], event_data: Mapping[str, Any], *names: str
) -> Any:
    for name in names:
        value = _mapping_get(event_data, name)
        if value is not None and _text(value) is not None:
            return value
        value = _mapping_get(record, name)
        if value is not None and _text(value) is not None:
            return value
    return None


def _json_records(payload: bytes) -> list[Mapping[str, Any] | None]:
    decoded = payload.decode("utf-8")
    try:
        parsed = json.loads(decoded)
    except json.JSONDecodeError:
        records: list[Mapping[str, Any] | None] = []
        for line in decoded.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                records.append(None)
                continue
            records.append(item if isinstance(item, Mapping) else None)
        if not records:
            raise
        return records

    if isinstance(parsed, Mapping):
        for key in ("Records", "records", "events", "Events"):
            children = _mapping_get(parsed, key)
            if isinstance(children, list):
                return [item if isinstance(item, Mapping) else None for item in children]
        return [parsed]
    if isinstance(parsed, list):
        return [item if isinstance(item, Mapping) else None for item in parsed]
    return [None]


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_records(payload: bytes) -> list[Mapping[str, Any]]:
    if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise ValueError("XML document types and entities are not allowed")
    root = ET.fromstring(payload)
    event_elements = (
        [root]
        if _xml_local_name(root.tag) == "Event"
        else [item for item in root.iter() if _xml_local_name(item.tag) == "Event"]
    )
    records: list[Mapping[str, Any]] = []
    for event in event_elements:
        system: dict[str, Any] = {}
        data: dict[str, Any] = {}
        system_element = next(
            (child for child in event if _xml_local_name(child.tag) == "System"),
            None,
        )
        if system_element is not None:
            for child in system_element:
                name = _xml_local_name(child.tag)
                if name == "Provider":
                    system["Provider"] = dict(child.attrib)
                elif name in {"TimeCreated", "Correlation", "Execution", "Security"}:
                    system[name] = dict(child.attrib)
                else:
                    system[name] = child.text
        event_data_element = next(
            (child for child in event if _xml_local_name(child.tag) == "EventData"),
            None,
        )
        if event_data_element is not None:
            unnamed = 0
            for child in event_data_element:
                if _xml_local_name(child.tag) != "Data":
                    continue
                name = child.attrib.get("Name") or f"unnamed_{unnamed}"
                unnamed += 1
                data[name] = child.text or ""
        records.append({"System": system, "EventData": data})
    if not records:
        raise ValueError("XML contains no Windows Event records")
    return records


def _provider(record: Mapping[str, Any]) -> str | None:
    direct = _first(
        record,
        "winlog.provider_name",
        "provider_name",
        "ProviderName",
        "System.Provider.Name",
    )
    if direct is not None:
        return _text(direct)
    provider = _path(record, "System.Provider")
    return _text(_mapping_get(provider, "Name")) if isinstance(provider, Mapping) else None


def _event_code(record: Mapping[str, Any]) -> str | None:
    value = _first(
        record,
        "winlog.event_id",
        "event.code",
        "EventID",
        "EventCode",
        "System.EventID",
    )
    return _normalize_integer(value) or _text(value)


def _event_action(provider: str | None, event_code: str | None) -> str | None:
    if event_code is None:
        return None
    lowered = (provider or "").casefold()
    if "sysmon" in lowered:
        return SYSMON_ACTIONS.get(event_code)
    if "security" in lowered or event_code in _SECURITY_ACTIONS:
        return _SECURITY_ACTIONS.get(event_code)
    return None


@dataclass(frozen=True, slots=True)
class WindowsAdapter:
    evidence_store: RawEvidenceStore
    tenant_id: str
    source_instance_id: str
    boot_id: str
    adapter_version: str = WINDOWS_ADAPTER_VERSION
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
        """Persist the bytes, then normalize every record in the payload."""

        raw = self.evidence_store.put(
            payload,
            tenant_id=self.tenant_id,
            platform=Platform.WINDOWS,
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
        if payload.startswith(_EVTX_MAGIC):
            return (
                self._unparseable(
                    raw,
                    accepted_at,
                    0,
                    "binary EVTX requires decoding by the trusted Windows collection tier",
                ),
            )

        try:
            stripped = payload.lstrip()
            if stripped.startswith(b"<"):
                records: Sequence[Mapping[str, Any] | None] = _xml_records(payload)
            else:
                records = _json_records(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ET.ParseError, ValueError) as exc:
            return (self._unparseable(raw, accepted_at, 0, str(exc)),)

        events: list[NormalizedEvent] = []
        for ordinal, record in enumerate(records):
            if record is None:
                events.append(
                    self._unparseable(
                        raw,
                        accepted_at,
                        ordinal,
                        "record is not a valid Windows Event object",
                    )
                )
            else:
                events.append(self._normalize_record(raw, record, ordinal, accepted_at))
        return tuple(events) or (
            self._unparseable(raw, accepted_at, 0, "payload contains no event records"),
        )

    def _event_id(
        self,
        raw: RawEvidenceRef,
        ordinal: int,
        native_event_id: str | None,
        provider: str | None = None,
        channel: str | None = None,
        record_fingerprint: str | None = None,
    ) -> str:
        identity = (
            f"native:{provider or ''}:{channel or ''}:{native_event_id}:"
            f"{record_fingerprint or raw.sha256}:raw:{raw.sha256}"
            if native_event_id
            else f"raw:{raw.sha256}:{ordinal}"
        )
        material = f"{self.tenant_id}\x00{self.source_instance_id}\x00{identity}"
        return "win:" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _unparseable(
        self,
        raw: RawEvidenceRef,
        ingested_at: datetime,
        ordinal: int,
        warning: str,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=self._event_id(raw, ordinal, None),
            tenant_id=self.tenant_id,
            platform=Platform.WINDOWS,
            source_type="windows_event",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            ingested_at=ingested_at,
            event_time_quality=EventTimeQuality.UNKNOWN,
            parse_status=ParseStatus.UNPARSEABLE,
            raw_evidence=raw,
            attributes={},
            parse_warnings=(warning,),
        )

    def _normalize_record(
        self,
        raw: RawEvidenceRef,
        record: Mapping[str, Any],
        ordinal: int,
        ingested_at: datetime,
    ) -> NormalizedEvent:
        data = _event_data(record)
        provider = _provider(record)
        event_code = _event_code(record)
        channel = _text(
            _first(record, "winlog.channel", "Channel", "System.Channel")
        )
        native_record_id = _text(
            _first(
                record,
                "winlog.record_id",
                "EventRecordID",
                "RecordId",
                "System.EventRecordID",
            )
        )
        activity_id = _normalize_guid(
            _first(record, "winlog.activity_id", "System.Correlation.ActivityID")
        )
        related_activity_id = _normalize_guid(
            _first(record, "winlog.related_activity_id", "System.Correlation.RelatedActivityID")
        )

        timestamp_value = _first(
            record,
            "@timestamp",
            "winlog.time_created",
            "event.created",
            "TimeCreated",
            "System.TimeCreated.SystemTime",
        )
        observed_at = _parse_timestamp(timestamp_value)
        if observed_at is None:
            utc_time = _record_value(record, data, "UtcTime")
            observed_at = _parse_timestamp(utc_time, utc_without_offset=True)
        warnings: list[str] = []
        if observed_at is None:
            observed_at = ingested_at
            time_quality = EventTimeQuality.COLLECTOR_ASSIGNED
            warnings.append("source event timestamp is missing or invalid")
        else:
            time_quality = EventTimeQuality.SOURCE_REPORTED

        process_guid = _normalize_guid(
            _record_value(record, data, "ProcessGuid", "ProcessGUID")
        )
        parent_process_guid = _normalize_guid(
            _record_value(record, data, "ParentProcessGuid", "ParentProcessGUID")
        )
        if event_code == "4688":
            # Security 4688 uses NewProcessId for the child and ProcessId for
            # the creator. They are distinct fields with overlapping names;
            # generic alias precedence would silently reverse the lineage.
            process_id = _normalize_integer(
                _record_value(record, data, "NewProcessId", "New Process ID")
            )
            parent_process_id = _normalize_integer(
                _record_value(record, data, "CreatorProcessId", "ProcessId")
            )
        else:
            process_id = _normalize_integer(
                _record_value(record, data, "ProcessId", "NewProcessId", "New Process ID")
            )
            parent_process_id = _normalize_integer(
                _record_value(
                    record,
                    data,
                    "ParentProcessId",
                    "CreatorProcessId",
                )
            )
        logon_guid = _normalize_guid(_record_value(record, data, "LogonGuid"))
        logon_id = _normalize_integer(
            _record_value(
                record,
                data,
                "LogonId",
                "SubjectLogonId",
                "TargetLogonId",
            )
        )

        attributes = _compact(
            {
                "event": {
                    "code": event_code,
                    "provider": provider,
                    "channel": channel,
                    "record_id": native_record_id,
                    "action": _event_action(provider, event_code),
                },
                "host": {
                    "id": self.source_instance_id,
                    "boot_id": self.boot_id,
                    "reported_name": _text(
                        _first(record, "winlog.computer_name", "Computer", "System.Computer")
                    ),
                },
                "process": {
                    "guid": process_guid,
                    "pid": process_id,
                    "executable": _text(
                        _record_value(
                            record, data, "Image", "NewProcessName", "New Process Name"
                        )
                    ),
                    "command_line": _text(
                        _record_value(
                            record,
                            data,
                            "CommandLine",
                            "ProcessCommandLine",
                            "Process Command Line",
                        )
                    ),
                    "parent": {
                        "guid": parent_process_guid,
                        "pid": parent_process_id,
                        "executable": _text(
                            _record_value(
                                record,
                                data,
                                "ParentImage",
                                "CreatorProcessName",
                                "Creator Process Name",
                            )
                        ),
                        "command_line": _text(
                            _record_value(record, data, "ParentCommandLine")
                        ),
                    },
                },
                "user": {
                    "name": _text(
                        _record_value(
                            record,
                            data,
                            "User",
                            "TargetUserName",
                            "SubjectUserName",
                            "AccountName",
                        )
                    ),
                    "sid": _text(
                        _record_value(
                            record, data, "UserId", "TargetUserSid", "SubjectUserSid"
                        )
                    ),
                    "logon_guid": logon_guid,
                    "logon_id": logon_id,
                },
                "file": {
                    "path": _text(
                        _record_value(record, data, "TargetFilename", "ImageLoaded")
                    )
                },
                "registry": {
                    "path": _text(_record_value(record, data, "TargetObject")),
                    "details": _text(_record_value(record, data, "Details")),
                },
                "network": {
                    "protocol": _text(_record_value(record, data, "Protocol")),
                    "initiated": _text(_record_value(record, data, "Initiated")),
                    "source": {
                        "ip": _text(_record_value(record, data, "SourceIp")),
                        "port": _normalize_integer(
                            _record_value(record, data, "SourcePort")
                        ),
                        "hostname": _text(
                            _record_value(record, data, "SourceHostname")
                        ),
                    },
                    "destination": {
                        "ip": _text(_record_value(record, data, "DestinationIp")),
                        "port": _normalize_integer(
                            _record_value(record, data, "DestinationPort")
                        ),
                        "hostname": _text(
                            _record_value(record, data, "DestinationHostname")
                        ),
                    },
                },
                "dns": {
                    "query": _text(_record_value(record, data, "QueryName")),
                    "status": _text(_record_value(record, data, "QueryStatus")),
                    "results": _text(_record_value(record, data, "QueryResults")),
                },
                "windows": {
                    "activity_id": activity_id,
                    "related_activity_id": related_activity_id,
                    "rule_name": _text(_record_value(record, data, "RuleName")),
                    "integrity_level": _text(
                        _record_value(record, data, "IntegrityLevel")
                    ),
                },
            }
        )

        if event_code is None:
            warnings.append("event code is missing")
        if provider is None:
            warnings.append("event provider is missing")
        parse_status = ParseStatus.PARTIAL if warnings else ParseStatus.PARSED

        entity_keys: list[EntityKey] = []
        # EventRecordID is provenance, not an entity-correlation edge. Windows
        # can reuse record numbers after a channel is cleared, so promoting it
        # to an EntityKey could join unrelated records.
        if process_guid:
            entity_keys.append(EntityKey("process_guid", process_guid, self._host_scope))
        if parent_process_guid:
            entity_keys.append(
                EntityKey("parent_process_guid", parent_process_guid, self._host_scope)
            )
        if process_id:
            entity_keys.append(EntityKey("process_pid", process_id, self._host_scope))
        if parent_process_id:
            entity_keys.append(
                EntityKey("parent_process_pid", parent_process_id, self._host_scope)
            )
        if logon_guid:
            entity_keys.append(EntityKey("logon_guid", logon_guid, self._host_scope))
        if logon_id:
            entity_keys.append(EntityKey("logon_id", logon_id, self._host_scope))
        if activity_id:
            entity_keys.append(EntityKey("activity_id", activity_id, self._host_scope))
        if related_activity_id:
            entity_keys.append(
                EntityKey("related_activity_id", related_activity_id, self._host_scope)
            )

        return NormalizedEvent(
            event_id=self._event_id(
                raw,
                ordinal,
                native_record_id,
                provider=provider,
                channel=channel,
                record_fingerprint=hashlib.sha256(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
            ),
            tenant_id=self.tenant_id,
            platform=Platform.WINDOWS,
            source_type="sysmon" if "sysmon" in (provider or "").casefold() else "windows_event",
            source_instance_id=self.source_instance_id,
            adapter_version=self.adapter_version,
            observed_at=observed_at,
            ingested_at=ingested_at,
            event_time_quality=time_quality,
            parse_status=parse_status,
            raw_evidence=raw,
            native_event_id=native_record_id,
            entity_keys=tuple(entity_keys),
            attributes=attributes,
            parse_warnings=tuple(warnings),
        )
