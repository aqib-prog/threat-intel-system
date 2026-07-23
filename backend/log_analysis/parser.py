"""Extracts structured evidence from raw security-log text.

Produces a flat list of LogEvent records - one per input line (Windows/Linux)
or per JSON record (AWS CloudTrail/Kubernetes audit) - each carrying the
untouched raw text (for evidence display) alongside a normalized form (for
pattern matching) and any fields the platform-specific parser could pull out.
"""

import base64
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field

from log_analysis.structured import normalize_field_name


KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]{1,60})=("(?:[^"\\]|\\.)*"|\S+)')
AUDITD_ARG_RE = re.compile(r'\ba(\d+)="?((?:[^"\s]|(?<=\\)")*)"?')
POWERSHELL_ENC_RE = re.compile(
    r"(?:-enc(?:odedcommand)?)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE
)
CARET_ESCAPE_RE = re.compile(r"\^(?=[A-Za-z0-9])")
BACKTICK_ESCAPE_RE = re.compile(r"`(?=[A-Za-z0-9])")
POWERSHELL_PIPELINE_MESSAGE_RE = re.compile(
    r"Pipeline execution details for command line:\s*(.*?)"
    r"(?:\r?\n\s*\r?\nContext Information:|\Z)",
    re.IGNORECASE | re.DOTALL,
)
AUDITD_MESSAGE_ID_RE = re.compile(r"\bmsg=audit\(([^)]+)\):")


# Deliberately scoped to the Windows concepts used most often by the current
# rule corpus. The source-field index remains available for less-common Sigma
# fields, so this canonical model can stay small instead of recreating OSSEM.
WINDOWS_CANONICAL_ALIASES: dict[str, tuple[str, ...]] = {
    "event.id": ("EventID", "EventCode"),
    "event.provider": ("ProviderName", "Provider_Name", "SourceName"),
    "event.channel": ("Channel", "LogName"),
    "event.action": ("EventType", "Action", "Operation"),
    "process.command_line": ("CommandLine", "ProcessCommandLine"),
    "process.executable": (
        "Image",
        "NewProcessName",
        "ProcessName",
        "ProcessPath",
        "Application",
    ),
    "process.parent.command_line": ("ParentCommandLine",),
    "process.parent.executable": ("ParentImage", "ParentProcessName"),
    "process.id": ("ProcessId", "ProcessID", "NewProcessId"),
    "process.parent.id": ("ParentProcessId", "ParentProcessID"),
    "user.name": ("User", "UserName", "AccountName", "SubjectUserName", "TargetUserName"),
    "user.domain": ("Domain", "SubjectDomainName", "TargetDomainName"),
    "user.id": ("UserID", "SubjectUserSid", "TargetUserSid"),
    "file.path": ("TargetFilename", "FileName", "Path", "ImageLoaded"),
    "registry.path": ("TargetObject", "ObjectName"),
    "network.source.ip": ("SourceIp", "SourceAddress", "IpAddress", "ClientAddress"),
    "network.source.port": ("SourcePort", "IpPort"),
    "network.destination.ip": ("DestinationIp", "DestAddress"),
    "network.destination.port": ("DestinationPort", "DestPort"),
    "network.destination.name": ("DestinationHostname", "Destination"),
    "network.protocol": ("Protocol",),
    "network.initiated": ("Initiated",),
    "dns.query": ("QueryName", "Query"),
    "service.name": ("ServiceName",),
    "service.path": ("ServiceFileName", "ImagePath"),
    "task.name": ("TaskName",),
    "script.content": ("ScriptBlockText", "Payload"),
}

LINUX_CANONICAL_ALIASES: dict[str, tuple[str, ...]] = {
    "event.action": ("type",),
    "process.command_line": ("CommandLine", "argv"),
    "process.executable": ("Image", "exe", "comm"),
    "process.parent.command_line": ("ParentCommandLine",),
    "process.parent.executable": ("ParentImage",),
    "process.id": ("pid",),
    "process.parent.id": ("ppid",),
    "process.working_directory": ("cwd",),
    "user.id": ("auid", "uid", "euid"),
    "group.id": ("gid", "egid"),
    "file.path": ("TargetFilename", "name"),
    "network.destination.ip": ("DestinationIp", "dst", "daddr"),
    "network.destination.name": ("DestinationHostname", "hostname"),
    "network.destination.port": ("DestinationPort", "dport"),
    "network.source.ip": ("SourceIp", "src", "saddr"),
}


# Deliberately limited to the ECS fields needed by the approved macOS Sigma
# candidates.  Full paths avoid conflating process.executable with
# process.parent.executable, which share the same leaf name in Elasticsearch.
MACOS_CANONICAL_ALIASES: dict[str, tuple[str, ...]] = {
    "process.executable": ("_source.process.executable", "process.executable"),
    "process.command_line": ("_source.process.command_line", "process.command_line"),
    "process.parent.executable": (
        "_source.process.parent.executable",
        "process.parent.executable",
    ),
    "file.path": ("_source.file.path", "file.path"),
}

MACOS_SIGMA_ALIASES: dict[str, str] = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "TargetFilename": "file.path",
}


@dataclass
class LogEvent:
    raw_line: str
    normalized_line: str
    fields: dict[str, str] = field(default_factory=dict)
    canonical_fields: dict[str, tuple[str, ...]] = field(default_factory=dict)
    source_fields: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # True means a complete structured record was parsed. A missing field is
    # then authoritative absence, not a reason to re-run a lossy raw rule.
    structured_complete: bool = False


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"')
    return value


def _normalize_obfuscation(line: str) -> str:
    """Undo cmd.exe caret-escaping and PowerShell backtick-escaping so
    mapping regexes match obfuscated commands the same as plain ones."""
    normalized = CARET_ESCAPE_RE.sub("", line)
    normalized = BACKTICK_ESCAPE_RE.sub("", normalized)
    return normalized


def _decode_powershell_command(line: str) -> str | None:
    match = POWERSHELL_ENC_RE.search(line)
    if not match:
        return None
    try:
        raw = base64.b64decode(match.group(1) + "==", validate=False)
        return raw.decode("utf-16-le", errors="ignore")
    except Exception:
        return None


def _parse_kv_line(line: str) -> dict[str, str]:
    return {key: _strip_quotes(value) for key, value in KV_RE.findall(line)}


def _deduplicate(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _source_field_index(obj: object) -> dict[str, tuple[str, ...]]:
    indexed: dict[str, list[str]] = defaultdict(list)

    def visit(value: object, path: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, (*path, str(key)))
            return
        if isinstance(value, (list, tuple)):
            for child in value:
                visit(child, path)
            return
        if value is None or not path:
            return
        rendered = str(value)
        full_name = normalize_field_name(".".join(path))
        leaf_name = normalize_field_name(path[-1])
        indexed[full_name].append(rendered)
        if leaf_name != full_name:
            indexed[leaf_name].append(rendered)

    visit(obj, ())
    return {key: _deduplicate(values) for key, values in indexed.items()}


def _canonicalize_windows(
    source_fields: dict[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    canonical: dict[str, tuple[str, ...]] = {}
    for canonical_name, aliases in WINDOWS_CANONICAL_ALIASES.items():
        values: list[str] = []
        for alias in aliases:
            values.extend(source_fields.get(normalize_field_name(alias), ()))
        if values:
            canonical[canonical_name] = _deduplicate(values)
    return canonical


def _canonicalize_linux(
    source_fields: dict[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    canonical: dict[str, tuple[str, ...]] = {}
    for canonical_name, aliases in LINUX_CANONICAL_ALIASES.items():
        values: list[str] = []
        for alias in aliases:
            values.extend(source_fields.get(normalize_field_name(alias), ()))
        if values:
            canonical[canonical_name] = _deduplicate(values)
    return canonical


def _canonicalize_macos(
    source_fields: dict[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    canonical: dict[str, tuple[str, ...]] = {}
    for canonical_name, aliases in MACOS_CANONICAL_ALIASES.items():
        values: list[str] = []
        for alias in aliases:
            values.extend(source_fields.get(normalize_field_name(alias), ()))
        if values:
            canonical[canonical_name] = _deduplicate(values)
    return canonical


def _enrich_linux_source_fields(
    source_fields: dict[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    """Bridge auditd/process-creation spellings without inventing values."""

    enriched = dict(source_fields)
    canonical = _canonicalize_linux(source_fields)
    for canonical_name, aliases in LINUX_CANONICAL_ALIASES.items():
        values = canonical.get(canonical_name)
        if not values:
            continue
        for alias in aliases:
            enriched.setdefault(normalize_field_name(alias), values)
    return enriched


def _enrich_macos_source_fields(
    source_fields: dict[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    """Bridge exact ECS paths to the four Sigma fields in the macOS corpus."""

    enriched = dict(source_fields)
    canonical = _canonicalize_macos(source_fields)
    for sigma_name, canonical_name in MACOS_SIGMA_ALIASES.items():
        values = canonical.get(canonical_name)
        if values:
            enriched.setdefault(normalize_field_name(sigma_name), values)
    return enriched


def _enrich_windows_source_fields(
    source_fields: dict[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    """Add conservative vendor aliases without overwriting direct fields."""

    enriched = dict(source_fields)
    canonical = _canonicalize_windows(source_fields)
    for canonical_name, aliases in WINDOWS_CANONICAL_ALIASES.items():
        values = canonical.get(canonical_name)
        if not values:
            continue
        for alias in aliases:
            enriched.setdefault(normalize_field_name(alias), values)

    # Legacy "Windows PowerShell" EventID 800 stores pipeline/script text in
    # Message rather than ScriptBlockText. Restrict this bridge to a confirmed
    # PowerShell channel/provider so unrelated event messages cannot satisfy
    # ps_script Sigma rules.
    context = (
        *source_fields.get(normalize_field_name("Channel"), ()),
        *source_fields.get(normalize_field_name("SourceName"), ()),
        *source_fields.get(normalize_field_name("ProviderName"), ()),
    )
    message = source_fields.get(normalize_field_name("Message"), ())
    event_ids = source_fields.get(normalize_field_name("EventID"), ())
    if (
        message
        and "800" in event_ids
        and any("powershell" in value.casefold() for value in context)
    ):
        pipeline_commands = tuple(
            match.group(1).strip()
            for value in message
            if (match := POWERSHELL_PIPELINE_MESSAGE_RE.search(value))
            and match.group(1).strip()
        )
        if pipeline_commands:
            enriched.setdefault(
                normalize_field_name("ScriptBlockText"),
                _deduplicate(list(pipeline_commands)),
            )
    return enriched


def _reconstruct_auditd_argv(fields: dict[str, str]) -> str | None:
    args = {int(num): value for num, value in AUDITD_ARG_RE.findall(" ".join(f"{k}={v}" for k, v in fields.items()))}
    if not args:
        return None
    return " ".join(args[i] for i in sorted(args))


# Real-world security-log exports very commonly put one field per line
# (Windows Event Viewer copy/paste, PowerShell Format-List, pretty-printed
# JSON) rather than everything smashed onto one line - a rule requiring two
# correlated fields (e.g. EventID=4769 + TicketEncryptionType=0x17 for
# Kerberoasting) silently never matches if those two fields land on
# different lines, since matching is otherwise strictly per-line. Windowing
# joins each line with the next few so cross-line field correlation still
# works, without sacrificing per-line precision for evidence quoting (the
# windowed event's raw_line stays the single anchor line, not the whole
# window, so "Strongest Evidence"/"Matched Log Lines" still shows one
# real line, not a multi-line blob).
WINDOW_SIZE = 6
MAX_LINES_TO_WINDOW = 3000


def _parse_text_lines(text: str, platform: str | None = None) -> list[LogEvent]:
    events: list[LogEvent] = []
    seen: set[str] = set()
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)

        normalized = _normalize_obfuscation(line)
        fields = _parse_kv_line(normalized)

        decoded = _decode_powershell_command(normalized)
        if decoded:
            fields["decoded_command"] = decoded
            normalized = f"{normalized} [decoded: {decoded}]"

        argv = (
            _reconstruct_auditd_argv(fields)
            if fields.get("type", "").casefold() == "execve"
            else None
        )
        if argv:
            fields["argv"] = argv
            normalized = f"{normalized} [argv: {argv}]"

        source_fields = _source_field_index(fields)
        if platform == "windows":
            source_fields = _enrich_windows_source_fields(source_fields)
            canonical_fields = _canonicalize_windows(source_fields)
        elif platform == "linux":
            source_fields = _enrich_linux_source_fields(source_fields)
            canonical_fields = _canonicalize_linux(source_fields)
        else:
            canonical_fields = {}
        events.append(
            LogEvent(
                raw_line=line,
                normalized_line=normalized,
                fields=fields,
                canonical_fields=canonical_fields,
                source_fields=source_fields,
            )
        )

    if 1 < len(lines) <= MAX_LINES_TO_WINDOW:
        # Half-stride overlap, not stride 1: two lines within WINDOW_SIZE of
        # each other are still guaranteed to co-occur in at least one
        # window, but this checks ~WINDOW_SIZE/2x fewer windows than a
        # window starting at every single line - the earlier stride-1
        # version took 16s on a 1500-line paste, which reads as "hung" in
        # a chat UI.
        stride = max(1, WINDOW_SIZE // 2)
        for i in range(0, len(lines), stride):
            window = lines[i : i + WINDOW_SIZE]
            if len(window) < 2:
                continue
            window_text = _normalize_obfuscation(" ".join(window))
            events.append(LogEvent(raw_line=lines[i], normalized_line=window_text, fields={}))

    return events


def _parse_linux_events(text: str) -> list[LogEvent]:
    """Group auditd lines by message ID into authoritative event records."""

    grouped: dict[str, list[str]] = {}
    fallback_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = AUDITD_MESSAGE_ID_RE.search(line)
        if match is None:
            fallback_lines.append(raw_line)
            continue
        grouped.setdefault(match.group(1), []).append(line)

    events: list[LogEvent] = []
    for lines in grouped.values():
        values: dict[str, list[str]] = defaultdict(list)
        normalized_lines: list[str] = []
        for line in lines:
            normalized = _normalize_obfuscation(line)
            fields = _parse_kv_line(normalized)
            argv = (
                _reconstruct_auditd_argv(fields)
                if fields.get("type", "").casefold() == "execve"
                else None
            )
            if argv:
                fields["argv"] = argv
                normalized = f"{normalized} [argv: {argv}]"
            normalized_lines.append(normalized)
            for key, value in fields.items():
                values[key].append(value)

        record = {key: _deduplicate(items) for key, items in values.items()}
        source_fields = _enrich_linux_source_fields(_source_field_index(record))
        events.append(
            LogEvent(
                raw_line="\n".join(lines),
                normalized_line=" ".join(normalized_lines),
                fields={key: " ".join(items) for key, items in record.items()},
                canonical_fields=_canonicalize_linux(source_fields),
                source_fields=source_fields,
            )
        )

    if fallback_lines:
        events.extend(_parse_text_lines("\n".join(fallback_lines), "linux"))
    if events:
        return events
    return _parse_text_lines(text, "linux")


def _flatten_json(obj, prefix: str = "") -> dict[str, str]:
    flat: dict[str, str] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            flat.update(_flatten_json(value, f"{prefix}.{key}" if prefix else key))
    elif isinstance(obj, list):
        for item in obj:
            flat.update(_flatten_json(item, prefix))
    else:
        flat[prefix] = str(obj)
    return flat


def _iter_json_records(text: str):
    """Yields individual record dicts from either a CloudTrail-style
    {"Records": [...]} blob, a bare JSON array, or one JSON object per line
    (the common Kubernetes audit-log-file shape)."""
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        parsed = None

    if isinstance(parsed, dict) and isinstance(parsed.get("Records"), list):
        yield from parsed["Records"]
        return
    if isinstance(parsed, list):
        yield from parsed
        return
    if isinstance(parsed, dict):
        yield parsed
        return

    for raw_line in stripped.splitlines():
        line = raw_line.strip().rstrip(",")
        if not line:
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(record, dict):
            yield record


def _json_event(record: dict, platform: str | None) -> LogEvent:
    raw_line = json.dumps(record, ensure_ascii=False)
    source_fields = _source_field_index(record)
    if platform == "windows":
        source_fields = _enrich_windows_source_fields(source_fields)
    elif platform == "macos":
        source_fields = _enrich_macos_source_fields(source_fields)
    return LogEvent(
        raw_line=raw_line,
        normalized_line=raw_line,
        fields=_flatten_json(record),
        canonical_fields=(
            _canonicalize_windows(source_fields)
            if platform == "windows"
            else _canonicalize_macos(source_fields)
            if platform == "macos"
            else {}
        ),
        source_fields=source_fields,
        structured_complete=True,
    )


def _parse_json_records(text: str, platform: str | None = None) -> list[LogEvent]:
    events: list[LogEvent] = []
    seen: set[str] = set()
    for record in _iter_json_records(text):
        stable_key = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if stable_key in seen:
            continue
        seen.add(stable_key)
        events.append(_json_event(record, platform))
    return events


def _parse_windows_events(text: str) -> list[LogEvent]:
    """Parse complete JSON records first, retaining raw fallback for bad lines."""

    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return _parse_json_records(text, "windows")

    json_events: list[LogEvent] = []
    fallback_lines: list[str] = []
    seen: set[str] = set()
    for raw_line in stripped.splitlines():
        line = raw_line.strip().rstrip(",")
        if not line:
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            fallback_lines.append(raw_line)
            continue
        if not isinstance(record, dict):
            fallback_lines.append(raw_line)
            continue
        stable_key = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if stable_key not in seen:
            seen.add(stable_key)
            json_events.append(_json_event(record, "windows"))

    if not json_events:
        return _parse_text_lines(text, "windows")
    if fallback_lines:
        json_events.extend(_parse_text_lines("\n".join(fallback_lines), "windows"))
    return json_events


def _parse_macos_events(text: str) -> list[LogEvent]:
    """Parse complete ECS JSON/NDJSON events with raw fallback for bad lines."""

    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return _parse_json_records(text, "macos")

    json_events: list[LogEvent] = []
    fallback_lines: list[str] = []
    seen: set[str] = set()
    for raw_line in stripped.splitlines():
        line = raw_line.strip().rstrip(",")
        if not line:
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            fallback_lines.append(raw_line)
            continue
        if not isinstance(record, dict):
            fallback_lines.append(raw_line)
            continue
        stable_key = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if stable_key not in seen:
            seen.add(stable_key)
            json_events.append(_json_event(record, "macos"))

    if not json_events:
        return _parse_text_lines(text, "macos")
    if fallback_lines:
        json_events.extend(_parse_text_lines("\n".join(fallback_lines), "macos"))
    return json_events


def parse_log(text: str, platform: str | None) -> list[LogEvent]:
    if platform == "windows":
        return _parse_windows_events(text)
    if platform == "linux":
        return _parse_linux_events(text)
    if platform == "macos":
        return _parse_macos_events(text)
    if platform in ("aws", "kubernetes"):
        json_events = _parse_json_records(text, platform)
        # Always ALSO run text-line parsing (with windowing), even when some
        # records parsed cleanly - malformed/truncated JSON (a missing
        # brace, a dropped comma) means SOME records in the same paste can
        # fail strict parsing while others succeed. Short-circuiting on
        # "found at least one valid record" silently drops every record
        # that didn't individually parse, even though its raw text still
        # contains readable, matchable substrings (analyzer matches by
        # regex search, not structured JSON, so it doesn't need the record
        # to have parsed to find "eventName": "DeleteTrail" in it).
        text_events = _parse_text_lines(text, platform)
        seen_raw = {e.raw_line for e in json_events}
        return json_events + [e for e in text_events if e.raw_line not in seen_raw]
    return _parse_text_lines(text, platform)
