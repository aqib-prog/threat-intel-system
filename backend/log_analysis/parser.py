"""Extracts structured evidence from raw security-log text.

Produces a flat list of LogEvent records - one per input line (Windows/Linux)
or per JSON record (AWS CloudTrail/Kubernetes audit) - each carrying the
untouched raw text (for evidence display) alongside a normalized form (for
pattern matching) and any fields the platform-specific parser could pull out.
"""

import base64
import json
import re
from dataclasses import dataclass, field


KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]{1,60})=("(?:[^"\\]|\\.)*"|\S+)')
AUDITD_ARG_RE = re.compile(r'\ba(\d+)="?((?:[^"\s]|(?<=\\)")*)"?')
POWERSHELL_ENC_RE = re.compile(
    r"(?:-enc(?:odedcommand)?)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE
)
CARET_ESCAPE_RE = re.compile(r"\^(?=[A-Za-z0-9])")
BACKTICK_ESCAPE_RE = re.compile(r"`(?=[A-Za-z0-9])")


@dataclass
class LogEvent:
    raw_line: str
    normalized_line: str
    fields: dict[str, str] = field(default_factory=dict)


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


def _parse_text_lines(text: str) -> list[LogEvent]:
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

        argv = _reconstruct_auditd_argv(fields)
        if argv:
            fields["argv"] = argv
            normalized = f"{normalized} [argv: {argv}]"

        events.append(LogEvent(raw_line=line, normalized_line=normalized, fields=fields))

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


def _parse_json_records(text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    seen: set[str] = set()
    for record in _iter_json_records(text):
        stable_key = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if stable_key in seen:
            continue
        seen.add(stable_key)
        raw_line = json.dumps(record, ensure_ascii=False)
        fields = _flatten_json(record)
        events.append(LogEvent(raw_line=raw_line, normalized_line=raw_line, fields=fields))
    return events


def parse_log(text: str, platform: str | None) -> list[LogEvent]:
    if platform in ("aws", "kubernetes"):
        json_events = _parse_json_records(text)
        # Always ALSO run text-line parsing (with windowing), even when some
        # records parsed cleanly - malformed/truncated JSON (a missing
        # brace, a dropped comma) means SOME records in the same paste can
        # fail strict parsing while others succeed. Short-circuiting on
        # "found at least one valid record" silently drops every record
        # that didn't individually parse, even though its raw text still
        # contains readable, matchable substrings (analyzer matches by
        # regex search, not structured JSON, so it doesn't need the record
        # to have parsed to find "eventName": "DeleteTrail" in it).
        text_events = _parse_text_lines(text)
        seen_raw = {e.raw_line for e in json_events}
        return json_events + [e for e in text_events if e.raw_line not in seen_raw]
    return _parse_text_lines(text)
