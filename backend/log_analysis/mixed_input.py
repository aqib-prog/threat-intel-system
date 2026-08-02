"""Conservative boundary detection for a log paste plus user questions.

The raw-log detector intentionally treats the whole turn as telemetry. That is
correct for a plain paste, but it also means a question appended after the log
can be swallowed. This module identifies only high-confidence boundaries:

* exactly one side must still be a raw log;
* the other side must begin like an explicit question/request; and
* the request side must not contain any line that itself looks like telemetry.

Ambiguous inputs return ``None`` and retain the existing single-log behaviour.
This is deliberately a boundary detector, not a parser or content filter.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass

from log_analysis import detector


_REQUEST_START_RE = re.compile(
    r"^\s*(?:(?:and|also|then|now|next|finally|please)\s+)*(?:"
    r"what|which|who|whom|whose|when|where|why|how|"
    r"does|do|did|is|are|was|were|can|could|should|would|will|"
    r"list|show|tell|explain|describe|give|name|"
    r"analy[sz]e|investigate|summarize|identify|find|"
    r"write|build|create|generate|provide|help|"
    r"ignore|disregard|forget|based\s+on|using|from"
    r")\b",
    re.IGNORECASE,
)
_AUDITD_LINE_RE = re.compile(
    r"^\s*type=[A-Z0-9_]+\s+msg=audit\([^)]+\):",
    re.IGNORECASE,
)
_JSON_FRAGMENT_LINE_RE = re.compile(
    r'^\s*(?:[{}\[\],]|"[^"]+"\s*:)',
)
_JSON_START_RE = re.compile(r"[\[{]")
_KEY_VALUE_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.@/-]*$")
_OUTER_CODE_FENCE_RE = re.compile(
    r"^\s*```(?:json|jsonl|ndjson|log|text|plaintext)?[ \t]*\r?\n"
    r"(?P<body>.*?)\r?\n```\s*$",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class MixedLogInput:
    """A confidently separated raw-log block and natural-language request."""

    log_text: str
    request_text: str
    platform: str | None
    request_position: str  # "before" or "after"


def unwrap_log_code_fence(text: str) -> str:
    """Remove one complete Markdown fence without touching inner content."""

    raw = str(text or "").strip()
    match = _OUTER_CODE_FENCE_RE.fullmatch(raw)
    return match.group("body").strip() if match else raw


def _detect_log_candidate(text: str) -> tuple[str, detector.DetectionResult]:
    normalized = unwrap_log_code_fence(text)
    return normalized, detector.detect(normalized)


def _is_json_record(value: object) -> bool:
    if isinstance(value, dict):
        if isinstance(value.get("Records"), list):
            records = value["Records"]
            return bool(records) and all(isinstance(item, dict) for item in records)
        return True
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, dict) for item in value)
    )


def is_structured_json_log(text: str) -> bool:
    """True only for a complete JSON/NDJSON log, never arbitrary prose.

    This is useful at the trust boundary: text stored inside a valid telemetry
    field is data, even when it contains instruction-like words. A request
    outside the JSON is not structurally contained and therefore does not pass.
    """

    stripped = str(text or "").strip()
    if not stripped:
        return False
    try:
        value = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        value = None
    if _is_json_record(value):
        try:
            return detector.detect(stripped).is_raw_log
        except Exception:
            return False

    records: list[object] = []
    for line in stripped.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            records.append(json.loads(candidate))
        except (json.JSONDecodeError, ValueError):
            return False
    if not records or not all(_is_json_record(item) for item in records):
        return False
    try:
        return detector.detect(stripped).is_raw_log
    except Exception:
        return False


def is_structured_key_value_line(line: str) -> bool:
    """Recognize one shell-quoted key=value telemetry record.

    Every shell token must belong to a field assignment. This is deliberately
    strict: trailing prose or an appended instruction creates a non-assignment
    token and prevents the record from becoming a trusted data envelope.
    """
    stripped = str(line or "").strip()
    if not stripped:
        return False
    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        return False
    if len(tokens) < 2:
        return False
    for token in tokens:
        key, separator, value = token.partition("=")
        if not separator or not value or not _KEY_VALUE_KEY_RE.fullmatch(key):
            return False
    return True


def is_structured_line_log(text: str) -> bool:
    """True for a complete multi-record auditd/key=value telemetry envelope."""
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    if len(lines) < 2:
        return False
    if not all(
        _AUDITD_LINE_RE.match(line) or is_structured_key_value_line(line)
        for line in lines
    ):
        return False
    try:
        return detector.detect("\n".join(lines)).is_raw_log
    except Exception:
        return False


def _looks_like_telemetry_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if _AUDITD_LINE_RE.match(stripped):
        return True
    if is_structured_key_value_line(stripped):
        return True
    if _JSON_FRAGMENT_LINE_RE.match(stripped):
        return True
    try:
        if _is_json_record(json.loads(stripped.rstrip(","))):
            return True
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return detector.detect(stripped).is_raw_log
    except Exception:
        return True


def _is_clear_request(text: str) -> bool:
    stripped = str(text or "").strip()
    if not stripped or len(stripped) > 8000:
        return False
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    if not lines or len(lines) > 30:
        return False
    if not _REQUEST_START_RE.match(lines[0]):
        return False
    if any(_looks_like_telemetry_line(line) for line in lines):
        return False
    try:
        if detector.detect(stripped).is_raw_log:
            return False
    except Exception:
        return False
    return True


def _candidate_boundaries(text: str) -> list[int]:
    boundaries: set[int] = set()
    newline_matches = list(re.finditer(r"\n+", text))

    # Trailing requests: only retain newlines whose following text actually
    # opens like a request. A large NDJSON/auditd paste therefore does not make
    # us re-run the detector once per record (the old all-newlines approach was
    # quadratic in the number of log lines).
    for match in newline_matches:
        if _REQUEST_START_RE.match(text[match.end() :]):
            boundaries.add(match.end())

    # Complete leading JSON followed immediately by prose (with or without a
    # newline) has an authoritative end offset from the JSON decoder.
    leading = len(text) - len(text.lstrip())
    try:
        _, end = json.JSONDecoder().raw_decode(text[leading:])
        boundaries.add(leading + end)
    except (json.JSONDecodeError, ValueError):
        pass

    # Leading requests followed by line-oriented logs. Stop at the first
    # credible transition; later log lines must not become alternative split
    # points just because the whole input began with a question.
    if _REQUEST_START_RE.match(text):
        for match in newline_matches:
            left = text[: match.start()].strip()
            first_right_line = text[match.end() :].lstrip().splitlines()[0:1]
            if (
                first_right_line
                and _is_clear_request(left)
                and _looks_like_telemetry_line(first_right_line[0])
            ):
                boundaries.add(match.end())
                break

        # Same-line "question {JSON}" input. The first plausible JSON start is
        # enough; when it parses completely its authoritative end also supports
        # a second request after the log.
        json_start = _JSON_START_RE.search(text)
        if json_start:
            start = json_start.start()
            if _is_clear_request(text[:start]):
                boundaries.add(start)
                try:
                    _, relative_end = json.JSONDecoder().raw_decode(text[start:])
                    boundaries.add(start + relative_end)
                except (json.JSONDecodeError, ValueError):
                    pass

    return sorted(boundary for boundary in boundaries if 0 < boundary < len(text))


def split_mixed_log_input(text: str) -> MixedLogInput | None:
    """Split a mixed turn, or return ``None`` when the boundary is uncertain."""

    raw = str(text or "").strip()
    if not raw:
        return None

    matches: list[MixedLogInput] = []
    boundaries = _candidate_boundaries(raw)
    for boundary in boundaries:
        left = raw[:boundary].strip()
        right = raw[boundary:].strip()
        if not left or not right:
            continue
        try:
            normalized_left, left_detection = _detect_log_candidate(left)
            normalized_right, right_detection = _detect_log_candidate(right)
        except Exception:
            continue
        if left_detection.is_raw_log == right_detection.is_raw_log:
            continue
        if left_detection.is_raw_log and _is_clear_request(right):
            matches.append(
                MixedLogInput(
                    normalized_left,
                    right,
                    left_detection.platform,
                    "after",
                )
            )
        elif right_detection.is_raw_log and _is_clear_request(left):
            matches.append(
                MixedLogInput(
                    normalized_right,
                    left,
                    right_detection.platform,
                    "before",
                )
            )

    # Questions may legitimately surround one central log block. Preserve both
    # request regions, in their original order, while keeping the log itself as
    # one intact analyzer input.
    for start_index, start in enumerate(boundaries):
        before = raw[:start].strip()
        if not _is_clear_request(before):
            continue
        for end in boundaries[start_index + 1 :]:
            after = raw[end:].strip()
            if not _is_clear_request(after):
                continue
            candidate_log = raw[start:end].strip()
            if not candidate_log:
                continue
            try:
                log_text, log_detection = _detect_log_candidate(candidate_log)
            except Exception:
                continue
            if log_detection.is_raw_log:
                matches.append(
                    MixedLogInput(
                        log_text,
                        f"{before}\n{after}",
                        log_detection.platform,
                        "both",
                    )
                )

    if not matches:
        return None

    # The correct boundary preserves the largest contiguous request. A later
    # split that accidentally absorbs the first question into the log produces
    # a shorter request and therefore loses here.
    matches.sort(
        key=lambda item: (
            len(item.request_text),
            int(is_structured_json_log(item.log_text)),
            len(item.log_text),
        ),
        reverse=True,
    )
    best = matches[0]
    # Two equally plausible but different boundaries are unsafe to guess.
    if len(matches) > 1:
        second = matches[1]
        if (
            len(second.request_text) == len(best.request_text)
            and second.log_text != best.log_text
        ):
            return None
    return best
