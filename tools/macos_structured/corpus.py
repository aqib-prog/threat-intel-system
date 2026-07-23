"""Deterministic reader for sbousseaden/macOS-ATTACK-DATASET exports.

The upstream files are Elasticsearch exports, not a uniform JSON container:
some contain one object, some concatenate objects, some wrap events below
``hits.events``, and a small number use Python-style triple-quoted strings.
This adapter repairs only those explicitly defined serialization defects and
emits stable NDJSON.  It never edits or redistributes the source corpus.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator


class CorpusFormatError(ValueError):
    pass


def _replace_triple_quoted_strings(text: str) -> tuple[str, int]:
    output: list[str] = []
    cursor = 0
    replacements = 0
    while cursor < len(text):
        start = text.find('"""', cursor)
        if start < 0:
            output.append(text[cursor:])
            break
        output.append(text[cursor:start])
        end = text.find('"""', start + 3)
        if end < 0:
            raise CorpusFormatError("unterminated triple-quoted string")
        output.append(json.dumps(text[start + 3 : end], ensure_ascii=False))
        replacements += 1
        cursor = end + 3
    return "".join(output), replacements


def _remove_trailing_commas(text: str) -> tuple[str, int]:
    output: list[str] = []
    in_string = False
    escaped = False
    removals = 0
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "]}":
                removals += 1
                index += 1
                continue
        output.append(char)
        index += 1
    return "".join(output), removals


def _close_missing_root_before_next_object(text: str) -> tuple[str, int]:
    """Repair a missing root ``}`` before a new column-zero object.

    One upstream export closes its ``_source`` object but omits the enclosing
    Elasticsearch-hit brace before immediately starting the next hit.  The
    column-zero and depth-one requirements keep this narrower than generic
    brace balancing, which could silently reinterpret arbitrary bad JSON.
    """

    output: list[str] = []
    brace_depth = 0
    bracket_depth = 0
    in_string = False
    escaped = False
    line_start = True
    repairs = 0
    for char in text:
        if not in_string and line_start and char == "{" and brace_depth == 1 and bracket_depth == 0:
            output.extend(("}", "\n"))
            brace_depth -= 1
            repairs += 1
        output.append(char)
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth -= 1
        line_start = char == "\n"
    return "".join(output), repairs


def _decode_concatenated(text: str) -> Iterator[Any]:
    decoder = json.JSONDecoder()
    cursor = 0
    while cursor < len(text):
        while cursor < len(text) and (text[cursor].isspace() or text[cursor] == ","):
            cursor += 1
        if cursor >= len(text):
            return
        try:
            value, cursor = decoder.raw_decode(text, cursor)
        except json.JSONDecodeError as exc:
            raise CorpusFormatError(
                f"unparseable JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc
        yield value


def _iter_event_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            yield from _iter_event_objects(item)
        return
    if not isinstance(value, dict):
        raise CorpusFormatError(f"top-level value is not an event object: {type(value).__name__}")

    hits = value.get("hits")
    if isinstance(hits, dict):
        wrapped = hits.get("events")
        if not isinstance(wrapped, list):
            wrapped = hits.get("hits")
        if isinstance(wrapped, list):
            for item in wrapped:
                yield from _iter_event_objects(item)
            return

    # Elasticsearch hit wrappers are retained whole: Sigma source-field paths
    # such as process.command_line are still indexed by their leaf/full aliases,
    # while the untouched envelope remains available as raw evidence.
    if isinstance(value.get("_source"), dict):
        yield value
        return
    if "event" in value or "process" in value or "file" in value:
        yield value
        return
    raise CorpusFormatError("JSON object contains no recognized Elastic event")


def read_macos_attack_file(path: Path) -> tuple[str, dict[str, int]]:
    original = path.read_text(encoding="utf-8-sig")
    repaired, triple_quotes = _replace_triple_quoted_strings(original)
    repaired, trailing_commas = _remove_trailing_commas(repaired)
    repaired, missing_root_closures = _close_missing_root_before_next_object(repaired)
    records = [
        event
        for value in _decode_concatenated(repaired)
        for event in _iter_event_objects(value)
    ]
    if not records:
        raise CorpusFormatError("file yielded no Elastic events")
    ndjson = "\n".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for record in records
    )
    return ndjson + "\n", {
        "source_bytes": len(original.encode("utf-8")),
        "record_count": len(records),
        "triple_quoted_string_repairs": triple_quotes,
        "trailing_comma_repairs": trailing_commas,
        "missing_root_closure_repairs": missing_root_closures,
    }
