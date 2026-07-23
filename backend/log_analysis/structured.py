"""Field-aware rule evaluation shared by the runtime and validation harness.

Structured conditions are generated offline from pySigma's parsed condition
tree.  The runtime representation deliberately contains only plain data and
compiled Python regexes; pySigma remains an offline build dependency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from itertools import product
from typing import Any, Mapping, Protocol, Sequence


class StructuredEvent(Protocol):
    normalized_line: str
    source_fields: Mapping[str, Sequence[str]]
    structured_complete: bool


def normalize_field_name(name: str) -> str:
    """Normalize vendor spelling without merging semantically distinct names."""

    return re.sub(r"[^a-z0-9]", "", name.casefold())


@lru_cache(maxsize=None)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _matcher_matches(matcher: Mapping[str, Any], value: str) -> bool:
    kind = matcher["kind"]
    if kind == "regex":
        return bool(_compile(str(matcher["pattern"])).search(value))
    if kind == "any":
        return any(_matcher_matches(child, value) for child in matcher["items"])
    raise ValueError(f"unknown structured matcher kind: {kind!r}")


def _condition_matches(
    node: Mapping[str, Any], source_fields: Mapping[str, Sequence[str]]
) -> bool:
    op = node["op"]
    if op == "field":
        values = source_fields.get(normalize_field_name(str(node["field"])), ())
        return any(_matcher_matches(node["matcher"], value) for value in values)
    if op == "and":
        return all(_condition_matches(child, source_fields) for child in node["items"])
    if op == "or":
        return any(_condition_matches(child, source_fields) for child in node["items"])
    if op == "not":
        return not _condition_matches(node["item"], source_fields)
    raise ValueError(f"unknown structured condition op: {op!r}")


def _requirements(node: Mapping[str, Any]) -> tuple[frozenset[str], ...]:
    """Return alternative positive-field sets sufficient to evaluate a rule.

    A complete JSON record is authoritative even when a field is absent: the
    absence is known, rather than an extraction failure.  These alternatives
    are used only for partial KV/Event-Viewer records, where raw fallback is
    retained until every positive field needed by one branch was extracted.
    """

    op = node["op"]
    if op == "field":
        return (frozenset({normalize_field_name(str(node["field"]))}),)
    if op == "not":
        return (frozenset(),)
    children = [_requirements(child) for child in node["items"]]
    if op == "or":
        return tuple(dict.fromkeys(item for alternatives in children for item in alternatives))
    if op != "and":
        raise ValueError(f"unknown structured condition op: {op!r}")

    combinations: list[frozenset[str]] = [frozenset()]
    for alternatives in children:
        combinations = [left | right for left, right in product(combinations, alternatives)]
        if len(combinations) > 256:
            # Pathological Boolean trees should fall back conservatively for
            # partial text records. Complete JSON records remain field-aware.
            merged = frozenset().union(*combinations)
            return (merged,)
    return tuple(dict.fromkeys(combinations))


def _referenced_fields(node: Mapping[str, Any]) -> frozenset[str]:
    op = node["op"]
    if op == "field":
        return frozenset({normalize_field_name(str(node["field"]))})
    if op == "not":
        return _referenced_fields(node["item"])
    return frozenset().union(*(_referenced_fields(child) for child in node["items"]))


@dataclass(frozen=True)
class StructuredCondition:
    tree: Mapping[str, Any]
    referenced_fields: frozenset[str]
    requirement_sets: tuple[frozenset[str], ...]
    positive_fields: frozenset[str]

    @classmethod
    def from_dict(cls, tree: Mapping[str, Any]) -> "StructuredCondition":
        requirements = _requirements(tree)
        positive = frozenset().union(*(item for item in requirements if item))
        if not positive:
            raise ValueError("structured condition has no positive field predicate")
        return cls(
            tree=tree,
            referenced_fields=_referenced_fields(tree),
            requirement_sets=requirements,
            positive_fields=positive,
        )

    def is_authoritative(self, event: StructuredEvent) -> bool:
        if event.structured_complete:
            return True
        available = frozenset(event.source_fields)
        return any(required and required <= available for required in self.requirement_sets)

    def matches(self, event: StructuredEvent) -> bool:
        return _condition_matches(self.tree, event.source_fields)


def hybrid_rule_matches(
    event: StructuredEvent,
    raw_pattern: re.Pattern[str],
    structured: StructuredCondition | None,
) -> tuple[bool, str]:
    """Evaluate one rule/event under the approved field-authoritative policy."""

    if structured is not None and structured.is_authoritative(event):
        return structured.matches(event), "structured"
    return bool(raw_pattern.search(event.normalized_line)), "raw"
