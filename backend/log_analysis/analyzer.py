"""Combines parsed log evidence with the deterministic mapping rules into a
deduplicated list of technique matches - one entry per matched technique,
keeping the highest-confidence evidence line found for it.
"""

from dataclasses import dataclass

from log_analysis.mappings import ALL_RULES, RULES_BY_PLATFORM
from log_analysis.parser import LogEvent


CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass
class TechniqueMatch:
    technique_name: str
    confidence: str
    reason: str
    source: str
    matched_line: str
    parent_hint: str | None = None


def analyze(events: list[LogEvent], platform: str | None) -> list[TechniqueMatch]:
    rules = RULES_BY_PLATFORM.get(platform or "", ALL_RULES) or ALL_RULES
    matches: dict[tuple[str, str | None], TechniqueMatch] = {}

    for event in events:
        haystack = event.normalized_line
        for rule in rules:
            if not rule.pattern.search(haystack):
                continue
            key = (rule.technique_name, rule.parent_hint)
            existing = matches.get(key)
            if existing and CONFIDENCE_RANK[existing.confidence] >= CONFIDENCE_RANK[rule.confidence]:
                continue
            matches[key] = TechniqueMatch(
                technique_name=rule.technique_name,
                confidence=rule.confidence,
                reason=rule.reason,
                source=rule.source,
                matched_line=event.raw_line,
                parent_hint=rule.parent_hint,
            )

    return sorted(
        matches.values(),
        key=lambda match: CONFIDENCE_RANK[match.confidence],
        reverse=True,
    )
