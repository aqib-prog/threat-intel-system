"""Structural validation of a generated answer before it leaves the backend.

Why this exists
---------------
Answers are produced by two very different mechanisms. The deterministic
renderers emit a fixed, well-formed shape ("Tactics explicitly connected to
APT29:" followed by bullets). The free-form LLM fallback - reached whenever no
renderer's pattern matched the question - emits whatever the model wrote, and
that has been observed to include:

  * markdown bold labels ("**Tactics:**") the rest of the stack does not expect,
  * a section header with NO body at all, which renders as an empty titled
    panel and looks to a reader like data was lost,
  * punctuation residue on an otherwise empty header line ("**"), which the
    section counter then charted as one item.

Rather than trying to guarantee every question reaches a deterministic renderer
- impossible, since phrasing is unbounded - this module guarantees that
whatever comes out is structurally sound.

Design constraint
-----------------
It MUST be an exact no-op for answers that are already well-formed. Every
transformation below is conditioned on a defect actually being present, so a
deterministic answer passes through byte-identical. That property is the gate:
it is asserted against real pipeline output in the tests, not assumed.
"""

from __future__ import annotations

import re

# "**Tactics:**" / "**Summary:** text" - a bold label emitted by the free-form
# path. Rewritten to the plain "Tactics:" form the deterministic renderers and
# the section counter already understand.
_BOLD_LABEL_RE = re.compile(r"^(\s*)\*\*([^*\n]{1,80}?):\*\*[ \t]*(.*)$")

# The answer schema promised to the UI. A free-form model sometimes emits a
# valid bold heading without the required colon ("**Techniques**"), or splits
# the closing marker onto its own line ("**Techniques\n**"). Both are section
# headings, not prose emphasis, and must be canonicalized before the API builds
# answer_presentation.
_SECTION_LABELS = (
    "Summary",
    "Description",
    "Overview",
    "Type",
    "ID",
    "MITRE ID",
    "Aliases",
    "Actors",
    "Tactics",
    "Techniques",
    "Subtechniques",
    "Parent Technique",
    "Procedure",
    "Procedures",
    "Platforms",
    "Tools",
    "Malware",
    "Campaigns",
    "Mitigations",
    "Detection Strategies",
    "Data Sources",
    "Data Components",
    "Log Sources",
    "Analytics",
    "Strongest Evidence",
)
_SECTION_LABEL_BY_CASEFOLD = {label.casefold(): label for label in _SECTION_LABELS}
_SECTION_LABEL_PATTERN = "|".join(
    re.escape(label) for label in sorted(_SECTION_LABELS, key=len, reverse=True)
)
_BOLD_LABEL_WITHOUT_COLON_RE = re.compile(
    rf"^(\s*)\*\*\s*({_SECTION_LABEL_PATTERN})\s*\*\*\s*$",
    re.IGNORECASE,
)
_SPLIT_BOLD_LABEL_RE = re.compile(
    rf"^(\s*)\*\*\s*({_SECTION_LABEL_PATTERN})\s*:?\s*$",
    re.IGNORECASE,
)
_MARKER_ONLY_RE = re.compile(r"^\s*\*{2,}\s*$")
_SPACED_BALANCED_BOLD_RE = re.compile(r"^(\s*)\*\*\s+(.+?)\s*\*\*(\s*)$")
_SPACED_UNCLOSED_BOLD_RE = re.compile(r"^(\s*)\*\*\s+(.+)$")

# A label line with nothing after the colon once bold markers are gone.
_BARE_LABEL_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /&'-]{0,80}):\s*$")

# A markdown list item under a header.
_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")


def _has_body(lines: list[str], index: int) -> bool:
    """Whether the header at ``index`` is followed by any real content before
    the next header. Blank lines alone do not count as content."""
    for line in lines[index + 1:]:
        stripped = line.strip()
        if not stripped:
            continue
        if _BULLET_RE.match(line):
            return True
        # Another bare label means the previous header never got a body.
        if _BARE_LABEL_RE.match(line):
            return False
        # Any other non-empty prose counts as the header's value.
        return True
    return False


def sanitize_answer(answer: str) -> str:
    """Return the answer with structural defects removed.

    Byte-identical output for a well-formed answer.
    """
    if not answer:
        return answer

    # Pass 0 - repair malformed emphasis before interpreting section labels.
    # CommonMark deliberately renders an opener followed by whitespace as
    # literal asterisks, which is the exact "** APT29..." leak seen in the UI.
    # Standalone marker lines are always residue: useful strong emphasis is
    # necessarily attached to text on the same line in this answer contract.
    raw_lines = answer.splitlines()
    lines: list[str] = []
    index = 0
    while index < len(raw_lines):
        line = raw_lines[index]

        split_label = _SPLIT_BOLD_LABEL_RE.match(line)
        if (
            split_label
            and index + 1 < len(raw_lines)
            and _MARKER_ONLY_RE.match(raw_lines[index + 1])
        ):
            indent, label = split_label.groups()
            canonical = _SECTION_LABEL_BY_CASEFOLD[label.casefold()]
            lines.append(f"{indent}{canonical}:")
            index += 2
            continue

        no_colon_label = _BOLD_LABEL_WITHOUT_COLON_RE.match(line)
        if no_colon_label:
            indent, label = no_colon_label.groups()
            canonical = _SECTION_LABEL_BY_CASEFOLD[label.casefold()]
            lines.append(f"{indent}{canonical}:")
            index += 1
            continue

        if _MARKER_ONLY_RE.match(line):
            index += 1
            continue

        spaced_balanced = _SPACED_BALANCED_BOLD_RE.match(line)
        if spaced_balanced:
            indent, body, trailing = spaced_balanced.groups()
            lines.append(f"{indent}**{body.strip()}**{trailing}")
            index += 1
            continue

        spaced_unclosed = _SPACED_UNCLOSED_BOLD_RE.match(line)
        if spaced_unclosed and not line.rstrip().endswith("**"):
            indent, body = spaced_unclosed.groups()
            lines.append(f"{indent}{body.rstrip()}")
            index += 1
            continue

        lines.append(line)
        index += 1

    # Pass 1 - unwrap bold labels so every label has one canonical shape.
    unwrapped: list[str] = []
    for line in lines:
        match = _BOLD_LABEL_RE.match(line)
        if match:
            indent, label, tail = match.groups()
            unwrapped.append(f"{indent}{label}: {tail}".rstrip())
        else:
            unwrapped.append(line)

    # Pass 2 - drop headers that never received a body. Done after unwrapping so
    # a bold empty header ("**Tactics:**") is recognised the same as a plain one.
    kept: list[str] = []
    for index, line in enumerate(unwrapped):
        if _BARE_LABEL_RE.match(line) and not _has_body(unwrapped, index):
            continue
        kept.append(line)

    # Pass 3 - collapse blank runs left behind by a removed header, and strip a
    # leading/trailing blank so the answer starts and ends on content.
    text = "\n".join(kept)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
