"""Deterministic multi-intent query splitting.

A single user turn can bundle several unrelated questions ("What techniques
does RIPTIDE use? Also who ran the SolarWinds Compromise?") and can be wrapped
in conversational filler ("Hey, how are you? Anyway, ..."). This module splits
such a turn into candidate sub-questions so each can be answered on its own.

Design choice: deterministic (regex) splitting, no LLM. The rest of the
pipeline has been hardened for reliability (identical answers across runs); an
LLM-based splitter would reintroduce exactly the non-determinism that work
removed. Splitting is intentionally conservative - it never splits on a bare
"and"/"or", which routinely joins compound entities inside one intent
("APT29 and Lazarus Group", "logon and network events").

Validity/security filtering (dropping chit-chat and gibberish) is NOT done
here - it needs the graph entity index and lives in multi_intent.py. This
module stays pure and unit-testable without a database or model.
"""

import re

# A real second question that begins with an additive adverb opens with a
# clause starter - an interrogative ("who/what/how...") or an imperative verb
# ("list/show/tell..."). Requiring one after the adverb is what separates a
# genuine new intent ("...also who uses it") from an adverb used MID-clause
# inside a single intent. The critical case: the alias phrase
# "S0002, also known as Mimikatz" - "known" is not a clause starter, so it is
# never split. Same protection for "also called / also referred to as ...".
_CLAUSE_STARTER = (
    r"what|which|who|whom|whose|when|where|why|how|"
    r"does|do|did|is|are|was|were|can|could|should|would|will|"
    r"list|show|tell|explain|describe|give|name"
)

# Boundaries between distinct questions: sentence/question terminators, hard
# line breaks, and additive adverbs that actually introduce a new clause. NOT
# bare "and"/"or" (they join compound entities within one intent), and NOT an
# additive adverb used mid-clause (guarded by the clause-starter lookahead).
# Biasing toward NOT splitting is safe: an un-split turn flows through the
# pipeline as a single question, exactly as it did before multi-intent existed.
_SPLIT_RE = re.compile(
    r"(?<=[.!?;])\s+"
    r"|\n+"
    r"|\b(?:also|additionally|separately|furthermore|moreover)\b[:,]?\s+"
    rf"(?=(?:{_CLAUSE_STARTER})\b)",
    re.IGNORECASE,
)

# Conversational lead-ins that can prefix a segment once split. Stripped from
# the front (repeatedly) so the residual question is clean for the pipeline's
# entity extraction. Deliberately anchored at the start only.
_LEADING_FILLER_RE = re.compile(
    r"^(?:hey|hi|hello|yo|ok(?:ay)?|so|well|anyway|anyways|"
    r"btw|and|also|plus|then|additionally|furthermore|moreover|"
    r"please|thanks|thank\s+you|um|uh|hmm|actually|by\s+the\s+way)"
    r"\b[\s,.:;\-]*",
    re.IGNORECASE,
)


def _strip_leading_filler(segment: str) -> str:
    """Remove stacked conversational lead-ins ("ok so anyway, ...")."""
    previous = None
    current = segment.strip()
    while current != previous:
        previous = current
        current = _LEADING_FILLER_RE.sub("", current, count=1).strip()
    return current


def segment_query(query: str) -> list[str]:
    """Split a raw query into ordered candidate sub-question strings.

    Pure and deterministic. Returns every non-empty candidate, including
    chit-chat/gibberish - the caller is responsible for validity filtering
    (see multi_intent.run_multi_pipeline). For a single-intent query this
    returns a one-element list (or empty for a blank query).
    """
    raw = str(query or "").strip()
    if not raw:
        return []

    candidates: list[str] = []
    for piece in _SPLIT_RE.split(raw):
        if piece is None:
            continue
        cleaned = _strip_leading_filler(piece).strip(" \t\r\n,;:")
        # A residue with no letters or digits (e.g. "!" left after stripping
        # "thanks") is punctuation, not a question - skip it.
        if cleaned and re.search(r"[A-Za-z0-9]", cleaned):
            candidates.append(cleaned)
    return candidates
