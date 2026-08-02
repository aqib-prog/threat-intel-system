"""LLM-assisted decomposition of "and/or"-joined compound questions.

The deterministic regex splitter (:mod:`orchestration.query_splitter`) handles
sentence terminators, newlines, and additive adverbs, and deliberately never
splits on a bare "and"/"or" because those also join a SINGLE intent
("compare APT29 and Lazarus Group", "tools and malware used by FIN7"). Whether a
given "and" separates two questions or joins one is genuinely ambiguous and no
regex can decide it - so for exactly those segments this module asks the local
llama3.1 model, constrained by a JSON schema.

Determinism: measured IDENTICAL over 20 runs at temperature 0 / seed 42 /
top_k 1, so this does not reintroduce run-to-run variation. Fail-safe: any
error, timeout, or disabled flag returns the segment unchanged, so the pipeline
degrades to the exact prior (regex-only) behaviour and never crashes.
"""

from __future__ import annotations

import json
import os
import re

from orchestration.query_splitter import segment_query

# Only invoke the model when a conjunction is followed by a new clause starter.
# A bare conjunction between entities/attributes is one intent ("APT29 and
# FIN7", "tools and malware", "shared by X and Y") and sending it to the model
# was the root cause of comparisons/intersections being destructively split.
_CLAUSE_STARTER = (
    r"what|which|who|whom|whose|when|where|why|how|"
    r"does|do|did|is|are|was|were|can|could|should|would|will|"
    r"list|show|tell|explain|describe|give|name"
)
_SEPARATE_CLAUSE_RE = re.compile(
    rf"(?:\b(?:and|or)\b|&)\s+(?=(?:{_CLAUSE_STARTER})\b)",
    re.IGNORECASE,
)

_STRUCTURED_REFERENCE_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,7}|(?:TA|DET|DC|DS|AN|T|G|S|M|C)\d{4}"
    r"(?:\.\d{3})?|(?:APT|FIN|UNC)\s*-?\s*\d{1,5})\b",
    re.IGNORECASE,
)
_REWRITE_SCAFFOLD_WORDS = {
    "a", "an", "and", "are", "does", "do", "for", "how", "is", "it", "list",
    "me", "of", "or", "show", "tell", "the", "to", "what", "which", "who",
}
_DEPENDENT_PRONOUN_RE = re.compile(
    r"\b(?:it|its|they|them|their|this|that|these|those|former|latter)\b",
    re.IGNORECASE,
)
_SUBJECT_SCAFFOLD_WORDS = {
    "a", "an", "and", "are", "can", "could", "deploy", "detect", "detections",
    "did", "do", "does", "explain", "for", "give", "has", "have", "how", "is",
    "it", "list", "me", "of", "or", "our", "please", "should", "show", "soc",
    "tell", "the", "to", "use", "uses", "what", "which", "who", "why", "would",
}

# A structured JSON schema forces the model to answer as a compiler, not a chat
# partner - eliminating prose drift and making the output parseable/repeatable.
_SCHEMA = {
    "type": "object",
    "properties": {
        "is_compound": {"type": "boolean"},
        "intents": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["is_compound", "intents"],
}

_SYSTEM = (
    "You are a deterministic query splitter for a cybersecurity threat-intel "
    "system.\n"
    "Split a user message into independent, standalone sub-questions ONLY when "
    "it contains genuinely separate requests about DIFFERENT subjects.\n\n"
    "RULES:\n"
    "1. A single intent that merely lists multiple entities or attributes with "
    "'and' is NOT compound. Set is_compound=false, intents=[].\n"
    "   - 'what tools and malware does FIN7 use' -> false\n"
    "   - 'compare APT29 and Lazarus Group' -> false\n"
    "   - 'what is mimikatz and how does it work' -> false\n"
    "2. Two requests about DIFFERENT subjects ARE compound. Set is_compound=true "
    "and return each as a complete standalone question that keeps its own "
    "entities and identifiers verbatim.\n"
    "   - 'what techniques does apt29 have and what is t1078' -> true, "
    "['what techniques does apt29 have', 'what is t1078']\n"
    "Return ONLY the JSON."
)

_MODEL = os.getenv("MULTI_INTENT_SPLIT_MODEL", "llama3.1")
# Enabled by default; set MULTI_INTENT_LLM_SPLIT=0 to force regex-only behaviour.
_ENABLED = os.getenv("MULTI_INTENT_LLM_SPLIT", "1").strip().lower() not in {"0", "false", "no"}
_TIMEOUT = float(os.getenv("MULTI_INTENT_SPLIT_TIMEOUT", "20"))

_client = None


def _get_client():
    global _client
    if _client is None:
        import ollama

        host = os.getenv("OLLAMA_HOST") or "http://127.0.0.1:11434"
        _client = ollama.Client(host=host, timeout=_TIMEOUT)
    return _client


def _has_independent_subject(intent: str) -> bool:
    """Whether a proposed card retains its own subject after splitting."""
    if _STRUCTURED_REFERENCE_RE.search(intent):
        return True
    content_words = [
        word
        for word in re.findall(r"[a-z0-9]+", intent.lower())
        if word not in _SUBJECT_SCAFFOLD_WORDS
    ]
    return bool(content_words)


def _llm_split_segment(segment: str) -> list[str]:
    """Ask the model whether ``segment`` is two questions. Returns the split
    sub-questions, or ``[segment]`` for a single intent or on ANY failure."""
    try:
        response = _get_client().chat(
            model=_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": segment},
            ],
            options={"temperature": 0.0, "seed": 42, "top_k": 1, "top_p": 0.0},
            format=_SCHEMA,
        )
        parsed = json.loads(response["message"]["content"])
    except Exception:
        return [segment]  # fail-safe: behave exactly like the regex-only path

    if not parsed.get("is_compound"):
        return [segment]
    intents = [str(item).strip() for item in parsed.get("intents", []) if str(item).strip()]
    # Guard against a destructive rewrite: require at least two real intents,
    # preserve every structured reference exactly, and reject any word the
    # model invented rather than copied from the source (apart from a tiny set
    # of grammatical scaffolding words). The model chooses a split boundary; it
    # is never trusted to rewrite the user's subjects or intent.
    if len(intents) < 2:
        return [segment]

    source_refs = sorted(
        re.sub(r"[\s-]+", "", match.group(0)).upper()
        for match in _STRUCTURED_REFERENCE_RE.finditer(segment)
    )
    output_refs = sorted(
        re.sub(r"[\s-]+", "", match.group(0)).upper()
        for intent in intents
        for match in _STRUCTURED_REFERENCE_RE.finditer(intent)
    )
    if output_refs != source_refs:
        return [segment]

    source_words = set(re.findall(r"[a-z0-9]+", segment.lower()))
    for intent in intents:
        # Each card is routed independently and has no conversational state.
        # A model output such as "what techniques do they use?" is therefore
        # not a valid split even when every word came from the source.
        if _DEPENDENT_PRONOUN_RE.search(intent):
            return [segment]
        words = re.findall(r"[a-z0-9]+", intent.lower())
        if not words:
            return [segment]
        for word in words:
            if word in source_words or word in _REWRITE_SCAFFOLD_WORDS:
                continue
            # Permit only trivial singular/plural or verb-agreement changes.
            if (
                word.rstrip("s") in {source.rstrip("s") for source in source_words}
                or word.rstrip("es") in {source.rstrip("es") for source in source_words}
            ):
                continue
            return [segment]
        if not _has_independent_subject(intent):
            return [segment]
    return intents


def decompose_query(query: str) -> list[str]:
    """Deterministic split first, then LLM-split only the segments that still
    contain a coordinating conjunction. A single-intent query returns a
    one-element list, identical to ``segment_query``."""
    candidates = segment_query(query)
    if not _ENABLED or len(candidates) == 0:
        return candidates

    result: list[str] = []
    for candidate in candidates:
        if _SEPARATE_CLAUSE_RE.search(candidate):
            result.extend(_llm_split_segment(candidate))
        else:
            result.append(candidate)
    return result
