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

# Only invoke the model when a segment actually contains a coordinating
# conjunction that MIGHT join two questions. Word-boundary anchored so it never
# fires on the substring "or" inside "for"/"Operation"/"actor"/"more".
_CONJUNCTION_RE = re.compile(r"\b(?:and|or)\b|&", re.IGNORECASE)

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
    # otherwise keep the original segment intact.
    return intents if len(intents) >= 2 else [segment]


def decompose_query(query: str) -> list[str]:
    """Deterministic split first, then LLM-split only the segments that still
    contain a coordinating conjunction. A single-intent query returns a
    one-element list, identical to ``segment_query``."""
    candidates = segment_query(query)
    if not _ENABLED or len(candidates) == 0:
        return candidates

    result: list[str] = []
    for candidate in candidates:
        if _CONJUNCTION_RE.search(candidate):
            result.extend(_llm_split_segment(candidate))
        else:
            result.append(candidate)
    return result
