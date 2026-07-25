"""Multi-intent orchestration: answer several questions bundled in one turn.

This wraps the existing, already-hardened ``run_pipeline`` rather than
modifying it. A turn is split into candidate sub-questions
(:mod:`orchestration.query_splitter`), chit-chat/gibberish candidates are
dropped, and each surviving valid sub-question is answered by an independent,
unchanged ``run_pipeline`` call. Single-intent turns take the exact same code
path they always did, so there is zero behavioural change for them.

Why a wrapper and not an edit to pipeline.py: every reliability, guardrail,
spelling-correction and grounding guarantee already proven for a single query
applies per sub-question automatically, and the single-intent path is
provably untouched.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from log_analysis import detector as log_analysis_detector
from orchestration.pipeline import PipelineResult, Source, get_driver, run_pipeline
from orchestration.query_decomposer import decompose_query
from retrieval.guardrail import (
    ensure_entity_indexes,
    generate_dynamic_hint_entities,
    has_cybersecurity_signal,
)

# A segment that survives filler-stripping but is a bare social phrase
# ("how are you", "good morning") is chit-chat, not a question to route.
_CHITCHAT_ONLY_RE = re.compile(
    r"^(?:how\s+(?:are|r)\s+(?:you|u)|how'?s?\s+it\s+going|what'?s\s+up|"
    r"good\s+(?:morning|afternoon|evening|day)|nice\s+to\s+meet\s+you|"
    r"how\s+do\s+you\s+do)\b[\s.!?]*$",
    re.IGNORECASE,
)
# Interrogative lead-ins / trailing "?" mark a genuine question worth routing
# even with no cyber keyword (an off-topic question gets a polite guardrail
# refusal rather than being silently dropped).
_QUESTION_RE = re.compile(
    r"\?\s*$|^\s*(?:what|which|who|whom|whose|when|where|why|how|"
    r"does|do|did|is|are|was|were|can|could|should|would|will|"
    r"list|show|tell|explain|describe|give|name)\b",
    re.IGNORECASE,
)


def _looks_like_word(token: str) -> bool:
    """A token that plausibly is a real word: has a vowel and isn't a random
    consonant/keyboard run. Filters gibberish like 'asdfghjkl', 'qwrtp'."""
    letters = re.sub(r"[^a-z]", "", token.lower())
    if len(letters) < 2:
        return False
    if not re.search(r"[aeiou]", letters):
        return False
    return not re.search(r"[bcdfghjklmnpqrstvwxz]{5,}", letters)


@dataclass
class AnswerSegment:
    """One answered sub-question within a multi-intent turn."""

    query: str
    answer: str
    filters: dict[str, Any]
    sources: list[Source]
    allowed: bool
    guardrail_category: str | None
    answer_source: str
    retrieved_count: int
    context_count: int
    log_evidence: list[dict[str, Any]] = field(default_factory=list)
    # Retrieved context strings for this segment, carried so an evaluator (RAGAS)
    # can score each segment's answer against its retrieved context. Populated
    # only when run_pipeline is called with include_contexts=True.
    retrieved_contexts: list[str] = field(default_factory=list)
    # "Did you mean" candidates when this segment referenced an unresolved code.
    suggestions: list[str] = field(default_factory=list)


@dataclass
class MultiPipelineResult:
    """Top-level result. ``segments`` is empty for single-intent turns, in
    which case the top-level fields mirror a plain ``PipelineResult`` exactly.
    For multi-intent turns the top-level fields are aggregates across segments
    (for back-compat clients that ignore ``segments``)."""

    query: str
    answer: str
    allowed: bool
    guardrail_category: str | None
    filters: dict[str, Any]
    sources: list[Source]
    retrieved_count: int
    context_count: int
    answer_source: str = "rag"
    log_evidence: list[dict[str, Any]] = field(default_factory=list)
    # Aggregate retrieved contexts (single-intent: the one answer's contexts).
    retrieved_contexts: list[str] = field(default_factory=list)
    # "Did you mean" candidates (single-intent: the one answer's suggestions).
    suggestions: list[str] = field(default_factory=list)
    segments: list[AnswerSegment] = field(default_factory=list)


def _segment_disposition(segment: str, driver) -> str:
    """Decide what to do with a candidate segment. Returns:

    - "route": send to run_pipeline (a real cybersecurity question, OR a
      genuine off-topic question — the latter gets a polite guardrail refusal
      instead of being silently dropped, which is the more transparent UX).
    - "drop": chit-chat or gibberish, silently removed.

    Cybersecurity signal / entity match is the fast "definitely answer" path.
    A grammatical question with neither is still routed (guardrail decides
    on/off-topic tone). Only bare social phrases and gibberish are dropped.
    """
    s = segment.strip()
    if not s:
        return "drop"
    tokens = re.findall(r"[A-Za-z']+", s)
    if not tokens or not any(_looks_like_word(t) for t in tokens):
        return "drop"  # gibberish / keyboard smash
    if has_cybersecurity_signal(s):
        return "route"
    if driver is not None:
        try:
            if generate_dynamic_hint_entities(s):
                return "route"
        except Exception:
            pass
    if _CHITCHAT_ONLY_RE.match(s):
        return "drop"  # "how are you", "good morning"
    if _QUESTION_RE.search(s):
        return "route"  # genuine off-topic question -> guardrail soft-refuses
    return "drop"


def _as_single(result: PipelineResult) -> MultiPipelineResult:
    return MultiPipelineResult(
        query=result.query,
        answer=result.answer,
        allowed=result.allowed,
        guardrail_category=result.guardrail_category,
        filters=result.filters,
        sources=result.sources,
        retrieved_count=result.retrieved_count,
        context_count=result.context_count,
        answer_source=result.answer_source,
        log_evidence=result.log_evidence,
        retrieved_contexts=list(result.retrieved_contexts),
        suggestions=list(result.suggestions),
        segments=[],
    )


def _merge_filters(segments: list[AnswerSegment]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for segment in segments:
        for key, value in (segment.filters or {}).items():
            values = value if isinstance(value, list) else [value]
            bucket = merged.setdefault(key, [])
            for item in values:
                if item not in bucket:
                    bucket.append(item)
    return merged


def _merge_sources(segments: list[AnswerSegment]) -> list[Source]:
    merged: list[Source] = []
    seen: set[tuple[str, str]] = set()
    for segment in segments:
        for source in segment.sources:
            key = (str(source.name), str(source.node_type))
            if key not in seen:
                seen.add(key)
                merged.append(source)
    return merged


def run_multi_pipeline(query: str, *, driver=None, **kwargs) -> MultiPipelineResult:
    """Answer a turn that may bundle several questions.

    Falls back to a single ``run_pipeline`` call (identical to prior
    behaviour) whenever the turn resolves to zero or one valid sub-question.
    """
    raw = str(query or "").strip()
    if not raw:
        return _as_single(run_pipeline(raw, **kwargs))

    # A raw-log paste must NOT be split: the log detector needs the whole
    # multi-line block together, and sentence/newline splitting would fragment
    # it line-by-line. Hand the intact paste to the single path, where
    # run_pipeline's own log-analysis branch handles it.
    try:
        if log_analysis_detector.detect(raw).is_raw_log:
            return _as_single(run_pipeline(raw, **kwargs))
    except Exception:
        pass

    candidates = decompose_query(raw)
    if len(candidates) <= 1:
        return _as_single(run_pipeline(raw, **kwargs))

    owned_driver = None
    if driver is None:
        try:
            driver = owned_driver = get_driver()
        except Exception:
            driver = None
    try:
        if driver is not None:
            ensure_entity_indexes(driver)
        valid = [c for c in candidates if _segment_disposition(c, driver) == "route"]
    finally:
        if owned_driver is not None:
            owned_driver.close()

    # 0 valid: nothing but chit-chat/gibberish - let the single path return
    # its normal fallback for the whole turn. 1 valid: a single real question
    # (the pipeline's own focus_security_query already strips the filler), so
    # run it exactly as before.
    if len(valid) <= 1:
        return _as_single(run_pipeline(raw, **kwargs))

    segments: list[AnswerSegment] = []
    for sub_question in valid:
        result = run_pipeline(sub_question, **kwargs)
        segments.append(
            AnswerSegment(
                query=sub_question,
                answer=result.answer,
                filters=result.filters,
                sources=result.sources,
                allowed=result.allowed,
                guardrail_category=result.guardrail_category,
                answer_source=result.answer_source,
                retrieved_count=result.retrieved_count,
                context_count=result.context_count,
                log_evidence=result.log_evidence,
                retrieved_contexts=list(result.retrieved_contexts),
                suggestions=list(result.suggestions),
            )
        )

    combined_answer = "\n\n".join(segment.answer for segment in segments if segment.answer)
    return MultiPipelineResult(
        query=raw,
        answer=combined_answer,
        allowed=any(segment.allowed for segment in segments),
        guardrail_category=None,
        filters=_merge_filters(segments),
        sources=_merge_sources(segments),
        retrieved_count=sum(segment.retrieved_count for segment in segments),
        context_count=sum(segment.context_count for segment in segments),
        answer_source="rag",
        log_evidence=[entry for segment in segments for entry in segment.log_evidence],
        retrieved_contexts=[c for segment in segments for c in segment.retrieved_contexts],
        segments=segments,
    )
