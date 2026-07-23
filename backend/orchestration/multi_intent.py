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

from dataclasses import dataclass, field
from typing import Any

from orchestration.pipeline import PipelineResult, Source, get_driver, run_pipeline
from orchestration.query_splitter import segment_query
from retrieval.guardrail import (
    ensure_entity_indexes,
    generate_dynamic_hint_entities,
    has_cybersecurity_signal,
)


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
    segments: list[AnswerSegment] = field(default_factory=list)


def _segment_is_valid(segment: str, driver) -> bool:
    """A candidate is a real question worth answering if it carries a
    cybersecurity keyword OR fuzzy-matches a known graph entity by name.

    The second check matters: keyword-free entity questions ("who ran the
    SolarWinds Compromise?", "what does Restrict Registry Permissions do?")
    have no signal word, and dropping them would silently lose a valid
    question. Chit-chat ("how are you doing today?") matches neither and is
    dropped.
    """
    if has_cybersecurity_signal(segment):
        return True
    if driver is None:
        return False
    try:
        return bool(generate_dynamic_hint_entities(segment))
    except Exception:
        return False


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

    candidates = segment_query(raw)
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
        valid = [c for c in candidates if _segment_is_valid(c, driver)]
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
        segments=segments,
    )
