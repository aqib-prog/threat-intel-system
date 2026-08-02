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
from log_analysis.mixed_input import split_mixed_log_input, unwrap_log_code_fence
from orchestration.pipeline import (
    PipelineResult,
    Source,
    SuggestionAction,
    get_driver,
    run_pipeline,
)
from orchestration.query_decomposer import decompose_query
from retrieval.guardrail import (
    ensure_entity_indexes,
    generate_dynamic_hint_entities,
    has_cybersecurity_signal,
)
from retrieval.input_shape import is_bare_operational_command

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
    r"\?\s*$|^\s*(?:(?:and|also|then|now|next|finally|please)\s+)*(?:"
    r"what|which|who|whom|whose|when|where|why|how|"
    r"does|do|did|is|are|was|were|can|could|should|would|will|"
    r"list|show|tell|explain|describe|give|name|"
    r"analy[sz]e|investigate|summarize|identify|find|"
    r"write|build|create|generate|provide|help|"
    r"ignore|disregard|forget)\b",
    re.IGNORECASE,
)
_REDUNDANT_LOG_DIRECTIVE_RE = re.compile(
    r"^\s*(?:please\s+)?(?:(?:can|could|would)\s+you\s+)?(?:"
    r"analy[sz]e|investigate|review|summarize|explain|interpret"
    r")(?:\s+(?:this|the|these|following|provided|above|below))?"
    # Allow bounded platform/source qualifiers such as "Windows Sysmon" or
    # "AWS CloudTrail" without accepting arbitrary trailing instructions.
    r"(?:\s+[a-z0-9_.-]+){0,5}\s+"
    r"(?:log|logs|telemetry|event|events|record|records|paste)"
    r"(?:\s+(?:for\s+me|above|below|and\s+tell\s+me\s+what\s+happened))?"
    r"[\s.!?:-]*$",
    re.IGNORECASE,
)
_LOG_CONTEXT_RE = re.compile(
    r"\b(?:(?:this|the|these|provided|above|below|following)"
    r"(?:\s+[a-z0-9_.-]+){0,5}\s+"
    r"(?:log|logs|telemetry|event|events|record|records|paste)|"
    r"(?:log|logs|telemetry|event|events|record|records)\s+"
    r"(?:above|below))\b",
    re.IGNORECASE,
)
_LOG_ATTRIBUTION_RE = re.compile(
    r"\b(?:actor|actors|group|groups|campaign|campaigns|"
    r"attribut\w*|responsible|behind|prove|proof|who)\b",
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
    # Backend-authoritative UI identity. The frontend must not infer that a
    # large query string is a log by parsing it independently.
    display_title: str | None
    segment_kind: str
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
    suggestion_actions: list[SuggestionAction] = field(default_factory=list)


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
    suggestion_actions: list[SuggestionAction] = field(default_factory=list)
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
    # Structured cybersecurity references are meaningful even when their
    # alphabetic portion has no vowel ("T1055", "XSS"). Check this before the
    # natural-language gibberish heuristic so identifier-only sub-questions are
    # never discarded from a multi-intent turn.
    if has_cybersecurity_signal(s):
        return "route"
    tokens = re.findall(r"[A-Za-z']+", s)
    if not tokens or not any(_looks_like_word(t) for t in tokens):
        return "drop"  # gibberish / keyboard smash
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
        suggestion_actions=list(result.suggestion_actions),
        segments=[],
    )


def _answer_segment(
    query: str,
    result: PipelineResult,
    *,
    display_title: str | None = None,
    segment_kind: str = "question",
) -> AnswerSegment:
    """Convert one independently-routed result into a UI answer segment."""

    return AnswerSegment(
        query=query,
        display_title=display_title,
        segment_kind=segment_kind,
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
        suggestion_actions=list(result.suggestion_actions),
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
            # Technique/sub-technique names are not globally unique in ATT&CK
            # ("Cloud Account" exists under more than one parent). Prefer the
            # authoritative external id so top-level compatibility fields do
            # not collapse distinct sources from separate answer cards.
            identity = str(source.external_id or source.name)
            key = (identity, str(source.node_type))
            if key not in seen:
                seen.add(key)
                merged.append(source)
    return merged


def _as_multi(query: str, segments: list[AnswerSegment]) -> MultiPipelineResult:
    """Aggregate independently-guarded segments for backward-compatible clients."""

    return MultiPipelineResult(
        query=query,
        answer="\n\n".join(segment.answer for segment in segments if segment.answer),
        allowed=any(segment.allowed for segment in segments),
        guardrail_category=None,
        filters=_merge_filters(segments),
        sources=_merge_sources(segments),
        retrieved_count=sum(segment.retrieved_count for segment in segments),
        context_count=sum(segment.context_count for segment in segments),
        answer_source="rag",
        log_evidence=[entry for segment in segments for entry in segment.log_evidence],
        retrieved_contexts=[
            context for segment in segments for context in segment.retrieved_contexts
        ],
        suggestions=[label for segment in segments for label in segment.suggestions],
        suggestion_actions=[
            action for segment in segments for action in segment.suggestion_actions
        ],
        segments=segments,
    )


def _route_candidates(candidates: list[str], driver) -> list[str]:
    """Apply the existing route/drop policy without changing ownership."""

    return [
        candidate
        for candidate in candidates
        if _segment_disposition(candidate, driver) == "route"
    ]


def _is_redundant_log_directive(candidate: str) -> bool:
    """A request already satisfied by running the dedicated log analyzer."""

    return bool(_REDUNDANT_LOG_DIRECTIVE_RE.match(str(candidate or "")))


def _is_log_dependent_request(candidate: str) -> bool:
    """True when a question requires the supplied telemetry as context."""

    text = str(candidate or "")
    return bool(
        _LOG_CONTEXT_RE.search(text)
        or re.match(r"^\s*(?:based\s+on|using|from)\s+(?:this|the)\s+log\b", text, re.I)
    )


def _is_log_attribution_request(candidate: str) -> bool:
    return _is_log_dependent_request(candidate) and bool(
        _LOG_ATTRIBUTION_RE.search(candidate)
    )


def _log_attribution_notice(query: str) -> PipelineResult:
    """Never convert technique evidence into unsupported actor attribution."""

    return PipelineResult(
        query=query,
        answer=(
            "The telemetry can support evidence-backed ATT&CK technique mappings, "
            "but it does not by itself establish which threat actor or campaign "
            "was responsible. I won't infer attribution from technique overlap "
            "alone; use corroborating infrastructure, malware, identity, timeline, "
            "and campaign evidence before making that conclusion."
        ),
        allowed=True,
        guardrail_category=None,
        filters={},
        sources=[],
        retrieved_count=0,
        context_count=0,
        answer_source="rag",
    )


def run_multi_pipeline(query: str, *, driver=None, **kwargs) -> MultiPipelineResult:
    """Answer a turn that may bundle several questions.

    Falls back to a single ``run_pipeline`` call (identical to prior
    behaviour) whenever the turn resolves to zero or one valid sub-question.
    """
    raw = str(query or "").strip()
    if not raw:
        return _as_single(run_pipeline(raw, **kwargs))

    # Keep one operational paste atomic. Without this boundary, shell line
    # continuations can be decomposed into several apparent cyber intents and
    # trigger multiple expensive guardrail/retrieval calls.
    if is_bare_operational_command(raw):
        return _as_single(run_pipeline(raw, **kwargs))

    # A raw-log paste is kept intact unless a high-confidence structural
    # boundary separates it from explicit natural-language request(s). The log
    # and every request then run independently: malicious evidence inside a log
    # remains data, while a harmful appended request cannot ride along with it.
    standalone_log = unwrap_log_code_fence(raw)
    try:
        raw_detection = log_analysis_detector.detect(standalone_log)
    except Exception:
        raw_detection = None
    try:
        # A question before JSON can lower the whole-turn detector score even
        # though the central JSON block is unquestionably telemetry. Boundary
        # detection validates the candidate log block independently, so run it
        # for every turn; ordinary questions have no qualifying boundary.
        mixed_log = split_mixed_log_input(raw)
    except Exception:
        # A confirmed raw paste must fail safe to its established single path.
        if raw_detection is not None and raw_detection.is_raw_log:
            single = _as_single(run_pipeline(standalone_log, **kwargs))
            if standalone_log != raw:
                single.query = raw
            return single
        mixed_log = None
    if (
        raw_detection is not None
        and raw_detection.is_raw_log
        and mixed_log is None
    ):
        single = _as_single(run_pipeline(standalone_log, **kwargs))
        if standalone_log != raw:
            single.query = raw
        return single

    if mixed_log is not None:
        candidates = decompose_query(mixed_log.request_text)

        owned_driver = None
        if driver is None:
            try:
                driver = owned_driver = get_driver()
            except Exception:
                driver = None
        try:
            if driver is not None:
                ensure_entity_indexes(driver)
            routed: list[tuple[str, str]] = []
            for candidate in candidates:
                if _is_log_attribution_request(candidate):
                    routed.append(("attribution_notice", candidate))
                    continue
                if (
                    _is_redundant_log_directive(candidate)
                    or _is_log_dependent_request(candidate)
                ):
                    # The dedicated log card already answers evidence/mapping
                    # questions. Do not send a context-stripped version to RAG.
                    continue
                if _segment_disposition(candidate, driver) == "route":
                    routed.append(("question", candidate))
        finally:
            if owned_driver is not None:
                owned_driver.close()

        # A pure "analyze this log" suffix is already satisfied by the log
        # analyzer. It must not create a second, context-free RAG card.
        if not routed:
            single = _as_single(run_pipeline(mixed_log.log_text, **kwargs))
            single.query = raw
            return single

        log_result = run_pipeline(mixed_log.log_text, **kwargs)
        segments = [
            _answer_segment(
                mixed_log.log_text,
                log_result,
                display_title="Log Analysis",
                segment_kind="log_analysis",
            )
        ]
        for route_kind, sub_question in routed:
            if route_kind == "attribution_notice":
                segments.append(
                    _answer_segment(
                        sub_question,
                        _log_attribution_notice(sub_question),
                        display_title="Attribution requires more evidence",
                        segment_kind="notice",
                    )
                )
            else:
                segments.append(
                    _answer_segment(
                        sub_question,
                        run_pipeline(sub_question, **kwargs),
                    )
                )
        return _as_multi(raw, segments)

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
        valid = _route_candidates(candidates, driver)
    finally:
        if owned_driver is not None:
            owned_driver.close()

    # 0 valid: nothing but chit-chat/gibberish - let the single path return
    # its normal fallback for the whole turn. If decomposition found multiple
    # candidates but only one is valid, run that validated candidate rather
    # than reattaching the discarded gibberish/chit-chat to the harm gate.
    if not valid:
        return _as_single(run_pipeline(raw, **kwargs))
    if len(valid) == 1:
        return _as_single(run_pipeline(valid[0], **kwargs))

    segments: list[AnswerSegment] = []
    for sub_question in valid:
        result = run_pipeline(sub_question, **kwargs)
        segments.append(_answer_segment(sub_question, result))

    return _as_multi(raw, segments)
