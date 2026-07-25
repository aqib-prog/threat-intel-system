"""FastAPI REST API for the threat-intel GraphRAG pipeline.

Run from the backend directory:
    uvicorn api.app:app --reload

Note: deliberately no `from __future__ import annotations` here. With it,
annotations are stored as unevaluated strings, and slowapi's @limiter.limit
wrapper (defined in a different module) can't resolve names like
`QueryRequest` when FastAPI introspects the wrapped endpoint - it silently
falls back to treating the body model as a query param. Python 3.10+'s
native `X | None` and `dict[str, Any]` syntax don't need the future import.
"""

import re
import sys
import time
from pathlib import Path
from time import perf_counter
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.concurrency import run_in_threadpool


# Existing backend modules import `config`, `retrieval`, etc. as top-level modules.
# This keeps the API runnable both as `uvicorn api.app:app` from /backend and
# `uvicorn backend.api.app:app` from the repo root.
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from orchestration.pipeline import PipelineError, get_driver, normalize_query, run_pipeline  # noqa: E402
from orchestration.multi_intent import run_multi_pipeline  # noqa: E402
from observability import langfuse_tracing as obs  # noqa: E402
from retrieval.guardrail import extract_filters, has_cybersecurity_signal  # noqa: E402
from api.settings import load_settings  # noqa: E402
from api.stats import StatsResponse, get_stats  # noqa: E402
from security import (  # noqa: E402
    AUTH_ENABLED,
    SecurityHeadersMiddleware,
    is_auth_misconfigured,
    limiter,
    log_and_sanitize,
    require_api_key,
)


SETTINGS = load_settings()
FALLBACK_ERROR = "I don't have enough information about this in my knowledge base."


app = FastAPI(
    title=SETTINGS.title,
    version=SETTINGS.version,
    description="REST API for guarded MITRE ATT&CK GraphRAG retrieval and generation.",
)


@app.on_event("shutdown")
def _flush_langfuse_on_shutdown() -> None:
    # Traces are sent by a background batch exporter; flush pending ones on a
    # clean shutdown so the last few requests aren't lost. No-op when tracing
    # is disabled, and it swallows its own errors.
    obs.flush()

# CORS: browser-facing origin allowlist. Fails closed if CORS_ORIGINS is unset
# (see api/settings.py) rather than defaulting to "*".
app.add_middleware(
    CORSMiddleware,
    allow_origins=SETTINGS.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Response hardening headers (X-Frame-Options, nosniff, etc).
app.add_middleware(SecurityHeadersMiddleware)

# Per-IP rate limiting on LLM- and database-backed endpoints.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


class QueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=SETTINGS.max_query_chars)
    top_k: int = Field(SETTINGS.default_top_k, ge=1, le=SETTINGS.max_top_k)
    candidate_k: int = Field(
        SETTINGS.default_candidate_k,
        ge=1,
        le=SETTINGS.max_candidate_k,
    )
    # When true, never offer a spell-correction "did you mean" gate for this
    # request. The frontend sets it after the user answers the gate (Yes runs
    # the corrected query, No runs the original) so a correction is offered at
    # most once and can never loop.
    skip_correction: bool = False


class NodeSource(BaseModel):
    name: str
    external_id: str | None = None
    url: str | None = None
    node_type: str
    relevance_score: float | None = None


class CorrectionSuggestion(BaseModel):
    """A spell-correction the UI offers via a blocking Yes/No gate when the
    original query returned no information. Yes re-queries `suggested`, No
    re-queries `original`; both then run through the full guardrail + pipeline."""

    original: str
    suggested: str


class AnswerSection(BaseModel):
    label: str
    count: int


class LogEvidenceEntry(BaseModel):
    technique_id: str
    technique_name: str
    matched_line: str
    confidence: str


class AnswerSegmentResponse(BaseModel):
    """One answered sub-question of a multi-intent turn. Each carries its OWN
    answer_sections (so its chart shows that question's real counts) and its
    own grounded_ids/sources - the frontend renders one card per segment."""

    query: str
    answer: str
    allowed: bool
    guardrail_category: str | None = None
    answer_source: str = "rag"
    nodes: list[NodeSource] = []
    answer_sections: list[AnswerSection] = []
    log_evidence: list[LogEvidenceEntry] = []
    grounded_ids: list[str] = []
    # "Did you mean" candidates when this segment referenced an unresolved code.
    suggestions: list[str] = []


class QueryResponse(BaseModel):
    query: str
    response: str
    answer: str
    filters: dict[str, Any]
    nodes: list[NodeSource]
    sources: list[NodeSource]
    allowed: bool
    guardrail_category: str | None = None
    retrieved_count: int
    context_count: int
    latency_ms: int
    # "rag" (default) vs "log_analysis" - see orchestration/pipeline.py's
    # PipelineResult. Additive fields; existing clients that ignore them
    # keep working unchanged.
    answer_source: str = "rag"
    log_evidence: list[LogEvidenceEntry] = []
    # Structured, authoritative category counts (Tactics/Techniques/Malware/...)
    # computed server-side from the deterministic answer. The frontend charts
    # these directly instead of regex-parsing the prose (which mis-counted
    # narrative text). Empty when the answer has no chartable list sections.
    answer_sections: list[AnswerSection] = []
    # Populated only for a multi-intent turn (>=2 answered sub-questions); each
    # entry is a self-contained answer with its own chart data. Empty for a
    # single-intent turn, where the top-level fields are the whole answer -
    # so existing single-answer clients are unaffected.
    segments: list[AnswerSegmentResponse] = []
    # MITRE ATT&CK ids appearing in `answer` that ACTUALLY EXIST in our graph.
    # The frontend only renders a citation/link for an id in this list, so a
    # hallucinated or unknown id (e.g. a fabricated "G9999") is never shown as
    # a clickable source. Grounds every citation in our real knowledge base.
    grounded_ids: list[str] = []
    # "Did you mean" candidates when the query referenced an entity code that
    # did not resolve (e.g. an unknown APT number). The frontend renders these
    # as clickable chips; empty for a normal answer.
    suggestions: list[str] = []
    # A spell-correction the UI offers via a blocking Yes/No gate: set only when
    # a single-intent query returned no info AND normalizing its spelling
    # produced a different query worth trying. Null otherwise.
    correction: CorrectionSuggestion | None = None


# Same prefix set as the frontend MITRE_ID_PATTERN (longer prefixes first).
_MITRE_ID_RE = re.compile(
    r"\b(?:TA|DET|DC|DS|AN|T|G|S|M|C)\d{4}(?:\.\d{3})?\b", re.IGNORECASE
)
_ALL_EXTERNAL_IDS: set[str] | None = None
_ALL_EXTERNAL_IDS_EXPIRES_AT = 0.0


def _all_external_ids() -> set[str]:
    """Return graph external IDs from a short-lived in-process cache.

    A refresh failure returns an empty set for the current response so an
    unverified ID can never become a citation. The expired cache remains
    expired, allowing the next request to retry the database lookup.
    """
    global _ALL_EXTERNAL_IDS, _ALL_EXTERNAL_IDS_EXPIRES_AT
    now = time.time()
    if _ALL_EXTERNAL_IDS is not None and now < _ALL_EXTERNAL_IDS_EXPIRES_AT:
        return _ALL_EXTERNAL_IDS

    try:
        driver = get_driver()
        try:
            with driver.session() as session:
                record = session.run(
                    "MATCH (n) WHERE n.external_id IS NOT NULL "
                    "RETURN collect(DISTINCT n.external_id) AS ids"
                ).single()
                refreshed_ids = {
                    str(value).upper() for value in (record["ids"] or [])
                }
        finally:
            driver.close()
    except Exception as exc:
        log_and_sanitize(exc, stage="citation grounding refresh")
        return set()

    _ALL_EXTERNAL_IDS = refreshed_ids
    _ALL_EXTERNAL_IDS_EXPIRES_AT = now + SETTINGS.citation_cache_seconds
    return _ALL_EXTERNAL_IDS


def grounded_mitre_ids(answer: str) -> list[str]:
    """Ids mentioned in the answer (bare or inside embedded links) that exist
    in the graph. Anything else is dropped so no ungrounded citation renders."""
    mentioned = {match.group(0).upper() for match in _MITRE_ID_RE.finditer(answer or "")}
    if not mentioned:
        return []
    return sorted(mentioned & _all_external_ids())


# Chartable relationship categories, matched against a section header's leading
# text. Ordered most-specific first so "detection strategies" wins over a bare
# "detection", "related techniques" over "techniques", etc. The value is the
# canonical label the frontend's category metadata is keyed on.
_CHART_CATEGORY_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"detection strateg(?:y|ies)", re.I), "Detection Strategies"),
    (re.compile(r"data components?", re.I), "Data Components"),
    (re.compile(r"log sources?", re.I), "Log Sources"),
    (re.compile(r"parent techniques", re.I), "Parent Techniques"),
    (re.compile(r"related techniques?", re.I), "Related Techniques"),
    (re.compile(r"sub-?techniques?", re.I), "Subtechniques"),
    (re.compile(r"analytics?", re.I), "Analytics"),
    (re.compile(r"techniques?", re.I), "Techniques"),
    (re.compile(r"tactics?", re.I), "Tactics"),
    (re.compile(r"mitigations?", re.I), "Mitigations"),
    (re.compile(r"campaigns?", re.I), "Campaigns"),
    (re.compile(r"(?:threat )?(?:actors?|groups?)", re.I), "Actors"),
    (re.compile(r"malware", re.I), "Malware"),
    (re.compile(r"tools?", re.I), "Tools"),
    (re.compile(r"platforms?", re.I), "Platforms"),
    (re.compile(r"(?:aliases|also known as)", re.I), "Aliases"),
    (re.compile(r"procedures?", re.I), "Procedures"),
]
# Header lines that are narrative or single-value and must never be charted -
# this is what stops a Description paragraph's comma-separated prose (e.g. a
# list of targeted industries) from being miscounted as a category.
_NON_CHART_HEADER = re.compile(
    r"^(?:description|summary|overview|type|id|mitre\s*id|url|cve(?:\s*id)?|"
    r"parent technique)$",
    re.I,
)
_BULLET_RE = re.compile(r"^\s*(?:[-*•]|\d+\.)\s+\S")
_HEADER_RE = re.compile(r"^\s*(?:\*\*)?([^:\n]{2,90}?)(?:\*\*)?:\s*(.*)$")


def _canonical_chart_category(header_text: str) -> str | None:
    stripped = header_text.strip().strip("*").strip()
    if _NON_CHART_HEADER.match(stripped):
        return None
    for pattern, label in _CHART_CATEGORY_RULES:
        if pattern.search(stripped):
            return label
    return None


def _count_inline_items(value: str) -> int:
    cleaned = re.sub(r"\([^)]*\)", "", value)
    cleaned = re.sub(r"\band\b", ",", cleaned, flags=re.I)
    return sum(1 for part in cleaned.split(",") if len(part.strip()) > 1)


def compute_answer_sections(answer: str) -> list[AnswerSection]:
    """Extract authoritative {label, count} sections from the deterministic
    answer text so the frontend can chart real category counts WITHOUT
    re-parsing prose. Narrative/single-value headers are excluded, so a
    Description paragraph never becomes a fake category. Counts come from the
    bullet list under a header (or its inline comma list), whichever is larger.
    """
    lines = (answer or "").splitlines()
    counts: dict[str, int] = {}
    order: list[str] = []
    for index, line in enumerate(lines):
        match = _HEADER_RE.match(line)
        if not match:
            continue
        label = _canonical_chart_category(match.group(1))
        if not label:
            continue
        inline = match.group(2).strip()
        inline_count = _count_inline_items(inline) if inline else 0
        bullet_count = 0
        for follow in lines[index + 1:]:
            if _BULLET_RE.match(follow):
                bullet_count += 1
            elif follow.strip() == "":
                if bullet_count:
                    break
                continue
            else:
                break
        count = max(inline_count, bullet_count)
        if count < 1:
            continue
        if label not in counts:
            order.append(label)
        counts[label] = max(counts.get(label, 0), count)
    return [AnswerSection(label=label, count=counts[label]) for label in order]


class HealthResponse(BaseModel):
    status: str
    api_version: str
    environment: str
    neo4j: str
    pipeline: str
    auth: str


class FiltersResponse(BaseModel):
    active_filters: dict[str, Any]
    supported_filters: list[str]
    query: str | None = None


SUPPORTED_FILTERS = [
    "threat_actor",
    "malware",
    "tool",
    "campaign",
    "tactic",
    "technique",
    "mitre_id",
    "cve_id",
    "platform",
    "node_type",
    "analytic",
    "detection_strategy",
    "data_component",
    "is_subtechnique",
]


@app.exception_handler(PipelineError)
async def pipeline_error_handler(_: Request, exc: PipelineError) -> JSONResponse:
    # exc.cause may embed internal details (Neo4j URIs, auth failures, LLM
    # provider errors) - log the full exception server-side and only return
    # the stage name (safe, non-sensitive) plus a generic message to callers.
    safe_message = log_and_sanitize(exc.cause, stage=exc.stage)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": "pipeline_error",
            "stage": exc.stage,
            "message": safe_message,
            "response": FALLBACK_ERROR,
        },
    )


@app.exception_handler(ValueError)
async def value_error_handler(_: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "bad_request", "message": str(exc)},
    )


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"service": SETTINGS.title, "status": "ok", "environment": SETTINGS.environment}


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    neo4j_status = "ok"
    try:
        driver = get_driver()
        driver.close()
    except Exception:
        neo4j_status = "unavailable"

    # Surface a missing API key in staging/production as a visible ops
    # signal rather than silently running unauthenticated - see
    # security/auth.py.
    auth_misconfigured = is_auth_misconfigured(SETTINGS.environment)
    auth_status = "enabled" if AUTH_ENABLED else ("MISCONFIGURED" if auth_misconfigured else "disabled")

    overall = "ok" if neo4j_status == "ok" and not auth_misconfigured else "degraded"
    return HealthResponse(
        status=overall,
        api_version=SETTINGS.version,
        environment=SETTINGS.environment,
        neo4j=neo4j_status,
        pipeline="loaded",
        auth=auth_status,
    )


@app.get("/stats", response_model=StatsResponse)
@limiter.limit(SETTINGS.rate_limit_stats)
async def stats(request: Request) -> StatsResponse:
    """Live counts from the graph, for display (never hardcode these client-side)."""

    def fetch() -> StatsResponse:
        driver = get_driver()
        try:
            return get_stats(driver, ttl_seconds=SETTINGS.stats_cache_seconds)
        finally:
            driver.close()

    return await run_in_threadpool(fetch)


@app.get("/filters", response_model=FiltersResponse, dependencies=[Depends(require_api_key)])
@limiter.limit(SETTINGS.rate_limit_filters)
async def filters(
    request: Request,
    query: str | None = Query(
        default=None,
        description="Optional query to extract active filters for frontend display.",
        max_length=SETTINGS.max_query_chars,
    ),
) -> FiltersResponse:
    if not query:
        return FiltersResponse(
            query=None,
            active_filters={},
            supported_filters=SUPPORTED_FILTERS,
        )

    def extract() -> dict[str, Any]:
        driver = get_driver()
        try:
            return extract_filters(query, driver)
        finally:
            driver.close()

    active_filters = await run_in_threadpool(extract)
    return FiltersResponse(
        query=query,
        active_filters=active_filters,
        supported_filters=SUPPORTED_FILTERS,
    )


@app.post("/query", response_model=QueryResponse, dependencies=[Depends(require_api_key)])
@limiter.limit(SETTINGS.rate_limit_query)
async def query(request: Request, payload: QueryRequest) -> QueryResponse:
    if payload.candidate_k < payload.top_k:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="candidate_k must be greater than or equal to top_k",
        )

    started = perf_counter()
    # One Langfuse trace per query. No-op unless LANGFUSE_ENABLED; a tracing
    # failure can never affect the response (obs.* swallow their own errors).
    with obs.span("rag_query") as trace:
        try:
            # A turn may bundle several sub-questions. run_multi_pipeline answers
            # each through the SAME unchanged run_pipeline and, for a single-intent
            # turn, falls back to one run_pipeline call whose top-level fields are
            # byte-identical to before (segments == []).
            result = await run_in_threadpool(
                run_multi_pipeline,
                payload.query,
                top_k=payload.top_k,
                candidate_k=payload.candidate_k,
            )
        except PipelineError as exc:
            # Record which stage failed so the dashboard shows where it broke,
            # then let the existing handler format the 503 response.
            trace.update(level="ERROR", status_message=f"pipeline stage failed: {exc.stage}")
            trace.update_trace(
                input=payload.query,
                metadata={"failed_stage": exc.stage, "outcome": "pipeline_error"},
            )
            raise

        latency_ms = int((perf_counter() - started) * 1000)
        trace.update_trace(
            input=payload.query,
            output=result.answer,
            metadata={
                "allowed": result.allowed,
                "guardrail_category": result.guardrail_category,
                "retrieved_count": result.retrieved_count,
                "context_count": result.context_count,
                "answer_source": result.answer_source,
                "latency_ms": latency_ms,
                "outcome": "answered" if result.allowed else "blocked",
            },
        )
        if not result.allowed:
            # A block is a "failure" the user wants to spot in the dashboard.
            trace.update(
                level="WARNING",
                status_message=f"blocked: {result.guardrail_category or 'guardrail'}",
            )

    nodes = [NodeSource(**source.__dict__) for source in result.sources]
    grounded = await run_in_threadpool(grounded_mitre_ids, result.answer)
    answer_sections = compute_answer_sections(result.answer) if result.allowed else []

    # Spell-correction "did you mean" gate. Offered ONLY when: the client didn't
    # already answer a gate (skip_correction), this is a single-intent turn
    # (no segments), the answer is a plain "no info", and normalizing the query's
    # spelling yields a different query that still carries a cybersecurity signal
    # (so we never suggest turning a query into off-topic noise). The corrected
    # or original query the user picks is re-submitted and re-runs the full
    # guardrail + pipeline, so security is unchanged either way.
    correction: CorrectionSuggestion | None = None
    if (
        not payload.skip_correction
        and not result.segments
        and result.allowed
        and result.answer.strip() == FALLBACK_ERROR
    ):
        normalized = await run_in_threadpool(normalize_query, result.query)
        if normalized != result.query and has_cybersecurity_signal(normalized):
            # Pre-validate: only offer the correction if the corrected query
            # actually resolves. Otherwise we'd suggest "did you mean X" only for
            # X to also return no info (e.g. a fixed typo around a fake id like
            # T9999). One extra pipeline run, and only on this rare path.
            probe = await run_in_threadpool(
                run_multi_pipeline,
                normalized,
                top_k=payload.top_k,
                candidate_k=payload.candidate_k,
            )
            if probe.allowed and probe.answer.strip() != FALLBACK_ERROR:
                correction = CorrectionSuggestion(original=result.query, suggested=normalized)

    # Per-segment payload for a multi-intent turn. Each segment carries its OWN
    # answer_sections (so its radar/gauge shows THAT sub-question's real counts,
    # never the merged combined-answer counts) and its own grounded ids/sources.
    # Empty list for a single-intent turn, so existing clients are unaffected.
    segments: list[AnswerSegmentResponse] = []
    for seg in result.segments:
        seg_sections = compute_answer_sections(seg.answer) if seg.allowed else []
        seg_grounded = await run_in_threadpool(grounded_mitre_ids, seg.answer)
        segments.append(
            AnswerSegmentResponse(
                query=seg.query,
                answer=seg.answer,
                allowed=seg.allowed,
                guardrail_category=seg.guardrail_category,
                answer_source=seg.answer_source,
                nodes=[NodeSource(**source.__dict__) for source in seg.sources],
                answer_sections=seg_sections,
                log_evidence=[LogEvidenceEntry(**entry) for entry in seg.log_evidence],
                grounded_ids=seg_grounded,
                suggestions=list(seg.suggestions),
            )
        )

    return QueryResponse(
        query=result.query,
        response=result.answer,
        answer=result.answer,
        filters=result.filters,
        nodes=nodes,
        sources=nodes,
        allowed=result.allowed,
        guardrail_category=result.guardrail_category,
        retrieved_count=result.retrieved_count,
        context_count=result.context_count,
        latency_ms=latency_ms,
        answer_source=result.answer_source,
        log_evidence=[LogEvidenceEntry(**entry) for entry in result.log_evidence],
        answer_sections=answer_sections,
        segments=segments,
        grounded_ids=grounded,
        suggestions=list(result.suggestions),
        correction=correction,
    )
