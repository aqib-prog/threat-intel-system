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

import sys
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

from orchestration.pipeline import PipelineError, get_driver, run_pipeline  # noqa: E402
from retrieval.guardrail import extract_filters  # noqa: E402
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


class NodeSource(BaseModel):
    name: str
    external_id: str | None = None
    node_type: str
    relevance_score: float | None = None


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
    result = await run_in_threadpool(
        run_pipeline,
        payload.query,
        top_k=payload.top_k,
        candidate_k=payload.candidate_k,
    )
    latency_ms = int((perf_counter() - started) * 1000)
    nodes = [NodeSource(**source.__dict__) for source in result.sources]

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
    )
