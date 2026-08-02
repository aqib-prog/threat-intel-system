#!/usr/bin/env python3
"""Comprehensive live API validation for the production chatbot.

This is intentionally separate from unit tests. It calls the running FastAPI
``/query`` endpoint and therefore exercises the real guardrails, Ollama,
Neo4j retrieval, generation, orchestration, citation grounding, and the JSON
contract consumed by the frontend.

Coverage:
* 156 independently verified Phase-E golden cases across 13 relationship types
* 24 multi-intent, noise, invalid-input, and raw-log orchestration scenarios
* 20 adversarial mixed-log and frontend-contract scenarios
* 70 defensive-domain and technical-reference false-positive guard cases

Every raw response and every expected-vs-actual fact diff is checkpointed.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
import urllib.error


REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RAG_ACCURACY = REPO / "tools" / "rag_accuracy"
GUARDRAIL_BASELINE = REPO / "tools" / "guardrail_baseline"
PARSED = REPO / "backend" / "data" / "parsed"
DEFAULT_REPORT = Path("/tmp/live-production-suite-report.json")
DEFAULT_MARKDOWN_REPORT = Path("/tmp/live-production-suite-report.md")
SCHEMA_VERSION = "live_production_suite_v1"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(RAG_ACCURACY))

import run_mixed_query_scenarios as mixed  # noqa: E402
from evaluate_rag import load_final_golden_set_cases, sha256_file  # noqa: E402


MITRE_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:T\d{4}(?:\.\d{3})?|TA\d{4}|M\d{4}|G\d{4}|S\d{4}|C\d{4}|"
    r"DET\d{4}|AN\d{4}|DC\d{4})"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
NEGATION_RE = re.compile(
    r"\b(?:no|not|none|never|neither|without|isn't|aren't|doesn't|don't|"
    r"does\s+not|do\s+not|no\s+active)\b",
    re.IGNORECASE,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def extract_mitre_ids(text: str) -> set[str]:
    return {match.group(0).upper() for match in MITRE_ID_RE.finditer(text or "")}


def extract_catalogued_mitre_ids(
    text: str,
    catalog: dict[str, dict[str, Any]],
) -> set[str]:
    """Extract ATT&CK IDs while resolving the TA#### naming collision.

    MITRE tactic IDs use TA####, but several threat-actor canonical names also
    use that shape (for example TA2541). A TA#### token is an ID only when it
    exists in the pinned tactic/entity catalog. Other prefixes do not have this
    known naming collision and remain visible so fabricated IDs such as T9999
    are still diagnosed as ungrounded.
    """
    return {
        external_id
        for external_id in extract_mitre_ids(text)
        if not external_id.startswith("TA") or external_id in catalog
    }


def normalize_text(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9.]+", (text or "").casefold()))


def _contains_name(answer: str, name: str) -> bool:
    return normalize_text(name) in normalize_text(answer)


def load_entity_catalog() -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for path in sorted(PARSED.glob("*.json")):
        if path.name == "relationships.json":
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            continue
        for item in payload:
            external_id = str(item.get("external_id") or "").upper()
            if not external_id:
                continue
            if external_id in catalog and catalog[external_id].get("name") != item.get(
                "name"
            ):
                raise RuntimeError(f"conflicting pinned names for {external_id}")
            catalog[external_id] = {
                "name": str(item.get("name") or ""),
                "url": item.get("url"),
                "source_file": path.name,
            }
    return catalog


def load_multi_intent_scenarios() -> tuple[list[dict[str, Any]], str]:
    path = RAG_ACCURACY / "golden_set_multi_intent.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list):
        raise RuntimeError("multi-intent golden artifact lacks scenarios")
    if payload.get("scenario_count") != len(scenarios) or len(scenarios) != 24:
        raise RuntimeError(
            f"multi-intent scenario count mismatch: {len(scenarios)}"
        )
    final_path = RAG_ACCURACY / "final_golden_set.json"
    if payload.get("source_golden_artifact_sha256") != sha256_file(final_path):
        raise RuntimeError("multi-intent artifact points to a changed final golden set")
    return scenarios, sha256_file(path)


def load_guardrail_allow_cases() -> list[dict[str, Any]]:
    specs = (
        ("domain_benign", "domain_benign_set.json", 64),
        ("reference_guard", "reference_guard_set.json", 6),
    )
    loaded: list[dict[str, Any]] = []
    for cohort, filename, expected_count in specs:
        path = GUARDRAIL_BASELINE / filename
        payload = json.loads(path.read_text(encoding="utf-8"))
        cases = payload.get("cases")
        if not isinstance(cases, list) or len(cases) != expected_count:
            raise RuntimeError(
                f"{filename} has {len(cases) if isinstance(cases, list) else 'invalid'} "
                f"cases; expected {expected_count}"
            )
        for case in cases:
            if case.get("expected_allowed") is not True:
                raise RuntimeError(
                    f"{filename}/{case.get('id')} is not an allow-case"
                )
            loaded.append(
                {
                    **case,
                    "cohort": cohort,
                    "artifact": filename,
                    "artifact_sha256": sha256_file(path),
                }
            )
    return loaded


def load_golden_index() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    cases = load_final_golden_set_cases()
    artifact_cache: dict[str, dict[str, dict[str, Any]]] = {}
    for case in cases:
        artifact = case["golden_artifact"]
        if artifact not in artifact_cache:
            path = RAG_ACCURACY / artifact
            payload = json.loads(path.read_text(encoding="utf-8"))
            pairs = payload.get("pairs")
            if not isinstance(pairs, list):
                raise RuntimeError(f"{artifact} does not contain a pairs list")
            artifact_cache[artifact] = {
                str(pair.get("id")): pair
                for pair in pairs
                if isinstance(pair, dict) and pair.get("id")
            }
        source_pair = artifact_cache[artifact].get(case["source_case_id"])
        if source_pair is None:
            raise RuntimeError(
                f"{artifact} does not contain source pair "
                f"{case['source_case_id']!r}"
            )
        case["source_pair"] = source_pair
    return cases, {case["case_id"]: case for case in cases}


def _entity_records(value: Any) -> dict[str, str]:
    """Return the entity at each structured golden leaf.

    Entity dictionaries can contain descriptive nested metadata (for example,
    a technique's full tactic list). Once a dictionary identifies its own
    entity, those nested fields are provenance rather than additional answer
    requirements and must not be promoted into mandatory facts.
    """
    records: dict[str, str] = {}
    if isinstance(value, dict):
        external_id = value.get("external_id")
        if isinstance(external_id, str) and external_id:
            records[external_id.upper()] = str(value.get("name") or "")
            return records
        for nested in value.values():
            records.update(_entity_records(nested))
    elif isinstance(value, list):
        for nested in value:
            records.update(_entity_records(nested))
    return records


def golden_fact_expectations(
    case: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
) -> tuple[dict[str, str], set[str], bool]:
    """Derive answer facts from structured truth, not explanatory prose.

    Most golden answers are complete lists, so every entity in their expected
    answer is required. Adversarial negative answers additionally explain a
    nearby true relationship; those contrast entities are useful context but
    are not facts the production answer must repeat. For those cases, only the
    directly queried entities and any structured expected results are required.
    """
    source_pair = case.get("source_pair")
    reference = str(case.get("reference") or "")
    if not isinstance(source_pair, dict):
        expected_ids = extract_catalogued_mitre_ids(reference, catalog)
        return (
            {
                external_id: str(catalog.get(external_id, {}).get("name") or "")
                for external_id in expected_ids
            },
            expected_ids,
            bool(NEGATION_RE.search(reference)),
        )

    source_answer = str(source_pair.get("expected_answer") or reference)
    answer_ids = extract_catalogued_mitre_ids(source_answer, catalog)
    expected_results: dict[str, str] = {}
    for key, value in source_pair.items():
        if key.startswith("expected_"):
            expected_results.update(_entity_records(value))

    case_type = str(source_pair.get("case_type") or "")
    explicit_negative = (
        source_pair.get("relationship_exists") is False
        or "negative" in case_type
    )
    if explicit_negative:
        required: dict[str, str] = {}
        for key, value in source_pair.items():
            if key in {
                "id",
                "question",
                "expected_answer",
                "provenance",
                "case_type",
                "relationship_type",
            }:
                continue
            if key.startswith("expected_"):
                continue
            required.update(_entity_records(value))
        required.update(expected_results)
        for external_id in extract_catalogued_mitre_ids(
            str(source_pair.get("question") or ""), catalog
        ):
            required.setdefault(
                external_id,
                str(catalog.get(external_id, {}).get("name") or ""),
            )
    else:
        required = {
            external_id: str(catalog.get(external_id, {}).get("name") or "")
            for external_id in answer_ids
        }

    allowed_ids = answer_ids | set(required)
    expects_negative = explicit_negative or not expected_results
    return required, allowed_ids, expects_negative


def error(code: str, message: str, **detail: Any) -> dict[str, Any]:
    return {"code": code, "message": message, **detail}


def validate_api_contract(
    response: dict[str, Any],
    catalog: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    catalog = catalog or load_entity_catalog()
    required = {
        "query",
        "answer",
        "response",
        "filters",
        "allowed",
        "guardrail_category",
        "retrieved_count",
        "context_count",
        "latency_ms",
        "answer_source",
        "nodes",
        "sources",
        "answer_sections",
        "answer_presentation",
        "log_evidence",
        "segments",
        "grounded_ids",
        "suggestions",
        "suggestion_actions",
        "correction",
    }
    missing = sorted(required - set(response))
    if missing:
        errors.append(
            error(
                "schema_missing_fields",
                f"top-level response omitted required fields: {missing}",
                fields=missing,
            )
        )
        return errors
    if response.get("answer") != response.get("response"):
        errors.append(
            error(
                "schema_answer_alias_mismatch",
                "answer and backward-compatible response fields differ",
            )
        )
    if response.get("nodes") != response.get("sources"):
        errors.append(
            error(
                "schema_source_alias_mismatch",
                "nodes and sources fields differ",
            )
        )
    if not isinstance(response.get("segments"), list):
        errors.append(error("schema_segments_type", "segments is not a list"))
        return errors
    units = [response, *response["segments"]]
    for index, unit in enumerate(units):
        label = "top_level" if index == 0 else f"segment_{index}"
        unit_required = {
            "answer",
            "allowed",
            "guardrail_category",
            "answer_source",
            "nodes",
            "answer_sections",
            "answer_presentation",
            "log_evidence",
            "grounded_ids",
            "suggestions",
            "suggestion_actions",
        }
        if index:
            unit_required.update({"query", "display_title", "segment_kind"})
        for field in sorted(unit_required):
            if field not in unit:
                errors.append(
                    error(
                        "schema_unit_missing_field",
                        f"{label} omitted {field}",
                        unit=label,
                        field=field,
                    )
                )
        if not isinstance(unit.get("grounded_ids", []), list):
            errors.append(
                error(
                    "schema_grounded_ids_type",
                    f"{label}.grounded_ids is not a list",
                    unit=label,
                )
            )
        answer_ids = extract_catalogued_mitre_ids(
            str(unit.get("answer") or ""), catalog
        )
        query_ids = extract_catalogued_mitre_ids(
            str(unit.get("query") or response.get("query") or ""), catalog
        )
        grounded_ids = {
            str(value).upper() for value in (unit.get("grounded_ids") or [])
        }
        impossible_grounding = sorted(grounded_ids - answer_ids)
        if impossible_grounding:
            errors.append(
                error(
                    "grounded_id_absent_from_answer",
                    f"{label} grounded IDs not present in its answer",
                    unit=label,
                    ids=impossible_grounding,
                )
            )
        ungrounded_claims = sorted(answer_ids - grounded_ids - query_ids)
        if ungrounded_claims:
            errors.append(
                error(
                    "ungrounded_answer_ids",
                    f"{label} contains non-input IDs absent from grounded_ids",
                    unit=label,
                    ids=ungrounded_claims,
                )
            )
        source_candidates = [
            *(unit.get("nodes") or []),
            *(unit.get("sources") or []),
        ]
        seen_sources: set[str] = set()
        for source in source_candidates:
            source_key = json.dumps(source, sort_keys=True, default=str)
            if source_key in seen_sources:
                continue
            seen_sources.add(source_key)
            if not source.get("name") or not source.get("node_type"):
                errors.append(
                    error(
                        "schema_invalid_source",
                        f"{label} source omitted name or node_type",
                        unit=label,
                        source=source,
                    )
                )
            url = source.get("url")
            external_id = str(source.get("external_id") or "")
            is_mitre_id = external_id.upper() in extract_mitre_ids(external_id)
            if is_mitre_id and url and not str(url).startswith(
                "https://attack.mitre.org/"
            ):
                errors.append(
                    error(
                        "non_authoritative_mitre_url",
                        f"{external_id} source URL is not an official ATT&CK URL",
                        unit=label,
                        external_id=external_id,
                        url=url,
                    )
                )
    return errors


def compare_golden_answer(
    unit: dict[str, Any],
    case: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    answer = str(unit.get("answer") or "")
    reference = str(case.get("reference") or "")
    required_entities, allowed_ids, expects_negation = golden_fact_expectations(
        case, catalog
    )
    expected_ids = set(required_entities)
    answer_ids = extract_catalogued_mitre_ids(answer, catalog)
    grounded_ids = {
        str(value).upper() for value in (unit.get("grounded_ids") or [])
    }
    missing_ids = sorted(
        external_id
        for external_id, name in required_entities.items()
        if external_id not in answer_ids
        and (not name or not _contains_name(answer, name))
    )
    unexpected_ids = sorted(answer_ids - allowed_ids)
    ungrounded_ids = sorted(answer_ids - grounded_ids)
    actual_negation = bool(NEGATION_RE.search(answer))

    errors: list[dict[str, Any]] = []
    if unit.get("allowed") is not True:
        errors.append(
            error(
                "golden_query_blocked",
                "a verified benign golden query was blocked",
                guardrail_category=unit.get("guardrail_category"),
            )
        )
    if not answer.strip():
        errors.append(error("empty_answer", "pipeline returned an empty answer"))
    if missing_ids:
        errors.append(
            error(
                "missing_expected_ids",
                f"answer omitted expected ATT&CK IDs: {missing_ids}",
                ids=missing_ids,
            )
        )
    if unexpected_ids:
        errors.append(
            error(
                "unexpected_answer_ids",
                "answer added ATT&CK IDs absent from the complete golden answer",
                ids=unexpected_ids,
            )
        )
    if ungrounded_ids:
        errors.append(
            error(
                "ungrounded_answer_ids",
                "answer mentioned IDs that the API could not ground in Neo4j",
                ids=ungrounded_ids,
            )
        )
    if expects_negation and not actual_negation:
        errors.append(
            error(
                "negative_polarity_lost",
                "golden answer is a negative/zero-path fact but answer lacks negation",
            )
        )
    if unit.get("answer_source") == "log_analysis":
        errors.append(
            error(
                "wrong_answer_source",
                "golden GraphRAG query was routed to log analysis",
            )
        )
    if not (unit.get("nodes") or unit.get("sources")):
        errors.append(
            error(
                "empty_sources",
                "golden GraphRAG answer returned no source nodes",
            )
        )

    comparison = {
        "expected_answer": reference,
        "expected_ids": sorted(expected_ids),
        "answer_ids": sorted(answer_ids),
        "grounded_ids": sorted(grounded_ids),
        "missing_expected_ids": missing_ids,
        "unexpected_answer_ids": unexpected_ids,
        "ungrounded_answer_ids": ungrounded_ids,
        "required_entities": required_entities,
        "expects_negative_polarity": expects_negation,
        "answer_has_negative_polarity": actual_negation,
        "source_count": len(unit.get("nodes") or unit.get("sources") or []),
    }
    return comparison, errors


def _response_units(response: dict[str, Any]) -> list[dict[str, Any]]:
    segments = response.get("segments") or []
    return list(segments) if segments else [response]


def validate_mixed_case(
    scenario: mixed.Scenario,
    response: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    messages: list[str] = []
    for validator in scenario.validators:
        messages.extend(validator(response))
    return (
        {"purpose": scenario.purpose},
        [error("mixed_contract_failure", message) for message in messages],
    )


def validate_guardrail_allow_case(
    case: dict[str, Any],
    response: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    if response.get("allowed") is not True:
        errors.append(
            error(
                "defensive_false_block",
                "a committed defensive/reference allow-case was blocked",
                guardrail_category=response.get("guardrail_category"),
                cohort=case["cohort"],
            )
        )
    return (
        {
            "expected_allowed": True,
            "actual_allowed": response.get("allowed"),
            "cohort": case["cohort"],
            "source_id": case["id"],
        },
        errors,
    )


def validate_multi_intent_case(
    scenario: dict[str, Any],
    response: dict[str, Any],
    golden_index: dict[str, dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    expected_specs = [
        spec for spec in scenario.get("segments", []) if spec.get("disposition") == "route"
    ]

    if scenario.get("raw_log"):
        log_specs = [
            spec for spec in scenario.get("segments", []) if spec.get("disposition") == "log"
        ]
        golden_specs = [spec for spec in expected_specs if spec.get("golden_id")]
        if log_specs and golden_specs:
            units = _response_units(response)
            log_units = [
                unit for unit in units if unit.get("answer_source") == "log_analysis"
            ]
            if len(log_units) != 1 or len(units) != 2:
                errors.append(
                    error(
                        "raw_log_mixed_shape",
                        "raw log plus question must yield one log card and one question card",
                        unit_count=len(units),
                        log_unit_count=len(log_units),
                    )
                )
            question_units = [
                unit for unit in units if unit.get("answer_source") != "log_analysis"
            ]
            if question_units:
                case = golden_index[golden_specs[0]["golden_id"]]
                comparison, fact_errors = compare_golden_answer(
                    question_units[0], case, catalog
                )
                comparisons.append(
                    {"golden_id": case["case_id"], **comparison}
                )
                errors.extend(fact_errors)
        else:
            if response.get("answer_source") != "log_analysis":
                errors.append(
                    error(
                        "raw_log_wrong_route",
                        "raw-log scenario did not use log_analysis",
                    )
                )
        return {"segment_comparisons": comparisons}, errors

    expected_count = int(scenario.get("expected_routed_count") or 0)
    units = _response_units(response)
    if scenario.get("expects_cards"):
        if len(response.get("segments") or []) != expected_count:
            errors.append(
                error(
                    "multi_segment_count",
                    f"expected {expected_count} cards, got "
                    f"{len(response.get('segments') or [])}",
                )
            )
    elif response.get("segments"):
        errors.append(
            error(
                "unexpected_multi_cards",
                "scenario expected the single-result path but returned cards",
                count=len(response["segments"]),
            )
        )

    if expected_count == 0:
        return {"segment_comparisons": comparisons}, errors
    if len(units) != expected_count:
        errors.append(
            error(
                "routed_unit_count",
                f"expected {expected_count} routed results, got {len(units)}",
            )
        )
    for index, spec in enumerate(expected_specs):
        if index >= len(units):
            break
        unit = units[index]
        golden_id = spec.get("golden_id")
        if golden_id:
            case = golden_index.get(golden_id)
            if case is None:
                errors.append(
                    error(
                        "unknown_multi_golden_id",
                        f"multi-intent scenario references unknown {golden_id}",
                    )
                )
                continue
            comparison, fact_errors = compare_golden_answer(unit, case, catalog)
            comparisons.append({"golden_id": golden_id, **comparison})
            errors.extend(fact_errors)
        elif spec.get("reason") == "offtopic_question":
            answer = normalize_text(str(unit.get("answer") or ""))
            soft_refusal = answer == normalize_text(
                "I don't have enough information about this in my knowledge base."
            )
            if unit.get("allowed") is not False and not soft_refusal:
                errors.append(
                    error(
                        "offtopic_fail_open",
                        "off-topic segment was neither blocked nor softly refused",
                        query=spec.get("text"),
                    )
                )
        elif spec.get("reason") == "cyber_question" and unit.get("allowed") is not True:
            errors.append(
                error(
                    "cyber_segment_blocked",
                    "legitimate cybersecurity segment was blocked",
                    query=spec.get("text"),
                )
            )
    return {"segment_comparisons": comparisons}, errors


def build_cases(suite: str) -> list[dict[str, Any]]:
    golden_cases, golden_index = load_golden_index()
    multi_scenarios, _multi_hash = load_multi_intent_scenarios()
    guardrail_cases = load_guardrail_allow_cases()
    cases: list[dict[str, Any]] = []
    if suite in {"mixed", "comprehensive"}:
        cases.extend(
            {
                "id": f"mixed::{scenario.name}",
                "suite": "mixed",
                "category": "mixed_log_contract",
                "query": scenario.query,
                "scenario": scenario,
                "purpose": scenario.purpose,
            }
            for scenario in mixed._scenarios()
        )
    if suite in {"golden", "comprehensive"}:
        cases.extend(
            {
                "id": f"golden::{case['case_id']}",
                "suite": "golden",
                "category": case["relationship_type"],
                "query": case["question"],
                "golden": case,
                "purpose": (
                    f"{case['relationship_type']} / {case.get('variant_kind')} / "
                    f"{case.get('sampling_slot')}"
                ),
            }
            for case in golden_cases
        )
    if suite in {"multi-intent", "comprehensive"}:
        cases.extend(
            {
                "id": f"multi::{scenario['id']}",
                "suite": "multi-intent",
                "category": scenario["category"],
                "query": scenario["input"],
                "multi": scenario,
                "purpose": scenario["description"],
                "golden_index": golden_index,
                # FastAPI rejects an empty QueryRequest before orchestration.
                # The artifact describes the lower-level splitter behavior,
                # while the real public API contract correctly returns 422.
                "expected_http_status": (
                    422 if scenario["id"] == "empty-turn" else None
                ),
            }
            for scenario in multi_scenarios
        )
    if suite in {"guardrail", "comprehensive"}:
        cases.extend(
            {
                "id": f"guardrail::{case['cohort']}::{case['id']}",
                "suite": "guardrail",
                "category": case["category"],
                "query": case["prompt"],
                "guardrail": case,
                "purpose": (
                    f"{case['cohort']} must remain allowed through the full API"
                ),
            }
            for case in guardrail_cases
        )
    return cases


def case_fingerprint(cases: list[dict[str, Any]]) -> str:
    serializable = [
        {
            "id": case["id"],
            "suite": case["suite"],
            "query": case["query"],
            "golden_id": (case.get("golden") or {}).get("case_id"),
            "golden_reference": (case.get("golden") or {}).get("reference"),
            "golden_artifact_sha256": (case.get("golden") or {}).get(
                "golden_artifact_sha256"
            ),
            "multi_expectation": case.get("multi"),
            "guardrail_expectation": case.get("guardrail"),
        }
        for case in cases
    ]
    return hashlib.sha256(
        json.dumps(
            {"schema_version": SCHEMA_VERSION, "cases": serializable},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def request_with_rate_limit_retry(
    url: str,
    *,
    api_key: str,
    query: str,
    timeout: float,
    max_retries: int,
) -> tuple[dict[str, Any], int]:
    transient_http_statuses = {429, 500, 502, 503, 504}
    retries = 0
    while True:
        try:
            return (
                mixed._request_json(
                    url,
                    api_key=api_key,
                    payload={"query": query},
                    timeout=timeout,
                ),
                retries,
            )
        except urllib.error.HTTPError as exc:
            if exc.code not in transient_http_statuses or retries >= max_retries:
                raise
            retry_after = exc.headers.get("Retry-After")
            if retry_after:
                try:
                    wait_seconds = max(1.0, float(retry_after))
                except ValueError:
                    wait_seconds = min(60.0, 2.0 ** (retries + 1))
            else:
                wait_seconds = min(60.0, 2.0 ** (retries + 1))
            retries += 1
            print(
                f"    transient HTTP {exc.code}; waiting {wait_seconds:.1f}s "
                f"(retry {retries}/{max_retries})",
                flush=True,
            )
            time.sleep(wait_seconds)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if retries >= max_retries:
                raise
            wait_seconds = min(60.0, 2.0 ** (retries + 1))
            retries += 1
            print(
                f"    transient {type(exc).__name__}; waiting "
                f"{wait_seconds:.1f}s (retry {retries}/{max_retries})",
                flush=True,
            )
            time.sleep(wait_seconds)


def validate_live_case(
    case: dict[str, Any],
    response: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    errors = validate_api_contract(response, catalog)
    if case["suite"] == "mixed":
        comparison, case_errors = validate_mixed_case(
            case["scenario"], response
        )
    elif case["suite"] == "golden":
        comparison, case_errors = compare_golden_answer(
            response, case["golden"], catalog
        )
    elif case["suite"] == "guardrail":
        comparison, case_errors = validate_guardrail_allow_case(
            case["guardrail"], response
        )
    else:
        comparison, case_errors = validate_multi_intent_case(
            case["multi"],
            response,
            case["golden_index"],
            catalog,
        )
    errors.extend(case_errors)
    return comparison, errors


def revalidate_saved_row(
    case: dict[str, Any],
    row: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    response = row.get("response")
    expected_http_status = case.get("expected_http_status")
    if expected_http_status is not None:
        if (
            isinstance(response, dict)
            and response.get("http_status") == expected_http_status
        ):
            return {
                **row,
                "status": "PASS",
                "errors": [],
                "comparison": {
                    "expected_http_status": expected_http_status,
                    "actual_http_status": expected_http_status,
                },
                "execution_error": None,
                "resumed_revalidated": True,
            }
        return None
    if row.get("status") == "ERROR" or not isinstance(response, dict) or not response:
        return None
    comparison, errors = validate_live_case(case, response, catalog)
    return {
        **row,
        "status": "FAIL" if errors else "PASS",
        "errors": errors,
        "comparison": comparison,
        "execution_error": None,
        "resumed_revalidated": True,
    }


def _duration(seconds: float | None) -> str:
    if seconds is None:
        return "--:--"
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return (
        f"{hours:d}:{minutes:02d}:{secs:02d}"
        if hours
        else f"{minutes:02d}:{secs:02d}"
    )


def print_progress(
    *,
    completed: int,
    total: int,
    results: list[dict[str, Any]],
    session_started: float,
) -> None:
    width = 32
    ratio = completed / total if total else 1.0
    filled = min(width, int(width * ratio))
    bar = "#" * filled + "-" * (width - filled)
    counts = Counter(row.get("status") for row in results)
    session_elapsed = time.perf_counter() - session_started
    measured = [
        float(row.get("elapsed_seconds") or 0.0)
        for row in results
        if not row.get("resumed_revalidated")
    ]
    mean_seconds = sum(measured) / len(measured) if measured else None
    eta = mean_seconds * (total - completed) if mean_seconds is not None else None
    print(
        f"Progress [{bar}] {completed}/{total} ({ratio * 100:5.1f}%) "
        f"PASS={counts['PASS']} FAIL={counts['FAIL']} ERROR={counts['ERROR']} "
        f"elapsed={_duration(session_elapsed)} ETA={_duration(eta)}",
        flush=True,
    )


def derive_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(row["status"] for row in results)
    by_suite: dict[str, Counter[str]] = defaultdict(Counter)
    by_category: dict[str, Counter[str]] = defaultdict(Counter)
    error_codes: Counter[str] = Counter()
    for row in results:
        by_suite[row["suite"]][row["status"]] += 1
        by_category[row["category"]][row["status"]] += 1
        error_codes.update(item["code"] for item in row.get("errors", []))
    return {
        "total": len(results),
        "passed": status_counts["PASS"],
        "failed": status_counts["FAIL"],
        "errors": status_counts["ERROR"],
        "by_suite": {key: dict(value) for key, value in sorted(by_suite.items())},
        "by_category": {
            key: dict(value) for key, value in sorted(by_category.items())
        },
        "failure_codes": dict(error_codes.most_common()),
        "possible_hallucination_cases": sum(
            any(item["code"] == "ungrounded_answer_ids" for item in row.get("errors", []))
            for row in results
        ),
        "unexpected_fact_cases": sum(
            any(item["code"] == "unexpected_answer_ids" for item in row.get("errors", []))
            for row in results
        ),
        "missing_fact_cases": sum(
            any(item["code"] == "missing_expected_ids" for item in row.get("errors", []))
            for row in results
        ),
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    summary = report["summary"]
    lines = [
        "# Live production suite",
        "",
        f"- Status: **{report['status']}**",
        f"- Cases: **{summary['total']}**",
        f"- Passed: **{summary['passed']}**",
        f"- Failed: **{summary['failed']}**",
        f"- Execution errors: **{summary['errors']}**",
        f"- Possible hallucination cases: **{summary['possible_hallucination_cases']}**",
        f"- Missing-fact cases: **{summary['missing_fact_cases']}**",
        f"- Unexpected-fact cases: **{summary['unexpected_fact_cases']}**",
        "",
        "## By suite",
        "",
        "| Suite | PASS | FAIL | ERROR |",
        "|---|---:|---:|---:|",
    ]
    for suite, counts in summary["by_suite"].items():
        lines.append(
            f"| {suite} | {counts.get('PASS', 0)} | "
            f"{counts.get('FAIL', 0)} | {counts.get('ERROR', 0)} |"
        )
    lines.extend(
        [
            "",
            "## Failures",
            "",
        ]
    )
    failures = [row for row in report["results"] if row["status"] != "PASS"]
    if not failures:
        lines.append("None.")
    for row in failures:
        lines.extend(
            [
                f"### {row['id']} — {row['status']}",
                "",
                f"- Query: `{row['query']}`",
                f"- Error codes: "
                f"`{', '.join(item['code'] for item in row.get('errors', []))}`",
                "",
                "```text",
                str((row.get("response") or {}).get("answer") or ""),
                "```",
                "",
            ]
        )
        for item in row.get("errors", []):
            lines.append(f"- **{item['code']}**: {item['message']}")
        lines.append("")
    atomic_write(path, "\n".join(lines) + "\n")


def _report_payload(
    *,
    cases: list[dict[str, Any]],
    fingerprint: str,
    results: list[dict[str, Any]],
    status: str,
    started_at: str,
) -> dict[str, Any]:
    final_path = RAG_ACCURACY / "final_golden_set.json"
    multi_path = RAG_ACCURACY / "golden_set_multi_intent.json"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "started_at": started_at,
        "updated_at": utc_now(),
        "suite_fingerprint": fingerprint,
        "coverage": {
            "case_count": len(cases),
            "mixed_case_count": sum(case["suite"] == "mixed" for case in cases),
            "golden_case_count": sum(case["suite"] == "golden" for case in cases),
            "multi_intent_case_count": sum(
                case["suite"] == "multi-intent" for case in cases
            ),
            "guardrail_allow_case_count": sum(
                case["suite"] == "guardrail" for case in cases
            ),
            "relationship_types": sorted(
                {
                    case["category"]
                    for case in cases
                    if case["suite"] == "golden"
                }
            ),
        },
        "truth_artifacts": {
            "final_golden_set": {
                "path": str(final_path),
                "sha256": sha256_file(final_path),
            },
            "multi_intent_golden": {
                "path": str(multi_path),
                "sha256": sha256_file(multi_path),
            },
            "pinned_source_manifest": {
                "path": str(RAG_ACCURACY / "source_manifest.json"),
                "sha256": sha256_file(RAG_ACCURACY / "source_manifest.json"),
            },
            "domain_benign_set": {
                "path": str(GUARDRAIL_BASELINE / "domain_benign_set.json"),
                "sha256": sha256_file(
                    GUARDRAIL_BASELINE / "domain_benign_set.json"
                ),
            },
            "reference_guard_set": {
                "path": str(GUARDRAIL_BASELINE / "reference_guard_set.json"),
                "sha256": sha256_file(
                    GUARDRAIL_BASELINE / "reference_guard_set.json"
                ),
            },
        },
        "summary": derive_summary(results),
        "results": results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-base", default="http://localhost:8000")
    parser.add_argument(
        "--suite",
        choices=(
            "comprehensive",
            "mixed",
            "golden",
            "multi-intent",
            "guardrail",
        ),
        default="comprehensive",
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-rate-limit-retries", type=int, default=5)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--markdown-report",
        type=Path,
        default=DEFAULT_MARKDOWN_REPORT,
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "revalidate and reuse completed PASS/FAIL responses from a matching "
            "checkpoint; interrupted ERROR and pending cases rerun"
        ),
    )
    parser.add_argument(
        "--rerun-failures",
        action="store_true",
        help=(
            "with --resume, rerun prior validation failures after revalidating "
            "them; PASS cases are still reused"
        ),
    )
    parser.add_argument(
        "--case-id",
        action="append",
        dest="case_ids",
        help="run only an exact fully-qualified case ID; repeat as needed",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--show-full-answers",
        action="store_true",
        help="print full answers; the JSON report always stores them in full",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.rerun_failures and not args.resume:
        print("FAIL: --rerun-failures requires --resume")
        return 2
    catalog = load_entity_catalog()
    cases = build_cases(args.suite)
    if args.case_ids:
        requested = set(args.case_ids)
        known = {case["id"] for case in cases}
        unknown = sorted(requested - known)
        if unknown:
            print(f"FAIL: unknown --case-id values: {unknown}")
            return 2
        cases = [case for case in cases if case["id"] in requested]
    if args.limit is not None:
        if args.limit < 1:
            print("FAIL: --limit must be at least 1")
            return 2
        cases = cases[: args.limit]
    if not cases:
        print("FAIL: no cases selected")
        return 2

    # Validate truth before making a single live request.
    golden_cases = [case["golden"] for case in cases if case.get("golden")]
    unknown_expected = sorted(
        {
            external_id
            for case in golden_cases
            for external_id in extract_mitre_ids(case["reference"])
            if external_id not in catalog
        }
    )
    if unknown_expected:
        print(f"FAIL: golden answers contain IDs absent from pinned data: {unknown_expected}")
        return 2

    fingerprint = case_fingerprint(cases)
    previous_results: dict[str, dict[str, Any]] = {}
    started_at = utc_now()
    if args.resume and args.report.exists():
        previous = json.loads(args.report.read_text(encoding="utf-8"))
        if (
            previous.get("schema_version") != SCHEMA_VERSION
            or previous.get("suite_fingerprint") != fingerprint
        ):
            print("FAIL: report checkpoint does not match this exact selected suite")
            return 2
        cases_by_id = {case["id"]: case for case in cases}
        for saved_row in previous.get("results", []):
            saved_case = cases_by_id.get(saved_row.get("id"))
            if saved_case is None:
                continue
            revalidated = revalidate_saved_row(
                saved_case, saved_row, catalog
            )
            if revalidated is None:
                continue
            if args.rerun_failures and revalidated["status"] == "FAIL":
                continue
            previous_results[revalidated["id"]] = revalidated
        started_at = previous.get("started_at") or started_at

    api_key = mixed._load_api_key()
    base = args.api_base.rstrip("/")
    try:
        health = mixed._request_json(
            f"{base}/health",
            api_key=api_key,
            payload=None,
            timeout=min(args.timeout, 10.0),
        )
    except Exception as exc:
        print(f"FAIL precheck: backend unavailable at {base}: {exc}")
        return 2

    print(f"Backend health: {health.get('status', 'unknown')}")
    print(
        f"Selected {len(cases)} cases: "
        f"{sum(case['suite'] == 'mixed' for case in cases)} mixed + "
        f"{sum(case['suite'] == 'golden' for case in cases)} golden + "
        f"{sum(case['suite'] == 'multi-intent' for case in cases)} multi-intent + "
        f"{sum(case['suite'] == 'guardrail' for case in cases)} guardrail allow"
    )
    print(
        f"Pinned entity catalog: {len(catalog)} IDs; "
        "all selected golden expectations resolved"
    )

    session_started = time.perf_counter()
    results_by_id = dict(previous_results)
    interrupted = False
    for index, case in enumerate(cases, start=1):
        if case["id"] in previous_results:
            status = previous_results[case["id"]]["status"]
            print(
                f"[{index:03d}/{len(cases)}] RESUME-{status} "
                f"{case['id']} (saved response revalidated)"
            )
            ordered_so_far = [
                results_by_id[selected["id"]]
                for selected in cases[:index]
                if selected["id"] in results_by_id
            ]
            print_progress(
                completed=len(ordered_so_far),
                total=len(cases),
                results=ordered_so_far,
                session_started=session_started,
            )
            continue
        started = time.perf_counter()
        response: dict[str, Any] = {}
        errors: list[dict[str, Any]] = []
        comparison: dict[str, Any] = {}
        rate_limit_retries = 0
        execution_error: dict[str, Any] | None = None
        try:
            response, rate_limit_retries = request_with_rate_limit_retry(
                f"{base}/query",
                api_key=api_key,
                query=case["query"],
                timeout=args.timeout,
                max_retries=args.max_rate_limit_retries,
            )
            comparison, errors = validate_live_case(
                case, response, catalog
            )
            status = "FAIL" if errors else "PASS"
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code == case.get("expected_http_status"):
                status = "PASS"
                response = {
                    "http_status": exc.code,
                    "body": body[:4000],
                }
                comparison = {
                    "expected_http_status": case["expected_http_status"],
                    "actual_http_status": exc.code,
                }
            else:
                status = "ERROR"
                execution_error = {
                    "type": "HTTPError",
                    "status": exc.code,
                    "body": body[:4000],
                }
                errors.append(
                    error(
                        "http_error",
                        f"HTTP {exc.code}: {body[:500]}",
                        status=exc.code,
                    )
                )
        except Exception as exc:
            status = "ERROR"
            execution_error = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            errors.append(
                error(
                    "execution_error",
                    f"{type(exc).__name__}: {exc}",
                )
            )
        elapsed = time.perf_counter() - started
        row = {
            "id": case["id"],
            "suite": case["suite"],
            "category": case["category"],
            "purpose": case["purpose"],
            "query": case["query"],
            "status": status,
            "elapsed_seconds": round(elapsed, 3),
            "rate_limit_retries": rate_limit_retries,
            "errors": errors,
            "comparison": comparison,
            "execution_error": execution_error,
            "response": response,
        }
        if case.get("golden"):
            row["golden_provenance"] = {
                key: case["golden"].get(key)
                for key in (
                    "case_id",
                    "relationship_type",
                    "variant_kind",
                    "sampling_slot",
                    "case_type",
                    "golden_artifact",
                    "golden_artifact_sha256",
                    "final_golden_set_sha256",
                )
            }
        results_by_id[case["id"]] = row
        print(
            f"[{index:03d}/{len(cases)}] {status} {case['id']} "
            f"({elapsed:.2f}s)"
        )
        answer = str(response.get("answer") or "")
        if args.show_full_answers:
            print("    answer:", answer)
        else:
            preview = answer.replace("\n", " ")[:500]
            print(f"    answer preview: {preview}")
        if comparison:
            for key in (
                "missing_expected_ids",
                "unexpected_answer_ids",
                "ungrounded_answer_ids",
                "missing_expected_names",
            ):
                if comparison.get(key):
                    print(f"    {key}: {comparison[key]}")
        for item in errors:
            print(f"    ERROR [{item['code']}]: {item['message']}")

        ordered = [
            results_by_id[selected["id"]]
            for selected in cases
            if selected["id"] in results_by_id
        ]
        checkpoint = _report_payload(
            cases=cases,
            fingerprint=fingerprint,
            results=ordered,
            status="interrupted" if status == "ERROR" else "in_progress",
            started_at=started_at,
        )
        atomic_write(
            args.report,
            json.dumps(checkpoint, indent=2, ensure_ascii=False) + "\n",
        )
        write_markdown(args.markdown_report, checkpoint)
        print_progress(
            completed=len(ordered),
            total=len(cases),
            results=ordered,
            session_started=session_started,
        )
        if status == "ERROR":
            interrupted = True
            print(
                "Infrastructure error persisted after retries. "
                "Stopping safely; rerun the same command with --resume.",
                flush=True,
            )
            break
        if args.delay:
            time.sleep(args.delay)

    ordered_results = [
        results_by_id[case["id"]]
        for case in cases
        if case["id"] in results_by_id
    ]
    completed = len(ordered_results) == len(cases) and not interrupted
    report = _report_payload(
        cases=cases,
        fingerprint=fingerprint,
        results=ordered_results,
        status="complete" if completed else "interrupted",
        started_at=started_at,
    )
    atomic_write(
        args.report,
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
    )
    write_markdown(args.markdown_report, report)
    summary = report["summary"]
    print(
        "\nLive production suite: "
        f"{len(ordered_results)}/{len(cases)} completed; "
        f"{summary['passed']} passed; "
        f"{summary['failed']} validation failures; "
        f"{summary['errors']} execution errors"
    )
    print(
        "Fact diagnostics: "
        f"{summary['missing_fact_cases']} missing, "
        f"{summary['unexpected_fact_cases']} unexpected, "
        f"{summary['possible_hallucination_cases']} possibly hallucinated/ungrounded"
    )
    print(f"JSON report: {args.report}")
    print(f"Markdown report: {args.markdown_report}")
    if not completed:
        return 2
    return 0 if summary["failed"] == 0 and summary["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
