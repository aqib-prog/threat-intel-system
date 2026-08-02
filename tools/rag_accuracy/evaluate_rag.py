#!/usr/bin/env python3
"""Run the Step-8a local-only Ragas prototype.

The production pipeline and the Ragas scorer intentionally run in separate
interpreters. The production backend venv keeps its existing dependency set;
the scorer uses the pinned, isolated environment from ``requirements.txt``.
Both processes enforce a loopback-only socket policy during evaluation.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
BACKEND_PYTHON = REPO_ROOT / "backend" / "venv" / "bin" / "python"
DEFAULT_JSON_REPORT = HERE / "rag_accuracy_report.json"
DEFAULT_MD_REPORT = HERE / "rag_accuracy_report.md"
DEFAULT_PIPELINE_RAW = HERE / "rag_pipeline_prototype_raw.json"
FINAL_GOLDEN_SET = HERE / "final_golden_set.json"
FINAL_JSON_REPORT = HERE / "final_golden_set_ragas_report.json"
FINAL_MD_REPORT = HERE / "final_golden_set_ragas_report.md"
FINAL_PIPELINE_CHECKPOINT = (
    HERE / "final_golden_set_pipeline_checkpoint.json"
)
FINAL_SCORING_CHECKPOINT = (
    HERE / "final_golden_set_scoring_checkpoint.json"
)
JUDGE_MODEL = "llama3.1:latest"
EMBEDDING_MODEL = "nomic-embed-text:latest"
OLLAMA_BASE_URL = "http://127.0.0.1:11434"
CONTEXT_SERIALIZATION = "pipeline_query_focused_relationship_context_v5"
PREVIOUS_CONTEXT_SERIALIZATION = (
    "pipeline_query_focused_relationship_context_v4"
)
PIPELINE_CHECKPOINT_SCHEMA = "rag_accuracy_pipeline_checkpoint_v3"
SCORING_CHECKPOINT_SCHEMA = "rag_accuracy_scoring_checkpoint_v8"
PREVIOUS_SCORING_CHECKPOINT_SCHEMA = "rag_accuracy_scoring_checkpoint_v7"
LEGACY_SCORING_CHECKPOINT_SCHEMA = "rag_accuracy_scoring_checkpoint_v2"
FAITHFULNESS_PROMPT_VERSION = "attack_graph_atomic_inverse_relations_v1"
FINAL_DATASET_NAME = "final_golden_set"
PROTOTYPE_DATASET_NAME = "prototype"
DEFAULT_SCORING_BATCH_SIZE = 5
DEFAULT_INCOMPLETE_SCORE_RETRIES = 2
RAGAS_JUDGE_SEED = 7
RAGAS_JUDGE_NUM_CTX = 16384
RAGAS_TIMEOUT_SECONDS = 600
# Retry ownership belongs to score_batch_with_incomplete_retries(), where the
# affected case is isolated and the checkpoint records every failure. Hidden
# library retries would otherwise repeat a long batch without preserving work.
RAGAS_MAX_RETRIES = 0
RAGAS_MAX_WAIT_SECONDS = 10
RAGAS_MAX_WORKERS = 1
REQUIRED_SCORE_METRICS = (
    "faithfulness",
    "context_precision",
    "context_recall",
)
NEGATIVE_SAMPLING_SLOTS = frozenset(
    {
        "negative_relationship",
        "zero_path",
        "adversarial_negative",
        "reverse_zero_path",
        "detection_component_zero_path",
        "platform_zero_path",
        "negative_chain",
    }
)
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
NEGATIVE_VALIDATION_METHOD = "deterministic_pinned_golden_facts_v1"
SET_OPERATION_SAMPLING_SLOTS = frozenset({"path_divergence"})
SET_OPERATION_VALIDATION_METHOD = "deterministic_pinned_set_algebra_v1"

# Deliberate, fixed prototype coverage: 15 cases spanning all seven completed
# relationship types. IDs are stable facts in the pinned golden artifacts.
SAMPLE_SELECTION = (
    ("technique_mitigation", "golden_set.json", "enterprise-mitigations-t1078"),
    ("technique_mitigation", "golden_set.json", "enterprise-mitigations-t1053"),
    ("technique_tactic", "golden_set_technique_tactic.json", "enterprise-tactics-t1053"),
    ("technique_tactic", "golden_set_technique_tactic.json", "enterprise-tactics-t1001"),
    ("group_technique", "golden_set_group_technique.json", "group-uses-techniques-g0002"),
    ("group_technique", "golden_set_group_technique.json", "group-uses-techniques-g0003"),
    ("software_technique", "golden_set_software_technique.json", "software-uses-techniques-s0002"),
    ("software_technique", "golden_set_software_technique.json", "software-uses-techniques-s0003"),
    ("group_software", "golden_set_group_software.json", "group-uses-software-g0002"),
    ("group_software", "golden_set_group_software.json", "group-uses-software-g0003"),
    ("technique_detection_strategy", "golden_set_technique_detection_strategy_prototype.json", "technique-detection-strategy-t1078"),
    ("technique_detection_strategy", "golden_set_technique_detection_strategy_prototype.json", "technique-detection-components-t1059.001"),
    ("campaign_group", "golden_set_campaign_group.json", "campaign-attributed-groups-c0011"),
    ("campaign_group", "golden_set_campaign_group.json", "campaign-attributed-groups-c0052"),
    ("campaign_group", "golden_set_campaign_group.json", "campaign-has-no-attributed-group-c0001"),
)


class EvaluationError(RuntimeError):
    """Raised when the measurement preconditions or invariants fail."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_sample_cases() -> list[dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for relationship_type, filename, pair_id in SAMPLE_SELECTION:
        if filename not in artifacts:
            path = HERE / filename
            artifacts[filename] = json.loads(path.read_text(encoding="utf-8"))
        pairs = artifacts[filename].get("pairs", [])
        matches = [pair for pair in pairs if pair.get("id") == pair_id]
        if len(matches) != 1:
            raise EvaluationError(
                f"expected exactly one {pair_id!r} pair in {filename}, found {len(matches)}"
            )
        if pair_id in seen_ids:
            raise EvaluationError(f"duplicate prototype pair ID: {pair_id}")
        seen_ids.add(pair_id)
        pair = matches[0]
        question = str(pair.get("question") or "").strip()
        reference = str(pair.get("expected_answer") or "").strip()
        if not question or not reference:
            raise EvaluationError(f"pair {pair_id} lacks question/reference text")
        cases.append(
            {
                "case_id": pair_id,
                "relationship_type": relationship_type,
                "golden_artifact": filename,
                "golden_artifact_sha256": sha256_file(HERE / filename),
                "question": question,
                "reference": reference,
            }
        )
    return cases


def load_final_golden_set_cases(
    path: Path = FINAL_GOLDEN_SET,
) -> list[dict[str, Any]]:
    """Load the independently verified Phase-E entries without rewriting truth."""
    if not path.exists():
        raise EvaluationError(f"final golden set does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise EvaluationError("final golden set does not contain an entries list")
    if len(entries) != 156:
        raise EvaluationError(
            f"final golden set has {len(entries)} entries; expected 156"
        )
    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for entry in entries:
        case_id = entry.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise EvaluationError("final golden set contains an entry without an ID")
        if case_id in seen_ids:
            raise EvaluationError(f"duplicate final golden-set case ID: {case_id}")
        seen_ids.add(case_id)
        question = entry.get("question")
        reference = entry.get("expected_answer")
        if not isinstance(question, str) or not question.strip():
            raise EvaluationError(f"final case {case_id} lacks question text")
        if not isinstance(reference, str) or not reference.strip():
            raise EvaluationError(f"final case {case_id} lacks reference text")
        expected_answer_hash = hashlib.sha256(reference.encode("utf-8")).hexdigest()
        if entry.get("expected_answer_sha256") != expected_answer_hash:
            raise EvaluationError(
                f"final case {case_id} has a stale expected-answer hash"
            )
        source_artifact = entry.get("source_golden_artifact")
        source_hash = entry.get("source_golden_artifact_sha256")
        if (
            not isinstance(source_artifact, str)
            or not isinstance(source_hash, str)
            or len(source_hash) != 64
        ):
            raise EvaluationError(
                f"final case {case_id} lacks source-artifact provenance"
            )
        source_path = HERE / source_artifact
        if not source_path.exists() or sha256_file(source_path) != source_hash:
            raise EvaluationError(
                f"final case {case_id} points to a missing or changed source artifact"
            )
        variant_kind = entry.get("variant_kind")
        if variant_kind not in {"original", "typo", "reworded"}:
            raise EvaluationError(
                f"final case {case_id} has unknown variant kind {variant_kind!r}"
            )
        cases.append(
            {
                "case_id": case_id,
                "relationship_type": entry.get("relationship_type"),
                "golden_artifact": source_artifact,
                "golden_artifact_sha256": source_hash,
                "question": question,
                "reference": reference,
                "variant_kind": variant_kind,
                "source_case_id": entry.get("source_case_id"),
                "sampling_slot": entry.get("sampling_slot"),
                "case_type": entry.get("case_type"),
                "final_golden_set_sha256": sha256_file(path),
            }
        )
    if len({case["relationship_type"] for case in cases}) != 13:
        raise EvaluationError("final golden set does not cover exactly 13 relationships")
    variant_counts = {
        kind: sum(case["variant_kind"] == kind for case in cases)
        for kind in ("original", "typo", "reworded")
    }
    if set(variant_counts.values()) != {52}:
        raise EvaluationError(
            f"final golden-set variant counts are not 52 each: {variant_counts}"
        )
    return cases


def is_loopback_host(host: Any) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", errors="replace")
    text = str(host).strip().strip("[]").lower()
    if text == "localhost":
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


class LoopbackOnlyNetworkAudit:
    """Record network destinations and reject every non-loopback destination."""

    def __init__(self) -> None:
        self.observed_hosts: set[str] = set()
        self.blocked_hosts: set[str] = set()
        self._getaddrinfo = socket.getaddrinfo
        self._connect = socket.socket.connect

    def _observe(self, host: Any) -> None:
        if host is None:
            return
        text = host.decode("ascii", errors="replace") if isinstance(host, bytes) else str(host)
        self.observed_hosts.add(text)
        if not is_loopback_host(host):
            self.blocked_hosts.add(text)
            raise EvaluationError(f"blocked non-local network destination: {text}")

    def __enter__(self) -> "LoopbackOnlyNetworkAudit":
        audit = self

        def audited_getaddrinfo(host: Any, *args: Any, **kwargs: Any):
            audit._observe(host)
            return audit._getaddrinfo(host, *args, **kwargs)

        def audited_connect(sock: socket.socket, address: Any):
            if isinstance(address, tuple) and address:
                audit._observe(address[0])
            return audit._connect(sock, address)

        socket.getaddrinfo = audited_getaddrinfo
        socket.socket.connect = audited_connect
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        socket.getaddrinfo = self._getaddrinfo
        socket.socket.connect = self._connect

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": "loopback_only",
            "observed_hosts": sorted(self.observed_hosts),
            "blocked_hosts": sorted(self.blocked_hosts),
            "openai_host_attempted": any(
                host.lower() == "openai.com" or host.lower().endswith(".openai.com")
                for host in self.observed_hosts
            ),
        }


def configure_local_only_environment() -> dict[str, Any]:
    os.environ.pop("OPENAI_API_KEY", None)
    os.environ.pop("OPENAI_BASE_URL", None)
    os.environ.pop("LANGSMITH_API_KEY", None)
    os.environ["RAGAS_DO_NOT_TRACK"] = "true"
    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ["HF_HUB_OFFLINE"] = "1"
    return {
        "OPENAI_API_KEY_present": "OPENAI_API_KEY" in os.environ,
        "OPENAI_BASE_URL_present": "OPENAI_BASE_URL" in os.environ,
        "RAGAS_DO_NOT_TRACK": os.environ["RAGAS_DO_NOT_TRACK"],
        "LANGCHAIN_TRACING_V2": os.environ["LANGCHAIN_TRACING_V2"],
    }


def verify_local_ollama() -> list[str]:
    """Fail before collection if the required local model is unavailable."""
    try:
        with urllib_request.urlopen(
            f"{OLLAMA_BASE_URL}/api/tags", timeout=5
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib_error.URLError, json.JSONDecodeError) as exc:
        raise EvaluationError(
            "local Ollama is unavailable; start it before resuming evaluation"
        ) from exc
    names = sorted(
        {
            str(model.get("name") or model.get("model") or "")
            for model in payload.get("models") or []
            if isinstance(model, dict)
        }
    )
    required_family = JUDGE_MODEL.split(":", 1)[0]
    if not any(name.split(":", 1)[0] == required_family for name in names):
        raise EvaluationError(
            f"local Ollama does not list required model family {required_family!r}"
        )
    return names


CASE_IDENTITY_FIELDS = (
    "case_id",
    "relationship_type",
    "golden_artifact",
    "golden_artifact_sha256",
    "question",
    "reference",
    "variant_kind",
    "source_case_id",
    "sampling_slot",
    "case_type",
    "final_golden_set_sha256",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def case_identity(case: dict[str, Any]) -> dict[str, Any]:
    return {
        field: case.get(field)
        for field in CASE_IDENTITY_FIELDS
        if field in case
    }


def dataset_fingerprint(cases: list[dict[str, Any]]) -> str:
    encoded = json.dumps(
        [case_identity(case) for case in cases],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scoring_input_fingerprint(
    rows: list[dict[str, Any]], configuration: dict[str, Any]
) -> str:
    encoded = json.dumps(
        {
            "rows": [
                {
                    **case_identity(row),
                    "answer": row.get("answer"),
                    "contexts": row.get("contexts"),
                }
                for row in rows
            ],
            "scoring_configuration": configuration,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def scoring_input_fingerprint(rows: list[dict[str, Any]]) -> str:
    return _scoring_input_fingerprint(rows, scoring_configuration())


def legacy_scoring_configuration_v2() -> dict[str, Any]:
    """Exact configuration bound into pre-applicability v2 checkpoints."""
    return {
        "judge_model": JUDGE_MODEL,
        "judge_seed": RAGAS_JUDGE_SEED,
        "judge_temperature": 0,
        "judge_format": "json",
        "judge_num_ctx": RAGAS_JUDGE_NUM_CTX,
        "embedding_model": EMBEDDING_MODEL,
        "metrics": list(REQUIRED_SCORE_METRICS),
        "timeout_seconds": RAGAS_TIMEOUT_SECONDS,
        "ragas_max_retries": RAGAS_MAX_RETRIES,
        "max_wait_seconds": RAGAS_MAX_WAIT_SECONDS,
        "max_workers": RAGAS_MAX_WORKERS,
    }


def scoring_configuration() -> dict[str, Any]:
    """Return every fixed setting that changes Ragas score semantics."""
    return {
        **legacy_scoring_configuration_v2(),
        "faithfulness_prompt_version": FAITHFULNESS_PROMPT_VERSION,
        "faithfulness_verdict_cardinality_required": True,
        "metric_applicability": (
            "positive_open_world_relationship_cases_only_v2"
        ),
        "negative_case_validation": NEGATIVE_VALIDATION_METHOD,
        "set_operation_validation": SET_OPERATION_VALIDATION_METHOD,
    }


def previous_scoring_configuration_v7() -> dict[str, Any]:
    """Exact configuration bound into pre-set-algebra v7 checkpoints."""
    return {
        **legacy_scoring_configuration_v2(),
        "faithfulness_prompt_version": FAITHFULNESS_PROMPT_VERSION,
        "faithfulness_verdict_cardinality_required": True,
        "metric_applicability": "positive_relationship_cases_only",
        "negative_case_validation": NEGATIVE_VALIDATION_METHOD,
    }


def merge_network_audits(*audits: dict[str, Any]) -> dict[str, Any]:
    observed: set[str] = set()
    blocked: set[str] = set()
    for audit in audits:
        observed.update(str(host) for host in audit.get("observed_hosts", []))
        blocked.update(str(host) for host in audit.get("blocked_hosts", []))
    return {
        "policy": "loopback_only",
        "observed_hosts": sorted(observed),
        "blocked_hosts": sorted(blocked),
        "openai_host_attempted": any(
            host.lower() == "openai.com" or host.lower().endswith(".openai.com")
            for host in observed
        ),
    }


def valid_pipeline_row(
    row: dict[str, Any], expected_case: dict[str, Any]
) -> bool:
    return (
        all(
            row.get(field) == value
            for field, value in case_identity(expected_case).items()
        )
        and isinstance(row.get("answer"), str)
        and isinstance(row.get("contexts"), list)
        and isinstance(row.get("sources"), list)
        and isinstance(row.get("allowed"), bool)
    )


def _load_pipeline_checkpoint(
    path: Path, cases: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("checkpoint_schema") != PIPELINE_CHECKPOINT_SCHEMA:
        raise EvaluationError(
            f"pipeline checkpoint uses an unknown schema: {path}"
        )
    expected_fingerprint = dataset_fingerprint(cases)
    if payload.get("dataset_fingerprint") != expected_fingerprint:
        raise EvaluationError(
            f"pipeline checkpoint is stale for this exact dataset: {path}"
        )
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise EvaluationError("pipeline checkpoint rows are malformed")
    cases_by_id = {case["case_id"]: case for case in cases}
    if len(cases_by_id) != len(cases):
        raise EvaluationError("pipeline input contains duplicate case IDs")
    seen: set[str] = set()
    for row in rows:
        case_id = row.get("case_id")
        expected = cases_by_id.get(case_id)
        if expected is None or case_id in seen or not valid_pipeline_row(row, expected):
            raise EvaluationError(
                f"pipeline checkpoint contains an invalid row for {case_id!r}"
            )
        seen.add(case_id)
    audit = payload.get("network_audit", {})
    if audit.get("blocked_hosts") or audit.get("openai_host_attempted"):
        raise EvaluationError("pipeline checkpoint failed its network audit")
    serialization = payload.get("context_serialization")
    if serialization == PREVIOUS_CONTEXT_SERIALIZATION:
        # v5 changed only one evidence contract: closed-world set operations
        # now export both complete relationship operands. Preserve every row
        # whose semantics did not change and force those cases through the real
        # pipeline again. This avoids trusting stale evidence without turning a
        # three-row refresh into a 156-query rerun.
        retained = [
            row
            for row in rows
            if case_evaluation_kind(cases_by_id[row["case_id"]])
            != "set_operation"
        ]
        return {
            **payload,
            "context_serialization": CONTEXT_SERIALIZATION,
            "status": "in_progress",
            "completed_count": len(retained),
            "remaining_count": len(cases) - len(retained),
            "last_error": None,
            "rows": retained,
            "migration": {
                "from_context_serialization": PREVIOUS_CONTEXT_SERIALIZATION,
                "retained_unchanged_rows": len(retained),
                "discarded_set_operation_rows": len(rows) - len(retained),
            },
        }
    if serialization != CONTEXT_SERIALIZATION:
        raise EvaluationError(
            f"pipeline checkpoint uses stale or unknown context serialization: {path}"
        )
    return payload


def run_pipeline_worker(input_path: Path, output_path: Path) -> int:
    from dotenv import load_dotenv

    # Force pipeline-stage tracing OFF during eval collection: the evaluation
    # emits its own clean per-case traces (with RAGAS scores) separately, so
    # letting every one of the 156 collection calls also fire 6 stage spans
    # would flood the dashboard with hundreds of stray traces. Set before
    # load_dotenv(override=False) so the backend/.env value can't turn it on.
    os.environ["LANGFUSE_ENABLED"] = "false"
    load_dotenv(REPO_ROOT / "backend" / ".env", override=False)
    environment = configure_local_only_environment()
    sys.path.insert(0, str(REPO_ROOT / "backend"))
    from orchestration.pipeline import run_pipeline

    cases = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise EvaluationError("pipeline worker input must be a non-empty case list")
    existing = _load_pipeline_checkpoint(output_path, cases)
    rows_by_id = {
        row["case_id"]: row for row in (existing or {}).get("rows", [])
    }
    previous_audit = (existing or {}).get("network_audit", {})
    previous_elapsed = float((existing or {}).get("elapsed_seconds", 0.0))
    started_at = (existing or {}).get("started_at") or utc_now()
    migration = (existing or {}).get("migration")
    session_started = time.perf_counter()

    def checkpoint(
        current_audit: dict[str, Any],
        *,
        status: str,
        last_error: dict[str, Any] | None = None,
    ) -> None:
        ordered_rows = [
            rows_by_id[case["case_id"]]
            for case in cases
            if case["case_id"] in rows_by_id
        ]
        payload = {
            "checkpoint_schema": PIPELINE_CHECKPOINT_SCHEMA,
            "dataset_fingerprint": dataset_fingerprint(cases),
            "context_serialization": CONTEXT_SERIALIZATION,
            "environment": environment,
            "network_audit": merge_network_audits(
                previous_audit, current_audit
            ),
            "status": status,
            "started_at": started_at,
            "updated_at": utc_now(),
            "elapsed_seconds": previous_elapsed
            + (time.perf_counter() - session_started),
            "case_count": len(cases),
            "completed_count": len(ordered_rows),
            "remaining_count": len(cases) - len(ordered_rows),
            "last_error": last_error,
            "rows": ordered_rows,
        }
        if migration:
            payload["migration"] = migration
        atomic_write_json(output_path, payload)

    current_audit: dict[str, Any] = {}
    try:
        with LoopbackOnlyNetworkAudit() as audit:
            try:
                if len(rows_by_id) < len(cases):
                    verify_local_ollama()
                for index, case in enumerate(cases, start=1):
                    if case["case_id"] in rows_by_id:
                        continue
                    result = run_pipeline(
                        case["question"], include_contexts=True
                    )
                    if result.allowed is not True:
                        raise EvaluationError(
                            "benign golden query was blocked during collection: "
                            f"{case['case_id']} "
                            f"({result.guardrail_category or 'unknown category'})"
                        )
                    result_dict = result.to_dict()
                    rows_by_id[case["case_id"]] = {
                        **case,
                        "answer": result.answer,
                        "allowed": result.allowed,
                        "guardrail_category": result.guardrail_category,
                        "contexts": list(result.retrieved_contexts),
                        "sources": result_dict["sources"],
                        "retrieved_count": result.retrieved_count,
                        "context_count": result.context_count,
                        "answer_source": result.answer_source,
                    }
                    current_audit = audit.to_dict()
                    checkpoint(current_audit, status="in_progress")
                    print(
                        f"pipeline checkpoint {len(rows_by_id)}/{len(cases)} "
                        f"after case {index}: {case['case_id']}",
                        flush=True,
                    )
            finally:
                current_audit = audit.to_dict()
        checkpoint(current_audit, status="complete")
    except BaseException as exc:
        checkpoint(
            current_audit,
            status="failed",
            last_error={
                "type": type(exc).__name__,
                "message": str(exc),
            },
        )
        raise
    return 0


def collect_pipeline_rows(
    cases: list[dict[str, Any]],
    checkpoint_path: Path | None = None,
) -> dict[str, Any]:
    if not BACKEND_PYTHON.exists():
        raise EvaluationError(f"backend interpreter not found: {BACKEND_PYTHON}")
    with tempfile.TemporaryDirectory(prefix="rag-accuracy-") as temp_dir:
        input_path = Path(temp_dir) / "cases.json"
        output_path = checkpoint_path or Path(temp_dir) / "pipeline.json"
        input_path.write_text(json.dumps(cases, ensure_ascii=False), encoding="utf-8")
        environment = os.environ.copy()
        environment.pop("OPENAI_API_KEY", None)
        environment.pop("OPENAI_BASE_URL", None)
        environment["PYTHONPATH"] = str(REPO_ROOT / "backend")
        completed = subprocess.run(
            [
                str(BACKEND_PYTHON),
                str(Path(__file__).resolve()),
                "--pipeline-worker",
                str(input_path),
                str(output_path),
            ],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise EvaluationError(
                "pipeline worker failed:\n"
                + completed.stdout[-4000:]
                + "\n"
                + completed.stderr[-4000:]
            )
        if not output_path.exists():
            raise EvaluationError("pipeline worker produced no result artifact")
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        payload["worker_stdout_tail"] = completed.stdout[-2000:]
        payload["worker_stderr_tail"] = completed.stderr[-2000:]
        return payload


def load_reusable_pipeline_rows(
    cases: list[dict[str, Any]], pipeline_raw: Path
) -> dict[str, Any]:
    if not pipeline_raw.exists():
        raise EvaluationError(f"pipeline raw artifact does not exist: {pipeline_raw}")
    payload = json.loads(pipeline_raw.read_text(encoding="utf-8"))
    if payload.get("context_serialization") != CONTEXT_SERIALIZATION:
        raise EvaluationError(
            "pipeline raw artifact uses stale or unknown context serialization"
        )
    rows = payload.get("rows", [])
    if len(rows) != len(cases):
        raise EvaluationError(
            f"pipeline raw artifact has {len(rows)} rows; expected {len(cases)}"
        )
    identity_fields = (
        "case_id",
        "relationship_type",
        "golden_artifact",
        "golden_artifact_sha256",
        "question",
        "reference",
    )
    for expected, actual in zip(cases, rows, strict=True):
        for field in identity_fields:
            if actual.get(field) != expected.get(field):
                raise EvaluationError(
                    f"pipeline raw artifact is stale for {expected['case_id']}: {field} differs"
                )
    audit = payload.get("network_audit", {})
    if audit.get("blocked_hosts") or audit.get("openai_host_attempted"):
        raise EvaluationError("pipeline raw artifact failed its network audit")
    return payload


def numeric_mean(values: list[Any]) -> tuple[float | None, int]:
    usable = [float(value) for value in values if value is not None and not math.isnan(float(value))]
    return (sum(usable) / len(usable) if usable else None, len(usable))


def extract_mitre_ids(text: str) -> set[str]:
    return {match.group(0).upper() for match in MITRE_ID_RE.finditer(text or "")}


def normalize_text(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9.]+", (text or "").casefold()))


def load_entity_catalog() -> dict[str, str]:
    """Load canonical names used to accept name-or-ID answer rendering."""
    catalog: dict[str, str] = {}
    parsed = REPO_ROOT / "backend" / "data" / "parsed"
    for path in sorted(parsed.glob("*.json")):
        if path.name == "relationships.json":
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            external_id = str(item.get("external_id") or "").upper()
            name = str(item.get("name") or "")
            if external_id:
                if external_id in catalog and catalog[external_id] != name:
                    raise EvaluationError(
                        f"conflicting pinned names for {external_id}"
                    )
                catalog[external_id] = name
    return catalog


def _entity_records(value: Any) -> dict[str, str]:
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


def load_source_pair(case: dict[str, Any]) -> dict[str, Any]:
    artifact = HERE / str(case.get("golden_artifact") or "")
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    pairs = payload.get("pairs")
    if not isinstance(pairs, list):
        raise EvaluationError(f"{artifact.name} does not contain a pairs list")
    source_case_id = case.get("source_case_id")
    matches = [pair for pair in pairs if pair.get("id") == source_case_id]
    if len(matches) != 1:
        raise EvaluationError(
            f"expected one source pair {source_case_id!r} in {artifact.name}; "
            f"found {len(matches)}"
        )
    pair = matches[0]
    if pair.get("expected_answer") != case.get("reference"):
        raise EvaluationError(
            f"source answer changed for final case {case.get('case_id')}"
        )
    return pair


def validate_negative_answer(
    row: dict[str, Any], catalog: dict[str, str]
) -> dict[str, Any]:
    """Validate graph-absence output without asking an LLM to infer absence.

    The source artifact and its hash establish the pinned graph fact. This
    check proves the production answer preserves the queried entities, the
    negative polarity, the permitted ATT&CK IDs, grounding, and RAG routing.
    """
    if case_polarity(row) != "negative":
        raise EvaluationError(
            f"deterministic negative validation received {row.get('case_id')}"
        )
    source_pair = load_source_pair(row)
    expected_fields = {
        key: value
        for key, value in source_pair.items()
        if key.startswith("expected_") and key != "expected_answer"
    }
    structured_negative = (
        source_pair.get("relationship_exists") is False
        or any(value == [] for value in expected_fields.values())
        or "negative" in str(source_pair.get("case_type") or "").casefold()
        or "no_" in str(source_pair.get("case_type") or "").casefold()
        or "zero" in str(source_pair.get("case_type") or "").casefold()
    )
    if not structured_negative:
        raise EvaluationError(
            f"negative case {row.get('case_id')} lacks structured negative truth"
        )

    required_entities: dict[str, str] = {
        external_id: catalog.get(external_id, "")
        for external_id in extract_mitre_ids(
            str(source_pair.get("question") or "")
        )
    }
    for key, value in source_pair.items():
        if key in {
            "id",
            "question",
            "expected_answer",
            "provenance",
            "case_type",
            "relationship_type",
        } or key.startswith("expected_"):
            continue
        required_entities.update(_entity_records(value))

    reference_ids = extract_mitre_ids(str(row.get("reference") or ""))
    allowed_ids = reference_ids | set(required_entities)
    answer = str(row.get("answer") or "")
    answer_ids = extract_mitre_ids(answer)
    normalized_answer = normalize_text(answer)
    missing_ids = sorted(
        external_id
        for external_id, name in required_entities.items()
        if external_id not in answer_ids
        and (not name or normalize_text(name) not in normalized_answer)
    )
    unexpected_ids = sorted(answer_ids - allowed_ids)
    evidence_text = "\n".join(
        [str(row.get("question") or "")]
        + [str(context) for context in row.get("contexts") or []]
    )
    # The pinned structured golden fact is authoritative evidence for this
    # deterministic branch. Some production renderers expose a nested
    # relationship ID (for example DET0862) that format_context() omits from
    # its flattened node text; that serializer gap is precisely why Ragas is
    # inapplicable here and must not turn a correct golden ID into a failure.
    grounded_ids = reference_ids | extract_mitre_ids(evidence_text) | {
        str(source.get("external_id") or "").upper()
        for source in row.get("sources") or []
        if source.get("external_id")
    }
    ungrounded_ids = sorted(answer_ids - grounded_ids)
    errors = []
    if row.get("allowed") is not True:
        errors.append("verified benign negative query was blocked")
    if not answer.strip():
        errors.append("pipeline returned an empty answer")
    if missing_ids:
        errors.append(f"missing queried entities: {missing_ids}")
    if unexpected_ids:
        errors.append(f"unexpected ATT&CK IDs: {unexpected_ids}")
    if ungrounded_ids:
        errors.append(f"ungrounded ATT&CK IDs: {ungrounded_ids}")
    if not NEGATION_RE.search(answer):
        errors.append("answer lost the golden negative polarity")
    if row.get("answer_source") == "log_analysis":
        errors.append("GraphRAG query was routed to log analysis")
    if not (row.get("sources") or row.get("contexts")):
        errors.append("answer has no retrieved evidence")
    return {
        "method": NEGATIVE_VALIDATION_METHOD,
        "passed": not errors,
        "source_case_id": row.get("source_case_id"),
        "source_artifact": row.get("golden_artifact"),
        "source_artifact_sha256": row.get("golden_artifact_sha256"),
        "structured_negative_truth": structured_negative,
        "required_entities": required_entities,
        "answer_ids": sorted(answer_ids),
        "allowed_ids": sorted(allowed_ids),
        "grounded_ids": sorted(grounded_ids),
        "errors": errors,
    }


def build_negative_validation_rows(
    rows: list[dict[str, Any]], catalog: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    catalog = catalog or load_entity_catalog()
    validated = []
    failures = []
    for row in rows:
        result = validate_negative_answer(row, catalog)
        validated_row = {
            **row,
            "evaluation_method": NEGATIVE_VALIDATION_METHOD,
            "ragas_metrics_applicable": False,
            "scores": {metric: None for metric in REQUIRED_SCORE_METRICS},
            "deterministic_validation": result,
        }
        validated.append(validated_row)
        if not result["passed"]:
            failures.append(
                f"{row['case_id']}={'; '.join(result['errors'])}"
            )
    if failures:
        raise EvaluationError(
            "negative golden validation failed: " + ", ".join(failures)
        )
    return validated


def _external_ids(records: Any) -> set[str]:
    return set(_entity_records(records))


def _relationship_section_ids(context: str, heading: str) -> set[str] | None:
    """Return IDs from one explicit relationship-list section.

    ``format_context()`` renders authoritative relationship lists as a heading
    followed by dash-prefixed records. Stopping at the first non-list line
    keeps another relationship section on the same node out of the operand.
    """
    lines = str(context or "").splitlines()
    try:
        start = lines.index(heading) + 1
    except ValueError:
        return None
    records: list[str] = []
    for line in lines[start:]:
        if not line.startswith("- "):
            break
        records.append(line)
    return extract_mitre_ids("\n".join(records))


def validate_set_operation_answer(
    row: dict[str, Any], catalog: dict[str, str]
) -> dict[str, Any]:
    """Validate a closed-world set difference from pinned operand sets.

    Ragas faithfulness is an open-world textual-entailment metric. It cannot
    prove that an item is *absent* from a complete graph relationship set and
    showed material phrasing sensitivity on identical answers/contexts. This
    validator instead verifies the source artifact's set algebra, the exact
    answer set, and both complete retrieved operand sets without an LLM.
    """
    if case_evaluation_kind(row) != "set_operation":
        raise EvaluationError(
            f"deterministic set validation received {row.get('case_id')}"
        )
    source_pair = load_source_pair(row)
    provenance = source_pair.get("provenance") or {}
    operation = provenance.get("set_operation")
    if operation != "software_direct_techniques minus campaign_direct_techniques":
        raise EvaluationError(
            f"unsupported or missing pinned set operation for {row.get('case_id')}"
        )
    if source_pair.get("case_type") != "campaign_software_technique_divergence":
        raise EvaluationError(
            f"unexpected set-operation case type for {row.get('case_id')}"
        )

    campaign = source_pair.get("campaign") or {}
    software = source_pair.get("software") or {}
    campaign_id = str(campaign.get("external_id") or "").upper()
    software_id = str(software.get("external_id") or "").upper()
    if not campaign_id or not software_id:
        raise EvaluationError(
            f"set-operation operands lack authoritative IDs for {row.get('case_id')}"
        )

    campaign_set = _external_ids(
        source_pair.get("expected_campaign_direct_techniques")
    )
    software_set = _external_ids(
        source_pair.get("expected_software_techniques")
    )
    expected_result = _external_ids(
        source_pair.get("expected_software_only_techniques")
    )
    expected_shared = _external_ids(
        source_pair.get("expected_shared_techniques")
    )
    expected_campaign_only = _external_ids(
        source_pair.get("expected_campaign_only_techniques")
    )
    algebra_checks = {
        "software_minus_campaign": software_set - campaign_set == expected_result,
        "intersection": software_set & campaign_set == expected_shared,
        "campaign_minus_software": campaign_set - software_set
        == expected_campaign_only,
    }

    answer = str(row.get("answer") or "")
    answer_ids = extract_mitre_ids(answer)
    answer_technique_ids = {
        external_id
        for external_id in answer_ids
        if external_id.startswith("T") and not external_id.startswith("TA")
    }
    missing_answer_ids = sorted(expected_result - answer_technique_ids)
    unexpected_answer_ids = sorted(answer_technique_ids - expected_result)
    normalized_answer = normalize_text(answer)
    expected_names = {
        str(record.get("name") or "")
        for record in source_pair.get("expected_software_only_techniques") or []
        if isinstance(record, dict) and record.get("name")
    }
    missing_answer_names = sorted(
        name
        for name in expected_names
        if normalize_text(name) not in normalized_answer
    )

    campaign_context_set: set[str] | None = None
    software_context_set: set[str] | None = None
    for context in row.get("contexts") or []:
        context_ids = extract_mitre_ids(str(context))
        if campaign_id in context_ids:
            candidate = _relationship_section_ids(
                str(context), "Techniques directly used by this Campaign:"
            )
            if candidate is not None:
                campaign_context_set = candidate
        if software_id in context_ids:
            software_type = str(software.get("stix_type") or "").casefold()
            node_type = "Tool" if software_type == "tool" else "Malware"
            candidate = _relationship_section_ids(
                str(context),
                f"Techniques directly used by this {node_type}:",
            )
            if candidate is not None:
                software_context_set = candidate

    source_ids = {
        str(source.get("external_id") or "").upper()
        for source in row.get("sources") or []
        if source.get("external_id")
    }
    errors: list[str] = []
    if row.get("allowed") is not True:
        errors.append("verified benign set-operation query was blocked")
    if not answer.strip():
        errors.append("pipeline returned an empty answer")
    if not all(algebra_checks.values()):
        errors.append(f"pinned source set algebra is inconsistent: {algebra_checks}")
    if missing_answer_ids:
        errors.append(f"answer is missing result IDs: {missing_answer_ids}")
    if unexpected_answer_ids:
        errors.append(f"answer contains non-result technique IDs: {unexpected_answer_ids}")
    if missing_answer_names:
        errors.append(f"answer is missing result names: {missing_answer_names}")
    for operand_id in (campaign_id, software_id):
        if operand_id not in answer_ids:
            errors.append(f"answer is missing operand ID: {operand_id}")
        if operand_id not in source_ids:
            errors.append(f"retrieved sources are missing operand ID: {operand_id}")
    if campaign_context_set is None:
        errors.append("campaign operand relationship section is absent from contexts")
    elif campaign_context_set != campaign_set:
        errors.append(
            "campaign context operand differs from pinned set: "
            f"missing={sorted(campaign_set - campaign_context_set)}, "
            f"unexpected={sorted(campaign_context_set - campaign_set)}"
        )
    if software_context_set is None:
        errors.append("software operand relationship section is absent from contexts")
    elif software_context_set != software_set:
        errors.append(
            "software context operand differs from pinned set: "
            f"missing={sorted(software_set - software_context_set)}, "
            f"unexpected={sorted(software_context_set - software_set)}"
        )
    if row.get("answer_source") == "log_analysis":
        errors.append("GraphRAG query was routed to log analysis")
    return {
        "method": SET_OPERATION_VALIDATION_METHOD,
        "passed": not errors,
        "operation": operation,
        "source_case_id": row.get("source_case_id"),
        "source_artifact": row.get("golden_artifact"),
        "source_artifact_sha256": row.get("golden_artifact_sha256"),
        "operand_ids": [software_id, campaign_id],
        "operand_counts": {
            "software": len(software_set),
            "campaign": len(campaign_set),
        },
        "expected_result_count": len(expected_result),
        "answer_result_count": len(answer_technique_ids),
        "shared_count": len(expected_shared),
        "campaign_only_count": len(expected_campaign_only),
        "algebra_checks": algebra_checks,
        "answer_exact_match": (
            not missing_answer_ids
            and not unexpected_answer_ids
            and not missing_answer_names
        ),
        "context_operands_exact_match": (
            campaign_context_set == campaign_set
            and software_context_set == software_set
        ),
        "missing_answer_ids": missing_answer_ids,
        "unexpected_answer_ids": unexpected_answer_ids,
        "errors": errors,
    }


def build_set_operation_validation_rows(
    rows: list[dict[str, Any]], catalog: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    catalog = catalog or load_entity_catalog()
    validated = []
    failures = []
    for row in rows:
        result = validate_set_operation_answer(row, catalog)
        validated_row = {
            **row,
            "evaluation_method": SET_OPERATION_VALIDATION_METHOD,
            "ragas_metrics_applicable": False,
            "scores": {metric: None for metric in REQUIRED_SCORE_METRICS},
            "deterministic_validation": result,
        }
        validated.append(validated_row)
        if not result["passed"]:
            failures.append(
                f"{row['case_id']}={'; '.join(result['errors'])}"
            )
    if failures:
        raise EvaluationError(
            "set-operation golden validation failed: " + ", ".join(failures)
        )
    return validated


def score_with_ragas(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from langchain_ollama import ChatOllama, OllamaEmbeddings
    from ragas import EvaluationDataset, SingleTurnSample, evaluate
    from ragas.embeddings import LangchainEmbeddingsWrapper
    from ragas.llms import LangchainLLMWrapper
    # These three established metrics remain available from ragas.metrics in
    # 0.4.3. The newer collections API uses a different Instructor-only LLM
    # interface and cannot accept the required LangchainLLMWrapper.
    from ragas.metrics import (
        Faithfulness,
        LLMContextPrecisionWithReference,
        LLMContextRecall,
    )
    from ragas.run_config import RunConfig

    judge = LangchainLLMWrapper(
        ChatOllama(
            model=JUDGE_MODEL,
            base_url=OLLAMA_BASE_URL,
            temperature=0,
            seed=RAGAS_JUDGE_SEED,
            format="json",
            num_ctx=RAGAS_JUDGE_NUM_CTX,
        )
    )
    langchain_embeddings = OllamaEmbeddings(
        model=EMBEDDING_MODEL,
        base_url=OLLAMA_BASE_URL,
    )
    embeddings = LangchainEmbeddingsWrapper(langchain_embeddings)
    embedding_probe = langchain_embeddings.embed_query("local embedding wiring probe")
    if not embedding_probe:
        raise EvaluationError("local embedding model returned an empty vector")

    samples = [
        SingleTurnSample(
            user_input=row["question"],
            response=row["answer"],
            retrieved_contexts=row["contexts"],
            reference=row["reference"],
        )
        for row in rows
    ]
    class CardinalityCheckedFaithfulness(Faithfulness):
        """Reject silently shortened local-judge verdict lists.

        Ragas otherwise divides by however many verdicts the model happened to
        return, even when that is fewer than the generated claims. Raising here
        converts the row to an incomplete score, which the checkpointed retry
        layer already isolates and retries instead of publishing.
        """

        async def _create_verdicts(self, row, statements, callbacks):
            verdicts = await super()._create_verdicts(
                row, statements, callbacks
            )
            if len(verdicts.statements) != len(statements):
                raise ValueError(
                    "faithfulness verdict cardinality mismatch: "
                    f"expected {len(statements)}, got "
                    f"{len(verdicts.statements)}"
                )
            return verdicts

    faithfulness = CardinalityCheckedFaithfulness(llm=judge)
    faithfulness.statement_generator_prompt.instruction = (
        "Given a question and answer, extract every externally checkable "
        "atomic factual claim asserted by the answer. For an affirmative or "
        "negative yes/no answer, do not emit a standalone meta-claim such as "
        "The answer is yes; express the underlying entity relationship with "
        "its polarity instead. A heading followed by bullets asserts the "
        "heading relationship for every bullet. Preserve ATT&CK identifiers "
        "exactly and do not invent or rename identifiers. Entity name and ID "
        "equivalences are factual claims when the answer asserts them. Use "
        "fully understandable statements without pronouns, include every "
        "factual assertion, and format the output as JSON."
    )
    faithfulness.nli_statements_prompt.instruction = (
        "Judge whether each statement is directly supported by the context. "
        "Context section headings define the relationship inherited by every "
        "bullet beneath them. The same graph edge may be stated in inverse "
        "grammatical direction without changing the fact: Campaign uses "
        "Technique is equivalent to Technique is used by Campaign; Detection "
        "Strategy contains Analytic is equivalent to Analytic belongs to "
        "Detection Strategy; source uses target is equivalent to target is "
        "used by source. A generic explicitly-connected claim is supported "
        "when the context names both exact entities in that requested "
        "directional relationship. Return verdict 1 for supported and 0 "
        "otherwise, with exactly one result for every input statement in the "
        "same order. Format the output as JSON."
    )

    metrics = [
        faithfulness,
        LLMContextPrecisionWithReference(llm=judge),
        LLMContextRecall(llm=judge),
    ]
    result = evaluate(
        dataset=EvaluationDataset(samples=samples),
        metrics=metrics,
        llm=judge,
        embeddings=embeddings,
        run_config=RunConfig(
            timeout=RAGAS_TIMEOUT_SECONDS,
            max_retries=RAGAS_MAX_RETRIES,
            max_wait=RAGAS_MAX_WAIT_SECONDS,
            max_workers=RAGAS_MAX_WORKERS,
        ),
        raise_exceptions=False,
        show_progress=True,
        batch_size=1,
    )
    frame_rows = result.to_pandas().to_dict(orient="records")
    if len(frame_rows) != len(rows):
        raise EvaluationError(
            f"Ragas returned {len(frame_rows)} rows for {len(rows)} inputs"
        )
    scored: list[dict[str, Any]] = []
    def clean_score(value: Any) -> float | None:
        if value is None:
            return None
        number = float(value)
        return None if math.isnan(number) else number

    for source, scores in zip(rows, frame_rows, strict=True):
        scored.append(
            {
                **source,
                "scores": {
                    "faithfulness": clean_score(scores.get("faithfulness")),
                    "context_precision": clean_score(scores.get("llm_context_precision_with_reference")),
                    "context_recall": clean_score(scores.get("context_recall")),
                },
            }
        )
    return scored, {
        "judge": f"ChatOllama/{JUDGE_MODEL}",
        "judge_wrapper": "ragas.llms.LangchainLLMWrapper",
        "judge_seed": RAGAS_JUDGE_SEED,
        "embeddings": f"OllamaEmbeddings/{EMBEDDING_MODEL}",
        "embeddings_wrapper": "ragas.embeddings.LangchainEmbeddingsWrapper",
        "embedding_probe_dimensions": len(embedding_probe),
        "ragas_version": __import__("ragas").__version__,
    }


def valid_scored_row(
    row: dict[str, Any], expected_pipeline_row: dict[str, Any]
) -> bool:
    scores = row.get("scores")
    if not isinstance(scores, dict):
        return False
    for metric in REQUIRED_SCORE_METRICS:
        value = scores.get(metric)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
        ):
            return False
    return (
        case_identity(row) == case_identity(expected_pipeline_row)
        and row.get("answer") == expected_pipeline_row.get("answer")
        and row.get("contexts") == expected_pipeline_row.get("contexts")
    )


def incomplete_score_metrics(row: dict[str, Any]) -> list[str]:
    """Return metrics that cannot be used in a complete measurement."""
    scores = row.get("scores")
    if not isinstance(scores, dict):
        return list(REQUIRED_SCORE_METRICS)
    missing = []
    for metric in REQUIRED_SCORE_METRICS:
        value = scores.get(metric)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
        ):
            missing.append(metric)
    return missing


def score_batch_with_incomplete_retries(
    rows: list[dict[str, Any]],
    *,
    max_incomplete_retries: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Score a batch, retrying only cases with incomplete metric vectors.

    Ragas evaluates all three metrics together, so the smallest safe retry unit
    is one case. A row is committed only when all required metrics came from a
    single complete attempt; successful metrics from different attempts are
    never spliced together.
    """
    if max_incomplete_retries < 0:
        raise EvaluationError("incomplete-score retries cannot be negative")
    expected_by_id = {row["case_id"]: row for row in rows}
    if len(expected_by_id) != len(rows):
        raise EvaluationError("scoring batch contains duplicate case IDs")

    complete_by_id: dict[str, dict[str, Any]] = {}
    pending = list(rows)
    local_models: dict[str, Any] | None = None
    last_attempt_by_id: dict[str, dict[str, Any]] = {}
    for attempt in range(max_incomplete_retries + 1):
        # The first attempt uses the configured batch. Retries isolate each
        # incomplete case so one long prompt cannot starve its neighbours.
        attempt_groups = [pending] if attempt == 0 else [[row] for row in pending]
        incomplete_ids = []
        for attempt_group in attempt_groups:
            scored_rows, attempt_models = score_with_ragas(attempt_group)
            if local_models is not None and local_models != attempt_models:
                raise EvaluationError(
                    "local model provenance changed during retries"
                )
            local_models = attempt_models

            returned_ids = [row.get("case_id") for row in scored_rows]
            if (
                len(returned_ids) != len(attempt_group)
                or len(set(returned_ids)) != len(returned_ids)
                or set(returned_ids)
                != {row["case_id"] for row in attempt_group}
            ):
                raise EvaluationError(
                    "Ragas returned missing, duplicate, or unexpected case IDs"
                )

            for scored in scored_rows:
                case_id = scored["case_id"]
                last_attempt_by_id[case_id] = scored
                expected = expected_by_id[case_id]
                if valid_scored_row(scored, expected):
                    complete_by_id[case_id] = scored
                else:
                    incomplete_ids.append(case_id)

        if not incomplete_ids:
            return (
                [complete_by_id[row["case_id"]] for row in rows],
                [],
                local_models,
            )
        pending = [expected_by_id[case_id] for case_id in incomplete_ids]
        if attempt < max_incomplete_retries:
            print(
                "retrying incomplete Ragas cases "
                f"({attempt + 1}/{max_incomplete_retries}): "
                + ", ".join(incomplete_ids),
                flush=True,
            )

    unresolved = [
        {
            "case_id": row["case_id"],
            "missing_metrics": incomplete_score_metrics(
                last_attempt_by_id.get(row["case_id"], {})
            ),
        }
        for row in pending
    ]
    return (
        [
            complete_by_id[row["case_id"]]
            for row in rows
            if row["case_id"] in complete_by_id
        ],
        unresolved,
        local_models or {},
    )


def _load_scoring_checkpoint(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    legacy_all_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    schema = payload.get("checkpoint_schema")
    if schema == LEGACY_SCORING_CHECKPOINT_SCHEMA:
        if legacy_all_rows is None:
            raise EvaluationError(
                "v2 scoring checkpoint migration requires the original full rows"
            )
        legacy_configuration = legacy_scoring_configuration_v2()
        if payload.get("scoring_configuration") != legacy_configuration:
            raise EvaluationError(
                f"legacy scoring checkpoint has a different judge configuration: {path}"
            )
        legacy_fingerprint = _scoring_input_fingerprint(
            legacy_all_rows, legacy_configuration
        )
        if payload.get("scoring_input_fingerprint") != legacy_fingerprint:
            raise EvaluationError(
                f"legacy scoring checkpoint is stale for the full pipeline rows: {path}"
            )
        all_expected = {row["case_id"]: row for row in legacy_all_rows}
        retained_ids = {row["case_id"] for row in rows}
        retained = []
        dropped = 0
        seen_legacy: set[str] = set()
        legacy_rows = payload.get("rows")
        if not isinstance(legacy_rows, list):
            raise EvaluationError("legacy scoring checkpoint rows are malformed")
        for scored in legacy_rows:
            case_id = scored.get("case_id")
            expected = all_expected.get(case_id)
            if (
                expected is None
                or case_id in seen_legacy
                or not valid_scored_row(scored, expected)
            ):
                raise EvaluationError(
                    f"legacy checkpoint contains an invalid row for {case_id!r}"
                )
            seen_legacy.add(case_id)
            if case_id in retained_ids:
                retained.append(scored)
            else:
                dropped += 1
        payload = {
            **payload,
            "checkpoint_schema": SCORING_CHECKPOINT_SCHEMA,
            "scoring_input_fingerprint": scoring_input_fingerprint(rows),
            "scoring_configuration": scoring_configuration(),
            "status": "in_progress",
            "case_count": len(rows),
            "completed_count": len(retained),
            "remaining_count": len(rows) - len(retained),
            "last_error": None,
            "rows": retained,
            "migration": {
                "from_schema": LEGACY_SCORING_CHECKPOINT_SCHEMA,
                "retained_positive_rows": len(retained),
                "discarded_inapplicable_negative_rows": dropped,
                "source_scoring_input_fingerprint": legacy_fingerprint,
            },
        }
    elif schema == PREVIOUS_SCORING_CHECKPOINT_SCHEMA:
        if legacy_all_rows is None:
            raise EvaluationError(
                "v7 scoring checkpoint migration requires the original full rows"
            )
        previous_configuration = previous_scoring_configuration_v7()
        if payload.get("scoring_configuration") != previous_configuration:
            raise EvaluationError(
                f"v7 scoring checkpoint has a different judge configuration: {path}"
            )
        previous_rows = [
            row
            for row in legacy_all_rows
            if case_polarity(row) == "positive"
        ]
        previous_expected = {row["case_id"]: row for row in previous_rows}
        retained_ids = {row["case_id"] for row in rows}
        retained = []
        dropped = 0
        seen_previous: set[str] = set()
        previous_scored_rows = payload.get("rows")
        if not isinstance(previous_scored_rows, list):
            raise EvaluationError("v7 scoring checkpoint rows are malformed")
        for scored in previous_scored_rows:
            case_id = scored.get("case_id")
            expected = previous_expected.get(case_id)
            scores = scored.get("scores")
            score_vector_is_complete = isinstance(scores, dict) and all(
                isinstance(scores.get(metric), (int, float))
                and not isinstance(scores.get(metric), bool)
                and math.isfinite(float(scores[metric]))
                for metric in REQUIRED_SCORE_METRICS
            )
            if (
                expected is None
                or case_id in seen_previous
                or case_identity(scored) != case_identity(expected)
                or not score_vector_is_complete
            ):
                raise EvaluationError(
                    f"v7 checkpoint contains an invalid row for {case_id!r}"
                )
            seen_previous.add(case_id)
            if case_id in retained_ids:
                # Only preserve scores whose exact answer and evidence still
                # match the refreshed pipeline row. The three set-operation
                # rows are intentionally excluded from retained_ids; every
                # ordinary row must pass the full per-row equality check.
                if not valid_scored_row(scored, expected):
                    raise EvaluationError(
                        f"v7 checkpoint score is stale for retained row {case_id!r}"
                    )
                retained.append(scored)
            else:
                dropped += 1
        payload = {
            **payload,
            "checkpoint_schema": SCORING_CHECKPOINT_SCHEMA,
            "scoring_input_fingerprint": scoring_input_fingerprint(rows),
            "scoring_configuration": scoring_configuration(),
            "status": "in_progress",
            "case_count": len(rows),
            "completed_count": len(retained),
            "remaining_count": len(rows) - len(retained),
            "last_error": None,
            "rows": retained,
            "migration": {
                "from_schema": PREVIOUS_SCORING_CHECKPOINT_SCHEMA,
                "retained_open_world_rows": len(retained),
                "discarded_set_operation_rows": dropped,
                "source_scoring_input_fingerprint": payload.get(
                    "scoring_input_fingerprint"
                ),
                "verification": "exact_per_retained_row_answer_and_context",
            },
        }
    elif schema != SCORING_CHECKPOINT_SCHEMA:
        raise EvaluationError(
            f"scoring checkpoint uses an unknown schema: {path}"
        )
    if payload.get("scoring_configuration") != scoring_configuration():
        raise EvaluationError(
            f"scoring checkpoint uses a different judge configuration: {path}"
        )
    expected_fingerprint = scoring_input_fingerprint(rows)
    if payload.get("scoring_input_fingerprint") != expected_fingerprint:
        raise EvaluationError(
            f"scoring checkpoint is stale for these exact pipeline rows: {path}"
        )
    expected_by_id = {row["case_id"]: row for row in rows}
    checkpoint_rows = payload.get("rows")
    if not isinstance(checkpoint_rows, list):
        raise EvaluationError("scoring checkpoint rows are malformed")
    seen: set[str] = set()
    for scored in checkpoint_rows:
        case_id = scored.get("case_id")
        expected = expected_by_id.get(case_id)
        if (
            expected is None
            or case_id in seen
            or not valid_scored_row(scored, expected)
        ):
            raise EvaluationError(
                f"scoring checkpoint contains an invalid row for {case_id!r}"
            )
        seen.add(case_id)
    audit = payload.get("network_audit", {})
    if audit.get("blocked_hosts") or audit.get("openai_host_attempted"):
        raise EvaluationError("scoring checkpoint failed its network audit")
    return payload


def score_with_ragas_checkpointed(
    rows: list[dict[str, Any]],
    checkpoint_path: Path,
    batch_size: int = DEFAULT_SCORING_BATCH_SIZE,
    incomplete_score_retries: int = DEFAULT_INCOMPLETE_SCORE_RETRIES,
    *,
    legacy_all_rows: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if batch_size < 1:
        raise EvaluationError("scoring batch size must be at least one")
    if incomplete_score_retries < 0:
        raise EvaluationError("incomplete-score retries cannot be negative")
    existing = _load_scoring_checkpoint(
        checkpoint_path, rows, legacy_all_rows=legacy_all_rows
    )
    scored_by_id = {
        row["case_id"]: row for row in (existing or {}).get("rows", [])
    }
    previous_audit = (existing or {}).get("network_audit", {})
    previous_elapsed = float((existing or {}).get("elapsed_seconds", 0.0))
    started_at = (existing or {}).get("started_at") or utc_now()
    local_models = (existing or {}).get("local_models")
    migration = (existing or {}).get("migration")
    pending = [row for row in rows if row["case_id"] not in scored_by_id]
    session_started = time.perf_counter()

    def checkpoint(
        current_audit: dict[str, Any],
        *,
        status: str,
        last_error: dict[str, Any] | None = None,
    ) -> None:
        ordered_rows = [
            scored_by_id[row["case_id"]]
            for row in rows
            if row["case_id"] in scored_by_id
        ]
        payload = {
            "checkpoint_schema": SCORING_CHECKPOINT_SCHEMA,
            "scoring_input_fingerprint": scoring_input_fingerprint(rows),
            "network_audit": merge_network_audits(
                previous_audit, current_audit
            ),
            "status": status,
            "started_at": started_at,
            "updated_at": utc_now(),
            "elapsed_seconds": previous_elapsed
            + (time.perf_counter() - session_started),
            "batch_size": batch_size,
            "incomplete_score_retries": incomplete_score_retries,
            "scoring_configuration": scoring_configuration(),
            "case_count": len(rows),
            "completed_count": len(ordered_rows),
            "remaining_count": len(rows) - len(ordered_rows),
            "local_models": local_models,
            "last_error": last_error,
            "rows": ordered_rows,
        }
        if migration:
            payload["migration"] = migration
        atomic_write_json(checkpoint_path, payload)

    if not rows and existing is None:
        local_models = {
            "judge": JUDGE_MODEL,
            "embeddings": EMBEDDING_MODEL,
            "invoked": False,
            "reason": "no Ragas-applicable cases selected",
        }
        checkpoint({}, status="complete")
        return [], local_models, merge_network_audits()

    if not pending:
        if not isinstance(local_models, dict):
            raise EvaluationError(
                "complete scoring checkpoint lacks local-model provenance"
            )
        if migration:
            checkpoint(previous_audit, status="complete")
        return (
            [scored_by_id[row["case_id"]] for row in rows],
            local_models,
            previous_audit,
        )

    cumulative_current_audit: dict[str, Any] = {}
    total_batches = (len(pending) + batch_size - 1) // batch_size
    for batch_index, offset in enumerate(
        range(0, len(pending), batch_size), start=1
    ):
        batch = pending[offset : offset + batch_size]
        batch_audit: dict[str, Any] = {}
        try:
            with LoopbackOnlyNetworkAudit() as audit:
                try:
                    batch_scored, incomplete, batch_models = (
                        score_batch_with_incomplete_retries(
                            batch,
                            max_incomplete_retries=incomplete_score_retries,
                        )
                    )
                finally:
                    batch_audit = audit.to_dict()
        except BaseException as exc:
            cumulative_current_audit = merge_network_audits(
                cumulative_current_audit, batch_audit
            )
            checkpoint(
                cumulative_current_audit,
                status="failed",
                last_error={
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "batch_index": batch_index,
                },
            )
            raise
        if local_models is not None and local_models != batch_models:
            raise EvaluationError("local model provenance changed between batches")
        local_models = batch_models
        for scored in batch_scored:
            scored_by_id[scored["case_id"]] = scored
        cumulative_current_audit = merge_network_audits(
            cumulative_current_audit, batch_audit
        )
        if incomplete:
            checkpoint(
                cumulative_current_audit,
                status="failed",
                last_error={
                    "type": "IncompleteRagasScores",
                    "message": (
                        "Ragas still returned incomplete metric vectors after "
                        f"{incomplete_score_retries} targeted retries"
                    ),
                    "batch_index": batch_index,
                    "cases": incomplete,
                },
            )
            raise EvaluationError(
                "Ragas measurement is incomplete after targeted retries: "
                + ", ".join(
                    f"{item['case_id']}={item['missing_metrics']}"
                    for item in incomplete
                )
            )
        checkpoint(cumulative_current_audit, status="in_progress")
        print(
            f"scoring checkpoint {len(scored_by_id)}/{len(rows)} "
            f"after batch {batch_index}/{total_batches}",
            flush=True,
        )
    checkpoint(cumulative_current_audit, status="complete")
    return (
        [scored_by_id[row["case_id"]] for row in rows],
        local_models,
        merge_network_audits(previous_audit, cumulative_current_audit),
    )


def derive_aggregates(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = REQUIRED_SCORE_METRICS
    overall: dict[str, Any] = {}
    for metric in metrics:
        mean, scored_count = numeric_mean([row["scores"].get(metric) for row in rows])
        overall[metric] = {
            "mean": mean,
            "scored_count": scored_count,
            "total_count": len(rows),
        }
    by_relationship: dict[str, Any] = {}
    for relationship_type in sorted({row["relationship_type"] for row in rows}):
        selected = [row for row in rows if row["relationship_type"] == relationship_type]
        by_relationship[relationship_type] = {}
        for metric in metrics:
            mean, scored_count = numeric_mean([row["scores"].get(metric) for row in selected])
            by_relationship[relationship_type][metric] = {
                "mean": mean,
                "scored_count": scored_count,
                "total_count": len(selected),
            }
    by_variant: dict[str, Any] = {}
    for variant_kind in sorted(
        {
            row["variant_kind"]
            for row in rows
            if isinstance(row.get("variant_kind"), str)
        }
    ):
        selected = [
            row for row in rows if row.get("variant_kind") == variant_kind
        ]
        by_variant[variant_kind] = {}
        for metric in metrics:
            mean, scored_count = numeric_mean(
                [row["scores"].get(metric) for row in selected]
            )
            by_variant[variant_kind][metric] = {
                "mean": mean,
                "scored_count": scored_count,
                "total_count": len(selected),
            }
    by_polarity: dict[str, Any] = {}
    for polarity in sorted({case_polarity(row) for row in rows}):
        selected = [row for row in rows if case_polarity(row) == polarity]
        by_polarity[polarity] = {}
        for metric in metrics:
            mean, scored_count = numeric_mean(
                [row["scores"].get(metric) for row in selected]
            )
            by_polarity[polarity][metric] = {
                "mean": mean,
                "scored_count": scored_count,
                "total_count": len(selected),
            }
    return {
        "overall": overall,
        "by_relationship_type": by_relationship,
        "by_variant_kind": by_variant,
        "by_case_polarity": by_polarity,
    }


def case_polarity(row: dict[str, Any]) -> str:
    """Separate graph-absence claims from positive relationship answers."""
    sampling_slot = row.get("sampling_slot")
    if not isinstance(sampling_slot, str):
        return "unspecified"
    return "negative" if sampling_slot in NEGATIVE_SAMPLING_SLOTS else "positive"


def case_evaluation_kind(row: dict[str, Any]) -> str:
    """Select a metric only when its assumptions match the claim shape."""
    if case_polarity(row) == "negative":
        return "graph_absence"
    if row.get("sampling_slot") in SET_OPERATION_SAMPLING_SLOTS:
        return "set_operation"
    return "ragas_open_world"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        (
            "# RAG Accuracy — final 156-case local Ragas measurement"
            if report["sample"].get("dataset") == FINAL_DATASET_NAME
            else "# RAG Accuracy — Step 8a local Ragas prototype"
        ),
        "",
        f"- Cases: {report['sample']['case_count']}",
        f"- Judge: `{report['local_models']['judge']}`",
        f"- Embeddings: `{report['local_models']['embeddings']}`",
        f"- OPENAI_API_KEY present: `{report['environment']['OPENAI_API_KEY_present']}`",
        f"- OpenAI host attempted: `{report['network_audit']['openai_host_attempted']}`",
        f"- Blocked external hosts: `{report['network_audit']['blocked_hosts']}`",
        "",
    ]
    negative_validation = report.get("negative_case_validation")
    set_operation_validation = report.get("set_operation_validation")
    if negative_validation or set_operation_validation:
        lines.extend(
            [
                "## Metric applicability",
                "",
                f"- Ragas-scored positive cases: "
                f"{report['sample']['ragas_applicable_case_count']}",
            ]
        )
        if negative_validation and negative_validation.get("case_count"):
            lines.extend(
                [
                    f"- Deterministically validated negative cases: "
                    f"{negative_validation['passed_count']}/"
                    f"{negative_validation['case_count']}",
                    "- Ragas metrics are `n/a` for graph-absence cases: "
                    "retrieved positive node descriptions are not an exhaustive "
                    "representation of graph non-edges.",
                ]
            )
        if set_operation_validation and set_operation_validation.get("case_count"):
            lines.extend(
                [
                    f"- Deterministically validated set-operation cases: "
                    f"{set_operation_validation['passed_count']}/"
                    f"{set_operation_validation['case_count']}",
                    "- Ragas metrics are `n/a` for closed-world set operations: "
                    "faithfulness requires proving exact membership and absence "
                    "across complete operands, which is verified directly.",
                ]
            )
        lines.append("")
    lines.extend(
        [
        "## Independently derived aggregate scores",
        "",
        "| Metric | Mean | Applicable/scored | Total cases |",
        "|---|---:|---:|---:|",
        ]
    )
    for metric, summary in report["aggregates"]["overall"].items():
        mean = "n/a" if summary["mean"] is None else f"{summary['mean']:.4f}"
        lines.append(
            f"| {metric} | {mean} | {summary['scored_count']} | "
            f"{summary['total_count']} |"
        )
    if report["aggregates"].get("by_variant_kind"):
        lines.extend(
            [
                "",
                "## Scores by phrasing variant",
                "",
                "| Variant | Metric | Mean | Scored |",
                "|---|---|---:|---:|",
            ]
        )
        for variant, metrics in report["aggregates"][
            "by_variant_kind"
        ].items():
            for metric, summary in metrics.items():
                mean = (
                    "n/a"
                    if summary["mean"] is None
                    else f"{summary['mean']:.4f}"
                )
                lines.append(
                    f"| {variant} | {metric} | {mean} | "
                    f"{summary['scored_count']}/{summary['total_count']} |"
                )
    if report["aggregates"].get("by_case_polarity"):
        lines.extend(
            [
                "",
                "## Scores by case polarity",
                "",
                "Negative cases assert that no qualifying relationship is recorded in "
                "the pinned graph snapshot; they are reported separately because that "
                "absence is not equivalent to a positive evidence statement.",
                "",
                "| Polarity | Metric | Mean | Scored |",
                "|---|---|---:|---:|",
            ]
        )
        for polarity, metrics in report["aggregates"][
            "by_case_polarity"
        ].items():
            for metric, summary in metrics.items():
                mean = (
                    "n/a"
                    if summary["mean"] is None
                    else f"{summary['mean']:.4f}"
                )
                lines.append(
                    f"| {polarity} | {metric} | {mean} | "
                    f"{summary['scored_count']}/{summary['total_count']} |"
                )
    lines.extend(
        [
            "",
            "## Scores by relationship type",
            "",
            "| Relationship | Metric | Mean | Scored |",
            "|---|---|---:|---:|",
        ]
    )
    for relationship, metrics in report["aggregates"][
        "by_relationship_type"
    ].items():
        for metric, summary in metrics.items():
            mean = (
                "n/a"
                if summary["mean"] is None
                else f"{summary['mean']:.4f}"
            )
            lines.append(
                f"| {relationship} | {metric} | {mean} | "
                f"{summary['scored_count']}/{summary['total_count']} |"
            )
    lines.extend(
        [
            "",
            "## Per-case raw scores",
            "",
            "| Relationship | Variant | Case | Method | Faithfulness | Context precision | Context recall | Sources |",
            "|---|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in report["rows"]:
        def value(name: str) -> str:
            score = row["scores"].get(name)
            return "n/a" if score is None or math.isnan(float(score)) else f"{float(score):.4f}"

        lines.append(
            f"| {row['relationship_type']} | {row.get('variant_kind', 'n/a')} | "
            f"{row['case_id']} | {row.get('evaluation_method', 'local_ragas_v0.4.3')} | "
            f"{value('faithfulness')} | {value('context_precision')} | "
            f"{value('context_recall')} | {len(row['sources'])} |"
        )
    lines.extend(
        [
            "",
            "Contexts come directly from `PipelineResult.retrieved_contexts`, using the "
            "same `generation.generate.format_context()` field serialization as the "
            "production answer path, one context document per retrieved node.",
            "",
        ]
    )
    return "\n".join(lines)


def _maybe_load_langfuse_env() -> None:
    """Fill LANGFUSE_* from backend/.env when not already exported, so the eval
    can push traces without extra shell setup. Never overrides a set value."""
    env_path = REPO_ROOT / "backend" / ".env"
    if not env_path.exists():
        return
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key.startswith("LANGFUSE_") and key not in os.environ:
                os.environ[key] = value.strip()
    except Exception:
        pass


def emit_ragas_traces_to_langfuse(scored_rows: list[dict[str, Any]]) -> None:
    """Optionally mirror each scored eval case into Langfuse: one trace per
    case carrying the question/answer/reference plus the three RAGAS scores,
    so results are filterable by relationship_type/variant_kind in the
    dashboard.

    Gated by LANGFUSE_ENABLED and fully fail-open - any error here can never
    affect the evaluation or its report. Langfuse listens on localhost, so this
    stays within the loopback-only network policy this tool enforces.
    """
    _maybe_load_langfuse_env()
    if os.getenv("LANGFUSE_ENABLED", "false").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    try:
        from langfuse import get_client

        client = get_client()
    except Exception:
        return
    try:
        for row in scored_rows:
            scores = row.get("scores") or {}
            with client.start_as_current_span(
                name="ragas_eval_case", input=row.get("question")
            ) as span:
                span.update_trace(
                    name="ragas_eval_case",
                    output=row.get("answer"),
                    metadata={
                        "case_id": row.get("case_id"),
                        "relationship_type": row.get("relationship_type"),
                        "variant_kind": row.get("variant_kind"),
                        "reference": row.get("reference"),
                    },
                )
                for metric, value in scores.items():
                    if value is None:
                        continue
                    try:
                        span.score_trace(name=metric, value=float(value))
                    except Exception:
                        pass
        client.flush()
    except Exception:
        pass


def run_evaluation(
    json_report: Path,
    md_report: Path,
    pipeline_raw: Path,
    reuse_pipeline_raw: bool = False,
    *,
    dataset: str = PROTOTYPE_DATASET_NAME,
    pipeline_checkpoint: Path | None = None,
    scoring_checkpoint: Path | None = None,
    scoring_batch_size: int = DEFAULT_SCORING_BATCH_SIZE,
    incomplete_score_retries: int = DEFAULT_INCOMPLETE_SCORE_RETRIES,
    selected_case_ids: list[str] | None = None,
) -> int:
    run_started = time.perf_counter()
    environment = configure_local_only_environment()
    if dataset == PROTOTYPE_DATASET_NAME:
        cases = load_sample_cases()
    elif dataset == FINAL_DATASET_NAME:
        cases = load_final_golden_set_cases()
    else:
        raise EvaluationError(f"unknown dataset: {dataset}")
    if selected_case_ids:
        requested = set(selected_case_ids)
        unknown = requested - {case["case_id"] for case in cases}
        if unknown:
            raise EvaluationError(
                "unknown requested case IDs: " + ", ".join(sorted(unknown))
            )
        cases = [case for case in cases if case["case_id"] in requested]
        if len(cases) != len(requested):
            raise EvaluationError("selected case IDs were not unique")
    if not cases:
        raise EvaluationError("evaluation dataset is empty")
    relationship_counts: dict[str, int] = {}
    for case in cases:
        relationship_counts[case["relationship_type"]] = (
            relationship_counts.get(case["relationship_type"], 0) + 1
        )

    if dataset == FINAL_DATASET_NAME:
        if reuse_pipeline_raw:
            raise EvaluationError(
                "the final dataset resumes automatically from its checkpoint; "
                "--reuse-pipeline-raw is prototype-only"
            )
        pipeline_checkpoint = pipeline_checkpoint or FINAL_PIPELINE_CHECKPOINT
        pipeline_payload = collect_pipeline_rows(
            cases, checkpoint_path=pipeline_checkpoint
        )
    elif reuse_pipeline_raw:
        pipeline_payload = load_reusable_pipeline_rows(cases, pipeline_raw)
    else:
        pipeline_payload = collect_pipeline_rows(cases)
        pipeline_raw.write_text(
            json.dumps(pipeline_payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    rows = pipeline_payload["rows"]
    empty_source_cases = [row["case_id"] for row in rows if not row["sources"]]
    if empty_source_cases and dataset == PROTOTYPE_DATASET_NAME:
        raise EvaluationError(
            "selected prototype queries returned empty sources: "
            + ", ".join(empty_source_cases)
        )
    empty_context_cases = [row["case_id"] for row in rows if not row["contexts"]]
    if empty_context_cases and dataset == PROTOTYPE_DATASET_NAME:
        raise EvaluationError(
            "selected prototype queries returned empty retrieved contexts: "
            + ", ".join(empty_context_cases)
        )

    if dataset == FINAL_DATASET_NAME:
        scoring_checkpoint = (
            scoring_checkpoint or FINAL_SCORING_CHECKPOINT
        )
        ragas_rows = [
            row
            for row in rows
            if case_evaluation_kind(row) == "ragas_open_world"
        ]
        negative_rows = [
            row
            for row in rows
            if case_evaluation_kind(row) == "graph_absence"
        ]
        set_operation_rows = [
            row
            for row in rows
            if case_evaluation_kind(row) == "set_operation"
        ]
        deterministic_negative_rows = build_negative_validation_rows(
            negative_rows
        )
        deterministic_set_operation_rows = (
            build_set_operation_validation_rows(set_operation_rows)
        )
        ragas_scored_rows, local_models, scoring_network_audit = (
            score_with_ragas_checkpointed(
                ragas_rows,
                checkpoint_path=scoring_checkpoint,
                batch_size=scoring_batch_size,
                incomplete_score_retries=incomplete_score_retries,
                legacy_all_rows=rows,
            )
        )
        scored_by_id = {
            row["case_id"]: {
                **row,
                "evaluation_method": "local_ragas_v0.4.3",
                "ragas_metrics_applicable": True,
            }
            for row in ragas_scored_rows
        }
        scored_by_id.update(
            {row["case_id"]: row for row in deterministic_negative_rows}
        )
        scored_by_id.update(
            {
                row["case_id"]: row
                for row in deterministic_set_operation_rows
            }
        )
        scored_rows = [scored_by_id[row["case_id"]] for row in rows]
    else:
        with LoopbackOnlyNetworkAudit() as scoring_audit:
            scored_rows, incomplete, local_models = (
                score_batch_with_incomplete_retries(
                    rows,
                    max_incomplete_retries=incomplete_score_retries,
                )
            )
        scoring_network_audit = scoring_audit.to_dict()
        if incomplete:
            raise EvaluationError(
                "Ragas prototype remains incomplete after targeted retries: "
                + ", ".join(
                    f"{item['case_id']}={item['missing_metrics']}"
                    for item in incomplete
                )
            )
    incomplete_scores = [
        {
            "case_id": row["case_id"],
            "missing_metrics": incomplete_score_metrics(row),
        }
        for row in scored_rows
        if row.get("ragas_metrics_applicable", True)
        and incomplete_score_metrics(row)
    ]
    if incomplete_scores:
        raise EvaluationError(
            "refusing to publish an incomplete Ragas measurement: "
            + ", ".join(
                f"{item['case_id']}={item['missing_metrics']}"
                for item in incomplete_scores
            )
        )
    network_audit = scoring_network_audit
    network_audit["pipeline_worker"] = pipeline_payload["network_audit"]
    if network_audit["blocked_hosts"] or network_audit["openai_host_attempted"]:
        raise EvaluationError(f"non-local scoring network attempt detected: {network_audit}")
    worker_audit = pipeline_payload["network_audit"]
    if worker_audit["blocked_hosts"] or worker_audit["openai_host_attempted"]:
        raise EvaluationError(f"non-local pipeline network attempt detected: {worker_audit}")

    report = {
        "phase": (
            "card6_part_b_final_golden_set_ragas_measurement"
            if dataset == FINAL_DATASET_NAME
            else "card6_part_b_step_8a_ragas_prototype"
        ),
        "measurement_only": True,
        "measurement_complete": True,
        "environment": environment,
        "network_audit": network_audit,
        "local_models": local_models,
        "scoring_configuration": scoring_configuration(),
        "sample": {
            "case_count": len(scored_rows),
            "dataset": dataset,
            "relationship_type_counts": relationship_counts,
            "variant_kind_counts": {
                kind: sum(row.get("variant_kind") == kind for row in scored_rows)
                for kind in ("original", "typo", "reworded")
                if any(row.get("variant_kind") == kind for row in scored_rows)
            },
            "selection_method": (
                "phase_e_complete_156_case_fixed_set"
                if dataset == FINAL_DATASET_NAME and not selected_case_ids
                else (
                    "explicit_case_id_subset_of_phase_e_fixed_set"
                    if dataset == FINAL_DATASET_NAME
                    else "fixed_deliberate_cross_relationship_sample"
                )
            ),
            "ragas_applicable_case_count": sum(
                row.get("ragas_metrics_applicable", True)
                for row in scored_rows
            ),
            "deterministic_negative_case_count": sum(
                case_evaluation_kind(row) == "graph_absence"
                for row in scored_rows
            ),
            "deterministic_set_operation_case_count": sum(
                case_evaluation_kind(row) == "set_operation"
                for row in scored_rows
            ),
        },
        "pipeline_preconditions": {
            "all_allowed": all(row["allowed"] for row in scored_rows),
            "all_sources_non_empty": all(bool(row["sources"]) for row in scored_rows),
            "all_retrieved_contexts_non_empty": all(
                bool(row["contexts"]) for row in scored_rows
            ),
            "context_serialization": CONTEXT_SERIALIZATION,
            "answer_sources": sorted({row["answer_source"] for row in scored_rows}),
            "empty_source_case_ids": empty_source_cases,
            "empty_context_case_ids": empty_context_cases,
        },
        "checkpointing": (
            {
                "pipeline_checkpoint": str(pipeline_checkpoint),
                "scoring_checkpoint": str(scoring_checkpoint),
                "pipeline": {
                    key: pipeline_payload.get(key)
                    for key in (
                        "checkpoint_schema",
                        "status",
                        "completed_count",
                        "remaining_count",
                        "elapsed_seconds",
                    )
                },
                "scoring": {
                    key: json.loads(
                        scoring_checkpoint.read_text(encoding="utf-8")
                    ).get(key)
                    for key in (
                        "checkpoint_schema",
                        "status",
                        "completed_count",
                        "remaining_count",
                        "elapsed_seconds",
                        "batch_size",
                        "incomplete_score_retries",
                    )
                },
                "checkpointed_elapsed_seconds_total": (
                    float(pipeline_payload.get("elapsed_seconds", 0.0))
                    + float(
                        json.loads(
                            scoring_checkpoint.read_text(encoding="utf-8")
                        ).get("elapsed_seconds", 0.0)
                    )
                ),
            }
            if dataset == FINAL_DATASET_NAME
            else None
        ),
        "wall_clock_seconds_this_invocation": time.perf_counter() - run_started,
        "negative_case_validation": {
            "method": NEGATIVE_VALIDATION_METHOD,
            "case_count": sum(
                case_evaluation_kind(row) == "graph_absence"
                for row in scored_rows
            ),
            "passed_count": sum(
                bool((row.get("deterministic_validation") or {}).get("passed"))
                for row in scored_rows
                if case_evaluation_kind(row) == "graph_absence"
            ),
            "failed_case_ids": [
                row["case_id"]
                for row in scored_rows
                if case_evaluation_kind(row) == "graph_absence"
                and not (row.get("deterministic_validation") or {}).get("passed")
            ],
            "rationale": (
                "Graph-absence claims are verified from pinned structured golden "
                "facts and production-answer polarity/entities. Ragas context "
                "metrics are not applied because positive retrieved node text "
                "does not encode exhaustive graph non-edges."
            ),
        },
        "set_operation_validation": {
            "method": SET_OPERATION_VALIDATION_METHOD,
            "case_count": sum(
                case_evaluation_kind(row) == "set_operation"
                for row in scored_rows
            ),
            "passed_count": sum(
                bool((row.get("deterministic_validation") or {}).get("passed"))
                for row in scored_rows
                if case_evaluation_kind(row) == "set_operation"
            ),
            "failed_case_ids": [
                row["case_id"]
                for row in scored_rows
                if case_evaluation_kind(row) == "set_operation"
                and not (row.get("deterministic_validation") or {}).get("passed")
            ],
            "rationale": (
                "Closed-world set-difference claims are verified by exact set "
                "algebra over both complete pinned operands and their retrieved "
                "relationship sections. Generic Ragas textual entailment is not "
                "applied because it cannot establish absence from a closed set."
            ),
        },
        "aggregates": derive_aggregates(scored_rows),
        "rows": scored_rows,
    }
    json_report.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    md_report.write_text(render_markdown(report), encoding="utf-8")
    # Optional, fail-open: mirror scored cases into Langfuse for dashboard
    # analysis. No-op unless LANGFUSE_ENABLED; never affects the report above.
    emit_ragas_traces_to_langfuse(scored_rows)
    if dataset == FINAL_DATASET_NAME:
        print(
            json.dumps(
                {
                    "json_report": str(json_report),
                    "md_report": str(md_report),
                    "case_count": len(scored_rows),
                    "network_audit": network_audit,
                    "checkpointing": report["checkpointing"],
                    "aggregates": report["aggregates"],
                },
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
        )
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        choices=(PROTOTYPE_DATASET_NAME, FINAL_DATASET_NAME),
        default=PROTOTYPE_DATASET_NAME,
    )
    parser.add_argument("--json-report", type=Path)
    parser.add_argument("--md-report", type=Path)
    parser.add_argument("--pipeline-raw", type=Path)
    parser.add_argument("--pipeline-checkpoint", type=Path)
    parser.add_argument("--scoring-checkpoint", type=Path)
    parser.add_argument(
        "--scoring-batch-size",
        type=int,
        default=DEFAULT_SCORING_BATCH_SIZE,
    )
    parser.add_argument(
        "--incomplete-score-retries",
        type=int,
        default=DEFAULT_INCOMPLETE_SCORE_RETRIES,
        help=(
            "retry only cases whose Ragas metric vector is incomplete; "
            "rows are never checkpointed until all metrics are numeric"
        ),
    )
    parser.add_argument(
        "--case-id",
        action="append",
        dest="case_ids",
        help="evaluate only an exact case ID; repeat for a deliberate smoke subset",
    )
    parser.add_argument(
        "--reuse-pipeline-raw",
        action="store_true",
        help="reuse only an exact, network-clean raw artifact from the fixed sample",
    )
    parser.add_argument(
        "--pipeline-worker",
        nargs=2,
        metavar=("INPUT_JSON", "OUTPUT_JSON"),
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.pipeline_worker:
        return run_pipeline_worker(Path(args.pipeline_worker[0]), Path(args.pipeline_worker[1]))
    final_dataset = args.dataset == FINAL_DATASET_NAME
    json_report = args.json_report or (
        FINAL_JSON_REPORT if final_dataset else DEFAULT_JSON_REPORT
    )
    md_report = args.md_report or (
        FINAL_MD_REPORT if final_dataset else DEFAULT_MD_REPORT
    )
    pipeline_raw = args.pipeline_raw or DEFAULT_PIPELINE_RAW
    return run_evaluation(
        json_report,
        md_report,
        pipeline_raw,
        reuse_pipeline_raw=args.reuse_pipeline_raw,
        dataset=args.dataset,
        pipeline_checkpoint=args.pipeline_checkpoint,
        scoring_checkpoint=args.scoring_checkpoint,
        scoring_batch_size=args.scoring_batch_size,
        incomplete_score_retries=args.incomplete_score_retries,
        selected_case_ids=args.case_ids,
    )


if __name__ == "__main__":
    raise SystemExit(main())
