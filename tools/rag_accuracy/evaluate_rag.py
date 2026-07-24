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
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


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
CONTEXT_SERIALIZATION = "pipeline_format_context_per_retrieved_node_v1"
PIPELINE_CHECKPOINT_SCHEMA = "rag_accuracy_pipeline_checkpoint_v1"
SCORING_CHECKPOINT_SCHEMA = "rag_accuracy_scoring_checkpoint_v1"
FINAL_DATASET_NAME = "final_golden_set"
PROTOTYPE_DATASET_NAME = "prototype"
DEFAULT_SCORING_BATCH_SIZE = 5

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


def scoring_input_fingerprint(rows: list[dict[str, Any]]) -> str:
    encoded = json.dumps(
        [
            {
                **case_identity(row),
                "answer": row.get("answer"),
                "contexts": row.get("contexts"),
            }
            for row in rows
        ],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
        atomic_write_json(output_path, payload)

    current_audit: dict[str, Any] = {}
    try:
        with LoopbackOnlyNetworkAudit() as audit:
            try:
                for index, case in enumerate(cases, start=1):
                    if case["case_id"] in rows_by_id:
                        continue
                    result = run_pipeline(
                        case["question"], include_contexts=True
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
            format="json",
            num_ctx=8192,
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
    metrics = [
        Faithfulness(llm=judge),
        LLMContextPrecisionWithReference(llm=judge),
        LLMContextRecall(llm=judge),
    ]
    result = evaluate(
        dataset=EvaluationDataset(samples=samples),
        metrics=metrics,
        llm=judge,
        embeddings=embeddings,
        run_config=RunConfig(
            timeout=240,
            max_retries=1,
            max_wait=10,
            max_workers=1,
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
    for metric in ("faithfulness", "context_precision", "context_recall"):
        value = scores.get(metric)
        if value is not None and (
            not isinstance(value, (int, float)) or math.isnan(float(value))
        ):
            return False
    return (
        case_identity(row) == case_identity(expected_pipeline_row)
        and row.get("answer") == expected_pipeline_row.get("answer")
        and row.get("contexts") == expected_pipeline_row.get("contexts")
    )


def _load_scoring_checkpoint(
    path: Path, rows: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("checkpoint_schema") != SCORING_CHECKPOINT_SCHEMA:
        raise EvaluationError(
            f"scoring checkpoint uses an unknown schema: {path}"
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
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if batch_size < 1:
        raise EvaluationError("scoring batch size must be at least one")
    existing = _load_scoring_checkpoint(checkpoint_path, rows)
    scored_by_id = {
        row["case_id"]: row for row in (existing or {}).get("rows", [])
    }
    previous_audit = (existing or {}).get("network_audit", {})
    previous_elapsed = float((existing or {}).get("elapsed_seconds", 0.0))
    started_at = (existing or {}).get("started_at") or utc_now()
    local_models = (existing or {}).get("local_models")
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
            "case_count": len(rows),
            "completed_count": len(ordered_rows),
            "remaining_count": len(rows) - len(ordered_rows),
            "local_models": local_models,
            "last_error": last_error,
            "rows": ordered_rows,
        }
        atomic_write_json(checkpoint_path, payload)

    if not pending:
        if not isinstance(local_models, dict):
            raise EvaluationError(
                "complete scoring checkpoint lacks local-model provenance"
            )
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
                    batch_scored, batch_models = score_with_ragas(batch)
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
    metrics = ("faithfulness", "context_precision", "context_recall")
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
    return {
        "overall": overall,
        "by_relationship_type": by_relationship,
        "by_variant_kind": by_variant,
    }


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
        "## Independently derived aggregate scores",
        "",
        "| Metric | Mean | Scored |",
        "|---|---:|---:|",
    ]
    for metric, summary in report["aggregates"]["overall"].items():
        mean = "n/a" if summary["mean"] is None else f"{summary['mean']:.4f}"
        lines.append(f"| {metric} | {mean} | {summary['scored_count']}/{summary['total_count']} |")
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
            "| Relationship | Variant | Case | Faithfulness | Context precision | Context recall | Sources |",
            "|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in report["rows"]:
        def value(name: str) -> str:
            score = row["scores"].get(name)
            return "n/a" if score is None or math.isnan(float(score)) else f"{float(score):.4f}"

        lines.append(
            f"| {row['relationship_type']} | {row.get('variant_kind', 'n/a')} | "
            f"{row['case_id']} | "
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
        scored_rows, local_models, scoring_network_audit = (
            score_with_ragas_checkpointed(
                rows,
                checkpoint_path=scoring_checkpoint,
                batch_size=scoring_batch_size,
            )
        )
    else:
        with LoopbackOnlyNetworkAudit() as scoring_audit:
            scored_rows, local_models = score_with_ragas(rows)
        scoring_network_audit = scoring_audit.to_dict()
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
        "environment": environment,
        "network_audit": network_audit,
        "local_models": local_models,
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
        selected_case_ids=args.case_ids,
    )


if __name__ == "__main__":
    raise SystemExit(main())
