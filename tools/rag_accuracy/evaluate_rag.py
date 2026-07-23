#!/usr/bin/env python3
"""Run the Step-8a local-only Ragas prototype.

The production pipeline and the Ragas scorer intentionally run in separate
interpreters. The production backend venv keeps its existing dependency set;
the scorer uses the pinned, isolated environment from ``requirements.txt``.
Both processes enforce a loopback-only socket policy during evaluation.
"""

from __future__ import annotations

import argparse
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
from typing import Any


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
BACKEND_PYTHON = REPO_ROOT / "backend" / "venv" / "bin" / "python"
DEFAULT_JSON_REPORT = HERE / "rag_accuracy_report.json"
DEFAULT_MD_REPORT = HERE / "rag_accuracy_report.md"
DEFAULT_PIPELINE_RAW = HERE / "rag_pipeline_prototype_raw.json"
JUDGE_MODEL = "llama3.1:latest"
EMBEDDING_MODEL = "nomic-embed-text:latest"
OLLAMA_BASE_URL = "http://127.0.0.1:11434"
CONTEXT_SERIALIZATION = "pipeline_format_context_per_retrieved_node_v1"

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


def run_pipeline_worker(input_path: Path, output_path: Path) -> int:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / "backend" / ".env", override=False)
    environment = configure_local_only_environment()
    sys.path.insert(0, str(REPO_ROOT / "backend"))
    from orchestration.pipeline import run_pipeline

    cases = json.loads(input_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    with LoopbackOnlyNetworkAudit() as audit:
        for case in cases:
            result = run_pipeline(case["question"], include_contexts=True)
            result_dict = result.to_dict()
            rows.append(
                {
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
            )
    payload = {
        "context_serialization": CONTEXT_SERIALIZATION,
        "environment": environment,
        "network_audit": audit.to_dict(),
        "rows": rows,
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


def collect_pipeline_rows(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not BACKEND_PYTHON.exists():
        raise EvaluationError(f"backend interpreter not found: {BACKEND_PYTHON}")
    with tempfile.TemporaryDirectory(prefix="rag-accuracy-") as temp_dir:
        input_path = Path(temp_dir) / "cases.json"
        output_path = Path(temp_dir) / "pipeline.json"
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
    return {"overall": overall, "by_relationship_type": by_relationship}


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# RAG Accuracy — Step 8a local Ragas prototype",
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
    lines.extend(
        [
            "",
            "## Per-case raw scores",
            "",
            "| Relationship | Case | Faithfulness | Context precision | Context recall | Sources |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in report["rows"]:
        def value(name: str) -> str:
            score = row["scores"].get(name)
            return "n/a" if score is None or math.isnan(float(score)) else f"{float(score):.4f}"

        lines.append(
            f"| {row['relationship_type']} | {row['case_id']} | "
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


def run_evaluation(
    json_report: Path,
    md_report: Path,
    pipeline_raw: Path,
    reuse_pipeline_raw: bool = False,
) -> int:
    environment = configure_local_only_environment()
    cases = load_sample_cases()
    relationship_counts: dict[str, int] = {}
    for case in cases:
        relationship_counts[case["relationship_type"]] = (
            relationship_counts.get(case["relationship_type"], 0) + 1
        )

    if reuse_pipeline_raw:
        pipeline_payload = load_reusable_pipeline_rows(cases, pipeline_raw)
    else:
        pipeline_payload = collect_pipeline_rows(cases)
        pipeline_raw.write_text(
            json.dumps(pipeline_payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    rows = pipeline_payload["rows"]
    empty_source_cases = [row["case_id"] for row in rows if not row["sources"]]
    if empty_source_cases:
        raise EvaluationError(
            "selected prototype queries returned empty sources: "
            + ", ".join(empty_source_cases)
        )
    empty_context_cases = [row["case_id"] for row in rows if not row["contexts"]]
    if empty_context_cases:
        raise EvaluationError(
            "selected prototype queries returned empty retrieved contexts: "
            + ", ".join(empty_context_cases)
        )

    with LoopbackOnlyNetworkAudit() as scoring_audit:
        scored_rows, local_models = score_with_ragas(rows)
    network_audit = scoring_audit.to_dict()
    network_audit["pipeline_worker"] = pipeline_payload["network_audit"]
    if network_audit["blocked_hosts"] or network_audit["openai_host_attempted"]:
        raise EvaluationError(f"non-local scoring network attempt detected: {network_audit}")
    worker_audit = pipeline_payload["network_audit"]
    if worker_audit["blocked_hosts"] or worker_audit["openai_host_attempted"]:
        raise EvaluationError(f"non-local pipeline network attempt detected: {worker_audit}")

    report = {
        "phase": "card6_part_b_step_8a_ragas_prototype",
        "measurement_only": True,
        "environment": environment,
        "network_audit": network_audit,
        "local_models": local_models,
        "sample": {
            "case_count": len(scored_rows),
            "relationship_type_counts": relationship_counts,
            "selection_method": "fixed_deliberate_cross_relationship_sample",
        },
        "pipeline_preconditions": {
            "all_allowed": all(row["allowed"] for row in scored_rows),
            "all_sources_non_empty": all(bool(row["sources"]) for row in scored_rows),
            "all_retrieved_contexts_non_empty": all(
                bool(row["contexts"]) for row in scored_rows
            ),
            "context_serialization": CONTEXT_SERIALIZATION,
            "answer_sources": sorted({row["answer_source"] for row in scored_rows}),
        },
        "aggregates": derive_aggregates(scored_rows),
        "rows": scored_rows,
    }
    json_report.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    md_report.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-report", type=Path, default=DEFAULT_JSON_REPORT)
    parser.add_argument("--md-report", type=Path, default=DEFAULT_MD_REPORT)
    parser.add_argument("--pipeline-raw", type=Path, default=DEFAULT_PIPELINE_RAW)
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
    return run_evaluation(
        args.json_report,
        args.md_report,
        args.pipeline_raw,
        reuse_pipeline_raw=args.reuse_pipeline_raw,
    )


if __name__ == "__main__":
    raise SystemExit(main())
