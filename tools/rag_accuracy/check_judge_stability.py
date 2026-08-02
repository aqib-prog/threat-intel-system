#!/usr/bin/env python3
"""Measure repeatability of the pinned local Ragas judge on a small sample.

This is deliberately separate from the full 156-case measurement. It reuses a
completed, network-clean pipeline checkpoint, scores the same fixed rows several
times with the seeded local judge, checkpoints after every repeat, and fails if
any metric is missing or changes between repeats.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import evaluate_rag as evaluator  # noqa: E402


SCHEMA_VERSION = "ragas_judge_stability_v1"
DEFAULT_CASE_IDS = (
    # Compact positive relationship.
    "enterprise-mitigations-t1001::original",
    # Explicit graph-absence case.
    "group-has-no-qualifying-techniques-g0017::original",
    # Long multi-hop answer that timed out in the first full run.
    "campaign-software-techniques-c0001-s0363::original",
)
DEFAULT_REPEATS = 3
DEFAULT_TOLERANCE = 1e-12


def select_probe_rows(
    pipeline_checkpoint: Path,
    case_ids: list[str],
) -> list[dict[str, Any]]:
    cases = evaluator.load_final_golden_set_cases()
    payload = evaluator._load_pipeline_checkpoint(pipeline_checkpoint, cases)
    if payload is None or payload.get("status") != "complete":
        raise evaluator.EvaluationError(
            "judge stability requires a complete pipeline checkpoint"
        )
    rows_by_id = {row["case_id"]: row for row in payload["rows"]}
    unknown = [case_id for case_id in case_ids if case_id not in rows_by_id]
    if unknown:
        raise evaluator.EvaluationError(
            "pipeline checkpoint lacks requested stability cases: "
            + ", ".join(unknown)
        )
    if len(set(case_ids)) != len(case_ids):
        raise evaluator.EvaluationError("stability case IDs must be unique")
    return [rows_by_id[case_id] for case_id in case_ids]


def score_vector(row: dict[str, Any]) -> dict[str, float]:
    missing = evaluator.incomplete_score_metrics(row)
    if missing:
        raise evaluator.EvaluationError(
            f"incomplete stability score for {row.get('case_id')}: {missing}"
        )
    return {
        metric: float(row["scores"][metric])
        for metric in evaluator.REQUIRED_SCORE_METRICS
    }


def derive_stability(
    runs: list[list[dict[str, Any]]],
    *,
    tolerance: float,
) -> dict[str, Any]:
    if tolerance < 0:
        raise evaluator.EvaluationError("stability tolerance cannot be negative")
    if not runs:
        raise evaluator.EvaluationError("stability probe has no completed runs")
    case_order = [row["case_id"] for row in runs[0]]
    for run in runs:
        if [row.get("case_id") for row in run] != case_order:
            raise evaluator.EvaluationError(
                "stability runs do not contain the same ordered cases"
            )

    cases: dict[str, Any] = {}
    all_stable = True
    for index, case_id in enumerate(case_order):
        vectors = [score_vector(run[index]) for run in runs]
        ranges = {
            metric: max(vector[metric] for vector in vectors)
            - min(vector[metric] for vector in vectors)
            for metric in evaluator.REQUIRED_SCORE_METRICS
        }
        stable = all(value <= tolerance for value in ranges.values())
        all_stable = all_stable and stable
        cases[case_id] = {
            "stable": stable,
            "score_ranges": ranges,
            "scores_by_repeat": vectors,
        }
    return {
        "stable": all_stable,
        "tolerance": tolerance,
        "case_count": len(case_order),
        "repeat_count": len(runs),
        "cases": cases,
    }


def load_checkpoint(
    path: Path,
    *,
    input_fingerprint: str,
    repeats: int,
    tolerance: float,
    rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version": SCHEMA_VERSION,
        "input_fingerprint": input_fingerprint,
        "scoring_configuration": evaluator.scoring_configuration(),
        "requested_repeats": repeats,
        "tolerance": tolerance,
    }
    for field, value in expected.items():
        if payload.get(field) != value:
            raise evaluator.EvaluationError(
                f"stability checkpoint differs on {field}: {path}"
            )
    completed_runs = payload.get("runs")
    if not isinstance(completed_runs, list) or len(completed_runs) > repeats:
        raise evaluator.EvaluationError("stability checkpoint runs are malformed")
    for run in completed_runs:
        if not isinstance(run, list) or len(run) != len(rows):
            raise evaluator.EvaluationError("stability checkpoint run is malformed")
        for scored, expected_row in zip(run, rows, strict=True):
            if not evaluator.valid_scored_row(scored, expected_row):
                raise evaluator.EvaluationError(
                    "stability checkpoint contains an incomplete or stale score"
                )
    audit = payload.get("network_audit", {})
    if audit.get("blocked_hosts") or audit.get("openai_host_attempted"):
        raise evaluator.EvaluationError(
            "stability checkpoint failed its local-only network audit"
        )
    return payload


def run_probe(
    *,
    pipeline_checkpoint: Path,
    report_path: Path,
    case_ids: list[str],
    repeats: int,
    tolerance: float,
    incomplete_score_retries: int,
) -> int:
    if repeats < 2:
        raise evaluator.EvaluationError("stability probe requires at least 2 repeats")
    environment = evaluator.configure_local_only_environment()
    rows = select_probe_rows(pipeline_checkpoint, case_ids)
    input_fingerprint = evaluator.scoring_input_fingerprint(rows)
    existing = load_checkpoint(
        report_path,
        input_fingerprint=input_fingerprint,
        repeats=repeats,
        tolerance=tolerance,
        rows=rows,
    )
    runs = list((existing or {}).get("runs", []))
    network_audit = (existing or {}).get("network_audit", {})
    local_models = (existing or {}).get("local_models")
    started_at = (existing or {}).get("started_at") or evaluator.utc_now()
    prior_elapsed = float((existing or {}).get("elapsed_seconds", 0.0))
    invocation_started = time.perf_counter()

    def checkpoint(status: str, last_error: dict[str, Any] | None = None) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": status,
            "measurement_only": True,
            "environment": environment,
            "pipeline_checkpoint": str(pipeline_checkpoint),
            "input_fingerprint": input_fingerprint,
            "scoring_configuration": evaluator.scoring_configuration(),
            "requested_repeats": repeats,
            "completed_repeats": len(runs),
            "remaining_repeats": repeats - len(runs),
            "tolerance": tolerance,
            "case_ids": case_ids,
            "network_audit": network_audit,
            "local_models": local_models,
            "started_at": started_at,
            "updated_at": evaluator.utc_now(),
            "elapsed_seconds": prior_elapsed
            + (time.perf_counter() - invocation_started),
            "last_error": last_error,
            "runs": runs,
        }
        if len(runs) == repeats:
            payload["stability"] = derive_stability(runs, tolerance=tolerance)
        evaluator.atomic_write_json(report_path, payload)

    try:
        while len(runs) < repeats:
            current_audit: dict[str, Any] = {}
            try:
                with evaluator.LoopbackOnlyNetworkAudit() as audit:
                    try:
                        scored, incomplete, models = (
                            evaluator.score_batch_with_incomplete_retries(
                                rows,
                                max_incomplete_retries=incomplete_score_retries,
                            )
                        )
                    finally:
                        current_audit = audit.to_dict()
            finally:
                network_audit = evaluator.merge_network_audits(
                    network_audit, current_audit
                )
            if incomplete:
                raise evaluator.EvaluationError(
                    "stability repeat remains incomplete: " + repr(incomplete)
                )
            if local_models is not None and local_models != models:
                raise evaluator.EvaluationError(
                    "local model provenance changed between stability repeats"
                )
            local_models = models
            runs.append(scored)
            checkpoint("in_progress")
            print(
                f"judge stability repeat {len(runs)}/{repeats} complete",
                flush=True,
            )
    except BaseException as exc:
        checkpoint(
            "failed",
            {"type": type(exc).__name__, "message": str(exc)},
        )
        raise

    stability = derive_stability(runs, tolerance=tolerance)
    checkpoint("complete" if stability["stable"] else "unstable")
    print(json.dumps(stability, indent=2, ensure_ascii=False))
    print(f"JSON report: {report_path}")
    return 0 if stability["stable"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pipeline-checkpoint", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    parser.add_argument(
        "--incomplete-score-retries",
        type=int,
        default=evaluator.DEFAULT_INCOMPLETE_SCORE_RETRIES,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return run_probe(
        pipeline_checkpoint=args.pipeline_checkpoint,
        report_path=args.report,
        case_ids=args.case_ids or list(DEFAULT_CASE_IDS),
        repeats=args.repeats,
        tolerance=args.tolerance,
        incomplete_score_retries=args.incomplete_score_retries,
    )


if __name__ == "__main__":
    raise SystemExit(main())
