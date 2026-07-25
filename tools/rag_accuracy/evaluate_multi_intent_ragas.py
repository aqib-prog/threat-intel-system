#!/usr/bin/env python3
"""RAGAS scoring for the multi-intent path (end-to-end through run_multi_pipeline).

This proves that when a turn bundles several questions, EACH answered segment is
as faithful/grounded as the single-intent path - by scoring every routed segment
against its golden ``expected_answer`` (sourced from final_golden_set.json).

It reuses the exact scorer the single-intent run uses (``score_with_ragas`` in
evaluate_rag.py: local llama3.1 judge + nomic-embed-text, loopback only) so the
numbers are directly comparable. Like evaluate_rag.py it runs in two
interpreters, because the two dependency sets are deliberately separate:

  * collection  -> backend venv (Neo4j + Ollama; runs run_multi_pipeline)
  * scoring     -> .ragas_venv  (ragas 0.4.3; runs score_with_ragas)

The scenarios come from ``golden_set_multi_intent.json``. Noise-only and
raw-log scenarios are not scored (they have no golden answer to score against);
their correctness is covered by the deterministic test_multi_intent_golden.py.

Row mapping: each routed segment's answer is paired with the golden reference of
the sub-question it answered (matched by normalized question text). A single-
fallback scenario (0/1 routed) with exactly one golden question yields one row
from the single combined answer.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from statistics import mean
from typing import Any

HERE = Path(__file__).resolve().parent
SCENARIOS_PATH = HERE / "golden_set_multi_intent.json"
JSON_REPORT = HERE / "multi_intent_ragas_report.json"
MD_REPORT = HERE / "multi_intent_ragas_report.md"
ROWS_CHECKPOINT = HERE / "multi_intent_pipeline_rows.json"

# Imported lazily/topline from the sibling evaluator so both runs use identical
# scoring, provenance, and paths. Safe to import in either interpreter (its
# heavy deps are imported inside the functions, not at module load).
from evaluate_rag import (  # noqa: E402
    BACKEND_PYTHON,
    FINAL_GOLDEN_SET,
    REPO_ROOT,
    EvaluationError,
    score_with_ragas,
)

_METRICS = ("faithfulness", "context_precision", "context_recall")


def _normalize(text: str) -> str:
    return re.sub(r"[\s]+", " ", str(text or "")).strip().casefold().rstrip("?.!;:")


def _golden_index() -> dict[str, dict[str, Any]]:
    entries = json.loads(FINAL_GOLDEN_SET.read_text())["entries"]
    return {
        e["id"]: {
            "question": e["question"],
            "reference": e["expected_answer"],
            "relationship_type": e.get("relationship_type"),
            "variant_kind": e.get("variant_kind"),
        }
        for e in entries
    }


# --------------------------------------------------------------------------
# Process A: collection (backend venv) - runs the real multi-intent pipeline.
# --------------------------------------------------------------------------
def collect_rows_worker(scenarios_path: Path, out_path: Path) -> int:
    from dotenv import load_dotenv

    # Same local-only posture as evaluate_rag's worker: no stray stage traces,
    # backend/.env respected, loopback-only models.
    os.environ["LANGFUSE_ENABLED"] = "false"
    load_dotenv(REPO_ROOT / "backend" / ".env", override=False)
    from evaluate_rag import configure_local_only_environment  # noqa: E402

    configure_local_only_environment()
    sys.path.insert(0, str(REPO_ROOT / "backend"))
    from orchestration.multi_intent import run_multi_pipeline  # noqa: E402

    scenarios = json.loads(scenarios_path.read_text())["scenarios"]
    golden = _golden_index()
    rows: list[dict[str, Any]] = []

    for sc in scenarios:
        if sc.get("raw_log"):
            continue  # log answers are not in the golden set - not RAGAS-scored
        golden_segs = [s for s in sc["segments"] if s.get("golden_id")]
        if not golden_segs:
            continue  # all-noise / all-off-topic / empty: nothing to score
        # normalized golden question text -> golden_id (to map answers back)
        by_text = {_normalize(s["text"]): s["golden_id"] for s in golden_segs}

        result = run_multi_pipeline(sc["input"], include_contexts=True)

        def _row(golden_id: str, answer: str, contexts: list[str], path: str) -> dict[str, Any]:
            g = golden[golden_id]
            return {
                "case_id": f"{sc['id']}::{golden_id}",
                "scenario_id": sc["id"],
                "category": sc["category"],
                "golden_id": golden_id,
                "relationship_type": g["relationship_type"],
                "variant_kind": g["variant_kind"],
                "path": path,
                "question": g["question"],
                "reference": g["reference"],
                "answer": answer,
                "contexts": list(contexts),
            }

        if result.segments:  # multi-segment turn -> one row per matched segment
            for seg in result.segments:
                gid = by_text.get(_normalize(seg.query))
                if gid:
                    rows.append(_row(gid, seg.answer, seg.retrieved_contexts, "multi_segment"))
        elif len(golden_segs) == 1:  # single-fallback -> the one combined answer
            gid = golden_segs[0]["golden_id"]
            rows.append(_row(gid, result.answer, result.retrieved_contexts, "single_fallback"))

        print(f"collected {sc['id']}: rows so far={len(rows)}", flush=True)

    out_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
    print(f"wrote {len(rows)} rows to {out_path}", flush=True)
    return 0


def _run_collection(limit: int | None) -> list[dict[str, Any]]:
    if not BACKEND_PYTHON.exists():
        raise EvaluationError(f"backend interpreter not found: {BACKEND_PYTHON}")
    with tempfile.TemporaryDirectory(prefix="multi-intent-ragas-") as tmp:
        out_path = Path(tmp) / "rows.json"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT / "backend")
        proc = subprocess.run(
            [str(BACKEND_PYTHON), str(Path(__file__).resolve()),
             "--collect-worker", str(SCENARIOS_PATH), str(out_path)],
            cwd=REPO_ROOT, env=env, text=True,
        )
        if proc.returncode != 0:
            raise EvaluationError("multi-intent collection worker failed")
        rows = json.loads(out_path.read_text())
    ROWS_CHECKPOINT.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
    return rows[:limit] if limit else rows


# --------------------------------------------------------------------------
# Aggregation + report.
# --------------------------------------------------------------------------
def _mean(values: list[Any]) -> float | None:
    nums = [float(v) for v in values if isinstance(v, (int, float))]
    return round(mean(nums), 4) if nums else None


def _group_means(scored: list[dict[str, Any]], key: str) -> dict[str, dict[str, float | None]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in scored:
        groups.setdefault(str(row.get(key)), []).append(row)
    return {
        name: {m: _mean([r["scores"].get(m) for r in rows]) for m in _METRICS}
        for name, rows in sorted(groups.items())
    }


def _build_report(scored: list[dict[str, Any]], judge_meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "purpose": "Per-segment RAGAS scores for the multi-intent path.",
        "scenarios_source": SCENARIOS_PATH.name,
        "golden_source": FINAL_GOLDEN_SET.name,
        "judge_meta": judge_meta,
        "row_count": len(scored),
        "overall": {m: _mean([r["scores"].get(m) for r in scored]) for m in _METRICS},
        "by_path": _group_means(scored, "path"),
        "by_relationship_type": _group_means(scored, "relationship_type"),
        "by_variant_kind": _group_means(scored, "variant_kind"),
        "rows": scored,
    }


def _write_md(report: dict[str, Any]) -> None:
    o = report["overall"]
    lines = [
        "# Multi-intent RAGAS report",
        "",
        f"- rows scored: **{report['row_count']}**",
        f"- judge: `{report['judge_meta'].get('judge')}` · embeddings: "
        f"`{report['judge_meta'].get('embeddings')}`",
        "",
        "## Overall",
        "",
        "| metric | mean |",
        "|---|---|",
        *[f"| {m} | {o[m]} |" for m in _METRICS],
        "",
        "## By path (multi-segment vs single-fallback)",
        "",
        "| path | faithfulness | context_precision | context_recall |",
        "|---|---|---|---|",
        *[f"| {p} | {v['faithfulness']} | {v['context_precision']} | {v['context_recall']} |"
          for p, v in report["by_path"].items()],
        "",
        "_Note: the local llama3.1 judge is known to under-score faithfulness on "
        "provably-correct answers; compare against the single-intent baseline "
        "rather than reading absolute values._",
        "",
    ]
    MD_REPORT.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="RAGAS scoring for the multi-intent path.")
    parser.add_argument("--collect-worker", nargs=2, metavar=("SCENARIOS", "OUT"),
                        help="internal: run the pipeline collection worker (backend venv)")
    parser.add_argument("--limit", type=int, default=None,
                        help="score only the first N rows (smoke test)")
    parser.add_argument("--rows-only", action="store_true",
                        help="collect and print rows without scoring (no ragas needed)")
    args = parser.parse_args()

    if args.collect_worker:
        return collect_rows_worker(Path(args.collect_worker[0]), Path(args.collect_worker[1]))

    rows = _run_collection(args.limit)
    if not rows:
        raise EvaluationError("no scoreable rows were collected")
    if args.rows_only:
        print(f"collected {len(rows)} rows (not scored). checkpoint: {ROWS_CHECKPOINT}")
        return 0

    scored, judge_meta = score_with_ragas(rows)
    report = _build_report(scored, judge_meta)
    from evaluate_rag import atomic_write_json
    atomic_write_json(JSON_REPORT, report)
    _write_md(report)
    print(f"\nscored {len(scored)} rows")
    print(f"overall: {report['overall']}")
    print(f"reports: {JSON_REPORT.name}, {MD_REPORT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
