#!/usr/bin/env python3
"""Card 6 Part A step 2: measure structured output and fail-closed parsing."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import evaluate as baseline  # noqa: E402
import evaluate_step1 as step1  # noqa: E402
from retrieval import guardrail as production  # noqa: E402


def is_default_block(result: dict[str, Any]) -> bool:
    return not bool(result.get("allowed")) and str(result.get("reason", "")).startswith(
        "Could not parse"
    )


def evaluate_case(case: step1.Step1Case) -> dict[str, Any]:
    start = time.perf_counter()
    topic_called = False
    topic_waived = False
    topic_fail_open = False
    topic_default_block = False
    harm_called = False
    harm_fail_open = False
    harm_default_block = False

    blacklist = production.check_blacklist(case.prompt)
    if not blacklist["allowed"]:
        allowed = False
        final_stage = "blacklist"
        decision_category = blacklist.get("category", "blocked")
    else:
        topic_result = production.check_topic_guardrail(case.prompt)
        topic_waived = bool(topic_result.get("waived_by_cybersecurity_signal"))
        topic_called = not topic_waived
        topic_fail_open = topic_called and step1.is_fail_open(topic_result)
        topic_default_block = topic_called and is_default_block(topic_result)
        if not topic_result["allowed"]:
            allowed = False
            final_stage = "topic_gate"
            decision_category = "llm_blocked"
        else:
            harm_called = True
            harm_result = production.check_llm_guardrail(case.prompt)
            harm_fail_open = step1.is_fail_open(harm_result)
            harm_default_block = is_default_block(harm_result)
            allowed = bool(harm_result["allowed"])
            final_stage = "allowed" if allowed else "harm_gate"
            decision_category = None if allowed else "llm_harm_blocked"

    return {
        "cohort": case.cohort,
        "corpus": case.corpus,
        "split": case.split,
        "source_id": case.source_id,
        "category": case.category,
        "prompt_sha256": case.prompt_sha256,
        "allowed": allowed,
        "blocked": not allowed,
        "final_stage": final_stage,
        "decision_category": decision_category,
        "topic_llm_called": topic_called,
        "topic_waived_by_cybersecurity_signal": topic_waived,
        "topic_fail_open": topic_fail_open,
        "topic_default_block": topic_default_block,
        "harm_called": harm_called,
        "harm_fail_open": harm_fail_open,
        "harm_default_block": harm_default_block,
        "elapsed_seconds": time.perf_counter() - start,
    }


def summarize(
    rows: list[dict[str, Any]], previous_fast_allow_keys: set[tuple[str, str, str]]
) -> dict[str, Any]:
    harmful = [row for row in rows if row["cohort"] == "harmful"]
    domain_benign = [row for row in rows if row["cohort"] == "domain_benign"]
    old_fast = [
        row
        for row in rows
        if (row["corpus"], row["split"], row["source_id"])
        in previous_fast_allow_keys
    ]
    return {
        "harmful": step1.totals(harmful),
        "domain_benign": step1.totals(domain_benign),
        "harmful_by_category": step1.by_category(harmful),
        "domain_benign_by_category": step1.by_category(domain_benign),
        "routing": {
            "topic_waived_count": sum(
                row["topic_waived_by_cybersecurity_signal"] for row in rows
            ),
            "topic_llm_call_count": sum(row["topic_llm_called"] for row in rows),
            "topic_fail_open_count": sum(row["topic_fail_open"] for row in rows),
            "topic_default_block_count": sum(
                row["topic_default_block"] for row in rows
            ),
            "harm_call_count": sum(row["harm_called"] for row in rows),
            "harm_fail_open_count": sum(row["harm_fail_open"] for row in rows),
            "harm_default_block_count": sum(
                row["harm_default_block"] for row in rows
            ),
            "previous_fast_allow_total": len(previous_fast_allow_keys),
            "previous_fast_allow_replayed": len(old_fast),
            "previous_fast_allow_harm_checked": sum(row["harm_called"] for row in old_fast),
            "previous_fast_allow_blocked": sum(row["blocked"] for row in old_fast),
        },
        "final_stages": dict(sorted(Counter(row["final_stage"] for row in rows).items())),
        "latency": step1.latency(rows),
    }


def render_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    before = report["comparison_step1"]
    harmful = metrics["harmful"]
    benign = metrics["domain_benign"]
    routing = metrics["routing"]
    return "\n".join(
        [
            "# Card 6 Part A step 2: structured output and fail-closed parsing",
            "",
            f"Status: **MEASURED** ({report['measured_at']})",
            "",
            "The classifier prompt/taxonomy and step-1 routing are unchanged. This",
            "checkpoint changes only Ollama output framing and the parse-failure default.",
            "",
            "## Step 1 / step 2",
            "",
            "| Measure | Step 1 | Step 2 |",
            "| --- | ---: | ---: |",
            f"| Topic fail-open | {before['topic_fail_open_count']} | {routing['topic_fail_open_count']} |",
            f"| Harm-seam fail-open | {before['harm_fail_open_count']} | {routing['harm_fail_open_count']} |",
            f"| Harmful blocked (same 500) | {before['harmful_blocked']}/500 ({before['harmful_block_rate']:.1%}) | {harmful['blocked']}/500 ({harmful['block_rate']:.1%}) |",
            f"| Domain-benign blocked (same 64) | {before['domain_benign_blocked']}/64 ({before['domain_benign_block_rate']:.1%}) | {benign['blocked']}/64 ({benign['block_rate']:.1%}) |",
            "",
            "## Parse reliability",
            "",
            f"- Topic LLM calls: **{routing['topic_llm_call_count']}**; fail-open: **{routing['topic_fail_open_count']}**; fail-closed parse defaults: **{routing['topic_default_block_count']}**.",
            f"- Harm-seam calls: **{routing['harm_call_count']}**; fail-open: **{routing['harm_fail_open_count']}**; fail-closed parse defaults: **{routing['harm_default_block_count']}**.",
            f"- Historical fast-allow probes reaching the harm seam: **{routing['previous_fast_allow_harm_checked']}/{routing['previous_fast_allow_total']}**.",
            f"- Total evaluation time: **{metrics['latency']['total_seconds']:.3f}s**; p50/p95 per case: **{metrics['latency']['p50_seconds']:.3f}s / {metrics['latency']['p95_seconds']:.3f}s**.",
            "",
            "The three historical JBB-benign fast-allows remain routing probes only and",
            "are excluded from both headline rates.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harmbench-root", type=Path, required=True)
    parser.add_argument("--jailbreakbench-root", type=Path, required=True)
    parser.add_argument("--jbb-behaviors-root", type=Path, required=True)
    parser.add_argument("--domain-set", type=Path, default=HERE / "domain_benign_set.json")
    parser.add_argument("--baseline-report", type=Path, default=HERE / "baseline_report.json")
    parser.add_argument("--step1-report", type=Path, default=HERE / "step1_report.json")
    parser.add_argument("--report-json", type=Path, default=HERE / "step2_report.json")
    parser.add_argument("--report-md", type=Path, default=HERE / "step2_report.md")
    parser.add_argument("--checkpoint-every", type=int, default=10)
    args = parser.parse_args()

    cases, sources, previous_fast_allow_keys = step1.load_step1_cases(
        args.harmbench_root.resolve(),
        args.jailbreakbench_root.resolve(),
        args.jbb_behaviors_root.resolve(),
        args.domain_set.resolve(),
        args.baseline_report.resolve(),
    )
    before = json.loads(args.step1_report.read_text(encoding="utf-8"))
    before_metrics = before["metrics"]
    partial_path = args.report_json.with_suffix(".partial.json")
    completed: dict[tuple[str, str, str], dict[str, Any]] = {}
    if partial_path.exists():
        for row in json.loads(partial_path.read_text(encoding="utf-8")).get("cases", []):
            completed[(row["cohort"], row["source_id"], row["prompt_sha256"])] = row

    results = []
    started = time.perf_counter()
    for index, case in enumerate(cases, start=1):
        key = (case.cohort, case.source_id, case.prompt_sha256)
        results.append(completed.get(key) or evaluate_case(case))
        if index % args.checkpoint_every == 0 or index == len(cases):
            partial_path.write_text(
                json.dumps({"cases": results}, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"evaluated {index}/{len(cases)}", flush=True)

    report = {
        "checkpoint": "card6_part_a_step_2_structured_fail_closed",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "guardrail_code_sha256": baseline.sha256(BACKEND / "retrieval/guardrail.py"),
        "model": baseline.model_metadata(),
        "sources": sources,
        "protocol": {
            "harmful_case_count": 500,
            "domain_benign_case_count": 64,
            "legacy_fast_allow_probe_count": len(cases) - 564,
            "classifier_taxonomy_changed": False,
            "structured_output_changed": True,
            "fail_closed_changed": True,
            "control_flow_changed": False,
            "execution": "sequential",
            "wall_seconds_this_process": round(time.perf_counter() - started, 6),
        },
        "comparison_step1": {
            "harmful_blocked": before_metrics["harmful"]["blocked"],
            "harmful_block_rate": before_metrics["harmful"]["block_rate"],
            "domain_benign_blocked": before_metrics["domain_benign"]["blocked"],
            "domain_benign_block_rate": before_metrics["domain_benign"]["block_rate"],
            "topic_fail_open_count": before_metrics["routing"]["topic_fail_open_count"],
            "harm_fail_open_count": before_metrics["routing"]["harm_fail_open_count"],
        },
        "metrics": summarize(results, previous_fast_allow_keys),
        "cases": results,
    }
    args.report_json.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.report_md.write_text(render_markdown(report), encoding="utf-8")
    partial_path.unlink(missing_ok=True)
    print(render_markdown(report), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
