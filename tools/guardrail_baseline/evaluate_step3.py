#!/usr/bin/env python3
"""Card 6 Part A step 3: measure the distinct offensive-uplift harm gate."""

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
import evaluate_step2 as step2  # noqa: E402
from retrieval import guardrail as production  # noqa: E402


def evaluate_case(case: step1.Step1Case) -> dict[str, Any]:
    start = time.perf_counter()
    topic_called = False
    topic_waived = False
    topic_fail_open = False
    topic_default_block = False
    harm_called = False
    harm_fail_open = False
    harm_default_block = False
    decision_reason: str | None = None

    blacklist = production.check_blacklist(case.prompt)
    if not blacklist["allowed"]:
        allowed = False
        final_stage = "blacklist"
        decision_category = blacklist.get("category", "blocked")
        reason = blacklist.get("message", decision_category)
    else:
        topic_result = production.check_topic_guardrail(case.prompt)
        topic_waived = bool(topic_result.get("waived_by_cybersecurity_signal"))
        topic_called = not topic_waived
        topic_fail_open = topic_called and step1.is_fail_open(topic_result)
        topic_default_block = topic_called and step2.is_default_block(topic_result)
        if not topic_result["allowed"]:
            allowed = False
            final_stage = "topic_gate"
            decision_category = "llm_blocked"
            reason = topic_result.get("reason", "No reason provided")
        else:
            harm_called = True
            harm_result = production.check_llm_guardrail(case.prompt)
            harm_fail_open = step1.is_fail_open(harm_result)
            harm_default_block = step2.is_default_block(harm_result)
            allowed = bool(harm_result["allowed"])
            final_stage = "allowed" if allowed else "harm_gate"
            decision_category = None if allowed else "llm_harm_blocked"
            reason = harm_result.get("reason", "No reason provided")

    # The user requested individual classifier reasoning for newly blocked
    # product-domain benign cases. Do not retain reasons for external harmful
    # corpora because a model could echo source prompt text into its reason.
    if case.cohort == "domain_benign" and not allowed:
        decision_reason = str(reason)

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
        "decision_reason": decision_reason,
        "topic_llm_called": topic_called,
        "topic_waived_by_cybersecurity_signal": topic_waived,
        "topic_fail_open": topic_fail_open,
        "topic_default_block": topic_default_block,
        "harm_called": harm_called,
        "harm_fail_open": harm_fail_open,
        "harm_default_block": harm_default_block,
        "elapsed_seconds": time.perf_counter() - start,
    }


def category_comparison(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    names = sorted(set(current) | set(previous))
    return {
        name: {
            "step2": previous.get(name, {"total": 0, "blocked": 0, "block_rate": 0.0}),
            "step3": current.get(name, {"total": 0, "blocked": 0, "block_rate": 0.0}),
            "blocked_delta": current.get(name, {}).get("blocked", 0)
            - previous.get(name, {}).get("blocked", 0),
        }
        for name in names
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
    before = report["comparison_step2"]
    harmful = metrics["harmful"]
    benign = metrics["domain_benign"]
    routing = metrics["routing"]
    lines = [
        "# Card 6 Part A step 3: defensive-vs-offensive-uplift harm gate",
        "",
        f"Status: **MEASURED** ({report['measured_at']})",
        "",
        "The topic prompt and step-1/2 routing are unchanged. The harm seam now has",
        "a distinct taxonomy for operational offensive uplift.",
        "",
        "## Step 2 / step 3",
        "",
        "| Measure | Step 2 | Step 3 |",
        "| --- | ---: | ---: |",
        f"| Harmful blocked (same 500) | {before['harmful']['blocked']}/500 ({before['harmful']['block_rate']:.1%}) | {harmful['blocked']}/500 ({harmful['block_rate']:.1%}) |",
        f"| Domain-benign blocked (same 64) | {before['domain_benign']['blocked']}/64 ({before['domain_benign']['block_rate']:.1%}) | {benign['blocked']}/64 ({benign['block_rate']:.1%}) |",
        f"| Topic fail-open / parse default | {before['routing']['topic_fail_open_count']} / {before['routing']['topic_default_block_count']} | {routing['topic_fail_open_count']} / {routing['topic_default_block_count']} |",
        f"| Harm fail-open / parse default | {before['routing']['harm_fail_open_count']} / {before['routing']['harm_default_block_count']} | {routing['harm_fail_open_count']} / {routing['harm_default_block_count']} |",
        "",
        "## Harmful block rate by category",
        "",
        "| Category | Step 2 | Step 3 | Blocked delta |",
        "| --- | ---: | ---: | ---: |",
    ]
    for category, values in report["harmful_category_comparison"].items():
        previous = values["step2"]
        current = values["step3"]
        lines.append(
            f"| {category} | {previous['blocked']}/{previous['total']} ({previous['block_rate']:.1%}) | {current['blocked']}/{current['total']} ({current['block_rate']:.1%}) | {values['blocked_delta']:+d} |"
        )
    lines.extend(
        [
            "",
            "## Newly blocked domain-benign cases",
            "",
        ]
    )
    newly_blocked = report["newly_blocked_domain_benign"]
    if not newly_blocked:
        lines.append("None.")
    else:
        for row in newly_blocked:
            lines.append(
                f"- `{row['source_id']}` ({row['category']}, {row['final_stage']}): {row['decision_reason']}"
            )
    lines.extend(
        [
            "",
            "The three historical JBB-benign fast-allows remain routing probes only and",
            "are excluded from both headline rates.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harmbench-root", type=Path, required=True)
    parser.add_argument("--jailbreakbench-root", type=Path, required=True)
    parser.add_argument("--jbb-behaviors-root", type=Path, required=True)
    parser.add_argument("--domain-set", type=Path, default=HERE / "domain_benign_set.json")
    parser.add_argument("--baseline-report", type=Path, default=HERE / "baseline_report.json")
    parser.add_argument("--step2-report", type=Path, default=HERE / "step2_report.json")
    parser.add_argument("--report-json", type=Path, default=HERE / "step3_report.json")
    parser.add_argument("--report-md", type=Path, default=HERE / "step3_report.md")
    parser.add_argument("--checkpoint-every", type=int, default=10)
    args = parser.parse_args()

    cases, sources, previous_fast_allow_keys = step1.load_step1_cases(
        args.harmbench_root.resolve(),
        args.jailbreakbench_root.resolve(),
        args.jbb_behaviors_root.resolve(),
        args.domain_set.resolve(),
        args.baseline_report.resolve(),
    )
    previous = json.loads(args.step2_report.read_text(encoding="utf-8"))
    previous_rows = previous["cases"]
    previous_domain_blocked = {
        row["source_id"]
        for row in previous_rows
        if row["cohort"] == "domain_benign" and row["blocked"]
    }
    code_sha256 = baseline.sha256(BACKEND / "retrieval/guardrail.py")
    partial_path = args.report_json.with_suffix(".partial.json")
    completed: dict[tuple[str, str, str], dict[str, Any]] = {}
    if partial_path.exists():
        partial = json.loads(partial_path.read_text(encoding="utf-8"))
        if partial.get("guardrail_code_sha256") == code_sha256:
            for row in partial.get("cases", []):
                completed[(row["cohort"], row["source_id"], row["prompt_sha256"])] = row

    results = []
    started = time.perf_counter()
    for index, case in enumerate(cases, start=1):
        key = (case.cohort, case.source_id, case.prompt_sha256)
        results.append(completed.get(key) or evaluate_case(case))
        if index % args.checkpoint_every == 0 or index == len(cases):
            partial_path.write_text(
                json.dumps(
                    {"guardrail_code_sha256": code_sha256, "cases": results},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"evaluated {index}/{len(cases)}", flush=True)

    metrics = summarize(results, previous_fast_allow_keys)
    newly_blocked = [
        {
            "source_id": row["source_id"],
            "category": row["category"],
            "final_stage": row["final_stage"],
            "decision_reason": row["decision_reason"],
            "topic_default_block": row["topic_default_block"],
            "harm_default_block": row["harm_default_block"],
        }
        for row in results
        if row["cohort"] == "domain_benign"
        and row["blocked"]
        and row["source_id"] not in previous_domain_blocked
    ]
    report = {
        "checkpoint": "card6_part_a_step_3_harm_taxonomy",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "guardrail_code_sha256": code_sha256,
        "model": baseline.model_metadata(),
        "sources": sources,
        "protocol": {
            "harmful_case_count": 500,
            "domain_benign_case_count": 64,
            "legacy_fast_allow_probe_count": len(cases) - 564,
            "topic_classifier_taxonomy_changed": False,
            "harm_classifier_taxonomy_changed": True,
            "classifiers_split": True,
            "structured_output_changed": False,
            "fail_closed_changed": False,
            "control_flow_changed": False,
            "blacklist_or_signal_logic_changed": False,
            "execution": "sequential",
            "wall_seconds_this_process": round(time.perf_counter() - started, 6),
        },
        "comparison_step2": {
            "harmful": previous["metrics"]["harmful"],
            "domain_benign": previous["metrics"]["domain_benign"],
            "routing": previous["metrics"]["routing"],
        },
        "metrics": metrics,
        "harmful_category_comparison": category_comparison(
            metrics["harmful_by_category"], previous["metrics"]["harmful_by_category"]
        ),
        "newly_blocked_domain_benign": newly_blocked,
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
