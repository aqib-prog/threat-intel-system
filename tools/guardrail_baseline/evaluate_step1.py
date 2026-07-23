#!/usr/bin/env python3
"""Card 6 Part A step 1: remeasure the provisional topic/harm seam."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
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
import evaluate_domain_benign as domain  # noqa: E402
from retrieval import guardrail as production  # noqa: E402


@dataclass(frozen=True)
class Step1Case:
    cohort: str
    corpus: str
    split: str
    source_id: str
    category: str
    prompt: str

    @property
    def prompt_sha256(self) -> str:
        return domain.prompt_hash(self.prompt)


def is_fail_open(result: dict[str, Any]) -> bool:
    return bool(result.get("allowed")) and str(result.get("reason", "")).startswith(
        "Could not parse"
    )


def evaluate_case(case: Step1Case) -> dict[str, Any]:
    start = time.perf_counter()
    topic_called = False
    topic_waived = False
    topic_fail_open = False
    harm_called = False
    harm_fail_open = False

    blacklist = production.check_blacklist(case.prompt)
    if not blacklist["allowed"]:
        allowed = False
        final_stage = "blacklist"
        decision_category = blacklist.get("category", "blocked")
    else:
        topic_result = production.check_topic_guardrail(case.prompt)
        topic_waived = bool(topic_result.get("waived_by_cybersecurity_signal"))
        topic_called = not topic_waived
        topic_fail_open = topic_called and is_fail_open(topic_result)
        if not topic_result["allowed"]:
            allowed = False
            final_stage = "topic_gate"
            decision_category = "llm_blocked"
        else:
            harm_called = True
            harm_result = production.check_llm_guardrail(case.prompt)
            harm_fail_open = is_fail_open(harm_result)
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
        "harm_called": harm_called,
        "harm_fail_open": harm_fail_open,
        "elapsed_seconds": time.perf_counter() - start,
    }


def rate(count: int, total: int) -> float:
    return round(count / total, 6) if total else 0.0


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def latency(rows: list[dict[str, Any]]) -> dict[str, Any]:
    values = [float(row["elapsed_seconds"]) for row in rows]
    return {
        "count": len(values),
        "total_seconds": round(sum(values), 6),
        "mean_seconds": round(statistics.fmean(values), 6) if values else 0.0,
        "p50_seconds": round(percentile(values, 0.50), 6),
        "p95_seconds": round(percentile(values, 0.95), 6),
        "max_seconds": round(max(values), 6) if values else 0.0,
    }


def totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = sum(row["blocked"] for row in rows)
    return {"total": len(rows), "blocked": blocked, "block_rate": rate(blocked, len(rows))}


def by_category(rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[row["category"]].append(row)
    return {name: totals(items) for name, items in sorted(groups.items())}


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
        "harmful": totals(harmful),
        "domain_benign": totals(domain_benign),
        "harmful_by_category": by_category(harmful),
        "domain_benign_by_category": by_category(domain_benign),
        "routing": {
            "topic_waived_count": sum(
                row["topic_waived_by_cybersecurity_signal"] for row in rows
            ),
            "topic_llm_call_count": sum(row["topic_llm_called"] for row in rows),
            "topic_fail_open_count": sum(row["topic_fail_open"] for row in rows),
            "harm_call_count": sum(row["harm_called"] for row in rows),
            "harm_fail_open_count": sum(row["harm_fail_open"] for row in rows),
            "previous_fast_allow_total": len(previous_fast_allow_keys),
            "previous_fast_allow_replayed": len(old_fast),
            "previous_fast_allow_harm_checked": sum(row["harm_called"] for row in old_fast),
            "previous_fast_allow_blocked": sum(row["blocked"] for row in old_fast),
        },
        "final_stages": dict(sorted(Counter(row["final_stage"] for row in rows).items())),
        "latency": latency(rows),
    }


def load_step1_cases(
    harmbench_root: Path,
    jailbreakbench_root: Path,
    jbb_behaviors_root: Path,
    domain_set_path: Path,
    baseline_report_path: Path,
) -> tuple[list[Step1Case], dict[str, Any], set[tuple[str, str, str]]]:
    source_cases, sources = baseline.load_cases(
        harmbench_root, jailbreakbench_root, jbb_behaviors_root
    )
    previous = json.loads(baseline_report_path.read_text(encoding="utf-8"))
    previous_fast_allow_keys = {
        (row["corpus"], row["split"], row["source_id"])
        for row in previous["cases"]
        if row["layer"] == "cybersecurity_fast_allow"
    }
    source_lookup = {
        (case.corpus, case.split, case.source_id): case for case in source_cases
    }
    cases = [
        Step1Case(
            cohort="harmful",
            corpus=case.corpus,
            split=case.split,
            source_id=case.source_id,
            category=case.category,
            prompt=case.prompt,
        )
        for case in source_cases
        if case.split == "harmful"
    ]
    # Three of the historical 51 fast-allows are from JBB's generic benign
    # split. Replay them only as routing probes; exclude them from both the
    # 500-case harmful metric and the product-specific benign metric.
    harmful_keys = {(case.corpus, case.split, case.source_id) for case in cases}
    for key in sorted(previous_fast_allow_keys - harmful_keys):
        case = source_lookup[key]
        cases.append(
            Step1Case(
                cohort="legacy_fast_allow_probe",
                corpus=case.corpus,
                split=case.split,
                source_id=case.source_id,
                category=case.category,
                prompt=case.prompt,
            )
        )

    domain_payload = domain.load_set(domain_set_path)
    cases.extend(
        Step1Case(
            cohort="domain_benign",
            corpus="card6_domain_benign",
            split="benign",
            source_id=case["id"],
            category=case["category"],
            prompt=case["prompt"],
        )
        for case in domain_payload["cases"]
    )
    return cases, sources, previous_fast_allow_keys


def render_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    before = report["comparison_baseline"]
    harmful = metrics["harmful"]
    benign = metrics["domain_benign"]
    routing = metrics["routing"]
    return "\n".join(
        [
            "# Card 6 Part A step 1: topic/harm structural separation",
            "",
            f"Status: **MEASURED** ({report['measured_at']})",
            "",
            "Step 1 changes routing only. The provisional harm seam intentionally uses",
            "the unchanged topic-oriented classifier taxonomy; JSON-mode, fail-closed",
            "behavior, and the real harm taxonomy remain later checkpoints.",
            "",
            "## Before / after",
            "",
            "| Measure | Before | After |",
            "| --- | ---: | ---: |",
            f"| Harmful blocked (same 500) | {before['harmful_blocked']}/500 ({before['harmful_block_rate']:.1%}) | {harmful['blocked']}/500 ({harmful['block_rate']:.1%}) |",
            f"| Domain-benign blocked (same 64) | {before['domain_benign_blocked']}/64 ({before['domain_benign_block_rate']:.1%}) | {benign['blocked']}/64 ({benign['block_rate']:.1%}) |",
            f"| Historical cybersecurity fast-allows reaching harm seam | 0/{routing['previous_fast_allow_total']} | {routing['previous_fast_allow_harm_checked']}/{routing['previous_fast_allow_total']} |",
            "",
            "## Routing and reliability observations",
            "",
            f"- Topic LLM calls: **{routing['topic_llm_call_count']}**; fail-open: **{routing['topic_fail_open_count']}**.",
            f"- Harm-seam calls: **{routing['harm_call_count']}**; fail-open: **{routing['harm_fail_open_count']}**.",
            f"- Historical fast-allow probes replayed: **{routing['previous_fast_allow_replayed']}**; blocked by provisional seam: **{routing['previous_fast_allow_blocked']}**.",
            f"- Total evaluation time: **{metrics['latency']['total_seconds']:.3f}s**; p50/p95 per case: **{metrics['latency']['p50_seconds']:.3f}s / {metrics['latency']['p95_seconds']:.3f}s**.",
            "",
            "The three historical JBB-benign fast-allows are routing probes only. They",
            "are excluded from both the 500-case harmful catch rate and the 64-case",
            "domain-specific benign block rate.",
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
    parser.add_argument("--domain-before-report", type=Path, default=HERE / "domain_benign_before_step1.json")
    parser.add_argument("--report-json", type=Path, default=HERE / "step1_report.json")
    parser.add_argument("--report-md", type=Path, default=HERE / "step1_report.md")
    parser.add_argument("--checkpoint-every", type=int, default=10)
    args = parser.parse_args()

    cases, sources, previous_fast_allow_keys = load_step1_cases(
        args.harmbench_root.resolve(),
        args.jailbreakbench_root.resolve(),
        args.jbb_behaviors_root.resolve(),
        args.domain_set.resolve(),
        args.baseline_report.resolve(),
    )
    before = json.loads(args.baseline_report.read_text(encoding="utf-8"))
    domain_before = json.loads(args.domain_before_report.read_text(encoding="utf-8"))
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
        "checkpoint": "card6_part_a_step_1_topic_harm_separation",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "guardrail_code_sha256": baseline.sha256(BACKEND / "retrieval/guardrail.py"),
        "model": baseline.model_metadata(),
        "sources": sources,
        "protocol": {
            "harmful_case_count": 500,
            "domain_benign_case_count": 64,
            "legacy_fast_allow_probe_count": len(cases) - 564,
            "classifier_taxonomy_changed": False,
            "structured_output_changed": False,
            "fail_closed_changed": False,
            "execution": "sequential",
            "wall_seconds_this_process": round(time.perf_counter() - started, 6),
        },
        "comparison_baseline": {
            "harmful_blocked": before["metrics"]["harmful_source_weighted"]["blocked"],
            "harmful_block_rate": before["metrics"]["harmful_source_weighted"]["block_rate"],
            "domain_benign_blocked": domain_before["blocked_count"],
            "domain_benign_block_rate": domain_before["block_rate"],
            "legacy_llm_call_count": before["metrics"]["llm_call_count"],
            "legacy_llm_fail_open_count": before["metrics"]["llm_fail_open_count"],
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
