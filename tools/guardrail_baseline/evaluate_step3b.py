#!/usr/bin/env python3
"""Card 6 Part A step 3b: widen the harm gate to general (non-cyber) harm.

Step 3 gave the harm gate a distinct offensive-uplift taxonomy and took
cybercrime_intrusion to 100%, but left clearly-harmful non-cyber requests
(e.g. historical-disinformation edits that reach the harm gate via a
cybersecurity-signal false positive) still allowed. Step 3b widens the harm
gate's BLOCK criteria to those categories while leaving the topic gate,
structured-output/JSON mode, fail-closed default, control flow, and the
defensive/educational ALLOW criteria unchanged.

Measurement logic (routing, per-case evaluation, summarisation) is reused
verbatim from evaluate_step3 so the ONLY difference between the step-3 and
step-3b numbers is the guardrail taxonomy change under test. This run compares
against step3_report.json and writes step3b_report.json/.md; it never
overwrites the historical step-3 artefacts.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
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
import evaluate_step3 as step3  # noqa: E402


def category_comparison(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    names = sorted(set(current) | set(previous))
    return {
        name: {
            "step3": previous.get(name, {"total": 0, "blocked": 0, "block_rate": 0.0}),
            "step3b": current.get(name, {"total": 0, "blocked": 0, "block_rate": 0.0}),
            "blocked_delta": current.get(name, {}).get("blocked", 0)
            - previous.get(name, {}).get("blocked", 0),
        }
        for name in names
    }


def render_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    before = report["comparison_step3"]
    harmful = metrics["harmful"]
    benign = metrics["domain_benign"]
    routing = metrics["routing"]
    lines = [
        "# Card 6 Part A step 3b: general-harm harm gate",
        "",
        f"Status: **MEASURED** ({report['measured_at']})",
        "",
        "The topic prompt, classifier split, structured output, fail-closed",
        "default, and step-1/2 routing are all unchanged. Only the harm gate's",
        "BLOCK taxonomy is widened to cover clearly-harmful non-cyber content.",
        "",
        "## Step 3 / step 3b",
        "",
        "| Measure | Step 3 | Step 3b |",
        "| --- | ---: | ---: |",
        f"| Harmful blocked (same 500) | {before['harmful']['blocked']}/500 ({before['harmful']['block_rate']:.1%}) | {harmful['blocked']}/500 ({harmful['block_rate']:.1%}) |",
        f"| Domain-benign blocked (same 64) | {before['domain_benign']['blocked']}/64 ({before['domain_benign']['block_rate']:.1%}) | {benign['blocked']}/64 ({benign['block_rate']:.1%}) |",
        f"| Topic fail-open / parse default | {before['routing']['topic_fail_open_count']} / {before['routing']['topic_default_block_count']} | {routing['topic_fail_open_count']} / {routing['topic_default_block_count']} |",
        f"| Harm fail-open / parse default | {before['routing']['harm_fail_open_count']} / {before['routing']['harm_default_block_count']} | {routing['harm_fail_open_count']} / {routing['harm_default_block_count']} |",
        "",
        "## Harmful block rate by category",
        "",
        "| Category | Step 3 | Step 3b | Blocked delta |",
        "| --- | ---: | ---: | ---: |",
    ]
    for category, values in report["harmful_category_comparison"].items():
        previous = values["step3"]
        current = values["step3b"]
        lines.append(
            f"| {category} | {previous['blocked']}/{previous['total']} ({previous['block_rate']:.1%}) | {current['blocked']}/{current['total']} ({current['block_rate']:.1%}) | {values['blocked_delta']:+d} |"
        )
    lines.extend(["", "## Newly blocked domain-benign cases", ""])
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
            "The three historical JBB-benign fast-allows remain routing probes only",
            "and are excluded from both headline rates.",
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
    parser.add_argument("--step3-report", type=Path, default=HERE / "step3_report.json")
    parser.add_argument("--report-json", type=Path, default=HERE / "step3b_report.json")
    parser.add_argument("--report-md", type=Path, default=HERE / "step3b_report.md")
    parser.add_argument("--checkpoint-every", type=int, default=10)
    args = parser.parse_args()

    cases, sources, previous_fast_allow_keys = step1.load_step1_cases(
        args.harmbench_root.resolve(),
        args.jailbreakbench_root.resolve(),
        args.jbb_behaviors_root.resolve(),
        args.domain_set.resolve(),
        args.baseline_report.resolve(),
    )
    previous = json.loads(args.step3_report.read_text(encoding="utf-8"))
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
        results.append(completed.get(key) or step3.evaluate_case(case))
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

    metrics = step3.summarize(results, previous_fast_allow_keys)
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
        "checkpoint": "card6_part_a_step_3b_general_harm_taxonomy",
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
        "comparison_step3": {
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
