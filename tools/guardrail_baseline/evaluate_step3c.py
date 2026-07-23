#!/usr/bin/env python3
"""Card 6 Part A step 3c: block copyrighted creative reproduction.

Step 3b left the `copyright` HarmBench category (verbatim "generate the lyrics
of ..." reproduction of creative works) mostly allowed. Step 3c adds verbatim
creative-work reproduction to the harm gate's BLOCK criteria, with an explicit
ALLOW carve-out for factual/technical/openly-licensed reference material
(MITRE ATT&CK text, CVE descriptions, standards, documentation) so the product's
core threat-intelligence job is not over-blocked.

Because the standing 64-case domain-benign set contains no reproduction-style
prompts, an over-broad copyright rule would be invisible to it. This run adds a
dedicated `reference_guard` cohort (reference_guard_set.json) of legitimate
MITRE/CVE/NIST reproduction requests that MUST stay allowed, so over-blocking is
detectable. The standard 500-harmful / 64-domain-benign basis is unchanged from
step 3b, keeping the headline numbers directly comparable; the guard cohort is
additive and touches no prior checkpoint's inputs.

Compares against step3b_report.json and writes step3c_report.{json,md}; never
overwrites the historical step-3b artefacts.
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
import evaluate_step2 as step2  # noqa: E402
import evaluate_step3 as step3  # noqa: E402
from retrieval import guardrail as production  # noqa: E402


# Cohorts whose per-case classifier reason is retained for human review. The
# external harmful corpora are excluded because a model could echo source prompt
# text into its reason; benign product-domain cohorts are safe and useful to
# keep when a case is (unexpectedly) blocked.
REASON_COHORTS = {"domain_benign", "reference_guard"}


def evaluate_case(case: step1.Step1Case) -> dict[str, Any]:
    """Identical routing/measurement to step3.evaluate_case; the only change is
    that reasons are retained for the reference_guard cohort too, so an
    over-block of legitimate reference reproduction is captured with its reason.
    """
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

    if case.cohort in REASON_COHORTS and not allowed:
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


def load_guard_cases(path: Path) -> list[step1.Step1Case]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [
        step1.Step1Case(
            cohort="reference_guard",
            corpus="card6_reference_guard",
            split="benign",
            source_id=case["id"],
            category=case["category"],
            prompt=case["prompt"],
        )
        for case in payload["cases"]
    ]


def guard_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = [row for row in rows if row["blocked"]]
    return {
        "total": len(rows),
        "blocked": len(blocked),
        "block_rate": (len(blocked) / len(rows)) if rows else 0.0,
        "blocked_cases": [
            {
                "source_id": row["source_id"],
                "category": row["category"],
                "final_stage": row["final_stage"],
                "decision_reason": row["decision_reason"],
            }
            for row in blocked
        ],
    }


def category_comparison(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    names = sorted(set(current) | set(previous))
    return {
        name: {
            "step3b": previous.get(name, {"total": 0, "blocked": 0, "block_rate": 0.0}),
            "step3c": current.get(name, {"total": 0, "blocked": 0, "block_rate": 0.0}),
            "blocked_delta": current.get(name, {}).get("blocked", 0)
            - previous.get(name, {}).get("blocked", 0),
        }
        for name in names
    }


def render_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    before = report["comparison_step3b"]
    harmful = metrics["harmful"]
    benign = metrics["domain_benign"]
    guard = report["reference_guard"]
    lines = [
        "# Card 6 Part A step 3c: copyright creative-reproduction harm gate",
        "",
        f"Status: **MEASURED** ({report['measured_at']})",
        "",
        "The topic gate, classifier split, structured output, fail-closed default,",
        "and step-1/2 routing are unchanged. The harm gate now also blocks verbatim",
        "reproduction of copyrighted creative works, with an explicit ALLOW carve-out",
        "for factual/technical/openly-licensed reference material.",
        "",
        "## Step 3b / step 3c",
        "",
        "| Measure | Step 3b | Step 3c |",
        "| --- | ---: | ---: |",
        f"| Harmful blocked (same 500) | {before['harmful']['blocked']}/500 ({before['harmful']['block_rate']:.1%}) | {harmful['blocked']}/500 ({harmful['block_rate']:.1%}) |",
        f"| Domain-benign blocked (same 64) | {before['domain_benign']['blocked']}/64 ({before['domain_benign']['block_rate']:.1%}) | {benign['blocked']}/64 ({benign['block_rate']:.1%}) |",
        f"| Reference-guard blocked (new {guard['total']}) | n/a | {guard['blocked']}/{guard['total']} ({guard['block_rate']:.1%}) |",
        "",
        "## Harmful block rate by category",
        "",
        "| Category | Step 3b | Step 3c | Blocked delta |",
        "| --- | ---: | ---: | ---: |",
    ]
    for category, values in report["harmful_category_comparison"].items():
        previous = values["step3b"]
        current = values["step3c"]
        lines.append(
            f"| {category} | {previous['blocked']}/{previous['total']} ({previous['block_rate']:.1%}) | {current['blocked']}/{current['total']} ({current['block_rate']:.1%}) | {values['blocked_delta']:+d} |"
        )
    lines.extend(
        [
            "",
            "## Reference-guard cohort (must stay fully allowed)",
            "",
            "Legitimate MITRE/CVE/NIST reproduction requests that guard against the",
            "copyright rule over-blocking core threat-intelligence work.",
            "",
        ]
    )
    if guard["blocked"] == 0:
        lines.append(f"All {guard['total']} reference-guard cases allowed. No over-block.")
    else:
        lines.append("OVER-BLOCK DETECTED - the following reference cases were blocked:")
        for row in guard["blocked_cases"]:
            lines.append(
                f"- `{row['source_id']}` ({row['category']}, {row['final_stage']}): {row['decision_reason']}"
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
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harmbench-root", type=Path, required=True)
    parser.add_argument("--jailbreakbench-root", type=Path, required=True)
    parser.add_argument("--jbb-behaviors-root", type=Path, required=True)
    parser.add_argument("--domain-set", type=Path, default=HERE / "domain_benign_set.json")
    parser.add_argument("--guard-set", type=Path, default=HERE / "reference_guard_set.json")
    parser.add_argument("--baseline-report", type=Path, default=HERE / "baseline_report.json")
    parser.add_argument("--step3b-report", type=Path, default=HERE / "step3b_report.json")
    parser.add_argument("--report-json", type=Path, default=HERE / "step3c_report.json")
    parser.add_argument("--report-md", type=Path, default=HERE / "step3c_report.md")
    parser.add_argument("--checkpoint-every", type=int, default=10)
    args = parser.parse_args()

    cases, sources, previous_fast_allow_keys = step1.load_step1_cases(
        args.harmbench_root.resolve(),
        args.jailbreakbench_root.resolve(),
        args.jbb_behaviors_root.resolve(),
        args.domain_set.resolve(),
        args.baseline_report.resolve(),
    )
    guard_cases = load_guard_cases(args.guard_set.resolve())
    all_cases = list(cases) + guard_cases

    previous = json.loads(args.step3b_report.read_text(encoding="utf-8"))
    previous_domain_blocked = {
        row["source_id"]
        for row in previous["cases"]
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
    for index, case in enumerate(all_cases, start=1):
        key = (case.cohort, case.source_id, case.prompt_sha256)
        results.append(completed.get(key) or evaluate_case(case))
        if index % args.checkpoint_every == 0 or index == len(all_cases):
            partial_path.write_text(
                json.dumps(
                    {"guardrail_code_sha256": code_sha256, "cases": results},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"evaluated {index}/{len(all_cases)}", flush=True)

    standard_results = [row for row in results if row["cohort"] != "reference_guard"]
    guard_results = [row for row in results if row["cohort"] == "reference_guard"]
    metrics = step3.summarize(standard_results, previous_fast_allow_keys)
    reference_guard = guard_summary(guard_results)
    newly_blocked = [
        {
            "source_id": row["source_id"],
            "category": row["category"],
            "final_stage": row["final_stage"],
            "decision_reason": row["decision_reason"],
            "topic_default_block": row["topic_default_block"],
            "harm_default_block": row["harm_default_block"],
        }
        for row in standard_results
        if row["cohort"] == "domain_benign"
        and row["blocked"]
        and row["source_id"] not in previous_domain_blocked
    ]
    report = {
        "checkpoint": "card6_part_a_step_3c_copyright_reproduction",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "guardrail_code_sha256": code_sha256,
        "model": baseline.model_metadata(),
        "sources": sources,
        "protocol": {
            "harmful_case_count": 500,
            "domain_benign_case_count": 64,
            "reference_guard_case_count": len(guard_cases),
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
        "comparison_step3b": {
            "harmful": previous["metrics"]["harmful"],
            "domain_benign": previous["metrics"]["domain_benign"],
            "routing": previous["metrics"]["routing"],
        },
        "metrics": metrics,
        "harmful_category_comparison": category_comparison(
            metrics["harmful_by_category"], previous["metrics"]["harmful_by_category"]
        ),
        "reference_guard": reference_guard,
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
