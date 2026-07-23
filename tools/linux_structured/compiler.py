#!/usr/bin/env python3
"""Card 5 Part 1 step 8: compile Linux field-aware Sigma conditions."""

from __future__ import annotations

import argparse
import json
import pprint
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
SIGMA_TOOLS = REPO / "tools/sigma_compiler"
DEFAULT_STEP2_REPORT = SIGMA_TOOLS / "full_recompile_report.json"
DEFAULT_REPORT = HERE / "compile_report.json"
DEFAULT_SPECS = HERE / "linux_structured_rule_specs.py"

for path in (str(BACKEND), str(SIGMA_TOOLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from log_analysis.parser import LINUX_CANONICAL_ALIASES  # noqa: E402
from log_analysis.structured import StructuredCondition  # noqa: E402
from prototype import CompileError, compile_structured_condition, verify_checkout_commit  # noqa: E402


def _source_path(rule: SigmaRule, sigma_root: Path) -> str:
    return Path(rule.source.path).resolve().relative_to(sigma_root.resolve()).as_posix()


def compile_linux_structured(
    sigma_root: Path, step2_report: dict[str, Any]
) -> tuple[dict[tuple[str, str], dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    sigma_commit = step2_report["sigma_commit"]
    verify_checkout_commit(sigma_root, sigma_commit, "Sigma")
    approved = [
        item
        for item in step2_report["mapping_candidates"]
        if item["platform"] == "linux"
    ]
    approved_by_path = {item["source_path"]: item for item in approved}

    collection = SigmaCollection.load_ruleset(
        [sigma_root / "rules/linux"], collect_errors=True
    )
    if collection.errors:
        raise CompileError(
            "pySigma collection errors: "
            + "; ".join(str(error) for error in collection.errors)
        )
    loaded_by_path = {
        _source_path(rule, sigma_root): rule
        for rule in collection.rules
        if isinstance(rule, SigmaRule)
    }

    specs: dict[tuple[str, str], dict[str, Any]] = {}
    review: list[dict[str, Any]] = []
    field_counts: Counter[str] = Counter()
    for source_path, candidate in sorted(approved_by_path.items()):
        rule = loaded_by_path.get(source_path)
        if rule is None:
            raise CompileError(f"approved source missing from checkout: {source_path}")
        try:
            tree = compile_structured_condition(rule)
            compiled = StructuredCondition.from_dict(tree)
        except (CompileError, ValueError) as exc:
            review.append(
                {
                    "source_path": source_path,
                    "source": candidate["citation"],
                    "technique_id": candidate["technique_id"],
                    "reason": str(exc),
                }
            )
            continue
        key = (candidate["citation"], candidate["technique_id"])
        if key in specs:
            raise CompileError(f"duplicate structured rule key: {key!r}")
        specs[key] = tree
        field_counts.update(compiled.referenced_fields)

    inventory = {
        "approved_linux_sigma_candidates": len(approved),
        "structured_linux_candidates": len(specs),
        "raw_fallback_only_candidates": len(review),
        "canonical_linux_field_count": len(LINUX_CANONICAL_ALIASES),
        "distinct_sigma_source_fields": len(field_counts),
        "sigma_source_field_references": dict(field_counts.most_common()),
    }
    return specs, review, inventory


def render_specs(
    specs: dict[tuple[str, str], dict[str, Any]], sigma_commit: str
) -> str:
    return (
        '"""Generated Card 5 step-8 Linux structured rule specs.\n\n'
        "This module contains plain data only; pySigma is not a runtime dependency.\n"
        '"""\n\n'
        f"SIGMA_COMMIT = {sigma_commit!r}\n\n"
        "STRUCTURED_BY_SOURCE_TECHNIQUE = "
        + pprint.pformat(specs, width=120, sort_dicts=False)
        + "\n"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigma-root", required=True, type=Path)
    parser.add_argument("--step2-report", type=Path, default=DEFAULT_STEP2_REPORT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--specs", type=Path, default=DEFAULT_SPECS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    step2_report = json.loads(args.step2_report.read_text(encoding="utf-8"))
    specs, review, inventory = compile_linux_structured(
        args.sigma_root, step2_report
    )
    report = {
        "checkpoint": "Card 5 Part 1 roadmap step 8 Linux pilot only",
        "sigma_commit": step2_report["sigma_commit"],
        "hybrid_policy": (
            "A structured condition is authoritative for a grouped Linux audit "
            "record once one full positive field branch is available; otherwise "
            "that rule/event falls back to raw regex."
        ),
        "inventory": inventory,
        "raw_fallback_only": review,
    }
    args.report.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    args.specs.write_text(
        render_specs(specs, step2_report["sigma_commit"]), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
