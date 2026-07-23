#!/usr/bin/env python3
"""Evaluate the unchanged production guardrail on the Card 6 domain-benign set."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
DEFAULT_SET = HERE / "domain_benign_set.json"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from retrieval import guardrail as production  # noqa: E402


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    position = (len(values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    weight = position - lower
    return values[lower] * (1 - weight) + values[upper] * weight


def load_set(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("domain-benign set must contain cases")
    ids = [case["id"] for case in cases]
    prompts = [case["prompt"] for case in cases]
    if len(ids) != len(set(ids)) or len(prompts) != len(set(prompts)):
        raise ValueError("domain-benign IDs and prompts must be unique")
    if not all(case.get("expected_allowed") is True for case in cases):
        raise ValueError("every domain-benign case must be expected_allowed=true")
    return payload


def evaluate(payload: dict, label: str) -> dict:
    results = []
    for case in payload["cases"]:
        start = time.perf_counter()
        decision = production.guardrail(case["prompt"])
        elapsed = time.perf_counter() - start
        results.append(
            {
                "id": case["id"],
                "category": case["category"],
                "prompt_sha256": prompt_hash(case["prompt"]),
                "expected_allowed": True,
                "allowed": bool(decision.get("allowed", True)),
                "decision_category": decision.get("category"),
                "elapsed_seconds": elapsed,
            }
        )
    blocked = [row for row in results if not row["allowed"]]
    latencies = [row["elapsed_seconds"] for row in results]
    return {
        "checkpoint": label,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "set_name": payload["name"],
        "case_count": len(results),
        "blocked_count": len(blocked),
        "block_rate": round(len(blocked) / len(results), 6),
        "blocked_ids": [row["id"] for row in blocked],
        "by_category": {
            category: {
                "total": sum(row["category"] == category for row in results),
                "blocked": sum(
                    row["category"] == category and not row["allowed"] for row in results
                ),
            }
            for category in sorted({row["category"] for row in results})
        },
        "decision_categories": dict(
            sorted(Counter(str(row["decision_category"]) for row in results).items())
        ),
        "latency": {
            "total_seconds": round(sum(latencies), 6),
            "p50_seconds": round(statistics.median(latencies), 6),
            "p95_seconds": round(percentile(latencies, 0.95), 6),
            "max_seconds": round(max(latencies), 6),
        },
        "cases": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--set", type=Path, default=DEFAULT_SET)
    parser.add_argument("--label", required=True)
    parser.add_argument("--report-json", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate(load_set(args.set), args.label)
    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                key: report[key]
                for key in ("checkpoint", "case_count", "blocked_count", "block_rate", "latency")
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
