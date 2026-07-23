#!/usr/bin/env python3
"""Build the reviewed Linux Sigma runtime bundle from committed artifacts."""

from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DEFAULT_STEP2_REPORT = REPO / "tools/sigma_compiler/full_recompile_report.json"
DEFAULT_SIGMA_SPECS = REPO / "tools/sigma_compiler/full_recompile_rule_specs.py"
DEFAULT_STRUCTURED_SPECS = REPO / "tools/linux_structured/linux_structured_rule_specs.py"
DEFAULT_OUTPUT = REPO / "backend/log_analysis/generated/linux_sigma_rules.json.gz"


class BuildError(RuntimeError):
    pass


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise BuildError(f"cannot load generated artifact: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_payload(
    step2_report: dict[str, Any], sigma_specs: ModuleType, structured_specs: ModuleType
) -> dict[str, Any]:
    commits = {
        step2_report["sigma_commit"],
        sigma_specs.SIGMA_COMMIT,
        structured_specs.SIGMA_COMMIT,
    }
    if len(commits) != 1:
        raise BuildError(f"Sigma commit mismatch across reviewed artifacts: {commits}")

    candidates = [
        item for item in step2_report["mapping_candidates"] if item["platform"] == "linux"
    ]
    candidate_keys = {
        (item["source_path"], item["technique_id"].upper(), item["citation"])
        for item in candidates
    }
    review_paths = {
        item["source_path"]
        for item in step2_report["needs_review"]
        if item["platform"] == "linux"
    }
    rules = []
    spec_keys: set[tuple[str, str, str]] = set()
    for item in sigma_specs.RULE_SPECS_BY_PLATFORM["linux"]:
        kwargs = item["rule_kwargs"]
        technique_id = item["technique_id"].upper()
        key = (item["source_path"], technique_id, kwargs["source"])
        if key not in candidate_keys:
            raise BuildError(f"runtime spec is not an approved mapping candidate: {key}")
        if item["source_path"] in review_paths:
            raise BuildError(f"needs_review source leaked into runtime: {item['source_path']}")
        if key in spec_keys:
            raise BuildError(f"duplicate runtime spec: {key}")
        spec_keys.add(key)
        rules.append(
            {
                "technique_id": technique_id,
                "source_path": item["source_path"],
                "rule_kwargs": kwargs,
                "structured_condition": structured_specs.STRUCTURED_BY_SOURCE_TECHNIQUE.get(
                    (kwargs["source"], technique_id)
                ),
            }
        )
    if spec_keys != candidate_keys:
        missing = sorted(candidate_keys - spec_keys)[:5]
        extra = sorted(spec_keys - candidate_keys)[:5]
        raise BuildError(f"candidate/spec partition mismatch; missing={missing}, extra={extra}")

    return {
        "schema_version": 1,
        "platform": "linux",
        "decision_policy": "mapping_candidate_only",
        "sigma_commit": commits.pop(),
        "inventory": {
            "mapping_candidate_count": len(rules),
            "structured_condition_count": sum(
                item["structured_condition"] is not None for item in rules
            ),
            "raw_fallback_only_count": sum(
                item["structured_condition"] is None for item in rules
            ),
        },
        "rules": rules,
    }


def render(payload: dict[str, Any]) -> bytes:
    raw = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=False
    ).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--step2-report", type=Path, default=DEFAULT_STEP2_REPORT)
    parser.add_argument("--sigma-specs", type=Path, default=DEFAULT_SIGMA_SPECS)
    parser.add_argument("--structured-specs", type=Path, default=DEFAULT_STRUCTURED_SPECS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = json.loads(args.step2_report.read_text(encoding="utf-8"))
    sigma = load_module(args.sigma_specs, "runtime_linux_sigma_specs")
    structured = load_module(args.structured_specs, "runtime_linux_structured_specs")
    payload = build_payload(report, sigma, structured)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(render(payload))
    print(json.dumps(payload["inventory"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
