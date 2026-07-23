#!/usr/bin/env python3
"""Build reviewed Falco runtime bundles from the committed mapping partition."""

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
DEFAULT_MANIFEST = REPO / "tools/falco_compiler/full_mapping_manifest.json"
DEFAULT_SPECS = REPO / "tools/falco_compiler/full_rule_specs.py"
DEFAULT_REPORT = REPO / "tools/falco_compiler/full_recompile_report.json"
DEFAULT_OUTPUT_DIR = REPO / "backend/log_analysis/generated"
PLATFORMS = ("kubernetes", "aws")


class BuildError(RuntimeError):
    pass


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise BuildError(f"cannot load generated artifact: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prefilter_choices(node: dict[str, Any]) -> list[tuple[int, tuple[str, ...]]]:
    """Find alternative literals logically required by a Falco tree."""

    kind = node["type"]
    if kind == "not":
        return []
    if kind == "predicate":
        if node.get("operator") not in {"=", "in", "intersects"}:
            return []
        terms = tuple(
            dict.fromkeys(
                str(value).casefold()
                for value in node.get("values", ())
                if isinstance(value, str) and len(value) >= 3
            )
        )
        if not terms:
            return []
        field = node.get("field", "")
        if field == "ct.name" or field == "ka.target.subresource":
            priority = 0
        elif field.startswith(("ka.target.resource", "ka.req.", "ct.src")):
            priority = 1
        elif field in {"ka.user.name", "ka.target.namespace"}:
            priority = 1
        elif field == "ka.verb":
            priority = 2
        elif "stage" in field or field in {"jevt.rawtime", "ka.response.code"}:
            priority = 9
        else:
            priority = 3
        return [(priority, terms)]

    children = node.get("children", ())
    if kind == "and":
        return [choice for child in children for choice in _prefilter_choices(child)]
    if kind == "or":
        selected: list[tuple[int, tuple[str, ...]]] = []
        for child in children:
            choices = _prefilter_choices(child)
            if not choices:
                return []
            selected.append(min(choices, key=lambda item: (item[0], len(item[1]))))
        return [
            (
                max(item[0] for item in selected),
                tuple(dict.fromkeys(term for _, terms in selected for term in terms)),
            )
        ]
    raise BuildError(f"unknown expanded Falco node type: {kind!r}")


def _prefilter_terms(tree: dict[str, Any]) -> tuple[str, ...]:
    choices = _prefilter_choices(tree)
    if not choices:
        raise BuildError("mapping candidate has no safe positive literal prefilter")
    return min(choices, key=lambda item: (item[0], len(item[1])))[1]


def build_payloads(
    manifest: dict[str, Any], specs: ModuleType, report: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    commits = {manifest.get("falco_commit"), specs.FALCO_COMMIT, report.get("falco_commit")}
    if len(commits) != 1:
        raise BuildError(f"Falco commit mismatch across reviewed artifacts: {commits}")

    rows = manifest.get("mappings")
    if not isinstance(rows, list):
        raise BuildError("mapping manifest must contain a mappings list")
    candidates = {
        (row["rule"], row["platform"], row["technique_id"].upper())
        for row in rows
        if row["decision"] == "mapping_candidate"
    }
    excluded = {
        (row["rule"], row["platform"])
        for row in rows
        if row["decision"] in {"needs_review", "source_disabled"}
    }
    report_candidates = {
        (row["rule"], row["platform"], row["attack"]["technique_id"].upper()): row
        for row in report.get("rules", ())
        if row["decision"] == "mapping_candidate"
    }
    if report_candidates.keys() != candidates:
        raise BuildError("mapping manifest and full report candidate partitions differ")
    emitted: set[tuple[str, str, str]] = set()
    by_platform: dict[str, list[dict[str, Any]]] = {platform: [] for platform in PLATFORMS}
    for item in specs.RULE_SPECS:
        kwargs = item["rule_kwargs"]
        platform = kwargs["platform"]
        technique_id = item["technique_id"].upper()
        key = (item["rule"], platform, technique_id)
        if platform not in by_platform:
            raise BuildError(f"unsupported Falco runtime platform: {platform}")
        if key not in candidates:
            raise BuildError(f"runtime spec is not an approved mapping candidate: {key}")
        if (item["rule"], platform) in excluded:
            raise BuildError(f"excluded Falco rule leaked into runtime: {key}")
        if key in emitted:
            raise BuildError(f"duplicate Falco runtime spec: {key}")
        emitted.add(key)
        prefilter_terms = _prefilter_terms(report_candidates[key]["expanded_condition_tree"])
        by_platform[platform].append(
            {
                "rule": item["rule"],
                "technique_id": technique_id,
                "source_file": item["source_file"],
                "mapping_confidence": item["mapping_confidence"],
                "rule_kwargs": kwargs,
                "structured_condition": None,
                "prefilter_terms": list(prefilter_terms),
            }
        )
    if emitted != candidates:
        raise BuildError(
            "candidate/spec partition mismatch; "
            f"missing={sorted(candidates - emitted)[:5]}, extra={sorted(emitted - candidates)[:5]}"
        )

    return {
        platform: {
            "schema_version": 1,
            "platform": platform,
            "decision_policy": "mapping_candidate_only",
            "falco_commit": specs.FALCO_COMMIT,
            "inventory": {
                "mapping_candidate_count": len(rules),
                "structured_condition_count": 0,
                "raw_fallback_only_count": len(rules),
            },
            "rules": rules,
        }
        for platform, rules in by_platform.items()
    }


def render(payload: dict[str, Any]) -> bytes:
    raw = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=False
    ).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--specs", type=Path, default=DEFAULT_SPECS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    specs = load_module(args.specs, "runtime_falco_specs")
    report = json.loads(args.report.read_text(encoding="utf-8"))
    payloads = build_payloads(manifest, specs, report)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for platform, payload in payloads.items():
        path = args.output_dir / f"{platform}_falco_rules.json.gz"
        path.write_bytes(render(payload))
        print(f"{platform}: {json.dumps(payload['inventory'], sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
