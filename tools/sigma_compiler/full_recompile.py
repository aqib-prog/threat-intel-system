#!/usr/bin/env python3
"""Card 5 Part 1, roadmap step 2: full Sigma recompilation preview.

This remains an offline, checkpoint-gated compiler. It emits a report and a
reviewable Python rule-spec artifact, but does not edit mappings.py.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import pprint
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from prototype import (
    CompileError,
    attack_technique_tags,
    compile_condition,
    resolve_technique_tags,
    verify_checkout_commit,
)


HERE = Path(__file__).resolve().parent
DEFAULT_REPORT = HERE / "full_recompile_report.json"
DEFAULT_SPECS = HERE / "full_recompile_rule_specs.py"
SOURCE_DIRS = {
    "windows": "rules/windows",
    "linux": "rules/linux",
    "macos": "rules/macos",
    "aws": "rules/cloud/aws/cloudtrail",
}
SIGMA_GENERATED_LISTS = (
    "WINDOWS_SIGMA_RULES",
    "WINDOWS_SIGMA_EXPANSION_RULES",
    "LINUX_SIGMA_RULES",
    "AWS_SIGMA_RULES",
    "MACOS_SIGMA_RULES",
    "MACOS_SIGMA_EXPANSION_RULES",
)
PRESERVED_LISTS = (
    "WINDOWS_RULES",
    "LINUX_RULES",
    "AWS_RULES",
    "KUBERNETES_RULES",
    "MACOS_RULES",
)


@dataclass(frozen=True)
class CatalogEntry:
    technique_id: str
    technique_name: str
    parent_hint: str | None


class TechniqueCatalog:
    def __init__(self, techniques_path: Path, relationships_path: Path):
        techniques = json.loads(techniques_path.read_text(encoding="utf-8"))
        relationships = json.loads(relationships_path.read_text(encoding="utf-8"))
        self.by_id = {item["external_id"].upper(): item for item in techniques}
        self.by_stix = {item["id"]: item for item in techniques}
        self.by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in techniques:
            self.by_name[item["name"]].append(item)
        self.parent_by_child: dict[str, str] = {
            relation["source_ref"]: relation["target_ref"]
            for relation in relationships
            if relation["relationship_type"] == "subtechnique-of"
        }

    def entry(self, technique_id: str) -> CatalogEntry:
        try:
            item = self.by_id[technique_id]
        except KeyError as exc:
            raise CompileError(
                f"technique {technique_id} is absent from the local ATT&CK dataset"
            ) from exc
        same_name = self.by_name[item["name"]]
        parent_hint: str | None = None
        if len(same_name) > 1:
            try:
                parent_stix = self.parent_by_child[item["id"]]
                parent_hint = self.by_stix[parent_stix]["name"]
            except KeyError as exc:
                raise CompileError(
                    f"duplicate technique name {item['name']!r} has no resolvable parent hint"
                ) from exc
        return CatalogEntry(technique_id, item["name"], parent_hint)

    def current_rule_ids(self, technique_name: str, parent_hint: str | None) -> list[str]:
        items = self.by_name.get(technique_name, [])
        if len(items) <= 1:
            return [item["external_id"].upper() for item in items]
        if parent_hint is None:
            return []
        result: list[str] = []
        for item in items:
            parent_stix = self.parent_by_child.get(item["id"])
            parent = self.by_stix.get(parent_stix or "")
            if parent and parent["name"] == parent_hint:
                result.append(item["external_id"].upper())
        return result


def confidence(rule: SigmaRule) -> str:
    name = getattr(rule.level, "name", str(rule.level)).lower()
    return {
        "informational": "low",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "high",
    }.get(name, "low")


def _base_rule_record(rule: SigmaRule, sigma_root: Path) -> dict[str, Any]:
    source_path = Path(rule.source.path).resolve().relative_to(sigma_root.resolve())
    return {
        "source": source_path.name,
        "source_path": source_path.as_posix(),
        "title": rule.title,
        "rule_id": str(rule.id or ""),
        "status": str(rule.status.name.lower()) if rule.status else None,
        "platform": (rule.logsource.product or "").lower(),
        "logsource": {
            "product": rule.logsource.product,
            "category": rule.logsource.category,
            "service": rule.logsource.service,
        },
        "confidence": confidence(rule),
    }


def compile_full_rules(
    sigma_root: Path, sigma_commit: str, catalog: TechniqueCatalog
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    verify_checkout_commit(sigma_root, sigma_commit, "Sigma")
    inputs = [sigma_root / relative for relative in SOURCE_DIRS.values()]
    collection = SigmaCollection.load_ruleset(inputs, collect_errors=True)
    if collection.errors:
        raise CompileError(
            "pySigma collection errors: " + "; ".join(str(error) for error in collection.errors)
        )

    candidates: list[dict[str, Any]] = []
    review: list[dict[str, Any]] = []
    input_by_platform: Counter[str] = Counter()
    projected_by_platform: Counter[str] = Counter()
    review_reasons: Counter[str] = Counter()

    for loaded in collection.rules:
        if not isinstance(loaded, SigmaRule):
            raise CompileError(f"full compiler does not accept {type(loaded).__name__}")
        if loaded.errors:
            raise CompileError(
                f"{loaded.title}: " + "; ".join(str(error) for error in loaded.errors)
            )
        base = _base_rule_record(loaded, sigma_root)
        platform = base["platform"]
        if platform not in SOURCE_DIRS:
            raise CompileError(
                f"{base['source_path']}: unexpected logsource product {platform!r}"
            )
        input_by_platform[platform] += 1
        resolution = resolve_technique_tags(attack_technique_tags(loaded))

        try:
            pattern = compile_condition(loaded)
            projected_by_platform[platform] += 1
        except CompileError as exc:
            reason = str(exc)
            review_reasons[f"projection: {reason}"] += 1
            review.append(
                {
                    **base,
                    "review_stage": "projection",
                    "review_reason": reason,
                    "technique_resolution": asdict(resolution),
                    "pattern": None,
                }
            )
            continue

        if resolution.status != "mapping_candidate":
            review_reasons["technique_resolution"] += 1
            review.append(
                {
                    **base,
                    "review_stage": "technique_resolution",
                    "review_reason": resolution.explanation,
                    "technique_resolution": asdict(resolution),
                    "candidate_techniques_after_parent_resolution": [
                        {
                            "technique_id": tag,
                            "technique_name": catalog.by_id.get(tag, {}).get(
                                "name", "<missing from local ATT&CK data>"
                            ),
                        }
                        for tag in resolution.resolved_tags
                    ],
                    "pattern": pattern,
                }
            )
            continue

        technique_id = resolution.resolved_tags[0]
        try:
            entry = catalog.entry(technique_id)
        except CompileError as exc:
            review_reasons[f"catalog: {exc}"] += 1
            review.append(
                {
                    **base,
                    "review_stage": "catalog",
                    "review_reason": str(exc),
                    "technique_resolution": asdict(resolution),
                    "pattern": pattern,
                }
            )
            continue

        candidates.append(
            {
                **base,
                "technique_id": entry.technique_id,
                "technique_name": entry.technique_name,
                "parent_hint": entry.parent_hint,
                "pattern": pattern,
                "tag_resolution": asdict(resolution),
                "reason": f"{loaded.title} (Sigma-sourced).",
                "citation": f"Sigma: {base['source']}",
            }
        )

    candidates.sort(key=lambda item: (item["platform"], item["source"], item["technique_id"]))
    review.sort(key=lambda item: (item["platform"], item["source"]))
    inventory = {
        "input_rule_count": len(collection.rules),
        "input_by_platform": dict(sorted(input_by_platform.items())),
        "projected_rule_count": sum(projected_by_platform.values()),
        "projected_by_platform": dict(sorted(projected_by_platform.items())),
        "candidate_by_platform": dict(
            sorted(Counter(item["platform"] for item in candidates).items())
        ),
        "review_by_platform": dict(sorted(Counter(item["platform"] for item in review).items())),
        "review_reasons": dict(sorted(review_reasons.items())),
    }
    return candidates, review, inventory


def _load_current_mappings(techniques_path: Path):
    backend_root = techniques_path.resolve().parents[2]
    if str(backend_root) not in sys.path:
        sys.path.insert(0, str(backend_root))
    return importlib.import_module("log_analysis.mappings")


def _coverage_ids(rules: list[Any], catalog: TechniqueCatalog) -> tuple[set[str], list[dict[str, Any]]]:
    ids: set[str] = set()
    unresolved: list[dict[str, Any]] = []
    for rule in rules:
        resolved = catalog.current_rule_ids(rule.technique_name, rule.parent_hint)
        if len(resolved) == 1:
            ids.add(resolved[0])
        else:
            unresolved.append(
                {
                    "technique_name": rule.technique_name,
                    "parent_hint": rule.parent_hint,
                    "source": rule.source,
                }
            )
    return ids, unresolved


def build_diff_summary(
    candidates: list[dict[str, Any]], mappings: Any, catalog: TechniqueCatalog
) -> dict[str, Any]:
    old_generated = [
        rule for list_name in SIGMA_GENERATED_LISTS for rule in getattr(mappings, list_name)
    ]
    preserved = [rule for list_name in PRESERVED_LISTS for rule in getattr(mappings, list_name)]
    # This report is the immutable step-2 review diff. Later runtime promotion
    # layers must not rewrite its historical "current mappings" baseline.
    checkpoint_current = preserved + old_generated
    current_ids, current_unresolved = _coverage_ids(checkpoint_current, catalog)
    preserved_ids, preserved_unresolved = _coverage_ids(preserved, catalog)
    proposed_ids = preserved_ids | {item["technique_id"] for item in candidates}

    old_keys: dict[tuple[str, str], Any] = {}
    old_unresolved_keys: list[dict[str, Any]] = []
    for rule in old_generated:
        ids = catalog.current_rule_ids(rule.technique_name, rule.parent_hint)
        if len(ids) == 1:
            old_keys[(rule.source, ids[0])] = rule
        else:
            old_unresolved_keys.append(
                {
                    "source": rule.source,
                    "technique_name": rule.technique_name,
                    "parent_hint": rule.parent_hint,
                }
            )
    new_keys = {(item["citation"], item["technique_id"]): item for item in candidates}
    retained = sorted(set(old_keys) & set(new_keys))
    new = sorted(set(new_keys) - set(old_keys))
    removed = sorted(set(old_keys) - set(new_keys))
    changed_regex = [
        key
        for key in retained
        if old_keys[key].pattern.pattern != new_keys[key]["pattern"]
    ]
    return {
        "current_total_rule_count": len(checkpoint_current),
        "current_generated_sigma_section_count": len(old_generated),
        "preserved_non_generated_rule_count": len(preserved),
        "proposed_generated_sigma_rule_count": len(candidates),
        "proposed_total_rule_count": len(preserved) + len(candidates),
        "rule_count_delta": len(preserved) + len(candidates) - len(checkpoint_current),
        "current_unique_technique_id_count": len(current_ids),
        "proposed_unique_technique_id_count": len(proposed_ids),
        "unique_technique_id_delta": len(proposed_ids) - len(current_ids),
        "current_unresolved_mapping_count": len(current_unresolved),
        "preserved_unresolved_mapping_count": len(preserved_unresolved),
        "old_generated_unresolved_mapping_count": len(old_unresolved_keys),
        "retained_source_technique_mapping_count": len(retained),
        "new_source_technique_mapping_count": len(new),
        "removed_source_technique_mapping_count": len(removed),
        "retained_mapping_regex_changed_count": len(changed_regex),
        "retained_mapping_regex_unchanged_count": len(retained) - len(changed_regex),
        "new_source_technique_mappings": [
            {"source": source, "technique_id": technique_id}
            for source, technique_id in new
        ],
        "removed_source_technique_mappings": [
            {"source": source, "technique_id": technique_id}
            for source, technique_id in removed
        ],
        "retained_mapping_regex_changes": [
            {
                "source": source,
                "technique_id": technique_id,
                "old_pattern": old_keys[(source, technique_id)].pattern.pattern,
                "new_pattern": new_keys[(source, technique_id)]["pattern"],
            }
            for source, technique_id in changed_regex
        ],
    }


def render_rule_specs(candidates: list[dict[str, Any]], sigma_commit: str) -> str:
    grouped: dict[str, list[dict[str, Any]]] = {platform: [] for platform in SOURCE_DIRS}
    for item in candidates:
        grouped[item["platform"]].append(
            {
                "technique_id": item["technique_id"],
                "source_path": item["source_path"],
                "rule_kwargs": {
                    "pattern": item["pattern"],
                    "technique_name": item["technique_name"],
                    "platform": item["platform"],
                    "confidence": item["confidence"],
                    "reason": item["reason"],
                    "source": item["citation"],
                    "parent_hint": item["parent_hint"],
                },
            }
        )
    rendered = pprint.pformat(grouped, width=120, sort_dicts=False)
    return (
        '"""Generated Card 5 step-2 Sigma rule specs — review preview only.\n\n'
        "This file is not imported by the runtime. Regenerate it with full_recompile.py.\n"
        '"""\n\n'
        f"SIGMA_COMMIT = {sigma_commit!r}\n"
        f"PYSIGMA_VERSION = {importlib.metadata.version('pysigma')!r}\n\n"
        f"RULE_SPECS_BY_PLATFORM = {rendered}\n"
    )


def build_report(
    candidates: list[dict[str, Any]],
    review: list[dict[str, Any]],
    inventory: dict[str, Any],
    diff_summary: dict[str, Any],
    sigma_commit: str,
) -> dict[str, Any]:
    unique_by_platform = {
        platform: len(
            {item["technique_id"] for item in candidates if item["platform"] == platform}
        )
        for platform in SOURCE_DIRS
    }
    return {
        "checkpoint": "Card 5 Part 1 roadmap step 2 only",
        "projection_notes": [
            "No generated candidate has been imported by the runtime or merged into mappings.py.",
            "All source directories are loaded through pySigma from one pinned Sigma commit.",
            "Genuinely multi-technique and untagged rules are retained in needs_review.",
            (
                "Field-null, field-reference, CIDR, and all-wildcard predicates are review-blocked "
                "rather than projected with changed semantics."
            ),
        ],
        "pysigma_version": importlib.metadata.version("pysigma"),
        "sigma_commit": sigma_commit,
        "source_directories": SOURCE_DIRS,
        "inventory": inventory,
        "mapping_candidate_count": len(candidates),
        "needs_review_count": len(review),
        "unique_candidate_technique_ids": len(
            {item["technique_id"] for item in candidates}
        ),
        "unique_candidate_technique_ids_by_platform": unique_by_platform,
        "diff_against_current_mappings": diff_summary,
        "mapping_candidates": candidates,
        "needs_review": review,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigma-root", required=True, type=Path)
    parser.add_argument("--sigma-commit", required=True)
    parser.add_argument("--techniques", required=True, type=Path)
    parser.add_argument("--relationships", required=True, type=Path)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--rule-specs", type=Path, default=DEFAULT_SPECS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    catalog = TechniqueCatalog(args.techniques, args.relationships)
    candidates, review, inventory = compile_full_rules(
        args.sigma_root, args.sigma_commit, catalog
    )
    mappings = _load_current_mappings(args.techniques)
    diff_summary = build_diff_summary(candidates, mappings, catalog)
    report = build_report(
        candidates, review, inventory, diff_summary, args.sigma_commit
    )
    args.report.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    args.rule_specs.write_text(
        render_rule_specs(candidates, args.sigma_commit), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "inventory": inventory,
                "mapping_candidate_count": len(candidates),
                "needs_review_count": len(review),
                "unique_candidate_technique_ids": report[
                    "unique_candidate_technique_ids"
                ],
                "unique_candidate_technique_ids_by_platform": report[
                    "unique_candidate_technique_ids_by_platform"
                ],
                "diff_against_current_mappings": {
                    key: value
                    for key, value in diff_summary.items()
                    if not isinstance(value, list)
                },
                "report": str(args.report),
                "rule_specs": str(args.rule_specs),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
