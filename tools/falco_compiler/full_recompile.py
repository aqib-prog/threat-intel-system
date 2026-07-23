#!/usr/bin/env python3
"""Card 5 Part 1, roadmap step 4: full Falco compilation preview."""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import pprint
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from prototype import (
    And,
    CompileError,
    Definitions,
    Macro,
    Not,
    Or,
    Predicate,
    compile_expression,
    constant_value,
    expression_to_dict,
    load_documents,
    parse_condition,
    verify_commit,
)


HERE = Path(__file__).resolve().parent
DEFAULT_MAPPING_MANIFEST = HERE / "full_mapping_manifest.json"
DEFAULT_VALIDATION_MANIFEST = HERE / "full_validation_manifest.json"
DEFAULT_MEDIUM_AUDIT = HERE / "medium_fit_mitre_audit.json"
DEFAULT_REPORT = HERE / "full_recompile_report.json"
DEFAULT_SPECS = HERE / "full_rule_specs.py"
DEFAULT_TABLE = HERE / "full_mapping_table.md"
DEFAULT_MEDIUM_AUDIT_TABLE = HERE / "medium_fit_mitre_audit.md"
SOURCE_FILES = {
    "kubernetes": "plugins/k8saudit/rules/k8s_audit_rules.yaml",
    "aws": "plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml",
}
CHECKPOINT_RUNTIME_LISTS = (
    "WINDOWS_RULES",
    "WINDOWS_SIGMA_RULES",
    "WINDOWS_SIGMA_EXPANSION_RULES",
    "LINUX_RULES",
    "LINUX_SIGMA_RULES",
    "AWS_RULES",
    "AWS_SIGMA_RULES",
    "KUBERNETES_RULES",
    "MACOS_RULES",
    "MACOS_SIGMA_RULES",
    "MACOS_SIGMA_EXPANSION_RULES",
)


class TechniqueCatalog:
    def __init__(self, techniques_path: Path, relationships_path: Path):
        techniques = json.loads(techniques_path.read_text(encoding="utf-8"))
        relationships = json.loads(relationships_path.read_text(encoding="utf-8"))
        self.by_id = {item["external_id"].upper(): item for item in techniques}
        self.by_stix = {item["id"]: item for item in techniques}
        self.by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in techniques:
            self.by_name[item["name"]].append(item)
        self.parent_by_child = {
            relation["source_ref"]: relation["target_ref"]
            for relation in relationships
            if relation["relationship_type"] == "subtechnique-of"
        }

    def resolve(self, technique_id: str) -> dict[str, Any]:
        try:
            item = self.by_id[technique_id.upper()]
        except KeyError as exc:
            raise CompileError(f"unknown ATT&CK technique {technique_id}") from exc
        parent_hint = None
        if len(self.by_name[item["name"]]) > 1:
            parent_stix = self.parent_by_child.get(item["id"])
            parent = self.by_stix.get(parent_stix or "")
            if not parent:
                raise CompileError(
                    f"duplicate ATT&CK name {item['name']!r} lacks a parent hint"
                )
            parent_hint = parent["name"]
        return {
            "technique_id": technique_id.upper(),
            "technique_name": item["name"],
            "technique_platforms": item.get("platforms", []),
            "parent_hint": parent_hint,
            "attack_url": "https://attack.mitre.org/techniques/"
            + technique_id.upper().replace(".", "/")
            + "/",
        }

    def current_rule_ids(self, technique_name: str, parent_hint: str | None) -> list[str]:
        items = self.by_name.get(technique_name, [])
        if len(items) <= 1:
            return [item["external_id"].upper() for item in items]
        if parent_hint is None:
            return []
        resolved: list[str] = []
        for item in items:
            parent = self.by_stix.get(self.parent_by_child.get(item["id"], ""))
            if parent and parent["name"] == parent_hint:
                resolved.append(item["external_id"].upper())
        return resolved


def priority_confidence(priority: str) -> str:
    return {
        "EMERGENCY": "high",
        "ALERT": "high",
        "CRITICAL": "high",
        "ERROR": "high",
        "WARNING": "medium",
        "NOTICE": "medium",
        "INFORMATIONAL": "low",
        "INFO": "low",
        "DEBUG": "low",
    }.get(priority.upper(), "low")


def load_source_rules(falco_root: Path) -> dict[str, tuple[dict[str, Any], Definitions]]:
    result: dict[str, tuple[dict[str, Any], Definitions]] = {}
    for platform, source_file in SOURCE_FILES.items():
        documents = load_documents(falco_root / source_file)
        definitions = Definitions(documents)
        for item in documents:
            if "rule" not in item:
                continue
            if item["rule"] in result:
                raise CompileError(f"duplicate Falco rule name {item['rule']!r}")
            result[item["rule"]] = (item, definitions)
    return result


def compile_all(
    falco_root: Path,
    mapping_manifest: dict[str, Any],
    catalog: TechniqueCatalog,
) -> list[dict[str, Any]]:
    verify_commit(falco_root, mapping_manifest["falco_commit"])
    source_rules = load_source_rules(falco_root)
    mappings = mapping_manifest["mappings"]
    if len(source_rules) != 70 or len(mappings) != 70:
        raise CompileError(
            f"step-4 corpus must contain 70 source rules and mappings, got "
            f"{len(source_rules)} and {len(mappings)}"
        )
    mapping_by_rule = {item["rule"]: item for item in mappings}
    if len(mapping_by_rule) != len(mappings):
        raise CompileError("mapping manifest contains duplicate rule names")
    if set(mapping_by_rule) != set(source_rules):
        raise CompileError(
            f"mapping/source mismatch: missing={sorted(set(source_rules)-set(mapping_by_rule))}, "
            f"extra={sorted(set(mapping_by_rule)-set(source_rules))}"
        )

    compiled: list[dict[str, Any]] = []
    for rule_name, (source_rule, definitions) in source_rules.items():
        mapping = mapping_by_rule[rule_name]
        platform = mapping["platform"]
        expected_file = SOURCE_FILES.get(platform)
        if expected_file is None:
            raise CompileError(f"{rule_name}: invalid platform {platform!r}")
        source_file = next(
            path for path in SOURCE_FILES.values()
            if (falco_root / path).is_file()
            and any(
                item.get("rule") == rule_name
                for item in load_documents(falco_root / path)
            )
        )
        if source_file != expected_file:
            raise CompileError(f"{rule_name}: mapping platform points at wrong source file")

        original = str(source_rule["condition"]).strip()
        expanded = definitions.expand(parse_condition(original))
        pattern = r"\A" + compile_expression(expanded) + r"[\s\S]*\Z"
        re.compile(pattern, re.IGNORECASE)
        constant = constant_value(expanded)
        source_enabled = source_rule.get("enabled", True) is not False
        effectively_enabled = source_enabled and constant is not False
        decision = mapping["decision"]
        if (decision == "source_disabled") == effectively_enabled:
            raise CompileError(
                f"{rule_name}: decision {decision!r} disagrees with source enabled/constant state"
            )
        if decision == "mapping_candidate" and not mapping.get("technique_id"):
            raise CompileError(f"{rule_name}: mapping candidate lacks a technique")
        if decision == "mapping_candidate" and mapping.get("mapping_confidence") not in {
            "high",
            "medium",
        }:
            raise CompileError(f"{rule_name}: low-confidence mapping cannot be a candidate")

        attack = None
        if mapping.get("technique_id"):
            attack = catalog.resolve(mapping["technique_id"])
            required_platforms = (
                {"Containers"}
                if platform == "kubernetes"
                else {"IaaS", "SaaS", "Containers"}
            )
            if not required_platforms.intersection(attack["technique_platforms"]):
                raise CompileError(
                    f"{rule_name}: {attack['technique_id']} is not valid for {platform}"
                )

        compiled.append(
            {
                "rule": rule_name,
                "source_file": source_file,
                "platform": platform,
                "description": str(source_rule["desc"]).strip(),
                "priority": str(source_rule["priority"]),
                "falco_source": str(source_rule["source"]),
                "source_enabled": source_enabled,
                "constant_value": constant,
                "effectively_enabled": effectively_enabled,
                "decision": decision,
                "mapping_confidence": mapping.get("mapping_confidence"),
                "mapping_rationale": mapping["rationale"],
                "attack": attack,
                "original_condition": original,
                "expanded_condition_tree": expression_to_dict(expanded),
                "pattern": pattern,
            }
        )
    return sorted(compiled, key=lambda item: (item["platform"], item["rule"]))


def validate_samples(
    compiled: list[dict[str, Any]], validation_manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    by_name = {item["rule"]: item for item in compiled}
    results: list[dict[str, Any]] = []
    for sample in validation_manifest["samples"]:
        rule = by_name[sample["rule"]]
        regex = re.compile(rule["pattern"], re.IGNORECASE)
        positive = json.dumps(sample["positive"], separators=(",", ":"))
        negative = json.dumps(sample["negative"], separators=(",", ":"))
        positive_passed = regex.search(positive) is not None
        negative_passed = regex.search(negative) is None
        results.append(
            {
                "rule": sample["rule"],
                "positive_passed": positive_passed,
                "negative_passed": negative_passed,
                "status": "pass" if positive_passed and negative_passed else "fail",
            }
        )
    return results


def validate_medium_fit_audit(
    compiled: list[dict[str, Any]], audit_manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    """Fail closed if the direct-MITRE audit and mapping decisions diverge."""
    rows = audit_manifest["rows"]
    if len(rows) != 14:
        raise CompileError(f"medium-fit audit must contain 14 rows, found {len(rows)}")
    by_name = {item["rule"]: item for item in compiled}
    seen: set[str] = set()
    for row in rows:
        rule_name = row["rule"]
        if rule_name in seen:
            raise CompileError(f"duplicate medium-fit audit row: {rule_name}")
        seen.add(rule_name)
        try:
            compiled_rule = by_name[rule_name]
        except KeyError as exc:
            raise CompileError(f"unknown medium-fit audit rule: {rule_name}") from exc
        expected_url = "https://attack.mitre.org/techniques/" + row[
            "technique_id"
        ].replace(".", "/") + "/"
        if row["mitre_url"] != expected_url:
            raise CompileError(f"{rule_name}: audit does not link its direct MITRE page")
        expected_decision = {
            "retain_candidate": "mapping_candidate",
            "move_to_needs_review": "needs_review",
        }.get(row["outcome"])
        if expected_decision is None:
            raise CompileError(f"{rule_name}: unknown audit outcome {row['outcome']!r}")
        if compiled_rule["decision"] != expected_decision:
            raise CompileError(
                f"{rule_name}: audit requires {expected_decision}, "
                f"mapping has {compiled_rule['decision']}"
            )
        if not row["direct_mitre_finding"] or not row["limitation"]:
            raise CompileError(f"{rule_name}: audit evidence is incomplete")
    return rows


def _load_current_mappings(techniques_path: Path):
    backend_root = techniques_path.resolve().parents[2]
    if str(backend_root) not in sys.path:
        sys.path.insert(0, str(backend_root))
    return importlib.import_module("log_analysis.mappings")


def checkpoint_runtime_rules(mappings: Any) -> list[Any]:
    """Return the immutable pre-promotion inventory reviewed at step 4."""

    return [
        rule
        for list_name in CHECKPOINT_RUNTIME_LISTS
        for rule in getattr(mappings, list_name)
    ]


def current_coverage_ids(mappings: Any, catalog: TechniqueCatalog) -> set[str]:
    return coverage_ids(checkpoint_runtime_rules(mappings), catalog)


def coverage_ids(rules: list[Any], catalog: TechniqueCatalog) -> set[str]:
    result: set[str] = set()
    for rule in rules:
        ids = catalog.current_rule_ids(rule.technique_name, rule.parent_hint)
        if len(ids) == 1:
            result.add(ids[0])
    return result


def build_diff(
    compiled: list[dict[str, Any]], mappings: Any, catalog: TechniqueCatalog, sigma_report: Path
) -> dict[str, Any]:
    candidates = [item for item in compiled if item["decision"] == "mapping_candidate"]
    falco_ids = {item["attack"]["technique_id"] for item in candidates}
    checkpoint_rules = checkpoint_runtime_rules(mappings)
    current_ids = current_coverage_ids(mappings, catalog)
    result = {
        "runtime_changed": False,
        "current_total_rule_count": len(checkpoint_rules),
        "current_kubernetes_rule_count": len(mappings.KUBERNETES_RULES),
        "proposed_falco_candidate_count": len(candidates),
        "proposed_falco_candidate_by_platform": dict(
            sorted(Counter(item["platform"] for item in candidates).items())
        ),
        "unique_falco_candidate_technique_id_count": len(falco_ids),
        "current_unique_technique_id_count": len(current_ids),
        "current_plus_falco_unique_technique_id_count": len(current_ids | falco_ids),
        "current_plus_falco_unique_technique_id_delta": len(current_ids | falco_ids)
        - len(current_ids),
    }
    if sigma_report.is_file():
        sigma = json.loads(sigma_report.read_text(encoding="utf-8"))
        sigma_ids = {item["technique_id"] for item in sigma["mapping_candidates"]}
        preserved_rules = [
            rule
            for list_name in (
                "WINDOWS_RULES",
                "LINUX_RULES",
                "AWS_RULES",
                "KUBERNETES_RULES",
                "MACOS_RULES",
            )
            for rule in getattr(mappings, list_name)
        ]
        step2_ids = coverage_ids(preserved_rules, catalog) | sigma_ids
        combined_ids = step2_ids | falco_ids
        result.update(
            {
                "step2_sigma_preview_rule_count": sigma["diff_against_current_mappings"][
                    "proposed_total_rule_count"
                ],
                "combined_sigma_falco_preview_rule_count": sigma[
                    "diff_against_current_mappings"
                ]["proposed_total_rule_count"]
                + len(candidates),
                "step2_sigma_preview_unique_technique_id_count": len(step2_ids),
                "combined_sigma_falco_preview_unique_technique_id_count": len(combined_ids),
                "combined_unique_technique_id_delta_over_sigma": len(combined_ids)
                - len(step2_ids),
                "new_falco_technique_ids_over_sigma_preview": sorted(
                    falco_ids - step2_ids
                ),
            }
        )
    return result


def render_specs(compiled: list[dict[str, Any]], commit: str) -> str:
    specs = []
    for item in compiled:
        if item["decision"] != "mapping_candidate":
            continue
        attack = item["attack"]
        specs.append(
            {
                "rule": item["rule"],
                "source_file": item["source_file"],
                "technique_id": attack["technique_id"],
                "mapping_confidence": item["mapping_confidence"],
                "rule_kwargs": {
                    "pattern": item["pattern"],
                    "technique_name": attack["technique_name"],
                    "platform": item["platform"],
                    "confidence": priority_confidence(item["priority"]),
                    "reason": f"{item['description']} (Falco-sourced).",
                    "source": f"Falco: {item['rule']}",
                    "parent_hint": attack["parent_hint"],
                },
            }
        )
    return (
        '"""Generated Card 5 step-4 Falco MappingRule specs — review only.\n\n'
        "This file is not imported by the runtime.\n"
        '"""\n\n'
        f"FALCO_COMMIT = {commit!r}\n\n"
        f"RULE_SPECS = {pprint.pformat(specs, width=120, sort_dicts=False)}\n"
    )


def render_mapping_table(compiled: list[dict[str, Any]], commit: str) -> str:
    lines = [
        "# Card 5 step-4 Falco → ATT&CK mapping review",
        "",
        f"Pinned Falco commit: `{commit}`",
        "",
        "No row in this table has been merged into `mappings.py`.",
        "",
        "| Platform | Falco rule | Decision | Proposed ATT&CK | Fit | Rationale |",
        "|---|---|---|---|---|---|",
    ]
    for item in compiled:
        attack = item["attack"]
        technique = (
            f"[{attack['technique_id']}]({attack['attack_url']}) — {attack['technique_name']}"
            if attack
            else "—"
        )
        values = [
            item["platform"],
            item["rule"],
            item["decision"],
            technique,
            item["mapping_confidence"] or "—",
            item["mapping_rationale"],
        ]
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in values) + " |")
    return "\n".join(lines) + "\n"


def render_medium_audit_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Step 4 medium-fit direct MITRE audit",
        "",
        "This is the targeted 14-row audit requested after the first step-4 checkpoint. "
        "Each finding was checked against the linked official MITRE ATT&CK technique page.",
        "",
        "| Rule | Technique reviewed | Direct MITRE finding | Outcome | Limitation |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        technique = f"[{row['technique_id']}]({row['mitre_url']})"
        values = (
            row["rule"],
            technique,
            row["direct_mitre_finding"],
            row["outcome"],
            row["limitation"],
        )
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in values) + " |")
    return "\n".join(lines) + "\n"


def build_report(
    compiled: list[dict[str, Any]],
    validation: list[dict[str, Any]],
    medium_fit_audit: list[dict[str, Any]],
    diff: dict[str, Any],
    commit: str,
) -> dict[str, Any]:
    return {
        "checkpoint": "Card 5 Part 1 roadmap step 4 only",
        "falco_commit": commit,
        "inventory": {
            "input_rule_count": len(compiled),
            "input_by_platform": dict(
                sorted(Counter(item["platform"] for item in compiled).items())
            ),
            "compiled_pattern_count": len(compiled),
            "effectively_enabled_count": sum(item["effectively_enabled"] for item in compiled),
            "source_disabled_count": sum(
                item["decision"] == "source_disabled" for item in compiled
            ),
            "mapping_candidate_count": sum(
                item["decision"] == "mapping_candidate" for item in compiled
            ),
            "needs_review_count": sum(item["decision"] == "needs_review" for item in compiled),
            "decision_by_platform": {
                platform: dict(
                    sorted(
                        Counter(
                            item["decision"]
                            for item in compiled
                            if item["platform"] == platform
                        ).items()
                    )
                )
                for platform in SOURCE_FILES
            },
        },
        "projection_notes": [
            "All 70 source rules are compiled and accounted for; no rule is silently discarded.",
            "Source-disabled and constant-false rules retain compiled output but emit no MappingRule candidate.",
            "Low-confidence or behaviorally ambiguous ATT&CK mappings remain in needs_review.",
            "All 14 medium-fit rows received a direct official-MITRE-page scope audit.",
            "No generated Falco rule is imported by the runtime or merged into mappings.py.",
            "Raw-JSON projection remains a Layer-1 approximation; Layer 2 owns canonical field extraction.",
        ],
        "validation": validation,
        "medium_fit_mitre_audit": medium_fit_audit,
        "diff_against_current_mappings": diff,
        "rules": compiled,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--falco-root", required=True, type=Path)
    parser.add_argument("--techniques", required=True, type=Path)
    parser.add_argument("--relationships", required=True, type=Path)
    parser.add_argument("--mapping-manifest", type=Path, default=DEFAULT_MAPPING_MANIFEST)
    parser.add_argument("--validation-manifest", type=Path, default=DEFAULT_VALIDATION_MANIFEST)
    parser.add_argument("--medium-audit", type=Path, default=DEFAULT_MEDIUM_AUDIT)
    parser.add_argument("--sigma-report", type=Path, default=HERE.parent / "sigma_compiler" / "full_recompile_report.json")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--rule-specs", type=Path, default=DEFAULT_SPECS)
    parser.add_argument("--mapping-table", type=Path, default=DEFAULT_TABLE)
    parser.add_argument("--medium-audit-table", type=Path, default=DEFAULT_MEDIUM_AUDIT_TABLE)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    mapping_manifest = json.loads(args.mapping_manifest.read_text(encoding="utf-8"))
    validation_manifest = json.loads(args.validation_manifest.read_text(encoding="utf-8"))
    medium_audit_manifest = json.loads(args.medium_audit.read_text(encoding="utf-8"))
    catalog = TechniqueCatalog(args.techniques, args.relationships)
    compiled = compile_all(args.falco_root, mapping_manifest, catalog)
    validation = validate_samples(compiled, validation_manifest)
    if not all(item["status"] == "pass" for item in validation):
        raise CompileError("one or more full-corpus validation samples failed")
    medium_fit_audit = validate_medium_fit_audit(compiled, medium_audit_manifest)
    mappings = _load_current_mappings(args.techniques)
    diff = build_diff(compiled, mappings, catalog, args.sigma_report)
    report = build_report(
        compiled, validation, medium_fit_audit, diff, mapping_manifest["falco_commit"]
    )
    args.report.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    args.rule_specs.write_text(
        render_specs(compiled, mapping_manifest["falco_commit"]), encoding="utf-8"
    )
    args.mapping_table.write_text(
        render_mapping_table(compiled, mapping_manifest["falco_commit"]),
        encoding="utf-8",
    )
    args.medium_audit_table.write_text(
        render_medium_audit_table(medium_fit_audit), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "inventory": report["inventory"],
                "validation": validation,
                "diff_against_current_mappings": diff,
                "report": str(args.report),
                "rule_specs": str(args.rule_specs),
                "mapping_table": str(args.mapping_table),
                "medium_audit_table": str(args.medium_audit_table),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
