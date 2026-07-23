#!/usr/bin/env python3
"""Generate the Step-6a technique/detection-strategy prototype.

The scope is intentionally narrow: active Enterprise techniques, their active
``detects`` relationship from an active DetectionStrategy, the strategy's
embedded ``x_mitre_analytic_refs``, and each analytic's embedded
``x_mitre_log_source_references`` to active DataComponent objects.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from generate_golden_set import (
    DEFAULT_MANIFEST,
    is_active,
    load_pinned_bundle,
    mitre_external_id,
    natural_list,
)


HERE = Path(__file__).resolve().parent
SELECTED_TECHNIQUE_IDS = (
    "T1078",      # Valid Accounts; multi-platform, five analytics.
    "T1053",      # Scheduled Task/Job; multi-platform, five analytics.
    "T1059.001",  # PowerShell; sub-technique, one analytic.
    "T1003.001",  # LSASS Memory; credential access, one analytic.
    "T1566.001",  # Spearphishing Attachment; three OS-specific analytics.
)
SCOPE = "active_detection_strategy_with_analytics_and_data_components"
METHODOLOGY_NOTE = (
    "DetectionStrategy-to-Technique is an active STIX detects relationship. "
    "DetectionStrategy-to-Analytic is represented by the strategy object's "
    "x_mitre_analytic_refs field. Analytic-to-DataComponent is represented by "
    "the analytic object's x_mitre_log_source_references field. Repeated log "
    "source rows are preserved in provenance, while expected data-component "
    "answers are deduplicated by DataComponent STIX ID."
)


class DetectionStrategyParserError(RuntimeError):
    """Raised when the scoped detection data is incomplete or inconsistent."""


def require_unique_external_ids(
    objects: list[dict[str, Any]], description: str
) -> dict[str, dict[str, Any]]:
    rows = [(mitre_external_id(obj), obj) for obj in objects]
    missing = [obj["id"] for external_id, obj in rows if external_id is None]
    if missing:
        raise DetectionStrategyParserError(
            f"active {description} objects lack MITRE external IDs: "
            + ", ".join(sorted(missing))
        )
    result = {external_id: obj for external_id, obj in rows if external_id}
    if len(result) != len(rows):
        raise DetectionStrategyParserError(
            f"active {description} objects have duplicate MITRE external IDs"
        )
    return result


def compact_technique(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "platforms": list(obj.get("x_mitre_platforms", [])),
    }


def compact_strategy(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
    }


def compact_component(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
    }


def compact_analytic(
    obj: dict[str, Any],
    data_components_by_stix: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    log_source_links = []
    for index, reference in enumerate(
        obj.get("x_mitre_log_source_references", [])
    ):
        if not isinstance(reference, dict):
            raise DetectionStrategyParserError(
                f"analytic {obj['id']} has a non-object log-source reference"
            )
        component_ref = reference.get("x_mitre_data_component_ref")
        if component_ref not in data_components_by_stix:
            raise DetectionStrategyParserError(
                f"analytic {obj['id']} references missing or inactive "
                f"DataComponent {component_ref}"
            )
        component = data_components_by_stix[component_ref]
        log_source_links.append(
            {
                "analytic_ref": obj["id"],
                "analytic_external_id": mitre_external_id(obj),
                "data_component_ref": component_ref,
                "data_component_external_id": mitre_external_id(component),
                "log_source_reference_index": index,
                "log_source_name": reference.get("name"),
                "log_source_channel": reference.get("channel"),
            }
        )
    component_ids = sorted(
        {link["data_component_ref"] for link in log_source_links},
        key=lambda stix_id: (
            mitre_external_id(data_components_by_stix[stix_id]) or "",
            stix_id,
        ),
    )
    return (
        {
            "stix_id": obj["id"],
            "external_id": mitre_external_id(obj),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "platforms": list(obj.get("x_mitre_platforms", [])),
            "data_components": [
                compact_component(data_components_by_stix[component_id])
                for component_id in component_ids
            ],
            "log_source_references": log_source_links,
        },
        log_source_links,
    )


def extract_detection_strategy_scope(
    bundle: dict[str, Any],
    technique_ids: tuple[str, ...] = SELECTED_TECHNIQUE_IDS,
) -> dict[str, Any]:
    if len(technique_ids) != len(set(technique_ids)):
        raise DetectionStrategyParserError("selected technique IDs are not unique")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise DetectionStrategyParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]

    active_technique_objects = [
        obj
        for obj in typed
        if obj.get("type") == "attack-pattern" and is_active(obj)
    ]
    active_strategy_objects = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-detection-strategy" and is_active(obj)
    ]
    active_analytic_objects = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-analytic" and is_active(obj)
    ]
    active_component_objects = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-data-component" and is_active(obj)
    ]
    techniques_by_external = require_unique_external_ids(
        active_technique_objects, "technique"
    )
    strategies_by_external = require_unique_external_ids(
        active_strategy_objects, "DetectionStrategy"
    )
    analytics_by_external = require_unique_external_ids(
        active_analytic_objects, "Analytic"
    )
    components_by_external = require_unique_external_ids(
        active_component_objects, "DataComponent"
    )
    strategies_by_stix = {obj["id"]: obj for obj in active_strategy_objects}
    analytics_by_stix = {obj["id"]: obj for obj in active_analytic_objects}
    components_by_stix = {obj["id"]: obj for obj in active_component_objects}
    active_technique_stix_ids = {obj["id"] for obj in active_technique_objects}

    missing_selected = [
        technique_id
        for technique_id in technique_ids
        if technique_id not in techniques_by_external
    ]
    if missing_selected:
        raise DetectionStrategyParserError(
            "selected active techniques are missing: "
            + ", ".join(missing_selected)
        )

    all_detects = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "detects"
    ]
    active_detects = [
        rel
        for rel in all_detects
        if is_active(rel)
        and rel.get("source_ref") in strategies_by_stix
        and rel.get("target_ref") in active_technique_stix_ids
    ]
    detects_by_technique: dict[str, list[dict[str, Any]]] = {}
    for rel in active_detects:
        detects_by_technique.setdefault(rel["target_ref"], []).append(rel)

    zero_strategy_techniques = [
        technique
        for technique in active_technique_objects
        if not detects_by_technique.get(technique["id"])
    ]
    multi_strategy_techniques = [
        technique
        for technique in active_technique_objects
        if len(detects_by_technique.get(technique["id"], [])) > 1
    ]

    strategy_analytic_ref_count = 0
    unique_referenced_analytics = set()
    for strategy in active_strategy_objects:
        analytic_refs = strategy.get("x_mitre_analytic_refs", [])
        if not isinstance(analytic_refs, list):
            raise DetectionStrategyParserError(
                f"strategy {strategy['id']} has invalid x_mitre_analytic_refs"
            )
        if len(analytic_refs) != len(set(analytic_refs)):
            raise DetectionStrategyParserError(
                f"strategy {strategy['id']} repeats an Analytic reference"
            )
        missing_analytics = [
            ref for ref in analytic_refs if ref not in analytics_by_stix
        ]
        if missing_analytics:
            raise DetectionStrategyParserError(
                f"strategy {strategy['id']} references missing or inactive "
                "Analytics: " + ", ".join(missing_analytics)
            )
        strategy_analytic_ref_count += len(analytic_refs)
        unique_referenced_analytics.update(analytic_refs)

    global_log_source_reference_count = 0
    global_analytic_component_pairs = set()
    for analytic in active_analytic_objects:
        _, links = compact_analytic(analytic, components_by_stix)
        global_log_source_reference_count += len(links)
        global_analytic_component_pairs.update(
            (link["analytic_ref"], link["data_component_ref"])
            for link in links
        )

    facts_by_technique = {}
    for technique_id in technique_ids:
        technique_obj = techniques_by_external[technique_id]
        relationships = detects_by_technique.get(technique_obj["id"], [])
        if len(relationships) != 1:
            raise DetectionStrategyParserError(
                f"selected technique {technique_id} has {len(relationships)} "
                "active DetectionStrategy links; expected exactly one"
            )
        detects_relationship = relationships[0]
        strategy_obj = strategies_by_stix[detects_relationship["source_ref"]]
        analytic_refs = strategy_obj.get("x_mitre_analytic_refs", [])
        analytics = []
        all_log_source_links = []
        strategy_analytic_links = []
        for analytic_ref in analytic_refs:
            analytic_obj = analytics_by_stix[analytic_ref]
            compacted, log_source_links = compact_analytic(
                analytic_obj, components_by_stix
            )
            analytics.append(compacted)
            all_log_source_links.extend(log_source_links)
            strategy_analytic_links.append(
                {
                    "strategy_ref": strategy_obj["id"],
                    "analytic_ref": analytic_ref,
                    "analytic_external_id": mitre_external_id(analytic_obj),
                    "source_field": "x_mitre_analytic_refs",
                }
            )
        analytics.sort(key=lambda row: (row["external_id"] or "", row["stix_id"]))
        strategy_analytic_links.sort(
            key=lambda row: (row["analytic_external_id"] or "", row["analytic_ref"])
        )
        component_ids = sorted(
            {link["data_component_ref"] for link in all_log_source_links},
            key=lambda stix_id: (
                mitre_external_id(components_by_stix[stix_id]) or "",
                stix_id,
            ),
        )
        all_log_source_links.sort(
            key=lambda row: (
                row["analytic_external_id"] or "",
                row["data_component_external_id"] or "",
                row["log_source_reference_index"],
            )
        )
        facts_by_technique[technique_id] = {
            "technique": compact_technique(technique_obj),
            "detection_strategy": compact_strategy(strategy_obj),
            "detects_relationship_stix_id": detects_relationship["id"],
            "analytics": analytics,
            "data_components": [
                compact_component(components_by_stix[component_id])
                for component_id in component_ids
            ],
            "strategy_analytic_links": strategy_analytic_links,
            "analytic_data_component_links": all_log_source_links,
        }

    return {
        "facts_by_technique": facts_by_technique,
        "global_coverage": {
            "active_technique_count": len(active_technique_objects),
            "active_detection_strategy_count": len(active_strategy_objects),
            "active_detects_relationship_count": len(active_detects),
            "techniques_with_zero_detection_strategies": len(
                zero_strategy_techniques
            ),
            "techniques_with_multiple_detection_strategies": len(
                multi_strategy_techniques
            ),
            "active_analytic_count": len(analytics_by_external),
            "strategy_analytic_reference_count": strategy_analytic_ref_count,
            "distinct_strategy_referenced_analytic_count": len(
                unique_referenced_analytics
            ),
            "unreferenced_active_analytic_count": (
                len(active_analytic_objects) - len(unique_referenced_analytics)
            ),
            "active_data_component_count": len(components_by_external),
            "analytic_log_source_reference_count": (
                global_log_source_reference_count
            ),
            "distinct_analytic_data_component_pair_count": len(
                global_analytic_component_pairs
            ),
        },
        "extraction_audit": {
            "bundle_detects_relationship_count": len(all_detects),
            "inactive_or_dangling_detects_relationship_count": (
                len(all_detects) - len(active_detects)
            ),
            "selected_technique_count": len(technique_ids),
        },
    }


def technique_label(technique: dict[str, Any]) -> str:
    return f"{technique['external_id']} ({technique['name']})"


def strategy_label(strategy: dict[str, Any]) -> str:
    return f"{strategy['external_id']} ({strategy['name']})"


def analytic_label(analytic: dict[str, Any]) -> str:
    return f"{analytic['external_id']} ({analytic['name']})"


def component_label(component: dict[str, Any]) -> str:
    return f"{component['external_id']} ({component['name']})"


def provenance(fact: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "technique_stix_id": fact["technique"]["stix_id"],
        "detection_strategy_stix_id": fact["detection_strategy"]["stix_id"],
        "detects_relationship_stix_id": fact[
            "detects_relationship_stix_id"
        ],
        "analytic_stix_ids": [row["stix_id"] for row in fact["analytics"]],
        "data_component_stix_ids": [
            row["stix_id"] for row in fact["data_components"]
        ],
        "strategy_analytic_links": fact["strategy_analytic_links"],
        "analytic_data_component_links": fact[
            "analytic_data_component_links"
        ],
    }


def generate_prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    pairs = []
    for technique_id in SELECTED_TECHNIQUE_IDS:
        fact = extracted["facts_by_technique"][technique_id]
        technique = fact["technique"]
        strategy = fact["detection_strategy"]
        analytics = fact["analytics"]
        components = fact["data_components"]
        if not analytics:
            raise DetectionStrategyParserError(
                f"selected strategy {strategy['external_id']} has no Analytics"
            )
        if not components:
            raise DetectionStrategyParserError(
                f"selected strategy {strategy['external_id']} has no DataComponents"
            )
        shared = {
            "relationship_type": "technique_detection_strategy",
            "technique": technique,
            "expected_detection_strategy": strategy,
            "expected_analytics": analytics,
            "expected_data_components": components,
            "provenance": provenance(fact, source),
        }
        pairs.append(
            {
                "id": f"technique-detection-strategy-{technique_id.lower()}",
                "case_type": "aggregate_technique_detection_strategy",
                "question": f"How is {technique_label(technique)} detected?",
                "expected_answer": (
                    f"{technique_label(technique)} is detected by "
                    f"{strategy_label(strategy)}. Its active analytics are "
                    f"{natural_list([analytic_label(row) for row in analytics])}."
                ),
                **shared,
            }
        )
        pairs.append(
            {
                "id": f"technique-detection-components-{technique_id.lower()}",
                "case_type": "aggregate_technique_detection_components",
                "question": (
                    "Which data components support detection of "
                    f"{technique_label(technique)}?"
                ),
                "expected_answer": (
                    f"The analytics under {strategy_label(strategy)} use "
                    f"{natural_list([component_label(row) for row in components])} "
                    f"to detect {technique_label(technique)} in the pinned "
                    "Enterprise ATT&CK snapshot."
                ),
                **shared,
            }
        )
    if len(pairs) != 10:
        raise DetectionStrategyParserError(
            f"expected 10 prototype pairs, generated {len(pairs)}"
        )
    return pairs


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    coverage = extracted["global_coverage"]
    negative_available = (
        coverage["techniques_with_zero_detection_strategies"] > 0
    )
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_step_6a_detection_strategy_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "x-mitre-detection-strategy",
            "target_type": "attack-pattern",
            "relationship_type": "detects",
            "embedded_child_types": [
                "x-mitre-analytic",
                "x-mitre-data-component",
            ],
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "technique_external_ids": list(SELECTED_TECHNIQUE_IDS),
            "technique_count": len(SELECTED_TECHNIQUE_IDS),
            "pair_count": len(pairs),
            "strategy_and_analytic_pairs": sum(
                pair["case_type"]
                == "aggregate_technique_detection_strategy"
                for pair in pairs
            ),
            "data_component_pairs": sum(
                pair["case_type"]
                == "aggregate_technique_detection_components"
                for pair in pairs
            ),
            "negative_zero_strategy_pair_included": negative_available,
            "negative_zero_strategy_pair_omission_reason": (
                None
                if negative_available
                else "All 697 active Enterprise techniques have one active "
                "DetectionStrategy in the pinned snapshot; no honest negative "
                "case exists."
            ),
        },
        "global_coverage": coverage,
        "extraction_audit": extracted["extraction_audit"],
        "parsed_data": extracted["facts_by_technique"],
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "golden_set_technique_detection_strategy_prototype.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    extracted = extract_detection_strategy_scope(bundle)
    payload = prototype_payload(extracted, source)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "source": source,
                "artifact": {
                    "output": str(args.output),
                    "selection": payload["selection"],
                },
                "global_coverage": payload["global_coverage"],
                "selected": {
                    technique_id: {
                        "strategy": fact["detection_strategy"],
                        "analytic_count": len(fact["analytics"]),
                        "data_component_count": len(fact["data_components"]),
                        "log_source_reference_count": len(
                            fact["analytic_data_component_links"]
                        ),
                    }
                    for technique_id, fact in payload["parsed_data"].items()
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DetectionStrategyParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
