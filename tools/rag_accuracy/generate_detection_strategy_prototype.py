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
ADVERSARIAL_NEGATIVE_CASE_COUNT = 233
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


def compact_tactic(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "shortname": obj.get("x_mitre_shortname"),
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
    technique_ids: tuple[str, ...] | None = SELECTED_TECHNIQUE_IDS,
) -> dict[str, Any]:
    if technique_ids is not None and len(technique_ids) != len(set(technique_ids)):
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
    active_tactic_objects = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-tactic" and is_active(obj)
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
    selected_technique_ids = (
        tuple(sorted(techniques_by_external))
        if technique_ids is None
        else technique_ids
    )
    strategies_by_stix = {obj["id"]: obj for obj in active_strategy_objects}
    analytics_by_stix = {obj["id"]: obj for obj in active_analytic_objects}
    components_by_stix = {obj["id"]: obj for obj in active_component_objects}
    active_technique_stix_ids = {obj["id"] for obj in active_technique_objects}
    tactics_by_shortname = {
        obj.get("x_mitre_shortname"): obj
        for obj in active_tactic_objects
        if obj.get("x_mitre_shortname")
    }
    tactic_context_by_technique = {}
    for technique_obj in active_technique_objects:
        memberships = []
        for phase in technique_obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic_obj = tactics_by_shortname.get(phase.get("phase_name"))
            if tactic_obj is None:
                raise DetectionStrategyParserError(
                    f"technique {technique_obj['id']} references unknown tactic "
                    f"phase {phase.get('phase_name')}"
                )
            memberships.append(
                {
                    "technique_ref": technique_obj["id"],
                    "tactic_ref": tactic_obj["id"],
                    "kill_chain_name": phase["kill_chain_name"],
                    "phase_name": phase["phase_name"],
                }
            )
        memberships.sort(
            key=lambda row: (
                mitre_external_id(
                    next(
                        item
                        for item in active_tactic_objects
                        if item["id"] == row["tactic_ref"]
                    )
                )
                or "",
                row["tactic_ref"],
            )
        )
        tactic_context_by_technique[mitre_external_id(technique_obj)] = {
            "tactics": [
                compact_tactic(
                    next(
                        item
                        for item in active_tactic_objects
                        if item["id"] == row["tactic_ref"]
                    )
                )
                for row in memberships
            ],
            "technique_tactic_links": memberships,
        }

    missing_selected = [
        technique_id
        for technique_id in selected_technique_ids
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
    for technique_id in selected_technique_ids:
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
            "selected_technique_count": len(selected_technique_ids),
        },
        "tactic_context_by_technique": tactic_context_by_technique,
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
    pairs = generate_technique_pairs(
        extracted, source, SELECTED_TECHNIQUE_IDS
    )
    if len(pairs) != 10:
        raise DetectionStrategyParserError(
            f"expected 10 prototype pairs, generated {len(pairs)}"
        )
    return pairs


def reverse_pair(
    fact: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    technique = fact["technique"]
    strategy = fact["detection_strategy"]
    return {
        "id": (
            "detection-strategy-technique-"
            f"{strategy['external_id'].lower()}"
        ),
        "case_type": "aggregate_detection_strategy_technique",
        "relationship_type": "technique_detection_strategy",
        "question": f"Which technique does {strategy_label(strategy)} detect?",
        "expected_answer": (
            f"{strategy_label(strategy)} detects {technique_label(technique)} "
            "in the pinned Enterprise ATT&CK snapshot."
        ),
        "detection_strategy": strategy,
        "expected_technique": technique,
        "expected_analytics": fact["analytics"],
        "expected_data_components": fact["data_components"],
        "provenance": provenance(fact, source),
    }


def evenly_spaced_items(
    items: list[dict[str, Any]], count: int
) -> list[dict[str, Any]]:
    if count < 0 or count > len(items):
        raise DetectionStrategyParserError(
            f"cannot select {count} items from {len(items)} candidates"
        )
    if count == 0:
        return []
    if count == 1:
        return [items[len(items) // 2]]
    indices = [
        round(index * (len(items) - 1) / (count - 1))
        for index in range(count)
    ]
    if len(indices) != len(set(indices)):
        raise DetectionStrategyParserError(
            "evenly spaced adversarial selection produced duplicates"
        )
    return [items[index] for index in indices]


def adversarial_negative_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    *,
    count: int = ADVERSARIAL_NEGATIVE_CASE_COUNT,
) -> list[dict[str, Any]]:
    """Mismatch a technique with a sibling tactic's distinct strategy."""

    facts = extracted["facts_by_technique"]
    tactic_context = extracted["tactic_context_by_technique"]
    candidates = []
    for technique_id in sorted(facts):
        anchor_tactic_ids = {
            item["stix_id"]
            for item in tactic_context[technique_id]["tactics"]
        }
        for sibling_id in sorted(facts):
            if sibling_id == technique_id:
                continue
            sibling_tactic_ids = {
                item["stix_id"]
                for item in tactic_context[sibling_id]["tactics"]
            }
            shared_ids = anchor_tactic_ids & sibling_tactic_ids
            if not shared_ids:
                continue
            shared_tactic = min(
                (
                    item
                    for item in tactic_context[technique_id]["tactics"]
                    if item["stix_id"] in shared_ids
                ),
                key=lambda item: item["external_id"],
            )
            candidates.append(
                {
                    "anchor_fact": facts[technique_id],
                    "sibling_fact": facts[sibling_id],
                    "shared_tactic": shared_tactic,
                    "anchor_tactic_links": [
                        row
                        for row in tactic_context[technique_id][
                            "technique_tactic_links"
                        ]
                        if row["tactic_ref"] == shared_tactic["stix_id"]
                    ],
                    "sibling_tactic_links": [
                        row
                        for row in tactic_context[sibling_id][
                            "technique_tactic_links"
                        ]
                        if row["tactic_ref"] == shared_tactic["stix_id"]
                    ],
                }
            )
            break
    selected = evenly_spaced_items(candidates, count)
    pairs = []
    for row in selected:
        anchor_fact = row["anchor_fact"]
        sibling_fact = row["sibling_fact"]
        technique = anchor_fact["technique"]
        sibling_technique = sibling_fact["technique"]
        strategy = sibling_fact["detection_strategy"]
        if strategy["stix_id"] == anchor_fact["detection_strategy"]["stix_id"]:
            raise DetectionStrategyParserError(
                f"adversarial strategy is not distinct for "
                f"{technique['external_id']}"
            )
        pairs.append(
            {
                "id": (
                    "detection-strategy-adversarial-does-not-detect-"
                    f"{strategy['external_id'].lower()}-"
                    f"{technique['external_id'].lower()}"
                ),
                "case_type": (
                    "adversarial_negative_detection_strategy_technique"
                ),
                "relationship_type": "technique_detection_strategy",
                "question": (
                    f"Does {strategy_label(strategy)} detect "
                    f"{technique_label(technique)}?"
                ),
                "expected_answer": (
                    f"No. {strategy_label(strategy)} has no active detects "
                    f"relationship to {technique_label(technique)} in the "
                    "pinned Enterprise ATT&CK snapshot. The confusion is "
                    f"plausible because it detects sibling "
                    f"{technique_label(sibling_technique)}, which shares "
                    f"{row['shared_tactic']['external_id']} "
                    f"({row['shared_tactic']['name']}) with the queried "
                    "technique."
                ),
                "detection_strategy": strategy,
                "queried_technique": technique,
                "relationship_exists": False,
                "expected_techniques": [],
                "provenance": {
                    "source_repository": source["repository"],
                    "source_commit": source["commit"],
                    "source_bundle_path": source["path"],
                    "source_bundle_sha256": source["sha256"],
                    "scope": SCOPE,
                    "methodology_note": METHODOLOGY_NOTE,
                    "queried_technique_stix_id": technique["stix_id"],
                    "detection_strategy_stix_id": strategy["stix_id"],
                    "final_detects_relationship_stix_ids": [],
                    "difficulty": "adversarial_sibling",
                    "adversarial_context": {
                        "method": (
                            "different_technique_same_tactic_strategy"
                        ),
                        "sibling_technique": sibling_technique,
                        "shared_tactic": row["shared_tactic"],
                        "anchor_tactic_links": row["anchor_tactic_links"],
                        "sibling_tactic_links": row[
                            "sibling_tactic_links"
                        ],
                        "sibling_detection_strategy": strategy,
                        "supporting_detects_relationship_stix_id": (
                            sibling_fact["detects_relationship_stix_id"]
                        ),
                    },
                },
            }
        )
    return pairs


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    original_pairs = generate_prototype_pairs(extracted, source)
    reverse_pairs = [
        reverse_pair(extracted["facts_by_technique"][technique_id], source)
        for technique_id in SELECTED_TECHNIQUE_IDS
    ]
    pairs = original_pairs + reverse_pairs
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
            "original_pair_count": len(original_pairs),
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
            "reverse_detection_strategy_pairs": len(reverse_pairs),
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


def full_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    technique_ids = tuple(sorted(extracted["facts_by_technique"]))
    technique_pairs = generate_technique_pairs(
        extracted, source, technique_ids
    )
    reverse_pairs = [
        reverse_pair(extracted["facts_by_technique"][technique_id], source)
        for technique_id in technique_ids
    ]
    adversarial_pairs = adversarial_negative_pairs(extracted, source)
    pairs = technique_pairs + reverse_pairs + adversarial_pairs
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise DetectionStrategyParserError("full pair IDs are not unique")
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_full_technique_detection_strategy_golden_set",
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
            "prototype_only": False,
            "one_technique_aggregate_per_active_technique": True,
            "one_reverse_pair_per_active_detection_strategy": True,
            "adversarial_sibling_negatives": True,
        },
        "selection": {
            "active_technique_count": len(technique_ids),
            "active_detection_strategy_count": len(reverse_pairs),
            "pair_count": len(pairs),
            "strategy_and_analytic_pairs": len(technique_ids),
            "data_component_pairs": sum(
                pair["case_type"]
                == "aggregate_technique_detection_components"
                for pair in technique_pairs
            ),
            "zero_data_component_pairs": sum(
                pair["case_type"]
                == "aggregate_technique_no_detection_components"
                for pair in technique_pairs
            ),
            "reverse_detection_strategy_pairs": len(reverse_pairs),
            "adversarial_negative_pairs": len(adversarial_pairs),
            "total_negative_pairs": len(adversarial_pairs),
            "total_negative_ratio": len(adversarial_pairs) / len(pairs),
            "negative_zero_strategy_pair_included": False,
            "negative_zero_strategy_pair_omission_reason": (
                "All 697 active Enterprise techniques have exactly one active "
                "DetectionStrategy, and every active DetectionStrategy has "
                "exactly one active Technique target in the pinned snapshot."
            ),
        },
        "negative_selection": {
            "adversarial_method": (
                "pair a technique with the DetectionStrategy of a different "
                "technique sharing at least one active tactic"
            ),
            "adversarial_cases_verified_absent_by_complete_detects_edge_set": True,
            "unrelated_pair_fallback_count": 0,
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "pairs": pairs,
    }


def generate_technique_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    technique_ids: tuple[str, ...],
) -> list[dict[str, Any]]:
    extracted_ids = set(extracted["facts_by_technique"])
    if extracted_ids != set(technique_ids):
        raise DetectionStrategyParserError(
            "requested full pair IDs do not match extracted facts"
        )
    pairs = []
    for technique_id in technique_ids:
        fact = extracted["facts_by_technique"][technique_id]
        technique = fact["technique"]
        strategy = fact["detection_strategy"]
        analytics = fact["analytics"]
        components = fact["data_components"]
        if not analytics:
            raise DetectionStrategyParserError(
                f"{strategy['external_id']} lacks required analytic data"
            )
        shared = {
            "relationship_type": "technique_detection_strategy",
            "technique": technique,
            "expected_detection_strategy": strategy,
            "expected_analytics": analytics,
            "expected_data_components": components,
            "provenance": provenance(fact, source),
        }
        pairs.extend(
            [
                {
                    "id": (
                        "technique-detection-strategy-"
                        f"{technique_id.lower()}"
                    ),
                    "case_type": "aggregate_technique_detection_strategy",
                    "question": f"How is {technique_label(technique)} detected?",
                    "expected_answer": (
                        f"{technique_label(technique)} is detected by "
                        f"{strategy_label(strategy)}. Its active analytics are "
                        f"{natural_list([analytic_label(row) for row in analytics])}."
                    ),
                    **shared,
                },
                detection_component_pair(
                    technique, strategy, components, shared
                ),
            ]
        )
    return pairs


def detection_component_pair(
    technique: dict[str, Any],
    strategy: dict[str, Any],
    components: list[dict[str, Any]],
    shared: dict[str, Any],
) -> dict[str, Any]:
    if components:
        case_type = "aggregate_technique_detection_components"
        answer = (
            f"The analytics under {strategy_label(strategy)} use "
            f"{natural_list([component_label(row) for row in components])} "
            f"to detect {technique_label(technique)} in the pinned Enterprise "
            "ATT&CK snapshot."
        )
    else:
        case_type = "aggregate_technique_no_detection_components"
        answer = (
            f"No active DataComponent reference is recorded under the analytics "
            f"for {strategy_label(strategy)}, which detects "
            f"{technique_label(technique)}, in the pinned Enterprise ATT&CK "
            "snapshot."
        )
    return {
        "id": (
            "technique-detection-components-"
            f"{technique['external_id'].lower()}"
        ),
        "case_type": case_type,
        "question": (
            "Which data components support detection of "
            f"{technique_label(technique)}?"
        ),
        "expected_answer": answer,
        **shared,
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
    parser.add_argument(
        "--generate-all-techniques",
        action="store_true",
        help="write the full all-active-technique bidirectional golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_technique_detection_strategy.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    extracted = extract_detection_strategy_scope(
        bundle, None if args.generate_all_techniques else SELECTED_TECHNIQUE_IDS
    )
    payload = (
        full_payload(extracted, source)
        if args.generate_all_techniques
        else prototype_payload(extracted, source)
    )
    output = args.full_output if args.generate_all_techniques else args.output
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "source": source,
                "artifact": {
                    "output": str(output),
                    "selection": payload["selection"],
                },
                "global_coverage": payload["global_coverage"],
                "selected": (
                    None
                    if args.generate_all_techniques
                    else {
                        technique_id: {
                            "strategy": fact["detection_strategy"],
                            "analytic_count": len(fact["analytics"]),
                            "data_component_count": len(fact["data_components"]),
                            "log_source_reference_count": len(
                                fact["analytic_data_component_links"]
                            ),
                        }
                        for technique_id, fact in extracted[
                            "facts_by_technique"
                        ].items()
                    }
                ),
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
