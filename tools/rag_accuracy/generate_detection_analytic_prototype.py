#!/usr/bin/env python3
"""Generate deterministic DetectionStrategy -[HAS_ANALYTIC]-> Analytic sets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from generate_detection_strategy_prototype import (
    DetectionStrategyParserError,
    analytic_label,
    compact_analytic,
    compact_strategy,
    require_unique_external_ids,
    strategy_label,
)
from generate_golden_set import (
    DEFAULT_MANIFEST,
    is_active,
    load_pinned_bundle,
    natural_list,
)
from generate_subtechnique_prototype import (
    SubtechniqueParserError,
    evenly_spaced_items,
)


HERE = Path(__file__).resolve().parent
SELECTED_STRATEGY_IDS = (
    "DET0039",
    "DET0094",
    "DET0460",
    "DET0560",
    "DET0001",
)
FOCUSED_ANALYTIC_BY_STRATEGY = {
    "DET0039": "AN0110",
    "DET0094": "AN0259",
    "DET0460": "AN1263",
    "DET0560": "AN1544",
    "DET0001": "AN0001",
}
NEGATIVE_ANALYTIC_BY_STRATEGY = {
    "DET0039": "AN0001",
    "DET0094": "AN0110",
    "DET0460": "AN1544",
    "DET0560": "AN1263",
    "DET0001": "AN0667",
}
FULL_ORPHAN_SAMPLE_COUNT = 5
FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT = 140
FULL_NEGATIVE_PROBE_ANALYTIC_IDS = (
    "AN0001",
    "AN0110",
    "AN0259",
    "AN1263",
    "AN1544",
    "AN0667",
    "AN0670",
    "AN0888",
    "AN0891",
    "AN0894",
)
PLATFORM_FILTER = "Linux"
SCOPE = "active_detection_strategy_embedded_analytic_references"
METHODOLOGY_NOTE = (
    "DetectionStrategy-to-Analytic links are read from each active Enterprise "
    "ATT&CK x-mitre-detection-strategy object's x_mitre_analytic_refs field; "
    "they are embedded references, not STIX relationship objects. Only active "
    "strategies and active analytics are included. Every linked analytic has at "
    "most one strategy parent. Strategy aggregation is exhaustive across all "
    "active strategies, and Linux filters apply to each child Analytic's own "
    "x_mitre_platforms field. Analytic-to-DataComponent references are out of "
    "scope for this golden set."
)
ORPHAN_SAMPLING_NOTE = (
    "Select five of the 13 active parentless analytics deterministically by "
    "taking evenly spaced entries from external-ID order. Five preserves an "
    "explicit no-parent case across the orphan ID range and platform shapes "
    "without disproportionately duplicating this small exceptional population."
)


class DetectionAnalyticParserError(DetectionStrategyParserError):
    """Raised when DetectionStrategy/Analytic data violates invariants."""


def compact_edge_analytic(
    obj: dict[str, Any],
    data_components_by_stix: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Reuse the established Analytic parser, retaining only edge-scope fields."""
    parsed, _ = compact_analytic(obj, data_components_by_stix)
    return {
        "stix_id": parsed["stix_id"],
        "external_id": parsed["external_id"],
        "name": parsed["name"],
        "platforms": sorted(set(parsed["platforms"])),
    }


def extract_detection_analytic_scope(bundle: dict[str, Any]) -> dict[str, Any]:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise DetectionAnalyticParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]
    strategy_objects = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-detection-strategy" and is_active(obj)
    ]
    analytic_objects = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-analytic" and is_active(obj)
    ]
    component_objects = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-data-component" and is_active(obj)
    ]
    strategy_objects_by_external = require_unique_external_ids(
        strategy_objects, "DetectionStrategy"
    )
    analytic_objects_by_external = require_unique_external_ids(
        analytic_objects, "Analytic"
    )
    require_unique_external_ids(component_objects, "DataComponent")
    analytic_objects_by_stix = {obj["id"]: obj for obj in analytic_objects}
    components_by_stix = {obj["id"]: obj for obj in component_objects}

    strategies = {
        external_id: compact_strategy(obj)
        for external_id, obj in strategy_objects_by_external.items()
    }
    analytics = {
        external_id: compact_edge_analytic(obj, components_by_stix)
        for external_id, obj in analytic_objects_by_external.items()
    }
    analytics_by_stix = {item["stix_id"]: item for item in analytics.values()}
    paths: list[dict[str, Any]] = []
    raw_reference_count = 0
    for strategy_external_id in sorted(strategy_objects_by_external):
        strategy_obj = strategy_objects_by_external[strategy_external_id]
        refs = strategy_obj.get("x_mitre_analytic_refs", [])
        if not isinstance(refs, list):
            raise DetectionAnalyticParserError(
                f"strategy {strategy_external_id} has non-list "
                "x_mitre_analytic_refs"
            )
        raw_reference_count += len(refs)
        if len(refs) != len(set(refs)):
            raise DetectionAnalyticParserError(
                f"strategy {strategy_external_id} has duplicate analytic refs"
            )
        for index, analytic_ref in enumerate(refs):
            if analytic_ref not in analytic_objects_by_stix:
                raise DetectionAnalyticParserError(
                    f"strategy {strategy_external_id} references missing or "
                    f"inactive Analytic {analytic_ref}"
                )
            analytic = analytics_by_stix[analytic_ref]
            paths.append(
                {
                    "detection_strategy_ref": strategy_obj["id"],
                    "detection_strategy_external_id": strategy_external_id,
                    "analytic_ref": analytic_ref,
                    "analytic_external_id": analytic["external_id"],
                    "source_field": "x_mitre_analytic_refs",
                    "source_field_index": index,
                }
            )
    paths.sort(
        key=lambda path: (
            path["detection_strategy_external_id"],
            path["analytic_external_id"],
            path["source_field_index"],
        )
    )
    pair_keys = {
        (path["detection_strategy_ref"], path["analytic_ref"])
        for path in paths
    }
    if len(pair_keys) != len(paths):
        raise DetectionAnalyticParserError(
            "multiple embedded references encode the same strategy/analytic pair"
        )

    paths_by_strategy: dict[str, list[dict[str, Any]]] = {}
    paths_by_analytic: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        paths_by_strategy.setdefault(path["detection_strategy_ref"], []).append(path)
        paths_by_analytic.setdefault(path["analytic_ref"], []).append(path)
    multi_parent = {
        analytic_ref: analytic_paths
        for analytic_ref, analytic_paths in paths_by_analytic.items()
        if len(analytic_paths) > 1
    }
    if multi_parent:
        raise DetectionAnalyticParserError(
            f"{len(multi_parent)} active analytics have multiple parents"
        )

    linked_analytic_ids = set(paths_by_analytic)
    orphans = sorted(
        [
            analytic
            for analytic in analytics.values()
            if analytic["stix_id"] not in linked_analytic_ids
        ],
        key=lambda item: (item["external_id"], item["stix_id"]),
    )
    strategy_rows = sorted(
        strategies.values(), key=lambda item: (item["external_id"], item["stix_id"])
    )
    analytic_rows = sorted(
        analytics.values(), key=lambda item: (item["external_id"], item["stix_id"])
    )
    linux_paths = [
        path
        for path in paths
        if PLATFORM_FILTER in analytics_by_stix[path["analytic_ref"]]["platforms"]
    ]
    strategies_with_linux = {
        path["detection_strategy_ref"] for path in linux_paths
    }
    strategies_without_analytics = [
        strategy
        for strategy in strategy_rows
        if strategy["stix_id"] not in paths_by_strategy
    ]
    return {
        "strategies": strategy_rows,
        "analytics": analytic_rows,
        "orphans": orphans,
        "paths": paths,
        "global_coverage": {
            "active_detection_strategy_count": len(strategy_rows),
            "active_analytic_count": len(analytic_rows),
            "active_strategy_analytic_link_count": len(paths),
            "active_linked_analytic_count": len(linked_analytic_ids),
            "active_orphan_analytic_count": len(orphans),
            "analytics_with_multiple_parents": len(multi_parent),
            "strategies_with_one_or_more_analytics": (
                len(strategy_rows) - len(strategies_without_analytics)
            ),
            "strategies_with_zero_analytics": len(strategies_without_analytics),
            "strategies_with_one_or_more_linux_analytics": len(
                strategies_with_linux
            ),
            "strategies_with_zero_linux_analytics": (
                len(strategy_rows) - len(strategies_with_linux)
            ),
            "linux_strategy_analytic_link_count": len(linux_paths),
        },
        "extraction_audit": {
            "raw_active_strategy_analytic_reference_count": raw_reference_count,
            "inactive_or_missing_analytic_reference_count": (
                raw_reference_count - len(paths)
            ),
            "duplicate_strategy_analytic_pair_count": len(paths) - len(pair_keys),
            "maximum_parent_count_per_active_analytic": max(
                (len(paths_by_analytic.get(item["stix_id"], [])) for item in analytic_rows),
                default=0,
            ),
        },
    }


def strategy_catalog(extracted: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["external_id"]: item for item in extracted["strategies"]}


def analytic_catalog(extracted: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["external_id"]: item for item in extracted["analytics"]}


def analytics_and_paths_for_strategy(
    strategy: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    analytics_by_stix = {item["stix_id"]: item for item in extracted["analytics"]}
    paths = [
        path
        for path in extracted["paths"]
        if path["detection_strategy_ref"] == strategy["stix_id"]
    ]
    analytic_ids = sorted(
        {path["analytic_ref"] for path in paths},
        key=lambda stix_id: (
            analytics_by_stix[stix_id]["external_id"],
            stix_id,
        ),
    )
    return [analytics_by_stix[item] for item in analytic_ids], paths


def strategy_and_path_for_analytic(
    analytic: dict[str, Any], extracted: dict[str, Any]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    strategies_by_stix = {
        item["stix_id"]: item for item in extracted["strategies"]
    }
    paths = [
        path for path in extracted["paths"] if path["analytic_ref"] == analytic["stix_id"]
    ]
    if len(paths) > 1:
        raise DetectionAnalyticParserError(
            f"expected at most one parent for {analytic['external_id']}, "
            f"found {len(paths)}"
        )
    if not paths:
        return None, None
    return strategies_by_stix[paths[0]["detection_strategy_ref"]], paths[0]


def edge_provenance(
    source: dict[str, Any],
    strategies: list[dict[str, Any]],
    analytics: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    *,
    queried_analytic: dict[str, Any] | None = None,
    platform_filter: str | None = None,
) -> dict[str, Any]:
    result = {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "detection_strategy_stix_ids": [item["stix_id"] for item in strategies],
        "analytic_stix_ids": [item["stix_id"] for item in analytics],
        "source_field": "x-mitre-detection-strategy.x_mitre_analytic_refs",
        "strategy_analytic_paths": paths,
    }
    if queried_analytic is not None:
        result["queried_analytic_stix_id"] = queried_analytic["stix_id"]
    if platform_filter is not None:
        result["platform_filter"] = platform_filter
        result["platform_source_field"] = "x-mitre-analytic.x_mitre_platforms"
        result["platform_applies_to"] = "child_analytic"
    return result


def parent_identification_pair(
    analytic: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    strategy, path = strategy_and_path_for_analytic(analytic, extracted)
    if strategy is None or path is None:
        return orphan_parent_identification_pair(analytic, extracted, source)
    return {
        "id": f"analytic-parent-strategy-{analytic['external_id'].lower()}",
        "case_type": "identify_analytic_detection_strategy",
        "relationship_type": "detection_strategy_has_analytic",
        "question": f"Which detection strategy does {analytic_label(analytic)} belong to?",
        "expected_answer": (
            f"{analytic_label(analytic)} belongs to {strategy_label(strategy)} "
            "in the pinned Enterprise ATT&CK snapshot."
        ),
        "analytic": analytic,
        "expected_detection_strategy": strategy,
        "provenance": edge_provenance(
            source, [strategy], [analytic], [path], queried_analytic=analytic
        ),
    }


def orphan_parent_identification_pair(
    analytic: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    strategy, path = strategy_and_path_for_analytic(analytic, extracted)
    if strategy is not None or path is not None:
        raise DetectionAnalyticParserError(
            f"orphan candidate {analytic['external_id']} has a parent"
        )
    return {
        "id": f"analytic-has-no-parent-strategy-{analytic['external_id'].lower()}",
        "case_type": "identify_analytic_no_detection_strategy",
        "relationship_type": "detection_strategy_has_analytic",
        "question": f"Which detection strategy does {analytic_label(analytic)} belong to?",
        "expected_answer": (
            "No active DetectionStrategy has an x_mitre_analytic_refs link to "
            f"{analytic_label(analytic)} in the pinned Enterprise ATT&CK snapshot."
        ),
        "analytic": analytic,
        "expected_detection_strategy": None,
        "provenance": edge_provenance(
            source, [], [], [], queried_analytic=analytic
        ),
    }


def strategy_aggregate_pair(
    strategy: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    analytics, paths = analytics_and_paths_for_strategy(strategy, extracted)
    if not analytics:
        return {
            "id": f"strategy-has-no-analytics-{strategy['external_id'].lower()}",
            "case_type": "aggregate_detection_strategy_no_analytics",
            "relationship_type": "detection_strategy_has_analytic",
            "question": f"What analytics does {strategy_label(strategy)} have?",
            "expected_answer": (
                "No active Analytic is referenced by "
                f"{strategy_label(strategy)} in the pinned Enterprise ATT&CK snapshot."
            ),
            "detection_strategy": strategy,
            "expected_analytics": [],
            "provenance": edge_provenance(source, [strategy], [], [],),
        }
    return {
        "id": f"strategy-analytics-{strategy['external_id'].lower()}",
        "case_type": "aggregate_detection_strategy_analytics",
        "relationship_type": "detection_strategy_has_analytic",
        "question": f"What analytics does {strategy_label(strategy)} have?",
        "expected_answer": (
            f"The active analytics referenced by {strategy_label(strategy)} are "
            f"{natural_list([analytic_label(item) for item in analytics])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "detection_strategy": strategy,
        "expected_analytics": analytics,
        "provenance": edge_provenance(source, [strategy], analytics, paths),
    }


def positive_relationship_pair(
    strategy: dict[str, Any],
    analytic: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    analytics, paths = analytics_and_paths_for_strategy(strategy, extracted)
    matching_paths = [path for path in paths if path["analytic_ref"] == analytic["stix_id"]]
    if analytic["stix_id"] not in {item["stix_id"] for item in analytics} or len(matching_paths) != 1:
        raise DetectionAnalyticParserError(
            f"positive pair {strategy['external_id']} -> {analytic['external_id']} does not exist"
        )
    return {
        "id": f"strategy-analytic-positive-{strategy['external_id'].lower()}-{analytic['external_id'].lower()}",
        "case_type": "positive_detection_strategy_analytic_relationship",
        "relationship_type": "detection_strategy_has_analytic",
        "question": f"Does {strategy_label(strategy)} have {analytic_label(analytic)}?",
        "expected_answer": (
            f"Yes. {strategy_label(strategy)} references {analytic_label(analytic)} "
            "in the pinned Enterprise ATT&CK snapshot."
        ),
        "detection_strategy": strategy,
        "candidate_analytic": analytic,
        "relationship_exists": True,
        "expected_analytics": [analytic],
        "provenance": edge_provenance(
            source, [strategy], [analytic], matching_paths, queried_analytic=analytic
        ),
    }


def negative_relationship_pair(
    strategy: dict[str, Any],
    candidate_analytic: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    path_keys = {
        (path["detection_strategy_ref"], path["analytic_ref"])
        for path in extracted["paths"]
    }
    if (strategy["stix_id"], candidate_analytic["stix_id"]) in path_keys:
        raise DetectionAnalyticParserError(
            f"negative pair {strategy['external_id']} -> "
            f"{candidate_analytic['external_id']} exists"
        )
    return {
        "id": f"strategy-analytic-negative-{strategy['external_id'].lower()}-{candidate_analytic['external_id'].lower()}",
        "case_type": "negative_detection_strategy_analytic_relationship",
        "relationship_type": "detection_strategy_has_analytic",
        "question": f"Does {strategy_label(strategy)} have {analytic_label(candidate_analytic)}?",
        "expected_answer": (
            "No active x_mitre_analytic_refs link exists from "
            f"{strategy_label(strategy)} to {analytic_label(candidate_analytic)} "
            "in the pinned Enterprise ATT&CK snapshot."
        ),
        "detection_strategy": strategy,
        "candidate_analytic": candidate_analytic,
        "relationship_exists": False,
        "expected_analytics": [],
        "provenance": edge_provenance(
            source, [strategy], [], [], queried_analytic=candidate_analytic
        ),
    }


def platform_aggregate_pair(
    strategy: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
    platform: str = PLATFORM_FILTER,
) -> dict[str, Any]:
    analytics, paths = analytics_and_paths_for_strategy(strategy, extracted)
    matching = [item for item in analytics if platform in item["platforms"]]
    matching_ids = {item["stix_id"] for item in matching}
    matching_paths = [path for path in paths if path["analytic_ref"] in matching_ids]
    slug = platform.lower().replace(" ", "-")
    if not matching:
        return {
            "id": f"strategy-has-no-{slug}-analytics-{strategy['external_id'].lower()}",
            "case_type": "aggregate_detection_strategy_no_platform_analytics",
            "relationship_type": "detection_strategy_has_analytic",
            "question": (
                f"Which analytics of {strategy_label(strategy)} apply to the "
                f"{platform} platform?"
            ),
            "expected_answer": (
                f"None of the active analytics referenced by {strategy_label(strategy)} "
                f"have {platform} in their own platforms field in the pinned "
                "Enterprise ATT&CK snapshot."
            ),
            "detection_strategy": strategy,
            "platform_filter": platform,
            "expected_analytics": [],
            "provenance": edge_provenance(
                source, [strategy], [], [], platform_filter=platform
            ),
        }
    return {
        "id": f"strategy-{slug}-analytics-{strategy['external_id'].lower()}",
        "case_type": "aggregate_detection_strategy_platform_analytics",
        "relationship_type": "detection_strategy_has_analytic",
        "question": (
            f"Which analytics of {strategy_label(strategy)} apply to the "
            f"{platform} platform?"
        ),
        "expected_answer": (
            f"The analytics of {strategy_label(strategy)} whose own platforms "
            f"include {platform} are "
            f"{natural_list([analytic_label(item) for item in matching])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "detection_strategy": strategy,
        "platform_filter": platform,
        "expected_analytics": matching,
        "provenance": edge_provenance(
            source,
            [strategy],
            matching,
            matching_paths,
            platform_filter=platform,
        ),
    }


def select_orphan_sample(extracted: dict[str, Any]) -> list[str]:
    orphan_ids = [item["external_id"] for item in extracted["orphans"]]
    return evenly_spaced_items(orphan_ids, FULL_ORPHAN_SAMPLE_COUNT)


def select_full_negative_cases(extracted: dict[str, Any]) -> dict[str, str]:
    strategies = strategy_catalog(extracted)
    analytics = analytic_catalog(extracted)
    path_keys = {
        (path["detection_strategy_ref"], path["analytic_ref"])
        for path in extracted["paths"]
    }
    selected = dict(NEGATIVE_ANALYTIC_BY_STRATEGY)
    needed = FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT - len(selected)
    eligible = [item for item in sorted(strategies) if item not in selected]
    for offset, strategy_id in enumerate(evenly_spaced_items(eligible, needed)):
        strategy = strategies[strategy_id]
        probes = (
            FULL_NEGATIVE_PROBE_ANALYTIC_IDS[offset % len(FULL_NEGATIVE_PROBE_ANALYTIC_IDS):]
            + FULL_NEGATIVE_PROBE_ANALYTIC_IDS[:offset % len(FULL_NEGATIVE_PROBE_ANALYTIC_IDS)]
        )
        for analytic_id in probes:
            analytic = analytics.get(analytic_id)
            if analytic is None:
                continue
            if (strategy["stix_id"], analytic["stix_id"]) not in path_keys:
                selected[strategy_id] = analytic_id
                break
        else:
            raise DetectionAnalyticParserError(
                f"no configured negative probe is absent for {strategy_id}"
            )
    if len(selected) != FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT:
        raise DetectionAnalyticParserError(
            f"expected {FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT} negatives, "
            f"selected {len(selected)}"
        )
    return selected


def generate_prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    strategies = strategy_catalog(extracted)
    analytics = analytic_catalog(extracted)
    selected_strategies = [strategies[item] for item in SELECTED_STRATEGY_IDS]
    focused = [analytics[FOCUSED_ANALYTIC_BY_STRATEGY[item]] for item in SELECTED_STRATEGY_IDS]
    orphan_sample_ids = select_orphan_sample(extracted)
    pairs = [parent_identification_pair(item, extracted, source) for item in focused]
    pairs.extend(
        orphan_parent_identification_pair(analytics[item], extracted, source)
        for item in orphan_sample_ids
    )
    pairs.extend(strategy_aggregate_pair(item, extracted, source) for item in selected_strategies)
    pairs.extend(
        positive_relationship_pair(strategy, analytic, extracted, source)
        for strategy, analytic in zip(selected_strategies, focused)
    )
    pairs.extend(platform_aggregate_pair(item, extracted, source) for item in selected_strategies)
    pairs.extend(
        negative_relationship_pair(
            strategy,
            analytics[NEGATIVE_ANALYTIC_BY_STRATEGY[strategy["external_id"]]],
            extracted,
            source,
        )
        for strategy in selected_strategies
    )
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise DetectionAnalyticParserError("prototype pair IDs are not unique")
    return pairs


def generate_full_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str], dict[str, str]]:
    strategies = strategy_catalog(extracted)
    analytics = analytic_catalog(extracted)
    orphan_sample_ids = select_orphan_sample(extracted)
    linked_parent_lookups = [
        parent_identification_pair(item, extracted, source)
        for item in extracted["analytics"]
        if item["external_id"] not in {orphan["external_id"] for orphan in extracted["orphans"]}
    ]
    orphan_lookups = [
        orphan_parent_identification_pair(analytics[item], extracted, source)
        for item in orphan_sample_ids
    ]
    aggregates = [
        strategy_aggregate_pair(strategies[item], extracted, source)
        for item in sorted(strategies)
    ]
    positives = []
    for strategy_id in sorted(strategies):
        strategy = strategies[strategy_id]
        children, _ = analytics_and_paths_for_strategy(strategy, extracted)
        if children:
            positives.append(
                positive_relationship_pair(strategy, children[0], extracted, source)
            )
    platform_pairs = [
        platform_aggregate_pair(strategies[item], extracted, source)
        for item in sorted(strategies)
    ]
    negative_cases = select_full_negative_cases(extracted)
    negatives = [
        negative_relationship_pair(
            strategies[strategy_id], analytics[analytic_id], extracted, source
        )
        for strategy_id, analytic_id in sorted(negative_cases.items())
    ]
    pairs = linked_parent_lookups + orphan_lookups + aggregates + positives + platform_pairs + negatives
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise DetectionAnalyticParserError("full pair IDs are not unique")
    return pairs, orphan_sample_ids, negative_cases


def parsed_data(extracted: dict[str, Any]) -> dict[str, Any]:
    strategy_rows = {}
    for strategy in extracted["strategies"]:
        analytics, paths = analytics_and_paths_for_strategy(strategy, extracted)
        strategy_rows[strategy["external_id"]] = {
            "detection_strategy": strategy,
            "analytics": analytics,
            "strategy_analytic_paths": paths,
        }
    orphan_rows = {
        item["external_id"]: item for item in extracted["orphans"]
    }
    return {"detection_strategies": strategy_rows, "orphan_analytics": orphan_rows}


def case_counts(pairs: list[dict[str, Any]]) -> dict[str, int]:
    return {
        name: sum(pair["case_type"] == name for pair in pairs)
        for name in sorted({pair["case_type"] for pair in pairs})
    }


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    counts = case_counts(pairs)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_detection_strategy_analytic_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "x-mitre-detection-strategy",
            "target_type": "x-mitre-analytic",
            "relationship_type": "x_mitre_analytic_refs",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "orphan_sampling_note": ORPHAN_SAMPLING_NOTE,
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "strategy_external_ids": list(SELECTED_STRATEGY_IDS),
            "pair_count": len(pairs),
            "linked_parent_identification_pairs": counts.get("identify_analytic_detection_strategy", 0),
            "orphan_parent_identification_pairs": counts.get("identify_analytic_no_detection_strategy", 0),
            "strategy_aggregate_pairs": counts.get("aggregate_detection_strategy_analytics", 0),
            "positive_relationship_pairs": counts.get("positive_detection_strategy_analytic_relationship", 0),
            "negative_relationship_pairs": counts.get("negative_detection_strategy_analytic_relationship", 0),
            "platform_constrained_pairs": sum(
                counts.get(name, 0)
                for name in (
                    "aggregate_detection_strategy_platform_analytics",
                    "aggregate_detection_strategy_no_platform_analytics",
                )
            ),
            "orphan_sample_external_ids": select_orphan_sample(extracted),
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "parsed_data": parsed_data(extracted),
        "pairs": pairs,
    }


def full_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs, orphan_sample_ids, negative_cases = generate_full_pairs(extracted, source)
    counts = case_counts(pairs)
    positive_count = counts.get("positive_detection_strategy_analytic_relationship", 0)
    negative_count = counts.get("negative_detection_strategy_analytic_relationship", 0)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_full_detection_strategy_analytic_golden_set",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "x-mitre-detection-strategy",
            "target_type": "x-mitre-analytic",
            "relationship_type": "x_mitre_analytic_refs",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "orphan_sampling_note": ORPHAN_SAMPLING_NOTE,
            "revoked_and_deprecated_excluded": True,
            "one_aggregate_per_active_strategy": True,
            "one_linux_constrained_pair_per_active_strategy": True,
            "one_parent_identification_per_linked_analytic": True,
        },
        "selection": {
            "pair_count": len(pairs),
            "linked_parent_identification_pairs": counts.get("identify_analytic_detection_strategy", 0),
            "orphan_parent_identification_pairs": counts.get("identify_analytic_no_detection_strategy", 0),
            "strategy_aggregate_pairs": sum(
                counts.get(name, 0)
                for name in (
                    "aggregate_detection_strategy_analytics",
                    "aggregate_detection_strategy_no_analytics",
                )
            ),
            "positive_relationship_pairs": positive_count,
            "negative_relationship_pairs": negative_count,
            "explicit_boolean_negative_ratio": negative_count / (positive_count + negative_count),
            "platform_constrained_positive_pairs": counts.get("aggregate_detection_strategy_platform_analytics", 0),
            "platform_constrained_zero_path_pairs": counts.get("aggregate_detection_strategy_no_platform_analytics", 0),
            "embedded_parent_identification_fact_count": counts.get("identify_analytic_detection_strategy", 0),
            "embedded_strategy_aggregate_fact_count": sum(
                len(pair.get("expected_analytics", []))
                for pair in pairs
                if pair["case_type"] == "aggregate_detection_strategy_analytics"
            ),
            "embedded_platform_constrained_fact_count": sum(
                len(pair.get("expected_analytics", []))
                for pair in pairs
                if pair["case_type"] in {
                    "aggregate_detection_strategy_platform_analytics",
                    "aggregate_detection_strategy_no_platform_analytics",
                }
            ),
        },
        "orphan_selection": {
            "method": ORPHAN_SAMPLING_NOTE,
            "selected_external_ids": orphan_sample_ids,
            "total_active_orphan_count": len(extracted["orphans"]),
            "all_selected_cases_verified_absent_by_extracted_path_set": True,
        },
        "negative_selection": {
            "method": (
                "Preserve the five prototype negatives, then choose 135 evenly "
                "spaced active strategies and rotate linked and orphan Analytic "
                "probes until a graph-verified strategy-to-analytic non-edge is found."
            ),
            "selected_strategy_to_candidate_analytic": negative_cases,
            "all_cases_verified_absent_by_extracted_path_set": True,
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "parsed_data": parsed_data(extracted),
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "golden_set_detection_analytic_prototype.json",
    )
    parser.add_argument(
        "--generate-full",
        action="store_true",
        help="write the full all-active-strategy golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_detection_analytic.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    extracted = extract_detection_analytic_scope(bundle)
    payload = full_payload(extracted, source) if args.generate_full else prototype_payload(extracted, source)
    output = args.full_output if args.generate_full else args.output
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "source": source,
                "artifact": {"output": str(output), "selection": payload["selection"]},
                "global_coverage": payload["global_coverage"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        DetectionAnalyticParserError,
        DetectionStrategyParserError,
        SubtechniqueParserError,
    ) as exc:
        raise SystemExit(f"FAIL: {exc}")
