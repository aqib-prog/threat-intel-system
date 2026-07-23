#!/usr/bin/env python3
"""Generate deterministic Analytic -[USES_DATA_COMPONENT]-> DataComponent sets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from generate_detection_strategy_prototype import (
    DetectionStrategyParserError,
    analytic_label,
    compact_analytic,
    compact_component,
    component_label,
    require_unique_external_ids,
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
SELECTED_ANALYTIC_IDS = (
    "AN0001",  # mixed Windows-log-capable and cloud-only components
    "AN0110",  # Linux analytic with two network components
    "AN0234",  # cloud components; zero Windows Event Log matches
    "AN0872",  # four components and two source rows for one edge
    "AN1551",  # maximum forward fan-out of ten components
)
FOCUSED_COMPONENT_BY_ANALYTIC = {
    "AN0001": "DC0082",
    "AN0110": "DC0078",
    "AN0234": "DC0081",
    "AN0872": "DC0059",
    "AN1551": "DC0002",
}
NEGATIVE_COMPONENT_BY_ANALYTIC = {
    "AN0001": "DC0026",
    "AN0110": "DC0002",
    "AN0234": "DC0032",
    "AN0872": "DC0024",
    "AN1551": "DC0081",
}
SELECTED_REVERSE_COMPONENT_IDS = (
    "DC0024",  # fan-in 1; enumerate completely
    "DC0004",  # fan-in 15; exact cap boundary, enumerate completely
    "DC0079",  # fan-in 16; first capped case
    "DC0032",  # maximum fan-in 858; capped stress case
    "DC0026",  # orphan DataComponent
)
FULL_ZERO_ANALYTIC_SAMPLE_COUNT = 5
FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT = 343
FULL_NEGATIVE_PROBE_COMPONENT_IDS = (
    "DC0032",
    "DC0064",
    "DC0039",
    "DC0085",
    "DC0082",
    "DC0026",
    "DC0030",
    "DC0044",
    "DC0095",
    "DC0100",
)
REVERSE_ENUMERATION_THRESHOLD = 15
REVERSE_SAMPLE_SIZE = 10
PROPERTY_NAME = "Windows Event Log source"
PROPERTY_LOG_SOURCE_PREFIX = "WinEventLog:"
SCOPE = "active_analytic_embedded_data_component_references"
METHODOLOGY_NOTE = (
    "Analytic-to-DataComponent links are read from each active Enterprise "
    "ATT&CK x-mitre-analytic object's x_mitre_log_source_references field; "
    "they are embedded references, not STIX relationship objects. Distinct "
    "Analytic/DataComponent endpoint pairs are counted as edges, while every "
    "supporting source row and its original index, name, and channel are "
    "preserved in provenance. Forward answers enumerate every distinct "
    "DataComponent because fan-out is at most ten. Reverse answers enumerate "
    "every Analytic through fan-in 15; larger answers contain the first ten "
    "Analytics by external-ID order plus the exact total distinct-edge count."
)
ZERO_ANALYTIC_SAMPLING_NOTE = (
    "Select five of the 45 active Analytics with no active DataComponent edge "
    "deterministically by taking evenly spaced entries from external-ID order."
)
PROPERTY_FILTER_NOTE = (
    "A DataComponent matches the property-constrained intent when at least one "
    "object in its own x_mitre_log_sources list has a name beginning exactly "
    "with 'WinEventLog:'. The filter is applied to DataComponents already "
    "linked to the queried Analytic, not to the Analytic's platform field or "
    "to free-text descriptions. The first matching row by original source-field "
    "index is retained as deterministic evidence for each matched component; "
    "the complete matching row set remains in parsed_data once per component."
)


class AnalyticDataComponentParserError(DetectionStrategyParserError):
    """Raised when Analytic/DataComponent data violates expected invariants."""


def component_log_source_rows(obj: dict[str, Any]) -> list[dict[str, Any]]:
    raw_rows = obj.get("x_mitre_log_sources", [])
    if not isinstance(raw_rows, list):
        raise AnalyticDataComponentParserError(
            f"DataComponent {obj['id']} has non-list x_mitre_log_sources"
        )
    rows = []
    for index, row in enumerate(raw_rows):
        if not isinstance(row, dict):
            raise AnalyticDataComponentParserError(
                f"DataComponent {obj['id']} has a non-object log source"
            )
        rows.append(
            {
                "data_component_ref": obj["id"],
                "data_component_external_id": compact_component(obj)["external_id"],
                "source_field": "x_mitre_log_sources",
                "source_field_index": index,
                "log_source_name": row.get("name"),
                "log_source_channel": row.get("channel"),
            }
        )
    return rows


def compact_edge_component(
    obj: dict[str, Any], property_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    compacted = compact_component(obj)
    return {
        **compacted,
        "log_source_count": len(property_rows),
        "has_windows_event_log_source": any(
            (row["log_source_name"] or "").startswith(PROPERTY_LOG_SOURCE_PREFIX)
            for row in property_rows
        ),
    }


def compact_edge_analytic(
    obj: dict[str, Any],
    components_by_stix: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parsed, paths = compact_analytic(obj, components_by_stix)
    return (
        {
            "stix_id": parsed["stix_id"],
            "external_id": parsed["external_id"],
            "name": parsed["name"],
            "platforms": sorted(set(parsed["platforms"])),
        },
        paths,
    )


def extract_analytic_datacomponent_scope(bundle: dict[str, Any]) -> dict[str, Any]:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise AnalyticDataComponentParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]
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
    analytic_objects_by_external = require_unique_external_ids(
        analytic_objects, "Analytic"
    )
    component_objects_by_external = require_unique_external_ids(
        component_objects, "DataComponent"
    )
    components_by_stix = {obj["id"]: obj for obj in component_objects}

    property_rows_by_component: dict[str, list[dict[str, Any]]] = {}
    components = {}
    for external_id in sorted(component_objects_by_external):
        obj = component_objects_by_external[external_id]
        property_rows = component_log_source_rows(obj)
        property_rows_by_component[obj["id"]] = property_rows
        components[external_id] = compact_edge_component(obj, property_rows)

    analytics = {}
    paths: list[dict[str, Any]] = []
    for external_id in sorted(analytic_objects_by_external):
        obj = analytic_objects_by_external[external_id]
        compacted, analytic_paths = compact_edge_analytic(obj, components_by_stix)
        analytics[external_id] = compacted
        paths.extend(analytic_paths)
    paths.sort(
        key=lambda path: (
            path["analytic_external_id"] or "",
            path["data_component_external_id"] or "",
            path["log_source_reference_index"],
        )
    )
    pair_keys = {
        (path["analytic_ref"], path["data_component_ref"])
        for path in paths
    }
    paths_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    paths_by_analytic: dict[str, list[dict[str, Any]]] = {}
    paths_by_component: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        key = (path["analytic_ref"], path["data_component_ref"])
        paths_by_pair.setdefault(key, []).append(path)
        paths_by_analytic.setdefault(path["analytic_ref"], []).append(path)
        paths_by_component.setdefault(path["data_component_ref"], []).append(path)

    analytic_rows = sorted(
        analytics.values(), key=lambda item: (item["external_id"], item["stix_id"])
    )
    component_rows = sorted(
        components.values(), key=lambda item: (item["external_id"], item["stix_id"])
    )
    zero_analytics = [
        item for item in analytic_rows if item["stix_id"] not in paths_by_analytic
    ]
    orphan_components = [
        item for item in component_rows if item["stix_id"] not in paths_by_component
    ]
    forward_counts = {
        analytic["stix_id"]: len(
            {
                path["data_component_ref"]
                for path in paths_by_analytic.get(analytic["stix_id"], [])
            }
        )
        for analytic in analytic_rows
    }
    reverse_counts = {
        component["stix_id"]: len(
            {
                path["analytic_ref"]
                for path in paths_by_component.get(component["stix_id"], [])
            }
        )
        for component in component_rows
    }
    windows_component_ids = {
        component["stix_id"]
        for component in component_rows
        if component["has_windows_event_log_source"]
    }
    windows_pair_keys = {
        key for key in pair_keys if key[1] in windows_component_ids
    }
    analytics_with_windows_component = {key[0] for key in windows_pair_keys}
    maximum_rows_per_pair = max(
        (len(pair_paths) for pair_paths in paths_by_pair.values()), default=0
    )
    return {
        "analytics": analytic_rows,
        "data_components": component_rows,
        "zero_analytics": zero_analytics,
        "orphan_data_components": orphan_components,
        "paths": paths,
        "component_log_source_rows": [
            row
            for component in component_rows
            for row in property_rows_by_component[component["stix_id"]]
        ],
        "global_coverage": {
            "active_analytic_count": len(analytic_rows),
            "active_data_component_count": len(component_rows),
            "analytic_log_source_reference_row_count": len(paths),
            "distinct_analytic_data_component_edge_count": len(pair_keys),
            "duplicate_reference_rows_beyond_distinct_edges": (
                len(paths) - len(pair_keys)
            ),
            "analytics_with_one_or_more_data_components": (
                len(analytic_rows) - len(zero_analytics)
            ),
            "analytics_with_zero_data_components": len(zero_analytics),
            "data_components_with_one_or_more_analytics": (
                len(component_rows) - len(orphan_components)
            ),
            "orphan_data_component_count": len(orphan_components),
            "maximum_data_components_per_analytic": max(forward_counts.values()),
            "maximum_analytics_per_data_component": max(reverse_counts.values()),
            "data_components_at_or_below_reverse_enumeration_threshold": sum(
                0 < count <= REVERSE_ENUMERATION_THRESHOLD
                for count in reverse_counts.values()
            ),
            "data_components_above_reverse_enumeration_threshold": sum(
                count > REVERSE_ENUMERATION_THRESHOLD
                for count in reverse_counts.values()
            ),
            "active_data_component_log_source_row_count": sum(
                len(rows) for rows in property_rows_by_component.values()
            ),
            "data_components_with_windows_event_log_source": len(
                windows_component_ids
            ),
            "analytic_data_component_edges_matching_windows_event_log_property": len(
                windows_pair_keys
            ),
            "analytics_with_one_or_more_windows_event_log_components": len(
                analytics_with_windows_component
            ),
            "analytics_with_zero_windows_event_log_components": (
                len(analytic_rows) - len(analytics_with_windows_component)
            ),
        },
        "extraction_audit": {
            "raw_active_analytic_log_source_reference_count": len(paths),
            "distinct_active_endpoint_pair_count": len(pair_keys),
            "endpoint_pairs_with_multiple_source_rows": sum(
                len(pair_paths) > 1 for pair_paths in paths_by_pair.values()
            ),
            "maximum_source_rows_for_one_endpoint_pair": maximum_rows_per_pair,
            "missing_or_inactive_data_component_reference_count": 0,
        },
    }


def analytic_catalog(extracted: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["external_id"]: item for item in extracted["analytics"]}


def component_catalog(extracted: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["external_id"]: item for item in extracted["data_components"]}


def components_and_paths_for_analytic(
    analytic: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    components_by_stix = {
        item["stix_id"]: item for item in extracted["data_components"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["analytic_ref"] == analytic["stix_id"]
    ]
    component_ids = sorted(
        {path["data_component_ref"] for path in paths},
        key=lambda stix_id: (
            components_by_stix[stix_id]["external_id"],
            stix_id,
        ),
    )
    return [components_by_stix[item] for item in component_ids], paths


def analytics_and_paths_for_component(
    component: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    analytics_by_stix = {
        item["stix_id"]: item for item in extracted["analytics"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["data_component_ref"] == component["stix_id"]
    ]
    analytic_ids = sorted(
        {path["analytic_ref"] for path in paths},
        key=lambda stix_id: (
            analytics_by_stix[stix_id]["external_id"],
            stix_id,
        ),
    )
    return [analytics_by_stix[item] for item in analytic_ids], paths


def property_rows_for_component(
    component: dict[str, Any], extracted: dict[str, Any]
) -> list[dict[str, Any]]:
    return [
        row
        for row in extracted["component_log_source_rows"]
        if row["data_component_ref"] == component["stix_id"]
        and (row["log_source_name"] or "").startswith(PROPERTY_LOG_SOURCE_PREFIX)
    ]


def edge_provenance(
    source: dict[str, Any],
    analytics: list[dict[str, Any]],
    components: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    *,
    queried_component: dict[str, Any] | None = None,
    property_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    distinct_keys = {
        (path["analytic_ref"], path["data_component_ref"])
        for path in paths
    }
    result = {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "analytic_stix_ids": [item["stix_id"] for item in analytics],
        "data_component_stix_ids": [item["stix_id"] for item in components],
        "source_field": "x-mitre-analytic.x_mitre_log_source_references",
        "analytic_data_component_paths": paths,
        "distinct_supported_edge_count": len(distinct_keys),
        "supporting_source_row_count": len(paths),
    }
    if queried_component is not None:
        result["queried_data_component_stix_id"] = queried_component["stix_id"]
    if property_evidence is not None:
        result["property_filter"] = {
            "property_name": PROPERTY_NAME,
            "source_field": "x-mitre-data-component.x_mitre_log_sources[].name",
            "match_operator": "starts_with",
            "match_value": PROPERTY_LOG_SOURCE_PREFIX,
            "applies_to": "linked_data_component",
            "methodology_note": PROPERTY_FILTER_NOTE,
        }
        result["data_component_property_evidence"] = property_evidence
    return result


def forward_aggregate_pair(
    analytic: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    components, paths = components_and_paths_for_analytic(analytic, extracted)
    if not components:
        return zero_forward_pair(analytic, extracted, source)
    return {
        "id": f"analytic-data-components-{analytic['external_id'].lower()}",
        "case_type": "aggregate_analytic_data_components",
        "relationship_type": "analytic_uses_data_component",
        "question": f"Which data components does {analytic_label(analytic)} use?",
        "expected_answer": (
            f"{analytic_label(analytic)} uses "
            f"{natural_list([component_label(item) for item in components])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "analytic": analytic,
        "expected_data_components": components,
        "provenance": edge_provenance(
            source, [analytic], components, paths
        ),
    }


def zero_forward_pair(
    analytic: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    components, paths = components_and_paths_for_analytic(analytic, extracted)
    if components or paths:
        raise AnalyticDataComponentParserError(
            f"zero-path Analytic {analytic['external_id']} has active edges"
        )
    return {
        "id": f"analytic-has-no-data-components-{analytic['external_id'].lower()}",
        "case_type": "aggregate_analytic_no_data_components",
        "relationship_type": "analytic_uses_data_component",
        "question": f"Which data components does {analytic_label(analytic)} use?",
        "expected_answer": (
            "No active Analytic/DataComponent endpoint pair is recorded for "
            f"{analytic_label(analytic)} in the pinned Enterprise ATT&CK snapshot."
        ),
        "analytic": analytic,
        "expected_data_components": [],
        "provenance": edge_provenance(source, [analytic], [], []),
    }


def reverse_aggregate_pair(
    component: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    analytics, paths = analytics_and_paths_for_component(component, extracted)
    total = len(analytics)
    if total == 0:
        return {
            "id": f"data-component-has-no-analytics-{component['external_id'].lower()}",
            "case_type": "aggregate_data_component_no_analytics",
            "relationship_type": "analytic_uses_data_component",
            "question": f"Which analytics use data component {component_label(component)}?",
            "expected_answer": (
                "No active Analytic/DataComponent endpoint pair targets "
                f"{component_label(component)} in the pinned Enterprise ATT&CK snapshot."
            ),
            "data_component": component,
            "expected_analytics": [],
            "expected_analytic_total_count": 0,
            "expected_analytics_complete": True,
            "reverse_answer_cap_threshold": REVERSE_ENUMERATION_THRESHOLD,
            "reverse_answer_sample_size": REVERSE_SAMPLE_SIZE,
            "provenance": edge_provenance(
                source, [], [component], [], queried_component=component
            ),
        }
    capped = total > REVERSE_ENUMERATION_THRESHOLD
    shown = analytics[:REVERSE_SAMPLE_SIZE] if capped else analytics
    if capped:
        answer = (
            f"{component_label(component)} is referenced by {total} active "
            "Analytics in the pinned Enterprise ATT&CK snapshot. The first "
            f"{REVERSE_SAMPLE_SIZE} by external-ID order are "
            f"{natural_list([analytic_label(item) for item in shown])} "
            f"({REVERSE_SAMPLE_SIZE} shown; {total} total)."
        )
        case_type = "aggregate_data_component_analytics_capped"
    else:
        answer = (
            f"{component_label(component)} is referenced by {total} active "
            f"Analytics: {natural_list([analytic_label(item) for item in shown])} "
            "in the pinned Enterprise ATT&CK snapshot."
        )
        case_type = "aggregate_data_component_analytics"
    return {
        "id": f"data-component-analytics-{component['external_id'].lower()}",
        "case_type": case_type,
        "relationship_type": "analytic_uses_data_component",
        "question": f"Which analytics use data component {component_label(component)}?",
        "expected_answer": answer,
        "data_component": component,
        "expected_analytics": shown,
        "expected_analytic_total_count": total,
        "expected_analytics_complete": not capped,
        "reverse_answer_cap_threshold": REVERSE_ENUMERATION_THRESHOLD,
        "reverse_answer_sample_size": REVERSE_SAMPLE_SIZE,
        "provenance": edge_provenance(
            source,
            analytics,
            [component],
            paths,
            queried_component=component,
        ),
    }


def positive_relationship_pair(
    analytic: dict[str, Any],
    component: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    components, paths = components_and_paths_for_analytic(analytic, extracted)
    matching_paths = [
        path for path in paths if path["data_component_ref"] == component["stix_id"]
    ]
    if component["stix_id"] not in {item["stix_id"] for item in components}:
        raise AnalyticDataComponentParserError(
            f"positive pair {analytic['external_id']} -> "
            f"{component['external_id']} does not exist"
        )
    return {
        "id": f"analytic-data-component-positive-{analytic['external_id'].lower()}-{component['external_id'].lower()}",
        "case_type": "positive_analytic_data_component_relationship",
        "relationship_type": "analytic_uses_data_component",
        "question": f"Does {analytic_label(analytic)} use {component_label(component)}?",
        "expected_answer": (
            f"Yes. {analytic_label(analytic)} uses {component_label(component)} "
            "in the pinned Enterprise ATT&CK snapshot."
        ),
        "analytic": analytic,
        "candidate_data_component": component,
        "relationship_exists": True,
        "expected_data_components": [component],
        "provenance": edge_provenance(
            source, [analytic], [component], matching_paths, queried_component=component
        ),
    }


def negative_relationship_pair(
    analytic: dict[str, Any],
    candidate_component: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    path_keys = {
        (path["analytic_ref"], path["data_component_ref"])
        for path in extracted["paths"]
    }
    if (analytic["stix_id"], candidate_component["stix_id"]) in path_keys:
        raise AnalyticDataComponentParserError(
            f"negative pair {analytic['external_id']} -> "
            f"{candidate_component['external_id']} exists"
        )
    return {
        "id": f"analytic-data-component-negative-{analytic['external_id'].lower()}-{candidate_component['external_id'].lower()}",
        "case_type": "negative_analytic_data_component_relationship",
        "relationship_type": "analytic_uses_data_component",
        "question": f"Does {analytic_label(analytic)} use {component_label(candidate_component)}?",
        "expected_answer": (
            "No active Analytic/DataComponent endpoint pair exists from "
            f"{analytic_label(analytic)} to {component_label(candidate_component)} "
            "in the pinned Enterprise ATT&CK snapshot."
        ),
        "analytic": analytic,
        "candidate_data_component": candidate_component,
        "relationship_exists": False,
        "expected_data_components": [],
        "provenance": edge_provenance(
            source,
            [analytic],
            [],
            [],
            queried_component=candidate_component,
        ),
    }


def property_constrained_pair(
    analytic: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    components, paths = components_and_paths_for_analytic(analytic, extracted)
    matching = [item for item in components if item["has_windows_event_log_source"]]
    matching_ids = {item["stix_id"] for item in matching}
    matching_paths = [
        path for path in paths if path["data_component_ref"] in matching_ids
    ]
    property_evidence = [
        property_rows_for_component(component, extracted)[0]
        for component in matching
    ]
    if not matching:
        return {
            "id": f"analytic-has-no-windows-event-log-components-{analytic['external_id'].lower()}",
            "case_type": "aggregate_analytic_no_property_data_components",
            "relationship_type": "analytic_uses_data_component",
            "question": (
                f"Which data components used by {analytic_label(analytic)} have "
                f"a {PROPERTY_NAME}?"
            ),
            "expected_answer": (
                f"None of the active DataComponents used by {analytic_label(analytic)} "
                f"have an x_mitre_log_sources name beginning with "
                f"'{PROPERTY_LOG_SOURCE_PREFIX}' in the pinned Enterprise ATT&CK snapshot."
            ),
            "analytic": analytic,
            "property_filter": PROPERTY_LOG_SOURCE_PREFIX,
            "expected_data_components": [],
            "provenance": edge_provenance(
                source, [analytic], [], [], property_evidence=[]
            ),
        }
    return {
        "id": f"analytic-windows-event-log-components-{analytic['external_id'].lower()}",
        "case_type": "aggregate_analytic_property_data_components",
        "relationship_type": "analytic_uses_data_component",
        "question": (
            f"Which data components used by {analytic_label(analytic)} have a "
            f"{PROPERTY_NAME}?"
        ),
        "expected_answer": (
            f"The DataComponents used by {analytic_label(analytic)} with an "
            f"x_mitre_log_sources name beginning with '{PROPERTY_LOG_SOURCE_PREFIX}' "
            f"are {natural_list([component_label(item) for item in matching])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "analytic": analytic,
        "property_filter": PROPERTY_LOG_SOURCE_PREFIX,
        "expected_data_components": matching,
        "provenance": edge_provenance(
            source,
            [analytic],
            matching,
            matching_paths,
            property_evidence=property_evidence,
        ),
    }


def select_zero_analytic_sample(extracted: dict[str, Any]) -> list[str]:
    zero_ids = [item["external_id"] for item in extracted["zero_analytics"]]
    return evenly_spaced_items(zero_ids, FULL_ZERO_ANALYTIC_SAMPLE_COUNT)


def select_full_negative_cases(extracted: dict[str, Any]) -> dict[str, str]:
    analytics = analytic_catalog(extracted)
    components = component_catalog(extracted)
    path_keys = {
        (path["analytic_ref"], path["data_component_ref"])
        for path in extracted["paths"]
    }
    selected = dict(NEGATIVE_COMPONENT_BY_ANALYTIC)
    needed = FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT - len(selected)
    eligible = [item for item in sorted(analytics) if item not in selected]
    for offset, analytic_id in enumerate(evenly_spaced_items(eligible, needed)):
        analytic = analytics[analytic_id]
        rotation = offset % len(FULL_NEGATIVE_PROBE_COMPONENT_IDS)
        probes = (
            FULL_NEGATIVE_PROBE_COMPONENT_IDS[rotation:]
            + FULL_NEGATIVE_PROBE_COMPONENT_IDS[:rotation]
        )
        for component_id in probes:
            component = components.get(component_id)
            if component is None:
                continue
            if (analytic["stix_id"], component["stix_id"]) not in path_keys:
                selected[analytic_id] = component_id
                break
        else:
            raise AnalyticDataComponentParserError(
                f"no configured negative probe is absent for {analytic_id}"
            )
    if len(selected) != FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT:
        raise AnalyticDataComponentParserError(
            f"expected {FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT} negatives, "
            f"selected {len(selected)}"
        )
    return selected


def generate_prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    analytics = analytic_catalog(extracted)
    components = component_catalog(extracted)
    selected_analytics = [analytics[item] for item in SELECTED_ANALYTIC_IDS]
    zero_ids = select_zero_analytic_sample(extracted)
    pairs = [
        forward_aggregate_pair(item, extracted, source)
        for item in selected_analytics
    ]
    pairs.extend(
        zero_forward_pair(analytics[item], extracted, source) for item in zero_ids
    )
    pairs.extend(
        reverse_aggregate_pair(components[item], extracted, source)
        for item in SELECTED_REVERSE_COMPONENT_IDS
    )
    pairs.extend(
        positive_relationship_pair(
            analytic,
            components[FOCUSED_COMPONENT_BY_ANALYTIC[analytic["external_id"]]],
            extracted,
            source,
        )
        for analytic in selected_analytics
    )
    pairs.extend(
        property_constrained_pair(analytic, extracted, source)
        for analytic in selected_analytics
    )
    pairs.extend(
        negative_relationship_pair(
            analytic,
            components[NEGATIVE_COMPONENT_BY_ANALYTIC[analytic["external_id"]]],
            extracted,
            source,
        )
        for analytic in selected_analytics
    )
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise AnalyticDataComponentParserError("prototype pair IDs are not unique")
    return pairs


def generate_full_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str], dict[str, str]]:
    analytics = analytic_catalog(extracted)
    components = component_catalog(extracted)
    zero_ids_all = {item["external_id"] for item in extracted["zero_analytics"]}
    zero_sample_ids = select_zero_analytic_sample(extracted)
    forward = [
        forward_aggregate_pair(item, extracted, source)
        for item in extracted["analytics"]
        if item["external_id"] not in zero_ids_all
    ]
    forward.extend(
        zero_forward_pair(analytics[item], extracted, source)
        for item in zero_sample_ids
    )
    reverse = [
        reverse_aggregate_pair(item, extracted, source)
        for item in extracted["data_components"]
    ]
    positives = []
    for analytic in extracted["analytics"]:
        child_components, _ = components_and_paths_for_analytic(analytic, extracted)
        if child_components:
            positives.append(
                positive_relationship_pair(
                    analytic, child_components[0], extracted, source
                )
            )
    property_pairs = [
        property_constrained_pair(item, extracted, source)
        for item in extracted["analytics"]
    ]
    negative_cases = select_full_negative_cases(extracted)
    negatives = [
        negative_relationship_pair(
            analytics[analytic_id], components[component_id], extracted, source
        )
        for analytic_id, component_id in sorted(negative_cases.items())
    ]
    pairs = forward + reverse + positives + property_pairs + negatives
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise AnalyticDataComponentParserError("full pair IDs are not unique")
    return pairs, zero_sample_ids, negative_cases


def parsed_data(extracted: dict[str, Any]) -> dict[str, Any]:
    analytic_rows = {}
    for analytic in extracted["analytics"]:
        components, paths = components_and_paths_for_analytic(analytic, extracted)
        analytic_rows[analytic["external_id"]] = {
            "analytic": analytic,
            "data_components": components,
            "analytic_data_component_paths": paths,
        }
    component_rows = {}
    for component in extracted["data_components"]:
        analytics, _ = analytics_and_paths_for_component(component, extracted)
        component_rows[component["external_id"]] = {
            "data_component": component,
            "analytic_count": len(analytics),
            "analytic_external_ids": [item["external_id"] for item in analytics],
            "windows_event_log_source_rows": property_rows_for_component(
                component, extracted
            ),
        }
    return {"analytics": analytic_rows, "data_components": component_rows}


def case_counts(pairs: list[dict[str, Any]]) -> dict[str, int]:
    return {
        name: sum(pair["case_type"] == name for pair in pairs)
        for name in sorted({pair["case_type"] for pair in pairs})
    }


def shared_scope(source: dict[str, Any], *, prototype_only: bool) -> dict[str, Any]:
    return {
        "domain": source["domain"],
        "source_type": "x-mitre-analytic",
        "target_type": "x-mitre-data-component",
        "relationship_type": "x_mitre_log_source_references",
        "answer_scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "zero_analytic_sampling_note": ZERO_ANALYTIC_SAMPLING_NOTE,
        "reverse_enumeration_threshold": REVERSE_ENUMERATION_THRESHOLD,
        "reverse_sample_size": REVERSE_SAMPLE_SIZE,
        "reverse_sample_order": "analytic_external_id_ascending",
        "property_filter_note": PROPERTY_FILTER_NOTE,
        "revoked_and_deprecated_excluded": True,
        "prototype_only": prototype_only,
    }


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    counts = case_counts(pairs)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_analytic_data_component_prototype",
        "source": source,
        "scope": shared_scope(source, prototype_only=True),
        "selection": {
            "analytic_external_ids": list(SELECTED_ANALYTIC_IDS),
            "reverse_data_component_external_ids": list(
                SELECTED_REVERSE_COMPONENT_IDS
            ),
            "zero_analytic_sample_external_ids": select_zero_analytic_sample(
                extracted
            ),
            "pair_count": len(pairs),
            "forward_positive_pairs": counts.get(
                "aggregate_analytic_data_components", 0
            ),
            "forward_zero_path_pairs": counts.get(
                "aggregate_analytic_no_data_components", 0
            ),
            "reverse_enumerated_pairs": counts.get(
                "aggregate_data_component_analytics", 0
            ),
            "reverse_capped_pairs": counts.get(
                "aggregate_data_component_analytics_capped", 0
            ),
            "reverse_zero_path_pairs": counts.get(
                "aggregate_data_component_no_analytics", 0
            ),
            "positive_relationship_pairs": counts.get(
                "positive_analytic_data_component_relationship", 0
            ),
            "negative_relationship_pairs": counts.get(
                "negative_analytic_data_component_relationship", 0
            ),
            "property_constrained_pairs": sum(
                counts.get(name, 0)
                for name in (
                    "aggregate_analytic_property_data_components",
                    "aggregate_analytic_no_property_data_components",
                )
            ),
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "parsed_data": parsed_data(extracted),
        "pairs": pairs,
    }


def full_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs, zero_sample_ids, negative_cases = generate_full_pairs(extracted, source)
    counts = case_counts(pairs)
    positive_count = counts.get("positive_analytic_data_component_relationship", 0)
    negative_count = counts.get("negative_analytic_data_component_relationship", 0)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_full_analytic_data_component_golden_set",
        "source": source,
        "scope": {
            **shared_scope(source, prototype_only=False),
            "one_forward_aggregate_per_linked_analytic": True,
            "one_reverse_aggregate_per_active_data_component": True,
            "one_property_constrained_pair_per_active_analytic": True,
        },
        "selection": {
            "pair_count": len(pairs),
            "forward_positive_pairs": counts.get(
                "aggregate_analytic_data_components", 0
            ),
            "forward_zero_path_pairs": counts.get(
                "aggregate_analytic_no_data_components", 0
            ),
            "reverse_enumerated_pairs": counts.get(
                "aggregate_data_component_analytics", 0
            ),
            "reverse_capped_pairs": counts.get(
                "aggregate_data_component_analytics_capped", 0
            ),
            "reverse_zero_path_pairs": counts.get(
                "aggregate_data_component_no_analytics", 0
            ),
            "positive_relationship_pairs": positive_count,
            "negative_relationship_pairs": negative_count,
            "explicit_boolean_negative_ratio": negative_count
            / (positive_count + negative_count),
            "property_constrained_positive_pairs": counts.get(
                "aggregate_analytic_property_data_components", 0
            ),
            "property_constrained_zero_path_pairs": counts.get(
                "aggregate_analytic_no_property_data_components", 0
            ),
            "embedded_forward_distinct_edge_fact_count": sum(
                len(pair.get("expected_data_components", []))
                for pair in pairs
                if pair["case_type"] == "aggregate_analytic_data_components"
            ),
            "embedded_reverse_total_fact_count": sum(
                pair.get("expected_analytic_total_count", 0)
                for pair in pairs
                if pair["case_type"]
                in {
                    "aggregate_data_component_analytics",
                    "aggregate_data_component_analytics_capped",
                    "aggregate_data_component_no_analytics",
                }
            ),
            "embedded_property_distinct_edge_fact_count": sum(
                len(pair.get("expected_data_components", []))
                for pair in pairs
                if pair["case_type"]
                in {
                    "aggregate_analytic_property_data_components",
                    "aggregate_analytic_no_property_data_components",
                }
            ),
        },
        "zero_analytic_selection": {
            "method": ZERO_ANALYTIC_SAMPLING_NOTE,
            "selected_external_ids": zero_sample_ids,
            "total_active_zero_path_count": len(extracted["zero_analytics"]),
            "all_selected_cases_verified_absent_by_extracted_path_set": True,
        },
        "negative_selection": {
            "method": (
                "Preserve the five prototype negatives, then choose 338 evenly "
                "spaced active Analytics and rotate active popular and orphan "
                "DataComponent probes until a graph-verified non-edge is found."
            ),
            "selected_analytic_to_candidate_data_component": negative_cases,
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
        default=HERE / "golden_set_analytic_datacomponent_prototype.json",
    )
    parser.add_argument(
        "--generate-full",
        action="store_true",
        help="write the full active Analytic/DataComponent golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_analytic_datacomponent.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    extracted = extract_analytic_datacomponent_scope(bundle)
    payload = (
        full_payload(extracted, source)
        if args.generate_full
        else prototype_payload(extracted, source)
    )
    output = args.full_output if args.generate_full else args.output
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
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
        AnalyticDataComponentParserError,
        DetectionStrategyParserError,
        SubtechniqueParserError,
    ) as exc:
        raise SystemExit(f"FAIL: {exc}")
