#!/usr/bin/env python3
"""Generate deterministic Technique -[SUBTECHNIQUE_OF]-> Technique golden sets."""

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
SELECTED_PARENT_IDS = ("T1027", "T1055", "T1059", "T1543", "T1547")
FOCUSED_CHILD_BY_PARENT = {
    "T1027": "T1027.001",
    "T1055": "T1055.001",
    "T1059": "T1059.001",
    "T1543": "T1543.001",
    "T1547": "T1547.001",
}
PROTOTYPE_ZERO_PATH_TECHNIQUE_IDS = (
    "T1005",  # top-level leaf
    "T1012",  # top-level leaf
    "T1014",  # top-level leaf
    "T1055.001",  # subtechnique; MITRE does not nest subtechniques
    "T1059.001",  # subtechnique; MITRE does not nest subtechniques
)
NEGATIVE_CHILD_BY_PARENT = {
    "T1027": "T1055",
    "T1055": "T1027",
    "T1059": "T1566",
    "T1543": "T1496",
    "T1547": "T1190",
}
FULL_ZERO_PATH_TOP_LEVEL_COUNT = 10
FULL_ZERO_PATH_SUBTECHNIQUE_COUNT = 10
FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT = 20
FULL_NEGATIVE_PROBE_TECHNIQUE_IDS = (
    "T1027",
    "T1055",
    "T1059",
    "T1566",
    "T1496",
    "T1486",
    "T1190",
    "T1531",
    "T1649",
    "T1583.001",
)
PLATFORM_FILTER = "Linux"
SCOPE = "active_attack_pattern_subtechnique_of_active_attack_pattern"
METHODOLOGY_NOTE = (
    "Only active STIX subtechnique-of relationships whose source and target "
    "are active Enterprise ATT&CK attack-pattern objects are included. The "
    "source is the child subtechnique and the target is its one parent. Parent "
    "identification is exhaustive for every active child; reverse aggregation "
    "is exhaustive for every parent. Parentless reverse cases use a documented "
    "bounded stratified sample rather than duplicating all non-parent nodes. "
    "Platform filters apply to each child subtechnique's own platforms field."
)
ZERO_PATH_SAMPLING_NOTE = (
    "Select 20 active non-parent techniques deterministically: preserve the "
    "five prototype zero-path cases, then use evenly spaced external-ID order "
    "to reach 10 top-level leaf techniques and 10 subtechniques. This covers "
    "both non-parent shapes without creating cases for all 596 non-parents."
)


class SubtechniqueParserError(RuntimeError):
    """Raised when subtechnique hierarchy data violates expected invariants."""


def require_unique_external_ids(
    objects: list[dict[str, Any]], description: str
) -> dict[str, dict[str, Any]]:
    rows = [(mitre_external_id(obj), obj) for obj in objects]
    missing = [obj["id"] for external_id, obj in rows if external_id is None]
    if missing:
        raise SubtechniqueParserError(
            f"active {description} objects lack MITRE external IDs: "
            + ", ".join(sorted(missing))
        )
    result = {external_id: obj for external_id, obj in rows if external_id}
    if len(result) != len(rows):
        raise SubtechniqueParserError(
            f"active {description} objects have duplicate MITRE external IDs"
        )
    return result


def compact_technique(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
        "platforms": sorted(set(obj.get("x_mitre_platforms", []))),
    }


def extract_subtechnique_scope(bundle: dict[str, Any]) -> dict[str, Any]:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise SubtechniqueParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]
    active_technique_objects = [
        obj
        for obj in typed
        if obj.get("type") == "attack-pattern" and is_active(obj)
    ]
    technique_catalog = require_unique_external_ids(
        active_technique_objects, "attack-pattern"
    )
    technique_by_stix = {obj["id"]: obj for obj in active_technique_objects}
    all_relationships = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "subtechnique-of"
    ]
    active_relationships = [
        rel
        for rel in all_relationships
        if is_active(rel)
        and rel.get("source_ref") in technique_by_stix
        and rel.get("target_ref") in technique_by_stix
    ]
    paths = [
        {
            "subtechnique_ref": rel["source_ref"],
            "parent_technique_ref": rel["target_ref"],
            "subtechnique_of_relationship_stix_id": rel["id"],
        }
        for rel in active_relationships
    ]
    paths.sort(
        key=lambda path: (
            mitre_external_id(technique_by_stix[path["parent_technique_ref"]])
            or "",
            mitre_external_id(technique_by_stix[path["subtechnique_ref"]])
            or "",
            path["subtechnique_of_relationship_stix_id"],
        )
    )
    pair_keys = {
        (path["subtechnique_ref"], path["parent_technique_ref"])
        for path in paths
    }
    if len(pair_keys) != len(paths):
        raise SubtechniqueParserError(
            "multiple active relationships encode the same child/parent pair"
        )

    paths_by_child: dict[str, list[dict[str, Any]]] = {}
    paths_by_parent: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        paths_by_child.setdefault(path["subtechnique_ref"], []).append(path)
        paths_by_parent.setdefault(path["parent_technique_ref"], []).append(path)
    if any(len(child_paths) != 1 for child_paths in paths_by_child.values()):
        raise SubtechniqueParserError(
            "an active subtechnique does not have exactly one active parent"
        )

    flagged_subtechnique_ids = {
        obj["id"]
        for obj in active_technique_objects
        if obj.get("x_mitre_is_subtechnique", False)
    }
    relationship_child_ids = set(paths_by_child)
    if flagged_subtechnique_ids != relationship_child_ids:
        missing_edges = flagged_subtechnique_ids - relationship_child_ids
        unflagged_children = relationship_child_ids - flagged_subtechnique_ids
        raise SubtechniqueParserError(
            "subtechnique flags and active hierarchy edges disagree: "
            f"missing_edges={len(missing_edges)}, "
            f"unflagged_children={len(unflagged_children)}"
        )
    parent_ids = set(paths_by_parent)
    nested_parents = parent_ids & flagged_subtechnique_ids
    if nested_parents:
        raise SubtechniqueParserError(
            "active subtechniques unexpectedly act as parent techniques"
        )

    compact_catalog = {
        external_id: compact_technique(obj)
        for external_id, obj in technique_catalog.items()
    }
    compact_by_stix = {
        item["stix_id"]: item for item in compact_catalog.values()
    }
    parents = sorted(
        [compact_by_stix[stix_id] for stix_id in parent_ids],
        key=lambda item: (item["external_id"] or "", item["stix_id"]),
    )
    subtechniques = sorted(
        [compact_by_stix[stix_id] for stix_id in flagged_subtechnique_ids],
        key=lambda item: (item["external_id"] or "", item["stix_id"]),
    )
    top_level_leaves = sorted(
        [
            item
            for item in compact_catalog.values()
            if not item["is_subtechnique"] and item["stix_id"] not in parent_ids
        ],
        key=lambda item: (item["external_id"] or "", item["stix_id"]),
    )
    linux_paths = [
        path
        for path in paths
        if "Linux" in compact_by_stix[path["subtechnique_ref"]]["platforms"]
    ]
    parents_with_linux = {path["parent_technique_ref"] for path in linux_paths}
    return {
        "active_technique_catalog": [
            compact_catalog[external_id]
            for external_id in sorted(compact_catalog)
        ],
        "parents": parents,
        "subtechniques": subtechniques,
        "top_level_leaves": top_level_leaves,
        "paths": paths,
        "children_count_by_parent": {
            compact_by_stix[parent_ref]["external_id"]: len(parent_paths)
            for parent_ref, parent_paths in paths_by_parent.items()
        },
        "global_coverage": {
            "active_technique_count": len(active_technique_objects),
            "active_subtechnique_of_edge_count": len(paths),
            "active_subtechnique_count": len(subtechniques),
            "active_parent_technique_count": len(parents),
            "active_top_level_leaf_technique_count": len(top_level_leaves),
            "active_nonparent_technique_count": (
                len(active_technique_objects) - len(parents)
            ),
            "subtechniques_with_exactly_one_parent": len(paths_by_child),
            "parent_techniques_that_are_subtechniques": len(nested_parents),
            "parents_with_one_or_more_linux_subtechniques": len(
                parents_with_linux
            ),
            "parents_with_zero_linux_subtechniques": (
                len(parents) - len(parents_with_linux)
            ),
            "linux_subtechnique_edge_count": len(linux_paths),
        },
        "extraction_audit": {
            "bundle_subtechnique_of_relationship_count": len(all_relationships),
            "inactive_or_dangling_subtechnique_of_relationship_count": (
                len(all_relationships) - len(paths)
            ),
            "flagged_subtechnique_without_active_parent_count": 0,
            "active_relationship_child_without_subtechnique_flag_count": 0,
        },
    }


def technique_label(technique: dict[str, Any]) -> str:
    return f"{technique['external_id']} ({technique['name']})"


def technique_catalog(extracted: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["external_id"]: item
        for item in extracted["active_technique_catalog"]
    }


def children_and_paths_for_parent(
    parent: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_stix = {
        item["stix_id"]: item for item in extracted["active_technique_catalog"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["parent_technique_ref"] == parent["stix_id"]
    ]
    child_ids = sorted(
        {path["subtechnique_ref"] for path in paths},
        key=lambda stix_id: (
            by_stix[stix_id]["external_id"] or "",
            stix_id,
        ),
    )
    return [by_stix[stix_id] for stix_id in child_ids], paths


def parent_and_path_for_child(
    child: dict[str, Any], extracted: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    by_stix = {
        item["stix_id"]: item for item in extracted["active_technique_catalog"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["subtechnique_ref"] == child["stix_id"]
    ]
    if len(paths) != 1:
        raise SubtechniqueParserError(
            f"expected one parent for {child['external_id']}, found {len(paths)}"
        )
    path = paths[0]
    return by_stix[path["parent_technique_ref"]], path


def hierarchy_provenance(
    parent: dict[str, Any],
    children: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    queried_child: dict[str, Any] | None = None,
    platform_filter: str | None = None,
) -> dict[str, Any]:
    result = {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "parent_technique_stix_id": parent["stix_id"],
        "subtechnique_stix_ids": [child["stix_id"] for child in children],
        "subtechnique_of_relationship_stix_ids": [
            path["subtechnique_of_relationship_stix_id"] for path in paths
        ],
        "relationship_paths": paths,
    }
    if queried_child is not None:
        result["queried_subtechnique_stix_id"] = queried_child["stix_id"]
    if platform_filter is not None:
        result["platform_filter"] = platform_filter
        result["platform_source_field"] = "attack-pattern.x_mitre_platforms"
        result["platform_applies_to"] = "child_subtechnique"
    return result


def parent_identification_pair(
    child: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    parent, path = parent_and_path_for_child(child, extracted)
    return {
        "id": f"subtechnique-parent-{child['external_id'].lower()}",
        "case_type": "identify_subtechnique_parent",
        "relationship_type": "technique_subtechnique_of_technique",
        "question": f"What is the parent technique of {technique_label(child)}?",
        "expected_answer": (
            f"The parent technique of {technique_label(child)} is "
            f"{technique_label(parent)} in the pinned Enterprise ATT&CK snapshot."
        ),
        "subtechnique": child,
        "expected_parent": parent,
        "provenance": hierarchy_provenance(
            parent, [child], [path], source, queried_child=child
        ),
    }


def parent_aggregate_pair(
    parent: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    children, paths = children_and_paths_for_parent(parent, extracted)
    if not children:
        return zero_subtechniques_pair(parent, extracted, source)
    return {
        "id": f"parent-subtechniques-{parent['external_id'].lower()}",
        "case_type": "aggregate_parent_subtechniques",
        "relationship_type": "technique_subtechnique_of_technique",
        "question": f"What are the subtechniques of {technique_label(parent)}?",
        "expected_answer": (
            f"The active subtechniques of {technique_label(parent)} are "
            f"{natural_list([technique_label(child) for child in children])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "parent_technique": parent,
        "expected_subtechniques": children,
        "provenance": hierarchy_provenance(
            parent, children, paths, source
        ),
    }


def zero_subtechniques_pair(
    technique: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    children, paths = children_and_paths_for_parent(technique, extracted)
    if children or paths:
        raise SubtechniqueParserError(
            f"zero-path technique {technique['external_id']} has active children"
        )
    return {
        "id": f"technique-has-no-subtechniques-{technique['external_id'].lower()}",
        "case_type": "aggregate_technique_no_subtechniques",
        "relationship_type": "technique_subtechnique_of_technique",
        "question": f"What are the subtechniques of {technique_label(technique)}?",
        "expected_answer": (
            "No active subtechnique-of relationship targets "
            f"{technique_label(technique)} in the pinned Enterprise ATT&CK "
            "snapshot."
        ),
        "parent_candidate": technique,
        "expected_subtechniques": [],
        "provenance": hierarchy_provenance(technique, [], [], source),
    }


def positive_relationship_pair(
    child: dict[str, Any],
    parent: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    actual_parent, path = parent_and_path_for_child(child, extracted)
    if actual_parent["stix_id"] != parent["stix_id"]:
        raise SubtechniqueParserError(
            f"positive pair {child['external_id']} -> {parent['external_id']} "
            "does not exist"
        )
    return {
        "id": (
            f"subtechnique-of-positive-{child['external_id'].lower()}-"
            f"{parent['external_id'].lower()}"
        ),
        "case_type": "positive_subtechnique_relationship",
        "relationship_type": "technique_subtechnique_of_technique",
        "question": (
            f"Is {technique_label(child)} a subtechnique of "
            f"{technique_label(parent)}?"
        ),
        "expected_answer": (
            f"Yes. {technique_label(child)} is a subtechnique of "
            f"{technique_label(parent)} in the pinned Enterprise ATT&CK snapshot."
        ),
        "candidate_subtechnique": child,
        "queried_parent": parent,
        "relationship_exists": True,
        "expected_subtechniques": [child],
        "provenance": hierarchy_provenance(
            parent, [child], [path], source, queried_child=child
        ),
    }


def negative_relationship_pair(
    candidate_child: dict[str, Any],
    queried_parent: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    path_keys = {
        (path["subtechnique_ref"], path["parent_technique_ref"])
        for path in extracted["paths"]
    }
    key = (candidate_child["stix_id"], queried_parent["stix_id"])
    if key in path_keys:
        raise SubtechniqueParserError(
            f"negative pair {candidate_child['external_id']} -> "
            f"{queried_parent['external_id']} exists"
        )
    if candidate_child["stix_id"] == queried_parent["stix_id"]:
        raise SubtechniqueParserError("negative pair cannot compare a node to itself")
    return {
        "id": (
            f"subtechnique-of-negative-{candidate_child['external_id'].lower()}-"
            f"{queried_parent['external_id'].lower()}"
        ),
        "case_type": "negative_subtechnique_relationship",
        "relationship_type": "technique_subtechnique_of_technique",
        "question": (
            f"Is {technique_label(candidate_child)} a subtechnique of "
            f"{technique_label(queried_parent)}?"
        ),
        "expected_answer": (
            "No active subtechnique-of relationship exists from "
            f"{technique_label(candidate_child)} to "
            f"{technique_label(queried_parent)} in the pinned Enterprise "
            "ATT&CK snapshot."
        ),
        "candidate_subtechnique": candidate_child,
        "queried_parent": queried_parent,
        "relationship_exists": False,
        "expected_subtechniques": [],
        "provenance": hierarchy_provenance(
            queried_parent, [], [], source, queried_child=candidate_child
        ),
    }


def platform_aggregate_pair(
    parent: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
    platform: str = PLATFORM_FILTER,
) -> dict[str, Any]:
    children, paths = children_and_paths_for_parent(parent, extracted)
    matching = [child for child in children if platform in child["platforms"]]
    matching_ids = {child["stix_id"] for child in matching}
    matching_paths = [
        path for path in paths if path["subtechnique_ref"] in matching_ids
    ]
    slug = platform.lower().replace(" ", "-")
    if not matching:
        return {
            "id": (
                f"parent-has-no-{slug}-subtechniques-"
                f"{parent['external_id'].lower()}"
            ),
            "case_type": "aggregate_parent_no_platform_subtechniques",
            "relationship_type": "technique_subtechnique_of_technique",
            "question": (
                f"Which subtechniques of {technique_label(parent)} apply to "
                f"{platform}?"
            ),
            "expected_answer": (
                f"None of the active subtechniques of {technique_label(parent)} "
                f"have {platform} in their own platforms field in the pinned "
                "Enterprise ATT&CK snapshot."
            ),
            "parent_technique": parent,
            "platform_filter": platform,
            "expected_subtechniques": [],
            "provenance": hierarchy_provenance(
                parent, [], [], source, platform_filter=platform
            ),
        }
    return {
        "id": (
            f"parent-{slug}-subtechniques-{parent['external_id'].lower()}"
        ),
        "case_type": "aggregate_parent_platform_subtechniques",
        "relationship_type": "technique_subtechnique_of_technique",
        "question": (
            f"Which subtechniques of {technique_label(parent)} apply to "
            f"{platform}?"
        ),
        "expected_answer": (
            f"The subtechniques of {technique_label(parent)} whose own platforms "
            f"include {platform} are "
            f"{natural_list([technique_label(child) for child in matching])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "parent_technique": parent,
        "platform_filter": platform,
        "expected_subtechniques": matching,
        "provenance": hierarchy_provenance(
            parent,
            matching,
            matching_paths,
            source,
            platform_filter=platform,
        ),
    }


def evenly_spaced_items(items: list[str], count: int) -> list[str]:
    if count <= 0:
        return []
    if len(items) < count:
        raise SubtechniqueParserError(
            f"cannot select {count} items from {len(items)} candidates"
        )
    if count == 1:
        return [items[len(items) // 2]]
    indices = [
        round(index * (len(items) - 1) / (count - 1))
        for index in range(count)
    ]
    if len(indices) != len(set(indices)):
        raise SubtechniqueParserError("evenly spaced selection produced duplicates")
    return [items[index] for index in indices]


def select_full_zero_path_sample(extracted: dict[str, Any]) -> list[str]:
    catalog = technique_catalog(extracted)
    parent_ids = {item["external_id"] for item in extracted["parents"]}
    prototype = [catalog[item] for item in PROTOTYPE_ZERO_PATH_TECHNIQUE_IDS]
    if any(item["external_id"] in parent_ids for item in prototype):
        raise SubtechniqueParserError("prototype zero-path technique became a parent")
    fixed_top = sorted(
        item["external_id"] for item in prototype if not item["is_subtechnique"]
    )
    fixed_sub = sorted(
        item["external_id"] for item in prototype if item["is_subtechnique"]
    )
    top_candidates = [
        item["external_id"]
        for item in extracted["top_level_leaves"]
        if item["external_id"] not in fixed_top
    ]
    sub_candidates = [
        item["external_id"]
        for item in extracted["subtechniques"]
        if item["external_id"] not in fixed_sub
    ]
    selected_top = fixed_top + evenly_spaced_items(
        top_candidates, FULL_ZERO_PATH_TOP_LEVEL_COUNT - len(fixed_top)
    )
    selected_sub = fixed_sub + evenly_spaced_items(
        sub_candidates, FULL_ZERO_PATH_SUBTECHNIQUE_COUNT - len(fixed_sub)
    )
    selected = sorted(selected_top + selected_sub)
    if len(selected) != len(set(selected)):
        raise SubtechniqueParserError("zero-path sample contains duplicates")
    return selected


def select_full_negative_cases(extracted: dict[str, Any]) -> dict[str, str]:
    catalog = technique_catalog(extracted)
    parents = {item["external_id"]: item for item in extracted["parents"]}
    path_keys = {
        (path["subtechnique_ref"], path["parent_technique_ref"])
        for path in extracted["paths"]
    }
    selected = dict(NEGATIVE_CHILD_BY_PARENT)
    needed = FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT - len(selected)
    eligible = [item for item in sorted(parents) if item not in selected]
    for offset, parent_id in enumerate(evenly_spaced_items(eligible, needed)):
        parent = parents[parent_id]
        probes = (
            FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[offset:]
            + FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[:offset]
        )
        for child_id in probes:
            child = catalog.get(child_id)
            if child is None or child["stix_id"] == parent["stix_id"]:
                continue
            if (child["stix_id"], parent["stix_id"]) not in path_keys:
                selected[parent_id] = child_id
                break
        else:
            raise SubtechniqueParserError(
                f"no configured negative probe is absent for {parent_id}"
            )
    if len(selected) != FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT:
        raise SubtechniqueParserError(
            f"expected {FULL_NEGATIVE_RELATIONSHIP_CASE_COUNT} negatives, "
            f"selected {len(selected)}"
        )
    return selected


def generate_prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    catalog = technique_catalog(extracted)
    parents = [catalog[item] for item in SELECTED_PARENT_IDS]
    children = [catalog[FOCUSED_CHILD_BY_PARENT[item]] for item in SELECTED_PARENT_IDS]
    pairs = [
        parent_identification_pair(child, extracted, source) for child in children
    ]
    pairs.extend(parent_aggregate_pair(parent, extracted, source) for parent in parents)
    pairs.extend(
        positive_relationship_pair(child, parent, extracted, source)
        for child, parent in zip(children, parents)
    )
    pairs.extend(
        platform_aggregate_pair(parent, extracted, source)
        for parent in parents
    )
    pairs.extend(
        negative_relationship_pair(
            catalog[NEGATIVE_CHILD_BY_PARENT[parent["external_id"]]],
            parent,
            extracted,
            source,
        )
        for parent in parents
    )
    pairs.extend(
        zero_subtechniques_pair(catalog[item], extracted, source)
        for item in PROTOTYPE_ZERO_PATH_TECHNIQUE_IDS
    )
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise SubtechniqueParserError("prototype pair IDs are not unique")
    return pairs


def generate_full_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str], dict[str, str]]:
    catalog = technique_catalog(extracted)
    parents = {item["external_id"]: item for item in extracted["parents"]}
    parent_identification = [
        parent_identification_pair(child, extracted, source)
        for child in extracted["subtechniques"]
    ]
    aggregates = [
        parent_aggregate_pair(parents[item], extracted, source)
        for item in sorted(parents)
    ]
    zero_sample_ids = select_full_zero_path_sample(extracted)
    zero_aggregates = [
        zero_subtechniques_pair(catalog[item], extracted, source)
        for item in zero_sample_ids
    ]
    positives = []
    for parent_id in sorted(parents):
        parent = parents[parent_id]
        children, _ = children_and_paths_for_parent(parent, extracted)
        positives.append(
            positive_relationship_pair(children[0], parent, extracted, source)
        )
    platform = [
        platform_aggregate_pair(parents[item], extracted, source)
        for item in sorted(parents)
    ]
    negative_cases = select_full_negative_cases(extracted)
    negatives = [
        negative_relationship_pair(
            catalog[child_id], parents[parent_id], extracted, source
        )
        for parent_id, child_id in sorted(negative_cases.items())
    ]
    pairs = (
        parent_identification
        + aggregates
        + zero_aggregates
        + positives
        + platform
        + negatives
    )
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise SubtechniqueParserError("full pair IDs are not unique")
    return pairs, zero_sample_ids, negative_cases


def parsed_data(extracted: dict[str, Any]) -> dict[str, Any]:
    parent_rows = {}
    for parent in extracted["parents"]:
        children, paths = children_and_paths_for_parent(parent, extracted)
        parent_rows[parent["external_id"]] = {
            "parent_technique": parent,
            "subtechniques": children,
            "relationship_paths": paths,
        }
    child_rows = {}
    for child in extracted["subtechniques"]:
        parent, path = parent_and_path_for_child(child, extracted)
        child_rows[child["external_id"]] = {
            "subtechnique": child,
            "parent_technique": parent,
            "relationship_path": path,
        }
    return {"parents": parent_rows, "subtechniques": child_rows}


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_subtechnique_hierarchy_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "attack-pattern",
            "target_type": "attack-pattern",
            "relationship_type": "subtechnique-of",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "zero_path_sampling_note": ZERO_PATH_SAMPLING_NOTE,
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "parent_external_ids": list(SELECTED_PARENT_IDS),
            "pair_count": len(pairs),
            "parent_identification_pairs": 5,
            "parent_aggregate_pairs": 5,
            "positive_relationship_pairs": 5,
            "platform_constrained_pairs": 5,
            "negative_relationship_pairs": 5,
            "zero_path_aggregate_pairs": 5,
            "negative_share_of_all_pairs": 5 / len(pairs),
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
    counts = {
        name: sum(pair["case_type"] == name for pair in pairs)
        for name in {pair["case_type"] for pair in pairs}
    }
    positive_count = counts.get("positive_subtechnique_relationship", 0)
    negative_count = counts.get("negative_subtechnique_relationship", 0)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_full_subtechnique_hierarchy_golden_set",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "attack-pattern",
            "target_type": "attack-pattern",
            "relationship_type": "subtechnique-of",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "zero_path_sampling_note": ZERO_PATH_SAMPLING_NOTE,
            "revoked_and_deprecated_excluded": True,
            "one_parent_identification_per_active_subtechnique": True,
            "one_aggregate_per_active_parent": True,
            "one_linux_constrained_pair_per_active_parent": True,
        },
        "selection": {
            "active_technique_count": len(extracted["active_technique_catalog"]),
            "pair_count": len(pairs),
            "parent_identification_pairs": counts.get(
                "identify_subtechnique_parent", 0
            ),
            "parent_aggregate_pairs": counts.get(
                "aggregate_parent_subtechniques", 0
            ),
            "zero_path_aggregate_pairs": counts.get(
                "aggregate_technique_no_subtechniques", 0
            ),
            "zero_path_top_level_leaf_pairs": sum(
                not technique_catalog(extracted)[item]["is_subtechnique"]
                for item in zero_sample_ids
            ),
            "zero_path_subtechnique_pairs": sum(
                technique_catalog(extracted)[item]["is_subtechnique"]
                for item in zero_sample_ids
            ),
            "positive_relationship_pairs": positive_count,
            "negative_relationship_pairs": negative_count,
            "explicit_boolean_negative_ratio": (
                negative_count / (positive_count + negative_count)
            ),
            "platform_constrained_positive_pairs": counts.get(
                "aggregate_parent_platform_subtechniques", 0
            ),
            "platform_constrained_zero_path_pairs": counts.get(
                "aggregate_parent_no_platform_subtechniques", 0
            ),
            "embedded_platform_constrained_fact_count": sum(
                len(pair.get("expected_subtechniques", []))
                for pair in pairs
                if pair["case_type"]
                in {
                    "aggregate_parent_platform_subtechniques",
                    "aggregate_parent_no_platform_subtechniques",
                }
            ),
            "embedded_parent_identification_fact_count": counts.get(
                "identify_subtechnique_parent", 0
            ),
            "embedded_parent_aggregate_fact_count": sum(
                len(pair.get("expected_subtechniques", []))
                for pair in pairs
                if pair["case_type"] == "aggregate_parent_subtechniques"
            ),
        },
        "zero_path_selection": {
            "method": ZERO_PATH_SAMPLING_NOTE,
            "selected_external_ids": zero_sample_ids,
            "all_cases_verified_absent_by_extracted_path_set": True,
        },
        "negative_selection": {
            "method": (
                "preserve the five prototype negatives, then choose 15 evenly "
                "spaced active parents and rotate active probe techniques until "
                "a graph-verified child-to-parent non-edge is found"
            ),
            "selected_parent_to_candidate_child": negative_cases,
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
        default=HERE / "golden_set_subtechnique_prototype.json",
    )
    parser.add_argument(
        "--generate-full",
        action="store_true",
        help="write the full all-active-hierarchy golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_subtechnique.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    extracted = extract_subtechnique_scope(bundle)
    if args.generate_full:
        payload = full_payload(extracted, source)
        output = args.full_output
    else:
        payload = prototype_payload(extracted, source)
        output = args.output
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
    except SubtechniqueParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
