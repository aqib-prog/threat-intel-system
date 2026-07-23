#!/usr/bin/env python3
"""Generate a scoped group-to-technique direct/campaign prototype."""

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
SELECTED_GROUP_IDS = ("G0007", "G0016", "G0032", "G0034", "G0046")
FOCUSED_TECHNIQUE_BY_GROUP = {
    "G0007": "T1003",      # APT28 -> OS Credential Dumping
    "G0016": "T1059.001",  # APT29 -> PowerShell
    "G0032": "T1059.003",  # Lazarus Group -> Windows Command Shell
    "G0034": "T1486",      # Sandworm Team -> Data Encrypted for Impact
    "G0046": "T1059.001",  # FIN7 -> PowerShell
}
NEGATIVE_TECHNIQUE_BY_GROUP = {
    "G0007": "T1496",      # APT28 -/-> Resource Hijacking
    "G0016": "T1486",      # APT29 -/-> Data Encrypted for Impact
    "G0046": "T1584.008",  # FIN7 -/-> Network Devices
}
FULL_NEGATIVE_EXISTENCE_CASE_COUNT = 20
FULL_NEGATIVE_PROBE_TECHNIQUE_IDS = (
    "T1496",
    "T1486",
    "T1584.008",
    "T1531",
    "T1649",
    "T1190",
    "T1003.001",
    "T1059.001",
    "T1566.001",
    "T1583.001",
)
MERGED_TECHNIQUE_SCOPE = (
    "direct_group_to_technique_union_campaign_attributed"
)
METHODOLOGY_NOTE = (
    "The answer is the union of active direct intrusion-set --uses--> "
    "attack-pattern paths and active campaign --attributed-to--> intrusion-set "
    "plus campaign --uses--> attack-pattern paths. Software-mediated techniques "
    "are excluded. Parent and sub-technique entries are both kept without "
    "deduplication when each has a qualifying edge; this may include a small "
    "number of entries beyond the live group page, but it will not omit any "
    "real technique represented by either included path."
)


class GroupTechniqueParserError(RuntimeError):
    """Raised when the scoped group-to-technique STIX facts are invalid."""


def compact_technique(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
    }


def extract_group_technique_scope(
    bundle: dict[str, Any],
    group_ids: tuple[str, ...] | None = SELECTED_GROUP_IDS,
) -> dict[str, Any]:
    """Extract active direct and campaign-attributed group technique paths."""

    if group_ids is not None and len(group_ids) != len(set(group_ids)):
        raise GroupTechniqueParserError("selected group IDs are not unique")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise GroupTechniqueParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]

    active_group_objects = [
        obj
        for obj in typed
        if obj.get("type") == "intrusion-set" and is_active(obj)
    ]
    group_rows = [
        (mitre_external_id(obj), obj) for obj in active_group_objects
    ]
    missing_external_ids = [
        obj["id"] for external_id, obj in group_rows if external_id is None
    ]
    if missing_external_ids:
        raise GroupTechniqueParserError(
            "active intrusion-set objects lack MITRE external IDs: "
            + ", ".join(sorted(missing_external_ids))
        )
    group_by_external_id = {
        external_id: obj for external_id, obj in group_rows
        if external_id is not None
    }
    if len(group_by_external_id) != len(group_rows):
        raise GroupTechniqueParserError(
            "active intrusion-set objects have duplicate MITRE external IDs"
        )
    if group_ids is None:
        selected_group_objects = [
            group_by_external_id[external_id]
            for external_id in sorted(group_by_external_id)
        ]
    else:
        missing = [
            external_id for external_id in group_ids
            if external_id not in group_by_external_id
        ]
        if missing:
            raise GroupTechniqueParserError(
                "selected active intrusion-set objects are missing: "
                + ", ".join(missing)
            )
        selected_group_objects = [
            group_by_external_id[external_id] for external_id in group_ids
        ]
    selected_group_stix_ids = {obj["id"] for obj in selected_group_objects}

    active_technique_by_id = {
        obj["id"]: obj
        for obj in typed
        if obj.get("type") == "attack-pattern" and is_active(obj)
    }
    active_campaign_by_id = {
        obj["id"]: obj
        for obj in typed
        if obj.get("type") == "campaign" and is_active(obj)
    }
    all_uses_relationships = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "uses"
    ]
    active_uses_relationships = [
        obj for obj in all_uses_relationships if is_active(obj)
    ]
    all_attribution_relationships = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "attributed-to"
    ]
    active_attribution_relationships = [
        obj for obj in all_attribution_relationships if is_active(obj)
    ]

    direct_relationships = [
        relationship
        for relationship in active_uses_relationships
        if relationship.get("source_ref") in selected_group_stix_ids
        and relationship.get("target_ref") in active_technique_by_id
    ]
    attribution_relationships = [
        relationship
        for relationship in active_attribution_relationships
        if relationship.get("source_ref") in active_campaign_by_id
        and relationship.get("target_ref") in selected_group_stix_ids
    ]
    campaign_ids = {
        relationship["source_ref"] for relationship in attribution_relationships
    }
    campaign_uses_by_campaign: dict[str, list[dict[str, Any]]] = {}
    for relationship in active_uses_relationships:
        source_ref = relationship.get("source_ref")
        if (
            source_ref in campaign_ids
            and relationship.get("target_ref") in active_technique_by_id
        ):
            campaign_uses_by_campaign.setdefault(source_ref, []).append(relationship)

    group_external_by_stix = {
        obj["id"]: mitre_external_id(obj) for obj in selected_group_objects
    }
    technique_external_by_stix = {
        obj["id"]: mitre_external_id(obj)
        for obj in active_technique_by_id.values()
    }
    paths: list[dict[str, Any]] = []
    for relationship in direct_relationships:
        paths.append(
            {
                "path_type": "direct",
                "group_ref": relationship["source_ref"],
                "technique_ref": relationship["target_ref"],
                "direct_uses_relationship_stix_id": relationship["id"],
            }
        )
    for attribution in attribution_relationships:
        campaign_ref = attribution["source_ref"]
        for campaign_uses in campaign_uses_by_campaign.get(campaign_ref, []):
            paths.append(
                {
                    "path_type": "campaign_attributed",
                    "group_ref": attribution["target_ref"],
                    "technique_ref": campaign_uses["target_ref"],
                    "campaign_ref": campaign_ref,
                    "attributed_to_relationship_stix_id": attribution["id"],
                    "campaign_uses_relationship_stix_id": campaign_uses["id"],
                }
            )
    paths.sort(
        key=lambda path: (
            group_external_by_stix[path["group_ref"]] or "",
            technique_external_by_stix[path["technique_ref"]] or "",
            path["path_type"],
            path.get("campaign_ref", ""),
            path.get("direct_uses_relationship_stix_id", ""),
            path.get("attributed_to_relationship_stix_id", ""),
            path.get("campaign_uses_relationship_stix_id", ""),
        )
    )
    path_keys = {
        (
            path["path_type"],
            path["group_ref"],
            path["technique_ref"],
            path.get("campaign_ref"),
            path.get("direct_uses_relationship_stix_id"),
            path.get("attributed_to_relationship_stix_id"),
            path.get("campaign_uses_relationship_stix_id"),
        )
        for path in paths
    }
    if len(path_keys) != len(paths):
        raise GroupTechniqueParserError("duplicate group-to-technique path records")

    referenced_technique_ids = {path["technique_ref"] for path in paths}
    groups = [
        {
            "stix_id": obj["id"],
            "external_id": mitre_external_id(obj),
            "name": obj.get("name"),
            "aliases": list(obj.get("aliases", [])),
        }
        for obj in selected_group_objects
    ]
    techniques = [
        compact_technique(obj)
        for obj in active_technique_by_id.values()
        if obj["id"] in referenced_technique_ids
    ]
    techniques.sort(key=lambda row: (row["external_id"] or "", row["stix_id"]))
    campaigns = [
        {
            "stix_id": obj["id"],
            "external_id": mitre_external_id(obj),
            "name": obj.get("name"),
        }
        for obj in active_campaign_by_id.values()
        if obj["id"] in campaign_ids
    ]
    campaigns.sort(key=lambda row: (row["external_id"] or "", row["stix_id"]))

    scope_metrics_by_group = {}
    for group in groups:
        group_paths = [
            path for path in paths if path["group_ref"] == group["stix_id"]
        ]
        attributed_campaign_ids_for_group = {
            relationship["source_ref"]
            for relationship in attribution_relationships
            if relationship["target_ref"] == group["stix_id"]
        }
        direct_ids = {
            path["technique_ref"]
            for path in group_paths
            if path["path_type"] == "direct"
        }
        campaign_technique_ids = {
            path["technique_ref"]
            for path in group_paths
            if path["path_type"] == "campaign_attributed"
        }
        merged_ids = direct_ids | campaign_technique_ids
        both_ids = direct_ids & campaign_technique_ids
        scope_metrics_by_group[group["stix_id"]] = {
            "scope": MERGED_TECHNIQUE_SCOPE,
            "direct_technique_count": len(direct_ids),
            "attributed_campaign_count": len(
                attributed_campaign_ids_for_group
            ),
            "campaign_attributed_technique_count": len(campaign_technique_ids),
            "direct_and_campaign_overlap_count": len(both_ids),
            "direct_only_technique_count": len(direct_ids - campaign_technique_ids),
            "campaign_only_technique_count": len(campaign_technique_ids - direct_ids),
            "merged_technique_count": len(merged_ids),
            "merged_parent_technique_count": sum(
                not bool(active_technique_by_id[technique_id].get(
                    "x_mitre_is_subtechnique"
                ))
                for technique_id in merged_ids
            ),
            "merged_subtechnique_count": sum(
                bool(active_technique_by_id[technique_id].get(
                    "x_mitre_is_subtechnique"
                ))
                for technique_id in merged_ids
            ),
        }

    active_object_ids = {
        obj["id"]
        for obj in typed
        if isinstance(obj.get("id"), str) and is_active(obj)
    }
    extraction_audit = {
        "uses": {
            "bundle_relationship_count": len(all_uses_relationships),
            "inactive_relationship_count": sum(
                not is_active(relationship)
                for relationship in all_uses_relationships
            ),
            "inactive_source_count": sum(
                relationship.get("source_ref") not in active_object_ids
                for relationship in all_uses_relationships
            ),
            "inactive_target_count": sum(
                relationship.get("target_ref") not in active_object_ids
                for relationship in all_uses_relationships
            ),
        },
        "attributed_to": {
            "bundle_relationship_count": len(all_attribution_relationships),
            "inactive_relationship_count": sum(
                not is_active(relationship)
                for relationship in all_attribution_relationships
            ),
            "inactive_source_count": sum(
                relationship.get("source_ref") not in active_object_ids
                for relationship in all_attribution_relationships
            ),
            "inactive_target_count": sum(
                relationship.get("target_ref") not in active_object_ids
                for relationship in all_attribution_relationships
            ),
        },
    }

    return {
        "groups": groups,
        "techniques": techniques,
        "active_technique_catalog": [
            compact_technique(obj) for obj in active_technique_by_id.values()
        ],
        "campaigns": campaigns,
        "paths": paths,
        "scope_metrics_by_group": scope_metrics_by_group,
        "extraction_audit": extraction_audit,
    }


def extraction_summary(extracted: dict[str, Any]) -> dict[str, Any]:
    paths = extracted["paths"]
    return {
        "group_count": len(extracted["groups"]),
        "path_count": len(paths),
        "direct_path_count": sum(
            path["path_type"] == "direct" for path in paths
        ),
        "campaign_attributed_path_count": sum(
            path["path_type"] == "campaign_attributed" for path in paths
        ),
        "distinct_techniques": len(extracted["techniques"]),
        "attributed_campaign_count": len(extracted["campaigns"]),
        "groups": [
            {
                "external_id": group["external_id"],
                "name": group["name"],
                **extracted["scope_metrics_by_group"][group["stix_id"]],
            }
            for group in extracted["groups"]
        ],
        "inactive_filter_audit": extracted["extraction_audit"],
    }


def all_group_scope_summary(extracted: dict[str, Any]) -> dict[str, Any]:
    """Return counts only for the all-active-group extraction checkpoint."""

    group_metrics = [
        extracted["scope_metrics_by_group"][group["stix_id"]]
        for group in extracted["groups"]
    ]
    zero_direct = sum(
        metrics["direct_technique_count"] == 0 for metrics in group_metrics
    )
    zero_campaign_techniques = sum(
        metrics["campaign_attributed_technique_count"] == 0
        for metrics in group_metrics
    )
    zero_both = sum(
        metrics["direct_technique_count"] == 0
        and metrics["campaign_attributed_technique_count"] == 0
        for metrics in group_metrics
    )
    with_attributed_campaign = sum(
        metrics["attributed_campaign_count"] > 0 for metrics in group_metrics
    )
    return {
        "active_group_count": len(extracted["groups"]),
        "merged_group_technique_pair_count": sum(
            metrics["merged_technique_count"] for metrics in group_metrics
        ),
        "groups_with_zero_direct_techniques": zero_direct,
        "groups_with_zero_campaign_attributed_techniques": (
            zero_campaign_techniques
        ),
        "groups_with_zero_direct_and_zero_campaign_techniques": zero_both,
        "groups_with_at_least_one_attributed_campaign": with_attributed_campaign,
        "groups_with_no_attributed_campaign": (
            len(group_metrics) - with_attributed_campaign
        ),
        "software_mediated_techniques_excluded": True,
        "parent_subtechnique_deduplication": "none",
        "per_group_special_casing": False,
    }


def technique_label(technique: dict[str, Any]) -> str:
    return f"{technique['external_id']} ({technique['name']})"


def group_label(group: dict[str, Any]) -> str:
    return f"{group['external_id']} ({group['name']})"


def provenance_path(path: dict[str, Any]) -> dict[str, Any]:
    if path["path_type"] == "direct":
        return {
            "path_type": "direct",
            "group_stix_id": path["group_ref"],
            "technique_stix_id": path["technique_ref"],
            "uses_relationship_stix_id": path[
                "direct_uses_relationship_stix_id"
            ],
        }
    return {
        "path_type": "campaign_attributed",
        "group_stix_id": path["group_ref"],
        "campaign_stix_id": path["campaign_ref"],
        "technique_stix_id": path["technique_ref"],
        "attributed_to_relationship_stix_id": path[
            "attributed_to_relationship_stix_id"
        ],
        "campaign_uses_relationship_stix_id": path[
            "campaign_uses_relationship_stix_id"
        ],
    }


def pair_provenance(
    group: dict[str, Any],
    techniques: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    scope_metrics: dict[str, Any] | None = None,
    queried_technique: dict[str, Any] | None = None,
) -> dict[str, Any]:
    technique_paths = []
    for technique in techniques:
        matching = [
            provenance_path(path)
            for path in paths
            if path["technique_ref"] == technique["stix_id"]
        ]
        if not matching:
            raise GroupTechniqueParserError(
                f"no provenance path for {technique['external_id']}"
            )
        technique_paths.append(
            {
                "technique_stix_id": technique["stix_id"],
                "path_types": sorted({path["path_type"] for path in matching}),
                "paths": matching,
            }
        )

    relationship_stix_ids: set[str] = set()
    campaign_stix_ids: set[str] = set()
    for path in paths:
        if path["path_type"] == "direct":
            relationship_stix_ids.add(path["direct_uses_relationship_stix_id"])
        else:
            relationship_stix_ids.add(path["attributed_to_relationship_stix_id"])
            relationship_stix_ids.add(path["campaign_uses_relationship_stix_id"])
            campaign_stix_ids.add(path["campaign_ref"])
    provenance = {
        "repository": source["repository"],
        "stix_commit": source["commit"],
        "bundle_path": source["path"],
        "bundle_sha256": source["sha256"],
        "group_stix_id": group["stix_id"],
        "scope": MERGED_TECHNIQUE_SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "software_mediated_techniques_excluded": True,
        "parent_subtechnique_deduplication": "none",
        "technique_stix_ids": [technique["stix_id"] for technique in techniques],
        "campaign_stix_ids": sorted(campaign_stix_ids),
        "relationship_stix_ids": sorted(relationship_stix_ids),
        "technique_paths": technique_paths,
    }
    if scope_metrics is not None:
        provenance.update(scope_metrics)
    if queried_technique is not None:
        provenance["queried_technique_stix_id"] = queried_technique["stix_id"]
    return provenance


def generate_prototype_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    focused_technique_by_group: dict[str, str] = FOCUSED_TECHNIQUE_BY_GROUP,
    negative_technique_by_group: dict[str, str] = NEGATIVE_TECHNIQUE_BY_GROUP,
) -> list[dict[str, Any]]:
    """Generate aggregate, focused-positive, and honest negative questions."""

    groups = {group["external_id"]: group for group in extracted["groups"]}
    techniques_by_stix = {
        technique["stix_id"]: technique for technique in extracted["techniques"]
    }
    active_techniques_by_external = {
        technique["external_id"]: technique
        for technique in extracted["active_technique_catalog"]
        if technique["external_id"] is not None
    }
    paths_by_group: dict[str, list[dict[str, Any]]] = {}
    for path in extracted["paths"]:
        paths_by_group.setdefault(path["group_ref"], []).append(path)

    pairs = []
    for group_external_id, group in groups.items():
        paths = paths_by_group.get(group["stix_id"], [])
        technique_ids = sorted(
            {path["technique_ref"] for path in paths},
            key=lambda stix_id: (
                techniques_by_stix[stix_id]["external_id"] or "",
                stix_id,
            ),
        )
        if not technique_ids:
            raise GroupTechniqueParserError(
                f"selected group {group_external_id} has no qualifying paths"
            )
        techniques = [techniques_by_stix[stix_id] for stix_id in technique_ids]
        labels = [technique_label(technique) for technique in techniques]
        scope_metrics = extracted["scope_metrics_by_group"].get(group["stix_id"])
        if scope_metrics is None:
            raise GroupTechniqueParserError(
                f"no scope metrics for {group_external_id}"
            )
        pairs.append(
            {
                "id": f"group-uses-techniques-{group_external_id.lower()}",
                "case_type": "aggregate_group_techniques",
                "relationship_type": "group_uses_technique",
                "question": f"What techniques does {group['name']} use?",
                "expected_answer": (
                    f"{group_label(group)} uses {natural_list(labels)} in the pinned "
                    "Enterprise ATT&CK snapshot under the direct-plus-campaign scope."
                ),
                "group": group,
                "expected_techniques": techniques,
                "provenance": pair_provenance(
                    group,
                    techniques,
                    paths,
                    source,
                    scope_metrics=scope_metrics,
                ),
            }
        )

        focused_external_id = focused_technique_by_group.get(group_external_id)
        if focused_external_id is None:
            raise GroupTechniqueParserError(
                f"no focused technique configured for {group_external_id}"
            )
        focused = [
            technique
            for technique in techniques
            if technique["external_id"] == focused_external_id
        ]
        if len(focused) != 1:
            raise GroupTechniqueParserError(
                f"expected one technique object for {group_external_id} -> "
                f"{focused_external_id}, found {len(focused)}"
            )
        focused_technique = focused[0]
        focused_paths = [
            path
            for path in paths
            if path["technique_ref"] == focused_technique["stix_id"]
        ]
        focused_label = technique_label(focused_technique)
        pairs.append(
            {
                "id": (
                    f"group-uses-technique-{group_external_id.lower()}-"
                    f"{focused_external_id.lower()}"
                ),
                "case_type": "focused_group_technique",
                "relationship_type": "group_uses_technique",
                "question": f"Does {group['name']} use {focused_label}?",
                "expected_answer": (
                    f"Yes. {group_label(group)} uses {focused_label} in the pinned "
                    "Enterprise ATT&CK snapshot under the direct-plus-campaign scope."
                ),
                "group": group,
                "expected_techniques": [focused_technique],
                "provenance": pair_provenance(
                    group,
                    [focused_technique],
                    focused_paths,
                    source,
                    queried_technique=focused_technique,
                ),
            }
        )

    for group_external_id, negative_external_id in negative_technique_by_group.items():
        group = groups.get(group_external_id)
        if group is None:
            raise GroupTechniqueParserError(
                f"negative-case group {group_external_id} is outside prototype scope"
            )
        negative_technique = active_techniques_by_external.get(negative_external_id)
        if negative_technique is None:
            raise GroupTechniqueParserError(
                f"negative-case technique {negative_external_id} is not active"
            )
        matching_paths = [
            path
            for path in paths_by_group.get(group["stix_id"], [])
            if path["technique_ref"] == negative_technique["stix_id"]
        ]
        if matching_paths:
            raise GroupTechniqueParserError(
                f"configured negative case {group_external_id} -> "
                f"{negative_external_id} has {len(matching_paths)} qualifying path(s)"
            )
        negative_label = technique_label(negative_technique)
        pairs.append(
            {
                "id": (
                    f"group-does-not-use-technique-{group_external_id.lower()}-"
                    f"{negative_external_id.lower()}"
                ),
                "case_type": "negative_group_technique",
                "relationship_type": "group_uses_technique",
                "question": f"Does {group['name']} use {negative_label}?",
                "expected_answer": (
                    "No active direct or campaign-attributed uses path exists between "
                    f"{group_label(group)} and {negative_label} in the pinned "
                    "Enterprise ATT&CK snapshot."
                ),
                "group": group,
                "queried_technique": negative_technique,
                "expected_techniques": [],
                "provenance": pair_provenance(
                    group,
                    [],
                    [],
                    source,
                    queried_technique=negative_technique,
                ),
            }
        )
    return pairs


def sorted_group_techniques_and_paths(
    group: dict[str, Any],
    extracted: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    techniques_by_stix = {
        technique["stix_id"]: technique for technique in extracted["techniques"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["group_ref"] == group["stix_id"]
    ]
    technique_ids = sorted(
        {path["technique_ref"] for path in paths},
        key=lambda stix_id: (
            techniques_by_stix[stix_id]["external_id"] or "",
            stix_id,
        ),
    )
    return [techniques_by_stix[stix_id] for stix_id in technique_ids], paths


def generate_full_aggregate_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    """Generate exactly one aggregate record for every active group."""

    pairs = []
    for group in extracted["groups"]:
        techniques, paths = sorted_group_techniques_and_paths(group, extracted)
        scope_metrics = extracted["scope_metrics_by_group"][group["stix_id"]]
        if techniques:
            labels = [technique_label(technique) for technique in techniques]
            pairs.append(
                {
                    "id": f"group-uses-techniques-{group['external_id'].lower()}",
                    "case_type": "aggregate_group_techniques",
                    "relationship_type": "group_uses_technique",
                    "question": f"What techniques does {group['name']} use?",
                    "expected_answer": (
                        f"{group_label(group)} uses {natural_list(labels)} in the "
                        "pinned Enterprise ATT&CK snapshot under the "
                        "direct-plus-campaign scope."
                    ),
                    "group": group,
                    "expected_techniques": techniques,
                    "provenance": pair_provenance(
                        group,
                        techniques,
                        paths,
                        source,
                        scope_metrics=scope_metrics,
                    ),
                }
            )
            continue
        pairs.append(
            {
                "id": (
                    "group-has-no-qualifying-techniques-"
                    f"{group['external_id'].lower()}"
                ),
                "case_type": "aggregate_group_no_qualifying_techniques",
                "relationship_type": "group_uses_technique",
                "question": f"What techniques does {group['name']} use?",
                "expected_answer": (
                    "No active direct or campaign-attributed group-to-technique "
                    f"path is recorded for {group_label(group)} in the pinned "
                    "Enterprise ATT&CK snapshot."
                ),
                "group": group,
                "expected_techniques": [],
                "provenance": pair_provenance(
                    group,
                    [],
                    [],
                    source,
                    scope_metrics=scope_metrics,
                ),
            }
        )
    return pairs


def evenly_spaced_groups(
    groups: list[dict[str, Any]], count: int
) -> list[dict[str, Any]]:
    if count < 0 or count > len(groups):
        raise GroupTechniqueParserError(
            f"cannot choose {count} distinct groups from a pool of {len(groups)}"
        )
    if count == 0:
        return []
    if count == 1:
        return [groups[len(groups) // 2]]
    indices = [
        round(index * (len(groups) - 1) / (count - 1))
        for index in range(count)
    ]
    if len(indices) != len(set(indices)):
        raise GroupTechniqueParserError("stratified group selection produced duplicates")
    return [groups[index] for index in indices]


def select_full_negative_cases(
    extracted: dict[str, Any],
    *,
    count: int = FULL_NEGATIVE_EXISTENCE_CASE_COUNT,
    preserved_cases: dict[str, str] = NEGATIVE_TECHNIQUE_BY_GROUP,
    probe_technique_ids: tuple[str, ...] = FULL_NEGATIVE_PROBE_TECHNIQUE_IDS,
) -> dict[str, str]:
    """Choose distinct, reproducible group/technique non-edges."""

    groups_by_external = {
        group["external_id"]: group for group in extracted["groups"]
    }
    active_techniques_by_external = {
        technique["external_id"]: technique
        for technique in extracted["active_technique_catalog"]
        if technique["external_id"] is not None
    }
    missing_probe_ids = [
        external_id for external_id in probe_technique_ids
        if external_id not in active_techniques_by_external
    ]
    if missing_probe_ids:
        raise GroupTechniqueParserError(
            "negative probe techniques are not active: "
            + ", ".join(missing_probe_ids)
        )
    selected = {
        group_external_id: technique_external_id
        for group_external_id, technique_external_id in preserved_cases.items()
        if group_external_id in groups_by_external
    }
    if len(selected) > count:
        raise GroupTechniqueParserError(
            "preserved negative cases exceed requested full negative count"
        )
    paths_by_group: dict[str, set[str]] = {}
    for path in extracted["paths"]:
        paths_by_group.setdefault(path["group_ref"], set()).add(
            path["technique_ref"]
        )
    for group_external_id, technique_external_id in selected.items():
        technique = active_techniques_by_external.get(technique_external_id)
        if technique is None:
            raise GroupTechniqueParserError(
                f"preserved negative technique {technique_external_id} is not active"
            )
        group = groups_by_external[group_external_id]
        if technique["stix_id"] in paths_by_group.get(group["stix_id"], set()):
            raise GroupTechniqueParserError(
                f"preserved negative {group_external_id} -> "
                f"{technique_external_id} has a qualifying path"
            )

    eligible_groups = [
        group
        for group in extracted["groups"]
        if group["external_id"] not in selected
        and extracted["scope_metrics_by_group"][group["stix_id"]][
            "merged_technique_count"
        ] > 0
    ]
    additional_groups = evenly_spaced_groups(
        eligible_groups, count - len(selected)
    )
    for group_index, group in enumerate(additional_groups):
        used_technique_ids = paths_by_group.get(group["stix_id"], set())
        start = group_index % len(probe_technique_ids)
        ordered_probes = (
            probe_technique_ids[start:] + probe_technique_ids[:start]
        )
        for technique_external_id in ordered_probes:
            technique = active_techniques_by_external[technique_external_id]
            if technique["stix_id"] not in used_technique_ids:
                selected[group["external_id"]] = technique_external_id
                break
        else:
            raise GroupTechniqueParserError(
                f"no configured negative probe is absent for {group['external_id']}"
            )
    if len(selected) != count:
        raise GroupTechniqueParserError(
            f"expected {count} negative cases, selected {len(selected)}"
        )
    return selected


def generate_negative_existence_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    negative_cases: dict[str, str],
) -> list[dict[str, Any]]:
    groups_by_external = {
        group["external_id"]: group for group in extracted["groups"]
    }
    techniques_by_external = {
        technique["external_id"]: technique
        for technique in extracted["active_technique_catalog"]
        if technique["external_id"] is not None
    }
    path_keys = {
        (path["group_ref"], path["technique_ref"])
        for path in extracted["paths"]
    }
    pairs = []
    for group_external_id in sorted(negative_cases):
        technique_external_id = negative_cases[group_external_id]
        group = groups_by_external[group_external_id]
        technique = techniques_by_external[technique_external_id]
        if (group["stix_id"], technique["stix_id"]) in path_keys:
            raise GroupTechniqueParserError(
                f"negative case {group_external_id} -> {technique_external_id} "
                "has a qualifying direct or campaign path"
            )
        label = technique_label(technique)
        pairs.append(
            {
                "id": (
                    f"group-does-not-use-technique-{group_external_id.lower()}-"
                    f"{technique_external_id.lower()}"
                ),
                "case_type": "negative_group_technique",
                "relationship_type": "group_uses_technique",
                "question": f"Does {group['name']} use {label}?",
                "expected_answer": (
                    "No active direct or campaign-attributed uses path exists between "
                    f"{group_label(group)} and {label} in the pinned Enterprise "
                    "ATT&CK snapshot."
                ),
                "group": group,
                "queried_technique": technique,
                "expected_techniques": [],
                "provenance": pair_provenance(
                    group,
                    [],
                    [],
                    source,
                    queried_technique=technique,
                ),
            }
        )
    return pairs


def full_group_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    aggregate_pairs = generate_full_aggregate_pairs(extracted, source)
    negative_cases = select_full_negative_cases(extracted)
    negative_pairs = generate_negative_existence_pairs(
        extracted, source, negative_cases
    )
    pairs = aggregate_pairs + negative_pairs
    positive_aggregates = sum(
        pair["case_type"] == "aggregate_group_techniques"
        for pair in aggregate_pairs
    )
    zero_path_aggregates = sum(
        pair["case_type"] == "aggregate_group_no_qualifying_techniques"
        for pair in aggregate_pairs
    )
    embedded_fact_count = sum(
        len(pair["expected_techniques"]) for pair in aggregate_pairs
    )
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_phase_2_full_group_technique_golden_set",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "intrusion-set",
            "target_type": "attack-pattern",
            "aggregate_answer_scope": MERGED_TECHNIQUE_SCOPE,
            "included_paths": ["direct", "campaign_attributed"],
            "software_mediated_techniques_excluded": True,
            "parent_subtechnique_deduplication": "none",
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "one_aggregate_pair_per_active_group": True,
        },
        "selection": {
            "active_group_count": len(extracted["groups"]),
            "embedded_group_technique_fact_count": embedded_fact_count,
            "pair_count": len(pairs),
            "positive_aggregate_pairs": positive_aggregates,
            "zero_path_aggregate_pairs": zero_path_aggregates,
            "negative_existence_pairs": len(negative_pairs),
            "negative_existence_distinct_group_count": len(
                {pair["group"]["external_id"] for pair in negative_pairs}
            ),
            "prototype_negative_cases_preserved": sum(
                group_external_id in negative_cases
                and negative_cases[group_external_id] == technique_external_id
                for group_external_id, technique_external_id
                in NEGATIVE_TECHNIQUE_BY_GROUP.items()
            ),
        },
        "negative_selection": {
            "method": (
                "preserve the three verified prototype negatives, then choose "
                "17 evenly spaced active groups with positive aggregates and "
                "select a configured active probe technique having zero direct "
                "or campaign-attributed paths"
            ),
            "case_count": len(negative_pairs),
            "all_cases_verified_absent_by_extracted_path_set": True,
        },
        "pairs": pairs,
    }


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    return {
        "schema_version": "1.1",
        "phase": "card6_part_b_phase_2_group_technique_uses_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "intrusion-set",
            "target_type": "attack-pattern",
            "aggregate_answer_scope": MERGED_TECHNIQUE_SCOPE,
            "included_paths": ["direct", "campaign_attributed"],
            "software_mediated_techniques_excluded": True,
            "parent_subtechnique_deduplication": "none",
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "group_external_ids": list(SELECTED_GROUP_IDS),
            "group_count": len(SELECTED_GROUP_IDS),
            "pair_count": len(pairs),
            "aggregate_pairs": sum(
                pair["case_type"] == "aggregate_group_techniques" for pair in pairs
            ),
            "focused_edge_pairs": sum(
                pair["case_type"] == "focused_group_technique" for pair in pairs
            ),
            "negative_edge_pairs": sum(
                pair["case_type"] == "negative_group_technique" for pair in pairs
            ),
        },
        "extraction": extraction_summary(extracted),
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--all-groups-summary",
        action="store_true",
        help="print all-active-group extraction counts without writing pairs",
    )
    parser.add_argument(
        "--generate-all-groups",
        action="store_true",
        help="write the full all-active-group golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_group_technique.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "golden_set_group_technique_prototype.json",
    )
    args = parser.parse_args()
    if args.all_groups_summary and args.generate_all_groups:
        parser.error(
            "--all-groups-summary and --generate-all-groups are mutually exclusive"
        )

    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    if args.all_groups_summary:
        extracted = extract_group_technique_scope(bundle, group_ids=None)
        print(json.dumps(all_group_scope_summary(extracted), indent=2, sort_keys=True))
        return 0
    if args.generate_all_groups:
        extracted = extract_group_technique_scope(bundle, group_ids=None)
        payload = full_group_payload(extracted, source)
        args.full_output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "source": source,
                    "artifact": {
                        "output": str(args.full_output),
                        "selection": payload["selection"],
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    extracted = extract_group_technique_scope(bundle)
    payload = prototype_payload(extracted, source)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "source": source,
                "extraction": payload["extraction"],
                "artifact": {
                    "output": str(args.output),
                    "selection": payload["selection"],
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
    except GroupTechniqueParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
