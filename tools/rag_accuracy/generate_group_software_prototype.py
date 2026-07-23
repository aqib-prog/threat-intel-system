#!/usr/bin/env python3
"""Generate a five-group direct software-use golden-set prototype."""

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
from generate_group_technique_prototype import SELECTED_GROUP_IDS


HERE = Path(__file__).resolve().parent
FOCUSED_SOFTWARE_BY_GROUP = {
    "G0007": "S0002",  # APT28 -> Mimikatz
    "G0016": "S0154",  # APT29 -> Cobalt Strike
    "G0034": "S0002",  # Sandworm Team -> Mimikatz
    "G0046": "S0154",  # FIN7 -> Cobalt Strike
}
NEGATIVE_GROUP_ID = "G0032"
NEGATIVE_SOFTWARE_ID = "S0266"  # Lazarus Group -/-> TrickBot
FULL_NEGATIVE_EXISTENCE_CASE_COUNT = 20
FULL_NEGATIVE_PROBE_SOFTWARE_IDS = (
    "S0002",  # Mimikatz
    "S0154",  # Cobalt Strike
    "S0366",  # WannaCry
    "S0266",  # TrickBot
    "S0633",  # Sliver
    "S0357",  # Impacket
    "S0521",  # JSP Web Shell
    "S0552",  # AdFind
    "S0194",  # POWRUNER
    "S0039",  # Net
)
SCOPE = "direct_group_to_software_union_campaign_attributed"
METHODOLOGY_NOTE = (
    "The answer is the union of active direct intrusion-set --uses--> "
    "malware/tool paths and active campaign --attributed-to--> intrusion-set "
    "plus campaign --uses--> malware/tool paths. Mobile-domain software remains "
    "excluded because the pinned source is the Enterprise ATT&CK bundle."
)


class GroupSoftwareParserError(RuntimeError):
    """Raised when scoped group-to-software facts are invalid."""


def require_unique_external_ids(
    objects: list[dict[str, Any]], description: str
) -> dict[str, dict[str, Any]]:
    rows = [(mitre_external_id(obj), obj) for obj in objects]
    missing = [obj["id"] for external_id, obj in rows if external_id is None]
    if missing:
        raise GroupSoftwareParserError(
            f"active {description} objects lack MITRE external IDs: "
            + ", ".join(sorted(missing))
        )
    result = {external_id: obj for external_id, obj in rows if external_id}
    if len(result) != len(rows):
        raise GroupSoftwareParserError(
            f"active {description} objects have duplicate MITRE external IDs"
        )
    return result


def compact_group(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "aliases": list(obj.get("aliases", [])),
    }


def compact_software(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "stix_type": obj.get("type"),
        "platforms": list(obj.get("x_mitre_platforms", [])),
    }


def extract_group_software_scope(
    bundle: dict[str, Any],
    group_ids: tuple[str, ...] | None = SELECTED_GROUP_IDS,
) -> dict[str, Any]:
    """Extract active direct and campaign-attributed group/software paths."""

    if group_ids is not None and len(group_ids) != len(set(group_ids)):
        raise GroupSoftwareParserError("selected group IDs are not unique")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise GroupSoftwareParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]

    group_catalog = require_unique_external_ids(
        [
            obj
            for obj in typed
            if obj.get("type") == "intrusion-set" and is_active(obj)
        ],
        "intrusion-set",
    )
    if group_ids is None:
        selected_groups = [
            group_catalog[external_id] for external_id in sorted(group_catalog)
        ]
    else:
        missing_groups = [gid for gid in group_ids if gid not in group_catalog]
        if missing_groups:
            raise GroupSoftwareParserError(
                "selected active groups are missing: " + ", ".join(missing_groups)
            )
        selected_groups = [group_catalog[gid] for gid in group_ids]
    selected_group_stix_ids = {obj["id"] for obj in selected_groups}

    active_software_objects = [
        obj
        for obj in typed
        if obj.get("type") in {"malware", "tool"} and is_active(obj)
    ]
    software_catalog = require_unique_external_ids(
        active_software_objects, "malware/tool"
    )
    software_by_stix = {obj["id"]: obj for obj in active_software_objects}
    campaign_by_stix = {
        obj["id"]: obj
        for obj in typed
        if obj.get("type") == "campaign" and is_active(obj)
    }
    all_uses = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "uses"
    ]
    direct_uses = [
        rel
        for rel in all_uses
        if is_active(rel)
        and rel.get("source_ref") in selected_group_stix_ids
        and rel.get("target_ref") in software_by_stix
    ]
    all_attributions = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "attributed-to"
    ]
    attributions = [
        rel
        for rel in all_attributions
        if is_active(rel)
        and rel.get("source_ref") in campaign_by_stix
        and rel.get("target_ref") in selected_group_stix_ids
    ]
    attributed_campaign_ids = {rel["source_ref"] for rel in attributions}
    campaign_uses = [
        rel
        for rel in all_uses
        if is_active(rel)
        and rel.get("source_ref") in attributed_campaign_ids
        and rel.get("target_ref") in software_by_stix
    ]
    campaign_uses_by_campaign: dict[str, list[dict[str, Any]]] = {}
    for rel in campaign_uses:
        campaign_uses_by_campaign.setdefault(rel["source_ref"], []).append(rel)

    paths = []
    for rel in direct_uses:
        paths.append({
            "path_type": "direct",
            "group_ref": rel["source_ref"],
            "software_ref": rel["target_ref"],
            "direct_uses_relationship_stix_id": rel["id"],
        })
    for attribution in attributions:
        campaign_ref = attribution["source_ref"]
        for rel in campaign_uses_by_campaign.get(campaign_ref, []):
            paths.append({
                "path_type": "campaign_attributed",
                "group_ref": attribution["target_ref"],
                "software_ref": rel["target_ref"],
                "campaign_ref": campaign_ref,
                "attributed_to_relationship_stix_id": attribution["id"],
                "campaign_uses_relationship_stix_id": rel["id"],
            })
    paths.sort(
        key=lambda path: (
            path["group_ref"],
            mitre_external_id(software_by_stix[path["software_ref"]]) or "",
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
            path["software_ref"],
            path.get("campaign_ref"),
            path.get("direct_uses_relationship_stix_id"),
            path.get("attributed_to_relationship_stix_id"),
            path.get("campaign_uses_relationship_stix_id"),
        )
        for path in paths
    }
    if len(path_keys) != len(paths):
        raise GroupSoftwareParserError("duplicate group-to-software path records")

    referenced_software = {path["software_ref"] for path in paths}
    software = [
        compact_software(obj)
        for obj in active_software_objects
        if obj["id"] in referenced_software
    ]
    software.sort(key=lambda row: (row["external_id"] or "", row["stix_id"]))
    groups = [compact_group(obj) for obj in selected_groups]

    counts = {}
    for group in groups:
        group_paths = [
            path for path in paths if path["group_ref"] == group["stix_id"]
        ]
        direct_ids = {
            path["software_ref"]
            for path in group_paths
            if path["path_type"] == "direct"
        }
        campaign_ids = {
            path["software_ref"]
            for path in group_paths
            if path["path_type"] == "campaign_attributed"
        }
        group_software_ids = direct_ids | campaign_ids
        counts[group["external_id"]] = {
            "total": len(group_software_ids),
            "malware": sum(
                software_by_stix[sid].get("type") == "malware"
                for sid in group_software_ids
            ),
            "tools": sum(
                software_by_stix[sid].get("type") == "tool"
                for sid in group_software_ids
            ),
            "direct_software_count": len(direct_ids),
            "campaign_attributed_software_count": len(campaign_ids),
            "direct_and_campaign_overlap_count": len(direct_ids & campaign_ids),
            "campaign_only_software_count": len(campaign_ids - direct_ids),
        }

    return {
        "groups": groups,
        "software": software,
        "active_software_catalog": [
            compact_software(software_catalog[external_id])
            for external_id in sorted(software_catalog)
        ],
        "paths": paths,
        "software_counts_by_group": counts,
        "extraction_audit": {
            "bundle_uses_relationship_count": len(all_uses),
            "inactive_uses_relationship_count": sum(
                not is_active(rel) for rel in all_uses
            ),
            "bundle_attributed_to_relationship_count": len(all_attributions),
            "inactive_attributed_to_relationship_count": sum(
                not is_active(rel) for rel in all_attributions
            ),
            "qualifying_direct_path_count": len(direct_uses),
            "qualifying_campaign_path_count": sum(
                path["path_type"] == "campaign_attributed" for path in paths
            ),
            "qualifying_path_count": len(paths),
        },
    }


def all_group_scope_summary(extracted: dict[str, Any]) -> dict[str, Any]:
    """Return Step-5b all-active-group counts without generating pairs."""

    metrics = extracted["software_counts_by_group"]
    if len(metrics) != len(extracted["groups"]):
        raise GroupSoftwareParserError("not every active group has scope metrics")
    return {
        "active_group_count": len(extracted["groups"]),
        "merged_group_software_pair_count": sum(
            row["total"] for row in metrics.values()
        ),
        "direct_group_software_pair_count": sum(
            row["direct_software_count"] for row in metrics.values()
        ),
        "campaign_attributed_group_software_pair_count": sum(
            row["campaign_attributed_software_count"] for row in metrics.values()
        ),
        "direct_and_campaign_overlap_pair_count": sum(
            row["direct_and_campaign_overlap_count"] for row in metrics.values()
        ),
        "campaign_only_group_software_pair_count": sum(
            row["campaign_only_software_count"] for row in metrics.values()
        ),
        "groups_with_zero_direct_software": sum(
            row["direct_software_count"] == 0 for row in metrics.values()
        ),
        "groups_with_zero_campaign_attributed_software": sum(
            row["campaign_attributed_software_count"] == 0
            for row in metrics.values()
        ),
        "groups_with_zero_direct_and_zero_campaign_software": sum(
            row["direct_software_count"] == 0
            and row["campaign_attributed_software_count"] == 0
            for row in metrics.values()
        ),
        "scope": SCOPE,
        "mobile_domain_software_excluded": True,
    }


def group_label(group: dict[str, Any]) -> str:
    return f"{group['external_id']} ({group['name']})"


def software_label(software: dict[str, Any]) -> str:
    return f"{software['external_id']} ({software['name']})"


def provenance(
    group: dict[str, Any],
    software: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    queried_software: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "group_stix_id": group["stix_id"],
        "software_stix_ids": [item["stix_id"] for item in software],
        "direct_uses_relationship_stix_ids": sorted(
            path["direct_uses_relationship_stix_id"]
            for path in paths
            if path["path_type"] == "direct"
        ),
        "attributed_to_relationship_stix_ids": sorted({
            path["attributed_to_relationship_stix_id"]
            for path in paths
            if path["path_type"] == "campaign_attributed"
        }),
        "campaign_uses_relationship_stix_ids": sorted(
            path["campaign_uses_relationship_stix_id"]
            for path in paths
            if path["path_type"] == "campaign_attributed"
        ),
        "relationship_paths": paths,
    }
    if queried_software is not None:
        result["queried_software_stix_id"] = queried_software["stix_id"]
    return result


def software_and_paths_for(
    group: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    software_by_stix = {
        item["stix_id"]: item for item in extracted["software"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["group_ref"] == group["stix_id"]
    ]
    software_ids = sorted(
        {path["software_ref"] for path in paths},
        key=lambda stix_id: (
            software_by_stix[stix_id]["external_id"] or "",
            stix_id,
        ),
    )
    return [software_by_stix[sid] for sid in software_ids], paths


def generate_prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    groups = {group["external_id"]: group for group in extracted["groups"]}
    active_software = {
        item["external_id"]: item for item in extracted["active_software_catalog"]
    }
    pairs = []

    for group_id in SELECTED_GROUP_IDS:
        group = groups[group_id]
        software, paths = software_and_paths_for(group, extracted)
        if not software:
            raise GroupSoftwareParserError(
                f"selected group {group_id} has no qualifying software paths"
            )
        labels = [software_label(item) for item in software]
        pairs.append(
            {
                "id": f"group-uses-software-{group_id.lower()}",
                "case_type": "aggregate_group_software",
                "relationship_type": "group_uses_software",
                "question": f"What tools or malware does {group['name']} use?",
                "expected_answer": (
                    f"{group_label(group)} uses {natural_list(labels)} in the pinned "
                    "Enterprise ATT&CK snapshot under the direct-plus-campaign scope."
                ),
                "group": group,
                "expected_software": software,
                "provenance": provenance(group, software, paths, source),
            }
        )

    for group_id, software_id in FOCUSED_SOFTWARE_BY_GROUP.items():
        group = groups[group_id]
        software = active_software.get(software_id)
        if software is None:
            raise GroupSoftwareParserError(
                f"focused software {software_id} is not active"
            )
        _, group_paths = software_and_paths_for(group, extracted)
        matching = [
            path
            for path in group_paths
            if path["software_ref"] == software["stix_id"]
        ]
        if not matching:
            raise GroupSoftwareParserError(
                f"focused edge {group_id} -> {software_id} does not exist"
            )
        label = software_label(software)
        pairs.append(
            {
                "id": f"group-uses-software-{group_id.lower()}-{software_id.lower()}",
                "case_type": "focused_group_software",
                "relationship_type": "group_uses_software",
                "question": f"Does {group['name']} use {label}?",
                "expected_answer": (
                    f"Yes. {group_label(group)} uses {label} in the pinned Enterprise "
                    "ATT&CK snapshot under the direct-plus-campaign scope."
                ),
                "group": group,
                "expected_software": [software],
                "provenance": provenance(
                    group,
                    [software],
                    matching,
                    source,
                    queried_software=software,
                ),
            }
        )

    group = groups[NEGATIVE_GROUP_ID]
    software = active_software.get(NEGATIVE_SOFTWARE_ID)
    if software is None:
        raise GroupSoftwareParserError(
            f"negative software {NEGATIVE_SOFTWARE_ID} is not active"
        )
    _, group_paths = software_and_paths_for(group, extracted)
    matching = [
        path
        for path in group_paths
        if path["software_ref"] == software["stix_id"]
    ]
    if matching:
        raise GroupSoftwareParserError(
            f"negative edge {NEGATIVE_GROUP_ID} -> {NEGATIVE_SOFTWARE_ID} exists"
        )
    label = software_label(software)
    pairs.append(
        {
            "id": (
                f"group-does-not-use-software-{NEGATIVE_GROUP_ID.lower()}-"
                f"{NEGATIVE_SOFTWARE_ID.lower()}"
            ),
            "case_type": "negative_group_software",
            "relationship_type": "group_uses_software",
            "question": f"Does {group['name']} use {label}?",
            "expected_answer": (
                "No active direct or campaign-attributed uses path exists between "
                f"{group_label(group)} and {label} in the pinned Enterprise ATT&CK "
                "snapshot."
            ),
            "group": group,
            "queried_software": software,
            "expected_software": [],
            "provenance": provenance(
                group, [], [], source, queried_software=software
            ),
        }
    )
    if len(pairs) != 10:
        raise GroupSoftwareParserError(
            f"expected 10 prototype pairs, generated {len(pairs)}"
        )
    return pairs


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_step_4a_group_software_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "intrusion-set",
            "target_types": ["malware", "tool"],
            "relationship_type": "uses",
            "answer_scope": SCOPE,
            "included_paths": ["direct", "campaign_attributed"],
            "mobile_domain_software_excluded": True,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "group_external_ids": list(SELECTED_GROUP_IDS),
            "group_count": len(SELECTED_GROUP_IDS),
            "pair_count": len(pairs),
            "aggregate_pairs": sum(
                pair["case_type"] == "aggregate_group_software" for pair in pairs
            ),
            "focused_edge_pairs": sum(
                pair["case_type"] == "focused_group_software" for pair in pairs
            ),
            "negative_edge_pairs": sum(
                pair["case_type"] == "negative_group_software" for pair in pairs
            ),
        },
        "extraction": {
            "software_counts_by_group": extracted["software_counts_by_group"],
            "distinct_referenced_software_count": len(extracted["software"]),
            "path_count": len(extracted["paths"]),
            "inactive_filter_audit": extracted["extraction_audit"],
        },
        "pairs": pairs,
    }


def evenly_spaced_items(
    items: list[dict[str, Any]], count: int
) -> list[dict[str, Any]]:
    if count < 0 or count > len(items):
        raise GroupSoftwareParserError(
            f"cannot choose {count} distinct objects from {len(items)}"
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
        raise GroupSoftwareParserError(
            "stratified group selection produced duplicates"
        )
    return [items[index] for index in indices]


def generate_full_aggregate_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    """Generate one honest aggregate record for every active group."""

    pairs = []
    for group in extracted["groups"]:
        software, paths = software_and_paths_for(group, extracted)
        if software:
            labels = [software_label(item) for item in software]
            pairs.append(
                {
                    "id": f"group-uses-software-{group['external_id'].lower()}",
                    "case_type": "aggregate_group_software",
                    "relationship_type": "group_uses_software",
                    "question": f"What tools or malware does {group['name']} use?",
                    "expected_answer": (
                        f"{group_label(group)} uses {natural_list(labels)} in the "
                        "pinned Enterprise ATT&CK snapshot under the "
                        "direct-plus-campaign scope."
                    ),
                    "group": group,
                    "expected_software": software,
                    "provenance": provenance(group, software, paths, source),
                }
            )
            continue

        pairs.append(
            {
                "id": (
                    "group-has-no-qualifying-software-"
                    f"{group['external_id'].lower()}"
                ),
                "case_type": "aggregate_group_no_qualifying_software",
                "relationship_type": "group_uses_software",
                "question": f"What tools or malware does {group['name']} use?",
                "expected_answer": (
                    "No active direct or campaign-attributed group-to-software "
                    f"path is recorded for {group_label(group)} in the pinned "
                    "Enterprise ATT&CK snapshot."
                ),
                "group": group,
                "expected_software": [],
                "provenance": provenance(group, [], [], source),
            }
        )
    return pairs


def select_full_negative_cases(
    extracted: dict[str, Any],
    *,
    count: int = FULL_NEGATIVE_EXISTENCE_CASE_COUNT,
) -> dict[str, str]:
    """Choose reproducible distinct-group direct-or-campaign non-edges."""

    groups_by_external = {
        item["external_id"]: item for item in extracted["groups"]
    }
    software_by_external = {
        item["external_id"]: item
        for item in extracted["active_software_catalog"]
    }
    missing_probes = [
        external_id
        for external_id in FULL_NEGATIVE_PROBE_SOFTWARE_IDS
        if external_id not in software_by_external
    ]
    if missing_probes:
        raise GroupSoftwareParserError(
            "negative probe software are not active: " + ", ".join(missing_probes)
        )
    path_keys = {
        (path["group_ref"], path["software_ref"])
        for path in extracted["paths"]
    }
    selected = {NEGATIVE_GROUP_ID: NEGATIVE_SOFTWARE_ID}
    preserved_group = groups_by_external[NEGATIVE_GROUP_ID]
    preserved_software = software_by_external[NEGATIVE_SOFTWARE_ID]
    if (preserved_group["stix_id"], preserved_software["stix_id"]) in path_keys:
        raise GroupSoftwareParserError(
            "preserved prototype negative now has a qualifying path"
        )

    eligible = [
        item
        for item in extracted["groups"]
        if item["external_id"] != NEGATIVE_GROUP_ID
        and extracted["software_counts_by_group"][item["external_id"]]["total"] > 0
    ]
    additional = evenly_spaced_items(eligible, count - len(selected))
    for index, group in enumerate(additional):
        offset = index % len(FULL_NEGATIVE_PROBE_SOFTWARE_IDS)
        probes = (
            FULL_NEGATIVE_PROBE_SOFTWARE_IDS[offset:]
            + FULL_NEGATIVE_PROBE_SOFTWARE_IDS[:offset]
        )
        for software_external_id in probes:
            software = software_by_external[software_external_id]
            if (group["stix_id"], software["stix_id"]) not in path_keys:
                selected[group["external_id"]] = software_external_id
                break
        else:
            raise GroupSoftwareParserError(
                f"no configured negative probe is absent for {group['external_id']}"
            )
    if len(selected) != count:
        raise GroupSoftwareParserError(
            f"expected {count} negative cases, selected {len(selected)}"
        )
    return selected


def generate_full_negative_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    negative_cases: dict[str, str],
) -> list[dict[str, Any]]:
    groups_by_external = {
        item["external_id"]: item for item in extracted["groups"]
    }
    software_by_external = {
        item["external_id"]: item
        for item in extracted["active_software_catalog"]
    }
    path_keys = {
        (path["group_ref"], path["software_ref"])
        for path in extracted["paths"]
    }
    pairs = []
    for group_external_id in sorted(negative_cases):
        software_external_id = negative_cases[group_external_id]
        group = groups_by_external[group_external_id]
        software = software_by_external[software_external_id]
        if (group["stix_id"], software["stix_id"]) in path_keys:
            raise GroupSoftwareParserError(
                f"negative case {group_external_id} -> {software_external_id} "
                "has a qualifying path"
            )
        label = software_label(software)
        pairs.append(
            {
                "id": (
                    f"group-does-not-use-software-{group_external_id.lower()}-"
                    f"{software_external_id.lower()}"
                ),
                "case_type": "negative_group_software",
                "relationship_type": "group_uses_software",
                "question": f"Does {group['name']} use {label}?",
                "expected_answer": (
                    "No active direct or campaign-attributed uses path exists "
                    f"between {group_label(group)} and {label} in the pinned "
                    "Enterprise ATT&CK snapshot."
                ),
                "group": group,
                "queried_software": software,
                "expected_software": [],
                "provenance": provenance(
                    group, [], [], source, queried_software=software
                ),
            }
        )
    return pairs


def full_group_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    aggregate_pairs = generate_full_aggregate_pairs(extracted, source)
    negative_cases = select_full_negative_cases(extracted)
    negative_pairs = generate_full_negative_pairs(
        extracted, source, negative_cases
    )
    positive_aggregates = [
        pair
        for pair in aggregate_pairs
        if pair["case_type"] == "aggregate_group_software"
    ]
    zero_path_aggregates = [
        pair
        for pair in aggregate_pairs
        if pair["case_type"] == "aggregate_group_no_qualifying_software"
    ]
    pairs = aggregate_pairs + negative_pairs
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_step_5c_full_group_software_golden_set",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "intrusion-set",
            "target_types": ["malware", "tool"],
            "relationship_type": "uses",
            "answer_scope": SCOPE,
            "included_paths": ["direct", "campaign_attributed"],
            "mobile_domain_software_excluded": True,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "one_aggregate_pair_per_active_group": True,
        },
        "selection": {
            "active_group_count": len(extracted["groups"]),
            "pair_count": len(pairs),
            "positive_aggregate_pairs": len(positive_aggregates),
            "zero_path_aggregate_pairs": len(zero_path_aggregates),
            "negative_existence_pairs": len(negative_pairs),
            "negative_existence_distinct_group_count": len(
                {pair["group"]["external_id"] for pair in negative_pairs}
            ),
            "embedded_group_software_fact_count": sum(
                len(pair["expected_software"])
                for pair in positive_aggregates
            ),
            "prototype_negative_preserved": (
                negative_cases.get(NEGATIVE_GROUP_ID) == NEGATIVE_SOFTWARE_ID
            ),
        },
        "negative_selection": {
            "method": (
                "preserve the verified prototype negative, then choose 19 "
                "evenly spaced positive-path active groups and select an active "
                "probe software object having zero direct-or-campaign paths"
            ),
            "all_cases_verified_absent_by_extracted_path_set": True,
        },
        "extraction": {
            "software_counts_by_group": extracted["software_counts_by_group"],
            "distinct_referenced_software_count": len(extracted["software"]),
            "path_count": len(extracted["paths"]),
            "inactive_filter_audit": extracted["extraction_audit"],
        },
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
        default=HERE / "golden_set_group_software.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "golden_set_group_software_prototype.json",
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
        extracted = extract_group_software_scope(bundle, group_ids=None)
        print(json.dumps(all_group_scope_summary(extracted), indent=2, sort_keys=True))
        return 0
    if args.generate_all_groups:
        extracted = extract_group_software_scope(bundle, group_ids=None)
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
    extracted = extract_group_software_scope(bundle)
    payload = prototype_payload(extracted, source)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
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
    except GroupSoftwareParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
