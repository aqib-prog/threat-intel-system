#!/usr/bin/env python3
"""Generate deterministic Campaign -[USES]-> Technique golden sets."""

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
SELECTED_CAMPAIGN_IDS = (
    "C0023",  # Operation Ghost
    "C0024",  # SolarWinds Compromise
    "C0034",  # 2022 Ukraine Electric Power Attack
    "C0038",  # HomeLand Justice
    "C0049",  # Leviathan Australian Intrusions
)
FOCUSED_TECHNIQUE_BY_CAMPAIGN = {
    "C0023": "T1001.002",
    "C0024": "T1053.005",
    "C0034": "T1059.001",
    "C0038": "T1003.001",
    "C0049": "T1018",
}
NEGATIVE_TECHNIQUE_BY_CAMPAIGN = {
    "C0023": "T1496",
    "C0024": "T1486",
    "C0034": "T1584.008",
    "C0038": "T1531",
    "C0049": "T1649",
}
FULL_NEGATIVE_EXISTENCE_CASE_COUNT = 10
ADVERSARIAL_NEGATIVE_CASE_COUNT = 86
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
PLATFORM_FILTER = "Windows"
SCOPE = "active_campaign_direct_uses_active_attack_pattern"
METHODOLOGY_NOTE = (
    "Only active direct STIX uses relationships from an active campaign to an "
    "active attack-pattern are included. No group or software-mediated paths "
    "are inferred. Parent techniques and sub-techniques remain distinct when "
    "each has its own relationship. Negative and zero-path answers assert only "
    "what is absent from the pinned Enterprise ATT&CK snapshot."
)


class CampaignTechniqueParserError(RuntimeError):
    """Raised when campaign/technique relationship data is invalid."""


def require_unique_external_ids(
    objects: list[dict[str, Any]], description: str
) -> dict[str, dict[str, Any]]:
    rows = [(mitre_external_id(obj), obj) for obj in objects]
    missing = [obj["id"] for external_id, obj in rows if external_id is None]
    if missing:
        raise CampaignTechniqueParserError(
            f"active {description} objects lack MITRE external IDs: "
            + ", ".join(sorted(missing))
        )
    result = {external_id: obj for external_id, obj in rows if external_id}
    if len(result) != len(rows):
        raise CampaignTechniqueParserError(
            f"active {description} objects have duplicate MITRE external IDs"
        )
    return result


def compact_campaign(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "first_seen": obj.get("first_seen"),
        "last_seen": obj.get("last_seen"),
    }


def compact_technique(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
        "platforms": sorted(set(obj.get("x_mitre_platforms", []))),
    }


def compact_group(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "aliases": sorted(set(obj.get("aliases", []))),
    }


def extract_campaign_technique_scope(
    bundle: dict[str, Any],
    campaign_ids: tuple[str, ...] | None = SELECTED_CAMPAIGN_IDS,
) -> dict[str, Any]:
    """Extract the global direct edge set plus the requested campaign anchors."""
    if campaign_ids is not None and len(campaign_ids) != len(set(campaign_ids)):
        raise CampaignTechniqueParserError("selected campaign IDs are not unique")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise CampaignTechniqueParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]
    active_campaign_objects = [
        obj for obj in typed if obj.get("type") == "campaign" and is_active(obj)
    ]
    active_technique_objects = [
        obj
        for obj in typed
        if obj.get("type") == "attack-pattern" and is_active(obj)
    ]
    active_group_objects = [
        obj
        for obj in typed
        if obj.get("type") == "intrusion-set" and is_active(obj)
    ]
    campaign_catalog = require_unique_external_ids(
        active_campaign_objects, "campaign"
    )
    technique_catalog = require_unique_external_ids(
        active_technique_objects, "attack-pattern"
    )
    selected_campaign_ids = (
        tuple(sorted(campaign_catalog)) if campaign_ids is None else campaign_ids
    )
    missing = [item for item in selected_campaign_ids if item not in campaign_catalog]
    if missing:
        raise CampaignTechniqueParserError(
            "selected active campaigns are missing: " + ", ".join(missing)
        )

    campaign_by_stix = {obj["id"]: obj for obj in active_campaign_objects}
    technique_by_stix = {obj["id"]: obj for obj in active_technique_objects}
    group_by_stix = {obj["id"]: obj for obj in active_group_objects}
    all_uses = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "uses"
    ]
    active_direct_uses = [
        rel
        for rel in all_uses
        if is_active(rel)
        and rel.get("source_ref") in campaign_by_stix
        and rel.get("target_ref") in technique_by_stix
    ]
    paths = [
        {
            "campaign_ref": rel["source_ref"],
            "technique_ref": rel["target_ref"],
            "uses_relationship_stix_id": rel["id"],
        }
        for rel in active_direct_uses
    ]
    paths.sort(
        key=lambda path: (
            mitre_external_id(campaign_by_stix[path["campaign_ref"]]) or "",
            mitre_external_id(technique_by_stix[path["technique_ref"]]) or "",
            path["uses_relationship_stix_id"],
        )
    )
    pair_keys = {(path["campaign_ref"], path["technique_ref"]) for path in paths}
    if len(pair_keys) != len(paths):
        raise CampaignTechniqueParserError(
            "multiple active relationships encode the same campaign/technique pair"
        )
    attribution_paths = [
        {
            "campaign_ref": rel["source_ref"],
            "group_ref": rel["target_ref"],
            "attributed_to_relationship_stix_id": rel["id"],
        }
        for rel in typed
        if rel.get("type") == "relationship"
        and rel.get("relationship_type") == "attributed-to"
        and is_active(rel)
        and rel.get("source_ref") in campaign_by_stix
        and rel.get("target_ref") in group_by_stix
    ]
    attribution_paths.sort(
        key=lambda path: (
            mitre_external_id(campaign_by_stix[path["campaign_ref"]]) or "",
            mitre_external_id(group_by_stix[path["group_ref"]]) or "",
            path["attributed_to_relationship_stix_id"],
        )
    )

    selected_campaign_objects = [
        campaign_catalog[item] for item in selected_campaign_ids
    ]
    selected_stix_ids = {obj["id"] for obj in selected_campaign_objects}
    selected_path_count = sum(
        path["campaign_ref"] in selected_stix_ids for path in paths
    )
    technique_counts_by_campaign = {
        external_id: sum(
            path["campaign_ref"] == campaign_catalog[external_id]["id"]
            for path in paths
        )
        for external_id in selected_campaign_ids
    }
    campaign_counts_by_technique = {
        external_id: sum(
            path["technique_ref"] == technique_catalog[external_id]["id"]
            for path in paths
        )
        for external_id in sorted(technique_catalog)
    }
    all_campaign_counts = {
        obj["id"]: sum(path["campaign_ref"] == obj["id"] for path in paths)
        for obj in active_campaign_objects
    }
    return {
        "campaigns": [compact_campaign(obj) for obj in selected_campaign_objects],
        "active_campaign_catalog": [
            compact_campaign(campaign_catalog[item])
            for item in sorted(campaign_catalog)
        ],
        "active_technique_catalog": [
            compact_technique(technique_catalog[item])
            for item in sorted(technique_catalog)
        ],
        "active_group_catalog": [
            compact_group(obj)
            for obj in sorted(
                active_group_objects,
                key=lambda item: mitre_external_id(item) or "",
            )
        ],
        "campaign_attribution_paths": attribution_paths,
        "paths": paths,
        "technique_counts_by_campaign": technique_counts_by_campaign,
        "campaign_counts_by_technique": campaign_counts_by_technique,
        "global_coverage": {
            "active_campaign_count": len(active_campaign_objects),
            "active_technique_count": len(active_technique_objects),
            "active_direct_campaign_technique_uses_edge_count": len(paths),
            "campaigns_with_one_or_more_techniques": sum(
                count > 0 for count in all_campaign_counts.values()
            ),
            "campaigns_with_zero_techniques": sum(
                count == 0 for count in all_campaign_counts.values()
            ),
            "techniques_with_one_or_more_campaigns": sum(
                count > 0 for count in campaign_counts_by_technique.values()
            ),
            "techniques_with_zero_campaigns": sum(
                count == 0 for count in campaign_counts_by_technique.values()
            ),
        },
        "extraction_audit": {
            "bundle_uses_relationship_count": len(all_uses),
            "inactive_non_campaign_or_dangling_uses_relationship_count": (
                len(all_uses) - len(paths)
            ),
            "selected_campaign_path_count": selected_path_count,
        },
    }


def campaign_label(campaign: dict[str, Any]) -> str:
    return f"{campaign['external_id']} ({campaign['name']})"


def technique_label(technique: dict[str, Any]) -> str:
    return f"{technique['external_id']} ({technique['name']})"


def paths_for_campaign(
    campaign: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    techniques = {
        item["stix_id"]: item for item in extracted["active_technique_catalog"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["campaign_ref"] == campaign["stix_id"]
    ]
    technique_ids = sorted(
        {path["technique_ref"] for path in paths},
        key=lambda stix_id: (
            techniques[stix_id]["external_id"] or "",
            stix_id,
        ),
    )
    return [techniques[item] for item in technique_ids], paths


def paths_for_technique(
    technique: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    campaigns = {
        item["stix_id"]: item for item in extracted["active_campaign_catalog"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["technique_ref"] == technique["stix_id"]
    ]
    campaign_ids = sorted(
        {path["campaign_ref"] for path in paths},
        key=lambda stix_id: (
            campaigns[stix_id]["external_id"] or "",
            stix_id,
        ),
    )
    return [campaigns[item] for item in campaign_ids], paths


def campaign_provenance(
    campaign: dict[str, Any],
    techniques: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    queried_technique: dict[str, Any] | None = None,
    platform_filter: str | None = None,
) -> dict[str, Any]:
    result = {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "campaign_stix_id": campaign["stix_id"],
        "technique_stix_ids": [item["stix_id"] for item in techniques],
        "uses_relationship_stix_ids": [
            path["uses_relationship_stix_id"] for path in paths
        ],
        "relationship_paths": paths,
    }
    if queried_technique is not None:
        result["queried_technique_stix_id"] = queried_technique["stix_id"]
    if platform_filter is not None:
        result["platform_filter"] = platform_filter
        result["platform_source_field"] = "attack-pattern.x_mitre_platforms"
    return result


def technique_provenance(
    technique: dict[str, Any],
    campaigns: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    source: dict[str, Any],
) -> dict[str, Any]:
    return {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "technique_stix_id": technique["stix_id"],
        "campaign_stix_ids": [item["stix_id"] for item in campaigns],
        "uses_relationship_stix_ids": [
            path["uses_relationship_stix_id"] for path in paths
        ],
        "relationship_paths": paths,
    }


def forward_pair(
    campaign: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    techniques, paths = paths_for_campaign(campaign, extracted)
    if not techniques:
        return {
            "id": f"campaign-has-no-techniques-{campaign['external_id'].lower()}",
            "case_type": "aggregate_campaign_no_techniques",
            "relationship_type": "campaign_uses_technique",
            "question": f"What techniques does {campaign_label(campaign)} use?",
            "expected_answer": (
                "No active direct uses relationship from "
                f"{campaign_label(campaign)} to an active technique is recorded "
                "in the pinned Enterprise ATT&CK snapshot."
            ),
            "campaign": campaign,
            "expected_techniques": [],
            "provenance": campaign_provenance(campaign, [], [], source),
        }
    return {
        "id": f"campaign-uses-techniques-{campaign['external_id'].lower()}",
        "case_type": "aggregate_campaign_techniques",
        "relationship_type": "campaign_uses_technique",
        "question": f"What techniques does {campaign_label(campaign)} use?",
        "expected_answer": (
            f"{campaign_label(campaign)} directly uses "
            f"{natural_list([technique_label(item) for item in techniques])} "
            "in the pinned Enterprise ATT&CK snapshot."
        ),
        "campaign": campaign,
        "expected_techniques": techniques,
        "provenance": campaign_provenance(
            campaign, techniques, paths, source
        ),
    }


def focused_pair(
    campaign: dict[str, Any],
    technique: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    _, paths = paths_for_campaign(campaign, extracted)
    matching = [path for path in paths if path["technique_ref"] == technique["stix_id"]]
    if len(matching) != 1:
        raise CampaignTechniqueParserError(
            f"expected one active edge {campaign['external_id']} -> "
            f"{technique['external_id']}, found {len(matching)}"
        )
    return {
        "id": (
            f"campaign-uses-technique-{campaign['external_id'].lower()}-"
            f"{technique['external_id'].lower()}"
        ),
        "case_type": "focused_campaign_technique",
        "relationship_type": "campaign_uses_technique",
        "question": (
            f"Does {campaign_label(campaign)} use {technique_label(technique)}?"
        ),
        "expected_answer": (
            f"Yes. {campaign_label(campaign)} directly uses "
            f"{technique_label(technique)} in the pinned Enterprise ATT&CK snapshot."
        ),
        "campaign": campaign,
        "queried_technique": technique,
        "expected_techniques": [technique],
        "provenance": campaign_provenance(
            campaign,
            [technique],
            matching,
            source,
            queried_technique=technique,
        ),
    }


def negative_pair(
    campaign: dict[str, Any],
    technique: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    path_keys = {
        (path["campaign_ref"], path["technique_ref"])
        for path in extracted["paths"]
    }
    if (campaign["stix_id"], technique["stix_id"]) in path_keys:
        raise CampaignTechniqueParserError(
            f"negative edge {campaign['external_id']} -> "
            f"{technique['external_id']} exists"
        )
    return {
        "id": (
            f"campaign-not-uses-technique-{campaign['external_id'].lower()}-"
            f"{technique['external_id'].lower()}"
        ),
        "case_type": "negative_campaign_technique",
        "relationship_type": "campaign_uses_technique",
        "question": (
            f"Does {campaign_label(campaign)} use {technique_label(technique)}?"
        ),
        "expected_answer": (
            "No active direct uses relationship exists from "
            f"{campaign_label(campaign)} to {technique_label(technique)} in the "
            "pinned Enterprise ATT&CK snapshot."
        ),
        "campaign": campaign,
        "queried_technique": technique,
        "expected_techniques": [],
        "provenance": campaign_provenance(
            campaign, [], [], source, queried_technique=technique
        ),
    }


def reverse_pair(
    technique: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    campaigns, paths = paths_for_technique(technique, extracted)
    if not campaigns:
        return {
            "id": f"technique-has-no-campaigns-{technique['external_id'].lower()}",
            "case_type": "aggregate_technique_no_campaigns",
            "relationship_type": "campaign_uses_technique",
            "question": f"Which campaigns use {technique_label(technique)}?",
            "expected_answer": (
                "No active direct uses relationship from an active campaign to "
                f"{technique_label(technique)} is recorded in the pinned "
                "Enterprise ATT&CK snapshot."
            ),
            "technique": technique,
            "expected_campaigns": [],
            "provenance": technique_provenance(technique, [], [], source),
        }
    return {
        "id": f"technique-used-by-campaigns-{technique['external_id'].lower()}",
        "case_type": "aggregate_technique_campaigns",
        "relationship_type": "campaign_uses_technique",
        "question": f"Which campaigns use {technique_label(technique)}?",
        "expected_answer": (
            f"{technique_label(technique)} is directly used by "
            f"{natural_list([campaign_label(item) for item in campaigns])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "technique": technique,
        "expected_campaigns": campaigns,
        "provenance": technique_provenance(
            technique, campaigns, paths, source
        ),
    }


def platform_pair(
    campaign: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
    platform: str = PLATFORM_FILTER,
) -> dict[str, Any]:
    techniques, paths = paths_for_campaign(campaign, extracted)
    matching = [item for item in techniques if platform in item["platforms"]]
    matching_stix = {item["stix_id"] for item in matching}
    matching_paths = [
        path for path in paths if path["technique_ref"] in matching_stix
    ]
    slug = platform.lower().replace(" ", "-")
    if not matching:
        return {
            "id": (
                f"campaign-has-no-{slug}-techniques-"
                f"{campaign['external_id'].lower()}"
            ),
            "case_type": "aggregate_campaign_no_platform_techniques",
            "relationship_type": "campaign_uses_technique",
            "question": (
                f"Which {platform} techniques does {campaign_label(campaign)} use?"
            ),
            "expected_answer": (
                "No active direct uses relationship from "
                f"{campaign_label(campaign)} to an active technique whose "
                f"Technique.platforms includes {platform} is recorded in the "
                "pinned Enterprise ATT&CK snapshot."
            ),
            "campaign": campaign,
            "platform_filter": platform,
            "expected_techniques": [],
            "provenance": campaign_provenance(
                campaign, [], [], source, platform_filter=platform
            ),
        }
    return {
        "id": (
            f"campaign-uses-{slug}-techniques-"
            f"{campaign['external_id'].lower()}"
        ),
        "case_type": "aggregate_campaign_platform_techniques",
        "relationship_type": "campaign_uses_technique",
        "question": (
            f"Which {platform} techniques does {campaign_label(campaign)} use?"
        ),
        "expected_answer": (
            f"The active techniques directly used by {campaign_label(campaign)} "
            f"whose Technique.platforms includes {platform} are "
            f"{natural_list([technique_label(item) for item in matching])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "campaign": campaign,
        "platform_filter": platform,
        "expected_techniques": matching,
        "provenance": campaign_provenance(
            campaign,
            matching,
            matching_paths,
            source,
            platform_filter=platform,
        ),
    }


def generate_prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    campaigns = {item["external_id"]: item for item in extracted["campaigns"]}
    techniques = {
        item["external_id"]: item
        for item in extracted["active_technique_catalog"]
    }
    pairs = [
        forward_pair(campaigns[item], extracted, source)
        for item in SELECTED_CAMPAIGN_IDS
    ]
    pairs.extend(
        focused_pair(
            campaigns[campaign_id], techniques[technique_id], extracted, source
        )
        for campaign_id, technique_id in FOCUSED_TECHNIQUE_BY_CAMPAIGN.items()
    )
    pairs.extend(
        reverse_pair(techniques[technique_id], extracted, source)
        for technique_id in FOCUSED_TECHNIQUE_BY_CAMPAIGN.values()
    )
    pairs.extend(
        platform_pair(campaigns[item], extracted, source)
        for item in SELECTED_CAMPAIGN_IDS
    )
    pairs.extend(
        negative_pair(
            campaigns[campaign_id], techniques[technique_id], extracted, source
        )
        for campaign_id, technique_id in NEGATIVE_TECHNIQUE_BY_CAMPAIGN.items()
    )
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise CampaignTechniqueParserError("prototype pair IDs are not unique")
    return pairs


def evenly_spaced_items(items: list[Any], count: int) -> list[Any]:
    if count <= 0:
        return []
    if len(items) < count:
        raise CampaignTechniqueParserError(
            f"cannot select {count} items from {len(items)} candidates"
        )
    if count == 1:
        return [items[len(items) // 2]]
    indices = [round(index * (len(items) - 1) / (count - 1)) for index in range(count)]
    return [items[index] for index in indices]


def select_full_negative_cases(extracted: dict[str, Any]) -> dict[str, str]:
    campaigns = {item["external_id"]: item for item in extracted["campaigns"]}
    techniques = {
        item["external_id"]: item
        for item in extracted["active_technique_catalog"]
    }
    paths = {
        (path["campaign_ref"], path["technique_ref"])
        for path in extracted["paths"]
    }
    selected = dict(NEGATIVE_TECHNIQUE_BY_CAMPAIGN)
    needed = FULL_NEGATIVE_EXISTENCE_CASE_COUNT - len(selected)
    candidates = [
        item
        for item in sorted(campaigns)
        if item not in selected
        and extracted["technique_counts_by_campaign"][item] > 0
    ]
    for offset, campaign_id in enumerate(evenly_spaced_items(candidates, needed)):
        campaign = campaigns[campaign_id]
        probes = (
            FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[offset:]
            + FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[:offset]
        )
        for technique_id in probes:
            technique = techniques.get(technique_id)
            if technique is None:
                continue
            if (campaign["stix_id"], technique["stix_id"]) not in paths:
                selected[campaign_id] = technique_id
                break
        else:
            raise CampaignTechniqueParserError(
                f"no configured negative probe is absent for {campaign_id}"
            )
    if len(selected) != FULL_NEGATIVE_EXISTENCE_CASE_COUNT:
        raise CampaignTechniqueParserError(
            f"expected {FULL_NEGATIVE_EXISTENCE_CASE_COUNT} negatives, "
            f"selected {len(selected)}"
        )
    return selected


def select_adversarial_negative_cases(
    extracted: dict[str, Any],
    existing_negative_cases: dict[str, str],
    *,
    count: int = ADVERSARIAL_NEGATIVE_CASE_COUNT,
) -> list[dict[str, Any]]:
    """Choose false campaign/technique pairs from a same-actor campaign."""

    campaigns = {
        item["stix_id"]: item for item in extracted["campaigns"]
    }
    groups = {
        item["stix_id"]: item for item in extracted["active_group_catalog"]
    }
    techniques = {
        item["stix_id"]: item
        for item in extracted["active_technique_catalog"]
    }
    techniques_by_campaign: dict[str, set[str]] = {
        campaign_ref: set() for campaign_ref in campaigns
    }
    technique_paths: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in extracted["paths"]:
        if path["campaign_ref"] not in campaigns:
            continue
        techniques_by_campaign[path["campaign_ref"]].add(
            path["technique_ref"]
        )
        technique_paths.setdefault(
            (path["campaign_ref"], path["technique_ref"]), []
        ).append(path)
    campaigns_by_group: dict[str, set[str]] = {}
    attribution_paths: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in extracted["campaign_attribution_paths"]:
        if path["campaign_ref"] not in campaigns:
            continue
        campaigns_by_group.setdefault(path["group_ref"], set()).add(
            path["campaign_ref"]
        )
        attribution_paths.setdefault(
            (path["campaign_ref"], path["group_ref"]), []
        ).append(path)
    existing_keys = {
        (
            next(
                item["stix_id"]
                for item in campaigns.values()
                if item["external_id"] == campaign_id
            ),
            next(
                item["stix_id"]
                for item in techniques.values()
                if item["external_id"] == technique_id
            ),
        )
        for campaign_id, technique_id in existing_negative_cases.items()
    }
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    for group_ref in sorted(
        campaigns_by_group,
        key=lambda ref: groups[ref]["external_id"],
    ):
        sibling_campaign_refs = sorted(
            campaigns_by_group[group_ref],
            key=lambda ref: campaigns[ref]["external_id"],
        )
        for campaign_ref in sibling_campaign_refs:
            for sibling_ref in sibling_campaign_refs:
                if sibling_ref == campaign_ref:
                    continue
                sibling_only = (
                    techniques_by_campaign[sibling_ref]
                    - techniques_by_campaign[campaign_ref]
                )
                for technique_ref in sorted(
                    sibling_only,
                    key=lambda ref: techniques[ref]["external_id"],
                ):
                    key = (campaign_ref, technique_ref)
                    if key in existing_keys:
                        continue
                    candidates.setdefault(
                        key,
                        {
                            "campaign": campaigns[campaign_ref],
                            "technique": techniques[technique_ref],
                            "sibling_campaign": campaigns[sibling_ref],
                            "shared_group": groups[group_ref],
                            "campaign_attribution_paths": sorted(
                                attribution_paths[(campaign_ref, group_ref)],
                                key=lambda path: path[
                                    "attributed_to_relationship_stix_id"
                                ],
                            ),
                            "sibling_attribution_paths": sorted(
                                attribution_paths[(sibling_ref, group_ref)],
                                key=lambda path: path[
                                    "attributed_to_relationship_stix_id"
                                ],
                            ),
                            "sibling_technique_paths": sorted(
                                technique_paths[(sibling_ref, technique_ref)],
                                key=lambda path: path[
                                    "uses_relationship_stix_id"
                                ],
                            ),
                        },
                    )
    selected = evenly_spaced_items(
        sorted(
            candidates.values(),
            key=lambda row: (
                row["campaign"]["external_id"],
                row["technique"]["external_id"],
                row["sibling_campaign"]["external_id"],
            ),
        ),
        count,
    )
    return selected


def adversarial_negative_pair(
    row: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    campaign = row["campaign"]
    technique = row["technique"]
    pair = negative_pair(campaign, technique, extracted, source)
    pair.update(
        {
            "id": (
                "campaign-adversarial-not-uses-technique-"
                f"{campaign['external_id'].lower()}-"
                f"{technique['external_id'].lower()}"
            ),
            "case_type": "adversarial_negative_campaign_technique",
            "relationship_exists": False,
            "expected_answer": (
                f"No active direct uses relationship exists from "
                f"{campaign_label(campaign)} to {technique_label(technique)} "
                "in the pinned Enterprise ATT&CK snapshot. The confusion is "
                f"plausible because sibling "
                f"{campaign_label(row['sibling_campaign'])}, attributed to "
                f"{row['shared_group']['external_id']} "
                f"({row['shared_group']['name']}) like the queried campaign, "
                f"does use {technique_label(technique)}."
            ),
        }
    )
    pair["provenance"].update(
        {
            "difficulty": "adversarial_sibling",
            "adversarial_context": {
                "method": "different_campaign_same_attributed_actor",
                "sibling_campaign": row["sibling_campaign"],
                "shared_group": row["shared_group"],
                "campaign_attribution_paths": row[
                    "campaign_attribution_paths"
                ],
                "sibling_attribution_paths": row[
                    "sibling_attribution_paths"
                ],
                "sibling_technique_paths": row[
                    "sibling_technique_paths"
                ],
            },
        }
    )
    return pair


def generate_full_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    campaigns = {item["external_id"]: item for item in extracted["campaigns"]}
    techniques = {
        item["external_id"]: item
        for item in extracted["active_technique_catalog"]
    }
    forward = [
        forward_pair(campaigns[item], extracted, source) for item in sorted(campaigns)
    ]
    reverse = [
        reverse_pair(techniques[item], extracted, source) for item in sorted(techniques)
    ]
    focused = []
    for campaign_id in sorted(campaigns):
        campaign = campaigns[campaign_id]
        used, _ = paths_for_campaign(campaign, extracted)
        if used:
            focused.append(focused_pair(campaign, used[0], extracted, source))
    platform = [
        platform_pair(campaigns[item], extracted, source)
        for item in sorted(campaigns)
    ]
    negative_cases = select_full_negative_cases(extracted)
    negatives = [
        negative_pair(
            campaigns[campaign_id], techniques[technique_id], extracted, source
        )
        for campaign_id, technique_id in sorted(negative_cases.items())
    ]
    adversarial_cases = select_adversarial_negative_cases(
        extracted, negative_cases
    )
    adversarial = [
        adversarial_negative_pair(row, extracted, source)
        for row in adversarial_cases
    ]
    pairs = forward + reverse + focused + platform + negatives + adversarial
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise CampaignTechniqueParserError("full pair IDs are not unique")
    return pairs, negative_cases


def parsed_campaign_data(extracted: dict[str, Any]) -> dict[str, Any]:
    return {
        campaign["external_id"]: {
            "campaign": campaign,
            "techniques": paths_for_campaign(campaign, extracted)[0],
            "relationship_paths": paths_for_campaign(campaign, extracted)[1],
        }
        for campaign in extracted["campaigns"]
    }


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_campaign_technique_uses_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "campaign",
            "target_type": "attack-pattern",
            "relationship_type": "uses",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "campaign_external_ids": list(SELECTED_CAMPAIGN_IDS),
            "campaign_count": len(SELECTED_CAMPAIGN_IDS),
            "pair_count": len(pairs),
            "forward_aggregate_pairs": 5,
            "focused_positive_pairs": 5,
            "reverse_aggregate_pairs": 5,
            "platform_constrained_pairs": 5,
            "negative_existence_pairs": 5,
            "explicit_point_negative_ratio": 0.5,
            "explicit_point_negative_share_of_all_pairs": 0.2,
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "parsed_data": parsed_campaign_data(extracted),
        "pairs": pairs,
    }


def full_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs, negative_cases = generate_full_pairs(extracted, source)
    counts = {
        name: sum(pair["case_type"] == name for pair in pairs)
        for name in {pair["case_type"] for pair in pairs}
    }
    focused_count = counts.get("focused_campaign_technique", 0)
    negative_count = counts.get("negative_campaign_technique", 0)
    adversarial_count = counts.get(
        "adversarial_negative_campaign_technique", 0
    )
    total_negative_count = negative_count + adversarial_count
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_full_campaign_technique_golden_set",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "campaign",
            "target_type": "attack-pattern",
            "relationship_type": "uses",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "one_forward_aggregate_per_active_campaign": True,
            "one_reverse_aggregate_per_active_technique": True,
            "one_windows_constrained_pair_per_active_campaign": True,
            "adversarial_sibling_negatives": True,
        },
        "selection": {
            "active_campaign_count": len(extracted["campaigns"]),
            "active_technique_count": len(extracted["active_technique_catalog"]),
            "pair_count": len(pairs),
            "forward_aggregate_pairs": counts.get("aggregate_campaign_techniques", 0),
            "forward_zero_path_pairs": counts.get(
                "aggregate_campaign_no_techniques", 0
            ),
            "reverse_aggregate_pairs": counts.get("aggregate_technique_campaigns", 0),
            "reverse_zero_path_pairs": counts.get(
                "aggregate_technique_no_campaigns", 0
            ),
            "focused_positive_pairs": focused_count,
            "platform_constrained_positive_pairs": counts.get(
                "aggregate_campaign_platform_techniques", 0
            ),
            "platform_constrained_zero_path_pairs": counts.get(
                "aggregate_campaign_no_platform_techniques", 0
            ),
            "negative_existence_pairs": negative_count,
            "negative_existence_distinct_campaign_count": len(negative_cases),
            "adversarial_negative_pairs": adversarial_count,
            "total_negative_pairs": total_negative_count,
            "total_negative_ratio": total_negative_count / len(pairs),
            "explicit_point_negative_ratio": (
                negative_count / (focused_count + negative_count)
            ),
            "embedded_forward_fact_count": sum(
                len(pair.get("expected_techniques", []))
                for pair in pairs
                if pair["case_type"].startswith("aggregate_campaign_")
                and "platform" not in pair["case_type"]
            ),
            "embedded_reverse_fact_count": sum(
                len(pair.get("expected_campaigns", []))
                for pair in pairs
                if pair["case_type"].startswith("aggregate_technique_")
            ),
        },
        "negative_selection": {
            "method": (
                "preserve the five verified prototype negatives, then choose "
                "five evenly spaced positive campaigns and select a configured "
                "active probe technique with no direct uses relationship"
            ),
            "all_cases_verified_absent_by_extracted_path_set": True,
            "adversarial_method": (
                "pair a campaign with a technique used by another campaign "
                "attributed to the same active group"
            ),
            "adversarial_cases_verified_absent_by_extracted_path_set": True,
            "unrelated_pair_fallback_count": 0,
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "parsed_data": parsed_campaign_data(extracted),
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "golden_set_campaign_technique_prototype.json",
    )
    parser.add_argument(
        "--generate-all-campaigns",
        action="store_true",
        help="write the full all-active-campaign/technique golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_campaign_technique.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    if args.generate_all_campaigns:
        extracted = extract_campaign_technique_scope(bundle, campaign_ids=None)
        payload = full_payload(extracted, source)
        output = args.full_output
    else:
        extracted = extract_campaign_technique_scope(bundle)
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
    except CampaignTechniqueParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
