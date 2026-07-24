#!/usr/bin/env python3
"""Generate deterministic Campaign -[USES]-> Malware/Tool golden sets."""

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
    "C0002",  # Night Dragon
    "C0023",  # Operation Ghost
    "C0024",  # SolarWinds Compromise
    "C0034",  # 2022 Ukraine Electric Power Attack
    "C0038",  # HomeLand Justice
)
FOCUSED_SOFTWARE_BY_CAMPAIGN = {
    "C0002": "S0008",  # Night Dragon -> gsecdump (Tool)
    "C0023": "S0051",  # Operation Ghost -> MiniDuke (Malware)
    "C0024": "S0559",  # SolarWinds Compromise -> SUNBURST (Malware)
    "C0034": "S0693",  # 2022 Ukraine Electric Power Attack -> CaddyWiper
    "C0038": "S0357",  # HomeLand Justice -> Impacket (Tool)
}
NEGATIVE_SOFTWARE_BY_CAMPAIGN = {
    "C0002": "S0154",
    "C0023": "S0366",
    "C0024": "S0266",
    "C0034": "S0002",
    "C0038": "S0633",
}
FULL_NEGATIVE_EXISTENCE_CASE_COUNT = 10
ADVERSARIAL_NEGATIVE_CASE_COUNT = 100
FULL_NEGATIVE_PROBE_SOFTWARE_IDS = (
    "S0002",  # Mimikatz (Tool)
    "S0154",  # Cobalt Strike (Malware)
    "S0366",  # WannaCry (Malware)
    "S0266",  # TrickBot (Malware)
    "S0633",  # Sliver (Tool)
    "S0357",  # Impacket (Tool)
    "S0521",  # JSP Web Shell (Malware)
    "S0552",  # AdFind (Tool)
    "S0194",  # POWRUNER (Malware)
    "S0039",  # Net (Tool)
)
PLATFORM_FILTER = "Windows"
SCOPE = "active_campaign_direct_uses_active_enterprise_malware_or_tool"
METHODOLOGY_NOTE = (
    "Only active direct STIX uses relationships from an active campaign to an "
    "active Enterprise ATT&CK malware or tool object are included. Malware and "
    "Tool share the software relationship scope but retain their exact STIX "
    "types in every entity and answer. Mobile-domain software is excluded "
    "because the pinned source is the Enterprise ATT&CK bundle. Negative and "
    "zero-path answers assert only what is absent from the pinned snapshot."
)


class CampaignSoftwareParserError(RuntimeError):
    """Raised when campaign/software relationship data is invalid."""


def require_unique_external_ids(
    objects: list[dict[str, Any]], description: str
) -> dict[str, dict[str, Any]]:
    rows = [(mitre_external_id(obj), obj) for obj in objects]
    missing = [obj["id"] for external_id, obj in rows if external_id is None]
    if missing:
        raise CampaignSoftwareParserError(
            f"active {description} objects lack MITRE external IDs: "
            + ", ".join(sorted(missing))
        )
    result = {external_id: obj for external_id, obj in rows if external_id}
    if len(result) != len(rows):
        raise CampaignSoftwareParserError(
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


def compact_software(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "stix_type": obj.get("type"),
        "platforms": sorted(set(obj.get("x_mitre_platforms", []))),
    }


def compact_group(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "aliases": sorted(set(obj.get("aliases", []))),
    }


def extract_campaign_software_scope(
    bundle: dict[str, Any],
    campaign_ids: tuple[str, ...] | None = SELECTED_CAMPAIGN_IDS,
) -> dict[str, Any]:
    """Extract the global direct edge set plus requested campaign anchors."""
    if campaign_ids is not None and len(campaign_ids) != len(set(campaign_ids)):
        raise CampaignSoftwareParserError("selected campaign IDs are not unique")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise CampaignSoftwareParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]
    active_campaign_objects = [
        obj for obj in typed if obj.get("type") == "campaign" and is_active(obj)
    ]
    active_software_objects = [
        obj
        for obj in typed
        if obj.get("type") in {"malware", "tool"} and is_active(obj)
    ]
    active_group_objects = [
        obj
        for obj in typed
        if obj.get("type") == "intrusion-set" and is_active(obj)
    ]
    campaign_catalog = require_unique_external_ids(
        active_campaign_objects, "campaign"
    )
    software_catalog = require_unique_external_ids(
        active_software_objects, "malware/tool"
    )
    selected_campaign_ids = (
        tuple(sorted(campaign_catalog)) if campaign_ids is None else campaign_ids
    )
    missing = [item for item in selected_campaign_ids if item not in campaign_catalog]
    if missing:
        raise CampaignSoftwareParserError(
            "selected active campaigns are missing: " + ", ".join(missing)
        )

    campaign_by_stix = {obj["id"]: obj for obj in active_campaign_objects}
    software_by_stix = {obj["id"]: obj for obj in active_software_objects}
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
        and rel.get("target_ref") in software_by_stix
    ]
    paths = [
        {
            "campaign_ref": rel["source_ref"],
            "software_ref": rel["target_ref"],
            "uses_relationship_stix_id": rel["id"],
        }
        for rel in active_direct_uses
    ]
    paths.sort(
        key=lambda path: (
            mitre_external_id(campaign_by_stix[path["campaign_ref"]]) or "",
            mitre_external_id(software_by_stix[path["software_ref"]]) or "",
            path["uses_relationship_stix_id"],
        )
    )
    pair_keys = {(path["campaign_ref"], path["software_ref"]) for path in paths}
    if len(pair_keys) != len(paths):
        raise CampaignSoftwareParserError(
            "multiple active relationships encode the same campaign/software pair"
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
    software_counts_by_campaign = {}
    for external_id in selected_campaign_ids:
        campaign_ref = campaign_catalog[external_id]["id"]
        targets = [
            software_by_stix[path["software_ref"]]
            for path in paths
            if path["campaign_ref"] == campaign_ref
        ]
        software_counts_by_campaign[external_id] = {
            "total": len(targets),
            "malware": sum(obj.get("type") == "malware" for obj in targets),
            "tools": sum(obj.get("type") == "tool" for obj in targets),
        }
    campaign_counts_by_software = {
        external_id: sum(
            path["software_ref"] == software_catalog[external_id]["id"]
            for path in paths
        )
        for external_id in sorted(software_catalog)
    }
    all_campaign_counts = {
        obj["id"]: sum(path["campaign_ref"] == obj["id"] for path in paths)
        for obj in active_campaign_objects
    }
    malware_ids = {
        obj["id"] for obj in active_software_objects if obj.get("type") == "malware"
    }
    tool_ids = {
        obj["id"] for obj in active_software_objects if obj.get("type") == "tool"
    }
    malware_edge_count = sum(path["software_ref"] in malware_ids for path in paths)
    tool_edge_count = sum(path["software_ref"] in tool_ids for path in paths)
    return {
        "campaigns": [compact_campaign(obj) for obj in selected_campaign_objects],
        "active_campaign_catalog": [
            compact_campaign(campaign_catalog[item])
            for item in sorted(campaign_catalog)
        ],
        "active_software_catalog": [
            compact_software(software_catalog[item])
            for item in sorted(software_catalog)
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
        "software_counts_by_campaign": software_counts_by_campaign,
        "campaign_counts_by_software": campaign_counts_by_software,
        "global_coverage": {
            "active_campaign_count": len(active_campaign_objects),
            "active_software_count": len(active_software_objects),
            "active_malware_count": len(malware_ids),
            "active_tool_count": len(tool_ids),
            "active_direct_campaign_software_uses_edge_count": len(paths),
            "active_direct_campaign_malware_uses_edge_count": malware_edge_count,
            "active_direct_campaign_tool_uses_edge_count": tool_edge_count,
            "campaigns_with_one_or_more_software": sum(
                count > 0 for count in all_campaign_counts.values()
            ),
            "campaigns_with_zero_software": sum(
                count == 0 for count in all_campaign_counts.values()
            ),
            "software_with_one_or_more_campaigns": sum(
                count > 0 for count in campaign_counts_by_software.values()
            ),
            "software_with_zero_campaigns": sum(
                count == 0 for count in campaign_counts_by_software.values()
            ),
            "malware_with_one_or_more_campaigns": sum(
                campaign_counts_by_software[mitre_external_id(obj)] > 0
                for obj in active_software_objects
                if obj["id"] in malware_ids
            ),
            "tools_with_one_or_more_campaigns": sum(
                campaign_counts_by_software[mitre_external_id(obj)] > 0
                for obj in active_software_objects
                if obj["id"] in tool_ids
            ),
        },
        "extraction_audit": {
            "bundle_uses_relationship_count": len(all_uses),
            "inactive_non_campaign_or_non_software_uses_relationship_count": (
                len(all_uses) - len(paths)
            ),
            "selected_campaign_path_count": selected_path_count,
        },
    }


def campaign_label(campaign: dict[str, Any]) -> str:
    return f"{campaign['external_id']} ({campaign['name']})"


def software_type_name(software: dict[str, Any]) -> str:
    stix_type = software.get("stix_type")
    if stix_type == "malware":
        return "Malware"
    if stix_type == "tool":
        return "Tool"
    raise CampaignSoftwareParserError(f"unsupported software type: {stix_type}")


def software_label(software: dict[str, Any]) -> str:
    return f"{software['external_id']} ({software['name']})"


def typed_software_label(software: dict[str, Any]) -> str:
    return f"{software_type_name(software)} {software_label(software)}"


def typed_software_sections(software: list[dict[str, Any]]) -> str:
    malware = [
        software_label(item)
        for item in software
        if item["stix_type"] == "malware"
    ]
    tools = [software_label(item) for item in software if item["stix_type"] == "tool"]
    return (
        f"Malware: {natural_list(malware) if malware else 'none'}. "
        f"Tools: {natural_list(tools) if tools else 'none'}."
    )


def paths_for_campaign(
    campaign: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    software = {
        item["stix_id"]: item for item in extracted["active_software_catalog"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["campaign_ref"] == campaign["stix_id"]
    ]
    software_ids = sorted(
        {path["software_ref"] for path in paths},
        key=lambda stix_id: (
            software[stix_id]["external_id"] or "",
            stix_id,
        ),
    )
    return [software[item] for item in software_ids], paths


def paths_for_software(
    software: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    campaigns = {
        item["stix_id"]: item for item in extracted["active_campaign_catalog"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["software_ref"] == software["stix_id"]
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
    software: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    queried_software: dict[str, Any] | None = None,
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
        "software_stix_ids": [item["stix_id"] for item in software],
        "software_stix_types": [item["stix_type"] for item in software],
        "uses_relationship_stix_ids": [
            path["uses_relationship_stix_id"] for path in paths
        ],
        "relationship_paths": paths,
    }
    if queried_software is not None:
        result["queried_software_stix_id"] = queried_software["stix_id"]
        result["queried_software_stix_type"] = queried_software["stix_type"]
    if platform_filter is not None:
        result["platform_filter"] = platform_filter
        result["platform_source_field"] = "malware/tool.x_mitre_platforms"
    return result


def software_provenance(
    software: dict[str, Any],
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
        "software_stix_id": software["stix_id"],
        "software_stix_type": software["stix_type"],
        "campaign_stix_ids": [item["stix_id"] for item in campaigns],
        "uses_relationship_stix_ids": [
            path["uses_relationship_stix_id"] for path in paths
        ],
        "relationship_paths": paths,
    }


def forward_pair(
    campaign: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    software, paths = paths_for_campaign(campaign, extracted)
    if not software:
        return {
            "id": f"campaign-has-no-software-{campaign['external_id'].lower()}",
            "case_type": "aggregate_campaign_no_qualifying_software",
            "relationship_type": "campaign_uses_software",
            "question": f"What malware or tools does {campaign_label(campaign)} use?",
            "expected_answer": (
                "No active direct uses relationship from "
                f"{campaign_label(campaign)} to active Enterprise malware or "
                "tools is recorded in the pinned Enterprise ATT&CK snapshot."
            ),
            "campaign": campaign,
            "expected_software": [],
            "provenance": campaign_provenance(campaign, [], [], source),
        }
    return {
        "id": f"campaign-uses-software-{campaign['external_id'].lower()}",
        "case_type": "aggregate_campaign_software",
        "relationship_type": "campaign_uses_software",
        "question": f"What malware or tools does {campaign_label(campaign)} use?",
        "expected_answer": (
            f"{campaign_label(campaign)} directly uses the following software. "
            f"{typed_software_sections(software)}"
        ),
        "campaign": campaign,
        "expected_software": software,
        "provenance": campaign_provenance(campaign, software, paths, source),
    }


def focused_pair(
    campaign: dict[str, Any],
    software: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    _, paths = paths_for_campaign(campaign, extracted)
    matching = [path for path in paths if path["software_ref"] == software["stix_id"]]
    if len(matching) != 1:
        raise CampaignSoftwareParserError(
            f"expected one active edge {campaign['external_id']} -> "
            f"{software['external_id']}, found {len(matching)}"
        )
    return {
        "id": (
            f"campaign-uses-software-{campaign['external_id'].lower()}-"
            f"{software['external_id'].lower()}"
        ),
        "case_type": "focused_campaign_software",
        "relationship_type": "campaign_uses_software",
        "question": (
            f"Does {campaign_label(campaign)} use {typed_software_label(software)}?"
        ),
        "expected_answer": (
            f"Yes. {campaign_label(campaign)} directly uses "
            f"{typed_software_label(software)} in the pinned Enterprise ATT&CK "
            "snapshot."
        ),
        "campaign": campaign,
        "queried_software": software,
        "expected_software": [software],
        "provenance": campaign_provenance(
            campaign,
            [software],
            matching,
            source,
            queried_software=software,
        ),
    }


def negative_pair(
    campaign: dict[str, Any],
    software: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    path_keys = {
        (path["campaign_ref"], path["software_ref"])
        for path in extracted["paths"]
    }
    if (campaign["stix_id"], software["stix_id"]) in path_keys:
        raise CampaignSoftwareParserError(
            f"negative edge {campaign['external_id']} -> "
            f"{software['external_id']} exists"
        )
    return {
        "id": (
            f"campaign-not-uses-software-{campaign['external_id'].lower()}-"
            f"{software['external_id'].lower()}"
        ),
        "case_type": "negative_campaign_software",
        "relationship_type": "campaign_uses_software",
        "question": (
            f"Does {campaign_label(campaign)} use {typed_software_label(software)}?"
        ),
        "expected_answer": (
            "No active direct uses relationship exists from "
            f"{campaign_label(campaign)} to {typed_software_label(software)} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "campaign": campaign,
        "queried_software": software,
        "expected_software": [],
        "provenance": campaign_provenance(
            campaign, [], [], source, queried_software=software
        ),
    }


def reverse_pair(
    software: dict[str, Any], extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    campaigns, paths = paths_for_software(software, extracted)
    typed_label = typed_software_label(software)
    if not campaigns:
        return {
            "id": f"software-has-no-campaigns-{software['external_id'].lower()}",
            "case_type": "aggregate_software_no_campaigns",
            "relationship_type": "campaign_uses_software",
            "question": f"Which campaigns use {typed_label}?",
            "expected_answer": (
                "No active direct uses relationship from an active campaign to "
                f"{typed_label} is recorded in the pinned Enterprise ATT&CK "
                "snapshot."
            ),
            "software": software,
            "expected_campaigns": [],
            "provenance": software_provenance(software, [], [], source),
        }
    return {
        "id": f"software-used-by-campaigns-{software['external_id'].lower()}",
        "case_type": "aggregate_software_campaigns",
        "relationship_type": "campaign_uses_software",
        "question": f"Which campaigns use {typed_label}?",
        "expected_answer": (
            f"{typed_label} is directly used by "
            f"{natural_list([campaign_label(item) for item in campaigns])} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        "software": software,
        "expected_campaigns": campaigns,
        "provenance": software_provenance(software, campaigns, paths, source),
    }


def platform_pair(
    campaign: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
    platform: str = PLATFORM_FILTER,
) -> dict[str, Any]:
    software, paths = paths_for_campaign(campaign, extracted)
    matching = [item for item in software if platform in item["platforms"]]
    matching_stix = {item["stix_id"] for item in matching}
    matching_paths = [
        path for path in paths if path["software_ref"] in matching_stix
    ]
    slug = platform.lower().replace(" ", "-")
    if not matching:
        return {
            "id": (
                f"campaign-has-no-{slug}-software-"
                f"{campaign['external_id'].lower()}"
            ),
            "case_type": "aggregate_campaign_no_platform_software",
            "relationship_type": "campaign_uses_software",
            "question": (
                f"Which {platform}-platform malware or tools does "
                f"{campaign_label(campaign)} use?"
            ),
            "expected_answer": (
                "No active direct uses relationship from "
                f"{campaign_label(campaign)} to active malware or tools whose "
                f"platforms include {platform} is recorded in the pinned "
                "Enterprise ATT&CK snapshot."
            ),
            "campaign": campaign,
            "platform_filter": platform,
            "expected_software": [],
            "provenance": campaign_provenance(
                campaign, [], [], source, platform_filter=platform
            ),
        }
    return {
        "id": (
            f"campaign-uses-{slug}-software-"
            f"{campaign['external_id'].lower()}"
        ),
        "case_type": "aggregate_campaign_platform_software",
        "relationship_type": "campaign_uses_software",
        "question": (
            f"Which {platform}-platform malware or tools does "
            f"{campaign_label(campaign)} use?"
        ),
        "expected_answer": (
            f"The software directly used by {campaign_label(campaign)} whose "
            f"platforms include {platform} is grouped by type as follows. "
            f"{typed_software_sections(matching)}"
        ),
        "campaign": campaign,
        "platform_filter": platform,
        "expected_software": matching,
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
    software = {
        item["external_id"]: item for item in extracted["active_software_catalog"]
    }
    pairs = [
        forward_pair(campaigns[item], extracted, source)
        for item in SELECTED_CAMPAIGN_IDS
    ]
    pairs.extend(
        focused_pair(
            campaigns[campaign_id], software[software_id], extracted, source
        )
        for campaign_id, software_id in FOCUSED_SOFTWARE_BY_CAMPAIGN.items()
    )
    pairs.extend(
        reverse_pair(software[software_id], extracted, source)
        for software_id in FOCUSED_SOFTWARE_BY_CAMPAIGN.values()
    )
    pairs.extend(
        platform_pair(campaigns[item], extracted, source)
        for item in SELECTED_CAMPAIGN_IDS
    )
    pairs.extend(
        negative_pair(
            campaigns[campaign_id], software[software_id], extracted, source
        )
        for campaign_id, software_id in NEGATIVE_SOFTWARE_BY_CAMPAIGN.items()
    )
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise CampaignSoftwareParserError("prototype pair IDs are not unique")
    return pairs


def evenly_spaced_items(items: list[Any], count: int) -> list[Any]:
    if count <= 0:
        return []
    if len(items) < count:
        raise CampaignSoftwareParserError(
            f"cannot select {count} items from {len(items)} candidates"
        )
    if count == 1:
        return [items[len(items) // 2]]
    indices = [
        round(index * (len(items) - 1) / (count - 1))
        for index in range(count)
    ]
    if len(indices) != len(set(indices)):
        raise CampaignSoftwareParserError(
            "evenly spaced campaign selection produced duplicates"
        )
    return [items[index] for index in indices]


def select_full_negative_cases(extracted: dict[str, Any]) -> dict[str, str]:
    campaigns = {item["external_id"]: item for item in extracted["campaigns"]}
    software = {
        item["external_id"]: item for item in extracted["active_software_catalog"]
    }
    paths = {
        (path["campaign_ref"], path["software_ref"])
        for path in extracted["paths"]
    }
    selected = dict(NEGATIVE_SOFTWARE_BY_CAMPAIGN)
    needed = FULL_NEGATIVE_EXISTENCE_CASE_COUNT - len(selected)
    candidates = [
        item
        for item in sorted(campaigns)
        if item not in selected
        and extracted["software_counts_by_campaign"][item]["total"] > 0
    ]
    for offset, campaign_id in enumerate(evenly_spaced_items(candidates, needed)):
        campaign = campaigns[campaign_id]
        probes = (
            FULL_NEGATIVE_PROBE_SOFTWARE_IDS[offset:]
            + FULL_NEGATIVE_PROBE_SOFTWARE_IDS[:offset]
        )
        for software_id in probes:
            candidate = software.get(software_id)
            if candidate is None:
                continue
            if (campaign["stix_id"], candidate["stix_id"]) not in paths:
                selected[campaign_id] = software_id
                break
        else:
            raise CampaignSoftwareParserError(
                f"no configured negative probe is absent for {campaign_id}"
            )
    if len(selected) != FULL_NEGATIVE_EXISTENCE_CASE_COUNT:
        raise CampaignSoftwareParserError(
            f"expected {FULL_NEGATIVE_EXISTENCE_CASE_COUNT} negatives, "
            f"selected {len(selected)}"
        )
    return selected


def activity_windows_overlap(
    campaign: dict[str, Any], sibling: dict[str, Any]
) -> bool:
    values = (
        campaign.get("first_seen"),
        campaign.get("last_seen"),
        sibling.get("first_seen"),
        sibling.get("last_seen"),
    )
    return all(values) and max(values[0], values[2]) <= min(
        values[1], values[3]
    )


def select_adversarial_negative_cases(
    extracted: dict[str, Any],
    existing_negative_cases: dict[str, str],
    *,
    count: int = ADVERSARIAL_NEGATIVE_CASE_COUNT,
) -> list[dict[str, Any]]:
    """Choose same-actor cases first, then overlapping activity windows."""

    campaigns = {
        item["stix_id"]: item for item in extracted["campaigns"]
    }
    groups = {
        item["stix_id"]: item for item in extracted["active_group_catalog"]
    }
    software = {
        item["stix_id"]: item
        for item in extracted["active_software_catalog"]
    }
    software_by_campaign: dict[str, set[str]] = {
        campaign_ref: set() for campaign_ref in campaigns
    }
    software_paths: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in extracted["paths"]:
        if path["campaign_ref"] not in campaigns:
            continue
        software_by_campaign[path["campaign_ref"]].add(path["software_ref"])
        software_paths.setdefault(
            (path["campaign_ref"], path["software_ref"]), []
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
    campaigns_by_external = {
        item["external_id"]: item for item in campaigns.values()
    }
    software_by_external = {
        item["external_id"]: item for item in software.values()
    }
    existing_keys = {
        (
            campaigns_by_external[campaign_id]["stix_id"],
            software_by_external[software_id]["stix_id"],
        )
        for campaign_id, software_id in existing_negative_cases.items()
    }
    same_actor_candidates: dict[tuple[str, str], dict[str, Any]] = {}
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
                for software_ref in sorted(
                    software_by_campaign[sibling_ref]
                    - software_by_campaign[campaign_ref],
                    key=lambda ref: software[ref]["external_id"],
                ):
                    key = (campaign_ref, software_ref)
                    if key in existing_keys:
                        continue
                    same_actor_candidates.setdefault(
                        key,
                        {
                            "campaign": campaigns[campaign_ref],
                            "software": software[software_ref],
                            "sibling_campaign": campaigns[sibling_ref],
                            "context_type": "shared_attributed_actor",
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
                            "sibling_software_paths": sorted(
                                software_paths[(sibling_ref, software_ref)],
                                key=lambda path: path[
                                    "uses_relationship_stix_id"
                                ],
                            ),
                        },
                    )
    ordered_same_actor = sorted(
        same_actor_candidates.values(),
        key=lambda row: (
            row["campaign"]["external_id"],
            row["software"]["external_id"],
            row["sibling_campaign"]["external_id"],
        ),
    )
    if len(ordered_same_actor) >= count:
        return evenly_spaced_items(ordered_same_actor, count)

    selected = list(ordered_same_actor)
    selected_keys = {
        (row["campaign"]["stix_id"], row["software"]["stix_id"])
        for row in selected
    }
    time_candidates: dict[tuple[str, str], dict[str, Any]] = {}
    ordered_campaigns = sorted(
        campaigns.values(), key=lambda item: item["external_id"]
    )
    for campaign in ordered_campaigns:
        for sibling in ordered_campaigns:
            if sibling["stix_id"] == campaign["stix_id"]:
                continue
            if not activity_windows_overlap(campaign, sibling):
                continue
            for software_ref in sorted(
                software_by_campaign[sibling["stix_id"]]
                - software_by_campaign[campaign["stix_id"]],
                key=lambda ref: software[ref]["external_id"],
            ):
                key = (campaign["stix_id"], software_ref)
                if (
                    key in existing_keys
                    or key in selected_keys
                    or key in time_candidates
                ):
                    continue
                time_candidates[key] = {
                    "campaign": campaign,
                    "software": software[software_ref],
                    "sibling_campaign": sibling,
                    "context_type": "overlapping_activity_window",
                    "activity_window_evidence": {
                        "campaign_first_seen": campaign["first_seen"],
                        "campaign_last_seen": campaign["last_seen"],
                        "sibling_first_seen": sibling["first_seen"],
                        "sibling_last_seen": sibling["last_seen"],
                    },
                    "sibling_software_paths": sorted(
                        software_paths[(sibling["stix_id"], software_ref)],
                        key=lambda path: path[
                            "uses_relationship_stix_id"
                        ],
                    ),
                }
    needed = count - len(selected)
    selected.extend(
        evenly_spaced_items(
            sorted(
                time_candidates.values(),
                key=lambda row: (
                    row["campaign"]["external_id"],
                    row["software"]["external_id"],
                    row["sibling_campaign"]["external_id"],
                ),
            ),
            needed,
        )
    )
    return selected


def adversarial_negative_pair(
    row: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    campaign = row["campaign"]
    software = row["software"]
    pair = negative_pair(campaign, software, extracted, source)
    if row["context_type"] == "shared_attributed_actor":
        context_phrase = (
            f"sibling {campaign_label(row['sibling_campaign'])}, which is "
            f"attributed to {row['shared_group']['external_id']} "
            f"({row['shared_group']['name']}) just like the queried campaign,"
        )
        context = {
            "method": "different_campaign_same_attributed_actor",
            "sibling_campaign": row["sibling_campaign"],
            "shared_group": row["shared_group"],
            "campaign_attribution_paths": row[
                "campaign_attribution_paths"
            ],
            "sibling_attribution_paths": row[
                "sibling_attribution_paths"
            ],
            "sibling_software_paths": row["sibling_software_paths"],
        }
    else:
        context_phrase = (
            f"sibling {campaign_label(row['sibling_campaign'])}, whose "
            "recorded activity window overlaps the queried campaign's window,"
        )
        context = {
            "method": "different_campaign_overlapping_activity_window",
            "sibling_campaign": row["sibling_campaign"],
            "activity_window_evidence": row["activity_window_evidence"],
            "sibling_software_paths": row["sibling_software_paths"],
        }
    pair.update(
        {
            "id": (
                "campaign-adversarial-not-uses-software-"
                f"{campaign['external_id'].lower()}-"
                f"{software['external_id'].lower()}"
            ),
            "case_type": "adversarial_negative_campaign_software",
            "relationship_exists": False,
            "expected_answer": (
                f"No active direct uses relationship exists from "
                f"{campaign_label(campaign)} to "
                f"{typed_software_label(software)} in the pinned Enterprise "
                "ATT&CK snapshot. The confusion is plausible because "
                f"{context_phrase} does use "
                f"{typed_software_label(software)}."
            ),
        }
    )
    pair["provenance"].update(
        {
            "difficulty": "adversarial_sibling",
            "adversarial_context": context,
        }
    )
    return pair


def generate_full_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    campaigns = {item["external_id"]: item for item in extracted["campaigns"]}
    software = {
        item["external_id"]: item for item in extracted["active_software_catalog"]
    }
    forward = [
        forward_pair(campaigns[item], extracted, source) for item in sorted(campaigns)
    ]
    reverse = [
        reverse_pair(software[item], extracted, source) for item in sorted(software)
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
            campaigns[campaign_id], software[software_id], extracted, source
        )
        for campaign_id, software_id in sorted(negative_cases.items())
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
        raise CampaignSoftwareParserError("full pair IDs are not unique")
    return pairs, negative_cases


def parsed_campaign_data(extracted: dict[str, Any]) -> dict[str, Any]:
    return {
        campaign["external_id"]: {
            "campaign": campaign,
            "software": paths_for_campaign(campaign, extracted)[0],
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
        "phase": "card6_part_b_campaign_software_uses_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "campaign",
            "target_types": ["malware", "tool"],
            "relationship_type": "uses",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "mobile_domain_software_excluded": True,
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
    focused_count = counts.get("focused_campaign_software", 0)
    negative_count = counts.get("negative_campaign_software", 0)
    adversarial_count = counts.get(
        "adversarial_negative_campaign_software", 0
    )
    total_negative_count = negative_count + adversarial_count
    adversarial_pairs = [
        pair
        for pair in pairs
        if pair["case_type"] == "adversarial_negative_campaign_software"
    ]
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_full_campaign_software_golden_set",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "campaign",
            "target_types": ["malware", "tool"],
            "relationship_type": "uses",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "mobile_domain_software_excluded": True,
            "revoked_and_deprecated_excluded": True,
            "one_forward_aggregate_per_active_campaign": True,
            "one_reverse_aggregate_per_active_software": True,
            "one_windows_constrained_pair_per_active_campaign": True,
            "adversarial_sibling_negatives": True,
        },
        "selection": {
            "active_campaign_count": len(extracted["campaigns"]),
            "active_software_count": len(extracted["active_software_catalog"]),
            "pair_count": len(pairs),
            "forward_aggregate_pairs": counts.get("aggregate_campaign_software", 0),
            "forward_zero_path_pairs": counts.get(
                "aggregate_campaign_no_qualifying_software", 0
            ),
            "reverse_aggregate_pairs": counts.get("aggregate_software_campaigns", 0),
            "reverse_zero_path_pairs": counts.get(
                "aggregate_software_no_campaigns", 0
            ),
            "reverse_malware_anchor_pairs": sum(
                pair["software"]["stix_type"] == "malware"
                for pair in pairs
                if pair["case_type"].startswith("aggregate_software_")
            ),
            "reverse_tool_anchor_pairs": sum(
                pair["software"]["stix_type"] == "tool"
                for pair in pairs
                if pair["case_type"].startswith("aggregate_software_")
            ),
            "focused_positive_pairs": focused_count,
            "platform_constrained_positive_pairs": counts.get(
                "aggregate_campaign_platform_software", 0
            ),
            "platform_constrained_zero_path_pairs": counts.get(
                "aggregate_campaign_no_platform_software", 0
            ),
            "negative_existence_pairs": negative_count,
            "negative_existence_distinct_campaign_count": len(negative_cases),
            "adversarial_negative_pairs": adversarial_count,
            "adversarial_same_actor_pairs": sum(
                pair["provenance"]["adversarial_context"]["method"]
                == "different_campaign_same_attributed_actor"
                for pair in adversarial_pairs
            ),
            "adversarial_overlapping_time_pairs": sum(
                pair["provenance"]["adversarial_context"]["method"]
                == "different_campaign_overlapping_activity_window"
                for pair in adversarial_pairs
            ),
            "total_negative_pairs": total_negative_count,
            "total_negative_ratio": total_negative_count / len(pairs),
            "explicit_point_negative_ratio": (
                negative_count / (focused_count + negative_count)
            ),
            "embedded_forward_fact_count": sum(
                len(pair.get("expected_software", []))
                for pair in pairs
                if pair["case_type"] in {
                    "aggregate_campaign_software",
                    "aggregate_campaign_no_qualifying_software",
                }
            ),
            "embedded_reverse_fact_count": sum(
                len(pair.get("expected_campaigns", []))
                for pair in pairs
                if pair["case_type"].startswith("aggregate_software_")
            ),
        },
        "negative_selection": {
            "method": (
                "preserve the five verified prototype negatives, then choose "
                "five evenly spaced positive campaigns and select a configured "
                "active malware/tool probe with no direct uses relationship"
            ),
            "all_cases_verified_absent_by_extracted_path_set": True,
            "adversarial_method": (
                "prefer a software object used by a different campaign "
                "attributed to the same actor; when that real topology is "
                "insufficient, use a different campaign with an overlapping "
                "recorded first_seen/last_seen activity window"
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
        default=HERE / "golden_set_campaign_software_prototype.json",
    )
    parser.add_argument(
        "--generate-all-campaigns",
        action="store_true",
        help="write the full all-active-campaign/software golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_campaign_software.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    if args.generate_all_campaigns:
        extracted = extract_campaign_software_scope(bundle, campaign_ids=None)
        payload = full_payload(extracted, source)
        output = args.full_output
    else:
        extracted = extract_campaign_software_scope(bundle)
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
    except CampaignSoftwareParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
