#!/usr/bin/env python3
"""Generate the Step-7a campaign-to-group attribution prototype."""

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
FOCUSED_GROUP_BY_CAMPAIGN = {
    "C0023": "G0016",  # Operation Ghost -> APT29
    "C0024": "G0016",  # SolarWinds Compromise -> APT29
    "C0034": "G0034",  # 2022 Ukraine Electric Power Attack -> Sandworm Team
    "C0038": "G1055",  # HomeLand Justice -> VOID MANTICORE
}
NEGATIVE_CAMPAIGN_ID = "C0024"
NEGATIVE_GROUP_ID = "G0007"  # SolarWinds Compromise -/-> APT28
FULL_NEGATIVE_EXISTENCE_CASE_COUNT = 10
FULL_NEGATIVE_PROBE_GROUP_IDS = (
    "G0016",  # APT29
    "G0034",  # Sandworm Team
    "G0096",  # APT41
    "G0049",  # OilRig
    "G0032",  # Lazarus Group
    "G0007",  # APT28
    "G1017",  # Volt Typhoon
    "G1055",  # VOID MANTICORE
    "G0065",  # Leviathan
    "G1048",  # UNC3886
)
SCOPE = "active_campaign_attributed_to_active_intrusion_set"
METHODOLOGY_NOTE = (
    "Only active STIX attributed-to relationships directed from an active "
    "campaign to an active intrusion-set are included. Negative cases assert "
    "only that no qualifying relationship exists in the pinned Enterprise "
    "ATT&CK snapshot; they do not make broader real-world attribution claims."
)


class CampaignGroupParserError(RuntimeError):
    """Raised when campaign/group attribution data is invalid."""


def require_unique_external_ids(
    objects: list[dict[str, Any]], description: str
) -> dict[str, dict[str, Any]]:
    rows = [(mitre_external_id(obj), obj) for obj in objects]
    missing = [obj["id"] for external_id, obj in rows if external_id is None]
    if missing:
        raise CampaignGroupParserError(
            f"active {description} objects lack MITRE external IDs: "
            + ", ".join(sorted(missing))
        )
    result = {external_id: obj for external_id, obj in rows if external_id}
    if len(result) != len(rows):
        raise CampaignGroupParserError(
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


def compact_group(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "aliases": list(obj.get("aliases", [])),
    }


def extract_campaign_group_scope(
    bundle: dict[str, Any],
    campaign_ids: tuple[str, ...] | None = SELECTED_CAMPAIGN_IDS,
) -> dict[str, Any]:
    if campaign_ids is not None and len(campaign_ids) != len(set(campaign_ids)):
        raise CampaignGroupParserError("selected campaign IDs are not unique")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise CampaignGroupParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]
    active_campaign_objects = [
        obj
        for obj in typed
        if obj.get("type") == "campaign" and is_active(obj)
    ]
    active_group_objects = [
        obj
        for obj in typed
        if obj.get("type") == "intrusion-set" and is_active(obj)
    ]
    campaign_catalog = require_unique_external_ids(
        active_campaign_objects, "campaign"
    )
    group_catalog = require_unique_external_ids(
        active_group_objects, "intrusion-set"
    )
    selected_campaign_ids = (
        tuple(sorted(campaign_catalog))
        if campaign_ids is None
        else campaign_ids
    )
    missing_campaigns = [
        campaign_id
        for campaign_id in selected_campaign_ids
        if campaign_id not in campaign_catalog
    ]
    if missing_campaigns:
        raise CampaignGroupParserError(
            "selected active campaigns are missing: "
            + ", ".join(missing_campaigns)
        )
    campaign_by_stix = {obj["id"]: obj for obj in active_campaign_objects}
    group_by_stix = {obj["id"]: obj for obj in active_group_objects}
    all_attributions = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "attributed-to"
    ]
    active_attributions = [
        rel
        for rel in all_attributions
        if is_active(rel)
        and rel.get("source_ref") in campaign_by_stix
        and rel.get("target_ref") in group_by_stix
    ]
    paths_by_campaign: dict[str, list[dict[str, Any]]] = {}
    for rel in active_attributions:
        paths_by_campaign.setdefault(rel["source_ref"], []).append(
            {
                "campaign_ref": rel["source_ref"],
                "group_ref": rel["target_ref"],
                "attributed_to_relationship_stix_id": rel["id"],
            }
        )
    for paths in paths_by_campaign.values():
        paths.sort(
            key=lambda path: (
                mitre_external_id(group_by_stix[path["group_ref"]]) or "",
                path["attributed_to_relationship_stix_id"],
            )
        )
    all_pair_keys = {
        (path["campaign_ref"], path["group_ref"])
        for paths in paths_by_campaign.values()
        for path in paths
    }
    if len(all_pair_keys) != len(active_attributions):
        raise CampaignGroupParserError(
            "multiple active relationships encode the same campaign/group pair"
        )

    selected_campaigns = [
        campaign_catalog[campaign_id] for campaign_id in selected_campaign_ids
    ]
    selected_stix_ids = {obj["id"] for obj in selected_campaigns}
    selected_paths = [
        path
        for campaign_ref, paths in paths_by_campaign.items()
        if campaign_ref in selected_stix_ids
        for path in paths
    ]
    referenced_group_ids = {path["group_ref"] for path in selected_paths}
    selected_groups = [
        compact_group(group_by_stix[group_id])
        for group_id in referenced_group_ids
    ]
    selected_groups.sort(
        key=lambda row: (row["external_id"] or "", row["stix_id"])
    )
    group_counts_by_campaign = {
        campaign_id: len(
            {
                path["group_ref"]
                for path in selected_paths
                if path["campaign_ref"] == campaign_catalog[campaign_id]["id"]
            }
        )
        for campaign_id in selected_campaign_ids
    }
    all_campaign_attribution_counts = {
        campaign["id"]: len(
            {path["group_ref"] for path in paths_by_campaign.get(campaign["id"], [])}
        )
        for campaign in active_campaign_objects
    }
    return {
        "campaigns": [compact_campaign(obj) for obj in selected_campaigns],
        "groups": selected_groups,
        "active_group_catalog": [
            compact_group(group_catalog[external_id])
            for external_id in sorted(group_catalog)
        ],
        "paths": selected_paths,
        "group_counts_by_campaign": group_counts_by_campaign,
        "global_coverage": {
            "active_campaign_count": len(active_campaign_objects),
            "active_group_count": len(active_group_objects),
            "active_attributed_to_relationship_count": len(active_attributions),
            "campaigns_with_zero_attributed_groups": sum(
                count == 0 for count in all_campaign_attribution_counts.values()
            ),
            "campaigns_with_one_attributed_group": sum(
                count == 1 for count in all_campaign_attribution_counts.values()
            ),
            "campaigns_with_multiple_attributed_groups": sum(
                count > 1 for count in all_campaign_attribution_counts.values()
            ),
        },
        "extraction_audit": {
            "bundle_attributed_to_relationship_count": len(all_attributions),
            "inactive_or_dangling_attributed_to_relationship_count": (
                len(all_attributions) - len(active_attributions)
            ),
            "selected_path_count": len(selected_paths),
        },
    }


def campaign_label(campaign: dict[str, Any]) -> str:
    return f"{campaign['external_id']} ({campaign['name']})"


def group_label(group: dict[str, Any]) -> str:
    return f"{group['external_id']} ({group['name']})"


def groups_and_paths_for(
    campaign: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    groups_by_stix = {group["stix_id"]: group for group in extracted["groups"]}
    paths = [
        path
        for path in extracted["paths"]
        if path["campaign_ref"] == campaign["stix_id"]
    ]
    group_ids = sorted(
        {path["group_ref"] for path in paths},
        key=lambda stix_id: (
            groups_by_stix[stix_id]["external_id"] or "",
            stix_id,
        ),
    )
    return [groups_by_stix[group_id] for group_id in group_ids], paths


def provenance(
    campaign: dict[str, Any],
    groups: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    queried_group: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "campaign_stix_id": campaign["stix_id"],
        "group_stix_ids": [group["stix_id"] for group in groups],
        "attributed_to_relationship_stix_ids": [
            path["attributed_to_relationship_stix_id"] for path in paths
        ],
        "relationship_paths": paths,
    }
    if queried_group is not None:
        result["queried_group_stix_id"] = queried_group["stix_id"]
    return result


def generate_prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    campaigns = {
        campaign["external_id"]: campaign for campaign in extracted["campaigns"]
    }
    active_groups = {
        group["external_id"]: group
        for group in extracted["active_group_catalog"]
    }
    pairs = []
    for campaign_id in SELECTED_CAMPAIGN_IDS:
        campaign = campaigns[campaign_id]
        groups, paths = groups_and_paths_for(campaign, extracted)
        if not groups:
            pairs.append(
                {
                    "id": f"campaign-has-no-attributed-group-{campaign_id.lower()}",
                    "case_type": "aggregate_campaign_no_attributed_group",
                    "relationship_type": "campaign_attributed_to_group",
                    "question": (
                        f"Which group is attributed to {campaign_label(campaign)}?"
                    ),
                    "expected_answer": (
                        "No active attributed-to relationship from "
                        f"{campaign_label(campaign)} to an active group is "
                        "recorded in the pinned Enterprise ATT&CK snapshot."
                    ),
                    "campaign": campaign,
                    "expected_groups": [],
                    "provenance": provenance(campaign, [], [], source),
                }
            )
            continue
        pairs.append(
            {
                "id": f"campaign-attributed-groups-{campaign_id.lower()}",
                "case_type": "aggregate_campaign_groups",
                "relationship_type": "campaign_attributed_to_group",
                "question": (
                    f"Which group is attributed to {campaign_label(campaign)}?"
                ),
                "expected_answer": (
                    f"{campaign_label(campaign)} is attributed to "
                    f"{natural_list([group_label(group) for group in groups])} "
                    "in the pinned Enterprise ATT&CK snapshot."
                ),
                "campaign": campaign,
                "expected_groups": groups,
                "provenance": provenance(campaign, groups, paths, source),
            }
        )

    for campaign_id, group_id in FOCUSED_GROUP_BY_CAMPAIGN.items():
        campaign = campaigns[campaign_id]
        group = active_groups[group_id]
        groups, paths = groups_and_paths_for(campaign, extracted)
        matching_paths = [
            path for path in paths if path["group_ref"] == group["stix_id"]
        ]
        if not matching_paths:
            raise CampaignGroupParserError(
                f"focused attribution {campaign_id} -> {group_id} does not exist"
            )
        pairs.append(
            {
                "id": (
                    f"campaign-attributed-group-{campaign_id.lower()}-"
                    f"{group_id.lower()}"
                ),
                "case_type": "focused_campaign_group",
                "relationship_type": "campaign_attributed_to_group",
                "question": (
                    f"Is {campaign_label(campaign)} attributed to "
                    f"{group_label(group)}?"
                ),
                "expected_answer": (
                    f"Yes. {campaign_label(campaign)} is attributed to "
                    f"{group_label(group)} in the pinned Enterprise ATT&CK "
                    "snapshot."
                ),
                "campaign": campaign,
                "queried_group": group,
                "expected_groups": [group],
                "provenance": provenance(
                    campaign,
                    [group],
                    matching_paths,
                    source,
                    queried_group=group,
                ),
            }
        )

    campaign = campaigns[NEGATIVE_CAMPAIGN_ID]
    group = active_groups[NEGATIVE_GROUP_ID]
    _, paths = groups_and_paths_for(campaign, extracted)
    matching_paths = [
        path for path in paths if path["group_ref"] == group["stix_id"]
    ]
    if matching_paths:
        raise CampaignGroupParserError(
            f"negative attribution {NEGATIVE_CAMPAIGN_ID} -> "
            f"{NEGATIVE_GROUP_ID} exists"
        )
    pairs.append(
        {
            "id": (
                f"campaign-not-attributed-group-{NEGATIVE_CAMPAIGN_ID.lower()}-"
                f"{NEGATIVE_GROUP_ID.lower()}"
            ),
            "case_type": "negative_campaign_group",
            "relationship_type": "campaign_attributed_to_group",
            "question": (
                f"Is {campaign_label(campaign)} attributed to "
                f"{group_label(group)}?"
            ),
            "expected_answer": (
                "No active attributed-to relationship exists from "
                f"{campaign_label(campaign)} to {group_label(group)} in the "
                "pinned Enterprise ATT&CK snapshot."
            ),
            "campaign": campaign,
            "queried_group": group,
            "expected_groups": [],
            "provenance": provenance(
                campaign, [], [], source, queried_group=group
            ),
        }
    )
    if len(pairs) != 10:
        raise CampaignGroupParserError(
            f"expected 10 prototype pairs, generated {len(pairs)}"
        )
    return pairs


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_step_7a_campaign_group_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "campaign",
            "target_type": "intrusion-set",
            "relationship_type": "attributed-to",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "campaign_external_ids": list(SELECTED_CAMPAIGN_IDS),
            "campaign_count": len(SELECTED_CAMPAIGN_IDS),
            "pair_count": len(pairs),
            "aggregate_pairs": sum(
                pair["case_type"].startswith("aggregate_campaign_")
                for pair in pairs
            ),
            "focused_positive_pairs": sum(
                pair["case_type"] == "focused_campaign_group"
                for pair in pairs
            ),
            "negative_existence_pairs": sum(
                pair["case_type"] == "negative_campaign_group"
                for pair in pairs
            ),
        },
        "parsed_data": {
            campaign["external_id"]: {
                "campaign": campaign,
                "attributed_groups": groups_and_paths_for(campaign, extracted)[0],
                "relationship_paths": groups_and_paths_for(campaign, extracted)[1],
            }
            for campaign in extracted["campaigns"]
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "pairs": pairs,
    }


def evenly_spaced_items(
    items: list[dict[str, Any]], count: int
) -> list[dict[str, Any]]:
    if count < 0 or count > len(items):
        raise CampaignGroupParserError(
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
        raise CampaignGroupParserError(
            "stratified campaign selection produced duplicates"
        )
    return [items[index] for index in indices]


def generate_full_aggregate_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    pairs = []
    for campaign in extracted["campaigns"]:
        groups, paths = groups_and_paths_for(campaign, extracted)
        if groups:
            pairs.append(
                {
                    "id": (
                        "campaign-attributed-groups-"
                        f"{campaign['external_id'].lower()}"
                    ),
                    "case_type": "aggregate_campaign_groups",
                    "relationship_type": "campaign_attributed_to_group",
                    "question": (
                        f"Which group is attributed to {campaign_label(campaign)}?"
                    ),
                    "expected_answer": (
                        f"{campaign_label(campaign)} is attributed to "
                        f"{natural_list([group_label(group) for group in groups])} "
                        "in the pinned Enterprise ATT&CK snapshot."
                    ),
                    "campaign": campaign,
                    "expected_groups": groups,
                    "provenance": provenance(
                        campaign, groups, paths, source
                    ),
                }
            )
            continue
        pairs.append(
            {
                "id": (
                    "campaign-has-no-attributed-group-"
                    f"{campaign['external_id'].lower()}"
                ),
                "case_type": "aggregate_campaign_no_attributed_group",
                "relationship_type": "campaign_attributed_to_group",
                "question": (
                    f"Which group is attributed to {campaign_label(campaign)}?"
                ),
                "expected_answer": (
                    "No active attributed-to relationship from "
                    f"{campaign_label(campaign)} to an active group is "
                    "recorded in the pinned Enterprise ATT&CK snapshot."
                ),
                "campaign": campaign,
                "expected_groups": [],
                "provenance": provenance(campaign, [], [], source),
            }
        )
    return pairs


def select_full_negative_cases(
    extracted: dict[str, Any],
    *,
    count: int = FULL_NEGATIVE_EXISTENCE_CASE_COUNT,
) -> dict[str, str]:
    campaigns = {
        campaign["external_id"]: campaign for campaign in extracted["campaigns"]
    }
    groups = {
        group["external_id"]: group
        for group in extracted["active_group_catalog"]
    }
    missing_probes = [
        group_id
        for group_id in FULL_NEGATIVE_PROBE_GROUP_IDS
        if group_id not in groups
    ]
    if missing_probes:
        raise CampaignGroupParserError(
            "negative probe groups are not active: " + ", ".join(missing_probes)
        )
    path_keys = {
        (path["campaign_ref"], path["group_ref"])
        for path in extracted["paths"]
    }
    preserved_campaign = campaigns[NEGATIVE_CAMPAIGN_ID]
    preserved_group = groups[NEGATIVE_GROUP_ID]
    if (preserved_campaign["stix_id"], preserved_group["stix_id"]) in path_keys:
        raise CampaignGroupParserError(
            "preserved prototype negative now has an attribution"
        )
    selected = {NEGATIVE_CAMPAIGN_ID: NEGATIVE_GROUP_ID}
    eligible = [
        campaign
        for campaign in extracted["campaigns"]
        if campaign["external_id"] != NEGATIVE_CAMPAIGN_ID
        and extracted["group_counts_by_campaign"][campaign["external_id"]] > 0
    ]
    additional = evenly_spaced_items(eligible, count - len(selected))
    for index, campaign in enumerate(additional):
        offset = index % len(FULL_NEGATIVE_PROBE_GROUP_IDS)
        probes = (
            FULL_NEGATIVE_PROBE_GROUP_IDS[offset:]
            + FULL_NEGATIVE_PROBE_GROUP_IDS[:offset]
        )
        for group_id in probes:
            group = groups[group_id]
            if (campaign["stix_id"], group["stix_id"]) not in path_keys:
                selected[campaign["external_id"]] = group_id
                break
        else:
            raise CampaignGroupParserError(
                f"no configured negative probe is absent for "
                f"{campaign['external_id']}"
            )
    if len(selected) != count:
        raise CampaignGroupParserError(
            f"expected {count} negative cases, selected {len(selected)}"
        )
    return selected


def generate_full_negative_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    negative_cases: dict[str, str],
) -> list[dict[str, Any]]:
    campaigns = {
        campaign["external_id"]: campaign for campaign in extracted["campaigns"]
    }
    groups = {
        group["external_id"]: group
        for group in extracted["active_group_catalog"]
    }
    path_keys = {
        (path["campaign_ref"], path["group_ref"])
        for path in extracted["paths"]
    }
    pairs = []
    for campaign_id in sorted(negative_cases):
        group_id = negative_cases[campaign_id]
        campaign = campaigns[campaign_id]
        group = groups[group_id]
        if (campaign["stix_id"], group["stix_id"]) in path_keys:
            raise CampaignGroupParserError(
                f"negative attribution {campaign_id} -> {group_id} exists"
            )
        pairs.append(
            {
                "id": (
                    f"campaign-not-attributed-group-{campaign_id.lower()}-"
                    f"{group_id.lower()}"
                ),
                "case_type": "negative_campaign_group",
                "relationship_type": "campaign_attributed_to_group",
                "question": (
                    f"Is {campaign_label(campaign)} attributed to "
                    f"{group_label(group)}?"
                ),
                "expected_answer": (
                    "No active attributed-to relationship exists from "
                    f"{campaign_label(campaign)} to {group_label(group)} in the "
                    "pinned Enterprise ATT&CK snapshot."
                ),
                "campaign": campaign,
                "queried_group": group,
                "expected_groups": [],
                "provenance": provenance(
                    campaign, [], [], source, queried_group=group
                ),
            }
        )
    return pairs


def full_campaign_payload(
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
        if pair["case_type"] == "aggregate_campaign_groups"
    ]
    zero_path_aggregates = [
        pair
        for pair in aggregate_pairs
        if pair["case_type"] == "aggregate_campaign_no_attributed_group"
    ]
    pairs = aggregate_pairs + negative_pairs
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_step_7c_full_campaign_group_golden_set",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "campaign",
            "target_type": "intrusion-set",
            "relationship_type": "attributed-to",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "one_aggregate_pair_per_active_campaign": True,
        },
        "selection": {
            "active_campaign_count": len(extracted["campaigns"]),
            "pair_count": len(pairs),
            "positive_aggregate_pairs": len(positive_aggregates),
            "zero_path_aggregate_pairs": len(zero_path_aggregates),
            "negative_existence_pairs": len(negative_pairs),
            "negative_existence_distinct_campaign_count": len(
                {pair["campaign"]["external_id"] for pair in negative_pairs}
            ),
            "multi_group_aggregate_pairs": sum(
                len(pair["expected_groups"]) > 1
                for pair in positive_aggregates
            ),
            "embedded_campaign_group_fact_count": sum(
                len(pair["expected_groups"]) for pair in positive_aggregates
            ),
            "prototype_negative_preserved": (
                negative_cases.get(NEGATIVE_CAMPAIGN_ID) == NEGATIVE_GROUP_ID
            ),
        },
        "negative_selection": {
            "method": (
                "preserve the verified prototype negative, then choose nine "
                "evenly spaced positive-attribution campaigns and select an "
                "active probe group having no attributed-to relationship"
            ),
            "all_cases_verified_absent_by_extracted_path_set": True,
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "parsed_data": {
            campaign["external_id"]: {
                "campaign": campaign,
                "attributed_groups": groups_and_paths_for(campaign, extracted)[0],
                "relationship_paths": groups_and_paths_for(campaign, extracted)[1],
            }
            for campaign in extracted["campaigns"]
        },
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "golden_set_campaign_group_prototype.json",
    )
    parser.add_argument(
        "--generate-all-campaigns",
        action="store_true",
        help="write the full all-active-campaign golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_campaign_group.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    if args.generate_all_campaigns:
        extracted = extract_campaign_group_scope(bundle, campaign_ids=None)
        payload = full_campaign_payload(extracted, source)
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
                    "global_coverage": payload["global_coverage"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    extracted = extract_campaign_group_scope(bundle)
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
                "parsed_data": payload["parsed_data"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CampaignGroupParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
