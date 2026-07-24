#!/usr/bin/env python3
"""Generate deterministic Campaign -> Software -> Technique chain golden sets."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import generate_campaign_software_prototype as campaign_software
import generate_software_technique_prototype as software_technique
from generate_golden_set import (
    DEFAULT_MANIFEST,
    is_active,
    load_pinned_bundle,
    natural_list,
)


HERE = Path(__file__).resolve().parent
SELECTED_CHAIN_PAIRS = (
    ("C0001", "S0363"),  # Frankenstein -> Empire (Tool)
    ("C0024", "S0560"),  # SolarWinds Compromise -> TEARDROP
    ("C0034", "S0693"),  # 2022 Ukraine Electric Power Attack -> CaddyWiper
    ("C0038", "S0357"),  # HomeLand Justice -> Impacket (Tool)
    ("C0047", "S0013"),  # RedDelta Modified PlugX... -> PlugX
)
PROTOTYPE_REVERSE_TECHNIQUE_IDS = (
    "T1012",
    "T1059.001",
    "T1486",
    "T1543.003",
    "T1011",  # Genuine zero-path reverse case.
)
PROTOTYPE_POSITIVE_TECHNIQUE_BY_CAMPAIGN = {
    "C0001": "T1003.001",
    "C0024": "T1012",
    "C0034": "T1485",
    "C0038": "T1558.005",
    "C0047": "T1012",
}
PROTOTYPE_NEGATIVE_TECHNIQUE_BY_CAMPAIGN = {
    "C0001": "T1485",
    "C0024": "T1486",
    "C0034": "T1059.001",
    "C0038": "T1190",
    "C0047": "T1003.001",
}
FULL_BOOLEAN_NEGATIVE_COUNT = 25
FULL_NAMED_NEGATIVE_COUNT = 25
FULL_DIVERGENCE_COUNT = 25
FULL_NEGATIVE_PROBE_TECHNIQUE_IDS = (
    "T1486",
    "T1059.001",
    "T1485",
    "T1003.001",
    "T1190",
    "T1543.003",
    "T1012",
    "T1112",
    "T1497.001",
    "T1078",
)
SCOPE = "active_campaign_uses_software_uses_technique_two_hop_chain"
METHODOLOGY_NOTE = (
    "A qualifying chain requires an active direct Campaign --uses--> "
    "Malware/Tool relationship and an independently active direct "
    "Malware/Tool --uses--> Technique relationship joined through the same "
    "software STIX object. Campaign-direct Technique edges do not create, "
    "filter, suppress, or deduplicate chain facts; they are consulted only by "
    "the explicit divergence case type. Malware and Tool are unified as "
    "software while retaining their exact STIX types. Parent and sub-technique "
    "objects remain distinct."
)


class CampaignSoftwareTechniqueChainError(RuntimeError):
    """Raised when the two-hop chain data is incomplete or inconsistent."""


def label(item: dict[str, Any]) -> str:
    return f"{item['external_id']} ({item['name']})"


def typed_software_label(item: dict[str, Any]) -> str:
    kind = {"malware": "Malware", "tool": "Tool"}.get(item["stix_type"])
    if kind is None:
        raise CampaignSoftwareTechniqueChainError(
            f"unsupported software type {item['stix_type']}"
        )
    return f"{kind} {label(item)}"


def evenly_spaced(items: list[Any], count: int) -> list[Any]:
    if count < 0 or count > len(items):
        raise CampaignSoftwareTechniqueChainError(
            f"cannot choose {count} distinct items from {len(items)}"
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
        raise CampaignSoftwareTechniqueChainError(
            "evenly spaced selection produced duplicates"
        )
    return [items[index] for index in indices]


def extract_chain_scope(bundle: dict[str, Any]) -> dict[str, Any]:
    """Join the two existing direct-edge extractors through software."""

    first = campaign_software.extract_campaign_software_scope(
        bundle, campaign_ids=None
    )
    second = software_technique.extract_software_technique_scope(
        bundle, software_ids=None
    )
    campaigns = first["active_campaign_catalog"]
    software = first["active_software_catalog"]
    techniques = second["active_technique_catalog"]
    campaign_by_stix = {item["stix_id"]: item for item in campaigns}
    software_by_stix = {item["stix_id"]: item for item in software}
    technique_by_stix = {item["stix_id"]: item for item in techniques}

    second_software = {
        item["stix_id"]: item for item in second["software"]
    }
    if set(software_by_stix) != set(second_software):
        raise CampaignSoftwareTechniqueChainError(
            "the two source extractors disagree on the active software catalog"
        )
    for stix_id, item in software_by_stix.items():
        other = second_software[stix_id]
        for field in ("external_id", "name", "stix_type"):
            if item[field] != other[field]:
                raise CampaignSoftwareTechniqueChainError(
                    f"software catalog mismatch for {stix_id}: {field}"
                )

    second_paths_by_software: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in second["paths"]:
        second_paths_by_software[path["software_ref"]].append(path)
    chain_paths = []
    for first_path in first["paths"]:
        for second_path in second_paths_by_software[
            first_path["software_ref"]
        ]:
            chain_paths.append(
                {
                    "campaign_ref": first_path["campaign_ref"],
                    "software_ref": first_path["software_ref"],
                    "technique_ref": second_path["technique_ref"],
                    "campaign_uses_software_relationship_stix_id": first_path[
                        "uses_relationship_stix_id"
                    ],
                    "software_uses_technique_relationship_stix_id": second_path[
                        "uses_relationship_stix_id"
                    ],
                }
            )
    chain_paths.sort(
        key=lambda path: (
            campaign_by_stix[path["campaign_ref"]]["external_id"],
            software_by_stix[path["software_ref"]]["external_id"],
            technique_by_stix[path["technique_ref"]]["external_id"],
            path["campaign_uses_software_relationship_stix_id"],
            path["software_uses_technique_relationship_stix_id"],
        )
    )
    chain_keys = {
        (path["campaign_ref"], path["software_ref"], path["technique_ref"])
        for path in chain_paths
    }
    if len(chain_keys) != len(chain_paths):
        raise CampaignSoftwareTechniqueChainError(
            "multiple active relationship pairs encode the same chain triple"
        )

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise CampaignSoftwareTechniqueChainError(
            "STIX bundle has no objects list"
        )
    typed = [item for item in objects if isinstance(item, dict)]
    all_uses = [
        item
        for item in typed
        if item.get("type") == "relationship"
        and item.get("relationship_type") == "uses"
    ]
    direct_campaign_technique = [
        item
        for item in all_uses
        if is_active(item)
        and item.get("source_ref") in campaign_by_stix
        and item.get("target_ref") in technique_by_stix
    ]
    campaign_direct_technique_paths = [
        {
            "campaign_ref": rel["source_ref"],
            "technique_ref": rel["target_ref"],
            "campaign_uses_technique_relationship_stix_id": rel["id"],
        }
        for rel in direct_campaign_technique
    ]
    campaign_direct_technique_paths.sort(
        key=lambda path: (
            campaign_by_stix[path["campaign_ref"]]["external_id"],
            technique_by_stix[path["technique_ref"]]["external_id"],
            path["campaign_uses_technique_relationship_stix_id"],
        )
    )
    direct_keys = {
        (path["campaign_ref"], path["technique_ref"])
        for path in campaign_direct_technique_paths
    }
    if len(direct_keys) != len(campaign_direct_technique_paths):
        raise CampaignSoftwareTechniqueChainError(
            "multiple active relationships encode one campaign/technique pair"
        )

    campaigns_with_chains = {
        path["campaign_ref"] for path in chain_paths
    }
    software_with_chains = {
        path["software_ref"] for path in chain_paths
    }
    techniques_with_chains = {
        path["technique_ref"] for path in chain_paths
    }
    campaign_technique_pairs = {
        (path["campaign_ref"], path["technique_ref"])
        for path in chain_paths
    }
    campaign_software_pairs = {
        (path["campaign_ref"], path["software_ref"])
        for path in chain_paths
    }
    divergence_pairs = 0
    for campaign_ref, software_ref in campaign_software_pairs:
        software_targets = {
            path["technique_ref"]
            for path in chain_paths
            if path["campaign_ref"] == campaign_ref
            and path["software_ref"] == software_ref
        }
        campaign_targets = {
            path["technique_ref"]
            for path in campaign_direct_technique_paths
            if path["campaign_ref"] == campaign_ref
        }
        divergence_pairs += bool(software_targets - campaign_targets)

    return {
        "campaigns": campaigns,
        "software": software,
        "techniques": techniques,
        "campaign_software_paths": first["paths"],
        "software_technique_paths": second["paths"],
        "campaign_direct_technique_paths": campaign_direct_technique_paths,
        "chain_paths": chain_paths,
        "global_coverage": {
            "active_campaign_count": len(campaigns),
            "active_software_count": len(software),
            "active_malware_count": sum(
                item["stix_type"] == "malware" for item in software
            ),
            "active_tool_count": sum(
                item["stix_type"] == "tool" for item in software
            ),
            "active_technique_count": len(techniques),
            "campaign_software_edge_count": len(first["paths"]),
            "software_technique_edge_count": len(second["paths"]),
            "campaign_direct_technique_edge_count": len(
                campaign_direct_technique_paths
            ),
            "chain_triple_count": len(chain_paths),
            "qualifying_campaign_software_pair_count": len(
                campaign_software_pairs
            ),
            "campaigns_with_one_or_more_chains": len(campaigns_with_chains),
            "campaigns_with_zero_chains": (
                len(campaigns) - len(campaigns_with_chains)
            ),
            "software_with_one_or_more_campaign_chains": len(
                software_with_chains
            ),
            "techniques_with_one_or_more_campaign_chains": len(
                techniques_with_chains
            ),
            "techniques_with_zero_campaign_chains": (
                len(techniques) - len(techniques_with_chains)
            ),
            "distinct_campaign_technique_chain_fact_count": len(
                campaign_technique_pairs
            ),
            "campaign_software_pairs_with_nonempty_divergence": (
                divergence_pairs
            ),
            "campaign_software_pairs_with_zero_divergence": (
                len(campaign_software_pairs) - divergence_pairs
            ),
        },
        "extraction_audit": {
            "campaign_software_extractor": first["extraction_audit"],
            "software_technique_extractor": second["extraction_audit"],
            "bundle_uses_relationship_count": len(all_uses),
            "joined_chain_path_count": len(chain_paths),
            "every_chain_path_has_both_relationship_ids": all(
                path["campaign_uses_software_relationship_stix_id"]
                and path["software_uses_technique_relationship_stix_id"]
                for path in chain_paths
            ),
        },
    }


def catalogs(
    extracted: dict[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    return (
        {item["external_id"]: item for item in extracted["campaigns"]},
        {item["external_id"]: item for item in extracted["software"]},
        {item["external_id"]: item for item in extracted["techniques"]},
    )


def chain_paths_for_pair(
    campaign: dict[str, Any],
    software: dict[str, Any],
    extracted: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        path
        for path in extracted["chain_paths"]
        if path["campaign_ref"] == campaign["stix_id"]
        and path["software_ref"] == software["stix_id"]
    ]


def first_hop_paths_for_campaign(
    campaign: dict[str, Any], extracted: dict[str, Any]
) -> list[dict[str, Any]]:
    return [
        path
        for path in extracted["campaign_software_paths"]
        if path["campaign_ref"] == campaign["stix_id"]
    ]


def entities_for_paths(
    paths: list[dict[str, Any]],
    extracted: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    campaign_by_stix = {
        item["stix_id"]: item for item in extracted["campaigns"]
    }
    software_by_stix = {
        item["stix_id"]: item for item in extracted["software"]
    }
    technique_by_stix = {
        item["stix_id"]: item for item in extracted["techniques"]
    }
    campaigns = [
        campaign_by_stix[stix_id]
        for stix_id in sorted(
            {path["campaign_ref"] for path in paths},
            key=lambda value: campaign_by_stix[value]["external_id"],
        )
    ]
    software = [
        software_by_stix[stix_id]
        for stix_id in sorted(
            {path["software_ref"] for path in paths},
            key=lambda value: software_by_stix[value]["external_id"],
        )
    ]
    techniques = [
        technique_by_stix[stix_id]
        for stix_id in sorted(
            {path["technique_ref"] for path in paths},
            key=lambda value: technique_by_stix[value]["external_id"],
        )
    ]
    return campaigns, software, techniques


def chain_provenance(
    source: dict[str, Any],
    campaigns: list[dict[str, Any]],
    software: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
    chain_paths: list[dict[str, Any]],
    *,
    first_hop_paths: list[dict[str, Any]] | None = None,
    queried_technique: dict[str, Any] | None = None,
) -> dict[str, Any]:
    first_hop_paths = first_hop_paths or []
    campaign_software_relationship_ids = {
        path["campaign_uses_software_relationship_stix_id"]
        for path in chain_paths
    }
    campaign_software_relationship_ids.update(
        path["uses_relationship_stix_id"] for path in first_hop_paths
    )
    result = {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "campaign_stix_ids": [item["stix_id"] for item in campaigns],
        "software_stix_ids": [item["stix_id"] for item in software],
        "software_stix_types": [item["stix_type"] for item in software],
        "technique_stix_ids": [item["stix_id"] for item in techniques],
        "campaign_uses_software_relationship_stix_ids": sorted(
            campaign_software_relationship_ids
        ),
        "software_uses_technique_relationship_stix_ids": sorted(
            {
                path["software_uses_technique_relationship_stix_id"]
                for path in chain_paths
            }
        ),
        "first_hop_paths": first_hop_paths,
        "chain_paths": chain_paths,
    }
    if queried_technique is not None:
        result["queried_technique_stix_id"] = queried_technique["stix_id"]
    return result


def named_chain_pair(
    campaign: dict[str, Any],
    software: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    paths = chain_paths_for_pair(campaign, software, extracted)
    if not paths:
        raise CampaignSoftwareTechniqueChainError(
            f"{campaign['external_id']} -> {software['external_id']} has no chain"
        )
    _, _, techniques = entities_for_paths(paths, extracted)
    return {
        "id": (
            f"campaign-software-techniques-{campaign['external_id'].lower()}-"
            f"{software['external_id'].lower()}"
        ),
        "case_type": "named_campaign_software_technique_chain",
        "relationship_type": "campaign_software_technique_chain",
        "question": (
            f"What techniques does {typed_software_label(software)}, used by "
            f"{label(campaign)}, employ?"
        ),
        "expected_answer": (
            f"{typed_software_label(software)}, which is directly used by "
            f"{label(campaign)}, directly uses "
            f"{natural_list([label(item) for item in techniques])} in the "
            "pinned Enterprise ATT&CK snapshot."
        ),
        "campaign": campaign,
        "software": software,
        "expected_techniques": techniques,
        "provenance": chain_provenance(
            source, [campaign], [software], techniques, paths
        ),
    }


def reverse_chain_pair(
    technique: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    paths = [
        path
        for path in extracted["chain_paths"]
        if path["technique_ref"] == technique["stix_id"]
    ]
    campaigns, software, _ = entities_for_paths(paths, extracted)
    if paths:
        case_type = "aggregate_technique_campaigns_via_software"
        answer = (
            f"{label(technique)} is used through associated malware or tools by "
            f"{natural_list([label(item) for item in campaigns])} in the pinned "
            "Enterprise ATT&CK snapshot. The qualifying intermediate software "
            f"is {natural_list([typed_software_label(item) for item in software])}."
        )
    else:
        case_type = "aggregate_technique_no_campaigns_via_software"
        answer = (
            "No active Campaign -> Malware/Tool -> Technique chain targets "
            f"{label(technique)} in the pinned Enterprise ATT&CK snapshot."
        )
    return {
        "id": f"technique-campaigns-via-software-{technique['external_id'].lower()}",
        "case_type": case_type,
        "relationship_type": "campaign_software_technique_chain",
        "question": (
            "Which campaigns have malware or tools that use "
            f"{label(technique)}?"
        ),
        "expected_answer": answer,
        "technique": technique,
        "expected_campaigns": campaigns,
        "expected_intermediate_software": software,
        "provenance": chain_provenance(
            source, campaigns, software, [technique] if paths else [], paths,
            queried_technique=technique,
        ),
    }


def boolean_chain_pair(
    campaign: dict[str, Any],
    technique: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
    *,
    expected: bool,
) -> dict[str, Any]:
    paths = [
        path
        for path in extracted["chain_paths"]
        if path["campaign_ref"] == campaign["stix_id"]
        and path["technique_ref"] == technique["stix_id"]
    ]
    if bool(paths) != expected:
        raise CampaignSoftwareTechniqueChainError(
            f"boolean expectation is wrong for {campaign['external_id']} / "
            f"{technique['external_id']}"
        )
    first_hop = first_hop_paths_for_campaign(campaign, extracted)
    software_by_stix = {
        item["stix_id"]: item for item in extracted["software"]
    }
    if expected:
        _, software, _ = entities_for_paths(paths, extracted)
        answer = (
            f"Yes. {label(technique)} is used by "
            f"{natural_list([typed_software_label(item) for item in software])}, "
            f"which {'is' if len(software) == 1 else 'are'} directly used by "
            f"{label(campaign)} in the pinned Enterprise ATT&CK snapshot."
        )
        case_type = "positive_campaign_software_technique_chain"
    else:
        software = [
            software_by_stix[stix_id]
            for stix_id in sorted(
                {path["software_ref"] for path in first_hop},
                key=lambda value: software_by_stix[value]["external_id"],
            )
        ]
        answer = (
            f"No. None of the active malware or tools directly used by "
            f"{label(campaign)} has an active direct uses relationship to "
            f"{label(technique)} in the pinned Enterprise ATT&CK snapshot."
        )
        case_type = "negative_campaign_software_technique_chain"
    return {
        "id": (
            f"campaign-chain-{'has' if expected else 'lacks'}-technique-"
            f"{campaign['external_id'].lower()}-{technique['external_id'].lower()}"
        ),
        "case_type": case_type,
        "relationship_type": "campaign_software_technique_chain",
        "question": (
            f"Is {label(technique)} used by any malware or tool associated with "
            f"{label(campaign)}?"
        ),
        "expected_answer": answer,
        "campaign": campaign,
        "queried_technique": technique,
        "relationship_exists": expected,
        "expected_intermediate_software": (
            software if expected else []
        ),
        "provenance": chain_provenance(
            source,
            [campaign],
            software,
            [technique] if expected else [],
            paths,
            first_hop_paths=[] if expected else first_hop,
            queried_technique=technique,
        ),
    }


def named_negative_pair(
    campaign: dict[str, Any],
    software: dict[str, Any],
    technique: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    pair_paths = chain_paths_for_pair(campaign, software, extracted)
    if not pair_paths:
        raise CampaignSoftwareTechniqueChainError(
            "named negative requires a real campaign/software chain anchor"
        )
    if any(path["technique_ref"] == technique["stix_id"] for path in pair_paths):
        raise CampaignSoftwareTechniqueChainError(
            f"named negative is a real chain: {campaign['external_id']} / "
            f"{software['external_id']} / {technique['external_id']}"
        )
    first_hop = [
        path
        for path in extracted["campaign_software_paths"]
        if path["campaign_ref"] == campaign["stix_id"]
        and path["software_ref"] == software["stix_id"]
    ]
    if len(first_hop) != 1:
        raise CampaignSoftwareTechniqueChainError(
            "named negative does not have exactly one active first-hop edge"
        )
    return {
        "id": (
            f"campaign-software-does-not-use-technique-"
            f"{campaign['external_id'].lower()}-{software['external_id'].lower()}-"
            f"{technique['external_id'].lower()}"
        ),
        "case_type": "negative_named_campaign_software_technique_chain",
        "relationship_type": "campaign_software_technique_chain",
        "question": (
            f"Does {typed_software_label(software)}, used by {label(campaign)}, "
            f"employ {label(technique)}?"
        ),
        "expected_answer": (
            f"No. {label(campaign)} directly uses "
            f"{typed_software_label(software)}, but that software has no active "
            f"direct uses relationship to {label(technique)} in the pinned "
            "Enterprise ATT&CK snapshot."
        ),
        "campaign": campaign,
        "software": software,
        "queried_technique": technique,
        "relationship_exists": False,
        "expected_techniques": [],
        "provenance": chain_provenance(
            source,
            [campaign],
            [software],
            [],
            [],
            first_hop_paths=first_hop,
            queried_technique=technique,
        ),
    }


def divergence_sets(
    campaign: dict[str, Any],
    software: dict[str, Any],
    extracted: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    chain_paths = chain_paths_for_pair(campaign, software, extracted)
    if not chain_paths:
        raise CampaignSoftwareTechniqueChainError(
            "divergence requires a qualifying campaign/software pair"
        )
    _, _, software_techniques = entities_for_paths(chain_paths, extracted)
    direct_paths = [
        path
        for path in extracted["campaign_direct_technique_paths"]
        if path["campaign_ref"] == campaign["stix_id"]
    ]
    technique_by_stix = {
        item["stix_id"]: item for item in extracted["techniques"]
    }
    direct_ids = {path["technique_ref"] for path in direct_paths}
    software_ids = {item["stix_id"] for item in software_techniques}

    def rows(stix_ids: set[str]) -> list[dict[str, Any]]:
        return sorted(
            (technique_by_stix[item] for item in stix_ids),
            key=lambda item: item["external_id"],
        )

    return (
        software_techniques,
        rows(direct_ids),
        rows(software_ids - direct_ids),
        rows(software_ids & direct_ids),
        rows(direct_ids - software_ids),
    )


def divergence_pair(
    campaign: dict[str, Any],
    software: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    (
        software_techniques,
        campaign_techniques,
        software_only,
        shared,
        campaign_only,
    ) = divergence_sets(campaign, software, extracted)
    if not software_only:
        raise CampaignSoftwareTechniqueChainError(
            f"{campaign['external_id']} / {software['external_id']} has no "
            "software-only divergence"
        )
    chain_paths = chain_paths_for_pair(campaign, software, extracted)
    direct_paths = [
        path
        for path in extracted["campaign_direct_technique_paths"]
        if path["campaign_ref"] == campaign["stix_id"]
    ]
    provenance = chain_provenance(
        source,
        [campaign],
        [software],
        software_techniques,
        chain_paths,
    )
    provenance.update(
        {
            "comparison_source": "active direct campaign --uses--> technique",
            "set_operation": (
                "software_direct_techniques minus campaign_direct_techniques"
            ),
            "campaign_direct_technique_stix_ids": [
                item["stix_id"] for item in campaign_techniques
            ],
            "campaign_uses_technique_relationship_stix_ids": [
                path["campaign_uses_technique_relationship_stix_id"]
                for path in direct_paths
            ],
            "campaign_direct_technique_paths": direct_paths,
        }
    )
    return {
        "id": (
            f"campaign-software-technique-divergence-"
            f"{campaign['external_id'].lower()}-{software['external_id'].lower()}"
        ),
        "case_type": "campaign_software_technique_divergence",
        "relationship_type": "campaign_software_technique_chain",
        "question": (
            f"Which techniques used by {typed_software_label(software)}, "
            f"associated with {label(campaign)}, are absent from the campaign's "
            "own direct technique relationships?"
        ),
        "expected_answer": (
            f"{typed_software_label(software)} has "
            f"{len(software_only)} software-only technique"
            f"{'' if len(software_only) == 1 else 's'} relative to "
            f"{label(campaign)}: "
            f"{natural_list([label(item) for item in software_only])}. "
            f"The two sets share {len(shared)} technique"
            f"{'' if len(shared) == 1 else 's'}; the campaign has "
            f"{len(campaign_only)} direct technique"
            f"{'' if len(campaign_only) == 1 else 's'} not used by this "
            "specific software."
        ),
        "campaign": campaign,
        "software": software,
        "expected_software_techniques": software_techniques,
        "expected_campaign_direct_techniques": campaign_techniques,
        "expected_software_only_techniques": software_only,
        "expected_shared_techniques": shared,
        "expected_campaign_only_techniques": campaign_only,
        "provenance": provenance,
    }


def pair_catalog(
    extracted: dict[str, Any],
) -> list[tuple[str, str]]:
    campaign_by_stix = {
        item["stix_id"]: item for item in extracted["campaigns"]
    }
    software_by_stix = {
        item["stix_id"]: item for item in extracted["software"]
    }
    keys = {
        (path["campaign_ref"], path["software_ref"])
        for path in extracted["chain_paths"]
    }
    return sorted(
        (
            (
                campaign_by_stix[campaign_ref]["external_id"],
                software_by_stix[software_ref]["external_id"],
            )
            for campaign_ref, software_ref in keys
        )
    )


def select_divergence_pairs(
    extracted: dict[str, Any],
) -> list[tuple[str, str]]:
    campaigns, software, _ = catalogs(extracted)
    eligible = []
    for campaign_id, software_id in pair_catalog(extracted):
        values = divergence_sets(
            campaigns[campaign_id], software[software_id], extracted
        )
        if values[2]:
            eligible.append((campaign_id, software_id))
    preserved = list(SELECTED_CHAIN_PAIRS)
    if any(item not in eligible for item in preserved):
        raise CampaignSoftwareTechniqueChainError(
            "a prototype divergence pair is no longer eligible"
        )
    remaining = [item for item in eligible if item not in preserved]
    selected = preserved + evenly_spaced(
        remaining, FULL_DIVERGENCE_COUNT - len(preserved)
    )
    if len(set(selected)) != FULL_DIVERGENCE_COUNT:
        raise CampaignSoftwareTechniqueChainError(
            "divergence selection contains duplicates"
        )
    return selected


def select_boolean_negative_cases(
    extracted: dict[str, Any],
) -> dict[str, str]:
    campaigns, _, techniques = catalogs(extracted)
    chain_keys = {
        (path["campaign_ref"], path["technique_ref"])
        for path in extracted["chain_paths"]
    }
    selected = dict(PROTOTYPE_NEGATIVE_TECHNIQUE_BY_CAMPAIGN)
    candidates = [
        campaign_id
        for campaign_id in sorted(campaigns)
        if campaign_id not in selected
        and any(
            path["campaign_ref"] == campaigns[campaign_id]["stix_id"]
            for path in extracted["chain_paths"]
        )
    ]
    for offset, campaign_id in enumerate(
        evenly_spaced(candidates, FULL_BOOLEAN_NEGATIVE_COUNT - len(selected))
    ):
        campaign = campaigns[campaign_id]
        probes = (
            FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[
                offset % len(FULL_NEGATIVE_PROBE_TECHNIQUE_IDS) :
            ]
            + FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[
                : offset % len(FULL_NEGATIVE_PROBE_TECHNIQUE_IDS)
            ]
        )
        for technique_id in probes:
            technique = techniques.get(technique_id)
            if technique is None:
                continue
            if (campaign["stix_id"], technique["stix_id"]) not in chain_keys:
                selected[campaign_id] = technique_id
                break
        else:
            raise CampaignSoftwareTechniqueChainError(
                f"no boolean negative probe is absent for {campaign_id}"
            )
    if len(selected) != FULL_BOOLEAN_NEGATIVE_COUNT:
        raise CampaignSoftwareTechniqueChainError(
            "wrong number of boolean negatives selected"
        )
    return selected


def select_named_negative_cases(
    extracted: dict[str, Any],
) -> dict[tuple[str, str], str]:
    campaigns, software, techniques = catalogs(extracted)
    selected = {
        pair: PROTOTYPE_NEGATIVE_TECHNIQUE_BY_CAMPAIGN[pair[0]]
        for pair in SELECTED_CHAIN_PAIRS
    }
    remaining = [
        pair for pair in pair_catalog(extracted) if pair not in selected
    ]
    additional = evenly_spaced(
        remaining, FULL_NAMED_NEGATIVE_COUNT - len(selected)
    )
    for offset, pair in enumerate(additional):
        campaign_id, software_id = pair
        campaign = campaigns[campaign_id]
        item = software[software_id]
        software_technique_ids = {
            path["technique_ref"]
            for path in chain_paths_for_pair(campaign, item, extracted)
        }
        probes = (
            FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[
                offset % len(FULL_NEGATIVE_PROBE_TECHNIQUE_IDS) :
            ]
            + FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[
                : offset % len(FULL_NEGATIVE_PROBE_TECHNIQUE_IDS)
            ]
        )
        for technique_id in probes:
            technique = techniques.get(technique_id)
            if technique is None:
                continue
            if technique["stix_id"] not in software_technique_ids:
                selected[pair] = technique_id
                break
        else:
            raise CampaignSoftwareTechniqueChainError(
                f"no named negative probe is absent for {pair}"
            )
    if len(selected) != FULL_NAMED_NEGATIVE_COUNT:
        raise CampaignSoftwareTechniqueChainError(
            "wrong number of named negatives selected"
        )
    return selected


def prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    campaigns, software, techniques = catalogs(extracted)
    pairs = [
        named_chain_pair(
            campaigns[campaign_id],
            software[software_id],
            extracted,
            source,
        )
        for campaign_id, software_id in SELECTED_CHAIN_PAIRS
    ]
    pairs.extend(
        reverse_chain_pair(techniques[technique_id], extracted, source)
        for technique_id in PROTOTYPE_REVERSE_TECHNIQUE_IDS
    )
    pairs.extend(
        boolean_chain_pair(
            campaigns[campaign_id],
            techniques[technique_id],
            extracted,
            source,
            expected=True,
        )
        for campaign_id, technique_id
        in PROTOTYPE_POSITIVE_TECHNIQUE_BY_CAMPAIGN.items()
    )
    pairs.extend(
        boolean_chain_pair(
            campaigns[campaign_id],
            techniques[technique_id],
            extracted,
            source,
            expected=False,
        )
        for campaign_id, technique_id
        in PROTOTYPE_NEGATIVE_TECHNIQUE_BY_CAMPAIGN.items()
    )
    pairs.extend(
        divergence_pair(
            campaigns[campaign_id],
            software[software_id],
            extracted,
            source,
        )
        for campaign_id, software_id in SELECTED_CHAIN_PAIRS
    )
    pairs.extend(
        named_negative_pair(
            campaigns[campaign_id],
            software[software_id],
            techniques[
                PROTOTYPE_NEGATIVE_TECHNIQUE_BY_CAMPAIGN[campaign_id]
            ],
            extracted,
            source,
        )
        for campaign_id, software_id in SELECTED_CHAIN_PAIRS
    )
    if len(pairs) != 30 or len({pair["id"] for pair in pairs}) != 30:
        raise CampaignSoftwareTechniqueChainError(
            "prototype must contain 30 unique pairs"
        )
    return pairs


def full_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> tuple[
    list[dict[str, Any]],
    dict[str, str],
    dict[tuple[str, str], str],
    list[tuple[str, str]],
]:
    campaigns, software, techniques = catalogs(extracted)
    named = [
        named_chain_pair(
            campaigns[campaign_id],
            software[software_id],
            extracted,
            source,
        )
        for campaign_id, software_id in pair_catalog(extracted)
    ]
    reverse = [
        reverse_chain_pair(techniques[technique_id], extracted, source)
        for technique_id in sorted(techniques)
    ]
    positive = []
    campaign_paths: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in extracted["chain_paths"]:
        campaign_paths[path["campaign_ref"]].append(path)
    campaign_by_stix = {
        item["stix_id"]: item for item in extracted["campaigns"]
    }
    technique_by_stix = {
        item["stix_id"]: item for item in extracted["techniques"]
    }
    for campaign_ref in sorted(
        campaign_paths,
        key=lambda value: campaign_by_stix[value]["external_id"],
    ):
        campaign = campaign_by_stix[campaign_ref]
        configured = PROTOTYPE_POSITIVE_TECHNIQUE_BY_CAMPAIGN.get(
            campaign["external_id"]
        )
        if configured is None:
            technique = min(
                (
                    technique_by_stix[path["technique_ref"]]
                    for path in campaign_paths[campaign_ref]
                ),
                key=lambda item: item["external_id"],
            )
        else:
            technique = techniques[configured]
        positive.append(
            boolean_chain_pair(
                campaign, technique, extracted, source, expected=True
            )
        )
    boolean_negative_cases = select_boolean_negative_cases(extracted)
    boolean_negatives = [
        boolean_chain_pair(
            campaigns[campaign_id],
            techniques[technique_id],
            extracted,
            source,
            expected=False,
        )
        for campaign_id, technique_id in sorted(
            boolean_negative_cases.items()
        )
    ]
    divergence_keys = select_divergence_pairs(extracted)
    divergences = [
        divergence_pair(
            campaigns[campaign_id],
            software[software_id],
            extracted,
            source,
        )
        for campaign_id, software_id in divergence_keys
    ]
    named_negative_cases = select_named_negative_cases(extracted)
    named_negatives = [
        named_negative_pair(
            campaigns[campaign_id],
            software[software_id],
            techniques[technique_id],
            extracted,
            source,
        )
        for (campaign_id, software_id), technique_id in sorted(
            named_negative_cases.items()
        )
    ]
    pairs = (
        named
        + reverse
        + positive
        + boolean_negatives
        + divergences
        + named_negatives
    )
    if len({pair["id"] for pair in pairs}) != len(pairs):
        raise CampaignSoftwareTechniqueChainError(
            "full chain pair IDs are not unique"
        )
    return (
        pairs,
        boolean_negative_cases,
        named_negative_cases,
        divergence_keys,
    )


def parsed_prototype_data(extracted: dict[str, Any]) -> dict[str, Any]:
    campaigns, software, _ = catalogs(extracted)
    result = {}
    for campaign_id, software_id in SELECTED_CHAIN_PAIRS:
        campaign = campaigns[campaign_id]
        item = software[software_id]
        paths = chain_paths_for_pair(campaign, item, extracted)
        _, _, techniques = entities_for_paths(paths, extracted)
        values = divergence_sets(campaign, item, extracted)
        result[f"{campaign_id}:{software_id}"] = {
            "campaign": campaign,
            "software": item,
            "techniques": techniques,
            "software_only_techniques": values[2],
            "shared_techniques": values[3],
            "campaign_only_techniques": values[4],
            "chain_paths": paths,
        }
    return result


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = prototype_pairs(extracted, source)
    counts = Counter(pair["case_type"] for pair in pairs)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_campaign_software_technique_chain_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "campaign",
            "intermediate_types": ["malware", "tool"],
            "target_type": "attack-pattern",
            "relationship_sequence": ["uses", "uses"],
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "mobile_domain_software_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "pair_count": len(pairs),
            "named_chain_pairs": counts[
                "named_campaign_software_technique_chain"
            ],
            "reverse_positive_pairs": counts[
                "aggregate_technique_campaigns_via_software"
            ],
            "reverse_zero_path_pairs": counts[
                "aggregate_technique_no_campaigns_via_software"
            ],
            "boolean_positive_pairs": counts[
                "positive_campaign_software_technique_chain"
            ],
            "boolean_negative_pairs": counts[
                "negative_campaign_software_technique_chain"
            ],
            "divergence_pairs": counts[
                "campaign_software_technique_divergence"
            ],
            "named_negative_pairs": counts[
                "negative_named_campaign_software_technique_chain"
            ],
            "selected_campaign_software_pairs": [
                {"campaign_external_id": campaign_id, "software_external_id": software_id}
                for campaign_id, software_id in SELECTED_CHAIN_PAIRS
            ],
            "prototype_pairs_preserved_in_full": True,
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "parsed_data": parsed_prototype_data(extracted),
        "pairs": pairs,
    }


def full_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    (
        pairs,
        boolean_negative_cases,
        named_negative_cases,
        divergence_keys,
    ) = full_pairs(extracted, source)
    counts = Counter(pair["case_type"] for pair in pairs)
    named = [
        pair
        for pair in pairs
        if pair["case_type"] == "named_campaign_software_technique_chain"
    ]
    reverse = [
        pair
        for pair in pairs
        if pair["case_type"].startswith("aggregate_technique_")
    ]
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_full_campaign_software_technique_chain",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_type": "campaign",
            "intermediate_types": ["malware", "tool"],
            "target_type": "attack-pattern",
            "relationship_sequence": ["uses", "uses"],
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "mobile_domain_software_excluded": True,
            "prototype_only": False,
            "one_named_pair_per_qualifying_campaign_software_edge": True,
            "one_reverse_pair_per_active_technique": True,
            "one_boolean_positive_per_campaign_with_a_chain": True,
        },
        "selection": {
            "pair_count": len(pairs),
            "named_chain_pairs": counts[
                "named_campaign_software_technique_chain"
            ],
            "reverse_positive_pairs": counts[
                "aggregate_technique_campaigns_via_software"
            ],
            "reverse_zero_path_pairs": counts[
                "aggregate_technique_no_campaigns_via_software"
            ],
            "boolean_positive_pairs": counts[
                "positive_campaign_software_technique_chain"
            ],
            "boolean_negative_pairs": counts[
                "negative_campaign_software_technique_chain"
            ],
            "divergence_pairs": counts[
                "campaign_software_technique_divergence"
            ],
            "named_negative_pairs": counts[
                "negative_named_campaign_software_technique_chain"
            ],
            "embedded_named_chain_fact_count": sum(
                len(pair["expected_techniques"]) for pair in named
            ),
            "embedded_reverse_campaign_fact_count": sum(
                len(pair["expected_campaigns"]) for pair in reverse
            ),
            "embedded_reverse_chain_path_count": sum(
                len(pair["provenance"]["chain_paths"]) for pair in reverse
            ),
            "prototype_pair_count_preserved": len(
                set(pair["id"] for pair in prototype_pairs(extracted, source))
                & set(pair["id"] for pair in pairs)
            ),
        },
        "sampling": {
            "boolean_negative_count": len(boolean_negative_cases),
            "boolean_negative_method": (
                "preserve five prototype non-edges, then choose 20 evenly "
                "spaced campaigns with chains and an active globally "
                "chain-observed technique absent from that campaign's chains"
            ),
            "named_negative_count": len(named_negative_cases),
            "named_negative_method": (
                "preserve five prototype first-hop-positive/second-hop-negative "
                "cases, then choose 20 evenly spaced qualifying campaign/software "
                "pairs and an absent active technique"
            ),
            "divergence_count": len(divergence_keys),
            "divergence_method": (
                "preserve five prototype pairs, then choose 20 evenly spaced "
                "qualifying pairs with a nonempty software-minus-campaign "
                "direct-technique difference"
            ),
            "all_negative_cases_verified_against_complete_chain_path_set": True,
        },
        "global_coverage": extracted["global_coverage"],
        "extraction_audit": extracted["extraction_audit"],
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            HERE
            / "golden_set_campaign_software_technique_chain_prototype.json"
        ),
    )
    parser.add_argument(
        "--generate-full",
        action="store_true",
        help="write the full two-hop chain golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_campaign_software_technique_chain.json",
    )
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    extracted = extract_chain_scope(bundle)
    payload = (
        full_payload(extracted, source)
        if args.generate_full
        else prototype_payload(extracted, source)
    )
    output = args.full_output if args.generate_full else args.output
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
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CampaignSoftwareTechniqueChainError as exc:
        raise SystemExit(f"FAIL: {exc}")
