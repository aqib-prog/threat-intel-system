#!/usr/bin/env python3
"""Backfill reverse questions onto the original six full golden sets.

This generator is deliberately an adapter over the original relationship
generators.  It regenerates their forward pairs from the pinned STIX bundle,
asserts that those pairs are still the unchanged prefix of each checked-in
artifact, and then appends deterministic reverse aggregates and non-edge
probes.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

import generate_campaign_group_prototype as campaign_group
import generate_group_software_prototype as group_software
import generate_group_technique_prototype as group_technique
import generate_software_technique_prototype as software_technique
from generate_golden_set import (
    DEFAULT_MANIFEST,
    enterprise_golden_set_payload,
    enterprise_tactic_golden_set_payload,
    extract_enterprise_mitigation_scope,
    is_active,
    load_pinned_bundle,
    mitre_external_id,
    natural_list,
)


HERE = Path(__file__).resolve().parent
MITIGATION_NEGATIVE_COUNT = 20
TACTIC_NEGATIVE_COUNT = 15
TECHNIQUE_GROUP_NEGATIVE_COUNT = 20
TECHNIQUE_SOFTWARE_NEGATIVE_COUNT = 25
SOFTWARE_GROUP_NEGATIVE_COUNT = 20
GROUP_CAMPAIGN_NEGATIVE_COUNT = 10
TACTIC_ADVERSARIAL_NEGATIVE_COUNT = 65
SOFTWARE_TECHNIQUE_ADVERSARIAL_NEGATIVE_COUNT = 119
GROUP_SOFTWARE_ADVERSARIAL_NEGATIVE_COUNT = 71


class ReverseBackfillError(RuntimeError):
    """Raised when a reverse artifact cannot be generated safely."""


def label(item: dict[str, Any]) -> str:
    return f"{item['external_id']} ({item['name']})"


def evenly_spaced(items: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    if count < 0 or count > len(items):
        raise ReverseBackfillError(
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
        raise ReverseBackfillError("evenly spaced selection produced duplicates")
    return [items[index] for index in indices]


def select_negative_pairs(
    anchors: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    edge_keys: set[tuple[str, str]],
    count: int,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    positive_anchors = [
        anchor
        for anchor in anchors
        if any(key[0] == anchor["stix_id"] for key in edge_keys)
    ]
    selected_anchors = evenly_spaced(positive_anchors, count)
    selected = []
    for offset, anchor in enumerate(selected_anchors):
        probes = candidates[offset % len(candidates) :] + candidates[
            : offset % len(candidates)
        ]
        candidate = next(
            (
                item
                for item in probes
                if (anchor["stix_id"], item["stix_id"]) not in edge_keys
            ),
            None,
        )
        if candidate is None:
            raise ReverseBackfillError(
                f"no negative candidate exists for {anchor['external_id']}"
            )
        selected.append((anchor, candidate))
    return selected


def assert_forward_prefix(
    artifact_path: Path, generated_forward_pairs: list[dict[str, Any]]
) -> None:
    current = json.loads(artifact_path.read_text(encoding="utf-8"))
    prefix = current.get("pairs", [])[: len(generated_forward_pairs)]
    if prefix != generated_forward_pairs:
        raise ReverseBackfillError(
            f"{artifact_path.name} no longer has the generator's unchanged "
            "forward pairs as its prefix"
        )


def finish_payload(
    payload: dict[str, Any],
    reverse_aggregates: list[dict[str, Any]],
    reverse_negatives: list[dict[str, Any]],
    *,
    direction: str,
) -> dict[str, Any]:
    original_count = len(payload["pairs"])
    zero_count = sum(
        "no_" in pair["case_type"] for pair in reverse_aggregates
    )
    payload["pairs"].extend(reverse_aggregates)
    payload["pairs"].extend(reverse_negatives)
    if len({pair["id"] for pair in payload["pairs"]}) != len(payload["pairs"]):
        raise ReverseBackfillError(f"duplicate pair ID after adding {direction}")
    payload["scope"]["reverse_direction_added"] = direction
    payload["scope"]["reverse_zero_path_handling"] = (
        "one explicit aggregate per active reverse anchor with no qualifying edge"
    )
    payload["selection"].update(
        {
            "original_pair_count": original_count,
            "reverse_aggregate_pairs": len(reverse_aggregates),
            "reverse_zero_path_pairs": zero_count,
            "reverse_negative_existence_pairs": len(reverse_negatives),
            "pair_count": len(payload["pairs"]),
        }
    )
    return payload


def append_adversarial_negatives(
    payload: dict[str, Any],
    pairs: list[dict[str, Any]],
    *,
    method: str,
    fallback_count: int = 0,
) -> dict[str, Any]:
    """Append harder graph-neighborhood non-edges without changing old pairs."""

    existing_ids = {pair["id"] for pair in payload["pairs"]}
    duplicate_ids = sorted(existing_ids & {pair["id"] for pair in pairs})
    if duplicate_ids:
        raise ReverseBackfillError(
            "adversarial pair IDs collide with existing pairs: "
            + ", ".join(duplicate_ids)
        )
    payload["pairs"].extend(pairs)
    easy_count = sum(
        pair["case_type"].startswith("negative_")
        for pair in payload["pairs"]
        if not pair["case_type"].startswith("adversarial_negative_")
    )
    adversarial_count = sum(
        pair["case_type"].startswith("adversarial_negative_")
        for pair in payload["pairs"]
    )
    total_negative_count = easy_count + adversarial_count
    payload["selection"].update(
        {
            "pair_count": len(payload["pairs"]),
            "easy_negative_pairs": easy_count,
            "adversarial_negative_pairs": adversarial_count,
            "total_negative_pairs": total_negative_count,
            "total_negative_ratio": total_negative_count / len(payload["pairs"]),
        }
    )
    payload["scope"]["adversarial_sibling_negatives"] = True
    payload["negative_selection"] = {
        "adversarial_method": method,
        "adversarial_cases_verified_absent_by_complete_edge_set": True,
        "unrelated_pair_fallback_count": fallback_count,
    }
    return payload


def compact_context_entity(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "stix_type": obj.get("type"),
    }


def tactic_adversarial_negative_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    existing_pairs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Pair a technique with a false tactic learned from a tactic sibling."""

    techniques = {item["stix_id"]: item for item in extracted["techniques"]}
    tactics = {item["stix_id"]: item for item in extracted["tactics"]}
    tactic_refs_by_technique = {
        technique_ref: {
            row["tactic_ref"]
            for row in extracted["technique_tactic_links"]
            if row["technique_ref"] == technique_ref
        }
        for technique_ref in techniques
    }
    existing_negative_keys = {
        (
            pair["queried_technique"]["stix_id"],
            pair["tactic"]["stix_id"],
        )
        for pair in existing_pairs
        if pair["case_type"] == "negative_tactic_technique"
    }
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    ordered_techniques = sorted(
        techniques.values(), key=lambda item: item["external_id"]
    )
    for technique in ordered_techniques:
        actual_tactics = tactic_refs_by_technique[technique["stix_id"]]
        for sibling in ordered_techniques:
            if sibling["stix_id"] == technique["stix_id"]:
                continue
            sibling_tactics = tactic_refs_by_technique[sibling["stix_id"]]
            shared = actual_tactics & sibling_tactics
            false_tactics = sibling_tactics - actual_tactics
            if not shared or not false_tactics:
                continue
            false_tactic_ref = min(
                false_tactics, key=lambda ref: tactics[ref]["external_id"]
            )
            key = (technique["stix_id"], false_tactic_ref)
            if key in existing_negative_keys:
                continue
            shared_tactic_ref = min(
                shared, key=lambda ref: tactics[ref]["external_id"]
            )
            candidates.setdefault(
                key,
                {
                    "technique": technique,
                    "false_tactic": tactics[false_tactic_ref],
                    "sibling_technique": sibling,
                    "shared_tactic": tactics[shared_tactic_ref],
                },
            )
            break
    selected = evenly_spaced(
        sorted(
            candidates.values(),
            key=lambda row: (
                row["technique"]["external_id"],
                row["false_tactic"]["external_id"],
            ),
        ),
        TACTIC_ADVERSARIAL_NEGATIVE_COUNT,
    )
    links = extracted["technique_tactic_links"]
    pairs = []
    for row in selected:
        technique = row["technique"]
        false_tactic = row["false_tactic"]
        sibling = row["sibling_technique"]
        shared_tactic = row["shared_tactic"]
        anchor_shared_links = [
            link
            for link in links
            if link["technique_ref"] == technique["stix_id"]
            and link["tactic_ref"] == shared_tactic["stix_id"]
        ]
        sibling_context_links = [
            link
            for link in links
            if link["technique_ref"] == sibling["stix_id"]
            and link["tactic_ref"]
            in {shared_tactic["stix_id"], false_tactic["stix_id"]}
        ]
        if not anchor_shared_links or len(sibling_context_links) != 2:
            raise ReverseBackfillError(
                f"incomplete tactic sibling evidence for {technique['external_id']}"
            )
        pairs.append(
            {
                "id": (
                    "enterprise-technique-tactic-adversarial-negative-"
                    f"{technique['external_id'].lower()}-"
                    f"{false_tactic['external_id'].lower()}"
                ),
                "case_type": "adversarial_negative_technique_tactic",
                "relationship_type": "technique_to_tactic",
                "question": (
                    f"Does {label(technique)} belong to {label(false_tactic)}?"
                ),
                "expected_answer": (
                    "No active kill-chain phase membership links "
                    f"{label(technique)} to {label(false_tactic)} in the pinned "
                    "Enterprise ATT&CK snapshot. The confusion is plausible "
                    f"because sibling {label(sibling)} shares "
                    f"{label(shared_tactic)} with the queried technique and "
                    f"does belong to {label(false_tactic)}."
                ),
                "queried_technique": technique,
                "tactic": false_tactic,
                "relationship_exists": False,
                "expected_tactics": [],
                "provenance": {
                    "repository": source["repository"],
                    "stix_commit": source["commit"],
                    "bundle_path": source["path"],
                    "bundle_sha256": source["sha256"],
                    "queried_technique_stix_id": technique["stix_id"],
                    "false_tactic_stix_id": false_tactic["stix_id"],
                    "final_technique_tactic_links": [],
                    "difficulty": "adversarial_sibling",
                    "adversarial_context": {
                        "method": "sibling_technique_tactic_cooccurrence",
                        "sibling_technique": sibling,
                        "shared_tactic": shared_tactic,
                        "anchor_shared_tactic_links": anchor_shared_links,
                        "sibling_context_tactic_links": sibling_context_links,
                    },
                },
            }
        )
    return pairs


def software_technique_adversarial_negative_pairs(
    bundle: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
    existing_pairs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Use another software item from the same actor/campaign neighborhood."""

    objects = [
        obj
        for obj in bundle.get("objects", [])
        if isinstance(obj, dict)
    ]
    active_contexts = {
        obj["id"]: obj
        for obj in objects
        if obj.get("type") in {"intrusion-set", "campaign"}
        and is_active(obj)
    }
    software = {
        item["stix_id"]: item for item in extracted["software"]
    }
    techniques = {
        item["stix_id"]: item
        for item in extracted["active_technique_catalog"]
    }
    context_edges: dict[str, dict[str, list[str]]] = {}
    for rel in objects:
        if (
            rel.get("type") == "relationship"
            and rel.get("relationship_type") == "uses"
            and is_active(rel)
            and rel.get("source_ref") in active_contexts
            and rel.get("target_ref") in software
        ):
            context_edges.setdefault(rel["source_ref"], {}).setdefault(
                rel["target_ref"], []
            ).append(rel["id"])
    technique_refs_by_software: dict[str, set[str]] = {
        software_ref: set() for software_ref in software
    }
    technique_paths: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in extracted["paths"]:
        technique_refs_by_software[path["software_ref"]].add(
            path["technique_ref"]
        )
        technique_paths.setdefault(
            (path["software_ref"], path["technique_ref"]), []
        ).append(path)
    existing_negative_keys = set()
    for pair in existing_pairs:
        if pair["case_type"] == "negative_software_technique":
            existing_negative_keys.add(
                (
                    pair["software"]["stix_id"],
                    pair["queried_technique"]["stix_id"],
                )
            )
        elif pair["case_type"] == "negative_technique_software":
            existing_negative_keys.add(
                (
                    pair["queried_software"]["stix_id"],
                    pair["technique"]["stix_id"],
                )
            )
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    ordered_contexts = sorted(
        context_edges,
        key=lambda ref: (
            mitre_external_id(active_contexts[ref]) or "",
            ref,
        ),
    )
    for context_ref in ordered_contexts:
        members = sorted(
            context_edges[context_ref],
            key=lambda ref: software[ref]["external_id"],
        )
        for anchor_ref in members:
            for sibling_ref in members:
                if sibling_ref == anchor_ref:
                    continue
                candidate_techniques = (
                    technique_refs_by_software[sibling_ref]
                    - technique_refs_by_software[anchor_ref]
                )
                for technique_ref in sorted(
                    candidate_techniques,
                    key=lambda ref: techniques[ref]["external_id"],
                ):
                    key = (anchor_ref, technique_ref)
                    if key in existing_negative_keys:
                        continue
                    candidates.setdefault(
                        key,
                        {
                            "software": software[anchor_ref],
                            "technique": techniques[technique_ref],
                            "context_source": compact_context_entity(
                                active_contexts[context_ref]
                            ),
                            "sibling_software": software[sibling_ref],
                            "context_to_anchor_relationship_stix_ids": sorted(
                                context_edges[context_ref][anchor_ref]
                            ),
                            "context_to_sibling_relationship_stix_ids": sorted(
                                context_edges[context_ref][sibling_ref]
                            ),
                            "sibling_software_technique_paths": sorted(
                                technique_paths[(sibling_ref, technique_ref)],
                                key=lambda path: path[
                                    "uses_relationship_stix_id"
                                ],
                            ),
                        },
                    )
    selected = evenly_spaced(
        sorted(
            candidates.values(),
            key=lambda row: (
                row["software"]["external_id"],
                row["technique"]["external_id"],
                row["context_source"]["external_id"] or "",
                row["sibling_software"]["external_id"],
            ),
        ),
        SOFTWARE_TECHNIQUE_ADVERSARIAL_NEGATIVE_COUNT,
    )
    pairs = []
    for row in selected:
        anchor = row["software"]
        technique = row["technique"]
        sibling = row["sibling_software"]
        if technique["stix_id"] in technique_refs_by_software[anchor["stix_id"]]:
            raise ReverseBackfillError(
                f"adversarial software edge exists for {anchor['external_id']} "
                f"and {technique['external_id']}"
            )
        base_provenance = software_technique.provenance(
            anchor, [], [], source, queried_technique=technique
        )
        base_provenance.update(
            {
                "difficulty": "adversarial_sibling",
                "adversarial_context": {
                    "method": "same_actor_or_campaign_software_neighborhood",
                    "shared_context_source": row["context_source"],
                    "sibling_software": sibling,
                    "context_to_anchor_relationship_stix_ids": row[
                        "context_to_anchor_relationship_stix_ids"
                    ],
                    "context_to_sibling_relationship_stix_ids": row[
                        "context_to_sibling_relationship_stix_ids"
                    ],
                    "sibling_software_technique_paths": row[
                        "sibling_software_technique_paths"
                    ],
                },
            }
        )
        pairs.append(
            {
                "id": (
                    "software-adversarial-does-not-use-technique-"
                    f"{anchor['external_id'].lower()}-"
                    f"{technique['external_id'].lower()}"
                ),
                "case_type": "adversarial_negative_software_technique",
                "relationship_type": "software_uses_technique",
                "question": (
                    f"Does {label(anchor)} use {label(technique)}?"
                ),
                "expected_answer": (
                    "No active direct uses relationship exists between "
                    f"{label(anchor)} and {label(technique)} in the pinned "
                    "Enterprise ATT&CK snapshot. The confusion is plausible "
                    f"because {label(sibling)} shares the same "
                    f"{row['context_source']['stix_type']} context and does "
                    f"use {label(technique)}."
                ),
                "software": anchor,
                "queried_technique": technique,
                "relationship_exists": False,
                "expected_techniques": [],
                "provenance": base_provenance,
            }
        )
    return pairs


def group_software_adversarial_negative_pairs(
    bundle: dict[str, Any],
    extracted: dict[str, Any],
    source: dict[str, Any],
    existing_pairs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Use software from a different actor with a real shared technique."""

    technique_scope = group_technique.extract_group_technique_scope(
        bundle, group_ids=None
    )
    groups = {item["stix_id"]: item for item in extracted["groups"]}
    software = {
        item["stix_id"]: item
        for item in extracted["active_software_catalog"]
    }
    techniques = {
        item["stix_id"]: item
        for item in technique_scope["active_technique_catalog"]
    }
    software_refs_by_group: dict[str, set[str]] = {
        group_ref: set() for group_ref in groups
    }
    software_paths: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in extracted["paths"]:
        software_refs_by_group[path["group_ref"]].add(path["software_ref"])
        software_paths.setdefault(
            (path["group_ref"], path["software_ref"]), []
        ).append(path)
    technique_refs_by_group: dict[str, set[str]] = {
        group_ref: set() for group_ref in groups
    }
    technique_paths: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in technique_scope["paths"]:
        if path["group_ref"] not in groups:
            continue
        technique_refs_by_group[path["group_ref"]].add(path["technique_ref"])
        technique_paths.setdefault(
            (path["group_ref"], path["technique_ref"]), []
        ).append(path)
    existing_negative_keys = set()
    for pair in existing_pairs:
        if pair["case_type"] == "negative_group_software":
            existing_negative_keys.add(
                (
                    pair["group"]["stix_id"],
                    pair["queried_software"]["stix_id"],
                )
            )
        elif pair["case_type"] == "negative_software_group":
            existing_negative_keys.add(
                (
                    pair["queried_group"]["stix_id"],
                    pair["software"]["stix_id"],
                )
            )
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    ordered_groups = sorted(
        groups.values(), key=lambda item: item["external_id"]
    )
    for anchor in ordered_groups:
        anchor_techniques = technique_refs_by_group[anchor["stix_id"]]
        for sibling in ordered_groups:
            if sibling["stix_id"] == anchor["stix_id"]:
                continue
            shared_techniques = (
                anchor_techniques
                & technique_refs_by_group[sibling["stix_id"]]
            )
            sibling_only_software = (
                software_refs_by_group[sibling["stix_id"]]
                - software_refs_by_group[anchor["stix_id"]]
            )
            if not shared_techniques or not sibling_only_software:
                continue
            shared_technique_ref = min(
                shared_techniques,
                key=lambda ref: techniques[ref]["external_id"],
            )
            for software_ref in sorted(
                sibling_only_software,
                key=lambda ref: software[ref]["external_id"],
            ):
                key = (anchor["stix_id"], software_ref)
                if key in existing_negative_keys:
                    continue
                candidates.setdefault(
                    key,
                    {
                        "group": anchor,
                        "software": software[software_ref],
                        "sibling_group": sibling,
                        "shared_technique": techniques[shared_technique_ref],
                        "anchor_shared_technique_paths": sorted(
                            technique_paths[
                                (anchor["stix_id"], shared_technique_ref)
                            ],
                            key=lambda path: json.dumps(
                                path, sort_keys=True
                            ),
                        ),
                        "sibling_shared_technique_paths": sorted(
                            technique_paths[
                                (sibling["stix_id"], shared_technique_ref)
                            ],
                            key=lambda path: json.dumps(
                                path, sort_keys=True
                            ),
                        ),
                        "sibling_software_paths": sorted(
                            software_paths[(sibling["stix_id"], software_ref)],
                            key=lambda path: json.dumps(
                                path, sort_keys=True
                            ),
                        ),
                    },
                )
    selected = evenly_spaced(
        sorted(
            candidates.values(),
            key=lambda row: (
                row["group"]["external_id"],
                row["software"]["external_id"],
                row["sibling_group"]["external_id"],
            ),
        ),
        GROUP_SOFTWARE_ADVERSARIAL_NEGATIVE_COUNT,
    )
    pairs = []
    for row in selected:
        group = row["group"]
        candidate_software = row["software"]
        if (
            candidate_software["stix_id"]
            in software_refs_by_group[group["stix_id"]]
        ):
            raise ReverseBackfillError(
                f"adversarial group/software edge exists for "
                f"{group['external_id']} and "
                f"{candidate_software['external_id']}"
            )
        base_provenance = group_software.provenance(
            group,
            [],
            [],
            source,
            queried_software=candidate_software,
        )
        base_provenance.update(
            {
                "difficulty": "adversarial_sibling",
                "adversarial_context": {
                    "method": "different_actor_with_overlapping_technique",
                    "sibling_group": row["sibling_group"],
                    "shared_technique": row["shared_technique"],
                    "anchor_shared_technique_paths": row[
                        "anchor_shared_technique_paths"
                    ],
                    "sibling_shared_technique_paths": row[
                        "sibling_shared_technique_paths"
                    ],
                    "sibling_software_paths": row[
                        "sibling_software_paths"
                    ],
                },
            }
        )
        pairs.append(
            {
                "id": (
                    "group-adversarial-does-not-use-software-"
                    f"{group['external_id'].lower()}-"
                    f"{candidate_software['external_id'].lower()}"
                ),
                "case_type": "adversarial_negative_group_software",
                "relationship_type": "group_uses_software",
                "question": (
                    f"Does {group['name']} use {label(candidate_software)}?"
                ),
                "expected_answer": (
                    "No active direct or campaign-attributed uses path exists "
                    f"between {label(group)} and {label(candidate_software)} "
                    "in the pinned Enterprise ATT&CK snapshot. The confusion "
                    f"is plausible because sibling actor "
                    f"{label(row['sibling_group'])} shares "
                    f"{label(row['shared_technique'])} with the queried actor "
                    f"and does use {label(candidate_software)}."
                ),
                "group": group,
                "queried_software": candidate_software,
                "relationship_exists": False,
                "expected_software": [],
                "provenance": base_provenance,
            }
        )
    return pairs


def mitigation_payload(
    bundle: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    extracted = extract_enterprise_mitigation_scope(bundle)
    payload = enterprise_golden_set_payload(extracted, source)
    techniques = {item["stix_id"]: item for item in extracted["techniques"]}
    relationships = extracted["mitigates_relationships"]
    edge_keys = {
        (row["mitigation_ref"], row["technique_ref"]) for row in relationships
    }
    reverse = []
    for mitigation in extracted["mitigations"]:
        paths = [
            row
            for row in relationships
            if row["mitigation_ref"] == mitigation["stix_id"]
        ]
        expected = sorted(
            {techniques[row["technique_ref"]]["stix_id"]: techniques[row["technique_ref"]]
             for row in paths}.values(),
            key=lambda item: item["external_id"],
        )
        case_type = (
            "aggregate_mitigation_techniques"
            if expected
            else "aggregate_mitigation_no_techniques"
        )
        answer = (
            f"{label(mitigation)} mitigates "
            f"{natural_list([label(item) for item in expected])} in the pinned "
            "Enterprise ATT&CK snapshot."
            if expected
            else "No active mitigates relationship originates from "
            f"{label(mitigation)} in the pinned Enterprise ATT&CK snapshot."
        )
        reverse.append(
            {
                "id": f"enterprise-mitigation-techniques-{mitigation['external_id'].lower()}",
                "case_type": case_type,
                "relationship_type": "technique_to_mitigation",
                "question": f"What techniques does {label(mitigation)} mitigate?",
                "expected_answer": answer,
                "mitigation": mitigation,
                "expected_techniques": expected,
                "provenance": {
                    "repository": source["repository"],
                    "stix_commit": source["commit"],
                    "bundle_path": source["path"],
                    "bundle_sha256": source["sha256"],
                    "mitigation_stix_id": mitigation["stix_id"],
                    "technique_stix_ids": [item["stix_id"] for item in expected],
                    "relationship_stix_ids": [row["stix_id"] for row in paths],
                    "mitigates_edges": [
                        {
                            "relationship_stix_id": row["stix_id"],
                            "mitigation_stix_id": row["mitigation_ref"],
                            "technique_stix_id": row["technique_ref"],
                        }
                        for row in paths
                    ],
                },
            }
        )
    negatives = []
    for mitigation, technique in select_negative_pairs(
        extracted["mitigations"],
        extracted["techniques"],
        edge_keys,
        MITIGATION_NEGATIVE_COUNT,
    ):
        negatives.append(
            {
                "id": (
                    f"enterprise-mitigation-technique-negative-"
                    f"{mitigation['external_id'].lower()}-{technique['external_id'].lower()}"
                ),
                "case_type": "negative_mitigation_technique",
                "relationship_type": "technique_to_mitigation",
                "question": f"Does {label(mitigation)} mitigate {label(technique)}?",
                "expected_answer": (
                    "No active mitigates relationship exists from "
                    f"{label(mitigation)} to {label(technique)} in the pinned "
                    "Enterprise ATT&CK snapshot."
                ),
                "mitigation": mitigation,
                "queried_technique": technique,
                "relationship_exists": False,
                "expected_techniques": [],
                "provenance": {
                    "repository": source["repository"],
                    "stix_commit": source["commit"],
                    "bundle_path": source["path"],
                    "bundle_sha256": source["sha256"],
                    "mitigation_stix_id": mitigation["stix_id"],
                    "queried_technique_stix_id": technique["stix_id"],
                    "technique_stix_ids": [],
                    "relationship_stix_ids": [],
                    "mitigates_edges": [],
                },
            }
        )
    return finish_payload(
        payload, reverse, negatives, direction="mitigation_to_technique"
    )


def tactic_payload(
    bundle: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    extracted = extract_enterprise_mitigation_scope(bundle)
    payload = enterprise_tactic_golden_set_payload(extracted, source)
    techniques = {item["stix_id"]: item for item in extracted["techniques"]}
    links = extracted["technique_tactic_links"]
    edge_keys = {(row["tactic_ref"], row["technique_ref"]) for row in links}
    reverse = []
    for tactic in extracted["tactics"]:
        paths = [row for row in links if row["tactic_ref"] == tactic["stix_id"]]
        expected = sorted(
            {techniques[row["technique_ref"]]["stix_id"]: techniques[row["technique_ref"]]
             for row in paths}.values(),
            key=lambda item: item["external_id"],
        )
        case_type = (
            "aggregate_tactic_techniques"
            if expected
            else "aggregate_tactic_no_techniques"
        )
        answer = (
            f"{label(tactic)} contains "
            f"{natural_list([label(item) for item in expected])} in the pinned "
            "Enterprise ATT&CK snapshot."
            if expected
            else "No active technique has a kill-chain phase membership for "
            f"{label(tactic)} in the pinned Enterprise ATT&CK snapshot."
        )
        reverse.append(
            {
                "id": f"enterprise-tactic-techniques-{tactic['external_id'].lower()}",
                "case_type": case_type,
                "relationship_type": "technique_to_tactic",
                "question": f"What techniques belong to {label(tactic)}?",
                "expected_answer": answer,
                "tactic": tactic,
                "expected_techniques": expected,
                "provenance": {
                    "repository": source["repository"],
                    "stix_commit": source["commit"],
                    "bundle_path": source["path"],
                    "bundle_sha256": source["sha256"],
                    "tactic_stix_id": tactic["stix_id"],
                    "technique_stix_ids": [item["stix_id"] for item in expected],
                    "link_source": "attack-pattern.kill_chain_phases",
                    "technique_tactic_links": [
                        {
                            "kill_chain_name": row["kill_chain_name"],
                            "phase_name": row["phase_name"],
                            "tactic_stix_id": row["tactic_ref"],
                            "technique_stix_id": row["technique_ref"],
                        }
                        for row in paths
                    ],
                },
            }
        )
    negatives = []
    for tactic, technique in select_negative_pairs(
        extracted["tactics"],
        extracted["techniques"],
        edge_keys,
        TACTIC_NEGATIVE_COUNT,
    ):
        negatives.append(
            {
                "id": (
                    f"enterprise-tactic-technique-negative-"
                    f"{tactic['external_id'].lower()}-{technique['external_id'].lower()}"
                ),
                "case_type": "negative_tactic_technique",
                "relationship_type": "technique_to_tactic",
                "question": f"Does {label(technique)} belong to {label(tactic)}?",
                "expected_answer": (
                    "No active kill-chain phase membership links "
                    f"{label(technique)} to {label(tactic)} in the pinned "
                    "Enterprise ATT&CK snapshot."
                ),
                "tactic": tactic,
                "queried_technique": technique,
                "relationship_exists": False,
                "expected_techniques": [],
                "provenance": {
                    "repository": source["repository"],
                    "stix_commit": source["commit"],
                    "bundle_path": source["path"],
                    "bundle_sha256": source["sha256"],
                    "tactic_stix_id": tactic["stix_id"],
                    "queried_technique_stix_id": technique["stix_id"],
                    "technique_stix_ids": [],
                    "link_source": "attack-pattern.kill_chain_phases",
                    "technique_tactic_links": [],
                },
            }
        )
    payload = finish_payload(
        payload, reverse, negatives, direction="tactic_to_technique"
    )
    adversarial = tactic_adversarial_negative_pairs(
        extracted, source, payload["pairs"]
    )
    return append_adversarial_negatives(
        payload,
        adversarial,
        method=(
            "pair a technique with a false tactic carried by a different "
            "technique that shares one of the queried technique's real tactics"
        ),
    )


def path_ids(paths: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    relationships: set[str] = set()
    campaigns: set[str] = set()
    for path in paths:
        for key in (
            "direct_uses_relationship_stix_id",
            "attributed_to_relationship_stix_id",
            "campaign_uses_relationship_stix_id",
            "uses_relationship_stix_id",
        ):
            if path.get(key):
                relationships.add(path[key])
        if path.get("campaign_ref"):
            campaigns.add(path["campaign_ref"])
    return sorted(relationships), sorted(campaigns)


def generic_reverse_payload(
    payload: dict[str, Any],
    *,
    anchors: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    anchor_ref: str,
    candidate_ref: str,
    expected_key: str,
    anchor_key: str,
    queried_key: str,
    aggregate_case: str,
    zero_case: str,
    negative_case: str,
    relationship_type: str,
    aggregate_id: Callable[[dict[str, Any]], str],
    negative_id: Callable[[dict[str, Any], dict[str, Any]], str],
    question: Callable[[dict[str, Any]], str],
    positive_answer: Callable[[dict[str, Any], list[dict[str, Any]]], str],
    zero_answer: Callable[[dict[str, Any]], str],
    negative_question: Callable[[dict[str, Any], dict[str, Any]], str],
    negative_answer: Callable[[dict[str, Any], dict[str, Any]], str],
    provenance_base: Callable[
        [dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]],
        dict[str, Any],
    ],
    negative_count: int,
    direction: str,
) -> dict[str, Any]:
    candidate_by_stix = {item["stix_id"]: item for item in candidates}
    edge_keys = {(path[anchor_ref], path[candidate_ref]) for path in paths}
    reverse = []
    for anchor in anchors:
        matching = [path for path in paths if path[anchor_ref] == anchor["stix_id"]]
        expected = sorted(
            {
                path[candidate_ref]: candidate_by_stix[path[candidate_ref]]
                for path in matching
            }.values(),
            key=lambda item: item["external_id"],
        )
        reverse.append(
            {
                "id": aggregate_id(anchor),
                "case_type": aggregate_case if expected else zero_case,
                "relationship_type": relationship_type,
                "question": question(anchor),
                "expected_answer": (
                    positive_answer(anchor, expected)
                    if expected
                    else zero_answer(anchor)
                ),
                anchor_key: anchor,
                expected_key: expected,
                "provenance": provenance_base(anchor, expected, matching),
            }
        )
    negatives = []
    for anchor, candidate in select_negative_pairs(
        anchors, candidates, edge_keys, negative_count
    ):
        provenance = provenance_base(anchor, [], [])
        provenance[f"queried_{candidate_ref.removesuffix('_ref')}_stix_id"] = (
            candidate["stix_id"]
        )
        negatives.append(
            {
                "id": negative_id(anchor, candidate),
                "case_type": negative_case,
                "relationship_type": relationship_type,
                "question": negative_question(anchor, candidate),
                "expected_answer": negative_answer(anchor, candidate),
                anchor_key: anchor,
                queried_key: candidate,
                "relationship_exists": False,
                expected_key: [],
                "provenance": provenance,
            }
        )
    return finish_payload(payload, reverse, negatives, direction=direction)


def technique_group_payload(
    bundle: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    extracted = group_technique.extract_group_technique_scope(
        bundle, group_ids=None
    )
    payload = group_technique.full_group_payload(extracted, source)

    def provenance(
        technique: dict[str, Any],
        groups: list[dict[str, Any]],
        paths: list[dict[str, Any]],
    ) -> dict[str, Any]:
        relationship_ids, campaign_ids = path_ids(paths)
        return {
            "repository": source["repository"],
            "stix_commit": source["commit"],
            "bundle_path": source["path"],
            "bundle_sha256": source["sha256"],
            "technique_stix_id": technique["stix_id"],
            "group_stix_ids": [item["stix_id"] for item in groups],
            "scope": group_technique.MERGED_TECHNIQUE_SCOPE,
            "methodology_note": group_technique.METHODOLOGY_NOTE,
            "software_mediated_techniques_excluded": True,
            "parent_subtechnique_deduplication": "none",
            "campaign_stix_ids": campaign_ids,
            "relationship_stix_ids": relationship_ids,
            "relationship_paths": [
                group_technique.provenance_path(path) for path in paths
            ],
        }

    payload = generic_reverse_payload(
        payload,
        anchors=extracted["active_technique_catalog"],
        candidates=extracted["groups"],
        paths=extracted["paths"],
        anchor_ref="technique_ref",
        candidate_ref="group_ref",
        expected_key="expected_groups",
        anchor_key="technique",
        queried_key="queried_group",
        aggregate_case="aggregate_technique_groups",
        zero_case="aggregate_technique_no_qualifying_groups",
        negative_case="negative_technique_group",
        relationship_type="group_uses_technique",
        aggregate_id=lambda item: f"technique-used-by-groups-{item['external_id'].lower()}",
        negative_id=lambda a, c: (
            f"technique-not-used-by-group-{a['external_id'].lower()}-"
            f"{c['external_id'].lower()}"
        ),
        question=lambda item: f"Which actors use {label(item)}?",
        positive_answer=lambda a, items: (
            f"{label(a)} is used by {natural_list([label(item) for item in items])} "
            "in the pinned Enterprise ATT&CK snapshot under the direct-plus-"
            "campaign scope."
        ),
        zero_answer=lambda item: (
            "No active direct or campaign-attributed uses path targets "
            f"{label(item)} from an active group in the pinned Enterprise ATT&CK "
            "snapshot."
        ),
        negative_question=lambda a, c: f"Does {label(c)} use {label(a)}?",
        negative_answer=lambda a, c: (
            "No active direct or campaign-attributed uses path exists between "
            f"{label(c)} and {label(a)} in the pinned Enterprise ATT&CK snapshot."
        ),
        provenance_base=provenance,
        negative_count=TECHNIQUE_GROUP_NEGATIVE_COUNT,
        direction="technique_to_group",
    )
    return payload


def technique_software_payload(
    bundle: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    extracted = software_technique.extract_software_technique_scope(
        bundle, software_ids=None
    )
    payload = software_technique.full_software_payload(extracted, source)

    def provenance(
        technique: dict[str, Any],
        software: list[dict[str, Any]],
        paths: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "source_repository": source["repository"],
            "source_commit": source["commit"],
            "source_bundle_path": source["path"],
            "source_bundle_sha256": source["sha256"],
            "scope": software_technique.SCOPE,
            "methodology_note": software_technique.METHODOLOGY_NOTE,
            "technique_stix_id": technique["stix_id"],
            "software_stix_ids": [item["stix_id"] for item in software],
            "uses_relationship_stix_ids": [
                path["uses_relationship_stix_id"] for path in paths
            ],
            "relationship_paths": paths,
        }

    payload = generic_reverse_payload(
        payload,
        anchors=extracted["active_technique_catalog"],
        candidates=extracted["software"],
        paths=extracted["paths"],
        anchor_ref="technique_ref",
        candidate_ref="software_ref",
        expected_key="expected_software",
        anchor_key="technique",
        queried_key="queried_software",
        aggregate_case="aggregate_technique_software",
        zero_case="aggregate_technique_no_software",
        negative_case="negative_technique_software",
        relationship_type="software_uses_technique",
        aggregate_id=lambda item: f"technique-used-by-software-{item['external_id'].lower()}",
        negative_id=lambda a, c: (
            f"technique-not-used-by-software-{a['external_id'].lower()}-"
            f"{c['external_id'].lower()}"
        ),
        question=lambda item: f"Which malware or tools use {label(item)}?",
        positive_answer=lambda a, items: (
            f"{label(a)} is directly used by "
            f"{natural_list([label(item) for item in items])} in the pinned "
            "Enterprise ATT&CK snapshot."
        ),
        zero_answer=lambda item: (
            "No active direct software-to-technique uses relationship targets "
            f"{label(item)} in the pinned Enterprise ATT&CK snapshot."
        ),
        negative_question=lambda a, c: f"Does {label(c)} use {label(a)}?",
        negative_answer=lambda a, c: (
            "No active direct uses relationship exists from "
            f"{label(c)} to {label(a)} in the pinned Enterprise ATT&CK snapshot."
        ),
        provenance_base=provenance,
        negative_count=TECHNIQUE_SOFTWARE_NEGATIVE_COUNT,
        direction="technique_to_software",
    )
    adversarial = software_technique_adversarial_negative_pairs(
        bundle, extracted, source, payload["pairs"]
    )
    return append_adversarial_negatives(
        payload,
        adversarial,
        method=(
            "pair software with a technique used by different software that "
            "shares a real direct actor-or-campaign software neighborhood"
        ),
    )


def software_group_payload(
    bundle: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    extracted = group_software.extract_group_software_scope(bundle, group_ids=None)
    payload = group_software.full_group_payload(extracted, source)

    def provenance(
        software: dict[str, Any],
        groups: list[dict[str, Any]],
        paths: list[dict[str, Any]],
    ) -> dict[str, Any]:
        relationship_ids, campaign_ids = path_ids(paths)
        return {
            "source_repository": source["repository"],
            "source_commit": source["commit"],
            "source_bundle_path": source["path"],
            "source_bundle_sha256": source["sha256"],
            "scope": group_software.SCOPE,
            "methodology_note": group_software.METHODOLOGY_NOTE,
            "software_stix_id": software["stix_id"],
            "group_stix_ids": [item["stix_id"] for item in groups],
            "campaign_stix_ids": campaign_ids,
            "relationship_stix_ids": relationship_ids,
            "direct_uses_relationship_stix_ids": sorted(
                path["direct_uses_relationship_stix_id"]
                for path in paths
                if path["path_type"] == "direct"
            ),
            "attributed_to_relationship_stix_ids": sorted(
                {
                    path["attributed_to_relationship_stix_id"]
                    for path in paths
                    if path["path_type"] == "campaign_attributed"
                }
            ),
            "campaign_uses_relationship_stix_ids": sorted(
                path["campaign_uses_relationship_stix_id"]
                for path in paths
                if path["path_type"] == "campaign_attributed"
            ),
            "relationship_paths": paths,
        }

    payload = generic_reverse_payload(
        payload,
        anchors=extracted["active_software_catalog"],
        candidates=extracted["groups"],
        paths=extracted["paths"],
        anchor_ref="software_ref",
        candidate_ref="group_ref",
        expected_key="expected_groups",
        anchor_key="software",
        queried_key="queried_group",
        aggregate_case="aggregate_software_groups",
        zero_case="aggregate_software_no_qualifying_groups",
        negative_case="negative_software_group",
        relationship_type="group_uses_software",
        aggregate_id=lambda item: f"software-used-by-groups-{item['external_id'].lower()}",
        negative_id=lambda a, c: (
            f"software-not-used-by-group-{a['external_id'].lower()}-"
            f"{c['external_id'].lower()}"
        ),
        question=lambda item: f"Which actors use {label(item)}?",
        positive_answer=lambda a, items: (
            f"{label(a)} is used by {natural_list([label(item) for item in items])} "
            "in the pinned Enterprise ATT&CK snapshot under the direct-plus-"
            "campaign scope."
        ),
        zero_answer=lambda item: (
            "No active direct or campaign-attributed group-to-software uses path "
            f"targets {label(item)} in the pinned Enterprise ATT&CK snapshot."
        ),
        negative_question=lambda a, c: f"Does {label(c)} use {label(a)}?",
        negative_answer=lambda a, c: (
            "No active direct or campaign-attributed uses path exists between "
            f"{label(c)} and {label(a)} in the pinned Enterprise ATT&CK snapshot."
        ),
        provenance_base=provenance,
        negative_count=SOFTWARE_GROUP_NEGATIVE_COUNT,
        direction="software_to_group",
    )
    adversarial = group_software_adversarial_negative_pairs(
        bundle, extracted, source, payload["pairs"]
    )
    return append_adversarial_negatives(
        payload,
        adversarial,
        method=(
            "pair a group with software used by a different group that shares "
            "a real direct-or-campaign-attributed technique"
        ),
    )


def group_campaign_payload(
    bundle: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    extracted = campaign_group.extract_campaign_group_scope(
        bundle, campaign_ids=None
    )
    payload = campaign_group.full_campaign_payload(extracted, source)

    def provenance(
        group: dict[str, Any],
        campaigns: list[dict[str, Any]],
        paths: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "source_repository": source["repository"],
            "source_commit": source["commit"],
            "source_bundle_path": source["path"],
            "source_bundle_sha256": source["sha256"],
            "scope": campaign_group.SCOPE,
            "methodology_note": campaign_group.METHODOLOGY_NOTE,
            "group_stix_id": group["stix_id"],
            "campaign_stix_ids": [item["stix_id"] for item in campaigns],
            "attributed_to_relationship_stix_ids": [
                path["attributed_to_relationship_stix_id"] for path in paths
            ],
            "relationship_paths": paths,
        }

    return generic_reverse_payload(
        payload,
        anchors=extracted["active_group_catalog"],
        candidates=extracted["campaigns"],
        paths=extracted["paths"],
        anchor_ref="group_ref",
        candidate_ref="campaign_ref",
        expected_key="expected_campaigns",
        anchor_key="group",
        queried_key="queried_campaign",
        aggregate_case="aggregate_group_campaigns",
        zero_case="aggregate_group_no_attributed_campaigns",
        negative_case="negative_group_campaign",
        relationship_type="campaign_attributed_to_group",
        aggregate_id=lambda item: f"group-attributed-campaigns-{item['external_id'].lower()}",
        negative_id=lambda a, c: (
            f"group-not-attributed-campaign-{a['external_id'].lower()}-"
            f"{c['external_id'].lower()}"
        ),
        question=lambda item: f"Which campaigns are attributed to {label(item)}?",
        positive_answer=lambda a, items: (
            f"{natural_list([label(item) for item in items])} "
            f"{'is' if len(items) == 1 else 'are'} attributed to {label(a)} in "
            "the pinned Enterprise ATT&CK snapshot."
        ),
        zero_answer=lambda item: (
            "No active campaign-to-group attributed-to relationship targets "
            f"{label(item)} in the pinned Enterprise ATT&CK snapshot."
        ),
        negative_question=lambda a, c: f"Is {label(c)} attributed to {label(a)}?",
        negative_answer=lambda a, c: (
            "No active attributed-to relationship exists from "
            f"{label(c)} to {label(a)} in the pinned Enterprise ATT&CK snapshot."
        ),
        provenance_base=provenance,
        negative_count=GROUP_CAMPAIGN_NEGATIVE_COUNT,
        direction="group_to_campaign",
    )


def write_artifact(
    path: Path,
    payload: dict[str, Any],
    original_pair_count: int,
) -> dict[str, Any]:
    assert_forward_prefix(path, payload["pairs"][:original_pair_count])
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "path": path.name,
        "original_pair_count": original_pair_count,
        "new_pair_count": len(payload["pairs"]) - original_pair_count,
        "total_pair_count": len(payload["pairs"]),
        "selection": payload["selection"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    jobs = [
        ("golden_set.json", mitigation_payload, 697),
        ("golden_set_technique_tactic.json", tactic_payload, 697),
        ("golden_set_group_technique.json", technique_group_payload, 194),
        ("golden_set_software_technique.json", technique_software_payload, 846),
        ("golden_set_group_software.json", software_group_payload, 194),
        ("golden_set_campaign_group.json", group_campaign_payload, 66),
    ]
    results = []
    for filename, builder, original_count in jobs:
        payload = builder(bundle, source)
        results.append(
            write_artifact(HERE / filename, payload, original_count)
        )
    print(json.dumps({"source": source, "artifacts": results}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReverseBackfillError as exc:
        raise SystemExit(f"FAIL: {exc}")
