#!/usr/bin/env python3
"""Extract mitigation facts from pinned Enterprise ATT&CK STIX.

The Phase-1 Persistence prototype remains available for reproducing its ten
golden pairs. Step 2a adds an all-Enterprise extraction path for active
techniques, their embedded technique-to-tactic links, and active ``mitigates``
relationships. No other STIX relationship type is parsed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "source_manifest.json"
SOURCE_KEY = "enterprise_attack_stix"
PERSISTENCE_PHASE = "persistence"
MITRE_KILL_CHAIN = "mitre-attack"
PROTOTYPE_TECHNIQUE_IDS = (
    # Five single-mitigation cases.
    "T1037.001",  # Windows logon script
    "T1112",      # Registry modification
    "T1205.001",  # Network signaling
    "T1543.001",  # macOS launch agent
    "T1653",      # Power settings
    # Five multi-mitigation cases.
    "T1037",      # Two mitigations; parent of the first case
    "T1053",      # Scheduled task/job
    "T1078",      # Valid accounts
    "T1098.003",  # Cloud roles
    "T1543.003",  # Windows service
)
TACTIC_PROTOTYPE_TECHNIQUE_IDS = (
    # Five single-tactic techniques spanning distinct tactic domains.
    "T1001",      # Command and Control
    "T1005",      # Collection
    "T1059.004",  # Execution
    "T1491",      # Impact
    "T1583.007",  # Resource Development
    # Five multi-tactic techniques with two to four memberships.
    "T1053",      # Execution, Persistence, Privilege Escalation
    "T1078",      # Initial Access, Persistence, Privilege Escalation, Stealth
    "T1197",      # Execution, Persistence, Stealth
    "T1205",      # Persistence, Stealth, Command and Control
    "T1556",      # Persistence, Credential Access, Defense Impairment
)


class PersistenceParserError(RuntimeError):
    """Raised when source provenance or the scoped STIX shape is invalid."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_output(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise PersistenceParserError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def load_pinned_bundle(stix_root: Path, manifest_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest.get(SOURCE_KEY)
    if not isinstance(entry, dict):
        raise PersistenceParserError(f"manifest is missing {SOURCE_KEY!r}")

    actual_commit = git_output(stix_root, "rev-parse", "HEAD")
    if actual_commit != entry.get("commit"):
        raise PersistenceParserError(
            f"source commit {actual_commit}, expected {entry.get('commit')}"
        )
    if git_output(stix_root, "status", "--porcelain"):
        raise PersistenceParserError("source checkout is dirty")

    bundle_path = stix_root / str(entry.get("path", ""))
    if not bundle_path.is_file():
        raise PersistenceParserError(f"bundle does not exist: {bundle_path}")
    actual_hash = sha256(bundle_path)
    if actual_hash != entry.get("sha256"):
        raise PersistenceParserError(
            f"bundle SHA256 {actual_hash}, expected {entry.get('sha256')}"
        )

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise PersistenceParserError("Enterprise source is not a STIX bundle")
    if not isinstance(bundle.get("objects"), list):
        raise PersistenceParserError("STIX bundle has no objects list")
    return bundle, entry


def is_active(obj: dict[str, Any]) -> bool:
    return not bool(obj.get("revoked")) and not bool(obj.get("x_mitre_deprecated"))


def mitre_external_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        if (
            isinstance(reference, dict)
            and reference.get("source_name") == "mitre-attack"
            and isinstance(reference.get("external_id"), str)
        ):
            return reference["external_id"]
    return None


def persistence_phase_links(obj: dict[str, Any]) -> list[dict[str, str]]:
    return [
        phase
        for phase in obj.get("kill_chain_phases", [])
        if isinstance(phase, dict)
        and phase.get("kill_chain_name") == MITRE_KILL_CHAIN
        and phase.get("phase_name") == PERSISTENCE_PHASE
    ]


def enterprise_phase_links(obj: dict[str, Any]) -> list[dict[str, str]]:
    """Return all Enterprise ATT&CK tactic memberships embedded on an object."""

    return [
        phase
        for phase in obj.get("kill_chain_phases", [])
        if isinstance(phase, dict)
        and phase.get("kill_chain_name") == MITRE_KILL_CHAIN
        and isinstance(phase.get("phase_name"), str)
    ]


def extract_persistence_scope(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return only the Step-1b object and relationship scope."""

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise PersistenceParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]

    tactics = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-tactic"
        and obj.get("x_mitre_shortname") == PERSISTENCE_PHASE
        and is_active(obj)
    ]
    if len(tactics) != 1:
        raise PersistenceParserError(
            f"expected one active Persistence tactic, found {len(tactics)}"
        )
    tactic_obj = tactics[0]
    tactic = {
        "stix_id": tactic_obj["id"],
        "external_id": mitre_external_id(tactic_obj),
        "name": tactic_obj.get("name"),
        "shortname": tactic_obj.get("x_mitre_shortname"),
    }

    technique_objects = [
        obj
        for obj in typed
        if obj.get("type") == "attack-pattern"
        and is_active(obj)
        and persistence_phase_links(obj)
    ]
    technique_objects.sort(key=lambda obj: (mitre_external_id(obj) or "", obj["id"]))
    technique_ids = {obj["id"] for obj in technique_objects}

    mitigation_by_id = {
        obj["id"]: obj
        for obj in typed
        if obj.get("type") == "course-of-action" and is_active(obj)
    }
    relationship_objects = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "mitigates"
        and obj.get("target_ref") in technique_ids
        and obj.get("source_ref") in mitigation_by_id
        and is_active(obj)
    ]
    relationship_objects.sort(key=lambda obj: obj["id"])
    referenced_mitigation_ids = {obj["source_ref"] for obj in relationship_objects}

    techniques = [
        {
            "stix_id": obj["id"],
            "external_id": mitre_external_id(obj),
            "name": obj.get("name"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
        }
        for obj in technique_objects
    ]
    mitigations = [
        {
            "stix_id": obj["id"],
            "external_id": mitre_external_id(obj),
            "name": obj.get("name"),
        }
        for obj in mitigation_by_id.values()
        if obj["id"] in referenced_mitigation_ids
    ]
    mitigations.sort(key=lambda obj: (obj["external_id"] or "", obj["stix_id"]))
    mitigates_relationships = [
        {
            "stix_id": obj["id"],
            "relationship_type": "mitigates",
            "mitigation_ref": obj["source_ref"],
            "technique_ref": obj["target_ref"],
        }
        for obj in relationship_objects
    ]
    technique_tactic_links = [
        {
            "technique_ref": obj["id"],
            "tactic_ref": tactic_obj["id"],
            "kill_chain_name": link["kill_chain_name"],
            "phase_name": link["phase_name"],
        }
        for obj in technique_objects
        for link in persistence_phase_links(obj)
    ]

    return {
        "tactic": tactic,
        "techniques": techniques,
        "mitigations": mitigations,
        "mitigates_relationships": mitigates_relationships,
        "technique_tactic_links": technique_tactic_links,
    }


def extract_enterprise_mitigation_scope(bundle: dict[str, Any]) -> dict[str, Any]:
    """Extract Step-2a mitigation facts for every active Enterprise technique.

    Techniques are keyed by their STIX object, not by tactic membership. Each
    technique therefore occurs exactly once and carries every active tactic
    referenced by its embedded ``kill_chain_phases``. Techniques without an
    active mitigation relationship remain in the result as negative cases.
    """

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise PersistenceParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]

    tactic_objects = [
        obj
        for obj in typed
        if obj.get("type") == "x-mitre-tactic"
        and is_active(obj)
        and isinstance(obj.get("x_mitre_shortname"), str)
    ]
    tactic_by_shortname: dict[str, dict[str, Any]] = {}
    for tactic in tactic_objects:
        shortname = tactic["x_mitre_shortname"]
        if shortname in tactic_by_shortname:
            raise PersistenceParserError(
                f"multiple active tactics use shortname {shortname!r}"
            )
        tactic_by_shortname[shortname] = tactic

    tactics = [
        {
            "stix_id": obj["id"],
            "external_id": mitre_external_id(obj),
            "name": obj.get("name"),
            "shortname": obj["x_mitre_shortname"],
        }
        for obj in tactic_objects
    ]
    tactics.sort(key=lambda obj: (obj["external_id"] or "", obj["stix_id"]))
    tactic_record_by_shortname = {row["shortname"]: row for row in tactics}

    technique_objects = [
        obj
        for obj in typed
        if obj.get("type") == "attack-pattern" and is_active(obj)
    ]
    technique_objects.sort(key=lambda obj: (mitre_external_id(obj) or "", obj["id"]))
    technique_ids = {obj["id"] for obj in technique_objects}
    if len(technique_ids) != len(technique_objects):
        raise PersistenceParserError("active technique STIX IDs are not unique")
    external_ids = [mitre_external_id(obj) for obj in technique_objects]
    if any(external_id is None for external_id in external_ids):
        raise PersistenceParserError("active technique is missing a MITRE external ID")
    if len(set(external_ids)) != len(external_ids):
        raise PersistenceParserError("active technique external IDs are not unique")

    mitigation_by_id = {
        obj["id"]: obj
        for obj in typed
        if obj.get("type") == "course-of-action" and is_active(obj)
    }
    relationship_objects = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "mitigates"
        and obj.get("target_ref") in technique_ids
        and obj.get("source_ref") in mitigation_by_id
        and is_active(obj)
    ]
    relationship_objects.sort(key=lambda obj: obj["id"])
    referenced_mitigation_ids = {obj["source_ref"] for obj in relationship_objects}
    relationship_counts: dict[str, int] = {}
    for relationship in relationship_objects:
        technique_ref = relationship["target_ref"]
        relationship_counts[technique_ref] = relationship_counts.get(technique_ref, 0) + 1

    technique_tactics: dict[str, list[dict[str, Any]]] = {}
    technique_tactic_links: list[dict[str, str]] = []
    for technique in technique_objects:
        seen_shortnames: set[str] = set()
        memberships: list[dict[str, Any]] = []
        for phase in enterprise_phase_links(technique):
            shortname = phase["phase_name"]
            if shortname in seen_shortnames:
                continue
            seen_shortnames.add(shortname)
            tactic_obj = tactic_by_shortname.get(shortname)
            tactic_record = tactic_record_by_shortname.get(shortname)
            if tactic_obj is None or tactic_record is None:
                raise PersistenceParserError(
                    f"technique {technique['id']} references unknown active tactic "
                    f"{shortname!r}"
                )
            memberships.append(tactic_record)
            technique_tactic_links.append(
                {
                    "technique_ref": technique["id"],
                    "tactic_ref": tactic_obj["id"],
                    "kill_chain_name": phase["kill_chain_name"],
                    "phase_name": shortname,
                }
            )
        memberships.sort(key=lambda row: (row["external_id"] or "", row["stix_id"]))
        technique_tactics[technique["id"]] = memberships

    techniques = []
    for obj in technique_objects:
        mitigation_count = relationship_counts.get(obj["id"], 0)
        techniques.append(
            {
                "stix_id": obj["id"],
                "external_id": mitre_external_id(obj),
                "name": obj.get("name"),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "tactics": technique_tactics[obj["id"]],
                "mitigation_relationship_count": mitigation_count,
                "mitigation_status": (
                    "has_mitigations" if mitigation_count else "zero_mitigations"
                ),
                "is_negative_case": mitigation_count == 0,
            }
        )

    mitigations = [
        {
            "stix_id": obj["id"],
            "external_id": mitre_external_id(obj),
            "name": obj.get("name"),
        }
        for obj in mitigation_by_id.values()
        if obj["id"] in referenced_mitigation_ids
    ]
    mitigations.sort(key=lambda obj: (obj["external_id"] or "", obj["stix_id"]))
    mitigates_relationships = [
        {
            "stix_id": obj["id"],
            "relationship_type": "mitigates",
            "mitigation_ref": obj["source_ref"],
            "technique_ref": obj["target_ref"],
        }
        for obj in relationship_objects
    ]
    technique_tactic_links.sort(
        key=lambda row: (row["technique_ref"], row["tactic_ref"])
    )

    return {
        "tactics": tactics,
        "techniques": techniques,
        "mitigations": mitigations,
        "mitigates_relationships": mitigates_relationships,
        "technique_tactic_links": technique_tactic_links,
    }


def enterprise_extraction_summary(extracted: dict[str, Any]) -> dict[str, int]:
    """Return only the Step-2a checkpoint counts."""

    techniques = extracted["techniques"]
    with_mitigations = sum(
        technique["mitigation_status"] == "has_mitigations"
        for technique in techniques
    )
    return {
        "active_techniques": len(techniques),
        "mitigation_edges": len(extracted["mitigates_relationships"]),
        "distinct_mitigations_referenced": len(extracted["mitigations"]),
        "techniques_with_mitigations": with_mitigations,
        "techniques_with_zero_mitigations": len(techniques) - with_mitigations,
        "techniques_with_multiple_tactics": sum(
            len(technique["tactics"]) > 1 for technique in techniques
        ),
    }


def extraction_summary(extracted: dict[str, Any], example_count: int = 3) -> dict[str, Any]:
    relationships = extracted["mitigates_relationships"]
    mitigation_counts: dict[str, int] = {}
    for relationship in relationships:
        technique_ref = relationship["technique_ref"]
        mitigation_counts[technique_ref] = mitigation_counts.get(technique_ref, 0) + 1
    examples = [
        {
            "external_id": technique["external_id"],
            "name": technique["name"],
            "stix_id": technique["stix_id"],
            "mitigation_relationship_count": mitigation_counts.get(technique["stix_id"], 0),
        }
        for technique in extracted["techniques"][:example_count]
    ]
    techniques_with_mitigations = sum(
        technique["stix_id"] in mitigation_counts
        for technique in extracted["techniques"]
    )
    return {
        "tactic": extracted["tactic"],
        "counts": {
            "persistence_techniques": len(extracted["techniques"]),
            "techniques_with_mitigations": techniques_with_mitigations,
            "techniques_without_mitigations": (
                len(extracted["techniques"]) - techniques_with_mitigations
            ),
            "technique_tactic_links": len(extracted["technique_tactic_links"]),
            "mitigates_relationships": len(relationships),
            "referenced_mitigations": len(extracted["mitigations"]),
        },
        "example_techniques": examples,
        "example_mitigations": extracted["mitigations"][:example_count],
    }


def mitigation_label(mitigation: dict[str, Any]) -> str:
    return f"{mitigation['external_id']} ({mitigation['name']})"


def natural_list(values: list[str]) -> str:
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return f"{', '.join(values[:-1])}, and {values[-1]}"


def generate_prototype_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    technique_ids: tuple[str, ...] = PROTOTYPE_TECHNIQUE_IDS,
) -> list[dict[str, Any]]:
    """Generate deterministic questions from the scoped STIX facts only."""

    if len(technique_ids) != len(set(technique_ids)):
        raise PersistenceParserError("prototype technique IDs are not unique")
    techniques = {row["external_id"]: row for row in extracted["techniques"]}
    mitigations = {row["stix_id"]: row for row in extracted["mitigations"]}
    relationships_by_technique: dict[str, list[dict[str, Any]]] = {}
    for relationship in extracted["mitigates_relationships"]:
        relationships_by_technique.setdefault(
            relationship["technique_ref"], []
        ).append(relationship)

    pairs = []
    for external_id in technique_ids:
        technique = techniques.get(external_id)
        if technique is None:
            raise PersistenceParserError(
                f"prototype technique {external_id} is absent from Persistence"
            )
        relationships = relationships_by_technique.get(technique["stix_id"], [])
        if not relationships:
            raise PersistenceParserError(
                f"prototype technique {external_id} has no active mitigation"
            )
        if len({row["mitigation_ref"] for row in relationships}) != len(relationships):
            raise PersistenceParserError(
                f"prototype technique {external_id} has duplicate mitigation edges"
            )
        relationships.sort(
            key=lambda row: (
                mitigations[row["mitigation_ref"]]["external_id"] or "",
                row["stix_id"],
            )
        )
        expected_mitigations = [
            mitigations[relationship["mitigation_ref"]]
            for relationship in relationships
        ]
        technique_label = f"{external_id} ({technique['name']})"
        answer = (
            f"{technique_label} is mitigated by "
            f"{natural_list([mitigation_label(row) for row in expected_mitigations])}."
        )
        pairs.append(
            {
                "id": f"persistence-mitigations-{external_id.lower()}",
                "relationship_type": "technique_to_mitigation",
                "question": f"What mitigates {technique_label}?",
                "expected_answer": answer,
                "expected_mitigations": [
                    {
                        "external_id": row["external_id"],
                        "name": row["name"],
                        "stix_id": row["stix_id"],
                    }
                    for row in expected_mitigations
                ],
                "provenance": {
                    "repository": source["repository"],
                    "stix_commit": source["commit"],
                    "bundle_path": source["path"],
                    "bundle_sha256": source["sha256"],
                    "tactic_stix_id": extracted["tactic"]["stix_id"],
                    "technique_stix_id": technique["stix_id"],
                    "mitigation_stix_ids": [
                        row["stix_id"] for row in expected_mitigations
                    ],
                    "relationship_stix_ids": [
                        row["stix_id"] for row in relationships
                    ],
                    "mitigates_edges": [
                        {
                            "relationship_stix_id": relationship["stix_id"],
                            "mitigation_stix_id": relationship["mitigation_ref"],
                            "technique_stix_id": relationship["technique_ref"],
                        }
                        for relationship in relationships
                    ],
                },
            }
        )
    return pairs


def phase1_golden_set_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    single_count = sum(len(pair["expected_mitigations"]) == 1 for pair in pairs)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_phase_1_persistence_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "tactic": extracted["tactic"],
            "relationship_type": "technique_to_mitigation",
            "revoked_and_deprecated_excluded": True,
        },
        "selection": {
            "method": "fixed_representative_ids_resolved_from_pinned_stix",
            "pair_count": len(pairs),
            "single_mitigation_pairs": single_count,
            "multiple_mitigation_pairs": len(pairs) - single_count,
        },
        "pairs": pairs,
    }


def generate_enterprise_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    """Generate one deterministic mitigation pair per active technique."""

    mitigations = {row["stix_id"]: row for row in extracted["mitigations"]}
    relationships_by_technique: dict[str, list[dict[str, Any]]] = {}
    for relationship in extracted["mitigates_relationships"]:
        relationships_by_technique.setdefault(
            relationship["technique_ref"], []
        ).append(relationship)

    pairs = []
    for technique in extracted["techniques"]:
        relationships = relationships_by_technique.get(technique["stix_id"], [])
        relationships.sort(
            key=lambda row: (
                mitigations[row["mitigation_ref"]]["external_id"] or "",
                row["stix_id"],
            )
        )
        if len({row["mitigation_ref"] for row in relationships}) != len(relationships):
            raise PersistenceParserError(
                f"technique {technique['external_id']} has duplicate mitigation edges"
            )
        if technique["mitigation_relationship_count"] != len(relationships):
            raise PersistenceParserError(
                f"technique {technique['external_id']} mitigation count is inconsistent"
            )

        expected_mitigations = [
            mitigations[relationship["mitigation_ref"]]
            for relationship in relationships
        ]
        external_id = technique["external_id"]
        technique_label = f"{external_id} ({technique['name']})"
        if expected_mitigations:
            case_type = "positive"
            answer = (
                f"{technique_label} is mitigated by "
                f"{natural_list([mitigation_label(row) for row in expected_mitigations])}."
            )
        else:
            case_type = "negative"
            answer = (
                f"No active mitigation relationship exists for {technique_label} "
                "in the pinned Enterprise ATT&CK snapshot."
            )

        expected_status = (
            "has_mitigations" if case_type == "positive" else "zero_mitigations"
        )
        if technique["mitigation_status"] != expected_status:
            raise PersistenceParserError(
                f"technique {external_id} mitigation status is inconsistent"
            )
        if technique["is_negative_case"] != (case_type == "negative"):
            raise PersistenceParserError(
                f"technique {external_id} negative-case flag is inconsistent"
            )

        pairs.append(
            {
                "id": f"enterprise-mitigations-{external_id.lower()}",
                "case_type": case_type,
                "relationship_type": "technique_to_mitigation",
                "question": f"What mitigates {technique_label}?",
                "expected_answer": answer,
                "expected_mitigations": [
                    {
                        "external_id": row["external_id"],
                        "name": row["name"],
                        "stix_id": row["stix_id"],
                    }
                    for row in expected_mitigations
                ],
                "provenance": {
                    "repository": source["repository"],
                    "stix_commit": source["commit"],
                    "bundle_path": source["path"],
                    "bundle_sha256": source["sha256"],
                    "technique_stix_id": technique["stix_id"],
                    "tactic_stix_ids": [
                        tactic["stix_id"] for tactic in technique["tactics"]
                    ],
                    "tactics": [
                        {
                            "external_id": tactic["external_id"],
                            "name": tactic["name"],
                            "shortname": tactic["shortname"],
                            "stix_id": tactic["stix_id"],
                        }
                        for tactic in technique["tactics"]
                    ],
                    "mitigation_stix_ids": [
                        row["stix_id"] for row in expected_mitigations
                    ],
                    "relationship_stix_ids": [
                        row["stix_id"] for row in relationships
                    ],
                    "mitigates_edges": [
                        {
                            "relationship_stix_id": relationship["stix_id"],
                            "mitigation_stix_id": relationship["mitigation_ref"],
                            "technique_stix_id": relationship["technique_ref"],
                        }
                        for relationship in relationships
                    ],
                },
            }
        )
    return pairs


def enterprise_golden_set_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_enterprise_pairs(extracted, source)
    positive_count = sum(pair["case_type"] == "positive" for pair in pairs)
    return {
        "schema_version": "2.0",
        "phase": "card6_part_b_phase_2_enterprise_mitigations",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "techniques": "all_active_enterprise_attack_patterns",
            "relationship_type": "technique_to_mitigation",
            "revoked_and_deprecated_excluded": True,
            "technique_level_deduplication": True,
            "all_tactic_memberships_in_provenance": True,
            "zero_mitigation_techniques_included": True,
        },
        "selection": {
            "method": "one_pair_per_active_enterprise_technique",
            "pair_count": len(pairs),
            "positive_case_count": positive_count,
            "negative_case_count": len(pairs) - positive_count,
        },
        "phase_1_fixture": {
            "path": "golden_set_phase1_fixture.json",
            "verified_technique_external_ids": list(PROTOTYPE_TECHNIQUE_IDS),
        },
        "pairs": pairs,
    }


def tactic_label(tactic: dict[str, Any]) -> str:
    return f"{tactic['external_id']} ({tactic['name']})"


def generate_tactic_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    technique_ids: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Generate technique-to-tactic pairs from embedded phase memberships."""

    if len(technique_ids) != len(set(technique_ids)):
        raise PersistenceParserError("tactic prototype technique IDs are not unique")
    techniques = {row["external_id"]: row for row in extracted["techniques"]}

    pairs = []
    for external_id in technique_ids:
        technique = techniques.get(external_id)
        if technique is None:
            raise PersistenceParserError(
                f"tactic prototype technique {external_id} is absent"
            )
        tactics = technique["tactics"]
        if not tactics:
            raise PersistenceParserError(
                f"tactic prototype technique {external_id} has no tactic membership"
            )

        technique_label = f"{external_id} ({technique['name']})"
        expected_tactics = [
            {
                "external_id": tactic["external_id"],
                "name": tactic["name"],
                "shortname": tactic["shortname"],
                "stix_id": tactic["stix_id"],
            }
            for tactic in tactics
        ]
        labels = [tactic_label(tactic) for tactic in expected_tactics]
        if len(labels) == 1:
            answer = f"{technique_label} belongs to the {labels[0]} tactic."
            case_type = "single_tactic"
        else:
            answer = (
                f"{technique_label} belongs to the {natural_list(labels)} tactics."
            )
            case_type = "multi_tactic"

        pairs.append(
            {
                "id": f"enterprise-tactics-{external_id.lower()}",
                "case_type": case_type,
                "relationship_type": "technique_to_tactic",
                "question": f"Which tactics does {technique_label} belong to?",
                "expected_answer": answer,
                "expected_tactics": expected_tactics,
                "provenance": {
                    "repository": source["repository"],
                    "stix_commit": source["commit"],
                    "bundle_path": source["path"],
                    "bundle_sha256": source["sha256"],
                    "technique_stix_id": technique["stix_id"],
                    "tactic_stix_ids": [
                        tactic["stix_id"] for tactic in expected_tactics
                    ],
                    "link_source": "attack-pattern.kill_chain_phases",
                    "technique_tactic_links": [
                        {
                            "kill_chain_name": MITRE_KILL_CHAIN,
                            "phase_name": tactic["shortname"],
                            "tactic_stix_id": tactic["stix_id"],
                            "technique_stix_id": technique["stix_id"],
                        }
                        for tactic in expected_tactics
                    ],
                },
            }
        )
    return pairs


def generate_tactic_prototype_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    technique_ids: tuple[str, ...] = TACTIC_PROTOTYPE_TECHNIQUE_IDS,
) -> list[dict[str, Any]]:
    """Generate the fixed, live-verified technique-to-tactic prototype."""

    return generate_tactic_pairs(extracted, source, technique_ids)


def generate_enterprise_tactic_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    """Generate exactly one tactic pair per active Enterprise technique."""

    technique_ids = tuple(
        technique["external_id"] for technique in extracted["techniques"]
    )
    return generate_tactic_pairs(extracted, source, technique_ids)


def tactic_prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_tactic_prototype_pairs(extracted, source)
    single_count = sum(pair["case_type"] == "single_tactic" for pair in pairs)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_phase_2_technique_tactic_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "relationship_type": "technique_to_tactic",
            "link_source": "attack-pattern.kill_chain_phases",
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "method": "fixed_representative_ids_resolved_from_pinned_stix",
            "pair_count": len(pairs),
            "single_tactic_pairs": single_count,
            "multi_tactic_pairs": len(pairs) - single_count,
            "technique_external_ids": list(TACTIC_PROTOTYPE_TECHNIQUE_IDS),
        },
        "pairs": pairs,
    }


def enterprise_tactic_golden_set_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_enterprise_tactic_pairs(extracted, source)
    single_count = sum(pair["case_type"] == "single_tactic" for pair in pairs)
    return {
        "schema_version": "2.0",
        "phase": "card6_part_b_phase_2_enterprise_technique_tactics",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "techniques": "all_active_enterprise_attack_patterns",
            "relationship_type": "technique_to_tactic",
            "link_source": "attack-pattern.kill_chain_phases",
            "revoked_and_deprecated_excluded": True,
            "technique_level_deduplication": True,
            "all_tactic_memberships_in_expected_answer": True,
        },
        "selection": {
            "method": "one_pair_per_active_enterprise_technique",
            "pair_count": len(pairs),
            "single_tactic_pairs": single_count,
            "multi_tactic_pairs": len(pairs) - single_count,
        },
        "prototype_fixture": {
            "path": "golden_set_technique_tactic_prototype.json",
            "verified_technique_external_ids": list(
                TACTIC_PROTOTYPE_TECHNIQUE_IDS
            ),
        },
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--artifact",
        choices=(
            "enterprise-mitigations",
            "enterprise-tactics",
            "tactic-prototype",
        ),
        default="enterprise-mitigations",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    extracted = extract_enterprise_mitigation_scope(bundle)
    summary = enterprise_extraction_summary(extracted)
    if args.artifact == "tactic-prototype":
        artifact = tactic_prototype_payload(extracted, source)
        output = args.output or HERE / "golden_set_technique_tactic_prototype.json"
    elif args.artifact == "enterprise-tactics":
        artifact = enterprise_tactic_golden_set_payload(extracted, source)
        output = args.output or HERE / "golden_set_technique_tactic.json"
    else:
        artifact = enterprise_golden_set_payload(extracted, source)
        output = args.output or HERE / "golden_set.json"
    output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "source": source,
                "extraction": summary,
                "artifact": {
                    "type": args.artifact,
                    "output": str(output),
                    "selection": artifact["selection"],
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
    except PersistenceParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
