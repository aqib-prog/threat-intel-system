#!/usr/bin/env python3
"""Generate a five-software direct technique-use golden-set prototype."""

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
SELECTED_SOFTWARE_IDS = ("S0002", "S0154", "S0367", "S0366", "S0266")
FOCUSED_TECHNIQUES = {
    "S0002": "T1003.001",
    "S0154": "T1059.001",
    "S0367": "T1053.005",
    "S0366": "T1486",
}
NEGATIVE_SOFTWARE_ID = "S0266"
NEGATIVE_TECHNIQUE_ID = "T1496"
FULL_NEGATIVE_EXISTENCE_CASE_COUNT = 25
FULL_NEGATIVE_PROBE_TECHNIQUE_IDS = (
    "T1496",
    "T1486",
    "T1649",
    "T1531",
    "T1003.001",
    "T1059.001",
    "T1566.001",
    "T1190",
    "T1583.001",
    "T1685",
)
SCOPE = "direct_software_to_technique_only"
METHODOLOGY_NOTE = (
    "Only active direct malware/tool --uses--> attack-pattern relationships are "
    "included. Group- or campaign-mediated paths are outside this relationship "
    "type. Parent and sub-technique objects remain distinct when each has its own "
    "qualifying relationship."
)


class SoftwareTechniqueParserError(RuntimeError):
    """Raised when the scoped software-to-technique STIX facts are invalid."""


def compact_software(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "stix_type": obj.get("type"),
        "platforms": list(obj.get("x_mitre_platforms", [])),
    }


def compact_technique(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "external_id": mitre_external_id(obj),
        "name": obj.get("name"),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
    }


def require_unique_external_ids(
    objects: list[dict[str, Any]], object_description: str
) -> dict[str, dict[str, Any]]:
    rows = [(mitre_external_id(obj), obj) for obj in objects]
    missing = [obj["id"] for external_id, obj in rows if external_id is None]
    if missing:
        raise SoftwareTechniqueParserError(
            f"active {object_description} objects lack MITRE external IDs: "
            + ", ".join(sorted(missing))
        )
    result = {external_id: obj for external_id, obj in rows if external_id}
    if len(result) != len(rows):
        raise SoftwareTechniqueParserError(
            f"active {object_description} objects have duplicate MITRE external IDs"
        )
    return result


def extract_software_technique_scope(
    bundle: dict[str, Any],
    software_ids: tuple[str, ...] | None = SELECTED_SOFTWARE_IDS,
) -> dict[str, Any]:
    """Extract direct active software-to-technique ``uses`` edges."""

    if software_ids is not None and len(software_ids) != len(set(software_ids)):
        raise SoftwareTechniqueParserError("selected software IDs are not unique")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise SoftwareTechniqueParserError("STIX bundle has no objects list")
    typed = [obj for obj in objects if isinstance(obj, dict)]

    software_catalog = require_unique_external_ids(
        [
            obj
            for obj in typed
            if obj.get("type") in {"malware", "tool"} and is_active(obj)
        ],
        "malware/tool",
    )
    if software_ids is None:
        selected_objects = [
            software_catalog[external_id]
            for external_id in sorted(software_catalog)
        ]
    else:
        missing = [
            external_id
            for external_id in software_ids
            if external_id not in software_catalog
        ]
        if missing:
            raise SoftwareTechniqueParserError(
                "selected active software objects are missing: "
                + ", ".join(missing)
            )
        selected_objects = [
            software_catalog[external_id] for external_id in software_ids
        ]
    selected_stix_ids = {obj["id"] for obj in selected_objects}

    active_technique_objects = [
        obj
        for obj in typed
        if obj.get("type") == "attack-pattern" and is_active(obj)
    ]
    technique_catalog = require_unique_external_ids(
        active_technique_objects, "attack-pattern"
    )
    technique_by_stix = {obj["id"]: obj for obj in active_technique_objects}

    all_uses = [
        obj
        for obj in typed
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "uses"
    ]
    direct_uses = [
        obj
        for obj in all_uses
        if is_active(obj)
        and obj.get("source_ref") in selected_stix_ids
        and obj.get("target_ref") in technique_by_stix
    ]
    direct_uses.sort(
        key=lambda rel: (
            mitre_external_id(technique_by_stix[rel["target_ref"]]) or "",
            rel["source_ref"],
            rel["id"],
        )
    )

    paths = [
        {
            "software_ref": rel["source_ref"],
            "technique_ref": rel["target_ref"],
            "uses_relationship_stix_id": rel["id"],
        }
        for rel in direct_uses
    ]
    if len({path["uses_relationship_stix_id"] for path in paths}) != len(paths):
        raise SoftwareTechniqueParserError("duplicate direct uses relationships")

    referenced_techniques = {path["technique_ref"] for path in paths}
    techniques = [
        compact_technique(obj)
        for obj in active_technique_objects
        if obj["id"] in referenced_techniques
    ]
    techniques.sort(key=lambda row: (row["external_id"] or "", row["stix_id"]))
    software = [compact_software(obj) for obj in selected_objects]

    counts = {}
    for item in software:
        counts[item["external_id"]] = len(
            {
                path["technique_ref"]
                for path in paths
                if path["software_ref"] == item["stix_id"]
            }
        )

    return {
        "software": software,
        "techniques": techniques,
        "active_technique_catalog": [
            compact_technique(technique_catalog[external_id])
            for external_id in sorted(technique_catalog)
        ],
        "paths": paths,
        "technique_counts_by_software": counts,
        "extraction_audit": {
            "bundle_uses_relationship_count": len(all_uses),
            "inactive_uses_relationship_count": sum(
                not is_active(rel) for rel in all_uses
            ),
            "qualifying_direct_path_count": len(paths),
        },
    }


def all_software_scope_summary(extracted: dict[str, Any]) -> dict[str, Any]:
    """Return Step-5a counts without generating golden-set records."""

    software_ids = {item["stix_id"] for item in extracted["software"]}
    pair_keys = {
        (path["software_ref"], path["technique_ref"])
        for path in extracted["paths"]
    }
    if len(pair_keys) != len(extracted["paths"]):
        raise SoftwareTechniqueParserError(
            "multiple relationships encode the same software/technique pair"
        )
    software_with_edges = {software_ref for software_ref, _ in pair_keys}
    return {
        "active_software_count": len(software_ids),
        "active_malware_count": sum(
            item["stix_type"] == "malware" for item in extracted["software"]
        ),
        "active_tool_count": sum(
            item["stix_type"] == "tool" for item in extracted["software"]
        ),
        "software_technique_pair_count": len(pair_keys),
        "software_with_at_least_one_technique": len(software_with_edges),
        "software_with_zero_techniques": len(software_ids - software_with_edges),
        "scope": SCOPE,
    }


def technique_label(technique: dict[str, Any]) -> str:
    return f"{technique['external_id']} ({technique['name']})"


def software_label(software: dict[str, Any]) -> str:
    return f"{software['external_id']} ({software['name']})"


def provenance(
    software: dict[str, Any],
    techniques: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    queried_technique: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "source_repository": source["repository"],
        "source_commit": source["commit"],
        "source_bundle_path": source["path"],
        "source_bundle_sha256": source["sha256"],
        "scope": SCOPE,
        "methodology_note": METHODOLOGY_NOTE,
        "software_stix_id": software["stix_id"],
        "technique_stix_ids": [item["stix_id"] for item in techniques],
        "uses_relationship_stix_ids": [
            path["uses_relationship_stix_id"] for path in paths
        ],
        "relationship_paths": paths,
    }
    if queried_technique is not None:
        result["queried_technique_stix_id"] = queried_technique["stix_id"]
    return result


def techniques_and_paths_for(
    software: dict[str, Any], extracted: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    techniques_by_stix = {
        technique["stix_id"]: technique for technique in extracted["techniques"]
    }
    paths = [
        path
        for path in extracted["paths"]
        if path["software_ref"] == software["stix_id"]
    ]
    technique_ids = sorted(
        {path["technique_ref"] for path in paths},
        key=lambda stix_id: (
            techniques_by_stix[stix_id]["external_id"] or "",
            stix_id,
        ),
    )
    return [techniques_by_stix[stix_id] for stix_id in technique_ids], paths


def generate_prototype_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    software_by_external = {
        item["external_id"]: item for item in extracted["software"]
    }
    active_techniques = {
        item["external_id"]: item
        for item in extracted["active_technique_catalog"]
    }
    pairs = []

    for software_id in SELECTED_SOFTWARE_IDS:
        software = software_by_external[software_id]
        techniques, paths = techniques_and_paths_for(software, extracted)
        if not techniques:
            raise SoftwareTechniqueParserError(
                f"selected software {software_id} has no direct technique edges"
            )
        labels = [technique_label(item) for item in techniques]
        pairs.append(
            {
                "id": f"software-uses-techniques-{software_id.lower()}",
                "case_type": "aggregate_software_techniques",
                "relationship_type": "software_uses_technique",
                "question": f"What techniques does {software['name']} use?",
                "expected_answer": (
                    f"{software_label(software)} directly uses {natural_list(labels)} "
                    "in the pinned Enterprise ATT&CK snapshot."
                ),
                "software": software,
                "expected_techniques": techniques,
                "provenance": provenance(software, techniques, paths, source),
            }
        )

    for software_id, technique_id in FOCUSED_TECHNIQUES.items():
        software = software_by_external[software_id]
        technique = active_techniques.get(technique_id)
        if technique is None:
            raise SoftwareTechniqueParserError(
                f"focused technique {technique_id} is not active"
            )
        _, software_paths = techniques_and_paths_for(software, extracted)
        matching = [
            path
            for path in software_paths
            if path["technique_ref"] == technique["stix_id"]
        ]
        if not matching:
            raise SoftwareTechniqueParserError(
                f"focused edge {software_id} -> {technique_id} does not exist"
            )
        label = technique_label(technique)
        pairs.append(
            {
                "id": f"software-uses-technique-{software_id.lower()}-{technique_id.lower()}",
                "case_type": "focused_software_technique",
                "relationship_type": "software_uses_technique",
                "question": f"Does {software['name']} use {label}?",
                "expected_answer": (
                    f"Yes. {software_label(software)} directly uses {label} in the "
                    "pinned Enterprise ATT&CK snapshot."
                ),
                "software": software,
                "expected_techniques": [technique],
                "provenance": provenance(
                    software,
                    [technique],
                    matching,
                    source,
                    queried_technique=technique,
                ),
            }
        )

    software = software_by_external[NEGATIVE_SOFTWARE_ID]
    technique = active_techniques.get(NEGATIVE_TECHNIQUE_ID)
    if technique is None:
        raise SoftwareTechniqueParserError(
            f"negative technique {NEGATIVE_TECHNIQUE_ID} is not active"
        )
    _, software_paths = techniques_and_paths_for(software, extracted)
    matching = [
        path
        for path in software_paths
        if path["technique_ref"] == technique["stix_id"]
    ]
    if matching:
        raise SoftwareTechniqueParserError(
            f"negative edge {NEGATIVE_SOFTWARE_ID} -> {NEGATIVE_TECHNIQUE_ID} exists"
        )
    label = technique_label(technique)
    pairs.append(
        {
            "id": (
                f"software-does-not-use-technique-{NEGATIVE_SOFTWARE_ID.lower()}-"
                f"{NEGATIVE_TECHNIQUE_ID.lower()}"
            ),
            "case_type": "negative_software_technique",
            "relationship_type": "software_uses_technique",
            "question": f"Does {software['name']} use {label}?",
            "expected_answer": (
                "No active direct uses relationship exists between "
                f"{software_label(software)} and {label} in the pinned Enterprise "
                "ATT&CK snapshot."
            ),
            "software": software,
            "queried_technique": technique,
            "expected_techniques": [],
            "provenance": provenance(
                software, [], [], source, queried_technique=technique
            ),
        }
    )
    if len(pairs) != 10:
        raise SoftwareTechniqueParserError(
            f"expected 10 prototype pairs, generated {len(pairs)}"
        )
    return pairs


def prototype_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    pairs = generate_prototype_pairs(extracted, source)
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_step_3a_software_technique_prototype",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_types": ["malware", "tool"],
            "target_type": "attack-pattern",
            "relationship_type": "uses",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "prototype_only": True,
        },
        "selection": {
            "software_external_ids": list(SELECTED_SOFTWARE_IDS),
            "software_count": len(SELECTED_SOFTWARE_IDS),
            "pair_count": len(pairs),
            "aggregate_pairs": sum(
                pair["case_type"] == "aggregate_software_techniques"
                for pair in pairs
            ),
            "focused_edge_pairs": sum(
                pair["case_type"] == "focused_software_technique"
                for pair in pairs
            ),
            "negative_edge_pairs": sum(
                pair["case_type"] == "negative_software_technique"
                for pair in pairs
            ),
        },
        "extraction": {
            "software": extracted["software"],
            "technique_counts_by_software": extracted[
                "technique_counts_by_software"
            ],
            "distinct_referenced_technique_count": len(extracted["techniques"]),
            "direct_path_count": len(extracted["paths"]),
            "inactive_filter_audit": extracted["extraction_audit"],
        },
        "pairs": pairs,
    }


def evenly_spaced_items(
    items: list[dict[str, Any]], count: int
) -> list[dict[str, Any]]:
    if count < 0 or count > len(items):
        raise SoftwareTechniqueParserError(
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
        raise SoftwareTechniqueParserError(
            "stratified software selection produced duplicates"
        )
    return [items[index] for index in indices]


def generate_full_aggregate_pairs(
    extracted: dict[str, Any], source: dict[str, Any]
) -> list[dict[str, Any]]:
    """Generate exactly one positive aggregate for every active software object."""

    pairs = []
    for software in extracted["software"]:
        techniques, paths = techniques_and_paths_for(software, extracted)
        if not techniques:
            raise SoftwareTechniqueParserError(
                f"active software {software['external_id']} has no technique edges"
            )
        labels = [technique_label(item) for item in techniques]
        pairs.append(
            {
                "id": f"software-uses-techniques-{software['external_id'].lower()}",
                "case_type": "aggregate_software_techniques",
                "relationship_type": "software_uses_technique",
                "question": f"What techniques does {software['name']} use?",
                "expected_answer": (
                    f"{software_label(software)} directly uses "
                    f"{natural_list(labels)} in the pinned Enterprise ATT&CK "
                    "snapshot."
                ),
                "software": software,
                "expected_techniques": techniques,
                "provenance": provenance(
                    software, techniques, paths, source
                ),
            }
        )
    return pairs


def select_full_negative_cases(
    extracted: dict[str, Any],
    *,
    count: int = FULL_NEGATIVE_EXISTENCE_CASE_COUNT,
) -> dict[str, str]:
    """Choose reproducible distinct-software direct non-edges."""

    software_by_external = {
        item["external_id"]: item for item in extracted["software"]
    }
    techniques_by_external = {
        item["external_id"]: item
        for item in extracted["active_technique_catalog"]
    }
    missing_probes = [
        external_id
        for external_id in FULL_NEGATIVE_PROBE_TECHNIQUE_IDS
        if external_id not in techniques_by_external
    ]
    if missing_probes:
        raise SoftwareTechniqueParserError(
            "negative probe techniques are not active: "
            + ", ".join(missing_probes)
        )
    selected = {NEGATIVE_SOFTWARE_ID: NEGATIVE_TECHNIQUE_ID}
    path_keys = {
        (path["software_ref"], path["technique_ref"])
        for path in extracted["paths"]
    }
    preserved_software = software_by_external[NEGATIVE_SOFTWARE_ID]
    preserved_technique = techniques_by_external[NEGATIVE_TECHNIQUE_ID]
    if (
        preserved_software["stix_id"], preserved_technique["stix_id"]
    ) in path_keys:
        raise SoftwareTechniqueParserError(
            "preserved prototype negative now has a direct path"
        )

    eligible = [
        item
        for item in extracted["software"]
        if item["external_id"] != NEGATIVE_SOFTWARE_ID
    ]
    additional = evenly_spaced_items(eligible, count - len(selected))
    for index, software in enumerate(additional):
        probes = (
            FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[index % len(FULL_NEGATIVE_PROBE_TECHNIQUE_IDS):]
            + FULL_NEGATIVE_PROBE_TECHNIQUE_IDS[:index % len(FULL_NEGATIVE_PROBE_TECHNIQUE_IDS)]
        )
        for technique_external_id in probes:
            technique = techniques_by_external[technique_external_id]
            if (software["stix_id"], technique["stix_id"]) not in path_keys:
                selected[software["external_id"]] = technique_external_id
                break
        else:
            raise SoftwareTechniqueParserError(
                f"no configured negative probe is absent for {software['external_id']}"
            )
    if len(selected) != count:
        raise SoftwareTechniqueParserError(
            f"expected {count} negative cases, selected {len(selected)}"
        )
    return selected


def generate_full_negative_pairs(
    extracted: dict[str, Any],
    source: dict[str, Any],
    negative_cases: dict[str, str],
) -> list[dict[str, Any]]:
    software_by_external = {
        item["external_id"]: item for item in extracted["software"]
    }
    techniques_by_external = {
        item["external_id"]: item
        for item in extracted["active_technique_catalog"]
    }
    path_keys = {
        (path["software_ref"], path["technique_ref"])
        for path in extracted["paths"]
    }
    pairs = []
    for software_external_id in sorted(negative_cases):
        technique_external_id = negative_cases[software_external_id]
        software = software_by_external[software_external_id]
        technique = techniques_by_external[technique_external_id]
        if (software["stix_id"], technique["stix_id"]) in path_keys:
            raise SoftwareTechniqueParserError(
                f"negative case {software_external_id} -> "
                f"{technique_external_id} has a direct path"
            )
        label = technique_label(technique)
        pairs.append(
            {
                "id": (
                    f"software-does-not-use-technique-{software_external_id.lower()}-"
                    f"{technique_external_id.lower()}"
                ),
                "case_type": "negative_software_technique",
                "relationship_type": "software_uses_technique",
                "question": f"Does {software['name']} use {label}?",
                "expected_answer": (
                    "No active direct uses relationship exists between "
                    f"{software_label(software)} and {label} in the pinned "
                    "Enterprise ATT&CK snapshot."
                ),
                "software": software,
                "queried_technique": technique,
                "expected_techniques": [],
                "provenance": provenance(
                    software, [], [], source, queried_technique=technique
                ),
            }
        )
    return pairs


def full_software_payload(
    extracted: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    aggregate_pairs = generate_full_aggregate_pairs(extracted, source)
    negative_cases = select_full_negative_cases(extracted)
    negative_pairs = generate_full_negative_pairs(
        extracted, source, negative_cases
    )
    pairs = aggregate_pairs + negative_pairs
    return {
        "schema_version": "1.0",
        "phase": "card6_part_b_step_5c_full_software_technique_golden_set",
        "source": source,
        "scope": {
            "domain": source["domain"],
            "source_types": ["malware", "tool"],
            "target_type": "attack-pattern",
            "relationship_type": "uses",
            "answer_scope": SCOPE,
            "methodology_note": METHODOLOGY_NOTE,
            "revoked_and_deprecated_excluded": True,
            "one_aggregate_pair_per_active_software": True,
        },
        "selection": {
            "active_software_count": len(extracted["software"]),
            "pair_count": len(pairs),
            "positive_aggregate_pairs": len(aggregate_pairs),
            "zero_path_aggregate_pairs": 0,
            "negative_existence_pairs": len(negative_pairs),
            "negative_existence_distinct_software_count": len(
                {pair["software"]["external_id"] for pair in negative_pairs}
            ),
            "embedded_software_technique_fact_count": sum(
                len(pair["expected_techniques"])
                for pair in aggregate_pairs
            ),
            "prototype_negative_preserved": (
                negative_cases.get(NEGATIVE_SOFTWARE_ID)
                == NEGATIVE_TECHNIQUE_ID
            ),
        },
        "negative_selection": {
            "method": (
                "preserve the verified prototype negative, then choose 24 "
                "evenly spaced active software objects and select an active "
                "probe technique having zero direct uses relationships"
            ),
            "all_cases_verified_absent_by_extracted_path_set": True,
        },
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--all-software-summary",
        action="store_true",
        help="print all-active-software extraction counts without writing pairs",
    )
    parser.add_argument(
        "--generate-all-software",
        action="store_true",
        help="write the full all-active-software golden set",
    )
    parser.add_argument(
        "--full-output",
        type=Path,
        default=HERE / "golden_set_software_technique.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "golden_set_software_technique_prototype.json",
    )
    args = parser.parse_args()
    if args.all_software_summary and args.generate_all_software:
        parser.error(
            "--all-software-summary and --generate-all-software are mutually exclusive"
        )
    bundle, source = load_pinned_bundle(
        args.stix_root.resolve(), args.manifest.resolve()
    )
    if args.all_software_summary:
        extracted = extract_software_technique_scope(bundle, software_ids=None)
        print(json.dumps(all_software_scope_summary(extracted), indent=2, sort_keys=True))
        return 0
    if args.generate_all_software:
        extracted = extract_software_technique_scope(bundle, software_ids=None)
        payload = full_software_payload(extracted, source)
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
    extracted = extract_software_technique_scope(bundle)
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
    except SoftwareTechniqueParserError as exc:
        raise SystemExit(f"FAIL: {exc}")
