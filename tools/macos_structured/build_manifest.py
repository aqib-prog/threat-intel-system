#!/usr/bin/env python3
"""Build the review-approved, parse-eligible macOS evaluation manifest."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path

from corpus import CorpusFormatError, read_macos_attack_file


HERE = Path(__file__).resolve().parent
DEFAULT_MAPPING = HERE / "manual_ground_truth_mapping.json"
DEFAULT_MANIFEST = HERE / "corpus_manifest.json"


def _commit(root: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def build_manifest(root: Path, mapping_path: Path) -> dict:
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    expected_commit = mapping["dataset"]["commit"]
    actual_commit = _commit(root)
    if actual_commit != expected_commit:
        raise RuntimeError(f"corpus commit {actual_commit} != {expected_commit}")

    cases = []
    excluded = []
    parse_inventory = Counter()
    for item in mapping["mappings"]:
        if item["decision"] != "mapping_candidate":
            continue
        path = root / item["file"]
        try:
            _text, details = read_macos_attack_file(path)
        except CorpusFormatError as exc:
            excluded.append(
                {
                    "capture": item["file"],
                    "reason": f"parse_eligibility: {exc}",
                }
            )
            continue
        parse_inventory.update(
            {
                "source_files": 1,
                "elastic_records": details["record_count"],
                "triple_quoted_string_repairs": details[
                    "triple_quoted_string_repairs"
                ],
                "trailing_comma_repairs": details["trailing_comma_repairs"],
                "missing_root_closure_repairs": details[
                    "missing_root_closure_repairs"
                ],
            }
        )
        cases.append(
            {
                "id": f"MACOS-ATTACK-{len(cases) + 1:03d}",
                "title": path.stem,
                "capture": item["file"],
                "reader": "macos_attack_dataset",
                "tactic": item["file"].split("/", 1)[0].casefold().replace(" ", "_"),
                "ground_truth": [technique["id"] for technique in item["techniques"]],
                "mapping_confidence": item["confidence"],
            }
        )

    return {
        "corpus_name": "sbousseaden/macOS-ATTACK-DATASET",
        "corpus_commit": expected_commit,
        "platform": "macos",
        "selection_policy": (
            "Use every review-approved mapping candidate that passes the deterministic "
            "macOS export parser. needs_review mappings and unparseable source files are "
            "listed but excluded from scoring. Selection occurs before detector results."
        ),
        "license_observation": (
            "The upstream README links GNU GPL v3. Corpus telemetry remains in the "
            "external pinned checkout and is not redistributed in this repository."
        ),
        "mapping_manifest": "tools/macos_structured/manual_ground_truth_mapping.json",
        "mapping_candidate_count": sum(
            item["decision"] == "mapping_candidate" for item in mapping["mappings"]
        ),
        "needs_review_count": sum(
            item["decision"] == "needs_review" for item in mapping["mappings"]
        ),
        "parse_inventory": dict(parse_inventory),
        "excluded": excluded,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-root", required=True, type=Path)
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING)
    parser.add_argument("--output", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    manifest = build_manifest(args.corpus_root, args.mapping)
    args.output.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "cases": len(manifest["cases"]),
                "excluded": len(manifest["excluded"]),
                "parse_inventory": manifest["parse_inventory"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
