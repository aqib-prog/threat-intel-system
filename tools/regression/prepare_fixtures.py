#!/usr/bin/env python3
"""Fetch the exact external checkouts required by the full regression gate."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SOURCES = {
    "sigma": (
        "https://github.com/SigmaHQ/sigma.git",
        "65b39fa48afc2739ed01df03ef61c68be995bb36",
    ),
    "falco": (
        "https://github.com/falcosecurity/plugins.git",
        "819918d43a743de78398d0a6ecb75305beeacaaa",
    ),
    "security-datasets": (
        "https://github.com/OTRF/Security-Datasets.git",
        "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
    ),
    "macos-attack-dataset": (
        "https://github.com/sbousseaden/macOS-ATTACK-DATASET.git",
        "0315ec88d1f4b338c07315223bc6a53619465472",
    ),
}


def run(command: list[str], *, cwd: Path | None = None, stdin: str | None = None) -> None:
    subprocess.run(command, cwd=cwd, input=stdin, text=True, check=True)


def clone(root: Path, name: str, sparse_paths: list[str] | None) -> Path:
    url, commit = SOURCES[name]
    destination = root / name
    if destination.exists():
        raise RuntimeError(f"destination already exists: {destination}")
    run(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(destination)])
    if sparse_paths:
        run(["git", "sparse-checkout", "init", "--no-cone"], cwd=destination)
        patterns = "\n".join(f"/{path}" for path in sparse_paths) + "\n"
        run(
            ["git", "sparse-checkout", "set", "--no-cone", "--stdin"],
            cwd=destination,
            stdin=patterns,
        )
    run(["git", "checkout", "--detach", commit], cwd=destination)
    return destination


def security_dataset_paths() -> list[str]:
    paths = {"LICENSE", "README.md"}
    for manifest_path in (
        REPO / "tools/security_datasets_baseline/corpus_manifest.json",
        REPO / "tools/linux_structured/corpus_manifest.json",
    ):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for case in manifest["cases"]:
            paths.update((case["metadata"], case["capture"]))
    return sorted(paths)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    sigma = clone(
        args.root,
        "sigma",
        ["rules/windows", "rules/linux", "rules/macos", "rules/cloud/aws/cloudtrail"],
    )
    falco = clone(
        args.root,
        "falco",
        [
            "plugins/k8saudit/rules/k8s_audit_rules.yaml",
            "plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml",
        ],
    )
    security = clone(args.root, "security-datasets", security_dataset_paths())
    macos = clone(args.root, "macos-attack-dataset", None)
    print(f"SIGMA_ROOT={sigma}")
    print(f"FALCO_ROOT={falco}")
    print(f"SECURITY_DATASETS_ROOT={security}")
    print(f"MACOS_ATTACK_DATASET_ROOT={macos}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
