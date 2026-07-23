"""Load reviewed, offline-compiled rules as dependency-free runtime data."""

from __future__ import annotations

import gzip
import json
from functools import lru_cache
from pathlib import Path
from typing import Any


GENERATED_DIR = Path(__file__).resolve().parent / "generated"
EXPECTED_SCHEMA_VERSION = 1
EXPECTED_SIGMA_COMMIT = "65b39fa48afc2739ed01df03ef61c68be995bb36"
EXPECTED_FALCO_COMMIT = "819918d43a743de78398d0a6ecb75305beeacaaa"
RUNTIME_BUNDLES = {
    "windows": GENERATED_DIR / "windows_sigma_rules.json.gz",
    "linux": GENERATED_DIR / "linux_sigma_rules.json.gz",
    "macos": GENERATED_DIR / "macos_sigma_rules.json.gz",
    "aws": GENERATED_DIR / "aws_falco_rules.json.gz",
    "kubernetes": GENERATED_DIR / "kubernetes_falco_rules.json.gz",
}
EXPECTED_PROVENANCE = {
    "windows": {"sigma_commit": EXPECTED_SIGMA_COMMIT},
    "linux": {"sigma_commit": EXPECTED_SIGMA_COMMIT},
    "macos": {"sigma_commit": EXPECTED_SIGMA_COMMIT},
    "aws": {"falco_commit": EXPECTED_FALCO_COMMIT},
    "kubernetes": {"falco_commit": EXPECTED_FALCO_COMMIT},
}


class RuntimeRuleArtifactError(RuntimeError):
    pass


@lru_cache(maxsize=None)
def load_runtime_rule_bundle(platform: str) -> dict[str, Any]:
    path = RUNTIME_BUNDLES.get(platform)
    if path is None:
        raise RuntimeRuleArtifactError(f"no compiled runtime bundle for {platform!r}")
    try:
        payload = json.loads(gzip.decompress(path.read_bytes()))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeRuleArtifactError(f"invalid compiled rule bundle: {path}") from exc

    expected = {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "platform": platform,
        "decision_policy": "mapping_candidate_only",
    } | EXPECTED_PROVENANCE[platform]
    for key, value in expected.items():
        if payload.get(key) != value:
            raise RuntimeRuleArtifactError(
                f"{path.name}: {key}={payload.get(key)!r}, expected {value!r}"
            )
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RuntimeRuleArtifactError(f"{path.name}: rules must be a non-empty list")
    return payload


def load_runtime_rule_records(platform: str) -> tuple[dict[str, Any], ...]:
    return tuple(load_runtime_rule_bundle(platform)["rules"])
