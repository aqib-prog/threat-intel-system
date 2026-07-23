#!/usr/bin/env python3
"""Permanent Card 5 Layer-4 regression gate.

``artifacts`` is deterministic and network-free. ``full`` additionally
reproduces generated compiler artifacts and all measurable corpus metrics from
pinned external checkouts; CI always uses ``full`` so fixture tests cannot be
silently skipped there.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PYTHON = sys.executable
PINNED = {
    "SIGMA_ROOT": "65b39fa48afc2739ed01df03ef61c68be995bb36",
    "FALCO_ROOT": "819918d43a743de78398d0a6ecb75305beeacaaa",
    "SECURITY_DATASETS_ROOT": "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
    "MACOS_ATTACK_DATASET_ROOT": "0315ec88d1f4b338c07315223bc6a53619465472",
}
TEST_FILES = (
    "tools/sigma_compiler/test_prototype.py",
    "tools/sigma_compiler/test_full_recompile.py",
    "tools/falco_compiler/test_prototype.py",
    "tools/falco_compiler/test_full_recompile.py",
    "tools/security_datasets_baseline/test_evaluate.py",
    "tools/windows_structured/test_structured.py",
    "tools/runtime_integration/test_windows_runtime.py",
    "tools/runtime_integration/test_linux_runtime.py",
    "tools/runtime_integration/test_macos_runtime.py",
    "tools/runtime_integration/test_falco_runtime.py",
    "tools/linux_structured/test_structured.py",
    "tools/macos_structured/test_structured.py",
)


class GateError(RuntimeError):
    pass


def run(command: list[str], env: dict[str, str], *, quiet: bool = False) -> None:
    shown = " ".join(command)
    print(f"\n$ {shown}", flush=True)
    result = subprocess.run(
        command,
        cwd=REPO,
        env=env,
        text=True,
        stdout=subprocess.PIPE if quiet else None,
        stderr=subprocess.STDOUT if quiet else None,
    )
    if result.returncode:
        if result.stdout:
            print(result.stdout)
        raise GateError(f"command failed ({result.returncode}): {shown}")


def verify_checkout(variable: str, env: dict[str, str]) -> Path:
    value = env.get(variable)
    if not value:
        raise GateError(f"full mode requires {variable}")
    root = Path(value).resolve()
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
    )
    if result.returncode or result.stdout.strip() != PINNED[variable]:
        actual = result.stdout.strip() or result.stderr.strip() or "not a git checkout"
        raise GateError(f"{variable} is {actual}, expected {PINNED[variable]}")
    git_env = dict(env)
    # Partial clones should not require network access merely to prove that
    # their materialized sparse paths are clean.
    git_env["GIT_NO_LAZY_FETCH"] = "1"
    if subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        env=git_env,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip():
        raise GateError(f"{variable} checkout is dirty")
    return root


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def assert_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise GateError(f"reproduction mismatch: {label}")


def compare_compiler_artifact(
    generated_report: Path,
    committed_report: Path,
    generated_specs: Path,
    committed_specs: Path,
    label: str,
) -> None:
    assert_equal(load_json(generated_report), load_json(committed_report), f"{label} report")
    assert_equal(
        generated_specs.read_text(encoding="utf-8"),
        committed_specs.read_text(encoding="utf-8"),
        f"{label} specs",
    )


def normalized_case(case: dict[str, Any]) -> dict[str, Any]:
    copy = dict(case)
    copy.pop("elapsed_seconds", None)
    return copy


def normalized_inventory(report: dict[str, Any]) -> dict[str, Any]:
    inventory = report["rule_inventory"]
    target = report["platform"]
    return {
        key: inventory[key]
        for key in (
            "total",
            "by_origin",
            "by_platform",
            "sigma_commit",
            "pysigma_version",
            "falco_commit",
        )
    } | {
        f"{target}_structured_rule_count": inventory.get(
            f"{target}_structured_rule_count", 0
        )
    }


def compare_evaluation(generated: Path, committed: Path, label: str) -> None:
    actual = load_json(generated)
    expected = load_json(committed)
    for key in ("checkpoint", "platform", "selection_policy", "license_observation", "corpus", "metrics"):
        assert_equal(actual[key], expected[key], f"{label} {key}")
    assert_equal(
        normalized_inventory(actual), normalized_inventory(expected), f"{label} rule inventory"
    )
    assert_equal(
        [normalized_case(case) for case in actual["cases"]],
        [normalized_case(case) for case in expected["cases"]],
        f"{label} cases",
    )
    for key in (
        "prefilter_rejections",
        "regex_searches",
        "structured_evaluations",
        "raw_fallback_searches",
    ):
        assert_equal(actual["performance"][key], expected["performance"][key], f"{label} {key}")


def reproduce_compilers(env: dict[str, str], temp: Path) -> None:
    sigma_root = env["SIGMA_ROOT"]
    falco_root = env["FALCO_ROOT"]
    techniques = REPO / "backend/data/parsed/techniques.json"
    relationships = REPO / "backend/data/parsed/relationships.json"

    sigma_report = temp / "sigma_report.json"
    sigma_specs = temp / "sigma_specs.py"
    run(
        [
            PYTHON,
            "tools/sigma_compiler/full_recompile.py",
            "--sigma-root",
            sigma_root,
            "--sigma-commit",
            PINNED["SIGMA_ROOT"],
            "--techniques",
            str(techniques),
            "--relationships",
            str(relationships),
            "--report",
            str(sigma_report),
            "--rule-specs",
            str(sigma_specs),
        ],
        env,
        quiet=True,
    )
    compare_compiler_artifact(
        sigma_report,
        REPO / "tools/sigma_compiler/full_recompile_report.json",
        sigma_specs,
        REPO / "tools/sigma_compiler/full_recompile_rule_specs.py",
        "full Sigma",
    )

    falco_report = temp / "falco_report.json"
    falco_specs = temp / "falco_specs.py"
    falco_table = temp / "falco_table.md"
    medium_table = temp / "medium_table.md"
    run(
        [
            PYTHON,
            "tools/falco_compiler/full_recompile.py",
            "--falco-root",
            falco_root,
            "--techniques",
            str(techniques),
            "--relationships",
            str(relationships),
            "--sigma-report",
            str(sigma_report),
            "--report",
            str(falco_report),
            "--rule-specs",
            str(falco_specs),
            "--mapping-table",
            str(falco_table),
            "--medium-audit-table",
            str(medium_table),
        ],
        env,
        quiet=True,
    )
    compare_compiler_artifact(
        falco_report,
        REPO / "tools/falco_compiler/full_recompile_report.json",
        falco_specs,
        REPO / "tools/falco_compiler/full_rule_specs.py",
        "full Falco",
    )
    assert_equal(
        falco_table.read_text(encoding="utf-8"),
        (REPO / "tools/falco_compiler/full_mapping_table.md").read_text(encoding="utf-8"),
        "Falco mapping table",
    )
    assert_equal(
        medium_table.read_text(encoding="utf-8"),
        (REPO / "tools/falco_compiler/medium_fit_mitre_audit.md").read_text(encoding="utf-8"),
        "Falco medium-fit audit table",
    )
    falco_runtime_dir = temp / "falco_runtime"
    run(
        [
            PYTHON,
            "tools/runtime_integration/build_falco.py",
            "--manifest",
            "tools/falco_compiler/full_mapping_manifest.json",
            "--specs",
            str(falco_specs),
            "--report",
            str(falco_report),
            "--output-dir",
            str(falco_runtime_dir),
        ],
        env,
        quiet=True,
    )
    for platform in ("aws", "kubernetes"):
        assert_equal(
            (falco_runtime_dir / f"{platform}_falco_rules.json.gz").read_bytes(),
            (
                REPO
                / f"backend/log_analysis/generated/{platform}_falco_rules.json.gz"
            ).read_bytes(),
            f"{platform.capitalize()} Falco runtime bundle",
        )

    for platform, directory, command in (
        ("windows", "windows_structured", "compiler.py"),
        ("linux", "linux_structured", "compiler.py"),
        ("macos", "macos_structured", "compiler.py"),
    ):
        report = temp / f"{platform}_compile.json"
        specs = temp / f"{platform}_specs.py"
        run(
            [
                PYTHON,
                f"tools/{directory}/{command}",
                "--sigma-root",
                sigma_root,
                "--step2-report",
                str(sigma_report),
                "--report",
                str(report),
                "--specs",
                str(specs),
            ],
            env,
            quiet=True,
        )
        committed_specs = {
            "windows": "windows_structured_rule_specs.py",
            "linux": "linux_structured_rule_specs.py",
            "macos": "macos_structured_rule_specs.py",
        }[platform]
        compare_compiler_artifact(
            report,
            REPO / f"tools/{directory}/compile_report.json",
            specs,
            REPO / f"tools/{directory}/{committed_specs}",
            f"{platform} structured",
        )
        runtime_builder = {
            "windows": "build_windows.py",
            "linux": "build_linux.py",
            "macos": "build_macos.py",
        }.get(platform)
        if runtime_builder:
            runtime_bundle = temp / f"{platform}_sigma_rules.json.gz"
            run(
                [
                    PYTHON,
                    f"tools/runtime_integration/{runtime_builder}",
                    "--step2-report",
                    str(sigma_report),
                    "--sigma-specs",
                    str(sigma_specs),
                    "--structured-specs",
                    str(specs),
                    "--output",
                    str(runtime_bundle),
                ],
                env,
                quiet=True,
            )
            assert_equal(
                runtime_bundle.read_bytes(),
                (
                    REPO
                    / f"backend/log_analysis/generated/{platform}_sigma_rules.json.gz"
                ).read_bytes(),
                f"{platform.capitalize()} runtime bundle",
            )


def reproduce_evaluations(env: dict[str, str], temp: Path) -> None:
    workers = env.get("CARD5_REGRESSION_WORKERS", "4")
    if not workers.isdecimal() or int(workers) < 1:
        raise GateError("CARD5_REGRESSION_WORKERS must be a positive integer")
    manifest_temp = temp / "macos_manifest.json"
    run(
        [
            PYTHON,
            "tools/macos_structured/build_manifest.py",
            "--corpus-root",
            env["MACOS_ATTACK_DATASET_ROOT"],
            "--output",
            str(manifest_temp),
        ],
        env,
        quiet=True,
    )
    assert_equal(
        load_json(manifest_temp),
        load_json(REPO / "tools/macos_structured/corpus_manifest.json"),
        "macOS corpus manifest",
    )

    platforms = (
        (
            "windows",
            "tools/security_datasets_baseline/corpus_manifest.json",
            "tools/security_datasets_baseline/baseline_report.json",
            "tools/windows_structured/windows_structured_rule_specs.py",
            "tools/windows_structured/step7_report.json",
            env["SECURITY_DATASETS_ROOT"],
            False,
        ),
        (
            "linux",
            "tools/linux_structured/corpus_manifest.json",
            "tools/linux_structured/baseline_report.json",
            "tools/linux_structured/linux_structured_rule_specs.py",
            "tools/linux_structured/step8_linux_report.json",
            env["SECURITY_DATASETS_ROOT"],
            False,
        ),
        (
            "macos",
            str(manifest_temp),
            "tools/macos_structured/baseline_report.json",
            "tools/macos_structured/macos_structured_rule_specs.py",
            "tools/macos_structured/step8_macos_report.json",
            env["MACOS_ATTACK_DATASET_ROOT"],
            True,
        ),
    )
    for (
        platform,
        manifest,
        baseline_artifact,
        specs,
        layer2_artifact,
        root,
        reproduce_baseline,
    ) in platforms:
        committed_baseline = REPO / baseline_artifact
        baseline = committed_baseline
        if reproduce_baseline:
            baseline = temp / f"{platform}_baseline.json"
            baseline_md = temp / f"{platform}_baseline.md"
            run(
                [
                    PYTHON,
                    "tools/security_datasets_baseline/evaluate.py",
                    "--datasets-root",
                    root,
                    "--manifest",
                    manifest,
                    "--report-json",
                    str(baseline),
                    "--report-md",
                    str(baseline_md),
                    "--workers",
                    workers,
                ],
                env,
                quiet=True,
            )
            compare_evaluation(baseline, committed_baseline, f"{platform} baseline")
        layer2 = temp / f"{platform}_layer2.json"
        layer2_md = temp / f"{platform}_layer2.md"
        run(
            [
                PYTHON,
                "tools/security_datasets_baseline/evaluate.py",
                "--datasets-root",
                root,
                "--manifest",
                manifest,
                "--structured-specs",
                specs,
                "--comparison-baseline-report",
                str(baseline),
                "--report-json",
                str(layer2),
                "--report-md",
                str(layer2_md),
                "--workers",
                workers,
            ],
            env,
            quiet=True,
        )
        compare_evaluation(layer2, REPO / layer2_artifact, f"{platform} layer2")


def run_tests(mode: str, env: dict[str, str]) -> None:
    test_env = dict(env)
    if mode == "artifacts":
        for variable in PINNED:
            test_env.pop(variable, None)
    for path in TEST_FILES:
        run([PYTHON, path, "-v"], test_env)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("artifacts", "full"), default="artifacts")
    args = parser.parse_args()
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = "0"

    if args.mode == "full":
        for variable in PINNED:
            verify_checkout(variable, env)
        with tempfile.TemporaryDirectory(prefix="card5-regression-") as directory:
            temp = Path(directory)
            reproduce_compilers(env, temp)
            reproduce_evaluations(env, temp)
    run_tests(args.mode, env)
    print(f"\nCard 5 Layer-4 {args.mode} regression gate: PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
