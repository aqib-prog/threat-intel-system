#!/usr/bin/env python3
"""Run every backend unittest file, including non-package directories.

``unittest discover`` only recurses into importable Python packages. Several
backend test directories intentionally have no ``__init__.py``, so relying on
one repository-wide discovery command silently omits their tests. This runner
loads each ``test*.py`` file by path and reports every individual result.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"


def _test_files() -> list[Path]:
    return sorted(
        path
        for path in BACKEND.rglob("test*.py")
        if "venv" not in path.parts and "__pycache__" not in path.parts
    )


def _load_file(path: Path) -> unittest.TestSuite:
    relative = path.relative_to(BACKEND).with_suffix("")
    module_name = "_backend_test_" + "_".join(relative.parts)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load test module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return unittest.defaultTestLoader.loadTestsFromModule(module)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run all backend unittest files with per-test output."
    )
    parser.add_argument(
        "--list-files",
        action="store_true",
        help="List discovered test files before running them.",
    )
    args = parser.parse_args()

    os.environ.setdefault("LANGFUSE_ENABLED", "false")
    sys.path.insert(0, str(BACKEND))

    files = _test_files()
    if not files:
        print(f"FAIL: no test files found under {BACKEND}")
        return 2
    if args.list_files:
        print("Discovered test files:")
        for path in files:
            print(f"  - {path.relative_to(REPO)}")

    suite = unittest.TestSuite(_load_file(path) for path in files)
    count = suite.countTestCases()
    print(f"Running {count} tests from {len(files)} files...")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        "\nBackend behavior suite: "
        f"{result.testsRun - len(result.failures) - len(result.errors)}/"
        f"{result.testsRun} passed; "
        f"{len(result.failures)} failed; {len(result.errors)} errors"
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
