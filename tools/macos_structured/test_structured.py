from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
SIGMA_TOOLS = REPO / "tools/sigma_compiler"
for path in (str(BACKEND), str(SIGMA_TOOLS), str(HERE)):
    if path not in sys.path:
        sys.path.insert(0, path)

from build_manifest import build_manifest
from compiler import compile_macos_structured
from corpus import read_macos_attack_file
from log_analysis.detector import detect
from log_analysis.parser import parse_log
from log_analysis.structured import StructuredCondition, hybrid_rule_matches


SPECS_PATH = HERE / "macos_structured_rule_specs.py"
COMPILE_REPORT = HERE / "compile_report.json"
STEP2_REPORT = SIGMA_TOOLS / "full_recompile_report.json"
MAPPING_JSON = HERE / "manual_ground_truth_mapping.json"
MAPPING_MD = HERE / "manual_ground_truth_mapping.md"
MANIFEST = HERE / "corpus_manifest.json"
BASELINE_REPORT = HERE / "baseline_report.json"
STEP8_REPORT = HERE / "step8_macos_report.json"


def load_specs():
    spec = importlib.util.spec_from_file_location("step8_macos_specs", SPECS_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MacOSStructuredArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.specs = load_specs().STRUCTURED_BY_SOURCE_TECHNIQUE

    def test_mapping_review_summary_is_rendered_and_reconciles(self):
        mapping = json.loads(MAPPING_JSON.read_text(encoding="utf-8"))
        markdown = MAPPING_MD.read_text(encoding="utf-8")
        counts = {
            "candidates": sum(x["decision"] == "mapping_candidate" for x in mapping["mappings"]),
            "review": sum(x["decision"] == "needs_review" for x in mapping["mappings"]),
            "multi": sum(x.get("multi_technique") is True for x in mapping["mappings"]),
            "medium": sum(x["confidence"] == "medium" for x in mapping["mappings"]),
        }
        self.assertEqual(counts, {"candidates": 55, "review": 11, "multi": 8, "medium": 7})
        for expected in (
            "55 `mapping_candidate` rows",
            "11 `needs_review` rows",
            "8 explicit multi-technique candidates",
            "7 medium-confidence candidates",
        ):
            self.assertIn(expected, markdown)
        self.assertNotIn("- jq:", markdown)
        self.assertNotIn("- error explicit", markdown)

    def test_manifest_is_conservative_and_contains_no_telemetry(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["corpus_commit"], "0315ec88d1f4b338c07315223bc6a53619465472")
        self.assertEqual(len(manifest["cases"]), 54)
        self.assertEqual(manifest["parse_inventory"]["elastic_records"], 88)
        self.assertEqual(len(manifest["excluded"]), 1)
        self.assertIn("Invalid control character", manifest["excluded"][0]["reason"])
        serialized = MANIFEST.read_text(encoding="utf-8")
        self.assertNotIn('"_source"', serialized)
        self.assertNotIn('"command_line"', serialized)

    def test_every_generated_tree_constructs(self):
        self.assertEqual(len(self.specs), 47)
        for key, tree in self.specs.items():
            with self.subTest(key=key):
                self.assertTrue(StructuredCondition.from_dict(tree).positive_fields)

    def test_macos_ecs_schema_is_not_misclassified_as_kubernetes(self):
        text = "\n".join(
            json.dumps(
                {
                    "_source": {
                        "event": {"kind": "event", "dataset": "endpoint.events.process"},
                        "host": {"os": {"platform": "macos"}},
                        "process": {
                            "executable": "/usr/bin/osascript",
                            "command_line": "osascript -e get the clipboard",
                        },
                        "@timestamp": f"2021-01-01T00:00:0{second}Z",
                    }
                }
            )
            for second in (1, 2)
        )
        result = detect(text)
        self.assertTrue(result.is_raw_log)
        self.assertEqual(result.platform, "macos")
        self.assertNotIn("platform_kubernetes", result.signals)

    def test_ecs_extractor_keeps_child_parent_and_file_paths_separate(self):
        record = {
            "_source": {
                "event": {"kind": "event", "dataset": "endpoint.events.file"},
                "host": {"os": {"platform": "macos"}},
                "process": {
                    "executable": "/usr/bin/cp",
                    "command_line": "cp source target",
                    "parent": {"executable": "/bin/zsh"},
                },
                "file": {"path": "/Users/test/.ssh/authorized_keys"},
            }
        }
        event = parse_log(json.dumps(record), "macos")[0]
        self.assertTrue(event.structured_complete)
        self.assertEqual(event.source_fields["image"], ("/usr/bin/cp",))
        self.assertEqual(event.source_fields["parentimage"], ("/bin/zsh",))
        self.assertEqual(event.source_fields["targetfilename"], ("/Users/test/.ssh/authorized_keys",))
        self.assertEqual(event.source_fields["commandline"], ("cp source target",))

    def test_complete_ecs_record_is_field_authoritative(self):
        condition = next(
            StructuredCondition.from_dict(tree)
            for (source, _technique), tree in self.specs.items()
            if source == "Sigma: proc_creation_macos_space_after_filename.yml"
        )
        event = parse_log(
            json.dumps(
                {
                    "_source": {
                        "host": {"os": {"platform": "macos"}},
                        "event": {"dataset": "endpoint.events.process"},
                        "process": {
                            "executable": "/usr/bin/osascript",
                            "command_line": "osascript -e harmless",
                        },
                        "unrelated": "raw-only-token",
                    }
                }
            ),
            "macos",
        )[0]
        matched, mode = hybrid_rule_matches(event, re.compile("raw-only-token"), condition)
        self.assertEqual(mode, "structured")
        self.assertFalse(matched)

    def test_step8_report_proves_real_precision_improvement(self):
        report = json.loads(STEP8_REPORT.read_text(encoding="utf-8"))
        baseline = report["comparison_step5_baseline"]["layer1_micro_strict_exact_id"]
        layer2 = report["metrics"]["layer2_macos_preview"]["micro_strict_exact_id"]
        compiler = json.loads(COMPILE_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(report["checkpoint"], "Card 5 Part 1 roadmap step 8 Macos pilot only")
        self.assertEqual(report["corpus"]["sample_count"], 54)
        self.assertEqual(report["corpus"]["detector_gate_pass_count"], 54)
        self.assertEqual(report["rule_inventory"]["macos_structured_rule_count"], 47)
        self.assertEqual(compiler["inventory"]["raw_fallback_only_candidates"], 0)
        self.assertEqual((baseline["tp"], baseline["fp"], baseline["fn"]), (14, 83, 49))
        self.assertEqual((layer2["tp"], layer2["fp"], layer2["fn"]), (14, 16, 49))
        self.assertGreater(layer2["precision"], baseline["precision"])
        self.assertEqual(layer2["recall"], baseline["recall"])
        self.assertEqual(report["performance"]["raw_fallback_searches"], 0)
        self.assertNotIn("evidence_excerpt", STEP8_REPORT.read_text(encoding="utf-8"))


@unittest.skipUnless(
    os.environ.get("MACOS_ATTACK_DATASET_ROOT"),
    "set MACOS_ATTACK_DATASET_ROOT for source-backed corpus tests",
)
class MacOSCorpusSourceTests(unittest.TestCase):
    def test_manifest_and_parser_inventory_reproduce(self):
        reproduced = build_manifest(
            Path(os.environ["MACOS_ATTACK_DATASET_ROOT"]), MAPPING_JSON
        )
        committed = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(reproduced, committed)
        total = 0
        for case in reproduced["cases"]:
            text, details = read_macos_attack_file(
                Path(os.environ["MACOS_ATTACK_DATASET_ROOT"]) / case["capture"]
            )
            events = parse_log(text, "macos")
            self.assertEqual(len(events), details["record_count"])
            self.assertTrue(all(event.structured_complete for event in events))
            total += len(events)
        self.assertEqual(total, 88)


@unittest.skipUnless(os.environ.get("SIGMA_ROOT"), "set SIGMA_ROOT for source tests")
class MacOSSigmaSourceTests(unittest.TestCase):
    def test_generated_inventory_reproduces(self):
        step2 = json.loads(STEP2_REPORT.read_text(encoding="utf-8"))
        specs, review, inventory = compile_macos_structured(
            Path(os.environ["SIGMA_ROOT"]), step2
        )
        artifact = json.loads(COMPILE_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(inventory, artifact["inventory"])
        self.assertEqual(len(specs), 47)
        self.assertEqual(review, [])


if __name__ == "__main__":
    unittest.main()
