from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPORT = HERE / "full_recompile_report.json"
SPECS = HERE / "full_rule_specs.py"
TABLE = HERE / "full_mapping_table.md"
MEDIUM_AUDIT_TABLE = HERE / "medium_fit_mitre_audit.md"
SIGMA_REPORT = HERE.parent / "sigma_compiler" / "full_recompile_report.json"


@unittest.skipUnless(
    REPORT.is_file() and SPECS.is_file() and TABLE.is_file() and MEDIUM_AUDIT_TABLE.is_file(),
    "generate full step-4 artifacts first",
)
class FullFalcoArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))
        spec = importlib.util.spec_from_file_location("full_falco_rule_specs", SPECS)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        cls.specs = module.RULE_SPECS
        cls.by_name = {item["rule"]: item for item in cls.report["rules"]}

    def test_all_48_plus_22_rules_are_accounted_for(self):
        inventory = self.report["inventory"]
        self.assertEqual(inventory["input_rule_count"], 70)
        self.assertEqual(inventory["input_by_platform"], {"aws": 22, "kubernetes": 48})
        self.assertEqual(
            inventory["input_rule_count"],
            inventory["mapping_candidate_count"]
            + inventory["needs_review_count"]
            + inventory["source_disabled_count"],
        )

    def test_decision_counts_are_conservative_and_stable(self):
        self.assertEqual(
            self.report["inventory"]["decision_by_platform"],
            {
                "kubernetes": {
                    "mapping_candidate": 27,
                    "needs_review": 16,
                    "source_disabled": 5,
                },
                "aws": {
                    "mapping_candidate": 11,
                    "needs_review": 9,
                    "source_disabled": 2,
                },
            },
        )

    def test_every_source_rule_has_a_compiled_regex(self):
        self.assertEqual(len(self.report["rules"]), 70)
        for item in self.report["rules"]:
            re.compile(item["pattern"], re.IGNORECASE)

    def test_source_disabled_rules_are_not_candidates(self):
        disabled = {
            item["rule"]
            for item in self.report["rules"]
            if item["decision"] == "source_disabled"
        }
        self.assertEqual(
            disabled,
            {
                "Create Disallowed Pod",
                "All K8s Audit Events",
                "Full K8s Administrative Access",
                "Untrusted Node Successfully Joined the Cluster",
                "Untrusted Node Unsuccessfully Tried to Join the Cluster",
                "All Cloudtrail Events",
                "List Buckets",
            },
        )
        self.assertTrue(all(not self.by_name[name]["effectively_enabled"] for name in disabled))

    def test_low_confidence_and_unmapped_rows_are_never_candidates(self):
        for item in self.report["rules"]:
            if item["decision"] == "mapping_candidate":
                self.assertIn(item["mapping_confidence"], {"high", "medium"})
                self.assertIsNotNone(item["attack"])
            if item["mapping_confidence"] == "low" or item["attack"] is None:
                self.assertNotEqual(item["decision"], "mapping_candidate")

    def test_medium_fit_direct_mitre_audit_is_complete_and_enforced(self):
        audit = self.report["medium_fit_mitre_audit"]
        self.assertEqual(len(audit), 14)
        self.assertEqual(len({item["rule"] for item in audit}), 14)
        moved = {
            item["rule"]
            for item in audit
            if item["outcome"] == "move_to_needs_review"
        }
        self.assertEqual(
            moved,
            {
                "port-forward",
                "Update Lambda Function Code",
                "Update Lambda Function Configuration",
            },
        )
        for item in audit:
            with self.subTest(rule=item["rule"]):
                technique_path = item["technique_id"].replace(".", "/")
                self.assertEqual(
                    item["mitre_url"],
                    f"https://attack.mitre.org/techniques/{technique_path}/",
                )
                expected = (
                    "needs_review"
                    if item["outcome"] == "move_to_needs_review"
                    else "mapping_candidate"
                )
                self.assertEqual(self.by_name[item["rule"]]["decision"], expected)

    def test_kubernetes_techniques_are_valid_for_containers(self):
        for item in self.report["rules"]:
            if item["platform"] == "kubernetes" and item["attack"]:
                self.assertIn("Containers", item["attack"]["technique_platforms"])

    def test_all_full_corpus_handcrafted_samples_pass(self):
        self.assertEqual(len(self.report["validation"]), 9)
        self.assertTrue(all(item["status"] == "pass" for item in self.report["validation"]))

    def test_nested_image_allowlists_do_not_suppress_mixed_pod(self):
        regex = re.compile(
            self.by_name["Pod Created in Kube Namespace"]["pattern"], re.IGNORECASE
        )
        base = {
            "stage": "ResponseComplete",
            "verb": "create",
            "objectRef": {"resource": "pods", "namespace": "kube-system"},
        }
        trusted_only = {
            **base,
            "requestObject": {
                "spec": {"containers": [{"image": "gke.gcr.io/kube-proxy:latest"}]}
            },
        }
        mixed = {
            **base,
            "requestObject": {
                "spec": {
                    "containers": [
                        {"image": "gke.gcr.io/kube-proxy:latest"},
                        {"image": "evil.example/backdoor:latest"},
                    ]
                }
            },
        }
        self.assertIsNone(regex.search(json.dumps(trusted_only, separators=(",", ":"))))
        self.assertIsNotNone(regex.search(json.dumps(mixed, separators=(",", ":"))))

    def test_specs_are_review_only_candidates_and_construct_at_runtime(self):
        expected = self.report["inventory"]["mapping_candidate_count"]
        self.assertEqual(len(self.specs), expected)
        backend = HERE.parents[1] / "backend"
        sys.path.insert(0, str(backend))
        from log_analysis.mappings import _rule

        constructed = [_rule(**item["rule_kwargs"]) for item in self.specs]
        self.assertEqual(len(constructed), expected)

    def test_mapping_table_has_one_row_per_source_rule(self):
        rows = [
            line
            for line in TABLE.read_text(encoding="utf-8").splitlines()
            if line.startswith("| ") and not line.startswith("| Platform")
        ]
        self.assertEqual(len(rows), 70)

    def test_medium_fit_audit_table_has_one_row_per_audited_rule(self):
        rows = [
            line
            for line in MEDIUM_AUDIT_TABLE.read_text(encoding="utf-8").splitlines()
            if line.startswith("| ") and not line.startswith("| Rule")
        ]
        self.assertEqual(len(rows), 14)

    def test_combined_diff_uses_validated_step2_baseline(self):
        sigma = json.loads(SIGMA_REPORT.read_text(encoding="utf-8"))
        diff = self.report["diff_against_current_mappings"]
        self.assertEqual(
            diff["step2_sigma_preview_unique_technique_id_count"],
            sigma["diff_against_current_mappings"]["proposed_unique_technique_id_count"],
        )
        self.assertFalse(diff["runtime_changed"])


if __name__ == "__main__":
    unittest.main()
