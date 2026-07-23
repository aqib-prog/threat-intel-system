from __future__ import annotations

import gzip
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from build_falco import build_payloads, load_module, render
from log_analysis.analyzer import analyze
from log_analysis.detector import detect
from log_analysis.mappings import RULES_BY_PLATFORM
from log_analysis.parser import parse_log
from log_analysis.runtime_rules import RUNTIME_BUNDLES, load_runtime_rule_bundle


MANIFEST = REPO / "tools/falco_compiler/full_mapping_manifest.json"
REPORT = REPO / "tools/falco_compiler/full_recompile_report.json"
SPECS = REPO / "tools/falco_compiler/full_rule_specs.py"
PERFORMANCE_REPORTS = {
    "aws": HERE / "aws_falco_performance_report.json",
    "kubernetes": HERE / "kubernetes_performance_report.json",
}


def aws_event(event_name: str) -> str:
    return json.dumps(
        {
            "eventVersion": "1.08",
            "eventTime": "2026-07-17T01:00:00Z",
            "eventSource": "ecs.amazonaws.com",
            "eventName": event_name,
            "awsRegion": "us-east-1",
            "userIdentity": {"type": "IAMUser", "userName": "operator"},
            "requestParameters": {"serviceName": "production-api"},
        }
    )


def kubernetes_event(verb: str, resource: str, code: int = 200) -> str:
    return json.dumps(
        {
            "apiVersion": "audit.k8s.io/v1",
            "kind": "Event",
            "auditID": "runtime-checkpoint",
            "stage": "ResponseComplete",
            "verb": verb,
            "user": {"username": "alice@example.com"},
            "objectRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "resource": resource,
                "name": "production-operator",
            },
            "responseStatus": {"code": code},
        }
    )


class FalcoRuntimeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))
        cls.specs = load_module(SPECS, "test_runtime_falco_specs")
        cls.payloads = {
            platform: load_runtime_rule_bundle(platform)
            for platform in ("kubernetes", "aws")
        }

    def test_bundle_inventories_are_mapping_candidate_only(self):
        expected = {"kubernetes": 27, "aws": 11}
        for platform, count in expected.items():
            payload = self.payloads[platform]
            self.assertEqual(payload["decision_policy"], "mapping_candidate_only")
            self.assertEqual(
                payload["inventory"],
                {
                    "mapping_candidate_count": count,
                    "structured_condition_count": 0,
                    "raw_fallback_only_count": count,
                },
            )
            self.assertEqual(len(payload["rules"]), count)

    def test_bundles_reproduce_byte_for_byte_from_reviewed_artifacts(self):
        rebuilt = build_payloads(self.manifest, self.specs, self.report)
        for platform, payload in rebuilt.items():
            self.assertEqual(RUNTIME_BUNDLES[platform].read_bytes(), render(payload))

    def test_no_needs_review_or_source_disabled_rule_is_present(self):
        excluded = {
            (row["rule"], row["platform"])
            for row in self.manifest["mappings"]
            if row["decision"] != "mapping_candidate"
        }
        runtime = {
            (item["rule"], platform)
            for platform, payload in self.payloads.items()
            for item in payload["rules"]
        }
        self.assertTrue(runtime.isdisjoint(excluded))

    def test_all_candidates_are_live_raw_rules(self):
        self.assertEqual(len(RULES_BY_PLATFORM["kubernetes"]), 50)
        self.assertEqual(len(RULES_BY_PLATFORM["aws"]), 46)
        for platform, count in (("kubernetes", 27), ("aws", 11)):
            falco = [
                rule
                for rule in RULES_BY_PLATFORM[platform]
                if rule.source.startswith("Falco: ")
            ]
            self.assertEqual(len(falco), count)
            self.assertTrue(all(rule.structured_condition is None for rule in falco))
            self.assertTrue(all(rule.prefilter_terms for rule in falco))

    def test_aws_candidate_runs_through_production_analyzer(self):
        positive = analyze(parse_log(aws_event("CreateService"), "aws"), "aws")
        nearby = analyze(parse_log(aws_event("UpdateService"), "aws"), "aws")
        self.assertTrue(
            any(
                item.technique_name == "Deploy Container"
                and item.source == "Falco: ECS Service Created"
                for item in positive
            )
        )
        self.assertFalse(any(item.technique_name == "Deploy Container" for item in nearby))

    def test_cloudtrail_schema_routes_only_to_aws_rules(self):
        text = aws_event("CreateService")
        detection = detect(text)
        self.assertTrue(detection.is_raw_log)
        self.assertEqual(detection.platform, "aws")
        matches = analyze(parse_log(text, detection.platform), detection.platform)
        self.assertEqual(
            {(item.technique_name, item.source) for item in matches},
            {("Deploy Container", "Falco: ECS Service Created")},
        )

    def test_kubernetes_candidate_runs_through_production_analyzer(self):
        positive = analyze(
            parse_log(kubernetes_event("create", "clusterroles", 201), "kubernetes"),
            "kubernetes",
        )
        nearby = analyze(
            parse_log(kubernetes_event("get", "clusterroles"), "kubernetes"),
            "kubernetes",
        )
        self.assertTrue(
            any(
                item.technique_name == "Additional Container Cluster Roles"
                and item.source == "Falco: K8s ClusterRole Created"
                for item in positive
            )
        )
        self.assertFalse(
            any(item.technique_name == "Additional Container Cluster Roles" for item in nearby)
        )

    def test_kubernetes_audit_schema_routes_to_kubernetes_rules(self):
        detection = detect(kubernetes_event("create", "clusterroles", 201))
        self.assertTrue(detection.is_raw_log)
        self.assertEqual(detection.platform, "kubernetes")

    def test_bundles_are_gzip_json_not_executable_code(self):
        for platform, path in RUNTIME_BUNDLES.items():
            if platform not in self.payloads:
                continue
            decoded = gzip.decompress(path.read_bytes()).decode("utf-8")
            self.assertEqual(json.loads(decoded)["platform"], platform)
            self.assertNotIn("import ", decoded)

    def test_recorded_performance_checkpoints_are_complete(self):
        for platform, path in PERFORMANCE_REPORTS.items():
            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(report["protocol"]["platform"], platform)
            self.assertEqual(report["protocol"]["repetitions"], 9)
            self.assertEqual(report["protocol"]["warmups"], 2)
            for variant in ("legacy", "integrated"):
                scenarios = report["variants"][variant]["scenarios"]
                self.assertEqual([item["event_count"] for item in scenarios], [10, 50, 250])
                self.assertLessEqual(scenarios[-1]["input_bytes"], 100_000)
            self.assertEqual(len(report["comparison"]), 3)


if __name__ == "__main__":
    unittest.main()
