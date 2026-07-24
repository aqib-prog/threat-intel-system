from __future__ import annotations

import ast
import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
GENERATOR = HERE / "generate_campaign_software_technique_chain_prototype.py"
PROTOTYPE = (
    HERE / "golden_set_campaign_software_technique_chain_prototype.json"
)
FULL = HERE / "golden_set_campaign_software_technique_chain.json"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_campaign_software_technique_chain", GENERATOR
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str) -> list[dict[str, str]]:
    return [
        {
            "source_name": "mitre-attack",
            "external_id": external_id,
        }
    ]


class CampaignSoftwareTechniqueChainUnitTests(unittest.TestCase):
    def setUp(self):
        self.campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
        }
        self.software = {
            "type": "malware",
            "id": "malware--one",
            "name": "Example Malware",
            "x_mitre_platforms": ["Windows"],
            "external_references": external("S0001"),
        }
        self.chain_technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--chain",
            "name": "Chain Technique",
            "external_references": external("T1001"),
        }
        self.campaign_only_technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--campaign-only",
            "name": "Campaign Direct Only",
            "external_references": external("T1002"),
        }
        self.zero_technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--zero",
            "name": "No Chain",
            "external_references": external("T1003"),
        }
        self.campaign_software = {
            "type": "relationship",
            "id": "relationship--campaign-software",
            "relationship_type": "uses",
            "source_ref": self.campaign["id"],
            "target_ref": self.software["id"],
        }
        self.software_technique = {
            "type": "relationship",
            "id": "relationship--software-technique",
            "relationship_type": "uses",
            "source_ref": self.software["id"],
            "target_ref": self.chain_technique["id"],
        }
        self.campaign_technique = {
            "type": "relationship",
            "id": "relationship--campaign-technique",
            "relationship_type": "uses",
            "source_ref": self.campaign["id"],
            "target_ref": self.campaign_only_technique["id"],
        }
        self.source = {
            "repository": "example",
            "commit": "commit",
            "path": "bundle.json",
            "sha256": "sha",
            "domain": "enterprise-attack",
        }

    def extract(self):
        return module.extract_chain_scope(
            {
                "type": "bundle",
                "objects": [
                    self.campaign,
                    self.software,
                    self.chain_technique,
                    self.campaign_only_technique,
                    self.zero_technique,
                    self.campaign_software,
                    self.software_technique,
                    self.campaign_technique,
                ],
            }
        )

    def test_requires_both_edges_joined_through_the_same_software(self):
        extracted = self.extract()
        self.assertEqual(extracted["global_coverage"]["chain_triple_count"], 1)
        self.assertEqual(
            extracted["global_coverage"][
                "distinct_campaign_technique_chain_fact_count"
            ],
            1,
        )
        path = extracted["chain_paths"][0]
        self.assertEqual(
            path["campaign_uses_software_relationship_stix_id"],
            self.campaign_software["id"],
        )
        self.assertEqual(
            path["software_uses_technique_relationship_stix_id"],
            self.software_technique["id"],
        )
        self.assertEqual(path["software_ref"], self.software["id"])

    def test_campaign_direct_technique_does_not_become_a_chain_fact(self):
        extracted = self.extract()
        campaigns, software, techniques = module.catalogs(extracted)
        pair = module.named_chain_pair(
            campaigns["C0001"],
            software["S0001"],
            extracted,
            self.source,
        )
        self.assertEqual(
            [item["external_id"] for item in pair["expected_techniques"]],
            ["T1001"],
        )
        negative = module.named_negative_pair(
            campaigns["C0001"],
            software["S0001"],
            techniques["T1002"],
            extracted,
            self.source,
        )
        self.assertFalse(negative["relationship_exists"])
        self.assertEqual(
            negative["provenance"][
                "campaign_uses_software_relationship_stix_ids"
            ],
            [self.campaign_software["id"]],
        )
        self.assertEqual(
            negative["provenance"][
                "software_uses_technique_relationship_stix_ids"
            ],
            [],
        )

    def test_divergence_is_a_real_set_difference(self):
        extracted = self.extract()
        campaigns, software, _ = module.catalogs(extracted)
        pair = module.divergence_pair(
            campaigns["C0001"],
            software["S0001"],
            extracted,
            self.source,
        )
        self.assertEqual(
            {
                item["external_id"]
                for item in pair["expected_software_only_techniques"]
            },
            {"T1001"},
        )
        self.assertEqual(
            {
                item["external_id"]
                for item in pair["expected_campaign_only_techniques"]
            },
            {"T1002"},
        )
        self.assertEqual(pair["expected_shared_techniques"], [])

    def test_reverse_zero_and_boolean_negative_are_explicit(self):
        extracted = self.extract()
        campaigns, _, techniques = module.catalogs(extracted)
        reverse = module.reverse_chain_pair(
            techniques["T1003"], extracted, self.source
        )
        self.assertEqual(
            reverse["case_type"],
            "aggregate_technique_no_campaigns_via_software",
        )
        self.assertEqual(reverse["expected_campaigns"], [])
        boolean = module.boolean_chain_pair(
            campaigns["C0001"],
            techniques["T1002"],
            extracted,
            self.source,
            expected=False,
        )
        self.assertFalse(boolean["relationship_exists"])
        self.assertEqual(boolean["provenance"]["chain_paths"], [])
        self.assertEqual(
            boolean["provenance"][
                "campaign_uses_software_relationship_stix_ids"
            ],
            [self.campaign_software["id"]],
        )

    def test_generator_has_no_llm_or_network_imports(self):
        tree = ast.parse(GENERATOR.read_text(encoding="utf-8"))
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertTrue(
            imported_roots.isdisjoint(
                {
                    "anthropic",
                    "httpx",
                    "langchain",
                    "ollama",
                    "openai",
                    "ragas",
                    "requests",
                    "urllib",
                }
            )
        )


@unittest.skipUnless(PROTOTYPE.exists() and FULL.exists(), "generate artifacts")
class CampaignSoftwareTechniqueChainArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prototype = json.loads(PROTOTYPE.read_text(encoding="utf-8"))
        cls.full = json.loads(FULL.read_text(encoding="utf-8"))
        cls.manifest = json.loads(
            (HERE / "source_manifest.json").read_text(encoding="utf-8")
        )["enterprise_attack_stix"]

    def test_prototype_case_breakdown(self):
        selection = self.prototype["selection"]
        self.assertEqual(selection["pair_count"], 30)
        self.assertEqual(selection["named_chain_pairs"], 5)
        self.assertEqual(selection["reverse_positive_pairs"], 4)
        self.assertEqual(selection["reverse_zero_path_pairs"], 1)
        self.assertEqual(selection["boolean_positive_pairs"], 5)
        self.assertEqual(selection["boolean_negative_pairs"], 5)
        self.assertEqual(selection["divergence_pairs"], 5)
        self.assertEqual(selection["named_negative_pairs"], 5)
        self.assertEqual(
            len({pair["id"] for pair in self.prototype["pairs"]}), 30
        )

    def test_full_case_and_fact_breakdown(self):
        selection = self.full["selection"]
        self.assertEqual(selection["pair_count"], 994)
        self.assertEqual(selection["named_chain_pairs"], 172)
        self.assertEqual(selection["reverse_positive_pairs"], 293)
        self.assertEqual(selection["reverse_zero_path_pairs"], 404)
        self.assertEqual(selection["boolean_positive_pairs"], 50)
        self.assertEqual(selection["boolean_negative_pairs"], 25)
        self.assertEqual(selection["divergence_pairs"], 25)
        self.assertEqual(selection["named_negative_pairs"], 25)
        self.assertEqual(selection["embedded_named_chain_fact_count"], 2371)
        self.assertEqual(selection["embedded_reverse_campaign_fact_count"], 1883)
        self.assertEqual(selection["embedded_reverse_chain_path_count"], 2371)
        self.assertEqual(selection["prototype_pair_count_preserved"], 30)
        self.assertEqual(
            self.full["global_coverage"]["techniques_with_zero_campaign_chains"],
            404,
        )

    def test_every_positive_chain_path_proves_both_hops(self):
        for artifact in (self.prototype, self.full):
            with self.subTest(phase=artifact["phase"]):
                for pair in artifact["pairs"]:
                    provenance = pair["provenance"]
                    self.assertEqual(
                        provenance["source_commit"], self.manifest["commit"]
                    )
                    self.assertEqual(
                        provenance["source_bundle_sha256"],
                        self.manifest["sha256"],
                    )
                    for path in provenance["chain_paths"]:
                        self.assertTrue(
                            path[
                                "campaign_uses_software_relationship_stix_id"
                            ]
                        )
                        self.assertTrue(
                            path[
                                "software_uses_technique_relationship_stix_id"
                            ]
                        )
                        self.assertIn(
                            path[
                                "campaign_uses_software_relationship_stix_id"
                            ],
                            provenance[
                                "campaign_uses_software_relationship_stix_ids"
                            ],
                        )
                        self.assertIn(
                            path[
                                "software_uses_technique_relationship_stix_id"
                            ],
                            provenance[
                                "software_uses_technique_relationship_stix_ids"
                            ],
                        )

    def test_solarwinds_teardrop_concrete_chain_and_divergence(self):
        named = next(
            pair
            for pair in self.prototype["pairs"]
            if pair["id"] == "campaign-software-techniques-c0024-s0560"
        )
        self.assertEqual(
            {
                item["external_id"] for item in named["expected_techniques"]
            },
            {
                "T1012",
                "T1027",
                "T1036.005",
                "T1112",
                "T1140",
                "T1543.003",
            },
        )
        divergence = next(
            pair
            for pair in self.prototype["pairs"]
            if pair["id"]
            == "campaign-software-technique-divergence-c0024-s0560"
        )
        self.assertEqual(
            {
                item["external_id"]
                for item in divergence["expected_software_only_techniques"]
            },
            {"T1012", "T1027", "T1112", "T1543.003"},
        )
        self.assertEqual(len(divergence["expected_shared_techniques"]), 2)
        self.assertEqual(
            len(divergence["expected_campaign_only_techniques"]), 69
        )

    def test_every_divergence_pair_recomputes_exactly(self):
        for pair in self.full["pairs"]:
            if pair["case_type"] != "campaign_software_technique_divergence":
                continue
            software_ids = {
                item["stix_id"]
                for item in pair["expected_software_techniques"]
            }
            campaign_ids = {
                item["stix_id"]
                for item in pair["expected_campaign_direct_techniques"]
            }
            self.assertEqual(
                {
                    item["stix_id"]
                    for item in pair["expected_software_only_techniques"]
                },
                software_ids - campaign_ids,
            )
            self.assertEqual(
                {
                    item["stix_id"]
                    for item in pair["expected_shared_techniques"]
                },
                software_ids & campaign_ids,
            )
            self.assertEqual(
                {
                    item["stix_id"]
                    for item in pair["expected_campaign_only_techniques"]
                },
                campaign_ids - software_ids,
            )

    def test_all_negatives_and_zero_paths_are_graph_verified_in_artifact(self):
        named_positives = {
            (
                pair["campaign"]["stix_id"],
                pair["software"]["stix_id"],
            ): {
                item["stix_id"] for item in pair["expected_techniques"]
            }
            for pair in self.full["pairs"]
            if pair["case_type"]
            == "named_campaign_software_technique_chain"
        }
        campaign_chain_techniques: dict[str, set[str]] = {}
        for (campaign_id, _), technique_ids in named_positives.items():
            campaign_chain_techniques.setdefault(campaign_id, set()).update(
                technique_ids
            )
        for pair in self.full["pairs"]:
            if pair["case_type"] == (
                "negative_named_campaign_software_technique_chain"
            ):
                key = (
                    pair["campaign"]["stix_id"],
                    pair["software"]["stix_id"],
                )
                self.assertIn(key, named_positives)
                self.assertNotIn(
                    pair["queried_technique"]["stix_id"],
                    named_positives[key],
                )
                self.assertTrue(
                    pair["provenance"][
                        "campaign_uses_software_relationship_stix_ids"
                    ]
                )
                self.assertEqual(
                    pair["provenance"][
                        "software_uses_technique_relationship_stix_ids"
                    ],
                    [],
                )
            elif pair["case_type"] == (
                "negative_campaign_software_technique_chain"
            ):
                self.assertNotIn(
                    pair["queried_technique"]["stix_id"],
                    campaign_chain_techniques[pair["campaign"]["stix_id"]],
                )
            elif pair["case_type"] == (
                "aggregate_technique_no_campaigns_via_software"
            ):
                self.assertFalse(pair["expected_campaigns"])
                self.assertFalse(pair["expected_intermediate_software"])
                self.assertFalse(pair["provenance"]["chain_paths"])

    def test_all_prototype_pairs_are_exactly_preserved_in_full(self):
        full_by_id = {pair["id"]: pair for pair in self.full["pairs"]}
        for pair in self.prototype["pairs"]:
            self.assertEqual(full_by_id[pair["id"]], pair)


if __name__ == "__main__":
    unittest.main()
