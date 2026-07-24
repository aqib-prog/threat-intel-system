from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_group_technique",
    HERE / "generate_group_technique_prototype.py",
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def relationship(
    stix_id: str,
    relationship_type: str,
    source_ref: str,
    target_ref: str,
    **extra,
):
    return {
        "type": "relationship",
        "id": stix_id,
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        **extra,
    }


class GroupTechniqueScopeTests(unittest.TestCase):
    def setUp(self):
        self.group = {
            "type": "intrusion-set",
            "id": "intrusion-set--one",
            "name": "Example Group",
            "aliases": ["Example Group"],
            "external_references": external("G0001"),
        }
        self.technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--one",
            "name": "Example Technique",
            "external_references": external("T1001"),
        }

    def extract(self, *objects):
        return module.extract_group_technique_scope(
            {"type": "bundle", "objects": [self.group, self.technique, *objects]},
            group_ids=("G0001",),
        )

    def test_unions_direct_and_campaign_paths_with_complete_ids(self):
        campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
        }
        campaign_only = {
            "type": "attack-pattern",
            "id": "attack-pattern--two",
            "name": "Campaign Technique",
            "external_references": external("T1002"),
        }
        objects = [
            campaign,
            campaign_only,
            relationship(
                "relationship--direct",
                "uses",
                self.group["id"],
                self.technique["id"],
            ),
            relationship(
                "relationship--attribution",
                "attributed-to",
                campaign["id"],
                self.group["id"],
            ),
            relationship(
                "relationship--campaign-overlap",
                "uses",
                campaign["id"],
                self.technique["id"],
            ),
            relationship(
                "relationship--campaign-only",
                "uses",
                campaign["id"],
                campaign_only["id"],
            ),
        ]

        result = self.extract(*objects)
        paths = result["paths"]
        metrics = result["scope_metrics_by_group"][self.group["id"]]

        self.assertEqual(
            [row["external_id"] for row in result["techniques"]],
            ["T1001", "T1002"],
        )
        self.assertEqual(len(paths), 3)
        self.assertEqual(metrics["direct_technique_count"], 1)
        self.assertEqual(metrics["campaign_attributed_technique_count"], 2)
        self.assertEqual(metrics["direct_and_campaign_overlap_count"], 1)
        self.assertEqual(metrics["merged_technique_count"], 2)
        campaign_path = next(
            path
            for path in paths
            if path["technique_ref"] == campaign_only["id"]
        )
        self.assertEqual(campaign_path["campaign_ref"], campaign["id"])
        self.assertEqual(
            campaign_path["attributed_to_relationship_stix_id"],
            "relationship--attribution",
        )
        self.assertEqual(
            campaign_path["campaign_uses_relationship_stix_id"],
            "relationship--campaign-only",
        )

    def test_excludes_software_paths_and_keeps_parent_and_subtechnique_edges(self):
        software = {
            "type": "malware",
            "id": "malware--one",
            "name": "Example Malware",
            "external_references": external("S0001"),
        }
        subtechnique = {
            "type": "attack-pattern",
            "id": "attack-pattern--sub",
            "name": "Example Sub-technique",
            "x_mitre_is_subtechnique": True,
            "external_references": external("T1001.001"),
        }
        software_only = {
            "type": "attack-pattern",
            "id": "attack-pattern--software-only",
            "name": "Software-only Technique",
            "external_references": external("T1002"),
        }
        objects = [
            software,
            subtechnique,
            software_only,
            relationship(
                "relationship--parent",
                "uses",
                self.group["id"],
                self.technique["id"],
            ),
            relationship(
                "relationship--sub",
                "uses",
                self.group["id"],
                subtechnique["id"],
            ),
            relationship(
                "relationship--group-software",
                "uses",
                self.group["id"],
                software["id"],
            ),
            relationship(
                "relationship--software-technique",
                "uses",
                software["id"],
                software_only["id"],
            ),
        ]

        result = self.extract(*objects)

        self.assertEqual(
            [row["external_id"] for row in result["techniques"]],
            ["T1001", "T1001.001"],
        )
        self.assertNotIn(
            "attack-pattern--software-only",
            {path["technique_ref"] for path in result["paths"]},
        )

    def test_excludes_inactive_relationships_and_endpoints_from_both_paths(self):
        campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
        }
        revoked_campaign = {
            **campaign,
            "id": "campaign--revoked",
            "external_references": external("C0002"),
            "revoked": True,
        }
        objects = [
            campaign,
            revoked_campaign,
            relationship(
                "relationship--revoked-direct",
                "uses",
                self.group["id"],
                self.technique["id"],
                revoked=True,
            ),
            relationship(
                "relationship--deprecated-attribution",
                "attributed-to",
                campaign["id"],
                self.group["id"],
                x_mitre_deprecated=True,
            ),
            relationship(
                "relationship--revoked-campaign-attribution",
                "attributed-to",
                revoked_campaign["id"],
                self.group["id"],
            ),
            relationship(
                "relationship--campaign-use",
                "uses",
                campaign["id"],
                self.technique["id"],
            ),
        ]

        result = self.extract(*objects)

        self.assertEqual(result["techniques"], [])
        self.assertEqual(result["paths"], [])
        self.assertEqual(
            result["extraction_audit"]["uses"]["inactive_relationship_count"],
            1,
        )
        self.assertEqual(
            result["extraction_audit"]["attributed_to"][
                "inactive_relationship_count"
            ],
            1,
        )

    def test_all_group_summary_includes_empty_groups_and_counts_each_distribution(self):
        empty_group = {
            "type": "intrusion-set",
            "id": "intrusion-set--empty",
            "name": "Empty Group",
            "external_references": external("G0002"),
        }
        campaign_group = {
            "type": "intrusion-set",
            "id": "intrusion-set--campaign",
            "name": "Campaign Group",
            "external_references": external("G0003"),
        }
        attributed_without_techniques_group = {
            "type": "intrusion-set",
            "id": "intrusion-set--attributed-empty",
            "name": "Attributed Empty Group",
            "external_references": external("G0004"),
        }
        campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
        }
        campaign_without_techniques = {
            "type": "campaign",
            "id": "campaign--empty",
            "name": "Campaign Without Techniques",
            "external_references": external("C0002"),
        }
        bundle = {
            "type": "bundle",
            "objects": [
                self.group,
                empty_group,
                campaign_group,
                attributed_without_techniques_group,
                campaign,
                campaign_without_techniques,
                self.technique,
                relationship(
                    "relationship--direct",
                    "uses",
                    self.group["id"],
                    self.technique["id"],
                ),
                relationship(
                    "relationship--attribution",
                    "attributed-to",
                    campaign["id"],
                    campaign_group["id"],
                ),
                relationship(
                    "relationship--campaign-use",
                    "uses",
                    campaign["id"],
                    self.technique["id"],
                ),
                relationship(
                    "relationship--empty-campaign-attribution",
                    "attributed-to",
                    campaign_without_techniques["id"],
                    attributed_without_techniques_group["id"],
                ),
            ],
        }

        result = module.extract_group_technique_scope(bundle, group_ids=None)
        summary = module.all_group_scope_summary(result)

        self.assertEqual(summary["active_group_count"], 4)
        self.assertEqual(summary["merged_group_technique_pair_count"], 2)
        self.assertEqual(summary["groups_with_zero_direct_techniques"], 3)
        self.assertEqual(
            summary["groups_with_zero_campaign_attributed_techniques"], 3
        )
        self.assertEqual(
            summary["groups_with_zero_direct_and_zero_campaign_techniques"], 2
        )
        self.assertEqual(summary["groups_with_at_least_one_attributed_campaign"], 2)
        self.assertEqual(summary["groups_with_no_attributed_campaign"], 2)
        self.assertEqual(summary["parent_subtechnique_deduplication"], "none")
        self.assertFalse(summary["per_group_special_casing"])


class GroupTechniquePairTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            "repository": "https://example.invalid/source.git",
            "commit": "a" * 40,
            "domain": "enterprise-attack",
            "path": "enterprise.json",
            "sha256": "b" * 64,
        }

    def synthetic_extracted(self, *, include_empty_group: bool = False):
        group = {
            "type": "intrusion-set",
            "id": "intrusion-set--one",
            "name": "Example Group",
            "aliases": ["Example Group"],
            "external_references": external("G0001"),
        }
        direct_and_campaign = {
            "type": "attack-pattern",
            "id": "attack-pattern--one",
            "name": "Both-path Technique",
            "external_references": external("T1001"),
        }
        absent = {
            "type": "attack-pattern",
            "id": "attack-pattern--absent",
            "name": "Absent Technique",
            "external_references": external("T1002"),
        }
        campaign = {
            "type": "campaign",
            "id": "campaign--one",
            "name": "Example Campaign",
            "external_references": external("C0001"),
        }
        empty_group = {
            "type": "intrusion-set",
            "id": "intrusion-set--empty",
            "name": "Empty Group",
            "aliases": ["Empty Group"],
            "external_references": external("G0002"),
        }
        objects = [
            group,
            direct_and_campaign,
            absent,
            campaign,
            relationship(
                "relationship--direct",
                "uses",
                group["id"],
                direct_and_campaign["id"],
            ),
            relationship(
                "relationship--attribution",
                "attributed-to",
                campaign["id"],
                group["id"],
            ),
            relationship(
                "relationship--campaign-use",
                "uses",
                campaign["id"],
                direct_and_campaign["id"],
            ),
        ]
        if include_empty_group:
            objects.append(empty_group)
        bundle = {
            "type": "bundle",
            "objects": objects,
        }
        group_ids = None if include_empty_group else ("G0001",)
        return module.extract_group_technique_scope(bundle, group_ids=group_ids)

    def test_pair_provenance_records_every_path_for_each_technique(self):
        pairs = module.generate_prototype_pairs(
            self.synthetic_extracted(),
            self.source,
            focused_technique_by_group={"G0001": "T1001"},
            negative_technique_by_group={"G0001": "T1002"},
        )
        aggregate, focused, negative = pairs
        record = aggregate["provenance"]["technique_paths"][0]

        self.assertEqual(
            record["path_types"], ["campaign_attributed", "direct"]
        )
        self.assertEqual(len(record["paths"]), 2)
        self.assertIn("Software-mediated techniques are excluded", aggregate[
            "provenance"
        ]["methodology_note"])
        self.assertEqual(
            aggregate["provenance"]["parent_subtechnique_deduplication"],
            "none",
        )
        self.assertEqual(len(focused["provenance"]["technique_paths"][0]["paths"]), 2)
        self.assertEqual(negative["expected_techniques"], [])
        self.assertEqual(negative["provenance"]["technique_paths"], [])
        self.assertIn(
            "No active direct or campaign-attributed uses path exists",
            negative["expected_answer"],
        )

    def test_rejects_negative_case_reachable_through_campaign(self):
        with self.assertRaisesRegex(
            module.GroupTechniqueParserError,
            "has 2 qualifying path",
        ):
            module.generate_prototype_pairs(
                self.synthetic_extracted(),
                self.source,
                focused_technique_by_group={"G0001": "T1001"},
                negative_technique_by_group={"G0001": "T1001"},
            )

    def test_full_aggregates_mark_empty_groups_and_negative_selection_is_absent(self):
        extracted = self.synthetic_extracted(include_empty_group=True)
        aggregates = module.generate_full_aggregate_pairs(extracted, self.source)
        negative_cases = module.select_full_negative_cases(
            extracted,
            count=1,
            preserved_cases={},
            probe_technique_ids=("T1002",),
        )
        negatives = module.generate_negative_existence_pairs(
            extracted, self.source, negative_cases
        )

        self.assertEqual(len(aggregates), 2)
        self.assertEqual(
            [pair["case_type"] for pair in aggregates],
            [
                "aggregate_group_techniques",
                "aggregate_group_no_qualifying_techniques",
            ],
        )
        self.assertEqual(aggregates[1]["expected_techniques"], [])
        self.assertIn(
            "No active direct or campaign-attributed group-to-technique path",
            aggregates[1]["expected_answer"],
        )
        self.assertEqual(negative_cases, {"G0001": "T1002"})
        self.assertEqual(len(negatives), 1)
        self.assertEqual(negatives[0]["provenance"]["technique_paths"], [])


@unittest.skipUnless(
    (HERE / "golden_set_group_technique_prototype.json").exists(),
    "generate the group prototype first",
)
class GroupTechniqueArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(
            (HERE / "golden_set_group_technique_prototype.json").read_text()
        )
        cls.manifest = json.loads((HERE / "source_manifest.json").read_text())[
            "enterprise_attack_stix"
        ]

    def test_scope_and_expected_five_group_totals(self):
        self.assertEqual(
            self.payload["scope"]["aggregate_answer_scope"],
            "direct_group_to_technique_union_campaign_attributed",
        )
        self.assertEqual(
            self.payload["scope"]["included_paths"],
            ["direct", "campaign_attributed"],
        )
        self.assertTrue(
            self.payload["scope"]["software_mediated_techniques_excluded"]
        )
        self.assertEqual(
            self.payload["scope"]["parent_subtechnique_deduplication"], "none"
        )
        self.assertEqual(self.payload["selection"]["group_count"], 5)
        self.assertEqual(self.payload["selection"]["pair_count"], 13)
        expected_totals = {
            "G0007": 101,
            "G0016": 119,
            "G0032": 119,
            "G0034": 99,
            "G0046": 67,
        }
        actual_totals = {
            row["external_id"]: row["merged_technique_count"]
            for row in self.payload["extraction"]["groups"]
        }
        self.assertEqual(actual_totals, expected_totals)

    def test_every_pair_has_complete_per_technique_path_provenance(self):
        for pair in self.payload["pairs"]:
            provenance = pair["provenance"]
            techniques = pair["expected_techniques"]
            self.assertEqual(provenance["stix_commit"], self.manifest["commit"])
            self.assertEqual(provenance["bundle_sha256"], self.manifest["sha256"])
            self.assertEqual(
                provenance["technique_stix_ids"],
                [technique["stix_id"] for technique in techniques],
            )
            self.assertEqual(
                [record["technique_stix_id"] for record in provenance["technique_paths"]],
                [technique["stix_id"] for technique in techniques],
            )
            for record in provenance["technique_paths"]:
                self.assertGreater(len(record["paths"]), 0)
                self.assertEqual(
                    record["path_types"],
                    sorted({path["path_type"] for path in record["paths"]}),
                )
                self.assertTrue(
                    set(record["path_types"]) <= {"direct", "campaign_attributed"}
                )

    def test_apt29_keeps_parent_and_subtechnique_entries(self):
        apt29 = next(
            pair
            for pair in self.payload["pairs"]
            if pair["id"] == "group-uses-techniques-g0016"
        )
        ids = {technique["external_id"] for technique in apt29["expected_techniques"]}

        self.assertEqual(len(ids), 119)
        self.assertTrue({"T1685", "T1685.001", "T1685.002"} <= ids)

    def test_three_negatives_have_zero_direct_or_campaign_paths(self):
        negatives = [
            pair
            for pair in self.payload["pairs"]
            if pair["case_type"] == "negative_group_technique"
        ]
        self.assertEqual(len(negatives), 3)
        for pair in negatives:
            self.assertEqual(pair["expected_techniques"], [])
            self.assertEqual(pair["provenance"]["relationship_stix_ids"], [])
            self.assertEqual(pair["provenance"]["campaign_stix_ids"], [])
            self.assertEqual(pair["provenance"]["technique_paths"], [])


@unittest.skipUnless(
    (HERE / "golden_set_group_technique.json").exists(),
    "generate the full group golden set first",
)
class FullGroupTechniqueArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(
            (HERE / "golden_set_group_technique.json").read_text()
        )
        cls.prototype = json.loads(
            (HERE / "golden_set_group_technique_prototype.json").read_text()
        )

    def test_expected_fact_and_pair_breakdown(self):
        selection = self.payload["selection"]
        self.assertEqual(selection["active_group_count"], 174)
        self.assertEqual(selection["embedded_group_technique_fact_count"], 4826)
        self.assertEqual(selection["pair_count"], 911)
        self.assertEqual(selection["original_pair_count"], 194)
        self.assertEqual(selection["reverse_aggregate_pairs"], 697)
        self.assertEqual(selection["reverse_zero_path_pairs"], 183)
        self.assertEqual(selection["reverse_negative_existence_pairs"], 20)
        self.assertEqual(selection["positive_aggregate_pairs"], 171)
        self.assertEqual(selection["zero_path_aggregate_pairs"], 3)
        self.assertEqual(selection["negative_existence_pairs"], 20)
        self.assertEqual(selection["negative_existence_distinct_group_count"], 20)
        self.assertEqual(selection["prototype_negative_cases_preserved"], 3)

    def test_has_exactly_one_aggregate_per_active_group(self):
        aggregates = [
            pair for pair in self.payload["pairs"]
            if pair["case_type"].startswith("aggregate_group_")
        ]
        self.assertEqual(len(aggregates), 174)
        self.assertEqual(
            len({pair["group"]["external_id"] for pair in aggregates}), 174
        )
        self.assertEqual(
            sum(len(pair["expected_techniques"]) for pair in aggregates), 4826
        )

    def test_zero_path_groups_are_explicit_negative_style_aggregates(self):
        zero_path = [
            pair for pair in self.payload["pairs"]
            if pair["case_type"] == "aggregate_group_no_qualifying_techniques"
        ]
        self.assertEqual(len(zero_path), 3)
        for pair in zero_path:
            self.assertEqual(pair["expected_techniques"], [])
            self.assertEqual(pair["provenance"]["technique_paths"], [])
            self.assertEqual(pair["provenance"]["direct_technique_count"], 0)
            self.assertEqual(
                pair["provenance"]["campaign_attributed_technique_count"], 0
            )
            self.assertIn(
                "No active direct or campaign-attributed group-to-technique path",
                pair["expected_answer"],
            )

    def test_negative_existence_cases_are_distinct_and_have_no_paths(self):
        negatives = [
            pair for pair in self.payload["pairs"]
            if pair["case_type"] == "negative_group_technique"
        ]
        self.assertEqual(len(negatives), 20)
        self.assertEqual(
            len({pair["group"]["external_id"] for pair in negatives}), 20
        )
        for pair in negatives:
            provenance = pair["provenance"]
            self.assertEqual(pair["expected_techniques"], [])
            self.assertEqual(provenance["technique_paths"], [])
            self.assertEqual(provenance["relationship_stix_ids"], [])
            self.assertEqual(provenance["campaign_stix_ids"], [])
            self.assertEqual(
                provenance["queried_technique_stix_id"],
                pair["queried_technique"]["stix_id"],
            )

    def test_every_positive_aggregate_has_complete_path_provenance(self):
        positives = [
            pair for pair in self.payload["pairs"]
            if pair["case_type"] == "aggregate_group_techniques"
        ]
        self.assertEqual(len(positives), 171)
        for pair in positives:
            technique_ids = [
                technique["stix_id"] for technique in pair["expected_techniques"]
            ]
            path_records = pair["provenance"]["technique_paths"]
            self.assertEqual(
                [record["technique_stix_id"] for record in path_records],
                technique_ids,
            )
            self.assertTrue(all(record["paths"] for record in path_records))

    def test_verified_prototype_aggregates_and_negatives_are_preserved(self):
        full_pairs = {pair["id"]: pair for pair in self.payload["pairs"]}
        preserved = [
            pair for pair in self.prototype["pairs"]
            if pair["case_type"] in {
                "aggregate_group_techniques",
                "negative_group_technique",
            }
        ]
        self.assertEqual(len(preserved), 8)
        for prototype_pair in preserved:
            self.assertEqual(full_pairs[prototype_pair["id"]], prototype_pair)


if __name__ == "__main__":
    unittest.main()
