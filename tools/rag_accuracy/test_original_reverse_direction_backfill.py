from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
PREFIX_EXPECTATIONS = {
    "golden_set.json": (
        697,
        "7ef540379c8532031f369a7a227a2236fa9b3324d60be93401a79ffe693f62e8",
    ),
    "golden_set_technique_tactic.json": (
        697,
        "379e568debb39a77e9fb053eb7852b87bb852249f6105760750bb40d783dfc3a",
    ),
    "golden_set_group_technique.json": (
        194,
        "1289c48804c45afdd0dc694787238512c044a673208cbbcd82ca15f2c6b53379",
    ),
    "golden_set_software_technique.json": (
        846,
        "522150cd6ad4bf639ff60dd75797e267aeca048402943eea3d83b002f268a0e9",
    ),
    "golden_set_group_software.json": (
        194,
        "cb02710561407db5c308b573bb73960e147eab44fbc9cc9363361285c27cea71",
    ),
    "golden_set_campaign_group.json": (
        66,
        "9145043ab57cb27431bbdd462f5d110a654d42667718a2da4ca5f093dac17216",
    ),
    "golden_set_technique_detection_strategy_prototype.json": (
        10,
        "df4ae01802f287098e241cf0972119c490b1c027583beeea2189d5c45b31b9f0",
    ),
}
REVERSE_COUNTS = {
    "golden_set.json": (44, 0, 20, 761),
    "golden_set_technique_tactic.json": (15, 0, 15, 792),
    "golden_set_group_technique.json": (697, 183, 20, 911),
    "golden_set_software_technique.json": (697, 210, 25, 1687),
    "golden_set_group_software.json": (821, 210, 20, 1106),
    "golden_set_campaign_group.json": (174, 155, 10, 250),
}
NEGATIVE_MEMBERSHIP_FIELDS = {
    "golden_set.json": ("mitigation", "queried_technique", "expected_techniques"),
    "golden_set_technique_tactic.json": (
        "tactic",
        "queried_technique",
        "expected_techniques",
    ),
    "golden_set_group_technique.json": (
        "technique",
        "queried_group",
        "expected_groups",
    ),
    "golden_set_software_technique.json": (
        "technique",
        "queried_software",
        "expected_software",
    ),
    "golden_set_group_software.json": (
        "software",
        "queried_group",
        "expected_groups",
    ),
    "golden_set_campaign_group.json": (
        "group",
        "queried_campaign",
        "expected_campaigns",
    ),
}


def load(name: str) -> dict:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def pair_hash(pairs: list[dict]) -> str:
    canonical = json.dumps(
        pairs, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


class OriginalReverseDirectionBackfillTests(unittest.TestCase):
    def test_every_original_pair_is_byte_semantically_unchanged(self):
        for filename, (count, expected_hash) in PREFIX_EXPECTATIONS.items():
            with self.subTest(filename=filename):
                pairs = load(filename)["pairs"]
                self.assertEqual(pair_hash(pairs[:count]), expected_hash)

    def test_reverse_counts_and_zero_paths_are_explicit(self):
        for filename, expected in REVERSE_COUNTS.items():
            with self.subTest(filename=filename):
                selection = load(filename)["selection"]
                actual = (
                    selection["reverse_aggregate_pairs"],
                    selection["reverse_zero_path_pairs"],
                    selection["reverse_negative_existence_pairs"],
                    selection["pair_count"],
                )
                self.assertEqual(actual, expected)

    def test_reverse_negative_cases_have_no_claimed_path(self):
        for filename, (original_count, _) in PREFIX_EXPECTATIONS.items():
            if filename not in REVERSE_COUNTS:
                continue
            with self.subTest(filename=filename):
                reverse = load(filename)["pairs"][original_count:]
                negatives = [
                    pair
                    for pair in reverse
                    if pair["case_type"].startswith("negative_")
                ]
                self.assertTrue(negatives)
                anchor_key, queried_key, expected_key = (
                    NEGATIVE_MEMBERSHIP_FIELDS[filename]
                )
                aggregates = {
                    pair[anchor_key]["stix_id"]: pair
                    for pair in reverse
                    if pair["case_type"].startswith("aggregate_")
                }
                for pair in negatives:
                    self.assertFalse(pair["relationship_exists"])
                    aggregate = aggregates[pair[anchor_key]["stix_id"]]
                    self.assertNotIn(
                        pair[queried_key]["stix_id"],
                        {
                            item["stix_id"]
                            for item in aggregate[expected_key]
                        },
                    )
                    provenance = pair["provenance"]
                    relationship_fields = [
                        value
                        for key, value in provenance.items()
                        if key.endswith("relationship_stix_ids")
                        or key == "technique_tactic_links"
                    ]
                    self.assertTrue(relationship_fields)
                    self.assertTrue(all(not value for value in relationship_fields))

    def test_spot_checked_reverse_facts(self):
        checks = [
            (
                "golden_set.json",
                "mitigation",
                "M1024",
                "expected_techniques",
                "T1112",
            ),
            (
                "golden_set_technique_tactic.json",
                "tactic",
                "TA0003",
                "expected_techniques",
                "T1053",
            ),
            (
                "golden_set_group_technique.json",
                "technique",
                "T1078",
                "expected_groups",
                "G0016",
            ),
            (
                "golden_set_software_technique.json",
                "technique",
                "T1078",
                "expected_software",
                "S0053",
            ),
            (
                "golden_set_group_software.json",
                "software",
                "S0002",
                "expected_groups",
                "G0016",
            ),
            (
                "golden_set_campaign_group.json",
                "group",
                "G0016",
                "expected_campaigns",
                "C0024",
            ),
        ]
        for filename, anchor_key, anchor_id, expected_key, expected_id in checks:
            with self.subTest(filename=filename, anchor=anchor_id):
                pair = next(
                    pair
                    for pair in load(filename)["pairs"]
                    if pair.get(anchor_key, {}).get("external_id") == anchor_id
                    and pair["case_type"].startswith("aggregate_")
                )
                self.assertIn(
                    expected_id,
                    {item["external_id"] for item in pair[expected_key]},
                )

    def test_adversarial_sibling_negatives_are_real_contextual_non_edges(self):
        expectations = {
            "golden_set_technique_tactic.json": (
                "adversarial_negative_technique_tactic",
                65,
            ),
            "golden_set_software_technique.json": (
                "adversarial_negative_software_technique",
                119,
            ),
            "golden_set_group_software.json": (
                "adversarial_negative_group_software",
                71,
            ),
        }
        for filename, (case_type, expected_count) in expectations.items():
            with self.subTest(filename=filename):
                artifact = load(filename)
                negatives = [
                    pair
                    for pair in artifact["pairs"]
                    if pair["case_type"] == case_type
                ]
                self.assertEqual(len(negatives), expected_count)
                self.assertGreaterEqual(
                    artifact["selection"]["total_negative_ratio"], 0.08
                )
                self.assertLessEqual(
                    artifact["selection"]["total_negative_ratio"], 0.15
                )
                sample = negatives[0]
                self.assertFalse(sample["relationship_exists"])
                context = sample["provenance"]["adversarial_context"]
                self.assertEqual(
                    sample["provenance"]["difficulty"],
                    "adversarial_sibling",
                )
                if filename == "golden_set_technique_tactic.json":
                    self.assertTrue(context["anchor_shared_tactic_links"])
                    self.assertEqual(
                        len(context["sibling_context_tactic_links"]), 2
                    )
                    queried_id = sample["queried_technique"]["external_id"]
                    forward = next(
                        pair
                        for pair in artifact["pairs"]
                        if pair["id"]
                        == f"enterprise-tactics-{queried_id.lower()}"
                    )
                    self.assertNotIn(
                        sample["tactic"]["stix_id"],
                        {
                            item["stix_id"]
                            for item in forward["expected_tactics"]
                        },
                    )
                elif filename == "golden_set_software_technique.json":
                    self.assertTrue(
                        context[
                            "context_to_anchor_relationship_stix_ids"
                        ]
                    )
                    self.assertTrue(
                        context[
                            "context_to_sibling_relationship_stix_ids"
                        ]
                    )
                    self.assertTrue(
                        context["sibling_software_technique_paths"]
                    )
                    forward = next(
                        pair
                        for pair in artifact["pairs"]
                        if pair.get("software", {}).get("stix_id")
                        == sample["software"]["stix_id"]
                        and pair["case_type"]
                        == "aggregate_software_techniques"
                    )
                    self.assertNotIn(
                        sample["queried_technique"]["stix_id"],
                        {
                            item["stix_id"]
                            for item in forward["expected_techniques"]
                        },
                    )
                else:
                    self.assertTrue(
                        context["anchor_shared_technique_paths"]
                    )
                    self.assertTrue(
                        context["sibling_shared_technique_paths"]
                    )
                    self.assertTrue(context["sibling_software_paths"])
                    forward = next(
                        pair
                        for pair in artifact["pairs"]
                        if pair.get("group", {}).get("stix_id")
                        == sample["group"]["stix_id"]
                        and pair["case_type"]
                        in {
                            "aggregate_group_software",
                            "aggregate_group_no_qualifying_software",
                        }
                    )
                    self.assertNotIn(
                        sample["queried_software"]["stix_id"],
                        {
                            item["stix_id"]
                            for item in forward["expected_software"]
                        },
                    )

    def test_detection_reverse_spot_check(self):
        full = load("golden_set_technique_detection_strategy.json")
        pair = next(
            pair
            for pair in full["pairs"]
            if pair.get("detection_strategy", {}).get("external_id")
            == "DET0560"
        )
        self.assertEqual(pair["expected_technique"]["external_id"], "T1078")
        self.assertEqual(
            pair["provenance"]["detects_relationship_stix_id"],
            "relationship--1b5cdb10-15a7-48ac-ab23-33edf7ef5602",
        )


if __name__ == "__main__":
    unittest.main()
