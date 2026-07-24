from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "rag_accuracy_generate", HERE / "generate_golden_set.py"
)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def external(external_id: str):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def technique(stix_id: str, external_id: str, phase: str | tuple[str, ...], **extra):
    phases = (phase,) if isinstance(phase, str) else phase
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": external_id,
        "external_references": external(external_id),
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": phase_name}
            for phase_name in phases
        ],
        **extra,
    }


class PersistenceScopeTests(unittest.TestCase):
    def setUp(self):
        self.tactic = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--persistence",
            "name": "Persistence",
            "x_mitre_shortname": "persistence",
            "external_references": external("TA0003"),
        }
        self.mitigation = {
            "type": "course-of-action",
            "id": "course-of-action--active",
            "name": "Active mitigation",
            "external_references": external("M0001"),
        }

    def extract(self, *objects):
        return module.extract_persistence_scope(
            {"type": "bundle", "objects": [self.tactic, *objects]}
        )

    def test_extracts_only_persistence_and_its_mitigates_relationship(self):
        persistence = technique("attack-pattern--persistence", "T1001", "persistence")
        execution = technique("attack-pattern--execution", "T1002", "execution")
        relationship = {
            "type": "relationship",
            "id": "relationship--mitigates",
            "relationship_type": "mitigates",
            "source_ref": self.mitigation["id"],
            "target_ref": persistence["id"],
        }
        unrelated = {
            "type": "relationship",
            "id": "relationship--uses",
            "relationship_type": "uses",
            "source_ref": self.mitigation["id"],
            "target_ref": persistence["id"],
        }
        result = self.extract(
            persistence, execution, self.mitigation, relationship, unrelated
        )
        self.assertEqual([row["external_id"] for row in result["techniques"]], ["T1001"])
        self.assertEqual([row["external_id"] for row in result["mitigations"]], ["M0001"])
        self.assertEqual(
            [row["stix_id"] for row in result["mitigates_relationships"]],
            ["relationship--mitigates"],
        )
        self.assertEqual(
            result["technique_tactic_links"],
            [{
                "technique_ref": persistence["id"],
                "tactic_ref": self.tactic["id"],
                "kill_chain_name": "mitre-attack",
                "phase_name": "persistence",
            }],
        )

    def test_skips_revoked_and_deprecated_objects_and_dangling_relationships(self):
        active = technique("attack-pattern--active", "T1001", "persistence")
        revoked = technique(
            "attack-pattern--revoked", "T1002", "persistence", revoked=True
        )
        deprecated = technique(
            "attack-pattern--deprecated",
            "T1003",
            "persistence",
            x_mitre_deprecated=True,
        )
        revoked_mitigation = {
            "type": "course-of-action",
            "id": "course-of-action--revoked",
            "name": "Revoked",
            "revoked": True,
            "external_references": external("M0002"),
        }
        relationships = [
            {
                "type": "relationship",
                "id": "relationship--revoked-target",
                "relationship_type": "mitigates",
                "source_ref": self.mitigation["id"],
                "target_ref": revoked["id"],
            },
            {
                "type": "relationship",
                "id": "relationship--revoked-source",
                "relationship_type": "mitigates",
                "source_ref": revoked_mitigation["id"],
                "target_ref": active["id"],
            },
            {
                "type": "relationship",
                "id": "relationship--itself-revoked",
                "relationship_type": "mitigates",
                "source_ref": self.mitigation["id"],
                "target_ref": active["id"],
                "revoked": True,
            },
        ]
        result = self.extract(
            active,
            revoked,
            deprecated,
            self.mitigation,
            revoked_mitigation,
            *relationships,
        )
        self.assertEqual([row["external_id"] for row in result["techniques"]], ["T1001"])
        self.assertEqual(result["mitigations"], [])
        self.assertEqual(result["mitigates_relationships"], [])

    def test_requires_exactly_one_active_persistence_tactic(self):
        with self.assertRaises(module.PersistenceParserError):
            module.extract_persistence_scope({"type": "bundle", "objects": []})


class EnterpriseMitigationScopeTests(unittest.TestCase):
    def setUp(self):
        self.persistence = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--persistence",
            "name": "Persistence",
            "x_mitre_shortname": "persistence",
            "external_references": external("TA0003"),
        }
        self.execution = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--execution",
            "name": "Execution",
            "x_mitre_shortname": "execution",
            "external_references": external("TA0002"),
        }
        self.mitigation = {
            "type": "course-of-action",
            "id": "course-of-action--active",
            "name": "Active mitigation",
            "external_references": external("M0001"),
        }

    def extract(self, *objects):
        return module.extract_enterprise_mitigation_scope(
            {
                "type": "bundle",
                "objects": [self.persistence, self.execution, *objects],
            }
        )

    def test_deduplicates_techniques_and_preserves_all_tactics_and_negatives(self):
        multi_tactic = technique(
            "attack-pattern--multi",
            "T1001",
            ("execution", "persistence", "persistence"),
        )
        zero_mitigation = technique(
            "attack-pattern--zero", "T1002", "persistence"
        )
        relationship = {
            "type": "relationship",
            "id": "relationship--mitigates",
            "relationship_type": "mitigates",
            "source_ref": self.mitigation["id"],
            "target_ref": multi_tactic["id"],
        }
        unrelated = {
            "type": "relationship",
            "id": "relationship--uses",
            "relationship_type": "uses",
            "source_ref": self.mitigation["id"],
            "target_ref": multi_tactic["id"],
        }

        result = self.extract(
            multi_tactic, zero_mitigation, self.mitigation, relationship, unrelated
        )

        self.assertEqual(
            [row["external_id"] for row in result["techniques"]],
            ["T1001", "T1002"],
        )
        by_id = {row["external_id"]: row for row in result["techniques"]}
        self.assertEqual(
            {row["shortname"] for row in by_id["T1001"]["tactics"]},
            {"execution", "persistence"},
        )
        self.assertEqual(by_id["T1001"]["mitigation_status"], "has_mitigations")
        self.assertFalse(by_id["T1001"]["is_negative_case"])
        self.assertEqual(by_id["T1002"]["mitigation_status"], "zero_mitigations")
        self.assertTrue(by_id["T1002"]["is_negative_case"])
        self.assertEqual(len(result["technique_tactic_links"]), 3)
        self.assertEqual(len(result["mitigates_relationships"]), 1)
        self.assertEqual(
            module.enterprise_extraction_summary(result),
            {
                "active_techniques": 2,
                "mitigation_edges": 1,
                "distinct_mitigations_referenced": 1,
                "techniques_with_mitigations": 1,
                "techniques_with_zero_mitigations": 1,
                "techniques_with_multiple_tactics": 1,
            },
        )

    def test_excludes_inactive_objects_relationships_and_endpoints(self):
        active = technique("attack-pattern--active", "T1001", "persistence")
        revoked = technique(
            "attack-pattern--revoked", "T1002", "execution", revoked=True
        )
        deprecated = technique(
            "attack-pattern--deprecated",
            "T1003",
            "execution",
            x_mitre_deprecated=True,
        )
        revoked_mitigation = {
            "type": "course-of-action",
            "id": "course-of-action--revoked",
            "name": "Revoked mitigation",
            "external_references": external("M0002"),
            "revoked": True,
        }
        relationships = [
            {
                "type": "relationship",
                "id": "relationship--inactive-target",
                "relationship_type": "mitigates",
                "source_ref": self.mitigation["id"],
                "target_ref": revoked["id"],
            },
            {
                "type": "relationship",
                "id": "relationship--inactive-source",
                "relationship_type": "mitigates",
                "source_ref": revoked_mitigation["id"],
                "target_ref": active["id"],
            },
            {
                "type": "relationship",
                "id": "relationship--inactive-edge",
                "relationship_type": "mitigates",
                "source_ref": self.mitigation["id"],
                "target_ref": active["id"],
                "x_mitre_deprecated": True,
            },
        ]

        result = self.extract(
            active,
            revoked,
            deprecated,
            self.mitigation,
            revoked_mitigation,
            *relationships,
        )
        self.assertEqual(
            [row["external_id"] for row in result["techniques"]], ["T1001"]
        )
        self.assertEqual(result["mitigations"], [])
        self.assertEqual(result["mitigates_relationships"], [])
        self.assertTrue(result["techniques"][0]["is_negative_case"])

    def test_rejects_unknown_tactic_membership(self):
        unknown = technique("attack-pattern--unknown", "T1001", "unknown")
        with self.assertRaises(module.PersistenceParserError):
            self.extract(unknown)


class GoldenPairTests(unittest.TestCase):
    def test_pair_content_and_provenance_are_resolved_from_extracted_facts(self):
        extracted = {
            "tactic": {"stix_id": "x-mitre-tactic--persistence"},
            "techniques": [
                {
                    "stix_id": "attack-pattern--one",
                    "external_id": "T1001",
                    "name": "Example technique",
                    "is_subtechnique": False,
                }
            ],
            "mitigations": [
                {
                    "stix_id": "course-of-action--one",
                    "external_id": "M1001",
                    "name": "Example mitigation",
                }
            ],
            "mitigates_relationships": [
                {
                    "stix_id": "relationship--one",
                    "relationship_type": "mitigates",
                    "mitigation_ref": "course-of-action--one",
                    "technique_ref": "attack-pattern--one",
                }
            ],
        }
        source = {
            "repository": "https://example.invalid/source.git",
            "commit": "a" * 40,
            "path": "enterprise.json",
            "sha256": "b" * 64,
        }
        pair = module.generate_prototype_pairs(
            extracted, source, technique_ids=("T1001",)
        )[0]
        self.assertEqual(
            pair["question"], "What mitigates T1001 (Example technique)?"
        )
        self.assertEqual(
            pair["expected_answer"],
            "T1001 (Example technique) is mitigated by M1001 (Example mitigation).",
        )
        self.assertEqual(
            pair["provenance"]["relationship_stix_ids"], ["relationship--one"]
        )
        self.assertEqual(pair["provenance"]["stix_commit"], "a" * 40)


class EnterprisePairTests(unittest.TestCase):
    def test_generates_positive_and_negative_pairs_with_complete_provenance(self):
        tactics = [
            {
                "stix_id": "x-mitre-tactic--execution",
                "external_id": "TA0002",
                "name": "Execution",
                "shortname": "execution",
            },
            {
                "stix_id": "x-mitre-tactic--persistence",
                "external_id": "TA0003",
                "name": "Persistence",
                "shortname": "persistence",
            },
        ]
        extracted = {
            "techniques": [
                {
                    "stix_id": "attack-pattern--positive",
                    "external_id": "T1001",
                    "name": "Positive technique",
                    "is_subtechnique": False,
                    "tactics": tactics,
                    "mitigation_relationship_count": 1,
                    "mitigation_status": "has_mitigations",
                    "is_negative_case": False,
                },
                {
                    "stix_id": "attack-pattern--negative",
                    "external_id": "T1002",
                    "name": "Negative technique",
                    "is_subtechnique": False,
                    "tactics": tactics[:1],
                    "mitigation_relationship_count": 0,
                    "mitigation_status": "zero_mitigations",
                    "is_negative_case": True,
                },
            ],
            "mitigations": [
                {
                    "stix_id": "course-of-action--one",
                    "external_id": "M1001",
                    "name": "Example mitigation",
                }
            ],
            "mitigates_relationships": [
                {
                    "stix_id": "relationship--one",
                    "relationship_type": "mitigates",
                    "mitigation_ref": "course-of-action--one",
                    "technique_ref": "attack-pattern--positive",
                }
            ],
        }
        source = {
            "repository": "https://example.invalid/source.git",
            "commit": "a" * 40,
            "domain": "enterprise-attack",
            "path": "enterprise.json",
            "sha256": "b" * 64,
        }

        pairs = module.generate_enterprise_pairs(extracted, source)

        positive, negative = pairs
        self.assertEqual(positive["case_type"], "positive")
        self.assertEqual(
            positive["provenance"]["tactic_stix_ids"],
            [row["stix_id"] for row in tactics],
        )
        self.assertEqual(
            positive["provenance"]["relationship_stix_ids"],
            ["relationship--one"],
        )
        self.assertEqual(negative["case_type"], "negative")
        self.assertEqual(negative["expected_mitigations"], [])
        self.assertEqual(negative["provenance"]["mitigation_stix_ids"], [])
        self.assertEqual(negative["provenance"]["relationship_stix_ids"], [])
        self.assertIn(
            "No active mitigation relationship exists", negative["expected_answer"]
        )
        self.assertIn("pinned Enterprise ATT&CK snapshot", negative["expected_answer"])


class TacticPrototypePairTests(unittest.TestCase):
    def test_generates_complete_single_and_multi_tactic_answers(self):
        execution = {
            "stix_id": "x-mitre-tactic--execution",
            "external_id": "TA0002",
            "name": "Execution",
            "shortname": "execution",
        }
        persistence = {
            "stix_id": "x-mitre-tactic--persistence",
            "external_id": "TA0003",
            "name": "Persistence",
            "shortname": "persistence",
        }
        extracted = {
            "techniques": [
                {
                    "stix_id": "attack-pattern--single",
                    "external_id": "T1001",
                    "name": "Single technique",
                    "tactics": [execution],
                },
                {
                    "stix_id": "attack-pattern--multi",
                    "external_id": "T1002",
                    "name": "Multi technique",
                    "tactics": [execution, persistence],
                },
            ]
        }
        source = {
            "repository": "https://example.invalid/source.git",
            "commit": "a" * 40,
            "domain": "enterprise-attack",
            "path": "enterprise.json",
            "sha256": "b" * 64,
        }

        single, multi = module.generate_tactic_prototype_pairs(
            extracted, source, technique_ids=("T1001", "T1002")
        )

        self.assertEqual(single["case_type"], "single_tactic")
        self.assertEqual(
            single["expected_answer"],
            "T1001 (Single technique) belongs to the TA0002 (Execution) tactic.",
        )
        self.assertEqual(multi["case_type"], "multi_tactic")
        self.assertEqual(
            multi["expected_answer"],
            "T1002 (Multi technique) belongs to the TA0002 (Execution) and "
            "TA0003 (Persistence) tactics.",
        )
        self.assertEqual(
            multi["provenance"]["tactic_stix_ids"],
            [execution["stix_id"], persistence["stix_id"]],
        )
        self.assertEqual(
            [row["phase_name"] for row in multi["provenance"]["technique_tactic_links"]],
            ["execution", "persistence"],
        )
        self.assertEqual(
            multi["provenance"]["link_source"],
            "attack-pattern.kill_chain_phases",
        )


@unittest.skipUnless((HERE / "golden_set.json").exists(), "generate the full set first")
class GoldenSetArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads((HERE / "golden_set.json").read_text())
        cls.manifest = json.loads((HERE / "source_manifest.json").read_text())[
            module.SOURCE_KEY
        ]

    def test_has_one_unique_pair_per_active_technique(self):
        all_pairs = self.payload["pairs"]
        pairs = [
            pair
            for pair in all_pairs
            if pair["case_type"] in {"positive", "negative"}
        ]
        self.assertEqual(len(pairs), 697)
        self.assertEqual(len(all_pairs), 761)
        self.assertEqual(len({pair["id"] for pair in all_pairs}), 761)
        self.assertEqual(len({pair["question"] for pair in all_pairs}), 761)
        self.assertEqual(self.payload["selection"]["original_pair_count"], 697)
        self.assertEqual(self.payload["selection"]["reverse_aggregate_pairs"], 44)
        self.assertEqual(
            self.payload["selection"]["reverse_negative_existence_pairs"], 20
        )
        self.assertEqual(
            sum(pair["case_type"] == "positive" for pair in pairs), 586
        )
        self.assertEqual(
            sum(pair["case_type"] == "negative" for pair in pairs), 111
        )

    def test_every_pair_has_complete_matching_provenance(self):
        for pair in self.payload["pairs"][:697]:
            provenance = pair["provenance"]
            mitigations = pair["expected_mitigations"]
            self.assertEqual(provenance["stix_commit"], self.manifest["commit"])
            self.assertEqual(provenance["bundle_sha256"], self.manifest["sha256"])
            self.assertEqual(
                provenance["mitigation_stix_ids"],
                [row["stix_id"] for row in mitigations],
            )
            self.assertEqual(
                provenance["tactic_stix_ids"],
                [row["stix_id"] for row in provenance["tactics"]],
            )
            self.assertEqual(
                len(provenance["relationship_stix_ids"]), len(mitigations)
            )
            if pair["case_type"] == "positive":
                self.assertTrue(mitigations)
                self.assertTrue(
                    all(
                        row["external_id"] in pair["expected_answer"]
                        for row in mitigations
                    )
                )
            else:
                self.assertEqual(mitigations, [])
                self.assertEqual(provenance["relationship_stix_ids"], [])
                self.assertIn(
                    "No active mitigation relationship exists",
                    pair["expected_answer"],
                )


@unittest.skipUnless(
    (HERE / "golden_set_phase1_fixture.json").exists(),
    "Phase 1 fixture must be preserved",
)
class Phase1FixtureTests(unittest.TestCase):
    def test_verified_phase1_provenance_is_preserved_in_full_set(self):
        fixture = json.loads(
            (HERE / "golden_set_phase1_fixture.json").read_text()
        )
        full = json.loads((HERE / "golden_set.json").read_text())
        full_by_technique = {
            pair["provenance"]["technique_stix_id"]: pair
            for pair in full["pairs"][:697]
        }
        self.assertEqual(len(fixture["pairs"]), 10)
        for fixture_pair in fixture["pairs"]:
            full_pair = full_by_technique[
                fixture_pair["provenance"]["technique_stix_id"]
            ]
            self.assertEqual(
                full_pair["provenance"]["mitigation_stix_ids"],
                fixture_pair["provenance"]["mitigation_stix_ids"],
            )
            self.assertEqual(
                full_pair["provenance"]["relationship_stix_ids"],
                fixture_pair["provenance"]["relationship_stix_ids"],
            )


@unittest.skipUnless(
    (HERE / "golden_set_technique_tactic_prototype.json").exists(),
    "generate the tactic prototype first",
)
class TacticPrototypeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(
            (HERE / "golden_set_technique_tactic_prototype.json").read_text()
        )
        cls.manifest = json.loads((HERE / "source_manifest.json").read_text())[
            module.SOURCE_KEY
        ]

    def test_has_ten_unique_balanced_pairs(self):
        pairs = self.payload["pairs"]
        self.assertEqual(len(pairs), 10)
        self.assertEqual(len({pair["id"] for pair in pairs}), 10)
        self.assertEqual(len({pair["question"] for pair in pairs}), 10)
        self.assertEqual(
            self.payload["selection"],
            {
                "method": "fixed_representative_ids_resolved_from_pinned_stix",
                "pair_count": 10,
                "single_tactic_pairs": 5,
                "multi_tactic_pairs": 5,
                "technique_external_ids": list(
                    module.TACTIC_PROTOTYPE_TECHNIQUE_IDS
                ),
            },
        )

    def test_every_pair_has_complete_matching_provenance(self):
        for pair in self.payload["pairs"]:
            provenance = pair["provenance"]
            tactics = pair["expected_tactics"]
            self.assertEqual(provenance["stix_commit"], self.manifest["commit"])
            self.assertEqual(provenance["bundle_sha256"], self.manifest["sha256"])
            self.assertEqual(
                provenance["tactic_stix_ids"],
                [row["stix_id"] for row in tactics],
            )
            self.assertEqual(
                len(provenance["technique_tactic_links"]), len(tactics)
            )
            self.assertTrue(
                all(row["external_id"] in pair["expected_answer"] for row in tactics)
            )


@unittest.skipUnless(
    (HERE / "golden_set_technique_tactic.json").exists(),
    "generate the full tactic set first",
)
class EnterpriseTacticArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(
            (HERE / "golden_set_technique_tactic.json").read_text()
        )
        cls.prototype = json.loads(
            (HERE / "golden_set_technique_tactic_prototype.json").read_text()
        )
        cls.manifest = json.loads((HERE / "source_manifest.json").read_text())[
            module.SOURCE_KEY
        ]

    def test_has_one_unique_pair_per_active_technique(self):
        all_pairs = self.payload["pairs"]
        pairs = [
            pair
            for pair in all_pairs
            if pair["case_type"] in {"single_tactic", "multi_tactic"}
        ]
        self.assertEqual(len(pairs), 697)
        self.assertEqual(len(all_pairs), 792)
        self.assertEqual(len({pair["id"] for pair in all_pairs}), 792)
        self.assertEqual(len({pair["question"] for pair in all_pairs}), 792)
        self.assertEqual(self.payload["selection"]["original_pair_count"], 697)
        self.assertEqual(self.payload["selection"]["reverse_aggregate_pairs"], 15)
        self.assertEqual(
            self.payload["selection"]["reverse_negative_existence_pairs"], 15
        )
        self.assertEqual(
            self.payload["selection"]["adversarial_negative_pairs"], 65
        )

    def test_every_pair_has_complete_matching_provenance(self):
        for pair in self.payload["pairs"][:697]:
            provenance = pair["provenance"]
            tactics = pair["expected_tactics"]
            self.assertTrue(tactics)
            self.assertEqual(provenance["stix_commit"], self.manifest["commit"])
            self.assertEqual(provenance["bundle_sha256"], self.manifest["sha256"])
            self.assertEqual(
                provenance["tactic_stix_ids"],
                [row["stix_id"] for row in tactics],
            )
            self.assertEqual(
                len(provenance["technique_tactic_links"]), len(tactics)
            )
            self.assertEqual(
                pair["case_type"],
                "single_tactic" if len(tactics) == 1 else "multi_tactic",
            )
            self.assertTrue(
                all(row["external_id"] in pair["expected_answer"] for row in tactics)
            )

    def test_verified_prototype_is_preserved_in_full_set(self):
        full_by_technique = {
            pair["provenance"]["technique_stix_id"]: pair
            for pair in self.payload["pairs"][:697]
        }
        self.assertEqual(len(self.prototype["pairs"]), 10)
        for prototype_pair in self.prototype["pairs"]:
            full_pair = full_by_technique[
                prototype_pair["provenance"]["technique_stix_id"]
            ]
            self.assertEqual(
                full_pair["expected_tactics"], prototype_pair["expected_tactics"]
            )
            self.assertEqual(
                full_pair["provenance"]["technique_tactic_links"],
                prototype_pair["provenance"]["technique_tactic_links"],
            )


if __name__ == "__main__":
    unittest.main()
