from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
GENERATOR = HERE / "build_final_golden_set.py"
SPEC = importlib.util.spec_from_file_location("build_final_golden_set", GENERATOR)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class FinalGoldenSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selected, cls.manifests = module.select_source_cases()
        cls.source_by_key = {
            (selected["artifact"], selected["pair"]["id"]): selected["pair"]
            for selected in cls.selected
        }

    def test_samples_four_cases_from_each_of_thirteen_full_artifacts(self):
        self.assertEqual(len(module.ARTIFACT_SPECS), 13)
        self.assertEqual(len(self.selected), 52)
        self.assertNotIn(
            "golden_set_phase1_fixture.json",
            {selected["artifact"] for selected in self.selected},
        )
        counts = {}
        for selected in self.selected:
            counts[selected["relationship_type"]] = (
                counts.get(selected["relationship_type"], 0) + 1
            )
        self.assertEqual(set(counts.values()), {4})

    def test_sampling_and_typo_generation_are_deterministic(self):
        again, again_manifests = module.select_source_cases()
        signature = [
            (
                selected["relationship_type"],
                selected["artifact"],
                selected["slot"],
                selected["pair"]["id"],
            )
            for selected in self.selected
        ]
        again_signature = [
            (
                selected["relationship_type"],
                selected["artifact"],
                selected["slot"],
                selected["pair"]["id"],
            )
            for selected in again
        ]
        self.assertEqual(signature, again_signature)
        self.assertEqual(self.manifests, again_manifests)
        for selected in self.selected:
            pair = selected["pair"]
            anchor = module.choose_anchor(pair)
            self.assertEqual(
                module.build_typo_variant(pair, anchor),
                module.build_typo_variant(pair, anchor),
            )

    def test_typo_variants_have_realistic_edit_distance(self):
        for selected in self.selected:
            pair = selected["pair"]
            anchor = module.choose_anchor(pair)
            typo = module.build_typo_variant(pair, anchor)
            self.assertIn(typo["edit_distance"], {1, 2}, pair["id"])
            self.assertGreaterEqual(
                typo["similarity"], module.MIN_TYPO_SIMILARITY, pair["id"]
            )
            self.assertNotEqual(
                anchor["reference"].casefold(),
                typo["mutated_reference"].casefold(),
                pair["id"],
            )
            self.assertIn(typo["mutated_reference"], typo["question"], pair["id"])

    def test_reference_answers_are_exact_source_values_for_every_variant(self):
        def deterministic_reword(original, anchor, attempt):
            return f"Regarding {anchor['reference']}, could you answer: {original}"

        with tempfile.TemporaryDirectory() as directory:
            payload = module.build_final_payload(
                output_path=Path(directory) / "not-yet-created.json",
                generate_rewordings=True,
                reuse_existing=False,
                requester=deterministic_reword,
            )
        self.assertEqual(len(payload["entries"]), 156)
        for entry in payload["entries"]:
            source = self.source_by_key[
                (entry["source_golden_artifact"], entry["source_case_id"])
            ]
            self.assertEqual(entry["expected_answer"], source["expected_answer"])
            self.assertEqual(
                entry["expected_answer"].encode("utf-8"),
                source["expected_answer"].encode("utf-8"),
            )

    def test_existing_verified_rewordings_make_reruns_idempotent(self):
        def deterministic_reword(original, anchor, attempt):
            return f"Regarding {anchor['reference']}, could you answer: {original}"

        def must_not_run(*_args, **_kwargs):
            self.fail("a verified existing rewording should have been reused")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "final.json"
            first = module.build_final_payload(
                output_path=output,
                generate_rewordings=True,
                reuse_existing=False,
                requester=deterministic_reword,
            )
            output.write_text(json.dumps(first), encoding="utf-8")
            second = module.build_final_payload(
                output_path=output,
                generate_rewordings=True,
                reuse_existing=True,
                requester=must_not_run,
            )
        self.assertEqual(first, second)

    def test_bad_rewording_is_rejected_after_one_retry(self):
        selected = self.selected[0]
        pair = selected["pair"]
        anchor = module.choose_anchor(pair)
        attempts = []

        def drifted(_original, _anchor, attempt):
            attempts.append(attempt)
            return "Which films won awards at the latest international festival?"

        question, metadata = module.generate_verified_rewording(
            pair, anchor, requester=drifted
        )
        self.assertIsNone(question)
        self.assertEqual(attempts, [1, 2])
        self.assertEqual(len(metadata["failures"]), 2)
        self.assertTrue(
            all(
                failure["reason"] == "anchor_verification_failed"
                for failure in metadata["failures"]
            )
        )

    def test_reword_verification_rejects_negation_polarity_drift(self):
        selected = next(
            item
            for item in self.selected
            if item["relationship_type"] == "software_technique"
            and item["slot"] == "adversarial_negative"
        )
        pair = selected["pair"]
        anchor = module.choose_anchor(pair)
        drifted = pair["question"].replace("Does ", "Does ", 1).replace(
            " use ", " not use ", 1
        )
        accepted, detail = module.verify_reworded_variant(
            pair["question"], drifted, anchor
        )
        self.assertFalse(accepted)
        self.assertEqual(detail["reason"], "negation_polarity_changed")

    def test_reword_verification_rejects_anchor_entity_retyping(self):
        selected = next(
            item
            for item in self.selected
            if item["relationship_type"] == "group_technique"
            and item["slot"] == "negative_relationship"
        )
        pair = selected["pair"]
        anchor = module.choose_anchor(pair)
        drifted = "Is Axiom a tool that uses T1496 (Resource Hijacking)?"
        accepted, detail = module.verify_reworded_variant(
            pair["question"], drifted, anchor
        )
        self.assertFalse(accepted)
        self.assertEqual(detail["reason"], "anchor_entity_type_changed")

    def test_source_links_resolve_and_hashes_match(self):
        manifest_hashes = {
            manifest["filename"]: manifest["sha256"]
            for manifest in self.manifests
        }
        for selected in self.selected:
            path = HERE / selected["artifact"]
            self.assertTrue(path.is_file())
            self.assertEqual(
                module.sha256_file(path), manifest_hashes[selected["artifact"]]
            )
            source_payload = json.loads(path.read_text(encoding="utf-8"))
            matching = [
                pair
                for pair in source_payload["pairs"]
                if pair["id"] == selected["pair"]["id"]
            ]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0], selected["pair"])

    def test_reword_anchor_verifier_accepts_exact_and_close_references(self):
        selected = next(
            item
            for item in self.selected
            if item["relationship_type"] == "software_technique"
            and item["slot"] == "forward_positive"
        )
        anchor = module.choose_anchor(selected["pair"])
        exact = f"Can you summarize the relationship for {anchor['reference']}?"
        accepted, detail = module.verify_reworded_anchor(exact, anchor)
        self.assertTrue(accepted)
        self.assertEqual(detail["method"], "exact_reference")

        typo_anchor = deepcopy(anchor)
        typo_anchor["external_id"] = None
        close, _ = module.typo_reference(typo_anchor["name"])
        accepted, detail = module.verify_reworded_anchor(
            f"Can you summarize the relationship for {close}?", typo_anchor
        )
        self.assertTrue(accepted)
        self.assertEqual(detail["method"], "fuzzy_reference")


if __name__ == "__main__":
    unittest.main()
