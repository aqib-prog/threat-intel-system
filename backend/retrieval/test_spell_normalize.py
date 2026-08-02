"""Tests for the conservative spell normalizer used by the harm-gate re-check.

Hermetic (no model): asserts it fixes common query typos, and - critically for
safety - that it does NOT touch IDs, entity-shaped tokens, or harmful words (so
a harmful query can never be "corrected" into a benign one before the gate).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from retrieval.spell_normalize import (  # noqa: E402
    normalize_question_scaffolding,
    spell_normalize,
)


class SpellNormalizeTests(unittest.TestCase):
    def test_fixes_common_query_typos(self):
        self.assertEqual(
            spell_normalize("waht tacktics duz T1078 blomg two?"),
            # Single-edit slips are repaired ("waht"->"what" by transposition,
            # "tacktics"->"tactics"). "duz" (3 edits from "does") and "blomg"
            # (2 from "belong") are deliberately left alone: repair fixes
            # near-certain slips, it never guesses. "two" is a real word and is
            # protected. The ID is untouched.
            "what tactics duz T1078 blomg two?",
        )
        self.assertEqual(spell_normalize("wht mitigates T1055"), "what mitigates T1055")
        self.assertEqual(spell_normalize("teh tehcniques of APT29"), "the techniques of APT29")

    def test_never_alters_ids_or_cves(self):
        for token in ("T1078", "G0016", "S0002", "TA0011", "CVE-2021-44228", "T1078.004"):
            self.assertIn(token, spell_normalize(f"what about {token}"))

    def test_leaves_harmful_and_unknown_words_intact(self):
        # These must NOT be "corrected" into benign vocabulary - the harm gate
        # relies on seeing them unchanged.
        for word in ("bomb", "ransomware", "exploit", "malware"):
            self.assertIn(word, spell_normalize(f"how to make a {word}").split())

    def test_valid_words_unchanged(self):
        text = "which campaigns are attributed to Lazarus Group"
        self.assertEqual(spell_normalize(text), text)

    def test_short_tokens_untouched(self):
        # <=2 chars are never "corrected" (avoids mangling "of", "to", "is").
        self.assertEqual(spell_normalize("is T1078 ok"), "is T1078 ok")

    def test_question_scaffolding_repairs_only_grammar(self):
        cases = {
            "What os APT29?": "What is APT29?",
            "**What os APT29?**": "**What is APT29?**",
            "which ar APT29 techniques?": "which are APT29 techniques?",
            "What dose FIN7 use?": "What does FIN7 use?",
            "Waht os Cobalt Strike?": "What is Cobalt Strike?",
            "Tell me what os SUNBURST?": "Tell me what is SUNBURST?",
            "waht is APT29?": "what is APT29?",
            "wht is FIN7?": "what is FIN7?",
            "whcih ar APT29 techniques?": "which are APT29 techniques?",
            "what si Lazarus Group?": "what is Lazarus Group?",
            "what re Sandworm Team techniques?": "what are Sandworm Team techniques?",
            "what dsoe FIN7 use?": "what does FIN7 use?",
            "who ws APT29?": "who is APT29?",
            "where cn I find T1078?": "where can I find T1078?",
        }
        for query, expected in cases.items():
            with self.subTest(query=query):
                self.assertEqual(normalize_question_scaffolding(query), expected)

    def test_question_scaffolding_never_rewrites_content(self):
        unchanged = (
            "What OS does APT29 target?",
            "Does T1001 get detected by DET0011?",
            "What is on the host?",
            "What on earth does APT29 do?",
            "EventData: Message=what os APT29",
            "Tell me about APT29",
        )
        for query in unchanged:
            with self.subTest(query=query):
                self.assertEqual(normalize_question_scaffolding(query), query)


if __name__ == "__main__":
    unittest.main()
