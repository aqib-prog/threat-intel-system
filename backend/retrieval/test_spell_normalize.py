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

from retrieval.spell_normalize import spell_normalize  # noqa: E402


class SpellNormalizeTests(unittest.TestCase):
    def test_fixes_common_query_typos(self):
        self.assertEqual(
            spell_normalize("waht tacktics duz T1078 blomg two?"),
            "what tactics does T1078 belong two?",
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


if __name__ == "__main__":
    unittest.main()
