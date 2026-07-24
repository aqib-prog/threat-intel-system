"""Tests for structured answer-section extraction and description truncation.

These lock in the universal chart fix: the backend computes real category
counts from the deterministic answer (never mis-counting narrative prose), and
descriptions are trimmed on a word/sentence boundary instead of mid-word.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

os.environ.setdefault("API_KEYS", "test-key")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:5173")

from api.app import compute_answer_sections  # noqa: E402
from generation.generate import truncate_description  # noqa: E402


class AnswerSectionsTests(unittest.TestCase):
    def _labels(self, answer):
        return [(s.label, s.count) for s in compute_answer_sections(answer)]

    def test_multi_category_actor_overview(self):
        answer = (
            "FIN7 (G0046)\n"
            "Description: FIN7 is a group that targeted retail, restaurant, "
            "hospitality, software, consulting, and utilities industries.\n\n"
            "Tactics explicitly connected to FIN7:\n"
            "- Execution\n- Persistence\n- Collection\n\n"
            "Techniques explicitly connected to FIN7:\n"
            "- Scheduled Task\n- VNC\n- Screen Capture\n- Rundll32\n\n"
            "Malware explicitly connected to FIN7:\n"
            "- GRIFFON\n- Carbanak\n\n"
            "Tools explicitly connected to FIN7:\n"
            "- Mimikatz\n"
        )
        # Description prose (with its comma list of industries) must NOT appear.
        self.assertEqual(
            self._labels(answer),
            [("Tactics", 3), ("Techniques", 4), ("Malware", 2), ("Tools", 1)],
        )

    def test_narrative_description_never_charted(self):
        # A bare description with a comma list must produce zero sections
        # (this is the "Description: 14" bug the fix eliminates).
        answer = (
            "FIN7 (G0046)\n"
            "Description: active since 2013 targeting retail, restaurant, "
            "hospitality, software, consulting, financial services, media, "
            "transportation, pharmaceutical, and utilities industries.\n"
        )
        self.assertEqual(self._labels(answer), [])

    def test_single_category(self):
        answer = (
            "Mitigations explicitly connected to Data Obfuscation (T1001):\n"
            "- Network Intrusion Prevention (M1031)\n"
        )
        self.assertEqual(self._labels(answer), [("Mitigations", 1)])

    def test_inline_comma_list_counted(self):
        answer = "Platforms: Windows, Linux, macOS\n"
        self.assertEqual(self._labels(answer), [("Platforms", 3)])

    def test_detection_beats_generic_and_data_component_routing(self):
        answer = (
            "Detection Strategies explicitly connected to T1001:\n"
            "- Detect Obfuscated C2 (DET0053)\n\n"
            "Supporting analytics:\n"
            "- Analytic 0144 (AN0144)\n- Analytic 0145 (AN0145)\n"
        )
        labels = dict(self._labels(answer))
        self.assertEqual(labels.get("Detection Strategies"), 1)
        self.assertEqual(labels.get("Analytics"), 2)

    def test_empty_and_blocked_answer(self):
        self.assertEqual(self._labels(""), [])
        self.assertEqual(
            self._labels("I don't have enough information about this in my knowledge base."),
            [],
        )


class TruncateDescriptionTests(unittest.TestCase):
    def test_short_text_unchanged(self):
        self.assertEqual(truncate_description("Short.", 400), "Short.")

    def test_cuts_on_sentence_boundary_not_midword(self):
        text = (
            "FIN7 is a financially-motivated threat group active since 2013. "
            "A part of the group operated under another name entirely and did more."
        )
        out = truncate_description(text, 70)
        self.assertTrue(out.endswith("2013."))
        self.assertNotIn("A part", out)  # no mid-sentence bleed

    def test_falls_back_to_word_boundary_with_ellipsis(self):
        text = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda"
        out = truncate_description(text, 20)
        self.assertTrue(out.endswith("…"))
        self.assertFalse(out[:-1].endswith(" "))
        # never splits a word
        self.assertTrue(all(w in text.split() for w in out[:-1].split()))


if __name__ == "__main__":
    unittest.main()
