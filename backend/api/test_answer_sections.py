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

from api.app import compute_answer_presentation, compute_answer_sections  # noqa: E402
from generation.answer_sanitizer import sanitize_answer  # noqa: E402
from generation.generate import truncate_description  # noqa: E402


class AnswerSectionsTests(unittest.TestCase):
    def test_leading_category_wins_for_every_contextual_heading_family(self):
        # The subject deliberately contains several competing category words.
        # Classification must always follow the relationship category at the
        # beginning, independent of which entity/category words occur later.
        cases = {
            "Detection Strategies": "Detection Strategies",
            "Data Components": "Data Components",
            "Log Sources": "Log Sources",
            "Parent Techniques": "Parent Techniques",
            "Related Techniques": "Related Techniques",
            "Subtechniques": "Subtechniques",
            "Analytics": "Analytics",
            "Techniques": "Techniques",
            "Tactics": "Tactics",
            "Mitigations": "Mitigations",
            "Campaigns": "Campaigns",
            "Actors": "Actors",
            "Malware": "Malware",
            "Tools": "Tools",
            "Platforms": "Platforms",
            "Aliases": "Aliases",
            "Procedures": "Procedures",
        }
        subject = "Lazarus Group Malware Tool Campaign Analytics"
        for heading, expected in cases.items():
            with self.subTest(heading=heading):
                answer = f"{heading} explicitly connected to {subject}:\n- Fact"
                sections = compute_answer_sections(answer)
                self.assertEqual(
                    [item.model_dump() for item in sections],
                    [{"label": expected, "count": 1}],
                )
                presentation = compute_answer_presentation(answer)
                self.assertEqual(
                    [block.label for block in presentation.blocks],
                    [expected],
                )

    def test_subject_entity_keyword_does_not_hijack_heading_category(self):
        answer = (
            "Malware explicitly connected to Lazarus Group:\n"
            "- BLINDINGCAN\n"
            "- WannaCry\n\n"
            "Tools explicitly connected to Lazarus Group:\n"
            "- RawDisk\n"
            "- netsh"
        )
        self.assertEqual(
            [item.model_dump() for item in compute_answer_sections(answer)],
            [
                {"label": "Malware", "count": 2},
                {"label": "Tools", "count": 2},
            ],
        )
        presentation = compute_answer_presentation(answer)
        self.assertIsNotNone(presentation)
        self.assertEqual(
            [block.label for block in presentation.blocks],
            ["Malware", "Tools"],
        )

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


class AnswerPresentationTests(unittest.TestCase):
    def test_malformed_model_markers_are_absent_from_authoritative_blocks(self):
        raw = (
            "**Summary**\n"
            "** APT29's operating system is not explicitly mentioned.\n\n"
            "**Techniques\n**\n"
            "• Boot or Logon Initialization Scripts\n"
            "• Windows Management Instrumentation"
        )
        cleaned = sanitize_answer(raw)
        presentation = compute_answer_presentation(cleaned)

        self.assertIsNotNone(presentation)
        self.assertEqual(
            [block.label for block in presentation.blocks],
            ["Summary", "Techniques"],
        )
        self.assertNotIn("**", presentation.preamble)
        self.assertTrue(
            all(
                "**" not in entry.heading and "**" not in entry.markdown
                for block in presentation.blocks
                for entry in block.entries
            )
        )

    def test_contextual_actor_headers_become_authoritative_blocks(self):
        answer = (
            "OilRig (G0049)\n"
            "Description: OilRig is a suspected Iranian threat group.\n\n"
            "Tactics explicitly connected to OilRig:\n"
            "- Execution\n- Persistence\n\n"
            "Techniques explicitly connected to OilRig:\n"
            "- Scheduled Task (T1053.005)\n"
        )
        presentation = compute_answer_presentation(answer)
        self.assertIsNotNone(presentation)
        self.assertEqual(presentation.preamble, "OilRig (G0049)")
        self.assertEqual(
            [block.label for block in presentation.blocks],
            ["Description", "Tactics", "Techniques"],
        )
        self.assertEqual(
            presentation.blocks[1].entries[0].heading,
            "Tactics explicitly connected to OilRig",
        )
        self.assertEqual(
            presentation.blocks[1].entries[0].markdown,
            "- Execution\n- Persistence",
        )

    def test_repeated_category_is_grouped_into_one_scroll_target(self):
        answer = (
            "Techniques explicitly connected to APT29 (G0016):\n"
            "- PowerShell (T1059.001)\n\n"
            "---\n\n"
            "Techniques explicitly connected to FIN7 (G0046):\n"
            "- Scheduled Task (T1053.005)\n"
        )
        presentation = compute_answer_presentation(answer)
        self.assertIsNotNone(presentation)
        self.assertEqual(len(presentation.blocks), 1)
        self.assertEqual(presentation.blocks[0].label, "Techniques")
        self.assertEqual(len(presentation.blocks[0].entries), 2)
        self.assertNotIn("---", presentation.blocks[0].entries[0].markdown)

    def test_unstructured_answer_preserves_raw_fallback(self):
        self.assertIsNone(
            compute_answer_presentation(
                "I don't have enough information about this in my knowledge base."
            )
        )


if __name__ == "__main__":
    unittest.main()
