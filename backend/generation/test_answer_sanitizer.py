"""Tests for structural sanitisation of generated answers.

The critical property is NOT that malformed output gets repaired - it is that
well-formed output is returned byte-identical. A sanitiser that "improves" a
correct answer is worse than no sanitiser at all, so the no-op cases below are
the ones that must never be relaxed.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from generation.answer_sanitizer import sanitize_answer  # noqa: E402


class NoOpOnWellFormedAnswers(unittest.TestCase):
    """Every shape the deterministic renderers actually emit must survive."""

    def test_actor_profile_unchanged(self):
        answer = (
            "APT29 (G0016)\n"
            "Description: [APT29](https://attack.mitre.org/groups/G0016) is a threat group.\n"
            "\n"
            "Tactics explicitly connected to APT29 (G0016):\n"
            "- Execution\n"
            "- Persistence\n"
        )
        self.assertEqual(sanitize_answer(answer), answer.strip())

    def test_relationship_list_unchanged(self):
        answer = (
            "Mitigations explicitly connected to Data Obfuscation (T1001):\n"
            "- Network Intrusion Prevention (M1031)"
        )
        self.assertEqual(sanitize_answer(answer), answer)

    def test_inline_value_header_unchanged(self):
        answer = "Platforms: Windows, Linux, macOS"
        self.assertEqual(sanitize_answer(answer), answer)

    def test_pairwise_verdict_unchanged(self):
        answer = "No. T1055 is not explicitly connected to M1013 in the knowledge graph."
        self.assertEqual(sanitize_answer(answer), answer)

    def test_refusal_unchanged(self):
        answer = "I don't have enough information about this in my knowledge base."
        self.assertEqual(sanitize_answer(answer), answer)

    def test_bold_list_items_are_not_touched(self):
        # Bold INSIDE a list item is valid markdown and carries meaning; only
        # bold used as a block label is rewritten.
        answer = "Techniques:\n- **Execution:** Scheduled Task\n- **Persistence:** WMI"
        self.assertEqual(sanitize_answer(answer), answer)

    def test_unregistered_valid_bold_heading_is_not_touched(self):
        answer = "**Important**\nKeep this defensive note."
        self.assertEqual(sanitize_answer(answer), answer)


class RepairsStructuralDefects(unittest.TestCase):
    def test_header_with_no_body_is_dropped(self):
        answer = "Tactics:\nTechniques:\n- Scheduled Task"
        out = sanitize_answer(answer)
        self.assertNotIn("Tactics:", out)
        self.assertIn("Techniques:", out)
        self.assertIn("- Scheduled Task", out)

    def test_bold_block_label_is_unwrapped(self):
        self.assertEqual(
            sanitize_answer("**Summary:** APT29 is a threat group."),
            "Summary: APT29 is a threat group.",
        )

    def test_empty_bold_header_is_dropped(self):
        out = sanitize_answer("**Type:** Threat Group\n\n**Tactics:**\nTechniques:\n- WMI")
        self.assertIn("Type: Threat Group", out)
        self.assertNotIn("Tactics:", out)

    def test_trailing_empty_header_is_dropped(self):
        # Nothing follows at all - the commonest truncation artefact.
        self.assertEqual(sanitize_answer("Summary: fine.\n\nTactics:"), "Summary: fine.")

    def test_empty_input_is_safe(self):
        self.assertEqual(sanitize_answer(""), "")

    def test_bold_header_without_colon_is_canonicalized(self):
        self.assertEqual(
            sanitize_answer("**Summary**\nAPT29 is a threat group."),
            "Summary:\nAPT29 is a threat group.",
        )

    def test_split_bold_header_is_canonicalized_and_marker_removed(self):
        answer = "**Techniques\n**\n- PowerShell\n- Scheduled Task"
        cleaned = sanitize_answer(answer)
        self.assertEqual(
            cleaned,
            "Techniques:\n- PowerShell\n- Scheduled Task",
        )
        self.assertNotIn("**", cleaned)

    def test_spaced_bold_prose_is_repaired_or_unwrapped(self):
        self.assertEqual(
            sanitize_answer("** APT29 is also called Cozy Bear.**"),
            "**APT29 is also called Cozy Bear.**",
        )
        self.assertEqual(
            sanitize_answer("** APT29 is also called Cozy Bear."),
            "APT29 is also called Cozy Bear.",
        )

    def test_screenshot_shape_has_no_literal_marker_residue(self):
        answer = (
            "**Summary**\n"
            "** APT29's operating system is not explicitly mentioned.\n\n"
            "**Techniques\n**\n"
            "• Boot or Logon Initialization Scripts\n"
            "• Windows Management Instrumentation"
        )
        cleaned = sanitize_answer(answer)
        self.assertEqual(
            cleaned,
            "Summary:\n"
            "APT29's operating system is not explicitly mentioned.\n\n"
            "Techniques:\n"
            "• Boot or Logon Initialization Scripts\n"
            "• Windows Management Instrumentation",
        )
        self.assertEqual(sanitize_answer(cleaned), cleaned)


if __name__ == "__main__":
    unittest.main()
