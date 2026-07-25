"""Structural regression for relationship-intent routing.

This is the permanent guard for the "Lazarus Group" class of bug: an entity
whose NAME contains a routing keyword ("Group", "Technique", ...) must not let
that keyword hijack which relationship the answer renders. "which campaigns are
attributed to Lazarus Group" must route to Campaigns, not Actors.

Hermetic (no Neo4j): it asserts the pure routing function `_relationship_intent`
directly, over representative keyword-named entities. The live full sweep over
every actor in the graph is a separate DB-gated check; this covers the class in
CI so a future edit can't silently reintroduce the hijack.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from generation.generate import _relationship_intent  # noqa: E402


class RelationshipRoutingTests(unittest.TestCase):
    def _label(self, query, node_type, entity_name):
        intent = _relationship_intent(query, node_type, entity_name)
        return intent[0] if intent else None

    def test_keyword_named_entity_does_not_hijack_routing(self):
        # (query, entity_name, node_type, expected label). Each entity name
        # contains a routing keyword that must NOT win over the real intent.
        cases = [
            ("which campaigns are attributed to Lazarus Group?", "Lazarus Group", "Actor", "Campaigns"),
            ("what techniques does Lazarus Group use?", "Lazarus Group", "Actor", "Techniques"),
            ("what malware does Equation Group use?", "Equation Group", "Actor", "Malware"),
            ("what tools does Threat Group-3390 use?", "Threat Group-3390", "Actor", "Tools"),
            ("which campaigns is Gorgon Group linked to?", "Gorgon Group", "Actor", "Campaigns"),
            ("what tactics does Cobalt Group use?", "Cobalt Group", "Actor", "Tactics"),
            ("which mitigations stop Winnti Group?", "Winnti Group", "Actor", "Mitigations"),
        ]
        failures = []
        for query, name, node_type, expected in cases:
            got = self._label(query, node_type, name)
            if got != expected:
                failures.append((name, query, expected, got))
        self.assertEqual(failures, [], f"name hijacked routing: {failures}")

    def test_legitimate_group_and_actor_intent_still_routes(self):
        # When the subject's name does NOT contain the keyword, an explicit
        # "groups"/"actors" object noun must still route to Actors.
        self.assertEqual(
            self._label("which groups use T1055?", "Technique", "Process Injection"), "Actors"
        )
        self.assertEqual(
            self._label("which actors are attributed to Operation Dream Job?", "Campaign", "Operation Dream Job"),
            "Actors",
        )

    def test_non_relationship_query_returns_none(self):
        self.assertIsNone(self._label("what is Lazarus Group?", "Actor", "Lazarus Group"))


if __name__ == "__main__":
    unittest.main()
