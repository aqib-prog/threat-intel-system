"""Regression tests for MITRE group relationship scope in graph traversal."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from retrieval import graph_traversal  # noqa: E402


class _Result:
    def single(self):
        return {}


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class _Driver:
    def session(self):
        return _Session()


class GroupRelationshipScopeTests(unittest.TestCase):
    def _cypher_for(self, node_type: str) -> str:
        with mock.patch.object(
            graph_traversal,
            "run_query",
            return_value=_Result(),
        ) as run:
            graph_traversal.traverse_node(_Driver(), "stix-id", node_type)
        return run.call_args.args[1]

    def test_actor_relationships_merge_direct_and_attributed_campaign_paths(self):
        cypher = self._cypher_for("Actor")
        self.assertIn("(a)-[:USES]->(t:Technique)", cypher)
        self.assertIn("(c:Campaign)-[:ATTRIBUTED_TO]->(a)", cypher)
        self.assertIn("(c)-[:USES]->(t:Technique)", cypher)
        self.assertIn("direct_techniques + campaign_techniques", cypher)
        self.assertIn("direct_malware + campaign_malware", cypher)
        self.assertIn("direct_tools + campaign_tools", cypher)

    def test_reverse_technique_and_software_lookups_use_the_same_scope(self):
        technique = self._cypher_for("Technique")
        malware = self._cypher_for("Malware")
        tool = self._cypher_for("Tool")

        self.assertIn("(c:Campaign)-[:USES]->(t)", technique)
        self.assertIn("(c)-[:ATTRIBUTED_TO]->(n:Actor)", technique)
        for cypher, subject in ((malware, "mal"), (tool, "tool")):
            self.assertIn(f"(c:Campaign)-[:USES]->({subject})", cypher)
            self.assertIn("(c)-[:ATTRIBUTED_TO]->(n:Actor)", cypher)
            self.assertIn("direct_actors + campaign_actors", cypher)

    def test_technique_exposes_campaigns_reached_through_software(self):
        cypher = self._cypher_for("Technique")
        self.assertIn("(c:Campaign)-[:USES]->(s)-[:USES]->(t)", cypher)
        self.assertIn("WHERE s:Malware OR s:Tool", cypher)
        self.assertIn("campaign_via_software_details", cypher)
        self.assertIn("campaign_software_details", cypher)


if __name__ == "__main__":
    unittest.main()
