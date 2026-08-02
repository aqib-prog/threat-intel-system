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

from generation.generate import (  # noqa: E402
    _build_answer,
    _relationship_intent,
    generate_campaign_software_technique_summary,
    generate_explicit_signal_summary,
    generate_named_detection_entity_summary,
    generate_multi_entity_relationship_summary,
    generate_pairwise_relationship_verdict,
    generate_requested_relationship_summary,
    normalize_query_for_routing,
)


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

    def test_short_interrogative_typo_is_repaired_for_routing_only(self):
        self.assertEqual(
            normalize_query_for_routing("What os apt29?"),
            "What is apt29?",
        )
        self.assertEqual(
            normalize_query_for_routing("which ar APT29 techniques?"),
            "which are APT29 techniques?",
        )
        self.assertEqual(
            normalize_query_for_routing("Waht os Cobalt Strike?"),
            "What is Cobalt Strike?",
        )
        self.assertEqual(
            normalize_query_for_routing("What dose FIN7 use?"),
            "What does FIN7 use?",
        )

    def test_routing_repair_preserves_acronyms_and_ordinary_words(self):
        unchanged = (
            "What OS does APT29 target?",
            "Does T1001 get detected by DET0011?",
            "What is on the host?",
            "Tell me about APT29",
        )
        for query in unchanged:
            with self.subTest(query=query):
                self.assertEqual(normalize_query_for_routing(query), query)

    def test_typoed_actor_definition_uses_complete_deterministic_profile(self):
        actor = {
            "node_type": "Actor",
            "name": "APT29",
            "external_id": "G0016",
            "description": "APT29 is a threat group.",
            "tactics": ["Persistence", "Credential Access"],
            "techniques": ["PowerShell (T1059.001)", "Valid Accounts (T1078)"],
            "malware": ["SUNBURST (S0559)"],
            "tools": ["Mimikatz (S0002)"],
            "campaigns": ["SolarWinds Compromise (C0024)"],
        }
        answer = _build_answer(
            "What os apt29?",
            [actor],
            {"threat_actor": ["APT29"]},
        )
        self.assertIn("APT29 (G0016)", answer)
        self.assertIn("Description: APT29 is a threat group.", answer)
        self.assertIn("Tactics explicitly connected to APT29:", answer)
        self.assertIn("Techniques explicitly connected to APT29:", answer)
        self.assertIn("Malware explicitly connected to APT29:", answer)
        self.assertIn("Tools explicitly connected to APT29:", answer)
        self.assertIn("Campaigns explicitly connected to APT29:", answer)

    def test_named_data_component_definition_is_rendered_authoritatively(self):
        node = {
            "node_type": "DataComponent",
            "name": "Process Creation",
            "external_id": "DC0032",
            "description": "A new process is initialized by an operating system.",
        }
        answer = generate_named_detection_entity_summary(
            "Quote the full MITRE ATT&CK data source definition for Process Creation.",
            [node],
            {"data_component": ["Process Creation"]},
        )
        self.assertEqual(
            answer,
            "Process Creation (DC0032)\n"
            "Type: DataComponent\n"
            "Description: A new process is initialized by an operating system.",
        )

    def test_explicit_api_signal_summary_uses_only_literal_matches(self):
        nodes = [
            {
                "node_type": "Analytic",
                "name": "Analytic 0717",
                "external_id": "AN0717",
                "description": "Monitor AssumeRole calls by unusual principals.",
            },
            {
                "node_type": "Analytic",
                "name": "Analytic 1594",
                "external_id": "AN1594",
                "description": "Monitor cloud object enumeration.",
            },
        ]
        answer = generate_explicit_signal_summary(
            "Which AWS signals identify anomalous AssumeRole activity?",
            nodes,
        )
        self.assertIn("AN0717", answer)
        self.assertNotIn("AN1594", answer)

    def test_software_is_the_combined_malware_and_tool_relationship(self):
        for query in (
            "What software does FIN7 use?",
            "List FIN7 software",
            "Which software is linked to FIN7?",
            "Show software used by FIN7",
        ):
            with self.subTest(query=query):
                self.assertEqual(
                    _relationship_intent(query, "Actor", "FIN7"),
                    ("Software", "software", None),
                )

    def test_software_in_technique_name_does_not_hijack_routing(self):
        self.assertEqual(
            _relationship_intent(
                "What techniques does Software Discovery use?",
                "Technique",
                "Software Discovery",
            ),
            ("Techniques", "techniques", "technique_details"),
        )

    def test_prevention_measure_wording_routes_technique_to_mitigations(self):
        self.assertEqual(
            _relationship_intent(
                "What measures are taken to prevent System Service Discovery?",
                "Technique",
                "System Service Discovery",
            ),
            ("Mitigations", "mitigations", "mitigation_details"),
        )

    def test_two_actor_relationship_lists_render_both_canonical_anchors(self):
        nodes = [
            {
                "node_type": "Actor",
                "name": "APT29",
                "external_id": "G0016",
                "techniques": ["PowerShell (T1059.001)", "Valid Accounts (T1078)"],
            },
            {
                "node_type": "Actor",
                "name": "Putter Panda",
                "external_id": "G0024",
                "techniques": ["Valid Accounts (T1078)", "Process Discovery (T1057)"],
            },
        ]
        answer = generate_multi_entity_relationship_summary(
            "What techniques do APT29 and APT2 use?",
            nodes,
            {"threat_actor": ["APT29", "Putter Panda"]},
        )
        self.assertIn("APT29 (G0016)", answer)
        self.assertIn("Putter Panda (G0024)", answer)
        self.assertIn("PowerShell (T1059.001)", answer)
        self.assertIn("Process Discovery (T1057)", answer)

    def test_shared_relationship_question_returns_only_intersection(self):
        nodes = [
            {
                "node_type": "Actor",
                "name": "APT29",
                "external_id": "G0016",
                "techniques": ["PowerShell (T1059.001)", "Valid Accounts (T1078)"],
            },
            {
                "node_type": "Actor",
                "name": "FIN7",
                "external_id": "G0046",
                "techniques": ["Valid Accounts (T1078)", "Process Discovery (T1057)"],
            },
        ]
        answer = generate_multi_entity_relationship_summary(
            "Which techniques do APT29 and FIN7 both use?",
            nodes,
            {"threat_actor": ["APT29", "FIN7"]},
        )
        self.assertIn("Valid Accounts (T1078)", answer)
        self.assertNotIn("PowerShell (T1059.001)", answer)
        self.assertNotIn("Process Discovery (T1057)", answer)

    def test_two_explicit_technique_ids_each_render_their_tactics(self):
        nodes = [
            {
                "node_type": "Technique",
                "name": "Valid Accounts",
                "external_id": "T1078",
                "tactics": ["Defense Evasion", "Persistence"],
            },
            {
                "node_type": "Technique",
                "name": "Process Injection",
                "external_id": "T1055",
                "tactics": ["Defense Evasion", "Privilege Escalation"],
            },
        ]
        answer = generate_multi_entity_relationship_summary(
            "Which tactics do T1078 and T1055 belong to?",
            nodes,
            {"mitre_id": ["T1078", "T1055"]},
        )
        self.assertIn("Valid Accounts (T1078)", answer)
        self.assertIn("Process Injection (T1055)", answer)
        self.assertIn("Persistence", answer)
        self.assertIn("Privilege Escalation", answer)
        self.assertNotIn("No. T1055 is not explicitly connected", answer)

    def test_resolved_technique_names_select_anchors_by_filter_ids(self):
        nodes = [
            {
                "node_type": "Technique",
                "name": "Valid Accounts",
                "external_id": "T1078",
                "tactics": ["Persistence"],
            },
            {
                "node_type": "Technique",
                "name": "Process Injection",
                "external_id": "T1055",
                "tactics": ["Privilege Escalation"],
            },
        ]
        answer = generate_multi_entity_relationship_summary(
            "Which tactics do Valid Accounts and Process Injection belong to?",
            nodes,
            {"mitre_id": ["T1078", "T1055"]},
        )
        self.assertIsNotNone(answer)
        self.assertIn("Valid Accounts (T1078)", answer)
        self.assertIn("Process Injection (T1055)", answer)

    def test_malware_and_tool_are_one_software_anchor_family(self):
        nodes = [
            {
                "node_type": "Malware",
                "name": "RIPTIDE",
                "external_id": "S0003",
                "techniques": ["Web Protocols (T1071.001)"],
            },
            {
                "node_type": "Tool",
                "name": "Mimikatz",
                "external_id": "S0002",
                "techniques": ["OS Credential Dumping (T1003)"],
            },
        ]
        answer = generate_multi_entity_relationship_summary(
            "What techniques do RIPTIDE and Mimikatz use?",
            nodes,
            {"malware": ["RIPTIDE"], "tool": ["Mimikatz"]},
        )
        self.assertIsNotNone(answer)
        self.assertIn("Techniques explicitly connected to RIPTIDE (S0003)", answer)
        self.assertIn("Techniques explicitly connected to Mimikatz (S0002)", answer)

    def test_shared_software_combines_malware_and_tools_before_intersection(self):
        nodes = [
            {
                "node_type": "Actor",
                "name": "APT29",
                "external_id": "G0016",
                "malware_details": [
                    {"name": "SUNBURST", "external_id": "S0559"},
                ],
                "tool_details": [
                    {"name": "Mimikatz", "external_id": "S0002"},
                ],
            },
            {
                "node_type": "Actor",
                "name": "FIN7",
                "external_id": "G0046",
                "malware_details": [
                    {"name": "BOOSTWRITE", "external_id": "S0415"},
                ],
                "tool_details": [
                    {"name": "Mimikatz", "external_id": "S0002"},
                ],
            },
        ]
        answer = generate_multi_entity_relationship_summary(
            "Which malware and tools do APT29 and FIN7 both use?",
            nodes,
            {"threat_actor": ["APT29", "FIN7"]},
        )
        self.assertIsNotNone(answer)
        self.assertIn("Mimikatz (S0002)", answer)
        self.assertNotIn("SUNBURST (S0559)", answer)
        self.assertNotIn("BOOSTWRITE (S0415)", answer)

    def test_pairwise_campaign_attribution_is_independent_of_retrieval_order(self):
        campaign = {
            "node_type": "Campaign",
            "name": "Operation Ghost",
            "external_id": "C0023",
            "actor_details": [{"name": "APT32", "external_id": "G0050"}],
        }
        actor = {
            "node_type": "Actor",
            "name": "Sandworm Team",
            "external_id": "G0034",
        }
        query = (
            "Is G0034 (Sandworm Team) the group to which "
            "Operation Ghost (C0023) is attributed?"
        )
        filters = {"mitre_id": ["G0034", "C0023"]}
        for nodes in ([actor, campaign], [campaign, actor]):
            with self.subTest(order=[node["node_type"] for node in nodes]):
                answer = generate_pairwise_relationship_verdict(query, nodes, filters)
                self.assertIn("No.", answer)
                self.assertIn("Operation Ghost (C0023)", answer)
                self.assertIn("Sandworm Team (G0034)", answer)

    def test_pairwise_campaign_tool_negative_names_both_anchors(self):
        campaign = {
            "node_type": "Campaign",
            "name": "Frankenstein",
            "external_id": "C0001",
            "tool_details": [],
        }
        tool = {
            "node_type": "Tool",
            "name": "PsExec",
            "external_id": "S0029",
        }
        answer = generate_pairwise_relationship_verdict(
            "Does C0001 (Frankenstein) use Tool S0029 (PsExec)?",
            [tool, campaign],
            {
                "mitre_id": ["S0029", "C0001"],
                "campaign": ["Frankenstein"],
                "tool": ["PsExec"],
                "node_type": ["Tool"],
            },
        )
        self.assertIsNotNone(answer)
        self.assertTrue(answer.startswith("No."), answer)
        self.assertIn("Frankenstein (C0001)", answer)
        self.assertIn("PsExec (S0029)", answer)

    def test_pairwise_subtechnique_negative_does_not_dump_child_lists(self):
        child = {
            "node_type": "Technique",
            "name": "Obfuscated Files or Information",
            "external_id": "T1027",
            "parent_technique_detail": None,
            "subtechnique_details": [
                {"name": "Binary Padding", "external_id": "T1027.001"}
            ],
        }
        proposed_parent = {
            "node_type": "Technique",
            "name": "Data Obfuscation",
            "external_id": "T1001",
            "subtechnique_details": [
                {"name": "Junk Data", "external_id": "T1001.001"}
            ],
        }
        answer = generate_pairwise_relationship_verdict(
            "Is T1027 a subtechnique of T1001?",
            [proposed_parent, child],
            {"mitre_id": ["T1027", "T1001"]},
        )
        self.assertIn("No.", answer)
        self.assertNotIn("T1027.001", answer)
        self.assertNotIn("T1001.001", answer)

    def test_pairwise_renderer_covers_every_supported_edge_family(self):
        cases = [
            ("Technique", "T1001", "Tactic", "TA0001", "tactic_details", "Does T1001 belong to tactic TA0001?"),
            ("Mitigation", "M1001", "Technique", "T1001", "technique_details", "Does M1001 mitigate T1001?"),
            ("Actor", "G0001", "Technique", "T1001", "technique_details", "Does G0001 use T1001?"),
            ("Malware", "S0001", "Technique", "T1001", "technique_details", "Does S0001 use T1001?"),
            ("Tool", "S0002", "Technique", "T1001", "technique_details", "Does S0002 use T1001?"),
            ("Actor", "G0001", "Malware", "S0001", "malware_details", "Does G0001 use S0001?"),
            ("Actor", "G0001", "Tool", "S0002", "tool_details", "Does G0001 use S0002?"),
            ("Campaign", "C0001", "Actor", "G0001", "actor_details", "Is C0001 attributed to G0001?"),
            ("Campaign", "C0001", "Technique", "T1001", "technique_details", "Does C0001 use T1001?"),
            ("Campaign", "C0001", "Malware", "S0001", "malware_details", "Does C0001 use S0001?"),
            ("Campaign", "C0001", "Tool", "S0002", "tool_details", "Does C0001 use S0002?"),
            ("DetectionStrategy", "DET0001", "Technique", "T1001", "technique_details", "Does DET0001 detect T1001?"),
            ("DetectionStrategy", "DET0001", "Analytic", "AN0001", "analytic_details", "Does DET0001 have analytic AN0001?"),
            ("Analytic", "AN0001", "DataComponent", "DC0001", "data_component_details", "Does AN0001 use data component DC0001?"),
        ]
        for (
            source_type,
            source_id,
            target_type,
            target_id,
            detail_key,
            query,
        ) in cases:
            source = {
                "node_type": source_type,
                "name": f"{source_type} source",
                "external_id": source_id,
                detail_key: [
                    {"name": f"{target_type} target", "external_id": target_id}
                ],
            }
            target = {
                "node_type": target_type,
                "name": f"{target_type} target",
                "external_id": target_id,
            }
            filters = {"mitre_id": [source_id, target_id]}
            with self.subTest(edge=f"{source_type}->{target_type}", linked=True):
                answer = generate_pairwise_relationship_verdict(
                    query, [target, source], filters
                )
                self.assertIsNotNone(answer)
                self.assertTrue(answer.startswith("Yes."), answer)
            source[detail_key] = []
            with self.subTest(edge=f"{source_type}->{target_type}", linked=False):
                answer = generate_pairwise_relationship_verdict(
                    query, [source, target], filters
                )
                self.assertIsNotNone(answer)
                self.assertTrue(answer.startswith("No."), answer)

    def test_campaign_software_chain_lists_software_techniques(self):
        campaign = {
            "node_type": "Campaign",
            "name": "Frankenstein",
            "external_id": "C0001",
            "tool_details": [{"name": "Empire", "external_id": "S0363"}],
            "technique_details": [
                {"name": "PowerShell", "external_id": "T1059.001"}
            ],
        }
        software = {
            "node_type": "Tool",
            "name": "Empire",
            "external_id": "S0363",
            "campaign_details": [{"name": "Frankenstein", "external_id": "C0001"}],
            "technique_details": [
                {"name": "PowerShell", "external_id": "T1059.001"},
                {"name": "Data Destruction", "external_id": "T1485"},
            ],
        }
        answer = generate_campaign_software_technique_summary(
            "What techniques does Tool S0363 (Empire), used by C0001 (Frankenstein), employ?",
            [campaign, software],
            {"mitre_id": ["S0363", "C0001"]},
        )
        self.assertIn("Frankenstein (C0001)", answer)
        self.assertIn("Empire (S0363)", answer)
        self.assertIn("PowerShell (T1059.001)", answer)
        self.assertIn("Data Destruction (T1485)", answer)

    def test_campaign_software_chain_negative_checks_third_anchor(self):
        campaign = {
            "node_type": "Campaign",
            "name": "Frankenstein",
            "external_id": "C0001",
            "tool_details": [{"name": "Empire", "external_id": "S0363"}],
        }
        software = {
            "node_type": "Tool",
            "name": "Empire",
            "external_id": "S0363",
            "technique_details": [
                {"name": "PowerShell", "external_id": "T1059.001"}
            ],
        }
        technique = {
            "node_type": "Technique",
            "name": "Data Destruction",
            "external_id": "T1485",
        }
        answer = generate_campaign_software_technique_summary(
            "Does Tool S0363 (Empire), used by C0001 (Frankenstein), employ T1485?",
            [software, technique, campaign],
            {"mitre_id": ["S0363", "C0001", "T1485"]},
        )
        self.assertIn("No.", answer)
        self.assertIn("C0001", answer)
        self.assertIn("T1485", answer)

    def test_campaign_software_divergence_is_set_difference(self):
        campaign = {
            "node_type": "Campaign",
            "name": "Frankenstein",
            "external_id": "C0001",
            "tool_details": [{"name": "Empire", "external_id": "S0363"}],
            "technique_details": [
                {"name": "PowerShell", "external_id": "T1059.001"}
            ],
        }
        software = {
            "node_type": "Tool",
            "name": "Empire",
            "external_id": "S0363",
            "technique_details": [
                {"name": "PowerShell", "external_id": "T1059.001"},
                {"name": "Process Injection", "external_id": "T1055"},
            ],
        }
        answer = generate_campaign_software_technique_summary(
            "Which techniques used by Empire, associated with Frankenstein, are absent from the campaign's own direct technique relationships?",
            [campaign, software],
            {"campaign": ["Frankenstein"], "tool": ["Empire"]},
        )
        self.assertIn("Process Injection (T1055)", answer)
        self.assertNotIn("PowerShell (T1059.001)", answer)

    def test_reverse_campaign_via_software_uses_explicit_traversal_field(self):
        technique = {
            "node_type": "Technique",
            "name": "Data Obfuscation",
            "external_id": "T1001",
            "campaign_via_software_details": [
                {"name": "SolarWinds Compromise", "external_id": "C0024"}
            ],
            "campaign_software_details": [
                {"name": "SUNBURST", "external_id": "S0559"}
            ],
        }
        answer = generate_campaign_software_technique_summary(
            "Which campaigns have malware or tools that use T1001?",
            [technique],
            {"mitre_id": ["T1001"]},
        )
        self.assertIn("SolarWinds Compromise (C0024)", answer)
        self.assertIn("SUNBURST (S0559)", answer)

    def test_no_data_components_still_reports_detection_strategy(self):
        technique = {
            "node_type": "Technique",
            "name": "DNS Server",
            "external_id": "T1583.002",
            "log_sources": [],
            "detection_strategy_details": [
                {"name": "Detect DNS Server Acquisition", "external_id": "DET0862"}
            ],
        }
        answer = generate_requested_relationship_summary(
            "Which data components support detection of T1583.002?",
            [technique],
        )
        self.assertIn("No data components", answer)
        self.assertIn("DET0862", answer)


if __name__ == "__main__":
    unittest.main()
