from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from generation import generate as generation  # noqa: E402
from retrieval import guardrail  # noqa: E402
from retrieval import graph_traversal  # noqa: E402


class RagRootCauseRegressionTests(unittest.TestCase):
    def test_requested_analytic_relationships_are_rendered_with_ids(self):
        analytic = {
            "node_type": "Analytic",
            "name": "Analytic 0001",
            "external_id": "AN0001",
            "detection_strategies": [
                "Detect Access to Cloud Instance Metadata API (IaaS)"
            ],
            "detection_strategy_details": [{
                "name": "Detect Access to Cloud Instance Metadata API (IaaS)",
                "external_id": "DET0001",
            }],
            "log_sources": [
                "Cloud Service Metadata",
                "Network Connection Creation",
                "Network Traffic Content",
            ],
            "data_component_details": [
                {"name": "Cloud Service Metadata", "external_id": "DC0070"},
                {"name": "Network Connection Creation", "external_id": "DC0082"},
                {"name": "Network Traffic Content", "external_id": "DC0085"},
            ],
        }
        detection_answer = generation.generate(
            "Which detection strategy does AN0001 (Analytic 0001) belong to?",
            [analytic],
            {"mitre_id": ["AN0001"]},
        )
        component_answer = generation.generate(
            "Which data components does AN0001 (Analytic 0001) use?",
            [analytic],
            {"mitre_id": ["AN0001"]},
        )
        self.assertIn("DET0001", detection_answer)
        self.assertIn("DC0070", component_answer)
        self.assertIn("DC0082", component_answer)
        self.assertIn("DC0085", component_answer)

    def test_parent_campaign_actor_and_reverse_actor_relationships_are_explicit(self):
        parent_answer = generation.generate(
            "What is the parent technique of T1001.002 (Steganography)?",
            [{
                "node_type": "Technique",
                "name": "Steganography",
                "external_id": "T1001.002",
                "parent_technique": "Data Obfuscation",
                "parent_technique_detail": {
                    "name": "Data Obfuscation",
                    "external_id": "T1001",
                },
            }],
            {"mitre_id": ["T1001.002"]},
        )
        campaign_answer = generation.generate(
            "Which group is C0022 (Operation Dream Job) attributed to?",
            [{
                "node_type": "Campaign",
                "name": "Operation Dream Job",
                "external_id": "C0022",
                "actors": ["Lazarus Group"],
                "actor_details": [{
                    "name": "Lazarus Group",
                    "external_id": "G0032",
                }],
            }],
            {"mitre_id": ["C0022"]},
        )
        actor_answer = generation.generate(
            "Which actors use T1001 (Data Obfuscation)?",
            [{
                "node_type": "Technique",
                "name": "Data Obfuscation",
                "external_id": "T1001",
                "actors": ["Gamaredon Group"],
                "actor_details": [{
                    "name": "Gamaredon Group",
                    "external_id": "G0047",
                }],
            }],
            {"mitre_id": ["T1001"]},
        )
        self.assertIn("Data Obfuscation (T1001)", parent_answer)
        self.assertIn("Lazarus Group (G0032)", campaign_answer)
        self.assertIn("Gamaredon Group (G0047)", actor_answer)

    def test_confirmed_empty_relationships_are_stated_and_not_fabricated(self):
        cases = (
            (
                "What are the subtechniques of T1005 (Data from Local System)?",
                {
                    "node_type": "Technique",
                    "name": "Data from Local System",
                    "external_id": "T1005",
                    "subtechniques": [],
                    "subtechnique_details": [],
                },
                "No subtechniques are recorded",
            ),
            (
                "Which data components does AN1937 (Analytic 1937) use?",
                {
                    "node_type": "Analytic",
                    "name": "Analytic 1937",
                    "external_id": "AN1937",
                    "log_sources": [],
                    "data_component_details": [],
                },
                "No data components are recorded",
            ),
            (
                "What mitigates T1007 (System Service Discovery)?",
                {
                    "node_type": "Technique",
                    "name": "System Service Discovery",
                    "external_id": "T1007",
                    "mitigations": [],
                    "mitigation_details": [],
                },
                "No mitigations are recorded",
            ),
        )
        for query, node, expected in cases:
            with self.subTest(query=query):
                answer = generation.generate(
                    query, [node], {"mitre_id": [node["external_id"]]}
                )
                self.assertIn(expected, answer)
                self.assertNotIn("Network Segmentation", answer)

    def test_detection_analytic_negative_is_checked_as_a_relationship(self):
        answer = generation.generate(
            "Does DET0001 have AN0667?",
            [{
                "node_type": "DetectionStrategy",
                "name": "Detect Access to Cloud Instance Metadata API (IaaS)",
                "external_id": "DET0001",
                "analytics": ["Detects metadata access."],
                "analytic_details": [{
                    "name": "Analytic 0001",
                    "external_id": "AN0001",
                    "platforms": ["IaaS"],
                }],
            }, {
                "node_type": "Analytic",
                "name": "Analytic 0667",
                "external_id": "AN0667",
            }],
            {"mitre_id": ["DET0001", "AN0667"]},
        )
        self.assertIn("No. AN0667 is not explicitly connected", answer)

    def test_technique_detection_rewording_keeps_detection_strategy_key(self):
        answer = generation.generate(
            "How is T1001 (Data Obfuscation) detected?",
            [{
                "node_type": "Technique",
                "name": "Data Obfuscation",
                "external_id": "T1001",
                "detections": [
                    "Detect Obfuscated C2 via Network Traffic Analysis"
                ],
                "detection_strategy_details": [{
                    "name": "Detect Obfuscated C2 via Network Traffic Analysis",
                    "external_id": "DET0053",
                }],
            }],
            {"mitre_id": ["T1001"]},
        )
        self.assertIn("DET0053", answer)

    def test_reworded_countermeasure_and_tactic_queries_use_relationship_fields(self):
        technique = {
            "node_type": "Technique",
            "name": "Data Obfuscation",
            "external_id": "T1001",
            "mitigations": ["Network Intrusion Prevention"],
            "mitigation_details": [{
                "name": "Network Intrusion Prevention",
                "external_id": "M1031",
            }],
            "tactics": ["Command and Control"],
            "tactic_details": [{
                "name": "Command and Control",
                "external_id": "TA0011",
            }],
        }
        mitigation_answer = generation.generate(
            "What countermeasures are in place for Data Obfuscation?",
            [technique],
        )
        tactic_answer = generation.generate(
            "To which tactics does Data Obfuscation belong?",
            [technique],
        )
        self.assertIn("Network Intrusion Prevention (M1031)", mitigation_answer)
        self.assertIn("Command and Control (TA0011)", tactic_answer)

    def test_name_only_technique_and_actor_typo_are_deterministic_hints(self):
        index = {
            "data obfuscation": {
                "real_name": "T1001",
                "type": "mitre_id",
            },
            "dragonok": {
                "real_name": "DragonOK",
                "type": "threat_actor",
            },
        }
        with mock.patch.object(guardrail, "GLOBAL_INDEX", index), mock.patch.object(
            guardrail, "TACTIC_CONTEXT_INDEX", {}
        ):
            technique = guardrail.extract_database_entity_hints(
                "What countermeasures are in place for Data Obfuscation?"
            )
            actor = guardrail.extract_database_entity_hints(
                "What techniques does DragnoOK use?"
            )
        self.assertEqual(technique["mitre_id"][0]["value"], "T1001")
        self.assertEqual(actor["threat_actor"][0]["value"], "DragonOK")
        self.assertEqual(actor["threat_actor"][0]["score"], 87.5)

    def test_entity_name_parenthetical_is_not_a_platform_filter(self):
        named_query = (
            "What analytics does DET0001 "
            "(Detect Access to Cloud Instance Metadata API (IaaS)) have?"
        )
        linux_query = "Which analytics of DET0001 apply to the Linux platform?"
        self.assertEqual(generation.query_platforms(named_query), set())
        self.assertEqual(generation.query_platforms(linux_query), {"linux"})

        node = {
            "node_type": "DetectionStrategy",
            "name": "Detect Access to Cloud Instance Metadata API (IaaS)",
            "external_id": "DET0001",
            "analytic_details": [{
                "name": "Analytic 0001",
                "external_id": "AN0001",
                "platforms": ["IaaS"],
            }],
        }
        self.assertIn("AN0001", generation.generate(named_query, [node]))
        self.assertIn(
            "No analytics with the requested platform (linux)",
            generation.generate(linux_query, [node]),
        )

    def test_validated_typo_filter_reaches_honest_empty_renderer(self):
        answer = generation.generate(
            "What techniques does DragnoOK use?",
            [{
                "node_type": "Actor",
                "name": "DragonOK",
                "external_id": "G0017",
                "techniques": [],
            }],
            {"node_type": ["Technique"], "threat_actor": ["DragonOK"]},
        )
        self.assertIn(
            "No techniques are recorded for DragonOK (G0017)",
            answer,
        )
        self.assertNotIn("DragnoOK", answer)

    def test_relationship_list_never_cuts_application_access_token(self):
        answer = generation.generate(
            "Which techniques does Application Developer Guidance prevent or mitigate?",
            [{
                "node_type": "Mitigation",
                "name": "Application Developer Guidance",
                "external_id": "M1013",
                "techniques": [
                    "File/Path Exclusions",
                    "Application Access Token",
                ],
            }],
            {"mitigation": ["Application Developer Guidance"]},
        )
        self.assertIn("- Application Access Token", answer)
        self.assertNotIn("- Application Access To\n", answer)

    def test_freeform_prompt_omits_raw_filters_and_requires_absence_answer(self):
        response = {"message": {"content": "Not found in the provided context."}}
        with mock.patch.object(
            generation.OLLAMA_CLIENT, "chat", return_value=response
        ) as chat:
            generation._build_answer(
                "Explain the supplied relationship.",
                [{
                    "node_type": "Technique",
                    "name": "Example",
                    "external_id": "T9999",
                    "description": "Example context.",
                }],
                {"mitre_id": ["T9999"], "analytic": ["AN0667"]},
            )
        prompt = chat.call_args.kwargs["messages"][1]["content"]
        self.assertNotIn("Filters applied", prompt)
        self.assertNotIn("'analytic': ['AN0667']", prompt)
        self.assertIn("specific fact or relationship asked about is absent", prompt)

    def test_harm_prompt_contains_the_two_benign_relationship_examples(self):
        response = {
            "message": {
                "content": '{"allowed": true, "reason": "Benign relationship lookup"}'
            }
        }
        with mock.patch.object(
            guardrail.OLLAMA_CLIENT, "chat", return_value=response
        ) as chat:
            result = guardrail.check_llm_guardrail(
                "What tools or malware does Axiom use?"
            )
        prompt = chat.call_args.kwargs["messages"][0]["content"]
        self.assertTrue(result["allowed"])
        self.assertIn("What tools or malware does Axiom use?", prompt)
        self.assertIn(
            "What tools or malware does Frankenstein (C0001) utilize?",
            prompt,
        )

    def test_graph_traversal_projects_relationship_ids_for_affected_types(self):
        class Result:
            @staticmethod
            def single():
                return {}

        class Session:
            def __init__(self):
                self.queries = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def run(self, query, **_):
                self.queries.append(str(query))
                return Result()

        class Driver:
            def __init__(self):
                self.sessions = []

            def session(self):
                session = Session()
                self.sessions.append(session)
                return session

        expected_projection = {
            "Technique": (
                "parent_technique_detail",
                "subtechnique_details",
                "mitigation_details",
            ),
            "Campaign": ("actor_details",),
            "DetectionStrategy": ("analytic_details", "technique_details"),
            "Analytic": (
                "data_component_details",
                "detection_strategy_details",
            ),
        }
        for node_type, fields in expected_projection.items():
            with self.subTest(node_type=node_type):
                driver = Driver()
                graph_traversal.traverse_node(driver, "internal-id", node_type)
                query = driver.sessions[0].queries[0]
                for field in fields:
                    self.assertIn(field, query)


    def test_unresolved_plainword_subject_refuses_instead_of_wrong_node(self):
        # "Axoim" (typo of Axiom) scores just under the fuzzy threshold, so no
        # subject filter resolves and retrieval surfaces unrelated Malware
        # nodes. The system must refuse, not answer about an arbitrary one.
        malware_nodes = [
            {"node_type": "Malware", "name": "Zox", "external_id": "S0672",
             "malware": [], "tools": []},
            {"node_type": "Malware", "name": "Hydraq", "external_id": "S0203",
             "malware": [], "tools": []},
        ]
        self.assertTrue(
            generation.relationship_subject_unresolved(
                "What tools or malware does Axoim use?",
                malware_nodes,
                {"node_type": ["Malware", "Tool"]},
            )
        )
        answer = generation.generate(
            "What tools or malware does Axoim use?",
            malware_nodes,
            {"node_type": ["Malware", "Tool"]},
        )
        self.assertIn("don't have enough information", answer)
        self.assertNotIn("Zox", answer)

    def test_resolved_subject_filter_is_not_refused(self):
        # Same shape, but the guardrail resolved the actor into a filter -
        # this must stay answerable (regression guard against over-refusing).
        actor_node = {
            "node_type": "Actor", "name": "Axiom", "external_id": "G0001",
            "malware": ["PlugX"], "tools": [],
            "malware_details": [{"name": "PlugX", "external_id": "S0013"}],
        }
        self.assertFalse(
            generation.relationship_subject_unresolved(
                "What tools or malware does Axiom use?",
                [actor_node],
                {"node_type": ["Malware", "Tool"], "threat_actor": ["Axiom"]},
            )
        )

    def test_named_subject_present_in_query_is_not_refused(self):
        # No filter, but the retrieved node's name appears in the query -
        # still a confident subject, must not be refused.
        technique_node = {
            "node_type": "Technique", "name": "Data Obfuscation",
            "external_id": "T1001", "mitigations": ["Network Intrusion Prevention"],
            "mitigation_details": [
                {"name": "Network Intrusion Prevention", "external_id": "M1031"}
            ],
        }
        self.assertFalse(
            generation.relationship_subject_unresolved(
                "What mitigates Data Obfuscation?", [technique_node], {},
            )
        )


    def test_technique_detection_answer_includes_analytic_ids(self):
        # "How is T#### detected?" must list the detection strategy AND its
        # supporting analytic IDs (universal across techniques).
        technique = {
            "node_type": "Technique",
            "name": "Data Obfuscation",
            "external_id": "T1001",
            "detections": ["Detect Obfuscated C2 via Network Traffic Analysis"],
            "detection_strategy_details": [{
                "name": "Detect Obfuscated C2 via Network Traffic Analysis",
                "external_id": "DET0053",
            }],
            "analytics": ["desc a", "desc b", "desc c"],
            "detection_analytic_details": [
                {"name": "Analytic 0144", "external_id": "AN0144"},
                {"name": "Analytic 0145", "external_id": "AN0145"},
                {"name": "Analytic 0146", "external_id": "AN0146"},
            ],
        }
        answer = generation.generate("How is T1001 (Data Obfuscation) detected?", [technique])
        self.assertIn("DET0053", answer)
        for an in ("AN0144", "AN0145", "AN0146"):
            self.assertIn(an, answer)

    def test_relationship_intent_routing_and_name_collisions(self):
        gi = generation._relationship_intent
        # "data component(s)" must beat generic detect wording (was misrouting
        # to detection strategies).
        self.assertEqual(
            gi("Which data components support detection of T1583.002?", "Technique")[0],
            "Data Components",
        )
        # A DataComponent subject: "data component" names the subject, so
        # "which analytics use DC####" must resolve to analytics, not itself.
        self.assertEqual(
            gi("Which analytics use data component DC0003?", "DataComponent")[0],
            "Analytics",
        )
        # A DetectionStrategy detecting a technique routes to its techniques
        # (grounded boolean), not a free-form profile dump.
        self.assertEqual(
            gi("Does DET0011 detect T1001?", "DetectionStrategy"),
            ("Techniques", "techniques", "technique_details"),
        )
        # Keyword inside the entity's OWN name must not hijack routing:
        # "Detect" in DET0001's name, "Analytic" in AN0001's name.
        self.assertEqual(
            gi("What analytics does DET0001 (Detect Access to Cloud Instance "
               "Metadata API (IaaS)) have?", "DetectionStrategy")[0],
            "Analytics",
        )
        self.assertEqual(
            gi("Which detection strategy does AN0001 (Analytic 0001) belong to?",
               "Analytic")[0],
            "Detection Strategies",
        )


if __name__ == "__main__":
    unittest.main()
