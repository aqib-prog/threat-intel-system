import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from neo4j import GraphDatabase, Query
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD


QUERY_TIMEOUT_SECONDS = float(os.getenv("NEO4J_QUERY_TIMEOUT_SECONDS", "30"))


def run_query(session, cypher: str, **parameters):
    return session.run(
        Query(cypher, timeout=QUERY_TIMEOUT_SECONDS),
        **parameters,
    )

def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return driver

def traverse_node(driver, node_id:str, node_type:str) -> dict:
    with driver.session() as session:

        if node_type == "Technique":
            result = run_query(session, """
                MATCH (t:Technique {id: $id})
                CALL { WITH t OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(n:Tactic) RETURN collect(DISTINCT n.name) AS tactics, collect(DISTINCT n {.name, .external_id}) AS tactic_details }
                CALL { WITH t OPTIONAL MATCH (n:Mitigation)-[:MITIGATES]->(t) RETURN collect(DISTINCT n.name) AS mitigations, collect(DISTINCT n {.name, .external_id}) AS mitigation_details }
                CALL { WITH t OPTIONAL MATCH (n:Actor)-[:USES]->(t) RETURN collect(DISTINCT n.name) AS direct_actors, collect(DISTINCT n {.name, .external_id}) AS direct_actor_details }
                CALL { WITH t OPTIONAL MATCH (c:Campaign)-[:USES]->(t) OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(n:Actor) RETURN collect(DISTINCT n.name) AS campaign_actors, collect(DISTINCT n {.name, .external_id}) AS campaign_actor_details }
                CALL { WITH t OPTIONAL MATCH (n:Malware)-[:USES]->(t) RETURN collect(DISTINCT n.name) AS malware, collect(DISTINCT n {.name, .external_id}) AS malware_details }
                CALL { WITH t OPTIONAL MATCH (n:Tool)-[:USES]->(t) RETURN collect(DISTINCT n.name) AS tools, collect(DISTINCT n {.name, .external_id}) AS tool_details }
                CALL { WITH t OPTIONAL MATCH (n:Campaign)-[:USES]->(t) RETURN collect(DISTINCT n.name) AS campaigns, collect(DISTINCT n {.name, .external_id}) AS campaign_details }
                CALL {
                    WITH t
                    OPTIONAL MATCH (c:Campaign)-[:USES]->(s)-[:USES]->(t)
                    WHERE s:Malware OR s:Tool
                    RETURN collect(DISTINCT c.name) AS campaigns_via_software,
                           collect(DISTINCT c {.name, .external_id}) AS campaign_via_software_details,
                           collect(DISTINCT s.name) AS campaign_software,
                           collect(DISTINCT s {.name, .external_id}) AS campaign_software_details
                }
                CALL { WITH t OPTIONAL MATCH (n:DetectionStrategy)-[:DETECTS]->(t) RETURN collect(DISTINCT n.name) AS detections, collect(DISTINCT n {.name, .external_id}) AS detection_strategy_details }
                CALL { WITH t OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(t) OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(n:Analytic) RETURN collect(DISTINCT n.description) AS analytics, collect(DISTINCT n {.name, .external_id}) AS detection_analytic_details }
                CALL { WITH t OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(t) OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(:Analytic)-[:USES_DATA_COMPONENT]->(n:DataComponent) RETURN collect(DISTINCT n.name) AS log_sources }
                CALL { WITH t OPTIONAL MATCH (t)-[:SUBTECHNIQUE_OF]->(n:Technique) RETURN head(collect(DISTINCT n.name)) AS parent_technique, head(collect(DISTINCT n {.name, .external_id})) AS parent_technique_detail }
                CALL { WITH t OPTIONAL MATCH (n:Technique)-[:SUBTECHNIQUE_OF]->(t) RETURN collect(DISTINCT n.name) AS subtechniques, collect(DISTINCT n {.name, .external_id}) AS subtechnique_details }
                RETURN t.name as name, t.external_id as id, t.url as url,
                       t.description as description,
                       t.platforms as platforms,
                       t.is_subtechnique as is_subtechnique,
                       tactics, mitigations,
                       reduce(acc = [], value IN direct_actors + campaign_actors |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS actors,
                       malware, tools, campaigns,
                       campaigns_via_software, campaign_software,
                       detections, analytics, log_sources, parent_technique,
                       subtechniques, tactic_details, mitigation_details,
                       reduce(acc = [], value IN direct_actor_details + campaign_actor_details |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS actor_details,
                       detection_strategy_details,
                       parent_technique_detail, subtechnique_details,
                       malware_details, tool_details, campaign_details,
                       campaign_via_software_details, campaign_software_details,
                       detection_analytic_details
            """, id=node_id)

        elif node_type == "Actor":
            result = run_query(session, """
                MATCH (a:Actor {id: $id})
                CALL { WITH a
                    OPTIONAL MATCH (a)-[:USES]->(t:Technique)
                    RETURN collect(DISTINCT t.name) AS direct_techniques, collect(DISTINCT t {.name, .external_id}) AS direct_technique_details
                }
                CALL { WITH a
                    OPTIONAL MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(a)
                    OPTIONAL MATCH (c)-[:USES]->(t:Technique)
                    RETURN collect(DISTINCT t.name) AS campaign_techniques, collect(DISTINCT t {.name, .external_id}) AS campaign_technique_details
                }
                CALL { WITH a
                    OPTIONAL MATCH (a)-[:USES]->(mal:Malware)
                    RETURN collect(DISTINCT mal.name) AS direct_malware, collect(DISTINCT mal {.name, .external_id}) AS direct_malware_details
                }
                CALL { WITH a
                    OPTIONAL MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(a)
                    OPTIONAL MATCH (c)-[:USES]->(mal:Malware)
                    RETURN collect(DISTINCT mal.name) AS campaign_malware, collect(DISTINCT mal {.name, .external_id}) AS campaign_malware_details
                }
                CALL { WITH a
                    OPTIONAL MATCH (a)-[:USES]->(tool:Tool)
                    RETURN collect(DISTINCT tool.name) AS direct_tools, collect(DISTINCT tool {.name, .external_id}) AS direct_tool_details
                }
                CALL { WITH a
                    OPTIONAL MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(a)
                    OPTIONAL MATCH (c)-[:USES]->(tool:Tool)
                    RETURN collect(DISTINCT tool.name) AS campaign_tools, collect(DISTINCT tool {.name, .external_id}) AS campaign_tool_details
                }
                CALL { WITH a
                    OPTIONAL MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(a)
                    RETURN collect(DISTINCT c.name) AS campaigns, collect(DISTINCT c {.name, .external_id}) AS campaign_details
                }
                CALL { WITH a
                    OPTIONAL MATCH (a)-[:USES]->(:Technique)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                    RETURN collect(DISTINCT tac.name) AS direct_tactics, collect(DISTINCT tac {.name, .external_id}) AS direct_tactic_details
                }
                CALL { WITH a
                    OPTIONAL MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(a)
                    OPTIONAL MATCH (c)-[:USES]->(:Technique)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                    RETURN collect(DISTINCT tac.name) AS campaign_tactics, collect(DISTINCT tac {.name, .external_id}) AS campaign_tactic_details
                }
                RETURN a.name as name, a.external_id as id, a.url as url,
                       a.description as description,
                       a.aliases as aliases,
                       reduce(acc = [], value IN direct_techniques + campaign_techniques |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS techniques,
                       reduce(acc = [], value IN direct_malware + campaign_malware |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS malware,
                       reduce(acc = [], value IN direct_tools + campaign_tools |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS tools,
                       campaigns,
                       reduce(acc = [], value IN direct_tactics + campaign_tactics |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS tactics,
                       reduce(acc = [], value IN direct_technique_details + campaign_technique_details |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS technique_details,
                       reduce(acc = [], value IN direct_malware_details + campaign_malware_details |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS malware_details,
                       reduce(acc = [], value IN direct_tool_details + campaign_tool_details |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS tool_details,
                       campaign_details,
                       reduce(acc = [], value IN direct_tactic_details + campaign_tactic_details |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS tactic_details
            """, id=node_id)

        elif node_type == "Malware":
            result = run_query(session, """
                MATCH (mal:Malware {id: $id})
                CALL { WITH mal OPTIONAL MATCH (mal)-[:USES]->(n:Technique) RETURN collect(DISTINCT n.name) AS techniques, collect(DISTINCT n {.name, .external_id}) AS technique_details }
                CALL { WITH mal OPTIONAL MATCH (n:Actor)-[:USES]->(mal) RETURN collect(DISTINCT n.name) AS direct_actors, collect(DISTINCT n {.name, .external_id}) AS direct_actor_details }
                CALL { WITH mal OPTIONAL MATCH (c:Campaign)-[:USES]->(mal) OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(n:Actor) RETURN collect(DISTINCT n.name) AS campaign_actors, collect(DISTINCT n {.name, .external_id}) AS campaign_actor_details }
                CALL { WITH mal OPTIONAL MATCH (n:Campaign)-[:USES]->(mal) RETURN collect(DISTINCT n.name) AS campaigns, collect(DISTINCT n {.name, .external_id}) AS campaign_details }
                CALL { WITH mal OPTIONAL MATCH (mal)-[:USES]->(:Technique)-[:BELONGS_TO_TACTIC]->(n:Tactic) RETURN collect(DISTINCT n.name) AS tactics, collect(DISTINCT n {.name, .external_id}) AS tactic_details }
                CALL { WITH mal OPTIONAL MATCH (mal)-[:USES]->(t:Technique) OPTIONAL MATCH (n:Mitigation)-[:MITIGATES]->(t) RETURN collect(DISTINCT n.name) AS mitigations, collect(DISTINCT n {.name, .external_id}) AS mitigation_details }
                RETURN mal.name as name, mal.external_id as id, mal.url as url,
                       mal.description as description,
                       mal.platforms as platforms,
                       mal.aliases as aliases,
                       techniques,
                       reduce(acc = [], value IN direct_actors + campaign_actors |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS actors,
                       campaigns, tactics, mitigations,
                       technique_details,
                       reduce(acc = [], value IN direct_actor_details + campaign_actor_details |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS actor_details,
                       campaign_details,
                       tactic_details, mitigation_details
            """, id=node_id)

        elif node_type == "Tool":
            result = run_query(session, """
                MATCH (tool:Tool {id: $id})
                CALL { WITH tool OPTIONAL MATCH (tool)-[:USES]->(n:Technique) RETURN collect(DISTINCT n.name) AS techniques, collect(DISTINCT n {.name, .external_id}) AS technique_details }
                CALL { WITH tool OPTIONAL MATCH (n:Actor)-[:USES]->(tool) RETURN collect(DISTINCT n.name) AS direct_actors, collect(DISTINCT n {.name, .external_id}) AS direct_actor_details }
                CALL { WITH tool OPTIONAL MATCH (c:Campaign)-[:USES]->(tool) OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(n:Actor) RETURN collect(DISTINCT n.name) AS campaign_actors, collect(DISTINCT n {.name, .external_id}) AS campaign_actor_details }
                CALL { WITH tool OPTIONAL MATCH (n:Campaign)-[:USES]->(tool) RETURN collect(DISTINCT n.name) AS campaigns, collect(DISTINCT n {.name, .external_id}) AS campaign_details }
                CALL { WITH tool OPTIONAL MATCH (tool)-[:USES]->(:Technique)-[:BELONGS_TO_TACTIC]->(n:Tactic) RETURN collect(DISTINCT n.name) AS tactics, collect(DISTINCT n {.name, .external_id}) AS tactic_details }
                CALL { WITH tool OPTIONAL MATCH (tool)-[:USES]->(t:Technique) OPTIONAL MATCH (n:Mitigation)-[:MITIGATES]->(t) RETURN collect(DISTINCT n.name) AS mitigations, collect(DISTINCT n {.name, .external_id}) AS mitigation_details }
                RETURN tool.name as name, tool.external_id as id, tool.url as url,
                       tool.description as description,
                       tool.platforms as platforms,
                       tool.aliases as aliases,
                       techniques,
                       reduce(acc = [], value IN direct_actors + campaign_actors |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS actors,
                       campaigns, tactics, mitigations,
                       technique_details,
                       reduce(acc = [], value IN direct_actor_details + campaign_actor_details |
                           CASE WHEN value IN acc THEN acc ELSE acc + value END) AS actor_details,
                       campaign_details,
                       tactic_details, mitigation_details
            """, id=node_id)

        elif node_type == "Mitigation":
            result = run_query(session, """
                MATCH (m:Mitigation {id: $id})
                CALL { WITH m OPTIONAL MATCH (m)-[:MITIGATES]->(n:Technique) RETURN collect(DISTINCT n.name) AS techniques, collect(DISTINCT n {.name, .external_id}) AS technique_details }
                CALL { WITH m OPTIONAL MATCH (m)-[:MITIGATES]->(:Technique)-[:BELONGS_TO_TACTIC]->(n:Tactic) RETURN collect(DISTINCT n.name) AS tactics, collect(DISTINCT n {.name, .external_id}) AS tactic_details }
                CALL { WITH m OPTIONAL MATCH (m)-[:MITIGATES]->(t:Technique) OPTIONAL MATCH (n:Actor)-[:USES]->(t) RETURN collect(DISTINCT n.name) AS actors, collect(DISTINCT n {.name, .external_id}) AS actor_details }
                RETURN m.name as name, m.external_id as id, m.url as url,
                       m.description as description,
                       techniques, tactics, actors,
                       technique_details, tactic_details, actor_details
            """, id=node_id)

        elif node_type == "Tactic":
            result = run_query(session, """
                MATCH (tac:Tactic {id: $id})
                CALL { WITH tac OPTIONAL MATCH (n:Technique)-[:BELONGS_TO_TACTIC]->(tac) RETURN collect(DISTINCT n.name) AS techniques, collect(DISTINCT n {.name, .external_id}) AS technique_details }
                CALL { WITH tac OPTIONAL MATCH (t:Technique)-[:BELONGS_TO_TACTIC]->(tac) OPTIONAL MATCH (n:Actor)-[:USES]->(t) RETURN collect(DISTINCT n.name) AS actors, collect(DISTINCT n {.name, .external_id}) AS actor_details }
                CALL { WITH tac OPTIONAL MATCH (t:Technique)-[:BELONGS_TO_TACTIC]->(tac) OPTIONAL MATCH (n:Mitigation)-[:MITIGATES]->(t) RETURN collect(DISTINCT n.name) AS mitigations, collect(DISTINCT n {.name, .external_id}) AS mitigation_details }
                RETURN tac.name as name, tac.external_id as id, tac.url as url,
                       tac.description as description,
                       tac.shortname as shortname,
                       techniques, actors, mitigations,
                       technique_details, actor_details, mitigation_details
            """, id=node_id)

        elif node_type == "Campaign":
            result = run_query(session, """
                MATCH (c:Campaign {id: $id})
                CALL { WITH c OPTIONAL MATCH (c)-[:USES]->(n:Technique) RETURN collect(DISTINCT n.name) AS techniques, collect(DISTINCT n {.name, .external_id}) AS technique_details }
                CALL { WITH c OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(n:Actor) RETURN collect(DISTINCT n.name) AS actors, collect(DISTINCT n {.name, .external_id}) AS actor_details }
                CALL { WITH c OPTIONAL MATCH (c)-[:USES]->(n:Malware) RETURN collect(DISTINCT n.name) AS malware, collect(DISTINCT n {.name, .external_id}) AS malware_details }
                CALL { WITH c OPTIONAL MATCH (c)-[:USES]->(n:Tool) RETURN collect(DISTINCT n.name) AS tools, collect(DISTINCT n {.name, .external_id}) AS tool_details }
                CALL { WITH c OPTIONAL MATCH (c)-[:USES]->(:Technique)-[:BELONGS_TO_TACTIC]->(n:Tactic) RETURN collect(DISTINCT n.name) AS tactics, collect(DISTINCT n {.name, .external_id}) AS tactic_details }
                RETURN c.name as name, c.external_id as id, c.url as url,
                       c.description as description,
                       c.first_seen as first_seen,
                       c.last_seen as last_seen,
                       techniques, actors, malware, tools, tactics,
                       actor_details, technique_details, malware_details,
                       tool_details, tactic_details
            """, id=node_id)

        elif node_type == "DetectionStrategy":
            result = run_query(session, """
                MATCH (ds:DetectionStrategy {id: $id})
                CALL { WITH ds OPTIONAL MATCH (ds)-[:DETECTS]->(n:Technique) RETURN collect(DISTINCT n.name) AS techniques, collect(DISTINCT n {.name, .external_id}) AS technique_details }
                CALL { WITH ds OPTIONAL MATCH (ds)-[:DETECTS]->(:Technique)-[:BELONGS_TO_TACTIC]->(n:Tactic) RETURN collect(DISTINCT n.name) AS tactics, collect(DISTINCT n {.name, .external_id}) AS tactic_details }
                CALL { WITH ds OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(n:Analytic) RETURN collect(DISTINCT n.description) AS analytics }
                CALL { WITH ds OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(:Analytic)-[:USES_DATA_COMPONENT]->(n:DataComponent) RETURN collect(DISTINCT n.name) AS log_sources }
                CALL {
                    WITH ds
                    OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(an:Analytic)
                    OPTIONAL MATCH (an)-[:USES_DATA_COMPONENT]->(dc:DataComponent)
                    WITH an, collect(DISTINCT dc.name) AS data_components
                    RETURN collect(DISTINCT an {
                        .name, .external_id, .description, .platforms,
                        log_sources: data_components
                    }) AS analytic_details
                }
                RETURN ds.name as name, ds.external_id as id, ds.url as url,
                       techniques, tactics, analytics, log_sources,
                       technique_details, analytic_details, tactic_details
            """, id=node_id)

        elif node_type == "Analytic":
            result = run_query(session, """
                MATCH (an:Analytic {id: $id})
                CALL { WITH an OPTIONAL MATCH (an)-[:USES_DATA_COMPONENT]->(n:DataComponent) RETURN collect(DISTINCT n.name) AS log_sources, collect(DISTINCT n {.name, .external_id}) AS data_component_details }
                CALL { WITH an OPTIONAL MATCH (n:DetectionStrategy)-[:HAS_ANALYTIC]->(an) RETURN collect(DISTINCT n.name) AS detection_strategies, collect(DISTINCT n {.name, .external_id}) AS detection_strategy_details }
                CALL { WITH an OPTIONAL MATCH (ds:DetectionStrategy)-[:HAS_ANALYTIC]->(an) OPTIONAL MATCH (ds)-[:DETECTS]->(n:Technique) RETURN collect(DISTINCT n.name) AS techniques, collect(DISTINCT n {.name, .external_id}) AS technique_details }
                RETURN an.name as name, an.external_id as id, an.url as url,
                       an.description as description,
                       an.platforms as platforms,
                       log_sources, detection_strategies, techniques,
                       data_component_details, detection_strategy_details,
                       technique_details
            """, id=node_id)

        elif node_type == "DataComponent":
            result = run_query(session, """
                MATCH (dc:DataComponent {id: $id})
                CALL { WITH dc OPTIONAL MATCH (n:Analytic)-[:USES_DATA_COMPONENT]->(dc) RETURN collect(DISTINCT n.name) AS analytics, collect(DISTINCT n {.name, .external_id}) AS analytic_details }
                CALL { WITH dc OPTIONAL MATCH (an:Analytic)-[:USES_DATA_COMPONENT]->(dc) OPTIONAL MATCH (n:DetectionStrategy)-[:HAS_ANALYTIC]->(an) RETURN collect(DISTINCT n.name) AS detection_strategies, collect(DISTINCT n {.name, .external_id}) AS detection_strategy_details }
                CALL { WITH dc OPTIONAL MATCH (an:Analytic)-[:USES_DATA_COMPONENT]->(dc) OPTIONAL MATCH (ds:DetectionStrategy)-[:HAS_ANALYTIC]->(an) OPTIONAL MATCH (ds)-[:DETECTS]->(n:Technique) RETURN collect(DISTINCT n.name) AS techniques, collect(DISTINCT n {.name, .external_id}) AS technique_details }
                RETURN dc.name as name, dc.external_id as id, dc.url as url,
                       dc.description as description,
                       dc.log_sources as log_sources,
                       analytics, detection_strategies, techniques,
                       analytic_details, detection_strategy_details, technique_details
            """, id=node_id)

        else:
            result = run_query(session, """
                MATCH (n {id: $id})
                RETURN n.name as name, n.external_id as id, n.url as url,
                       n.description as description
            """, id=node_id)
        
        record = result.single()
        return dict(record) if record else {}
    
def traverse_nodes(driver, nodes:list)-> list[dict]:
    results = []
    for node in nodes:
        context = traverse_node(driver, node['id'], node['type'])
        if context:
            context['node_type'] = node['type']
            if node.get('external_id'):
                context['external_id'] = node['external_id']
            elif context.get('id'):
                context['external_id'] = context['id']
            if 'score' in node:
                context['score'] = node['score']
            if 'source_score' in node:
                context['source_score'] = node['source_score']
            if 'rrf_score' in node:
                context['rrf_score'] = node['rrf_score']
            results.append(context)
    return results

if __name__ == "__main__":
    driver = get_driver()
    with driver.session() as session:
        result = session.run(
            "MATCH (t:Technique {external_id: 'T1078'}) RETURN t.id as id")
        record = result.single()
        test_nodes = [{"id": record["id"], "type": "Technique"}]

    results = traverse_nodes(driver, test_nodes)
    import json
    print(json.dumps(results, indent=2, default=str))
    driver.close()
