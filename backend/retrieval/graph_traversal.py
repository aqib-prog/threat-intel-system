import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return driver

def traverse_node(driver, node_id:str, node_type:str) -> dict:
    with driver.session() as session:

        if node_type == "Technique":
            result = session.run("""
                MATCH (t:Technique {id: $id})
                OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
                OPTIONAL MATCH (a:Actor)-[:USES]->(t)
                OPTIONAL MATCH (mal:Malware)-[:USES]->(t)
                OPTIONAL MATCH (tool:Tool)-[:USES]->(t)
                OPTIONAL MATCH (c:Campaign)-[:USES]->(t)
                OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(t)
                OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(an:Analytic)-[:USES_DATA_COMPONENT]->(dc:DataComponent)
                OPTIONAL MATCH (t)-[:SUBTECHNIQUE_OF]->(parent:Technique)
                OPTIONAL MATCH (sub:Technique)-[:SUBTECHNIQUE_OF]->(t)
                RETURN t.name as name, t.external_id as id, 
                       t.description as description,
                       t.platforms as platforms,
                       t.is_subtechnique as is_subtechnique,
                       collect(DISTINCT tac.name) as tactics,
                       collect(DISTINCT m.name) as mitigations,
                       collect(DISTINCT a.name) as actors,
                       collect(DISTINCT mal.name) as malware,
                       collect(DISTINCT tool.name) as tools,
                       collect(DISTINCT c.name) as campaigns,
                       collect(DISTINCT ds.name) as detections,
                       collect(DISTINCT an.description) as analytics,
                       collect(DISTINCT dc.name) as log_sources,
                       parent.name as parent_technique,
                       collect(DISTINCT sub.name) as subtechniques
            """, id=node_id)

        elif node_type == "Actor":
            result = session.run("""
                MATCH (a:Actor {id: $id})
                OPTIONAL MATCH (a)-[:USES]->(t:Technique)
                OPTIONAL MATCH (a)-[:USES]->(mal:Malware)
                OPTIONAL MATCH (a)-[:USES]->(tool:Tool)
                OPTIONAL MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(a)
                OPTIONAL MATCH (a)-[:USES]->(t2:Technique)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                RETURN a.name as name, a.external_id as id, 
                       a.description as description,
                       a.aliases as aliases,
                       collect(DISTINCT t.name) as techniques,
                       collect(DISTINCT mal.name) as malware,
                       collect(DISTINCT tool.name) as tools,
                       collect(DISTINCT c.name) as campaigns,
                       collect(DISTINCT tac.name) as tactics
            """, id=node_id)

        elif node_type == "Malware":
            result = session.run("""
                MATCH (mal:Malware {id: $id})
                OPTIONAL MATCH (mal)-[:USES]->(t:Technique)
                OPTIONAL MATCH (a:Actor)-[:USES]->(mal)
                OPTIONAL MATCH (c:Campaign)-[:USES]->(mal)
                OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
                RETURN mal.name as name, mal.external_id as id, 
                       mal.description as description,
                       mal.platforms as platforms,
                       mal.aliases as aliases,
                       collect(DISTINCT t.name) as techniques,
                       collect(DISTINCT a.name) as actors,
                       collect(DISTINCT c.name) as campaigns,
                       collect(DISTINCT tac.name) as tactics,
                       collect(DISTINCT m.name) as mitigations
            """, id=node_id)

        elif node_type == "Tool":
            result = session.run("""
                MATCH (tool:Tool {id: $id})
                OPTIONAL MATCH (tool)-[:USES]->(t:Technique)
                OPTIONAL MATCH (a:Actor)-[:USES]->(tool)
                OPTIONAL MATCH (c:Campaign)-[:USES]->(tool)
                OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
                RETURN tool.name as name, tool.external_id as id, 
                       tool.description as description,
                       tool.platforms as platforms,
                       tool.aliases as aliases,
                       collect(DISTINCT t.name) as techniques,
                       collect(DISTINCT a.name) as actors,
                       collect(DISTINCT c.name) as campaigns,
                       collect(DISTINCT tac.name) as tactics,
                       collect(DISTINCT m.name) as mitigations
            """, id=node_id)

        elif node_type == "Mitigation":
            result = session.run("""
                MATCH (m:Mitigation {id: $id})
                OPTIONAL MATCH (m)-[:MITIGATES]->(t:Technique)
                OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                OPTIONAL MATCH (a:Actor)-[:USES]->(t)
                RETURN m.name as name, m.external_id as id, 
                       m.description as description,
                       collect(DISTINCT t.name) as techniques,
                       collect(DISTINCT tac.name) as tactics,
                       collect(DISTINCT a.name) as actors
            """, id=node_id)

        elif node_type == "Tactic":
            result = session.run("""
                MATCH (tac:Tactic {id: $id})
                OPTIONAL MATCH (t:Technique)-[:BELONGS_TO_TACTIC]->(tac)
                OPTIONAL MATCH (a:Actor)-[:USES]->(t)
                OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
                RETURN tac.name as name, tac.external_id as id, 
                       tac.description as description,
                       tac.shortname as shortname,
                       collect(DISTINCT t.name) as techniques,
                       collect(DISTINCT a.name) as actors,
                       collect(DISTINCT m.name) as mitigations
            """, id=node_id)

        elif node_type == "Campaign":
            result = session.run("""
                MATCH (c:Campaign {id: $id})
                OPTIONAL MATCH (c)-[:USES]->(t:Technique)
                OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(a:Actor)
                OPTIONAL MATCH (c)-[:USES]->(mal:Malware)
                OPTIONAL MATCH (c)-[:USES]->(tool:Tool)
                OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                RETURN c.name as name, c.external_id as id, 
                       c.description as description,
                       c.first_seen as first_seen, 
                       c.last_seen as last_seen,
                       collect(DISTINCT t.name) as techniques,
                       collect(DISTINCT a.name) as actors,
                       collect(DISTINCT mal.name) as malware,
                       collect(DISTINCT tool.name) as tools,
                       collect(DISTINCT tac.name) as tactics
            """, id=node_id)

        elif node_type == "DetectionStrategy":
            result = session.run("""
                MATCH (ds:DetectionStrategy {id: $id})
                OPTIONAL MATCH (ds)-[:DETECTS]->(t:Technique)
                OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(an:Analytic)
                OPTIONAL MATCH (an)-[:USES_DATA_COMPONENT]->(dc:DataComponent)
                OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                RETURN ds.name as name, ds.external_id as id,
                       collect(DISTINCT t.name) as techniques,
                       collect(DISTINCT tac.name) as tactics,
                       collect(DISTINCT an.description) as analytics,
                       collect(DISTINCT dc.name) as log_sources
            """, id=node_id)

        elif node_type == "Analytic":
            result = session.run("""
                MATCH (an:Analytic {id: $id})
                OPTIONAL MATCH (an)-[:USES_DATA_COMPONENT]->(dc:DataComponent)
                OPTIONAL MATCH (ds:DetectionStrategy)-[:HAS_ANALYTIC]->(an)
                OPTIONAL MATCH (ds)-[:DETECTS]->(t:Technique)
                RETURN an.name as name, an.external_id as id, 
                       an.description as description,
                       an.platforms as platforms,
                       collect(DISTINCT dc.name) as log_sources,
                       collect(DISTINCT ds.name) as detection_strategies,
                       collect(DISTINCT t.name) as techniques
            """, id=node_id)

        elif node_type == "DataComponent":
            result = session.run("""
                MATCH (dc:DataComponent {id: $id})
                OPTIONAL MATCH (an:Analytic)-[:USES_DATA_COMPONENT]->(dc)
                OPTIONAL MATCH (ds:DetectionStrategy)-[:HAS_ANALYTIC]->(an)
                OPTIONAL MATCH (ds)-[:DETECTS]->(t:Technique)
                RETURN dc.name as name, dc.external_id as id, 
                       dc.description as description,
                       dc.log_sources as log_sources,
                       collect(DISTINCT an.name) as analytics,
                       collect(DISTINCT ds.name) as detection_strategies,
                       collect(DISTINCT t.name) as techniques
            """, id=node_id)

        else:
            result = session.run("""
                MATCH (n {id: $id})
                RETURN n.name as name, n.external_id as id, 
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

