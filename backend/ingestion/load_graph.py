


from neo4j import GraphDatabase
import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    print("Connected to Neo4j successfully!")
    return driver


def create_constraints(driver):
    contraints = [
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Actor) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Malware) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Tool) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Tactic) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Campaign) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:DataComponent) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Analytic) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:DetectionStrategy) REQUIRE n.id IS UNIQUE"

    ]

    with driver.session() as session:
        for c in contraints:
            session.run(c)
        print("Constraints created successfully!")


def load_techniques(driver):
    techniques = json.load(open("data/parsed/techniques.json"))
    with driver.session() as session:
        for t in techniques:
            session.run("""
                       MERGE (n:Technique {id: $id})
                       SET n:MitreNode,
                           n.name = $name,
                           n.description = $description,
                           n.external_id = $external_id,
                           n.url = $url,
                           n.platforms = $platforms,
                           n.kill_chain_phases = $kill_chain_phases,
                           n.is_subtechnique = $is_subtechnique                    
        """,
                        id=t["id"],
                        name=t["name"],
                        description=t["description"],
                        external_id=t["external_id"],
                        url=t["url"],
                        platforms=t.get("platforms", []),
                        kill_chain_phases=t.get("kill_chain_phases", []),
                        is_subtechnique=t.get("is_subtechnique", False))
    print(f"Loaded {len(techniques)} techniques")


def load_actors(driver):
    actors = json.load(open("data/parsed/actors.json"))
    with driver.session() as session:
        for a in actors:
            session.run("""
                        MERGE (n:Actor {id: $id})
                        SET n:MitreNode,
                        n.name = $name,
                        n.description = $description,
                        n.external_id = $external_id,
                        n.url = $url,
                        n.aliases = $aliases
                        """,
                        id=a["id"],
                        name=a["name"],
                        description=a["description"],
                        external_id=a["external_id"],
                        url=a["url"],
                        aliases=a.get("aliases", []))
    print(f"Loaded {len(actors)} actors")


def load_malware(driver):
    malwares = json.load(open("data/parsed/malware.json"))
    with driver.session() as session:
        for m in malwares:
            session.run("""
                        MERGE (n:Malware {id: $id})
                        SET n:MitreNode, 
                        n.name = $name,
                        n.description = $description,
                        n.external_id = $external_id,
                        n.url = $url,
                        n.platforms = $platforms,
                        n.aliases = $aliases
""",
                        id=m["id"],
                        name=m["name"],
                        description=m["description"],
                        external_id=m["external_id"],
                        url=m["url"],
                        platforms=m.get("platforms", []),
                        aliases=m.get("aliases", []))
    print(f"Loaded {len(malwares)} malware")


def load_tools(driver):
    tools = json.load(open("data/parsed/tools.json"))
    with driver.session() as session:
        for t in tools:
            session.run("""
                        MERGE (n:Tool {id: $id})
                        SET n:MitreNode,
                        n.name = $name,
                        n.description = $description,
                        n.external_id = $external_id,
                        n.url = $url,
                        n.platforms = $platforms,
                        n.aliases = $aliases
                        
""",                       id=t["id"],
                        name=t["name"],
                        description=t["description"],
                        external_id=t["external_id"],
                        url=t["url"],
                        platforms=t.get("platforms", []),
                        aliases=t.get("aliases", []))
    print(f"Loaded {len(tools)} tools")


def load_mitigations(driver):
    mitigations = json.load(open("data/parsed/mitigations.json"))
    with driver.session() as session:
        for m in mitigations:
            session.run("""
                        MERGE (n:Mitigation {id: $id})
                        SET n:MitreNode, 
                        n.name = $name,
                        n.description = $description,
                        n.external_id = $external_id,
                        n.url = $url
                        """,
                        id=m["id"],
                        name=m["name"],
                        description=m["description"],
                        external_id=m["external_id"],
                        url=m["url"])
    print(f"Loaded {len(mitigations)} mitigations")


def load_tactics(driver):
    tactics = json.load(open("data/parsed/tactics.json"))
    with driver.session() as session:
        for t in tactics:
            session.run("""
                        MERGE (n:Tactic {id: $id})
                        SET n:MitreNode, 
                        n.name = $name,
                        n.description = $description,
                        n.external_id = $external_id,
                        n.url = $url,
                        n.shortname = $shortname                        
""",
                        id=t["id"],
                        name=t["name"],
                        description=t["description"],
                        external_id=t["external_id"],
                        url=t["url"],
                        shortname=t.get("shortname"))
    print(f"Loaded {len(tactics)} tactics")


def load_campaigns(driver):
    campaigns = json.load(open("data/parsed/campaigns.json"))
    with driver.session() as session:
        for c in campaigns:
            session.run("""
                        MERGE (n:Campaign {id: $id})
                        SET n:MitreNode,
                        n.name = $name,
                        n.description = $description,
                        n.external_id = $external_id,
                        n.url = $url,
                        n.first_seen = $first_seen,
                        n.last_seen = $last_seen                        
""",
                        id=c["id"],
                        name=c["name"],
                        description=c["description"],
                        external_id=c["external_id"],
                        url=c["url"],
                        first_seen=c.get("first_seen"),
                        last_seen=c.get("last_seen"))
    print(f"Loaded {len(campaigns)} campaigns")


def load_data_components(driver):
    components = json.load(open("data/parsed/data_components.json"))
    with driver.session() as session:
        for c in components:
            session.run("""
                        MERGE (n:DataComponent {id: $id})
                        SET n:MitreNode, 
                        n.name = $name,
                        n.description = $description,
                        n.external_id = $external_id,
                        n.url = $url,
                        n.log_sources = $log_sources                     
""",                        id=c["id"],
                        name=c["name"],
                        description=c["description"],
                        external_id=c["external_id"],
                        url=c["url"],
                        log_sources=str(c.get("log_sources", [])))
    print(f"Loaded {len(components)} data components")


def load_analytics(driver):
    analytics = json.load(open("data/parsed/analytics.json"))
    with driver.session() as session:
        for a in analytics:
            session.run("""
                        MERGE (n:Analytic {id: $id})
                        SET n:MitreNode, 
                        n.name = $name,
                        n.description = $description,
                        n.external_id = $external_id,
                        n.url = $url,
                        n.platforms = $platforms
                        """,
                        id=a["id"],
                        name=a["name"],
                        description=a["description"],
                        external_id=a["external_id"],
                        url=a["url"],
                        platforms=a.get("platforms", []))
    print(f"Loaded {len(analytics)} analytics")


def load_detection_strategies(driver):
    strategies = json.load(open("data/parsed/detection_strategies.json"))
    with driver.session() as session:
        for s in strategies:
            session.run("""
                        MERGE (n:DetectionStrategy {id: $id})
                        SET n:MitreNode, 
                        n.name = $name,
                        n.external_id = $external_id,
                        n.url = $url
                        """,
                        id=s["id"],
                        name=s["name"],
                        external_id=s["external_id"],
                        url=s["url"])
    print(f"Loaded {len(strategies)} detection strategies")


def load_relationships(driver):
    relationships = json.load(open("data/parsed/relationships.json"))

    node_labels = {
        "attack-pattern": "Technique",
        "intrusion-set": "Actor",
        "malware": "Malware",
        "tool": "Tool",
        "course-of-action": "Mitigation",
        "campaign": "Campaign",
        "x-mitre-detection-strategy": "DetectionStrategy"
    }

    loaded = 0
    skipped = 0
    with driver.session() as session:
        for r in relationships:
            src_type = r["source_ref"].split("--")[0]
            tgt_type = r["target_ref"].split("--")[0]
            src_label = node_labels.get(src_type)
            tgt_label = node_labels.get(tgt_type)

            if not src_label or not tgt_label:
                skipped += 1
                continue

            rel_type = r["relationship_type"].upper().replace("-", "_")

            query = f"""
                MATCH (src:{src_label} {{id: $source_ref}})
                MATCH (tgt:{tgt_label} {{id: $target_ref}})
                MERGE (src)-[:{rel_type}]->(tgt)
            """
            session.run(query,
                        source_ref=r["source_ref"],
                        target_ref=r["target_ref"])
            loaded += 1

    print(f"Loaded {loaded} relationships, skipped {skipped}")


def load_analytic_relationships(driver):
    strategies = json.load(open("data/parsed/detection_strategies.json"))
    analytics = json.load(open("data/parsed/analytics.json"))

    loaded = 0
    with driver.session() as session:
        for s in strategies:
            for ref in s.get("analytic_refs", []):
                session.run("""
                    MATCH (s:DetectionStrategy {id: $sid})
                    MATCH (a:Analytic {id: $aid})
                    MERGE (s)-[:HAS_ANALYTIC]->(a)
                """, sid=s["id"], aid=ref)
                loaded += 1

        for a in analytics:
            for ref in a.get("data_component_refs", []):
                session.run("""
                    MATCH (a:Analytic {id: $aid})
                    MATCH (d:DataComponent {id: $did})
                    MERGE (a)-[:USES_DATA_COMPONENT]->(d)
                """, aid=a["id"], did=ref)
                loaded += 1
    print(f"Loaded {loaded} analytic relationships")

def load_tactic_relationships(driver):
    with driver.session() as session:
        result = session.run("""
            MATCH (t:Technique)
            WHERE t.kill_chain_phases IS NOT NULL
            RETURN t.id, t.kill_chain_phases
        """)
        
        loaded = 0
        for record in result:
            for phase in record["t.kill_chain_phases"]:
                session.run("""
                    MATCH (t:Technique {id: $tid})
                    MATCH (tac:Tactic {shortname: $shortname})
                    MERGE (t)-[:BELONGS_TO_TACTIC]->(tac)
                """, tid=record["t.id"], shortname=phase)
                loaded += 1
        
        print(f"Loaded {loaded} tactic relationships")
        

if __name__ == "__main__":
    driver = get_driver()
    create_constraints(driver)
    load_techniques(driver)
    load_actors(driver)
    load_malware(driver)
    load_tools(driver)
    load_mitigations(driver)
    load_tactics(driver)
    load_campaigns(driver)
    load_data_components(driver)
    load_analytics(driver)
    load_detection_strategies(driver)
    load_relationships(driver)
    load_analytic_relationships(driver)
    load_tactic_relationships(driver)
    driver.close()
