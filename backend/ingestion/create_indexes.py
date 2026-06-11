
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    print("Connected to Neo4j")
    return driver


def create_fulltext_index(driver):
    with driver.session() as session:
        session.run("""
                    CREATE FULLTEXT INDEX mitre_bm25 IF NOT EXISTS 
                    FOR (n:Technique|Actor|Malware|Tool|Mitigation|Tactic|Campaign|DataComponent|Analytic|DetectionStrategy)
                    ON EACH [n.name, n.description, n.external_id]
                    """)
        print("BM25 index created")


def create_vector_index(driver):
    with driver.session() as session:
        session.run("DROP INDEX mitre_vector IF EXISTS")
        session.run("""
                    CREATE VECTOR INDEX mitre_vector IF NOT EXISTS
                    FOR (n:MitreNode)
                    ON n.embedding
                    OPTIONS {indexConfig: {
                    `vector.dimensions`:768,
                    `vector.similarity_function`: 'cosine'
                    }}
                    """)
        print("Vector index created")


if __name__ == "__main__":
    driver = get_driver()
    create_fulltext_index(driver)
    create_vector_index(driver)
    driver.close()
