import sys
import os 
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
import ollama

def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    print("Connected to Neo4j")
    return driver


def embed_nodes(driver):
    with driver.session() as session:
        # Get all nodes that dont have embeddings yet
        result = session.run("""
                            MATCH (n:MitreNode)
                            WHERE n.embedding IS NULL 
                            RETURN n.id as id, n.name as name, n.description as description
                             """)
        nodes = list(result)
        print(f"Nodes to embed: {len(nodes)}")

        for i, node in enumerate(nodes):
            #Create context rick text for embedding
            text = f"{node['name']}. {node['description']}" if node['description'] else node['name']

            #Get embedding from ollama
            response = ollama.embeddings(model = 'nomic-embed-text', prompt=text)
            embedding = response['embedding']

            #Store embedding in Neo4j
            session.run("""
                        MATCH (n:MitreNode {id: $id})
                        SET n.embedding = $embedding
                        """, id=node['id'], embedding=embedding)
                        
            if (i+1) % 100 == 0:
                print(f"Embedded {i+1}/{len(nodes)} nodes")

    print(f"All nodes embedded")

if __name__ == "__main__":
    driver = get_driver()
    embed_nodes(driver)
    driver.close()

