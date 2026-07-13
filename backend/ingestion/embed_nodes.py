import sys
import os 
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
import ollama
from ingestion.contextualize import (
    CONTEXT_VERSION,
    build_contextual_text,
    build_embedding_text,
    context_fingerprint,
)


EMBEDDING_MODEL = 'nomic-embed-text'

def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    print("Connected to Neo4j")
    return driver


def embed_nodes(driver):
    with driver.session() as session:
        # Migration for embeddings written by the first contextual-retrieval pass,
        # before context_version was stored as a separate property.
        session.run("""
            MATCH (n:MitreNode)
            WHERE n.context_fingerprint IS NOT NULL AND n.context_version IS NULL
            SET n.context_version = $context_version
        """, context_version=CONTEXT_VERSION)

        # Context is derived from node metadata and explicit graph relationships.
        # Full graph reloads invalidate fingerprints; normal reruns fetch only stale nodes.
        result = session.run("""
            MATCH (n:MitreNode)
            WHERE n.embedding IS NULL
               OR n.context_fingerprint IS NULL
               OR coalesce(n.embedding_model, '') <> $embedding_model
               OR coalesce(n.context_version, '') <> $context_version
            OPTIONAL MATCH (n)-[r]-(other:MitreNode)
            RETURN n.id AS id,
                   n.name AS name,
                   n.description AS description,
                   n.external_id AS external_id,
                   n.aliases AS aliases,
                   n.platforms AS platforms,
                   n.kill_chain_phases AS kill_chain_phases,
                   n.shortname AS shortname,
                   n.first_seen AS first_seen,
                   n.last_seen AS last_seen,
                   n.log_sources AS log_sources,
                   labels(n) AS labels,
                   n.context_fingerprint AS stored_fingerprint,
                   n.embedding IS NOT NULL AS has_embedding,
                   collect(DISTINCT CASE WHEN r IS NULL THEN null ELSE {
                       relationship: type(r),
                       direction: CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END,
                       other_name: other.name,
                       other_external_id: other.external_id,
                       other_labels: labels(other)
                   } END) AS relationships
        """, embedding_model=EMBEDDING_MODEL, context_version=CONTEXT_VERSION)
        nodes = list(result)
        print(f"Nodes to inspect: {len(nodes)}")

        embedded = 0
        skipped = 0
        failures = []
        for i, node in enumerate(nodes):
            node_data = dict(node)
            contextual_text = build_contextual_text(
                node_data, node_data.get('relationships')
            )
            fingerprint = context_fingerprint(contextual_text, EMBEDDING_MODEL)
            if node_data.get('has_embedding') and node_data.get('stored_fingerprint') == fingerprint:
                skipped += 1
                continue

            text = build_embedding_text(node_data, contextual_text)
            try:
                response = ollama.embeddings(model=EMBEDDING_MODEL, prompt=text)
                embedding = response['embedding']
                session.run("""
                    MATCH (n:MitreNode {id: $id})
                    SET n.embedding = $embedding,
                        n.contextual_text = $contextual_text,
                        n.context_fingerprint = $fingerprint,
                        n.embedding_model = $embedding_model,
                        n.context_version = $context_version
                """, id=node_data['id'], embedding=embedding,
                    contextual_text=contextual_text, fingerprint=fingerprint,
                    embedding_model=EMBEDDING_MODEL, context_version=CONTEXT_VERSION)
                embedded += 1
            except Exception as exc:
                failures.append(f"{node_data['id']}: {exc}")

            if (i + 1) % 100 == 0:
                print(f"Inspected {i + 1}/{len(nodes)} nodes; embedded {embedded}")

    print(f"Contextual embeddings updated: {embedded}; unchanged: {skipped}")
    if failures:
        sample = "; ".join(failures[:5])
        raise RuntimeError(f"Failed to embed {len(failures)} nodes. First failures: {sample}")

if __name__ == "__main__":
    driver = get_driver()
    try:
        embed_nodes(driver)
    finally:
        driver.close()
