
import ollama
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from neo4j import GraphDatabase

def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return driver


def vector_search(driver, query: str, k: int = 10) -> list[dict]:
    embedding = ollama.embeddings(
        model='nomic-embed-text', prompt=query)['embedding']
    with driver.session() as session:
        result = session.run('''
    MATCH (node:MitreNode)
    WHERE node.embedding IS NOT NULL
    WITH node, vector.similarity.cosine(node.embedding, $embedding) AS score
    ORDER BY score DESC
    LIMIT $k
    RETURN node.id as id, node.name as name,
           node.external_id as external_id,
           labels(node)[0] as type, score
''', embedding=embedding, k=k)
        
        return [dict(r) for r in result]

def bm25_search(driver, query: str, k: int=10) -> list[dict]:
    with driver.session() as session:
        result = session.run('''
                             CALL db.index.fulltext.queryNodes($index, $search_query)
                             YIELD node, score
                             RETURN node.id as id, node.name as name,
                                node.external_id as external_id,
                                labels(node)[0] as type, score
                             LIMIT $k''',
                             index='mitre_bm25', search_query=query, k=k)
        return [dict(r) for r in result]


def expand_query(query: str) -> list[str]:
    response = ollama.chat(
        model='llama3.1',
        messages=[{
            'role': 'user',
            'content': f"""
             Generate 3 different search queries for this cybersecurity question.
             Return ONLY the queries, one per line, no numbering, no explanation.
             Original query: {query}"""
        }]
    )
    expanded = response['message']['content'].strip().split('\n')
    expanded = [q.strip() for q in expanded if q.strip()]
    return [query] + expanded[:3]

def rrf_fusion(vector_results: list, bm25_results: list, k: int=60) -> list[dict]:
    scores = {}
    for rank, r in enumerate(vector_results):
        id_ = r['id']
        if id_ not in scores:
            scores[id_] = {'data':r, 'score':0}
        scores[id_]['score'] += 1/(k+rank+1)
    
    for rank, r in enumerate(bm25_results):
        id_ = r['id']
        if id_ not in scores:
            scores[id_] = {'data':r, 'score':0}
        scores[id_]['score'] += 1/(k+rank+1)
    
    ranked = sorted(scores.values(), key=lambda x: x['score'], reverse=True)
    return [r['data'] for r in ranked]

def search(query: str, top_k: int = 10) -> list[dict]:
    driver = get_driver()
    queries = expand_query(query)

    all_vector, all_bm25 = [], []
    for q in queries:
        all_vector.extend(vector_search(driver, q))
        all_bm25.extend(bm25_search(driver, q))

    fused = rrf_fusion(all_vector, all_bm25)
    driver.close()
    return fused[:top_k]

if __name__ == "__main__":
    results = search("credential theft using stolen passwords")
    print("=== Search Results ===")
    for r in results:
        print(f"[{r['type']}] {r['name']} ({r['external_id']})")

