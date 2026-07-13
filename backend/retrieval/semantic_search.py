
import ollama
import re
import sys
import os
from rapidfuzz import fuzz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from neo4j import GraphDatabase

def get_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return driver


MITRE_ID_RE = re.compile(r"\b([GMSTC]A?\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
EXTERNAL_ID_RE = re.compile(
    r"\b(?:[GMSTC]A?\d{4}(?:\.\d{3})?|AN\d{4}|DET\d{4}|DC\d{4})\b",
    re.IGNORECASE
)
ENTITY_REFERENCE_RE = re.compile(
    r"\b(?:[A-Z]{2,}\d+[A-Z0-9]*|[A-Z][a-z]+[A-Z][A-Za-z0-9]*|[A-Za-z]+\d+[A-Za-z0-9]*)\b"
)
LOW_SIGNAL_QUERY_RE = re.compile(
    r"^\s*(?:"
    r"hi|hello|hey|hi\s*,?\s*(?:there|how\s+are\s+you)?|hello\s*,?\s*(?:there|how\s+are\s+you)?|"
    r"how\s+are\s+you|"
    r"thanks|thank\s+you|thx|"
    r"what\s+can\s+you\s+do\??|"
    r"who\s+are\s+you\??"
    r")\s*[.!?]*\s*$",
    re.IGNORECASE
)
OFF_TOPIC_QUERY_RE = re.compile(
    r"\b(?:recipe|pasta|movie|dating\s+advice|phone\s+to\s+buy|weather)\b",
    re.IGNORECASE,
)
JAILBREAK_QUERY_RE = re.compile(
    r"(?:\bforget\b.*\brules\b|\bact\s+as\s+dan\b|\bjailbreak\b|"
    r"\bignore\b.*\b(?:instructions|guidelines)\b|\bhow\s+to\s+hack\b)",
    re.IGNORECASE,
)
CYBER_SIGNAL_QUERY_RE = re.compile(
    r"\b(?:cyber(?:security)?|security\s+investigation|threat|attack(?:er|ers)?|"
    r"malware|ransomware|phishing|adversar(?:y|ies)|detect(?:ion)?|logs?|"
    r"mitre|techniques?|tactics?|campaigns?|mitigations?|analytics?|"
    r"data\s+sources?|actors?|tools?|credential|persistence|"
    r"lateral\s+movement|APT\s*\d+|[GMSTC]A?\d{4}(?:\.\d{3})?|"
    r"CVE-\d{4}-\d{4,7})\b",
    re.IGNORECASE,
)

REQUEST_NODE_TYPE_PATTERNS = {
    "Technique": re.compile(r"\btechniques?\b", re.IGNORECASE),
    "Actor": re.compile(r"\bactors\b", re.IGNORECASE),
    "Malware": re.compile(r"\bmalwares?\b", re.IGNORECASE),
    "Tool": re.compile(r"\btools\b", re.IGNORECASE),
    "Mitigation": re.compile(r"\bmitigations?\b", re.IGNORECASE),
    "Tactic": re.compile(r"\btactics\b", re.IGNORECASE),
    "Campaign": re.compile(r"\bcampaigns\b", re.IGNORECASE),
    "Analytic": re.compile(r"\banalytics?\b", re.IGNORECASE),
    "DetectionStrategy": re.compile(r"\bdetection\s+strateg(?:y|ies)\b", re.IGNORECASE),
    "DataComponent": re.compile(r"\bdata\s+components?\b", re.IGNORECASE),
}

QUALIFIER_NODE_TYPE_PATTERNS = {
    "Technique": re.compile(r"\btechnique\b", re.IGNORECASE),
    "Actor": re.compile(r"\bactor\b", re.IGNORECASE),
    "Tool": re.compile(r"\btool\b", re.IGNORECASE),
    "Tactic": re.compile(r"\btactic\b", re.IGNORECASE),
    "Campaign": re.compile(r"\bcampaign\b", re.IGNORECASE),
}

_FUZZY_ENTITY_CANDIDATES: list[dict] | None = None


def infer_node_types(query: str) -> set[str]:
    requested = {
        node_type
        for node_type, pattern in REQUEST_NODE_TYPE_PATTERNS.items()
        if pattern.search(query)
    }
    if requested:
        return requested

    return {
        node_type
        for node_type, pattern in QUALIFIER_NODE_TYPE_PATTERNS.items()
        if pattern.search(query)
    }


def is_low_signal_query(query: str) -> bool:
    value = (query or "").strip()
    if not re.search(r"[A-Za-z0-9]", value):
        return True
    if len(compact_text(value)) <= 1:
        return True
    if re.fullmatch(r"show\s+me\s+everything", value, re.IGNORECASE):
        return True
    return bool(
        LOW_SIGNAL_QUERY_RE.fullmatch(value)
        or (
            OFF_TOPIC_QUERY_RE.search(value)
            and not CYBER_SIGNAL_QUERY_RE.search(value)
        )
        or JAILBREAK_QUERY_RE.search(value)
    )


def compact_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def explicit_reference_tokens(query: str) -> set[str]:
    return {
        compact_text(match.group(0))
        for match in ENTITY_REFERENCE_RE.finditer(query)
        if not EXTERNAL_ID_RE.fullmatch(match.group(0))
        and not CVE_ID_RE.fullmatch(match.group(0))
    }


def has_exact_query_reference(query: str, node: dict) -> bool:
    compact_query = compact_text(query)
    name = compact_text(str(node.get("name") or ""))
    external_id = compact_text(str(node.get("external_id") or ""))
    return bool(
        (name and name in compact_query)
        or (external_id and external_id in compact_query)
    )


def common_prefix_len(left: str, right: str) -> int:
    count = 0
    for left_char, right_char in zip(left, right):
        if left_char != right_char:
            break
        count += 1
    return count


def is_partial_entity_reference_match(query: str, node: dict) -> bool:
    name = compact_text(str(node.get("name") or ""))
    if not name or has_exact_query_reference(query, node):
        return False

    tokens = explicit_reference_tokens(query)
    if (
        re.fullmatch(r"apt\d+", name)
        and name not in tokens
        and any(re.fullmatch(r"apt\d+", token) for token in tokens)
    ):
        return True

    for token in tokens:
        if not token or token == name:
            continue
        prefix_len = common_prefix_len(token, name)
        shorter = min(len(token), len(name))
        longer = max(len(token), len(name))
        if prefix_len >= 4 and shorter / longer < 0.8:
            return True

    return False


def vector_search(driver, query: str, k: int = 10) -> list[dict]:
    embedding = ollama.embeddings(
        model='nomic-embed-text', prompt=query)['embedding']
    with driver.session() as session:
        try:
            result = session.run('''
                CALL db.index.vector.queryNodes('mitre_vector', $k, $embedding)
                YIELD node, score
                RETURN node.id as id, node.name as name,
                       node.external_id as external_id,
                       head([label IN labels(node) WHERE label <> 'MitreNode']) as type,
                       score
            ''', embedding=embedding, k=k)
            return [dict(r) for r in result]
        except Exception:
            # Compatibility fallback for databases without an online vector index.
            result = session.run('''
                MATCH (node:MitreNode)
                WHERE node.embedding IS NOT NULL
                WITH node, vector.similarity.cosine(node.embedding, $embedding) AS score
                ORDER BY score DESC
                LIMIT $k
                RETURN node.id as id, node.name as name,
                       node.external_id as external_id,
                       head([label IN labels(node) WHERE label <> 'MitreNode']) as type,
                       score
            ''', embedding=embedding, k=k)
        
        return [dict(r) for r in result]

def bm25_search(driver, query: str, k: int=10) -> list[dict]:
    search_query = sanitize_bm25_query(query)
    if not search_query:
        return []

    with driver.session() as session:
        try:
            result = session.run('''
                                 CALL db.index.fulltext.queryNodes($index, $search_query)
                                 YIELD node, score
                                 RETURN node.id as id, node.name as name,
                                    node.external_id as external_id,
                                    head([label IN labels(node) WHERE label <> 'MitreNode']) as type, score
                                 LIMIT $k''',
                                 index='mitre_bm25', search_query=search_query, k=k)
            return [dict(r) for r in result]
        except Exception:
            return []


def sanitize_bm25_query(query: str) -> str:
    cleaned = re.sub(r"&&|\|\|", " ", query)
    cleaned = re.sub(r"[\+!\(\)\{\}\[\]\^\"~\*\?:\\/\-]", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def exact_id_search(driver, query: str) -> list[dict]:
    ids = sorted({match.group(0).upper() for match in EXTERNAL_ID_RE.finditer(query)})
    if not ids:
        return []

    with driver.session() as session:
        result = session.run('''
            MATCH (node:MitreNode)
            WHERE toUpper(node.external_id) IN $ids
            RETURN node.id as id, node.name as name,
                   node.external_id as external_id,
                   head([label IN labels(node) WHERE label <> 'MitreNode']) as type, 1.0 as score
        ''', ids=ids)
        return [dict(r) for r in result]


def exact_name_search(driver, query: str, k: int = 10) -> list[dict]:
    query_tokens = [token.lower() for token in re.findall(r"[A-Za-z0-9_.-]+", query)]
    with driver.session() as session:
        result = session.run('''
            MATCH (node:MitreNode)
            WHERE (
                node.name IS NOT NULL
                AND size(node.name) >= 3
                AND toLower($search_text) CONTAINS toLower(node.name)
            )
            OR any(alias IN coalesce(node.aliases, [])
                WHERE size(alias) >= 3
                AND (
                    toLower(alias) IN $query_tokens
                    OR toLower($search_text) CONTAINS toLower(alias)
                )
            )
            RETURN node.id as id, node.name as name,
                   node.external_id as external_id,
                   head([label IN labels(node) WHERE label <> 'MitreNode']) as type, 1.0 as score
            LIMIT $k
        ''', search_text=query, query_tokens=query_tokens, k=k)
        return [dict(r) for r in result]


def fuzzy_entity_search(driver, query: str, k: int = 5) -> list[dict]:
    global _FUZZY_ENTITY_CANDIDATES
    query_words = re.findall(r"[A-Za-z0-9_.-]+", query)
    compact_query = compact_text(query)
    if not query_words or len(compact_query) < 4:
        return []

    if _FUZZY_ENTITY_CANDIDATES is None:
        with driver.session() as session:
            result = session.run('''
                MATCH (node:MitreNode)
                RETURN node.id as id, node.name as name,
                       node.external_id as external_id,
                       node.aliases as aliases,
                       head([label IN labels(node) WHERE label <> 'MitreNode']) as type
            ''')
            _FUZZY_ENTITY_CANDIDATES = [dict(record) for record in result]
    candidates = _FUZZY_ENTITY_CANDIDATES

    matches = []
    ignored = {"malware", "technique", "campaign", "analytic", "detection"}
    for candidate in candidates:
        references = [candidate.get("name"), *(candidate.get("aliases") or [])]
        best = 0.0
        for reference in references:
            reference = str(reference or "").strip()
            compact_reference = compact_text(reference)
            if len(compact_reference) < 5 or compact_reference in ignored:
                continue
            if compact_reference in compact_query:
                best = 100.0
                break
            word_count = max(1, len(reference.split()))
            for size in range(max(1, word_count - 1), min(len(query_words), word_count + 1) + 1):
                for start in range(len(query_words) - size + 1):
                    phrase = " ".join(query_words[start:start + size])
                    best = max(best, fuzz.ratio(reference.casefold(), phrase.casefold()))
        if best >= 87.0:
            item = dict(candidate)
            item["score"] = best / 100.0
            matches.append(item)

    matches.sort(key=lambda item: item["score"], reverse=True)
    return matches[:k]


def clean_expanded_query(value: str) -> str:
    value = value.strip()
    value = re.sub(r"^\s*(?:[-*]|\d+[\).])\s*", "", value)
    return value.strip(" \"'")


def referenced_ids(query: str) -> set[str]:
    ids = {match.group(0).upper() for match in EXTERNAL_ID_RE.finditer(query)}
    ids.update(match.upper() for match in CVE_ID_RE.findall(query))
    return ids


def deterministic_query_expansions(query: str) -> list[str]:
    value = query.lower()
    expansions = []
    if re.search(r"\b(?:admin\s+share|admin\$|c\$|smb\s+share|windows\s+admin\s+share)", value):
        expansions.append("SMB/Windows Admin Shares T1021.002 lateral movement remote services")
    if re.search(r"\b(?:remote\s+service|service\s+creation|create(?:d)?\s+service|windows\s+service)", value):
        expansions.append("Service Execution Windows Service Create or Modify System Process remote services")
    if re.search(r"\b(?:event\s+4624|logon\s+type\s+3|network\s+logon)", value):
        expansions.append("Valid Accounts Remote Services Windows logon session authentication")
    if re.search(r"\b(?:rdp|remote\s+desktop)", value):
        expansions.append("Remote Desktop Protocol T1021.001 lateral movement")
    if re.search(r"\b(?:wmi|windows\s+management\s+instrumentation)", value):
        expansions.append("Windows Management Instrumentation T1047 execution lateral movement")
    return expansions


def expand_query(query: str) -> list[str]:
    try:
        response = ollama.chat(
            model='llama3.1',
            messages=[{
                'role': 'user',
                'content': f"""
                 Generate 3 different search queries for this cybersecurity question.
                 Preserve any MITRE ATT&CK IDs exactly as written.
                 Return ONLY the queries, one per line, no numbering, no explanation.
                 Original query: {query}"""
            }]
        )
        expanded = response['message']['content'].strip().split('\n')
    except Exception:
        expanded = []

    original_ids = referenced_ids(query)
    deterministic = deterministic_query_expansions(query)
    queries = [query]
    seen = {query.lower()}
    for candidate in deterministic:
        if candidate.lower() not in seen:
            queries.append(candidate)
            seen.add(candidate.lower())
    for candidate in expanded:
        cleaned = clean_expanded_query(candidate)
        candidate_ids = referenced_ids(cleaned)
        if candidate_ids and not candidate_ids <= original_ids:
            continue
        if cleaned and cleaned.lower() not in seen:
            queries.append(cleaned)
            seen.add(cleaned.lower())

    return queries[:4]

def rrf_fusion(vector_results: list, bm25_results: list, exact_results: list | None = None,
               requested_types: set[str] | None = None, k: int=60) -> list[dict]:
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

    for rank, r in enumerate(exact_results or []):
        id_ = r['id']
        if id_ not in scores:
            scores[id_] = {'data': r, 'score': 0}
        scores[id_]['score'] += 1.0 / (rank + 1)

    requested_types = requested_types or set()
    if requested_types:
        for item in scores.values():
            if item['data'].get('type') in requested_types:
                item['score'] += 0.08
    
    ranked = sorted(scores.values(), key=lambda x: x['score'], reverse=True)
    fused = []
    for r in ranked:
        item = dict(r['data'])
        item['source_score'] = item.get('score')
        item['rrf_score'] = r['score']
        fused.append(item)
    return fused

def search(query: str, top_k: int = 10, driver=None) -> list[dict]:
    if not query.strip() or is_low_signal_query(query):
        return []

    owns_driver = driver is None
    if owns_driver:
        driver = get_driver()
    try:
        queries = expand_query(query)
        requested_types = infer_node_types(query)
        retrieval_k = max(top_k * 3, 20)

        all_vector, all_bm25 = [], []
        for q in queries:
            all_vector.extend(vector_search(driver, q, k=retrieval_k))
            all_bm25.extend(bm25_search(driver, q, k=retrieval_k))

        exact_results = (
            exact_id_search(driver, query)
            + exact_name_search(driver, query)
            + fuzzy_entity_search(driver, query)
        )
        fused = rrf_fusion(
            all_vector,
            all_bm25,
            exact_results=exact_results,
            requested_types=requested_types
        )
        filtered = [
            node for node in fused
            if not is_partial_entity_reference_match(query, node)
        ]
        return filtered[:top_k]
    finally:
        if owns_driver:
            driver.close()

if __name__ == "__main__":
    results = search("credential theft using stolen passwords")
    print("=== Search Results ===")
    for r in results:
        print(f"[{r['type']}] {r['name']} ({r['external_id']})")
