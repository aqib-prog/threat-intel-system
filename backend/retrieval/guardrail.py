import re
import ollama
import json

import re

from neo4j import GraphDatabase
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

def get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


OFF_TOPIC_BLACKLIST = {
    # Strictly limits keywords to pure consumer/lifestyle terms with zero dual-use in a SOC
    "clearly_offtopic": re.compile(
        r"\b(?:"
        r"recipe\s+for\s+(?:pasta|chicken|cake|lasagna|pizza|soup|cookies)|"
        r"horoscope\s+today|dating\s+advice|relationship\s+problems|"
        r"restaurant\s+near\s+me|best\s+places\s+to\s+eat|"
        r"movie\s+recommendations?|what\s+to\s+watch\s+on\s+netflix|"
        r"discount\s+codes?|coupon\s+for"
        r")\b",
        re.IGNORECASE
    ),
    # Catches explicit structural bypasses without restricting standard security queries
    "jailbreak": re.compile(
        r"(?:"
        r"\b(?:ignore|1gn0r3)\s+(?:all\s+)?(?:rules|instructions|guidelines)\b|"
        r"\bforget\s+(?:all\s+)?(?:rules|instructions)\b|"
        r"\bj[a4][i1]lb[r]?[e3][a4]k\b|"
        r"\bdan\s+mode\b|"
        r"ignore[-\s]+all[-\s]+instructions|"
        r"\bunjailbreak\b"
        r")",
        re.IGNORECASE
    )
}


FALLBACK_MESSAGES = {
    "clearly_offtopic": "I'm a cybersecurity assistant focused on threat intelligence and MITRE ATT&CK. I can't help with general topics.",
    "jailbreak": "This request has been blocked. I only assist with cybersecurity analysis."
}


def check_blacklist(query: str) -> dict:
    for category, pattern in OFF_TOPIC_BLACKLIST.items():
        if pattern.search(query):
            return {
                "allowed": False,
                "category": category,
                "message": FALLBACK_MESSAGES[category]
            }
    return {"allowed": True}


def check_llm_guardrail(query: str) -> dict:
    response = ollama.chat(
        model='llama3.1',
        messages=[{
            'role': 'user',
            'content': f"""You are a guardrail for a cybersecurity threat intelligence system.

Your ONLY job is to block queries that have ABSOLUTELY ZERO connection to cybersecurity.

ALWAYS ALLOW if there is even the slightest cybersecurity connection.
When in doubt -> ALWAYS ALLOW.

Only block these obvious cases:
- Pure food/cooking requests ("recipe for pasta", "how to cook chicken")
- Pure entertainment ("recommend me a movie", "who won the game")
- Pure personal life ("dating advice", "relationship problems")
- Pure shopping ("best phone to buy", "discount codes")

Everything else -> ALLOW

Query: {query}

Respond ONLY with valid JSON:
{{"allowed": true/false, "reason": "one line reason"}}"""
        }]
    )
    try:
        return json.loads(response['message']['content'].strip())
    except:
        return {"allowed": True, "reason": "Could not parse, allowing by default"}


def guardrail(query: str) -> dict:
    # Layer 1 - blacklist
    blacklist_result = check_blacklist(query)
    if not blacklist_result["allowed"]:
        return blacklist_result

    # Layer 2 - LLM
    llm_result = check_llm_guardrail(query)
    if not llm_result["allowed"]:
        return {
            "allowed": False,
            "category": "llm_blocked",
            "message": f"I'm a cybersecurity assistant. I can't help with that. {llm_result['reason']}"
        }

    return {"allowed": True}


# Extract Filter
CYBER_ENTITY_REGEX = {
    "mitre_id": re.compile(
        r"\b([GMSTC]A?\d{4}(?:\.\d{3})?)\b", re.IGNORECASE
    ),
    "cve_id": re.compile(
        r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE
    ),
    "threat_actor": re.compile(
        r"\b(APT\s*\d+|UNC\s*\d+|G\d{4}|(?:[A-Z][a-z]+\s+(?:Bear|Spider|Typhoon|Panda|Kitten|Blizzard|Tempest|Tiger|Dragon)))\b"
    ),
    "platform": re.compile(
        r"\b(Windows|macOS|Linux|Containers|Kubernetes|IaaS|SaaS|Android|iOS|ESXi)\b",
        re.IGNORECASE
    ),
    "node_type": re.compile(
        r"\b(technique|actor|malware|tool|mitigation|tactic|campaign|analytic|detection\s+strategy|data\s+component)\b",
        re.IGNORECASE
    )
}

NODE_TYPE_MAP = {
    "technique": "Technique",
    "actor": "Actor",
    "malware": "Malware",
    "tool": "Tool",
    "mitigation": "Mitigation",
    "tactic": "Tactic",
    "campaign": "Campaign",
    "analytic": "Analytic",
    "detection strategy": "DetectionStrategy",
    "data component": "DataComponent"
}


def extract_entities_regex(query: str) -> dict:
    extracted = {}
    for entity_type, pattern in CYBER_ENTITY_REGEX.items():
        matches = list(set(pattern.findall(query)))
        if matches:
            if entity_type == "node_type":
                extracted[entity_type] = [
                NODE_TYPE_MAP.get(m.lower(), m) for m in matches]
            else:
                extracted[entity_type] = matches

    return extracted

def validate_against_graph(field: str, value: str, driver) -> str | None:
    with driver.session() as session:

        if field == "threat_actor":
            result = session.run("""
                MATCH (a:Actor)
                WHERE toLower(a.name) CONTAINS toLower($value)
                OR ANY(alias IN a.aliases WHERE toLower(alias) CONTAINS toLower($value))
                RETURN a.name LIMIT 1
            """, value=value)
            record = result.single()
            return record["a.name"] if record else None

        elif field == "platform":
            result = session.run("""
                MATCH (n:MitreNode)
                WHERE ANY(p IN n.platforms WHERE toLower(p) CONTAINS toLower($value))
                RETURN n.platforms LIMIT 1
            """, value=value)
            record = result.single()
            if record:
                for p in record["n.platforms"]:
                    if value.lower() in p.lower():
                        return p
            return None

        elif field == "node_type":
            valid_types = ["Technique", "Actor", "Malware", "Tool", "Mitigation",
                           "Tactic", "Campaign", "Analytic", "DetectionStrategy", "DataComponent"]
            for t in valid_types:
                if t.lower() == value.lower():
                    return t
            return None

        elif field == "mitre_id":
            result = session.run("""
                MATCH (n:MitreNode)
                WHERE n.external_id = $value
                RETURN n.external_id LIMIT 1
            """, value=value.upper())
            record = result.single()
            return record["n.external_id"] if record else None

        elif field == "malware":
            result = session.run("""
                MATCH (m:Malware)
                WHERE toLower(m.name) CONTAINS toLower($value)
                OR ANY(alias IN m.aliases WHERE toLower(alias) CONTAINS toLower($value))
                RETURN m.name LIMIT 1
            """, value=value)
            record = result.single()
            return record["m.name"] if record else None

        elif field == "tool":
            result = session.run("""
                MATCH (t:Tool)
                WHERE toLower(t.name) CONTAINS toLower($value)
                OR ANY(alias IN t.aliases WHERE toLower(alias) CONTAINS toLower($value))
                RETURN t.name LIMIT 1
            """, value=value)
            record = result.single()
            return record["t.name"] if record else None

        elif field == "campaign":
            result = session.run("""
                MATCH (c:Campaign)
                WHERE toLower(c.name) CONTAINS toLower($value)
                OR toLower(c.description) CONTAINS toLower($value)
                RETURN c.name LIMIT 1
            """, value=value)
            record = result.single()
            return record["c.name"] if record else None

        elif field == "tactic":
            result = session.run("""
                MATCH (t:Tactic)
                WHERE toLower(t.name) CONTAINS toLower($value)
                OR toLower(t.shortname) CONTAINS toLower($value)
                RETURN t.name LIMIT 1
            """, value=value)
            record = result.single()
            return record["t.name"] if record else None

        elif field == "analytic":
            result = session.run("""
                MATCH (a:Analytic)
                WHERE toLower(a.name) CONTAINS toLower($value)
                OR a.external_id = $value
                RETURN a.name LIMIT 1
            """, value=value)
            record = result.single()
            return record["a.name"] if record else None

        elif field == "detection_strategy":
            result = session.run("""
                MATCH (ds:DetectionStrategy)
                WHERE toLower(ds.name) CONTAINS toLower($value)
                OR ds.external_id = $value
                RETURN ds.name LIMIT 1
            """, value=value)
            record = result.single()
            return record["ds.name"] if record else None

        elif field == "data_component":
            result = session.run("""
                MATCH (dc:DataComponent)
                WHERE toLower(dc.name) CONTAINS toLower($value)
                OR dc.external_id = $value
                RETURN dc.name LIMIT 1
            """, value=value)
            record = result.single()
            return record["dc.name"] if record else None

        elif field == "cve_id":
            result = session.run("""
                MATCH (n:MitreNode)
                WHERE toLower(n.description) CONTAINS toLower($value)
                RETURN n.name, n.external_id LIMIT 1
            """, value=value)
            record = result.single()
            return value.upper() if record else None

    return None

def validate_and_correct_field(field:str,value:str,driver)->tuple | None:
    result = validate_against_graph(field, value, driver)
    if result:
        return field, result
    
    # If fields are misplaced 
    all_fields = ["threat_actor", "malware", "tool", "campaign",
                  "tactic", "mitre_id", "analytic",
                  "detection_strategy", "data_component", "cve_id"]
    
    for fallback in all_fields:
        if fallback == field:
            continue
        result = validate_against_graph(fallback, value, driver)
        if result:
            print(f"Corrected: '{value}' moved from '{field}' to '{fallback}'")
            return fallback, result
        
    # If no valid field is found
    return None

def validate_all_entities(entities: dict, driver)-> dict:
    validated = {}
    for field, values in entities.items():
        if not values:
            continue
        if isinstance(values,list):
            for value in values:
                result = validate_and_correct_field(field, value, driver)
                if result:
                    correct_field, correct_value = result
                    if correct_field not in validated:
                        validated[correct_field] = []
                    if correct_value not in validated[correct_field]:
                        validated[correct_field].append(correct_value)
        else:
            result = validate_and_correct_field(field, values, driver)
            if result:
                correct_field, correct_value = result
                validated[correct_field] = [correct_value]

    return validated

if __name__ == "__main__":
    print("\n=== Graph Validation Tests ===\n")
    driver = get_driver()
    validation_tests = [
    ("threat_actor", "APT29"),
    ("threat_actor", "Cozy Bear"),
    ("threat_actor", "Mimikatz"),      # misplaced - should move to tool
    ("tool", "APT29"),                 # misplaced - should move to threat_actor
    ("threat_actor", "Lazarous Group"), # typo
    ("malware", "mimikats"),            # typo
    ("threat_actor", "FakeActor123"),   # not in graph
    ("mitre_id", "T9999"),             # not in graph
    ("mitre_id", "T1078"),             # valid
    ("platform", "Windows"),           # valid
    ("platform", "widndows"),          # typo - should fail
    ("tactic", "credential-access"),   # valid
    ("cve_id", "CVE-2024-1234"),       # check if referenced in graph
    ("data_component", "DC0084"),      # valid
    ("detection_strategy", "DET0237"), # valid
    ("analytic", "AN0110"),            # valid
]

    for field, value in validation_tests:
        result = validate_and_correct_field(field, value, driver)
        if result:
            correct_field, correct_value = result
            if correct_field == field:
                print(f" Valid -> {field}: '{correct_value}'")
            else:
                print(f" Corrected -> '{field}' to '{correct_field}': '{correct_value}'")
        else:
            print(f" Not found -> {field}: '{value}' -> null")
    driver.close()

    # Test validate_all_entities with mixed data
print("\n=== validate_all_entities Tests ===\n")

test_entities = [
    # Clean valid entities
    {"threat_actor": ["APT29"], "platform": ["Windows"], "node_type": ["Technique"]},
    # Mixed valid and invalid
    {"threat_actor": ["APT29", "FakeActor123"], "platform": ["Windows", "widndows"]},
    # Misplaced fields
    {"threat_actor": ["Mimikatz", "APT29"], "tool": ["Cozy Bear"]},
    # Empty lists
    {"mitre_id": [], "threat_actor": ["APT29"], "platform": []},
    # All invalid
    {"threat_actor": ["FakeActor123"], "mitre_id": ["T9999"]},
]

driver = get_driver()
for i, entities in enumerate(test_entities):
    print(f"Input {i+1}: {entities}")
    result = validate_all_entities(entities, driver)
    print(f"Output {i+1}: {result}\n")
driver.close()



            

