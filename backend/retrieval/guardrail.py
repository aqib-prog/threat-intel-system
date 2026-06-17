import re
import ollama
import json

from neo4j import GraphDatabase
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from rapidfuzz import process, fuzz


def get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


# Global fuzzy index
FUZZY_INDEX = {}
TACTIC_CONTEXT_INDEX = {}
GENERIC_ENTITY_CATEGORY_WORDS = set()
ENTITY_FIELDS = {
    "threat_actor", "malware", "tool", "campaign", "tactic",
    "platform", "node_type", "analytic", "detection_strategy",
    "data_component"
}

MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact"
]

STOPWORD_CANDIDATES = {
    "show", "what", "which", "tell", "give", "list", "does", "did", "use",
    "uses", "used", "using", "for", "from", "with", "about", "the", "and",
    "or", "me", "all", "are", "is", "in", "on", "of", "to", "run", "runs",
    "ran", "tool", "tools", "malware", "actor", "actors", "campaign",
    "campaigns", "operation", "operations", "technique", "techniques",
    "tactic", "tactics", "access", "bear", "spider", "panda", "kitten",
    "typhoon", "blizzard", "tempest", "tiger", "dragon", "windows",
    "macos", "linux", "android", "ios", "esxi", "iaas", "saas",
    "containers", "kubernetes"
}

STRUCTURAL_WORDS = {
    "tool", "tools", "malware", "actor", "actors", "campaign", "campaigns",
    "operation", "operations", "technique", "techniques", "tactic",
    "tactics", "platform", "platforms"
}

NAMED_ENTITY_FIELDS = {
    "threat_actor", "malware", "tool", "campaign"
}


def build_fuzzy_index(driver):
    global FUZZY_INDEX, TACTIC_CONTEXT_INDEX
    with driver.session() as session:

        # Actors + aliases
        actors = session.run(
            "MATCH (a:Actor) RETURN a.name as name, a.aliases as aliases")
        actor_names = {}
        for r in actors:
            actor_names[r["name"]] = r["name"]
            for alias in (r["aliases"] or []):
                actor_names[alias] = r["name"]  # alias->real name
        FUZZY_INDEX["threat_actor"] = actor_names

        # Malware + aliases
        malwares = session.run(
            "MATCH (m:Malware) RETURN m.name as name, m.aliases as aliases")
        malware_names = {}
        for r in malwares:
            malware_names[r["name"]] = r["name"]
            for alias in (r["aliases"] or []):
                malware_names[alias] = r["name"]
        FUZZY_INDEX["malware"] = malware_names

        # Tools + aliases
        tools = session.run(
            "MATCH (t:Tool) RETURN t.name as name, t.aliases as aliases")
        tool_names = {}
        for r in tools:
            tool_names[r["name"]] = r["name"]
            for alias in (r["aliases"] or []):
                tool_names[alias] = r["name"]
        FUZZY_INDEX["tool"] = tool_names

        # Campaigns
        campaigns = session.run("MATCH (c:Campaign) RETURN c.name as name")
        FUZZY_INDEX["campaign"] = {r["name"]: r["name"] for r in campaigns}

        # Tactics
        tactics = session.run(
            "MATCH (t:Tactic) RETURN t.name as name, t.shortname as shortname, t.description as description")
        tactic_names = {}
        for r in tactics:
            tactic_names[r["name"]] = r["name"]
            if r["shortname"]:
                tactic_names[r["shortname"]] = r["name"]
            TACTIC_CONTEXT_INDEX[r["name"]] = {
                "shortname": r["shortname"],
                "description": r["description"] or ""
            }
        FUZZY_INDEX["tactic"] = tactic_names

    print(f"Fuzzy index built ")
    print(f"  Actors: {len(FUZZY_INDEX['threat_actor'])}")
    print(f"  Malware: {len(FUZZY_INDEX['malware'])}")
    print(f"  Tools: {len(FUZZY_INDEX['tool'])}")
    print(f"  Campaigns: {len(FUZZY_INDEX['campaign'])}")
    print(f"  Tactics: {len(FUZZY_INDEX['tactic'])}")


GLOBAL_INDEX = {}


def build_global_index(driver):
    global GLOBAL_INDEX, TACTIC_CONTEXT_INDEX, GENERIC_ENTITY_CATEGORY_WORDS
    GLOBAL_INDEX = {}
    TACTIC_CONTEXT_INDEX = {}
    category_contexts = []
    with driver.session() as session:

        # Actors + aliases
        actors = session.run(
            "MATCH (a:Actor) RETURN a.name as name, a.aliases as aliases, a.description as description")
        for r in actors:
            GLOBAL_INDEX[r["name"].lower()] = {
                "real_name": r["name"], "type": "threat_actor"}
            for alias in (r["aliases"] or []):
                GLOBAL_INDEX[alias.lower()] = {
                    "real_name": r["name"], "type": "threat_actor"}
            category_contexts.append({
                "names": [r["name"], *(r["aliases"] or [])],
                "description": r["description"] or ""
            })

        # Malware + aliases
        malwares = session.run(
            "MATCH (m:Malware) RETURN m.name as name, m.aliases as aliases, m.description as description")
        for r in malwares:
            GLOBAL_INDEX[r["name"].lower()] = {
                "real_name": r["name"], "type": "malware"}
            for alias in (r["aliases"] or []):
                GLOBAL_INDEX[alias.lower()] = {
                    "real_name": r["name"], "type": "malware"}
            category_contexts.append({
                "names": [r["name"], *(r["aliases"] or [])],
                "description": r["description"] or ""
            })

        # Tools + aliases
        tools = session.run(
            "MATCH (t:Tool) RETURN t.name as name, t.aliases as aliases, t.description as description")
        for r in tools:
            GLOBAL_INDEX[r["name"].lower()] = {
                "real_name": r["name"], "type": "tool"}
            for alias in (r["aliases"] or []):
                GLOBAL_INDEX[alias.lower()] = {
                    "real_name": r["name"], "type": "tool"}
            category_contexts.append({
                "names": [r["name"], *(r["aliases"] or [])],
                "description": r["description"] or ""
            })

        # Campaigns
        campaigns = session.run(
            "MATCH (c:Campaign) RETURN c.name as name, c.description as description")
        for r in campaigns:
            GLOBAL_INDEX[r["name"].lower()] = {
                "real_name": r["name"], "type": "campaign"}
            category_contexts.append({
                "names": [r["name"]],
                "description": r["description"] or ""
            })

        # Tactics
        tactics = session.run(
            "MATCH (t:Tactic) RETURN t.name as name, t.shortname as shortname, t.description as description")
        for r in tactics:
            GLOBAL_INDEX[r["name"].lower()] = {
                "real_name": r["name"], "type": "tactic"}
            if r["shortname"]:
                GLOBAL_INDEX[r["shortname"].lower()] = {
                    "real_name": r["name"], "type": "tactic"}
            TACTIC_CONTEXT_INDEX[r["name"]] = {
                "shortname": r["shortname"],
                "description": r["description"] or ""
            }

    GENERIC_ENTITY_CATEGORY_WORDS = build_generic_entity_category_words(
        category_contexts)
    print(f"Global index built: {len(GLOBAL_INDEX)} entries ")


def ensure_entity_indexes(driver):
    if not FUZZY_INDEX:
        build_fuzzy_index(driver)
    if not GLOBAL_INDEX:
        build_global_index(driver)


def query_ngrams(query: str, max_words: int = 4) -> list[str]:
    tokens = re.findall(r'\b\w+\b', query.lower())
    candidates = []
    for n in range(1, max_words + 1):
        for i in range(len(tokens) - n + 1):
            candidate = " ".join(tokens[i:i + n]).strip()
            if candidate:
                candidates.append(candidate)
    return candidates


def is_matchable_candidate(candidate: str) -> bool:
    if len(candidate) < 4:
        return False
    if candidate in STOPWORD_CANDIDATES:
        return False
    if re.match(r'^[gmstc]a?\d{4}', candidate, re.IGNORECASE):
        return False
    return True


def is_global_entity_candidate(candidate: str) -> bool:
    if not is_matchable_candidate(candidate):
        return False

    if candidate.lower().strip() in GLOBAL_INDEX:
        return True

    tokens = candidate.split()
    content_tokens = {
        token for token in tokens
        if token not in STOPWORD_CANDIDATES
        and token not in STRUCTURAL_WORDS
    }
    if content_tokens and content_tokens <= GENERIC_ENTITY_CATEGORY_WORDS:
        return False
    if any(token in STRUCTURAL_WORDS for token in tokens):
        return False
    if tokens[0] in STOPWORD_CANDIDATES:
        return False
    return True


def has_reasonable_length(candidate: str, matched_key: str) -> bool:
    candidate_len = max(len(candidate.replace(" ", "")), 1)
    matched_len = max(len(matched_key.replace(" ", "")), 1)
    return matched_len / candidate_len >= 0.65


def compact_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def token_set(value: str) -> set[str]:
    return set(re.findall(r"\b[a-z0-9]{3,}\b", value.lower()))


def token_list(value: str) -> list[str]:
    return re.findall(r"\b[a-z0-9]{3,}\b", value.lower())


def content_token_set(value: str) -> set[str]:
    return {
        token for token in token_set(value)
        if token not in STOPWORD_CANDIDATES
        and token not in STRUCTURAL_WORDS
    }


def is_generic_entity_category_value(value: str) -> bool:
    if value.lower().strip() in GLOBAL_INDEX:
        return False

    tokens = content_token_set(value)
    return bool(tokens) and tokens <= GENERIC_ENTITY_CATEGORY_WORDS


def descriptor_category_tokens(description: str) -> set[str]:
    categories = set()
    text = re.sub(r"\[[^\]]+\]\([^)]+\)", " ", description.lower())

    for match in re.finditer(
        r"\b(?:is|are|was|were)\s+(?:an?|the)\s+([^.;:\n]{1,120})",
        text
    ):
        phrase = re.split(
            r"\b(?:that|which|used|uses|leveraged|designed|known|written|"
            r"developed|created|observed|reported|associated|targeting|by|"
            r"for|with|to|and|or)\b|,|\(",
            match.group(1),
            maxsplit=1
        )[0]
        tokens = [
            token for token in token_list(phrase)
            if token not in STOPWORD_CANDIDATES
            and token not in STRUCTURAL_WORDS
        ]
        if tokens:
            categories.add(tokens[-1])

    return categories


def build_generic_entity_category_words(entity_contexts: list[dict]) -> set[str]:
    document_frequency = {}
    suffix_frequency = {}
    descriptor_frequency = {}

    for context in entity_contexts:
        name_tokens = set()
        for name in context["names"]:
            tokens = [
                token for token in token_list(name)
                if token not in STOPWORD_CANDIDATES
                and token not in STRUCTURAL_WORDS
            ]
            name_tokens.update(tokens)
            if len(tokens) > 1:
                suffix = tokens[-1]
                suffix_frequency[suffix] = suffix_frequency.get(suffix, 0) + 1

        for token in name_tokens:
            document_frequency[token] = document_frequency.get(token, 0) + 1

        for token in descriptor_category_tokens(context["description"]):
            descriptor_frequency[token] = descriptor_frequency.get(token, 0) + 1

    category_words = set()
    for token, count in document_frequency.items():
        if count >= 4 or suffix_frequency.get(token, 0) >= 2:
            category_words.add(token)
    for token, count in descriptor_frequency.items():
        if count >= 2:
            category_words.add(token)

    return category_words


def is_single_token_false_extension(candidate: str, matched_key: str) -> bool:
    candidate_compact = compact_text(candidate)
    matched_compact = compact_text(matched_key)

    if not candidate_compact or not matched_compact:
        return True

    if " " in candidate.strip():
        return False

    if candidate_compact == matched_compact:
        return False

    # Reject ordinary words that only match because the entity adds a prefix,
    # suffix, digit, or one boundary character: "evil" -> "revil",
    # "group" -> "group5".
    if candidate_compact in matched_compact or matched_compact in candidate_compact:
        return True

    return False


def is_confident_entity_match(candidate: str, matched_key: str,
                              score: float,
                              allow_single_to_multi: bool = False) -> bool:
    if not has_reasonable_length(candidate, matched_key):
        return False

    candidate_tokens = candidate.split()
    matched_tokens = matched_key.split()

    if (
        len(candidate_tokens) == 1
        and not allow_single_to_multi
        and is_single_token_false_extension(candidate, matched_key)
    ):
        return False

    if (
        len(candidate_tokens) == 1
        and len(matched_tokens) > 1
        and not allow_single_to_multi
    ):
        return False

    if len(candidate_tokens) == 1:
        return score >= 86

    return score >= 82


def best_entity_match(candidate: str, choices, scorer, threshold: int,
                      allow_single_to_multi: bool = False):
    results = process.extract(
        candidate,
        choices,
        scorer=scorer,
        score_cutoff=threshold,
        limit=10
    )

    for matched_key, score, _ in results:
        if is_confident_entity_match(
            candidate,
            matched_key,
            score,
            allow_single_to_multi=allow_single_to_multi
        ):
            return matched_key, score

    return None


def extract_tactic_by_context(query: str, threshold: int = 2) -> dict:
    matches = {}
    query_tokens = content_token_set(query)

    if not query_tokens or not TACTIC_CONTEXT_INDEX:
        return matches

    tactic_tokens = {}
    token_document_frequency = {}
    for tactic_name, context in TACTIC_CONTEXT_INDEX.items():
        tokens = content_token_set(
            f"{tactic_name} {context.get('shortname') or ''} {context.get('description') or ''}"
        )
        tactic_tokens[tactic_name] = tokens
        for token in tokens:
            token_document_frequency[token] = token_document_frequency.get(token, 0) + 1

    max_document_frequency = max(2, len(TACTIC_CONTEXT_INDEX) // 4)
    query_tokens = {
        token for token in query_tokens
        if token_document_frequency.get(token, 0) <= max_document_frequency
    }
    if not query_tokens:
        return matches

    scored = []
    for tactic_name, context_tokens in tactic_tokens.items():
        overlap = query_tokens & context_tokens
        score = len(overlap)
        if score >= threshold:
            scored.append((score, tactic_name, overlap))

    if not scored:
        return matches

    scored.sort(reverse=True)
    best_score, best_tactic, overlap = scored[0]

    if len(scored) > 1 and best_score == scored[1][0]:
        return matches

    source_text = " ".join(
        token for token in re.findall(r"\b\w+\b", query.lower())
        if token in overlap
    )
    add_entity_match(matches, "tactic", best_tactic, source_text, best_score)
    return matches


def add_entity_match(matches: dict, entity_type: str, real_name: str,
                     source_text: str, score: float):
    if entity_type not in matches:
        matches[entity_type] = []

    for existing in matches[entity_type]:
        if existing["value"] == real_name:
            existing_source_len = len(existing["source_text"])
            source_len = len(source_text)
            if (
                score > existing["score"] + 2
                or (abs(score - existing["score"]) <= 2 and source_len < existing_source_len)
            ):
                existing["source_text"] = source_text
                existing["score"] = score
            return

    matches[entity_type].append({
        "value": real_name,
        "source_text": source_text,
        "score": score
    })


def extract_tactic_direct(query: str, threshold: int = 76) -> dict:
    matches = {}
    for candidate in query_ngrams(query, max_words=3):
        if not is_matchable_candidate(candidate):
            continue
        tokens = candidate.split()
        if tokens[0] in STOPWORD_CANDIDATES:
            continue

        result = best_entity_match(
            candidate,
            MITRE_TACTICS,
            scorer=fuzz.ratio,
            threshold=threshold
        )
        if result:
            real_name, score = result
            add_entity_match(matches, "tactic", real_name, candidate, score)

    return matches


def extract_campaign_indicators(query: str, threshold: int = 75) -> dict:
    matches = {}
    campaign_keys = [
        key for key, info in GLOBAL_INDEX.items()
        if info["type"] == "campaign"
    ]
    if not campaign_keys:
        return matches

    for regex_match in re.finditer(
        r"\b((?:\w+[\s-]+){0,3}\w+)\s+(?:campaign|campaigns|operation|operations)\b",
        query,
        re.IGNORECASE
    ):
        phrase = regex_match.group(1).lower().strip()
        words = phrase.split()
        suffixes = [" ".join(words[i:]) for i in range(len(words))]

        for candidate in suffixes:
            if not is_matchable_candidate(candidate):
                continue
            tokens = candidate.split()
            if tokens[0] in STOPWORD_CANDIDATES or tokens[-1] in STOPWORD_CANDIDATES:
                continue

            result = best_entity_match(
                candidate,
                campaign_keys,
                scorer=fuzz.WRatio,
                threshold=threshold,
                allow_single_to_multi=True
            )
            if not result:
                continue

            matched_key, score = result
            entity_info = GLOBAL_INDEX[matched_key]
            add_entity_match(
                matches,
                "campaign",
                entity_info["real_name"],
                candidate,
                score
            )
            break

    return matches


def extract_database_entity_hints(query: str, low_threshold: int = 82) -> dict:
    matches = extract_tactic_direct(query)
    tactic_context_matches = extract_tactic_by_context(query)
    for field, items in tactic_context_matches.items():
        for item in items:
            add_entity_match(
                matches,
                field,
                item["value"],
                item["source_text"],
                item["score"]
            )

    campaign_matches = extract_campaign_indicators(query)
    for field, items in campaign_matches.items():
        for item in items:
            add_entity_match(
                matches,
                field,
                item["value"],
                item["source_text"],
                item["score"]
            )
    if not GLOBAL_INDEX:
        return matches

    for candidate in query_ngrams(query, max_words=3):
        if not is_global_entity_candidate(candidate):
            continue

        result = best_entity_match(
            candidate,
            GLOBAL_INDEX.keys(),
            scorer=fuzz.ratio,
            threshold=low_threshold
        )

        if not result:
            continue

        matched_key, score = result
        entity_info = GLOBAL_INDEX[matched_key]
        real_name = entity_info["real_name"]
        entity_type = entity_info["type"]

        if len(real_name) < 4:
            continue

        add_entity_match(matches, entity_type, real_name, candidate, score)

    return matches


def entities_from_hints(hints: dict) -> dict:
    entities = {}
    for field, items in hints.items():
        values = []
        for item in items:
            value = item["value"]
            if value not in values:
                values.append(value)
        if values:
            entities[field] = values
    return entities


def format_database_hints(hints: dict) -> str:
    if not hints:
        return "None"

    hint_strings = []
    for entity_type, items in hints.items():
        values = [
            f"{item['value']} from '{item['source_text']}'"
            for item in items
        ]
        hint_strings.append(
            f"Potential {entity_type} mentioned: {', '.join(values)}"
        )
    return "\n".join(hint_strings)


def hint_supports_value(hints: dict, field: str, value: str,
                        source_text: str) -> bool:
    normalized_value = value.lower().strip()
    normalized_source = source_text.lower().strip()
    for item in hints.get(field, []):
        if (
            item["value"].lower() == normalized_value
            and item["source_text"].lower() == normalized_source
        ):
            return True
    return False


def source_supports_value(field: str, value: str, source_text: str,
                          query: str, hints: dict) -> bool:
    if not value or str(value).lower() == "null":
        return False

    source = str(source_text or "").strip()
    if not source:
        return False

    normalized_query = query.lower()
    normalized_source = source.lower()
    normalized_value = str(value).lower().strip()

    if normalized_source not in normalized_query:
        return False

    if hint_supports_value(hints, field, str(value), source):
        return True

    if field in NAMED_ENTITY_FIELDS and is_generic_entity_category_value(str(value)):
        return False

    if normalized_value in normalized_query:
        return True

    if field in NAMED_ENTITY_FIELDS:
        return False

    return fuzz.WRatio(normalized_source, normalized_value) >= 82


def normalize_llm_entity_output(raw_output: dict, query: str,
                                hints: dict) -> dict:
    normalized = {}

    for field, body in raw_output.items():
        if field == "is_subtechnique":
            if isinstance(body, bool):
                normalized[field] = body
            continue

        if field not in ENTITY_FIELDS:
            continue

        values = []

        if isinstance(body, list):
            items = body
        elif isinstance(body, dict):
            items = [body]
        elif isinstance(body, str):
            items = [{"value": body, "source_text": body}]
        else:
            items = []

        for item in items:
            if isinstance(item, dict):
                value = item.get("value") or item.get("extracted_value")
                source = item.get("source_text") or item.get(
                    "exact_query_substring")
            else:
                value = item
                source = item

            if isinstance(value, str) and "," in value:
                split_values = [v.strip()
                                for v in value.split(",") if v.strip()]
            else:
                split_values = [value]

            for split_value in split_values:
                if not isinstance(split_value, str):
                    continue
                if source_supports_value(field, split_value, source, query, hints):
                    if split_value not in values:
                        values.append(split_value)

        if values:
            normalized[field] = values

    return normalized


def generate_dynamic_hints(query: str, low_threshold: int = 82) -> str:
    hints = extract_database_entity_hints(query, low_threshold)
    return format_database_hints(hints)


def generate_dynamic_hint_entities(query: str, low_threshold: int = 82) -> dict:
    return extract_database_entity_hints(query, low_threshold)


def generate_legacy_dynamic_hints(query: str, low_threshold: int = 65) -> str:
    tokens = re.findall(r'\b\w+\b', query.lower())

    # Generate 1, 2, 3 word combinations
    candidates = []
    for n in range(1, 4):
        for i in range(len(tokens) - n + 1):
            candidates.append(" ".join(tokens[i:i+n]))

    hints = {}
    for candidate in candidates:
        if len(candidate) < 4:
            continue
        if re.match(r'^[gmstc]a?\d{4}', candidate):
            continue

        result = process.extractOne(
            candidate,
            GLOBAL_INDEX.keys(),
            scorer=fuzz.ratio,
            score_cutoff=low_threshold
        )

        if result:
            matched_key = result[0]
            score = result[1]
            entity_info = GLOBAL_INDEX[matched_key]
            real_name = entity_info["real_name"]
            entity_type = entity_info["type"]

            # Verify not too short
            if len(real_name) < 4:
                continue

            if entity_type not in hints:
                hints[entity_type] = set()
            hints[entity_type].add(real_name)

    if not hints:
        return "None"

    hint_strings = []
    for e_type, names in hints.items():
        hint_strings.append(f"Potential {e_type}: {', '.join(names)}")

    return "\n".join(hint_strings)


def fuzzy_match(field: str, value: str, threshold: int = 85, query: str = "") -> str | None:
    if field not in FUZZY_INDEX:
        return None

    # Skip short values
    if len(value.strip()) < 4:
        return None

    # Skip very long values (whole sentences from LLM)
    if len(value.strip()) > 50:
        return None

    # Skip MITRE IDs — regex handles those
    if re.match(r'^[GMSTC]A?\d{4}', value, re.IGNORECASE):
        return None

    index = FUZZY_INDEX[field]
    normalized_index = {str(key).lower(): key for key in index.keys()}

    # Use strict ratio for short inputs, WRatio for longer ones
    scorer = fuzz.ratio if len(value) < 15 else fuzz.WRatio

    result = process.extractOne(
        value.lower(),
        normalized_index.keys(),
        scorer=scorer,
        score_cutoff=threshold
    )

    if result:
        matched_key = normalized_index[result[0]]
        score = result[1]
        real_name = index[matched_key]

        # Reject if matched result is too short compared to input
        length_ratio = len(real_name) / max(len(value), 1)
        if length_ratio < 0.5:
            print(
                f"Rejected: '{value}' → '{real_name}' length ratio too low ({length_ratio:.2f})")
            return None

        # Verify value is contextually related to query
        if query:
            query_relevance = fuzz.partial_ratio(value.lower(), query.lower())
            if query_relevance < 60:
                print(
                    f"Rejected: '{value}' not relevant to query (score: {query_relevance})")
                return None

        print(f"Fuzzy match: '{value}' → '{real_name}' (score: {score:.1f})")
        return real_name

    return None


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
        r"\b(techniques?|actors?|malwares?|tools?|mitigations?|tactics?|campaigns?|analytics?|detection\s+strateg(?:y|ies)|data\s+components?)\b",
        re.IGNORECASE
    )
}

NODE_TYPE_MAP = {
    "technique": "Technique",
    "techniques": "Technique",
    "actor": "Actor",
    "actors": "Actor",
    "malware": "Malware",
    "malwares": "Malware",
    "tool": "Tool",
    "tools": "Tool",
    "mitigation": "Mitigation",
    "mitigations": "Mitigation",
    "tactic": "Tactic",
    "tactics": "Tactic",
    "campaign": "Campaign",
    "campaigns": "Campaign",
    "analytic": "Analytic",
    "analytics": "Analytic",
    "detection strategy": "DetectionStrategy",
    "detection strategies": "DetectionStrategy",
    "data component": "DataComponent",
    "data components": "DataComponent"
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


def extract_entities_llm(query: str, regex_entities: dict,
                         database_hints: dict | None = None) -> dict:
    database_hints = database_hints or {}
    database_hint_text = format_database_hints(database_hints)
    response = ollama.chat(
        model='llama3.1',
        messages=[{
            'role': 'user',
            'content': f"""You are a cybersecurity entity extractor for a MITRE ATT&CK threat intelligence system.
Extract and normalize ALL entities from this query. Also validate and correct the regex-extracted entities provided.

Query: {query}

Regex already extracted (may have typos or be incomplete):
{json.dumps(regex_entities, indent=2)}

Verified database clues from deterministic fuzzy matching:
{database_hint_text}

Instructions:
- Fix any typos in regex results (e.g. "Lazarous Group" → "Lazarus Group")
- Extract ALL entities explicitly mentioned in query
- If a query term strongly resembles a verified database clue, use the corrected database value
- Campaign means a named cyber operation, intrusion wave, or compromise, e.g. in "SolarWinds campaign" extract the campaign
- If multiple entities are mentioned, return multiple objects in that field's list
- NEVER add mitre_id or cve_id - regex handles those exclusively
- NEVER add entities not explicitly mentioned in query
- NEVER add threat actors, malware or tools not explicitly named in query
- Only fix typos of explicitly mentioned entities
- Every extracted entity MUST include source_text copied exactly from the user's query
- Set fields to [] if not mentioned in query

Respond ONLY with valid JSON, no explanation:
{{
    "threat_actor": [{{"value": "corrected actor name", "source_text": "exact query substring"}}],
    "platform": [{{"value": "Windows/Linux/macOS/etc", "source_text": "exact query substring"}}],
    "node_type": [{{"value": "Technique/Actor/Malware/Tool/Mitigation/Tactic/Campaign/Analytic/DetectionStrategy/DataComponent", "source_text": "exact query substring"}}],
    "malware": [{{"value": "corrected malware name", "source_text": "exact query substring"}}],
    "tool": [{{"value": "corrected tool name", "source_text": "exact query substring"}}],
    "campaign": [{{"value": "corrected campaign name", "source_text": "exact query substring"}}],
    "tactic": [{{"value": "corrected tactic name", "source_text": "exact query substring"}}],
    "is_subtechnique": true/false/null
}}"""
        }]
    )
    try:
        raw = response['message']['content'].strip()
        # clean any markdown
        raw = raw.replace('```json', '').replace('```', '').strip()
        extracted = json.loads(raw)
        return normalize_llm_entity_output(extracted, query, database_hints)
    except:
        return {}


def validate_against_graph(field: str, value: str, driver, query: str = "") -> str | None:
    if not value or len(value.strip()) < 3:
        return None

    if field in NAMED_ENTITY_FIELDS and is_generic_entity_category_value(value):
        return None

    # Use fuzzy matching for name-based fields
    if field in FUZZY_INDEX:
        result = fuzzy_match(field, value, query=query)
        if result:
            return result

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
            if not re.match(r'^CVE-\d{4}-\d{4,7}$', value, re.IGNORECASE):
                return None
            result = session.run("""
        MATCH (n:MitreNode)
        WHERE toLower(n.description) CONTAINS toLower($value)
        RETURN n.name LIMIT 1
    """, value=value)
            record = result.single()
            return value.upper() if record else None
    return None


def validate_and_correct_field(field: str, value: str, driver, query: str = "") -> tuple | None:
    result = validate_against_graph(field, value, driver, query)
    if result:
        return field, result

    all_fields = ["threat_actor", "malware", "tool", "campaign",
                  "tactic", "mitre_id", "analytic",
                  "detection_strategy", "data_component", "cve_id"]

    for fallback in all_fields:
        if fallback == field:
            continue
        result = validate_against_graph(fallback, value, driver, query)
        if result:
            print(f"Corrected: '{value}' moved from '{field}' to '{fallback}'")
            return fallback, result

    return None


def validate_all_entities(entities: dict, driver, query: str = "") -> dict:
    validated = {}

    for field, values in entities.items():
        if not values:
            continue

        if field == "is_subtechnique":
            if isinstance(values, bool):
                validated[field] = values
            continue

        if isinstance(values, list):
            for value in values:
                if not isinstance(value, str):
                    continue
                result = validate_and_correct_field(
                    field, value, driver, query)
                if result:
                    correct_field, correct_value = result
                    if correct_field not in validated:
                        validated[correct_field] = []
                    if correct_value not in validated[correct_field]:
                        validated[correct_field].append(correct_value)
        else:
            if not isinstance(values, str):
                continue
            result = validate_and_correct_field(field, values, driver, query)
            if result:
                correct_field, correct_value = result
                validated[correct_field] = [correct_value]

    return validated


def extract_filters(query: str, driver) -> dict:
    ensure_entity_indexes(driver)
    regex_entities = extract_entities_regex(query)
    database_hints = generate_dynamic_hint_entities(query)
    deterministic_entities = entities_from_hints(database_hints)
    seeded_regex_entities = dict(regex_entities)

    for k, values in deterministic_entities.items():
        if k not in seeded_regex_entities:
            seeded_regex_entities[k] = list(values)
            continue
        existing = seeded_regex_entities[k]
        if not isinstance(existing, list):
            existing = [existing]
        for value in values:
            if value not in existing:
                existing.append(value)
        seeded_regex_entities[k] = existing

    llm_entities = extract_entities_llm(
        query, seeded_regex_entities, database_hints)

    merged = {}
    for k, v in seeded_regex_entities.items():
        merged[k] = v if isinstance(v, list) else [v]

    for k, v in llm_entities.items():
        if not v:
            continue
        if isinstance(v, str) and ',' in v:
            values = [x.strip() for x in v.split(',')]
        elif isinstance(v, list):
            values = v
        else:
            values = [v]

        if k not in merged:
            merged[k] = values
        else:
            for val in values:
                if val not in merged[k]:
                    merged[k].append(val)

    # Pass query for context validation
    validated = validate_all_entities(merged, driver, query)
    return validated


if __name__ == "__main__":
    driver = get_driver()
    build_fuzzy_index(driver)

    full_tests = [
        # Normal queries
        "What techniques does Lazarus Group use on Windows?",
        "Show me mitigations for lateral movement tactic",
        "What malware does Cozy Bear use?",
        "Tell me about T1078 on Linux",
        "What tools does APT29 use in SolarWinds campaign?",
        "Show me Mimikatz tool techniques",
        # Typo tests
        "What techniques does Lazarous Group use on Windwos?",
        "Show me Mimikats tool on macOS",
        "What does APt 29 do in lateral movment tactic?",
        "Tell me about t1078 technique on lnux",
        "What campains did Scatterd Spider run?",
        "Show me techniqes for credentail access",
        # Misplaced field tests
        "Show me APT29 malware",
        "What is Mimikatz actor doing?",
        # Multiple entities
        "What techniques do APT29 and Lazarus Group use on Windows and Linux?",
        "Show me T1078 and T1053 mitigations",
        # Alias tests
        "What does Cozy Bear do?",
        "What does Evil Corp use?",
        # ID based
        "Tell me about TA0006",
        "What is G0016?",
        "Show me S0039",
        # Vague queries
        "What is lateral movement?",
        "How do attackers steal credentials?",
        "What is ransomware?",
        # Empty/irrelevant
        "Hello",
        "What can you do?",
        # Subtechnique
        "Show me subtechniques of T1078",
        "What are parent techniques for T1078.001?",
        # Random/fake values
        "What does FakeAPT999 do?",
        "Tell me about T9999 technique",
        "Show me XYZMalware on Windows",
        "What is operation FakeOperation123?",
        "Tell me about CVE-9999-9999",
        "What does RandomGroup use?",
        "Show me techniques for FakeTactic",
        # Additional fuzzy tests
        "What does Lazarous Group do on Windwos?",
        "Show me Cobalt Strke malware",
        "What is latral movment tactic?",
        "What does Evl Corp use?",
        "Show me techniqes used by Scatterd Spider",
        "What campains did Lazrus Group run?",
    ]

    print("=== Full Filter Extraction Tests ===\n")
    for q in full_tests:
        filters = extract_filters(q, driver)
        print(f"Query: {q}")
        print(f"Filters: {filters}\n")

    driver.close()
