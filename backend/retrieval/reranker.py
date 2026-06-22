import json
import os
import re
import sys
from typing import Any

import ollama

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


MITRE_ID_RE = re.compile(r"\b[GMSTC]A?\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

RELATION_FIELDS = {
    "threat_actor": ["actors", "threat_actors"],
    "malware": ["malware"],
    "tool": ["tools"],
    "campaign": ["campaigns"],
    "tactic": ["tactics"],
}

SELF_TYPE_BY_FILTER = {
    "threat_actor": "Actor",
    "malware": "Malware",
    "tool": "Tool",
    "campaign": "Campaign",
    "tactic": "Tactic",
}


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple) or isinstance(value, set):
        return list(value)
    return [value]


def node_type(node: dict) -> str:
    return str(node.get("node_type") or node.get("type") or "")


def node_external_id(node: dict) -> str:
    external_id = node.get("external_id")
    if external_id:
        return str(external_id)

    fallback_id = str(node.get("id") or "")
    if MITRE_ID_RE.fullmatch(fallback_id):
        return fallback_id
    return ""


def unique_values(values: list) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = normalize_text(text)
        if key not in seen:
            seen.add(key)
            result.append(text)
    return result


def relation_values(node: dict, fields: list[str]) -> list[str]:
    values = []
    for field in fields:
        values.extend(as_list(node.get(field)))
    return unique_values(values)


def any_exact_match(needles: list, haystack: list) -> bool:
    normalized_haystack = {normalize_text(value) for value in haystack}
    return any(normalize_text(value) in normalized_haystack for value in needles)


def node_names(node: dict) -> list[str]:
    values = []
    if node.get("name"):
        values.append(node["name"])
    values.extend(as_list(node.get("aliases")))
    return unique_values(values)


def retrieval_score(node: dict) -> float:
    raw = node.get("rrf_score", node.get("score", node.get("source_score", 0.0)))
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return 0.0

    if score <= 0:
        return 0.0
    if score <= 1:
        return score * 2.0
    return min(score, 10.0) * 0.2


def deterministic_score(query: str, node: dict, filters: dict | None = None) -> tuple[float, list[str]]:
    filters = filters or {}
    score = 0.0
    reasons = []
    current_type = node_type(node)
    names = node_names(node)
    external_id = node_external_id(node)

    type_filters = as_list(filters.get("node_type"))
    if current_type and any_exact_match(type_filters, [current_type]):
        score += 3.0
        reasons.append("node_type")

    platform_filters = as_list(filters.get("platform"))
    platforms = relation_values(node, ["platforms"])
    if platform_filters and any_exact_match(platform_filters, platforms):
        score += 2.0
        reasons.append("platform")

    mitre_filters = as_list(filters.get("mitre_id"))
    if external_id and any_exact_match(mitre_filters, [external_id]):
        score += 3.0
        reasons.append("mitre_id")

    for filter_field, relation_fields in RELATION_FIELDS.items():
        expected_values = as_list(filters.get(filter_field))
        if not expected_values:
            continue

        matched = False
        requested_type_excludes_current = (
            bool(type_filters)
            and current_type
            and not any_exact_match(type_filters, [current_type])
        )
        if (
            current_type == SELF_TYPE_BY_FILTER.get(filter_field)
            and not requested_type_excludes_current
        ):
            matched = any_exact_match(expected_values, names)
        if not matched:
            matched = any_exact_match(expected_values, relation_values(node, relation_fields))

        if matched:
            score += 2.0
            reasons.append(filter_field)

    query_text = normalize_text(query)
    if external_id and normalize_text(external_id) in query_text:
        score += 1.0
        reasons.append("query_id")
    if names and any(normalize_text(name) in query_text for name in names):
        score += 1.0
        reasons.append("query_name")

    original_score = retrieval_score(node)
    if original_score:
        score += original_score
        reasons.append("retrieval_score")

    return score, reasons


def clipped_score(value: float) -> float:
    return min(max(value, 0.0), 10.0)


def build_node_context(node: dict, index: int | None = None) -> str:
    lines = []
    if index is not None:
        lines.append(f"Index: {index}")
    if node.get("name"):
        lines.append(f"Name: {node['name']}")

    current_type = node_type(node)
    if current_type:
        lines.append(f"Type: {current_type}")

    external_id = node_external_id(node)
    if external_id:
        lines.append(f"ID: {external_id}")

    aliases = relation_values(node, ["aliases"])
    if aliases:
        lines.append(f"Aliases: {', '.join(aliases[:5])}")

    description = str(node.get("description") or "").strip()
    if description:
        lines.append(f"Description: {description[:350]}")

    compact_fields = [
        ("Tactics", ["tactics"], 5),
        ("Platforms", ["platforms"], 5),
        ("Techniques", ["techniques", "subtechniques"], 5),
        ("Used by actors", ["actors", "threat_actors"], 5),
        ("Related malware", ["malware"], 5),
        ("Related tools", ["tools"], 5),
        ("Campaigns", ["campaigns"], 5),
        ("Mitigations", ["mitigations"], 3),
        ("Detections", ["detections", "detection_strategies"], 3),
        ("Data sources", ["log_sources"], 3),
    ]

    for label, fields, limit in compact_fields:
        values = relation_values(node, fields)
        if values:
            lines.append(f"{label}: {', '.join(values[:limit])}")

    return "\n".join(lines)


def extract_json_object(text: str) -> dict:
    cleaned = text.strip().replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return {}

    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}


def batch_llm_scores(query: str, candidates: list[dict], filters: dict | None = None) -> dict[int, float]:
    if not candidates:
        return {}

    candidate_blocks = [
        build_node_context(node, index=i)
        for i, node in enumerate(candidates)
    ]

    response = ollama.chat(
        model="llama3.1",
        messages=[{
            "role": "user",
            "content": f"""You are a relevance reranker for a cybersecurity MITRE ATT&CK RAG system.

Score each candidate from 0 to 10 for how well it answers the user query.

User query:
{query}

Validated filters:
{json.dumps(filters or {}, indent=2)}

Candidates:
{chr(10).join('---\\n' + block for block in candidate_blocks)}

Rules:
- Prefer candidates matching the validated filters.
- Prefer exact MITRE IDs, node types, platforms, and explicit relationships.
- Penalize entities that are only generally cybersecurity-related.
- Return ONLY valid JSON in this shape:
{{"scores": [{{"index": 0, "score": 8.5}}, {{"index": 1, "score": 3.0}}]}}
"""
        }],
        options={"temperature": 0}
    )

    raw = response.get("message", {}).get("content", "")
    parsed = extract_json_object(raw)
    scores = {}
    for item in parsed.get("scores", []):
        try:
            index = int(item["index"])
            score = clipped_score(float(item["score"]))
        except (KeyError, TypeError, ValueError):
            continue
        if 0 <= index < len(candidates):
            scores[index] = score
    return scores


def rerank(
    query: str,
    nodes: list[dict],
    top_k: int = 5,
    filters: dict | None = None,
    candidate_k: int = 20,
    use_llm: bool = True,
    deterministic_weight: float = 0.6,
    llm_weight: float = 0.4,
    max_llm_boost: float = 2.0,
    max_llm_penalty: float = 2.0,
) -> list[dict]:
    if not nodes:
        return []

    scored_nodes = []
    for node in nodes:
        scored = dict(node)
        raw_score, reasons = deterministic_score(query, scored, filters)
        scored["deterministic_score"] = clipped_score(raw_score)
        scored["deterministic_reasons"] = reasons
        scored_nodes.append(scored)

    scored_nodes.sort(key=lambda item: item["deterministic_score"], reverse=True)
    candidates = scored_nodes[:max(top_k, min(candidate_k, len(scored_nodes)))]

    llm_scores = batch_llm_scores(query, candidates, filters) if use_llm else {}
    for index, node in enumerate(candidates):
        llm_score = llm_scores.get(index)
        node["llm_score"] = llm_score
        if llm_score is None:
            effective_llm_score = node["deterministic_score"]
        else:
            effective_llm_score = max(
                node["deterministic_score"] - max_llm_penalty,
                min(llm_score, node["deterministic_score"] + max_llm_boost)
            )
        node["relevance_score"] = clipped_score(
            deterministic_weight * node["deterministic_score"]
            + llm_weight * effective_llm_score
        )

    candidates.sort(key=lambda item: item["relevance_score"], reverse=True)
    return candidates[:top_k]


def score_node(query: str, node: dict, filters: dict | None = None,
               use_llm: bool = False) -> float:
    if not use_llm:
        score, _ = deterministic_score(query, node, filters)
        return clipped_score(score)

    result = rerank(query, [node], top_k=1, filters=filters, candidate_k=1, use_llm=True)
    return result[0]["relevance_score"] if result else 0.0


if __name__ == "__main__":
    query = "What techniques does Lazarus Group use on Windows?"
    filters = {
        "node_type": ["Technique"],
        "threat_actor": ["Lazarus Group"],
        "platform": ["Windows"]
    }
    mock_nodes = [
        {
            "name": "Valid Accounts",
            "node_type": "Technique",
            "id": "T1078",
            "description": "Adversaries may obtain and abuse credentials of existing accounts.",
            "tactics": ["Initial Access", "Defense Evasion"],
            "platforms": ["Windows", "Linux", "macOS"],
            "actors": ["Lazarus Group", "APT29"],
            "score": 0.83
        },
        {
            "name": "Lazarus Group",
            "node_type": "Actor",
            "id": "G0032",
            "description": "Lazarus Group is a North Korean state-sponsored cyber threat group.",
            "tools": ["Mimikatz", "PsExec"],
            "score": 0.91
        },
        {
            "name": "Phishing",
            "node_type": "Technique",
            "id": "T1566",
            "description": "Adversaries may send phishing messages to gain access.",
            "platforms": ["Windows", "Linux", "macOS"],
            "score": 0.72
        }
    ]

    for rank, node in enumerate(rerank(query, mock_nodes, top_k=3, filters=filters, use_llm=False), 1):
        print(f"{rank}. {node['name']} -> {node['relevance_score']:.2f} {node['deterministic_reasons']}")
