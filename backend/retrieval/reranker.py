import os
import re
import sys
from functools import lru_cache
from typing import Any

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


MITRE_ID_RE = re.compile(r"\b[GMSTC]A?\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
DEFAULT_CROSS_ENCODER_MODEL = "BAAI/bge-reranker-v2-m3"
CROSS_ENCODER_WEIGHT = 0.8
DETERMINISTIC_WEIGHT = 0.2

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


def hard_match_priority(node: dict, filters: dict | None = None) -> int:
    """Protect exact validated entities from lexical near-match displacement."""
    filters = filters or {}
    current_type = node_type(node)
    requested_types = as_list(filters.get("node_type"))

    external_id = node_external_id(node)
    if external_id and any_exact_match(as_list(filters.get("mitre_id")), [external_id]):
        return 3

    names = node_names(node)
    for filter_field, expected_type in SELF_TYPE_BY_FILTER.items():
        if (
            current_type == expected_type
            and any_exact_match(as_list(filters.get(filter_field)), names)
        ):
            return 2

    if requested_types and any_exact_match(requested_types, [current_type]):
        return 1
    return 0


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


def _resolve_device(torch_module) -> str:
    configured = os.getenv("RERANKER_DEVICE", "auto").strip().lower()
    if configured != "auto":
        return configured
    if torch_module.cuda.is_available():
        return "cuda"
    if getattr(torch_module.backends, "mps", None) and torch_module.backends.mps.is_available():
        return "mps"
    return "cpu"


@lru_cache(maxsize=1)
def load_cross_encoder():
    """Load the production reranker once and reuse it for all requests."""
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "Cross-encoder dependencies are missing. Install torch and transformers "
            "inside the backend virtual environment."
        ) from exc

    model_name = os.getenv("RERANKER_MODEL", DEFAULT_CROSS_ENCODER_MODEL)
    device = _resolve_device(torch)
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    model.to(device)
    model.eval()
    return tokenizer, model, device, torch


def batch_cross_encoder_scores(query: str, candidates: list[dict]) -> list[float]:
    """Return normalized query-to-candidate relevance scores in the range 0..1."""
    if not candidates:
        return []

    tokenizer, model, device, torch = load_cross_encoder()
    contexts = [build_node_context(node) for node in candidates]
    batch_size = max(1, int(os.getenv("RERANKER_BATCH_SIZE", "8")))
    max_length = max(128, int(os.getenv("RERANKER_MAX_LENGTH", "512")))
    scores: list[float] = []

    for start in range(0, len(contexts), batch_size):
        passages = contexts[start:start + batch_size]
        encoded = tokenizer(
            [query] * len(passages),
            passages,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}
        with torch.inference_mode():
            logits = model(**encoded).logits.reshape(-1).float()
            batch_scores = torch.sigmoid(logits).cpu().tolist()
        scores.extend(float(score) for score in batch_scores)

    return scores


def rerank(
    query: str,
    nodes: list[dict],
    top_k: int = 5,
    filters: dict | None = None,
    candidate_k: int = 20,
    cross_encoder_weight: float = CROSS_ENCODER_WEIGHT,
    deterministic_weight: float = DETERMINISTIC_WEIGHT,
) -> list[dict]:
    if not nodes:
        return []

    scored_nodes = []
    for node in nodes:
        scored = dict(node)
        raw_score, reasons = deterministic_score(query, scored, filters)
        scored["deterministic_score"] = clipped_score(raw_score)
        scored["deterministic_reasons"] = reasons
        scored["hard_match_priority"] = hard_match_priority(scored, filters)
        scored_nodes.append(scored)

    scored_nodes.sort(
        key=lambda item: (item["hard_match_priority"], item["deterministic_score"]),
        reverse=True,
    )
    candidates = scored_nodes[:max(top_k, min(candidate_k, len(scored_nodes)))]

    if cross_encoder_weight < 0 or deterministic_weight < 0:
        raise ValueError("Reranker weights cannot be negative")
    total_weight = cross_encoder_weight + deterministic_weight
    if total_weight <= 0:
        raise ValueError("At least one reranker weight must be positive")

    cross_encoder_scores = batch_cross_encoder_scores(query, candidates)
    if len(cross_encoder_scores) != len(candidates):
        raise RuntimeError(
            "Cross-encoder returned an unexpected number of relevance scores"
        )
    for node, cross_encoder_score in zip(candidates, cross_encoder_scores):
        deterministic_normalized = node["deterministic_score"] / 10.0
        combined = (
            cross_encoder_weight * cross_encoder_score
            + deterministic_weight * deterministic_normalized
        ) / total_weight
        node["cross_encoder_score"] = cross_encoder_score
        combined_score = combined * 10.0
        if node["hard_match_priority"] >= 2:
            combined_score = max(
                combined_score,
                9.5 + 0.25 * (node["hard_match_priority"] - 2),
            )
        node["relevance_score"] = clipped_score(combined_score)

    candidates.sort(
        key=lambda item: (item["hard_match_priority"], item["relevance_score"]),
        reverse=True,
    )
    return candidates[:top_k]


def score_node(query: str, node: dict, filters: dict | None = None) -> float:
    result = rerank(query, [node], top_k=1, filters=filters, candidate_k=1)
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

    for rank, node in enumerate(rerank(query, mock_nodes, top_k=3, filters=filters), 1):
        print(f"{rank}. {node['name']} -> {node['relevance_score']:.2f} {node['deterministic_reasons']}")
