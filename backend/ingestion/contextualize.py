import hashlib
import json
from collections import defaultdict
from typing import Any


CONTEXT_VERSION = "mitre-graph-context-v1"
MAX_RELATED_PER_GROUP = 8
MAX_SCALAR_FIELD_CHARS = 600
MAX_EMBEDDING_CHARS = 4_000


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split())


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else f"{value[:limit - 3]}..."


def _list_values(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return sorted({_clean(item) for item in value if _clean(item)}, key=str.casefold)


def node_type(labels: Any) -> str:
    clean_labels = [str(label) for label in (labels or []) if label != "MitreNode"]
    return clean_labels[0] if clean_labels else "MITRE ATT&CK entity"


def build_contextual_text(node: dict, relationships: list[dict] | None = None) -> str:
    """Build concise, factual context to prepend to a MITRE node before indexing."""
    name = _clean(node.get("name")) or "Unnamed entity"
    external_id = _clean(node.get("external_id"))
    kind = node_type(node.get("labels"))
    identifier = f" ({external_id})" if external_id else ""
    parts = [f"MITRE ATT&CK context: {name}{identifier} is a {kind}."]

    metadata_fields = (
        ("Aliases", "aliases"),
        ("Platforms", "platforms"),
        ("Kill chain phases", "kill_chain_phases"),
    )
    for label, key in metadata_fields:
        values = _list_values(node.get(key))
        if values:
            parts.append(f"{label}: {', '.join(values)}.")

    scalar_fields = (
        ("Tactic short name", "shortname"),
        ("First seen", "first_seen"),
        ("Last seen", "last_seen"),
        ("Log sources", "log_sources"),
    )
    for label, key in scalar_fields:
        value = _truncate(_clean(node.get(key)), MAX_SCALAR_FIELD_CHARS)
        if value:
            parts.append(f"{label}: {value}.")

    grouped: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for relation in relationships or []:
        relation_type = _clean(relation.get("relationship"))
        direction = _clean(relation.get("direction"))
        related_name = _clean(relation.get("other_name"))
        related_id = _clean(relation.get("other_external_id"))
        related_type = node_type(relation.get("other_labels"))
        if not relation_type or not direction or not related_name:
            continue
        related = f"{related_name} ({related_id})" if related_id else related_name
        grouped[(direction, relation_type, related_type)].add(related)

    for (direction, relation_type, related_type), values in sorted(grouped.items()):
        selected = sorted(values, key=str.casefold)[:MAX_RELATED_PER_GROUP]
        remainder = len(values) - len(selected)
        suffix = f" and {remainder} more" if remainder else ""
        parts.append(
            f"{direction.capitalize()} {relation_type} relationships to "
            f"{related_type}: {', '.join(selected)}{suffix}."
        )

    return " ".join(parts)


def build_embedding_text(node: dict, contextual_text: str) -> str:
    name = _clean(node.get("name"))
    description = _clean(node.get("description"))
    original_text = ". ".join(value for value in (name, description) if value)
    text = f"{contextual_text}\n\nContent: {original_text}" if original_text else contextual_text
    return text[:MAX_EMBEDDING_CHARS]


def context_fingerprint(contextual_text: str, embedding_model: str) -> str:
    payload = {
        "version": CONTEXT_VERSION,
        "embedding_model": embedding_model,
        "contextual_text": contextual_text,
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
