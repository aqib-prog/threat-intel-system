import ollama
import re


MAX_FIELD_CHARS = 1600
MAX_COMPARISON_FIELD_ITEMS = 5
EXTERNAL_ID_RE = re.compile(r"\b(?:[GMSTC]A?\d{4}(?:\.\d{3})?|AN\d{4}|DET\d{4}|DC\d{4})\b", re.IGNORECASE)
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
ENTITY_REFERENCE_RE = re.compile(
    r"\b(?:[A-Z]{2,}\d+[A-Z0-9]*|[A-Z][a-z]+[A-Z][A-Za-z0-9]*|[A-Za-z]+\d+[A-Za-z0-9]*)\b"
)
PLATFORM_TERMS = {
    "windows",
    "linux",
    "macos",
    "office suite",
    "saas",
    "iaas",
    "containers",
    "network devices",
    "esxi",
    "identity provider",
}


SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst specialized in MITRE ATT&CK framework.

Your job is to answer questions STRICTLY based on the provided context only.

Rules:
- ONLY use information from the provided context
- NEVER add information not present in the context
- If context doesn't contain enough information, say "I don't have enough information about this in my knowledge base"
- Always cite MITRE IDs when available (e.g. T1078, G0032)
- Be precise and technical
- Structure your response clearly
- Never hallucinate techniques, actors, or campaigns not in context
- Treat context entries as search candidates, not automatic answers
- Only state relationships that are explicitly shown in relationship fields such as Actors, Techniques, Malware, Tools, Campaigns, Platforms, Mitigations, Detections, or Tactics
- Do not infer that an actor uses a technique, campaign, malware, or tool unless the context explicitly connects them
- For platform-specific questions, only include a technique/tool/malware when the same context item explicitly includes the requested platform
- Do not combine an actor's general relationship list with a platform from a different context item
- Treat comma-separated relationship lists as evidence of membership only, not as quantitative datasets
- Do not count items in relationship lists
- Do not report numeric counts, totals, or "broader/narrower range" comparisons unless the context explicitly provides a written count
- Do not use absence as evidence; avoid phrases like "not explicitly excluded" """


def query_mentions(value: str, query: str) -> bool:
    return bool(query and value and value.lower() in query.lower())


def compact_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def explicit_reference_tokens(query: str) -> set[str]:
    return {
        compact_text(match.group(0))
        for match in ENTITY_REFERENCE_RE.finditer(query or "")
        if not EXTERNAL_ID_RE.fullmatch(match.group(0))
        and not CVE_ID_RE.fullmatch(match.group(0))
    }


def context_mentions_token(nodes: list[dict], token: str) -> bool:
    for node in nodes:
        values = [
            node.get("name"),
            node.get("external_id"),
            node.get("id"),
            node.get("description"),
        ]
        for field in (
            "aliases",
            "tactics",
            "platforms",
            "techniques",
            "actors",
            "malware",
            "tools",
            "campaigns",
            "mitigations",
            "detections",
            "analytics",
            "log_sources",
            "detection_strategies",
            "subtechniques",
            "parent_technique",
        ):
            value = node.get(field)
            if isinstance(value, list):
                values.extend(value)
            else:
                values.append(value)

        if any(token and token in compact_text(str(value or "")) for value in values):
            return True
    return False


def has_unresolved_explicit_reference(query: str, nodes: list[dict]) -> bool:
    tokens = explicit_reference_tokens(query)
    return any(not context_mentions_token(nodes, token) for token in tokens)


def query_platforms(query: str) -> set[str]:
    query_lower = query.lower()
    return {platform for platform in PLATFORM_TERMS if platform in query_lower}


def is_comparison_query(query: str) -> bool:
    query_lower = query.lower()
    return any(
        term in query_lower
        for term in ("compare", "comparison", "similar", "similarities", "different", "differences")
    )


def list_contains_mentioned_value(values: list, targets: set[str]) -> bool:
    normalized_values = {str(value).lower() for value in values if value}
    return any(target.lower() in normalized_values for target in targets)


def filter_platform_actor_context(nodes: list[dict], query: str) -> list[dict]:
    platforms = query_platforms(query)
    if not platforms:
        return nodes

    mentioned_actors = {
        str(node.get("name"))
        for node in nodes
        if (node.get("node_type") or node.get("type")) == "Actor"
        and query_mentions(str(node.get("name") or ""), query)
    }
    if not mentioned_actors:
        return nodes

    filtered_nodes = []
    for node in nodes:
        node_type = node.get("node_type") or node.get("type")
        if node_type == "Actor":
            filtered_nodes.append(node)
            continue

        actors = node.get("actors") or []
        node_platforms = node.get("platforms") or []
        if (
            isinstance(actors, list)
            and isinstance(node_platforms, list)
            and list_contains_mentioned_value(actors, mentioned_actors)
            and list_contains_mentioned_value(node_platforms, platforms)
        ):
            filtered_nodes.append(node)

    return filtered_nodes


def mentioned_actor_nodes(nodes: list[dict], query: str) -> list[dict]:
    return [
        node
        for node in nodes
        if (node.get("node_type") or node.get("type")) == "Actor"
        and query_mentions(str(node.get("name") or ""), query)
    ]


def format_examples(values: list, limit: int = MAX_COMPARISON_FIELD_ITEMS) -> str:
    clean_values = [str(value) for value in values if value]
    if not clean_values:
        return "None shown in context"
    text = ", ".join(clean_values[:limit])
    if len(clean_values) > limit:
        text = f"{text}, ..."
    return text


def shared_values(left: list, right: list) -> list[str]:
    right_values = {str(value).lower() for value in right if value}
    return [str(value) for value in left if value and str(value).lower() in right_values]


def generate_actor_comparison(query: str, nodes: list[dict]) -> str | None:
    if not is_comparison_query(query):
        return None

    actors = mentioned_actor_nodes(nodes, query)
    if len(actors) < 2:
        return None

    left, right = actors[:2]
    left_name = left.get("name", "Unknown")
    right_name = right.get("name", "Unknown")
    left_id = left.get("external_id") or left.get("id")
    right_id = right.get("external_id") or right.get("id")

    lines = [
        f"Comparison: {left_name} ({left_id}) vs {right_name} ({right_id})",
        "",
    ]

    if left.get("description"):
        lines.append(f"{left_name}: {left['description'][:300]}")
    if right.get("description"):
        lines.append(f"{right_name}: {right['description'][:300]}")

    fields = [
        ("Tactics", "tactics"),
        ("Techniques", "techniques"),
        ("Malware", "malware"),
        ("Tools", "tools"),
        ("Campaigns", "campaigns"),
    ]

    for label, key in fields:
        left_values = left.get(key) or []
        right_values = right.get(key) or []
        if not left_values and not right_values:
            continue

        shared = shared_values(left_values, right_values)
        lines.extend([
            "",
            f"{label}:",
            f"- Shared examples: {format_examples(shared)}",
            f"- {left_name} examples: {format_examples(left_values)}",
            f"- {right_name} examples: {format_examples(right_values)}",
        ])

    lines.append("")
    lines.append("This comparison only uses explicit actor fields shown in the retrieved context.")
    return "\n".join(lines)


def format_list_value(values: list, query: str, comparison_mode: bool = False) -> str:
    clean_values = [str(item) for item in values if item]
    if not clean_values:
        return ""

    prioritized = [value for value in clean_values if query_mentions(value, query)]
    remaining = [value for value in clean_values if value not in prioritized]
    ordered_values = prioritized + remaining

    if comparison_mode:
        selected = ordered_values[:MAX_COMPARISON_FIELD_ITEMS]
        text = ", ".join(selected)
        if len(ordered_values) > len(selected):
            text = f"{text}, ..."
        return text

    selected = []
    selected_chars = 0
    for value in ordered_values:
        next_chars = len(value) + (2 if selected else 0)
        if selected and selected_chars + next_chars > MAX_FIELD_CHARS:
            break
        selected.append(value)
        selected_chars += next_chars

    text = ", ".join(selected)
    if len(ordered_values) > len(selected):
        text = f"{text}, ..."
    return text


def format_context(nodes: list[dict], query: str = "") -> str:
    if not nodes:
        return "No relevant context found."

    context_blocks = []
    for index, node in enumerate(nodes, 1):
        node_type = node.get("node_type") or node.get("type") or "Unknown"
        name = node.get("name") or "Unknown"
        external_id = node.get("external_id") or node.get("id")

        lines = [f"[{index}] {node_type} - {name}"]

        if external_id:
            lines.append(f"ID: {external_id}")

        if node.get("description"):
            lines.append(f"Description: {node['description'][:400]}")

        fields = [
            ("Tactics", "tactics"),
            ("Platforms", "platforms"),
            ("Techniques", "techniques"),
            ("Actors", "actors"),
            ("Malware", "malware"),
            ("Tools", "tools"),
            ("Campaigns", "campaigns"),
            ("Mitigations", "mitigations"),
            ("Detections", "detections"),
            ("Analytics", "analytics"),
            ("Log Sources", "log_sources"),
            ("Detection Strategies", "detection_strategies"),
            ("Subtechniques", "subtechniques"),
            ("Parent Technique", "parent_technique"),
        ]

        platforms_in_query = query_platforms(query)
        comparison_mode = is_comparison_query(query)
        for label, key in fields:
            if (
                platforms_in_query
                and node_type == "Actor"
                and key in {"techniques", "malware", "tools"}
            ):
                continue

            value = node.get(key)
            if not value:
                continue
            if isinstance(value, list):
                formatted_value = format_list_value(value, query, comparison_mode)
                if formatted_value:
                    if comparison_mode:
                        label = f"{label} Examples"
                    lines.append(f"{label}: {formatted_value}")
            else:
                lines.append(f"{label}: {value}")

        context_blocks.append("\n".join(lines))

    return "\n\n---\n\n".join(context_blocks)


def generate(query: str, nodes: list[dict], filters: dict | None = None) -> str:
    if not nodes:
        return "I don't have enough information about this in my knowledge base."

    nodes = filter_platform_actor_context(nodes, query)
    if not nodes:
        return "I don't have enough information about this in my knowledge base."

    if has_unresolved_explicit_reference(query, nodes):
        return "I don't have enough information about this in my knowledge base."

    comparison = generate_actor_comparison(query, nodes)
    if comparison:
        return comparison

    context = format_context(nodes, query)
    filter_text = ""
    if filters:
        filter_text = f"\nFilters applied: {filters}\n"

    response = ollama.chat(
        model="llama3.1",
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": f"""Context from MITRE ATT&CK knowledge base:

{context}
{filter_text}
---

Question: {query}

Critical answer constraints:
- Answer based strictly on the context above.
- Do not include caveated items that are not explicitly connected in the context.
- Do not count comma-separated relationship-list items.
- For comparisons, compare explicit facts and examples only; do not use broader/narrower range wording unless the context provides written counts.

Answer:""",
            },
        ],
        options={"temperature": 0},
    )

    return response["message"]["content"].strip()


if __name__ == "__main__":
    query = "What techniques does Lazarus Group use on Windows?"

    mock_nodes = [
        {
            "name": "Lazarus Group",
            "node_type": "Actor",
            "external_id": "G0032",
            "description": "Lazarus Group is a North Korean state-sponsored cyber threat group that has been attributed to the Reconnaissance General Bureau.",
            "techniques": [
                "Valid Accounts",
                "Command and Scripting Interpreter",
                "OS Credential Dumping",
            ],
            "malware": ["BLINDINGCAN", "HOPLIGHT", "BADCALL"],
            "tools": ["Mimikatz", "PsExec"],
            "tactics": [
                "Initial Access",
                "Execution",
                "Persistence",
                "Credential Access",
            ],
            "campaigns": ["Operation Dream Job"],
        },
        {
            "name": "Valid Accounts",
            "node_type": "Technique",
            "external_id": "T1078",
            "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
            "tactics": [
                "Defense Evasion",
                "Initial Access",
                "Persistence",
                "Privilege Escalation",
            ],
            "platforms": ["Windows", "Linux", "macOS"],
            "actors": ["Lazarus Group", "APT29"],
            "mitigations": [
                "Privileged Account Management",
                "Multi-factor Authentication",
            ],
        },
        {
            "name": "OS Credential Dumping",
            "node_type": "Technique",
            "external_id": "T1003",
            "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
            "tactics": ["Credential Access"],
            "platforms": ["Windows", "Linux", "macOS"],
            "actors": ["Lazarus Group", "APT28"],
            "tools": ["Mimikatz"],
        },
    ]

    print("=== Generate Response Test ===\n")
    print(f"Query: {query}\n")
    print(f"Response:\n{generate(query, mock_nodes)}")
