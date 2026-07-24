import ollama
import re

from config import OLLAMA_CLIENT

MAX_FIELD_CHARS = 1600
MAX_COMPARISON_FIELD_ITEMS = 5
EXTERNAL_ID_RE = re.compile(r"\b(?:[GMSTC]A?\d{4}(?:\.\d{3})?|AN\d{4}|DET\d{4}|DC\d{4})\b", re.IGNORECASE)
NAME_ID_PAIR_RE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9 /_.:'-]{1,100}?)\s*"
    r"\((?P<id>(?:[GMSTC]A?\d{4}(?:\.\d{3})?|AN\d{4}|DET\d{4}|DC\d{4}))\)",
    re.IGNORECASE,
)
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
ENTITY_REFERENCE_RE = re.compile(
    r"\b(?:[A-Z]{2,}\d+[A-Z0-9]*|[A-Z][a-z]+[A-Z][A-Za-z0-9]*|"
    r"[A-Za-z]+\d+[A-Za-z0-9]*|[A-Z]{2,}[A-Z][a-z]+)\b"
)
PLATFORM_TERMS = {
    "windows",
    "linux",
    "macos",
    "android",
    "ios",
    "kubernetes",
    "office suite",
    "saas",
    "iaas",
    "containers",
    "network devices",
    "esxi",
    "identity provider",
}
TELEMETRY_FIELD_RE = re.compile(
    r"\b(?:event\s*id|eventid|logon\s*type|logontype|process\s*name|processname|"
    r"command\s*line|commandline|account(?:name)?|source\s*ip|sourceip|"
    r"destination\s*ip|destinationip|destination\s*port|destinationport|"
    r"share\s*name|sharename|object\s*name|objectname|access\s*mask|accessmask|"
    r"authentication\s*package|authenticationpackage|service\s*name|servicename|"
    r"image\s*path|imagepath|parent\s*process|parentprocess)\b",
    re.IGNORECASE,
)


SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst specialized in MITRE ATT&CK framework.

Your job is to answer questions STRICTLY based on the provided context only.

Rules:
- ONLY use information from the provided context
- NEVER add information not present in the context
- If context doesn't contain enough information, say "I don't have enough information about this in my knowledge base"
- Cite a MITRE ID only when that exact name-ID pair appears on the same context item
- Relationship-list names do not carry IDs; list those names without inventing IDs
- Be precise and technical
- Structure your response clearly
- Never hallucinate techniques, actors, or campaigns not in context
- Treat context entries as search candidates, not automatic answers
- Only state relationships that are explicitly shown in relationship fields such as Actors, Techniques, Malware, Tools, Campaigns, Platforms, Mitigations, Detections, or Tactics
- Do not infer that an actor uses a technique, campaign, malware, or tool unless the context explicitly connects them
- For platform-specific questions, only include a technique/tool/malware when the same context item explicitly includes the requested platform
- Do not combine an actor's general relationship list with a platform from a different context item
- Do not group techniques under tactic headings unless the question explicitly requests tactic grouping
- For campaign technique questions, list each explicitly connected technique independently
- Treat comma-separated relationship lists as evidence of membership only, not as quantitative datasets
- Do not count items in relationship lists
- Do not report numeric counts, totals, or "broader/narrower range" comparisons unless the context explicitly provides a written count
- Do not use absence as evidence; avoid phrases like "not explicitly excluded"

Response formatting:
- Prefer stable labeled sections so the UI can render them consistently.
- Use only relevant labels from this set when they apply: Summary, Description, Type, MITRE ID, Tactics, Techniques, Subtechniques, Parent Technique, Procedure, Platforms, Tools, Malware, Campaigns, Mitigations, Detection Strategies, Data Sources, Analytics, Strongest Evidence.
- For labeled facts, write each as `Label: value` on its own line.
- For lists, write `Label:` followed by markdown bullets.
- For explanatory comparisons, use bullets with bold labels, e.g. `- **Tactic:** ...`, `- **Technique:** ...`, `- **Procedure:** ...`.
- Do not invent a section just to satisfy formatting; only include sections supported by context. """


def query_mentions(value: str, query: str) -> bool:
    return bool(query and value and compact_text(value) in compact_text(query))


def compact_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def truncate_description(text: str, limit: int) -> str:
    """Trim a description to at most ``limit`` chars without cutting mid-word.

    Prefers ending at the last sentence boundary inside the window (so the text
    reads as complete); otherwise falls back to the last whole word and appends
    an ellipsis. Replaces the bare ``description[:limit]`` slices that produced
    ugly mid-word cuts like "...United States. A p"."""
    text = str(text or "")
    if len(text) <= limit:
        return text
    window = text[:limit]
    sentence_end = max(window.rfind(". "), window.rfind("! "), window.rfind("? "))
    # Only end on a sentence if it isn't so early it drops most of the window.
    if sentence_end >= int(limit * 0.6):
        return window[: sentence_end + 1]
    space = window.rfind(" ")
    trimmed = window[:space] if space > 0 else window
    return trimmed.rstrip(",;:. ") + "…"


def is_raw_telemetry_query(query: str) -> bool:
    return bool(TELEMETRY_FIELD_RE.search(query or ""))


def sanitize_generated_ids(answer: str, nodes: list[dict]) -> str:
    """Allow only exact name-ID pairs grounded in retrieved context nodes."""
    grounded_pairs = []
    grounded_ids = set()
    for node in nodes:
        external_id = str(node.get("external_id") or node.get("id") or "").upper()
        name = compact_text(str(node.get("name") or ""))
        if external_id and name and EXTERNAL_ID_RE.fullmatch(external_id):
            grounded_pairs.append((name, external_id))
            grounded_ids.add(external_id)

    def replace_pair(match: re.Match) -> str:
        name_text = match.group("name")
        candidate_name = compact_text(name_text)
        candidate_id = match.group("id").upper()
        is_grounded = any(
            candidate_id == grounded_id
            and (
                candidate_name == grounded_name
                or candidate_name.endswith(grounded_name)
            )
            for grounded_name, grounded_id in grounded_pairs
        )
        return match.group(0) if is_grounded else name_text.rstrip()

    sanitized = NAME_ID_PAIR_RE.sub(replace_pair, answer)
    sanitized = EXTERNAL_ID_RE.sub(
        lambda match: match.group(0)
        if match.group(0).upper() in grounded_ids
        else "",
        sanitized,
    )
    sanitized = re.sub(r"[ \t]+\n", "\n", sanitized)
    sanitized = re.sub(r" {2,}", " ", sanitized)
    return sanitized.strip()


def explicit_reference_tokens(query: str) -> set[str]:
    if is_raw_telemetry_query(query):
        return set()
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
    explicit_ids = {
        match.group(0).upper() for match in EXTERNAL_ID_RE.finditer(query or "")
    }
    explicit_ids.update(match.upper() for match in CVE_ID_RE.findall(query or ""))
    for external_id in explicit_ids:
        if not context_mentions_token(nodes, compact_text(external_id)):
            return True

    tokens = explicit_reference_tokens(query)
    return any(not context_mentions_token(nodes, token) for token in tokens)


def explicit_reference_status(query: str, nodes: list[dict]) -> tuple[list[str], list[str]]:
    """Split every explicit ID/name reference in the query into (resolved,
    unresolved) against the retrieved context, preserving original casing
    for display. A query naming several entities where only some resolve
    (e.g. one real actor plus one made-up one) should still be answerable
    for the real ones, not refused outright - see generate()."""
    resolved: list[str] = []
    unresolved: list[str] = []
    seen: set[str] = set()

    explicit_ids = list(dict.fromkeys(
        match.group(0).upper() for match in EXTERNAL_ID_RE.finditer(query or "")
    ))
    explicit_ids += [
        match.upper()
        for match in dict.fromkeys(CVE_ID_RE.findall(query or ""))
        if match.upper() not in explicit_ids
    ]
    for external_id in explicit_ids:
        if external_id in seen:
            continue
        seen.add(external_id)
        bucket = resolved if context_mentions_token(nodes, compact_text(external_id)) else unresolved
        bucket.append(external_id)

    if is_raw_telemetry_query(query):
        return resolved, unresolved

    for match in ENTITY_REFERENCE_RE.finditer(query or ""):
        raw = match.group(0)
        if EXTERNAL_ID_RE.fullmatch(raw) or CVE_ID_RE.fullmatch(raw):
            continue
        key = compact_text(raw)
        if not key or key in seen:
            continue
        seen.add(key)
        bucket = resolved if context_mentions_token(nodes, key) else unresolved
        bucket.append(raw)

    return resolved, unresolved


def validated_filter_resolves_context(filters: dict | None, nodes: list[dict]) -> bool:
    """Honor an entity typo correction already validated against Neo4j."""
    for field in (
        "threat_actor",
        "malware",
        "tool",
        "campaign",
        "tactic",
        "mitigation",
        "analytic",
        "detection_strategy",
        "data_component",
    ):
        for value in (filters or {}).get(field, []):
            if context_mentions_token(nodes, compact_text(str(value))):
                return True
    return False


def _without_entity_name_parentheticals(query: str) -> str:
    """Remove a parenthesized MITRE entity name immediately following its ID."""
    stripped = query
    for match in reversed(list(EXTERNAL_ID_RE.finditer(query or ""))):
        start = match.end()
        while start < len(stripped) and stripped[start].isspace():
            start += 1
        if start >= len(stripped) or stripped[start] != "(":
            continue

        depth = 0
        for index in range(start, len(stripped)):
            if stripped[index] == "(":
                depth += 1
            elif stripped[index] == ")":
                depth -= 1
                if depth == 0:
                    stripped = stripped[:start] + " " + stripped[index + 1:]
                    break
    return stripped


def query_platforms(query: str) -> set[str]:
    query_lower = _without_entity_name_parentheticals(query).lower()
    return {platform for platform in PLATFORM_TERMS if platform in query_lower}


# Shared by every profile-style renderer (actor/campaign/software/tactic/
# mitigation overview) so a broad, keyword-free question ("What does RIPTIDE
# do?", "Tell me about APT29") gets the same deterministic all-fields answer
# as an explicit "everything" request, instead of falling through to
# unstable free-form LLM synthesis. One shared trigger kept in sync here
# rather than each renderer maintaining its own ad hoc broad-phrasing regex.
BROAD_OVERVIEW_RE = re.compile(
    r"\b(?:tell\s+me\s+about|what\s+does\b.*\bdo\b|what\s+is\b|describe|"
    r"overview|everything|analysis|summary|profile)\b",
    re.IGNORECASE,
)


def is_broad_overview_query(query: str) -> bool:
    return bool(BROAD_OVERVIEW_RE.search(query.strip()))


def is_comparison_query(query: str) -> bool:
    query_lower = query.lower()
    return any(
        term in query_lower
        for term in ("compare", "comparison", "similar", "similarities", "different", "differences")
    )


def is_unsupported_count_query(query: str) -> bool:
    return bool(re.search(r"\b(?:count|how many|total number)\b", query, re.IGNORECASE))


def is_unsupported_meta_query(query: str) -> bool:
    patterns = (
        r"\b(?:system|hidden)\s+prompt\b",
        r"\b(?:reveal|show|print|repeat)\b.*\b(?:prompt|instructions)\b",
        r"\bignore\b.*\b(?:context|instructions)\b",
        r"\bpretend\b.*\bdatabase\b",
        r"\b(?:latest|current|most\s+recent)\b",
        r"\bforget\b.*\brules\b",
        r"\bact\s+as\s+dan\b",
        r"\bjailbreak\b",
        r"\bignore\b.*\bguidelines\b",
        r"\bhow\s+to\s+hack\b",
    )
    return any(re.search(pattern, query, re.IGNORECASE) for pattern in patterns)


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


def filter_context_by_validated_relationships(
    nodes: list[dict],
    filters: dict | None,
) -> list[dict]:
    """Remove candidates that contradict validated relationship constraints."""
    filters = filters or {}
    constraints = {
        "actors": filters.get("threat_actor", []),
        "tactics": filters.get("tactic", []),
        "platforms": filters.get("platform", []),
        "campaigns": filters.get("campaign", []),
    }
    requested_ids = {
        str(value).upper() for value in filters.get("mitre_id", []) if value
    }
    normalized_constraints = {
        field: {str(value).lower() for value in values if value}
        for field, values in constraints.items()
    }
    if not any(normalized_constraints.values()):
        return nodes

    filtered = []
    for node in nodes:
        node_type = node.get("node_type") or node.get("type")
        if str(node.get("external_id") or "").upper() in requested_ids:
            filtered.append(node)
            continue
        if node_type not in {"Technique", "Malware", "Tool"}:
            filtered.append(node)
            continue

        valid = True
        for field, expected in normalized_constraints.items():
            if not expected:
                continue
            if field == "tactics" and node_type not in {"Technique", "Malware", "Tool"}:
                continue
            actual_value = node.get(field) or []
            if not isinstance(actual_value, list):
                actual_value = [actual_value]
            actual = {str(value).lower() for value in actual_value if value}
            if not expected.intersection(actual):
                valid = False
                break
        if valid:
            filtered.append(node)
    return filtered


def is_id_focused_filter_scope(filters: dict | None) -> bool:
    filters = filters or {}
    if not filters.get("mitre_id"):
        return False
    broader_scope_fields = (
        "threat_actor",
        "malware",
        "tool",
        "campaign",
        "tactic",
        "platform",
        "cve_id",
    )
    return not any(filters.get(field) for field in broader_scope_fields)


def telemetry_technique_names(query: str) -> list[str]:
    value = query.lower()
    names = []
    if re.search(r"\b(?:event\s*id\s*=?\s*4624|event\s+4624|logon\s+type\s*=?\s*3|network\s+logon|ntlm)", value):
        names.extend(["Valid Accounts", "Remote Services"])
    if re.search(r"\b(?:event\s*id\s*=?\s*4672|sedebugprivilege|sebackupprivilege|serestoreprivilege|special\s+privileges)", value):
        names.extend(["Valid Accounts", "Access Token Manipulation"])
    if re.search(r"\b(?:admin\s+share|admin\$|c\$|smb\s+share|windows\s+admin\s+share|\\\\[^\\\s]+\\admin\$)", value):
        names.append("SMB/Windows Admin Shares")
    if re.search(r"\b(?:event\s*id\s*=?\s*7045|remote\s+service|service\s+creation|create(?:d)?\s+service|windows\s+service|sc\.exe\s+\\\\|sc\s+\\\\|binpath=)", value):
        names.extend(["Service Execution", "Windows Service"])
    if re.search(r"\b(?:rdp|remote\s+desktop)", value):
        names.append("Remote Desktop Protocol")
    if re.search(r"\b(?:wmi|windows\s+management\s+instrumentation)", value):
        names.append("Windows Management Instrumentation")
    if re.search(r"\b(?:whoami|whoami\.exe|whoami\s+/all)", value):
        names.append("System Owner/User Discovery")
    if re.search(r"\b(?:nltest|domain_trusts|domain\s+trust)", value):
        names.append("Domain Trust Discovery")
    if re.search(r"\b(?:net\s+group|domain\s+admins|permission\s+groups?)", value):
        names.append("Permission Groups Discovery")
    if re.search(r"\b(?:net\s+view|remote\s+system\s+discovery)", value):
        names.append("Remote System Discovery")
    if re.search(r"\b(?:cmd\.exe|commandline=.*cmd|windows\s+command\s+shell)", value):
        names.append("Windows Command Shell")
    if re.search(r"\b(?:powershell(?:\.exe)?|encodedcommand|-enc\b|-nop\b|frombase64string)", value):
        names.append("PowerShell")
    if re.search(r"\b(?:reg\s+save|hklm\\sam|hklm\\\\sam|sam\.save|system\.save)", value):
        names.extend(["OS Credential Dumping", "Security Account Manager"])
    if re.search(r"\b(?:vssadmin|volume\s+shadow|shadow\s+copy)", value):
        names.append("OS Credential Dumping")
    if re.search(r"\b(?:rundll32(?:\.exe)?|rundll32\.exe\s+.*\.dll)", value):
        names.append("Rundll32")
    if re.search(r"\b(?:event\s*id\s*=?\s*4663|objectname=|read(data)?|file\s+access)", value):
        names.append("File and Directory Discovery")
    if re.search(r"\b(?:rar(?:\.exe)?|7z(?:\.exe)?|zip|archive\.rar|archive\s+collected)", value):
        names.extend(["Archive Collected Data", "Archive via Utility"])
    if re.search(r"\b(?:event\s*id\s*=?\s*5156|destinationip=|destinationport=443|outbound|exfil)", value):
        names.extend(["Exfiltration Over Web Service", "Exfiltration Over C2 Channel"])
    if re.search(r"\b(?:wevtutil\s+cl|event\s*id\s*=?\s*1102|audit\s+log\s+was\s+cleared|clear(?:ed)?\s+.*log)", value):
        names.extend(["Clear Windows Event Logs", "Indicator Removal"])
    seen = set()
    return [name for name in names if not (name in seen or seen.add(name))]


def telemetry_evidence_for_technique(query: str, technique_name: str) -> list[str]:
    value = query.lower()
    evidence_patterns = {
        "Valid Accounts": [
            (r"event\s*id\s*=?\s*4624|logon\s+type\s*=?\s*3|network\s+logon|ntlm", "network logon / NTLM authentication event"),
            (r"svc-|service\s+account", "service-account style username"),
        ],
        "Remote Services": [(r"event\s*id\s*=?\s*4624|admin\$|sc\.exe\s+\\\\", "remote access over Windows services/shares")],
        "SMB/Windows Admin Shares": [(r"admin\$|\\\\[^\\\s]+\\admin\$", "ADMIN$ administrative share access or copy")],
        "Service Execution": [(r"sc\.exe\s+\\\\|event\s*id\s*=?\s*7045|start\s+\w+svc", "remote service creation/start activity")],
        "Windows Service": [(r"event\s*id\s*=?\s*7045|binpath=", "new Windows service installation")],
        "System Owner/User Discovery": [(r"whoami", "whoami execution")],
        "Domain Trust Discovery": [(r"nltest|domain_trusts", "domain trust enumeration")],
        "Permission Groups Discovery": [(r"net\s+group|domain\s+admins", "domain group enumeration")],
        "Remote System Discovery": [(r"net\s+view", "remote system/domain enumeration")],
        "Windows Command Shell": [(r"cmd\.exe", "cmd.exe command execution")],
        "PowerShell": [(r"powershell|encodedcommand|-enc\b|-nop\b", "PowerShell with encoded or hidden execution flags")],
        "OS Credential Dumping": [(r"reg\s+save|hklm\\sam|sam\.save|system\.save|vssadmin", "SAM/SYSTEM registry save or shadow-copy activity")],
        "Security Account Manager": [(r"reg\s+save|hklm\\sam|sam\.save", "SAM hive save command")],
        "Rundll32": [(r"rundll32", "rundll32 loading a DLL entry point")],
        "File and Directory Discovery": [(r"event\s*id\s*=?\s*4663|objectname=", "object/file access telemetry")],
        "Archive Collected Data": [(r"rar|7z|archive\.rar", "archive utility creating compressed collection")],
        "Archive via Utility": [(r"rar|7z|archive\.rar", "archive utility command line")],
        "Exfiltration Over Web Service": [(r"destinationport=443|destinationip=|outbound", "outbound network connection over HTTPS")],
        "Exfiltration Over C2 Channel": [(r"destinationip=|destinationport=443|outbound", "outbound network connection after collection/archive")],
        "Clear Windows Event Logs": [(r"wevtutil\s+cl|event\s*id\s*=?\s*1102|audit\s+log\s+was\s+cleared", "event log clearing command or audit-log-cleared event")],
        "Indicator Removal": [(r"wevtutil\s+cl|event\s*id\s*=?\s*1102|audit\s+log\s+was\s+cleared", "log clearing / indicator removal evidence")],
    }
    evidence = []
    for pattern, description in evidence_patterns.get(technique_name, []):
        if re.search(pattern, value) and description not in evidence:
            evidence.append(description)
    return evidence


def generate_telemetry_indicator_summary(query: str, nodes: list[dict]) -> str | None:
    if not re.search(r"\b(?:log|logs|event|events|telemetry|could\s+.*indicate|indicate)\b", query, re.IGNORECASE):
        return None
    expected_names = telemetry_technique_names(query)
    if not expected_names:
        return None
    node_by_name = {
        str(node.get("name") or "").lower(): node
        for node in nodes
        if (node.get("node_type") or node.get("type")) == "Technique"
    }
    matched = [
        node_by_name[name.lower()]
        for name in expected_names
        if name.lower() in node_by_name
    ]
    if not matched:
        return None

    lines = ["Based on the provided telemetry, the strongest ATT&CK mappings are:"]
    lines.append("")
    lines.append("Techniques:")
    for node in matched:
        name = node.get("name") or "Unknown"
        external_id = node.get("external_id") or node.get("id")
        lines.append(f"- {name} ({external_id})" if external_id else f"- {name}")

    tactics = []
    detections = []
    mitigations = []
    for node in matched:
        for value in node.get("tactics") or []:
            if value and value not in tactics:
                tactics.append(value)
        for value in node.get("detections") or node.get("detection_strategies") or []:
            if value and value not in detections:
                detections.append(value)
        for value in node.get("mitigations") or []:
            if value and value not in mitigations:
                mitigations.append(value)

    if tactics:
        lines.append("")
        lines.append("Tactics:")
        lines.extend(f"- {value}" for value in tactics[:12])

    if detections:
        lines.append("")
        lines.append("Detection Strategies:")
        lines.extend(f"- {value}" for value in detections[:12])

    if mitigations:
        lines.append("")
        lines.append("Mitigations:")
        lines.extend(f"- {value}" for value in mitigations[:12])

    evidence_lines = []
    for node in matched:
        name = str(node.get("name") or "Unknown")
        evidence = telemetry_evidence_for_technique(query, name)
        if evidence:
            external_id = node.get("external_id") or node.get("id")
            heading = f"{name} ({external_id})" if external_id else name
            evidence_lines.append(f"- {heading}: {', '.join(evidence)}")
    if evidence_lines:
        lines.append("")
        lines.append("Strongest Evidence:")
        lines.extend(evidence_lines[:12])

    return "\n".join(lines)


def mentioned_actor_nodes(nodes: list[dict], query: str) -> list[dict]:
    return [
        node
        for node in nodes
        if (node.get("node_type") or node.get("type")) == "Actor"
        and query_mentions(str(node.get("name") or ""), query)
    ]


def generate_actor_usage_list(query: str, nodes: list[dict]) -> str | None:
    """Answer actor-usage list questions directly from explicit graph fields."""
    if not re.search(r"\b(?:which|what)\b.*\bactors?\b", query, re.IGNORECASE):
        return None
    if not re.search(r"\b(?:use|uses|using)\b", query, re.IGNORECASE):
        return None

    for node in nodes:
        node_type = node.get("node_type") or node.get("type")
        name = str(node.get("name") or "")
        actors = node.get("actors") or []
        if (
            node_type not in {"Technique", "Malware", "Tool"}
            or not query_mentions(name, query)
            or not isinstance(actors, list)
            or not actors
        ):
            continue

        external_id = node.get("external_id") or node.get("id")
        heading = f"{name} ({external_id})" if external_id else name
        lines = [f"Threat actors explicitly connected to {heading}:"]
        lines.extend(f"- {actor}" for actor in actors if actor)
        return "\n".join(lines)

    return None


def generate_actor_relationship_list(query: str, nodes: list[dict]) -> str | None:
    """Render a singular actor's explicit relationship field without LLM drift."""
    if not nodes or (nodes[0].get("node_type") or nodes[0].get("type")) != "Actor":
        return None
    if query_platforms(query):
        return None
    if re.search(r"\b(?:compare|versus|and)\b", query, re.IGNORECASE):
        return None

    patterns = (
        (r"\b(?:techniques?|techniqes?)\b", "Techniques", "techniques"),
        (r"\bmalware\b", "Malware", "malware"),
        (r"\btools?\b", "Tools", "tools"),
        (r"\b(?:campaigns?|campains?)\b", "Campaigns", "campaigns"),
        (r"\b(?:tactics?|movment|movement)\b", "Tactics", "tactics"),
    )
    actor = nodes[0]
    name = actor.get("name") or "Unknown actor"
    external_id = actor.get("external_id") or actor.get("id")
    heading = f"{name} ({external_id})" if external_id else name

    for pattern, label, key in patterns:
        if not re.search(pattern, query, re.IGNORECASE):
            continue
        values = actor.get(key) or []
        if isinstance(values, list) and values:
            return "\n".join([
                f"{label} explicitly connected to {heading}:",
                *(f"- {value}" for value in values if value),
            ])

    if re.search(r"\b(?:use|uses|using)\b", query, re.IGNORECASE):
        lines = [f"Explicit relationships for {heading}:"]
        for label, key in (("Techniques", "techniques"), ("Malware", "malware"), ("Tools", "tools")):
            values = actor.get(key) or []
            if isinstance(values, list) and values:
                lines.append(f"{label}: {', '.join(str(value) for value in values if value)}")
        return "\n".join(lines) if len(lines) > 1 else None

    if is_broad_overview_query(query):
        lines = [heading]
        if actor.get("description"):
            lines.append(f"Description: {truncate_description(actor['description'], 400)}")
        aliases = actor.get("aliases") or []
        if isinstance(aliases, list) and aliases:
            lines.append(f"Aliases: {', '.join(str(value) for value in aliases if value)}")
        for label, key in (
            ("Techniques", "techniques"),
            ("Malware", "malware"),
            ("Tools", "tools"),
            ("Campaigns", "campaigns"),
            ("Tactics", "tactics"),
        ):
            values = actor.get(key) or []
            if isinstance(values, list) and values:
                lines.append(f"\n{label} explicitly connected to {heading}:")
                lines.extend(f"- {value}" for value in values if value)
        return "\n".join(lines)

    return None


def generate_software_relationship_list(query: str, nodes: list[dict]) -> str | None:
    """Render a malware or tool's explicit relationship field without LLM drift."""
    if not nodes or (nodes[0].get("node_type") or nodes[0].get("type")) not in {"Malware", "Tool"}:
        return None
    if query_platforms(query):
        return None
    if re.search(r"\b(?:compare|versus)\b", query, re.IGNORECASE):
        return None

    patterns = (
        (r"\b(?:techniques?|techniqes?)\b", "Techniques", "techniques"),
        (r"\bactors?\b", "Actors", "actors"),
        (r"\b(?:campaigns?|campains?)\b", "Campaigns", "campaigns"),
        (r"\b(?:tactics?|movment|movement)\b", "Tactics", "tactics"),
        (r"\bmitigations?\b", "Mitigations", "mitigations"),
    )
    software = nodes[0]
    name = software.get("name") or "Unknown software"
    external_id = software.get("external_id") or software.get("id")
    heading = f"{name} ({external_id})" if external_id else name

    for pattern, label, key in patterns:
        if not re.search(pattern, query, re.IGNORECASE):
            continue
        values = software.get(key) or []
        if isinstance(values, list) and values:
            return "\n".join([
                f"{label} explicitly connected to {heading}:",
                *(f"- {value}" for value in values if value),
            ])

    if is_broad_overview_query(query):
        lines = [heading]
        if software.get("description"):
            lines.append(f"Description: {truncate_description(software['description'], 400)}")
        for _, label, key in patterns:
            values = software.get(key) or []
            if isinstance(values, list) and values:
                lines.append(f"\n{label} explicitly connected to {heading}:")
                lines.extend(f"- {value}" for value in values if value)
        if len(lines) > 1:
            return "\n".join(lines)

    return None


def generate_tactic_relationship_list(query: str, nodes: list[dict]) -> str | None:
    """Render a tactic's explicit techniques field without LLM drift."""
    if not nodes or (nodes[0].get("node_type") or nodes[0].get("type")) != "Tactic":
        return None
    if not re.search(r"\b(?:techniques?|techniqes?)\b", query, re.IGNORECASE) and not is_broad_overview_query(query):
        return None
    if re.search(r"\b(?:compare|versus)\b", query, re.IGNORECASE):
        return None

    tactic = nodes[0]
    techniques = tactic.get("techniques") or []
    if not isinstance(techniques, list) or not techniques:
        return None

    name = tactic.get("name") or "Unknown tactic"
    external_id = tactic.get("external_id") or tactic.get("id")
    heading = f"{name} ({external_id})" if external_id else name
    return "\n".join([
        f"Techniques explicitly connected to {heading}:",
        *(f"- {value}" for value in techniques if value),
    ])


def generate_mitigation_relationship_list(query: str, nodes: list[dict]) -> str | None:
    """Render a mitigation's explicit relationship fields without LLM drift."""
    if not nodes or (nodes[0].get("node_type") or nodes[0].get("type")) != "Mitigation":
        return None
    if re.search(r"\b(?:compare|versus)\b", query, re.IGNORECASE):
        return None

    # A Mitigation relates to Techniques only, via MITIGATES - so the verb
    # "mitigate(s/d)" is synonymous with "its techniques" ("What does X
    # mitigate?" == "What techniques does X mitigate?"). Fold it into the
    # techniques trigger so the canonical phrasing resolves deterministically
    # instead of falling through to free-form synthesis.
    patterns = (
        (r"\b(?:techniques?|techniqes?|mitigates?|mitigated|mitigation)\b", "Techniques", "techniques"),
        (r"\b(?:actors?|groups?)\b", "Actors", "actors"),
        (r"\b(?:tactics?|movment|movement)\b", "Tactics", "tactics"),
    )
    mitigation = nodes[0]
    name = mitigation.get("name") or "Unknown mitigation"
    external_id = mitigation.get("external_id") or mitigation.get("id")
    heading = f"{name} ({external_id})" if external_id else name

    for pattern, label, key in patterns:
        if not re.search(pattern, query, re.IGNORECASE):
            continue
        values = mitigation.get(key) or []
        if isinstance(values, list) and values:
            return "\n".join([
                f"{label} explicitly connected to {heading}:",
                *(f"- {value}" for value in values if value),
            ])

    if is_broad_overview_query(query):
        lines = [heading]
        if mitigation.get("description"):
            lines.append(f"Description: {truncate_description(mitigation['description'], 400)}")
        for _, label, key in patterns:
            values = mitigation.get(key) or []
            if isinstance(values, list) and values:
                lines.append(f"\n{label} explicitly connected to {heading}:")
                lines.extend(f"- {value}" for value in values if value)
        if len(lines) > 1:
            return "\n".join(lines)

    return None


def generate_actor_overview(
    query: str,
    nodes: list[dict],
    filters: dict | None = None,
) -> str | None:
    """Render broad actor requests from explicit graph fields without invented IDs."""
    requested_fields = {
        key
        for pattern, key in (
            (r"\btechniques?\b", "techniques"),
            (r"\bmalware\b", "malware"),
            (r"\btools?\b", "tools"),
            (r"\bcampaigns?\b", "campaigns"),
            (r"\bmitigations?\b", "mitigations"),
            (r"\btactics?\b", "tactics"),
        )
        if re.search(pattern, query, re.IGNORECASE)
    }
    if not is_broad_overview_query(query) and len(requested_fields) < 3:
        return None

    requested_actors = {
        str(value).lower() for value in (filters or {}).get("threat_actor", [])
    }
    # A broad, entity-agnostic phrase ("what does X do") matches regardless
    # of what X actually is - without an explicit actor filter, only trust
    # it here when the query's own primary/seed node is an Actor. Otherwise
    # a Malware/Tool question that happens to retrieve a related Actor as
    # secondary context (e.g. "What does RIPTIDE do?" pulling in the actor
    # that uses it) would wrongly answer about that unrelated actor instead
    # of falling through to the Software renderer.
    primary_type = (nodes[0].get("node_type") or nodes[0].get("type")) if nodes else None
    if not requested_actors and primary_type != "Actor":
        return None

    actor = next(
        (
            node
            for node in nodes
            if (node.get("node_type") or node.get("type")) == "Actor"
            and (
                not requested_actors
                or str(node.get("name") or "").lower() in requested_actors
            )
        ),
        None,
    )
    if not actor:
        return None

    name = str(actor.get("name") or "Unknown actor")
    external_id = actor.get("external_id") or actor.get("id")
    lines = [f"{name} ({external_id})" if external_id else name]
    if actor.get("description"):
        lines.append(f"Description: {truncate_description(actor['description'], 400)}")

    labels = {
        "tactics": "Tactics",
        "techniques": "Techniques",
        "malware": "Malware",
        "tools": "Tools",
        "campaigns": "Campaigns",
    }
    for key in ("tactics", "techniques", "malware", "tools", "campaigns"):
        if requested_fields and key not in requested_fields and not is_broad_overview_query(query):
            continue
        values = actor.get(key) or []
        if isinstance(values, list) and values:
            lines.append(f"\n{labels[key]} explicitly connected to {name}:")
            lines.extend(f"- {value}" for value in values if value)

    if "mitigations" in requested_fields or is_broad_overview_query(query):
        mitigations = []
        for node in nodes:
            actors = node.get("actors") or []
            if not isinstance(actors, list) or name.lower() not in {
                str(value).lower() for value in actors
            }:
                continue
            for mitigation in node.get("mitigations") or []:
                if mitigation and mitigation not in mitigations:
                    mitigations.append(mitigation)
        if mitigations:
            lines.append(f"\nMitigations in retrieved {name}-related context:")
            lines.extend(f"- {value}" for value in mitigations)

    lines.append("\nRelationship-list entries are shown without IDs unless an exact name-ID pair was retrieved.")
    return "\n".join(lines)


def generate_campaign_overview(
    query: str,
    nodes: list[dict],
    filters: dict | None = None,
) -> str | None:
    """Render campaign relationships deterministically without inventing IDs."""
    requested_campaigns = {
        str(value).lower() for value in (filters or {}).get("campaign", [])
    }
    if not requested_campaigns:
        return None

    campaign = next(
        (
            node
            for node in nodes
            if (node.get("node_type") or node.get("type")) == "Campaign"
            and str(node.get("name") or "").lower() in requested_campaigns
        ),
        None,
    )
    if not campaign:
        return None

    asks_for_relationships = re.search(
        r"\b(?:techniques?|malware|tools?|actors?|groups?|detections?|strategies|logs?|data\s+sources?)\b",
        query,
        re.IGNORECASE,
    )
    if not asks_for_relationships and not is_broad_overview_query(query):
        return None

    name = str(campaign.get("name") or "Unknown campaign")
    external_id = campaign.get("external_id") or campaign.get("id")
    lines = [f"{name} ({external_id})" if external_id else name]
    if campaign.get("description"):
        lines.append(f"Description: {truncate_description(campaign['description'], 500)}")

    requested_fields = (
        ("Techniques", "techniques", r"\btechniques?\b"),
        ("Malware", "malware", r"\bmalware\b"),
        ("Tools", "tools", r"\btools?\b"),
        ("Actors", "actors", r"\b(?:actors?|groups?)\b"),
    )
    broad = is_broad_overview_query(query)
    for label, key, pattern in requested_fields:
        if not broad and not re.search(pattern, query, re.IGNORECASE):
            continue
        values = campaign.get(key) or []
        if isinstance(values, list) and values:
            lines.append(f"\n{label} explicitly connected to {name}:")
            lines.extend(f"- {value}" for value in values if value)

    requested_platforms = query_platforms(query)
    detections = []
    log_sources = []
    for node in nodes:
        campaigns = {str(value).lower() for value in node.get("campaigns") or [] if value}
        if name.lower() not in campaigns:
            continue
        platforms = {str(value).lower() for value in node.get("platforms") or [] if value}
        if requested_platforms and not requested_platforms.intersection(platforms):
            continue
        for value in node.get("detections") or node.get("detection_strategies") or []:
            if value and value not in detections:
                detections.append(value)
        for value in node.get("log_sources") or []:
            if value and value not in log_sources:
                log_sources.append(value)

    if re.search(r"\b(?:detect|detection|strategies)\b", query, re.IGNORECASE) and detections:
        lines.append(f"\nDetection strategies in retrieved {name}-related context:")
        lines.extend(f"- {value}" for value in detections)
    if re.search(r"\b(?:logs?|data\s+sources?)\b", query, re.IGNORECASE) and log_sources:
        lines.append(f"\nLog sources in retrieved {name}-related context:")
        lines.extend(f"- {value}" for value in log_sources)

    lines.append("\nRelationship-list entries are shown without IDs unless an exact name-ID pair was retrieved.")
    return "\n".join(lines)


def is_detection_query(query: str) -> bool:
    return bool(re.search(r"\b(?:detect|detection|logs?|data\s+sources?)\b", query, re.IGNORECASE))


def filtered_analytic_details(node: dict, query: str) -> list[str]:
    requested_platforms = query_platforms(query)
    details = node.get("analytic_details") or []
    rendered = []
    for detail in details:
        if not isinstance(detail, dict):
            continue
        platforms = {
            str(value).lower() for value in (detail.get("platforms") or []) if value
        }
        if requested_platforms and not requested_platforms.intersection(platforms):
            continue
        name = str(detail.get("name") or "").strip()
        description = str(detail.get("description") or "").strip()
        text = f"{name}: {description}" if name and description else name or description
        if text:
            rendered.append(text[:600])
    return rendered


def _relationship_primary_node(query: str, nodes: list[dict]) -> dict | None:
    requested_ids = [
        match.group(0).upper() for match in EXTERNAL_ID_RE.finditer(query or "")
    ]
    for requested_id in requested_ids:
        for node in nodes:
            external_id = str(node.get("external_id") or node.get("id") or "").upper()
            if external_id == requested_id:
                return node

    for node in nodes:
        if query_mentions(str(node.get("name") or ""), query):
            return node
    return nodes[0] if nodes else None


# Filter keys that only scope a search (never identify a specific subject
# entity). Any OTHER populated filter key means the guardrail resolved a real
# named/ID'd subject, which is what a relationship query needs to be answerable.
_SUBJECT_SCOPE_FILTER_KEYS = {"node_type", "platform", "platforms"}


def relationship_subject_unresolved(
    query: str, nodes: list[dict], filters: dict | None = None
) -> bool:
    """True when a query expresses a subject-relationship intent (e.g. "what
    malware does X use") but its subject failed to resolve, so retrieval only
    returned unrelated object-type neighbours. Without this guard a renderer
    would answer about an arbitrary wrong node (e.g. a typo'd short actor name
    like "Axoim" that scores just under the fuzzy threshold, leaving the
    pipeline to surface Malware nodes and pick the first one).

    Explicit MITRE/CVE IDs and CamelCase names are already covered by
    explicit_reference_status(); this only closes the plain-single-word gap
    those miss. Deliberately conservative: it fires only when NONE of a
    matching node name, an in-query ID match, or a resolved subject filter is
    present, so correctly-resolved queries (including tolerated typos that DO
    resolve, like "DragnoOK") are never refused.
    """
    if EXTERNAL_ID_RE.search(query or "") or CVE_ID_RE.search(query or ""):
        return False

    primary = _relationship_primary_node(query, nodes)
    if not primary:
        return False

    node_type = str(primary.get("node_type") or primary.get("type") or "")
    if not _relationship_intent(query, node_type):
        return False

    # A retrieved node whose name the user actually typed = confident subject.
    for node in nodes:
        if query_mentions(str(node.get("name") or ""), query):
            return False

    # The guardrail resolved a real subject entity into the filters.
    if filters:
        for key, value in filters.items():
            if key not in _SUBJECT_SCOPE_FILTER_KEYS and value:
                return False

    return True


def _relationship_intent(query: str, node_type: str) -> tuple[str, str, str | None] | None:
    """Return the requested relationship as (label, value key, detail key).

    All intent keywords are matched against the query with entity-name
    parentheticals removed, so a relationship word that happens to appear
    inside an entity's own MITRE name - "Detect" in DET0001's name,
    "Analytic" in AN0001's name, "Software" as a technique name - never
    hijacks the routing. Only the user's actual intent wording counts.
    """
    q = _without_entity_name_parentheticals(query)
    if node_type == "DetectionStrategy" and re.search(r"\bAN\d{4}\b", q, re.IGNORECASE):
        return "Analytics", "analytics", "analytic_details"
    if node_type == "Analytic" and re.search(r"\bDC\d{4}\b", q, re.IGNORECASE):
        return "Data Components", "log_sources", "data_component_details"
    if re.search(r"\bparent\s+technique\b", q, re.IGNORECASE):
        return "Parent Technique", "parent_technique", "parent_technique_detail"
    if re.search(r"\bsub-?techniques?\b", q, re.IGNORECASE):
        return "Subtechniques", "subtechniques", "subtechnique_details"
    # Explicit "data component(s)" wins over generic detect/detection wording
    # (e.g. "which data components support detection of T####" must not route
    # to detection strategies). Skipped when the subject IS a DataComponent,
    # where the phrase names the subject itself, not the requested relationship
    # (then fall through so "which analytics use DC####" resolves to analytics).
    if node_type != "DataComponent" and re.search(r"\bdata\s+components?\b", q, re.IGNORECASE):
        return "Data Components", "log_sources", "data_component_details"
    # An explicit "analytics" object noun wins over generic detect/detection wording.
    if re.search(r"\banalytics?\b", q, re.IGNORECASE):
        return "Analytics", "analytics", "analytic_details"
    if re.search(r"\bdetection\s+strateg(?:y|ies)\b", q, re.IGNORECASE):
        return (
            "Detection Strategies",
            "detection_strategies" if node_type == "Analytic" else "detections",
            "detection_strategy_details",
        )
    if node_type == "Technique" and re.search(
        r"\b(?:detect|detects|detected|detection)\b", q, re.IGNORECASE
    ):
        return "Detection Strategies", "detections", "detection_strategy_details"
    # A DetectionStrategy detects Techniques; "does DET#### detect T####" must
    # render its technique list (grounded), not fall to a free-form profile dump.
    if node_type == "DetectionStrategy" and re.search(
        r"\b(?:detect|detects|detected|detection)\b", q, re.IGNORECASE
    ):
        return "Techniques", "techniques", "technique_details"
    if (
        re.search(r"\b(?:countermeasures?|mitigations?)\b", q, re.IGNORECASE)
        or (node_type == "Technique" and re.search(r"\bmitigates?\b", q, re.IGNORECASE))
    ):
        return "Mitigations", "mitigations", "mitigation_details"
    if (
        node_type == "Mitigation"
        and re.search(r"\b(?:prevent|prevents|mitigate|mitigates|mitigated)\b", q, re.IGNORECASE)
    ):
        return "Techniques", "techniques", "technique_details"
    if re.search(r"\btactics?\b", q, re.IGNORECASE):
        return "Tactics", "tactics", "tactic_details"
    if re.search(r"\b(?:actors?|groups?)\b", q, re.IGNORECASE):
        return "Actors", "actors", "actor_details"
    if (
        re.search(r"\bmalware\b", q, re.IGNORECASE)
        and re.search(r"\btools?\b", q, re.IGNORECASE)
    ):
        return "Software", "software", None
    if re.search(r"\b(?:techniques?|techniqes?)\b", q, re.IGNORECASE):
        return "Techniques", "techniques", "technique_details"
    if re.search(r"\bcampaigns?\b", q, re.IGNORECASE):
        return "Campaigns", "campaigns", "campaign_details"
    if re.search(r"\bmalware\b", q, re.IGNORECASE):
        return "Malware", "malware", "malware_details"
    if re.search(r"\btools?\b", q, re.IGNORECASE):
        return "Tools", "tools", "tool_details"
    return None


def _relationship_items(node: dict, value_key: str, detail_key: str | None) -> list[str]:
    details = node.get(detail_key) if detail_key else None
    if isinstance(details, list) and details:
        rendered = []
        for detail in details:
            if not isinstance(detail, dict):
                continue
            name = str(detail.get("name") or "").strip()
            external_id = str(detail.get("external_id") or "").strip()
            if name:
                rendered.append(f"{name} ({external_id})" if external_id else name)
        if rendered:
            return rendered

    values = node.get(value_key) or []
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if value]


def generate_requested_relationship_summary(query: str, nodes: list[dict]) -> str | None:
    """Render the relationship explicitly requested instead of a generic profile."""
    node = _relationship_primary_node(query, nodes)
    if not node:
        return None

    node_type = str(node.get("node_type") or node.get("type") or "")
    intent = _relationship_intent(query, node_type)
    if not intent:
        return None

    label, value_key, detail_key = intent
    name = str(node.get("name") or "Unknown")
    external_id = str(node.get("external_id") or node.get("id") or "")
    heading = f"{name} ({external_id})" if external_id else name

    if value_key == "software":
        malware = _relationship_items(node, "malware", "malware_details")
        tools = _relationship_items(node, "tools", "tool_details")
        if not malware and not tools:
            return f"No malware or tools are recorded for {heading} in the knowledge graph."
        lines = [f"Software explicitly connected to {heading}:"]
        if malware:
            lines.append("Malware:")
            lines.extend(f"- {value}" for value in malware)
        if tools:
            lines.append("Tools:")
            lines.extend(f"- {value}" for value in tools)
        return "\n".join(lines)

    if value_key == "parent_technique":
        detail = node.get(detail_key) if detail_key else None
        if isinstance(detail, dict) and detail.get("name"):
            related_name = str(detail["name"])
            related_id = str(detail.get("external_id") or "")
            related = f"{related_name} ({related_id})" if related_id else related_name
        else:
            related = str(node.get(value_key) or "").strip()
        if related:
            return f"Parent Technique of {heading}:\n- {related}"
        return f"No parent technique is recorded for {heading} in the knowledge graph."

    requested_ids = [
        match.group(0).upper() for match in EXTERNAL_ID_RE.finditer(query or "")
    ]
    if len(requested_ids) > 1 and re.search(
        r"\b(?:does|is|has|have|associated|belong)\b", query, re.IGNORECASE
    ):
        target_id = requested_ids[1]
        linked_ids = {
            str(detail.get("external_id") or "").upper()
            for detail in (node.get(detail_key) or [])
            if isinstance(detail, dict)
        } if detail_key else set()
        if linked_ids:
            verdict = "Yes" if target_id in linked_ids else "No"
            return (
                f"{verdict}. {target_id} is "
                f"{'explicitly connected' if verdict == 'Yes' else 'not explicitly connected'} "
                f"to {heading} by the requested relationship in the knowledge graph."
            )

    if value_key == "analytics":
        requested_platforms = query_platforms(query)
        details = node.get("analytic_details") or []
        if isinstance(details, list) and details:
            matching_details = []
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                platforms = {
                    str(value).lower() for value in detail.get("platforms") or [] if value
                }
                if requested_platforms and not requested_platforms.intersection(platforms):
                    continue
                matching_details.append(detail)
            items = []
            for detail in matching_details:
                analytic_name = str(detail.get("name") or "").strip()
                analytic_id = str(detail.get("external_id") or "").strip()
                if analytic_name:
                    items.append(
                        f"{analytic_name} ({analytic_id})" if analytic_id else analytic_name
                    )
        else:
            items = [] if requested_platforms else _relationship_items(
                node, value_key, detail_key
            )
        if items:
            return "\n".join([
                f"Analytics explicitly connected to {heading}:",
                *(f"- {value}" for value in items),
            ])
        if requested_platforms:
            platforms = ", ".join(sorted(requested_platforms))
            return (
                f"No analytics with the requested platform ({platforms}) are "
                f"recorded for {heading} in the knowledge graph."
            )
        return f"No analytics are recorded for {heading} in the knowledge graph."

    items = _relationship_items(node, value_key, detail_key)

    if items:
        lines = [
            f"{label} explicitly connected to {heading}:",
            *(f"- {value}" for value in items),
        ]
        # "How is T#### detected?" wants the detection strategy AND the analytic
        # IDs under it. Only the technique->detection path carries these, so
        # append them when rendering a Technique's detection strategies.
        if value_key == "detections" and node_type == "Technique":
            analytics = _relationship_items(node, "analytics", "detection_analytic_details")
            if analytics:
                lines.append("Supporting analytics:")
                lines.extend(f"- {value}" for value in analytics)
        return "\n".join(lines)
    return f"No {label.lower()} are recorded for {heading} in the knowledge graph."


def generate_exact_id_summary(query: str, nodes: list[dict]) -> str | None:
    """Answer explicit MITRE ID lookups without allowing model substitutions."""
    requested_ids = list(dict.fromkeys(
        match.group(0).upper() for match in EXTERNAL_ID_RE.finditer(query or "")
    ))
    if not requested_ids:
        return None

    nodes_by_id = {
        str(node.get("external_id") or node.get("id") or "").upper(): node
        for node in nodes
    }
    blocks = []
    for requested_id in requested_ids:
        node = nodes_by_id.get(requested_id)
        if not node:
            continue
        external_id = str(node.get("external_id") or node.get("id") or "")
        name = node.get("name") or "Unknown"
        node_type = node.get("node_type") or node.get("type")
        lines = [f"{name} ({external_id})"]
        if node_type:
            lines.append(f"Type: {node_type}")
        if node.get("description"):
            lines.append(f"Description: {truncate_description(node['description'], 400)}")
        for label, key in (
            ("Platforms", "platforms"),
            ("Tactics", "tactics"),
            ("Techniques", "techniques"),
            ("Actors", "actors"),
            ("Malware", "malware"),
            ("Tools", "tools"),
            ("Campaigns", "campaigns"),
            ("Mitigations", "mitigations"),
            ("Subtechniques", "subtechniques"),
        ):
            values = node.get(key) or []
            if isinstance(values, list) and values:
                lines.append(f"{label}: {', '.join(str(value) for value in values if value)}")
        if node.get("parent_technique"):
            lines.append(f"Parent Technique: {node['parent_technique']}")
        if is_detection_query(query):
            for label, values in (
                (
                    "Detection Strategies",
                    node.get("detection_strategies") or node.get("detections") or [],
                ),
                ("Log Sources", node.get("log_sources") or []),
            ):
                if isinstance(values, list) and values:
                    lines.append(f"{label}: {', '.join(str(value) for value in values if value)}")
            analytics = filtered_analytic_details(node, query)
            if (
                not analytics
                and not node.get("analytic_details")
                and not query_platforms(query)
            ):
                analytics = [str(value) for value in node.get("analytics") or [] if value]
            if analytics:
                lines.append("Analytics:")
                lines.extend(f"- {value}" for value in analytics)
        blocks.append("\n".join(lines))

    return "\n\n---\n\n".join(blocks) if blocks else None


def generate_mixed_lookup_summary(query: str, nodes: list[dict]) -> str | None:
    if not re.search(r"\b(?:tell\s+me\s+about|what\s+is|show\s+me)\b", query, re.IGNORECASE):
        return None
    if not EXTERNAL_ID_RE.search(query or ""):
        return None
    if re.search(r"\b(?:use|uses|using|detect|detection|mitigate|mitigation|compare|versus)\b", query, re.IGNORECASE):
        return None

    blocks = []
    actor_nodes = [
        node
        for node in nodes
        if (node.get("node_type") or node.get("type")) == "Actor"
        and query_mentions(str(node.get("name") or ""), query)
    ]
    for actor in actor_nodes:
        external_id = actor.get("external_id") or actor.get("id")
        heading = f"{actor.get('name')} ({external_id})" if external_id else str(actor.get("name") or "Unknown")
        lines = [heading]
        if actor.get("description"):
            lines.append(f"Description: {truncate_description(actor['description'], 400)}")
        aliases = actor.get("aliases") or []
        if isinstance(aliases, list) and aliases:
            lines.append(f"Aliases: {', '.join(str(value) for value in aliases if value)}")
        blocks.append("\n".join(lines))

    id_summary = generate_exact_id_summary(query, nodes)
    if id_summary:
        blocks.append(id_summary)

    return "\n\n---\n\n".join(blocks) if blocks else None


def format_examples(values: list, limit: int = MAX_COMPARISON_FIELD_ITEMS) -> str:
    clean_values = [str(value) for value in values if value]
    if not clean_values:
        return "None shown in context"
    text = ", ".join(clean_values[:limit])
    if len(clean_values) > limit:
        text = f"{text}, ..."
    return text


def shared_values(value_lists: list[list]) -> list[str]:
    """Values present in every list (case-insensitive), preserving the
    first list's original casing/order."""
    if not value_lists:
        return []
    normalized_sets = [
        {str(value).lower() for value in values if value} for values in value_lists
    ]
    common = set.intersection(*normalized_sets) if normalized_sets else set()
    first = value_lists[0]
    seen = set()
    result = []
    for value in first:
        if not value:
            continue
        key = str(value).lower()
        if key in common and key not in seen:
            seen.add(key)
            result.append(str(value))
    return result


def generate_actor_comparison(query: str, nodes: list[dict]) -> str | None:
    if not is_comparison_query(query):
        return None

    actors = mentioned_actor_nodes(nodes, query)
    if len(actors) < 2:
        return None

    names = [actor.get("name", "Unknown") for actor in actors]
    ids = [actor.get("external_id") or actor.get("id") for actor in actors]
    headings = [
        f"{name} ({id_})" if id_ else name for name, id_ in zip(names, ids)
    ]

    lines = [f"Comparison: {' vs '.join(headings)}", ""]

    for actor, name in zip(actors, names):
        if actor.get("description"):
            lines.append(f"{name}: {truncate_description(actor['description'], 300)}")

    fields = [
        ("Tactics", "tactics"),
        ("Techniques", "techniques"),
        ("Malware", "malware"),
        ("Tools", "tools"),
        ("Campaigns", "campaigns"),
    ]

    for label, key in fields:
        value_lists = [actor.get(key) or [] for actor in actors]
        if not any(value_lists):
            continue

        shared = shared_values(value_lists)
        lines.extend(["", f"{label}:", f"- Shared examples: {format_examples(shared)}"])
        lines.extend(
            f"- {name} examples: {format_examples(values)}"
            for name, values in zip(names, value_lists)
        )

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
            lines.append(f"Description: {truncate_description(node['description'], 400)}")

        fields = [
            ("Aliases", "aliases"),
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

        analytics = filtered_analytic_details(node, query)
        if analytics:
            lines.append(f"Analytics: {' | '.join(analytics)}")

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
            if key == "analytics" and node.get("analytic_details"):
                continue
            if key == "analytics" and platforms_in_query:
                continue
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

    if is_unsupported_count_query(query) or is_unsupported_meta_query(query):
        return "I don't have enough information about this in my knowledge base."

    nodes = filter_platform_actor_context(nodes, query)
    nodes = filter_context_by_validated_relationships(nodes, filters)
    if not nodes:
        return "I don't have enough information about this in my knowledge base."

    # A query can name several entities where only some are real (e.g. a
    # valid actor plus a made-up one). Refuse only if NONE of the named
    # entities resolve; if at least one does, answer about that one and
    # note the rest weren't found, instead of discarding a fully-grounded
    # answer over an unrelated unresolved token.
    resolved_refs, unresolved_refs = explicit_reference_status(query, nodes)
    resolved_by_filter = validated_filter_resolves_context(filters, nodes)
    if unresolved_refs and not resolved_refs and not resolved_by_filter:
        return "I don't have enough information about this in my knowledge base."

    # A plain-word subject (not an ID/CamelCase name) that failed to resolve
    # slips past explicit_reference_status; refuse rather than answer about an
    # arbitrary unrelated node the semantic search happened to surface.
    if relationship_subject_unresolved(query, nodes, filters):
        return "I don't have enough information about this in my knowledge base."

    answer = _build_answer(query, nodes, filters)
    if unresolved_refs and answer and not resolved_by_filter:
        answer += (
            f"\n\nNote: I don't have information about "
            f"{', '.join(unresolved_refs)} in my knowledge base."
        )
    return answer


def _build_answer(query: str, nodes: list[dict], filters: dict | None = None) -> str:
    telemetry_summary = generate_telemetry_indicator_summary(query, nodes)
    if telemetry_summary:
        return telemetry_summary

    relationship_summary = generate_requested_relationship_summary(query, nodes)
    if relationship_summary:
        return relationship_summary

    overview = generate_actor_overview(query, nodes, filters)
    if overview:
        return overview

    campaign_overview = generate_campaign_overview(query, nodes, filters)
    if campaign_overview:
        return campaign_overview

    if is_id_focused_filter_scope(filters):
        exact_id_summary = generate_exact_id_summary(query, nodes)
        if exact_id_summary:
            return exact_id_summary

    mixed_lookup = generate_mixed_lookup_summary(query, nodes)
    if mixed_lookup:
        return mixed_lookup

    actor_relationships = generate_actor_relationship_list(query, nodes)
    if actor_relationships:
        return actor_relationships

    software_relationships = generate_software_relationship_list(query, nodes)
    if software_relationships:
        return software_relationships

    tactic_relationships = generate_tactic_relationship_list(query, nodes)
    if tactic_relationships:
        return tactic_relationships

    mitigation_relationships = generate_mitigation_relationship_list(query, nodes)
    if mitigation_relationships:
        return mitigation_relationships

    actor_usage = generate_actor_usage_list(query, nodes)
    if actor_usage:
        return actor_usage

    comparison = generate_actor_comparison(query, nodes)
    if comparison:
        return comparison

    context = format_context(nodes, query)

    response = OLLAMA_CLIENT.chat(
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
---

Question: {query}

Critical answer constraints:
- Answer based strictly on the context above.
- If the specific fact or relationship asked about is absent from the context, say it was not found in the provided context; never substitute a plausible relationship.
- Internal retrieval filters are not relationship evidence and must never be used as facts.
- Do not include caveated items that are not explicitly connected in the context.
- Do not count comma-separated relationship-list items.
- For comparisons, compare explicit facts and examples only; do not use broader/narrower range wording unless the context provides written counts.
- Do not group techniques by tactic unless the question explicitly asks for that grouping.
- Format using stable labels when applicable:
  - Single item: `Description: ...`, `Type: ...`, `Platforms: ...`, `Tactics: ...`, etc.
  - Lists: `Techniques:` then markdown bullets.
  - Explanations/comparisons: bullets like `- **Tactic:** ...`, `- **Technique:** ...`, `- **Procedure:** ...`.

Answer:""",
            },
        ],
        options={"temperature": 0},
    )

    return sanitize_generated_ids(response["message"]["content"].strip(), nodes)


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
