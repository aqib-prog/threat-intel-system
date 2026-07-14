"""Renders log-analysis technique matches into the same markdown shape the
existing RAG path produces (Techniques / Tactics / Detection Strategies /
Mitigations / Strongest Evidence category-card sections) so the frontend's
existing rendering (MarkdownMessage, category cards) needs no changes.

Deliberately does not call generation.generate.generate_telemetry_indicator_summary
- that function re-derives technique names from the query text via the old,
narrower telemetry_technique_names() list, which would ignore this card's
richer, multi-platform analyzer output entirely.
"""

import re

from log_analysis.analyzer import TechniqueMatch


MAX_LIST_ITEMS = 12
PLAIN_PLATFORM_COMMAND_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\s+\S+\s+(?:mac|macos|linux|windows|win)\s+(.+)$",
    re.IGNORECASE,
)
KV_PROCESS_RE = re.compile(
    r"\b(?:ProcessName|ParentProcess|Image|NewProcessName|Application|Command|exe)\s*=\s*\"?([^\"\s]+)",
    re.IGNORECASE,
)
COMMAND_LINE_RE = re.compile(r"\bCommandLine\s*=\s*\"?(.+?)(?:\"\s+\w+=|$)", re.IGNORECASE)
KNOWN_CLI_TOOLS = {
    "adfind",
    "bash",
    "certutil",
    "chflags",
    "cmd",
    "copy",
    "curl",
    "defaults",
    "dot_clean",
    "history",
    "launchctl",
    "net",
    "osascript",
    "plutil",
    "powershell",
    "rar",
    "reg",
    "rundll32",
    "sc",
    "security",
    "sh",
    "spctl",
    "tccutil",
    "vssadmin",
    "wevtutil",
    "wget",
    "whoami",
    "xattr",
    "zsh",
}


def _add_unique(target: list[str], values) -> None:
    if isinstance(values, str):
        values = [values]
    for value in values or []:
        text = str(value or "").strip()
        if text and text not in target:
            target.append(text)


def _command_name(value: str) -> str | None:
    token = value.strip().strip("\"'").split()[0] if value.strip() else ""
    if not token:
        return None
    token = token.replace("\\\\", "\\")
    name = re.split(r"[\\/]", token)[-1].strip("\"'")
    if not name:
        return None
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name


def _extract_observed_tools(matches: list[TechniqueMatch]) -> list[str]:
    """Return tools/commands actually visible in the submitted telemetry.

    This intentionally does not use graph relationships such as
    (:Tool)-[:USES]->(:Technique); those mean "known software related to this
    ATT&CK technique", not "observed in this log paste".
    """
    tools: list[str] = []

    for match in matches:
        line = match.matched_line

        for regex_match in KV_PROCESS_RE.finditer(line):
            _add_unique(tools, [_command_name(regex_match.group(1))])

        command_line = COMMAND_LINE_RE.search(line)
        if command_line:
            _add_unique(tools, [_command_name(command_line.group(1))])

        platform_command = PLAIN_PLATFORM_COMMAND_RE.search(line)
        if platform_command:
            _add_unique(tools, [_command_name(platform_command.group(1))])

        lowered = line.lower()
        for known in KNOWN_CLI_TOOLS:
            if re.search(rf"(?<![\w.-]){re.escape(known)}(?:\.exe)?(?![\w.-])", lowered):
                _add_unique(tools, [known])

    return tools


def _extract_observed_platforms(matches: list[TechniqueMatch]) -> list[str]:
    platforms: list[str] = []
    platform_patterns = [
        ("macOS", re.compile(r"(?<![\w.-])(?:mac|macos)(?![\w.-])", re.IGNORECASE)),
        ("Windows", re.compile(r"(?<![\w.-])(?:win|windows|eventid|powershell|cmd\.exe)(?![\w.-])", re.IGNORECASE)),
        ("Linux", re.compile(r"(?<![\w.-])(?:linux|auditd|syslog|/bin/|/etc/|/var/log/)(?![\w.-])", re.IGNORECASE)),
        ("AWS", re.compile(r"(?<![\w.-])(?:aws|cloudtrail|eventname)(?![\w.-])", re.IGNORECASE)),
        ("Kubernetes", re.compile(r"(?<![\w.-])(?:kubernetes|k8s|kubectl|pod|daemonset)(?![\w.-])", re.IGNORECASE)),
    ]

    for match in matches:
        for platform, pattern in platform_patterns:
            if pattern.search(match.matched_line):
                _add_unique(platforms, [platform])

    return platforms


def format_log_analysis_answer(
    matches: list[TechniqueMatch],
    graph_nodes: list[dict],
) -> str:
    if not matches:
        return "I don't have enough information about this in my knowledge base."

    node_by_name = {str(node.get("name") or "").lower(): node for node in graph_nodes}
    matched_nodes = [
        (match, node_by_name[match.technique_name.lower()])
        for match in matches
        if match.technique_name.lower() in node_by_name
    ]
    if not matched_nodes:
        return "I don't have enough information about this in my knowledge base."

    lines = ["Based on the provided log data, the strongest ATT&CK mappings are:", "", "Techniques:"]
    for _, node in matched_nodes:
        name = node.get("name") or "Unknown"
        external_id = node.get("external_id") or node.get("id")
        lines.append(f"- {name} ({external_id})" if external_id else f"- {name}")

    tactics: list[str] = []
    detections: list[str] = []
    mitigations: list[str] = []
    data_sources: list[str] = []
    observed_tools = _extract_observed_tools(matches)
    observed_platforms = _extract_observed_platforms(matches)
    for _, node in matched_nodes:
        _add_unique(tactics, node.get("tactics"))
        _add_unique(detections, node.get("detections") or node.get("detection_strategies"))
        _add_unique(mitigations, node.get("mitigations"))
        _add_unique(data_sources, node.get("log_sources") or node.get("data_sources"))

    if tactics:
        lines += ["", "Tactics:", *(f"- {value}" for value in tactics[:MAX_LIST_ITEMS])]
    if observed_tools:
        lines += ["", "Tools:", *(f"- {value}" for value in observed_tools[:MAX_LIST_ITEMS])]
    if observed_platforms:
        lines += ["", "Platforms:", *(f"- {value}" for value in observed_platforms[:MAX_LIST_ITEMS])]
    if detections:
        lines += ["", "Detection Strategies:", *(f"- {value}" for value in detections[:MAX_LIST_ITEMS])]
    if data_sources:
        lines += ["", "Data Sources:", *(f"- {value}" for value in data_sources[:MAX_LIST_ITEMS])]
    if mitigations:
        lines += ["", "Mitigations:", *(f"- {value}" for value in mitigations[:MAX_LIST_ITEMS])]

    evidence_lines = []
    for match, node in matched_nodes:
        name = node.get("name") or "Unknown"
        external_id = node.get("external_id") or node.get("id")
        heading = f"{name} ({external_id})" if external_id else name
        evidence_lines.append(f"- {heading}: {match.reason}")
    if evidence_lines:
        lines += ["", "Strongest Evidence:", *evidence_lines[:MAX_LIST_ITEMS]]

    return "\n".join(lines)
