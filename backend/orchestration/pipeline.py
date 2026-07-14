"""End-to-end orchestration for the threat-intelligence GraphRAG backend.

Flow: guardrail -> filter extraction -> contextual hybrid search -> graph
traversal -> reranking -> grounded generation -> structured response.
"""

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

from neo4j import GraphDatabase

from config import NEO4J_PASSWORD, NEO4J_URI, NEO4J_USER
from generation.generate import generate
from log_analysis import detector as log_analysis_detector
from log_analysis.analyzer import analyze as analyze_log_evidence
from log_analysis.formatter import format_log_analysis_answer
from log_analysis.parser import parse_log
from retrieval.graph_traversal import traverse_nodes
from retrieval.guardrail import check_blacklist, extract_filters, guardrail
from retrieval.reranker import rerank
from retrieval.semantic_search import is_low_signal_query, search


FALLBACK = "I don't have enough information about this in my knowledge base."
MIN_RELEVANCE_SCORE = float(os.getenv("MIN_RERANK_RELEVANCE_SCORE", "0.5"))
REQUESTED_MITRE_ID_RE = re.compile(
    r"\b[GMSTC]A?\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)
REQUESTED_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
COUNT_QUERY_RE = re.compile(r"\b(?:how\s+many|count|number\s+of|total)\b", re.IGNORECASE)
SPACED_ATTACK_ID_RE = re.compile(
    r"\b(?P<prefix>[GMSTC]A?)\s+(?P<num>\d{4})(?:\s*\.\s*(?P<sub>\d{3}))?\b",
    re.IGNORECASE,
)
SECURITY_SEGMENT_RE = re.compile(
    r"\b(?:cyber(?:security)?|security\s+investigation|threat|attack(?:er|ers)?|"
    r"malware|ransomware|phishing|adversar(?:y|ies)|detect(?:ion)?|logs?|"
    r"events?|telemetry|logon|admin\s+share|remote\s+service|service\s+creation|"
    r"event\s*id|eventid|process\s*name|processname|command\s*line|commandline|"
    r"account\s*name|accountname|source\s*ip|sourceip|destination\s*ip|destinationip|"
    r"share\s*name|sharename|authentication\s*package|authenticationpackage|"
    r"object\s*name|objectname|access\s*mask|accessmask|"
    r"powershell|cmd\.exe|sc\.exe|reg\.exe|rundll32|wevtutil|vssadmin|"
    r"mitre|techniques?|tactics?|campaigns?|mitigations?|analytics?|"
    r"data\s+sources?|actors?|tools?|credential|persistence|"
    r"lateral\s+movement|APT\s*\d+|[GMSTC]A?\d{4}(?:\.\d{3})?|"
    r"CVE-\d{4}-\d{4,7})\b",
    re.IGNORECASE,
)


def focus_security_query(query: str) -> str:
    """Remove unrelated conversational segments when a security question is present."""
    segments = [
        segment.strip(" \t\r\n.,;:")
        for segment in re.split(r"(?<=[.!?])\s+|\n+|\bseparately\b[:,]?", query, flags=re.IGNORECASE)
        if segment.strip(" \t\r\n.,;:")
    ]
    if len(segments) <= 1:
        return query

    security_segments = [segment for segment in segments if SECURITY_SEGMENT_RE.search(segment)]
    return " ".join(security_segments) if security_segments else query


def normalize_spaced_attack_ids(query: str) -> str:
    def replace(match: re.Match) -> str:
        value = f"{match.group('prefix')}{match.group('num')}"
        if match.group("sub"):
            value = f"{value}.{match.group('sub')}"
        return value.upper()

    return SPACED_ATTACK_ID_RE.sub(replace, query)


def is_unsupported_count_query(query: str) -> bool:
    return bool(COUNT_QUERY_RE.search(query))


def has_unresolved_explicit_id(query: str, filters: dict[str, Any]) -> bool:
    """True only if NONE of the explicitly-referenced MITRE/CVE IDs in the
    query resolve against the graph.

    A query naming several IDs where only one is fake (e.g. "T1078,
    T1059.001, and T9999") should still be answerable for the real ones -
    refusing the whole answer over one bad ID mixed in with good ones
    discards real, correct data for no benefit. If at least one ID
    resolves, the pipeline proceeds with the valid one(s); generate.py's
    explicit_reference_status then notes any ID that didn't validate.
    """
    requested_mitre_ids = {
        match.group(0).upper() for match in REQUESTED_MITRE_ID_RE.finditer(query)
    }
    validated_mitre_ids = {
        str(value).upper() for value in filters.get("mitre_id", []) if value
    }
    if requested_mitre_ids and not (requested_mitre_ids & validated_mitre_ids):
        return True

    requested_cve_ids = {
        match.group(0).upper() for match in REQUESTED_CVE_ID_RE.finditer(query)
    }
    validated_cve_ids = {
        str(value).upper() for value in filters.get("cve_id", []) if value
    }
    if requested_cve_ids and not (requested_cve_ids & validated_cve_ids):
        return True
    return False


def explicit_ids_exist(driver, query: str) -> bool:
    """Validate explicit identifiers before invoking LLM filter extraction.

    Returns False (refuse) only when NONE of the explicitly-referenced
    MITRE/CVE IDs resolve against the graph. A query naming several IDs
    where only some are fake (e.g. "T1078, T1059.001, and T9999") should
    still proceed for the real ones - has_unresolved_explicit_id and
    generate.py's explicit_reference_status narrow to / annotate the valid
    subset once the pipeline continues past this check.
    """
    requested_mitre_ids = {
        match.group(0).upper() for match in REQUESTED_MITRE_ID_RE.finditer(query)
    }
    requested_cve_ids = {
        match.group(0).upper() for match in REQUESTED_CVE_ID_RE.finditer(query)
    }
    if not requested_mitre_ids and not requested_cve_ids:
        return True

    found_any = False
    with driver.session() as session:
        if requested_mitre_ids:
            records = session.run(
                "MATCH (n:MitreNode) WHERE n.external_id IN $ids "
                "RETURN collect(DISTINCT n.external_id) AS ids",
                ids=list(requested_mitre_ids),
            ).single()
            found_ids = {str(value).upper() for value in (records["ids"] or [])}
            if requested_mitre_ids & found_ids:
                found_any = True

        for cve_id in requested_cve_ids:
            record = session.run(
                "MATCH (n:MitreNode) "
                "WHERE toLower(n.description) CONTAINS toLower($cve_id) "
                "RETURN count(n) > 0 AS found",
                cve_id=cve_id,
            ).single()
            if record and record["found"]:
                found_any = True

    return found_any


def should_limit_to_exact_id_nodes(filters: dict[str, Any]) -> bool:
    """Only narrow retrieval to exact IDs for ID-focused queries.

    Mixed prompts can contain a MITRE ID plus other entities/questions. In that case
    the ID should seed retrieval, not discard the other validated context.
    """
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


def is_ambiguous_short_reference(query: str, filters: dict[str, Any]) -> bool:
    """Block short ambiguous fragments that are not validated graph entities."""
    if any(filters.values()):
        return False
    match = re.fullmatch(
        r"(?:tell\s+me\s+about|what\s+is|show\s+me)\s+([A-Za-z][A-Za-z-]{1,8})\??",
        query.strip(),
        re.IGNORECASE,
    )
    if not match:
        return False
    token = match.group(1)
    return not (
        token.isupper()
        or REQUESTED_MITRE_ID_RE.fullmatch(token)
        or REQUESTED_CVE_ID_RE.fullmatch(token)
    )


def fetch_filter_seed_nodes(driver, filters: dict[str, Any]) -> list[dict]:
    """Guarantee validated entities are present before semantic candidates."""
    parameters = {
        "actors": filters.get("threat_actor", []),
        "malware": filters.get("malware", []),
        "tools": filters.get("tool", []),
        "campaigns": filters.get("campaign", []),
        "tactics": filters.get("tactic", []),
        "ids": filters.get("mitre_id", []),
    }
    if not any(parameters.values()):
        return []

    with driver.session() as session:
        records = session.run(
            """
            MATCH (n:MitreNode)
            WHERE (n:Actor AND n.name IN $actors)
               OR (n:Malware AND n.name IN $malware)
               OR (n:Tool AND n.name IN $tools)
               OR (n:Campaign AND n.name IN $campaigns)
               OR (n:Tactic AND n.name IN $tactics)
               OR n.external_id IN $ids
            RETURN n.id AS id, n.name AS name, n.external_id AS external_id,
                   CASE
                       WHEN n:Actor THEN 'Actor'
                       WHEN n:Malware THEN 'Malware'
                       WHEN n:Tool THEN 'Tool'
                       WHEN n:Campaign THEN 'Campaign'
                       WHEN n:Tactic THEN 'Tactic'
                       WHEN n:Technique THEN 'Technique'
                       WHEN n:Mitigation THEN 'Mitigation'
                       WHEN n:DetectionStrategy THEN 'DetectionStrategy'
                       WHEN n:Analytic THEN 'Analytic'
                       WHEN n:DataComponent THEN 'DataComponent'
                       ELSE 'MitreNode'
                   END AS type
            """,
            **parameters,
        )
        seeds = [
            {
                "id": record["id"],
                "name": record["name"],
                "external_id": record["external_id"],
                "type": record["type"],
                "score": 10.0,
                "source": "validated_filter",
            }
            for record in records
        ]

        actors = parameters["actors"]
        tactics = parameters["tactics"]
        platforms = filters.get("platform", [])
        requested_types = filters.get("node_type", [])
        if actors and tactics and "Technique" in requested_types:
            related_records = session.run(
                """
                MATCH (a:Actor)-[:USES]->(t:Technique)-[:BELONGS_TO_TACTIC]->(tac:Tactic)
                WHERE a.name IN $actors
                  AND tac.name IN $tactics
                  AND (
                      size($platforms) = 0
                      OR any(platform IN t.platforms WHERE platform IN $platforms)
                  )
                RETURN DISTINCT t.id AS id, t.name AS name,
                       t.external_id AS external_id, 'Technique' AS type
                """,
                actors=actors,
                tactics=tactics,
                platforms=platforms,
            )
            known_ids = {seed["id"] for seed in seeds}
            for record in related_records:
                if record["id"] in known_ids:
                    continue
                known_ids.add(record["id"])
                seeds.append({
                    "id": record["id"],
                    "name": record["name"],
                    "external_id": record["external_id"],
                    "type": record["type"],
                    "score": 9.5,
                    "source": "validated_relationship",
                })

        return seeds


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


def fetch_telemetry_seed_nodes(driver, query: str) -> list[dict]:
    names = telemetry_technique_names(query)
    if not names:
        return []
    with driver.session() as session:
        records = session.run(
            """
            MATCH (n:MitreNode)
            WHERE n.name IN $names
            RETURN n.id AS id, n.name AS name, n.external_id AS external_id,
                   CASE
                       WHEN n:Technique THEN 'Technique'
                       WHEN n:Actor THEN 'Actor'
                       WHEN n:Malware THEN 'Malware'
                       WHEN n:Tool THEN 'Tool'
                       WHEN n:Campaign THEN 'Campaign'
                       WHEN n:Tactic THEN 'Tactic'
                       ELSE 'MitreNode'
                   END AS type
            """,
            names=names,
        )
        return [
            {
                "id": record["id"],
                "name": record["name"],
                "external_id": record["external_id"],
                "type": record["type"],
                "score": 9.8,
                "source": "telemetry_seed",
            }
            for record in records
        ]


def should_skip_semantic_search(
    query: str,
    filters: dict[str, Any],
    seed_nodes: list[dict],
) -> bool:
    """Use deterministic graph seeds directly for anchored lookup questions."""
    if not seed_nodes:
        return False
    if any(node.get("source") == "telemetry_seed" for node in seed_nodes):
        return True
    if filters.get("mitre_id"):
        return True
    if filters.get("campaign"):
        return True
    if filters.get("tactic") and re.search(
        r"\b(?:what\s+is|tell\s+me\s+about|show\s+me)\b",
        query,
        re.IGNORECASE,
    ):
        return True
    if filters.get("threat_actor") and not (
        filters.get("platform") and "Technique" in filters.get("node_type", [])
    ):
        return True
    return False


class PipelineError(RuntimeError):
    def __init__(self, stage: str, cause: Exception):
        self.stage = stage
        self.cause = cause
        super().__init__(f"Pipeline failed during {stage}: {cause}")


@dataclass
class Source:
    name: str
    external_id: str | None
    node_type: str
    relevance_score: float | None


@dataclass
class PipelineResult:
    query: str
    answer: str
    allowed: bool
    guardrail_category: str | None
    filters: dict[str, Any]
    sources: list[Source]
    retrieved_count: int
    context_count: int
    # "rag" (default) is the existing question-answering path this whole
    # module already implemented; "log_analysis" marks a response produced
    # by the deterministic raw-log branch below instead. Additive fields
    # only - every existing call site keeps working unchanged.
    answer_source: str = "rag"
    log_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def get_driver():
    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASSWORD),
        notifications_disabled_classifications=["DEPRECATION"],
    )
    driver.verify_connectivity()
    return driver


def fallback_result(
    query: str,
    category: str | None = None,
    filters: dict[str, Any] | None = None,
) -> PipelineResult:
    return PipelineResult(
        query=query,
        answer=FALLBACK,
        allowed=category is None,
        guardrail_category=category,
        filters=filters or {},
        sources=[],
        retrieved_count=0,
        context_count=0,
    )


def fetch_nodes_by_names(driver, matches: list) -> list[dict]:
    """Resolve exact Neo4j Technique nodes by name for the log-analysis
    branch - deliberately by name, not by a hardcoded technique_id, so the
    live graph (not this code) is always the source of truth for the
    current external_id (see this card's research notes on ATT&CK v19's
    technique renumbering). A few sub-technique names are reused under more
    than one parent technique (e.g. "Cloud Account" under both Account
    Discovery and Create Account) - matches.parent_hint disambiguates those
    via the SUBTECHNIQUE_OF relationship instead of guessing from name alone."""
    if not matches:
        return []
    items = [{"name": match.technique_name, "parent": match.parent_hint} for match in matches]
    with driver.session() as session:
        records = session.run(
            """
            UNWIND $items AS item
            MATCH (n:Technique {name: item.name})
            OPTIONAL MATCH (n)-[:SUBTECHNIQUE_OF]->(p:Technique)
            WITH n, item, p.name AS parent_name
            WHERE item.parent IS NULL OR parent_name = item.parent
            RETURN DISTINCT n.id AS id, n.name AS name, n.external_id AS external_id
            """,
            items=items,
        )
        return [
            {
                "id": record["id"],
                "name": record["name"],
                "external_id": record["external_id"],
                "type": "Technique",
                "score": 10.0,
                "source": "log_analysis",
            }
            for record in records
        ]


def run_log_analysis_pipeline(query: str, driver, platform: str | None) -> PipelineResult:
    """Isolated branch for genuinely large raw-log pastes (see
    backend/log_analysis/detector.py) - deterministic parsing and mapping
    instead of semantic search. Reuses traverse_nodes/Source from the
    existing RAG path but otherwise shares no code with it, so the
    question-answering path above is untouched by this branch's presence."""
    events = parse_log(query, platform)
    matches = analyze_log_evidence(events, platform)
    if not matches:
        # Distinct from the generic FALLBACK used for unrelated/unanswerable
        # questions - this tells the user their input WAS recognized as raw
        # telemetry, it just didn't match any of the current deterministic
        # rules (a coverage gap, not "this isn't a security question").
        return PipelineResult(
            query=query,
            answer=(
                "This looks like raw log/telemetry data, but none of it matched a "
                "known deterministic ATT&CK mapping rule in this system yet. No "
                "technique is being guessed - this is a coverage gap, not a "
                "negative result about the log itself."
            ),
            allowed=True,
            guardrail_category=None,
            filters={},
            sources=[],
            retrieved_count=0,
            context_count=0,
            answer_source="log_analysis",
        )

    seed_nodes = fetch_nodes_by_names(driver, matches)
    if not seed_nodes:
        return fallback_result(query)

    try:
        contexts = traverse_nodes(driver, seed_nodes)
    except Exception as exc:
        raise PipelineError("graph_traversal", exc) from exc
    if not contexts:
        return fallback_result(query)

    answer = format_log_analysis_answer(matches, contexts)
    match_by_name = {match.technique_name.lower(): match for match in matches}

    sources: list[Source] = []
    log_evidence: list[dict[str, Any]] = []
    for node in contexts:
        name = str(node.get("name") or "")
        match = match_by_name.get(name.lower())
        if not match:
            continue
        external_id = node.get("external_id") or node.get("id")
        sources.append(
            Source(
                name=name or "Unknown",
                external_id=external_id,
                node_type=str(node.get("node_type") or node.get("type") or "Technique"),
                relevance_score=10.0,
            )
        )
        log_evidence.append({
            "technique_id": external_id or "",
            "technique_name": name,
            "matched_line": match.matched_line,
            "confidence": match.confidence,
        })

    return PipelineResult(
        query=query,
        answer=answer,
        allowed=True,
        guardrail_category=None,
        filters={},
        sources=sources,
        retrieved_count=len(seed_nodes),
        context_count=len(contexts),
        answer_source="log_analysis",
        log_evidence=log_evidence,
    )


def run_pipeline(
    query: str,
    *,
    top_k: int = 8,
    candidate_k: int = 30,
) -> PipelineResult:
    """Run one query through the complete grounded GraphRAG pipeline."""
    query = normalize_spaced_attack_ids(str(query or "").strip())
    if not query:
        return fallback_result(query)
    if is_unsupported_count_query(query):
        return fallback_result(query)
    if top_k < 1 or candidate_k < top_k:
        raise ValueError("candidate_k must be greater than or equal to top_k >= 1")

    # Isolated branch: genuinely large raw-log pastes skip the
    # question-answering path entirely (see log_analysis/detector.py's
    # stricter, multi-signal bar - a short question that merely mentions a
    # field name never crosses it and falls through to the code below
    # exactly as it did before this branch existed).
    #
    # Detection runs BEFORE guardrail() deliberately: raw telemetry is
    # unconditionally cybersecurity-relevant, so only the deterministic
    # layer-1 blacklist (jailbreak/injection strings) applies to it -
    # guardrail()'s layer-2 LLM topic classifier asks "is this even about
    # cybersecurity?", a question that's both unnecessary for confirmed log
    # data and, being LLM-based, non-deterministic - reproduced directly
    # during testing: 1 of 15 identical calls got a false "not allowed" from
    # the LLM layer alone, which would otherwise make an entirely
    # deterministic analysis path randomly fail with no code-level cause.
    log_detection = log_analysis_detector.detect(query)
    if log_detection.is_raw_log:
        try:
            blacklist_result = check_blacklist(query)
        except Exception as exc:
            raise PipelineError("guardrail", exc) from exc
        if not blacklist_result.get("allowed", True):
            return fallback_result(query, category=blacklist_result.get("category", "blocked"))

        driver = None
        try:
            try:
                driver = get_driver()
            except Exception as exc:
                raise PipelineError("database_connection", exc) from exc
            return run_log_analysis_pipeline(query, driver, log_detection.platform)
        finally:
            if driver is not None:
                driver.close()

    try:
        guardrail_result = guardrail(query)
    except Exception as exc:
        raise PipelineError("guardrail", exc) from exc
    if not guardrail_result.get("allowed", True):
        return fallback_result(query, category=guardrail_result.get("category", "blocked"))

    focused_query = focus_security_query(query)
    if is_low_signal_query(focused_query):
        return fallback_result(query)

    driver = None
    try:
        try:
            driver = get_driver()
        except Exception as exc:
            raise PipelineError("database_connection", exc) from exc

        if not explicit_ids_exist(driver, focused_query):
            return fallback_result(query)

        try:
            filters = extract_filters(focused_query, driver)
        except Exception as exc:
            raise PipelineError("filter_extraction", exc) from exc
        if is_ambiguous_short_reference(focused_query, filters):
            return fallback_result(query, filters=filters)
        if has_unresolved_explicit_id(focused_query, filters):
            return fallback_result(query, filters=filters)

        telemetry_seed_nodes = fetch_telemetry_seed_nodes(driver, focused_query)
        telemetry_seed_names = {
            str(node.get("name") or "").lower()
            for node in telemetry_seed_nodes
            if node.get("name")
        }
        seed_nodes = telemetry_seed_nodes + fetch_filter_seed_nodes(driver, filters)
        try:
            semantic_nodes = [] if should_skip_semantic_search(
                focused_query,
                filters,
                seed_nodes,
            ) else search(focused_query, top_k=candidate_k, driver=driver)
        except Exception as exc:
            raise PipelineError("retrieval", exc) from exc
        retrieved = []
        seen_node_ids = set()
        for node in [*seed_nodes, *semantic_nodes]:
            node_id = node.get("id")
            if not node_id or node_id in seen_node_ids:
                continue
            seen_node_ids.add(node_id)
            retrieved.append(node)
            if len(retrieved) >= candidate_k:
                break
        if not retrieved:
            return fallback_result(query, filters=filters)

        requested_ids = {
            str(value).upper() for value in filters.get("mitre_id", []) if value
        }
        if requested_ids and should_limit_to_exact_id_nodes(filters):
            exact_id_nodes = [
                node
                for node in retrieved
                if str(node.get("external_id") or "").upper() in requested_ids
            ]
            if exact_id_nodes:
                retrieved = exact_id_nodes

        try:
            contexts = traverse_nodes(driver, retrieved)
        except Exception as exc:
            raise PipelineError("graph_traversal", exc) from exc
        if not contexts:
            return fallback_result(query, filters=filters)

        try:
            ranked = rerank(
                focused_query,
                contexts,
                top_k=top_k,
                filters=filters,
                candidate_k=candidate_k,
            )
        except Exception as exc:
            raise PipelineError("reranking", exc) from exc
        if telemetry_seed_names:
            telemetry_contexts = [
                {**node, "relevance_score": 10.0}
                for node in contexts
                if str(node.get("name") or "").lower() in telemetry_seed_names
            ]
            seen_ranked = {node.get("id") for node in telemetry_contexts}
            ranked = [
                *telemetry_contexts,
                *(node for node in ranked if node.get("id") not in seen_ranked),
            ][:top_k]
        if not ranked or float(ranked[0].get("relevance_score") or 0.0) < MIN_RELEVANCE_SCORE:
            return fallback_result(query, filters=filters)

        try:
            answer = generate(focused_query, ranked, filters=filters)
        except Exception as exc:
            raise PipelineError("generation", exc) from exc

        source_nodes = [] if not answer or answer.strip() == FALLBACK else ranked
        sources = [
            Source(
                name=str(node.get("name") or "Unknown"),
                external_id=node.get("external_id") or node.get("id"),
                node_type=str(node.get("node_type") or node.get("type") or "Unknown"),
                relevance_score=node.get("relevance_score"),
            )
            for node in source_nodes
        ]
        return PipelineResult(
            query=query,
            answer=answer or FALLBACK,
            allowed=True,
            guardrail_category=None,
            filters=filters,
            sources=sources,
            retrieved_count=len(retrieved),
            context_count=len(contexts),
        )
    finally:
        if driver is not None:
            driver.close()


def answer_query(query: str, **kwargs) -> str:
    """Convenience wrapper for callers that only need the final answer text."""
    return run_pipeline(query, **kwargs).answer


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the threat-intel GraphRAG pipeline")
    parser.add_argument("query", nargs="+", help="Question to answer")
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--candidate-k", type=int, default=30)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    try:
        result = run_pipeline(
            " ".join(args.query),
            top_k=args.top_k,
            candidate_k=args.candidate_k,
        )
    except (PipelineError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(result.answer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
