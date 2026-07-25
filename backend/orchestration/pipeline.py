"""End-to-end orchestration for the threat-intelligence GraphRAG backend.

Flow: guardrail -> filter extraction -> contextual hybrid search -> graph
traversal -> reranking -> grounded generation -> structured response.
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from neo4j import GraphDatabase

from config import NEO4J_PASSWORD, NEO4J_URI, NEO4J_USER
from generation.generate import format_context, generate
from observability import langfuse_tracing as obs
from log_analysis import detector as log_analysis_detector
from log_analysis.analyzer import analyze as analyze_log_evidence
from log_analysis.formatter import format_log_analysis_answer
from log_analysis.parser import parse_log
from retrieval.graph_traversal import traverse_nodes
from retrieval.guardrail import check_blacklist, check_llm_guardrail, extract_filters, guardrail
from retrieval.reranker import rerank
from retrieval.semantic_search import is_low_signal_query, search


FALLBACK = "I don't have enough information about this in my knowledge base."
MIN_RELEVANCE_SCORE = float(os.getenv("MIN_RERANK_RELEVANCE_SCORE", "0.5"))
REQUESTED_MITRE_ID_RE = re.compile(
    r"\b[GMSTC]A?\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)
REQUESTED_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# Actor ALIAS codes (APT29, FIN7, UNC2452) - these are actor names/aliases, NOT
# MITRE external_ids (which are G/T/S/M/C-prefixed and handled above). A near
# miss here changes the entity entirely (apt20 != apt2), so an alias code that
# does not resolve to a real actor must refuse, never fuzzy-substitute.
REQUESTED_ACTOR_CODE_RE = re.compile(r"\b(?:APT|FIN|UNC)\s?-?\d{1,5}\b", re.IGNORECASE)
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


def _normalize_actor_code(value: str) -> str:
    """Fold an actor code for exact comparison: lowercase, no spaces/dashes.
    'APT 29' / 'apt-29' / 'APT29' all -> 'apt29'."""
    return re.sub(r"[\s-]+", "", str(value or "")).lower()


def actor_codes_in_query(query: str) -> set[str]:
    """Normalized actor alias-codes explicitly referenced in the query."""
    return {
        _normalize_actor_code(match.group(0))
        for match in REQUESTED_ACTOR_CODE_RE.finditer(query)
    }


def resolve_actor_codes(driver, codes: set[str]) -> set[str]:
    """Return the subset of codes that EXACTLY match a real Actor name/alias.
    No fuzzy matching: for a structured code a one-character miss is a different
    group, so only an exact (normalized) hit counts."""
    if not codes:
        return set()
    with driver.session() as session:
        record = session.run(
            """
            MATCH (a:Actor)
            WITH [a.name] + coalesce(a.aliases, []) AS names
            UNWIND names AS nm
            WITH toLower(replace(replace(nm, ' ', ''), '-', '')) AS norm
            WHERE norm IN $codes
            RETURN collect(DISTINCT norm) AS found
            """,
            codes=list(codes),
        ).single()
    return {str(value) for value in (record["found"] if record else [])}


def actor_code_suggestions(driver, codes: set[str], limit: int = 4) -> list[str]:
    """Closest real actor names/aliases that share a code's alpha prefix, so an
    unknown 'apt20' can offer 'did you mean APT2 / APT28 / APT29'. Exact fuzzy
    ranking, but only as a non-authoritative suggestion - never auto-applied."""
    if not codes:
        return []
    prefixes = {re.match(r"[a-z]+", code).group(0) for code in codes if re.match(r"[a-z]+", code)}
    if not prefixes:
        return []
    with driver.session() as session:
        record = session.run(
            """
            MATCH (a:Actor)
            WITH [a.name] + coalesce(a.aliases, []) AS names
            UNWIND names AS nm
            WITH nm WHERE any(p IN $prefixes WHERE toLower(nm) STARTS WITH p)
            RETURN collect(DISTINCT nm) AS names
            """,
            prefixes=list(prefixes),
        ).single()
    candidates = list(record["names"]) if record and record["names"] else []
    if not candidates:
        return []
    from rapidfuzz import fuzz, process

    ranked: list[tuple[str, float]] = []
    for code in codes:
        for name, score, _ in process.extract(code, candidates, scorer=fuzz.ratio, limit=limit):
            ranked.append((name, score))
    ranked.sort(key=lambda item: item[1], reverse=True)
    seen: set[str] = set()
    ordered: list[str] = []
    for name, _ in ranked:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
        if len(ordered) >= limit:
            break
    return ordered


# ID/code-shaped reference tokens (T1055, G0016, S0001, apt29, TA0011...).
_REFERENCE_TOKEN_RE = re.compile(r"\b([A-Za-z]{1,4})[-\s]?(\d{2,6})(?:\.\d{1,3})?\b")
_MITRE_ID_PREFIXES = {"T", "G", "S", "M", "C", "TA", "DET", "AN", "DC", "DS"}
_ACTOR_CODE_PREFIXES = {"APT", "FIN", "UNC"}

# Subject-extraction for name-based "did you mean". Precise patterns (not raw
# n-grams) so we only fuzzy a real subject phrase, keeping suggestions clean.
_SUBJECT_PATTERNS = [
    re.compile(r"(?:what|who)(?:'s|\s+is|\s+are|\s+was|\s+were)\s+(.+?)[?.!]*$", re.IGNORECASE),
    re.compile(r"(?:tell me about|talk about|about|explain|describe|info on|profile of|details? (?:on|for|about))\s+(.+?)[?.!]*$", re.IGNORECASE),
    re.compile(r"\b(?:does|do|did|is|are|was|were)\s+(.+?)\s+(?:use|uses|used|deploy|run|have|attributed|connected|do)\b", re.IGNORECASE),
    re.compile(r"^(.+?)\s+(?:techniques?|malware|tools?|campaigns?|mitigations?|tactics?)\b", re.IGNORECASE),
]
_NAME_STOPWORDS = {
    "the", "a", "an", "of", "to", "for", "is", "are", "was", "were", "do", "does",
    "did", "what", "which", "who", "how", "that", "this", "in", "on", "and", "or",
    "use", "uses", "used", "have", "has", "you", "me", "about", "by", "with",
}
# Object nouns the user asks ABOUT - trimmed off the subject phrase. Deliberately
# excludes "group"/"actor" etc. because those are NAME components ("Lazarus
# Group"), not the object of the question.
_NAME_RELATION_WORDS = {
    "techniques", "technique", "malware", "tools", "tool", "campaigns", "campaign",
    "mitigations", "mitigation", "tactics", "tactic", "detections", "detection",
    "analytics", "software",
}
# Entity-name index cache (name -> external_id), short-lived like the API's id cache.
_ENTITY_NAME_INDEX: list[tuple[str, str]] | None = None
_ENTITY_NAME_INDEX_EXPIRES = 0.0


def _entity_name_index(driver) -> list[tuple[str, str]]:
    """Cached (name, external_id) for named entities + aliases. Powers name-based
    'did you mean'. A refresh failure keeps serving the last good cache (or [])."""
    global _ENTITY_NAME_INDEX, _ENTITY_NAME_INDEX_EXPIRES
    now = time.time()
    if _ENTITY_NAME_INDEX is not None and now < _ENTITY_NAME_INDEX_EXPIRES:
        return _ENTITY_NAME_INDEX
    try:
        with driver.session() as session:
            records = session.run(
                "MATCH (n) WHERE n.name IS NOT NULL AND "
                "(n:Actor OR n:Malware OR n:Tool OR n:Campaign OR n:Technique OR n:Mitigation) "
                "WITH n, [n.name] + coalesce(n.aliases, []) AS names "
                "UNWIND names AS nm RETURN DISTINCT nm AS name, n.external_id AS id"
            )
            # Drop very short names ("AT", "sh") - they match almost any string
            # via substring scoring and are pure suggestion noise.
            data = [
                (str(r["name"]), str(r["id"] or ""))
                for r in records
                if r["name"] and len(str(r["name"])) >= 4
            ]
    except Exception:
        return _ENTITY_NAME_INDEX or []
    _ENTITY_NAME_INDEX = data
    _ENTITY_NAME_INDEX_EXPIRES = now + 300
    return data


def _candidate_name_phrases(query: str) -> list[str]:
    """Extract the query's subject phrase(s) - the thing the user named - so we
    can fuzzy it against real entity names. Trims relation/stop words so
    'what techniques does Lazrus Grp use' yields 'Lazrus Grp'."""
    phrases: list[str] = []
    seen: set[str] = set()
    for pattern in _SUBJECT_PATTERNS:
        match = pattern.search(query or "")
        if not match:
            continue
        tokens = re.findall(r"[A-Za-z0-9.'/-]+", match.group(1))
        while tokens and tokens[-1].lower() in (_NAME_RELATION_WORDS | _NAME_STOPWORDS):
            tokens.pop()
        while tokens and tokens[0].lower() in _NAME_STOPWORDS:
            tokens.pop(0)
        phrase = " ".join(tokens).strip()
        key = phrase.lower()
        if len(phrase) >= 4 and key not in seen and not all(
            t.lower() in _NAME_STOPWORDS for t in tokens
        ):
            seen.add(key)
            phrases.append(phrase)
    return phrases


def reference_suggestions(driver, query: str, limit: int = 4) -> list[str]:
    """Closest real entities for any ID/code-shaped reference in the query that
    does NOT resolve exactly - so a "no information" answer can offer "did you
    mean" instead of a dead end. Covers malformed MITRE ids (T10557 -> T1055
    (Process Injection)) and actor codes (apt20 -> APT2). Returns [] when the
    query has no such reference at all (e.g. plain "how are you"), so chit-chat
    never gets spurious suggestions. Fail-safe: any error returns []."""
    tokens: list[tuple[str, str]] = []
    for match in _REFERENCE_TOKEN_RE.finditer(query or ""):
        prefix = match.group(1).upper()
        if prefix in _MITRE_ID_PREFIXES or prefix in _ACTOR_CODE_PREFIXES:
            tokens.append((prefix, re.sub(r"[\s-]+", "", match.group(0)).upper()))

    from rapidfuzz import fuzz, process

    ordered: list[str] = []
    seen: set[str] = set()
    try:
        with driver.session() as session:
            for prefix, token in tokens:
                if prefix in _ACTOR_CODE_PREFIXES:
                    record = session.run(
                        "MATCH (a:Actor) WITH [a.name] + coalesce(a.aliases, []) AS names "
                        "UNWIND names AS nm WITH nm WHERE toUpper(nm) STARTS WITH $p "
                        "RETURN collect(DISTINCT nm) AS names",
                        p=prefix,
                    ).single()
                    candidates = list(record["names"]) if record and record["names"] else []
                    if any(re.sub(r"[\s-]+", "", c).upper() == token for c in candidates):
                        continue  # the code resolves exactly - nothing to suggest
                    ranked = [name for name, _s, _i in process.extract(token, candidates, scorer=fuzz.ratio, limit=limit)]
                else:
                    record = session.run(
                        "MATCH (n:MitreNode) WHERE n.external_id STARTS WITH $p "
                        "RETURN collect(DISTINCT {id: n.external_id, name: n.name}) AS items",
                        p=prefix,
                    ).single()
                    items = list(record["items"]) if record and record["items"] else []
                    ids = [it["id"] for it in items if it["id"]]
                    if token in {i.upper() for i in ids}:
                        continue  # exact id exists - not a miss
                    id_to_name = {it["id"]: it["name"] for it in items}
                    ranked = []
                    for cid, _s, _i in process.extract(token, ids, scorer=fuzz.ratio, limit=limit):
                        nm = id_to_name.get(cid)
                        ranked.append(f"{nm} ({cid})" if nm else cid)
                for label in ranked:
                    if label not in seen:
                        seen.add(label)
                        ordered.append(label)
    except Exception:
        ordered = []  # fall through to name-based matching below

    # Name-based "did you mean": for a garbled entity NAME that didn't resolve
    # (below the pipeline's fuzzy threshold but still recognizable), suggest the
    # closest real names. High score band keeps this precise, not noisy.
    if len(ordered) < limit:
        phrases = _candidate_name_phrases(query)
        if phrases:
            names = _entity_name_index(driver)
            if names:
                from rapidfuzz import fuzz, process

                choices = [n for n, _ in names]
                id_by_name = {n: i for n, i in names}
                for phrase in phrases:
                    raw = process.extract(phrase, choices, scorer=fuzz.WRatio, limit=8)
                    # If the phrase IS a real entity name, it's not a typo - a
                    # no-info answer for it is a different problem, not a
                    # "did you mean", so suggest nothing.
                    if raw and raw[0][1] >= 100:
                        continue
                    hits: list[tuple[str, float]] = []
                    for name, score, _ in raw:
                        # 82-99: a close typo, not an exact hit and not noise.
                        if not (82 <= score < 100):
                            continue
                        # Length guard: a short name matching a long phrase (or
                        # vice-versa) is substring noise ("at" vs "weather").
                        if min(len(phrase), len(name)) / max(len(phrase), len(name)) < 0.5:
                            continue
                        hits.append((name, score))
                    # Margin gate: keep only names within a few points of the best
                    # match, so a shared generic word ("Group" -> "Group Policy
                    # Discovery") can't ride in behind the real match.
                    if hits:
                        best = hits[0][1]
                        for name, score in hits:
                            if best - score > 4:
                                break
                            ext = id_by_name.get(name)
                            label = f"{name} ({ext})" if ext else name
                            if label not in seen:
                                seen.add(label)
                                ordered.append(label)
                            if len(ordered) >= limit:
                                break
                    if len(ordered) >= limit:
                        break
    return ordered[:limit]


def normalize_query(query: str, driver=None) -> str:
    """Spelling-normalize a query for the "did you mean" correction gate: fix
    common scaffolding-word typos (via spell_normalize) AND correct a garbled
    ENTITY name toward a real graph entity, for typos that fell below the
    pipeline's own fuzzy-resolution threshold. Returns the query unchanged when
    nothing confidently corrects. Fail-safe: any error returns spell_normalize
    only. Manages its own driver when none is passed."""
    from retrieval.spell_normalize import spell_normalize

    text = spell_normalize(query)
    phrases = _candidate_name_phrases(text)
    if not phrases:
        return text

    owned = None
    if driver is None:
        try:
            driver = owned = get_driver()
        except Exception:
            return text
    try:
        names = _entity_name_index(driver)
        if not names:
            return text
        from rapidfuzz import fuzz, process

        choices = [n for n, _ in names]
        for phrase in phrases:
            raw = process.extract(phrase, choices, scorer=fuzz.WRatio, limit=5)
            if not raw or raw[0][1] >= 100:
                continue  # already an exact entity - not a typo
            best_name, best_score, _ = raw[0]
            if not (78 <= best_score < 100):
                continue
            if min(len(phrase), len(best_name)) / max(len(phrase), len(best_name)) < 0.6:
                continue  # length mismatch -> substring noise
            second = raw[1][1] if len(raw) > 1 else 0.0
            if best_score - second < 3:
                continue  # ambiguous between two entities
            if best_name.lower() == phrase.lower():
                continue
            pattern = re.compile(re.escape(phrase), re.IGNORECASE)
            if pattern.search(text):
                text = pattern.sub(best_name, text, count=1)
    except Exception:
        return spell_normalize(query)
    finally:
        if owned is not None:
            owned.close()
    return text


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
        "mitigation",
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
        "mitigations": filters.get("mitigation", []),
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
               OR (n:Mitigation AND n.name IN $mitigations)
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
    if filters.get("mitigation"):
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
    url: str | None = None


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
    retrieved_contexts: list[str] = field(default_factory=list)
    # Non-authoritative "did you mean" candidates, set only when an explicitly
    # referenced entity code (e.g. an unknown APT number) could not be resolved.
    # The frontend renders these as clickable chips; they are never auto-applied.
    suggestions: list[str] = field(default_factory=list)

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
    answer: str | None = None,
    suggestions: list[str] | None = None,
) -> PipelineResult:
    return PipelineResult(
        query=query,
        answer=answer or FALLBACK,
        allowed=category is None,
        guardrail_category=category,
        filters=filters or {},
        sources=[],
        retrieved_count=0,
        context_count=0,
        retrieved_contexts=[],
        suggestions=suggestions or [],
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


def run_log_analysis_pipeline(
    query: str,
    driver,
    platform: str | None,
    *,
    include_contexts: bool = False,
) -> PipelineResult:
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
            retrieved_contexts=[],
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
    retrieved_contexts: list[str] = []
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
                url=node.get("url"),
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
        if include_contexts:
            retrieved_contexts.append(
                "\n".join(
                    (
                        format_context([node], query),
                        f"Matched Line: {match.matched_line}",
                        f"Match Reason: {match.reason}",
                        f"Confidence: {match.confidence}",
                    )
                )
            )

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
        retrieved_contexts=retrieved_contexts,
    )


def run_pipeline(
    query: str,
    *,
    top_k: int = 8,
    candidate_k: int = 30,
    include_contexts: bool = False,
) -> PipelineResult:
    """Run one query through the complete grounded GraphRAG pipeline.

    ``include_contexts`` is an evaluation-only opt-in. When enabled, the
    result carries the same formatted node facts supplied to generation;
    the production default performs no context serialization.
    """
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

        try:
            harm_result = check_llm_guardrail(query)
        except Exception as exc:
            raise PipelineError("guardrail", exc) from exc
        if not harm_result.get("allowed", True):
            return fallback_result(query, category="llm_harm_blocked")

        driver = None
        try:
            try:
                driver = get_driver()
            except Exception as exc:
                raise PipelineError("database_connection", exc) from exc
            return run_log_analysis_pipeline(
                query,
                driver,
                log_detection.platform,
                include_contexts=include_contexts,
            )
        finally:
            if driver is not None:
                driver.close()

    with obs.span("guardrail"):
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

        def _fb(**kw):
            """A "no information" result, with universal "did you mean"
            suggestions attached whenever the query referenced an ID/code that
            did not resolve (T10557, G9999, ...). Chit-chat/plain queries get
            none. Suggestion failures never affect the answer."""
            fr = fallback_result(query, **kw)
            if fr.allowed and fr.answer.strip() == FALLBACK and not fr.suggestions:
                try:
                    fr.suggestions = reference_suggestions(driver, focused_query)
                except Exception:
                    pass
            return fr

        if not explicit_ids_exist(driver, focused_query):
            return _fb()

        # Actor alias-code guard: if the query names actor codes (APT##/FIN##/
        # UNC##) and NONE resolve to a real actor, refuse with suggestions rather
        # than let LLM filter extraction fabricate a different group (the exact
        # apt20 -> "Putter Panda" failure). If at least one code resolves, proceed
        # for the valid one(s), mirroring the mixed-ID philosophy above.
        referenced_actor_codes = actor_codes_in_query(focused_query)
        if referenced_actor_codes and not resolve_actor_codes(driver, referenced_actor_codes):
            unknown = ", ".join(sorted(code.upper() for code in referenced_actor_codes))
            suggestions = actor_code_suggestions(driver, referenced_actor_codes)
            return fallback_result(
                query,
                answer=f"I don't have {unknown} in my knowledge base.",
                suggestions=suggestions,
            )

        with obs.span("filter_extraction"):
            try:
                filters = extract_filters(focused_query, driver)
            except Exception as exc:
                raise PipelineError("filter_extraction", exc) from exc
        if is_ambiguous_short_reference(focused_query, filters):
            return _fb(filters=filters)
        if has_unresolved_explicit_id(focused_query, filters):
            return _fb(filters=filters)

        telemetry_seed_nodes = fetch_telemetry_seed_nodes(driver, focused_query)
        telemetry_seed_names = {
            str(node.get("name") or "").lower()
            for node in telemetry_seed_nodes
            if node.get("name")
        }
        seed_nodes = telemetry_seed_nodes + fetch_filter_seed_nodes(driver, filters)
        with obs.span("retrieval"):
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
            return _fb(filters=filters)

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

        with obs.span("graph_traversal"):
            try:
                contexts = traverse_nodes(driver, retrieved)
            except Exception as exc:
                raise PipelineError("graph_traversal", exc) from exc
        if not contexts:
            return _fb(filters=filters)

        with obs.span("reranking"):
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
            return _fb(filters=filters)

        with obs.span("generation"):
            try:
                answer = generate(focused_query, ranked, filters=filters)
            except Exception as exc:
                raise PipelineError("generation", exc) from exc

        final_answer = answer or FALLBACK
        is_no_info = not answer or final_answer.strip() == FALLBACK
        source_nodes = [] if is_no_info else ranked
        sources = [
            Source(
                name=str(node.get("name") or "Unknown"),
                external_id=node.get("external_id") or node.get("id"),
                url=node.get("url"),
                node_type=str(node.get("node_type") or node.get("type") or "Unknown"),
                relevance_score=node.get("relevance_score"),
            )
            for node in source_nodes
        ]
        # A generated "no information" answer still offers "did you mean" when the
        # query referenced an id/code that didn't resolve.
        final_suggestions: list[str] = []
        if is_no_info:
            try:
                final_suggestions = reference_suggestions(driver, focused_query)
            except Exception:
                final_suggestions = []
        return PipelineResult(
            query=query,
            answer=final_answer,
            allowed=True,
            guardrail_category=None,
            filters=filters,
            sources=sources,
            retrieved_count=len(retrieved),
            context_count=len(contexts),
            retrieved_contexts=(
                [format_context([node], focused_query) for node in ranked]
                if include_contexts
                else []
            ),
            suggestions=final_suggestions,
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
