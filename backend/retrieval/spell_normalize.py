"""Conservative spell normalization for the harm-gate re-check.

Purpose: a benign, typo-garbled cybersecurity question ("waht tacktics duz
T1078 blomg two?") trips the LLM harm classifier even though its clean form is
fine. This corrects obvious typos of common question/cyber words toward a FIXED
vocabulary so the classifier reads a normal question - WITHOUT touching IDs,
entity names, or anything it isn't confident about, and without changing intent.

It is deliberately narrow: it never invents words, only nudges a near-miss token
to a known vocabulary word within a tight edit distance. Harmful intent survives
(the harmful words aren't in this benign vocabulary, so they're left as-is), so
running the harm gate on the normalized text still blocks genuine harm.
"""

from __future__ import annotations

import re

from rapidfuzz import fuzz, process
from rapidfuzz.distance import Levenshtein

# Common question scaffolding + cyber vocabulary that gets typo'd in queries.
# NOT harmful terms - so a harmful word never gets "corrected" into a safe one.
_VOCAB = {
    # question words / verbs
    "what", "which", "who", "whom", "whose", "when", "where", "why", "how",
    "does", "do", "did", "is", "are", "was", "were", "can", "could", "should",
    "would", "will", "list", "show", "tell", "explain", "describe", "give",
    "name", "use", "uses", "used", "using", "have", "has", "had", "belong",
    "belongs", "associated", "attributed", "connected", "related", "deploy",
    "deploys", "run", "runs", "work", "works", "mitigate", "mitigates",
    "mitigated", "detect", "detects", "prevent", "prevents", "target",
    "targets", "leverage", "leverages", "about", "compare",
    # cyber nouns
    "technique", "techniques", "tactic", "tactics", "malware", "tool", "tools",
    "campaign", "campaigns", "mitigation", "mitigations", "actor", "actors",
    "group", "groups", "software", "procedure", "procedures", "subtechnique",
    "subtechniques", "detection", "detections", "analytic", "analytics",
    "platform", "platforms", "source", "sources", "component", "components",
    "threat", "adversary", "attack", "exploit", "vulnerability", "credential",
    "credentials", "persistence", "escalation", "execution", "exfiltration",
    "discovery", "evasion", "injection", "phishing", "account", "accounts",
    # connectors
    "the", "and", "for", "with", "from", "that", "this", "does",
}
# Ultra-common typos that fuzzy ratio scores below threshold (transpositions /
# heavy contractions) but are unambiguous. Small and explicit on purpose.
_DIRECT = {
    "waht": "what", "wht": "what", "whta": "what", "wat": "what",
    "wich": "which", "whcih": "which", "duz": "does", "doz": "does",
    "teh": "the", "taktics": "tactics", "tacktics": "tactics",
    "tacticks": "tactics", "blomg": "belong", "blong": "belong",
    "mitigaes": "mitigates", "mitiagtes": "mitigates", "assocaited": "associated",
    "assoicated": "associated", "atributed": "attributed", "campiagns": "campaigns",
    "tehcniques": "techniques", "techniqes": "techniques", "techniqe": "technique",
}


def _fix_token(token: str) -> str:
    low = token.lower()
    if len(low) <= 2 or low in _VOCAB:
        return token
    if low in _DIRECT:
        return _DIRECT[low]
    match = process.extractOne(low, _VOCAB, scorer=fuzz.ratio, score_cutoff=82)
    if match and 0 < Levenshtein.distance(low, match[0]) <= 2:
        return match[0]
    return token


def spell_normalize(text: str) -> str:
    """Return the query with near-miss common words corrected. Pure-alpha runs
    only, so IDs (T1078), CVEs, and alphanumerics are never altered."""
    return re.sub(r"[A-Za-z]+", lambda m: _fix_token(m.group(0)), text or "")
