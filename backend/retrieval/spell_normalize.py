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

from rapidfuzz import process
from rapidfuzz.distance import DamerauLevenshtein

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
    # Legitimate short words. Listed so the context rule can NEVER rewrite a
    # word the user actually meant ("what ON the host", "tools OF FIN7") - the
    # rule only fires for short tokens absent from this vocabulary.
    "a", "an", "as", "at", "be", "by", "do", "go", "he", "if", "in", "is",
    "it", "me", "my", "no", "of", "on", "or", "so", "to", "up", "us", "we",
    # Number words and other short real words. Present purely as protection:
    # "two" is one edit from "to", and silently rewriting it would corrupt a
    # question the user spelled correctly ("what are the two tactics").
    "one", "two", "three", "four", "five", "six", "ten", "all", "any", "new",
    "not", "now", "out", "own", "see", "set", "top", "who", "why", "yes",
}
# Ultra-common typos that fuzzy ratio scores below threshold (transpositions /
# heavy contractions) but are unambiguous. Small and explicit on purpose.
# Frequency priors, NOT a typo list.
#
# Nearly every typo is now repaired generically (Damerau-Levenshtein for 3+
# characters, grammatical context for 1-2), so new ones need no code change.
# This map exists only for tokens that are genuinely TIED by edit distance,
# where the tie-break is knowledge of usage rather than of spelling: "wht" is
# one edit from what / who / why alike, and the distance rule correctly refuses
# to guess - but in a question it is overwhelmingly "what". Encoding that prior
# is what a frequency-ranked dictionary would do for us if we shipped one.
_DIRECT = {
    "wht": "what",   # tied with who / why
    "whi": "which",  # tied with who / why
    "hw": "how",
    "teh": "the",    # tied with ten
}


# Words that legitimately follow an interrogative ("what IS", "which DOES").
# Used for context-sensitive repair of short tokens, where similarity alone is
# undecidable: "os" is edit-distance 1 from is/of/on/as/us/or simultaneously, so
# no scorer can rank them. What disambiguates it is the preceding word - after
# "what", only a copula/auxiliary is grammatical. This is the same principle a
# real spellchecker uses (context, not just distance), generalised to the whole
# class rather than enumerated typo-by-typo.
_INTERROGATIVES = {
    "what", "which", "who", "whom", "whose", "where", "when", "why", "how",
}
_COPULAS = ("is", "are", "was", "were", "do", "does", "did", "can", "will")
_QUESTION_LEAD_INS = {
    ("tell", "me"),
    ("please",),
    ("please", "tell", "me"),
    ("can", "you", "tell", "me"),
    ("could", "you", "tell", "me"),
}


def _fix_token(token: str) -> str:
    """Repair a token in isolation, using edit distance against the vocabulary.

    Distance is Damerau-Levenshtein: it charges a swap of two adjacent letters
    as ONE edit. That matters because transposition is the most common human
    typo ("dose"/"does", "teh"/"the", "adn"/"and"), and plain Levenshtein
    charges it two - which is why those previously needed hand-written entries.
    The budget scales with word length, so a short word must be near-exact while
    a long one may drift further, and a correction is only accepted when it is
    strictly closer than every runner-up (an ambiguous tie is left alone).
    """
    low = token.lower()
    if low in _VOCAB:
        return token
    # Frequency prior beats distance for tokens that are genuinely tied.
    if low in _DIRECT:
        return _DIRECT[low]
    if len(low) <= 2:
        # Undecidable in isolation - handled by the context pass.
        return token

    # Exactly ONE edit, at every length. The vocabulary here is deliberately
    # small, so a two-edit budget starts rewriting ordinary English that simply
    # is not in it - "files" became "five", which would have silently altered
    # the text the harm classifier reads. One edit keeps repair to near-certain
    # slips (a single wrong/missing/extra letter, or one adjacent swap) and
    # leaves anything less certain untouched.
    budget = 1
    candidates = process.extract(
        low, _VOCAB, scorer=DamerauLevenshtein.distance, limit=2
    )
    if not candidates:
        return token
    best, best_distance, _ = candidates[0]
    if best_distance == 0 or best_distance > budget:
        return token
    # Reject ambiguity: if a second word is equally close, we cannot know which
    # was meant, so changing it would be a guess.
    if len(candidates) > 1 and candidates[1][1] == best_distance:
        return token
    return best


def _repair_short_after_interrogative(low: str) -> str | None:
    """Best copula for an unknown short token sitting right after a question
    word. Generalises to any near-miss ("os", "si", "iw", "ar", "dose") without
    listing them, because the grammatical slot - not the string - decides."""
    best, best_distance = None, 99
    for candidate in _COPULAS:
        distance = DamerauLevenshtein.distance(low, candidate)
        # One edit per two characters: a short word must be near-exact, a longer
        # auxiliary ("does") may drift slightly further.
        if distance < best_distance and distance <= max(1, len(candidate) // 2):
            best, best_distance = candidate, distance
    return best


def normalize_question_scaffolding(text: str) -> str:
    """Normalize only the interrogative/auxiliary grammar used for routing.

    Unlike :func:`spell_normalize`, this function never considers entity names,
    IDs, relationship nouns, or ordinary prose. It may repair a misspelled
    opening question word and the auxiliary immediately following the first
    recognized interrogative. Everything else is preserved byte-for-byte.

    Lowercase is required for an auxiliary repair so an acronym such as ``OS``
    can never silently become ``is``. Valid short words (``on``, ``of``, etc.)
    are protected by ``_VOCAB``. This gives deterministic renderers a safe
    grammar signal without mutating the query used by security or retrieval.
    """
    source = text or ""
    tokens = list(re.finditer(r"[A-Za-z0-9]+", source))
    if not tokens:
        return source

    replacements: dict[int, str] = {}
    interrogative_index: int | None = None

    # The opening token is the only place where a misspelled interrogative is
    # inferred. An exact interrogative may appear later in polite phrasing such
    # as "Tell me what os APT29?" and is still safe to use as grammar context.
    first = tokens[0].group(0)
    first_fixed = _fix_token(first)
    if (
        first.lower() not in _INTERROGATIVES
        and first_fixed.lower() in _INTERROGATIVES
        and (first.islower() or first.istitle())
    ):
        replacements[0] = (
            first_fixed.capitalize() if first.istitle() else first_fixed.lower()
        )
        interrogative_index = 0
    else:
        for index, token in enumerate(tokens):
            prefix = tuple(item.group(0).lower() for item in tokens[:index])
            if (
                token.group(0).lower() in _INTERROGATIVES
                and (index == 0 or prefix in _QUESTION_LEAD_INS)
            ):
                interrogative_index = index
                break

    if interrogative_index is None or interrogative_index + 1 >= len(tokens):
        return source

    auxiliary_index = interrogative_index + 1
    auxiliary = tokens[auxiliary_index].group(0)
    auxiliary_low = auxiliary.lower()
    if auxiliary.islower() and auxiliary_low not in _VOCAB:
        repaired = _repair_short_after_interrogative(auxiliary_low)
        if repaired:
            replacements[auxiliary_index] = repaired

    if not replacements:
        return source

    pieces: list[str] = []
    position = 0
    for index, token in enumerate(tokens):
        pieces.append(source[position:token.start()])
        pieces.append(replacements.get(index, token.group(0)))
        position = token.end()
    pieces.append(source[position:])
    return "".join(pieces)


def spell_normalize(text: str) -> str:
    """Return the query with near-miss common words corrected.

    Two passes, because correctability depends on length:

    * tokens of 3+ characters are repaired by similarity against the curated
      vocabulary - at that length the nearest word is effectively unique;
    * 1-2 character tokens are repaired only from grammatical context (an
      unknown short word directly after an interrogative becomes the nearest
      copula), since similarity alone cannot separate is/of/on/as/us.

    A token already in the vocabulary is never touched, so real words ("what
    is ON the host", "tools OF FIN7") are safe. Only pure-alpha runs are
    considered, so IDs (T1078), CVEs, and alphanumerics are never altered.
    """
    source = text or ""
    out: list[str] = []
    last_word: str | None = None
    position = 0

    # Whole alphanumeric runs, NOT bare letter runs. Matching only [A-Za-z]
    # would grab the "APT" inside "APT29" and "correct" it to a vocabulary word,
    # destroying the entity reference ("APT29" -> "at29"). Any run containing a
    # digit is an identifier and is passed through untouched.
    for match in re.finditer(r"[A-Za-z0-9]+", source):
        out.append(source[position:match.start()])
        token = match.group(0)
        low = token.lower()
        if any(character.isdigit() for character in token):
            out.append(token)
            last_word = low
            position = match.end()
            continue
        fixed = _fix_token(token)

        # Context pass: only for short tokens the isolated pass left alone, and
        # only when they are not already a legitimate word.
        if (
            fixed == token
            and len(low) <= 2
            and low not in _VOCAB
            and last_word in _INTERROGATIVES
        ):
            repaired = _repair_short_after_interrogative(low)
            if repaired:
                fixed = repaired

        out.append(fixed)
        last_word = fixed.lower()
        position = match.end()

    out.append(source[position:])
    return "".join(out)
