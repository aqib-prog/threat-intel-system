#!/usr/bin/env python3
"""Build the fixed Phase-E RAG accuracy set from the 13 full artifacts.

Sampling and typo generation are deterministic.  The only model-authored
content is the alternate wording of a question; reference answers and source
provenance are copied directly from their source golden records.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DEFAULT_OUTPUT = HERE / "final_golden_set.json"
MODEL = "llama3.1"
CASES_PER_RELATIONSHIP = 4
REWORDING_BATCH_SIZE = 8
MIN_TYPO_SIMILARITY = 0.75
MIN_REWORD_ANCHOR_SIMILARITY = 0.82


ARTIFACT_SPECS: tuple[dict[str, Any], ...] = (
    {
        "label": "technique_mitigation",
        "filename": "golden_set.json",
        "slots": (
            ("forward_positive", ("positive",)),
            ("reverse_positive", ("aggregate_mitigation_techniques",)),
            ("negative_relationship", ("negative_mitigation_technique",)),
            ("zero_path", ("negative",)),
        ),
    },
    {
        "label": "technique_tactic",
        "filename": "golden_set_technique_tactic.json",
        "slots": (
            ("forward_positive", ("single_tactic",)),
            ("forward_multi_tactic", ("multi_tactic",)),
            ("reverse_positive", ("aggregate_tactic_techniques",)),
            ("adversarial_negative", ("adversarial_negative_technique_tactic",)),
        ),
    },
    {
        "label": "group_technique",
        "filename": "golden_set_group_technique.json",
        "slots": (
            ("forward_positive", ("aggregate_group_techniques",)),
            ("reverse_positive", ("aggregate_technique_groups",)),
            ("negative_relationship", ("negative_group_technique",)),
            ("zero_path", ("aggregate_group_no_qualifying_techniques",)),
        ),
    },
    {
        "label": "software_technique",
        "filename": "golden_set_software_technique.json",
        "slots": (
            ("forward_positive", ("aggregate_software_techniques",)),
            ("reverse_positive", ("aggregate_technique_software",)),
            ("adversarial_negative", ("adversarial_negative_software_technique",)),
            ("reverse_zero_path", ("aggregate_technique_no_software",)),
        ),
    },
    {
        "label": "group_software",
        "filename": "golden_set_group_software.json",
        "slots": (
            ("forward_positive", ("aggregate_group_software",)),
            ("reverse_positive", ("aggregate_software_groups",)),
            ("adversarial_negative", ("adversarial_negative_group_software",)),
            ("zero_path", ("aggregate_group_no_qualifying_software",)),
        ),
    },
    {
        "label": "campaign_group",
        "filename": "golden_set_campaign_group.json",
        "slots": (
            ("forward_positive", ("aggregate_campaign_groups",)),
            ("reverse_positive", ("aggregate_group_campaigns",)),
            ("negative_relationship", ("negative_campaign_group",)),
            ("zero_path", ("aggregate_campaign_no_attributed_group",)),
        ),
    },
    {
        "label": "technique_detection_strategy",
        "filename": "golden_set_technique_detection_strategy.json",
        "slots": (
            ("forward_positive", ("aggregate_technique_detection_strategy",)),
            ("reverse_positive", ("aggregate_detection_strategy_technique",)),
            (
                "adversarial_negative",
                ("adversarial_negative_detection_strategy_technique",),
            ),
            (
                "detection_component_zero_path",
                ("aggregate_technique_no_detection_components",),
            ),
        ),
    },
    {
        "label": "campaign_technique",
        "filename": "golden_set_campaign_technique.json",
        "slots": (
            ("forward_positive", ("aggregate_campaign_techniques",)),
            ("reverse_positive", ("aggregate_technique_campaigns",)),
            ("adversarial_negative", ("adversarial_negative_campaign_technique",)),
            ("focused_positive", ("focused_campaign_technique",)),
        ),
    },
    {
        "label": "campaign_software",
        "filename": "golden_set_campaign_software.json",
        "slots": (
            ("forward_positive", ("aggregate_campaign_software",)),
            ("reverse_positive", ("aggregate_software_campaigns",)),
            ("adversarial_negative", ("adversarial_negative_campaign_software",)),
            ("focused_positive", ("focused_campaign_software",)),
        ),
    },
    {
        "label": "subtechnique",
        "filename": "golden_set_subtechnique.json",
        "slots": (
            ("forward_parent_lookup", ("identify_subtechnique_parent",)),
            ("reverse_children_lookup", ("aggregate_parent_subtechniques",)),
            ("negative_relationship", ("negative_subtechnique_relationship",)),
            ("zero_path", ("aggregate_technique_no_subtechniques",)),
        ),
    },
    {
        "label": "detection_analytic",
        "filename": "golden_set_detection_analytic.json",
        "slots": (
            ("forward_positive", ("aggregate_detection_strategy_analytics",)),
            ("reverse_positive", ("identify_analytic_detection_strategy",)),
            (
                "negative_relationship",
                ("negative_detection_strategy_analytic_relationship",),
            ),
            (
                "platform_zero_path",
                ("aggregate_detection_strategy_no_platform_analytics",),
            ),
        ),
    },
    {
        "label": "analytic_datacomponent",
        "filename": "golden_set_analytic_datacomponent.json",
        "slots": (
            ("forward_positive", ("aggregate_analytic_data_components",)),
            ("reverse_positive", ("aggregate_data_component_analytics",)),
            (
                "negative_relationship",
                ("negative_analytic_data_component_relationship",),
            ),
            ("zero_path", ("aggregate_analytic_no_data_components",)),
        ),
    },
    {
        "label": "campaign_software_technique_chain",
        "filename": "golden_set_campaign_software_technique_chain.json",
        "slots": (
            ("forward_chain", ("named_campaign_software_technique_chain",)),
            (
                "reverse_chain",
                ("aggregate_technique_campaigns_via_software",),
            ),
            (
                "negative_chain",
                ("negative_named_campaign_software_technique_chain",),
            ),
            ("path_divergence", ("campaign_software_technique_divergence",)),
        ),
    },
)


class BuildError(RuntimeError):
    """Raised when an input or output invariant is violated."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_pairs(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    pairs = payload.get("pairs")
    if not isinstance(pairs, list):
        raise BuildError(f"{path.name} does not contain a pairs list")
    ids = [pair.get("id") for pair in pairs]
    if any(not isinstance(pair_id, str) or not pair_id for pair_id in ids):
        raise BuildError(f"{path.name} contains a pair without a stable ID")
    if len(ids) != len(set(ids)):
        raise BuildError(f"{path.name} contains duplicate pair IDs")
    return pairs


def _balanced_parenthetical(text: str, opening_index: int) -> tuple[str, int] | None:
    depth = 0
    for index in range(opening_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[opening_index + 1 : index], index + 1
    return None


def displayed_entities(question: str) -> list[dict[str, Any]]:
    """Extract ``ID (Name)`` displays, including names with parentheses."""
    id_pattern = re.compile(
        r"(?<![A-Za-z0-9])"
        r"(TA\d{4}|DET\d{4}|AN\d{4}|DC\d{4}|[TMSG C]\d{4}(?:\.\d{3})?)"
        r"(?![A-Za-z0-9.])",
        re.IGNORECASE | re.VERBOSE,
    )
    entities: list[dict[str, Any]] = []
    for match in id_pattern.finditer(question):
        cursor = match.end()
        while cursor < len(question) and question[cursor].isspace():
            cursor += 1
        name = None
        if cursor < len(question) and question[cursor] == "(":
            parsed = _balanced_parenthetical(question, cursor)
            if parsed:
                name = parsed[0]
        entities.append(
            {
                "external_id": match.group(1),
                "name": name,
                "stix_id": None,
                "_position": match.start(),
            }
        )
    return entities


def direct_entity_candidates(pair: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for key, value in pair.items():
        if (
            key.startswith("expected_")
            or key in {"provenance"}
            or not isinstance(value, dict)
        ):
            continue
        external_id = value.get("external_id")
        name = value.get("name")
        if external_id or name:
            candidates.append(
                {
                    "external_id": external_id,
                    "name": name,
                    "stix_id": value.get("stix_id"),
                    "_source_key": key,
                }
            )
    return candidates


def _first_position(question: str, values: list[str | None]) -> int | None:
    positions = [
        question.casefold().find(value.casefold())
        for value in values
        if isinstance(value, str) and value and value.casefold() in question.casefold()
    ]
    return min(positions) if positions else None


def choose_anchor(pair: dict[str, Any]) -> dict[str, Any]:
    """Choose the first question subject represented by a source entity."""
    question = str(pair.get("question") or "")
    candidates = direct_entity_candidates(pair)
    by_external_id = {
        str(candidate["external_id"]).upper(): candidate
        for candidate in candidates
        if candidate.get("external_id")
    }
    for displayed in displayed_entities(question):
        direct = by_external_id.get(str(displayed["external_id"]).upper())
        if direct:
            displayed.update(
                {
                    key: direct.get(key)
                    for key in ("name", "stix_id", "_source_key")
                    if direct.get(key)
                }
            )
        candidates.append(displayed)

    positioned: list[tuple[int, dict[str, Any]]] = []
    for candidate in candidates:
        position = candidate.get("_position")
        if position is None:
            position = _first_position(
                question, [candidate.get("external_id"), candidate.get("name")]
            )
        if position is not None:
            positioned.append((int(position), candidate))
    if not positioned:
        raise BuildError(f"cannot identify an anchor for {pair.get('id')}")
    positioned.sort(
        key=lambda item: (
            item[0],
            0 if item[1].get("stix_id") else 1,
            str(item[1].get("external_id") or ""),
        )
    )
    entity = positioned[0][1]
    name = entity.get("name")
    external_id = entity.get("external_id")
    if (
        isinstance(name, str)
        and len(name.strip()) >= 4
        and name.casefold() in question.casefold()
    ):
        reference = name
        reference_kind = "name"
    elif (
        isinstance(external_id, str)
        and len(external_id) >= 4
        and external_id.casefold() in question.casefold()
    ):
        reference = external_id
        reference_kind = "external_id"
    else:
        raise BuildError(f"anchor in {pair.get('id')} has no mutable reference")
    return {
        "external_id": external_id,
        "name": name,
        "stix_id": entity.get("stix_id"),
        "source_key": entity.get("_source_key"),
        "reference": reference,
        "reference_kind": reference_kind,
    }


def levenshtein_distance(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def typo_reference(reference: str) -> tuple[str, str]:
    """Apply one deterministic adjacent transposition or character drop."""
    words = list(re.finditer(r"[A-Za-z0-9]+", reference))
    words.sort(key=lambda match: (-len(match.group(0)), match.start()))
    for word_match in words:
        word = word_match.group(0)
        if len(word) < 5:
            continue
        midpoint = len(word) // 2
        indices = sorted(
            range(1, len(word) - 1),
            key=lambda index: (abs(index - midpoint), index),
        )
        for index in indices:
            if word[index].isalnum() and word[index + 1].isalnum() and (
                word[index].casefold() != word[index + 1].casefold()
            ):
                changed = (
                    word[:index]
                    + word[index + 1]
                    + word[index]
                    + word[index + 2 :]
                )
                typo = (
                    reference[: word_match.start()]
                    + changed
                    + reference[word_match.end() :]
                )
                return typo, "adjacent_transposition"
    for word_match in words:
        word = word_match.group(0)
        if len(word) >= 5:
            index = max(1, min(len(word) - 2, len(word) // 2))
            typo = (
                reference[: word_match.start()]
                + word[:index]
                + word[index + 1 :]
                + reference[word_match.end() :]
            )
            return typo, "single_character_drop"
    raise BuildError(f"reference is too short for a realistic typo: {reference!r}")


def replace_first_case_insensitive(text: str, old: str, new: str) -> str:
    result, count = re.subn(re.escape(old), lambda _: new, text, count=1, flags=re.I)
    if count != 1:
        raise BuildError(f"anchor reference {old!r} was not uniquely replaceable")
    return result


def build_typo_variant(pair: dict[str, Any], anchor: dict[str, Any]) -> dict[str, Any]:
    mutated, mutation = typo_reference(str(anchor["reference"]))
    similarity = SequenceMatcher(
        None, str(anchor["reference"]).casefold(), mutated.casefold()
    ).ratio()
    distance = levenshtein_distance(str(anchor["reference"]), mutated)
    if similarity < MIN_TYPO_SIMILARITY or distance not in {1, 2}:
        raise BuildError(
            f"unrealistic typo for {pair['id']}: "
            f"similarity={similarity:.3f}, distance={distance}"
        )
    return {
        "question": replace_first_case_insensitive(
            str(pair["question"]), str(anchor["reference"]), mutated
        ),
        "mutated_reference": mutated,
        "mutation": mutation,
        "similarity": round(similarity, 6),
        "edit_distance": distance,
    }


def normalize_text(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _contains_exact(text: str, reference: str) -> bool:
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9]){re.escape(reference)}(?![A-Za-z0-9])",
            text,
            re.IGNORECASE,
        )
    )


def verify_reworded_anchor(
    question: str, anchor: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    """Deterministically require the same ID/name or a close name window."""
    references = [
        reference
        for reference in (anchor.get("external_id"), anchor.get("name"))
        if isinstance(reference, str) and len(reference.strip()) >= 4
    ]
    for reference in references:
        if _contains_exact(question, reference):
            return True, {
                "method": "exact_reference",
                "matched_reference": reference,
                "score": 1.0,
            }

    words = normalize_text(question).split()
    best_score = 0.0
    best_reference = None
    for reference in references:
        reference_words = normalize_text(reference).split()
        if not reference_words:
            continue
        for width in range(max(1, len(reference_words) - 1), len(reference_words) + 2):
            for start in range(0, max(0, len(words) - width + 1)):
                window = " ".join(words[start : start + width])
                score = SequenceMatcher(
                    None, " ".join(reference_words), window
                ).ratio()
                if score > best_score:
                    best_score = score
                    best_reference = reference
    accepted = best_score >= MIN_REWORD_ANCHOR_SIMILARITY
    return accepted, {
        "method": "fuzzy_reference" if accepted else "no_recognizable_reference",
        "matched_reference": best_reference if accepted else None,
        "score": round(best_score, 6),
    }


def verify_reworded_variant(
    original_question: str, candidate_question: str, anchor: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    """Verify anchor, all displayed entities, and boolean negation polarity."""
    anchor_ok, anchor_detail = verify_reworded_anchor(candidate_question, anchor)
    if not anchor_ok:
        return False, {"reason": "anchor_not_preserved", "anchor": anchor_detail}

    entity_checks: list[dict[str, Any]] = []
    for entity in displayed_entities(original_question):
        entity_anchor = {
            "external_id": entity.get("external_id"),
            "name": entity.get("name"),
        }
        preserved, detail = verify_reworded_anchor(
            candidate_question, entity_anchor
        )
        entity_checks.append(
            {
                "external_id": entity.get("external_id"),
                "name": entity.get("name"),
                "preserved": preserved,
                "verification": detail,
            }
        )
        if not preserved:
            return False, {
                "reason": "displayed_entity_not_preserved",
                "anchor": anchor_detail,
                "entity_checks": entity_checks,
            }

    negation_words = {"not", "no", "never", "without", "absent", "lacks", "lack"}
    original_negations = [
        word
        for word in normalize_text(original_question).split()
        if word in negation_words
    ]
    candidate_negations = [
        word
        for word in normalize_text(candidate_question).split()
        if word in negation_words
    ]
    if bool(original_negations) != bool(candidate_negations):
        return False, {
            "reason": "negation_polarity_changed",
            "anchor": anchor_detail,
            "entity_checks": entity_checks,
            "original_negations": original_negations,
            "candidate_negations": candidate_negations,
        }
    anchor_phrase = normalize_text(str(anchor.get("reference") or ""))
    candidate_normalized = normalize_text(candidate_question)
    original_normalized = normalize_text(original_question)
    entity_type_words = (
        "actor",
        "group",
        "tool",
        "malware",
        "campaign",
        "technique",
        "tactic",
        "mitigation",
        "analytic",
    )
    retyping_phrases = [
        f"is {anchor_phrase} a {entity_type}"
        for entity_type in entity_type_words
    ] + [
        f"is {anchor_phrase} an {entity_type}"
        for entity_type in entity_type_words
    ]
    introduced_retyping = [
        phrase
        for phrase in retyping_phrases
        if phrase in candidate_normalized and phrase not in original_normalized
    ]
    if introduced_retyping:
        return False, {
            "reason": "anchor_entity_type_changed",
            "anchor": anchor_detail,
            "entity_checks": entity_checks,
            "introduced_retyping_phrases": introduced_retyping,
        }
    return True, {
        "reason": "verified",
        "anchor": anchor_detail,
        "entity_checks": entity_checks,
        "negation_polarity_preserved": True,
    }


def _ollama_client() -> tuple[Any, float]:
    sys.path.insert(0, str(REPO_ROOT / "backend"))
    from config import OLLAMA_CLIENT, OLLAMA_TIMEOUT

    return OLLAMA_CLIENT, OLLAMA_TIMEOUT


def request_rewording(
    original_question: str, anchor: dict[str, Any], attempt: int
) -> str:
    client, _ = _ollama_client()
    anchor_reference = str(anchor["reference"])
    response = client.chat(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "Rewrite cybersecurity knowledge-graph questions without "
                    "changing their factual target, relationship, direction, "
                    "polarity, filters, or scope. Output JSON only."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Rewrite the question below using natural wording and a "
                    "meaningfully different sentence structure. Preserve every "
                    "MITRE ID, named entity, boolean polarity, platform/property "
                    "filter, and relationship direction. The exact anchor text "
                    f"{anchor_reference!r} MUST appear verbatim. Do not answer "
                    "the question and do not add facts.\n\n"
                    f"Original question: {original_question}\n"
                    f"Retry number: {attempt}\n\n"
                    'Return exactly: {\"question\": \"...\"}'
                ),
            },
        ],
        format="json",
        options={"temperature": 0},
    )
    content = response.message.content
    payload = json.loads(content)
    question = payload.get("question") if isinstance(payload, dict) else None
    if not isinstance(question, str) or not question.strip():
        raise BuildError("Ollama response lacks a non-empty question")
    return " ".join(question.strip().splitlines())


def request_rewording_batch(
    items: list[dict[str, Any]], attempt: int
) -> dict[str, str]:
    """Request multiple independent rewrites in one bounded Ollama call."""
    client, _ = _ollama_client()
    requests = [
        {
            "case_id": item["pair"]["id"],
            "original_question": item["pair"]["question"],
            "required_anchor_text": item["anchor"]["reference"],
        }
        for item in items
    ]
    response = client.chat(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "Rewrite cybersecurity knowledge-graph questions without "
                    "changing their factual target, relationship, direction, "
                    "polarity, filters, or scope. Output JSON only."
                ),
            },
            {
                "role": "user",
                "content": (
                    "For every input object below, produce exactly one natural "
                    "alternate wording. Use meaningfully different sentence "
                    "structure. Preserve every MITRE ID, named entity, boolean "
                    "polarity, platform/property filter, and relationship "
                    "direction. Each required_anchor_text MUST appear verbatim "
                    "in its rewrite. Do not answer or add facts. Return every "
                    "case_id exactly once.\n\n"
                    f"Retry number: {attempt}\n"
                    f"Inputs: {json.dumps(requests, ensure_ascii=False)}\n\n"
                    'Return exactly: {"rewrites": ['
                    '{"case_id": "...", "question": "..."}, ...]}'
                ),
            },
        ],
        format="json",
        options={"temperature": 0},
    )
    payload = json.loads(response.message.content)
    rows = payload.get("rewrites") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise BuildError("Ollama batch response lacks a rewrites list")
    results: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        case_id = row.get("case_id")
        question = row.get("question")
        if (
            isinstance(case_id, str)
            and isinstance(question, str)
            and question.strip()
            and case_id not in results
        ):
            results[case_id] = " ".join(question.strip().splitlines())
    return results


def generate_verified_rewording(
    pair: dict[str, Any],
    anchor: dict[str, Any],
    requester: Callable[[str, dict[str, Any], int], str] = request_rewording,
) -> tuple[str | None, dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    original = str(pair["question"])
    for attempt in (1, 2):
        try:
            candidate = requester(original, anchor, attempt)
            if candidate.casefold() == original.casefold():
                failures.append({"attempt": attempt, "reason": "unchanged_question"})
                continue
            accepted, verification = verify_reworded_variant(
                original, candidate, anchor
            )
            if accepted:
                return candidate, {
                    "attempts": attempt,
                    "verification": verification,
                    "prior_failures": failures,
                }
            failures.append(
                {
                    "attempt": attempt,
                    "reason": "anchor_verification_failed",
                    "verification": verification,
                }
            )
        except Exception as exc:
            failures.append(
                {
                    "attempt": attempt,
                    "reason": "generation_error",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
    return None, {"attempts": 2, "failures": failures}


def generate_verified_rewordings_batch(
    items: list[dict[str, Any]],
    requester: Callable[[list[dict[str, Any]], int], dict[str, str]] = (
        request_rewording_batch
    ),
) -> tuple[dict[tuple[str, str], tuple[str, dict[str, Any]]], list[dict[str, Any]]]:
    """Generate in bounded batches, independently verifying every returned row."""
    accepted: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
    failures_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {
        (item["artifact"], item["pair"]["id"]): [] for item in items
    }
    pending = list(items)
    for attempt in (1, 2):
        next_pending: list[dict[str, Any]] = []
        for offset in range(0, len(pending), REWORDING_BATCH_SIZE):
            batch = pending[offset : offset + REWORDING_BATCH_SIZE]
            print(
                f"rewording attempt {attempt}: batch "
                f"{offset // REWORDING_BATCH_SIZE + 1}/"
                f"{(len(pending) + REWORDING_BATCH_SIZE - 1) // REWORDING_BATCH_SIZE} "
                f"({len(batch)} cases)",
                flush=True,
            )
            try:
                returned = requester(batch, attempt)
            except Exception as exc:
                returned = {}
                batch_error = {
                    "attempt": attempt,
                    "reason": "batch_generation_error",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            else:
                batch_error = None
            for item in batch:
                pair = item["pair"]
                key = (item["artifact"], pair["id"])
                candidate = returned.get(pair["id"])
                if candidate is None:
                    failure = batch_error or {
                        "attempt": attempt,
                        "reason": "missing_from_batch_response",
                    }
                    failures_by_key[key].append(failure)
                    next_pending.append(item)
                    continue
                if candidate.casefold() == str(pair["question"]).casefold():
                    failures_by_key[key].append(
                        {"attempt": attempt, "reason": "unchanged_question"}
                    )
                    next_pending.append(item)
                    continue
                verified, verification = verify_reworded_variant(
                    str(pair["question"]), candidate, item["anchor"]
                )
                if not verified:
                    failures_by_key[key].append(
                        {
                            "attempt": attempt,
                            "reason": "anchor_verification_failed",
                            "verification": verification,
                        }
                    )
                    next_pending.append(item)
                    continue
                accepted[key] = (
                    candidate,
                    {
                        "attempts": attempt,
                        "verification": verification,
                        "prior_failures": failures_by_key[key],
                    },
                )
        pending = next_pending
        if not pending:
            break
    omitted = [
        {
            "source_golden_artifact": item["artifact"],
            "source_case_id": item["pair"]["id"],
            "attempts": 2,
            "failures": failures_by_key[
                (item["artifact"], item["pair"]["id"])
            ],
        }
        for item in pending
    ]
    return accepted, omitted


def _eligible_pair(pair: dict[str, Any]) -> bool:
    try:
        anchor = choose_anchor(pair)
        build_typo_variant(pair, anchor)
    except (BuildError, KeyError, TypeError):
        return False
    reference_occurrences = str(pair["question"]).casefold().count(
        str(anchor["reference"]).casefold()
    )
    return (
        bool(pair.get("expected_answer"))
        and isinstance(pair.get("provenance"), dict)
        and reference_occurrences == 1
    )


def select_source_cases() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    seen_ids: set[tuple[str, str]] = set()
    for spec in ARTIFACT_SPECS:
        path = HERE / spec["filename"]
        pairs = load_pairs(path)
        chosen_for_artifact: list[dict[str, Any]] = []
        slot_report: list[dict[str, Any]] = []
        for slot_name, accepted_types in spec["slots"]:
            candidates = sorted(
                (
                    pair
                    for pair in pairs
                    if pair.get("case_type") in accepted_types
                    and (spec["filename"], pair["id"]) not in seen_ids
                    and _eligible_pair(pair)
                ),
                key=lambda pair: pair["id"],
            )
            if not candidates:
                raise BuildError(
                    f"{spec['filename']} has no eligible case for {slot_name}: "
                    f"{accepted_types}"
                )
            pair = candidates[0]
            seen_ids.add((spec["filename"], pair["id"]))
            selected_case = {
                "relationship_type": spec["label"],
                "artifact": spec["filename"],
                "slot": slot_name,
                "pair": pair,
            }
            selected.append(selected_case)
            chosen_for_artifact.append(selected_case)
            slot_report.append(
                {
                    "slot": slot_name,
                    "eligible_case_types": list(accepted_types),
                    "selected_case_id": pair["id"],
                    "selected_case_type": pair["case_type"],
                }
            )
        if len(chosen_for_artifact) != CASES_PER_RELATIONSHIP:
            raise BuildError(f"{spec['label']} did not select exactly four cases")
        manifests.append(
            {
                "relationship_type": spec["label"],
                "filename": spec["filename"],
                "sha256": sha256_file(path),
                "source_pair_count": len(pairs),
                "sampling_slots": slot_report,
            }
        )
    return selected, manifests


def _base_entry(
    selected: dict[str, Any],
    artifact_sha256: str,
    anchor: dict[str, Any],
    variant_kind: str,
    question: str,
) -> dict[str, Any]:
    pair = selected["pair"]
    answer = pair["expected_answer"]
    return {
        "id": f"{pair['id']}::{variant_kind}",
        "source_case_id": pair["id"],
        "source_golden_artifact": selected["artifact"],
        "source_golden_artifact_sha256": artifact_sha256,
        "relationship_type": selected["relationship_type"],
        "source_relationship_type": pair.get("relationship_type"),
        "sampling_slot": selected["slot"],
        "case_type": pair.get("case_type"),
        "variant_kind": variant_kind,
        "original_question": pair["question"],
        "question": question,
        "expected_answer": answer,
        "expected_answer_sha256": hashlib.sha256(
            answer.encode("utf-8")
        ).hexdigest(),
        "anchor": deepcopy(anchor),
        "source_provenance": deepcopy(pair["provenance"]),
    }


def _reusable_rewordings(output_path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    if not output_path.exists():
        return {}
    try:
        payload = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    reusable: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in payload.get("entries", []):
        if entry.get("variant_kind") == "reworded":
            key = (entry.get("source_golden_artifact"), entry.get("source_case_id"))
            reusable[key] = entry
    return reusable


def build_final_payload(
    *,
    output_path: Path = DEFAULT_OUTPUT,
    generate_rewordings: bool = True,
    reuse_existing: bool = True,
    requester: Callable[[str, dict[str, Any], int], str] | None = None,
    batch_requester: Callable[
        [list[dict[str, Any]], int], dict[str, str]
    ] = request_rewording_batch,
) -> dict[str, Any]:
    selected, manifests = select_source_cases()
    hashes = {item["filename"]: item["sha256"] for item in manifests}
    reusable = _reusable_rewordings(output_path) if reuse_existing else {}
    entries: list[dict[str, Any]] = []
    omitted_rewordings: list[dict[str, Any]] = []
    generated_by_key: dict[
        tuple[str, str], tuple[str, dict[str, Any]]
    ] = {}

    prepared: list[dict[str, Any]] = []
    if generate_rewordings:
        for selected_case in selected:
            pair = selected_case["pair"]
            anchor = choose_anchor(pair)
            artifact_hash = hashes[selected_case["artifact"]]
            reuse_key = (selected_case["artifact"], pair["id"])
            reusable_entry = reusable.get(reuse_key)
            if (
                reusable_entry
                and reusable_entry.get("expected_answer") == pair["expected_answer"]
                and reusable_entry.get("source_golden_artifact_sha256")
                == artifact_hash
            ):
                accepted, verification = verify_reworded_variant(
                    str(pair["question"]),
                    str(reusable_entry.get("question") or ""),
                    anchor,
                )
                if accepted:
                    generated_by_key[reuse_key] = (
                        reusable_entry["question"],
                        {
                            key: deepcopy(value)
                            for key, value in (
                                reusable_entry.get("variant_metadata") or {}
                            ).items()
                            if key != "reused_from_existing_output"
                        }
                        or {
                            "model": MODEL,
                            "temperature": 0,
                            "verification": verification,
                        },
                    )
                    continue
            prepared.append({**selected_case, "anchor": anchor})

        if requester is None:
            batched, omitted_rewordings = generate_verified_rewordings_batch(
                prepared, requester=batch_requester
            )
            for key, (question, metadata) in batched.items():
                generated_by_key[key] = (
                    question,
                    {
                        "model": MODEL,
                        "temperature": 0,
                        **metadata,
                    },
                )

    for selected_case in selected:
        pair = selected_case["pair"]
        anchor = choose_anchor(pair)
        artifact_hash = hashes[selected_case["artifact"]]
        original = _base_entry(
            selected_case,
            artifact_hash,
            anchor,
            "original",
            pair["question"],
        )
        entries.append(original)

        typo = build_typo_variant(pair, anchor)
        typo_entry = _base_entry(
            selected_case,
            artifact_hash,
            anchor,
            "typo",
            typo["question"],
        )
        typo_entry["variant_metadata"] = {
            key: value for key, value in typo.items() if key != "question"
        }
        entries.append(typo_entry)

        if not generate_rewordings:
            continue
        reuse_key = (selected_case["artifact"], pair["id"])
        if requester is not None and reuse_key not in generated_by_key:
            reworded, metadata = generate_verified_rewording(
                pair, anchor, requester=requester
            )
            if reworded is None:
                omitted_rewordings.append(
                    {
                        "source_golden_artifact": selected_case["artifact"],
                        "source_case_id": pair["id"],
                        **metadata,
                    }
                )
                continue
            generated_by_key[reuse_key] = (
                reworded,
                {
                    "model": MODEL,
                    "temperature": 0,
                    **metadata,
                },
            )
        generated = generated_by_key.get(reuse_key)
        if generated is None:
            continue
        reworded, metadata = generated
        reworded_entry = _base_entry(
            selected_case,
            artifact_hash,
            anchor,
            "reworded",
            reworded,
        )
        reworded_entry["variant_metadata"] = metadata
        entries.append(reworded_entry)

    variant_counts = {
        kind: sum(entry["variant_kind"] == kind for entry in entries)
        for kind in ("original", "typo", "reworded")
    }
    relationship_counts = {
        spec["label"]: {
            kind: sum(
                entry["relationship_type"] == spec["label"]
                and entry["variant_kind"] == kind
                for entry in entries
            )
            for kind in ("original", "typo", "reworded")
        }
        for spec in ARTIFACT_SPECS
    }
    return {
        "schema_version": "1.0",
        "purpose": "Phase E fixed local-RAGAS sample with phrasing robustness variants",
        "source_relationship_type_count": len(ARTIFACT_SPECS),
        "excluded_artifacts": [
            {
                "filename": "golden_set_phase1_fixture.json",
                "reason": (
                    "legacy 10-pair Persistence-only prototype superseded by "
                    "the full technique-to-mitigation artifact"
                ),
            }
        ],
        "sampling_policy": {
            "cases_per_relationship_type": CASES_PER_RELATIONSHIP,
            "source_case_count": len(selected),
            "selection_order": (
                "For each documented slot, choose the lexicographically smallest "
                "case ID among the slot's listed case types whose question has a "
                "resolvable anchor, whose expected answer and provenance are "
                "present, and whose deterministic typo passes the realism bounds."
            ),
            "random_sampling": False,
            "artifacts": manifests,
        },
        "variant_policy": {
            "originals_per_source_case": 1,
            "typos_per_source_case": 1,
            "rewordings_per_source_case_maximum": 1,
            "typo_methods": [
                "adjacent_transposition",
                "single_character_drop",
            ],
            "typo_minimum_sequence_similarity": MIN_TYPO_SIMILARITY,
            "typo_allowed_levenshtein_distances": [1, 2],
            "rewording_model": MODEL,
            "rewording_temperature": 0,
            "rewording_max_attempts": 2,
            "rewording_batch_size": REWORDING_BATCH_SIZE,
            "rewording_anchor_minimum_fuzzy_similarity": (
                MIN_REWORD_ANCHOR_SIMILARITY
            ),
            "reference_answer_policy": (
                "Copy the source expected_answer string exactly; neither typo "
                "generation nor Ollama may determine or modify reference truth."
            ),
        },
        "generation_summary": {
            "entry_count": len(entries),
            "variant_counts": variant_counts,
            "relationship_variant_counts": relationship_counts,
            "verified_rewording_count": variant_counts["reworded"],
            "omitted_rewording_count": len(omitted_rewordings),
            "omitted_rewordings": omitted_rewordings,
        },
        "entries": entries,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--no-rewordings",
        action="store_true",
        help="Build only deterministic originals and typo variants.",
    )
    parser.add_argument(
        "--no-reuse",
        action="store_true",
        help="Regenerate rather than reuse already-verified rewordings.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = build_final_payload(
        output_path=args.output,
        generate_rewordings=not args.no_rewordings,
        reuse_existing=not args.no_reuse,
    )
    args.output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    summary = payload["generation_summary"]
    print(
        json.dumps(
            {
                "output": str(args.output),
                "entry_count": summary["entry_count"],
                "variant_counts": summary["variant_counts"],
                "omitted_rewording_count": summary["omitted_rewording_count"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
