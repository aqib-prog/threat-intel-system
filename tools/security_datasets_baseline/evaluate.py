#!/usr/bin/env python3
"""Card 5 Part 1 step 5: pre-Layer-2 Security-Datasets baseline."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from re import _constants, _parser
from typing import Any, Iterable
from zipfile import ZipFile

import yaml


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
DEFAULT_MANIFEST = HERE / "corpus_manifest.json"
DEFAULT_REPORT_JSON = HERE / "baseline_report.json"
DEFAULT_REPORT_MD = HERE / "baseline_report.md"
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
# Even one-character branches must be retained: dropping a short alternative
# would turn an otherwise useful OR guard into TRUE and send every long JSON
# event through a potentially expensive regex. Short guards only affect speed;
# the original regex still decides the match.
MIN_PREFILTER_LITERAL = 1

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from log_analysis.detector import detect  # noqa: E402
from log_analysis.mappings import (  # noqa: E402
    AWS_RULES,
    AWS_SIGMA_RULES,
    KUBERNETES_RULES,
    LINUX_RULES,
    LINUX_SIGMA_RULES,
    MACOS_RULES,
    MACOS_SIGMA_EXPANSION_RULES,
    MACOS_SIGMA_RULES,
    WINDOWS_RULES,
    WINDOWS_SIGMA_EXPANSION_RULES,
    WINDOWS_SIGMA_RULES,
)
from log_analysis.parser import parse_log  # noqa: E402
from log_analysis.structured import StructuredCondition  # noqa: E402


# The step-5/7/8 reports are historical checkpoint measurements. Keep their
# original 288-rule runtime inventory explicit even as reviewed compiler output
# is promoted into production one platform at a time. Runtime integration has
# its own exact-artifact and production-analyzer regression tests.
CHECKPOINT_RUNTIME_RULES_BY_PLATFORM = {
    "windows": WINDOWS_RULES + WINDOWS_SIGMA_RULES + WINDOWS_SIGMA_EXPANSION_RULES,
    "linux": LINUX_RULES + LINUX_SIGMA_RULES,
    "aws": AWS_RULES + AWS_SIGMA_RULES,
    "kubernetes": KUBERNETES_RULES,
    "macos": MACOS_RULES + MACOS_SIGMA_RULES + MACOS_SIGMA_EXPANSION_RULES,
}


class EvaluationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Prefilter:
    kind: str
    value: str | tuple["Prefilter", ...] | None = None

    def matches(self, lowered_text: str) -> bool:
        if self.kind == "true":
            return True
        if self.kind == "needle":
            return str(self.value) in lowered_text
        children = self.value if isinstance(self.value, tuple) else ()
        if self.kind == "all":
            return all(child.matches(lowered_text) for child in children)
        if self.kind == "any":
            return any(child.matches(lowered_text) for child in children)
        raise AssertionError(self.kind)

    def to_dict(self) -> dict[str, Any]:
        if self.kind in {"true", "needle"}:
            return {"kind": self.kind, "value": self.value}
        children = self.value if isinstance(self.value, tuple) else ()
        return {"kind": self.kind, "children": [child.to_dict() for child in children]}

    def anchors(self) -> tuple[str, ...] | None:
        """Return an OR-list of literals every match must contain.

        For an ALL node, any child is a necessary condition, so choose the
        child with the longest shortest anchor. For ANY, every branch must be
        represented. None means no safe literal anchor is available.
        """
        if self.kind == "true":
            return None
        if self.kind == "needle":
            return (str(self.value),)
        children = self.value if isinstance(self.value, tuple) else ()
        child_anchors = [child.anchors() for child in children]
        if self.kind == "any":
            if any(anchors is None for anchors in child_anchors):
                return None
            return tuple(
                sorted({needle for anchors in child_anchors for needle in anchors or ()})
            )
        available = [anchors for anchors in child_anchors if anchors]
        if not available:
            return None
        return max(
            available,
            key=lambda anchors: (min(map(len, anchors)), -len(anchors), max(map(len, anchors))),
        )


TRUE_PREFILTER = Prefilter("true")


def _combine(kind: str, children: Iterable[Prefilter]) -> Prefilter:
    flat: list[Prefilter] = []
    for child in children:
        if kind == "any" and child.kind == "true":
            return TRUE_PREFILTER
        if kind == "all" and child.kind == "true":
            continue
        if child.kind == kind and isinstance(child.value, tuple):
            flat.extend(child.value)
        else:
            flat.append(child)
    unique: dict[str, Prefilter] = {repr(child): child for child in flat}
    ordered = list(unique.values())
    if not ordered:
        return TRUE_PREFILTER
    if len(ordered) == 1:
        return ordered[0]
    if kind == "all":
        ordered.sort(key=lambda item: len(str(item.value)), reverse=True)
    return Prefilter(kind, tuple(ordered))


def _literal_prefilter(chars: list[int]) -> Prefilter:
    value = "".join(chr(char) for char in chars)
    if len(value) < MIN_PREFILTER_LITERAL or not value.isprintable():
        return TRUE_PREFILTER
    return Prefilter("needle", value.lower())


def _prefilter_from_sequence(sequence: Iterable[tuple[Any, Any]]) -> Prefilter:
    required: list[Prefilter] = []
    literals: list[int] = []

    def flush() -> None:
        nonlocal literals
        if literals:
            required.append(_literal_prefilter(literals))
            literals = []

    for op, arg in sequence:
        if op is _constants.LITERAL:
            literals.append(arg)
            continue
        flush()
        if op is _constants.SUBPATTERN:
            required.append(_prefilter_from_sequence(arg[-1]))
        elif op is _constants.BRANCH:
            required.append(
                _combine("any", (_prefilter_from_sequence(branch) for branch in arg[1]))
            )
        elif op is _constants.ASSERT:
            required.append(_prefilter_from_sequence(arg[1]))
        elif op in {
            _constants.MAX_REPEAT,
            _constants.MIN_REPEAT,
            getattr(_constants, "POSSESSIVE_REPEAT", object()),
        }:
            minimum, _, repeated = arg
            if minimum > 0:
                required.append(_prefilter_from_sequence(repeated))
        elif op is _constants.GROUPREF_EXISTS:
            _, yes_branch, no_branch = arg
            branches = [_prefilter_from_sequence(yes_branch)]
            if no_branch is not None:
                branches.append(_prefilter_from_sequence(no_branch))
            required.append(_combine("any", branches))
        # ASSERT_NOT, optional repeats, character classes, categories, and
        # zero-width assertions cannot safely exclude a raw line.
    flush()
    return _combine("all", required)


@lru_cache(maxsize=None)
def build_prefilter(pattern: str, flags: int = re.IGNORECASE) -> Prefilter:
    """Return a conservative raw-substring guard for an existing regex.

    A false result is safe to skip: only mandatory positive literal runs are
    retained. The original regex remains the source of truth for every line
    that passes this performance guard.
    """
    try:
        return _prefilter_from_sequence(_parser.parse(pattern, flags))
    except (re.error, ValueError, TypeError):
        return TRUE_PREFILTER


@dataclass(frozen=True)
class EvaluationRule:
    pattern: re.Pattern[str]
    technique_id: str
    confidence: str
    platform: str
    origin: str
    source: str
    structured_condition: StructuredCondition | None = None


_WORKER_RULES: list[EvaluationRule] | None = None


@dataclass
class PatternBundle:
    pattern: re.Pattern[str]
    prefilter: Prefilter
    rules: list[EvaluationRule]


class TechniqueResolver:
    def __init__(self, techniques_path: Path, relationships_path: Path):
        techniques = json.loads(techniques_path.read_text(encoding="utf-8"))
        relationships = json.loads(relationships_path.read_text(encoding="utf-8"))
        self.by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.by_stix = {item["id"]: item for item in techniques}
        for item in techniques:
            self.by_name[item["name"]].append(item)
        self.parent_by_child = {
            item["source_ref"]: item["target_ref"]
            for item in relationships
            if item["relationship_type"] == "subtechnique-of"
        }

    def resolve(self, name: str, parent_hint: str | None) -> str:
        candidates = self.by_name.get(name, [])
        if len(candidates) == 1:
            return candidates[0]["external_id"].upper()
        if parent_hint:
            matches = []
            for item in candidates:
                parent = self.by_stix.get(self.parent_by_child.get(item["id"], ""))
                if parent and parent["name"] == parent_hint:
                    matches.append(item)
            if len(matches) == 1:
                return matches[0]["external_id"].upper()
        raise EvaluationError(
            f"cannot resolve runtime technique {name!r} with parent {parent_hint!r}"
        )


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise EvaluationError(f"cannot load generated specs: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_rules(
    windows_structured_specs: Path | None = None,
    *,
    structured_specs: Path | None = None,
    structured_platform: str | None = None,
) -> tuple[list[EvaluationRule], dict[str, Any]]:
    if windows_structured_specs is not None:
        if structured_specs is not None:
            raise EvaluationError("provide only one structured-spec artifact")
        structured_specs = windows_structured_specs
        structured_platform = "windows"
    if (structured_specs is None) != (structured_platform is None):
        raise EvaluationError(
            "structured specs and their target platform must be provided together"
        )
    resolver = TechniqueResolver(
        BACKEND / "data/parsed/techniques.json",
        BACKEND / "data/parsed/relationships.json",
    )
    rules: list[EvaluationRule] = []
    for platform, platform_rules in CHECKPOINT_RUNTIME_RULES_BY_PLATFORM.items():
        for rule in platform_rules:
            rules.append(
                EvaluationRule(
                    pattern=rule.pattern,
                    technique_id=resolver.resolve(rule.technique_name, rule.parent_hint),
                    confidence=rule.confidence,
                    platform=platform,
                    origin="runtime",
                    source=rule.source,
                    structured_condition=rule.structured_condition,
                )
            )

    sigma = _load_module(
        REPO / "tools/sigma_compiler/full_recompile_rule_specs.py", "step5_sigma_specs"
    )
    structured_by_key: dict[tuple[str, str], Any] = {}
    if structured_specs is not None:
        structured_module = _load_module(
            structured_specs, f"layer2_{structured_platform}_structured_specs"
        )
        if structured_module.SIGMA_COMMIT != sigma.SIGMA_COMMIT:
            raise EvaluationError(
                "structured specs and Sigma rule specs use different commits"
            )
        structured_by_key = structured_module.STRUCTURED_BY_SOURCE_TECHNIQUE
    for platform, specs in sigma.RULE_SPECS_BY_PLATFORM.items():
        for item in specs:
            kwargs = item["rule_kwargs"]
            structured_tree = (
                structured_by_key.get(
                    (kwargs["source"], item["technique_id"].upper())
                )
                if platform == structured_platform
                else None
            )
            rules.append(
                EvaluationRule(
                    pattern=re.compile(kwargs["pattern"], re.IGNORECASE),
                    technique_id=item["technique_id"].upper(),
                    confidence=kwargs["confidence"],
                    platform=platform,
                    origin="sigma_preview",
                    source=kwargs["source"],
                    structured_condition=(
                        StructuredCondition.from_dict(structured_tree)
                        if structured_tree is not None
                        else None
                    ),
                )
            )

    falco = _load_module(
        REPO / "tools/falco_compiler/full_rule_specs.py", "step5_falco_specs"
    )
    for item in falco.RULE_SPECS:
        kwargs = item["rule_kwargs"]
        rules.append(
            EvaluationRule(
                pattern=re.compile(kwargs["pattern"], re.IGNORECASE),
                technique_id=item["technique_id"].upper(),
                confidence=kwargs["confidence"],
                platform=kwargs["platform"],
                origin="falco_preview",
                source=kwargs["source"],
            )
        )
    inventory = {
        "total": len(rules),
        "by_origin": dict(sorted(Counter(rule.origin for rule in rules).items())),
        "by_platform": dict(sorted(Counter(rule.platform for rule in rules).items())),
        "sigma_commit": sigma.SIGMA_COMMIT,
        "pysigma_version": sigma.PYSIGMA_VERSION,
        "falco_commit": falco.FALCO_COMMIT,
    }
    for platform in CHECKPOINT_RUNTIME_RULES_BY_PLATFORM:
        inventory[f"{platform}_structured_rule_count"] = sum(
            rule.structured_condition is not None and rule.platform == platform
            for rule in rules
        )
    return rules, inventory


def bundle_rules(rules: list[EvaluationRule]) -> list[PatternBundle]:
    grouped: dict[tuple[str, int], list[EvaluationRule]] = defaultdict(list)
    for rule in rules:
        grouped[(rule.pattern.pattern, rule.pattern.flags)].append(rule)
    return [
        PatternBundle(
            pattern=members[0].pattern,
            prefilter=build_prefilter(pattern, flags),
            rules=members,
        )
        for (pattern, flags), members in grouped.items()
    ]


def verify_checkout(root: Path, expected_commit: str) -> None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True
    )
    actual = result.stdout.strip()
    if actual != expected_commit:
        raise EvaluationError(f"Security-Datasets commit {actual} != {expected_commit}")


def manifest_commit(manifest: dict[str, Any]) -> str:
    commit = manifest.get("corpus_commit", manifest.get("security_datasets_commit"))
    if not isinstance(commit, str) or not commit:
        raise EvaluationError("manifest has no pinned corpus commit")
    return commit


def ground_truth(metadata: dict[str, Any]) -> list[str]:
    result = []
    for item in metadata.get("attack_mappings", []):
        technique = str(item["technique"]).upper()
        sub = item.get("sub-technique")
        if isinstance(sub, int):
            sub = f"{sub:03d}"
        result.append(f"{technique}.{sub}" if sub else technique)
    return sorted(set(result))


def read_capture(path: Path, reader: str | None = None) -> tuple[str, str, int]:
    if reader == "macos_attack_dataset":
        macos_tools = REPO / "tools/macos_structured"
        if str(macos_tools) not in sys.path:
            sys.path.insert(0, str(macos_tools))
        from corpus import read_macos_attack_file

        text, details = read_macos_attack_file(path)
        return text, path.name, details["source_bytes"]
    if reader is not None:
        raise EvaluationError(f"unsupported capture reader: {reader}")
    if not path.name.casefold().endswith(".zip"):
        text = path.read_text(encoding="utf-8-sig")
        return text, path.name, len(text.encode("utf-8"))
    with ZipFile(path) as archive:
        supported_suffixes = (".json", ".jsonl", ".ndjson", ".log", ".txt")
        members = [
            item
            for item in archive.infolist()
            if item.filename.casefold().endswith(supported_suffixes)
            and not item.filename.startswith("__MACOSX/")
            and not item.is_dir()
        ]
        if len(members) != 1:
            raise EvaluationError(
                f"{path}: expected one supported log member, found {len(members)}"
            )
        member = members[0]
        return (
            archive.read(member).decode("utf-8", errors="replace"),
            member.filename,
            member.file_size,
        )


def _aggregate_predictions(
    matches: list[tuple[EvaluationRule, str]], origins: set[str]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for rule, _evidence in matches:
        if rule.origin not in origins:
            continue
        current = result.get(rule.technique_id)
        rank = CONFIDENCE_RANK[rule.confidence]
        if current is None or rank > CONFIDENCE_RANK[current["confidence"]]:
            result[rule.technique_id] = {
                "confidence": rule.confidence,
                "sources": [rule.source],
                "origins": [rule.origin],
            }
        elif rank == CONFIDENCE_RANK[current["confidence"]]:
            current["sources"] = sorted(set(current["sources"] + [rule.source]))[:10]
            current["origins"] = sorted(set(current["origins"] + [rule.origin]))
    return dict(sorted(result.items()))


def evaluate_case(
    root: Path, case: dict[str, str], all_rules: list[EvaluationRule]
) -> dict[str, Any]:
    capture_path = root / case["capture"]
    metadata_path = root / case["metadata"] if case.get("metadata") else None
    if not capture_path.is_file() or (metadata_path is not None and not metadata_path.is_file()):
        raise EvaluationError(f"fixture missing: {metadata_path} / {capture_path}")
    metadata = (
        yaml.safe_load(metadata_path.read_text(encoding="utf-8-sig")) or {}
        if metadata_path is not None
        else {}
    )
    explicit_ground_truth = case.get("ground_truth")
    expected = (
        sorted({str(item).upper() for item in explicit_ground_truth})
        if isinstance(explicit_ground_truth, list)
        else ground_truth(metadata)
    )
    if not expected:
        raise EvaluationError(f"{metadata_path}: empty ATT&CK ground truth")
    raw_text, member, uncompressed_bytes = read_capture(
        capture_path, case.get("reader")
    )
    started = time.perf_counter()
    detection = detect(raw_text)
    platform = detection.platform
    eligible = [
        rule for rule in all_rules if platform is None or rule.platform == platform
    ]
    events = parse_log(raw_text, platform) if detection.is_raw_log else []
    lines = [(event.normalized_line, event.normalized_line.lower(), event.raw_line) for event in events]
    corpus_lowered = "\n".join(lowered for _, lowered, _ in lines)
    matches: list[tuple[EvaluationRule, str]] = []
    raw_evidence_by_pattern: dict[tuple[str, int], str] = {}
    prefilter_rejections = 0
    regex_searches = 0
    bundles = bundle_rules(eligible)
    for bundle in bundles:
        evidence = None
        anchors = bundle.prefilter.anchors()
        if anchors and not any(anchor in corpus_lowered for anchor in anchors):
            prefilter_rejections += len(lines)
            continue
        for normalized, lowered, raw in lines:
            if anchors and not any(anchor in lowered for anchor in anchors):
                prefilter_rejections += 1
                continue
            if not bundle.prefilter.matches(lowered):
                prefilter_rejections += 1
                continue
            regex_searches += 1
            if bundle.pattern.search(normalized):
                evidence = raw
                break
        if evidence is not None:
            raw_evidence_by_pattern[
                (bundle.pattern.pattern, bundle.pattern.flags)
            ] = evidence
            matches.extend((rule, evidence) for rule in bundle.rules)

    runtime = _aggregate_predictions(matches, {"runtime"})
    expanded = _aggregate_predictions(
        matches, {"runtime", "sigma_preview", "falco_preview"}
    )
    field_event_indices: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        for field_name in event.source_fields:
            field_event_indices[field_name].append(index)

    layer2_matches: list[tuple[EvaluationRule, str]] = []
    structured_evaluations = 0
    structured_rule_count = 0
    raw_fallback_searches = 0
    for rule in eligible:
        condition = rule.structured_condition
        if condition is None:
            evidence = raw_evidence_by_pattern.get(
                (rule.pattern.pattern, rule.pattern.flags)
            )
            if evidence is not None:
                layer2_matches.append((rule, evidence))
            continue

        structured_rule_count += 1
        if any(not required for required in condition.requirement_sets):
            candidate_indices = range(len(events))
        else:
            candidate_indices = sorted(
                {
                    index
                    for field_name in condition.positive_fields
                    for index in field_event_indices.get(field_name, ())
                }
            )
        evidence = None
        considered = set(candidate_indices)
        for index in candidate_indices:
            event = events[index]
            if not condition.is_authoritative(event):
                continue
            structured_evaluations += 1
            if condition.matches(event):
                evidence = event.raw_line
                break

        if evidence is None:
            # Only partial records for which the required fields could not be
            # extracted retain the raw fallback. Complete JSON records are
            # authoritative even when a referenced field is absent.
            for index, event in enumerate(events):
                if index in considered or condition.is_authoritative(event):
                    continue
                raw_fallback_searches += 1
                if rule.pattern.search(event.normalized_line):
                    evidence = event.raw_line
                    break
        if evidence is not None:
            layer2_matches.append((rule, evidence))

    layer2 = _aggregate_predictions(
        layer2_matches, {"runtime", "sigma_preview", "falco_preview"}
    )
    return {
        "metadata_id": case.get(
            "id", metadata.get("id", metadata_path.stem if metadata_path else capture_path.stem)
        ),
        "title": case.get("title", metadata.get("title", "")),
        "tactic": case["tactic"],
        "capture": case["capture"],
        "archive_member": member,
        "uncompressed_bytes": uncompressed_bytes,
        "ground_truth": expected,
        "detector": {
            "is_raw_log": detection.is_raw_log,
            "score": detection.score,
            "platform": platform,
            "signals": detection.signals,
        },
        "parsed_event_count": len(events),
        "eligible_rule_count": len(eligible),
        "unique_pattern_count": len(bundles),
        "prefilter_rejections": prefilter_rejections,
        "regex_searches": regex_searches,
        "runtime_predictions": runtime,
        "expanded_predictions": expanded,
        "layer2_predictions": layer2,
        "structured_rule_count": structured_rule_count,
        "structured_evaluations": structured_evaluations,
        "raw_fallback_searches": raw_fallback_searches,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }


def _initialize_worker(
    structured_specs: str | None = None,
    structured_platform: str | None = None,
) -> None:
    global _WORKER_RULES
    _WORKER_RULES = load_rules(
        structured_specs=Path(structured_specs) if structured_specs else None,
        structured_platform=structured_platform,
    )[0]


def _evaluate_case_worker(
    payload: tuple[int, str, dict[str, str]]
) -> tuple[int, dict[str, Any]]:
    index, root, case = payload
    if _WORKER_RULES is None:
        raise EvaluationError("worker rule inventory was not initialized")
    return index, evaluate_case(Path(root), case, _WORKER_RULES)


def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _score_sets(predicted: set[str], expected: set[str]) -> dict[str, Any]:
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _safe_ratio(2 * precision * recall, precision + recall),
    }


def score_cases(cases: list[dict[str, Any]], prediction_key: str) -> dict[str, Any]:
    totals = Counter()
    macro = Counter()
    family_totals = Counter()
    exact_samples = 0
    detected_samples = 0
    by_tactic: dict[str, list[dict[str, Any]]] = defaultdict(list)
    confidence_counts = {
        confidence: Counter() for confidence in ("high", "medium", "low")
    }
    threshold_counts = {
        "high_only": Counter(),
        "high_and_medium": Counter(),
        "all_confidences": Counter(),
    }

    for case in cases:
        predictions = case[prediction_key]
        predicted = set(predictions)
        expected = set(case["ground_truth"])
        score = _score_sets(predicted, expected)
        totals.update({key: score[key] for key in ("tp", "fp", "fn")})
        macro.update({key: score[key] for key in ("precision", "recall", "f1")})
        exact_samples += predicted == expected
        detected_samples += bool(predicted & expected)
        by_tactic[case["tactic"]].append(case)

        family = _score_sets(
            {item.split(".", 1)[0] for item in predicted},
            {item.split(".", 1)[0] for item in expected},
        )
        family_totals.update({key: family[key] for key in ("tp", "fp", "fn")})

        for confidence in confidence_counts:
            bucket = {
                technique
                for technique, detail in predictions.items()
                if detail["confidence"] == confidence
            }
            confidence_counts[confidence]["tp"] += len(bucket & expected)
            confidence_counts[confidence]["fp"] += len(bucket - expected)
            confidence_counts[confidence]["ground_truth"] += len(expected)

        threshold_sets = {
            "high_only": {
                technique
                for technique, detail in predictions.items()
                if detail["confidence"] == "high"
            },
            "high_and_medium": {
                technique
                for technique, detail in predictions.items()
                if detail["confidence"] in {"high", "medium"}
            },
            "all_confidences": predicted,
        }
        for name, threshold_set in threshold_sets.items():
            value = _score_sets(threshold_set, expected)
            threshold_counts[name].update(
                {key: value[key] for key in ("tp", "fp", "fn")}
            )

    micro = _score_sets_from_counts(totals)
    family_micro = _score_sets_from_counts(family_totals)
    count = len(cases)
    return {
        "sample_count": count,
        "micro_strict_exact_id": micro,
        "macro_strict_exact_id": {
            key: _safe_ratio(macro[key], count) for key in ("precision", "recall", "f1")
        },
        "family_aware_diagnostic": family_micro,
        "samples_with_any_correct_prediction": detected_samples,
        "samples_with_exact_prediction_set": exact_samples,
        "confidence_buckets_disjoint": {
            name: _score_confidence_bucket(counts)
            for name, counts in confidence_counts.items()
        },
        "confidence_thresholds_cumulative": {
            name: _score_sets_from_counts(counts)
            for name, counts in threshold_counts.items()
        },
        "by_tactic": {
            tactic: score_cases(items, prediction_key)["micro_strict_exact_id"]
            | {"sample_count": len(items)}
            for tactic, items in sorted(by_tactic.items())
        }
        if len(by_tactic) > 1
        else {},
    }


def _score_sets_from_counts(counts: Counter) -> dict[str, Any]:
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _safe_ratio(2 * precision * recall, precision + recall),
    }


def _score_confidence_bucket(counts: Counter) -> dict[str, Any]:
    tp, fp, ground_truth_count = counts["tp"], counts["fp"], counts["ground_truth"]
    return {
        "tp": tp,
        "fp": fp,
        "prediction_count": tp + fp,
        "precision": _safe_ratio(tp, tp + fp),
        "recall_contribution": _safe_ratio(tp, ground_truth_count),
    }


def render_markdown(report: dict[str, Any]) -> str:
    runtime = report["metrics"]["runtime_current"]
    expanded = report["metrics"]["layer1_preview"]
    platform = report["platform"]
    platform_label = platform.capitalize()
    layer2_key = f"layer2_{platform}_preview"
    layer2 = report["metrics"].get(layer2_key)
    comparison_baseline = report.get("comparison_step5_baseline")
    analyzed = layer2 or expanded
    analyzed_prediction_key = (
        "layer2_predictions" if layer2 is not None else "expanded_predictions"
    )
    runtime_strict = runtime["micro_strict_exact_id"]
    expanded_strict = expanded["micro_strict_exact_id"]
    analyzed_family = analyzed["family_aware_diagnostic"]
    false_positive_techniques: Counter[str] = Counter()
    false_positive_sources: Counter[str] = Counter()
    prediction_counts: list[int] = []
    sample_count = len(report["cases"])
    for case in report["cases"]:
        expected = set(case["ground_truth"])
        predictions = case[analyzed_prediction_key]
        prediction_counts.append(len(predictions))
        for technique_id, detail in predictions.items():
            if technique_id in expected:
                continue
            false_positive_techniques[technique_id] += 1
            false_positive_sources.update(set(detail["sources"]))

    mean_predictions = _safe_ratio(sum(prediction_counts), len(prediction_counts))
    lines = [
        (
            f"# Card 5 structured-field pilot: {platform_label}"
            if layer2 is not None
            else "# Card 5 step-5 pre-Layer-2 baseline"
        ),
        "",
        f"{report['corpus_name']} commit: `{report['corpus_commit']}`",
        "",
        "## Primary strict metrics",
        "",
        "Sample-level predictions are compared to metadata ATT&CK IDs using exact IDs. "
        f"Micro scores aggregate TP/FP/FN across all {sample_count} captures.",
        "",
        "| Rule set | Precision | Recall | F1 | TP | FP | FN |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    result_rows = [("Current runtime", runtime), ("Layer-1 preview", expanded)]
    if layer2 is not None:
        result_rows.append((f"Layer-2 {platform_label} preview", layer2))
    for name, result in result_rows:
        metric = result["micro_strict_exact_id"]
        lines.append(
            f"| {name} | {metric['precision']:.3f} | {metric['recall']:.3f} | "
            f"{metric['f1']:.3f} | {metric['tp']} | {metric['fp']} | {metric['fn']} |"
        )
    lines += [
        "",
        (
            f"## Layer-2 {platform_label} preview confidence thresholds"
            if layer2 is not None
            else "## Layer-1 preview confidence thresholds"
        ),
        "",
        "| Threshold | Precision | Recall | F1 | TP | FP | FN |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, metric in analyzed["confidence_thresholds_cumulative"].items():
        lines.append(
            f"| {name.replace('_', ' ')} | {metric['precision']:.3f} | "
            f"{metric['recall']:.3f} | {metric['f1']:.3f} | {metric['tp']} | "
            f"{metric['fp']} | {metric['fn']} |"
        )
    lines += [
        "",
        (
            f"## Per-tactic Layer-2 {platform_label} preview"
            if layer2 is not None
            else "## Per-tactic Layer-1 preview"
        ),
        "",
        "| Tactic | Samples | Precision | Recall | F1 | TP | FP | FN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for tactic, metric in analyzed["by_tactic"].items():
        lines.append(
            f"| {tactic} | {metric['sample_count']} | {metric['precision']:.3f} | "
            f"{metric['recall']:.3f} | {metric['f1']:.3f} | {metric['tp']} | "
            f"{metric['fp']} | {metric['fn']} |"
        )
    lines += ["", "## Checkpoint verdict and failure analysis", ""]
    if layer2 is not None:
        layer2_strict = layer2["micro_strict_exact_id"]
        comparison_strict = (
            comparison_baseline["layer1_micro_strict_exact_id"]
            if comparison_baseline
            else expanded_strict
        )
        lines += [
            f"The {platform_label} structured pilot changes strict precision from "
            f"{comparison_strict['precision']:.1%} to {layer2_strict['precision']:.1%} "
            f"({100 * (layer2_strict['precision'] - comparison_strict['precision']):+.1f} "
            f"percentage points) and recall from {comparison_strict['recall']:.1%} "
            f"to {layer2_strict['recall']:.1%} "
            f"({100 * (layer2_strict['recall'] - comparison_strict['recall']):+.1f} "
            "percentage points).",
            "",
            f"The field-authoritative preview emits a mean of {mean_predictions:.1f} "
            f"distinct technique IDs per capture (minimum {min(prediction_counts)}, "
            f"maximum {max(prediction_counts)}). Parent/sub-technique-family scoring "
            f"is {analyzed_family['precision']:.1%} precision and "
            f"{analyzed_family['recall']:.1%} recall.",
        ]
    else:
        lines += [
            f"The Layer-1 preview clears the proposed recall bar "
            f"({expanded_strict['recall']:.1%} versus 60%) but fails the proposed "
            f"precision bar ({expanded_strict['precision']:.1%} versus 80%). It "
            f"raises recall by "
            f"{100 * (expanded_strict['recall'] - runtime_strict['recall']):+.1f} "
            f"percentage points from the current runtime, while precision changes by "
            f"{100 * (expanded_strict['precision'] - runtime_strict['precision']):+.1f} "
            "percentage points.",
            "",
            f"The preview emits a mean of {mean_predictions:.1f} distinct technique IDs "
            f"per capture (minimum {min(prediction_counts)}, maximum "
            f"{max(prediction_counts)}). Parent/sub-technique-family scoring improves "
            f"the result only to {analyzed_family['precision']:.1%} precision and "
            f"{analyzed_family['recall']:.1%} recall, so ID granularity is not the "
            "main cause of the precision failure.",
        ]
    lines += ["", "Most frequent strict false-positive technique IDs:", ""]
    lines.extend(
        f"- `{technique_id}` in {count}/{sample_count} captures"
        for technique_id, count in false_positive_techniques.most_common(10)
    )
    lines += [
        "",
        "Most frequent contributing sources (one count per affected capture):",
        "",
    ]
    lines.extend(
        f"- `{source}` in {count}/{sample_count} captures"
        for source, count in false_positive_sources.most_common(10)
    )
    if layer2 is not None:
        lines += [
            "",
            "Structured Sigma predicates are evaluated against their original "
            "source fields, so unrelated values elsewhere in an event cannot "
            "satisfy a field-specific condition.",
        ]
    else:
        lines += [
            "",
            "The dominant failure is field erasure in the pre-Layer-2 raw-text "
            "projection. The generated regexes preserve Boolean structure but not "
            "which JSON field a literal belongs to.",
        ]
    lines += [
        "",
        "## Method and limitations",
        "",
        (
            f"- {platform_label} records use field-authoritative Sigma matching; partial "
            "records retain per-rule raw fallback until a complete positive field "
            f"branch is extracted. Raw-only and non-{platform_label} rules are unchanged."
            if layer2 is not None
            else "- This is the existing raw-text detector/parser/regex approach; no canonical field extraction is used."
        ),
        "- The primary metric is sample-level exact ATT&CK-ID matching. A parent/sub-technique family diagnostic is included in JSON but is not used as the headline result.",
        "- Each capture contains attack activity plus surrounding host telemetry. Predictions outside the metadata labels count as false positives, even when they may describe real secondary behavior present in the capture.",
        "- This attack-only corpus cannot establish a benign-log false-positive rate; that requires the separate benign batch described in Card 5 Layer 3.",
        "- A conservative mandatory-literal prefilter skips lines that cannot satisfy a regex, then the original Python regex decides every candidate. This changes performance, not matching semantics.",
        f"- {report['license_observation']}",
        "",
        "## Case details",
        "",
        (
            "| Dataset | Tactic | Ground truth | Runtime predictions | Layer-1 predictions | Layer-2 predictions | Seconds |"
            if layer2 is not None
            else "| Dataset | Tactic | Ground truth | Runtime predictions | Layer-1 predictions | Seconds |"
        ),
        (
            "|---|---|---|---|---|---|---:|"
            if layer2 is not None
            else "|---|---|---|---|---|---:|"
        ),
    ]
    for case in report["cases"]:
        values = [
            case["metadata_id"],
            case["tactic"],
            ", ".join(case["ground_truth"]),
            ", ".join(case["runtime_predictions"]) or "—",
            ", ".join(case["expanded_predictions"]) or "—",
        ]
        if layer2 is not None:
            values.append(", ".join(case["layer2_predictions"]) or "—")
        values.append(f"{case['elapsed_seconds']:.3f}")
        lines.append(
            "| " + " | ".join(values) + " |"
        )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--datasets-root", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report-json", type=Path, default=DEFAULT_REPORT_JSON)
    parser.add_argument("--report-md", type=Path, default=DEFAULT_REPORT_MD)
    parser.add_argument("--windows-structured-specs", type=Path)
    parser.add_argument(
        "--structured-specs",
        type=Path,
        help="field-aware specs for the platform declared by the selected manifest",
    )
    parser.add_argument("--comparison-baseline-report", type=Path)
    parser.add_argument("--max-cases", type=int)
    parser.add_argument("--workers", type=int, default=1)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    corpus_commit = manifest_commit(manifest)
    verify_checkout(args.datasets_root, corpus_commit)
    if args.windows_structured_specs and args.structured_specs:
        raise EvaluationError("provide only one structured-spec artifact")
    structured_specs = args.structured_specs or args.windows_structured_specs
    structured_platform = (
        ("windows" if args.windows_structured_specs else manifest["platform"])
        if structured_specs
        else None
    )
    if args.windows_structured_specs and manifest["platform"] != "windows":
        raise EvaluationError(
            "--windows-structured-specs requires a Windows corpus manifest"
        )
    cases = manifest["cases"]
    if args.max_cases:
        cases = cases[: args.max_cases]
    rules, rule_inventory = load_rules(
        structured_specs=structured_specs,
        structured_platform=structured_platform,
    )
    if args.workers < 1:
        raise EvaluationError("--workers must be positive")
    indexed_results: dict[int, dict[str, Any]] = {}
    if args.workers == 1:
        for index, case in enumerate(cases, 1):
            indexed_results[index] = evaluate_case(args.datasets_root, case, rules)
            result = indexed_results[index]
            print(
                f"[{index:02d}/{len(cases)}] {result['metadata_id']} "
                f"events={result['parsed_event_count']} "
                f"layer1={len(result['expanded_predictions'])} "
                f"layer2={len(result['layer2_predictions'])} "
                f"seconds={result['elapsed_seconds']:.3f}",
                flush=True,
            )
    else:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=args.workers,
            initializer=_initialize_worker,
            initargs=(
                str(structured_specs) if structured_specs else None,
                structured_platform,
            ),
        ) as executor:
            futures = {
                executor.submit(
                    _evaluate_case_worker, (index, str(args.datasets_root), case)
                ): index
                for index, case in enumerate(cases, 1)
            }
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                index, result = future.result()
                indexed_results[index] = result
                completed += 1
                print(
                    f"[{completed:02d}/{len(cases)} completed; case {index:02d}] "
                    f"{result['metadata_id']} events={result['parsed_event_count']} "
                    f"layer1={len(result['expanded_predictions'])} "
                    f"layer2={len(result['layer2_predictions'])} "
                    f"seconds={result['elapsed_seconds']:.3f}",
                    flush=True,
                )
    results = [indexed_results[index] for index in sorted(indexed_results)]
    metrics = {
        "runtime_current": score_cases(results, "runtime_predictions"),
        "layer1_preview": score_cases(results, "expanded_predictions"),
    }
    if structured_specs:
        metrics[f"layer2_{structured_platform}_preview"] = score_cases(
            results, "layer2_predictions"
        )
    comparison_baseline = None
    if args.comparison_baseline_report:
        baseline_report = json.loads(
            args.comparison_baseline_report.read_text(encoding="utf-8")
        )
        if baseline_report.get(
            "corpus_commit", baseline_report.get("security_datasets_commit")
        ) != corpus_commit:
            raise EvaluationError("comparison baseline uses a different dataset commit")
        if baseline_report["corpus"]["sample_count"] != len(results):
            raise EvaluationError("comparison baseline uses a different sample count")
        comparison_baseline = {
            "artifact": str(args.comparison_baseline_report),
            "layer1_micro_strict_exact_id": baseline_report["metrics"][
                "layer1_preview"
            ]["micro_strict_exact_id"],
        }
    report = {
        "checkpoint": (
            (
                "Card 5 Part 1 roadmap step 7 Windows pilot only"
                if structured_platform == "windows"
                else f"Card 5 Part 1 roadmap step 8 {structured_platform.capitalize()} pilot only"
            )
            if structured_specs
            else (
                "Card 5 Part 1 roadmap step 8 macOS raw baseline only"
                if manifest["platform"] == "macos"
                else "Card 5 Part 1 roadmap step 5 only"
            )
        ),
        "corpus_name": manifest.get("corpus_name", "Security-Datasets"),
        "corpus_commit": corpus_commit,
        "platform": manifest["platform"],
        "selection_policy": manifest["selection_policy"],
        "license_observation": manifest["license_observation"],
        "rule_inventory": rule_inventory,
        "comparison_step5_baseline": comparison_baseline,
        "corpus": {
            "sample_count": len(results),
            "by_tactic": dict(sorted(Counter(case["tactic"] for case in results).items())),
            "uncompressed_bytes": sum(case["uncompressed_bytes"] for case in results),
            "parsed_event_count": sum(case["parsed_event_count"] for case in results),
            "detector_gate_pass_count": sum(case["detector"]["is_raw_log"] for case in results),
        },
        "metrics": metrics,
        "performance": {
            "workers": args.workers,
            "sum_case_elapsed_seconds": round(sum(case["elapsed_seconds"] for case in results), 3),
            "prefilter_rejections": sum(case["prefilter_rejections"] for case in results),
            "regex_searches": sum(case["regex_searches"] for case in results),
            "structured_evaluations": sum(
                case["structured_evaluations"] for case in results
            ),
            "raw_fallback_searches": sum(
                case["raw_fallback_searches"] for case in results
            ),
        },
        "cases": results,
    }
    if "security_datasets_commit" in manifest:
        report["security_datasets_commit"] = corpus_commit
    args.report_json.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    args.report_md.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"corpus": report["corpus"], "metrics": report["metrics"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
