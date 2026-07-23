#!/usr/bin/env python3
"""Card 5 step-1 pySigma compiler prototype.

The output is a review artifact, not a runtime ruleset. In particular, this
script never edits mappings.py and never silently assigns a genuinely
multi-technique Sigma rule to every rule-level ATT&CK tag.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    Placeholder,
    SigmaBool,
    SigmaCasedString,
    SigmaExpansion,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)


HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "prototype_manifest.json"
SCAN = r"[\s\S]*"
ATTACK_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
EXAMPLE_FIELDS = (
    "EventID",
    "Image",
    "NewProcessName",
    "ProcessName",
    "OriginalFileName",
    "ParentImage",
    "CommandLine",
    "User",
)


class CompileError(RuntimeError):
    """Raised when projection would require an unsafe or unknown guess."""


@dataclass(frozen=True)
class TechniqueResolution:
    status: str
    original_tags: list[str]
    resolved_tags: list[str]
    explanation: str


@dataclass(frozen=True)
class CompiledRule:
    source: str
    title: str
    rule_id: str
    platform: str
    confidence: str
    pattern: str
    technique_resolution: TechniqueResolution


def _literal_sigma_string(value: SigmaString) -> str:
    """Project a Sigma string into a Python regex for raw-event substring search.

    pySigma has already applied modifiers, so contains/startswith/endswith are
    represented by explicit wildcard markers. Leading/trailing multi-wildcards
    are redundant under our surrounding event scan and are removed to avoid
    pathological backtracking. Internal wildcards retain their Sigma meaning.
    """

    if isinstance(value, SigmaCasedString):
        raise CompileError(
            "SigmaCasedString cannot be preserved because MappingRule compiles "
            "all patterns with re.IGNORECASE"
        )

    parts = list(value.s)
    while parts and parts[0] is SpecialChars.WILDCARD_MULTI:
        parts.pop(0)
    while parts and parts[-1] is SpecialChars.WILDCARD_MULTI:
        parts.pop()

    projected: list[str] = []
    for part in parts:
        if isinstance(part, str):
            # A parsed JSON event is re-serialized before runtime matching, so
            # each Windows path separator appears doubled there while plain
            # KV/Event Viewer text contains one separator. Accept one or more
            # literal backslashes at each Sigma path-separator position.
            projected.append("".join(r"\\+" if char == "\\" else re.escape(char) for char in part))
        elif part is SpecialChars.WILDCARD_MULTI:
            projected.append(SCAN + "?")
        elif part is SpecialChars.WILDCARD_SINGLE:
            projected.append(r"[\s\S]")
        elif isinstance(part, Placeholder):
            raise CompileError(f"unexpanded Sigma placeholder: {part.name}")
        else:
            raise CompileError(f"unsupported SigmaString part: {type(part).__name__}")

    result = "".join(projected)
    if not result:
        raise CompileError("empty/all-wildcard Sigma string would match every event")
    return result


def _leaf_regex(value: Any) -> str:
    if isinstance(value, SigmaRegularExpression):
        raw = str(value.regexp)
        flags = {
            flag
            for enum_value, flag in (
                (SigmaRegularExpressionFlag.IGNORECASE, "i"),
                (SigmaRegularExpressionFlag.MULTILINE, "m"),
                (SigmaRegularExpressionFlag.DOTALL, "s"),
            )
            if enum_value in value.flags
        }
        # Python only permits a global `(?ims)` group at the beginning of the
        # whole pattern. A Sigma regex becomes one leaf inside a lookahead, so
        # turn any leading global group into an equivalent scoped group.
        leading_flags = re.match(r"^\(\?([ims]+)\)", raw)
        if leading_flags:
            flags.update(leading_flags.group(1))
            raw = raw[leading_flags.end() :]
        rendered_flags = "".join(sorted(flags))
        return f"(?{rendered_flags}:{raw})" if rendered_flags else f"(?:{raw})"
    if isinstance(value, SigmaExpansion):
        if not value.values:
            raise CompileError("empty SigmaExpansion would match no meaningful value")
        return "(?:" + "|".join(_leaf_regex(item) for item in value.values) + ")"
    if isinstance(value, SigmaString):
        return _literal_sigma_string(value)
    if isinstance(value, SigmaNumber):
        return re.escape(str(value.number))
    if isinstance(value, SigmaBool):
        return re.escape(str(value.boolean).lower())
    raise CompileError(f"unsupported pySigma value type: {type(value).__name__}")


def _predicate(node: Any) -> str:
    """Compile a parsed pySigma condition node into a zero-width predicate."""

    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        # Step 1 deliberately projects away field identity because the current
        # runtime searches a flattened raw event. Layer 2 will restore fields.
        return f"(?={SCAN}(?:{_leaf_regex(node.value)}))"
    if isinstance(node, ConditionAND):
        return "".join(_predicate(child) for child in node.args)
    if isinstance(node, ConditionOR):
        return "(?:" + "|".join(_predicate(child) for child in node.args) + ")"
    if isinstance(node, ConditionNOT):
        if len(node.args) != 1:
            raise CompileError(f"ConditionNOT has {len(node.args)} children")
        return f"(?!{_predicate(node.args[0])})"
    if isinstance(node, ConditionItem):
        raise CompileError(f"unsupported condition node: {type(node).__name__}")
    raise CompileError(f"unsupported parsed node: {type(node).__name__}")


def compile_condition(rule: SigmaRule) -> str:
    parsed = [condition.parsed for condition in rule.detection.parsed_condition]
    if not parsed:
        raise CompileError("rule has no parsed conditions")
    predicate = _predicate(parsed[0]) if len(parsed) == 1 else "(?:" + "|".join(_predicate(p) for p in parsed) + ")"
    pattern = rf"\A{predicate}{SCAN}\Z"
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise CompileError(f"generated invalid regex: {exc}") from exc
    return pattern


def _field_string_regex(value: SigmaString) -> str:
    """Preserve Sigma equality/contains/start/end semantics for one field."""

    if isinstance(value, SigmaCasedString):
        raise CompileError(
            "SigmaCasedString cannot be preserved because structured rules "
            "currently use the runtime's case-insensitive policy"
        )
    projected: list[str] = []
    for part in value.s:
        if isinstance(part, str):
            projected.append(re.escape(part))
        elif part is SpecialChars.WILDCARD_MULTI:
            projected.append(SCAN)
        elif part is SpecialChars.WILDCARD_SINGLE:
            projected.append(r"[\s\S]")
        elif isinstance(part, Placeholder):
            raise CompileError(f"unexpanded Sigma placeholder: {part.name}")
        else:
            raise CompileError(f"unsupported SigmaString part: {type(part).__name__}")
    if not projected or all(part == SCAN for part in projected):
        raise CompileError("empty/all-wildcard Sigma field value is not selective")
    return rf"\A{''.join(projected)}\Z"


def _structured_matcher(value: Any) -> dict[str, Any]:
    if isinstance(value, SigmaExpansion):
        if not value.values:
            raise CompileError("empty SigmaExpansion would match no meaningful value")
        return {
            "kind": "any",
            "items": [_structured_matcher(item) for item in value.values],
        }
    if isinstance(value, SigmaRegularExpression):
        return {"kind": "regex", "pattern": _leaf_regex(value)}
    if isinstance(value, SigmaString):
        return {"kind": "regex", "pattern": _field_string_regex(value)}
    if isinstance(value, SigmaNumber):
        return {"kind": "regex", "pattern": rf"\A{re.escape(str(value.number))}\Z"}
    if isinstance(value, SigmaBool):
        return {
            "kind": "regex",
            "pattern": rf"\A{re.escape(str(value.boolean).lower())}\Z",
        }
    raise CompileError(f"unsupported structured pySigma value: {type(value).__name__}")


def _structured_predicate(node: Any) -> dict[str, Any]:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return {
            "op": "field",
            "field": node.field,
            "matcher": _structured_matcher(node.value),
        }
    if isinstance(node, ConditionValueExpression):
        raise CompileError("fieldless Sigma value requires raw fallback")
    if isinstance(node, ConditionAND):
        return {"op": "and", "items": [_structured_predicate(child) for child in node.args]}
    if isinstance(node, ConditionOR):
        return {"op": "or", "items": [_structured_predicate(child) for child in node.args]}
    if isinstance(node, ConditionNOT):
        if len(node.args) != 1:
            raise CompileError(f"ConditionNOT has {len(node.args)} children")
        return {"op": "not", "item": _structured_predicate(node.args[0])}
    if isinstance(node, ConditionItem):
        raise CompileError(f"unsupported structured condition node: {type(node).__name__}")
    raise CompileError(f"unsupported structured parsed node: {type(node).__name__}")


def compile_structured_condition(rule: SigmaRule) -> dict[str, Any]:
    """Serialize a field-aware pySigma condition for dependency-free runtime use."""

    parsed = [condition.parsed for condition in rule.detection.parsed_condition]
    if not parsed:
        raise CompileError("rule has no parsed conditions")
    if len(parsed) == 1:
        return _structured_predicate(parsed[0])
    return {"op": "or", "items": [_structured_predicate(item) for item in parsed]}


def attack_technique_tags(rule: SigmaRule) -> list[str]:
    result: list[str] = []
    for tag in rule.tags:
        match = ATTACK_TECHNIQUE_RE.fullmatch(str(tag))
        if match:
            result.append(match.group(1).upper())
    return sorted(set(result))


def resolve_technique_tags(tags: list[str]) -> TechniqueResolution:
    """Resolve only the unambiguous parent/single-child overlap.

    ATT&CK sub-technique IDs are `<parent>.<three digits>`. A parent tag is
    redundant when one of its own sub-techniques is present. If removing every
    redundant parent leaves more than one technique, the rule remains genuinely
    multi-technique and must be reviewed.
    """

    original = sorted(set(tags))
    if not original:
        return TechniqueResolution(
            status="needs_review",
            original_tags=[],
            resolved_tags=[],
            explanation="Sigma rule has no ATT&CK technique tag.",
        )

    redundant_parents = {
        tag for tag in original if any(other.startswith(tag + ".") for other in original)
    }
    leaves = [tag for tag in original if tag not in redundant_parents]
    if len(leaves) == 1:
        auto = bool(redundant_parents)
        return TechniqueResolution(
            status="mapping_candidate",
            original_tags=original,
            resolved_tags=leaves,
            explanation=(
                "Parent/sub-technique overlap auto-resolved to the more specific sub-technique."
                if auto
                else "Single ATT&CK technique tag."
            ),
        )
    return TechniqueResolution(
        status="needs_review",
        original_tags=original,
        resolved_tags=leaves,
        explanation=(
            "Multiple distinct ATT&CK techniques remain after removing redundant parents; "
            "the whole-rule regex was not assigned to any one technique."
        ),
    )


def _confidence(rule: SigmaRule) -> str:
    name = getattr(rule.level, "name", str(rule.level)).lower()
    confidence_by_level = {
        "informational": "low",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "high",
    }
    return confidence_by_level.get(name, "low")


def compile_sample(sigma_root: Path, manifest: dict[str, Any]) -> list[CompiledRule]:
    verify_checkout_commit(sigma_root, manifest["sigma_commit"], "Sigma")
    relative_paths = [Path(item) for item in manifest["rules"]]
    if not 10 <= len(relative_paths) <= 20:
        raise CompileError(f"prototype manifest must contain 10–20 rules, found {len(relative_paths)}")
    paths = [sigma_root / path for path in relative_paths]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise CompileError("missing Sigma rules: " + ", ".join(missing))

    collection = SigmaCollection.load_ruleset(paths, collect_errors=True)
    if collection.errors:
        raise CompileError("pySigma collection errors: " + "; ".join(str(error) for error in collection.errors))
    if len(collection.rules) != len(paths):
        raise CompileError(f"pySigma loaded {len(collection.rules)} rules from {len(paths)} files")

    compiled: list[CompiledRule] = []
    for loaded in collection.rules:
        if not isinstance(loaded, SigmaRule):
            raise CompileError(f"prototype does not accept {type(loaded).__name__}")
        if loaded.errors:
            raise CompileError(f"{loaded.title}: " + "; ".join(str(error) for error in loaded.errors))
        product = (loaded.logsource.product or "").lower()
        if product != "windows":
            raise CompileError(f"{loaded.title}: expected Windows logsource, found {product!r}")
        source = Path(loaded.source.path).name if loaded.source and loaded.source.path else "unknown.yml"
        compiled.append(
            CompiledRule(
                source=source,
                title=loaded.title,
                rule_id=str(loaded.id or ""),
                platform=product,
                confidence=_confidence(loaded),
                pattern=compile_condition(loaded),
                technique_resolution=resolve_technique_tags(attack_technique_tags(loaded)),
            )
        )
    return sorted(compiled, key=lambda item: item.source)


def verify_checkout_commit(root: Path, expected: str, label: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise CompileError(f"{label} source is not a readable Git checkout: {root}")
    actual = result.stdout.strip()
    if actual != expected:
        raise CompileError(f"{label} checkout is {actual}, expected pinned commit {expected}")


def _technique_catalog(path: Path) -> tuple[dict[str, str], Counter[str]]:
    techniques = json.loads(path.read_text(encoding="utf-8"))
    by_id = {item["external_id"].upper(): item["name"] for item in techniques}
    return by_id, Counter(by_id.values())


def _candidate(rule: CompiledRule, technique_id: str, by_id: dict[str, str], names: Counter[str]) -> dict[str, Any]:
    try:
        technique_name = by_id[technique_id]
    except KeyError as exc:
        raise CompileError(f"{rule.source}: technique {technique_id} is absent from local ATT&CK data") from exc
    if names[technique_name] != 1:
        raise CompileError(
            f"{rule.source}: technique name {technique_name!r} is not unique; parent_hint derivation is required"
        )
    reason = f"{rule.title} (Sigma-sourced)."
    return {
        "source": rule.source,
        "title": rule.title,
        "rule_id": rule.rule_id,
        "platform": rule.platform,
        "confidence": rule.confidence,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "pattern": rule.pattern,
        "tag_resolution": asdict(rule.technique_resolution),
        "python": (
            f"_rule({rule.pattern!r}, {technique_name!r}, 'windows', {rule.confidence!r},\n"
            f"      {reason!r},\n"
            f"      {'Sigma: ' + rule.source!r}),"
        ),
    }


def _review_item(rule: CompiledRule, by_id: dict[str, str]) -> dict[str, Any]:
    candidates = [
        {"technique_id": tag, "technique_name": by_id.get(tag, "<missing from local ATT&CK data>")}
        for tag in rule.technique_resolution.resolved_tags
    ]
    return {
        "source": rule.source,
        "title": rule.title,
        "rule_id": rule.rule_id,
        "platform": rule.platform,
        "confidence": rule.confidence,
        "pattern": rule.pattern,
        "original_technique_tags": rule.technique_resolution.original_tags,
        "candidate_techniques_after_parent_resolution": candidates,
        "review_reason": rule.technique_resolution.explanation,
    }


def _dataset_ground_truth(metadata_path: Path) -> list[str]:
    metadata = yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
    result: list[str] = []
    for item in metadata.get("attack_mappings", []):
        technique = str(item["technique"]).upper()
        sub = item.get("sub-technique")
        result.append(f"{technique}.{sub}" if sub else technique)
    return result


def _event_example(line: str) -> dict[str, Any]:
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return {"raw_excerpt": line[:500]}
    example = {field: event[field] for field in EXAMPLE_FIELDS if field in event}
    if example:
        return example
    message = str(event.get("Message", ""))
    return {"Message_excerpt": message[:500]} if message else {"raw_excerpt": line[:500]}


def validate_security_datasets(
    compiled: list[CompiledRule], datasets_root: Path, cases: list[dict[str, str]]
) -> list[dict[str, Any]]:
    by_source = {rule.source: rule for rule in compiled}
    results: list[dict[str, Any]] = []
    for case in cases:
        rule = by_source[case["rule"]]
        capture = datasets_root / case["capture"]
        metadata = datasets_root / case["metadata"]
        if not capture.is_file() or not metadata.is_file():
            raise CompileError(f"validation fixture missing for {rule.source}: {capture} / {metadata}")
        regex = re.compile(rule.pattern, re.IGNORECASE)
        count = 0
        example: dict[str, Any] | None = None
        with ZipFile(capture) as archive:
            members = [
                name
                for name in archive.namelist()
                if name.endswith(".json") and not name.startswith("__MACOSX/")
            ]
            if len(members) != 1:
                raise CompileError(f"{capture}: expected one JSON member, found {members}")
            with archive.open(members[0]) as handle:
                for raw in handle:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line and regex.search(line):
                        count += 1
                        if example is None:
                            example = _event_example(line)
        if count == 0:
            raise CompileError(f"{rule.source}: generated regex matched zero events in {capture.name}")
        results.append(
            {
                "metadata_id": metadata.stem,
                "dataset_ground_truth_at_pinned_commit": _dataset_ground_truth(metadata),
                "source_rule": rule.source,
                "rule_mapping_status": rule.technique_resolution.status,
                "sigma_technique_tags_at_pinned_commit": rule.technique_resolution.original_tags,
                "capture": case["capture"],
                "matching_event_count": count,
                "example": example,
                "status": "pass",
            }
        )
    return results


def build_report(
    compiled: list[CompiledRule], manifest: dict[str, Any], techniques_path: Path, datasets_root: Path | None
) -> dict[str, Any]:
    if datasets_root is not None:
        verify_checkout_commit(
            datasets_root, manifest["security_datasets_commit"], "Security-Datasets"
        )
    by_id, names = _technique_catalog(techniques_path)
    candidates: list[dict[str, Any]] = []
    review: list[dict[str, Any]] = []
    for rule in compiled:
        resolution = rule.technique_resolution
        if resolution.status == "mapping_candidate":
            candidates.extend(_candidate(rule, tag, by_id, names) for tag in resolution.resolved_tags)
        else:
            review.append(_review_item(rule, by_id))

    validation = (
        validate_security_datasets(compiled, datasets_root, manifest["validation_cases"])
        if datasets_root is not None
        else []
    )
    return {
        "checkpoint": "Card 5 Part 1 roadmap step 1 only",
        "projection_notes": [
            "No candidate in this report has been added to backend/log_analysis/mappings.py.",
            (
                "pySigma field predicates are projected onto the current flattened raw-event "
                "model; field-aware matching remains Layer 2 work."
            ),
            (
                "Windows path separators match one-or-more literal backslashes so both plain "
                "logs and JSON-escaped logs are accepted."
            ),
            (
                "Genuinely multi-technique and untagged rules retain compiled regexes in "
                "needs_review but emit no MappingRule candidate."
            ),
        ],
        "pysigma_version": importlib.metadata.version("pysigma"),
        "sigma_commit": manifest["sigma_commit"],
        "security_datasets_commit": manifest["security_datasets_commit"],
        "sample_rule_count": len(compiled),
        "mapping_candidate_count": len(candidates),
        "needs_review_count": len(review),
        "mapping_candidates": candidates,
        "needs_review": review,
        "security_dataset_validation": validation,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigma-root", required=True, type=Path)
    parser.add_argument("--techniques", required=True, type=Path)
    parser.add_argument("--security-datasets-root", type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    compiled = compile_sample(args.sigma_root, manifest)
    report = build_report(compiled, manifest, args.techniques, args.security_datasets_root)
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
