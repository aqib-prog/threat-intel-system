#!/usr/bin/env python3
"""Card 5 Part 1, roadmap step 3: five-rule Falco DSL prototype.

This is deliberately not a general Falco parser. It supports only the syntax
exercised by the checkpoint manifest and fails closed on unknown fields,
operators, macros, or malformed expressions.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml


HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "prototype_manifest.json"
DEFAULT_REPORT = HERE / "prototype_report.json"


class CompileError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    value: Any
    offset: int


@dataclass(frozen=True)
class And:
    children: tuple[Any, ...]


@dataclass(frozen=True)
class Or:
    children: tuple[Any, ...]


@dataclass(frozen=True)
class Not:
    child: Any


@dataclass(frozen=True)
class Predicate:
    field: str
    operator: str
    values: tuple[Any, ...] = ()


@dataclass(frozen=True)
class Macro:
    name: str


@dataclass(frozen=True)
class CompiledRule:
    source_file: str
    rule: str
    description: str
    platform: str
    priority: str
    source: str
    original_condition: str
    expanded_condition_tree: dict[str, Any]
    pattern: str


def tokenize(condition: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    while i < len(condition):
        if condition[i].isspace():
            i += 1
            continue
        start = i
        char = condition[i]
        if char in "(),":
            tokens.append(Token({"(": "LPAREN", ")": "RPAREN", ",": "COMMA"}[char], char, i))
            i += 1
            continue
        if condition.startswith(("!=", ">=", "<="), i):
            tokens.append(Token("OP", condition[i : i + 2], i))
            i += 2
            continue
        if char in "=><":
            tokens.append(Token("OP", char, i))
            i += 1
            continue
        if char in ('"', "'"):
            quote = char
            i += 1
            value: list[str] = []
            while i < len(condition) and condition[i] != quote:
                if condition[i] == "\\" and i + 1 < len(condition):
                    i += 1
                    value.append(condition[i])
                    i += 1
                else:
                    value.append(condition[i])
                    i += 1
            if i >= len(condition):
                raise CompileError(f"unterminated string at offset {start}")
            i += 1
            tokens.append(Token("SCALAR", "".join(value), start))
            continue
        while i < len(condition):
            if condition[i].isspace() or condition[i] in "(),=><!\"'":
                break
            i += 1
        if i == start:
            raise CompileError(f"unexpected character {condition[i]!r} at offset {i}")
        raw = condition[start:i]
        lowered = raw.lower()
        if lowered == "true":
            value: Any = True
            kind = "SCALAR"
        elif lowered == "false":
            value = False
            kind = "SCALAR"
        elif re.fullmatch(r"-?\d+", raw):
            value = int(raw)
            kind = "SCALAR"
        else:
            value = raw
            kind = "WORD"
        tokens.append(Token(kind, value, start))
    tokens.append(Token("EOF", None, len(condition)))
    return tokens


class Parser:
    def __init__(self, condition: str):
        self.condition = condition
        self.tokens = tokenize(condition)
        self.index = 0

    @property
    def current(self) -> Token:
        return self.tokens[self.index]

    def advance(self) -> Token:
        token = self.current
        self.index += 1
        return token

    def word_is(self, value: str) -> bool:
        return self.current.kind == "WORD" and str(self.current.value).lower() == value

    def accept_word(self, value: str) -> bool:
        if self.word_is(value):
            self.advance()
            return True
        return False

    def parse(self):
        expression = self.parse_or()
        if self.current.kind != "EOF":
            raise CompileError(
                f"unexpected token {self.current.value!r} at offset {self.current.offset}"
            )
        return expression

    def parse_or(self):
        children = [self.parse_and()]
        while self.accept_word("or"):
            children.append(self.parse_and())
        return children[0] if len(children) == 1 else Or(tuple(children))

    def parse_and(self):
        children = [self.parse_unary()]
        while self.accept_word("and"):
            children.append(self.parse_unary())
        return children[0] if len(children) == 1 else And(tuple(children))

    def parse_unary(self):
        if self.accept_word("not"):
            return Not(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self):
        if self.current.kind == "LPAREN":
            self.advance()
            expression = self.parse_or()
            if self.current.kind != "RPAREN":
                raise CompileError(f"expected ')' at offset {self.current.offset}")
            self.advance()
            return expression
        if self.current.kind != "WORD":
            raise CompileError(
                f"expected field or macro at offset {self.current.offset}, got {self.current.value!r}"
            )
        name = str(self.advance().value)
        if self.accept_word("exists"):
            return Predicate(name, "exists")
        if self.current.kind == "OP":
            operator = str(self.advance().value)
            value = self.parse_scalar()
            predicate = Predicate(name, "=" if operator == "!=" else operator, (value,))
            return Not(predicate) if operator == "!=" else predicate
        for operator in ("in", "intersects"):
            if self.accept_word(operator):
                return Predicate(name, operator, tuple(self.parse_value_group()))
        for operator in ("startswith", "contains"):
            if self.accept_word(operator):
                return Predicate(name, operator, (self.parse_scalar(),))
        return Macro(name)

    def parse_scalar(self):
        if self.current.kind not in ("WORD", "SCALAR"):
            raise CompileError(f"expected scalar at offset {self.current.offset}")
        return self.advance().value

    def parse_value_group(self) -> list[Any]:
        if self.current.kind != "LPAREN":
            return [self.parse_scalar()]
        self.advance()
        values: list[Any] = []
        if self.current.kind == "RPAREN":
            self.advance()
            return values
        while True:
            values.append(self.parse_scalar())
            if self.current.kind == "RPAREN":
                self.advance()
                return values
            if self.current.kind != "COMMA":
                raise CompileError(f"expected ',' or ')' at offset {self.current.offset}")
            self.advance()


def parse_condition(condition: str):
    return Parser(condition).parse()


class Definitions:
    def __init__(self, documents: list[dict[str, Any]]):
        self.rules = {item["rule"]: item for item in documents if "rule" in item}
        self.macros = {item["macro"]: str(item["condition"]) for item in documents if "macro" in item}
        self.lists = {item["list"]: list(item.get("items", [])) for item in documents if "list" in item}
        self._expanded_macros: dict[str, Any] = {}

    def flatten_values(self, values: tuple[Any, ...], stack: tuple[str, ...] = ()) -> tuple[Any, ...]:
        flattened: list[Any] = []
        for value in values:
            if isinstance(value, str) and value in self.lists:
                if value in stack:
                    raise CompileError(f"cyclic Falco list reference: {' -> '.join((*stack, value))}")
                flattened.extend(self.flatten_values(tuple(self.lists[value]), (*stack, value)))
            else:
                flattened.append(value)
        return tuple(flattened)

    def expand(self, expression, stack: tuple[str, ...] = ()):
        if isinstance(expression, Macro):
            name = expression.name
            if name not in self.macros:
                raise CompileError(f"unknown Falco macro {name!r}")
            if name in stack:
                raise CompileError(f"cyclic Falco macro reference: {' -> '.join((*stack, name))}")
            if not stack and name in self._expanded_macros:
                return self._expanded_macros[name]
            expanded = self.expand(parse_condition(self.macros[name]), (*stack, name))
            if not stack:
                self._expanded_macros[name] = expanded
            return expanded
        if isinstance(expression, Predicate):
            return Predicate(
                expression.field,
                expression.operator,
                self.flatten_values(expression.values),
            )
        if isinstance(expression, Not):
            return Not(self.expand(expression.child, stack))
        if isinstance(expression, And):
            return And(tuple(self.expand(child, stack) for child in expression.children))
        if isinstance(expression, Or):
            return Or(tuple(self.expand(child, stack) for child in expression.children))
        raise CompileError(f"unknown expression node {type(expression).__name__}")


SIMPLE_FIELDS = {
    "jevt.value[/stage]": "stage",
    "ka.verb": "verb",
    "ka.req.pod.containers.privileged": "privileged",
    "ka.req.pod.initContainers.privileged": "privileged",
    "ka.req.pod.ephemeralContainers.privileged": "privileged",
    "ka.req.pod.containers.image.repository": "image",
    "ka.auth.decision": "authorization.k8s.io/decision",
    "ka.uri": "requestURI",
    "ka.req.role.rules.resources": "resources",
    "ka.req.role.rules.verbs": "verbs",
    "ct.name": "eventName",
    "ct.src": "eventSource",
    "ct.region": "awsRegion",
}

SCOPED_FIELDS = {
    "ka.target.resource": ("objectRef", "resource"),
    "ka.target.subresource": ("objectRef", "subresource"),
    "ka.target.name": ("objectRef", "name"),
    "ka.target.namespace": ("objectRef", "namespace"),
    "ka.user.name": ("user", "username"),
    "ka.req.binding.role": ("requestObject", "roleRef", "name"),
    "ka.req.service.type": ("requestObject", "spec", "type"),
    "ka.req.pod.host_ipc": ("requestObject", "spec", "hostIPC"),
    "ka.req.pod.host_network": ("requestObject", "spec", "hostNetwork"),
    "ka.req.pod.host_pid": ("requestObject", "spec", "hostPID"),
    "ka.req.pod.volumes.hostpath": ("requestObject", "spec", "volumes", "hostPath", "path"),
    "ka.response.code": ("responseStatus", "code"),
    "ka.req.configmap.obj": ("requestObject", "data"),
    "ct.user.identitytype": ("userIdentity", "type"),
    "ct.request.username": ("requestParameters", "userName"),
    "json.value[/responseElements/ConsoleLogin]": ("responseElements", "ConsoleLogin"),
    "json.value[/additionalEventData/MFAUsed]": ("additionalEventData", "MFAUsed"),
}

ARRAY_FIELDS = {"ka.req.role.rules.resources", "ka.req.role.rules.verbs"}
IMAGE_REPOSITORY_FIELD = "ka.req.pod.containers.image.repository"


def exact(value: str) -> str:
    return f"(?-i:{re.escape(value)})"


def json_value(value: Any, prefix: bool = False) -> str:
    if isinstance(value, bool):
        return exact("true" if value else "false")
    if isinstance(value, (int, float)):
        return exact(str(value))
    literal = exact(str(value))
    return exact('"') + literal + (r'[^"\\]*' if prefix else "") + exact('"')


def key_pattern(key: str) -> str:
    return exact(f'"{key}"') + r"\s*:\s*"


def field_base(field: str) -> str:
    if field == "ct.error":
        # Verified against plugins/cloudtrail/pkg/cloudtrail/extract.go:
        # ct.error is errorCode; errorMessage is the distinct ct.errormessage.
        return key_pattern("errorCode")
    if field in SIMPLE_FIELDS:
        return key_pattern(SIMPLE_FIELDS[field])
    if field in SCOPED_FIELDS:
        path = SCOPED_FIELDS[field]
        if len(path) == 2:
            parent, child = path
            # Refuse to cross a nested-object boundary for direct children,
            # which could otherwise bind identitytype to an unrelated key.
            return key_pattern(parent) + r"\{[^{}]{0,2000}?" + key_pattern(child)
        result = ""
        for key in path[:-1]:
            result += key_pattern(key) + r"(?:\{|\[)[\s\S]{0,6000}?"
        return result + key_pattern(path[-1])
    if field.startswith("json.value[/") or field.startswith("jevt.value[/"):
        start = field.index("[/") + 2
        path = field[start:-1].split("/")
        if not path or any(not part for part in path):
            raise CompileError(f"invalid Falco JSON pointer field {field!r}")
        result = ""
        for key in path[:-1]:
            result += key_pattern(key) + r"(?:\{|\[)[\s\S]{0,6000}?"
        return result + key_pattern(path[-1])
    raise CompileError(f"unsupported Falco field {field!r} in raw-JSON projection")


def repository_value_pattern(repository: str) -> str:
    return (
        exact('"')
        + exact(repository)
        + r"(?:(?-i::|@)[^\"\\]*)?"
        + exact('"')
    )


def predicate_search_patterns(predicate: Predicate) -> list[str]:
    field = predicate.field
    operator = predicate.operator
    if field == "jevt.rawtime":
        if operator == "exists":
            return [r"[\s\S]*"]
        if operator == "=" and predicate.values == (0,):
            return [r"(?!)"]
        raise CompileError(f"unsupported jevt.rawtime predicate {operator} {predicate.values}")
    if field == "evt.num":
        if operator == ">" and predicate.values == (0,):
            return [r"[\s\S]*"]
        raise CompileError(f"unsupported evt.num predicate {operator} {predicate.values}")
    if operator == "exists":
        return [field_base(field)]
    if not predicate.values:
        if operator in {"in", "intersects"}:
            return [r"(?!)"]
        raise CompileError(f"{field} {operator} has an empty value list")
    if operator not in {"=", "in", "intersects", "startswith", "contains"}:
        raise CompileError(f"unsupported Falco operator {operator!r}")

    base = field_base(field)
    patterns: list[str] = []
    for value in predicate.values:
        if field == IMAGE_REPOSITORY_FIELD:
            if operator not in {"=", "in"}:
                raise CompileError(f"unsupported repository operator {operator!r}")
            patterns.append(base + repository_value_pattern(str(value)))
        elif field == "ka.req.configmap.obj" and operator == "contains":
            patterns.append(base + r"[\s\S]{0,12000}?" + exact(str(value)))
        elif field == "ka.response.code" and operator == "startswith":
            prefix = exact(str(value))
            patterns.append(base + f"(?:{prefix}[0-9]*|" + exact('"') + prefix + r"[0-9]*" + exact('"') + ")")
        elif field in ARRAY_FIELDS and operator == "intersects":
            patterns.append(base + r"\[[^\]]*" + json_value(value) + r"[^\]]*\]")
        elif operator == "startswith":
            patterns.append(base + json_value(value, prefix=True))
        elif operator == "contains":
            patterns.append(base + exact('"') + r'[^"\\]*' + exact(str(value)) + r'[^"\\]*' + exact('"'))
        elif operator in {"=", "in", "intersects"}:
            patterns.append(base + json_value(value))
    return patterns


def assertion_for_patterns(patterns: list[str]) -> str:
    assertions = [f"(?=[\\s\\S]*(?:{pattern}))" for pattern in patterns]
    if len(assertions) == 1:
        return assertions[0]
    return "(?:" + "|".join(assertions) + ")"


def disallowed_repository_assertion(predicate: Predicate) -> str:
    repositories = [str(value) for value in predicate.values]
    if not repositories:
        return assertion_for_patterns([field_base(predicate.field) + repository_value_pattern("")])
    allowed = "|".join(
        exact(repository) + r"(?=(?-i::|@|\"))" for repository in repositories
    )
    pattern = (
        field_base(predicate.field)
        + exact('"')
        + f"(?!(?:{allowed}))"
        + r'[^"\\]+'
        + exact('"')
    )
    return assertion_for_patterns([pattern])


def allowed_repository_assertion(predicate: Predicate) -> str:
    if not predicate.values:
        return assertion_for_patterns([r"(?!)"])
    any_repository = assertion_for_patterns(
        [field_base(predicate.field) + exact('"') + r'[^"\\]+' + exact('"')]
    )
    disallowed = disallowed_repository_assertion(predicate)
    return any_repository + f"(?!{disallowed})"


def compile_expression(expression) -> str:
    if isinstance(expression, Predicate):
        if (
            expression.field == IMAGE_REPOSITORY_FIELD
            and expression.operator == "in"
        ):
            # Falco's `in` requires the full extracted repository set to be
            # contained in the allowlist, not merely one intersecting image.
            return allowed_repository_assertion(expression)
        return assertion_for_patterns(predicate_search_patterns(expression))
    if isinstance(expression, And):
        return "".join(compile_expression(child) for child in expression.children)
    if isinstance(expression, Or):
        return "(?:" + "|".join(compile_expression(child) for child in expression.children) + ")"
    if isinstance(expression, Not):
        return f"(?!{compile_expression(expression.child)})"
    raise CompileError(f"unexpanded expression node {type(expression).__name__}")


def constant_value(expression) -> bool | None:
    """Evaluate only source-defined constants; return None for event predicates."""
    if isinstance(expression, Predicate):
        if expression.field == "jevt.rawtime":
            if expression.operator == "exists":
                return True
            if expression.operator == "=" and expression.values == (0,):
                return False
        if expression.field == "evt.num" and expression.operator == ">" and expression.values == (0,):
            return True
        if expression.operator in {"in", "intersects"} and not expression.values:
            return False
        return None
    if isinstance(expression, Not):
        child = constant_value(expression.child)
        return None if child is None else not child
    if isinstance(expression, And):
        values = [constant_value(child) for child in expression.children]
        if False in values:
            return False
        return True if all(value is True for value in values) else None
    if isinstance(expression, Or):
        values = [constant_value(child) for child in expression.children]
        if True in values:
            return True
        return False if all(value is False for value in values) else None
    return None


def expression_to_dict(expression) -> dict[str, Any]:
    if isinstance(expression, Predicate):
        return {
            "type": "predicate",
            "field": expression.field,
            "operator": expression.operator,
            "values": list(expression.values),
        }
    if isinstance(expression, Not):
        return {"type": "not", "child": expression_to_dict(expression.child)}
    if isinstance(expression, (And, Or)):
        return {
            "type": "and" if isinstance(expression, And) else "or",
            "children": [expression_to_dict(child) for child in expression.children],
        }
    if isinstance(expression, Macro):
        return {"type": "macro", "name": expression.name}
    raise CompileError(f"unknown expression node {type(expression).__name__}")


def verify_commit(root: Path, expected: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    actual = result.stdout.strip()
    if actual != expected:
        raise CompileError(f"Falco checkout is {actual}, expected pinned commit {expected}")


def load_documents(path: Path) -> list[dict[str, Any]]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        raise CompileError(f"{path}: expected a top-level YAML list")
    return [item for item in loaded if isinstance(item, dict)]


def compile_manifest(falco_root: Path, manifest: dict[str, Any]) -> list[CompiledRule]:
    verify_commit(falco_root, manifest["falco_commit"])
    if len(manifest["rules"]) != 5:
        raise CompileError("step-3 prototype manifest must contain exactly five rules")

    definitions_by_file: dict[str, Definitions] = {}
    compiled: list[CompiledRule] = []
    for selected in manifest["rules"]:
        source_file = selected["source_file"]
        if source_file not in definitions_by_file:
            definitions_by_file[source_file] = Definitions(
                load_documents(falco_root / source_file)
            )
        definitions = definitions_by_file[source_file]
        try:
            rule = definitions.rules[selected["rule"]]
        except KeyError as exc:
            raise CompileError(f"{source_file}: missing rule {selected['rule']!r}") from exc
        original = str(rule["condition"]).strip()
        expanded = definitions.expand(parse_condition(original))
        pattern = r"\A" + compile_expression(expanded) + r"[\s\S]*\Z"
        re.compile(pattern, re.IGNORECASE)
        compiled.append(
            CompiledRule(
                source_file=source_file,
                rule=selected["rule"],
                description=str(rule["desc"]).strip(),
                platform=selected["platform"],
                priority=str(rule["priority"]),
                source=str(rule["source"]),
                original_condition=original,
                expanded_condition_tree=expression_to_dict(expanded),
                pattern=pattern,
            )
        )
    return compiled


def validate_samples(
    compiled: list[CompiledRule], manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    selected_by_name = {item["rule"]: item for item in manifest["rules"]}
    results: list[dict[str, Any]] = []
    for rule in compiled:
        regex = re.compile(rule.pattern, re.IGNORECASE)
        selected = selected_by_name[rule.rule]
        positive = [
            bool(regex.search(json.dumps(sample, separators=(",", ":"))))
            for sample in selected["positive_samples"]
        ]
        negative = [
            not bool(regex.search(json.dumps(sample, separators=(",", ":"))))
            for sample in selected["negative_samples"]
        ]
        results.append(
            {
                "rule": rule.rule,
                "positive_samples": len(positive),
                "positive_passed": sum(positive),
                "negative_samples": len(negative),
                "negative_passed": sum(negative),
                "status": "pass" if all(positive) and all(negative) else "fail",
            }
        )
    return results


def build_report(
    compiled: list[CompiledRule], manifest: dict[str, Any], validation: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "checkpoint": "Card 5 Part 1 roadmap step 3 only",
        "falco_commit": manifest["falco_commit"],
        "sample_rule_count": len(compiled),
        "sample_by_platform": {
            platform: sum(rule.platform == platform for rule in compiled)
            for platform in ("kubernetes", "aws")
        },
        "projection_notes": [
            "No prototype rule is imported by the runtime or merged into mappings.py.",
            "The parser supports only constructs exercised by these five rules and fails closed elsewhere.",
            "Macros and lists are expanded from the pinned Falco files before regex generation.",
            "Falco string comparisons remain case-sensitive inside the runtime's IGNORECASE wrapper.",
            "Raw-JSON field projection is a Layer-1 approximation; canonical structured field matching remains Card 5 Layer 2.",
            "No MITRE mappings are assigned in step 3; that review starts with roadmap step 4.",
        ],
        "source_field_audit": {
            "cloudtrail": {
                "ct.name": "eventName",
                "ct.src": "eventSource",
                "ct.error": "errorCode",
                "ct.user.identitytype": "userIdentity.type",
            },
            "k8saudit": {
                "ka.auth.decision": "annotations[\"authorization.k8s.io/decision\"]",
                "ka.target.resource": "objectRef.resource",
                "ka.target.subresource": "objectRef.subresource",
                "ka.uri": "requestURI",
                "ka.req.pod.containers.image.repository": "requestObject.spec.containers[*].image, repository portion",
                "ka.req.pod.*Containers.privileged": "requestObject.spec.*Containers[*].securityContext.privileged",
            },
        },
        "rules": [asdict(rule) for rule in compiled],
        "validation": validation,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--falco-root", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    compiled = compile_manifest(args.falco_root, manifest)
    validation = validate_samples(compiled, manifest)
    if not all(item["status"] == "pass" for item in validation):
        raise CompileError("one or more prototype validations failed")
    report = build_report(compiled, manifest, validation)
    args.report.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "falco_commit": report["falco_commit"],
                "sample_rule_count": report["sample_rule_count"],
                "sample_by_platform": report["sample_by_platform"],
                "validation": report["validation"],
                "report": str(args.report),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
