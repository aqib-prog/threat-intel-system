from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path

from prototype import (
    And,
    CompileError,
    Definitions,
    Or,
    Predicate,
    compile_expression,
    compile_manifest,
    parse_condition,
    validate_samples,
)


HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "prototype_manifest.json").read_text(encoding="utf-8"))


class ParserTests(unittest.TestCase):
    def test_and_binds_more_tightly_than_or(self):
        parsed = parse_condition("a=1 or b=2 and c=3")
        self.assertIsInstance(parsed, Or)
        self.assertIsInstance(parsed.children[1], And)

    def test_unknown_field_fails_closed(self):
        with self.assertRaisesRegex(CompileError, "unsupported Falco field"):
            compile_expression(Predicate("unknown.field", "=", ("value",)))

    def test_unknown_macro_fails_closed(self):
        definitions = Definitions([])
        with self.assertRaisesRegex(CompileError, "unknown Falco macro"):
            definitions.expand(parse_condition("missing_macro"))

    def test_cyclic_macro_fails_closed(self):
        definitions = Definitions(
            [
                {"macro": "first", "condition": "second"},
                {"macro": "second", "condition": "first"},
            ]
        )
        with self.assertRaisesRegex(CompileError, "cyclic Falco macro"):
            definitions.expand(parse_condition("first"))


@unittest.skipUnless(os.environ.get("FALCO_ROOT"), "set FALCO_ROOT for source-backed tests")
class FalcoPrototypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = compile_manifest(Path(os.environ["FALCO_ROOT"]), MANIFEST)
        cls.by_name = {
            rule.rule: re.compile(rule.pattern, re.IGNORECASE) for rule in cls.compiled
        }

    def test_manifest_is_exactly_five_mixed_rules(self):
        self.assertEqual(len(self.compiled), 5)
        self.assertEqual(
            {platform: sum(rule.platform == platform for rule in self.compiled)
             for platform in ("kubernetes", "aws")},
            {"kubernetes": 3, "aws": 2},
        )

    def test_all_handcrafted_positive_and_negative_samples(self):
        validation = validate_samples(self.compiled, MANIFEST)
        self.assertTrue(all(item["status"] == "pass" for item in validation))
        self.assertEqual(sum(item["positive_samples"] for item in validation), 8)
        self.assertEqual(sum(item["negative_samples"] for item in validation), 10)

    def test_runtime_ignorecase_does_not_broaden_falco_literals(self):
        regex = self.by_name["ECS Task Run or Started"]
        lowercased_value = json.dumps(
            {"eventSource": "ecs.amazonaws.com", "eventName": "runtask"},
            separators=(",", ":"),
        )
        self.assertIsNone(regex.search(lowercased_value))

    def test_scoped_identity_type_does_not_bind_unrelated_type(self):
        regex = self.by_name["Console Login Without MFA"]
        sample = {
            "eventName": "ConsoleLogin",
            "userIdentity": {"type": "IAMUser"},
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "No"},
            "resources": [{"type": "AssumedRole"}],
        }
        self.assertIsNotNone(regex.search(json.dumps(sample, separators=(",", ":"))))

    def test_ct_error_does_not_alias_ct_errormessage(self):
        regex = self.by_name["ECS Task Run or Started"]
        sample = {
            "eventSource": "ecs.amazonaws.com",
            "eventName": "RunTask",
            "errorMessage": "present without the distinct errorCode field",
        }
        self.assertIsNotNone(regex.search(json.dumps(sample, separators=(",", ":"))))

    def test_mixed_trusted_and_untrusted_images_still_alerts(self):
        selected = next(
            item for item in MANIFEST["rules"] if item["rule"] == "Create Privileged Pod"
        )
        mixed = selected["positive_samples"][1]
        self.assertIsNotNone(
            self.by_name["Create Privileged Pod"].search(
                json.dumps(mixed, separators=(",", ":"))
            )
        )


if __name__ == "__main__":
    unittest.main()
