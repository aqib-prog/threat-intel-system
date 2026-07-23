from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
SIGMA_TOOLS = REPO / "tools/sigma_compiler"
for path in (str(BACKEND), str(SIGMA_TOOLS), str(HERE)):
    if path not in sys.path:
        sys.path.insert(0, path)

from compiler import compile_windows_structured
from log_analysis.detector import detect
from log_analysis.parser import LogEvent, parse_log
from log_analysis.structured import StructuredCondition, hybrid_rule_matches


SPECS_PATH = HERE / "windows_structured_rule_specs.py"
REPORT_PATH = HERE / "compile_report.json"
STEP2_REPORT = SIGMA_TOOLS / "full_recompile_report.json"
STEP7_REPORT = HERE / "step7_report.json"


def load_specs():
    spec = importlib.util.spec_from_file_location("step7_specs", SPECS_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(SPECS_PATH.is_file(), "generate the step-7 specs first")
class StructuredArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_specs()
        cls.specs = cls.module.STRUCTURED_BY_SOURCE_TECHNIQUE

    def condition(self, source: str, technique_id: str) -> StructuredCondition:
        return StructuredCondition.from_dict(self.specs[(source, technique_id)])

    def test_every_generated_tree_constructs(self):
        for key, tree in self.specs.items():
            with self.subTest(key=key):
                self.assertTrue(StructuredCondition.from_dict(tree).positive_fields)

    def test_windows_json_extractor_emits_canonical_and_source_fields(self):
        text = json.dumps(
            {
                "EventID": 3,
                "Image": r"C:\Windows\System32\dns.exe",
                "DestinationPort": 25,
                "Initiated": True,
            }
        )
        events = parse_log(text, "windows")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertTrue(event.structured_complete)
        self.assertEqual(event.canonical_fields["event.id"], ("3",))
        self.assertEqual(event.canonical_fields["network.destination.port"], ("25",))
        self.assertEqual(event.source_fields["initiated"], ("True",))

    def test_detector_recognizes_quoted_windows_json_field_names(self):
        records = [
            {
                "EventID": 1,
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "UtcTime": f"2020-01-01T00:00:0{second}Z",
            }
            for second in (1, 2)
        ]
        result = detect("\n".join(json.dumps(record) for record in records))
        self.assertTrue(result.is_raw_log)
        self.assertEqual(result.platform, "windows")

    def test_windows_json_schema_outweighs_linux_strings_inside_values(self):
        text = "\n".join(
            json.dumps(
                {
                    "EventID": 1,
                    "ProviderGuid": "{test}",
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "CommandLine": "auditd type=EXECVE exe=/usr/bin/test uid=1000",
                    "UtcTime": f"2020-01-01T00:00:0{second}Z",
                }
            )
            for second in (1, 2)
        )
        result = detect(text)
        self.assertTrue(result.is_raw_log)
        self.assertEqual(result.platform, "windows")

    def test_wmi_event_id_is_bound_to_its_field(self):
        condition = self.condition(
            "Sigma: sysmon_wmi_event_subscription.yml", "T1546.003"
        )
        wrong = parse_log(
            json.dumps({"EventID": 1, "UtcTime": "2020-10-20T20:19:21Z"}),
            "windows",
        )[0]
        right = parse_log(json.dumps({"EventID": 19}), "windows")[0]
        self.assertFalse(condition.matches(wrong))
        self.assertTrue(condition.matches(right))

    def test_smtp_port_and_initiated_are_bound_to_fields(self):
        condition = self.condition(
            "Sigma: net_connection_win_susp_outbound_smtp_connections.yml",
            "T1048.003",
        )
        wrong = parse_log(
            json.dumps({"EventID": 25, "DestinationPort": 443, "Initiated": True}),
            "windows",
        )[0]
        right = parse_log(
            json.dumps({"EventID": 3, "DestinationPort": 25, "Initiated": True}),
            "windows",
        )[0]
        self.assertFalse(condition.matches(wrong))
        self.assertTrue(condition.matches(right))

    def test_exact_field_value_does_not_accept_nearby_value(self):
        condition = self.condition(
            "Sigma: create_remote_thread_win_hktl_cobaltstrike.yml", "T1055.001"
        )
        wrong = parse_log(
            json.dumps({"StartAddress": "0000000000000B81"}), "windows"
        )[0]
        right = parse_log(
            json.dumps({"StartAddress": "0000000000000B80"}), "windows"
        )[0]
        self.assertFalse(condition.matches(wrong))
        self.assertTrue(condition.matches(right))

    def test_nested_and_or_and_negative_filter_are_preserved(self):
        regsvr32 = self.condition(
            "Sigma: proc_creation_win_regsvr32_network_pattern.yml", "T1218.010"
        )
        self.assertTrue(
            regsvr32.matches(
                parse_log(
                    json.dumps(
                        {
                            "Image": r"C:\Windows\System32\regsvr32.exe",
                            "CommandLine": "regsvr32 /i:https://example.test/a.sct",
                        }
                    ),
                    "windows",
                )[0]
            )
        )
        self.assertFalse(
            regsvr32.matches(
                parse_log(
                    json.dumps(
                        {
                            "Image": r"C:\Windows\System32\regsvr32.exe",
                            "CommandLine": "regsvr32 local.dll",
                        }
                    ),
                    "windows",
                )[0]
            )
        )

        schtasks = self.condition(
            "Sigma: proc_creation_win_schtasks_creation.yml", "T1053.005"
        )
        suspicious = parse_log(
            json.dumps(
                {
                    "Image": r"C:\Windows\System32\schtasks.exe",
                    "CommandLine": "schtasks.exe /create /tn Evil",
                    "User": r"LAB\alice",
                }
            ),
            "windows",
        )[0]
        filtered = parse_log(
            json.dumps(
                {
                    "Image": r"C:\Windows\System32\schtasks.exe",
                    "CommandLine": "schtasks.exe /create /tn Evil",
                    "User": r"NT AUTHORITY\SYSTEM",
                }
            ),
            "windows",
        )[0]
        self.assertTrue(schtasks.matches(suspicious))
        self.assertFalse(schtasks.matches(filtered))

    def test_canonical_process_path_alias_matches_sysmon_image(self):
        condition = self.condition(
            "Sigma: win_bits_client_new_job_via_bitsadmin.yml", "T1197"
        )
        event = parse_log(
            json.dumps(
                {
                    "EventID": 3,
                    "Image": r"C:\Windows\System32\bitsadmin.exe",
                }
            ),
            "windows",
        )[0]
        self.assertEqual(
            event.source_fields["processpath"],
            (r"C:\Windows\System32\bitsadmin.exe",),
        )
        self.assertTrue(condition.matches(event))

    def test_powershell_message_alias_is_channel_scoped(self):
        condition = self.condition(
            "Sigma: posh_ps_invoke_command_remote.yml", "T1021.006"
        )
        script = "invoke-command test -ComputerName server01 "
        message = (
            "Pipeline execution details for command line: "
            + script
            + ".\r\n\r\nContext Information:\r\nDetailSequence=1"
        )
        powershell = parse_log(
            json.dumps(
                {
                    "EventID": 800,
                    "Channel": "Windows PowerShell",
                    "Message": message,
                }
            ),
            "windows",
        )[0]
        unrelated = parse_log(
            json.dumps(
                {"EventID": 800, "Channel": "System", "Message": message}
            ),
            "windows",
        )[0]
        self.assertTrue(condition.matches(powershell))
        self.assertFalse(condition.matches(unrelated))

    def test_complete_record_known_absence_does_not_raw_fallback(self):
        condition = self.condition(
            "Sigma: win_capi2_acquire_certificate_private_key.yml", "T1649"
        )
        event = parse_log(
            json.dumps({"EventID": 1, "UnrelatedNumber": 70}), "windows"
        )[0]
        matched, mode = hybrid_rule_matches(event, re.compile("70"), condition)
        self.assertEqual(mode, "structured")
        self.assertFalse(matched)

    def test_partial_record_falls_back_only_until_required_field_exists(self):
        condition = self.condition(
            "Sigma: win_capi2_acquire_certificate_private_key.yml", "T1649"
        )
        missing = LogEvent(raw_line="value=70", normalized_line="value=70")
        matched, mode = hybrid_rule_matches(missing, re.compile("70"), condition)
        self.assertEqual((matched, mode), (True, "raw"))

        present = parse_log("EventID=1 UnrelatedNumber=70", "windows")[0]
        matched, mode = hybrid_rule_matches(present, re.compile("70"), condition)
        self.assertEqual(mode, "structured")
        self.assertFalse(matched)

    def test_step7_checkpoint_report_proves_precision_improvement(self):
        report = json.loads(STEP7_REPORT.read_text(encoding="utf-8"))
        baseline = report["comparison_step5_baseline"][
            "layer1_micro_strict_exact_id"
        ]
        layer2 = report["metrics"]["layer2_windows_preview"][
            "micro_strict_exact_id"
        ]

        self.assertEqual(
            report["checkpoint"],
            "Card 5 Part 1 roadmap step 7 Windows pilot only",
        )
        self.assertEqual(report["corpus"]["sample_count"], 40)
        self.assertEqual(report["corpus"]["detector_gate_pass_count"], 40)
        self.assertEqual(report["rule_inventory"]["windows_structured_rule_count"], 1587)
        compiler_report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(compiler_report["inventory"]["raw_fallback_only_candidates"], 11)
        self.assertEqual(
            (baseline["tp"], baseline["fp"], baseline["fn"]),
            (26, 1391, 14),
        )
        self.assertEqual((layer2["tp"], layer2["fp"], layer2["fn"]), (23, 338, 17))
        self.assertGreater(layer2["precision"], baseline["precision"])
        self.assertEqual(report["performance"]["raw_fallback_searches"], 0)

        serialized = STEP7_REPORT.read_text(encoding="utf-8")
        self.assertNotIn("evidence_excerpt", serialized)


@unittest.skipUnless(os.environ.get("SIGMA_ROOT"), "set SIGMA_ROOT for source-backed tests")
class SourceBackedCompilerTests(unittest.TestCase):
    def test_generated_inventory_reproduces(self):
        step2 = json.loads(STEP2_REPORT.read_text(encoding="utf-8"))
        specs, review, inventory = compile_windows_structured(
            Path(os.environ["SIGMA_ROOT"]), step2
        )
        artifact = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(inventory, artifact["inventory"])
        self.assertEqual(len(specs), inventory["structured_windows_candidates"])
        self.assertEqual(len(review), inventory["raw_fallback_only_candidates"])


if __name__ == "__main__":
    unittest.main()
