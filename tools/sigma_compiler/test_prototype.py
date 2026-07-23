from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path

from sigma.collection import SigmaCollection

from prototype import compile_sample, resolve_technique_tags


HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "prototype_manifest.json").read_text(encoding="utf-8"))


class TechniqueResolutionTests(unittest.TestCase):
    def test_single_tag_is_candidate(self):
        result = resolve_technique_tags(["T1105"])
        self.assertEqual(result.status, "mapping_candidate")
        self.assertEqual(result.resolved_tags, ["T1105"])

    def test_parent_and_only_child_resolves_to_child(self):
        result = resolve_technique_tags(["T1003", "T1003.003"])
        self.assertEqual(result.status, "mapping_candidate")
        self.assertEqual(result.resolved_tags, ["T1003.003"])
        self.assertIn("auto-resolved", result.explanation)

    def test_parent_with_two_children_still_needs_review(self):
        result = resolve_technique_tags(["T1003", "T1003.002", "T1003.003"])
        self.assertEqual(result.status, "needs_review")
        self.assertEqual(result.resolved_tags, ["T1003.002", "T1003.003"])

    def test_distinct_techniques_need_review(self):
        result = resolve_technique_tags(["T1197", "T1105"])
        self.assertEqual(result.status, "needs_review")


@unittest.skipUnless(os.environ.get("SIGMA_ROOT"), "set SIGMA_ROOT for end-to-end prototype tests")
class SigmaPrototypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = compile_sample(Path(os.environ["SIGMA_ROOT"]), MANIFEST)
        cls.by_source = {rule.source: re.compile(rule.pattern, re.IGNORECASE) for rule in cls.rules}
        cls.models = {rule.source: rule for rule in cls.rules}

    def assert_matches(self, source: str, text: str):
        self.assertIsNotNone(self.by_source[source].search(text), source)

    def assert_not_matches(self, source: str, text: str):
        self.assertIsNone(self.by_source[source].search(text), source)

    def compile_extra_rule(self, relative_path: str):
        path = Path(os.environ["SIGMA_ROOT"]) / relative_path
        rule = SigmaCollection.load_ruleset([path], collect_errors=True).rules[0]
        from prototype import compile_condition

        return re.compile(compile_condition(rule), re.IGNORECASE)

    def test_manifest_stays_inside_checkpoint_limit(self):
        self.assertEqual(len(self.rules), 16)
        self.assertTrue(10 <= len(self.rules) <= 20)

    def test_parent_subtechnique_rule_auto_resolves(self):
        resolution = self.models["proc_creation_win_esentutl_params.yml"].technique_resolution
        self.assertEqual(resolution.status, "mapping_candidate")
        self.assertEqual(resolution.resolved_tags, ["T1003.003"])

    def test_genuine_multi_and_missing_tags_are_reviewed(self):
        for source in (
            "proc_creation_win_susp_eventlog_clear.yml",
            "proc_creation_win_bitsadmin_download.yml",
            "proc_creation_win_rundll32_process_dump_via_comsvcs.yml",
            "proc_creation_win_ping_hex_ip.yml",
            "proc_creation_win_uac_bypass_cmstp.yml",
            "proc_creation_win_instalutil_no_log_execution.yml",
        ):
            self.assertEqual(self.models[source].technique_resolution.status, "needs_review", source)

    def test_contains_all_requires_all_values(self):
        source = "proc_creation_win_instalutil_no_log_execution.yml"
        self.assert_matches(
            source,
            r"Image=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe "
            r"CommandLine=InstallUtil.exe /logfile= /LogToConsole=false /u payload.dll",
        )
        self.assert_not_matches(
            source,
            r"Image=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe "
            r"CommandLine=InstallUtil.exe /logfile= /u payload.dll",
        )
        self.assert_matches(
            source,
            r'{"Image":"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe",'
            r'"CommandLine":"InstallUtil.exe /logfile= /LogToConsole=false /u payload.dll"}',
        )

    def test_nested_and_or_regsvr32(self):
        source = "proc_creation_win_regsvr32_network_pattern.yml"
        self.assert_matches(
            source,
            r"Image=C:\Windows\System32\regsvr32.exe CommandLine=regsvr32 /i:https://example.test/a.sct",
        )
        self.assert_not_matches(
            source,
            r"Image=C:\Windows\System32\regsvr32.exe CommandLine=regsvr32 local.dll",
        )

    def test_negative_filter_is_preserved(self):
        source = "proc_creation_win_schtasks_creation.yml"
        self.assert_matches(
            source,
            r"Image=C:\Windows\System32\schtasks.exe CommandLine=schtasks.exe /create /tn Evil User=LAB\alice",
        )
        self.assert_not_matches(
            source,
            r"Image=C:\Windows\System32\schtasks.exe "
            r"CommandLine=schtasks.exe /create /tn Evil User=NT AUTHORITY\SYSTEM",
        )

    def test_sigma_regular_expression_is_preserved(self):
        source = "proc_creation_win_ping_hex_ip.yml"
        self.assert_matches(source, r"Image=C:\Windows\System32\ping.exe CommandLine=ping.exe 0xC0A80101")
        self.assert_not_matches(source, r"Image=C:\Windows\System32\ping.exe CommandLine=ping.exe 192.168.1.1")

    def test_windash_expansion_is_or_linked(self):
        regex = self.compile_extra_rule(
            "rules/windows/process_creation/proc_creation_win_msdt_arbitrary_command_execution.yml"
        )
        self.assertIsNotNone(
            regex.search(
                r"Image=C:\Windows\System32\msdt.exe "
                r"CommandLine=msdt.exe PCWDiagnostic /af payload.diagcab"
            )
        )

    def test_leading_inline_regex_flags_are_scoped(self):
        regex = self.compile_extra_rule(
            "rules/windows/process_creation/proc_creation_win_powershell_token_obfuscation.yml"
        )
        self.assertIsInstance(regex, re.Pattern)

    def test_complex_comsvcs_rule(self):
        self.assert_matches(
            "proc_creation_win_rundll32_process_dump_via_comsvcs.yml",
            r"Image=C:\Windows\System32\rundll32.exe CommandLine=rundll32.exe comsvcs.dll MiniDump 756 dump.dmp full",
        )

    def test_eventlog_filter_excludes_msiexec_noise(self):
        source = "proc_creation_win_susp_eventlog_clear.yml"
        self.assert_matches(
            source,
            r"Image=C:\Windows\System32\wevtutil.exe CommandLine=wevtutil.exe set-log Security /lfn:C:\Temp\x.evtx",
        )
        self.assert_not_matches(
            source,
            r"ParentImage=C:\Windows\System32\msiexec.exe Image=C:\Windows\System32\wevtutil.exe "
            r"CommandLine=wevtutil.exe sl Microsoft-RMS-MSIPC/Debug",
        )

    def test_netsh_dropbox_filter_and_wildcard_are_preserved(self):
        source = "proc_creation_win_netsh_fw_add_rule.yml"
        self.assert_matches(
            source,
            r"Image=C:\Windows\System32\netsh.exe CommandLine=netsh advfirewall firewall add rule name=Evil",
        )
        self.assert_not_matches(
            source,
            r'Image=C:\Windows\System32\netsh.exe CommandLine=netsh advfirewall firewall add rule '
            r'name=Dropbox dir=in action=allow "program=C:\Program Files\Dropbox\Client\Dropbox.exe" '
            r'enable=yes profile=Any',
        )


if __name__ == "__main__":
    unittest.main()
