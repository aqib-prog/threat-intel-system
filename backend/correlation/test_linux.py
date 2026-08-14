from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from correlation.linux import LinuxAdapter
from correlation.local import LocalRawEvidenceStore
from correlation.models import ParseStatus, Platform


NOW = datetime(2026, 8, 4, 14, 0, tzinfo=timezone.utc)
PROCESS_GUID = "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"
PARENT_GUID = "{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}"


class LinuxAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = LocalRawEvidenceStore(self.root / "evidence")
        self.adapter = LinuxAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="linux-host-1",
            boot_id="boot-1",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _ingest(self, text: str):
        return self.adapter.ingest(
            text.encode(),
            media_type="text/plain",
            collected_at=NOW,
        )

    def test_compound_audit_records_share_only_the_event_serial_key(self) -> None:
        text = "\n".join(
            (
                'type=SYSCALL msg=audit(1618347101.412:2045): arch=c000003e syscall=59 success=yes exit=0 ppid=1204 pid=3412 auid=1000 uid=0 euid=0 gid=0 tty=pts0 ses=3 comm="bash" exe="/usr/bin/bash" key="exec"',
                'type=EXECVE msg=audit(1618347101.412:2045): argc=3 a0="chmod" a1="+x" a2="/tmp/mal_agent"',
                'type=CWD msg=audit(1618347101.412:2045): cwd="/home/user"',
                'type=PATH msg=audit(1618347101.412:2045): item=0 name="/tmp/mal_agent" inode=42',
            )
        )
        events = self._ingest(text)
        self.assertEqual(len(events), 4)
        self.assertTrue(all(event.platform is Platform.LINUX for event in events))
        serial_scopes = {
            (key.value, key.scope)
            for event in events
            for key in event.entity_keys
            if key.kind == "audit_event_serial"
        }
        self.assertEqual(serial_scopes, {("2045", "linux-host-1:boot-1")})
        self.assertEqual(events[1].attributes["process"]["command_line"], "chmod +x /tmp/mal_agent")
        self.assertEqual(events[3].attributes["file"]["path"], "/tmp/mal_agent")
        self.assertEqual({event.native_event_id for event in events}, {"2045"})
        self.assertEqual(len({event.event_id for event in events}), 4)

    def test_audit_login_context_is_not_promoted_to_process_identity(self) -> None:
        event = self._ingest(
            'type=USER_CMD msg=audit(1618347102.000:2046): pid=3500 uid=1000 auid=1000 ses=3 cmd="sudo id" res=success'
        )[0]
        kinds = {key.kind for key in event.entity_keys}
        self.assertIn("audit_session", kinds)
        self.assertIn("login_uid", kinds)
        self.assertNotIn("process_guid", kinds)
        self.assertNotIn("audit_serial_process", kinds)

    def test_unset_audit_identity_sentinels_are_not_keys(self) -> None:
        event = self._ingest(
            "type=SYSCALL msg=audit(1618347103.000:2047): pid=1 ppid=0 auid=4294967295 ses=4294967295 success=yes"
        )[0]
        kinds = {key.kind for key in event.entity_keys}
        self.assertNotIn("audit_session", kinds)
        self.assertNotIn("login_uid", kinds)

    def test_proctitle_hex_is_decoded_without_changing_raw_evidence(self) -> None:
        line = (
            "type=PROCTITLE msg=audit(1618347104.000:2048): "
            "proctitle=636174002F6574632F7373682F737368645F636F6E666967"
        )
        event = self._ingest(line)[0]
        self.assertEqual(event.attributes["process"]["command_line"], "cat /etc/ssh/sshd_config")
        self.assertEqual(self.store.get(event.raw_evidence), line.encode())

    def test_sysmon_for_linux_xml_preserves_process_guid(self) -> None:
        xml = f"""Aug 04 host sysmon: <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Linux-Sysmon\"/><EventID>1</EventID><TimeCreated SystemTime=\"2026-08-04T13:59:58Z\"/><EventRecordID>77</EventRecordID><Channel>Linux-Sysmon/Operational</Channel></System><EventData><Data Name=\"ProcessGuid\">{PROCESS_GUID}</Data><Data Name=\"ProcessId\">3412</Data><Data Name=\"Image\">/usr/bin/bash</Data><Data Name=\"CommandLine\">bash -c id</Data><Data Name=\"ParentProcessGuid\">{PARENT_GUID}</Data><Data Name=\"ParentProcessId\">1204</Data></EventData></Event>"""
        event = self._ingest(xml)[0]
        self.assertEqual(event.source_type, "sysmon_linux")
        self.assertEqual(event.attributes["event"]["action"], "process_start")
        self.assertEqual(event.attributes["process"]["guid"], PROCESS_GUID.lower())
        self.assertIn("process_guid", {key.kind for key in event.entity_keys})

    def test_auditbeat_json_and_journald_message_are_supported(self) -> None:
        auditbeat = {
            "@timestamp": "2026-08-04T13:59:57Z",
            "auditd": {
                "sequence": 2050,
                "message_type": "syscall",
                "result": "success",
                "data": {"syscall": "execve", "key": "exec"},
            },
            "process": {
                "pid": 4000,
                "ppid": 3999,
                "executable": "/usr/bin/id",
                "args": ["id", "-u"],
            },
            "user": {"id": "0", "audit": {"id": "1000"}},
        }
        event = self.adapter.ingest(
            json.dumps(auditbeat).encode(),
            media_type="application/json",
            collected_at=NOW,
        )[0]
        self.assertEqual(event.source_type, "auditd")
        self.assertEqual(event.attributes["process"]["command_line"], "id -u")
        self.assertIn("audit_event_serial", {key.kind for key in event.entity_keys})

        journal = {
            "MESSAGE": "type=SYSCALL msg=audit(1618347105.000:2051): pid=41 ppid=1 auid=1000 ses=3 success=yes",
            "_HOSTNAME": "untrusted-host-name",
        }
        journal_event = self.adapter.ingest(
            json.dumps(journal).encode(),
            media_type="application/json",
            collected_at=NOW,
        )[0]
        self.assertEqual(journal_event.attributes["host"]["id"], "linux-host-1")
        self.assertEqual(journal_event.native_event_id, "2051")

    def test_audit_pattern_inside_arbitrary_json_value_is_not_native_audit(self) -> None:
        record = {
            "user_supplied_text": (
                "type=SYSCALL msg=audit(1618347105.000:2051): pid=41 success=yes"
            )
        }
        event = self.adapter.ingest(
            json.dumps(record).encode(),
            media_type="application/json",
            collected_at=NOW,
        )[0]
        self.assertEqual(event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIsNone(event.native_event_id)

    def test_unknown_and_oversized_payloads_are_retained_as_unparseable(self) -> None:
        event = self._ingest("ordinary application text")[0]
        self.assertEqual(event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(self.store.get(event.raw_evidence), b"ordinary application text")

        limited = LinuxAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="linux-host-1",
            boot_id="boot-1",
            max_payload_bytes=3,
        )
        oversized = limited.ingest(
            b"1234", media_type="text/plain", collected_at=NOW
        )[0]
        self.assertEqual(oversized.parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(self.store.get(oversized.raw_evidence), b"1234")


if __name__ == "__main__":
    unittest.main()
