from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from correlation.local import LocalRawEvidenceStore
from correlation.models import EventTimeQuality, ParseStatus, Platform
from correlation.windows import WindowsAdapter


NOW = datetime(2026, 8, 4, 13, 0, tzinfo=timezone.utc)
PROCESS_GUID = "{11111111-1111-1111-1111-111111111111}"
PARENT_GUID = "{22222222-2222-2222-2222-222222222222}"
LOGON_GUID = "{33333333-3333-3333-3333-333333333333}"


def _sysmon_event(event_id: int, record_id: int, **event_data):
    return {
        "@timestamp": "2026-08-04T12:59:59.123456Z",
        "host": {"name": "untrusted-reported-host"},
        "winlog": {
            "provider_name": "Microsoft-Windows-Sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": record_id,
            "event_id": event_id,
            "computer_name": "WINDOWS-01",
            "event_data": event_data,
        },
    }


class WindowsAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = LocalRawEvidenceStore(self.root / "evidence")
        self.adapter = WindowsAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="trusted-host-id",
            boot_id="boot-2026-08-04",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _ingest_json(self, value):
        return self.adapter.ingest(
            json.dumps(value).encode(),
            media_type="application/json",
            collected_at=NOW,
        )

    def test_sysmon_process_create_preserves_authoritative_lineage(self) -> None:
        event = self._ingest_json(
            _sysmon_event(
                1,
                901,
                UtcTime="2026-08-04 12:59:59.123",
                ProcessGuid=PROCESS_GUID,
                ProcessId="0x2a",
                Image=r"C:\Windows\System32\cmd.exe",
                CommandLine="cmd.exe /c whoami",
                ParentProcessGuid=PARENT_GUID,
                ParentProcessId="4",
                ParentImage=r"C:\Windows\System32\services.exe",
                LogonGuid=LOGON_GUID,
                LogonId="0x3e7",
                User="NT AUTHORITY\\SYSTEM",
            )
        )[0]

        self.assertEqual(event.platform, Platform.WINDOWS)
        self.assertEqual(event.source_type, "sysmon")
        self.assertEqual(event.parse_status, ParseStatus.PARSED)
        self.assertEqual(event.attributes["event"]["action"], "process_start")
        self.assertEqual(event.attributes["process"]["pid"], "42")
        self.assertEqual(event.attributes["process"]["guid"], PROCESS_GUID.lower())
        self.assertEqual(
            event.attributes["process"]["parent"]["guid"], PARENT_GUID.lower()
        )
        self.assertEqual(event.attributes["user"]["logon_id"], "999")
        self.assertEqual(event.attributes["host"]["id"], "trusted-host-id")
        self.assertEqual(event.attributes["host"]["reported_name"], "WINDOWS-01")
        self.assertIn(
            ("process_guid", PROCESS_GUID.lower(), "trusted-host-id:boot-2026-08-04"),
            {(key.kind, key.value, key.scope) for key in event.entity_keys},
        )
        self.assertTrue(event.raw_evidence.uri.startswith("file://"))

    def test_network_event_reuses_same_process_guid_scope(self) -> None:
        event = self._ingest_json(
            _sysmon_event(
                3,
                902,
                ProcessGuid=PROCESS_GUID,
                ProcessId="42",
                Image=r"C:\Windows\System32\cmd.exe",
                Protocol="tcp",
                Initiated="true",
                SourceIp="10.0.0.5",
                SourcePort="55123",
                DestinationIp="203.0.113.10",
                DestinationPort="443",
            )
        )[0]
        self.assertEqual(event.attributes["event"]["action"], "network_connection")
        self.assertEqual(event.attributes["network"]["destination"]["port"], "443")
        self.assertIn(
            PROCESS_GUID.lower(),
            {key.value for key in event.entity_keys if key.kind == "process_guid"},
        )

    def test_exported_event_xml_is_supported(self) -> None:
        xml = f"""<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
          <System>
            <Provider Name=\"Microsoft-Windows-Sysmon\" />
            <EventID>5</EventID>
            <TimeCreated SystemTime=\"2026-08-04T12:59:59.0000000Z\" />
            <EventRecordID>903</EventRecordID>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>WINDOWS-01</Computer>
          </System>
          <EventData>
            <Data Name=\"ProcessGuid\">{PROCESS_GUID}</Data>
            <Data Name=\"ProcessId\">42</Data>
          </EventData>
        </Event>""".encode()
        event = self.adapter.ingest(
            xml,
            media_type="application/xml",
            collected_at=NOW,
        )[0]
        self.assertEqual(event.attributes["event"]["action"], "process_end")
        self.assertEqual(event.native_event_id, "903")
        self.assertEqual(event.event_time_quality, EventTimeQuality.SOURCE_REPORTED)

    def test_security_4688_uses_pid_and_logon_scope_without_inventing_guid(self) -> None:
        record = {
            "System": {
                "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                "EventID": "4688",
                "EventRecordID": "1001",
                "Channel": "Security",
                "TimeCreated": {"SystemTime": "2026-08-04T12:59:58Z"},
            },
            "EventData": {
                "NewProcessId": "0x2a",
                "NewProcessName": r"C:\Windows\System32\whoami.exe",
                "ProcessId": "0x4",
                "CreatorProcessName": r"C:\Windows\System32\cmd.exe",
                "SubjectLogonId": "0x3e7",
                "SubjectUserSid": "S-1-5-18",
            },
        }
        event = self._ingest_json(record)[0]
        keys = {(key.kind, key.value) for key in event.entity_keys}
        self.assertEqual(event.attributes["event"]["action"], "process_start")
        self.assertEqual(event.attributes["process"]["pid"], "42")
        self.assertEqual(event.attributes["process"]["parent"]["pid"], "4")
        self.assertIn(("process_pid", "42"), keys)
        self.assertIn(("parent_process_pid", "4"), keys)
        self.assertNotIn("process_guid", {key.kind for key in event.entity_keys})

    def test_malformed_ndjson_keeps_each_record_visible(self) -> None:
        good = json.dumps(_sysmon_event(1, 904, ProcessGuid=PROCESS_GUID))
        payload = (good + "\n{broken-json\n").encode()
        events = self.adapter.ingest(
            payload,
            media_type="application/x-ndjson",
            collected_at=NOW,
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].parse_status, ParseStatus.PARSED)
        self.assertEqual(events[1].parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(events[0].raw_evidence, events[1].raw_evidence)

    def test_binary_evtx_and_oversized_payload_are_stored_not_guessed(self) -> None:
        evtx = _EVTX = b"ElfFile\x00" + b"binary"
        event = self.adapter.ingest(
            evtx,
            media_type="application/vnd.ms-evtx",
            collected_at=NOW,
        )[0]
        self.assertEqual(event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("trusted Windows collection tier", event.parse_warnings[0])
        self.assertEqual(self.store.get(event.raw_evidence), evtx)

        limited = WindowsAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="trusted-host-id",
            boot_id="boot-2026-08-04",
            max_payload_bytes=4,
        )
        oversized = limited.ingest(
            b"12345", media_type="application/octet-stream", collected_at=NOW
        )[0]
        self.assertEqual(oversized.parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(self.store.get(oversized.raw_evidence), b"12345")

    def test_event_id_is_stable_for_replayed_native_record(self) -> None:
        record = _sysmon_event(1, 905, ProcessGuid=PROCESS_GUID)
        first = self._ingest_json(record)[0]
        second = self._ingest_json(record)[0]
        self.assertEqual(first.event_id, second.event_id)

        # EventRecordID alone is not a lifetime-unique identity: clearing a
        # Windows channel can restart its numbering. Different record content
        # with the same ID must not collide or create a correlation key.
        reused_record_id = _sysmon_event(1, 905, ProcessGuid=PARENT_GUID)
        third = self._ingest_json(reused_record_id)[0]
        self.assertNotEqual(first.event_id, third.event_id)
        self.assertNotIn("windows_event_record", {key.kind for key in first.entity_keys})


if __name__ == "__main__":
    unittest.main()
