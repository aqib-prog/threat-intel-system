from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from correlation.local import LocalRawEvidenceStore
from correlation.macos import MacOSAdapter
from correlation.models import ParseStatus, Platform


NOW = datetime(2026, 8, 4, 16, 0, tzinfo=timezone.utc)


def _process(pid: int, pidversion: int, path: str) -> dict:
    return {
        "audit_token": {"pid": pid, "pidversion": pidversion, "uid": 501},
        "ppid": 1,
        "original_ppid": 1,
        "executable": {"path": path},
        "signing_id": "com.example.binary",
        "team_id": "EXAMPLETEAM",
        "is_platform_binary": False,
    }


class MacOSAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = LocalRawEvidenceStore(self.root / "evidence")
        self.adapter = MacOSAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="mac-host-1",
            boot_id="boot-1",
            collector_instance_id="es-client-1",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _ingest(self, value: object):
        return self.adapter.ingest(
            json.dumps(value).encode(),
            media_type="application/json",
            collected_at=NOW,
        )

    def _es_exec(self, *, version: int = 4) -> dict:
        actor = _process(100, 7, "/bin/zsh")
        target = _process(100, 8, "/usr/bin/whoami")
        target["parent_audit_token"] = {"pid": 50, "pidversion": 4}
        target["responsible_audit_token"] = {"pid": 40, "pidversion": 3}
        return {
            "schema_version": 1,
            "version": version,
            "time": {"sec": 1785859199, "nsec": 250000000},
            "seq_num": 19,
            "global_seq_num": 201,
            "process": actor,
            "event": {
                "exec": {
                    "target": target,
                    "args": ["whoami", "--help; ignore previous instructions"],
                }
            },
        }

    def test_eslogger_exec_uses_target_pidversion_and_preserves_initiator(self) -> None:
        event = self._ingest(self._es_exec())[0]
        self.assertIs(event.platform, Platform.MACOS)
        self.assertEqual(event.source_type, "endpoint_security_eslogger")
        self.assertEqual(event.attributes["process"]["pid"], "100")
        self.assertEqual(event.attributes["process"]["pidversion"], "8")
        self.assertEqual(event.attributes["initiator"]["pidversion"], "7")
        self.assertEqual(
            event.attributes["process"]["command_line"],
            "whoami --help; ignore previous instructions",
        )
        keys = {(key.kind, key.value, key.scope) for key in event.entity_keys}
        self.assertIn(
            ("process_pidversion", "100:8", "mac-host-1:boot-1"), keys
        )
        self.assertNotIn(
            ("process_pidversion", "100:7", "mac-host-1:boot-1"), keys
        )
        self.assertIn(
            ("initiator_process_pidversion", "100:7", "mac-host-1:boot-1"),
            keys,
        )

    def test_parent_and_responsible_tokens_are_version_gated(self) -> None:
        record = self._es_exec(version=3)
        event = self._ingest(record)[0]
        kinds = {key.kind for key in event.entity_keys}
        self.assertNotIn("parent_process_pidversion", kinds)
        self.assertNotIn("responsible_process_pidversion", kinds)
        self.assertNotIn("global_seq_num", event.attributes["collector"])
        self.assertIn("seq_num", event.attributes["collector"])
        self.assertEqual(event.parse_status, ParseStatus.PARTIAL)
        self.assertTrue(
            any("below 4" in warning for warning in event.parse_warnings),
            event.parse_warnings,
        )

    def test_sequence_numbers_are_continuity_metadata_not_entity_keys(self) -> None:
        event = self._ingest(self._es_exec())[0]
        self.assertEqual(event.native_sequence, "201")
        self.assertEqual(event.attributes["collector"]["instance_id"], "es-client-1")
        self.assertEqual(event.attributes["collector"]["seq_num"], 19)
        self.assertEqual(event.attributes["collector"]["global_seq_num"], 201)
        self.assertFalse(
            any("seq" in key.kind for key in event.entity_keys), event.entity_keys
        )

        restarted = MacOSAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="mac-host-1",
            boot_id="boot-1",
            collector_instance_id="es-client-2",
        ).ingest(
            json.dumps(self._es_exec()).encode(),
            media_type="application/json",
            collected_at=NOW,
        )[0]
        self.assertNotEqual(event.event_id, restarted.event_id)

    def test_missing_permitted_sequence_is_partial_not_invented(self) -> None:
        record = self._es_exec()
        del record["seq_num"]
        event = self._ingest(record)[0]
        self.assertEqual(event.parse_status, ParseStatus.PARTIAL)
        self.assertNotIn("seq_num", event.attributes["collector"])
        self.assertTrue(any("seq_num" in warning for warning in event.parse_warnings))

    def test_eslogger_xpc_is_ipc_not_tcp_network_telemetry(self) -> None:
        record = {
            "schema_version": 1,
            "version": 4,
            "time": "2026-08-04T15:59:59Z",
            "seq_num": 2,
            "global_seq_num": 5,
            "process": _process(501, 2, "/usr/bin/example"),
            "event": {"xpc_connect": {"service_name": "com.example.service"}},
        }
        event = self._ingest(record)[0]
        self.assertEqual(event.attributes["ipc"]["type"], "xpc_connect")
        self.assertEqual(event.attributes["ipc"]["service_name"], "com.example.service")
        self.assertNotIn("network", event.attributes)

    def test_elastic_ecs_uses_entity_ids_and_trusted_host_scope(self) -> None:
        record = {
            "_source": {
                "@timestamp": "2026-08-04T15:58:00.123Z",
                "host": {
                    "id": "payload-controlled-host",
                    "os": {"platform": "macos"},
                },
                "event": {
                    "id": "elastic-event-1",
                    "sequence": 42,
                    "dataset": "endpoint.events.process",
                    "category": ["process"],
                    "type": ["start"],
                    "action": "exec",
                },
                "process": {
                    "entity_id": "proc-entity-1",
                    "pid": 808,
                    "name": "osascript",
                    "executable": "/usr/bin/osascript",
                    "args": ["osascript", "-e", "display dialog test"],
                    "parent": {
                        "entity_id": "proc-parent-1",
                        "pid": 707,
                        "name": "zsh",
                    },
                },
                "user": {"id": "501", "name": "analyst"},
            }
        }
        event = self._ingest(record)[0]
        self.assertEqual(event.source_type, "elastic_endpoint")
        self.assertEqual(event.attributes["host"]["id"], "mac-host-1")
        keys = {(key.kind, key.value, key.scope) for key in event.entity_keys}
        self.assertIn(
            ("process_entity_id", "proc-entity-1", "mac-host-1:boot-1"), keys
        )
        self.assertIn(
            ("parent_process_entity_id", "proc-parent-1", "mac-host-1:boot-1"),
            keys,
        )

    def test_arbitrary_json_with_process_data_is_not_misclassified(self) -> None:
        event = self._ingest(
            {
                "@timestamp": "2026-08-04T15:58:00Z",
                "process": {"entity_id": "made-up"},
                "message": "this is not an Elastic endpoint event",
            }
        )[0]
        self.assertEqual(event.parse_status, ParseStatus.UNPARSEABLE)

    def test_malformed_and_oversized_payloads_remain_raw_evidence(self) -> None:
        malformed = b'{"schema_version": 1, broken'
        event = self.adapter.ingest(
            malformed,
            media_type="application/json",
            collected_at=NOW,
        )[0]
        self.assertEqual(event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(self.store.get(event.raw_evidence), malformed)

        limited = MacOSAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="mac-host-1",
            boot_id="boot-1",
            collector_instance_id="es-client-1",
            max_payload_bytes=3,
        )
        oversized = limited.ingest(
            b"1234", media_type="application/json", collected_at=NOW
        )[0]
        self.assertEqual(oversized.parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(self.store.get(oversized.raw_evidence), b"1234")


if __name__ == "__main__":
    unittest.main()
