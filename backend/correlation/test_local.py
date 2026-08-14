from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from correlation.local import (
    EventConflictError,
    EvidenceIntegrityError,
    JournalCorruptionError,
    LocalEventJournal,
    LocalRawEvidenceStore,
)
from correlation.models import (
    EntityKey,
    EventTimeQuality,
    NormalizedEvent,
    ParseStatus,
    Platform,
    RawEvidenceRef,
)


NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


class LocalCorrelationStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = LocalRawEvidenceStore(self.root / "evidence")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _put(self, payload: bytes = b'{"EventID":1}') -> RawEvidenceRef:
        return self.store.put(
            payload,
            tenant_id="tenant-a",
            platform=Platform.WINDOWS,
            source_instance_id="host-a",
            media_type="application/json",
            collected_at=NOW,
        )

    def _event(self, *, event_id: str = "event-1") -> NormalizedEvent:
        return NormalizedEvent(
            event_id=event_id,
            tenant_id="tenant-a",
            platform=Platform.WINDOWS,
            source_type="sysmon",
            source_instance_id="host-a",
            adapter_version="1.0.0",
            observed_at=NOW,
            ingested_at=NOW,
            event_time_quality=EventTimeQuality.SOURCE_REPORTED,
            parse_status=ParseStatus.PARSED,
            raw_evidence=self._put(),
            native_event_id="native-1",
            entity_keys=(EntityKey("process_guid", "guid-1", "host-a:boot-a"),),
            attributes={"event": {"id": 1}},
        )

    def test_evidence_write_is_atomic_idempotent_and_verified(self) -> None:
        first = self._put()
        second = self._put()

        self.assertEqual(first, second)
        self.assertEqual(self.store.get(first), b'{"EventID":1}')
        self.assertEqual(len(list((self.root / "evidence").rglob("*.raw"))), 1)
        self.assertNotIn("tenant-a", first.uri)
        self.assertNotIn("host-a", first.uri)

    def test_tenant_and_source_namespaces_do_not_share_storage_paths(self) -> None:
        payload = b"same bytes"
        first = self._put(payload)
        second = self.store.put(
            payload,
            tenant_id="tenant-b",
            platform=Platform.WINDOWS,
            source_instance_id="host-a",
            media_type="application/octet-stream",
            collected_at=NOW,
        )
        self.assertEqual(first.sha256, second.sha256)
        self.assertNotEqual(first.uri, second.uri)

    def test_corrupted_and_out_of_root_evidence_is_rejected(self) -> None:
        reference = self._put()
        Path(reference.uri.removeprefix("file://")).write_bytes(b"tampered")
        with self.assertRaisesRegex(EvidenceIntegrityError, "byte length"):
            self.store.get(reference)

        outside = self.root / "outside.raw"
        outside.write_bytes(b"outside")
        external = RawEvidenceRef(
            sha256=hashlib.sha256(b"outside").hexdigest(),
            uri=outside.resolve().as_uri(),
            byte_length=7,
            media_type="application/octet-stream",
            collected_at=NOW,
        )
        with self.assertRaisesRegex(EvidenceIntegrityError, "escapes"):
            self.store.get(external)

    def test_journal_publish_replay_restart_and_idempotency(self) -> None:
        path = self.root / "events" / "normalized.jsonl"
        journal = LocalEventJournal(path)
        event = self._event()

        journal.publish(event)
        journal.publish(event)
        self.assertEqual(list(journal.events()), [event])
        self.assertEqual(list(LocalEventJournal(path).events()), [event])
        self.assertEqual(path.read_bytes().count(b"\n"), 1)

    def test_same_event_id_may_exist_in_different_tenants(self) -> None:
        journal = LocalEventJournal(self.root / "events.jsonl")
        first = self._event()
        second = replace(first, tenant_id="tenant-b")
        journal.publish(first)
        journal.publish(second)
        self.assertEqual(len(list(journal.events())), 2)

    def test_conflicting_event_payload_is_rejected(self) -> None:
        journal = LocalEventJournal(self.root / "events.jsonl")
        first = self._event()
        journal.publish(first)
        conflicting = replace(first, native_event_id="different")
        with self.assertRaisesRegex(EventConflictError, "different content"):
            journal.publish(conflicting)

    def test_truncated_final_record_is_ignored_but_internal_corruption_fails(self) -> None:
        path = self.root / "events.jsonl"
        journal = LocalEventJournal(path)
        event = self._event()
        journal.publish(event)
        with path.open("ab") as handle:
            handle.write(b'{"journal_schema_version":')
        self.assertEqual(list(LocalEventJournal(path).events()), [event])

        # A later publish must remove the uncommitted tail before appending,
        # otherwise the next valid JSON record would be glued onto it.
        recovered = LocalEventJournal(path)
        second = self._event(event_id="event-2")
        recovered.publish(second)
        self.assertEqual(list(LocalEventJournal(path).events()), [event, second])

        path.write_bytes(b"not-json\n" + json.dumps({"unused": True}).encode() + b"\n")
        with self.assertRaisesRegex(JournalCorruptionError, "invalid JSON"):
            LocalEventJournal(path)


if __name__ == "__main__":
    unittest.main()
