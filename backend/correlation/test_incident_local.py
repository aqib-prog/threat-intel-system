from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from correlation.edges import DeterministicEdgeBuilder
from correlation.incident_local import (
    IncidentJournalCorruptionError,
    LocalIncidentHistory,
)
from correlation.incidents import IncidentBuilder, IncidentChangeKind
from correlation.models import EntityKey
from correlation.test_incidents import _event


def _snapshot(event_ids: tuple[str, ...]):
    key = EntityKey("process_guid", "process-1", "host:boot")
    events = [
        _event(event_id, key, seconds=index)
        for index, event_id in enumerate(event_ids)
    ]
    edges = DeterministicEdgeBuilder().build(events).edges
    return IncidentBuilder().build(events, edges)


class LocalIncidentHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "incidents.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_restart_preserves_revisions_and_rollback_appends_history(self) -> None:
        first = _snapshot(("event-1",))
        second = _snapshot(("event-1", "event-2"))
        history = LocalIncidentHistory(self.path)
        history.append(first)
        history.append(second)

        restarted = LocalIncidentHistory(self.path)
        self.assertEqual(restarted.current_snapshot, second)
        self.assertEqual(len(restarted.revisions), 2)
        rollback = restarted.rollback(first.snapshot_id)

        self.assertEqual(rollback.changes[0].kind, IncidentChangeKind.CONTRACTED)
        self.assertEqual(restarted.current_snapshot, first)
        self.assertEqual(
            restarted.timeline,
            (first.snapshot_id, second.snapshot_id, first.snapshot_id),
        )
        self.assertEqual(LocalIncidentHistory(self.path).current_snapshot, first)

    def test_repeated_current_snapshot_is_idempotent_on_disk(self) -> None:
        snapshot = _snapshot(("event-1",))
        history = LocalIncidentHistory(self.path)
        history.append(snapshot)
        size = self.path.stat().st_size

        self.assertIsNone(history.append(snapshot))
        self.assertEqual(self.path.stat().st_size, size)
        self.assertEqual(len(history.revisions), 1)

    def test_crash_truncated_tail_is_ignored_then_removed_before_append(self) -> None:
        first = _snapshot(("event-1",))
        second = _snapshot(("event-1", "event-2"))
        history = LocalIncidentHistory(self.path)
        history.append(first)
        with self.path.open("ab") as handle:
            handle.write(b'{"incomplete":')

        restarted = LocalIncidentHistory(self.path)
        self.assertEqual(restarted.current_snapshot, first)
        restarted.append(second)

        self.assertTrue(self.path.read_bytes().endswith(b"\n"))
        self.assertEqual(LocalIncidentHistory(self.path).current_snapshot, second)

    def test_tampered_committed_record_is_rejected(self) -> None:
        snapshot = _snapshot(("event-1",))
        LocalIncidentHistory(self.path).append(snapshot)
        record = json.loads(self.path.read_text())
        record["revision"]["revision_id"] = "incident-revision:" + ("0" * 64)
        self.path.write_text(json.dumps(record) + "\n")

        with self.assertRaises(IncidentJournalCorruptionError):
            LocalIncidentHistory(self.path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_journal_is_rejected(self) -> None:
        target = Path(self.temporary.name) / "target.jsonl"
        target.write_text("")
        os.symlink(target, self.path)

        with self.assertRaises(IncidentJournalCorruptionError):
            LocalIncidentHistory(self.path)


if __name__ == "__main__":
    unittest.main()
