from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from correlation.heuristics import HeuristicPolicy
from correlation.replay import CorrelationReplayRunner, ReplayPolicy
from correlation.replay_local import (
    LocalReplayArchive,
    ReplayArchiveIntegrityError,
)
from correlation.test_heuristics import _event
from correlation.test_replay import _Source


def _result():
    events = [
        _event("parent", pid="100"),
        _event("child", pid="200", ppid="100", seconds=1),
    ]
    return CorrelationReplayRunner(
        ReplayPolicy(
            heuristic=HeuristicPolicy.pid_lineage_shadow(
                max_parent_pid_gap_seconds=10
            )
        )
    ).run(_Source(events))


class LocalReplayArchiveTests(unittest.TestCase):
    def test_concurrent_idempotent_publish_is_race_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            result = _result()

            def publish(_):
                return LocalReplayArchive(directory).put(result)

            with ThreadPoolExecutor(max_workers=8) as pool:
                report_ids = tuple(pool.map(publish, range(32)))

            self.assertEqual(set(report_ids), {result.report.report_id})
            self.assertEqual(
                LocalReplayArchive(directory).get_report(report_ids[0]),
                result.report,
            )

    def test_round_trip_complete_review_records_and_idempotent_put(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = LocalReplayArchive(directory)
            result = _result()

            report_id = archive.put(result)
            second_id = archive.put(result)

            self.assertEqual(second_id, report_id)
            self.assertEqual(archive.get_report(report_id), result.report)
            self.assertEqual(
                archive.review_records(report_id, "heuristic_edges"),
                tuple(edge.to_dict() for edge in result.heuristic_edges.edges),
            )
            self.assertEqual(
                archive.review_records(report_id, "shadow_assessments"),
                tuple(
                    item.to_dict()
                    for item in result.shadow_comparison.assessments
                ),
            )
            self.assertEqual(
                archive.review_records(report_id, "shadow_components"),
                tuple(
                    item.to_dict()
                    for item in result.shadow_comparison.components
                ),
            )

    def test_corruption_and_unsupported_artifacts_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = LocalReplayArchive(directory)
            result = _result()
            report_id = archive.put(result)
            digest = report_id.split(":", 1)[1]
            edge_path = Path(directory) / digest / "heuristic_edges.jsonl"
            edge_path.write_bytes(edge_path.read_bytes() + b"{}\n")

            with self.assertRaises(ReplayArchiveIntegrityError):
                archive.review_records(report_id, "heuristic_edges")
            with self.assertRaises(ValueError):
                archive.review_records(report_id, "unknown")
            with self.assertRaises(ValueError):
                archive.get_report("../../escape")

    def test_result_and_report_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = LocalReplayArchive(directory)
            result = _result()
            other = CorrelationReplayRunner().run(
                _Source([_event("other", pid="900")])
            )
            mismatched = replace(result, report=other.report)

            with self.assertRaises(ReplayArchiveIntegrityError):
                archive.put(mismatched)

    def test_symlink_root_and_archive_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ReplayArchiveIntegrityError):
                LocalReplayArchive(linked)

            archive = LocalReplayArchive(real)
            result = _result()
            report_id = archive.put(result)
            digest = report_id.split(":", 1)[1]
            report_path = real / digest / "report.json"
            report_path.unlink()
            report_path.symlink_to(real / digest / "heuristic_edges.jsonl")
            with self.assertRaises(ReplayArchiveIntegrityError):
                archive.get_report(report_id)

    def test_file_size_limit_is_enforced_on_read(self):
        with tempfile.TemporaryDirectory() as directory:
            writer = LocalReplayArchive(directory)
            result = _result()
            report_id = writer.put(result)
            reader = LocalReplayArchive(directory, max_file_bytes=1)

            with self.assertRaises(ReplayArchiveIntegrityError):
                reader.get_report(report_id)


if __name__ == "__main__":
    unittest.main()
