"""Durable local archive for replay reports and shadow-review artifacts."""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable

from correlation.replay import (
    CorrelationReplayReport,
    CorrelationReplayResult,
    _artifact_manifest,
    _canonical_json,
)


_REPORT_ID = re.compile(r"^correlation-replay:([0-9a-f]{64})$")
_REVIEW_ARTIFACTS = {
    "heuristic_edges": "heuristic_edges.jsonl",
    "shadow_assessments": "shadow_assessments.jsonl",
    "shadow_components": "shadow_components.jsonl",
}
DEFAULT_MAX_ARCHIVE_FILE_BYTES = 2 * 1024 * 1024 * 1024


class ReplayArchiveError(RuntimeError):
    pass


class ReplayArchiveIntegrityError(ReplayArchiveError):
    pass


def _report_digest(report_id: str) -> str:
    match = _REPORT_ID.fullmatch(str(report_id or ""))
    if match is None:
        raise ValueError("invalid correlation replay report ID")
    return match.group(1)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(_canonical_json(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def _write_jsonl(path: Path, values: Iterable[dict[str, Any]]) -> None:
    with path.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        for value in values:
            handle.write(_canonical_json(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


class LocalReplayArchive:
    """Content-addressed, immutable replay output storage.

    The bounded report is stored separately from complete JSONL review streams.
    Every read validates canonical encoding, record count, and the report's
    length-delimited artifact digest before returning records.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        max_file_bytes: int = DEFAULT_MAX_ARCHIVE_FILE_BYTES,
    ) -> None:
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        requested_root = Path(root).expanduser()
        if requested_root.exists() and requested_root.is_symlink():
            raise ReplayArchiveIntegrityError("archive root must not be a symlink")
        self.root = requested_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_file_bytes = max_file_bytes

    def _directory(self, report_id: str) -> Path:
        return self.root / _report_digest(report_id)

    @staticmethod
    def _validate_result(result: CorrelationReplayResult) -> None:
        if not isinstance(result, CorrelationReplayResult):
            raise TypeError("result must be a CorrelationReplayResult")
        rebuilt = CorrelationReplayReport.create(
            policy=result.policy,
            edge_result=result.deterministic_edges,
            snapshot=result.deterministic_snapshot,
            heuristic_result=result.heuristic_edges,
            shadow_result=result.shadow_comparison,
        )
        if rebuilt != result.report:
            raise ReplayArchiveIntegrityError(
                "replay result does not match its report"
            )

    def put(self, result: CorrelationReplayResult) -> str:
        self._validate_result(result)
        report_id = result.report.report_id
        destination = self._directory(report_id)
        if destination.exists():
            self._verify_archive(destination, result.report)
            return report_id

        temporary = Path(tempfile.mkdtemp(prefix=".replay-", dir=self.root))
        try:
            _write_json(temporary / "report.json", result.report.to_dict())
            _write_jsonl(
                temporary / _REVIEW_ARTIFACTS["heuristic_edges"],
                (edge.to_dict() for edge in result.heuristic_edges.edges),
            )
            _write_jsonl(
                temporary / _REVIEW_ARTIFACTS["shadow_assessments"],
                (
                    item.to_dict()
                    for item in result.shadow_comparison.assessments
                ),
            )
            _write_jsonl(
                temporary / _REVIEW_ARTIFACTS["shadow_components"],
                (
                    item.to_dict()
                    for item in result.shadow_comparison.components
                ),
            )
            _fsync_directory(temporary)
            try:
                os.rename(temporary, destination)
            except OSError as exc:
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                self._verify_archive(destination, result.report)
            _fsync_directory(self.root)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        self._verify_archive(destination, result.report)
        return report_id

    def _safe_file(self, directory: Path, name: str) -> Path:
        self._safe_directory(directory)
        path = directory / name
        try:
            metadata = path.lstat()
        except FileNotFoundError as exc:
            raise ReplayArchiveIntegrityError(
                f"archive file is missing: {name}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReplayArchiveIntegrityError(
                f"archive path is not a regular file: {name}"
            )
        if metadata.st_size > self.max_file_bytes:
            raise ReplayArchiveIntegrityError(
                f"archive file exceeds configured size limit: {name}"
            )
        return path

    def _safe_directory(self, directory: Path) -> None:
        try:
            metadata = directory.lstat()
        except FileNotFoundError as exc:
            raise ReplayArchiveIntegrityError(
                "archive report directory is missing"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ReplayArchiveIntegrityError(
                "archive report path must be a real directory"
            )

    def get_report(self, report_id: str) -> CorrelationReplayReport:
        directory = self._directory(report_id)
        report_path = self._safe_file(directory, "report.json")
        try:
            raw = report_path.read_bytes()
            if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
                raise ValueError("report must contain one complete JSON record")
            value = json.loads(raw)
        except (OSError, ValueError) as exc:
            raise ReplayArchiveIntegrityError("invalid replay report file") from exc
        report = CorrelationReplayReport.from_dict(value)
        if report.report_id != report_id:
            raise ReplayArchiveIntegrityError("report directory ID mismatch")
        return report

    def review_records(
        self,
        report_id: str,
        artifact_name: str,
    ) -> tuple[dict, ...]:
        if artifact_name not in _REVIEW_ARTIFACTS:
            raise ValueError("unsupported replay review artifact")
        report = self.get_report(report_id)
        directory = self._directory(report_id)
        path = self._safe_file(directory, _REVIEW_ARTIFACTS[artifact_name])
        records: list[dict[str, Any]] = []
        try:
            with path.open("rb") as handle:
                for line in handle:
                    if not line.endswith(b"\n"):
                        raise ValueError("incomplete JSONL record")
                    encoded = line[:-1]
                    value = json.loads(encoded)
                    if not isinstance(value, dict):
                        raise ValueError("JSONL record must be an object")
                    if _canonical_json(value) != encoded:
                        raise ValueError("JSONL record is not canonical")
                    records.append(value)
        except (OSError, ValueError) as exc:
            raise ReplayArchiveIntegrityError(
                f"invalid replay artifact: {artifact_name}"
            ) from exc

        expected = report.to_dict()["artifacts"][artifact_name]
        actual = _artifact_manifest(records)
        if actual != expected:
            raise ReplayArchiveIntegrityError(
                f"replay artifact digest mismatch: {artifact_name}"
            )
        return tuple(records)

    def _verify_archive(
        self,
        directory: Path,
        expected_report: CorrelationReplayReport,
    ) -> None:
        self._safe_directory(directory)
        report = self.get_report(expected_report.report_id)
        if report != expected_report:
            raise ReplayArchiveIntegrityError("stored replay report mismatch")
        for artifact_name in _REVIEW_ARTIFACTS:
            self.review_records(report.report_id, artifact_name)
