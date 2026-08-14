"""Durable local incident snapshot and revision history.

This is the single-node implementation of ``IncidentHistoryStore``. A
distributed staging/production implementation can replace it without changing
the immutable snapshot and revision contracts.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from correlation.incidents import (
    IncidentHistory,
    IncidentRevision,
    IncidentRevisionError,
    IncidentSnapshot,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX production uses another store.
    fcntl = None


LOCAL_INCIDENT_JOURNAL_SCHEMA_VERSION = "1.0.0"


class IncidentJournalError(RuntimeError):
    pass


class IncidentJournalCorruptionError(IncidentJournalError):
    pass


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class LocalIncidentHistory:
    """Append-only, restart-safe local incident history."""

    def __init__(self, path: str | Path, *, fsync_on_append: bool = True):
        # Keep the final path component unresolved so a caller-supplied
        # symlink remains detectable rather than being silently followed.
        self.path = Path(path).expanduser().absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock_path = self.path.with_suffix(f"{self.path.suffix}.lock")
        self.fsync_on_append = fsync_on_append
        self._thread_lock = threading.RLock()
        self._validate_path()
        self._load_history()

    def _validate_path(self) -> None:
        if self.path.exists():
            if self.path.is_symlink():
                raise IncidentJournalCorruptionError(
                    "incident journal path must not be a symlink"
                )
            if not stat.S_ISREG(self.path.stat().st_mode):
                raise IncidentJournalCorruptionError(
                    "incident journal path must be a regular file"
                )

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self._thread_lock:
            if self.lock_path.is_symlink():
                raise IncidentJournalCorruptionError(
                    "incident journal lock path must not be a symlink"
                )
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.lock_path, flags, 0o600)
            except OSError as exc:
                raise IncidentJournalError(
                    "unable to open incident journal lock"
                ) from exc
            with os.fdopen(descriptor, "a+b", closefd=True) as lock_handle:
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if fcntl is not None:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _record_bytes(
        snapshot: IncidentSnapshot,
        revision: IncidentRevision,
    ) -> bytes:
        record = {
            "journal_schema_version": LOCAL_INCIDENT_JOURNAL_SCHEMA_VERSION,
            "snapshot": snapshot.to_dict(),
            "revision": revision.to_dict(),
        }
        return (
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    def _load_history(self) -> IncidentHistory:
        history = IncidentHistory()
        if not self.path.exists():
            return history
        self._validate_path()
        lines = self.path.read_bytes().splitlines(keepends=True)
        for index, line in enumerate(lines):
            if not line.endswith(b"\n"):
                if index == len(lines) - 1:
                    break
                raise IncidentJournalCorruptionError(
                    f"incident journal record {index + 1} is truncated"
                )
            try:
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise IncidentJournalCorruptionError(
                    f"incident journal record {index + 1} is invalid JSON"
                ) from exc
            if (
                value.get("journal_schema_version")
                != LOCAL_INCIDENT_JOURNAL_SCHEMA_VERSION
            ):
                raise IncidentJournalCorruptionError(
                    f"incident journal record {index + 1} has an unsupported schema"
                )
            snapshot_value = value.get("snapshot")
            revision_value = value.get("revision")
            if not isinstance(snapshot_value, dict) or not isinstance(
                revision_value, dict
            ):
                raise IncidentJournalCorruptionError(
                    f"incident journal record {index + 1} is incomplete"
                )
            try:
                snapshot = IncidentSnapshot.from_dict(snapshot_value)
                recorded_revision = IncidentRevision.from_dict(revision_value)
                expected_revision = history.append(snapshot)
            except (TypeError, ValueError, IncidentRevisionError) as exc:
                raise IncidentJournalCorruptionError(
                    f"incident journal record {index + 1} is invalid"
                ) from exc
            if expected_revision is None or expected_revision != recorded_revision:
                raise IncidentJournalCorruptionError(
                    f"incident journal record {index + 1} breaks revision history"
                )
        return history

    def _discard_uncommitted_tail(self) -> None:
        if not self.path.exists():
            return
        self._validate_path()
        raw = self.path.read_bytes()
        if not raw or raw.endswith(b"\n"):
            return
        committed_length = raw.rfind(b"\n") + 1
        flags = os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags)
        try:
            os.ftruncate(descriptor, committed_length)
            if self.fsync_on_append:
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if self.fsync_on_append:
            _fsync_directory(self.path.parent)

    def _append_locked(
        self,
        history: IncidentHistory,
        snapshot: IncidentSnapshot,
    ) -> IncidentRevision | None:
        revision = history.append(snapshot)
        if revision is None:
            return None
        record = self._record_bytes(snapshot, revision)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        try:
            view = memoryview(record)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise IncidentJournalError(
                        "incident journal append made no progress"
                    )
                view = view[written:]
            if self.fsync_on_append:
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if self.fsync_on_append:
            _fsync_directory(self.path.parent)
        return revision

    @property
    def current_snapshot(self) -> IncidentSnapshot | None:
        with self._exclusive_lock():
            return self._load_history().current_snapshot

    @property
    def revisions(self) -> tuple[IncidentRevision, ...]:
        with self._exclusive_lock():
            return self._load_history().revisions

    @property
    def timeline(self) -> tuple[str, ...]:
        with self._exclusive_lock():
            return self._load_history().timeline

    def get_snapshot(self, snapshot_id: str) -> IncidentSnapshot:
        with self._exclusive_lock():
            try:
                return self._load_history().get_snapshot(snapshot_id)
            except IncidentRevisionError as exc:
                raise IncidentJournalError("unknown incident snapshot") from exc

    def append(self, snapshot: IncidentSnapshot) -> IncidentRevision | None:
        if not isinstance(snapshot, IncidentSnapshot):
            raise TypeError("snapshot must be an IncidentSnapshot")
        with self._exclusive_lock():
            self._discard_uncommitted_tail()
            history = self._load_history()
            return self._append_locked(history, snapshot)

    def rollback(self, snapshot_id: str) -> IncidentRevision | None:
        with self._exclusive_lock():
            self._discard_uncommitted_tail()
            history = self._load_history()
            try:
                snapshot = history.get_snapshot(snapshot_id)
            except IncidentRevisionError as exc:
                raise IncidentJournalError("unknown incident snapshot") from exc
            return self._append_locked(history, snapshot)
