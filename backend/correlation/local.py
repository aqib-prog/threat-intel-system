"""Durable local implementations of the correlation infrastructure ports.

These implementations are intended for development, replay, and a single-node
staging deployment. Distributed staging/production backends replace them via
the ports in :mod:`correlation.ports`; event envelopes remain identical.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import threading
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator
from urllib.parse import unquote, urlparse

from correlation.models import NormalizedEvent, Platform, RawEvidenceRef

try:  # POSIX local/staging processes get cross-process journal exclusion.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX hosts.
    fcntl = None


LOCAL_JOURNAL_SCHEMA_VERSION = "1.0.0"


class CorrelationStorageError(RuntimeError):
    pass


class EvidenceIntegrityError(CorrelationStorageError):
    pass


class JournalCorruptionError(CorrelationStorageError):
    pass


class EventConflictError(CorrelationStorageError):
    pass


def _namespace(value: str, field_name: str) -> str:
    rendered = str(value or "").strip()
    if not rendered:
        raise ValueError(f"{field_name} must not be empty")
    # Do not place tenant or sensor-controlled text in filesystem paths.
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class LocalRawEvidenceStore:
    """Content-addressed, tenant-isolated raw byte storage.

    Files are created atomically and never overwritten. Reads always verify the
    expected length and SHA-256 so disk corruption or path substitution cannot
    silently enter replay.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _evidence_path(
        self,
        *,
        tenant_id: str,
        platform: Platform,
        source_instance_id: str,
        digest: str,
    ) -> Path:
        tenant_namespace = _namespace(tenant_id, "tenant_id")
        source_namespace = _namespace(source_instance_id, "source_instance_id")
        return (
            self.root
            / tenant_namespace
            / platform.value
            / source_namespace
            / digest[:2]
            / f"{digest}.raw"
        )

    def put(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        platform: Platform,
        source_instance_id: str,
        media_type: str,
        collected_at,
        content_encoding: str | None = None,
    ) -> RawEvidenceRef:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if not isinstance(platform, Platform):
            raise TypeError("platform must be a Platform")

        digest = hashlib.sha256(payload).hexdigest()
        destination = self._evidence_path(
            tenant_id=tenant_id,
            platform=platform,
            source_instance_id=source_instance_id,
            digest=digest,
        )
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        if not destination.exists():
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{digest}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb", closefd=True) as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                try:
                    # A hard link publishes the completed inode without ever
                    # replacing an existing immutable evidence object.
                    os.link(temporary, destination)
                    _fsync_directory(destination.parent)
                except FileExistsError:
                    pass
            finally:
                temporary.unlink(missing_ok=True)

        reference = RawEvidenceRef(
            sha256=digest,
            uri=destination.resolve().as_uri(),
            byte_length=len(payload),
            media_type=media_type,
            collected_at=collected_at,
            content_encoding=content_encoding,
        )
        # A concurrent writer may have won the destination race. Verify it was
        # the same content before acknowledging this write.
        self.get(reference)
        return reference

    def _path_from_reference(self, reference: RawEvidenceRef) -> Path:
        parsed = urlparse(reference.uri)
        if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
            raise EvidenceIntegrityError("local evidence reference must use file://")
        candidate = Path(unquote(parsed.path))
        if candidate.is_symlink():
            raise EvidenceIntegrityError("evidence reference must not be a symlink")
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise EvidenceIntegrityError("evidence object is missing") from exc
        if not resolved.is_relative_to(self.root):
            raise EvidenceIntegrityError("evidence reference escapes the configured root")
        mode = resolved.stat().st_mode
        if not stat.S_ISREG(mode):
            raise EvidenceIntegrityError("evidence reference is not a regular file")
        return resolved

    def get(self, reference: RawEvidenceRef) -> bytes:
        path = self._path_from_reference(reference)
        payload = path.read_bytes()
        if len(payload) != reference.byte_length:
            raise EvidenceIntegrityError("evidence byte length does not match reference")
        digest = hashlib.sha256(payload).hexdigest()
        if digest != reference.sha256:
            raise EvidenceIntegrityError("evidence SHA-256 does not match reference")
        return payload


class LocalEventJournal:
    """Append-only, idempotent JSONL journal for normalized events."""

    def __init__(self, path: str | Path, *, fsync_on_publish: bool = True):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock_path = self.path.with_suffix(f"{self.path.suffix}.lock")
        self.fsync_on_publish = fsync_on_publish
        self._thread_lock = threading.RLock()
        if self.path.exists() and self.path.is_symlink():
            raise JournalCorruptionError("journal path must not be a symlink")
        # Validate existing state eagerly so startup cannot hide corruption.
        self._load_records()

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self._thread_lock:
            with self.lock_path.open("a+b") as lock_handle:
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if fcntl is not None:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _record_bytes(event: NormalizedEvent) -> bytes:
        record = {
            "journal_schema_version": LOCAL_JOURNAL_SCHEMA_VERSION,
            "event": event.to_dict(),
        }
        return (
            json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _event_key(event: NormalizedEvent) -> tuple[str, str]:
        return event.tenant_id, event.event_id

    def _load_records(self) -> list[tuple[NormalizedEvent, bytes]]:
        if not self.path.exists():
            return []
        if self.path.is_symlink():
            raise JournalCorruptionError("journal path must not be a symlink")
        raw = self.path.read_bytes()
        lines = raw.splitlines(keepends=True)
        loaded: list[tuple[NormalizedEvent, bytes]] = []
        seen: dict[tuple[str, str], bytes] = {}
        for index, line in enumerate(lines):
            if not line.endswith(b"\n"):
                if index == len(lines) - 1:
                    # A process can die between opening an append and writing
                    # the complete record. The incomplete tail is not committed.
                    break
                raise JournalCorruptionError(
                    f"journal record {index + 1} is truncated"
                )
            try:
                decoded = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise JournalCorruptionError(
                    f"journal record {index + 1} is invalid JSON"
                ) from exc
            if decoded.get("journal_schema_version") != LOCAL_JOURNAL_SCHEMA_VERSION:
                raise JournalCorruptionError(
                    f"journal record {index + 1} has an unsupported schema"
                )
            event_value = decoded.get("event")
            if not isinstance(event_value, dict):
                raise JournalCorruptionError(
                    f"journal record {index + 1} has no event object"
                )
            try:
                event = NormalizedEvent.from_dict(event_value)
            except (TypeError, ValueError) as exc:
                raise JournalCorruptionError(
                    f"journal record {index + 1} contains an invalid event"
                ) from exc
            canonical = self._record_bytes(event)
            key = self._event_key(event)
            prior = seen.get(key)
            if prior is not None and prior != canonical:
                raise JournalCorruptionError(
                    "journal contains conflicting payloads for "
                    f"tenant/event {key[0]!r}/{key[1]!r}"
                )
            if prior is None:
                seen[key] = canonical
                loaded.append((event, canonical))
        return loaded

    def _discard_uncommitted_tail(self) -> None:
        """Remove only a crash-truncated final record before the next append."""

        if not self.path.exists():
            return
        if self.path.is_symlink():
            raise JournalCorruptionError("journal path must not be a symlink")
        raw = self.path.read_bytes()
        if not raw or raw.endswith(b"\n"):
            return
        committed_length = raw.rfind(b"\n") + 1
        descriptor = os.open(self.path, os.O_WRONLY)
        try:
            os.ftruncate(descriptor, committed_length)
            if self.fsync_on_publish:
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if self.fsync_on_publish:
            _fsync_directory(self.path.parent)

    def publish(self, event: NormalizedEvent) -> None:
        if not isinstance(event, NormalizedEvent):
            raise TypeError("event must be a NormalizedEvent")
        record = self._record_bytes(event)
        key = self._event_key(event)

        with self._exclusive_lock():
            self._discard_uncommitted_tail()
            records = self._load_records()
            existing = {self._event_key(item): raw for item, raw in records}
            if key in existing:
                if existing[key] == record:
                    return
                raise EventConflictError(
                    "event_id already exists with different content for tenant "
                    f"{event.tenant_id!r}: {event.event_id!r}"
                )

            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                view = memoryview(record)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise CorrelationStorageError("journal append made no progress")
                    view = view[written:]
                if self.fsync_on_publish:
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if self.fsync_on_publish:
                _fsync_directory(self.path.parent)

    def events(self) -> Iterable[NormalizedEvent]:
        with self._exclusive_lock():
            snapshot = tuple(event for event, _ in self._load_records())
        return iter(snapshot)
