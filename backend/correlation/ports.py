"""Infrastructure-neutral ports for correlation ingestion and replay.

Implementations may use local files during development or distributed
services in staging/production.  Domain code depends only on these contracts.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Iterable, Protocol

from correlation.incidents import IncidentRevision, IncidentSnapshot
from correlation.models import NormalizedEvent, Platform, RawEvidenceRef

if TYPE_CHECKING:
    from correlation.replay import CorrelationReplayReport, CorrelationReplayResult


class RawEvidenceStore(Protocol):
    """Durably store sensor bytes before any parser is allowed to run."""

    def put(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        platform: Platform,
        source_instance_id: str,
        media_type: str,
        collected_at: datetime,
        content_encoding: str | None = None,
    ) -> RawEvidenceRef: ...

    def get(self, reference: RawEvidenceRef) -> bytes: ...


class EventPublisher(Protocol):
    """Publish normalized envelopes with at-least-once-safe event IDs."""

    def publish(self, event: NormalizedEvent) -> None: ...


class EventReplaySource(Protocol):
    """Read the same envelopes used by live processing, in replay batches."""

    def events(self) -> Iterable[NormalizedEvent]: ...


class IncidentHistoryStore(Protocol):
    """Persist immutable incident snapshots and append-only revisions."""

    @property
    def current_snapshot(self) -> IncidentSnapshot | None: ...

    @property
    def revisions(self) -> tuple[IncidentRevision, ...]: ...

    def get_snapshot(self, snapshot_id: str) -> IncidentSnapshot: ...

    def append(self, snapshot: IncidentSnapshot) -> IncidentRevision | None: ...

    def rollback(self, snapshot_id: str) -> IncidentRevision | None: ...


class ReplayArchive(Protocol):
    """Persist a replay summary and complete shadow-review artifacts."""

    def put(self, result: CorrelationReplayResult) -> str: ...

    def get_report(self, report_id: str) -> CorrelationReplayReport: ...

    def review_records(
        self,
        report_id: str,
        artifact_name: str,
    ) -> tuple[dict, ...]: ...
