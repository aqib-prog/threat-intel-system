"""Background removal of expired session rows.

An expired session is already unusable - ``resolve_session`` rejects it and
deletes it on sight. This exists purely so the table does not grow without
bound: every login writes a row, and without a sweep nothing ever reclaims the
dead ones. Left alone, lookups slow down and backups fill with rows that can
never authenticate anyone.

Runs inside the application process rather than as a system crontab. It needs
no host configuration, behaves identically in development and in a container,
and already has a database handle. A real scheduler becomes worthwhile once
several replicas run at once, at which point this should be replaced rather
than duplicated - see the note on leader election below.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from auth.models import SessionLocal
from auth.service import purge_expired_sessions
from auth.settings import SETTINGS


logger = logging.getLogger(__name__)


def sweep_once() -> int:
    """Delete every expired session. Returns how many rows were removed.

    Synchronous and self-contained so it can also be invoked from a management
    command or a test without an event loop.
    """
    db = SessionLocal()
    try:
        return purge_expired_sessions(db)
    finally:
        db.close()


async def _sweep_loop(interval_seconds: int) -> None:
    while True:
        # Wait FIRST. Startup is the busiest moment in the process's life, and
        # this is the least urgent thing it will ever do.
        await asyncio.sleep(interval_seconds)
        try:
            # Threadpool: the ORM call is blocking, and holding the event loop
            # during it would stall every in-flight request.
            removed = await asyncio.to_thread(sweep_once)
            if removed:
                logger.info("auth: purged %d expired session(s)", removed)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            # Housekeeping must never take the API down. A failed sweep is
            # logged and retried on the next tick; the sessions it did not
            # remove are still expired and still rejected at authentication.
            logger.exception("auth: expired-session sweep failed; will retry")


def start_session_cleanup() -> asyncio.Task | None:
    """Start the background sweep. Returns the task so it can be cancelled.

    Returns ``None`` when session enforcement is disabled, since there are then
    no sessions worth reclaiming.
    """
    if not SETTINGS.require_session:
        return None
    interval = max(60, SETTINGS.session_cleanup_interval_seconds)
    task = asyncio.create_task(_sweep_loop(interval), name="auth-session-cleanup")
    logger.info("auth: expired-session sweep every %ds", interval)
    return task


async def stop_session_cleanup(task: asyncio.Task | None) -> None:
    """Cancel the sweep and wait for it to unwind.

    Without the await, shutdown can race the task mid-query and surface as a
    spurious error in the logs of an otherwise clean stop.
    """
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":  # Manual/cron entry point: python -m auth.cleanup
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    print(f"purged {sweep_once()} expired session(s)")
