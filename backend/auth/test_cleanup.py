"""Tests for expired-session housekeeping.

The properties that matter are not "it deletes rows" but the ones that keep it
safe to run unattended: it must never remove a LIVE session, and a failure must
never take the API down.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from auth import cleanup, service  # noqa: E402
from auth.models import Base, Session as SessionRow  # noqa: E402

# A dedicated engine, never the application's - the same isolation reason as
# test_auth.py: auth.models is usually imported before this file runs, so an
# env var would arrive too late and these tests would delete real sessions.
_TMP_DB = Path(tempfile.gettempdir()) / "ti_auth_cleanup_test.db"
_TMP_DB.unlink(missing_ok=True)
_engine = create_engine(f"sqlite:///{_TMP_DB}", connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)

GOOD_PASSWORD = "correct-horse-battery"


class SessionCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(_engine)

    def setUp(self) -> None:
        self.db = TestSessionLocal()
        self.user = service.create_user(
            self.db, f"cleanup-{uuid.uuid4().hex[:12]}@example.com", GOOD_PASSWORD
        )

    def tearDown(self) -> None:
        self.db.close()

    def _expire(self, token: str) -> None:
        row = (
            self.db.query(SessionRow)
            .filter(SessionRow.token_hash == service.hash_token(token))
            .one()
        )
        row.expires_at = service.utcnow() - dt.timedelta(minutes=1)
        self.db.commit()

    def test_expired_rows_are_removed(self):
        token, _ = service.issue_session(self.db, self.user)
        self._expire(token)
        self.assertEqual(service.purge_expired_sessions(self.db), 1)
        self.assertEqual(self.db.query(SessionRow).count(), 0)

    def test_live_sessions_are_never_removed(self):
        """The one thing a sweep must not do is log people out."""
        live_token, _ = service.issue_session(self.db, self.user)
        dead_token, _ = service.issue_session(self.db, self.user)
        self._expire(dead_token)

        removed = service.purge_expired_sessions(self.db)

        self.assertEqual(removed, 1)
        self.assertIsNotNone(service.resolve_session(self.db, live_token))
        self.assertIsNone(service.resolve_session(self.db, dead_token))

    def test_sweep_is_idempotent(self):
        token, _ = service.issue_session(self.db, self.user)
        self._expire(token)
        service.purge_expired_sessions(self.db)
        self.assertEqual(service.purge_expired_sessions(self.db), 0)

    def test_sweep_on_empty_table_is_safe(self):
        self.db.query(SessionRow).delete()
        self.db.commit()
        self.assertEqual(service.purge_expired_sessions(self.db), 0)


class SweepLoopTests(unittest.IsolatedAsyncioTestCase):
    """The loop is driven deterministically: `sleep` yields once, then raises
    CancelledError to end it. Letting a mocked sleep return instantly forever
    spins the event loop and starves everything else, which hangs the suite
    rather than testing it."""

    async def _run_one_iteration(self, sweep) -> None:
        async def immediate(func, *args, **kwargs):
            return func(*args, **kwargs)

        sleeps = mock.AsyncMock(side_effect=[None, asyncio.CancelledError()])
        with mock.patch.object(cleanup, "sweep_once", sweep), mock.patch.object(
            cleanup.asyncio, "to_thread", immediate
        ), mock.patch.object(cleanup.asyncio, "sleep", sleeps):
            with self.assertRaises(asyncio.CancelledError):
                await cleanup._sweep_loop(60)

    async def test_a_failing_sweep_does_not_kill_the_loop(self):
        """Housekeeping must never take the API down: the exception is
        swallowed and the loop reaches its next sleep."""
        calls: list[int] = []

        def failing() -> int:
            calls.append(1)
            raise RuntimeError("database temporarily unavailable")

        await self._run_one_iteration(failing)
        self.assertEqual(len(calls), 1)

    async def test_a_successful_sweep_runs(self):
        calls: list[int] = []

        def ok() -> int:
            calls.append(1)
            return 3

        await self._run_one_iteration(ok)
        self.assertEqual(len(calls), 1)

    async def test_stop_tolerates_no_task(self):
        await cleanup.stop_session_cleanup(None)

    async def test_disabled_enforcement_starts_no_task(self):
        """With sessions turned off there is nothing to reclaim.

        AuthSettings is frozen, so the whole object is swapped for a modified
        copy rather than mutating a field - which is the point of it being
        frozen in the first place.
        """
        disabled = dataclasses.replace(cleanup.SETTINGS, require_session=False)
        with mock.patch.object(cleanup, "SETTINGS", disabled):
            self.assertIsNone(cleanup.start_session_cleanup())


if __name__ == "__main__":
    unittest.main()
