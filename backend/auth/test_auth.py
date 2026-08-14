"""Security tests for per-user authentication.

These assert the properties that matter if this is ever exposed to the internet,
not just the happy path. Each test names the attack it prevents.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from auth import service  # noqa: E402
from auth.models import Base  # noqa: E402

# A dedicated engine, NOT the application's.
#
# Setting AUTH_DATABASE_URL here is not enough: when the whole backend suite
# runs, `auth.models` has usually been imported already (api.app pulls it in),
# so its engine is bound before this file executes and the tests would write to
# the REAL credential store - colliding with actual accounts. Every test below
# takes its session from this factory instead, and the service layer accepts the
# session as an argument, so isolation is total regardless of import order.
_TMP_DB = Path(tempfile.gettempdir()) / "ti_auth_test.db"
_TMP_DB.unlink(missing_ok=True)
_engine = create_engine(f"sqlite:///{_TMP_DB}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(_engine)

GOOD_PASSWORD = "correct-horse-battery"


class CredentialStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        init_db()

    def setUp(self) -> None:
        self.db = SessionLocal()

    def tearDown(self) -> None:
        self.db.close()

    def _unique_email(self) -> str:
        # uuid, not the test name: a stale database file must never turn a
        # passing test red.
        return f"user-{uuid.uuid4().hex[:12]}@example.com"

    def test_password_is_never_stored_in_recoverable_form(self):
        user = service.create_user(self.db, self._unique_email(), GOOD_PASSWORD)
        self.assertNotIn(GOOD_PASSWORD, user.password_hash)
        self.assertTrue(user.password_hash.startswith("$argon2id$"))

    def test_email_is_normalized_so_one_account_cannot_be_registered_twice(self):
        email = self._unique_email()
        service.create_user(self.db, f"  {email.upper()} ", GOOD_PASSWORD)
        with self.assertRaises(service.AuthError):
            service.create_user(self.db, email, GOOD_PASSWORD)

    def test_login_is_case_insensitive_on_email(self):
        email = self._unique_email()
        service.create_user(self.db, email, GOOD_PASSWORD)
        user = service.authenticate(self.db, email.upper(), GOOD_PASSWORD)
        self.assertEqual(user.email, email)

    def test_short_password_is_rejected(self):
        with self.assertRaises(service.WeakPasswordError):
            service.create_user(self.db, self._unique_email(), "short")

    def test_absurdly_long_password_is_rejected(self):
        # Argon2 is memory-hard; unbounded input would be a denial-of-service lever.
        with self.assertRaises(service.WeakPasswordError):
            service.create_user(self.db, self._unique_email(), "x" * 5000)

    def test_wrong_password_and_unknown_email_are_indistinguishable(self):
        """Prevents user enumeration: an attacker must not be able to learn which
        addresses are registered by comparing error messages."""
        email = self._unique_email()
        service.create_user(self.db, email, GOOD_PASSWORD)

        with self.assertRaises(service.AuthError) as wrong_password:
            service.authenticate(self.db, email, "definitely-not-the-password")
        with self.assertRaises(service.AuthError) as unknown_email:
            service.authenticate(self.db, "ghost@example.com", GOOD_PASSWORD)

        self.assertEqual(str(wrong_password.exception), str(unknown_email.exception))

    def test_malformed_email_is_rejected(self):
        with self.assertRaises(service.AuthError):
            service.create_user(self.db, "not-an-email", GOOD_PASSWORD)


class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        init_db()

    def setUp(self) -> None:
        self.db = SessionLocal()
        self.user = service.create_user(
            self.db, f"session-{uuid.uuid4().hex[:12]}@example.com", GOOD_PASSWORD
        )

    def tearDown(self) -> None:
        self.db.close()

    def test_raw_token_is_not_stored(self):
        """A stolen database must not yield usable session cookies."""
        token, _ = service.issue_session(self.db, self.user)
        from auth.models import Session as SessionRow

        rows = self.db.query(SessionRow).all()
        self.assertTrue(all(row.token_hash != token for row in rows))

    def test_valid_token_resolves_to_its_user(self):
        token, _ = service.issue_session(self.db, self.user)
        self.assertEqual(service.resolve_session(self.db, token).id, self.user.id)

    def test_tampered_token_is_rejected(self):
        token, _ = service.issue_session(self.db, self.user)
        self.assertIsNone(service.resolve_session(self.db, token + "x"))

    def test_missing_token_is_rejected(self):
        self.assertIsNone(service.resolve_session(self.db, None))
        self.assertIsNone(service.resolve_session(self.db, ""))

    def test_revoked_session_stops_working_immediately(self):
        """The reason server-side sessions were chosen over a stateless JWT."""
        token, _ = service.issue_session(self.db, self.user)
        service.revoke_session(self.db, token)
        self.assertIsNone(service.resolve_session(self.db, token))

    def test_expired_session_is_rejected_and_cleaned_up(self):
        import datetime as dt

        from auth.models import Session as SessionRow

        token, _ = service.issue_session(self.db, self.user)
        row = (
            self.db.query(SessionRow)
            .filter(SessionRow.token_hash == service.hash_token(token))
            .one()
        )
        row.expires_at = service.utcnow() - dt.timedelta(seconds=1)
        self.db.commit()

        self.assertIsNone(service.resolve_session(self.db, token))
        self.assertEqual(
            self.db.query(SessionRow)
            .filter(SessionRow.token_hash == service.hash_token(token))
            .count(),
            0,
        )

    def test_each_login_issues_a_distinct_token(self):
        """Blocks session fixation: an attacker-supplied token is never adopted."""
        first, _ = service.issue_session(self.db, self.user)
        second, _ = service.issue_session(self.db, self.user)
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
