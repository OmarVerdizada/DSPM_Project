"""M2/C1: a session is a row, and a password change ends every one of them.

Three of C1's parts, and the three that need no change to how a token is carried:

* **Durable idle state.** The idle timeout lived in a per-process dictionary. A restart
  therefore admitted every abandoned session once more, and with several workers each
  knew only what it had seen itself. `user_sessions` is now the authority the first time
  any process sees a session.
* **Revoke on password change.** Changing a password after a compromise is only worth
  doing if whoever had the old one is signed out. Nothing did that: the old token kept
  working for the rest of its eight hours.
* **Login timing.** An unknown account returned before any hashing, so a sign-in attempt
  for a name that exists came back measurably later than one for a name that does not -
  an enumeration oracle that writes no audit entry and trips no throttle.

The per-account session cap is here too: it is what bounds the new table, and what stops
a stolen credential quietly accumulating sessions.

Q4's tests/test_session_revocation_contract.py still holds the contracts this must not
break; this file is about what C1 changed.
"""

from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from backend import db, security, store

PASSWORD = "an-analyst-1"


class _SessionCase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "sessions.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()

        self.tenant = "tenant-c1"
        self.user = "analyst-one"
        store.create_tenant(self.tenant, "C1")
        store.create_user(self.user, security.hash_password(PASSWORD), "analyst", self.tenant)

        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)

    def _token(self, subject: str | None = None) -> str:
        return security.create_token(subject or self.user, "analyst", self.tenant)

    def _jti(self, token: str) -> str:
        return json.loads(security._b64url_decode(token.split(".")[1]))["jti"]

    def _restart(self) -> None:
        """What a new process knows about sessions: nothing, except the rows."""
        security._session_last_seen.clear()
        store._forget_revocation()


class ASessionOutlivesTheProcessTest(_SessionCase):

    def test_issuing_a_token_records_the_session(self) -> None:
        token = self._token()
        self.assertEqual(store.count_sessions_for_user(self.user), 1)
        self.assertIsNotNone(store.session_last_seen(self._jti(token)))

    def test_an_idle_session_is_refused_after_a_restart(self) -> None:
        """The defect this fixes: the process that was watching forgot, so the session
        was admitted again - a laptop left open overnight signed back in by a deploy."""
        token = self._token()
        jti = self._jti(token)
        with mock.patch.object(security, "SESSION_IDLE_SECONDS", 60):
            security.verify_token(token)
            store.touch_session(jti, int(time.time()) - 600)
            self._restart()
            with self.assertRaises(HTTPException):
                security.verify_token(token)
        self.assertTrue(store.is_token_revoked(jti), "the decision must outlive the process")

    def test_an_active_session_survives_a_restart(self) -> None:
        token = self._token()
        with mock.patch.object(security, "SESSION_IDLE_SECONDS", 3600):
            security.verify_token(token)
            self._restart()
            self.assertEqual(security.verify_token(token).subject, self.user)

    def test_a_session_from_before_this_release_still_works(self) -> None:
        """Migrating active sessions deliberately: a token issued by the previous
        version has no row, and must be admitted and recorded rather than refused."""
        token = self._token()
        jti = self._jti(token)
        store.forget_session(jti)          # as if it had been issued before the upgrade
        self._restart()
        with mock.patch.object(security, "SESSION_IDLE_SECONDS", 3600):
            self.assertEqual(security.verify_token(token).subject, self.user)

    def test_the_hot_path_does_not_write_on_every_request(self) -> None:
        """The reason last-seen was in memory at all. Correctness here does not need a
        write per request, and the authenticated path must not pay for one."""
        token = self._token()
        with mock.patch.object(security, "SESSION_IDLE_SECONDS", 3600), \
             mock.patch.object(security, "touch_session", wraps=store.touch_session) as touched:
            for _ in range(20):
                security.verify_token(token)
        self.assertEqual(touched.call_count, 1, "one write, not twenty")
        # security imports touch_session by name, so this patches where it is USED;
        # patching backend.store.touch_session leaves the reference security holds
        # untouched and the assertion passes for the wrong reason.

    def test_the_throttle_can_never_outrun_a_short_idle_window(self) -> None:
        # A 60-second write interval with a 60-second idle timeout would let a session
        # look fresh for its whole window. The interval is capped at a quarter of it.
        for idle, expected_max in ((3600, 60.0), (120, 30.0), (40, 10.0)):
            with self.subTest(idle=idle), mock.patch.object(security, "SESSION_IDLE_SECONDS", idle):
                self.assertLessEqual(security._session_touch_interval(), expected_max)

    def test_signing_out_removes_the_session_row(self) -> None:
        token = self._token()
        security.revoke_token(token)
        self.assertEqual(store.count_sessions_for_user(self.user), 0)
        self.assertTrue(store.is_token_revoked(self._jti(token)))


class APasswordChangeEndsEverySessionTest(_SessionCase):

    def test_every_token_dies_not_just_the_one_in_hand(self) -> None:
        tokens = [self._token() for _ in range(3)]
        for token in tokens:
            security.verify_token(token)

        ended = store.revoke_sessions_for_user(self.user)

        self.assertEqual(ended, 3)
        self._restart()
        for index, token in enumerate(tokens):
            with self.subTest(token=index), self.assertRaises(HTTPException):
                security.verify_token(token)

    def test_it_reaches_sessions_this_process_never_saw(self) -> None:
        """The property a per-process map could not have: a token issued by another
        worker, never verified here, still ends."""
        token = self._token()
        self._restart()
        store.revoke_sessions_for_user(self.user)
        with self.assertRaises(HTTPException):
            security.verify_token(token)

    def test_another_account_is_untouched(self) -> None:
        store.create_user("other-one", security.hash_password(PASSWORD), "viewer", self.tenant)
        mine, theirs = self._token(), self._token("other-one")
        store.revoke_sessions_for_user(self.user)
        with self.assertRaises(HTTPException):
            security.verify_token(mine)
        self.assertEqual(security.verify_token(theirs).subject, "other-one")

    def test_an_account_with_no_sessions_is_not_an_error(self) -> None:
        self.assertEqual(store.revoke_sessions_for_user("never-signed-in"), 0)
        self.assertEqual(store.revoke_sessions_for_user(""), 0)

    def test_one_session_can_be_spared(self) -> None:
        # For the caller who is changing their own password in a flow that keeps them
        # signed in; the route does not use it today, and the test pins the option.
        keep, drop = self._token(), self._token()
        ended = store.revoke_sessions_for_user(self.user, keep_jti=self._jti(keep))
        self.assertEqual(ended, 1)
        self._restart()
        self.assertEqual(security.verify_token(keep).subject, self.user)
        with self.assertRaises(HTTPException):
            security.verify_token(drop)


class AnAccountIsCappedTest(_SessionCase):

    def test_the_oldest_sessions_are_revoked_past_the_cap(self) -> None:
        # Session times are whole seconds, so "oldest" needs sessions issued in different
        # seconds. This used to sleep 10 ms - the same second - and passed on SQLite only
        # because its ties happened to come back in insertion order (C0.5, PostgreSQL).
        start = time.time()
        with mock.patch.dict(os.environ, {"DSPM_MAX_SESSIONS_PER_USER": "3"}):
            tokens = []
            for step in range(5):
                with mock.patch("time.time", return_value=start + step):
                    tokens.append(self._token())
        self.assertEqual(store.count_sessions_for_user(self.user), 3)
        self._restart()
        # The two eldest are revoked, not merely forgotten: a token in someone's hand
        # has to stop working.
        for token in tokens[:2]:
            with self.subTest(token=token[:12]), self.assertRaises(HTTPException):
                security.verify_token(token)
        self.assertEqual(security.verify_token(tokens[-1]).subject, self.user)

    def test_the_session_just_issued_is_never_the_one_revoked(self) -> None:
        # Three sign-ins in one second tie on every timestamp. Whatever the cap evicts,
        # it must not be the session the caller has just been handed.
        start = time.time()
        with mock.patch.dict(os.environ, {"DSPM_MAX_SESSIONS_PER_USER": "1"}), \
                mock.patch("time.time", return_value=start):
            tokens = [self._token() for _ in range(3)]
        self.assertEqual(store.count_sessions_for_user(self.user), 1)
        self._restart()
        self.assertEqual(security.verify_token(tokens[-1]).subject, self.user)
        for token in tokens[:-1]:
            with self.subTest(token=token[:12]), self.assertRaises(HTTPException):
                security.verify_token(token)

    def test_the_cap_can_be_turned_off(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_MAX_SESSIONS_PER_USER": "0"}):
            for _ in range(6):
                self._token()
        self.assertEqual(store.count_sessions_for_user(self.user), 6)

    def test_expired_rows_do_not_accumulate(self) -> None:
        with mock.patch.object(security, "TOKEN_TTL_SECONDS", -10):
            self._token()
        self.assertEqual(store.count_sessions_for_user(self.user), 1, "written, then aged out")
        self._token()      # any later issue prunes what has expired
        self.assertEqual(store.count_sessions_for_user(self.user), 1)


class ThroughTheRoutesTest(_SessionCase):
    """What an operator actually does: change a password, or have one reset for them."""

    def setUp(self) -> None:
        super().setUp()
        from fastapi.testclient import TestClient

        from backend.app import app

        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        store.create_user("admin-two", security.hash_password("an-admin-kestrel-1"), "admin", self.tenant)

    def _auth(self, username: str) -> tuple[dict, str]:
        token = security.create_token(username, "admin", self.tenant)
        return {"Authorization": f"Bearer {token}"}, token

    def test_changing_my_password_signs_all_of_me_out(self) -> None:
        headers, _token = self._auth("admin-two")
        other = security.create_token("admin-two", "admin", self.tenant)
        self.assertEqual(self.client.get("/api/profile", headers=headers).status_code, 200)

        response = self.client.post(
            "/api/auth/change-password",
            json={"current_password": "an-admin-kestrel-1", "new_password": "a-new-kestrel-2"},
            headers=headers,
        )

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertGreaterEqual(body["sessions_ended"], 2)
        self.assertTrue(body["reauthenticate"], "the console has to know it must sign in again")
        self._restart()
        self.assertEqual(self.client.get("/api/profile", headers=headers).status_code, 401)
        self.assertTrue(store.is_token_revoked(self._jti(other)), "every session, not only this one")
        self.assertIsNotNone(security.authenticate_user("admin-two", "a-new-kestrel-2"))

    def test_a_wrong_current_password_changes_and_ends_nothing(self) -> None:
        headers, _ = self._auth("admin-two")
        response = self.client.post(
            "/api/auth/change-password",
            json={"current_password": "not-the-one-1", "new_password": "a-new-kestrel-2"},
            headers=headers,
        )
        # C8: 403, not 401 - the session is sound, the proof offered with it is not, and
        # a 401 is what the console reads as an expired token (tests/test_route_throttles.py).
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get("/api/profile", headers=headers).status_code, 200)
        self.assertIsNotNone(security.authenticate_user("admin-two", "an-admin-kestrel-1"))

    def test_an_admin_reset_ends_the_targets_sessions_and_not_their_own(self) -> None:
        headers, _admin_token = self._auth("admin-two")
        victim = self._token()          # the account being reset, signed in elsewhere
        security.verify_token(victim)

        response = self.client.post(
            f"/api/users/{self.user}/reset-password",
            json={"password": "reset-by-admin-1"},
            headers=headers,
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertGreaterEqual(response.json()["sessions_ended"], 1)
        self._restart()
        with self.assertRaises(HTTPException):
            security.verify_token(victim)
        self.assertEqual(self.client.get("/api/profile", headers=headers).status_code, 200,
                         "the administrator doing the reset stays signed in")
        self.assertIsNotNone(security.authenticate_user(self.user, "reset-by-admin-1"))

    def test_the_audit_says_how_many_sessions_ended(self) -> None:
        headers, _ = self._auth("admin-two")
        self.client.post(
            "/api/auth/change-password",
            json={"current_password": "an-admin-kestrel-1", "new_password": "a-new-kestrel-2"},
            headers=headers,
        )
        events = [e for e in store.read_audit_log(self.tenant, 50) if e["action"] == "user.password_changed"]
        self.assertTrue(events)
        self.assertIn("sessions_ended", json.dumps(events[0]))


@unittest.skipIf(db.is_postgres(), "builds an older SQLite file; the PostgreSQL upgrade path is scripted in C0.5")
class TheUpgradeReachesAnOlderInstallTest(unittest.TestCase):
    """Revision 0018 on a database that predates the table (roadmap C0.4 cares about
    this too: an upgrade that only works on a fresh database is not an upgrade)."""

    def test_the_table_is_created_and_the_revision_recorded(self) -> None:
        from backend import migrations

        with tempfile.TemporaryDirectory() as tmp:
            original = store.DB_PATH
            store.DB_PATH = Path(tmp) / "older.sqlite"
            try:
                migrations.upgrade()
                # Wind the install back to before C1: the table gone, the revision
                # unrecorded. This is the shape every existing install upgrades from.
                with store._connect() as conn:
                    conn.execute("DROP TABLE IF EXISTS user_sessions")
                    conn.execute("DELETE FROM schema_migrations WHERE revision >= 18")

                migrations.upgrade()

                with store._connect() as conn:
                    columns = {row["name"] for row in conn.execute("PRAGMA table_info(user_sessions)")}
                    recorded = conn.execute(
                        "SELECT COUNT(*) AS n FROM schema_migrations WHERE revision = 18"
                    ).fetchone()["n"]
                    # ... and the upgrade is idempotent, which is what a re-run after a
                    # failed deploy depends on.
                    store.create_user("after-upgrade", security.hash_password("a-pass-kestrel-1"), "viewer", "default")
                migrations.upgrade()
            finally:
                store.DB_PATH = original
        self.assertEqual(columns, {"jti", "username", "issued_at", "expires_at", "last_seen_at"})
        self.assertEqual(int(recorded), 1)
        self.assertGreaterEqual(migrations.expected_revision(), 18)


class SigningInTellsNothingApartTest(_SessionCase):

    def test_an_unknown_account_is_hashed_against_too(self) -> None:
        with mock.patch.object(security, "verify_password", wraps=security.verify_password) as verify:
            self.assertIsNone(security.authenticate_user("no-such-user", PASSWORD))
        self.assertEqual(verify.call_count, 1, "an unknown name must still cost a hash")

    def test_a_disabled_account_is_hashed_against_too(self) -> None:
        store.update_user_active(self.user, False)
        with mock.patch.object(security, "verify_password", wraps=security.verify_password) as verify:
            self.assertIsNone(security.authenticate_user(self.user, PASSWORD))
        self.assertEqual(verify.call_count, 1)

    def test_the_dummy_hash_is_this_installs_work_factor(self) -> None:
        # A cheaper dummy would leave the same oracle, just smaller.
        security._dummy_password_hash.cache_clear()
        self.addCleanup(security._dummy_password_hash.cache_clear)
        dummy = security._dummy_password_hash()
        self.assertTrue(dummy.startswith("pbkdf2_sha256$"))
        self.assertEqual(dummy.split("$")[1], security.hash_password("a-real-one-1").split("$")[1])
        self.assertFalse(security.verify_password("", dummy))

    def test_known_and_unknown_take_comparably_long(self) -> None:
        """Measured as a ratio of medians over several runs rather than a single
        threshold: a wall-clock assertion on a loaded machine is a flake generator
        (roadmap M0 polish), and what matters is that neither is an order of
        magnitude cheaper than the other."""
        security._dummy_password_hash()          # pay the one-off cost outside the loop

        def timed(username: str) -> float:
            started = time.perf_counter()
            security.authenticate_user(username, "wrong-password-1")
            return time.perf_counter() - started

        known = statistics.median(timed(self.user) for _ in range(5))
        unknown = statistics.median(timed("no-such-user") for _ in range(5))
        self.assertGreater(unknown, known / 4,
                           f"an unknown account is far cheaper than a known one: {unknown:.4f}s vs {known:.4f}s")
        self.assertLess(unknown, known * 4)


if __name__ == "__main__":
    unittest.main()
