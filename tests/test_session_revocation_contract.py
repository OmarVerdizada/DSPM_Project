"""M0/Q4: what a session token does today, written down before C1 and C8 change it.

Sign-in, sign-out and the idle timeout are the controls the security review is about
to touch, and most of their behaviour is decided in one function - verify_token. It
reads the database on every call, which is what makes a disabled account or a lowered
role take effect immediately, and that is the property a refactor is most likely to
optimise away by accident.

Tests marked GAP pin behaviour a C-item is meant to change. One failing is the signal
to rewrite it to the new behaviour in the commit that changes it, not a regression.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from backend import security, store

PASSWORD = "an-analyst-1"


class _SessionCase(unittest.TestCase):
    """One tenant, one active analyst, in a database of this test's own."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        self.original_db = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "sessions.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", self.original_db))
        store.init_db()

        self.tenant = "tenant-sessions"
        self.user = "analyst-one"
        store.create_tenant(self.tenant, "Sessions")
        store.create_user(self.user, security.hash_password(PASSWORD), "analyst", self.tenant)

        # Both caches are process-wide and would otherwise carry one test's answer
        # into the next (and into the rest of the suite).
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)

    def _token(self, subject: str | None = None, role: str = "analyst") -> str:
        return security.create_token(subject or self.user, role, self.tenant)

    def _jti(self, token: str) -> str:
        return json.loads(security._b64url_decode(token.split(".")[1]))["jti"]

    def assertRefused(self, token: str) -> None:
        with self.assertRaises(HTTPException) as refused:
            security.verify_token(token)
        self.assertEqual(refused.exception.status_code, 401)
        self.assertEqual(refused.exception.detail, "Invalid or expired token",
                         "the reason a token failed is not told to the caller")


class AValidSessionTest(_SessionCase):

    def test_a_fresh_token_resolves_to_the_account(self) -> None:
        principal = security.verify_token(self._token())
        self.assertEqual((principal.subject, principal.role, principal.tenant_id),
                         (self.user, "analyst", self.tenant))
        self.assertEqual(principal.auth_type, "jwt")

    def test_the_role_comes_from_the_database_not_the_token(self) -> None:
        # A token minted as admin cannot outlive the demotion of its account: the
        # row is authoritative on every request. C1 must keep this true.
        principal = security.verify_token(self._token(role="admin"))
        self.assertEqual(principal.role, "analyst")

    def test_the_tenant_comes_from_the_database_not_the_token(self) -> None:
        token = security.create_token(self.user, "analyst", "some-other-tenant")
        self.assertEqual(security.verify_token(token).tenant_id, self.tenant)

    def test_a_disabled_account_stops_working_immediately(self) -> None:
        token = self._token()
        security.verify_token(token)
        store.update_user_active(self.user, False)
        self.assertRefused(token)

    def test_an_account_that_no_longer_exists_is_refused(self) -> None:
        self.assertRefused(security.create_token("never-existed", "admin", self.tenant))


class ARefusedSessionTest(_SessionCase):

    def test_an_expired_token_is_refused(self) -> None:
        with mock.patch.object(security, "TOKEN_TTL_SECONDS", -10):
            token = self._token()
        self.assertRefused(token)

    def test_a_tampered_payload_is_refused(self) -> None:
        header, payload, signature = self._token().split(".")
        claims = json.loads(security._b64url_decode(payload))
        claims["role"] = "admin"
        forged = security._b64url(json.dumps(claims, separators=(",", ":")).encode())
        self.assertRefused(f"{header}.{forged}.{signature}")

    def test_structurally_broken_tokens_are_refused(self) -> None:
        for description, token in (
            ("empty", ""),
            ("one segment", "abc"),
            ("two segments", "abc.def"),
            ("four segments", "a.b.c.d"),
            ("unsigned", self._token().rsplit(".", 1)[0] + "."),
            ("not base64", "!!!.???.###"),
        ):
            with self.subTest(description):
                self.assertRefused(token)

    def test_a_token_with_no_session_id_is_refused(self) -> None:
        # Nothing can revoke a token that carries no jti, so is_token_revoked treats
        # an empty one as already revoked and the token never works.
        header = security._b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        payload = security._b64url(json.dumps(
            {"sub": self.user, "role": "analyst", "tenant": self.tenant, "exp": int(time.time()) + 600},
            separators=(",", ":")).encode())
        message = f"{header}.{payload}"
        self.assertRefused(f"{message}.{security._sign(message)}")
        self.assertTrue(store.is_token_revoked(""))


class SigningOutTest(_SessionCase):

    def test_revoking_a_token_stops_it_in_this_process_at_once(self) -> None:
        token = self._token()
        security.verify_token(token)          # the revocation cache now holds "not revoked"
        security.revoke_token(token)          # ... and the write has to clear it
        self.assertRefused(token)
        self.assertTrue(store.is_token_revoked(self._jti(token)))

    def test_revoking_one_session_leaves_the_others_alone(self) -> None:
        first, second = self._token(), self._token()
        security.revoke_token(first)
        self.assertRefused(first)
        self.assertEqual(security.verify_token(second).subject, self.user)

    def test_revoking_a_broken_token_is_a_no_op_rather_than_an_error(self) -> None:
        # Sign-out is called with whatever the browser had; it must not 500.
        for token in ("", "abc", "a.b", "a.b.c", "x." + security._b64url(b"not json") + ".y"):
            with self.subTest(token=token):
                self.assertIsNone(security.revoke_token(token))

    def test_a_revocation_outlives_the_token_it_revoked(self) -> None:
        token = self._token()
        security.revoke_token(token)
        store._forget_revocation()  # as if another process, or after the cache expired
        self.assertTrue(store.is_token_revoked(self._jti(token)))


class TheIdleTimeoutTest(_SessionCase):

    def test_a_session_left_untouched_too_long_is_revoked_not_merely_refused(self) -> None:
        token = self._token()
        jti = self._jti(token)
        with mock.patch.object(security, "SESSION_IDLE_SECONDS", 60):
            security.verify_token(token)
            # C1: the durable row is the authority a process reads on first sight,
            # so ageing it is how a session goes idle - not editing a dictionary.
            store.touch_session(jti, int(time.time() - 120))
            security._session_last_seen.pop(jti, None)
            self.assertRefused(token)
            # The decision is written to the database, so it holds for every worker
            # and survives a restart - not just for the process that noticed.
            self.assertTrue(store.is_token_revoked(jti))
            security._session_last_seen.clear()
            self.assertRefused(token)

    def test_a_session_this_process_has_never_seen_is_admitted_once(self) -> None:
        # What keeps tokens issued before a restart working.
        token = self._token()
        with mock.patch.object(security, "SESSION_IDLE_SECONDS", 60):
            security._session_last_seen.clear()
            self.assertEqual(security.verify_token(token).subject, self.user)

    def test_the_timeout_can_be_turned_off(self) -> None:
        token = self._token()
        jti = self._jti(token)
        with mock.patch.object(security, "SESSION_IDLE_SECONDS", 0):
            store.touch_session(jti, int(time.time() - 100_000))
            security._session_last_seen.pop(jti, None)
            self.assertEqual(security.verify_token(token).subject, self.user)
        self.assertFalse(store.is_token_revoked(jti))


class SigningInTest(_SessionCase):

    def test_the_right_password_returns_the_account(self) -> None:
        principal = security.authenticate_user(self.user, PASSWORD)
        self.assertEqual((principal.subject, principal.role, principal.tenant_id),
                         (self.user, "analyst", self.tenant))

    def test_a_successful_sign_in_is_recorded(self) -> None:
        self.assertIsNone(store.get_user(self.user)["last_login_at"])
        security.authenticate_user(self.user, PASSWORD)
        self.assertIsNotNone(store.get_user(self.user)["last_login_at"])

    def test_the_wrong_password_returns_nothing(self) -> None:
        self.assertIsNone(security.authenticate_user(self.user, PASSWORD.upper()))
        self.assertIsNone(security.authenticate_user(self.user, PASSWORD + "x"))
        self.assertIsNone(security.authenticate_user(self.user, ""))

    def test_an_unknown_account_returns_nothing(self) -> None:
        self.assertIsNone(security.authenticate_user("no-such-user", PASSWORD))

    def test_a_disabled_account_cannot_sign_in(self) -> None:
        store.update_user_active(self.user, False)
        self.assertIsNone(security.authenticate_user(self.user, PASSWORD))

    def test_signing_in_does_not_say_which_half_was_wrong(self) -> None:
        # Both return None rather than distinguishing "no such user" from "bad
        # password", which is what stops the form enumerating accounts.
        self.assertIsNone(security.authenticate_user("no-such-user", PASSWORD))
        self.assertIsNone(security.authenticate_user(self.user, "wrong-one-1"))


if __name__ == "__main__":
    unittest.main()
