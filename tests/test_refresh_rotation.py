"""M2/C1: a bounded access token, and a refresh token that cannot be used twice.

An eight-hour access token is a bearer credential with an eight-hour blast radius:
whoever lifts it from a browser, a proxy log or a crash dump holds the account for the
rest of the working day, and only an explicit revocation shortens that. C1 bounds it to
half an hour and carries the session on a refresh token instead.

That only helps if the refresh token is single use, because a long-lived refresh token
is the same problem wearing a different name. So each exchange retires the token
presented and issues the next one in the same **family**. Presenting a retired token
means two parties hold the chain - the one that rotated it and one replaying a copy -
and since there is no way to tell which is which, the family ends. Both sign in again;
neither keeps a working session.

The gate for this half of C1 is "refresh replay fails", and that is the test below that
matters most. The rest hold the properties around it: the cookie is out of reach of
scripts, a demotion is seen on the next refresh rather than at the end of the chain,
and signing out or changing a password ends the chain rather than leaving it minting
access tokens.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import security, store
from backend.app import app

PASSWORD = "an-analyst-1"
TENANT = "tenant-refresh"
USER = "analyst-one"
ROOT = Path(__file__).resolve().parent.parent
SMOKE = ROOT / "tests" / "js" / "refresh_retry_smoke.js"
NODE = shutil.which("node")


class _RefreshCase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "refresh.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant(TENANT, "Refresh")
        store.create_user(USER, security.hash_password(PASSWORD), "analyst", TENANT)

        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)

        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def _login(self) -> dict:
        response = self.client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn(security.REFRESH_COOKIE, response.cookies, "login must hand back a refresh cookie")
        return response.json()

    def _jti(self, token: str) -> str:
        return json.loads(security._b64url_decode(token.split(".")[1]))["jti"]


class TheAccessTokenIsBoundedTest(_RefreshCase):

    def test_half_an_hour_by_default(self) -> None:
        self.assertEqual(security.TOKEN_TTL_SECONDS, 1800)
        self.assertEqual(self._login()["expires_in"], 1800)

    def test_the_session_still_lasts_the_working_day(self) -> None:
        # The eight hours moved from the access token to the refresh token; the session
        # did not get shorter, its bearer credential did.
        self.assertEqual(security.REFRESH_TTL_SECONDS, 28800)

    def test_the_token_itself_expires_at_the_bounded_time(self) -> None:
        claims = json.loads(security._b64url_decode(self._login()["access_token"].split(".")[1]))
        self.assertLessEqual(claims["exp"] - claims["iat"], 1800)


class TheRefreshCookieTest(_RefreshCase):

    def test_it_is_out_of_reach_of_any_script_on_the_page(self) -> None:
        response = self.client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
        header = response.headers["set-cookie"]
        self.assertIn("httponly", header.lower(), "an XSS must not be able to read the session")
        self.assertIn("samesite=strict", header.lower())
        self.assertIn("path=/api/auth", header.lower(),
                      "it should not ride along on every API call the console makes")

    def test_it_is_marked_secure_in_production(self) -> None:
        with mock.patch("backend.app.IS_PRODUCTION", True):
            response = self.client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
        self.assertIn("secure", response.headers["set-cookie"].lower())

    def test_it_is_not_marked_secure_on_a_plain_http_console(self) -> None:
        # A Secure cookie on http://localhost is simply never sent back, and refresh
        # would silently never work on a development install.
        with mock.patch("backend.app.IS_PRODUCTION", False):
            response = self.client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
        self.assertNotIn("secure", response.headers["set-cookie"].lower())

    def test_only_the_hash_is_stored(self) -> None:
        self._login()
        secret = self.client.cookies.get(security.REFRESH_COOKIE)
        self.assertTrue(secret)
        with store._connect() as conn:
            rows = [dict(row) for row in conn.execute("SELECT * FROM refresh_tokens").fetchall()]
        self.assertTrue(rows)
        self.assertNotIn(secret, json.dumps(rows), "a copy of the table must not be a set of sessions")


class RotationTest(_RefreshCase):

    def test_refreshing_returns_a_new_access_token_and_a_new_cookie(self) -> None:
        first = self._login()
        before = self.client.cookies.get(security.REFRESH_COOKIE)

        response = self.client.post("/api/auth/refresh")

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertNotEqual(body["access_token"], first["access_token"])
        self.assertEqual(body["role"], "analyst")
        self.assertEqual(body["tenant_id"], TENANT)
        self.assertNotEqual(self.client.cookies.get(security.REFRESH_COOKIE), before,
                            "the refresh token must rotate, not be reused")

    def test_the_new_access_token_works_and_the_old_one_does_not(self) -> None:
        first = self._login()
        second = self.client.post("/api/auth/refresh").json()

        self.assertEqual(self.client.get(
            "/api/profile", headers={"Authorization": f"Bearer {second['access_token']}"}).status_code, 200)
        self.assertEqual(self.client.get(
            "/api/profile", headers={"Authorization": f"Bearer {first['access_token']}"}).status_code, 401,
            "the access token a refresh replaces is revoked, not left running")

    def test_a_chain_of_refreshes_keeps_working(self) -> None:
        self._login()
        for round_number in range(4):
            with self.subTest(round=round_number):
                response = self.client.post("/api/auth/refresh")
                self.assertEqual(response.status_code, 200)
                token = response.json()["access_token"]
                self.assertEqual(self.client.get(
                    "/api/profile", headers={"Authorization": f"Bearer {token}"}).status_code, 200)

    def test_a_role_change_is_seen_on_the_next_refresh(self) -> None:
        self._login()
        store.update_user_role(USER, "viewer")
        body = self.client.post("/api/auth/refresh").json()
        self.assertEqual(body["role"], "viewer", "a demotion must not wait for the chain to end")

    def test_a_disabled_account_cannot_refresh(self) -> None:
        self._login()
        store.update_user_active(USER, False)
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)
        self.assertEqual(store.count_refresh_tokens_for_user(USER), 0, "and its chain is ended")


class ReplayEndsTheFamilyTest(_RefreshCase):
    """The gate: refresh replay fails."""

    def test_presenting_a_retired_token_twice_ends_the_whole_family(self) -> None:
        self._login()
        stolen = self.client.cookies.get(security.REFRESH_COOKIE)

        # The legitimate console rotates...
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 200)
        live = self.client.cookies.get(security.REFRESH_COOKIE)

        # ... and then the copy is presented.
        replay = self.client.post("/api/auth/refresh", cookies={security.REFRESH_COOKIE: stolen})

        self.assertEqual(replay.status_code, 401)
        self.assertEqual(store.count_refresh_tokens_for_user(USER), 0,
                         "a replay ends the family, not only the token replayed")
        # Including the honest holder: there is no way to tell which one was the thief.
        self.assertEqual(
            self.client.post("/api/auth/refresh", cookies={security.REFRESH_COOKIE: live}).status_code, 401)

    def test_the_access_sessions_of_that_family_are_revoked_too(self) -> None:
        first = self._login()
        stolen = self.client.cookies.get(security.REFRESH_COOKIE)
        second = self.client.post("/api/auth/refresh").json()

        self.client.post("/api/auth/refresh", cookies={security.REFRESH_COOKIE: stolen})

        security._session_last_seen.clear()
        store._forget_revocation()
        for label, token in (("first", first["access_token"]), ("second", second["access_token"])):
            with self.subTest(label):
                self.assertEqual(self.client.get(
                    "/api/profile", headers={"Authorization": f"Bearer {token}"}).status_code, 401)

    def test_a_replay_is_recorded(self) -> None:
        self._login()
        stolen = self.client.cookies.get(security.REFRESH_COOKIE)
        self.client.post("/api/auth/refresh")
        self.client.post("/api/auth/refresh", cookies={security.REFRESH_COOKIE: stolen})
        actions = [event["action"] for event in store.read_audit_log("default", 50)]
        self.assertIn("auth.refresh_replayed", actions)

    def test_every_failure_says_the_same_thing(self) -> None:
        # Unknown, expired and replayed must not be distinguishable to the caller.
        self._login()
        stolen = self.client.cookies.get(security.REFRESH_COOKIE)
        self.client.post("/api/auth/refresh")
        replayed = self.client.post("/api/auth/refresh", cookies={security.REFRESH_COOKIE: stolen})
        unknown = self.client.post("/api/auth/refresh", cookies={security.REFRESH_COOKIE: "not-a-token"})
        missing = self.client.post("/api/auth/refresh", cookies={})
        bodies = {replayed.text, unknown.text, missing.text}
        self.assertEqual(len(bodies), 1, f"the failures differ: {bodies}")
        self.assertEqual({replayed.status_code, unknown.status_code, missing.status_code}, {401})

    def test_a_failed_refresh_clears_the_cookie(self) -> None:
        self._login()
        self.client.post("/api/auth/refresh", cookies={security.REFRESH_COOKIE: "not-a-token"})
        header = self.client.post(
            "/api/auth/refresh", cookies={security.REFRESH_COOKIE: "not-a-token"}
        ).headers.get("set-cookie", "")
        self.assertIn(security.REFRESH_COOKIE, header)
        self.assertTrue("max-age=0" in header.lower() or "expires=" in header.lower())

    def test_an_expired_refresh_token_is_refused(self) -> None:
        with mock.patch.object(security, "REFRESH_TTL_SECONDS", -10):
            self._login()
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)


class EndingASessionEndsTheChainTest(_RefreshCase):

    def test_signing_out_stops_the_cookie_minting_tokens(self) -> None:
        body = self._login()
        headers = {"Authorization": f"Bearer {body['access_token']}"}
        self.assertEqual(self.client.post("/api/auth/logout", headers=headers).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)
        self.assertEqual(store.count_refresh_tokens_for_user(USER), 0)

    def test_a_password_change_stops_it_too(self) -> None:
        body = self._login()
        headers = {"Authorization": f"Bearer {body['access_token']}"}
        response = self.client.post(
            "/api/auth/change-password",
            json={"current_password": PASSWORD, "new_password": "a-new-kestrel-2"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(store.count_refresh_tokens_for_user(USER), 0,
                         "ending the access sessions alone would leave a token that mints new ones")
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)

    def test_an_admin_reset_stops_it_too(self) -> None:
        store.create_user("admin-two", security.hash_password("an-admin-kestrel-1"), "admin", TENANT)
        victim = self._login()
        admin_headers = {"Authorization": f"Bearer {security.create_token('admin-two', 'admin', TENANT)}"}

        self.client.post(f"/api/users/{USER}/reset-password",
                         json={"password": "reset-by-admin-1"}, headers=admin_headers)

        self.assertEqual(store.count_refresh_tokens_for_user(USER), 0)
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)
        self.assertEqual(self.client.get(
            "/api/profile", headers={"Authorization": f"Bearer {victim['access_token']}"}).status_code, 401)


class TheConsoleRetriesOnceTest(unittest.TestCase):
    """The console's half, driven rather than grepped.

    Without it a bounded access token signs an operator out every half hour, which is
    how a security control gets turned off again. The real frontend/app.js runs in Node
    against a stubbed server (tests/js/refresh_retry_smoke.js): the access token is
    stale, so the first call of each panel is rejected exactly as an expired one would
    be.
    """

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def _drive(self, **scenario) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "scenario.json"
            fixture.write_text(json.dumps(scenario), encoding="utf-8")
            result = subprocess.run(
                [NODE, str(SMOKE), str(fixture)],
                cwd=ROOT, capture_output=True, text=True, timeout=180, check=False,
            )
        self.assertTrue(result.stdout.strip(), f"the smoke printed nothing: {result.stderr[-400:]}")
        report = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertIsNone(report.get("error"), report.get("error"))
        return report

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_rejected_call_is_refreshed_and_retried(self) -> None:
        report = self._drive(calls=1, refreshSucceeds=True)
        self.assertEqual(report["refreshCalls"], 1)
        self.assertEqual(report["resolved"], 1, "the caller should never see the expiry")
        self.assertEqual(report["rejected"], 0)

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_concurrent_rejections_share_one_refresh(self) -> None:
        """The failure this prevents: five panels each exchanging the cookie, the second
        presenting a token the first retired, and the server ending the family for a
        replay that was the console's own doing."""
        report = self._drive(calls=5, refreshSucceeds=True)
        self.assertEqual(report["refreshCalls"], 1, "one exchange for five rejections")
        self.assertEqual(report["resolved"], 5)
        self.assertEqual(report["rejected"], 0)

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_failed_refresh_ends_the_session_rather_than_looping(self) -> None:
        report = self._drive(calls=3, refreshSucceeds=False)
        self.assertEqual(report["refreshCalls"], 1)
        self.assertEqual(report["resolved"], 0)
        self.assertEqual(report["rejected"], 3)
        self.assertGreaterEqual(report["redirected"], 1, "the operator is sent to sign in")

    def test_the_retry_keeps_the_method(self) -> None:
        # api(path, payload, method, options): passing options where method goes turns
        # every retried GET into a POST, which fails as 405 rather than as a retry.
        app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn("api(path, payload, method, { ...options, isRetry: true })", app_js)

    def test_the_login_page_keeps_the_cookie(self) -> None:
        login_js = (ROOT / "frontend" / "login.js").read_text(encoding="utf-8")
        self.assertIn('credentials: "same-origin"', login_js)

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_signing_out_with_a_lapsed_access_token_still_ends_the_chain(self) -> None:
        """Sign-out is what ends the refresh chain on the server. Sent with an access
        token that has lapsed - half an hour after the last call - it was refused, the
        page cleared itself anyway, and the cookie stayed in the browser minting
        sessions for whoever used it next."""
        report = self._drive(drive="logout", refreshSucceeds=True)
        self.assertEqual(report["refreshCalls"], 1, "renew once")
        self.assertEqual(report["logoutCalls"], 2, "then send the sign-out again")
        self.assertEqual(report["logoutAccepted"], 1, "and the server accepted it")
        self.assertEqual(report["resolved"], 1)

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_signing_out_when_the_session_is_already_gone_still_signs_out(self) -> None:
        report = self._drive(drive="logout", refreshSucceeds=False)
        self.assertEqual(report["logoutCalls"], 1, "nothing to renew, so nothing to resend")
        self.assertEqual(report["logoutAccepted"], 0)
        self.assertEqual(report["resolved"], 1, "the page still signs itself out")


class TheSettingsPageRenewsTooTest(unittest.TestCase):
    """The settings page (profile.js) has its own api(). Until this it did not renew:
    half an hour after sign-in every panel on it failed, and its sign-out had the same
    lapsed-token gap as the console's."""

    _drive = TheConsoleRetriesOnceTest._drive

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_rejected_call_is_refreshed_and_retried(self) -> None:
        report = self._drive(script="profile.js", calls=3, refreshSucceeds=True)
        self.assertEqual(report["refreshCalls"], 1, "one exchange for three rejections")
        self.assertEqual(report["resolved"], 3)
        self.assertEqual(report["rejected"], 0)

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_failed_refresh_is_reported_not_looped(self) -> None:
        report = self._drive(script="profile.js", calls=2, refreshSucceeds=False)
        self.assertEqual(report["refreshCalls"], 1)
        self.assertEqual(report["rejected"], 2)

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_signing_out_with_a_lapsed_access_token_still_ends_the_chain(self) -> None:
        report = self._drive(script="profile.js", drive="logout", refreshSucceeds=True)
        self.assertEqual(report["logoutAccepted"], 1)
        self.assertGreaterEqual(report["redirected"], 1, "and the page goes to sign-in")

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_changed_password_sends_the_operator_to_sign_in(self) -> None:
        """The server ends every session on a password change, this one included. The
        page used to say "Password changed." and stay, on a session that no longer
        worked - under a heading promising "You stay signed in on this device"."""
        report = self._drive(script="profile.js", drive="password_changed", refreshSucceeds=True)
        self.assertEqual(report["tokenLeft"], "", "the dead token is not kept")
        self.assertGreaterEqual(report["redirected"], 1)

    def test_the_page_no_longer_promises_the_session_survives(self) -> None:
        html = (ROOT / "frontend" / "profile.html").read_text(encoding="utf-8")
        self.assertNotIn("You stay signed in", html)


class TheUpgradeCarriesExistingSessionsTest(_RefreshCase):

    def test_a_token_issued_before_this_release_still_works_until_it_expires(self) -> None:
        # No refresh cookie exists for it; it simply runs out its own life, and the
        # console sends the operator to sign in once.
        legacy = security.create_token(USER, "analyst", TENANT)
        self.assertEqual(self.client.get(
            "/api/profile", headers={"Authorization": f"Bearer {legacy}"}).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)

    def test_revision_0019_creates_the_table_on_an_older_install(self) -> None:
        from backend import migrations

        # setUp builds the database with init_db (the convergent baseline), so the
        # revision history does not exist yet; the runner creates it.
        migrations.upgrade()
        with store._connect() as conn:
            conn.execute("DROP TABLE IF EXISTS refresh_tokens")
            conn.execute("DELETE FROM schema_migrations WHERE revision >= 19")
        migrations.upgrade()
        with store._connect() as conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(refresh_tokens)")}
        self.assertEqual(columns, {"token_hash", "family_id", "username", "session_jti",
                                   "issued_at", "expires_at", "used_at"})
        self.assertEqual(migrations.expected_revision(), 19)


if __name__ == "__main__":
    unittest.main()
