"""M2/C8: the routes other than sign-in that answer a guess are throttled.

Sign-in has been throttled since M4. Three other routes check a secret and were not:

* **Change password** checks the current password, so an access token lifted from a
  browser was an unlimited oracle for the password behind it. Counted per ACCOUNT -
  the attacker holds the account's token, so the address tells nothing - and a
  correct password clears it.
* **Register** checks an invite or registration code. Public, so counted per address,
  and a success does NOT clear it: one valid code must not reset the history of an
  address that has been guessing.
* **Refresh** checks a cookie that cannot be guessed but can be replayed, and each
  replay writes an audit row and ends a family. Per address, generous.

All three share the sign-in failure table, which is where a latent bug surfaced: every
check pruned EVERY key by its own window, so a ten-minute check erased the history a
one-hour throttle was counting. The store now prunes a key by its own window and the
rest only by a 24-hour horizon.
"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import app as app_module
from backend import security, store
from backend.app import app

TENANT = "tenant-throttle"
USER = "throttle-analyst"
OTHER = "throttle-viewer"
PASSWORD = "a-throttle-pass-7"
WRONG = "not-the-password-9"
NEW = "a-fresh-throttle-8"


class _ThrottleCase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "throttle.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        self.tenant = store.create_tenant(TENANT, "Throttle")
        store.create_user(USER, security.hash_password(PASSWORD), "analyst", TENANT)
        store.create_user(OTHER, security.hash_password(PASSWORD), "viewer", TENANT)
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def _token(self, user: str = USER, role: str = "analyst") -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, role, TENANT)}"}


class ChangePasswordTest(_ThrottleCase):
    LIMIT = app_module.PASSWORD_CHANGE_THROTTLE.limit

    def _change(self, current: str, new: str = NEW, headers: dict | None = None):
        return self.client.post(
            "/api/auth/change-password",
            json={"current_password": current, "new_password": new},
            headers=headers or self._token(),
        )

    def test_the_default_is_five_in_fifteen_minutes(self) -> None:
        self.assertEqual((self.LIMIT, app_module.PASSWORD_CHANGE_THROTTLE.window_seconds), (5, 900))

    def test_a_wrong_current_password_is_403_not_401(self) -> None:
        # A 401 is what the console reads as an expired access token: it would renew
        # the session and send the wrong password again, counting it twice.
        response = self._change(WRONG)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"], "Current password is incorrect")

    def test_after_the_limit_even_the_right_password_is_refused(self) -> None:
        for _ in range(self.LIMIT):
            self.assertEqual(self._change(WRONG).status_code, 403)
        response = self._change(PASSWORD)
        self.assertEqual(response.status_code, 429, "the oracle stops answering, right or wrong")
        self.assertIsNotNone(security.authenticate_user(USER, PASSWORD), "and nothing changed")
        self.assertIsNone(security.authenticate_user(USER, NEW))

    def test_it_counts_the_account_not_the_session(self) -> None:
        for _ in range(self.LIMIT):
            self._change(WRONG, headers=self._token())
        # A second session of the same account - a second stolen token - is refused too.
        self.assertEqual(self._change(WRONG, headers=self._token()).status_code, 429)
        # Another account, from the same address, is not.
        other = self._token(OTHER, "viewer")
        self.assertEqual(self._change(WRONG, headers=other).status_code, 403)

    def test_a_correct_password_clears_the_count(self) -> None:
        for _ in range(self.LIMIT - 1):
            self._change(WRONG)
        # Right current password, but a new one the policy refuses: nothing changes,
        # and the proof of the current password still clears the count.
        self.assertEqual(self._change(PASSWORD, new="kestrel-4x9").status_code, 400)
        for _ in range(self.LIMIT):
            self.assertEqual(self._change(WRONG).status_code, 403)
        self.assertEqual(self._change(WRONG).status_code, 429)

    def test_each_refusal_is_audited(self) -> None:
        self._change(WRONG)
        self._change(WRONG)
        refused = [e for e in store.read_audit_log(TENANT, 50) if e["action"] == "user.password_change_refused"]
        self.assertEqual(len(refused), 2)

    def test_it_does_not_count_against_signing_in(self) -> None:
        for _ in range(self.LIMIT + 2):
            self._change(WRONG)
        response = self.client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
        self.assertEqual(response.status_code, 200, "a separate namespace from the sign-in throttle")


class RegisterTest(_ThrottleCase):
    LIMIT = app_module.REGISTER_THROTTLE.limit

    def _register(self, username: str, code: str, *, tenant: str = TENANT, password: str = "a-register-pass-3"):
        return self.client.post("/api/auth/register", json={
            "username": username, "password": password, "tenant_id": tenant, "registration_code": code,
        })

    def test_the_default_is_ten_in_an_hour(self) -> None:
        self.assertEqual((self.LIMIT, app_module.REGISTER_THROTTLE.window_seconds), (10, 3600))

    def test_after_the_limit_even_a_valid_code_is_refused(self) -> None:
        for n in range(self.LIMIT):
            self.assertEqual(self._register(f"guess-{n}", f"wrong-code-{n}").status_code, 403)
        response = self._register("late-arrival", self.tenant["registration_code"])
        self.assertEqual(response.status_code, 429)
        self.assertIsNone(store.get_user("late-arrival"))

    def test_every_kind_of_refusal_counts(self) -> None:
        for n in range(self.LIMIT - 2):
            self._register(f"guess-{n}", "wrong-code")
        self.assertEqual(self._register("anyone", "x", tenant="no-such-tenant").status_code, 403)
        self.assertEqual(self._register(USER, self.tenant["registration_code"]).status_code, 409)
        self.assertEqual(self._register("late-arrival", self.tenant["registration_code"]).status_code, 429)

    def test_a_success_does_not_clear_the_address(self) -> None:
        for n in range(self.LIMIT - 1):
            self._register(f"guess-{n}", "wrong-code")
        self.assertEqual(self._register("found-it", self.tenant["registration_code"]).status_code, 200)
        self.assertEqual(self._register("one-more", "wrong-code").status_code, 403)
        self.assertEqual(self._register("next-one", self.tenant["registration_code"]).status_code, 429)

    def test_a_refused_password_is_not_a_guess(self) -> None:
        # The code was right; the new user's choice of password is not an attack.
        for n in range(self.LIMIT + 2):
            response = self._register(f"weak-{n}", self.tenant["registration_code"], password="password1234")
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self._register("strong", self.tenant["registration_code"]).status_code, 200)


class RefreshTest(_ThrottleCase):
    LIMIT = app_module.REFRESH_THROTTLE.limit

    def _refresh(self, cookie: str):
        response = self.client.post("/api/auth/refresh", cookies={security.REFRESH_COOKIE: cookie})
        self.client.cookies.clear()
        return response

    def _login_cookie(self) -> str:
        response = self.client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
        self.assertEqual(response.status_code, 200, response.text)
        cookie = response.cookies[security.REFRESH_COOKIE]
        self.client.cookies.clear()
        return cookie

    def test_the_default_is_thirty_in_five_minutes(self) -> None:
        self.assertEqual((self.LIMIT, app_module.REFRESH_THROTTLE.window_seconds), (30, 300))

    def test_after_the_limit_a_good_cookie_is_refused_and_not_spent(self) -> None:
        good = self._login_cookie()
        for n in range(self.LIMIT):
            self.assertEqual(self._refresh(f"junk-{n}").status_code, 401)
        refused = self._refresh(good)
        self.assertEqual(refused.status_code, 429)
        self.assertNotIn("set-cookie", {k.lower() for k in refused.headers},
                         "the address is refused; the cookie is not touched")
        # Once the address may ask again, the cookie still works: the 429 did not
        # consume it (which would have looked like a replay and ended the family).
        store.clear_login_failures("refresh:testclient")
        self.assertEqual(self._refresh(good).status_code, 200)

    def test_a_successful_renewal_is_not_counted(self) -> None:
        cookie = self._login_cookie()
        for _ in range(self.LIMIT + 2):
            response = self._refresh(cookie)
            self.assertEqual(response.status_code, 200, response.text)
            cookie = response.cookies[security.REFRESH_COOKIE]


class ThrottlesKeepTheirOwnHistoryTest(_ThrottleCase):
    """The store's pruning bug, which only mattered once throttles had different windows."""

    def _insert(self, key: str, age_seconds: float) -> None:
        with store._connect() as conn:
            conn.execute("INSERT INTO login_failures (rate_key, timestamp) VALUES (?, ?)",
                         (key, time.time() - age_seconds))

    def test_a_short_window_check_does_not_erase_a_long_windows_history(self) -> None:
        for _ in range(3):
            self._insert("register:10.0.0.9", 1800)       # half an hour old
        # A ten-minute check on another key - a sign-in, say - used to prune these.
        store.count_login_failures("ip:10.0.0.7", 600)
        store.record_login_failure("ip:10.0.0.7", 600)
        self.assertEqual(store.count_login_failures("register:10.0.0.9", 3600), 3)

    def test_a_key_is_still_pruned_by_its_own_window(self) -> None:
        self._insert("refresh:10.0.0.9", 900)
        self.assertEqual(store.count_login_failures("refresh:10.0.0.9", 300), 0)
        with store._connect() as conn:
            left = conn.execute("SELECT COUNT(*) FROM login_failures WHERE rate_key = ?",
                                ("refresh:10.0.0.9",)).fetchone()[0]
        self.assertEqual(left, 0)

    def test_everything_older_than_the_horizon_goes(self) -> None:
        self._insert("register:10.0.0.9", store._THROTTLE_HORIZON_SECONDS + 60)
        store.count_login_failures("ip:10.0.0.7", 600)
        with store._connect() as conn:
            left = conn.execute("SELECT COUNT(*) FROM login_failures").fetchone()[0]
        self.assertEqual(left, 0, "the table stays bounded")

    def test_no_throttle_outlives_the_horizon(self) -> None:
        for throttle in (app_module.PASSWORD_CHANGE_THROTTLE, app_module.REGISTER_THROTTLE,
                         app_module.REFRESH_THROTTLE):
            self.assertLessEqual(throttle.window_seconds, store._THROTTLE_HORIZON_SECONDS, throttle.name)
        self.assertLessEqual(app_module.LOGIN_WINDOW_SECONDS, store._THROTTLE_HORIZON_SECONDS)


if __name__ == "__main__":
    unittest.main()
