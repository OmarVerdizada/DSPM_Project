"""C2: a second factor for privileged identities (TOTP, RFC 6238).

Gate line: "MFA blocks privileged action". Administrators get no session until they
prove (or first set up) an authenticator; nobody exercises an MFA-scoped permission -
tenant.admin, platform.admin, credential.manage, and storing any vault credential - from a
session that has not proved it; an API key, which cannot, never holds one.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import identity, mfa, security, store
from backend.app import app

PASSWORD = "Kestrel-mfa-pass-91"


def _code(secret: str, offset: int = 0) -> str:
    return mfa.code_at(secret, mfa.current_step() + offset)


class TheAlgorithmTest(unittest.TestCase):
    """RFC 6238 Appendix B (SHA-1), truncated to six digits as authenticators show."""

    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32("12345678901234567890")

    def test_the_rfc_vectors(self) -> None:
        for time, expected in ((59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
                               (1234567890, "005924"), (2000000000, "279037")):
            with self.subTest(time=time):
                self.assertEqual(mfa.code_at(self.SECRET, time // 30), expected)

    def test_skew_is_one_step_either_side_and_no_more(self) -> None:
        now = 1_000_000_000
        step = mfa.current_step(now)
        for offset, accepted in ((-2, False), (-1, True), (0, True), (1, True), (2, False)):
            with self.subTest(offset=offset):
                result = mfa.matching_step(self.SECRET, mfa.code_at(self.SECRET, step + offset), now)
                self.assertEqual(result is not None, accepted)

    def test_recovery_codes_are_long_random_and_hashed(self) -> None:
        codes = mfa.generate_recovery_codes()
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)
        for code in codes:
            self.assertRegex(code, r"^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$")
        self.assertEqual(mfa.recovery_hash(codes[0].lower()), mfa.recovery_hash(codes[0]))
        self.assertNotIn(mfa.normalize_recovery_code(codes[0]), mfa.recovery_hash(codes[0]))


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "mfa.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant("t-mfa", "MFA")
        for name, role in (("boss", "admin"), ("ana", "analyst"), ("vic", "viewer"), ("ops", "scan_operator")):
            store.create_user(name, security.hash_password(PASSWORD), role, "t-mfa")
        self.client = TestClient(app)
        # a fresh per-account code throttle for every test
        for name in ("boss", "ana", "vic", "ops"):
            store.clear_login_failures(f"mfa:{name}")

    def _login(self, name: str, workspace: str = "") -> dict:
        response = self.client.post("/api/auth/login", json={"username": name, "password": PASSWORD,
                                                               "workspace": workspace})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _enrol_at_sign_in(self, name: str) -> tuple[str, dict]:
        challenge = self._login(name)
        self.assertTrue(challenge.get("mfa_enrollment_required"), challenge)
        started = self.client.post("/api/auth/mfa/enroll/start", json={"mfa_token": challenge["mfa_token"]}).json()
        confirmed = self.client.post("/api/auth/mfa/enroll/confirm",
                                     json={"mfa_token": challenge["mfa_token"], "code": _code(started["secret"])})
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        return started["secret"], confirmed.json()

    def _bearer(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def _actions(self, tenant: str = "t-mfa") -> list[dict]:
        return store.read_audit_log(tenant, 200)


class AnAdministratorNeedsASecondFactorTest(_Case):

    def test_sign_in_returns_no_session_before_the_factor(self) -> None:
        challenge = self._login("boss")
        self.assertTrue(challenge["mfa_enrollment_required"])
        self.assertNotIn("access_token", challenge)
        self.assertNotIn("dspm_refresh", self.client.cookies)
        # The challenge is not a bearer credential.
        self.assertEqual(self.client.get("/api/users", headers=self._bearer(challenge["mfa_token"])).status_code, 401)

    def test_enrollment_needs_a_matching_code_before_it_counts(self) -> None:
        challenge = self._login("boss")
        started = self.client.post("/api/auth/mfa/enroll/start", json={"mfa_token": challenge["mfa_token"]}).json()
        self.assertTrue(started["otpauth_uri"].startswith("otpauth://totp/Sentro%20DSPM%3Aboss%40t-mfa?secret="))
        wrong = self.client.post("/api/auth/mfa/enroll/confirm", json={"mfa_token": challenge["mfa_token"], "code": "000000"})
        self.assertEqual(wrong.status_code, 400)
        self.assertFalse(identity.mfa_state(store.get_user("boss"))["enabled"])
        right = self.client.post("/api/auth/mfa/enroll/confirm",
                                 json={"mfa_token": challenge["mfa_token"], "code": _code(started["secret"])})
        self.assertEqual(right.status_code, 200)
        body = right.json()
        self.assertTrue(body["mfa_verified"])
        self.assertEqual(len(body["recovery_codes"]), 10)
        self.assertEqual(self.client.get("/api/users", headers=self._bearer(body["access_token"])).status_code, 200)

    def test_the_secret_is_never_shown_again_and_is_encrypted_at_rest(self) -> None:
        secret, session = self._enrol_at_sign_in("boss")
        headers = self._bearer(session["access_token"])
        for path in ("/api/profile", "/api/profile/mfa"):
            with self.subTest(path=path):
                self.assertNotIn(secret, self.client.get(path, headers=headers).text)
        record = store.get_user_mfa("boss")
        self.assertNotIn(secret, json.dumps(record))
        for code in session["recovery_codes"]:
            self.assertNotIn(mfa.normalize_recovery_code(code), json.dumps(record))
        audit = json.dumps(self._actions())
        self.assertNotIn(secret, audit)
        self.assertNotIn(session["recovery_codes"][0], audit)

    def test_a_valid_code_signs_in_and_an_invalid_one_does_not(self) -> None:
        secret, _ = self._enrol_at_sign_in("boss")
        challenge = self._login("boss")
        self.assertTrue(challenge["mfa_required"])
        wrong = self.client.post("/api/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": "123456"})
        self.assertEqual(wrong.status_code, 401)
        self.assertIn("auth.mfa_failed", [row["action"] for row in self._actions()])
        right = self.client.post("/api/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": _code(secret, 1)})
        self.assertEqual(right.status_code, 200, right.text)
        self.assertTrue(right.json()["mfa_verified"])

    def test_a_code_is_accepted_once(self) -> None:
        secret, _ = self._enrol_at_sign_in("boss")  # enrollment consumed the current step
        code = _code(secret, 1)
        first = self.client.post("/api/auth/mfa/verify",
                                 json={"mfa_token": self._login("boss")["mfa_token"], "code": code})
        self.assertEqual(first.status_code, 200)
        replay = self.client.post("/api/auth/mfa/verify",
                                  json={"mfa_token": self._login("boss")["mfa_token"], "code": code})
        self.assertEqual(replay.status_code, 401, "the same step twice")
        older = self.client.post("/api/auth/mfa/verify",
                                 json={"mfa_token": self._login("boss")["mfa_token"], "code": _code(secret)})
        self.assertEqual(older.status_code, 401, "a step older than the last accepted")

    def test_a_recovery_code_works_once(self) -> None:
        _secret, session = self._enrol_at_sign_in("boss")
        code = session["recovery_codes"][3]
        first = self.client.post("/api/auth/mfa/verify",
                                 json={"mfa_token": self._login("boss")["mfa_token"], "recovery_code": code.lower()})
        self.assertEqual(first.status_code, 200)
        again = self.client.post("/api/auth/mfa/verify",
                                 json={"mfa_token": self._login("boss")["mfa_token"], "recovery_code": code})
        self.assertEqual(again.status_code, 401)
        self.assertEqual(identity.mfa_state(store.get_user("boss"))["recovery_codes_left"], 9)

    def test_a_challenge_is_spent_by_its_success(self) -> None:
        secret, enrolled = self._enrol_at_sign_in("boss")
        token = self._login("boss")["mfa_token"]
        self.assertEqual(self.client.post("/api/auth/mfa/verify", json={"mfa_token": token, "code": _code(secret, 1)}).status_code, 200)
        # A recovery code, not an earlier step: step monotonicity alone refuses that, and
        # would hide a challenge that was never spent (the C2 mutation run found it).
        again = self.client.post("/api/auth/mfa/verify", json={"mfa_token": token,
                                                                 "recovery_code": enrolled["recovery_codes"][0]})
        self.assertEqual(again.status_code, 401)

    def test_a_challenge_for_one_purpose_opens_no_other(self) -> None:
        self._enrol_at_sign_in("boss")
        verify_token = self._login("boss")["mfa_token"]
        self.assertEqual(self.client.post("/api/auth/mfa/enroll/start", json={"mfa_token": verify_token}).status_code, 401)
        forged = verify_token[:-3] + ("AAA" if not verify_token.endswith("AAA") else "BBB")
        self.assertEqual(self.client.post("/api/auth/mfa/verify", json={"mfa_token": forged, "code": "000000"}).status_code, 401)

    def test_wrong_codes_are_throttled_per_account(self) -> None:
        self._enrol_at_sign_in("boss")
        token = self._login("boss")["mfa_token"]
        statuses = [self.client.post("/api/auth/mfa/verify", json={"mfa_token": token, "code": "000000"}).status_code
                    for _ in range(6)]
        self.assertEqual(statuses[:5], [401] * 5)
        self.assertEqual(statuses[5], 429)


class TheGateOnPrivilegedActionTest(_Case):

    def test_an_administrator_session_without_the_factor_is_refused_privileged_routes(self) -> None:
        unverified = security.create_token("boss", "admin", "t-mfa", mfa_verified=False)
        refused = self.client.get("/api/users", headers=self._bearer(unverified))
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(refused.json()["detail"]["code"], "mfa_required")
        # reads that need no MFA-scoped permission still work
        self.assertEqual(self.client.get("/api/findings", headers=self._bearer(unverified)).status_code, 200)
        verified = security.create_token("boss", "admin", "t-mfa", mfa_verified=True)
        self.assertEqual(self.client.get("/api/users", headers=self._bearer(verified)).status_code, 200)

    def test_storing_a_credential_needs_a_verified_session_whoever_asks(self) -> None:
        body = {"username": "svc", "password": "Sv3-secret-value", "domain": "CORP"}
        for name, role in (("ana", "analyst"), ("ops", "scan_operator")):
            with self.subTest(role=role):
                token = security.create_token(name, role, "t-mfa", mfa_verified=False)
                refused = self.client.post("/api/credentials", json=body, headers=self._bearer(token))
                self.assertEqual(refused.status_code, 403)
                self.assertEqual(refused.json()["detail"]["code"], "mfa_required")

    def test_an_analyst_steps_up_by_setting_up_a_factor(self) -> None:
        session = self._login("ana")  # no MFA required at sign-in for an analyst
        self.assertIn("access_token", session)
        self.assertFalse(session["mfa_verified"])
        headers = self._bearer(session["access_token"])
        body = {"username": "svc", "password": "Sv3-secret-value", "domain": "CORP"}
        self.assertEqual(self.client.post("/api/credentials", json=body, headers=headers).status_code, 403)
        started = self.client.post("/api/profile/mfa/enroll/start", headers=headers).json()
        confirmed = self.client.post("/api/profile/mfa/enroll/confirm", headers=headers,
                                     json={"code": _code(started["secret"])})
        self.assertEqual(confirmed.status_code, 200)
        self.assertTrue(confirmed.json()["session_verified"])
        stored = self.client.post("/api/credentials", json=body, headers=headers)
        self.assertEqual(stored.status_code, 200, stored.text)
        # From now on the analyst is challenged at sign-in too.
        self.assertTrue(self._login("ana")["mfa_required"])

    def test_a_step_up_with_a_code_opens_the_session(self) -> None:
        secret, _ = self._enrol_at_sign_in("boss")
        unverified = security.create_token("boss", "admin", "t-mfa", mfa_verified=False)
        headers = self._bearer(unverified)
        self.assertEqual(self.client.post("/api/profile/mfa/verify", headers=headers, json={"code": "000000"}).status_code, 401)
        self.assertEqual(self.client.post("/api/profile/mfa/verify", headers=headers,
                                          json={"code": _code(secret, 1)}).status_code, 200)
        self.assertEqual(self.client.get("/api/users", headers=headers).status_code, 200)

    def test_an_api_key_never_holds_an_mfa_scoped_permission(self) -> None:
        admin = self._bearer(security.create_token("boss", "admin", "t-mfa", mfa_verified=True))
        refused = self.client.post("/api/api-keys", headers=admin, json={"label": "robot", "role": "analyst"})
        self.assertEqual(refused.status_code, 400)
        self.assertIn("second factor", refused.json()["detail"])
        allowed = self.client.post("/api/api-keys", headers=admin, json={"label": "robot", "role": "viewer"})
        self.assertEqual(allowed.status_code, 200)
        key = allowed.json()["api_key"]
        # and a key that already holds one (issued before C2) is refused at use
        key_id = store.create_api_key_record("t-mfa", security.hash_api_key("dspm_legacy_key"), "old", "analyst",
                                             "boss", "2099-01-01T00:00:00+00:00")
        self.assertTrue(key_id)
        stored = self.client.post("/api/credentials", headers={"X-API-Key": "dspm_legacy_key"},
                                  json={"username": "svc", "password": "Sv3-secret-value", "domain": "CORP"})
        self.assertEqual(stored.status_code, 403)
        self.assertEqual(self.client.get("/api/findings", headers={"X-API-Key": key}).status_code, 200)

    def test_a_promoted_account_must_prove_the_factor(self) -> None:
        session = self._login("vic")
        headers = self._bearer(session["access_token"])
        store.update_user_role("vic", "admin", "t-mfa")
        # role is read from the row on every request: admin now, but the session is unverified
        refused = self.client.get("/api/users", headers=headers)
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(refused.json()["detail"]["code"], "mfa_required")
        # and the session cannot be renewed into an administrator's session
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)

    def test_a_demoted_account_loses_privilege_at_once(self) -> None:
        secret, session = self._enrol_at_sign_in("boss")
        store.create_user("boss2", security.hash_password(PASSWORD), "admin", "t-mfa")  # keep an admin
        headers = self._bearer(session["access_token"])
        self.assertEqual(self.client.get("/api/users", headers=headers).status_code, 200)
        store.update_user_role("boss", "viewer", "t-mfa")
        self.assertEqual(self.client.get("/api/users", headers=headers).status_code, 403)
        del secret

    def test_an_unverified_administrator_session_is_not_renewed(self) -> None:
        # A session from before C2 (or any path that skipped MFA) ends at its next refresh.
        token = security.create_token("boss", "admin", "t-mfa", mfa_verified=False)
        secret, _family, _exp = security.issue_refresh_token("boss", security._token_jti(token), mfa_verified=False)
        self.assertEqual(security.rotate_refresh_token(secret)["status"], "mfa_required")
        token = security.create_token("boss", "admin", "t-mfa", mfa_verified=True)
        secret, _family, _exp = security.issue_refresh_token("boss", security._token_jti(token), mfa_verified=True)
        renewed = security.rotate_refresh_token(secret)
        self.assertEqual(renewed["status"], "ok")
        self.assertTrue(security.verify_token(renewed["access_token"]).mfa_verified, "the flag survives rotation")


class ResettingTheFactorTest(_Case):

    def test_an_administrator_resets_a_lost_factor_and_the_sessions_end(self) -> None:
        store.create_user("ana2", security.hash_password(PASSWORD), "analyst", "t-mfa")
        user = store.get_user("ana2")
        started = identity.start_enrollment(user)
        identity.confirm_enrollment(user, _code(started["secret"]))
        session = security.create_token("ana2", "analyst", "t-mfa", mfa_verified=True)
        admin = self._bearer(security.create_token("boss", "admin", "t-mfa", mfa_verified=True))
        reset = self.client.post("/api/users/ana2/mfa/reset", headers=admin)
        self.assertEqual(reset.status_code, 200)
        self.assertTrue(reset.json()["reset"])
        self.assertFalse(identity.mfa_state(store.get_user("ana2"))["enabled"])
        self.assertEqual(self.client.get("/api/profile", headers=self._bearer(session)).status_code, 401)
        self.assertIn("auth.mfa_reset", [row["action"] for row in self._actions()])

    def test_resetting_needs_an_administrator_with_a_verified_session(self) -> None:
        unverified = self._bearer(security.create_token("boss", "admin", "t-mfa", mfa_verified=False))
        self.assertEqual(self.client.post("/api/users/ana/mfa/reset", headers=unverified).status_code, 403)
        viewer = self._bearer(security.create_token("vic", "viewer", "t-mfa", mfa_verified=True))
        self.assertEqual(self.client.post("/api/users/ana/mfa/reset", headers=viewer).status_code, 403)

    def test_the_built_in_administrator_is_reset_only_from_the_host(self) -> None:
        if store.get_user("admin") is None:
            store.create_user("admin", security.hash_password(PASSWORD), "admin", "default")
        platform = self._bearer(security.create_token("admin", "admin", "default", mfa_verified=True))
        self.assertEqual(self.client.post("/api/users/admin/mfa/reset", headers=platform).status_code, 403)

    def test_a_required_factor_cannot_be_switched_off_by_its_owner(self) -> None:
        _secret, session = self._enrol_at_sign_in("boss")
        refused = self.client.post("/api/profile/mfa/disable", headers=self._bearer(session["access_token"]))
        self.assertEqual(refused.status_code, 400)
        self.assertTrue(identity.mfa_state(store.get_user("boss"))["enabled"])


class TheFactorGoesWithItsAccountTest(_Case):
    """Found while scoping C2's tables (2026-09-28): deleting an account left its MFA row,
    so the next account given the same key inherited someone else's authenticator."""

    def test_a_deleted_account_takes_its_factor_with_it(self) -> None:
        store.create_user("ana2", security.hash_password(PASSWORD), "analyst", "t-mfa")
        user = store.get_user("ana2")
        started = identity.start_enrollment(user)
        identity.confirm_enrollment(user, _code(started["secret"]))
        admin = self._bearer(security.create_token("boss", "admin", "t-mfa", mfa_verified=True))
        self.assertEqual(self.client.post("/api/users/ana2/delete", headers=admin).status_code, 200)
        self.assertIsNone(store.get_user_mfa("ana2"))
        store.create_user("ana2", security.hash_password(PASSWORD), "analyst", "t-mfa")
        self.assertFalse(identity.mfa_state(store.get_user("ana2"))["enabled"], "a new account starts without a factor")

    def test_erasing_a_workspace_erases_its_factors_and_directory_settings(self) -> None:
        user = store.get_user("boss")
        started = identity.start_enrollment(user)
        identity.confirm_enrollment(user, _code(started["secret"]))
        store.save_directory_settings("t-mfa", False, {"host": "dc.example.test"}, "", "boss")
        store.delete_tenant_with_data("t-mfa")
        self.assertIsNone(store.get_user_mfa("boss"))
        self.assertIsNone(store.get_directory_settings("t-mfa"))


class TheHostResetTest(_Case):

    def test_the_cli_resets_a_factor_and_records_it(self) -> None:
        self._enrol_at_sign_in("boss")
        import main

        with mock.patch("sys.stdout"):
            status = main.main(["mfa", "reset", "boss"])
        self.assertEqual(status, 0)
        self.assertFalse(identity.mfa_state(store.get_user("boss"))["enabled"])
        rows = [row for row in self._actions() if row["action"] == "auth.mfa_reset"]
        self.assertEqual(rows[-1]["detail"]["by"], "host")


class ExitReviewTokensAreOnlyWhatTheyAreTest(_Case):
    """M3 exit review: the MFA challenge and the download token are signed with the same key
    as an access token, over "<prefix>.<payload>". Given their prefix back as a header, both
    verified as a session - a first factor alone reached every non-gated admin permission."""

    def test_an_mfa_challenge_is_not_a_session(self) -> None:
        token = self._login("boss")["mfa_token"]
        for bearer in (f"mfa.{token}", token):
            response = self.client.get("/api/profile", headers=self._bearer(bearer))
            self.assertEqual(response.status_code, 401, bearer[:12])

    def test_a_download_token_is_not_a_session(self) -> None:
        token = security.create_artifact_download_token("artifact-1", "t-mfa", "ana", "analyst")
        response = self.client.get("/api/profile", headers=self._bearer(f"artifact_dl.{token}"))
        self.assertEqual(response.status_code, 401)

    def test_an_access_token_still_is(self) -> None:
        token = security.create_token("ana", "analyst", "t-mfa")
        self.assertEqual(self.client.get("/api/profile", headers=self._bearer(token)).status_code, 200)

    def test_a_spent_challenge_reads_as_spent(self) -> None:
        token = security.create_mfa_challenge("boss", "enroll")
        claims = security.read_mfa_challenge(token, ("enroll",))
        self.assertIsNotNone(claims)
        self.assertTrue(security.spend_mfa_challenge(claims))
        self.assertIsNone(security.read_mfa_challenge(token, ("enroll",)),
                          "a spent enrolment challenge must not reach enroll/confirm again")


if __name__ == "__main__":
    unittest.main()
