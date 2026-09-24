"""Passwords: M0/Q4's characterization, rewritten as C8 changed it.

Q4 pinned the password rules and the stored hash before C8 touched them, with two gaps
marked GAP. C8 has landed:

  * **The policy.** Eight characters with a letter and a digit was all it took, so
    "passwor1" was a valid password. The floor is now twelve (configurable, never below
    eight), and a password is refused if it is common or known-breached (checked offline,
    see backend.breached_passwords), mostly one character, or contains the username. The
    letters-and-digits rule stays, so nothing refused before is accepted now.
  * **A malformed stored hash** - cut short by a bad restore, edited by hand - raised
    ValueError out of the sign-in path as a 500. It is now a failed sign-in.
  * **The work factor** rose from 310,000 PBKDF2 rounds to 600,000, and a hash made
    with fewer is upgraded silently at the next successful sign-in - the only moment the
    plaintext is available to do it.

What must never change stays pinned: the stored format, a per-password salt, the clamp
on the work factor, and a hash verifying with the rounds it was written with - because
changing any of those is the one change that can lock every account out of an install.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from backend import breached_passwords, security, store
from backend.security import (
    hash_password,
    password_needs_rehash,
    validate_password_strength,
    verify_password,
)

STORED = re.compile(r"^pbkdf2_sha256\$(\d+)\$([0-9a-f]{32})\$([0-9a-f]{64})$")
GOOD = "correct7horse-staple"


class ThePolicyTest(unittest.TestCase):

    def assertRejected(self, password, contains: str, **kwargs) -> None:
        with self.assertRaises(HTTPException) as refused:
            validate_password_strength(password, **kwargs)
        self.assertEqual(refused.exception.status_code, 400)
        self.assertIn(contains, refused.exception.detail)

    def test_a_long_uncommon_password_with_letters_and_digits_is_enough(self) -> None:
        for password in (GOOD, "Tr1cky-Horse-Battery9", "paroləmiz-dağ-2024", "a1b2c3d4e5f6-kestrel"):
            with self.subTest(password=password):
                self.assertIsNone(validate_password_strength(password))

    def test_the_floor_is_twelve(self) -> None:
        self.assertEqual(security.password_min_length(), 12)
        self.assertRejected("kestrel-482", "at least 12 characters")
        self.assertIsNone(validate_password_strength("kestrel-4821"))

    def test_an_operator_may_raise_it_but_never_below_eight(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_PASSWORD_MIN_LENGTH": "16"}):
            self.assertRejected("kestrel-4821", "at least 16 characters")
        with mock.patch.dict(os.environ, {"DSPM_PASSWORD_MIN_LENGTH": "4"}):
            self.assertEqual(security.password_min_length(), 8)
        with mock.patch.dict(os.environ, {"DSPM_PASSWORD_MIN_LENGTH": "not-a-number"}):
            self.assertEqual(security.password_min_length(), 12)

    def test_nothing_at_all_is_refused_as_too_short(self) -> None:
        for empty in ("", None):
            with self.subTest(value=empty):
                self.assertRejected(empty, "at least 12 characters")

    def test_longer_than_two_hundred_is_refused(self) -> None:
        # The cap is what stops a megabyte of input being run through 600k PBKDF2
        # rounds on the login path.
        self.assertIsNone(validate_password_strength("kestrel-" + "a" * 188 + "1"))
        self.assertRejected("kestrel-" + "a" * 192 + "1", "too long")

    def test_letters_only_and_digits_only_are_still_refused(self) -> None:
        self.assertRejected("kestrel-harbour", "letters and numbers")
        self.assertRejected("4821-7730-9912", "letters and numbers")

    def test_a_repetitive_password_is_refused(self) -> None:
        self.assertRejected("aaaaaaaaaaa1", "too repetitive")
        self.assertRejected("ab1ab1ab1ab1", "too repetitive")

    def test_a_password_containing_the_username_is_refused(self) -> None:
        self.assertRejected("svc-kestrel-4821", "must not contain the username", username="kestrel")
        self.assertRejected("SVC-KESTREL-4821", "must not contain the username", username="kestrel")
        # A very short username would forbid half the dictionary; it is not applied.
        self.assertIsNone(validate_password_strength("an-kestrel-4821", username="an"))

    def test_common_passwords_are_refused_however_they_are_decorated(self) -> None:
        for password in ("Password2024!", "P@ssw0rd12345", "Welcome123456", "qwerty123456",
                         "passwordpassword1", "sentro-admin-1", "Admin-Password-2024", "1qaz2wsx3edc"):
            with self.subTest(password=password):
                self.assertRejected(password, "too common or has appeared in a breach")

    def test_hashing_applies_the_policy(self) -> None:
        with self.assertRaises(HTTPException) as refused:
            hash_password("short1")
        self.assertEqual(refused.exception.status_code, 400)
        with self.assertRaises(HTTPException):
            hash_password("svc-kestrel-4821", username="kestrel")


class TheBreachCorpusTest(unittest.TestCase):
    """The operator-supplied list: sorted SHA-1 hashes, searched on disk."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        self.breached = ["kestrel-harbour-77", "blue-moon-lantern-9", "orchid-4492-velvet"]
        hashes = {hashlib.sha1(p.encode()).hexdigest().upper() for p in self.breached}
        filler = {hashlib.sha1(f"filler-{i}".encode()).hexdigest().upper() for i in range(5000)}
        lines = [f"{h}:{i + 1}" for i, h in enumerate(sorted(hashes | filler))]
        self.corpus = Path(self.temp_dir.name) / "pwned.txt"
        # The "Pwned Passwords" download uses CRLF; the search must not care.
        self.corpus.write_bytes("\r\n".join(lines).encode("ascii") + b"\r\n")

    def _with_corpus(self):
        return mock.patch.dict(os.environ, {"DSPM_BREACHED_PASSWORDS_FILE": str(self.corpus)})

    def test_a_listed_password_is_refused(self) -> None:
        with self._with_corpus():
            for password in self.breached:
                with self.subTest(password=password):
                    self.assertTrue(breached_passwords.in_breach_corpus(password))
                    with self.assertRaises(HTTPException):
                        validate_password_strength(password)

    def test_an_unlisted_password_is_not(self) -> None:
        with self._with_corpus():
            self.assertFalse(breached_passwords.in_breach_corpus(GOOD))
            self.assertIsNone(validate_password_strength(GOOD))

    def test_every_key_in_the_file_is_found(self) -> None:
        # The binary search is the part that could be subtly wrong - at the first line,
        # the last line, and around every seek boundary.
        keys = [line.split(b":")[0].decode() for line in self.corpus.read_bytes().splitlines() if line]
        for key in keys[:50] + keys[-50:] + keys[::97]:
            with self.subTest(key=key[:10]):
                self.assertTrue(breached_passwords.sorted_file_contains(self.corpus, key))
        self.assertFalse(breached_passwords.sorted_file_contains(self.corpus, "0" * 40))
        self.assertFalse(breached_passwords.sorted_file_contains(self.corpus, "F" * 40))

    def test_a_file_of_bare_hashes_works_too(self) -> None:
        bare = Path(self.temp_dir.name) / "bare.txt"
        keys = sorted(hashlib.sha1(p.encode()).hexdigest().upper() for p in self.breached)
        bare.write_text("\n".join(keys) + "\n", encoding="ascii")
        for key in keys:
            self.assertTrue(breached_passwords.sorted_file_contains(bare, key))

    def test_a_missing_file_degrades_to_the_built_in_list(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_BREACHED_PASSWORDS_FILE": str(self.corpus) + ".gone"}):
            self.assertFalse(breached_passwords.in_breach_corpus(GOOD))
            self.assertIsNone(validate_password_strength(GOOD))
            with self.assertRaises(HTTPException):
                validate_password_strength("Password2024!")

    def test_the_file_is_not_read_into_memory(self) -> None:
        with self._with_corpus(), mock.patch.object(Path, "read_bytes", side_effect=AssertionError("read whole file")):
            self.assertTrue(breached_passwords.in_breach_corpus(self.breached[0]))


class TheStoredHashTest(unittest.TestCase):

    def test_the_stored_format_is_algorithm_rounds_salt_digest(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_PBKDF2_ROUNDS", None)
            stored = hash_password(GOOD)
        match = STORED.match(stored)
        self.assertIsNotNone(match, f"the stored format changed: {stored.split('$')[0]}")
        self.assertEqual(int(match.group(1)), 600_000, "C8's default work factor")

    def test_the_same_password_hashes_differently_every_time(self) -> None:
        first, second = hash_password(GOOD), hash_password(GOOD)
        self.assertNotEqual(first, second, "the salt must be per password, not per install")
        for stored in (first, second):
            self.assertTrue(verify_password(GOOD, stored))

    def test_the_work_factor_is_clamped_at_both_ends(self) -> None:
        for configured, expected in (("1", 210_000), ("500000", 500_000), ("9000000", 1_200_000)):
            with (
                self.subTest(configured=configured),
                mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": configured}),
            ):
                self.assertEqual(int(STORED.match(hash_password(GOOD)).group(1)), expected)

    def test_a_hash_is_verified_with_the_rounds_it_was_written_with(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "210000"}):
            stored = hash_password(GOOD)
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "400000"}):
            self.assertTrue(verify_password(GOOD, stored))


class VerifyingAPasswordTest(unittest.TestCase):

    def setUp(self) -> None:
        self.stored = hash_password(GOOD)

    def test_the_right_password_verifies(self) -> None:
        self.assertTrue(verify_password(GOOD, self.stored))

    def test_a_near_miss_does_not(self) -> None:
        for wrong in ("correct7horse-staplf", "Correct7horse-staple", GOOD + " ", " " + GOOD, ""):
            with self.subTest(wrong=wrong):
                self.assertFalse(verify_password(wrong, self.stored))

    def test_an_unrecognised_hash_is_simply_false(self) -> None:
        for stored in ("", "not-a-hash", "bcrypt$2b$12$something", hashlib.md5(b"x").hexdigest()):
            with self.subTest(stored=stored):
                self.assertFalse(verify_password(GOOD, stored))

    def test_a_malformed_stored_hash_fails_the_sign_in_rather_than_raising(self) -> None:
        # C8, the opposite of what Q4 pinned: these used to raise ValueError out of the
        # login path as a 500.
        for stored in ("pbkdf2_sha256$310000$abcd",
                       "pbkdf2_sha256$many$" + "a" * 32 + "$" + "b" * 64,
                       "pbkdf2_sha256$0$" + "a" * 32 + "$" + "b" * 64,
                       "pbkdf2_sha256$$$",
                       "pbkdf2_sha256$" + "9" * 400 + "$aa$bb"):
            with self.subTest(stored=stored[:32]):
                self.assertFalse(verify_password(GOOD, stored))


class TheLegacyHashTest(unittest.TestCase):
    """Plain SHA-256 rows from before PBKDF2. Off unless an operator turns them on."""

    def setUp(self) -> None:
        self.legacy = hashlib.sha256(GOOD.encode()).hexdigest()

    def test_a_legacy_hash_is_refused_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_ALLOW_LEGACY_SHA256_PASSWORDS", None)
            self.assertFalse(verify_password(GOOD, self.legacy))

    def test_a_legacy_hash_verifies_only_when_it_is_allowed(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ALLOW_LEGACY_SHA256_PASSWORDS": "1"}):
            self.assertTrue(verify_password(GOOD, self.legacy))
            self.assertFalse(verify_password("another-kestrel-9", self.legacy))

    def test_only_the_exact_opt_in_value_enables_it(self) -> None:
        for value in ("0", "true", "yes", "on", "", "TRUE"):
            with (
                self.subTest(value=value),
                mock.patch.dict(os.environ, {"DSPM_ALLOW_LEGACY_SHA256_PASSWORDS": value}),
            ):
                self.assertFalse(verify_password(GOOD, self.legacy))


class RehashOnSignInTest(unittest.TestCase):
    """C8: a work-factor increase reaches existing passwords at their next sign-in."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "rehash.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant("tenant-rehash", "Rehash")

    def _rounds(self, username: str) -> int:
        return int(store.get_user(username)["password_hash"].split("$")[1])

    def test_an_old_work_factor_is_upgraded_at_sign_in(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "210000"}):
            store.create_user("old-hash", hash_password(GOOD), "analyst", "tenant-rehash")
        self.assertEqual(self._rounds("old-hash"), 210_000)
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "400000"}):
            self.assertIsNotNone(security.authenticate_user("old-hash", GOOD))
            self.assertEqual(self._rounds("old-hash"), 400_000)
            self.assertIsNotNone(security.authenticate_user("old-hash", GOOD), "and it still signs in")

    def test_a_current_hash_is_left_alone(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "210000"}):
            store.create_user("current", hash_password(GOOD), "analyst", "tenant-rehash")
            before = store.get_user("current")["password_hash"]
            security.authenticate_user("current", GOOD)
            self.assertEqual(store.get_user("current")["password_hash"], before)

    def test_a_failed_sign_in_changes_nothing(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "210000"}):
            store.create_user("failed", hash_password(GOOD), "analyst", "tenant-rehash")
        before = store.get_user("failed")["password_hash"]
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "400000"}):
            self.assertIsNone(security.authenticate_user("failed", "not-the-password-1"))
        self.assertEqual(store.get_user("failed")["password_hash"], before)

    def test_a_legacy_sha256_row_becomes_pbkdf2(self) -> None:
        store.create_user("legacy", hashlib.sha256(GOOD.encode()).hexdigest(), "analyst", "tenant-rehash")
        with mock.patch.dict(os.environ, {"DSPM_ALLOW_LEGACY_SHA256_PASSWORDS": "1"}):
            self.assertIsNotNone(security.authenticate_user("legacy", GOOD))
        self.assertTrue(store.get_user("legacy")["password_hash"].startswith("pbkdf2_sha256$"))
        # ... so the operator can turn the legacy opt-in off again afterwards.
        self.assertIsNotNone(security.authenticate_user("legacy", GOOD))

    def test_a_password_the_policy_now_refuses_still_signs_in_and_upgrades(self) -> None:
        # Refusing a sign-in because the policy tightened would lock accounts out
        # rather than protect them. The policy governs what may be CHOSEN.
        weak = "passwor1"
        store.create_user("weak", security._pbkdf2_hash(weak, 210_000), "viewer", "tenant-rehash")
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "400000"}):
            self.assertIsNotNone(security.authenticate_user("weak", weak))
            self.assertEqual(self._rounds("weak"), 400_000)

    def test_needs_rehash_reads_the_stored_parameters(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "600000"}):
            self.assertTrue(password_needs_rehash("pbkdf2_sha256$310000$aa$bb"))
            self.assertFalse(password_needs_rehash("pbkdf2_sha256$600000$aa$bb"))
            self.assertTrue(password_needs_rehash(hashlib.sha256(b"x").hexdigest()))
            self.assertFalse(password_needs_rehash("pbkdf2_sha256$broken"))


class TheBuiltInAdminTest(unittest.TestCase):
    """The admin password is chosen in an environment variable, so a policy refusal
    happens at startup - where an HTTP 400 would mean nothing."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "admin.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        with store._connect() as conn:
            conn.execute("DELETE FROM users WHERE username = 'admin'")

    def test_a_weak_configured_admin_password_stops_startup_with_a_reason(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ADMIN_PASSWORD": "Admin12345"}), \
             self.assertRaises(RuntimeError) as refused:
            security.ensure_default_admin()
        self.assertIn("DSPM_ADMIN_PASSWORD", str(refused.exception))
        self.assertIn("at least 12", str(refused.exception))

    def test_a_good_configured_admin_password_is_accepted(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ADMIN_PASSWORD": "Kestrel-Harbour-4821"}):
            security.ensure_default_admin()
        self.assertIsNotNone(security.authenticate_user("admin", "Kestrel-Harbour-4821"))

    def test_the_generated_admin_password_meets_the_policy(self) -> None:
        # Otherwise a fresh local install would fail on its own generated password.
        for _ in range(20):
            generated = security._generate_dev_admin_password()
            with self.subTest(generated=generated[:4]):
                self.assertIsNone(validate_password_strength(generated, username="admin"))


class ThroughTheRoutesTest(unittest.TestCase):
    """Every route that sets a password applies the whole policy, username included."""

    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from backend.app import app

        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "routes.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant("tenant-routes", "Routes")
        store.create_user("kestrel-ops", hash_password(GOOD), "analyst", "tenant-routes")
        store.create_user("harbour-admin", hash_password(GOOD), "admin", "tenant-routes")
        store._forget_revocation()
        security._session_last_seen.clear()
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def _as(self, username: str, role: str) -> dict:
        return {"Authorization": f"Bearer {security.create_token(username, role, 'tenant-routes')}"}

    def test_changing_my_password_to_one_containing_my_name_is_refused(self) -> None:
        response = self.client.post(
            "/api/auth/change-password",
            json={"current_password": GOOD, "new_password": "my-kestrel-ops-4821"},
            headers=self._as("kestrel-ops", "analyst"),
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("must not contain the username", response.json()["detail"])
        self.assertIsNotNone(security.authenticate_user("kestrel-ops", GOOD), "and nothing changed")

    def test_changing_to_a_common_password_is_refused(self) -> None:
        response = self.client.post(
            "/api/auth/change-password",
            json={"current_password": GOOD, "new_password": "Password2024!"},
            headers=self._as("kestrel-ops", "analyst"),
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("too common", response.json()["detail"])

    def test_an_admin_cannot_create_a_user_whose_password_contains_their_name(self) -> None:
        response = self.client.post(
            "/api/users",
            json={"username": "harbour-lead", "password": "harbour-lead-4821",
                  "role": "viewer", "tenant_id": "tenant-routes"},
            headers=self._as("harbour-admin", "admin"),
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIsNone(store.get_user("harbour-lead"))

    def test_an_admin_reset_to_the_targets_name_is_refused(self) -> None:
        response = self.client.post(
            "/api/users/kestrel-ops/reset-password",
            json={"password": "kestrel-ops-reset-9"},
            headers=self._as("harbour-admin", "admin"),
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIsNotNone(security.authenticate_user("kestrel-ops", GOOD))

    def test_a_short_password_is_told_the_real_floor(self) -> None:
        # The request models keep a coarse eight-character pre-filter; the policy gives
        # the real message, because the floor is configurable and they cannot know it.
        response = self.client.post(
            "/api/auth/change-password",
            json={"current_password": GOOD, "new_password": "kestrel-4x9"},
            headers=self._as("kestrel-ops", "analyst"),
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("at least 12 characters", response.json()["detail"])


class TheOperatorExampleTest(unittest.TestCase):
    """.env.example is the list the README sends operators to, and what they copy."""

    def setUp(self) -> None:
        self.example = (Path(__file__).resolve().parent.parent / ".env.example").read_text(encoding="utf-8")

    def _value(self, name: str) -> str:
        for line in self.example.splitlines():
            if line.startswith(f"{name}="):
                return line.split("=", 1)[1].strip()
        self.fail(f"{name} is not documented in .env.example")

    def test_every_session_and_password_setting_is_documented(self) -> None:
        for name in ("DSPM_TOKEN_TTL_SECONDS", "DSPM_REFRESH_TOKEN_TTL_SECONDS", "DSPM_MAX_SESSIONS_PER_USER",
                     "DSPM_SESSION_IDLE_SECONDS", "DSPM_SESSION_TOUCH_SECONDS", "DSPM_PBKDF2_ROUNDS",
                     "DSPM_PASSWORD_MIN_LENGTH", "DSPM_BREACHED_PASSWORDS_FILE", "DSPM_ALLOW_DL_TOKEN_QUERY"):
            with self.subTest(name=name):
                self._value(name)

    def test_copying_it_does_not_reopen_what_c8_closed(self) -> None:
        self.assertEqual(self._value("DSPM_ALLOW_DL_TOKEN_QUERY"), "0",
                         "the example must not turn the query-string download token back on")
        self.assertEqual(self._value("DSPM_ALLOW_LEGACY_SHA256_PASSWORDS"), "0")
        self.assertLessEqual(int(self._value("DSPM_TOKEN_TTL_SECONDS")), 1800,
                             "the example must not lengthen the access token past C1's bound")
        self.assertGreaterEqual(int(self._value("DSPM_PASSWORD_MIN_LENGTH")), 12)


if __name__ == "__main__":
    unittest.main()
