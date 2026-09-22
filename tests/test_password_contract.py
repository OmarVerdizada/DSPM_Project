"""M0/Q4: what the password rules and the stored hash are today, before C1 changes them.

Two things are written down here. The strength rule, because every message it raises is
shown to an operator and C1 will add rules to it. And the stored format, because changing
a hash format is the one change that can lock every account out of a customer's install:
whatever C1 does, it has to keep reading what is already in their users table.

Tests marked GAP pin behaviour a C-item is meant to change.
"""

from __future__ import annotations

import hashlib
import os
import re
import unittest
from unittest import mock

from fastapi import HTTPException

from backend.security import hash_password, validate_password_strength, verify_password

STORED = re.compile(r"^pbkdf2_sha256\$(\d+)\$([0-9a-f]{32})\$([0-9a-f]{64})$")


class TheStrengthRuleTest(unittest.TestCase):

    def assertRejected(self, password, contains: str) -> None:
        with self.assertRaises(HTTPException) as refused:
            validate_password_strength(password)
        self.assertEqual(refused.exception.status_code, 400)
        self.assertIn(contains, refused.exception.detail)

    def test_letters_and_digits_and_eight_characters_is_enough(self) -> None:
        for password in ("passwor1", "a1b2c3d4", "Parol123!", "paroləmiz1"):
            with self.subTest(password=password):
                self.assertIsNone(validate_password_strength(password))

    def test_shorter_than_eight_is_refused(self) -> None:
        self.assertRejected("abc1234", "at least 8 characters")

    def test_nothing_at_all_is_refused_as_too_short(self) -> None:
        for empty in ("", None):
            with self.subTest(value=empty):
                self.assertRejected(empty, "at least 8 characters")

    def test_longer_than_two_hundred_is_refused(self) -> None:
        # The cap is what stops a megabyte of input being run through 310k PBKDF2
        # rounds on the login path.
        self.assertIsNone(validate_password_strength("a" * 199 + "1"))
        self.assertRejected("a" * 200 + "1", "too long")

    def test_letters_only_and_digits_only_are_refused(self) -> None:
        self.assertRejected("abcdefghij", "letters and numbers")
        self.assertRejected("1234567890", "letters and numbers")

    def test_nothing_more_is_required(self) -> None:
        # GAP (C1): no case, symbol, repetition or breach-list rule today. Eight
        # characters of "passwor1" is accepted. When C1 adds a rule, this test is
        # where the new floor gets written down.
        self.assertIsNone(validate_password_strength("passwor1"))
        self.assertIsNone(validate_password_strength("11111111a"))


class TheStoredHashTest(unittest.TestCase):

    def test_the_stored_format_is_algorithm_rounds_salt_digest(self) -> None:
        stored = hash_password("an-operator-1")
        match = STORED.match(stored)
        self.assertIsNotNone(match, f"the stored format changed: {stored.split('$')[0]}")
        self.assertEqual(int(match.group(1)), 310_000, "the default work factor")

    def test_the_same_password_hashes_differently_every_time(self) -> None:
        first, second = hash_password("an-operator-1"), hash_password("an-operator-1")
        self.assertNotEqual(first, second, "the salt must be per password, not per install")
        for stored in (first, second):
            self.assertTrue(verify_password("an-operator-1", stored))

    def test_the_work_factor_is_clamped_at_both_ends(self) -> None:
        # An operator cannot weaken the install below 210k rounds by setting the
        # variable, nor make a login take a minute by setting it absurdly high.
        for configured, expected in (("1", 210_000), ("500000", 500_000), ("9000000", 1_200_000)):
            with (
                self.subTest(configured=configured),
                mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": configured}),
            ):
                self.assertEqual(int(STORED.match(hash_password("an-operator-1")).group(1)), expected)

    def test_a_hash_is_verified_with_the_rounds_it_was_written_with(self) -> None:
        # The upgrade path: a hash written when the install used fewer rounds must
        # keep verifying after the setting is raised.
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "210000"}):
            stored = hash_password("an-operator-1")
        with mock.patch.dict(os.environ, {"DSPM_PBKDF2_ROUNDS": "400000"}):
            self.assertTrue(verify_password("an-operator-1", stored))

    def test_hashing_applies_the_strength_rule(self) -> None:
        with self.assertRaises(HTTPException) as refused:
            hash_password("short1")
        self.assertEqual(refused.exception.status_code, 400)


class VerifyingAPasswordTest(unittest.TestCase):

    def setUp(self) -> None:
        self.stored = hash_password("an-operator-1")

    def test_the_right_password_verifies(self) -> None:
        self.assertTrue(verify_password("an-operator-1", self.stored))

    def test_a_near_miss_does_not(self) -> None:
        for wrong in ("an-operator-2", "An-Operator-1", "an-operator-1 ", " an-operator-1", ""):
            with self.subTest(wrong=wrong):
                self.assertFalse(verify_password(wrong, self.stored))

    def test_an_unrecognised_hash_is_simply_false(self) -> None:
        for stored in ("", "not-a-hash", "bcrypt$2b$12$something", hashlib.md5(b"x").hexdigest()):
            with self.subTest(stored=stored):
                self.assertFalse(verify_password("an-operator-1", stored))

    def test_a_truncated_stored_hash_raises_today(self) -> None:
        # GAP (C1): a row whose hash was cut short - a bad restore, a hand edit -
        # raises ValueError out of the login path instead of failing the login.
        # Sign-in turns that into a 500 rather than "invalid credentials".
        with self.assertRaises(ValueError):
            verify_password("an-operator-1", "pbkdf2_sha256$310000$abcd")

    def test_a_stored_hash_with_a_non_numeric_round_count_raises_today(self) -> None:
        # GAP (C1), same shape: the rounds field is trusted to be an integer.
        with self.assertRaises(ValueError):
            verify_password("an-operator-1", "pbkdf2_sha256$many$" + "a" * 32 + "$" + "b" * 64)


class TheLegacyHashTest(unittest.TestCase):
    """Plain SHA-256 rows from before PBKDF2. Off unless an operator turns them on."""

    def setUp(self) -> None:
        self.legacy = hashlib.sha256(b"an-operator-1").hexdigest()

    def test_a_legacy_hash_is_refused_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_ALLOW_LEGACY_SHA256_PASSWORDS", None)
            self.assertFalse(verify_password("an-operator-1", self.legacy))

    def test_a_legacy_hash_verifies_only_when_it_is_allowed(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ALLOW_LEGACY_SHA256_PASSWORDS": "1"}):
            self.assertTrue(verify_password("an-operator-1", self.legacy))
            self.assertFalse(verify_password("another-operator-1", self.legacy))

    def test_only_the_exact_opt_in_value_enables_it(self) -> None:
        for value in ("0", "true", "yes", "on", "", "TRUE"):
            with (
                self.subTest(value=value),
                mock.patch.dict(os.environ, {"DSPM_ALLOW_LEGACY_SHA256_PASSWORDS": value}),
            ):
                self.assertFalse(verify_password("an-operator-1", self.legacy))


if __name__ == "__main__":
    unittest.main()
