"""M0/Q4: what an artifact download token does today, written down before C8 changes it.

A download token is a bearer credential in a URL. C8 is going to narrow it - single
use, a shorter life, no query-string delivery - and the only way to tell a narrowing
from a breakage is to have today's behaviour written down first. So these tests are
deliberately two kinds at once:

  * CONTRACT - the parts that must keep working however C8 lands: a token is bound to
    one artifact, it expires, it is signed, and nothing about it is trusted when the
    signature does not check out.
  * KNOWN GAP - the parts C8 is meant to change. They are marked GAP and say what the
    fix turns them into, so the test fails loudly when the behaviour moves and the
    person who moved it knows whether they meant to.

A GAP test failing is not a regression. It is the signal to rewrite that test to the
new behaviour, in the commit that changes it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import unittest
from unittest import mock

from fastapi import HTTPException

from backend import security
from backend.security import (
    ARTIFACT_DL_TOKEN_TTL_SECONDS,
    create_artifact_download_token,
    require_artifact_principal,
    verify_artifact_download_token,
)

ARTIFACT = "a" * 32
OTHER_ARTIFACT = "b" * 32


def _sign_claims(claims: dict, *, secret: str | None = None) -> str:
    """Mint a token the way the product does, so a test can vary one claim at a time."""
    payload = security._b64url(json.dumps(claims, separators=(",", ":")).encode())
    key = (secret if secret is not None else security.SECRET_KEY).encode()
    signature = security._b64url(hmac.new(key, f"artifact_dl.{payload}".encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def _claims(**overrides) -> dict:
    claims = {
        "aid": ARTIFACT,
        "tenant": "tenant-a",
        "sub": "analyst-1",
        "role": "analyst",
        "exp": int(time.time()) + 300,
    }
    claims.update(overrides)
    return claims


class ADownloadTokenCarriesTheCallerTest(unittest.TestCase):
    """The identity the artifact route acts as when a token is presented."""

    def test_a_fresh_token_verifies_for_its_own_artifact(self) -> None:
        token = create_artifact_download_token(ARTIFACT, "tenant-a", "analyst-1", "analyst")
        principal = verify_artifact_download_token(token, ARTIFACT)
        self.assertIsNotNone(principal)
        self.assertEqual((principal.subject, principal.role, principal.tenant_id),
                         ("analyst-1", "analyst", "tenant-a"))
        self.assertEqual(principal.auth_type, "artifact_dl_token",
                         "the route must be able to tell a download token from a session")

    def test_the_default_life_is_five_minutes(self) -> None:
        self.assertEqual(ARTIFACT_DL_TOKEN_TTL_SECONDS, 300)

    def test_every_role_the_system_has_is_carried_verbatim(self) -> None:
        for role in ("admin", "analyst", "viewer"):
            with self.subTest(role=role):
                token = create_artifact_download_token(ARTIFACT, "tenant-a", "someone", role)
                self.assertEqual(verify_artifact_download_token(token, ARTIFACT).role, role)


class ADownloadTokenIsBoundTest(unittest.TestCase):
    """The bindings that make it a token for one file rather than a skeleton key."""

    def test_a_token_for_another_artifact_is_refused(self) -> None:
        token = create_artifact_download_token(ARTIFACT, "tenant-a", "analyst-1", "analyst")
        self.assertIsNone(verify_artifact_download_token(token, OTHER_ARTIFACT))

    def test_an_expired_token_is_refused(self) -> None:
        token = create_artifact_download_token(ARTIFACT, "tenant-a", "analyst-1", "analyst", ttl_seconds=-1)
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))

    def test_a_token_signed_with_another_key_is_refused(self) -> None:
        token = _sign_claims(_claims(), secret="a-different-install-secret")
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT),
                          "a token minted on another install must not open this one")

    def test_claims_cannot_be_edited_without_the_key(self) -> None:
        payload, _, signature = create_artifact_download_token(
            ARTIFACT, "tenant-a", "viewer-1", "viewer").partition(".")
        claims = json.loads(security._b64url_decode(payload))
        claims["role"] = "admin"
        forged = security._b64url(json.dumps(claims, separators=(",", ":")).encode())
        self.assertIsNone(verify_artifact_download_token(f"{forged}.{signature}", ARTIFACT))

    def test_a_tampered_signature_is_refused(self) -> None:
        token = create_artifact_download_token(ARTIFACT, "tenant-a", "analyst-1", "analyst")
        payload, _, signature = token.partition(".")
        flipped = ("X" if signature[0] != "X" else "Y") + signature[1:]
        self.assertIsNone(verify_artifact_download_token(f"{payload}.{flipped}", ARTIFACT))

    def test_an_incomplete_claim_set_is_refused(self) -> None:
        # Signed by us, so only the claim check can refuse these.
        for description, claims in (
            ("no artifact", _claims(aid="")),
            ("no tenant", _claims(tenant="")),
            ("no subject", _claims(sub="")),
            ("a role the system does not have", _claims(role="root")),
            ("a role that is empty", _claims(role="")),
        ):
            with self.subTest(description):
                self.assertIsNone(verify_artifact_download_token(_sign_claims(claims), ARTIFACT))

    def test_malformed_tokens_are_refused_rather_than_raising(self) -> None:
        # The artifact route calls this on attacker-controlled input, so "no"
        # has to be a return value, not an exception that becomes a 500.
        payload = security._b64url(b"not json at all")  # correctly signed, still not claims
        signature = security._b64url(
            hmac.new(security.SECRET_KEY.encode(), f"artifact_dl.{payload}".encode(), hashlib.sha256).digest()
        )
        for description, token in (
            ("empty", ""),
            ("none", None),
            ("no separator", "justonepart"),
            ("only a separator", "."),
            ("not base64", "!!!!.####"),
            ("signed but not JSON", f"{payload}.{signature}"),
            ("an extra segment", create_artifact_download_token(ARTIFACT, "t", "s", "viewer") + ".extra"),
        ):
            with self.subTest(description):
                self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))


class WhatADownloadTokenDoesNotCheckTest(unittest.TestCase):
    """GAP (C8). A verified token is trusted entirely on its own contents.

    Nothing about the account is re-read: not whether the user still exists, not
    whether they are still active, not whether their session was signed out, and not
    whether their role was lowered since the token was minted. For a five-minute
    token handed to the caller who just authenticated that is a deliberate trade, and
    it is the trade C8 revisits.
    """

    def test_no_account_state_is_consulted(self) -> None:
        token = create_artifact_download_token(ARTIFACT, "tenant-a", "analyst-1", "analyst")
        with mock.patch.object(security, "get_user") as get_user, \
             mock.patch.object(security, "is_token_revoked") as is_revoked:
            principal = verify_artifact_download_token(token, ARTIFACT)
        self.assertIsNotNone(principal)
        get_user.assert_not_called()   # C8: an account disabled mid-window still downloads
        is_revoked.assert_not_called()  # C8: signing out does not stop an issued download token

    def test_a_token_is_reusable_until_it_expires(self) -> None:
        token = create_artifact_download_token(ARTIFACT, "tenant-a", "analyst-1", "analyst")
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                self.assertIsNotNone(verify_artifact_download_token(token, ARTIFACT),
                                     "C8 turns this into single use; rewrite this test then")

    def test_the_role_is_the_one_it_was_minted_with(self) -> None:
        # Demoted to viewer in the database a second later: the token still says admin.
        token = create_artifact_download_token(ARTIFACT, "tenant-a", "someone", "admin")
        self.assertEqual(verify_artifact_download_token(token, ARTIFACT).role, "admin")


class HowTheArtifactRouteAcceptsATokenTest(unittest.TestCase):
    """require_artifact_principal: which of the two deliveries wins, and the fallback."""

    def setUp(self) -> None:
        self.token = create_artifact_download_token(ARTIFACT, "tenant-a", "analyst-1", "analyst")

    def test_the_header_is_accepted(self) -> None:
        principal = require_artifact_principal(ARTIFACT, x_artifact_token=self.token)
        self.assertEqual(principal.auth_type, "artifact_dl_token")

    def test_the_query_string_is_accepted_by_default(self) -> None:
        # GAP (C8): a token in the query lands in every proxy and access log on the
        # path. It is on by default for the popup case; C8 flips this default.
        self.assertTrue(security.ALLOW_DL_TOKEN_QUERY)
        principal = require_artifact_principal(ARTIFACT, dl_token=self.token)
        self.assertEqual(principal.subject, "analyst-1")

    def test_the_query_string_is_ignored_when_it_is_turned_off(self) -> None:
        with (
            mock.patch.object(security, "ALLOW_DL_TOKEN_QUERY", False),
            self.assertRaises(HTTPException) as refused,
        ):
            require_artifact_principal(ARTIFACT, dl_token=self.token)
        self.assertEqual(refused.exception.status_code, 401)

    def test_a_header_token_is_taken_before_the_query_even_when_it_is_junk(self) -> None:
        # The header is chosen first and the query is then never looked at, so a
        # broken header does not silently fall through to a good query token - it
        # falls through to ordinary authentication, which here has no credentials.
        with self.assertRaises(HTTPException) as refused:
            require_artifact_principal(ARTIFACT, dl_token=self.token, x_artifact_token="junk")
        self.assertEqual(refused.exception.status_code, 401)

    def test_a_token_for_another_artifact_falls_back_to_ordinary_authentication(self) -> None:
        with self.assertRaises(HTTPException) as refused:
            require_artifact_principal(OTHER_ARTIFACT, x_artifact_token=self.token)
        self.assertEqual(refused.exception.status_code, 401)
        self.assertEqual(refused.exception.detail, "Authentication required")

    def test_no_token_at_all_falls_back_to_ordinary_authentication(self) -> None:
        with self.assertRaises(HTTPException) as refused:
            require_artifact_principal(ARTIFACT)
        self.assertEqual(refused.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
