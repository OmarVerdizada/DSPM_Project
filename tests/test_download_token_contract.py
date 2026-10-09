"""Artifact download tokens: M0/Q4's characterization, rewritten as C8 changed them.

Q4 wrote down what a download token did before C8 touched it - including four known
gaps, marked GAP, each saying what the fix would turn it into. C8 has landed, so those
four are now the positive regressions Q4 asked for:

  * **Single use.** It was reusable for its whole five-minute life, so a link copied out
    of a browser, a screen share or a log was a working credential for anyone.
  * **Bound to the account.** It never re-read the account: a disabled user, a signed-out
    session and a demoted role all still downloaded. It now dies with the session that
    minted it, with the account, and with any change of role or tenant.
  * **No query string.** It was accepted from `?dl_token=` by default, and a query string
    is written to every proxy and access log on the path. It is now refused unless an
    operator turns it back on for a non-production install, and production ignores that.
  * **Minted before C8** (no id to spend) is refused rather than grandfathered.

The contracts Q4 held stay as they were: a token is bound to one artifact, it expires,
it is signed, and nothing about it is trusted when the signature does not check out.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from backend import security, store
from backend.security import (
    ARTIFACT_DL_TOKEN_TTL_SECONDS,
    create_artifact_download_token,
    require_artifact_principal,
    verify_artifact_download_token,
)

ARTIFACT = "a" * 32
OTHER_ARTIFACT = "b" * 32
TENANT = "tenant-a"
USER = "analyst-1"


def _sign_claims(claims: dict, *, secret: str | None = None) -> str:
    """Mint a token the way the product does, so a test can vary one claim at a time."""
    payload = security._b64url(json.dumps(claims, separators=(",", ":")).encode())
    key = (secret if secret is not None else security.SECRET_KEY).encode()
    signature = security._b64url(hmac.new(key, f"artifact_dl.{payload}".encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


class _AccountCase(unittest.TestCase):
    """One tenant, one analyst with a live session, in a database of this test's own."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "downloads.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant(TENANT, "Downloads")
        store.create_user(USER, security.hash_password("an-analyst-1"), "analyst", TENANT)
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        self.session = security.create_token(USER, "analyst", TENANT)
        self.sid = json.loads(security._b64url_decode(self.session.split(".")[1]))["jti"]

    def _token(self, artifact: str = ARTIFACT, **kwargs) -> str:
        options = {"session_id": self.sid}
        options.update(kwargs)
        return create_artifact_download_token(artifact, TENANT, USER, "analyst", **options)

    def _claims(self, **overrides) -> dict:
        claims = {"aid": ARTIFACT, "tenant": TENANT, "sub": USER, "role": "analyst",
                  "exp": int(time.time()) + 300, "jti": os.urandom(12).hex(), "sid": self.sid}
        claims.update(overrides)
        return claims


class ADownloadTokenCarriesTheCallerTest(_AccountCase):
    """The identity the artifact route acts as when a token is presented."""

    def test_a_fresh_token_verifies_for_its_own_artifact(self) -> None:
        principal = verify_artifact_download_token(self._token(), ARTIFACT)
        self.assertIsNotNone(principal)
        self.assertEqual((principal.subject, principal.role, principal.tenant_id), (USER, "analyst", TENANT))
        self.assertEqual(principal.auth_type, "artifact_dl_token",
                         "the route must be able to tell a download token from a session")
        self.assertEqual(principal.session_id, self.sid, "and which session it came from")

    def test_the_default_life_is_five_minutes(self) -> None:
        self.assertEqual(ARTIFACT_DL_TOKEN_TTL_SECONDS, 300)

    def test_every_role_is_carried_while_the_account_holds_it(self) -> None:
        for role in ("admin", "analyst", "viewer"):
            with self.subTest(role=role):
                store.update_user_role(USER, role)
                token = create_artifact_download_token(ARTIFACT, TENANT, USER, role, session_id=self.sid)
                self.assertEqual(verify_artifact_download_token(token, ARTIFACT).role, role)


class ADownloadTokenIsBoundTest(_AccountCase):
    """The bindings that make it a token for one file rather than a skeleton key."""

    def test_a_token_for_another_artifact_is_refused(self) -> None:
        self.assertIsNone(verify_artifact_download_token(self._token(), OTHER_ARTIFACT))

    def test_an_expired_token_is_refused(self) -> None:
        self.assertIsNone(verify_artifact_download_token(self._token(ttl_seconds=-1), ARTIFACT))

    def test_a_token_signed_with_another_key_is_refused(self) -> None:
        token = _sign_claims(self._claims(), secret="a-different-install-secret")
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT),
                          "a token minted on another install must not open this one")

    def test_claims_cannot_be_edited_without_the_key(self) -> None:
        payload, _, signature = self._token().partition(".")
        claims = json.loads(security._b64url_decode(payload))
        claims["role"] = "admin"
        forged = security._b64url(json.dumps(claims, separators=(",", ":")).encode())
        self.assertIsNone(verify_artifact_download_token(f"{forged}.{signature}", ARTIFACT))

    def test_a_tampered_signature_is_refused(self) -> None:
        payload, _, signature = self._token().partition(".")
        flipped = ("X" if signature[0] != "X" else "Y") + signature[1:]
        self.assertIsNone(verify_artifact_download_token(f"{payload}.{flipped}", ARTIFACT))

    def test_an_incomplete_claim_set_is_refused(self) -> None:
        # Signed by us, so only the claim check can refuse these.
        for description, claims in (
            ("no artifact", self._claims(aid="")),
            ("no tenant", self._claims(tenant="")),
            ("no subject", self._claims(sub="")),
            ("a role the system does not have", self._claims(role="root")),
            ("a role that is empty", self._claims(role="")),
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
        list_payload = security._b64url(b"[1, 2, 3]")
        list_signature = security._b64url(
            hmac.new(security.SECRET_KEY.encode(), f"artifact_dl.{list_payload}".encode(), hashlib.sha256).digest()
        )
        for description, token in (
            ("empty", ""),
            ("none", None),
            ("no separator", "justonepart"),
            ("only a separator", "."),
            ("not base64", "!!!!.####"),
            ("signed but not JSON", f"{payload}.{signature}"),
            ("signed JSON that is not an object", f"{list_payload}.{list_signature}"),
            ("an extra segment", self._token() + ".extra"),
        ):
            with self.subTest(description):
                self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))


class WhatADownloadTokenNowChecksTest(_AccountCase):
    """C8. Each of these was a GAP assertion in Q4 that the opposite was true."""

    def test_it_can_be_used_exactly_once(self) -> None:
        token = self._token()
        self.assertIsNotNone(verify_artifact_download_token(token, ARTIFACT))
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT),
                          "a copied link must not be a second download")

    def test_two_requests_racing_with_one_link_cannot_both_succeed(self) -> None:
        token = self._token()
        results: list[object] = []
        barrier = threading.Barrier(6)

        def attempt() -> None:
            barrier.wait()
            results.append(verify_artifact_download_token(token, ARTIFACT))

        threads = [threading.Thread(target=attempt) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sum(1 for result in results if result is not None), 1,
                         "the spend is the check - exactly one winner")

    def test_checking_without_spending_is_possible(self) -> None:
        token = self._token()
        self.assertIsNotNone(verify_artifact_download_token(token, ARTIFACT, consume=False))
        self.assertIsNotNone(verify_artifact_download_token(token, ARTIFACT))

    def test_signing_out_kills_the_link(self) -> None:
        token = self._token()
        security.revoke_token(self.session)
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))

    def test_a_password_change_kills_the_link(self) -> None:
        token = self._token()
        store.revoke_sessions_for_user(USER)
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))

    def test_a_disabled_account_kills_the_link(self) -> None:
        token = self._token()
        store.update_user_active(USER, False)
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))

    def test_a_demoted_account_kills_the_link(self) -> None:
        # Minted under one set of privileges is not re-interpreted under another.
        token = self._token()
        store.update_user_role(USER, "viewer")
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))

    def test_a_promoted_account_kills_the_link_too(self) -> None:
        # Any change of role, not only a lowering: the link carries what it was minted with.
        token = self._token()
        store.update_user_role(USER, "admin")
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))

    def test_an_account_that_no_longer_exists_is_refused(self) -> None:
        token = create_artifact_download_token(ARTIFACT, TENANT, "gone-user", "analyst", session_id=self.sid)
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))

    def test_a_token_with_no_session_is_refused(self) -> None:
        self.assertIsNone(verify_artifact_download_token(self._token(session_id=""), ARTIFACT))

    def test_a_token_for_another_tenant_is_refused(self) -> None:
        store.create_tenant("tenant-b", "Other")
        token = create_artifact_download_token(ARTIFACT, "tenant-b", USER, "analyst", session_id=self.sid)
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT),
                          "the account does not belong to that tenant")

    def test_a_platform_admin_pivoted_into_a_tenant_can_still_download(self) -> None:
        store.create_tenant("tenant-b", "Other")
        # The built-in platform admin ("admin" in "default") is seeded at app startup;
        # this test's database was built without it.
        if store.get_user("admin") is None:
            if not store.tenant_exists("default"):
                store.create_tenant("default", "Default")
            store.create_user("admin", security.hash_password("platform-admin-1"), "admin", "default")
        admin_session = security.create_token("admin", "admin", "default")
        admin_sid = json.loads(security._b64url_decode(admin_session.split(".")[1]))["jti"]
        token = create_artifact_download_token(ARTIFACT, "tenant-b", "admin", "admin", session_id=admin_sid)
        principal = verify_artifact_download_token(token, ARTIFACT)
        self.assertIsNotNone(principal)
        self.assertEqual(principal.tenant_id, "tenant-b")

    def test_a_token_minted_before_c8_is_refused(self) -> None:
        # No jti means nothing to spend: it could never be single use.
        legacy = _sign_claims({"aid": ARTIFACT, "tenant": TENANT, "sub": USER, "role": "analyst",
                               "exp": int(time.time()) + 300, "sid": self.sid})
        # Refused even when the caller only checks and does not spend: the id is what
        # makes it single use, and a token that cannot be spent must not be honoured.
        self.assertIsNone(verify_artifact_download_token(legacy, ARTIFACT, consume=False))
        self.assertIsNone(verify_artifact_download_token(legacy, ARTIFACT))

    def test_an_api_key_caller_is_bound_by_single_use_and_its_life(self) -> None:
        # No session to bind to: the key holder fetches with the key itself.
        token = create_artifact_download_token(ARTIFACT, TENANT, "api-key", "analyst")
        self.assertIsNotNone(verify_artifact_download_token(token, ARTIFACT))
        self.assertIsNone(verify_artifact_download_token(token, ARTIFACT))


class HowTheArtifactRouteAcceptsATokenTest(_AccountCase):
    """require_artifact_principal: which delivery is taken, and the fallback."""

    def setUp(self) -> None:
        super().setUp()
        self.token = self._token()

    def test_the_header_is_accepted(self) -> None:
        principal = require_artifact_principal(ARTIFACT, x_artifact_token=self.token)
        self.assertEqual(principal.auth_type, "artifact_dl_token")

    def test_the_query_string_is_refused_by_default(self) -> None:
        # C8: a token in a query string lands in every proxy and access log on the path.
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local"}):
            os.environ.pop("DSPM_ALLOW_DL_TOKEN_QUERY", None)
            with self.assertRaises(HTTPException) as refused:
                require_artifact_principal(ARTIFACT, dl_token=self.token)
        self.assertEqual(refused.exception.status_code, 401)

    def test_an_operator_can_allow_it_outside_production(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local", "DSPM_ALLOW_DL_TOKEN_QUERY": "1"}):
            principal = require_artifact_principal(ARTIFACT, dl_token=self.token)
        self.assertEqual(principal.subject, USER)

    def test_production_ignores_the_opt_in(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production", "DSPM_ALLOW_DL_TOKEN_QUERY": "1"}), \
             self.assertRaises(HTTPException) as refused:
            require_artifact_principal(ARTIFACT, dl_token=self.token)
        self.assertEqual(refused.exception.status_code, 401)

    def test_a_header_token_is_taken_before_the_query_even_when_it_is_junk(self) -> None:
        # The header is chosen first and the query is then never looked at, so a
        # broken header does not silently fall through to a good query token - it
        # falls through to ordinary authentication, which here has no credentials.
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local", "DSPM_ALLOW_DL_TOKEN_QUERY": "1"}), \
             self.assertRaises(HTTPException) as refused:
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

    def test_the_owner_can_still_fetch_with_their_own_session(self) -> None:
        # A spent download token is not the end of the artifact: the session that owns
        # it can fetch it again with its bearer token.
        from fastapi.security import HTTPAuthorizationCredentials

        require_artifact_principal(ARTIFACT, x_artifact_token=self.token)
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=self.session)
        principal = require_artifact_principal(ARTIFACT, x_artifact_token=self.token, credentials=credentials)
        self.assertEqual(principal.auth_type, "jwt")


class ThroughTheReportRouteTest(_AccountCase):
    """C8's gate - expired, replayed, revoked and demoted links - through the HTTP path
    the console takes: file a report, fetch it once with the header, and see what every
    other attempt gets."""

    def setUp(self) -> None:
        super().setUp()
        from fastapi.testclient import TestClient

        from backend.app import app
        from backend.reporting import artifacts

        patcher = mock.patch.object(artifacts, "ARTIFACT_ROOT", Path(self.temp_dir.name) / "artifacts")
        patcher.start()
        self.addCleanup(patcher.stop)
        store.save_scan_history(TENANT, {
            "scan_id": "scan-dl-1", "timestamp": "2026-09-24T08:00:00+00:00", "source": "local",
            "summary": {"total_files": 1},
            "files": [{"name": "cards.csv", "path": r"C:\Finance\cards.csv", "source": "local",
                       "risk": {"level": "HIGH", "score": 70, "reasons": ["CHD"],
                                "remediation": {"actions": ["Restrict the share"]}},
                       "findings": [{"type": "pci_chd_pan", "count": 1}]}],
        })
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.bearer = {"Authorization": f"Bearer {self.session}"}

    def _file(self) -> dict:
        response = self.client.post("/api/v1/reports", json={"scan_id": "scan-dl-1"}, headers=self.bearer)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _fetch(self, artifact: dict, **headers) -> int:
        return self.client.get(f"{artifact['artifact_path']}?inline=1", headers=headers).status_code

    def test_the_console_path_works_once(self) -> None:
        artifact = self._file()
        response = self.client.get(f"{artifact['artifact_path']}?inline=1",
                                   headers={"X-Artifact-Token": artifact["download_token"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content[:5], b"%PDF-")

    def test_a_replayed_link_is_refused(self) -> None:
        artifact = self._file()
        header = {"X-Artifact-Token": artifact["download_token"]}
        self.assertEqual(self._fetch(artifact, **header), 200)
        self.assertEqual(self._fetch(artifact, **header), 401)

    def test_a_link_from_a_signed_out_session_is_refused(self) -> None:
        artifact = self._file()
        self.client.post("/api/auth/logout", headers=self.bearer)
        store._forget_revocation()
        self.assertEqual(self._fetch(artifact, **{"X-Artifact-Token": artifact["download_token"]}), 401)

    def test_a_link_for_a_demoted_account_is_refused(self) -> None:
        artifact = self._file()
        store.update_user_role(USER, "viewer")
        self.assertEqual(self._fetch(artifact, **{"X-Artifact-Token": artifact["download_token"]}), 401)

    def test_an_expired_link_is_refused(self) -> None:
        with mock.patch.object(security, "ARTIFACT_DL_TOKEN_TTL_SECONDS", -1), \
             mock.patch("backend.reporting.artifacts.create_artifact_download_token",
                        side_effect=lambda *a, **k: create_artifact_download_token(*a, ttl_seconds=-1, **k)):
            artifact = self._file()
        self.assertEqual(self._fetch(artifact, **{"X-Artifact-Token": artifact["download_token"]}), 401)

    def test_a_link_in_the_query_string_is_refused(self) -> None:
        artifact = self._file()
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local"}):
            os.environ.pop("DSPM_ALLOW_DL_TOKEN_QUERY", None)
            status = self.client.get(
                f"{artifact['artifact_path']}?inline=1&dl_token={artifact['download_token']}").status_code
        self.assertEqual(status, 401)

    def test_the_owner_can_fetch_again_with_their_own_session(self) -> None:
        artifact = self._file()
        self.assertEqual(self._fetch(artifact, **{"X-Artifact-Token": artifact["download_token"]}), 200)
        self.assertEqual(self._fetch(artifact, **self.bearer), 200,
                         "a spent link is not the end of the report")

    def test_nothing_the_route_returns_is_a_credential_in_a_url(self) -> None:
        artifact = self._file()
        for key in ("download_url", "preview_url", "html_download_url", "artifact_path"):
            with self.subTest(key):
                self.assertNotIn("dl_token", artifact[key])


if __name__ == "__main__":
    unittest.main()
