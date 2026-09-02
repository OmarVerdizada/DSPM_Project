"""Track P-D: the necessary-substring prefilter must be RECALL-EXACT. For every
input, classify_content with the prefilter ON must return byte-identical findings
to the un-prefiltered full scan. If any declared anchor is not truly necessary,
the positive that triggers that rule would be wrongly skipped and these tests fail.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from classification.regex_classifier import _RULE_PREFILTER, classify_content

# A valid positive per anchored rule: it must (a) actually trigger the rule, and
# (b) contain the rule's necessary literal (so the prefilter keeps it). Validated
# rules (card/iban/bic) use known-good values.
_POSITIVES: dict[str, str] = {
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc123DEF456\n-----END RSA PRIVATE KEY-----",
    "saml_private_key": "saml signing config -----BEGIN RSA PRIVATE KEY-----",
    "aws_access_key": "key AKIAIOSFODNN7EXAMPLE here",
    "aws_secret_key": "aws_secret_access_key = wJalrXUtnFEMIbK7MDENGbPxRfiCYEXAMPLEKEY",
    "jwt": "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk",
    "connection_string": "server=db.local;uid=admin;pwd=secretvalue;db=prod;",
    "azure_storage_key": "AccountName=acct;AccountKey=abcd1234efgh5678ijkl==",
    "azure_sas_token": "sv=2021-06-08&ss=b&srt=sco&sp=rwdlacupx&spr=https&sig=abcd1234efgh5678ijklmnopqrstuv==",
    "google_api_key": "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    "gcp_service_account": '"type": "service_account", "private_key_id": "abcdef0123456789"',
    "slack_token": "xoxb-1234567890-abcdefghijkl",
    "github_token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "gitlab_token": "glpat-abcdefghij1234567890",
    "npm_token": "npm_abcdefghijklmnopqrstuvwxyz0123456789",
    "stripe_key": "sk_live_abcdefghijklmnopqrstuvwx",
    "sendgrid_key": "SG.abcdefghijklmnop.qrstuvwxyz0123456789",
    "datadog_key": "DD_API_KEY=abcdef0123456789abcdef0123456789",
    "sentry_dsn": "https://abcdef0123456789@o123.ingest.sentry.io/12345",
    "okta_token": "okta_token = abcdefghij1234567890KLMNOP",
    "auth0_secret": "AUTH0_CLIENT_SECRET = abcdefghij1234567890KLMNOPqrstuv",
    "newrelic_key": "NEW_RELIC_LICENSE_KEY = abcdefghij1234567890KLMNOPqrstuvwx1234",
    "database_uri": "postgres://admin:s3cret@db.local:5432/prod",
    "jdbc_connection": "jdbc:mysql://db.local:3306/prod;user=admin;password=secret",
    "basic_auth_url": "https://admin:s3cretpw@internal.example.com/path",
    "docker_auth_config": '{"auths": {"registry.io": {"auth": "YWRtaW46cGFzc3dvcmQ="}}}',
    "kubeconfig_secret": "apiVersion: v1\nkind: Config\ntoken: abcdef0123456789ABCDEF._-",
    "terraform_state_secret": '"password": "supersecretvalue"',
    "source_code_secret_context": "db_password = getenv()",
    "mfa_recovery_context": "MFA recovery code: ABCD-1234-EFGH",
    "swift_bic": "SWIFT: DEUTDEFF",
    "email": "contact alice@example.com now",
    "password": "password: hunter2value",
    "bearer_token": "Authorization: Bearer abcdefghij1234567890KLMNOPqrst",
    "confidential_keyword": "This document is confidential.",
    "legal_contract_context": "See the master service agreement.",
    "phi_context": "The patient diagnosis is recorded.",
    "payroll_context": "Monthly payroll and salary data.",
    "customer_context": "Attached: customer list export.",
    "board_context": "Q3 board minutes and merger notes.",
    "security_ops_context": "Ticket references CVE-2021-44228 vulnerability.",
    "repo_archive_context": "Found .git-credentials in the repo backup.",
    "build_log_context": "See the CI job log and deploy log.",
    "special_category_context": "Includes biometric and fingerprint data.",
    "retention_policy_context": "Per the records retention schedule.",
}

# A single blob that exercises many rules at once.
_KITCHEN_SINK = "\n".join(_POSITIVES.values())


class PrefilterParityTests(unittest.TestCase):
    def test_every_anchored_rule_has_a_positive_fixture(self) -> None:
        # Guards against adding an anchor without a parity fixture for it.
        missing = set(_RULE_PREFILTER) - set(_POSITIVES)
        self.assertEqual(missing, set(), f"anchored rules without a positive fixture: {missing}")

    def test_each_positive_triggers_its_rule_under_both_modes(self) -> None:
        for name, text in _POSITIVES.items():
            on = {f["type"] for f in classify_content(text)}
            off = {f["type"] for f in classify_content(text, _prefilter=False)}
            self.assertIn(name, off, f"fixture for {name} does not actually trigger it (fix the fixture)")
            self.assertIn(name, on, f"prefilter WRONGLY skipped {name} — its anchor is not truly necessary")

    def test_full_parity_on_each_positive(self) -> None:
        for name, text in _POSITIVES.items():
            self.assertEqual(
                classify_content(text), classify_content(text, _prefilter=False),
                f"prefilter changed findings for {name}",
            )

    def test_full_parity_on_kitchen_sink(self) -> None:
        self.assertEqual(classify_content(_KITCHEN_SINK), classify_content(_KITCHEN_SINK, _prefilter=False))

    def test_content_with_no_anchors_is_identical(self) -> None:
        plain = "the quick brown fox jumps over the lazy dog " * 50
        self.assertEqual(classify_content(plain), classify_content(plain, _prefilter=False))

    def test_prefilter_can_be_disabled_by_env(self) -> None:
        # With the prefilter env-disabled, the default call equals the forced-full scan.
        from unittest import mock
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_PREFILTER": "0"}):
            self.assertEqual(classify_content(_KITCHEN_SINK), classify_content(_KITCHEN_SINK, _prefilter=False))


class PrefilterCorpusParityTests(unittest.TestCase):
    """Parity across the real synthetic estate, if present (skipped in CI where the
    gitignored corpus is absent)."""

    def test_parity_over_enterprise_test_data(self) -> None:
        root = Path(__file__).resolve().parent.parent / "enterprise_test_data"
        if not root.exists():
            self.skipTest("enterprise_test_data not present")
        checked = 0
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not text:
                continue
            self.assertEqual(
                classify_content(text), classify_content(text, _prefilter=False),
                f"prefilter changed findings for {path.name}",
            )
            checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
