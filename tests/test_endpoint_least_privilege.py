"""An endpoint scan is encrypted, and does not need an administrator.

Two claims this defends:

  * the WinRM channel is never plaintext, and that is stated rather than left
    to whatever the installed auth library happens to expose;
  * scanning needs no administrator, so nothing on the scan path may quietly
    start requiring one, and the product must stop telling operators it does.
"""

from __future__ import annotations

import inspect
import unittest
from pathlib import Path

from collectors.winrm_endpoint_scanner import (
    WinRMEndpointConfig,
    WinRMEndpointScanner,
    _access_verdict,
)

SCANNER_SRC = Path("collectors/winrm_endpoint_scanner.py").read_text(encoding="utf-8")
APP_SRC = Path("backend/app.py").read_text(encoding="utf-8")
MARKUP = Path("frontend/index.html").read_text(encoding="utf-8")
SCRIPT = Path("frontend/app.js").read_text(encoding="utf-8")


def scanner(**kwargs) -> WinRMEndpointScanner:
    config = WinRMEndpointConfig(host="10.0.0.5", username="svc_scan", password="x", **kwargs)
    return WinRMEndpointScanner(config)


class ChannelEncryptionTests(unittest.TestCase):
    """A scan carries the customer's file content; it never travels in clear."""

    def test_http_demands_encryption_rather_than_hoping_for_it(self) -> None:
        # pywinrm's 'auto' encrypts only when the auth object exposes a session
        # key, and when it does not it sends plaintext over 5985 in silence.
        self.assertEqual(scanner(use_ssl=False)._winrm_message_encryption(), "always")

    def test_https_leaves_it_to_tls(self) -> None:
        # The channel is already encrypted; a second wrapping buys nothing.
        self.assertEqual(scanner(use_ssl=True)._winrm_message_encryption(), "auto")

    def test_the_policy_reaches_the_session(self) -> None:
        source = inspect.getsource(WinRMEndpointScanner._winrm_session)
        self.assertIn('"message_encryption": self._winrm_message_encryption()', source)

    def test_a_policy_change_cannot_borrow_an_old_session(self) -> None:
        identity = inspect.getsource(WinRMEndpointScanner._session_identity)
        self.assertIn("self._winrm_message_encryption()", identity)
        self.assertNotEqual(
            scanner(use_ssl=False)._session_identity(),
            scanner(use_ssl=True)._session_identity(),
        )


class ScanPrivilegeTests(unittest.TestCase):
    """Nothing on the scan path tests for administrator. Keep it that way."""

    def test_the_scan_path_has_no_administrator_gate(self) -> None:
        """Administrator may be REPORTED, never required.

        Counting IsInRole occurrences was the wrong test: check_access reports
        whether the account is an admin, which is the point of it. What matters
        is that no occurrence refuses to proceed - only local activation does,
        and that is about the DSPM host, not the target.
        """
        scan = inspect.getsource(WinRMEndpointScanner.scan)
        self.assertNotIn("Administrator", scan)
        preflight = inspect.getsource(WinRMEndpointScanner.check_access)
        self.assertIn("isAdmin", preflight)
        # Reported, not enforced: no branch in the preflight refuses on it.
        self.assertNotIn("if (-not $isAdmin)", preflight)

    def test_the_credential_fields_do_not_ask_for_an_administrator(self) -> None:
        """The SCAN credential, not the optional local-activation one.

        Preparing WinRM on this server does need an administrator and its
        fields still say so; the scan credential is what had to stop asking.
        """
        basics = MARKUP[MARKUP.index('id="endpoint-username"') - 900:]
        basics = basics[:basics.index('id="endpoint-credential-ref"')]
        self.assertIn("Scan username", basics)
        self.assertNotIn('placeholder="Administrator"', basics)
        self.assertNotIn("Admin username", basics)

    def test_a_path_denial_is_not_answered_with_use_an_admin(self) -> None:
        """One hint used to serve two different refusals.

        A single NTFS denial told the operator to find a local administrator,
        which is how a domain admin becomes the account of least resistance.
        """
        hint = APP_SRC[APP_SRC.index('code = "access_denied"'):]
        hint = hint[:hint.index("elif ")]
        self.assertIn("Remote Management Users", hint)
        self.assertIn("Grant it read access", hint)
        self.assertNotIn("credential that is local admin on the target", hint)


class AccessPreflightTests(unittest.TestCase):
    """An operator can see whether a low-privilege account is enough."""

    def test_the_scanner_can_report_what_it_can_reach(self) -> None:
        self.assertTrue(hasattr(WinRMEndpointScanner, "check_access"))
        source = inspect.getsource(WinRMEndpointScanner.check_access)
        # It reads directory entries and stages nothing beyond an empty probe.
        self.assertIn("Get-ChildItem", source)
        self.assertNotIn("Set-Service", source)
        self.assertNotIn("Enable-PSRemoting", source)

    def test_it_is_reachable_and_audited(self) -> None:
        self.assertIn('"/api/endpoint/check-access"', APP_SRC)
        self.assertIn('"endpoint.access.check"', APP_SRC)
        # Every recorded action needs a plain-language label; the audit trail
        # test enforces the general rule, this pins this one.
        self.assertIn('"endpoint.access.check":', SCRIPT)

    def test_the_console_can_ask_before_it_scans(self) -> None:
        self.assertIn('id="endpoint-access-btn"', MARKUP)
        self.assertIn("/api/endpoint/check-access", SCRIPT)

    def test_the_verdict_never_tells_an_admin_they_needed_to_be_one(self) -> None:
        admin = _access_verdict(True, 4, 4, True)
        self.assertIn("does not need administrator", admin)
        self.assertIn("Remote Management Users", admin)

    def test_the_verdict_is_useful_when_the_account_is_partly_blocked(self) -> None:
        partial = _access_verdict(False, 1, 4, True)
        self.assertIn("1 of 4", partial)
        self.assertIn("read grant", partial)

    def test_a_temp_it_cannot_write_is_reported_first(self) -> None:
        # The scan stages content there; nothing else matters if it cannot.
        blocked = _access_verdict(False, 4, 4, False)
        self.assertIn("temp", blocked.lower())


class LeastPrivilegeDocTests(unittest.TestCase):
    """The runbook has to be right about which lever actually grants access."""

    def setUp(self) -> None:
        self.doc = Path("docs/ENDPOINT_LEAST_PRIVILEGE.md").read_text(encoding="utf-8")

    def test_it_names_the_grant_that_works(self) -> None:
        self.assertIn("Remote Management Users", self.doc)
        self.assertIn("SeNetworkLogonRight", self.doc)

    def test_it_corrects_the_session_configuration_dead_end(self) -> None:
        # pywinrm opens the WinRS `cmd` shell, not Microsoft.PowerShell, so the
        # RootSDDL governs and Set-PSSessionConfiguration grants nothing.
        self.assertIn("Set-PSSessionConfiguration", self.doc)
        self.assertIn("RootSDDL", self.doc)
        self.assertIn("AllowRemoteShellAccess", self.doc)

    def test_it_rejects_backup_operators_rather_than_recommending_it(self) -> None:
        # The heading wraps in the source, so match on the claim, not the name.
        self.assertIn("SeBackupPrivilege", self.doc)
        self.assertIn("will not help", self.doc)

    def test_it_separates_the_one_time_admin_step(self) -> None:
        self.assertIn("What still needs an administrator", self.doc)
        self.assertIn("once per machine", self.doc.lower())

    def test_it_is_honest_about_the_smb_collector(self) -> None:
        # The operator asked about "the endpoint"; the encryption ceiling is on
        # the file-server path, and saying so is part of the answer.
        self.assertIn("pysmb", self.doc)
        self.assertIn("smbprotocol", self.doc)
        self.assertIn("does not affect endpoint scans", self.doc)


if __name__ == "__main__":
    unittest.main()
