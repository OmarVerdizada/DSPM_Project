"""A filed report is its account's alone: the folder it lives in names the exact account.

Each account's reports were kept in a folder named by _safe(account), which drops every
character but letters, digits, '-' and '_' and cuts at 80. "john.doe" and "johndoe" -
or "john@acme", the key an account gets when its sign-in name is taken in another
workspace, and "johnacme" - mapped to one folder, and each could list and download the
other's reports. The folder is now named by a hash of the workspace and the account, and
a report filed under the old name stays readable only while that folder can be nobody
else's.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from backend import store
from backend.reporting import artifacts
from backend.security import Principal

SCAN_ID = "scan-owner-001"


def _report() -> dict:
    return {
        "scan_id": SCAN_ID,
        "timestamp": "2026-10-08T09:00:00+00:00",
        "source": "local",
        "summary": {"total_files": 1},
        "files": [{
            "name": "payroll.csv", "path": r"C:\Payroll\payroll.csv", "source": "local",
            "risk": {"level": "HIGH", "score": 71, "reasons": ["Personal data"],
                     "remediation": {"actions": ["Review access"]}},
            "findings": [{"type": "pii_name", "count": 2}],
        }],
    }


class _Workspace(unittest.TestCase):
    """One workspace with one saved scan, and an artifact folder of this test's own."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        patcher = mock.patch.object(artifacts, "ARTIFACT_ROOT", Path(self.temp.name) / "artifacts")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tag = uuid4().hex[:8]
        self.tenant = f"rep-owner-{self.tag}"
        store.create_tenant(self.tenant, "Report owner")
        store.save_scan_history(self.tenant, _report())

    def _account(self, username: str) -> Principal:
        """An account of the workspace. Usernames are installation-wide; the caller makes them unique."""
        store.create_user(username, "!", "analyst", self.tenant)
        self.addCleanup(store.delete_user, username)
        return Principal(username, "analyst", self.tenant)

    def _file(self, principal: Principal) -> str:
        return artifacts.create_report_artifact(principal, {}, scan_id=SCAN_ID)["artifact_id"]

    def _file_as_before(self, principal: Principal) -> str:
        """A report filed before the folders were hashed: in the folder _safe(account) named."""
        artifact_id = self._file(principal)
        legacy = artifacts.ARTIFACT_ROOT / artifacts._safe(self.tenant) / "artifacts" / artifacts._safe(principal.subject)
        legacy.mkdir(parents=True, exist_ok=True)
        for path in artifacts._artifact_dir(principal).glob(f"{artifact_id}.*"):
            shutil.move(str(path), str(legacy / path.name))
        return artifact_id

    def assertReads(self, principal: Principal, artifact_id: str) -> None:
        self.assertEqual((artifacts.load_artifact_metadata(principal, artifact_id) or {}).get("artifact_id"),
                         artifact_id, principal.subject)
        for format in ("pdf", "html"):
            located = artifacts.artifact_file(principal, artifact_id, format)
            self.assertIsNotNone(located, f"{principal.subject} lost its {format}")
            assert located is not None
            self.assertTrue(located[0].is_file())

    def assertCannotRead(self, principal: Principal, artifact_id: str) -> None:
        self.assertIsNone(artifacts.load_artifact_metadata(principal, artifact_id), principal.subject)
        for format in ("pdf", "html"):
            self.assertIsNone(artifacts.artifact_file(principal, artifact_id, format), f"{principal.subject} {format}")


class NamesThatCleanAlikeKeepTheirReportsApartTest(_Workspace):

    def _pairs(self) -> list[tuple[str, str]]:
        long = f"{self.tag}" + "x" * 80
        return [(f"john.doe-{self.tag}", f"johndoe-{self.tag}"),
                (f"john@acme{self.tag}", f"johnacme{self.tag}"),
                (f"{long}-one", f"{long}-two")]

    def test_neither_account_of_a_pair_reads_the_others_report(self) -> None:
        for first_name, second_name in self._pairs():
            with self.subTest(first=first_name[:40], second=second_name[:40]):
                first, second = self._account(first_name), self._account(second_name)
                self.assertEqual(artifacts._safe(first_name), artifacts._safe(second_name), "the pair must clean alike")
                self.assertNotEqual(artifacts._artifact_dir(first), artifacts._artifact_dir(second))
                firsts, seconds = self._file(first), self._file(second)
                self.assertReads(first, firsts)
                self.assertReads(second, seconds)
                self.assertCannotRead(second, firsts)
                self.assertCannotRead(first, seconds)

    def test_the_same_account_name_in_another_workspace_is_another_folder(self) -> None:
        principal = self._account(f"jane.roe-{self.tag}")
        artifact_id = self._file(principal)
        elsewhere = Principal(principal.subject, "analyst", f"rep-owner-other-{self.tag}")
        self.assertNotEqual(artifacts._artifact_dir(principal).name, artifacts._artifact_dir(elsewhere).name)
        self.assertCannotRead(elsewhere, artifact_id)

    def test_an_account_named_after_anothers_folder_cannot_open_it(self) -> None:
        victim = self._account(f"alice-{self.tag}")
        artifact_id = self._file(victim)
        folder = artifacts._artifact_dir(victim).name
        lookalikes = {folder, artifacts._safe(folder)} - {victim.subject}
        self.assertTrue(lookalikes, "the folder is named for the account, not by it")
        for name in sorted(lookalikes):
            with self.subTest(name=name):
                self.assertCannotRead(self._account(name), artifact_id)


class AReportFiledBeforeTest(_Workspace):

    def test_stays_readable_by_the_only_account_its_folder_can_belong_to(self) -> None:
        owner = self._account(f"jane.roe-{self.tag}")
        self._account(f"bob-{self.tag}")
        artifact_id = self._file_as_before(owner)
        self.assertFalse((artifacts._artifact_dir(owner) / f"{artifact_id}.json").exists())
        self.assertReads(owner, artifact_id)
        self.assertCannotRead(Principal(f"bob-{self.tag}", "analyst", self.tenant), artifact_id)

    def test_is_read_by_neither_account_when_two_could_have_filed_it(self) -> None:
        dotted = self._account(f"john.doe-{self.tag}")
        plain = self._account(f"johndoe-{self.tag}")
        artifact_id = self._file_as_before(dotted)
        self.assertCannotRead(plain, artifact_id)
        self.assertCannotRead(dotted, artifact_id)

    def test_is_read_by_neither_account_when_their_names_differ_only_in_case(self) -> None:
        # NTFS compares folder names without case: "JaneRoe" and "janeroe" filed in one folder.
        upper = self._account(f"JaneRoe-{self.tag}")
        lower = self._account(f"janeroe-{self.tag}")
        artifact_id = self._file_as_before(upper)
        self.assertCannotRead(lower, artifact_id)
        self.assertCannotRead(upper, artifact_id)

    def test_is_not_read_when_another_workspaces_folder_is_the_same_on_disk(self) -> None:
        owner = self._account(f"jane.roe-{self.tag}")
        artifact_id = self._file_as_before(owner)
        self.assertReads(owner, artifact_id)
        store.create_tenant(self.tenant.upper(), "Same folder but for case")
        self.assertCannotRead(owner, artifact_id)

    def test_the_administrator_and_api_keys_are_accounts_of_every_workspace(self) -> None:
        # The platform administrator pivots into any workspace and API keys act as
        # "api-key": neither has an account row in the workspace, and both filed reports
        # in the folder their name cleaned to.
        for subject, lookalike in (("admin", "a.dmin"), ("api-key", "api.-key")):
            with self.subTest(subject=subject):
                filer = Principal(subject, "admin", self.tenant, "jwt", "default")
                artifact_id = self._file_as_before(filer)
                self.assertReads(filer, artifact_id)
                self.assertCannotRead(self._account(lookalike), artifact_id)


class RetentionFindsEveryFolderTest(_Workspace):
    """W3.5 removes the reports filed from a scan past its window, in both kinds of folder."""

    def test_a_scan_past_retention_takes_its_reports_with_it(self) -> None:
        current = self._file(self._account(f"carol-{self.tag}"))
        before = self._file_as_before(self._account(f"dave.e-{self.tag}"))
        self.assertEqual(artifacts.prune_report_artifacts(self.tenant, {SCAN_ID}), 2)
        tenant_root = artifacts.ARTIFACT_ROOT / artifacts._safe(self.tenant) / "artifacts"
        self.assertEqual([path.name for path in tenant_root.rglob("*") if path.is_file()], [])
        self.assertNotEqual(current, before)


if __name__ == "__main__":
    unittest.main()
