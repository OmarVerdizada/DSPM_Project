"""D7: who can read the sensitive files - from the ACLs scans already read.

Gate line: "Fixture principal-to-file query is accurate and tenant-isolated." And the
defects D7 found on the way: a Deny entry read like an Allow, "Remote Desktop Users"
counted as "Users", and "writable" meaning anyone - Administrators included - could write.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import security, store
from backend.app import app
from collectors import win_security
from permissions import acl_analyzer
from permissions.acl_analyzer import analyze_acl, effective_access

ROOT = Path(__file__).resolve().parents[1]
GUESTS = "S-1-5-32-546"
CARD = "4111 1111 1111 1111"


def entry(principal: str, rights: str = "Read", kind: str = "allow", sid: str = "", mask: int | None = None) -> dict:
    item = {"principal": principal, "sid": sid, "rights": rights, "type": kind}
    if mask is not None:
        item["mask"] = mask
    return item


class TheAnalysisTest(unittest.TestCase):

    def test_a_deny_cancels_the_same_principals_allow(self) -> None:
        acl = {"entries": [entry("Everyone", "Read", sid="S-1-1-0"), entry("Everyone", "Read", "deny", sid="S-1-1-0")]}
        self.assertFalse(analyze_acl(acl)["wide_access"], "Everyone: Deny is not broad access")
        self.assertEqual(effective_access(acl), [])
        partly = {"entries": [entry("Everyone", "Modify", sid="S-1-1-0"),
                              entry("Everyone", "Write", "deny", sid="S-1-1-0")]}
        verdict = analyze_acl(partly)
        self.assertTrue(verdict["wide_access"])
        self.assertFalse(verdict["writable"], "reading allowed, writing denied")

    def test_broad_groups_are_named_exactly_or_known_by_sid(self) -> None:
        for principal, sid in (("BUILTIN\\Users", ""), ("Everyone", ""), ("CORP\\Domain Users", ""),
                               ("NT AUTHORITY\\Authenticated Users", ""), ("renamed", "S-1-5-11"),
                               ("CORP\\renamed", "S-1-5-21-1-2-3-513")):
            with self.subTest(principal=principal, sid=sid):
                self.assertTrue(analyze_acl({"entries": [entry(principal, sid=sid)]})["wide_access"])
        for principal in ("BUILTIN\\Remote Desktop Users", "BUILTIN\\Power Users", "CORP\\Finance Users",
                          "CORP\\users-archive"):
            with self.subTest(principal=principal):
                self.assertFalse(analyze_acl({"entries": [entry(principal)]})["wide_access"], principal)

    def test_writable_means_a_broad_group_can_write(self) -> None:
        administrators = {"entries": [entry("BUILTIN\\Administrators", "FullControl", sid="S-1-5-32-544"),
                                      entry("CORP\\alice", "Modify")]}
        verdict = analyze_acl(administrators)
        self.assertFalse(verdict["writable"], "an administrator or the owner writing is not exposure")
        self.assertTrue(verdict["privileged_access"])
        self.assertTrue(analyze_acl({"entries": [entry("Everyone", "Modify", sid="S-1-1-0")]})["writable"])

    def test_rights_from_masks_including_generic_ones(self) -> None:
        self.assertTrue(analyze_acl({"entries": [entry("Everyone", "", sid="S-1-1-0", mask=0x80000000)]})["wide_access"])
        self.assertTrue(analyze_acl({"entries": [entry("Everyone", "", sid="S-1-1-0", mask=0x10000000)]})["writable"])
        self.assertFalse(analyze_acl({"entries": [entry("Everyone", "", sid="S-1-1-0", mask=0x100000)]})["wide_access"],
                         "Synchronize alone reads nothing")

    def test_service_and_indexer_accounts_are_flagged(self) -> None:
        for principal, sid in (("NT SERVICE\\WSearch", ""), ("IIS APPPOOL\\intranet", ""), ("x", "S-1-5-80-1-2-3"),
                               ("NT AUTHORITY\\NETWORK SERVICE", "S-1-5-20")):
            with self.subTest(principal=principal):
                self.assertEqual(analyze_acl({"entries": [entry(principal, sid=sid)]})["service_readers"], [principal])
        with mock.patch.dict(os.environ, {"DSPM_INDEXER_PRINCIPALS": "CORP\\svc-crawl, spider"}):
            self.assertEqual(analyze_acl({"entries": [entry("CORP\\svc-crawl")]})["service_readers"], ["CORP\\svc-crawl"])
            self.assertEqual(analyze_acl({"entries": [entry("CORP\\Spider")]})["service_readers"], ["CORP\\Spider"])
        self.assertEqual(analyze_acl({"entries": [entry("CORP\\svc-crawl")]})["service_readers"], [])

    def test_older_records_read_as_allow_entries_unless_they_carry_types(self) -> None:
        legacy = {"principals": ["Everyone", "CORP\\bob"], "permissions": ["ReadAndExecute, Synchronize", "Modify"]}
        self.assertTrue(analyze_acl(legacy)["wide_access"])
        typed = dict(legacy, types=["deny", "allow"])
        self.assertFalse(analyze_acl(typed)["wide_access"], "a PowerShell read that reported Deny")

    def test_the_analysis_is_part_of_the_reuse_signature(self) -> None:
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        engine = DSPMDiscoveryEngine(ScanConfig(tenant_id="t", local_path="."))
        self.assertIn(acl_analyzer.ACL_ANALYSIS_VERSION, engine._version_sig())


@unittest.skipUnless(sys.platform == "win32", "Windows security descriptors")
class TheWindowsReadTest(unittest.TestCase):

    def test_the_entries_say_allow_or_deny_and_whether_inherited(self) -> None:
        folder = ROOT / "tmp" / f"d7-acl-{os.getpid()}"
        folder.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, folder, True)
        target = folder / "guarded.txt"
        target.write_text("x", encoding="utf-8")
        for grant in (["/grant", f"*{GUESTS}:(R)"], ["/deny", f"*{GUESTS}:(W)"]):
            subprocess.run(["icacls", str(target), *grant], check=True, capture_output=True)
        acl = win_security.security_for_path(str(target))
        guests = [item for item in acl["entries"] if item["sid"] == GUESTS]
        self.assertEqual(sorted(item["type"] for item in guests), ["allow", "deny"])
        self.assertTrue(all(not item["inherited"] for item in guests), "set on the file itself")
        self.assertTrue(any(item["inherited"] for item in acl["entries"]), "the folder's entries are inherited")
        self.assertEqual(len(acl["principals"]), len(acl["entries"]), "the parallel lists are unchanged")
        access = {item.key: item for item in effective_access(acl)}
        self.assertTrue(access[GUESTS].read)
        self.assertFalse(access[GUESTS].write, "the deny removes write")


@unittest.skipUnless(sys.platform == "win32", "icacls sets the fixture's ACLs")
class WhoCanReadTheSensitiveFilesTest(unittest.TestCase):
    """A scanned fixture: Guests can read a file with a card number, can read a file with
    nothing in it, and are denied a second card file."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d7.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in ("t-acc", "t-other"):
            store.create_tenant(tenant, tenant)
        store.create_user("acc-admin", security.hash_password("Kestrel-lantern-4471"), "admin", "t-acc")
        store.create_user("other-admin", security.hash_password("Kestrel-lantern-4471"), "admin", "t-other")
        self.client = TestClient(app)
        self.relative = Path("tmp") / f"d7-estate-{os.getpid()}-{id(self)}"
        self.folder = ROOT / self.relative
        self.folder.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.payroll = self._file("payroll.txt", f"Payroll export\nPrimary card {CARD} for travel.\n", "/grant", "R")
        self.notes = self._file("notes.txt", "Office move planning, nothing sensitive.\n", "/grant", "R")
        self.denied = self._file("card-denied.txt", f"Backup card {CARD}.\n", "/grant", "R")
        subprocess.run(["icacls", str(self.denied), "/deny", f"*{GUESTS}:(R)"], check=True, capture_output=True)

    def _file(self, name: str, text: str, action: str, right: str) -> Path:
        path = self.folder / name
        path.write_text(text, encoding="utf-8")
        subprocess.run(["icacls", str(path), action, f"*{GUESTS}:({right})"], check=True, capture_output=True)
        return path

    def as_(self, user: str, tenant: str) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, 'admin', tenant)}"}

    def scan(self, label: str = "") -> None:
        with mock.patch("backend.app.partitioned_scans_enabled", return_value=False):
            response = self.client.post("/api/scan", headers=self.as_("acc-admin", "t-acc"), json={
                "local_path": self.relative.as_posix(), "async_scan": False, "save_report": True,
                "compact_result": False, "incremental_enabled": False, "scan_label": label})
        self.assertEqual(response.status_code, 200, response.text[:400])

    def files(self, **params) -> set[str]:
        response = self.client.get("/api/access/files", params=params, headers=self.as_("acc-admin", "t-acc"))
        self.assertEqual(response.status_code, 200, response.text)
        return {Path(item["path"]).name for item in response.json()["files"]}

    def test_the_principal_to_file_answers_are_accurate(self) -> None:
        self.scan()
        principals = self.client.get("/api/access/principals", params={"kind": "broad"},
                                     headers=self.as_("acc-admin", "t-acc")).json()["principals"]
        guests = next(item for item in principals if item["key"] == GUESTS)
        self.assertTrue(guests["broad"])
        self.assertEqual(guests["readable_sensitive_files"], 1, "the payroll file; the denied card file is not readable")
        self.assertEqual(guests["readable_files"], 2, "payroll and notes")
        self.assertEqual(self.files(key=GUESTS), {"payroll.txt"})
        self.assertEqual(self.files(key=GUESTS, sensitive_only="false"), {"payroll.txt", "notes.txt"})
        self.assertIn("payroll.txt", self.files(kind="broad"))
        self.assertNotIn("card-denied.txt", self.files(kind="broad"))
        self.assertEqual(self.files(key=GUESTS, writable_only="true", sensitive_only="false"), set())

    def test_another_workspace_sees_none_of_it(self) -> None:
        self.scan()
        other = self.as_("other-admin", "t-other")
        self.assertEqual(self.client.get("/api/access/principals", headers=other).json()["principals"], [])
        response = self.client.get("/api/access/files", params={"key": GUESTS, "sensitive_only": "false"}, headers=other)
        self.assertEqual(response.json()["files"], [])

    def test_a_changed_acl_changes_the_answer_at_the_next_scan(self) -> None:
        self.scan()
        self.assertEqual(self.files(key=GUESTS), {"payroll.txt"})
        subprocess.run(["icacls", str(self.payroll), "/remove:g", f"*{GUESTS}"], check=True, capture_output=True)
        self.scan()
        self.assertEqual(self.files(key=GUESTS), set(), "the index is replaced when the asset is scanned again")

    def test_a_file_that_is_gone_leaves_the_index(self) -> None:
        self.scan(label="d7-estate")
        self.assertIn("notes.txt", self.files(key=GUESTS, sensitive_only="false"))
        self.notes.unlink()
        self.scan(label="d7-estate")
        self.assertNotIn("notes.txt", self.files(key=GUESTS, sensitive_only="false"),
                         "a named, complete scan prunes the asset and its access rows")
        with store._connect() as conn:
            orphans = conn.execute("SELECT COUNT(*) AS n FROM asset_access aa WHERE NOT EXISTS (SELECT 1 FROM assets a "
                                   "WHERE a.tenant_id = aa.tenant_id AND a.id = aa.asset_id)").fetchone()["n"]
        self.assertEqual(orphans, 0)

    def test_the_questions_need_a_principal_or_a_kind(self) -> None:
        admin = self.as_("acc-admin", "t-acc")
        self.assertEqual(self.client.get("/api/access/files", headers=admin).status_code, 400)
        self.assertEqual(self.client.get("/api/access/files", params={"kind": "everyone"}, headers=admin).status_code, 400)


if __name__ == "__main__":
    unittest.main()
