"""Revision 0055: who owns a file, who can read, write, modify or fully control it, which
grants are explicit and which inherited, what changed - from collection to the console.

Gate lines (the owner/permissions prompt): every ACL fixture reads the same through the
SMB and the WinRM collector; collection -> persistence -> API -> findings -> remediation
-> "Who can read" -> file detail tell the same truth; nothing is called effective access
while group membership is not resolved; an ACL that could not be read is said, never
shown as "no permissions"; an ACL-only change is a permission change, not a content
change; a tenant never sees another's principals; permission findings only where a
sensitive file is exposed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.testclient import TestClient

from backend import security, store
from backend.app import app
from collectors import win_security
from collectors.acl_powershell import acl_from_fields
from collectors.smb_scanner import SMBConfig, SMBScanner, normalize_acl
from collectors.winrm_endpoint_scanner import _endpoint_acl
from permissions import access_findings
from permissions.acl_analyzer import (
    analyze_acl,
    acl_state,
    owner_of,
    principal_access,
    principal_type,
    rights_label,
)

ROOT = Path(__file__).resolve().parents[1]
CARD = "4111 1111 1111 1111"
EVERYONE, AUTH_USERS, USERS, GUESTS, SYSTEM, ADMINS = (
    "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-18", "S-1-5-32-544")
DOMAIN = "S-1-5-21-1004336348-1177238915-682003330"
ALICE, BOB, CAROL, FINANCE = f"{DOMAIN}-1105", f"{DOMAIN}-1106", f"{DOMAIN}-1107", f"{DOMAIN}-2201"
DOMAIN_USERS = f"{DOMAIN}-513"
ORPHAN = "S-1-5-21-9-9-9-1234"
READ, READ_EXECUTE, WRITE, MODIFY, FULL, DELETE = 0x120089, 0x1200A9, 0x100116, 0x1301BF, 0x1F01FF, 0x10000
NAMES = {EVERYONE: "Everyone", AUTH_USERS: "NT AUTHORITY\\Authenticated Users", USERS: "BUILTIN\\Users",
         GUESTS: "BUILTIN\\Guests", SYSTEM: "NT AUTHORITY\\SYSTEM", ADMINS: "BUILTIN\\Administrators",
         ALICE: "CORP\\alice", BOB: "CORP\\bob", CAROL: "CORP\\carol", FINANCE: "CORP\\Finance",
         DOMAIN_USERS: "CORP\\Domain Users", ORPHAN: ORPHAN}


def ace(sid: str, mask: int, kind: str = "Allow", inherited: bool = False, aflags: int = 0) -> tuple:
    return (sid, mask, kind, inherited, aflags)


# The fifteen fixtures of the prompt, each an owner, a DACL and whether it is protected.
FIXTURES = {
    "owner_only": (ALICE, [], False),
    "explicit_read": (ALICE, [ace(EVERYONE, READ)], False),
    "inherited_read": (ALICE, [ace(USERS, READ_EXECUTE, inherited=True)], False),
    "explicit_write": (ALICE, [ace(BOB, WRITE)], False),
    "inherited_modify": (ALICE, [ace(AUTH_USERS, MODIFY, inherited=True)], False),
    "full_control": (ALICE, [ace(DOMAIN_USERS, FULL)], False),
    "explicit_deny": (ALICE, [ace(EVERYONE, READ, "Deny"), ace(EVERYONE, READ, inherited=True)], False),
    "mixed_allow_deny": (ALICE, [ace(BOB, DELETE, "Deny"), ace(BOB, MODIFY)], False),
    "broad_group": (ALICE, [ace(GUESTS, READ), ace(SYSTEM, FULL, inherited=True)], False),
    "user_specific": (ALICE, [ace(CAROL, READ), ace(ADMINS, FULL, inherited=True)], False),
    "unresolved_sid": (ALICE, [ace(ORPHAN, READ)], False),
    "owner_change_before": (ALICE, [ace(ADMINS, FULL, inherited=True)], False),
    "owner_change_after": (ORPHAN, [ace(ADMINS, FULL, inherited=True)], False),
    "inheritance_disabled": (ALICE, [ace(ADMINS, FULL), ace(FINANCE, READ)], True),
    # Bob is in CORP\Finance: the ACL names the group, and so does the access - Bob does not
    # appear, because group membership is not expanded.
    "nested_group": (ALICE, [ace(FINANCE, READ, inherited=True)], False),
    # An inherit-only entry applies to a folder's children, not to the object it is on.
    "inherit_only": (ALICE, [ace(EVERYONE, READ, aflags=2 + 4 * 2)], False),
}


def winrm_item(name: str) -> dict:
    """What the endpoint script sends (collectors.acl_powershell's ConvertTo-DspmAclFields)."""
    owner, entries, protected = FIXTURES[name]
    return {"acl_fields": {
        "acl_state": "collected", "owner": NAMES[owner], "owner_sid": owner, "acl_protected": protected,
        "principals": [NAMES[sid] for sid, *_ in entries], "sids": [sid for sid, *_ in entries],
        "masks": [mask - (1 << 32) if mask >= 1 << 31 else mask for _sid, mask, *_ in entries],
        "types": [kind for _sid, _mask, kind, *_ in entries],
        "inherited": [inherited for _sid, _mask, _kind, inherited, _flags in entries],
        "aflags": [flags for *_, flags in entries]}}


def smb_batch_acl(name: str) -> dict:
    """The SMB collector's batched PowerShell answer for the same ACL, through its parser."""
    scanner = SMBScanner(SMBConfig(server="files.example.test"))
    row = {"path": "share/x.txt", "ok": True, "acl_fields": winrm_item(name)["acl_fields"]}
    completed = SimpleNamespace(returncode=0, stdout=json.dumps({"results": [row]}), stderr="")
    return scanner._parse_acl_batch("\\\\files.example.test\\share", completed)["share/x.txt"]


def inproc_acl(name: str) -> dict:
    """The in-process read's shape (local files, and SMB when the console can open the UNC
    path): raw ACE flags, a mask per entry, the SID lookup's type."""
    owner, entries, protected = FIXTURES[name]
    shaped = []
    for sid, mask, kind, inherited, aflags in entries:
        raw = (0x2 if aflags & 1 else 0) | (0x1 if aflags & 2 else 0) | (0x4 if aflags & 4 else 0) | (0x8 if aflags & 8 else 0)
        entry = {"principal": NAMES[sid], "sid": sid, "rights": win_security.rights_to_names(mask), "mask": mask,
                 "type": kind.lower(), "inherited": inherited, "flags": raw | (0x10 if inherited else 0),
                 "principal_type": ""}
        if raw & 0x8:
            entry["inherit_only"] = True
        shaped.append(entry)
    acl = normalize_acl(NAMES[owner], [entry["principal"] for entry in shaped],
                        [entry["rights"] for entry in shaped], entries=shaped)
    acl.update({"owner_sid": owner, "state": "collected", "protected": protected})
    return acl


def own_acl(folder: Path) -> None:
    """The estate's permissions are the test's alone. A checkout under C:\\ inherits
    BUILTIN\\Users read (a profile folder does not), and that broad group would read every
    fixture - correctly reported, since group nesting is not resolved, but not what the test
    sets up. Only Administrators, SYSTEM and the account running the test, nothing inherited."""
    who = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True)
    sid = who.stdout.strip().split(",")[-1].strip().strip('"')
    subprocess.run(["icacls", str(folder), "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
                    "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", f"*{sid}:(OI)(CI)F"],
                   check=True, capture_output=True)


def grant_unmapped_sid(path: Path, sid: str) -> None:
    """icacls refuses a SID no authority can name (1332); .NET writes it as given."""
    script = (f"$acl = Get-Acl -LiteralPath '{path}'; "
              f"$sid = New-Object System.Security.Principal.SecurityIdentifier '{sid}'; "
              "$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'Read', 'Allow'); "
              f"$acl.AddAccessRule($rule); Set-Acl -LiteralPath '{path}' -AclObject $acl")
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], check=True,
                   capture_output=True, timeout=120)


def view(acl: dict) -> list[tuple]:
    """Each principal's direct access, as compared across sources."""
    return sorted((row.key, row.granted, row.denied, row.explicit_granted, row.inherited_granted, row.is_owner,
                   row.broad, row.unresolved) for row in principal_access(acl))


def by_key(acl: dict) -> dict:
    return {row.key: row for row in principal_access(acl)}


class EveryFixtureReadsTheSameThroughEverySourceTest(unittest.TestCase):
    def test_smb_winrm_and_the_in_process_read_agree(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                winrm, smb, local = _endpoint_acl(winrm_item(name)), smb_batch_acl(name), inproc_acl(name)
                self.assertEqual(view(winrm), view(smb))
                self.assertEqual(view(winrm), view(local))
                self.assertEqual(owner_of(winrm), owner_of(local))
                self.assertEqual(winrm.get("protected"), FIXTURES[name][2])
                self.assertEqual(acl_state(winrm), "collected")

    def test_what_each_fixture_grants(self) -> None:
        def access(name: str, sid: str):
            return by_key(_endpoint_acl(winrm_item(name)))[sid]

        owner = access("owner_only", ALICE)
        self.assertEqual((owner.is_owner, owner.level, owner.rights), (True, "none", "None"))
        explicit = access("explicit_read", EVERYONE)
        self.assertEqual((explicit.read, explicit.write, explicit.granted_by, explicit.broad), (True, False, "explicit", True))
        inherited = access("inherited_read", USERS)
        self.assertEqual((inherited.level, inherited.granted_by, inherited.rights), ("read", "inherited", "Read & execute"))
        write = access("explicit_write", BOB)
        self.assertEqual((write.write, write.modify, write.level, write.rights), (True, False, "write", "Write"))
        modify = access("inherited_modify", AUTH_USERS)
        self.assertEqual((modify.modify, modify.full_control, modify.level, modify.granted_by),
                         (True, False, "modify", "inherited"))
        full = access("full_control", DOMAIN_USERS)
        self.assertEqual((full.full_control, full.change_permissions, full.broad, full.rights),
                         (True, True, True, "Full control"))
        denied = access("explicit_deny", EVERYONE)
        self.assertEqual((denied.read, denied.has_deny), (False, True), "an explicit deny outranks an inherited allow")
        mixed = access("mixed_allow_deny", BOB)
        self.assertEqual((mixed.write, mixed.modify, mixed.has_deny), (True, False, True),
                         "Allow Modify less Deny Delete is write, not modify")
        self.assertEqual(rights_label(mixed.denied), "Delete")
        self.assertTrue(access("broad_group", GUESTS).broad)
        self.assertFalse(access("broad_group", SYSTEM).broad)
        self.assertTrue(access("broad_group", SYSTEM).privileged)
        carol = access("user_specific", CAROL)
        self.assertEqual((carol.broad, carol.read, carol.principal_type), (False, True, "unknown"),
                         "a domain account's kind is not provable from its SID alone")
        orphan = access("unresolved_sid", ORPHAN)
        self.assertEqual((orphan.principal_type, orphan.unresolved, orphan.read), ("unresolved_sid", True, True))
        locked = _endpoint_acl(winrm_item("inheritance_disabled"))
        self.assertTrue(locked["protected"])
        self.assertTrue(all(row.explicit for row in principal_access(locked) if not row.is_owner))
        nested = by_key(_endpoint_acl(winrm_item("nested_group")))
        self.assertIn(FINANCE, nested)
        self.assertNotIn(BOB, nested, "membership is not expanded - Bob's access through Finance is not his row")
        only = by_key(_endpoint_acl(winrm_item("inherit_only")))
        self.assertNotIn(EVERYONE, only, "an inherit-only entry does not apply to the file")

    def test_a_principal_type_is_what_the_sid_proves_or_what_the_lookup_said(self) -> None:
        self.assertEqual(principal_type("Everyone", EVERYONE), "well_known_group")
        self.assertEqual(principal_type("NT AUTHORITY\\SYSTEM", SYSTEM), "service")
        self.assertEqual(principal_type("NT SERVICE\\TrustedInstaller", "S-1-5-80-956008885-3418522649"), "service")
        self.assertEqual(principal_type("BUILTIN\\Users", USERS), "group")
        self.assertEqual(principal_type("CORP\\Administrator", f"{DOMAIN}-500"), "user")
        self.assertEqual(principal_type("CORP\\Domain Users", DOMAIN_USERS), "group")
        self.assertEqual(principal_type("CORP\\WS01$", f"{DOMAIN}-3001"), "computer")
        self.assertEqual(principal_type(ORPHAN, ORPHAN), "unresolved_sid")
        self.assertEqual(principal_type("CORP\\carol", CAROL), "unknown")
        self.assertEqual(principal_type("CORP\\carol", CAROL, "user"), "user", "the lookup's answer is kept")

    def test_a_failed_read_is_said_and_never_reads_as_no_permissions(self) -> None:
        winrm = _endpoint_acl({"acl_fields": {"acl_state": "failed", "acl_error": "access_denied"}})
        self.assertEqual((acl_state(winrm), winrm["error"]), ("failed", "access_denied"))
        self.assertIn("could not be read", " ".join(analyze_acl(winrm)["issues"]))
        self.assertEqual(acl_state(_endpoint_acl({"path": "x", "acl_fields": None})), "not_collected")
        scanner = SMBScanner(SMBConfig(server="files.example.test", username="u", password="p"))
        with mock.patch("collectors.smb_scanner.win_security.available", return_value=False), \
                mock.patch("collectors.smb_scanner.subprocess.run",
                           return_value=SimpleNamespace(returncode=1, stdout="", stderr="boom")):
            failed = scanner._acl_for_path("share", "x.txt")
        self.assertEqual(acl_state(failed), "failed")
        self.assertEqual(access_findings.derive({"path": "x", "acl": failed}, [{"type": "pci_chd_pan"}]), [],
                         "an unread ACL raises no permission finding")
        # Permissions off, the owner still read: an owner alone is not an ACL that was read.
        owner_only = {"owner": ORPHAN, "owner_sid": ORPHAN, "principals": [], "permissions": [], "state": "not_collected"}
        self.assertEqual(access_findings.derive({"path": "x", "acl": owner_only}, [{"type": "pci_chd_pan"}]), [])
        missing = win_security.read_security(str(ROOT / "tmp" / f"no-such-{os.getpid()}.txt"))
        if win_security.available():
            self.assertEqual((missing["state"], missing["error"]), ("failed", "not_found"))


class PermissionFindingsTest(unittest.TestCase):
    DATA = [{"type": "pci_chd_pan", "display_name": "Payment card number", "risk": "CRITICAL"}]

    def derive(self, name: str, data=None, **kwargs) -> dict:
        record = {"path": "C:\\Finance\\cards.txt", "acl": _endpoint_acl(winrm_item(name))}
        return {finding["type"]: finding for finding in access_findings.derive(record, self.DATA if data is None else data, **kwargs)}

    def test_no_sensitive_data_no_permission_finding(self) -> None:
        self.assertEqual(self.derive("full_control", data=[]), {}, "an ACL alone is never a finding")
        self.assertEqual(self.derive("user_specific"), {}, "a named user and Administrators are not an exposure")

    def test_a_broad_reader_is_one_finding_that_says_who_how_and_why(self) -> None:
        found = self.derive("explicit_read", risk_level="HIGH")
        self.assertEqual(set(found), {"access_broad_read"})
        finding = found["access_broad_read"]
        self.assertEqual(finding["risk"], "HIGH", "Everyone reading card data on a high-risk file")
        exposure = finding["access_exposure"]
        self.assertEqual([grant["principal"] for grant in exposure["principals"]], ["Everyone"])
        self.assertEqual(exposure["principals"][0]["granted_by"], "explicit")
        self.assertEqual(exposure["owner"]["name"], "CORP\\alice")
        self.assertIn("Payment card number", exposure["severity_rationale"])
        self.assertIn("Group membership was not expanded", exposure["access_model"])
        steps = " ".join(finding["recommendations"])
        self.assertIn('icacls "C:\\Finance\\cards.txt" /remove:g *S-1-1-0', steps)
        self.assertIn("never changes permissions", steps)

    def test_an_inherited_grant_is_not_answered_with_a_blind_removal(self) -> None:
        steps = " ".join(self.derive("inherited_modify")["access_broad_write"]["recommendations"])
        self.assertIn("inherited from a parent folder", steps)
        self.assertIn("disabling inheritance", steps)
        self.assertNotIn("/remove:g", steps, "an inherited entry cannot be removed on the file alone")

    def test_write_supersedes_read_and_full_control_is_high(self) -> None:
        found = self.derive("full_control")
        self.assertEqual(set(found), {"access_broad_write"})
        self.assertEqual(found["access_broad_write"]["risk"], "HIGH")

    def test_a_denied_broad_group_is_no_exposure(self) -> None:
        self.assertEqual(self.derive("explicit_deny"), {})

    def test_owner_unresolved_and_service_findings(self) -> None:
        self.assertIn("access_owner_risk", self.derive("owner_change_after"))
        self.assertIn("access_unresolved_sid", self.derive("unresolved_sid"))
        record = {"path": "C:\\www\\cards.txt", "acl": {"owner": "CORP\\alice", "owner_sid": ALICE, "entries": [
            {"principal": "IUSR", "sid": "S-1-5-17", "mask": READ, "type": "allow", "inherited": True}]}}
        found = {finding["type"]: finding for finding in access_findings.derive(record, self.DATA)}
        self.assertEqual(found["access_service_read"]["risk"], "MEDIUM", "a web identity reads for any request")

    def test_too_many_principals_is_excessive(self) -> None:
        entries = [{"principal": f"CORP\\u{index}", "sid": f"{DOMAIN}-{3000 + index}", "mask": READ, "type": "allow"}
                   for index in range(4)]
        record = {"path": "x", "acl": {"owner": "CORP\\alice", "owner_sid": ALICE, "entries": entries}}
        with mock.patch.dict(os.environ, {"DSPM_ACCESS_MAX_PRINCIPALS": "3"}):
            found = {finding["type"] for finding in access_findings.derive(record, self.DATA)}
        self.assertEqual(found, {"access_excessive_principals"})

    def test_off_means_off(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ACCESS_FINDINGS": "0"}):
            self.assertEqual(self.derive("full_control"), {})

    def test_an_unread_acl_is_not_answered_with_remove_broad_groups(self) -> None:
        from risk.risk_engine import calculate_risk

        record = {"name": "cards.txt", "path": "C:\\Data\\cards.txt", "extension": ".txt", "size": 4096}
        for acl in ({}, {"state": "failed", "error": "access_denied"}):
            assessment = analyze_acl(acl, record)
            risk = calculate_risk(record, [{"type": "credit_card", "risk": "HIGH", "count": 1}], assessment).to_dict()
            actions = " ".join(risk["remediation"]["actions"]) + " ".join(risk.get("dlp_recommendations") or [])
            self.assertNotIn("Remove broad or writable groups", actions)
            self.assertNotIn("Review AD group membership", actions)
        exposed = analyze_acl({"owner": "O", "entries": [{"principal": "Everyone", "sid": EVERYONE, "mask": READ,
                                                           "type": "allow"}]}, record)
        risk = calculate_risk(record, [{"type": "credit_card", "risk": "HIGH", "count": 1}], exposed).to_dict()
        self.assertIn("Remove broad or writable groups", risk["remediation"]["actions"])

    def test_a_permission_finding_is_not_a_data_class(self) -> None:
        from backend.domain.models import _asset_finding_types

        access = access_findings.derive({"path": "x", "acl": _endpoint_acl(winrm_item("explicit_read"))}, self.DATA)
        self.assertTrue(access)
        record = {"findings": [{"type": "pci_chd_pan", "display_name": "Payment card number"}, *access]}
        self.assertEqual(json.loads(_asset_finding_types(record)), ["Payment card number"])


class PermissionChangesTest(unittest.TestCase):
    """What changed between two reads of one file's ACL (store._acl_change)."""

    def rows(self, name: str, sensitive: int = 1) -> dict:
        return store._access_rows(_endpoint_acl(winrm_item(name)), sensitive, 80)

    def test_owner_change_is_a_change(self) -> None:
        change = store._acl_change(self.rows("owner_change_before"), self.rows("owner_change_after"))
        self.assertTrue(change["owner_changed"])
        self.assertIn("owner CORP\\alice", change["summary"])

    def test_a_broad_group_gaining_read_on_sensitive_data_is_high(self) -> None:
        change = store._acl_change(self.rows("owner_only"), self.rows("explicit_read"))
        self.assertEqual((change["severity"], change["broad_exposure"]), ("high", 1))
        everyone = next(item for item in change["changes"] if item["key"] == EVERYONE)
        self.assertIn("gained_read", everyone["changes"])
        self.assertIn("explicit_added", everyone["changes"])

    def test_a_removed_deny_is_a_change(self) -> None:
        change = store._acl_change(self.rows("explicit_deny"), self.rows("inherited_read") | self.rows("explicit_read"))
        everyone = next(item for item in change["changes"] if item["key"] == EVERYONE)
        self.assertIn("deny_removed", everyone["changes"])
        self.assertTrue(change["deny_removed"])

    def test_names_and_sensitivity_are_not_permission_changes(self) -> None:
        before = self.rows("explicit_read", sensitive=0)
        self.assertIsNone(store._acl_change(before, self.rows("explicit_read", sensitive=1)))
        renamed = {key: (row[0], "Jeder", *row[2:]) for key, row in before.items()}
        self.assertIsNone(store._acl_change(before, renamed))


@unittest.skipUnless(os.name == "nt" and shutil.which("icacls") and shutil.which("powershell.exe"),
                     "reads real Windows ACLs")
class RealAclsReadTheSameByWinrmAndInProcessTest(unittest.TestCase):
    """Real ACLs set with icacls, read by the endpoint script (run here by the local
    powershell.exe - the transport is not part of it) and by the in-process reader the
    local and SMB collectors use, over the local path and over \\\\127.0.0.1\\C$."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path("C:\\") / f"dspm_access_model_{os.getpid()}"
        shutil.rmtree(cls.root, ignore_errors=True)
        cls.root.mkdir()
        grants = {"everyone_read.txt": ["/grant", "*S-1-1-0:(R)"],
                  "users_modify.txt": ["/grant", "*S-1-5-32-545:(M)"],
                  "guests_denied.txt": ["/deny", "*S-1-5-32-546:(R)"],
                  "protected.txt": ["/inheritance:r", "/grant:r", "*S-1-5-32-544:(F)"]}
        for name, args in grants.items():
            (cls.root / name).write_text("x", encoding="utf-8")
            subprocess.run(["icacls", str(cls.root / name), *args], check=True, capture_output=True)
        (cls.root / "orphan_read.txt").write_text("x", encoding="utf-8")
        grant_unmapped_sid(cls.root / "orphan_read.txt", ORPHAN)
        from collectors.winrm_endpoint_scanner import _read_json, _scan_script

        script = _scan_script([str(cls.root)], max_depth=1, read_content=False, max_read_bytes=1000,
                              allowed_extensions=[], extension_filter_enabled=False, include_hidden=True,
                              include_system=True, hidden_filter_enabled=False, system_filter_enabled=False,
                              read_acl=True, inspect_archives=False, hash_files=False, read_owner=True,
                              parallel_workers=1)
        path = cls.root.parent / f"dspm_access_model_{os.getpid()}.ps1"
        path.write_text(script, encoding="utf-8-sig")
        try:
            run = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)],
                                 capture_output=True, timeout=300, check=False)
        finally:
            path.unlink(missing_ok=True)
        assert run.returncode == 0, run.stderr.decode("utf-8", "replace")[:500]
        records = (_read_json(run.stdout) or {}).get("records", [])
        cls.winrm = {Path(record["path"]).name: _endpoint_acl(record) for record in records}
        from collectors.acl_powershell import acl_read_stats

        cls.stats = acl_read_stats(record.get("acl_fields") for record in records)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_the_endpoint_script_and_the_in_process_read_agree(self) -> None:
        self.assertEqual(set(self.winrm), {"everyone_read.txt", "users_modify.txt", "guests_denied.txt",
                                           "orphan_read.txt", "protected.txt"})
        for name, winrm in self.winrm.items():
            with self.subTest(file=name):
                local = win_security.read_security(str(self.root / name))
                self.assertEqual(view(winrm), view(local))
                self.assertEqual((winrm["owner"], winrm["owner_sid"], winrm["protected"]),
                                 (local["owner"], local["owner_sid"], local["protected"]))
                unc = win_security.read_security(f"\\\\127.0.0.1\\C$\\{self.root.name}\\{name}")
                if unc.get("state") == "collected":  # the admin share is reachable on this host
                    self.assertEqual(view(unc), view(local))

    def test_the_smb_powershell_batch_reads_them_all_in_one_process(self) -> None:
        # The SMB collector's fallback when it cannot read in-process: one PowerShell process,
        # the paths on stdin, over the admin share - the same rows as the in-process read.
        unc = win_security.read_security(f"\\\\127.0.0.1\\C$\\{self.root.name}\\everyone_read.txt")
        if unc.get("state") != "collected":
            self.skipTest("the admin share is not reachable on this host")
        scanner = SMBScanner(SMBConfig(server="127.0.0.1"))
        paths = [f"/{self.root.name}/{name}" for name in sorted(self.winrm)]
        with mock.patch("collectors.smb_scanner.win_security.available", return_value=False):
            scanner._prefetch_acl_paths("C$", paths)
        self.assertEqual(scanner.last_scan_diagnostics.get("acl_batch_processes"), 1)
        for path in paths:
            with self.subTest(path=path):
                read = scanner._acl_cache[scanner._unc_path("C$", path)]
                self.assertEqual(view(read), view(win_security.read_security(str(self.root / path.rsplit("/", 1)[1]))))

    def test_each_sid_is_named_once_a_command(self) -> None:
        sids = {row.key for acl in self.winrm.values() for row in principal_access(acl)}
        self.assertEqual((self.stats["reads"], self.stats["failed"]), (5, 0))
        self.assertGreater(self.stats["entries"], len(sids), "the files share their inherited entries")
        self.assertLessEqual(self.stats["sid_lookups"], len(sids), "one translation a SID, not one an entry")

    def test_what_windows_says_is_what_sentro_says(self) -> None:
        everyone = by_key(self.winrm["everyone_read.txt"])[EVERYONE]
        self.assertEqual((everyone.read, everyone.write, everyone.granted_by), (True, False, "explicit"))
        users = by_key(self.winrm["users_modify.txt"])[USERS]
        self.assertTrue(users.modify)
        self.assertEqual(users.explicit_granted & 0x10000, 0x10000, "the explicit Modify grants Delete")
        guests = by_key(self.winrm["guests_denied.txt"])[GUESTS]
        self.assertEqual((guests.has_deny, guests.read), (True, False))
        orphan = by_key(self.winrm["orphan_read.txt"])[ORPHAN]
        self.assertEqual(orphan.principal_type, "unresolved_sid")
        protected = self.winrm["protected.txt"]
        self.assertTrue(protected["protected"])
        self.assertEqual([row.key for row in principal_access(protected) if not row.is_owner], [ADMINS])
        local_types = {entry["sid"]: entry["principal_type"]
                       for entry in win_security.read_security(str(self.root / "users_modify.txt"))["entries"]}
        self.assertEqual(local_types[USERS], "group", "the in-process lookup reports the account type")


@unittest.skipUnless(os.name == "nt" and shutil.which("icacls"), "reads real Windows ACLs")
class FromCollectionToTheConsoleTest(unittest.TestCase):
    """A scanned fixture, read back through every surface: who can read, the file detail,
    the findings and their remediation, the changes - and nothing of it in another tenant."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "access.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in ("t-acl", "t-pivot"):
            store.create_tenant(tenant, tenant)
        store.create_user("acl-admin", security.hash_password("Kestrel-lantern-4471"), "admin", "t-acl")
        store.create_user("pivot-admin", security.hash_password("Kestrel-lantern-4471"), "admin", "t-pivot")
        self.client = TestClient(app)
        self.relative = Path("tmp") / f"access-estate-{os.getpid()}-{id(self)}"
        self.folder = ROOT / self.relative
        self.folder.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.folder, True)
        own_acl(self.folder)
        self.payroll = self._file("payroll.txt", f"Payroll export\nPrimary card {CARD} for travel.\n",
                                  "/grant", f"*{EVERYONE}:(R)")
        self.ledger = self._file("ledger.txt", f"Ledger\nCard {CARD} settles monthly.\n", "/grant", f"*{USERS}:(M)")
        self.notes = self._file("notes.txt", "Office move planning, nothing sensitive.\n", "/grant", f"*{EVERYONE}:(F)")
        self.orphaned = self.folder / "orphaned.txt"
        self.orphaned.write_text(f"Backup card {CARD}.\n", encoding="utf-8")
        grant_unmapped_sid(self.orphaned, ORPHAN)

    def _file(self, name: str, text: str, *args: str) -> Path:
        path = self.folder / name
        path.write_text(text, encoding="utf-8")
        subprocess.run(["icacls", str(path), *args], check=True, capture_output=True)
        return path

    def as_(self, user: str, tenant: str) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, 'admin', tenant)}"}

    def get(self, url: str, user: str = "acl-admin", tenant: str = "t-acl", **params):
        response = self.client.get(url, params=params, headers=self.as_(user, tenant))
        return response

    def scan(self, *, incremental: bool = False) -> None:
        with mock.patch("backend.app.partitioned_scans_enabled", return_value=False):
            response = self.client.post("/api/scan", headers=self.as_("acl-admin", "t-acl"), json={
                "local_path": self.relative.as_posix(), "async_scan": False, "save_report": True,
                "compact_result": False, "incremental_enabled": incremental, "scan_label": "access-estate"})
        self.assertEqual(response.status_code, 200, response.text[:400])

    def asset_id(self, name: str) -> str:
        with store._connect() as conn:
            row = conn.execute("SELECT id FROM assets WHERE tenant_id = ? AND name = ?", ("t-acl", name)).fetchone()
        return str(row["id"])

    def findings(self) -> dict[tuple[str, str], dict]:
        response = self.get("/api/findings", category="access_exposure", limit=200)
        self.assertEqual(response.status_code, 200, response.text[:300])
        return {(Path((item.get("file") or {}).get("path") or "").name, item.get("type")): item
                for item in response.json()["items"]}

    def test_one_truth_on_every_surface(self) -> None:
        self.scan()
        everyone = next(item for item in self.get("/api/access/principals").json()["principals"]
                        if item["key"] == EVERYONE)
        self.assertEqual((everyone["readable_sensitive_files"], everyone["readable_files"],
                          everyone["full_control_files"]), (1, 2, 1), "payroll and notes; notes has no data")
        users = next(item for item in self.get("/api/access/principals", kind="broad").json()["principals"]
                     if item["key"] == USERS)
        self.assertGreaterEqual(users["writable_sensitive_files"], 1)
        files = {item["name"]: item for item in self.get("/api/access/files", key=EVERYONE).json()["files"]}
        self.assertEqual(set(files), {"payroll.txt"})
        self.assertEqual(files["payroll.txt"]["grants"][0]["granted_by"], "explicit")
        writable = {item["name"] for item in self.get("/api/access/files", kind="broad", access="write").json()["files"]}
        self.assertEqual(writable, {"ledger.txt"})
        # This host's own folders may carry an orphaned SID of their own, inherited by every file.
        unresolved = self.get("/api/access/principals", kind="unresolved").json()["principals"]
        self.assertIn(ORPHAN, [item["key"] for item in unresolved])
        self.assertTrue(all(item["unresolved"] and item["principal_type"] == "unresolved_sid" for item in unresolved))
        self.assertEqual(self.get("/api/access/files", key=ORPHAN).json()["files"][0]["name"], "orphaned.txt")

        detail = self.get(f"/api/access/assets/{self.asset_id('payroll.txt')}").json()
        self.assertEqual(detail["acl_state"], "collected")
        self.assertTrue(detail["owner"]["sid"].startswith("S-1-5-"))
        self.assertFalse(detail["access_model"]["group_membership_resolved"])
        self.assertEqual(detail["access_model"]["label"], "Direct ACL access")
        everyone_entry = next(entry for entry in detail["entries"] if entry["sid"] == EVERYONE)
        self.assertEqual((everyone_entry["access"], everyone_entry["inherited"], everyone_entry["applies_to"]),
                         ("allow", False, "This file"))
        self.assertGreaterEqual(detail["summary"]["read"], 2)
        self.assertEqual(detail["summary"]["broad"], 1)

        findings = self.findings()
        self.assertIn(("payroll.txt", "access_broad_read"), findings)
        self.assertIn(("ledger.txt", "access_broad_write"), findings)
        self.assertIn(("orphaned.txt", "access_unresolved_sid"), findings)
        self.assertFalse(any(name == "notes.txt" for name, _ in findings), "no data, no permission finding")
        finding_id = findings[("payroll.txt", "access_broad_read")]["finding_id"]
        listed = findings[("payroll.txt", "access_broad_read")]
        self.assertEqual(listed["exposure"], "BROAD_INTERNAL")
        self.assertIn("broad group can read", listed["reason"])
        self.assertNotIn("DLP", listed["recommendation"])
        detail = self.get(f"/api/findings/{finding_id}").json()["finding"]
        exposure = detail["access_exposure"]
        self.assertEqual(exposure["principals"][0]["principal"], "Everyone")
        self.assertTrue(any("/remove:g *S-1-1-0" in step for step in detail["recommendations"]))
        self.assertEqual(detail["access"]["exposed_principals"][0]["key"], EVERYONE)
        # A data finding on the same file carries the same owner and exposure.
        data_finding = next(item for item in self.get("/api/findings", limit=200).json()["items"]
                            if Path(item["file"]["path"]).name == "payroll.txt"
                            and item["type"] not in access_findings.ACCESS_FINDING_TYPES)
        data_detail = self.get(f"/api/findings/{data_finding['finding_id']}").json()["finding"]
        self.assertEqual(data_detail["access"]["owner"], detail["access"]["owner"])
        self.assertEqual(data_detail["access"]["exposed_principals"], detail["access"]["exposed_principals"])
        summary = self.get("/api/access/summary").json()
        self.assertEqual((summary["sensitive_broad_read_files"], summary["sensitive_broad_write_files"]), (2, 1))
        self.assertGreaterEqual(summary["unresolved_sid_files"], 1)
        self.assertEqual(summary["acl_states"]["collected"], 4)

    def test_the_maintained_counts_are_the_rows(self) -> None:
        self.scan()
        counted = self.get("/api/access/principals").json()["principals"]
        with mock.patch.dict(os.environ, {"DSPM_MAINTAINED_COUNTS": "0"}):
            direct = self.get("/api/access/principals").json()["principals"]
            direct_summary = self.get("/api/access/summary").json()
        self.assertEqual(counted, direct)
        summary = self.get("/api/access/summary").json()
        self.assertEqual({key: summary[key] for key in ("sensitive_broad_read_files", "sensitive_broad_write_files",
                                                        "unresolved_sid_files")},
                         {key: direct_summary[key] for key in ("sensitive_broad_read_files",
                                                               "sensitive_broad_write_files", "unresolved_sid_files")})

    def test_an_acl_only_change_is_a_permission_change_not_a_content_change(self) -> None:
        self.scan(incremental=True)
        before = self.get(f"/api/access/assets/{self.asset_id('payroll.txt')}").json()
        subprocess.run(["icacls", str(self.payroll), "/grant", f"*{EVERYONE}:(M)"], check=True, capture_output=True)
        self.scan(incremental=True)
        changes = self.get("/api/access/changes").json()["changes"]
        payroll = next(change for change in changes if Path(change["path"]).name == "payroll.txt")
        self.assertTrue(payroll["broad_exposure"] and payroll["gained_write"])
        self.assertEqual(payroll["severity"], "high")
        everyone = next(item for item in payroll["changes"] if item["key"] == EVERYONE)
        self.assertIn("gained_modify", everyone["changes"])
        with store._connect() as conn:
            row = conn.execute("SELECT content_changed_scan_id FROM assets WHERE tenant_id = ? AND name = ?",
                               ("t-acl", "payroll.txt")).fetchone()
        self.assertEqual(row["content_changed_scan_id"] or "", "", "the content did not change")
        after = self.get(f"/api/access/assets/{self.asset_id('payroll.txt')}").json()
        self.assertEqual(after["changes"][0]["id"], payroll["id"])
        self.assertNotEqual(before["principals"], after["principals"])
        current = self.findings()
        self.assertIn(("payroll.txt", "access_broad_write"), current, "the finding follows the ACL the scan read")
        self.assertNotIn(("payroll.txt", "access_broad_read"), current, "write supersedes read: one finding a file")

    def test_another_tenant_sees_none_of_it(self) -> None:
        self.scan()
        subprocess.run(["icacls", str(self.ledger), "/grant", f"*{EVERYONE}:(R)"], check=True, capture_output=True)
        self.scan()
        self.assertTrue(self.get("/api/access/changes").json()["changes"], "the owning tenant sees its change")
        pivot = {"user": "pivot-admin", "tenant": "t-pivot"}
        self.assertEqual(self.get("/api/access/principals", **pivot).json()["principals"], [])
        self.assertEqual(self.get("/api/access/files", key=EVERYONE, sensitive_only="false", **pivot).json()["files"], [])
        self.assertEqual(self.get("/api/access/files", kind="broad", **pivot).json()["files"], [])
        self.assertEqual(self.get("/api/access/changes", **pivot).json()["changes"], [])
        self.assertEqual(self.get(f"/api/access/assets/{self.asset_id('payroll.txt')}", **pivot).status_code, 404)
        summary = self.get("/api/access/summary", **pivot).json()
        self.assertEqual((summary["sensitive_broad_read_files"], summary["acl_states"]["collected"]), (0, 0))

    def test_a_file_whose_acl_could_not_be_read_keeps_what_was_known(self) -> None:
        self.scan()
        payroll = self.asset_id("payroll.txt")
        known = self.get(f"/api/access/assets/{payroll}").json()["principals"]
        real = win_security.read_security

        def failing(path, **kwargs):
            if str(path).endswith("payroll.txt"):
                return {"state": "failed", "error": "access_denied"}
            return real(path, **kwargs)

        with mock.patch("collectors.win_security.read_security", side_effect=failing):
            self.scan()
        detail = self.get(f"/api/access/assets/{payroll}").json()
        self.assertEqual((detail["acl_state"], detail["acl_error"]), ("failed", "access_denied"))
        self.assertEqual(detail["principals"], known, "the last read that worked stays, with the scan that made it")
        self.assertEqual(self.get("/api/access/changes").json()["changes"], [], "an unread ACL is not a change")
        self.assertEqual(self.get("/api/access/summary").json()["acl_states"]["failed"], 1)
        self.assertNotIn(("payroll.txt", "access_broad_read"), self.findings(), "no finding from an unread ACL")

    def test_rows_from_before_the_model_record_no_change(self) -> None:
        self.scan()
        with store._connect() as conn:
            conn.execute("UPDATE asset_access SET principal_type = '', has_explicit = 0, explicit_mask = 0 "
                         "WHERE tenant_id = ?", ("t-acl",))
        self.scan()
        self.assertEqual(self.get("/api/access/changes").json()["changes"], [],
                         "rows revision 0055 has not filled are rewritten, not compared")
        with store._connect() as conn:
            filled = conn.execute("SELECT COUNT(*) AS n FROM asset_access WHERE tenant_id = ? AND principal_type = ''",
                                  ("t-acl",)).fetchone()["n"]
        self.assertEqual(filled, 0)

    def test_the_questions_are_bounded(self) -> None:
        self.assertEqual(self.get("/api/access/files", kind="everyone").status_code, 400)
        self.assertEqual(self.get("/api/access/files", key=EVERYONE, access="effective").status_code, 400)
        self.assertEqual(self.get("/api/access/files", key=EVERYONE, cursor="not-a-cursor").status_code, 400)
        self.assertEqual(self.get("/api/access/changes", severity="urgent").status_code, 400)


if __name__ == "__main__":
    unittest.main()
