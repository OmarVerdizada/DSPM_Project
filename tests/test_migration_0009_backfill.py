"""M0/Q1: revision 0009 rebuilds the finding queue from data that predates it.

`add_remediation_operational_index` turns each asset's stored detail into one operational
`findings` row. A finding that carries no `finding_id` - which is what an install older
than revision 0009 has - gets one derived from the tenant, asset, rule and path. That line
called `hashlib.sha256` while `backend/store.py` imported no `hashlib`, so the upgrade
raised `NameError` on exactly the data the backfill exists for. Every finding written by
this build carries an id, which is why the suite never reached it.

These build a database at revision 8 the way the runner builds one, put assets with
id-less findings in it, and run the upgrade the operator would run. The re-run assertion
matters as much as the first: a migration that is not idempotent cannot be retried after a
failure, and this one is re-applied by 0016 and 0017 through `add_tenant_integrity`.

PostgreSQL is out of scope here: the suite shares one database there, and rebuilding it
from revision 1 is C0.5's disposable-database work.
"""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend import db, migrations, store

TENANT = "q1-upgrade"


def _asset(asset_id: str, path: str, findings: list[dict], *, owner: str = "CORP\\owner") -> tuple:
    detail = {"path": path, "name": path.rsplit("\\", 1)[-1], "source": "smb", "owner": owner, "findings": findings}
    return (TENANT, asset_id, "smb", path, path.rsplit("\\", 1)[-1], owner, "2026-09-01T00:00:00Z",
            json.dumps(detail, ensure_ascii=False), len(findings))


@unittest.skipIf(db.is_postgres(), "rebuilding from revision 1 needs the disposable database of C0.5")
class TheUpgradeFromBeforeRevision0009Test(unittest.TestCase):

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._previous = store.DB_PATH
        store.DB_PATH = Path(self._dir.name) / "old-install.sqlite"
        self._build_revision_8()
        self._seed_assets()

    def tearDown(self) -> None:
        store.DB_PATH = self._previous
        self._dir.cleanup()

    def _build_revision_8(self) -> None:
        """Exactly what migrations.upgrade() does, stopping before 0009."""
        with store._connect() as conn:
            migrations._ensure_table(conn)
            for number, name, revision in migrations._revisions():
                if number > 8:
                    break
                revision(conn)
                conn.execute(
                    "INSERT INTO schema_migrations (revision, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                    (number, name, migrations._checksum(revision), datetime.now(timezone.utc).isoformat()),
                )
        with store._connect() as conn:
            self.assertEqual(migrations.current_revision(conn), 8)
            self.assertEqual(conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"], 0)

    def _seed_assets(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with store._connect() as conn:
            conn.execute("INSERT INTO tenants (tenant_id, display_name, registration_code, created_at, updated_at) "
                         "VALUES (?, ?, '', ?, ?)", (TENANT, "Q1", now, now))
            conn.executemany(
                "INSERT INTO assets (tenant_id, id, source, path, name, owner, modified_at, detail_json, finding_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    # No finding_id anywhere: the shape that raised NameError.
                    _asset("asset-a", r"\\fs01\finance\payroll.xlsx", [
                        {"type": "credit_card", "risk": {"level": "CRITICAL", "score": 90}, "framework": "PCI DSS",
                         "count": 3, "owner": "ana@corp"},
                        {"type": "email", "severity": "LOW", "framework": "gdpr"},
                    ]),
                    # One that already has an id: it must be kept, not re-derived.
                    _asset("asset-b", r"\\fs01\hr\contracts.docx", [
                        {"type": "national_id", "finding_id": "kept-id-0001", "risk": "HIGH", "frameworks": ["gdpr"]},
                    ]),
                    # Two findings of one rule on one asset collapse onto one derived id.
                    _asset("asset-c", r"\\fs01\it\dump.log", [
                        {"type": "password", "risk": "HIGH"},
                        {"type": "password", "risk": "MEDIUM"},
                    ]),
                    # Neither of these may stop the upgrade.
                    (TENANT, "asset-empty", "smb", r"\\fs01\it\empty.txt", "empty.txt", "", "", "{}", 0),
                    (TENANT, "asset-broken", "smb", r"\\fs01\it\broken.txt", "broken.txt", "", "", "{not json", 0),
                ],
            )

    def _findings(self) -> list[dict]:
        with store._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT id, asset_id, rule, severity, is_current, risk_score, owner, framework, file_path "
                "FROM findings WHERE tenant_id = ? ORDER BY id", (TENANT,)).fetchall()]

    def test_the_upgrade_rebuilds_the_queue_from_findings_that_carry_no_id(self) -> None:
        self.assertEqual(migrations.upgrade(), migrations.expected_revision())

        rows = self._findings()
        self.assertEqual(len(rows), 4, f"one row per finding, the repeated rule collapsed: {rows}")
        by_asset = {row["asset_id"] for row in rows}
        self.assertEqual(by_asset, {"asset-a", "asset-b", "asset-c"})
        self.assertTrue(all(row["is_current"] == 1 for row in rows), "the backfill marks the current estate")

        derived = [row["id"] for row in rows if row["id"] != "kept-id-0001"]
        self.assertEqual(len(derived), 3)
        for finding_id in derived:
            self.assertEqual(len(finding_id), 24, finding_id)
            self.assertTrue(all(char in "0123456789abcdef" for char in finding_id), finding_id)
        self.assertIn("kept-id-0001", [row["id"] for row in rows], "an id the data already had was replaced")

        card = next(row for row in rows if row["rule"] == "credit_card")
        self.assertEqual((card["severity"], card["risk_score"], card["owner"]), ("CRITICAL", 90, "ana@corp"))
        self.assertEqual(card["framework"], "pci_dss")
        self.assertEqual(card["file_path"], r"\\fs01\finance\payroll.xlsx")

    def test_running_it_again_changes_no_id_and_no_row(self) -> None:
        migrations.upgrade()
        before = self._findings()

        with store._connect() as conn:
            store.add_remediation_operational_index(conn)
        self.assertEqual(self._findings(), before, "a re-applied migration rewrote the queue")

        self.assertEqual(migrations.upgrade(), migrations.expected_revision())
        self.assertEqual(self._findings(), before, "a second upgrade changed the queue")

    def test_the_findings_are_readable_through_the_store_afterwards(self) -> None:
        migrations.upgrade()
        page = store.list_remediation_findings(TENANT, scope="current", status="all", limit=50)
        self.assertEqual(page["total"], 4, page)
        self.assertEqual({item["file"]["path"] for item in page["items"]},
                         {r"\\fs01\finance\payroll.xlsx", r"\\fs01\hr\contracts.docx", r"\\fs01\it\dump.log"})
        self.assertEqual({item["type"] for item in page["items"]},
                         {"credit_card", "email", "national_id", "password"})


class TheMissingImportCannotComeBackTest(unittest.TestCase):
    """The defect was a missing module-level import, so name it directly as well."""

    def test_store_imports_hashlib_at_module_level(self) -> None:
        tree = ast.parse(Path(store.__file__).read_text(encoding="utf-8"))
        imported = {alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
        self.assertIn("hashlib", imported,
                      "revision 0009 derives finding ids with hashlib.sha256; without the import the upgrade "
                      "raises NameError on any install whose findings predate finding_id")


if __name__ == "__main__":
    unittest.main()
