"""Track S-B - queryable inventory model.

The ``assets`` row now carries the columns the inventory UI filters / sorts /
searches on (extension, share, risk, size, owner, modified_at, finding_count,
top_frameworks, hidden/system/protected flags, search_text), denormalized during
the scan-normalization pass. These tests pin the population and the DB round-trip
so the eventual inventory API (S-C) can query the DB instead of a blob.

Store tests isolate via a temp SQLite file; on Postgres the conftest fixture
provides the clean slate, so the same tests validate both backends.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from backend import db, store
from backend.domain import normalize_scan_report


def _report(scan_id: str, files: list[dict], source: str = "local") -> dict:
    return {"scan_id": scan_id, "source": source, "summary": {}, "files": files}


RICH_FILE = {
    "path": "/share/Finance/q4.xlsx", "name": "q4.xlsx", "extension": ".XLSX",
    "share": "Finance", "size": 8192, "owner": "acme\\bob",
    "modified_at": "2026-06-15T09:00:00+00:00",
    "is_hidden": True, "is_system": False, "protected": True,
    "risk": {"level": "CRITICAL", "score": 95},
    "findings": [
        {"type": "pan", "framework": "PCI-DSS", "frameworks": ["GDPR"]},
        {"type": "pan", "framework": "PCI-DSS", "frameworks": []},
        {"type": "ssn", "framework": "GDPR", "frameworks": []},
    ],
}


class NormalizePopulationTests(unittest.TestCase):
    """Pure-function population - no database."""

    def test_asset_carries_inventory_columns(self) -> None:
        a = normalize_scan_report("t", _report("s1", [RICH_FILE])).assets[0]
        self.assertEqual(a.extension, ".xlsx")  # lowercased
        self.assertEqual(a.share, "Finance")
        self.assertEqual(a.risk_level, "CRITICAL")
        self.assertEqual(a.risk_score, 95)
        self.assertEqual(a.size, 8192)
        self.assertEqual(a.owner, "acme\\bob")
        self.assertEqual(a.modified_at, "2026-06-15T09:00:00+00:00")
        self.assertEqual(a.finding_count, 3)
        self.assertEqual((a.is_hidden, a.is_system, a.is_protected), (1, 0, 1))
        self.assertIn("q4.xlsx", a.search_text)
        self.assertEqual(a.search_text, a.search_text.lower())

    def test_top_frameworks_ranked(self) -> None:
        a = normalize_scan_report("t", _report("s1", [RICH_FILE])).assets[0]
        parts = a.top_frameworks.split(",")
        self.assertIn("PCI-DSS", parts)  # 2 primary
        self.assertIn("GDPR", parts)     # 1 primary + 1 in a frameworks list

    def test_risk_as_bare_string(self) -> None:
        f = dict(RICH_FILE, risk="HIGH")
        a = normalize_scan_report("t", _report("s1", [f])).assets[0]
        self.assertEqual((a.risk_level, a.risk_score), ("HIGH", 0))

    def test_missing_fields_default_safely(self) -> None:
        a = normalize_scan_report("t", _report("s1", [{"path": "/x", "name": "x"}])).assets[0]
        self.assertEqual(a.risk_score, 0)
        self.assertEqual(a.finding_count, 0)
        self.assertEqual(a.share, "")
        self.assertEqual((a.is_hidden, a.is_system, a.is_protected), (0, 0, 0))


class _TempStore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = store.DB_PATH
        store.DB_PATH = Path(self._tmp.name) / "sb.sqlite"
        store.init_db()

    def tearDown(self) -> None:
        store.DB_PATH = self._orig
        self._tmp.cleanup()


class AssetsRoundTripTests(_TempStore):
    def test_save_populates_asset_columns(self) -> None:
        tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(tid, "SB")
        store.save_scan_history(tid, _report("s1", [RICH_FILE]))
        with store._connect() as c:
            r = c.execute(
                "SELECT extension, risk_level, risk_score, size, finding_count, "
                "top_frameworks, is_hidden, is_protected, search_text "
                "FROM assets WHERE tenant_id = ?", (tid,)).fetchone()
        self.assertEqual(r["extension"], ".xlsx")
        self.assertEqual(r["risk_score"], 95)
        self.assertEqual(r["finding_count"], 3)
        self.assertEqual(r["is_hidden"], 1)
        self.assertIn("q4.xlsx", r["search_text"])

    def test_rescan_updates_row_in_place(self) -> None:
        tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(tid, "SB")
        store.save_scan_history(tid, _report("s1", [RICH_FILE]))
        lower = dict(RICH_FILE, risk={"level": "LOW", "score": 10}, findings=[])
        store.save_scan_history(tid, _report("s2", [lower]))
        with store._connect() as c:
            rows = c.execute(
                "SELECT risk_score, finding_count FROM assets WHERE tenant_id = ?", (tid,)).fetchall()
        self.assertEqual(len(rows), 1)  # same asset id, upserted not duplicated
        self.assertEqual(rows[0]["risk_score"], 10)
        self.assertEqual(rows[0]["finding_count"], 0)

    def test_filter_and_sort_by_inventory_columns(self) -> None:
        tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(tid, "SB")
        files = [
            {"path": "/a.txt", "name": "a.txt", "extension": ".txt", "risk": {"level": "LOW", "score": 5}, "size": 1},
            {"path": "/b.xlsx", "name": "b.xlsx", "extension": ".xlsx", "risk": {"level": "CRITICAL", "score": 99}, "size": 999},
        ]
        store.save_scan_history(tid, _report("s1", files))
        with store._connect() as c:
            names = [r["name"] for r in c.execute(
                "SELECT name FROM assets WHERE tenant_id = ? AND risk_score >= 50 ORDER BY risk_score DESC",
                (tid,)).fetchall()]
        self.assertEqual(names, ["b.xlsx"])  # DB-side filter + sort


class MigrationAndBackfillTests(_TempStore):
    def test_init_db_idempotent_columns_persist(self) -> None:
        store.init_db()  # setUp ran it once; a second run must not error
        with store._connect() as c:
            cols = db.table_columns(c, "assets")
        self.assertTrue({"extension", "risk_score", "search_text", "top_frameworks"} <= cols)

    def test_backfill_populates_inventory_columns(self) -> None:
        tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(tid, "SB")
        store.save_scan_history(tid, _report("s1", [RICH_FILE]))
        # Simulate a pre-S-B mirror by clearing the inventory columns.
        with store._connect() as c:
            c.execute(
                "UPDATE assets SET risk_score = 0, finding_count = 0, extension = '' WHERE tenant_id = ?",
                (tid,))
        result = store.backfill_normalized_scans(tid)
        self.assertGreaterEqual(result["mirrored"], 1)
        with store._connect() as c:
            r = c.execute(
                "SELECT risk_score, finding_count, extension FROM assets WHERE tenant_id = ?", (tid,)).fetchone()
        self.assertEqual((r["risk_score"], r["finding_count"], r["extension"]), (95, 3, ".xlsx"))


if __name__ == "__main__":
    unittest.main()
