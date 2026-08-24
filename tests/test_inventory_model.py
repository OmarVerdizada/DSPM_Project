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

import json
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
        self.assertIn("critical", a.search_text)
        self.assertIn("pci_dss", a.search_text)
        self.assertIn("pan", a.search_text)
        self.assertEqual(a.search_text, a.search_text.lower())
        self.assertEqual(set(json.loads(a.finding_types)), {"pan", "ssn"})
        self.assertEqual(set(json.loads(a.framework_keys)), {"gdpr", "pci_dss"})
        self.assertEqual(json.loads(a.detail_json)["owner"], "acme\\bob")

    def test_top_frameworks_ranked(self) -> None:
        a = normalize_scan_report("t", _report("s1", [RICH_FILE])).assets[0]
        parts = a.top_frameworks.split(",")
        self.assertIn("PCI-DSS", parts)  # 2 primary
        self.assertIn("GDPR", parts)     # 1 primary + 1 in a frameworks list

    def test_scalar_frameworks_value_is_not_split_into_letters(self) -> None:
        record = dict(RICH_FILE, findings=[{"type": "token", "frameworks": "GDPR"}])
        asset = normalize_scan_report("t", _report("s1", [record])).assets[0]
        self.assertEqual(asset.top_frameworks, "GDPR")
        self.assertEqual(json.loads(asset.framework_keys), ["gdpr"])

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
        self.assertTrue({"extension", "risk_score", "search_text", "top_frameworks", "finding_types", "framework_keys", "detail_json"} <= cols)

    def test_keyset_and_readiness_indexes_are_installed_and_used(self) -> None:
        expected = {
            "idx_assets_tenant_risk_score_id", "idx_assets_tenant_size_id",
            "idx_assets_tenant_finding_count_id", "idx_assets_tenant_modified_c_id",
            "idx_assets_tenant_name_c_id", "idx_assets_tenant_missing_detail",
        }
        if db.is_sqlite():
            expected.add("idx_assets_tenant_empty_detail")
        with store._connect() as conn:
            if db.is_postgres():
                installed = {
                    row["indexname"] for row in conn.execute(
                        "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()"
                    ).fetchall()
                }
                plans = {}
            else:
                installed = {
                    row["name"] for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'index'"
                    ).fetchall()
                }
                plans = {}
                for sort, (column, is_text, direction) in store.INVENTORY_SORTS.items():
                    expression = f"COALESCE({column}, '')" if is_text else column
                    rows = conn.execute(
                        f"EXPLAIN QUERY PLAN SELECT id FROM assets WHERE tenant_id = ? "
                        f"ORDER BY {expression} {direction}, id {direction} LIMIT ?",
                        ("tenant", 101),
                    ).fetchall()
                    plans[sort] = " ".join(str(row[3]) for row in rows)
                readiness_plan = " ".join(
                    str(row[3]) for row in conn.execute(
                        "EXPLAIN QUERY PLAN SELECT 1 FROM assets "
                        "INDEXED BY idx_assets_tenant_empty_detail "
                        "WHERE tenant_id = ? AND detail_json = '{}' LIMIT 1",
                        ("tenant",),
                    ).fetchall()
                )
        self.assertTrue(expected <= installed)
        for sort, plan in plans.items():
            self.assertIn(f"idx_assets_tenant_{'modified_c' if sort == 'modified_at' else 'name_c' if sort == 'name' else sort}_id", plan)
        if db.is_sqlite():
            self.assertIn("idx_assets_tenant_empty_detail", readiness_plan)

    def test_sqlite_substring_search_uses_trigram_fts_and_tracks_upserts(self) -> None:
        if db.is_postgres():
            self.skipTest("PostgreSQL substring plans are covered by the live pg_trgm test")
        tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(tid, "SB")
        first = dict(RICH_FILE, path="/Finance/Q4_100%.xlsx", name="Q4_100%.xlsx", owner="NeedleOwner")
        store.save_scan_history(tid, _report("fts-1", [first]))
        self.assertTrue(store._sqlite_inventory_fts_enabled)
        filt = store._inventory_filters("", "", "", "NeedleOwner", "")
        where, params = store._inventory_normalized_where(tid, filt)
        with store._connect() as conn:
            plan = " ".join(
                str(row[3]) for row in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT id FROM assets WHERE " + " AND ".join(where),
                    tuple(params),
                ).fetchall()
            )
        self.assertIn("assets_search_fts", plan)
        self.assertEqual(store._list_inventory_normalized(tid, filt, "risk_score", "", 10)["total"], 1)

        replacement = dict(first, owner="CleanOwner")
        store.save_scan_history(tid, _report("fts-2", [replacement]))
        self.assertEqual(store._list_inventory_normalized(tid, filt, "risk_score", "", 10)["total"], 0)

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

    def test_backfill_replays_oldest_to_newest_for_latest_asset_state(self) -> None:
        tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(tid, "SB")
        old = dict(RICH_FILE, risk={"level": "LOW", "score": 10}, findings=[])
        new = dict(RICH_FILE, risk={"level": "CRITICAL", "score": 99})
        # Deliberately make lexical scan-id order disagree with creation order.
        store.save_scan_history(tid, _report("zzzz-old", [old]))
        store.save_scan_history(tid, _report("aaaa-new", [new]))
        with store._connect() as conn:
            conn.execute("DELETE FROM assets WHERE tenant_id = ?", (tid,))
            conn.execute("DELETE FROM scan_runs WHERE tenant_id = ?", (tid,))

        result = store.backfill_normalized_scans(tid)
        self.assertEqual(result["failed"], 0)
        with store._connect() as conn:
            row = conn.execute(
                "SELECT risk_level, risk_score FROM assets WHERE tenant_id = ?", (tid,)
            ).fetchone()
        self.assertEqual((row["risk_level"], row["risk_score"]), ("CRITICAL", 99))


if __name__ == "__main__":
    unittest.main()
