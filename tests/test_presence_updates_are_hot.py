"""An unchanged rescan's presence updates are HOT, and W3.3's per-scan reads stay bounded.

W2.1 (revision 0042) made an unchanged rescan move only each asset's presence marker -
``current_scan_id`` and ``observed_at`` - and dropped the index revision 0039 had built on
it, so those updates could be HOT: a new row version on the same page, no new index
entries. Revision 0046 (W3.3) indexed the marker again for its per-scan reads, and every
presence update since wrote an entry in every index of ``assets``: 4,000 files, unchanged
rescan, 24.7 MiB of WAL and 5,340 HOT updates of 12,007 with its two indexes, 17.7 MiB and
8,008 without (measured 2026-10-08, sentro_test). Revision 0049 drops them; the reads are
bounded by (tenant, scan label) instead - an asset a scan still owns carries its label.
"""
from __future__ import annotations

import contextlib
import re
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from backend import db, store

_OBSERVED = "2026-10-08T00:00:00+00:00"


def _report(scan_id: str, label: str, paths: list[str], *, timestamp: str = _OBSERVED) -> dict:
    files = []
    for index, path in enumerate(paths):
        name = path.rsplit("/", 1)[-1]
        files.append({
            "path": path, "name": name, "extension": ".txt", "size": 100 + index, "source": "smb",
            "share": "finance", "owner": "CORP\\owner", "reuse_key": f"smb:{path}", "modified_at": _OBSERVED,
            "sha256": f"{index % 7:064x}", "content_status": "scanned",
            "risk": {"level": "HIGH" if index % 2 else "LOW", "score": 80 if index % 2 else 30},
            "findings": [{"finding_id": f"{scan_id}-{index}", "type": "email", "risk": "HIGH", "framework": "gdpr",
                          "count": 1, "status": "OPEN"}],
        })
    return {"scan_id": scan_id, "source": "smb", "summary": {"total_files": len(files)}, "scan_label": label,
            "timestamp": timestamp, "completed_at": timestamp, "files": files}


def _paths(prefix: str, count: int) -> list[str]:
    return [f"//fs01/{prefix}/f{index:04d}.txt" for index in range(count)]


class _Store(unittest.TestCase):
    def setUp(self) -> None:
        if not db.is_postgres():
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "hot.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
        store.init_db()
        self.tenant = f"hot-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Presence")


def _asset_indexes() -> dict[str, str]:
    """Every index on ``assets`` with its definition, partial predicates and expressions included."""
    with store._connect() as conn, db.platform_scope("migration"):
        if db.is_postgres():
            rows = conn.execute("SELECT indexname AS name, indexdef AS sql FROM pg_indexes "
                                "WHERE schemaname = current_schema() AND tablename = 'assets'").fetchall()
            return {str(row["name"]): str(row["sql"]) for row in rows}
        rows = conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'assets'").fetchall()
        indexes = {}
        for row in rows:
            columns = [str(info["name"]) for info in conn.execute(f"PRAGMA index_info('{row['name']}')").fetchall()
                       if info["name"]]
            indexes[str(row["name"])] = f"{row['sql'] or ''} {' '.join(columns)}"
        return indexes


class NoIndexCoversThePresenceMarkerTest(_Store):

    def test_no_index_on_assets_names_a_presence_column(self) -> None:
        indexes = _asset_indexes()
        self.assertIn("idx_assets_tenant_scan_label_id", indexes, "the index the per-scan reads go through")
        covering = {name: sql for name, sql in indexes.items()
                    if any(column in sql for column in store.PRESENCE_COLUMNS)}
        self.assertEqual(covering, {}, "an index on the presence marker makes every presence update non-HOT")

    def test_revision_49_drops_them_and_the_converged_schema_does_not_build_them_again(self) -> None:
        with store._connect() as conn, db.platform_scope("migration"):
            # An install that applied revision 0046 as it was.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_scan_content_hash "
                         "ON assets (tenant_id, current_scan_id, content_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_scan_risk ON assets (tenant_id, current_scan_id, risk_score)")
        self.assertLessEqual(set(store.PRESENCE_INDEXES), set(_asset_indexes()))
        with store._connect() as conn, db.platform_scope("migration"):
            store.drop_presence_indexes(conn)
            store.drop_presence_indexes(conn)  # re-runnable
        self.assertEqual(set(store.PRESENCE_INDEXES) & set(_asset_indexes()), set())
        # Revision 0046's function is also the converged schema: it must not bring them back.
        with store._connect() as conn, db.platform_scope("migration"):
            store.add_hash_changes(conn)
        self.assertEqual(set(store.PRESENCE_INDEXES) & set(_asset_indexes()), set())


@unittest.skipUnless(db.is_postgres(), "HOT is PostgreSQL's")
class APresenceUpdateIsHotTest(_Store):
    FILES = 200

    def test_an_unchanged_rescans_presence_update_stays_on_its_page(self) -> None:
        store.save_scan_history(self.tenant, _report("scan-a", "finance", _paths("finance", self.FILES)))
        with db.tenant_scope(self.tenant):
            context = store._connect()
            conn = context.__enter__()
            try:
                ids = [str(row["id"]) for row in conn.execute(
                    "SELECT id FROM assets WHERE tenant_id = ?", (self.tenant,)).fetchall()]
                store._stamp_presence(conn, self.tenant, "scan-b", _OBSERVED, ids)
                # This transaction's own counters: the cumulative views lag behind a commit.
                row = conn.execute("SELECT n_tup_upd, n_tup_hot_upd FROM pg_stat_xact_user_tables "
                                   "WHERE relname = 'assets' AND schemaname = current_schema()").fetchone()
            finally:
                conn._raw.rollback()
                context.__exit__(None, None, None)
        updated, hot = int(row["n_tup_upd"]), int(row["n_tup_hot_upd"])
        self.assertEqual(updated, self.FILES)
        # Fillfactor 60 leaves room on each page for about two thirds of its rows' new
        # versions in one transaction; an indexed presence column leaves room for none.
        self.assertGreaterEqual(hot, updated // 2, f"{hot} of {updated} presence updates were HOT")


class _Capturing:
    """The store's connection, with every SELECT that reads ``assets`` written down."""

    def __init__(self, conn, captured: list) -> None:
        self._conn, self._captured = conn, captured

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        if text.upper().startswith("SELECT") and " assets" in text:
            self._captured.append((text, tuple(params)))
        return self._conn.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._conn, name)


class EachPerScanReadIsBoundedByTheLabelTest(_Store):
    """W3.3's reads - the hash changes recorded after a save, a filed report's source and a
    run's view - each go through an index bounded by (tenant, scan label), never a scan of
    the table and never an index on the presence marker."""

    def _captured_reads(self) -> list[tuple[str, tuple]]:
        store.save_scan_history(self.tenant, _report("scan-big", "estate", _paths("estate", 300)))
        store.save_scan_history(self.tenant, _report("scan-small", "spot", _paths("spot", 40)))
        captured: list[tuple[str, tuple]] = []
        real = store._connect

        @contextlib.contextmanager
        def capturing():
            with real() as conn:
                yield _Capturing(conn, captured)

        store._connect = capturing
        try:
            with db.tenant_scope(self.tenant):
                store.record_hash_changes(self.tenant, "scan-small")
                store.read_report_source(self.tenant, "scan-small")
                store._scan_rows_from_assets(self.tenant, "scan-small")
        finally:
            store._connect = real
        reads = [(sql, params) for sql, params in captured if "scan_reports" not in sql.split(" WHERE ")[0]]
        self.assertGreaterEqual(len(reads), 7, "a per-scan read was not captured")
        return reads

    def test_every_read_is_an_index_search_on_tenant_and_label(self) -> None:
        reads = self._captured_reads()
        if db.is_postgres():
            with store._connect() as conn, db.platform_scope("migration"):
                conn.execute("ANALYZE assets")
        for sql, params in reads:
            with self.subTest(sql=sql[:90]):
                self.assertIn("scan_label = ?", sql)
                with db.tenant_scope(self.tenant), store._connect() as conn:
                    if db.is_postgres():
                        # With sequential scans off, the plan shows what bounds the read. On
                        # 3,200 analyzed rows the planner chose the same index with them on.
                        conn.execute("SET LOCAL enable_seqscan = off")
                        plan = "\n".join(str(row[0]) for row in conn.execute("EXPLAIN " + sql, params).fetchall())
                        self.assertNotIn("Seq Scan on assets", plan)
                        self.assertRegex(plan, r"Index Scan using idx_assets_tenant_scan_label_id on assets")
                        self.assertRegex(plan, r"Index Cond: \(\(tenant_id = .*\) AND \(scan_label = ")
                    else:
                        # SQLite has no switch for sequential scans: on a table this small its
                        # statistics prefer one. INDEXED BY is the same question - can the
                        # label's index bound this read? - and is an error when it cannot.
                        forced = re.sub(r"\b(FROM|JOIN) assets( AS a)?\b",
                                        r"\1 assets\2 INDEXED BY idx_assets_tenant_scan_label_id", sql)
                        plan = "\n".join(str(row["detail"]) for row in conn.execute(
                            "EXPLAIN QUERY PLAN " + forced, params).fetchall())
                        self.assertRegex(plan, r"SEARCH (assets|a) USING INDEX idx_assets_tenant_scan_label_id "
                                               r"\(tenant_id=\? AND scan_label=\?")


class TheLabelFindsExactlyTheScansRowsTest(_Store):
    """``scan_label = L(S) AND current_scan_id = S`` is ``current_scan_id = S``: every asset a
    scan still owns was last written by it, with its label."""

    def _owned(self, scan_id: str) -> tuple[set[str], set[str]]:
        with db.tenant_scope(self.tenant), store._connect() as conn:
            where, bound = store._scan_assets_bound(conn, self.tenant, scan_id)
            bounded = {str(row["path"]) for row in conn.execute(
                f"SELECT path FROM assets WHERE {where}", bound).fetchall()}  # noqa: S608 - the bound's own clause
            plain = {str(row["path"]) for row in conn.execute(
                "SELECT path FROM assets WHERE tenant_id = ? AND current_scan_id = ?", (self.tenant, scan_id)).fetchall()}
        return bounded, plain

    def test_files_taken_over_by_a_scan_of_another_label_leave_the_first(self) -> None:
        store.save_scan_history(self.tenant, _report("scan-a", "finance", _paths("shared", 30),
                                                     timestamp="2026-10-01T00:00:00+00:00"))
        # A later scan under another name sees ten of the same files, and some of its own.
        store.save_scan_history(self.tenant, _report("scan-b", "audit", _paths("shared", 10) + _paths("audit", 5),
                                                     timestamp="2026-10-02T00:00:00+00:00"))
        # And an unnamed scan.
        store.save_scan_history(self.tenant, _report("scan-c", "", _paths("loose", 4),
                                                     timestamp="2026-10-03T00:00:00+00:00"))
        for scan_id, expected in (("scan-a", 20), ("scan-b", 15), ("scan-c", 4)):
            with self.subTest(scan=scan_id):
                bounded, plain = self._owned(scan_id)
                self.assertEqual(len(plain), expected)
                self.assertEqual(bounded, plain)

    def test_a_scan_without_a_report_row_is_matched_on_its_id(self) -> None:
        with db.tenant_scope(self.tenant), store._connect() as conn:
            where, bound = store._scan_assets_bound(conn, self.tenant, "no-such-scan")
        # W4.2: or a file of a unit the scan skipped as unchanged (seen without a write).
        self.assertEqual(where, f"tenant_id = ? AND (current_scan_id = ? OR {store._skipped_presence('assets')})")
        self.assertEqual(bound, (self.tenant, "no-such-scan", "no-such-scan"))


if __name__ == "__main__":
    unittest.main()
