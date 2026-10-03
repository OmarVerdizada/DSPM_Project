"""W1.4 (scaling roadmap, 2026-10): the database work a scan and a click cost must not depend
on what PostgreSQL's statistics happen to say, nor grow with the size of the scan.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from backend import db, store

LABEL = "finance-share"


def _file(path: str) -> dict:
    name = path.rsplit("/", 1)[-1]
    return {"path": path, "name": name, "extension": ".txt", "size": 10,
            "modified_at": "2026-09-01T00:00:00+00:00", "risk": {"level": "HIGH", "score": 80},
            "findings": [{"finding_id": f"f-{name}", "type": "email", "risk": "HIGH",
                          "framework": "gdpr", "count": 1, "status": "OPEN"}]}


def _report(scan_id: str, paths, label: str = LABEL) -> dict:
    return {"scan_id": scan_id, "source": "smb", "summary": {}, "scan_label": label,
            "timestamp": "2026-09-01T00:00:00+00:00", "files": [_file(path) for path in paths]}


class _Recording:
    """A connection that remembers every statement it ran."""

    def __init__(self, conn) -> None:
        self.conn = conn
        self.statements: list[str] = []

    def execute(self, sql, params=()):
        self.statements.append(sql)
        return self.conn.execute(sql, params)


class TheUnseenAssetsOfANamedScanLeaveTest(unittest.TestCase):
    """The prune was four statements of ``asset_id IN (SELECT id FROM assets ...)``. A first
    save writes every row in the transaction that prunes, before PostgreSQL has statistics;
    it estimated one row, chose a nested loop, and a 20,000-file first save was still
    pruning after 634 s. It now reads the stale ids through an index range and removes them
    by id, a chunk at a time."""

    def setUp(self) -> None:
        self.tenant = f"w14-prune-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Prune")

    def _count(self, sql: str, *params) -> int:
        with store._connect() as conn:
            return int(conn.execute(sql, (self.tenant, *params)).fetchone()[0])

    def _paths(self) -> set[str]:
        with store._connect() as conn:
            return {row["path"] for row in conn.execute(
                "SELECT path FROM assets WHERE tenant_id = ?", (self.tenant,)).fetchall()}

    def _assert_prunes(self, first: str, second: str) -> None:
        everything = [f"//fs01/finance/file{index}.txt" for index in range(11)]
        kept = everything[:4]
        store.save_scan_history(self.tenant, _report(first, everything))
        store.save_scan_history(self.tenant, _report("other-scope", ["//fs01/hr/a.txt"], label="hr-share"))
        self.assertEqual(self._count("SELECT COUNT(*) FROM asset_versions WHERE tenant_id = ?"), 12)

        with patch.object(store, "_ID_CHUNK", 3):  # seven stale assets: three chunks
            store.save_scan_history(self.tenant, _report(second, kept))

        self.assertEqual(self._paths(), {*kept, "//fs01/hr/a.txt"})
        self.assertEqual(self._count("SELECT COUNT(*) FROM asset_versions WHERE tenant_id = ?"), 5)
        current = self._count("SELECT COUNT(*) FROM findings WHERE tenant_id = ? AND is_current = 1")
        historical = self._count("SELECT COUNT(*) FROM findings WHERE tenant_id = ? AND is_current = 0")
        self.assertEqual((current, historical), (5, 7))

    def test_stale_assets_older_than_the_scan_leave_across_chunks(self) -> None:
        self._assert_prunes("scan-a", "scan-b")

    def test_stale_assets_whose_scan_id_sorts_after_this_one_leave_too(self) -> None:
        # current_scan_id <> ? is read as two ranges; this one is the "above" side.
        self._assert_prunes("scan-z", "scan-b")

    def test_a_rescan_that_saw_everything_removes_nothing(self) -> None:
        paths = [f"//fs01/finance/file{index}.txt" for index in range(5)]
        store.save_scan_history(self.tenant, _report("scan-a", paths))
        store.save_scan_history(self.tenant, _report("scan-b", paths))
        self.assertEqual(self._paths(), set(paths))
        self.assertEqual(self._count("SELECT COUNT(*) FROM findings WHERE tenant_id = ? AND is_current = 1"), 5)

    def test_no_prune_statement_joins_back_to_assets(self) -> None:
        store.save_scan_history(self.tenant, _report("scan-a", [f"//fs01/finance/f{i}.txt" for i in range(4)]))
        store.save_scan_history(self.tenant, _report("scan-b", ["//fs01/finance/f0.txt"]))
        with store._connect() as conn:
            conn.execute("UPDATE assets SET current_scan_id = 'scan-a' WHERE tenant_id = ?", (self.tenant,))
            recording = _Recording(conn)
            store._prune_unseen_assets(recording, self.tenant, LABEL, "scan-c")
        self.assertTrue(recording.statements)
        for sql in recording.statements:
            self.assertNotIn("(SELECT", sql.upper().replace("( SELECT", "(SELECT"), sql)
        self.assertEqual(self._paths(), set())

    def test_the_stale_read_is_served_by_the_prune_index(self) -> None:
        sql = ("SELECT current_scan_id, id FROM assets WHERE tenant_id = ? AND scan_label = ? "
               "AND current_scan_id < ? AND (current_scan_id, id) > (?, ?) ORDER BY current_scan_id, id LIMIT ?")
        params = (self.tenant, LABEL, "scan-b", "", "", 900)
        with store._connect() as conn:
            if db.is_postgres():
                # Whether the index is chosen on a near-empty table is the planner's call;
                # that the predicate and the order can be served by it is not.
                conn.execute("SET LOCAL enable_seqscan = off")
                conn.execute("SET LOCAL enable_bitmapscan = off")
                plan = " ".join(str(row[0]) for row in conn.execute(f"EXPLAIN {sql}", params).fetchall())
                self.assertNotIn("Sort", plan, plan)
            else:
                plan = " ".join(str(row[-1]) for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}", params).fetchall())
                self.assertNotIn("TEMP B-TREE", plan.upper(), plan)
        self.assertIn("idx_assets_tenant_scan_label_current_id", plan)


_WRITE = re.compile(r"^\s*(?:INSERT\s+(?:OR\s+\w+\s+)?INTO|UPDATE|DELETE\s+FROM)\s+(\w+)", re.IGNORECASE)


class _Tracing:
    """A connection that records each statement it runs with the rows it touched."""

    def __init__(self, conn, log: list) -> None:
        self._conn = conn
        self._log = log

    def execute(self, sql, params=()):
        cursor = self._conn.execute(sql, params)
        self._log.append((" ".join(str(sql).split()), getattr(cursor, "rowcount", -1)))
        return cursor

    def executemany(self, sql, rows):
        rows = list(rows)
        cursor = self._conn.executemany(sql, rows)
        self._log.append((" ".join(str(sql).split()), len(rows)))
        return cursor

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _tracing_connect(log: list):
    real = store._connect

    @contextlib.contextmanager
    def connect():
        with real() as conn:
            yield _Tracing(conn, log)

    return connect


class AClickWritesOneFindingTest(unittest.TestCase):
    """A lifecycle action re-saved the whole report that held the finding: every asset,
    finding and index row of the scan and the encrypted body, for one click. It now writes
    the finding's row, its index row in the scan that owns it and the audit trail, in one
    transaction; what was said about the finding lives on its row (`lifecycle_json`,
    revision 0040) and readers lay it over the saved report."""

    FILES = 300

    def setUp(self) -> None:
        self.tenant = f"w14-click-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Click")
        store.save_scan_history(self.tenant, _report("scan-a", [f"//fs01/finance/f{i}.txt" for i in range(self.FILES)]))
        self.finding_id = self._id("//fs01/finance/f7.txt")

    def _id(self, path: str) -> str:
        with store._connect() as conn:
            return str(conn.execute("SELECT id FROM findings WHERE tenant_id = ? AND file_path = ?",
                                    (self.tenant, path)).fetchone()["id"])

    def _row(self) -> dict:
        with store._connect() as conn:
            return dict(conn.execute("SELECT * FROM findings WHERE tenant_id = ? AND id = ?",
                                     (self.tenant, self.finding_id)).fetchone())

    def _act(self, action: str, payload: dict) -> dict:
        return store.update_finding_lifecycle(self.tenant, self.finding_id, action, payload, "analyst")

    def test_an_action_writes_its_row_its_index_row_and_the_audit_trail(self) -> None:
        log: list = []
        resaved = AssertionError("a lifecycle action re-saved the report")
        with patch.object(store, "save_scan_history", side_effect=resaved), \
                patch.object(store, "_connect", _tracing_connect(log)):
            self._act("assign", {"owner": "hr-team", "comment": "yours now"})
        writes = [(match.group(1).lower(), rows) for sql, rows in log if (match := _WRITE.match(sql))]
        tables = {table for table, _rows in writes}
        # Bookkeeping beside the three rows: the audit chain's head, and the workspace's
        # cache generation (`tenants.estate_generation`) moved after the commit.
        bookkeeping = {"audit_chain_heads", "tenants"}
        self.assertLessEqual(tables, {"findings", "finding_index", "audit_events", *bookkeeping}, writes)
        for table, rows in writes:
            self.assertLessEqual(rows, 1, f"{table}: {rows} rows for one click")
        data_rows = sum(rows for table, rows in writes if table not in bookkeeping)
        self.assertLessEqual(data_rows, 3, writes)
        self.assertIn("findings", tables)
        self.assertIn("audit_events", tables)

    def test_the_change_is_what_every_reader_sees(self) -> None:
        self._act("assign", {"owner": "hr-team", "comment": "yours now"})
        row = self._row()
        self.assertEqual((row["status"], row["owner"]), ("ASSIGNED", "hr-team"))

        finding = store.get_finding(self.tenant, self.finding_id)
        self.assertEqual((finding["status"], finding["owner"], finding["assignee"]), ("ASSIGNED", "hr-team", "hr-team"))
        self.assertEqual([comment["comment"] for comment in finding["comments"]], ["yours now"])
        self.assertEqual([event["action"] for event in store.get_finding_history(self.tenant, self.finding_id)],
                         ["assign"])

        report = store.read_scan_report(self.tenant, "scan-a")
        in_body = next(item for file_obj in report["files"] for item in file_obj["findings"]
                       if item["finding_id"] == self.finding_id)
        self.assertEqual((in_body["status"], in_body["owner"]), ("ASSIGNED", "hr-team"))
        self.assertEqual(len(in_body["comments"]), 1)

        with store._connect() as conn:
            index = conn.execute("SELECT status, response_json FROM finding_index WHERE tenant_id = ? AND finding_id = ?",
                                 (self.tenant, self.finding_id)).fetchone()
        self.assertEqual(index["status"], "ASSIGNED")
        self.assertEqual(json.loads(store.unpack_json_text(index["response_json"]))["owner"], "hr-team")

        page = store.list_remediation_findings(self.tenant, status="all", q="hr-team")
        self.assertEqual([item["finding_id"] for item in page["items"]], [self.finding_id],
                         "the queue search still matches the old owner")

    def test_what_was_said_about_a_finding_survives_the_next_scan(self) -> None:
        self._act("comment", {"comment": "checked with finance"})
        self._act("status", {"status": "CONFIRMED"})
        store.save_scan_history(self.tenant, _report("scan-b", [f"//fs01/finance/f{i}.txt" for i in range(self.FILES)]))

        finding = store.get_finding(self.tenant, self.finding_id)
        self.assertEqual(finding["scan_id"], "scan-b")
        self.assertEqual(finding["status"], "CONFIRMED")
        self.assertEqual([comment["comment"] for comment in finding["comments"]], ["checked with finance"])
        self.assertEqual([event["action"] for event in finding["status_history"]], ["comment", "status"])

        # Acted on again after the rescan: the detail comes from the row, not from the new
        # scan's copy of the finding, which never held it.
        self._act("comment", {"comment": "still open"})
        finding = store.get_finding(self.tenant, self.finding_id)
        self.assertEqual([comment["comment"] for comment in finding["comments"]],
                         ["checked with finance", "still open"])

    def test_detail_an_earlier_action_left_in_the_report_is_kept(self) -> None:
        # Before W1.4 an action re-saved the report, so its comment lives only in the body.
        store._update_finding_lifecycle_in_report(self.tenant, self.finding_id, "comment",
                                                  {"comment": "from before the upgrade"}, "analyst")
        self.assertEqual(self._row()["lifecycle_json"], "")
        self._act("comment", {"comment": "after the upgrade"})
        finding = store.get_finding(self.tenant, self.finding_id)
        self.assertEqual([comment["comment"] for comment in finding["comments"]],
                         ["from before the upgrade", "after the upgrade"])
        self.assertEqual(len(finding["status_history"]), 2)

    def test_two_analysts_commenting_at_once_both_keep_their_comment(self) -> None:
        # Below the workspace-wide edit lock, on purpose: the row is read again under its
        # own lock, so two edits that both read the finding first still both land.
        real = store._stored_finding_response

        def slow(*args, **kwargs):
            response = real(*args, **kwargs)
            time.sleep(0.3)  # both have read the finding before either writes
            return response

        errors: list = []

        def comment(text: str) -> None:
            try:
                store._update_finding_lifecycle(self.tenant, self.finding_id, "comment", {"comment": text}, "analyst")
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        with patch.object(store, "_stored_finding_response", slow):
            threads = [threading.Thread(target=comment, args=(text,)) for text in ("first", "second")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(errors, [])
        finding = store.get_finding(self.tenant, self.finding_id)
        self.assertEqual(sorted(comment["comment"] for comment in finding["comments"]), ["first", "second"])

    def test_a_historical_finding_is_still_read_only(self) -> None:
        store.save_scan_history(self.tenant, _report("scan-b", ["//fs01/finance/f0.txt"]))
        with self.assertRaisesRegex(ValueError, "read-only"):
            self._act("comment", {"comment": "too late"})

    def test_the_workflow_endpoint_writes_the_row_too(self) -> None:
        resaved = AssertionError("a workflow update re-saved the report")
        with patch.object(store, "save_scan_history", side_effect=resaved):
            updated = store.update_finding_workflow(
                self.tenant, "scan-a", {"path": "//fs01/finance/f7.txt", "type": "email"},
                {"review_status": "confirmed", "owner": "legal", "comment": "seen"}, "analyst")
        self.assertEqual(updated["review_status"], "confirmed")
        self.assertEqual(self._row()["owner"], "legal")
        finding = store.get_finding(self.tenant, self.finding_id)
        self.assertEqual((finding["review_status"], finding["owner"]), ("confirmed", "legal"))
        self.assertEqual(finding["status_history"][-1]["comment"], "seen")


class EveryPostgresSessionIsBoundedTest(unittest.TestCase):
    """A statement whose plan went wrong ran for as long as it liked, holding its locks,
    and a transaction a crashed caller left open held its locks until its connection
    closed. Application sessions now open with statement, lock and idle-in-transaction
    timeouts; the schema upgrade lifts them for its own transaction."""

    def test_the_session_options_carry_the_three_bounds(self) -> None:
        with patch.dict(os.environ, {"DSPM_PG_STATEMENT_TIMEOUT_SECONDS": "30", "DSPM_PG_LOCK_TIMEOUT_SECONDS": "0"}):
            options = db.session_options()
        self.assertIn("-c statement_timeout=30000", options)
        self.assertIn("-c lock_timeout=0", options)
        self.assertIn("-c idle_in_transaction_session_timeout=1800000", options)

    @unittest.skipUnless(db.is_postgres(), "PostgreSQL session settings")
    def test_a_statement_past_its_bound_is_cancelled(self) -> None:
        with patch.dict(os.environ, {"DSPM_PG_STATEMENT_TIMEOUT_SECONDS": "1"}):
            db.close_pool()
            try:
                with store._connect() as conn:
                    self.assertEqual(conn.execute("SHOW statement_timeout").fetchone()[0], "1s")
                with self.assertRaisesRegex(Exception, "statement timeout"), store._connect() as conn:
                    conn.execute("SELECT pg_sleep(3)")
            finally:
                db.close_pool()

    @unittest.skipUnless(db.is_postgres(), "the runner lifts PostgreSQL session settings")
    def test_the_schema_upgrade_runs_unbounded(self) -> None:
        from backend import migrations

        seen: dict = {}
        real = store._connect

        class Probe:
            def __init__(self, conn) -> None:
                self._conn = conn

            def execute(self, sql, params=()):
                cursor = self._conn.execute(sql, params)
                if str(sql).startswith("SELECT pg_advisory_xact_lock"):
                    for parameter in ("statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout"):
                        seen[parameter] = self._conn.execute(f"SHOW {parameter}").fetchone()[0]
                return cursor

            def __getattr__(self, name):
                return getattr(self._conn, name)

        @contextlib.contextmanager
        def connect():
            with real() as conn:
                yield Probe(conn)

        with patch.object(store, "_connect", connect):
            migrations.upgrade()
        self.assertEqual(seen, {"statement_timeout": "0", "lock_timeout": "0",
                                "idle_in_transaction_session_timeout": "0"})
        with store._connect() as conn:
            self.assertEqual(conn.execute("SHOW statement_timeout").fetchone()[0], "15min",
                             "the lift outlived the upgrade transaction")
