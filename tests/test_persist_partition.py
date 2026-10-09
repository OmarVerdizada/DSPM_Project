"""B2.2b-1: a finished partition persists on its own.

A partitioned scan writes each partition as it finishes, and a later finalize step
does what only the whole scan can. The danger is in statements that look local and
are not: the ordinary write deletes every finding occurrence of the scan, writes the
immutable scan run with the whole-scan summary, prunes assets and baseline objects
it did not see, and deletes the whole finding index. Run by a partition, each of
those would destroy the partitions before it.

These tests pin that partitions persisted separately write exactly the rows one save
writes - including against a prior scan whose findings an analyst has triaged -
that none of those whole-scan statements runs, that the ledger rather than the
caller decides where a partition's findings sit, that a failed or stale write leaves
nothing behind, and that retention keeps what finalize will need.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from backend import artifacts, db, store

SCAN = "scan-partitioned"
_TABLES = ("assets", "asset_versions", "findings", "finding_occurrences", "finding_index", "scan_object_baselines")
_VOLATILE = {"scan_object_baselines": {"last_seen_at", "updated_at"}, "findings": {"seq"}, "finding_index": {"seq"}}


def _files(count: int, *, start: int = 0, level_shift: int = 0) -> list[dict]:
    files = []
    for index in range(start, start + count):
        files.append({
            "path": f"//fs01/share/dept{index % 5}/file{index}.txt",
            "name": f"file{index}.txt",
            "extension": ".txt",
            "size": 1000 + index,
            "source": "smb",
            "share": "share",
            "owner": "CORP/svc",
            "content_status": "scanned",
            "sha256": f"{index:064x}",
            "content_hash": f"{index:064x}",
            "modified_at": "2026-01-01T00:00:00Z",
            "reuse_key": f"smb://fs01/share/dept{index % 5}/file{index}.txt",
            "risk": {"level": ("HIGH", "LOW", "MEDIUM")[(index + level_shift) % 3], "score": 40 + index % 50,
                     "reasons": ["r"], "dlp_recommendations": ["a"]},
            "findings": [
                {"type": ("credit_card", "email")[which], "finding_id": f"f-{index}-{which}",
                 "risk": ("HIGH", "LOW", "MEDIUM")[(index + which + level_shift) % 3],
                 "count": 1 + which, "occurrence_count": 1 + which,
                 "description": "d", "samples": ["x"], "category": "pii", "framework": "gdpr"}
                for which in range(2)
            ],
        })
    return files


def _header(*, label: str = "", complete: bool = False, timestamp: str = "2026-09-14T00:00:00Z") -> dict:
    return {
        "timestamp": timestamp,
        "source": "smb",
        "mode": "full",
        "summary": {"total_files": 0},
        "scan_diagnostics": {"incremental": {
            "enabled": True, "baseline_update": True, "scope_key": "scope-partitioned",
            "version_signature": "v1", "complete": complete,
        }},
        **({"scan_label": label} if label else {}),
    }


def _copy(value):
    return json.loads(json.dumps(value))


class _PartitionTest(unittest.TestCase):
    """A database of its own. `DSPM_DB_PATH` alone would not do it: `store.DB_PATH`
    is read at import, so the path is patched on the module."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._db_path = Path(self._dir.name) / "partition.sqlite"
        self._previous_path = store.DB_PATH
        store.DB_PATH = self._db_path
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "partitions")

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    # -- state --------------------------------------------------------------------------------------------
    def _snapshot(self) -> Path:
        target = Path(self._dir.name) / f"snapshot-{uuid.uuid4().hex[:6]}.sqlite"
        with sqlite3.connect(str(self._db_path)) as source, sqlite3.connect(str(target)) as copy:
            source.backup(copy)
        source.close()
        copy.close()
        return target

    def _restore(self, snapshot: Path) -> None:
        with sqlite3.connect(str(snapshot)) as source, sqlite3.connect(str(self._db_path)) as live:
            source.backup(live)
        source.close()
        live.close()

    def _fingerprint(self) -> dict:
        out = {}
        with store._connect() as conn:
            for table in _TABLES:
                rows = conn.execute(f"SELECT * FROM {table} WHERE tenant_id = ?", (self.tenant,)).fetchall()
                skip = _VOLATILE.get(table, set())
                serialised = sorted(
                    json.dumps({k: str(row[k]) for k in row.keys() if k not in skip}, sort_keys=True)
                    for row in rows
                )
                out[table] = (len(rows), hashlib.sha256("\n".join(serialised).encode()).hexdigest())
        return out

    def _order(self, table: str = "finding_index", scan_id: str = SCAN) -> list[str]:
        column = "finding_id" if table == "finding_index" else "id"
        where = "scan_id" if table == "finding_index" else "scan_id"
        with store._connect() as conn:
            return [str(r[column]) for r in conn.execute(
                f"SELECT {column} FROM {table} WHERE tenant_id = ? AND {where} = ? ORDER BY seq",
                (self.tenant, scan_id),
            ).fetchall()]

    def _count(self, sql: str, *params) -> int:
        with store._connect() as conn:
            return int(conn.execute(sql, (self.tenant, *params)).fetchone()[0])

    # -- scans --------------------------------------------------------------------------------------------
    def _single(self, files: list[dict], header: dict, scan_id: str = SCAN) -> None:
        store.save_scan_history(self.tenant, {**_copy(header), "scan_id": scan_id, "files": _copy(files)})

    def _partitioned(self, parts: list[list[dict]], header: dict, scan_id: str = SCAN) -> list[dict]:
        store.create_scan_partitions(self.tenant, scan_id, "job-p", [{"part": index} for index in range(len(parts))])
        results = []
        for records in parts:
            unit = store.claim_next_partition(self.tenant, scan_id)
            results.append(store.persist_partition(
                self.tenant, scan_id, unit["partition_id"], unit["attempt"], _copy(header), _copy(records),
                write_estate=True,
            ))
        return results


class PartitionsWriteWhatOneSaveWritesTest(_PartitionTest):

    def test_on_an_empty_estate_the_rows_match_and_follow_plan_order(self) -> None:
        clean = self._snapshot()
        self._single(_files(12), _header())
        single, single_order = self._fingerprint(), self._order()

        self._restore(clean)
        self._partitioned([_files(7), _files(5, start=7)], _header())
        self.assertEqual(self._fingerprint(), single)
        self.assertEqual(self._order(), single_order)

    def test_against_a_prior_scan_with_triage_the_rows_still_match(self) -> None:
        """Carry-forward is where a partition could most plausibly differ: it reads
        the lifecycle a previous scan and an analyst left behind."""
        self._single(_files(12), _header(timestamp="2026-09-01T00:00:00Z"), scan_id="scan-prior")
        with store._connect() as conn:
            conn.execute(
                "UPDATE findings SET status = 'CONFIRMED', owner = 'analyst@corp', sla_due = '2026-12-31' "
                "WHERE tenant_id = ? AND id IN ('f-4-0', 'f-5-1', 'f-9-0')",
                (self.tenant,),
            )
        prior = self._snapshot()
        # Overlaps the prior scan, adds new files, and changes severities so the
        # escalation rule is exercised too.
        files = _files(12, start=4, level_shift=1)

        self._single(files, _header())
        single, single_order = self._fingerprint(), self._order()

        self._restore(prior)
        self._partitioned([files[:5], files[5:9], files[9:]], _header())
        self.assertEqual(self._fingerprint(), single)
        self.assertEqual(self._order(), single_order)
        with store._connect() as conn:
            kept = conn.execute(
                "SELECT status, owner FROM findings WHERE tenant_id = ? AND id = 'f-4-0'", (self.tenant,),
            ).fetchone()
        self.assertEqual((kept["status"], kept["owner"]), ("CONFIRMED", "analyst@corp"),
                         "a partition reset the analyst's triage")


class NoWholeScanStatementRunsTest(_PartitionTest):

    def test_a_partition_writes_no_scan_run_or_report_and_prunes_nothing(self) -> None:
        self._single(_files(1, start=900), _header(label="partitioned", complete=True), scan_id="scan-earlier")
        self.assertEqual(self._count(
            "SELECT COUNT(*) FROM assets WHERE tenant_id = ? AND current_scan_id = 'scan-earlier'"), 1)

        self._partitioned([_files(2), _files(2, start=2)], _header(label="partitioned", complete=True))

        self.assertEqual(self._count("SELECT COUNT(*) FROM scan_runs WHERE tenant_id = ? AND id = ?", SCAN), 0,
                         "a partition wrote the immutable scan run before the summary existed")
        self.assertEqual(self._count("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ? AND scan_id = ?", SCAN), 0)
        self.assertEqual(self._count(
            "SELECT COUNT(*) FROM assets WHERE tenant_id = ? AND current_scan_id = 'scan-earlier'"), 1,
            "a partition pruned an asset it never saw")
        self.assertEqual(self._count(
            "SELECT COUNT(*) FROM scan_object_baselines WHERE tenant_id = ? AND last_scan_id = 'scan-earlier'"), 1,
            "a partition pruned a baseline object it never saw")

    def test_a_later_partition_keeps_the_earlier_partitions_rows(self) -> None:
        self._partitioned([_files(2), _files(2, start=2)], _header())
        self.assertEqual(self._count(
            "SELECT COUNT(*) FROM finding_occurrences WHERE tenant_id = ? AND scan_id = ?", SCAN), 8)
        self.assertEqual(self._count(
            "SELECT COUNT(*) FROM finding_index WHERE tenant_id = ? AND scan_id = ?", SCAN), 8)


class TheLedgerDecidesTest(_PartitionTest):

    def test_the_order_is_the_plans_not_the_order_partitions_finish_in(self) -> None:
        clean = self._snapshot()
        parts = [_files(3), _files(3, start=3), _files(3, start=6)]
        self._single([f for part in parts for f in part], _header())
        single_order = self._order()

        self._restore(clean)
        store.create_scan_partitions(self.tenant, SCAN, "job-p", [{"part": i} for i in range(3)])
        units = [store.claim_next_partition(self.tenant, SCAN) for _ in range(3)]
        for unit, records in reversed(list(zip(units, parts))):
            store.persist_partition(self.tenant, SCAN, unit["partition_id"], unit["attempt"],
                                    _header(), _copy(records), write_estate=True)
        self.assertEqual(self._order(), single_order)
        self.assertEqual(self._count("SELECT COUNT(*) FROM finding_index WHERE tenant_id = ?"), 18,
                         "a partition deleted another partition's index range")

    def test_a_worker_that_lost_its_partition_writes_nothing_at_all(self) -> None:
        store.create_scan_partitions(self.tenant, SCAN, "job-p", [{"part": 0}])
        stale = store.claim_next_partition(self.tenant, SCAN)
        store.requeue_interrupted_partitions(self.tenant)
        store.claim_next_partition(self.tenant, SCAN)
        with mock.patch.object(artifacts, "put_stream", side_effect=AssertionError("wrote an artifact")):
            with self.assertRaises(store.PartitionNotClaimed):
                store.persist_partition(self.tenant, SCAN, stale["partition_id"], stale["attempt"], _header(),
                                        _files(3), write_estate=True)
        self.assertEqual(self._count("SELECT COUNT(*) FROM assets WHERE tenant_id = ?"), 0)
        self.assertEqual(store.list_scan_partitions(self.tenant, SCAN)[0]["status"], "running")

    def test_an_unplanned_partition_is_refused(self) -> None:
        with self.assertRaises(store.PartitionNotClaimed):
            store.persist_partition(self.tenant, SCAN, "p99999", 1, _header(), _files(1), write_estate=True)

    def test_a_plan_too_long_to_order_is_refused_when_it_is_made(self) -> None:
        with self.assertRaises(ValueError):
            store.create_scan_partitions(self.tenant, SCAN, "job-p", [{}] * (store.MAX_SCAN_PARTITIONS + 1))
        self.assertEqual(store.MAX_SCAN_PARTITIONS, 2147)
        self.assertLessEqual(store.MAX_SCAN_PARTITIONS * store.PARTITION_SEQ_SPAN - 1, 2_147_483_647)


@unittest.skipIf(db.is_postgres(), "restores a SQLite snapshot mid-test")
class AFailedWriteLeavesNothingTest(_PartitionTest):

    def test_a_write_that_fails_partway_rolls_back_and_a_smaller_rerun_is_exact(self) -> None:
        """The ledger re-runs an interrupted partition, possibly over fewer files."""
        clean = self._snapshot()
        smaller = _files(2)
        self._single(smaller, _header())
        expected = self._fingerprint()

        self._restore(clean)
        store.create_scan_partitions(self.tenant, SCAN, "job-p", [{"part": 0}])
        first = store.claim_next_partition(self.tenant, SCAN)
        with mock.patch.object(artifacts, "put_stream", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                store.persist_partition(self.tenant, SCAN, first["partition_id"], first["attempt"], _header(),
                                        _files(4), write_estate=True)
        self.assertEqual(self._count("SELECT COUNT(*) FROM assets WHERE tenant_id = ?"), 0,
                         "rows of a failed partition survived")
        store.requeue_interrupted_partitions(self.tenant)
        again = store.claim_next_partition(self.tenant, SCAN)
        store.persist_partition(self.tenant, SCAN, again["partition_id"], again["attempt"], _header(),
                                _copy(smaller), write_estate=True)
        self.assertEqual(self._fingerprint(), expected)


class WhatFinalizeReadsBackTest(_PartitionTest):

    def test_the_records_come_back_as_the_rows_left_them(self) -> None:
        records = _files(4)
        header = {**_header(), "summary": {"total_files": 4, "high": 2}}
        store.create_scan_partitions(self.tenant, SCAN, "job-p", [{"part": 0}])
        unit = store.claim_next_partition(self.tenant, SCAN)
        store.persist_partition(self.tenant, SCAN, unit["partition_id"], unit["attempt"], header, records,
                                write_estate=True)
        row = store.list_scan_partitions(self.tenant, SCAN)[0]
        self.assertEqual(row["status"], "done")
        self.assertEqual(row["summary"], {"total_files": 4, "high": 2})
        self.assertTrue(row["diagnostics"]["incremental"]["prune_skipped"])
        self.assertEqual(row["records_bytes"], len(json.dumps(records, ensure_ascii=False).encode("utf-8")))
        stored = json.loads(artifacts.get_bytes(self.tenant, row["records_ref"]))
        # Writing the rows fills lifecycle fields into the findings; finalize must
        # stream what a single save would have stored, so the records include them.
        self.assertEqual(stored, json.loads(json.dumps(records, ensure_ascii=False)))
        self.assertIn("first_seen", stored[0]["findings"][0])
        self.assertIn("status", stored[0]["findings"][0])

    def test_with_the_artifact_tier_off_the_records_are_kept_inline(self) -> None:
        records = _files(3)
        with mock.patch.dict(os.environ, {"DSPM_REPORT_ARTIFACTS": "0"}):
            store.create_scan_partitions(self.tenant, SCAN, "job-p", [{"part": 0}])
            unit = store.claim_next_partition(self.tenant, SCAN)
            store.persist_partition(self.tenant, SCAN, unit["partition_id"], unit["attempt"], _header(), records,
                                    write_estate=True)
        with store._connect() as conn:
            row = conn.execute(
                "SELECT records_ref, records_json FROM scan_partitions WHERE tenant_id = ?", (self.tenant,),
            ).fetchone()
        self.assertEqual(row["records_ref"], "")
        self.assertEqual(json.loads(store.unpack_json_text(row["records_json"])),
                         json.loads(json.dumps(records, ensure_ascii=False)))

    def test_iter_json_array_is_json_dumps(self) -> None:
        for items in ([], [{}], [{"a": "Şəmsi"}, [1, 2], None], _files(2)):
            self.assertEqual("".join(store.iter_json_array(items)), json.dumps(items, ensure_ascii=False))


class RetentionKeepsWhatFinalizeNeedsTest(_PartitionTest):

    def test_a_partitions_records_survive_artifact_collection(self) -> None:
        store.create_scan_partitions(self.tenant, SCAN, "job-p", [{"part": 0}])
        unit = store.claim_next_partition(self.tenant, SCAN)
        store.persist_partition(self.tenant, SCAN, unit["partition_id"], unit["attempt"], _header(), _files(3),
                                write_estate=True)
        ref = store.list_scan_partitions(self.tenant, SCAN)[0]["records_ref"]

        referenced = store.referenced_artifact_ids()
        self.assertIn((self.tenant, ref), referenced)
        artifacts.prune(referenced, grace_seconds=0)
        self.assertTrue(artifacts.exists(self.tenant, ref), "retention collected a partition's records")

    def test_both_retention_entry_points_use_the_same_definition(self) -> None:
        import importlib.util

        root = Path(__file__).resolve().parents[1]
        for script in ("db_artifacts.py", "db_retention.py"):
            text = (root / "scripts" / script).read_text(encoding="utf-8")
            self.assertIn("referenced_artifact_ids()", text, f"{script} computes its own referenced set")
        spec = importlib.util.spec_from_file_location("db_artifacts_cli", root / "scripts" / "db_artifacts.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        store.create_scan_partitions(self.tenant, SCAN, "job-p", [{"part": 0}])
        unit = store.claim_next_partition(self.tenant, SCAN)
        store.persist_partition(self.tenant, SCAN, unit["partition_id"], unit["attempt"], _header(), _files(2),
                                write_estate=True)
        ref = store.list_scan_partitions(self.tenant, SCAN)[0]["records_ref"]
        self.assertIn((self.tenant, ref), module._referenced())


class LimitsAndSchemaTest(_PartitionTest):

    def test_the_index_refuses_to_spill_into_the_next_partitions_range(self) -> None:
        report = {**_header(), "scan_id": SCAN, "files": _files(2)}
        with self.assertRaises(ValueError):
            with store._connect() as conn:
                store._write_finding_index(conn, self.tenant, report, seq_offset=0, seq_span=3)

    def test_the_estate_write_refuses_to_spill_too(self) -> None:
        report = {**_header(), "scan_id": SCAN, "files": _files(2)}
        with self.assertRaises(ValueError):
            with store._connect() as conn:
                store._write_normalized_rows(conn, self.tenant, report,
                                             partition={"seq_offset": 0, "seq_span": 3, "write_estate": True})

    @unittest.skipIf(db.is_postgres(), "reads SQLite's EXPLAIN QUERY PLAN")
    def test_a_partitions_deletes_seek_to_its_own_rows(self) -> None:
        """Measured before revision 0013: both deletes walked every row the scan had
        written, so each partition's write cost more memory and time than the last."""
        with store._connect() as conn:
            occurrences = " ".join(str(row[3]) for row in conn.execute(
                "EXPLAIN QUERY PLAN DELETE FROM finding_occurrences "
                "WHERE tenant_id = ? AND scan_id = ? AND finding_id IN (?, ?)", ("t", "s", "a", "b"),
            ).fetchall())
            index_range = " ".join(str(row[3]) for row in conn.execute(
                "EXPLAIN QUERY PLAN DELETE FROM finding_index "
                "WHERE tenant_id = ? AND scan_id = ? AND seq >= ? AND seq < ?", ("t", "s", 0, 10),
            ).fetchall())
        self.assertIn("idx_occurrences_scan_finding (tenant_id=? AND scan_id=? AND finding_id=?)", occurrences)
        self.assertIn("idx_finding_index_tenant_scan_seq (tenant_id=? AND scan_id=? AND seq>? AND seq<?)", index_range)

    @unittest.skipIf(db.is_postgres(), "builds an older SQLite file; the PostgreSQL upgrade path is scripted in C0.5")
    def test_revision_0013_replaces_the_indexes_on_an_existing_database(self) -> None:
        path = os.path.join(self._dir.name, "indexes-0012.sqlite")
        raw = sqlite3.connect(path)
        raw.executescript(
            "CREATE TABLE finding_occurrences (tenant_id TEXT, finding_id TEXT, scan_id TEXT, locator TEXT);"
            "CREATE TABLE finding_index (tenant_id TEXT, scan_id TEXT, seq INTEGER, finding_id TEXT);"
            "CREATE INDEX idx_occurrences_scan ON finding_occurrences (tenant_id, scan_id);"
            "CREATE INDEX idx_finding_index_tenant_scan ON finding_index (tenant_id, scan_id);"
        )
        raw.commit()
        raw.close()
        for _ in range(2):
            with db.connect(path) as conn:
                store.add_partition_write_indexes(conn)
        with db.connect(path) as conn:
            names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        self.assertIn("idx_occurrences_scan_finding", names)
        self.assertIn("idx_finding_index_tenant_scan_seq", names)
        self.assertNotIn("idx_occurrences_scan", names)
        self.assertNotIn("idx_finding_index_tenant_scan", names)

    def test_revision_0012_upgrades_an_existing_ledger(self) -> None:
        path = os.path.join(self._dir.name, "ledger-0011.sqlite")
        raw = sqlite3.connect(path)
        raw.execute(
            "CREATE TABLE scan_partitions (tenant_id TEXT NOT NULL, scan_id TEXT NOT NULL, partition_id TEXT NOT NULL, "
            "job_id TEXT NOT NULL DEFAULT '', ordinal INTEGER NOT NULL DEFAULT 0, spec_json TEXT NOT NULL DEFAULT '{}', "
            "status TEXT NOT NULL DEFAULT 'queued', attempt INTEGER NOT NULL DEFAULT 0, files INTEGER NOT NULL DEFAULT 0, "
            "error TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL DEFAULT '', finished_at TEXT NOT NULL DEFAULT '', "
            "updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, scan_id, partition_id))"
        )
        raw.commit()
        raw.close()
        for _ in range(2):
            with db.connect(path) as conn:
                store.add_scan_partition_records(conn)
        with db.connect(path) as conn:
            columns = db.table_columns(conn, "scan_partitions")
        for column in ("records_ref", "records_bytes", "records_json", "summary_json", "diagnostics_json"):
            self.assertIn(column, columns)


if __name__ == "__main__":
    unittest.main()
