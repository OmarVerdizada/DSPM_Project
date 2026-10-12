"""W3.5 (scaling roadmap, section 24, decisions D2 and D3): storage stops growing.

Every scan kept a second full copy of the estate for ever: finalize streamed every unit's
records again into one report body, `finding_occurrences` and `asset_versions` were written
and never read, artifact collection was off, and each of seven backup sets tarred the whole
artifact store through %TEMP%. Now:

- a scan is stored as its summary and a manifest of the record artifacts it already wrote,
  and every reader streams through the manifest (D3);
- the latest 3 completed scans of each name keep their per-file rows; older ones keep their
  summary, coverage, audit events and their findings' lifecycle, reduced in bounded batches;
  a workspace under legal hold keeps everything (D2);
- artifact collection is on, after each scan, and never takes a held workspace's objects;
- the two unread tables are no longer written;
- backups stage nothing in plaintext and copy artifact objects incrementally;
- the configuration is resolved where the database is chosen, so no tool runs on a stray
  data\\dspm.sqlite, and importing the store no longer scans every workspace.
"""
from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from backend import artifacts, backup, config, db, housekeeping, partitioned_scan, security, store
from discovery.discovery_engine import DSPMDiscoveryEngine
from tests.test_finalize_partitioned_scan import _diagnostics, _records

ROOT = Path(__file__).resolve().parents[1]
LABEL = "finance-share"
TIMESTAMP = "2026-10-07T08:00:00Z"
PASSWORD = "a-w35-harbour-pass-9"
_PER_SCAN_TABLES = ("finding_index", "scan_records", "scan_partitions", "finding_occurrences", "asset_versions")


def _report(scan_id: str, records: list[dict], *, label: str | None = LABEL) -> dict:
    copied = json.loads(json.dumps(records))
    report = {
        "scan_id": scan_id, "timestamp": TIMESTAMP, "source": "smb", "mode": "full",
        "summary": DSPMDiscoveryEngine._build_summary(json.loads(json.dumps(records))).to_dict(),
        "files": copied, "scan_diagnostics": _diagnostics(len(records)),
    }
    if label:
        report["scan_label"] = label
    return report


class _Store(unittest.TestCase):
    """A workspace of its own with the W3.5 defaults; collection runs only when a test asks."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        environment = mock.patch.dict(os.environ, {
            "DSPM_ARTIFACT_DIR": str(self.root / "artifacts"), "DSPM_REPORT_ARTIFACTS": "1",
            "DSPM_STORE_REPORT_BODY": "0", "DSPM_SCAN_RETENTION_PER_LABEL": "3",
            "DSPM_FINDING_INDEX_KEEP_SCANS": "", "DSPM_RETENTION_PRUNE_ARTIFACTS": "1",
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.collect_after_scan = housekeeping.collect_after_scan
        soon = mock.patch.object(housekeeping, "collect_after_scan", return_value=False)
        soon.start()
        self.addCleanup(soon.stop)
        self.tenant = f"w35{uuid.uuid4().hex[:8]}"
        if db.is_postgres():
            store.create_tenant(self.tenant, "W3.5")
            self.addCleanup(store.delete_tenant_with_data, self.tenant)
            return
        previous = store.DB_PATH
        store.DB_PATH = self.root / "w35.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", previous)
        store.init_db()
        store.create_tenant(self.tenant, "W3.5")

    # -- helpers -----------------------------------------------------------------------------------------------
    def _rows(self, sql: str, params: tuple = ()) -> list:
        with db.tenant_scope(self.tenant):
            with store._connect() as conn:
                return conn.execute(sql, params).fetchall()

    def _count(self, table: str, scan_id: str | None = None) -> int:
        sql, params = f"SELECT COUNT(*) AS n FROM {table} WHERE tenant_id = ?", [self.tenant]  # noqa: S608 - fixed names
        if scan_id:
            sql += " AND scan_id = ?"
            params.append(scan_id)
        return int(self._rows(sql, tuple(params))[0]["n"])

    def _per_scan_rows(self) -> dict[str, int]:
        return {table: self._count(table) for table in _PER_SCAN_TABLES}

    def _objects(self) -> list[str]:
        return sorted(content_id for _tenant, content_id, _path in artifacts.iter_objects(self.tenant))

    def _collect_now(self) -> int:
        """The shipped collection, with no grace period: every object here is minutes old."""
        real = artifacts.prune
        with mock.patch.object(artifacts, "prune", lambda referenced, **kw: real(referenced, 0, **kw)):
            return housekeeping.collect_artifacts()

    def _save_partitioned(self, scan_id: str, parts: list[list[dict]], *, label: str = LABEL) -> dict:
        store.create_scan_partitions(self.tenant, scan_id, f"job-{scan_id}", [{"part": i} for i in range(len(parts))])
        for part in parts:
            records = json.loads(json.dumps(part))
            unit = store.claim_next_partition(self.tenant, scan_id)
            header = {"timestamp": TIMESTAMP, "source": "smb", "mode": "full", "scan_label": label,
                      "summary": DSPMDiscoveryEngine._build_summary(json.loads(json.dumps(records))).to_dict(),
                      "scan_diagnostics": _diagnostics(len(records))}
            store.persist_partition(self.tenant, scan_id, unit["partition_id"], unit["attempt"], header, records,
                                    write_estate=True)
        return partitioned_scan.finalize_scan(self.tenant, scan_id, timestamp=TIMESTAMP, source="smb",
                                              scan_label=label, compliance_enabled=False, compliance_frameworks=[])


# ── D3: a scan is its summary and a manifest ───────────────────────────────────────────
class AScanIsItsSummaryAndAManifestTest(_Store):

    def test_a_saved_scan_keeps_no_body_and_reads_back_whole(self) -> None:
        records = _records(range(12))
        store.save_scan_history(self.tenant, _report("s1", records))
        [row] = self._rows("SELECT report_json, report_ref FROM scan_reports WHERE tenant_id = ? AND scan_id = 's1'",
                           (self.tenant,))
        self.assertEqual((row["report_json"] or "", row["report_ref"] or ""), ("", ""), "a verbatim body was stored")
        [entry] = self._rows("SELECT records_ref, files FROM scan_records WHERE tenant_id = ? AND scan_id = 's1'",
                             (self.tenant,))
        self.assertEqual(entry["files"], 12)
        # One copy of the records: the manifest's artifact, and no body beside it.
        self.assertEqual(self._objects(), [entry["records_ref"]])
        self.assertIsInstance(json.loads(artifacts.get_text(self.tenant, entry["records_ref"])), list)
        report = store.read_scan_report(self.tenant, "s1")
        self.assertEqual([record["path"] for record in report["files"]], [record["path"] for record in records])
        self.assertEqual(report["summary"]["total_files"], 12)
        self.assertEqual(store.scan_report_body_size(self.tenant, "s1"), ("s1", -1))

    def test_a_partitioned_scan_names_the_records_its_units_wrote(self) -> None:
        records = _records(range(20))
        parts = [records[:7], records[7:15], records[15:]]
        self._save_partitioned("p1", parts)
        units = self._rows("SELECT ordinal, records_ref, files FROM scan_records WHERE tenant_id = ? AND scan_id = 'p1' "
                           "ORDER BY ordinal", (self.tenant,))
        self.assertEqual([unit["files"] for unit in units], [7, 8, 5])
        # The units' own artifacts, named by the manifest - and nothing else once finalize's
        # step artifact (its compliance sections, W3.2) is collected: finalize released the
        # records from the partitions to the manifest instead of streaming a second copy.
        self._collect_now()
        self.assertEqual(sorted(unit["records_ref"] for unit in units), self._objects(),
                         "finalize streamed a second copy of the estate")
        [row] = self._rows("SELECT report_json, report_ref FROM scan_reports WHERE tenant_id = ? AND scan_id = 'p1'",
                           (self.tenant,))
        self.assertEqual((row["report_json"] or "", row["report_ref"] or ""), ("", ""))
        report = store.read_scan_report(self.tenant, "p1")
        self.assertEqual([record["path"] for record in report["files"]], [record["path"] for record in records],
                         "the records come back in plan order")

    def test_the_verbatim_body_is_off_by_default(self) -> None:
        with mock.patch.dict(os.environ):
            os.environ.pop("DSPM_STORE_REPORT_BODY", None)
            self.assertFalse(store.store_report_body())
            store.save_scan_history(self.tenant, _report("d1", _records(range(2))))
        [row] = self._rows("SELECT report_ref FROM scan_reports WHERE tenant_id = ? AND scan_id = 'd1'", (self.tenant,))
        self.assertEqual(row["report_ref"] or "", "")
        self.assertEqual(self._count("scan_records", "d1"), 1)
        self.assertEqual(config.SETTINGS["DSPM_STORE_REPORT_BODY"].default, "0")

    def test_a_verbatim_body_is_still_there_for_whoever_asks_for_it(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_STORE_REPORT_BODY": "1"}):
            store.save_scan_history(self.tenant, _report("b1", _records(range(3))))
        [row] = self._rows("SELECT report_ref FROM scan_reports WHERE tenant_id = ? AND scan_id = 'b1'", (self.tenant,))
        self.assertEqual(len(row["report_ref"]), 64)
        self.assertEqual(self._count("scan_records", "b1"), 0)
        self.assertEqual(len(store.read_scan_report(self.tenant, "b1")["files"]), 3)

    def test_the_label_lookup_reads_through_the_manifest(self) -> None:
        store.save_scan_history(self.tenant, _report("l1", _records(range(4))))
        found = store.read_latest_scan_report_by_label(self.tenant, LABEL)
        self.assertEqual(len(found["files"]), 4)

    def test_the_unread_tables_are_not_written(self) -> None:
        store.save_scan_history(self.tenant, _report("u1", _records(range(10))))
        self._save_partitioned("u2", [_records(range(10, 15)), _records(range(15, 20))])
        self.assertEqual((self._count("finding_occurrences"), self._count("asset_versions")), (0, 0))
        # W4.1: nor the index - an estate finding answers from its row and its asset's record.
        self.assertEqual(self._count("finding_index"), 0, "the index is still written for estate scans")


class TheHistoryReportStreamsTest(_Store):

    def setUp(self) -> None:
        super().setUp()
        store.create_user(f"{self.tenant}-boss", security.hash_password(PASSWORD), "admin", self.tenant)
        self.client = TestClient(store_app())
        self.addCleanup(self.client.close)
        self.headers = {"Authorization": f"Bearer {security.create_token(f'{self.tenant}-boss', 'admin', self.tenant)}"}

    def test_every_record_streams_through_the_manifest_and_no_size_refuses_it(self) -> None:
        records = _records(range(30))
        self._save_partitioned("h1", [records[:10], records[10:20], records[20:]])
        reads = []
        real = store._compose_from_manifest
        with mock.patch.dict(os.environ, {"DSPM_REPORT_BODY_MAX_BYTES": "10"}), \
                mock.patch.object(store, "_compose_from_manifest",
                                  side_effect=lambda *a, **k: reads.append(1) or real(*a, **k)):
            response = self.client.get("/api/history/h1/report?include_files=true", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()["report"]
        self.assertEqual([record["path"] for record in body["files"]], [record["path"] for record in records])
        self.assertEqual(body["scan_id"], "h1")
        self.assertEqual(reads, [], "the whole scan was composed in memory")

    def test_a_scan_past_its_window_answers_gone_with_its_summary_kept(self) -> None:
        for index in range(4):
            store.save_scan_history(self.tenant, _report(f"g{index}", _records(range(index, index + 3))))
        self.assertEqual(store.scan_retention_state(self.tenant, "g0"), "summary")
        gone = self.client.get("/api/history/g0/report?include_files=true", headers=self.headers)
        self.assertEqual(gone.status_code, 410, gone.text)
        summary = self.client.get("/api/history/g0/report?include_files=false", headers=self.headers)
        self.assertEqual(summary.status_code, 200, summary.text)
        self.assertEqual(summary.json()["report"]["summary"]["total_files"], 3)


def store_app():
    from backend.app import app

    return app


# ── D2: the latest 3 completed scans of each name ──────────────────────────────────────
class RetentionKeepsTheLatestScansOfEachNameTest(_Store):

    def test_ten_unchanged_scans_store_what_three_do(self) -> None:
        records = _records(range(16))
        for index in range(3):
            store.save_scan_history(self.tenant, _report(f"s{index:02d}", records))
        self._collect_now()
        after_three = (self._per_scan_rows(), self._objects())
        for index in range(3, 10):
            store.save_scan_history(self.tenant, _report(f"s{index:02d}", records))
        self._collect_now()
        self.assertEqual((self._per_scan_rows(), self._objects()), after_three)
        states = {row["scan_id"]: row["retention_state"] for row in self._rows(
            "SELECT scan_id, retention_state FROM scan_reports WHERE tenant_id = ?", (self.tenant,))}
        self.assertEqual(sorted(scan for scan, state in states.items() if state != "summary"), ["s07", "s08", "s09"])

    def test_the_records_of_scans_past_the_window_are_collected(self) -> None:
        for index in range(5):
            store.save_scan_history(self.tenant, _report(f"c{index}", _records(range(index * 4, index * 4 + 4))))
        kept = sorted(row["records_ref"] for row in self._rows(
            "SELECT records_ref FROM scan_records WHERE tenant_id = ?", (self.tenant,)))
        self.assertEqual(len(kept), 3)
        self.assertEqual(len(self._objects()), 5, "nothing is collected inside the grace period")
        self.assertEqual(self._collect_now(), 2)
        self.assertEqual(self._objects(), kept)

    def test_each_name_has_its_own_window(self) -> None:
        for index in range(4):
            store.save_scan_history(self.tenant, _report(f"a{index}", _records(range(3)), label="alpha"))
        for index in range(2):
            store.save_scan_history(self.tenant, _report(f"b{index}", _records(range(3)), label="beta"))
        reduced = sorted(row["scan_id"] for row in self._rows(
            "SELECT scan_id FROM scan_reports WHERE tenant_id = ? AND retention_state = 'summary'", (self.tenant,)))
        self.assertEqual(reduced, ["a0"])

    def test_a_reduced_scan_keeps_its_summary_audit_and_lifecycle(self) -> None:
        store.save_scan_history(self.tenant, _report("old", _records(range(8))))
        store.audit(self.tenant, "analyst", "scan.reviewed", {"scan_id": "old"})
        with db.tenant_scope(self.tenant):
            with store._connect() as conn:
                conn.execute("UPDATE findings SET status = 'CONFIRMED', owner = 'analyst@corp' "
                             "WHERE tenant_id = ? AND id = 'g-4'", (self.tenant,))
        audit_before = self._count("audit_events")
        for index in range(3):
            store.save_scan_history(self.tenant, _report(f"new{index}", _records(range(100 + index, 102 + index))))
        self.assertEqual(store.scan_retention_state(self.tenant, "old"), "summary")
        self.assertEqual((self._count("finding_index", "old"), self._count("scan_records", "old")), (0, 0))
        compact = store.read_scan_report_compact(self.tenant, "old")
        self.assertEqual(compact["summary"]["total_files"], 8)
        [finding] = self._rows("SELECT status, owner FROM findings WHERE tenant_id = ? AND id = 'g-4'", (self.tenant,))
        self.assertEqual((finding["status"], finding["owner"]), ("CONFIRMED", "analyst@corp"))
        self.assertGreaterEqual(self._count("audit_events"), audit_before)
        self.assertEqual(self._count("scan_runs"), 4, "every scan run is kept")

    def test_a_workspace_under_legal_hold_keeps_everything(self) -> None:
        store.set_legal_hold(self.tenant, True, "matter 2026-17")
        for index in range(5):
            store.save_scan_history(self.tenant, _report(f"h{index}", _records(range(index, index + 2))))
        self.assertEqual(self._count("scan_records"), 5)
        self.assertTrue(store.apply_scan_retention(self.tenant)["held"])
        store.set_legal_hold(self.tenant, False)
        result = store.apply_scan_retention(self.tenant)
        self.assertEqual((result["held"], result["scans"]), (False, 2))
        self.assertEqual(self._count("scan_records"), 3)

    def test_rows_go_in_bounded_batches(self) -> None:
        store.set_legal_hold(self.tenant, True, "while the scans are written")
        for index in range(4):
            store.save_scan_history(self.tenant, _report(f"r{index}", _records(range(10))))
        store.set_legal_hold(self.tenant, False)
        # The index rows an install from before W4.1 holds for its older scans (W4.1 writes
        # none for an estate scan): retention removes them in bounded batches all the same.
        with store._connect() as conn:
            conn.executemany(
                "INSERT INTO finding_index (tenant_id, scan_id, seq, finding_id, status, response_json, index_version) "
                "VALUES (?, 'r0', ?, ?, 'OPEN', '', '')",
                [(self.tenant, seq, f"legacy-{seq}") for seq in range(10)])
        index_rows = self._count("finding_index", "r0")
        self.assertGreater(index_rows, 6)
        transactions = []
        real = store._connect

        def counting(*args, **kwargs):
            transactions.append(1)
            return real(*args, **kwargs)

        with mock.patch.object(store, "_connect", counting):
            result = store.apply_scan_retention(self.tenant, batch=3)
        self.assertEqual(result["scans"], 1)
        self.assertEqual(self._count("finding_index", "r0"), 0)
        self.assertGreaterEqual(len(transactions), index_rows // 3, "the index rows went in one transaction")

    def test_the_finding_index_follows_the_window(self) -> None:
        for raw, expected in (("", 3), ("0", 0), ("2", 2)):
            with mock.patch.dict(os.environ, {"DSPM_FINDING_INDEX_KEEP_SCANS": raw}):
                self.assertEqual(store._finding_index_retention(), expected, raw)
        with mock.patch.dict(os.environ, {"DSPM_SCAN_RETENTION_PER_LABEL": "5", "DSPM_FINDING_INDEX_KEEP_SCANS": ""}):
            self.assertEqual(store._finding_index_retention(), 5)

    def test_housekeeping_applies_the_window_to_every_workspace(self) -> None:
        store.set_legal_hold(self.tenant, True, "while the scans are written")
        for index in range(5):
            store.save_scan_history(self.tenant, _report(f"k{index}", _records(range(index, index + 2))))
        store.set_legal_hold(self.tenant, False)
        summary = housekeeping.run_retention(apply=True)
        [scans] = [item for item in summary["data_classes"] if item["data_class"] == "scan_records"]
        self.assertGreater(scans["removed_rows"], 0)
        self.assertEqual(self._count("scan_records"), 3)


# ── collection on by default ───────────────────────────────────────────────────────────
class ArtifactCollectionTest(_Store):

    def test_it_is_on_by_default(self) -> None:
        with mock.patch.dict(os.environ):
            os.environ.pop("DSPM_RETENTION_PRUNE_ARTIFACTS", None)
            self.assertTrue(housekeeping.prune_artifacts_enabled())
        self.assertEqual(config.SETTINGS["DSPM_RETENTION_PRUNE_ARTIFACTS"].default, "1")

    def test_it_runs_after_a_scan_once_per_interval(self) -> None:
        calls = []

        def collect():
            calls.append(threading.current_thread().name)
            return 0

        with mock.patch.object(housekeeping, "collect_artifacts", collect), \
                mock.patch.dict(housekeeping._collect_state, {"last": 0.0, "running": False}):
            self.assertGreater(housekeeping.COLLECT_AFTER_SCAN_SECONDS, 0)
            self.assertTrue(self.collect_after_scan())
            self.assertFalse(self.collect_after_scan(), "a second collection within the interval")
        # On the scan's own thread: nothing outlives the work that asked for it.
        self.assertEqual(calls, [threading.current_thread().name])

    def test_a_scan_asks_for_it(self) -> None:
        store.save_scan_history(self.tenant, _report("ask", _records(range(2))))
        housekeeping.collect_after_scan.assert_called()

    def test_a_held_workspace_keeps_its_objects_and_a_reused_object_is_new_again(self) -> None:
        other = f"w35{uuid.uuid4().hex[:8]}"
        store.create_tenant(other, "other")
        if db.is_postgres():
            self.addCleanup(store.delete_tenant_with_data, other)
        held = artifacts.put_bytes(self.tenant, b"held evidence")
        loose = artifacts.put_bytes(other, b"nobody names this")
        reused = artifacts.put_bytes(other, b"written again")
        old = time.time() - 7200
        for tenant, ref in ((self.tenant, held), (other, loose), (other, reused)):
            os.utime(artifacts.object_path(tenant, ref.content_id), (old, old))
        artifacts.put_bytes(other, b"written again")  # the dedupe path refreshes it
        store.set_legal_hold(self.tenant, True, "matter")
        self.assertEqual(housekeeping.collect_artifacts(), 1)
        self.assertTrue(artifacts.exists(self.tenant, held.content_id))
        self.assertFalse(artifacts.exists(other, loose.content_id))
        self.assertTrue(artifacts.exists(other, reused.content_id))
        store.set_legal_hold(self.tenant, False)

    def test_the_interrupted_write_sweep_runs_with_it(self) -> None:
        root = artifacts.artifact_root() / self.tenant
        root.mkdir(parents=True, exist_ok=True)
        scratch = root / ".streaming-dead.part"
        scratch.write_bytes(b"half a body")
        old = time.time() - 7200
        os.utime(scratch, (old, old))
        housekeeping.collect_artifacts()
        self.assertFalse(scratch.exists())


# ── backups ────────────────────────────────────────────────────────────────────────────
@unittest.skipIf(db.is_postgres(), "SQLite sets; the PostgreSQL set is driven on sentro_test by test_c11")
class BackupsAreIncrementalAndStageNothingTest(_Store):

    def setUp(self) -> None:
        super().setUp()
        self.backups = self.root / "backups"
        self.temp = self.root / "temp"
        self.temp.mkdir()
        environment = mock.patch.dict(os.environ, {"DSPM_BACKUP_DIR": str(self.backups), "DSPM_DB_URL": "",
                                                   "DSPM_BACKUP_KEY": Fernet.generate_key().decode()})
        environment.start()
        self.addCleanup(environment.stop)
        temp = mock.patch.object(backup.tempfile, "tempdir", str(self.temp))
        temp.start()
        self.addCleanup(temp.stop)

    def _set(self) -> tuple[Path, dict]:
        manifest = backup.create_sqlite_backup(store.DB_PATH)
        report = backup.verify_backup(manifest)
        self.assertTrue(report["ok"], report)
        backup.mark_verified(manifest)
        return manifest, json.loads(manifest.read_text(encoding="utf-8"))["artifacts"]

    def _stored(self, directory: Path) -> list[Path]:
        return sorted((directory / backup.OBJECTS_DIR).glob("*/*/*.enc"))

    def test_a_set_copies_only_the_objects_the_directory_lacks(self) -> None:
        artifacts.put_bytes(self.tenant, b"first body")
        artifacts.put_bytes(self.tenant, b"second body")
        _first, block = self._set()
        self.assertEqual((block["format"], block["objects"], block["copied_objects"]), (backup.OBJECTS_FORMAT, 2, 2))
        _second, block = self._set()
        self.assertEqual((block["objects"], block["copied_objects"]), (2, 0))
        artifacts.put_bytes(self.tenant, b"third body")
        _third, block = self._set()
        self.assertEqual((block["objects"], block["copied_objects"]), (3, 1))
        self.assertEqual(len(self._stored(self.backups)), 3, "one copy of each object, whatever the sets")
        self.assertFalse(list(self.backups.glob("*.tar*")), "a whole-store archive was written")

    def test_nothing_is_staged_in_temp_and_no_plaintext_reaches_the_backup_directory(self) -> None:
        artifacts.put_bytes(self.tenant, b"a body")
        written = []
        real_encrypt, real_decrypt = backup.encrypt_file, backup.decrypt_file

        def encrypting(source, dest):
            written.append(Path(source))
            return real_encrypt(source, dest)

        def decrypting(source, dest):
            written.append(Path(dest))
            return real_decrypt(source, dest)

        with mock.patch.object(backup, "encrypt_file", encrypting), mock.patch.object(backup, "decrypt_file", decrypting):
            self._set()
        self.assertTrue(written)
        for path in written:
            self.assertFalse(path.resolve().is_relative_to(self.temp.resolve()), f"staged in %TEMP%: {path}")
            self.assertFalse(path.resolve().is_relative_to(self.backups.resolve()), f"plaintext in backups: {path}")
        self.assertEqual(list(self.temp.iterdir()), [])
        self.assertEqual(backup.plaintext_dumps(self.backups), [])

    def test_retention_collects_the_objects_no_remaining_set_names(self) -> None:
        artifacts.put_bytes(self.tenant, b"only the old set has this")
        old_ref = artifacts.put_bytes(self.tenant, b"every set has this")
        self._set()
        doomed = artifacts.object_path(self.tenant, artifacts.put_bytes(self.tenant, b"only the old set has this").content_id)
        doomed.unlink()
        artifacts.put_bytes(self.tenant, b"only the new set has this")
        self._set()
        self.assertEqual(len(self._stored(self.backups)), 3)
        past = time.time() - backup.STAGING_STALE_SECONDS - 60
        for path in self._stored(self.backups):
            os.utime(path, (past, past))
        removed = backup.apply_retention(keep_sets=1)
        self.assertEqual(len(removed), 1)
        names = {path.name[:-4] for path in self._stored(self.backups)}
        self.assertEqual(len(names), 2)
        self.assertIn(old_ref.content_id, names)

    def test_an_inventory_that_cannot_be_read_collects_nothing(self) -> None:
        artifacts.put_bytes(self.tenant, b"a body")
        manifest, block = self._set()
        stray = self.backups / backup.OBJECTS_DIR / self.tenant / "ab" / ("ab" + "0" * 62 + ".enc")
        stray.parent.mkdir(parents=True, exist_ok=True)
        stray.write_bytes(b"x")
        past = time.time() - backup.STAGING_STALE_SECONDS - 60
        os.utime(stray, (past, past))
        inventory = self.backups / block["inventory_file"]
        inventory.write_bytes(inventory.read_bytes()[:-5])
        self.assertEqual(backup.collect_backup_objects(self.backups), 0)
        self.assertTrue(stray.exists())
        inventory.unlink()
        self.assertFalse(backup.verify_backup(manifest)["ok"])

    def test_a_damaged_object_is_rewritten_by_the_next_set(self) -> None:
        artifacts.put_bytes(self.tenant, b"a body worth keeping")
        manifest, _block = self._set()
        [stored] = self._stored(self.backups)
        data = bytearray(stored.read_bytes())
        data[-3] ^= 0xFF
        stored.write_bytes(bytes(data))
        self.assertFalse(backup.verify_backup(manifest)["ok"], "the damage is seen")
        _next, block = self._set()
        self.assertEqual(block["copied_objects"], 1)

    def test_damage_to_an_object_an_earlier_set_copied_fails_the_later_set(self) -> None:
        """A set re-names the objects earlier sets copied without copying them again; only
        their recorded digests can tell such an object was damaged since."""
        artifacts.put_bytes(self.tenant, b"copied by the first set")
        self._set()
        later = backup.create_sqlite_backup(store.DB_PATH)
        block = json.loads(later.read_text(encoding="utf-8"))["artifacts"]
        self.assertEqual(block["copied_objects"], 0)
        self.assertTrue(backup.verify_backup(later)["ok"])
        [stored] = self._stored(self.backups)
        data = bytearray(stored.read_bytes())
        data[10] ^= 0x01
        stored.write_bytes(bytes(data))
        report = backup.verify_backup(later)
        self.assertFalse(report["ok"])
        self.assertIn("1 artifact object(s) do not match their recorded digest", report["problems"])

    def test_the_copy_off_host_is_incremental_and_restores(self) -> None:
        first_ref = artifacts.put_bytes(self.tenant, b"first")
        first, _block = self._set()
        offhost = self.root / "offhost"
        backup.copy_set(first, offhost)
        second_ref = artifacts.put_bytes(self.tenant, b"second")
        second, _block = self._set()
        copied = []
        real = backup._copy_whole
        with mock.patch.object(backup, "_copy_whole", side_effect=lambda s, t, d: copied.append(Path(t)) or real(s, t, d)):
            target = backup.copy_set(second, offhost)
        objects_copied = [path for path in copied if backup.OBJECTS_DIR in path.parts]
        self.assertEqual(len(objects_copied), 1, "an object the copy holds travelled again")
        self.assertTrue(backup.verify_backup(target)["ok"])
        restored = self.root / "restored-store"
        added = backup._add_artifact_objects(target, json.loads(target.read_text(encoding="utf-8")), restored)
        self.assertEqual(added, 2)
        with mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(restored)}):
            self.assertEqual(artifacts.get_bytes(self.tenant, first_ref.content_id), b"first")
            self.assertEqual(artifacts.get_bytes(self.tenant, second_ref.content_id), b"second")

    def test_a_set_an_older_release_wrote_still_verifies_and_restores(self) -> None:
        ref = artifacts.put_bytes(self.tenant, b"a body from before W3.5")
        manifest, _block = self._set()
        document = json.loads(manifest.read_text(encoding="utf-8"))
        # The artifact tier as older releases wrote it: a tar of the objects, encrypted whole.
        plain = self.root / "legacy.tar"
        with tarfile.open(plain, "w") as tar:
            tar.add(artifacts.object_path(self.tenant, ref.content_id),
                    arcname=f"{self.tenant}/{ref.content_id}{artifacts.OBJECT_SUFFIX}")
        archive = self.backups / "legacy.artifacts.tar.enc"
        _plain_sha, cipher_sha = backup.encrypt_file(plain, archive)
        plain.unlink()
        document["artifacts"] = {"objects": 1, "inventory_sha256": backup._names_digest([f"{self.tenant}/{ref.content_id}"]),
                                 "file": archive.name, "archive_sha256": cipher_sha}
        manifest.write_text(json.dumps(document), encoding="utf-8")
        self.assertTrue(backup.verify_backup(manifest)["ok"])
        restored = self.root / "legacy-store"
        self.assertEqual(backup._add_artifact_objects(manifest, document, restored), 1)
        self.assertTrue((restored / self.tenant / ref.content_id[:2] / f"{ref.content_id}.enc").exists())
        self.assertFalse([path for path in self.root.iterdir() if path.name.startswith(backup.STAGING_PREFIX)])

    def test_the_plaintext_check_reads_past_the_objects(self) -> None:
        folder = self.backups / backup.OBJECTS_DIR / self.tenant / "00"
        folder.mkdir(parents=True)
        for index in range(30):
            (folder / f"{index:064x}.enc").write_bytes(b"\x00\x00\x00\x10gAAAAA" + b"x" * 16)
        planted = self.backups / "zz_left_behind.dump"
        planted.write_bytes(b"PGDMP" + b"\x00" * 64)
        hidden = folder / "notes.sql"
        hidden.write_bytes(b"CREATE TABLE secrets (x int); INSERT INTO secrets VALUES (1);")
        with mock.patch.object(backup, "_MAX_FILES_EXAMINED", 5):
            found = {path.name for path, _kind in backup.plaintext_dumps(self.backups)}
        self.assertEqual(found, {"zz_left_behind.dump", "notes.sql"})


# ── the configuration is resolved where the database is chosen ─────────────────────────
class TheConfigurationIsResolvedInTheDatabaseModuleTest(unittest.TestCase):

    def _python(self, code: str, extra: dict) -> subprocess.CompletedProcess:
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("DSPM_") and key not in {"PYTHONPATH"}}
        env.update({"PYTHONPATH": str(ROOT), **extra})
        return subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), env=env, capture_output=True, text=True,
                              timeout=120)

    def test_a_tool_reads_the_configuration_file(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder, "tool.sqlite").as_posix()
            config_file = Path(folder, "sentro.toml")
            config_file.write_text(f"[settings]\nDSPM_DB_PATH = '{database}'\nDSPM_LOG_LEVEL = 'WARNING'\n", encoding="utf-8")
            ran = self._python("import os, backend.db; print(os.environ.get('DSPM_DB_PATH', ''))",
                               {"DSPM_CONFIG_FILE": str(config_file)})
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertEqual(ran.stdout.strip(), database)

    def test_a_refused_configuration_stops_the_tool(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            config_file = Path(folder, "sentro.toml")
            config_file.write_text("[settings]\nDSPM_NOT_A_SETTING = '1'\n", encoding="utf-8")
            ran = self._python("import backend.db", {"DSPM_CONFIG_FILE": str(config_file)})
        self.assertNotEqual(ran.returncode, 0)
        self.assertIn("DSPM_NOT_A_SETTING", ran.stderr)

    def test_a_database_url_file_selects_postgresql(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            url_file = Path(folder, "db_url")
            url_file.write_text("postgresql://tool:not-a-real-pass@127.0.0.1:1/nowhere\n", encoding="utf-8")
            ran = self._python("import backend.db as d; print(d.is_postgres())", {"DSPM_DB_URL_FILE": str(url_file)})
        self.assertEqual((ran.returncode, ran.stdout.strip()), (0, "True"), ran.stderr)
        self.assertNotIn("not-a-real-pass", ran.stdout + ran.stderr)

    def test_the_default_sqlite_file_is_not_created_unasked(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            default = Path(folder, "data", "dspm.sqlite")
            with mock.patch.object(db, "_default_sqlite_path", return_value=default.resolve()), \
                    mock.patch.object(config, "_BOOTSTRAPPED", None), mock.patch.dict(os.environ, {"DSPM_DB_URL": ""}):
                os.environ.pop("DSPM_DB_PATH", None)
                with self.assertRaises(RuntimeError) as refused:
                    with db.connect(default):
                        pass
                self.assertIn("No database is configured", str(refused.exception))
                self.assertFalse(default.exists(), "the stray file was created anyway")
                os.environ["DSPM_DB_PATH"] = str(default)
                with db.connect(default) as conn:
                    conn.execute("SELECT 1")
                self.assertTrue(default.exists(), "an explicitly chosen file is created")

    def test_config_check_does_not_apply_what_it_shows(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            config_file = Path(folder, "sentro.toml")
            config_file.write_text("[settings]\nDSPM_NOT_A_SETTING = '1'\n", encoding="utf-8")
            ran = self._python("from backend import config; config.defer_bootstrap(); import backend.db; print('ok')",
                               {"DSPM_CONFIG_FILE": str(config_file)})
        self.assertEqual((ran.returncode, ran.stdout.strip()), (0, "ok"), ran.stderr)


class ImportingTheStoreScansNothingTest(unittest.TestCase):

    def test_the_demo_purge_is_not_run_at_import(self) -> None:
        tree = ast.parse((ROOT / "backend" / "store.py").read_text(encoding="utf-8"))
        called = [node for statement in tree.body if not isinstance(statement, (ast.FunctionDef, ast.ClassDef))
                  for node in ast.walk(statement)
                  if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_purge_demo_sample_assets_everywhere"]
        self.assertEqual(called, [], "the store still scans every workspace when it is imported")

    def test_the_server_runs_it_once_at_startup(self) -> None:
        from backend.app import app

        with mock.patch.object(store, "_purge_demo_sample_assets_everywhere", return_value=0) as purge, \
                mock.patch.dict(os.environ, {"DSPM_RETENTION_INTERVAL_SECONDS": "0", "DSPM_BACKUP_SCHEDULE_HOURS": "0"}):
            with TestClient(app):
                pass
        purge.assert_called_once_with()


# ── the node profiles ──────────────────────────────────────────────────────────────────
class TheNodeProfilesTest(unittest.TestCase):

    FOLDER = ROOT / "deploy" / "node-profiles"

    def test_every_profile_names_only_settings_and_says_its_figures_are_extrapolated(self) -> None:
        for name in ("node-16gb.env", "node-32gb.env"):
            text = (self.FOLDER / name).read_text(encoding="utf-8")
            self.assertIn("EXTRAPOLATED", text, name)
            for line in text.splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    key, _, value = line.partition("=")
                    self.assertIn(key.strip(), config.SETTINGS, f"{name}: {key} is not a Sentro setting")
                    self.assertIsNone(config._check_value(config.SETTINGS[key.strip()], value), f"{name}: {line}")
        for name in ("postgresql-16gb.conf", "postgresql-32gb.conf", "README.md"):
            self.assertIn("EXTRAPOLATED", (self.FOLDER / name).read_text(encoding="utf-8"), name)

    def test_the_pools_fit_the_connections_postgresql_allows(self) -> None:
        for size in ("16gb", "32gb"):
            settings = dict(line.split("=", 1) for line in (self.FOLDER / f"node-{size}.env").read_text(
                encoding="utf-8").splitlines() if line.strip() and not line.startswith("#"))
            conf = {key.strip(): value.split("#")[0].strip() for key, value in (
                line.split("=", 1) for line in (self.FOLDER / f"postgresql-{size}.conf").read_text(
                    encoding="utf-8").splitlines() if "=" in line and not line.lstrip().startswith("#"))}
            pools = sum(int(settings[key]) for key in ("DSPM_DB_POOL_MAX", "DSPM_DB_POOL_MAX_API", "DSPM_DB_POOL_MAX_HEAVY"))
            workers = int(settings.get("DSPM_SCAN_WORKERS", "1")) + 1
            allowed = int(conf["max_connections"])
            self.assertLess(pools * workers, allowed, f"{size}: {workers} processes of {pools} connections")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
