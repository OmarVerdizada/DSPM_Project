"""W4.1: one copy of each fact - a finding the estate holds is not stored again per scan.

Every scan wrote one ``finding_index`` row per finding: an unchanged rescan of 6,000 files
added 9,600 rows and 1.9 KB per file, the largest thing an unchanged scan stored
(amplification probe, 2026-10-08). The rows had one reader - the drawer, its occurrences
and the triage path, which read the newest row of a finding - and that reader already fell
back to the finding's row and its asset's record. The estate now answers first; the index
is written only for the scans whose findings get no rows (the demo dataset).

The proof is parity: with the old per-scan rows written beside it (``_INDEX_ESTATE_FINDINGS``
on), the drawer answers exactly what the newest index row held - except the finding's
lifecycle times, which come from its row ("lifecycle belongs to the row"): a changed file's
record holds its findings as that scan re-detected them, and the index said a finding first
seen months ago was first seen today.
"""
from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from backend import store
from tests.test_partitioned_local_scan import TENANT, _LocalTest

_ROW_LIFECYCLE = ("first_seen", "last_seen")


class _Scenario(_LocalTest):

    def setUp(self) -> None:
        super().setUp()
        # W4.2: an unchanged unit is now skipped whole; this proves the path a unit that is
        # read takes - per-file reuse - so every unit here is read (the skip has its own
        # parity tests, test_w42_*).
        os.environ["DSPM_UNCHANGED_UNIT_SKIP"] = "0"
    def _config(self, name: str = "w41", **overrides):
        return super()._config(
            name, persistent_cache_enabled=True, incremental_enabled=True, incremental_scope="scope-w41",
            baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                TENANT, "scope-w41", key, size, mtime, version),
            **overrides)

    def _scan(self) -> dict:
        from backend import partitioned_scan

        compact = partitioned_scan.run_partitioned_scan(TENANT, self._config(), scan_label="estate",
                                                        compliance_enabled=True, compliance_frameworks=["gdpr"],
                                                        max_files=3)
        self.assertIsNotNone(compact, "the estate was not partitioned")
        return compact

    def _current_ids(self) -> list[str]:
        with store._connect() as conn:
            return [str(row["id"]) for row in conn.execute(
                "SELECT id FROM findings WHERE tenant_id = ? AND is_current = 1 ORDER BY id", (TENANT,)).fetchall()]

    def _row(self, finding_id: str) -> dict:
        with store._connect() as conn:
            return dict(conn.execute("SELECT * FROM findings WHERE tenant_id = ? AND id = ?",
                                     (TENANT, finding_id)).fetchone())

    def _changed_file(self) -> None:
        # The file keeps what it held and gains a value: a scan that reads it again re-detects
        # its old findings, and one finding is new.
        path = self.estate / "b_dept" / "b1.txt"
        path.write_text(path.read_text(encoding="utf-8") + "\nand maria.lopez@example.com too\n", encoding="utf-8")


class TheDrawerAnswersAsTheIndexDidTest(_Scenario):

    def _old_answer(self, finding_id: str) -> dict | None:
        """What the drawer answered before W4.1: the newest index row, the lifecycle laid on."""
        response = store._find_finding_response_normalized(TENANT, finding_id)
        if response is None:
            return None
        row = self._row(finding_id)
        if row["lifecycle_json"]:
            store._overlay_lifecycle(response, row)
        return response

    def _assert_parity(self, step: str) -> None:
        ids = self._current_ids()
        self.assertTrue(ids, f"{step}: the scan found nothing")
        for finding_id in ids:
            old, new = self._old_answer(finding_id), store.get_finding(TENANT, finding_id)
            self.assertIsNotNone(old, f"{step}: no index row was kept beside the estate")
            row = self._row(finding_id)
            for key in sorted(set(old) | set(new)):
                if key in _ROW_LIFECYCLE:
                    self.assertEqual(new.get(key), row[key], f"{step}: {key} is the row's")
                    if key == "first_seen" and old.get(key) != row[key]:
                        self._redetected.add(finding_id)
                else:
                    self.assertEqual(new.get(key), old.get(key), f"{step}: {finding_id} {key}")
            self.assertEqual(store.get_finding_occurrences(TENANT, finding_id), old.get("occurrences") or [])
            self.assertEqual(store.get_finding_history(TENANT, finding_id),
                             old.get("status_history") or old.get("history") or [])

    def test_first_unchanged_changed_and_acted_on(self) -> None:
        self._redetected: set[str] = set()
        self._use_database("parity")
        with mock.patch.object(store, "_INDEX_ESTATE_FINDINGS", True):
            self._scan()
            self._assert_parity("first scan")
            self._scan()
            self._assert_parity("unchanged rescan")
            self._changed_file()
            self._scan()
            self._assert_parity("one file changed")
            finding_id = self._current_ids()[0]
            store.update_finding_lifecycle(TENANT, finding_id, "assign", {"owner": "hr-team", "comment": "yours"},
                                           "analyst")
            self._assert_parity("after an action")
            self._scan()
            self._assert_parity("rescanned after the action")
        # A re-detected finding keeps the day it was first seen; the index said it was today.
        self.assertTrue(self._redetected, "the changed file re-detected none of its findings")


class AnEstateScanStoresNoIndexRowTest(_Scenario):

    def test_no_row_per_finding_per_scan_and_every_finding_still_answers(self) -> None:
        self._use_database("no-index")
        self._scan()
        self._scan()
        self._changed_file()
        self._scan()
        with store._connect() as conn:
            self.assertEqual(int(conn.execute("SELECT COUNT(*) FROM finding_index WHERE tenant_id = ?",
                                              (TENANT,)).fetchone()[0]), 0)
        ids = self._current_ids()
        self.assertTrue(ids)
        for finding_id in ids:
            answer = store.get_finding(TENANT, finding_id)
            self.assertIsNotNone(answer, finding_id)
            self.assertEqual(answer["finding_id"], finding_id)
            self.assertEqual(answer["first_seen"], self._row(finding_id)["first_seen"])


class TheDemoDatasetIsStillIndexedTest(unittest.TestCase):
    """The demo dataset's findings get no rows (they never enter the estate), so its scans
    still write the index, and its drawer answers from it."""

    def test_a_demo_scan_writes_the_index_and_its_findings_answer(self) -> None:
        import tempfile
        from pathlib import Path

        from backend import db

        if not db.is_postgres():
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "demo.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
        store.init_db()
        tenant = "w41-demo"
        store.create_tenant(tenant, "demo")
        path = "enterprise_test_data/finance/payroll.txt"
        store.save_scan_history(tenant, {
            "scan_id": "demo-1", "source": "local", "timestamp": "2026-10-08T00:00:00Z",
            "summary": {"total_files": 1},
            "files": [{"name": "payroll.txt", "path": path, "size": 10,
                       "findings": [{"finding_id": "demo-f1", "type": "email", "risk": "HIGH", "count": 1}]}],
        })
        with store._connect() as conn:
            self.assertEqual(int(conn.execute("SELECT COUNT(*) FROM findings WHERE tenant_id = ?",
                                              (tenant,)).fetchone()[0]), 0)
            self.assertEqual(int(conn.execute("SELECT COUNT(*) FROM finding_index WHERE tenant_id = ?",
                                              (tenant,)).fetchone()[0]), 1)
        answer = store.get_finding(tenant, "demo-f1")
        self.assertEqual((answer["finding_id"], answer["file"]["path"]), ("demo-f1", path))
        self.assertEqual(json.loads(json.dumps(answer))["type"], "email")


if __name__ == "__main__":
    unittest.main()
