"""W4.1 restore drill: what one copy of each fact leans on comes back from a backup.

After W4.1 a scan's records are content-addressed objects two scans can share, a baseline
row holds a reference to its asset's record instead of a copy, and a finding's drawer
answers from its row and its asset's record. A backup must bring all three back together:
lose the artifact store and the estate's rows, restore, and the scans' records, the drawer,
the baseline's replay and an unchanged rescan answer as they did - on SQLite and on the
disposable PostgreSQL database (the drill replaces its contents, as the C11 drill does).
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import backup, db, partitioned_scan, store
from tests.test_partitioned_local_scan import TENANT, _LocalTest


class ARestoreBringsBackWhatOneCopyLeansOnTest(_LocalTest):

    def _scan(self) -> tuple[str, dict]:
        config = self._config(
            "drill", persistent_cache_enabled=False, incremental_enabled=True, incremental_scope="scope-drill",
            baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                TENANT, "scope-drill", key, size, mtime, version))
        compact = partitioned_scan.run_partitioned_scan(TENANT, config, scan_label="estate",
                                                        compliance_enabled=True, compliance_frameworks=["gdpr"],
                                                        max_files=3)
        self.assertIsNotNone(compact, "the estate was not partitioned")
        partitioned_scan.join_planners(60)
        return str(compact["scan_id"]), (compact.get("scan_diagnostics") or {}).get("incremental") or {}

    def _state(self, scans: list[str], finding_id: str, path: str) -> dict:
        return {
            "records": {scan: [record for _ordinal, unit in store.iter_scan_records(TENANT, scan) for record in unit]
                        for scan in scans},
            "drawer": store.get_finding(TENANT, finding_id),
            "probe": store.probe_incremental_object(TENANT, "scope-drill", path, *self._fingerprint(path)),
        }

    def _fingerprint(self, path: str) -> tuple:
        with store._connect() as conn:
            row = conn.execute("SELECT size, mtime, version_signature FROM scan_object_baselines "
                               "WHERE tenant_id = ? AND scope_key = 'scope-drill' AND object_key = ?",
                               (TENANT, path)).fetchone()
        return int(row["size"]), str(row["mtime"]), str(row["version_signature"])

    def test_backup_lose_restore(self) -> None:
        self._use_database("drill")
        artifacts = Path(os.environ["DSPM_ARTIFACT_DIR"])
        first, _ = self._scan()
        second, counts = self._scan()
        total = int(counts.get("total_objects") or 0)
        with store._connect() as conn:
            finding = conn.execute("SELECT id, file_path FROM findings WHERE tenant_id = ? AND is_current = 1 "
                                   "ORDER BY id LIMIT 1", (TENANT,)).fetchone()
            path = str(conn.execute("SELECT object_key FROM scan_object_baselines WHERE tenant_id = ? "
                                    "AND scope_key = 'scope-drill' AND snapshot_json = '' ORDER BY object_key "
                                    "LIMIT 1", (TENANT,)).fetchone()["object_key"])
        before = self._state([first, second], str(finding["id"]), path)
        self.assertEqual(before["probe"]["state"], "unchanged")
        self.assertTrue(all(before["records"].values()))

        out = Path(tempfile.mkdtemp(prefix="w41-drill-"))
        self.addCleanup(shutil.rmtree, out, True)
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_DIR": str(out)}):
            manifest = backup.create_backup(out)
            self.assertTrue(backup.verify_backup(manifest)["ok"])
            # Lost: every stored object, and the estate's rows the references point at.
            shutil.rmtree(artifacts)
            with store._connect() as conn:
                for table in ("asset_access", "findings", "assets"):
                    conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (TENANT,))  # noqa: S608
            self.assertEqual(store.probe_incremental_object(TENANT, "scope-drill", path, *self._fingerprint(path)),
                             {"state": "changed"})
            if db.is_postgres():
                result = backup.restore_postgres_backup(manifest, os.environ["DSPM_DB_URL"], artifacts)
                self.assertEqual(result["tables_differing"], [])
            else:
                result = backup.restore_sqlite_backup(manifest, store.DB_PATH, artifacts)
                self.assertGreater(result["artifact_objects_added"], 0)

        self.assertEqual(self._state([first, second], str(finding["id"]), path), before)
        # W4.2: and the manifest came back with the rows, so an unchanged rescan skips every
        # unit - reads nothing, replays nothing - as before the loss.
        compact = partitioned_scan.run_partitioned_scan(
            TENANT, self._config("drill", persistent_cache_enabled=False, incremental_enabled=True,
                                 incremental_scope="scope-drill",
                                 baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                                     TENANT, "scope-drill", key, size, mtime, version)),
            scan_label="estate", compliance_enabled=True, compliance_frameworks=["gdpr"], max_files=3)
        partitioned_scan.join_planners(60)
        diagnostics = compact.get("scan_diagnostics") or {}
        self.assertEqual((diagnostics.get("incremental") or {}).get("content_reads"), 0)
        self.assertEqual(diagnostics.get("units_skipped"), (diagnostics.get("partitioned") or {}).get("partitions"))
        self.assertGreater(total, 0)


if __name__ == "__main__":
    unittest.main()
