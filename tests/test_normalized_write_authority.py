"""Authoritative normalized writes (roadmap Phase 5, DB-07).

Before Phase 5 the normalized surfaces were a best-effort mirror: a failure
was logged and swallowed, so the database could hold a scan report whose
assets/findings projection did not exist. The inventory read path then served
an estate that was silently missing that scan.

These tests pin the new contract: the projection is written in the same
transaction as the report, a failure fails the whole save and leaves nothing
behind, and the documented escape hatch still restores the old behaviour.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from backend import db, store


def _report(scan_id: str, files: int = 3) -> dict:
    return {
        "scan_id": scan_id,
        "source": "smb",
        "scan_label": "Authority check",
        "summary": {"total_files": files, "high": files},
        "files": [
            {
                "path": f"/share/doc{i}.txt",
                "name": f"doc{i}.txt",
                "risk": {"level": "HIGH", "score": 80, "reasons": ["r"], "dlp_recommendations": ["d"]},
                "findings": [{"type": "email", "risk": "HIGH", "count": 1}],
            }
            for i in range(files)
        ],
    }


class _TempStore(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant = f"norm-auth-{uuid4().hex[:8]}"
        if db.is_postgres():
            store.create_tenant(self.tenant, "Normalized authority")
            self.addCleanup(store.delete_tenant_with_data, self.tenant)
            return
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self._orig = store.DB_PATH
        store.DB_PATH = Path(self._tmp.name) / "authority.sqlite"

        def _restore() -> None:
            store.DB_PATH = self._orig

        self.addCleanup(_restore)
        from backend import migrations

        migrations.upgrade()
        store.create_tenant(self.tenant, "Normalized authority")

    def _counts(self) -> tuple[int, int]:
        with store._connect() as conn:
            reports = int(conn.execute(
                "SELECT COUNT(*) AS n FROM scan_reports WHERE tenant_id = ?", (self.tenant,)
            ).fetchone()["n"])
            assets = int(conn.execute(
                "SELECT COUNT(*) AS n FROM assets WHERE tenant_id = ?", (self.tenant,)
            ).fetchone()["n"])
        return reports, assets


class AuthoritativeWrites(_TempStore):
    def test_a_healthy_save_writes_both_surfaces(self) -> None:
        store.save_scan_history(self.tenant, _report("ok-scan"))
        reports, assets = self._counts()
        self.assertEqual(reports, 1)
        self.assertEqual(assets, 3)

    def test_normalized_failure_fails_the_whole_save(self) -> None:
        """The regression this phase closes: no report row may survive a
        projection failure."""
        with mock.patch.object(
            store, "_write_normalized_rows", side_effect=RuntimeError("disk on fire")
        ):
            with self.assertRaises(store.NormalizedWriteFailed) as caught:
                store.save_scan_history(self.tenant, _report("doomed-scan"))
        self.assertIn("doomed-scan", str(caught.exception))
        self.assertIn("rolled back", str(caught.exception))
        self.assertEqual(self._counts(), (0, 0))

    def test_a_failed_save_leaves_no_trace_for_readers(self) -> None:
        with mock.patch.object(
            store, "_write_normalized_rows", side_effect=RuntimeError("nope")
        ):
            with self.assertRaises(store.NormalizedWriteFailed):
                store.save_scan_history(self.tenant, _report("ghost-scan"))
        self.assertEqual(store.read_scan_history(self.tenant), [])
        self.assertIsNone(store.read_scan_report(self.tenant, "ghost-scan"))
        self.assertEqual(store.inventory_facets(self.tenant)["total"], 0)

    def test_report_write_failure_also_rolls_back_the_projection(self) -> None:
        """The other direction: both surfaces share one transaction, so a
        failure serializing the report body must not leave its assets behind."""
        store.save_scan_history(self.tenant, _report("first-scan"))
        before = self._counts()

        real_dumps = store.json.dumps

        def fail_on_the_report_body(value, *args, **kwargs):
            # The report row serializes the whole body; the projection does not.
            if isinstance(value, dict) and "files" in value:
                raise RuntimeError("report body serialization failed")
            return real_dumps(value, *args, **kwargs)

        with mock.patch.object(store.json, "dumps", side_effect=fail_on_the_report_body):
            with self.assertRaises(RuntimeError):
                store.save_scan_history(self.tenant, _report("second-scan"))

        self.assertEqual(self._counts(), before, "a failed save must change neither surface")


class BestEffortEscapeHatch(_TempStore):
    def test_flag_restores_legacy_mirror_behaviour(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_NORMALIZED_WRITE_BEST_EFFORT": "1"}):
            with mock.patch.object(
                store, "_write_normalized_rows", side_effect=RuntimeError("degraded")
            ):
                scan_id = store.save_scan_history(self.tenant, _report("degraded-scan"))
        self.assertEqual(scan_id, "degraded-scan")
        reports, assets = self._counts()
        self.assertEqual(reports, 1, "the report is kept in best-effort mode")
        self.assertEqual(assets, 0, "and the projection is knowingly absent")

    def test_default_is_authoritative(self) -> None:
        os.environ.pop("DSPM_NORMALIZED_WRITE_BEST_EFFORT", None)
        self.assertFalse(store._normalized_write_is_best_effort())


if __name__ == "__main__":
    unittest.main()
