"""Gaps found auditing phases 0-6, and the fixes for them.

Each test here corresponds to something the implementation claimed but did not
do, or a hole the phases left between them:

1. **Reset left report bodies on disk.** ``reset_default_tenant_data`` deleted
   the scan rows and nothing else, so once bodies moved to the artifact tier a
   "reset this tenant" left findings, paths and owners readable on disk - the
   same remanence bug tenant erasure had before Phase 5b.
2. **The migration checksum was recorded but never compared.** The module said
   it made edits "detectable"; nothing read it back.
3. **Tenant isolation coverage was a point-in-time fact.** Revisions 0003 and
   0004 enumerate the tables that exist when they run, so a table added by a
   later revision would silently have neither a tenant foreign key nor RLS.
4. **A missing report body surfaced as an opaque 500.**
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from backend import artifacts, db, migrations, store


def _report(scan_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "source": "smb",
        "summary": {"total_files": 1},
        "files": [{
            "path": "/audit/doc.txt", "name": "doc.txt",
            "risk": {"level": "HIGH", "score": 80},
            "findings": [{"type": "email", "risk": "HIGH"}],
        }],
    }


class _Sandbox(unittest.TestCase):
    """Private database and artifact store."""

    def setUp(self) -> None:
        if db.is_postgres():
            self.skipTest("drives a private database file")
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self._env = mock.patch.dict(os.environ, {
            "DSPM_ARTIFACT_DIR": str(root / "artifacts"),
            "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(root / "artifact_key"),
        })
        self._env.start()
        self.addCleanup(self._env.stop)
        self._orig = store.DB_PATH
        store.DB_PATH = root / "audit.sqlite"

        def _restore() -> None:
            store.DB_PATH = self._orig

        self.addCleanup(_restore)
        migrations.upgrade()


class ResetErasesReportBodies(_Sandbox):
    def setUp(self) -> None:
        super().setUp()
        store.create_user("admin", "x" * 60, "admin", "default", "Local Administrator")

    def test_reset_removes_the_bodies_not_just_the_rows(self) -> None:
        store.save_scan_history("default", _report("reset-me"))
        self.assertEqual(artifacts.store_stats()["objects"], 1)

        usage = store.reset_default_tenant_data()

        self.assertEqual(store.read_scan_history("default"), [])
        self.assertEqual(
            artifacts.store_stats()["objects"], 0,
            "a reset that leaves report contents on disk has not erased anything",
        )
        self.assertEqual(usage.get("artifacts_removed"), 1)

    def test_reset_reports_what_it_removed(self) -> None:
        for index in range(3):
            store.save_scan_history("default", _report(f"scan-{index}"))
        usage = store.reset_default_tenant_data()
        self.assertGreaterEqual(usage.get("artifacts_removed", 0), 1)


class ChecksumIsActuallyCompared(_Sandbox):
    def test_an_untouched_database_reports_no_drift(self) -> None:
        with store._connect() as conn:
            self.assertEqual(migrations.checksum_drift(conn), [])

    def test_an_edited_revision_is_detected(self) -> None:
        """The property the module claimed but never checked."""
        with store._connect() as conn:
            conn.execute(
                "UPDATE schema_migrations SET checksum = ? WHERE revision = 1",
                ("0" * 64,),
            )
        with store._connect() as conn:
            drift = migrations.checksum_drift(conn)
        self.assertEqual([item["revision"] for item in drift], [1])
        self.assertEqual(drift[0]["applied_checksum"], "0" * 12)

    def test_a_stamped_revision_is_not_compared(self) -> None:
        """A stamped revision never ran, so its source never built anything."""
        with store._connect() as conn:
            conn.execute(
                "UPDATE schema_migrations SET checksum = ?, name = ? WHERE revision = 1",
                ("0" * 64, "baseline (stamped)"),
            )
        with store._connect() as conn:
            self.assertEqual(migrations.checksum_drift(conn), [])

    def test_status_exposes_drift(self) -> None:
        self.assertIn("checksum_drift", migrations.status())


class TenantIsolationCoverage(_Sandbox):
    def test_coverage_is_reported_and_is_a_no_op_on_sqlite(self) -> None:
        coverage = store.tenant_isolation_coverage()
        self.assertFalse(coverage["applicable"], "RLS is a PostgreSQL control")
        self.assertEqual(coverage["missing_rls"], [])


@unittest.skipUnless(db.is_postgres(), "catalog coverage is a PostgreSQL property")
class TenantIsolationCoverageOnPostgres(unittest.TestCase):
    def test_every_tenant_scoped_table_has_its_foreign_key_and_rls(self) -> None:
        """The build gate for the structural gap: revisions 0003/0004 covered
        the tables that existed when they ran, so a table added later must
        bring its own coverage. This fails the build if one does not."""
        coverage = store.tenant_isolation_coverage()
        self.assertTrue(coverage["applicable"])
        self.assertGreater(coverage["scoped_tables"], 0)
        self.assertEqual(coverage["missing_foreign_key"], [],
                         "a tenant-scoped table has no foreign key to tenants")
        self.assertEqual(coverage["missing_rls"], [],
                         "a tenant-scoped table is not under FORCE row-level security")


class MissingArtifactIsAnHonestError(_Sandbox):
    def setUp(self) -> None:
        super().setUp()
        # The route authenticates before it reads, so the sandbox needs the
        # built-in admin the token names.
        store.create_user("admin", "x" * 60, "admin", "default", "Local Administrator")

    def _lose_the_records(self) -> None:
        """W3.5: a scan is stored as a manifest of record artifacts; lose the one it names."""
        store.save_scan_history("default", _report("gone"))
        with store._connect() as conn:
            ref = conn.execute(
                "SELECT records_ref FROM scan_records WHERE tenant_id = 'default' AND scan_id = 'gone'"
            ).fetchone()["records_ref"]
        artifacts.object_path("default", ref).unlink()

    def test_a_missing_body_raises_a_named_error(self) -> None:
        self._lose_the_records()
        with self.assertRaises(artifacts.ArtifactMissing) as caught:
            store.read_scan_report("default", "gone")
        self.assertIn("artifact", str(caught.exception).lower())

    def test_the_api_answers_503_rather_than_500(self) -> None:
        from fastapi.testclient import TestClient
        from backend.app import app

        self._lose_the_records()
        client = TestClient(app, raise_server_exceptions=False)
        from backend.security import create_token

        # Streamed through the manifest, the report is checked before its 200 is sent: a
        # body cut short after the status would be the dishonest answer.
        response = client.get(
            "/api/history/latest/report",
            headers={"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"},
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertIn("artifact", response.json()["detail"].lower())


if __name__ == "__main__":
    unittest.main()
