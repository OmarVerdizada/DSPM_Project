"""Startup diagnostics: which build serves which database, and an import that does not
upgrade a database a live server of an older build is serving.

Found 2026-10-05: a server started from a checkout whose migrations ended at revision 35
kept running while the checkout moved on to 43, and development commands run from that
checkout upgraded the server's database under it at import. Every sign-in then failed
with "the database schema is at revision 43, newer than this build's 35" - and nothing
said which build, which source tree or which database that was.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import unittest
from contextlib import suppress
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from backend import db, migrations, runtime_identity, schema_guard, store


class _Database(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._dir.cleanup)
        original = store.DB_PATH
        if not db.is_postgres():
            store.DB_PATH = Path(self._dir.name) / "runtime.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        migrations.upgrade()
        self.addCleanup(self._forget_all)

    def _forget_all(self) -> None:
        with store._connect() as conn:
            conn.execute("DELETE FROM app_settings WHERE key LIKE ?", (store.RUNTIME_INSTANCE_PREFIX + "%",))

    def _instance(self, instance_id: str, *, supports: int, age_seconds: float = 0.0, pid: int = 4242) -> None:
        store.register_runtime_instance({"instance_id": instance_id, "role": "server", "host": "old-host", "pid": pid,
                                         "started_at": "2026-10-02T07:06:47+00:00", "schema_supported": supports,
                                         "source_tree": r"C:\old\checkout", "commit": "feef271"})
        if age_seconds:
            with store._connect() as conn:
                row = conn.execute("SELECT value FROM app_settings WHERE key = ?",
                                   (store.RUNTIME_INSTANCE_PREFIX + instance_id,)).fetchone()
                record = json.loads(row["value"])
                beat = datetime.fromisoformat(record["heartbeat_at"]) - timedelta(seconds=age_seconds)
                record["heartbeat_at"] = beat.isoformat()
                conn.execute("UPDATE app_settings SET value = ? WHERE key = ?",
                             (json.dumps(record), store.RUNTIME_INSTANCE_PREFIX + instance_id))


class WhereTheDatabaseIsTest(unittest.TestCase):

    def test_a_postgres_location_names_host_port_and_database_and_no_credential(self) -> None:
        url = "postgresql://sentro_app:s3cret-Kestrel@db.internal:6543/sentro_prod?sslmode=require"
        with mock.patch.dict(os.environ, {"DSPM_DB_URL": url}):
            location = runtime_identity.database_location()
            described = runtime_identity.describe_location()
        self.assertEqual(location, {"backend": "postgres", "host": "db.internal", "port": 6543,
                                    "database": "sentro_prod"})
        self.assertEqual(described, "postgres db.internal:6543/sentro_prod")
        for secret in ("s3cret-Kestrel", "sentro_app", "sslmode"):
            self.assertNotIn(secret, json.dumps(location) + described)

    @unittest.skipIf(db.is_postgres(), "the SQLite file")
    def test_a_sqlite_location_is_its_file(self) -> None:
        self.assertEqual(runtime_identity.database_location(),
                         {"backend": "sqlite", "path": str(Path(store.DB_PATH).resolve())})


class WhichBuildIsThisTest(unittest.TestCase):

    def test_the_commit_is_read_from_git_without_running_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git" / "refs" / "heads").mkdir(parents=True)
            (root / ".git" / "HEAD").write_text("ref: refs/heads/sentro-ironhack\n", encoding="utf-8")
            (root / ".git" / "refs" / "heads" / "sentro-ironhack").write_text("3096ea7" + "0" * 33 + "\n",
                                                                              encoding="utf-8")
            self.assertEqual(runtime_identity.git_revision(root), {"commit": "3096ea700000", "branch": "sentro-ironhack"})
            (root / ".git" / "refs" / "heads" / "sentro-ironhack").unlink()
            (root / ".git" / "packed-refs").write_text("feef271" + "1" * 33 + " refs/heads/sentro-ironhack\n",
                                                       encoding="utf-8")
            self.assertEqual(runtime_identity.git_revision(root)["commit"], "feef27111111")
            (root / ".git" / "HEAD").write_text("abcdef1234567890\n", encoding="utf-8")
            self.assertEqual(runtime_identity.git_revision(root), {"commit": "abcdef123456", "branch": ""})
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(runtime_identity.git_revision(Path(tmp)), {"commit": "", "branch": ""},
                             "an installed build has no .git")

    def test_a_process_older_than_its_source_tree_is_told_from_one_that_is_not(self) -> None:
        self.assertEqual(runtime_identity.on_disk_revision(), migrations.expected_revision(),
                         "the revision list on disk is the one this process loaded")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "backend").mkdir()
            text = (runtime_identity.SOURCE_TREE / "backend" / "migrations.py").read_text(encoding="utf-8")
            later = migrations.expected_revision() + 1
            text = text.replace("    ]\n\n\ndef expected_revision",
                                f'    ({later}, "a_later_revision", store.add_a_later_revision),\n'
                                "    ]\n\n\ndef expected_revision", 1)
            (root / "backend" / "migrations.py").write_text(text, encoding="utf-8")
            self.assertEqual(runtime_identity.on_disk_revision(root), later)

    def test_the_startup_banner_says_build_schema_and_database(self) -> None:
        line = runtime_identity.banner(41)
        self.assertIn(f"supports schema revision {migrations.expected_revision()}", line)
        self.assertIn("at revision 41", line)
        self.assertIn(runtime_identity.source_tree(), line)
        self.assertIn(runtime_identity.describe_location(), line)


class TheRegistryTest(_Database):

    def test_live_processes_are_listed_and_a_silent_one_ages_out(self) -> None:
        self._instance("live", supports=43)
        self._instance("crashed", supports=35, age_seconds=runtime_identity.STALE_SECONDS + 5)
        live = store.runtime_instances(runtime_identity.STALE_SECONDS)
        self.assertEqual([item["instance_id"] for item in live], ["live"])
        self.assertEqual({item["instance_id"] for item in store.runtime_instances()}, {"live", "crashed"})
        store.forget_runtime_instance("live")
        self.assertEqual(store.runtime_instances(runtime_identity.STALE_SECONDS), [])

    def test_a_server_registers_itself_and_deregisters_at_shutdown(self) -> None:
        with mock.patch.object(runtime_identity, "HEARTBEAT_SECONDS", 3600):
            runtime_identity.register("server")
            try:
                mine = [item for item in store.runtime_instances() if item["instance_id"] == runtime_identity.instance_id()]
                self.assertEqual(len(mine), 1)
                self.assertEqual(mine[0]["schema_supported"], migrations.expected_revision())
                self.assertEqual(mine[0]["source_tree"], runtime_identity.source_tree())
            finally:
                runtime_identity.deregister()
        self.assertFalse([item for item in store.runtime_instances()
                          if item["instance_id"] == runtime_identity.instance_id()])


class AnImportDoesNotUpgradeUnderALiveServerTest(_Database):

    def _behind_by_one(self) -> int:
        latest = migrations.expected_revision()
        with store._connect() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE revision = ?", (latest,))
        return latest

    def _applied(self) -> int:
        with store._connect() as conn:
            return migrations.current_revision(conn)

    def test_a_live_older_server_stops_the_upgrade_and_is_named(self) -> None:
        latest = self._behind_by_one()
        self._instance("old-server", supports=latest - 1, pid=10648)
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local"}), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_MIGRATIONS_CLI", None)
            with self.assertRaisesRegex(RuntimeError, "Refusing to upgrade") as refused:
                store.ensure_schema_ready()
        message = str(refused.exception)
        for detail in ("pid 10648", r"C:\old\checkout", f"revision {latest - 1}", "python main.py migrate upgrade"):
            self.assertIn(detail, message)
        self.assertEqual(self._applied(), latest - 1, "the database was upgraded anyway")

    def test_with_no_live_older_server_the_import_upgrades_as_before(self) -> None:
        latest = self._behind_by_one()
        self._instance("crashed", supports=latest - 1, age_seconds=runtime_identity.STALE_SECONDS + 5)
        self._instance("current", supports=latest)
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local"}):
            os.environ.pop("DSPM_MIGRATIONS_CLI", None)
            store.ensure_schema_ready()
        self.assertEqual(self._applied(), latest)


class AMismatchIsDiagnosedInTheLogTest(_Database):

    def setUp(self) -> None:
        super().setUp()
        schema_guard.reset()
        self.addCleanup(schema_guard.reset)

    def test_the_log_says_the_process_is_older_than_its_checkout_and_the_sign_in_does_not(self) -> None:
        applied = migrations.expected_revision()
        self._instance("newer-server", supports=applied)
        with mock.patch.object(migrations, "expected_revision", return_value=applied - 8), \
                mock.patch.object(runtime_identity, "on_disk_revision", return_value=applied), \
                self.assertLogs("backend.schema_guard", level=logging.ERROR) as logged:
            message = schema_guard.problem()
        self.assertIn(f"newer than this build's {applied - 8}", message)
        self.assertNotIn(runtime_identity.source_tree(), message, "a path on the sign-in page")
        diagnosis = " ".join(logged.output)
        for detail in ("older than its own source tree", "Restart it", runtime_identity.describe_location(),
                       f"Revision {applied} (", "pid 4242 on old-host"):
            self.assertIn(detail, diagnosis)


class TheRuntimeRouteTest(_Database):

    def test_a_platform_administrator_sees_builds_and_database_and_no_secret(self) -> None:
        from fastapi.testclient import TestClient

        from backend.app import app
        from backend.security import create_token, hash_password

        with suppress(Exception):
            store.create_tenant("default", "default")
        if store.get_user("admin") is None:
            store.create_user("admin", hash_password("x9!Runtime-Kestrel"), "admin", "default")
        self._instance("other-server", supports=migrations.expected_revision())
        with TestClient(app) as client:
            self.assertIn(client.get("/api/admin/runtime").status_code, (401, 403))
            response = client.get("/api/admin/runtime",
                                  headers={"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["this"]["schema_supported"], migrations.expected_revision())
        self.assertEqual(payload["this"]["on_disk_revision"], migrations.expected_revision())
        self.assertEqual(payload["database"]["applied_revision"], payload["database"]["expected_revision"])
        self.assertIn("other-server", [item["instance_id"] for item in payload["instances"]])
        rendered = json.dumps(payload).lower()
        for secret in ("password", "dspm_db_url", "postgresql://"):
            self.assertNotIn(secret, rendered)


if __name__ == "__main__":
    unittest.main()
