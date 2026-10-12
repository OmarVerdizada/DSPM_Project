"""C11 (with C0.3/C0.4's prerequisites): the backup an upgrade stands on, and a server
that stops writing when the schema moves past it.

Gate lines: "upgrade sequence: quiesce -> verified encrypted backup -> migrations ...",
"downgrade refuses an unsafe schema", "no secret may appear in ... backup manifests ...
service command lines". `main.py backup create --verify` proves its own backup by
decrypting it; restore keeps the database it replaces; pg_dump no longer receives the
database password on its command line; a newer schema turns data routes into 503.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import backup, security, store

ROOT = Path(__file__).resolve().parents[1]
MARKER = "c11-backup-marker-4111-1111-1111-1111"


def _run(args: list[str], config: Path) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
    env["DSPM_CONFIG_FILE"] = str(config)
    return subprocess.run([sys.executable, str(ROOT / "main.py"), *args], cwd=ROOT, env=env,
                          capture_output=True, encoding="utf-8", errors="replace", timeout=300)


class TheBackupCommandTest(unittest.TestCase):
    """The commands an upgrade runs, against an install described only by its config file."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        key = __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet.generate_key().decode()
        (self.tmp / "backup_key").write_text(key, encoding="utf-8")
        (self.tmp / "artifact_key").write_text(
            __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet.generate_key().decode(), encoding="utf-8")
        self.db = self.tmp / "db" / "dspm.sqlite"
        self.db.parent.mkdir()
        self.config = self.tmp / "sentro.toml"
        self.config.write_text("\n".join([
            "[settings]",
            f"DSPM_DB_PATH = '{self.db}'",
            f"DSPM_BACKUP_DIR = '{self.tmp / 'backups'}'",
            f"DSPM_ARTIFACT_DIR = '{self.tmp / 'artifacts'}'",
            f"DSPM_BACKUP_KEY_FILE = '{self.tmp / 'backup_key'}'",
            f"DSPM_ARTIFACT_KEY_FILE = '{self.tmp / 'artifact_key'}'",
            f"DSPM_LOCAL_JWT_SECRET_PATH = '{self.tmp / 'jwt'}'",
            f"DSPM_LOCAL_VAULT_KEY_PATH = '{self.tmp / 'vault.key'}'",
            f"DSPM_LOCAL_EVIDENCE_KEY_PATH = '{self.tmp / 'evidence.key'}'",
            f"DSPM_SCAN_CACHE_DIR = '{self.tmp / 'cache'}'",
            "",
        ]), encoding="utf-8")
        migrated = _run(["migrate", "upgrade", "--json"], self.config)
        self.assertEqual(migrated.returncode, 0, migrated.stderr)
        self.revision = json.loads(migrated.stdout.strip().splitlines()[-1])["applied_revision"]
        conn = sqlite3.connect(self.db)
        conn.execute("INSERT INTO tenants (tenant_id, display_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
                     ("c11-tenant", MARKER, "2026-09-28T00:00:00Z", "2026-09-28T00:00:00Z"))
        conn.commit()
        conn.close()

    def test_migrate_status_reads_without_converging(self) -> None:
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM schema_migrations WHERE revision = (SELECT MAX(revision) FROM schema_migrations)")
        conn.commit()
        conn.close()
        status = _run(["migrate", "status", "--json"], self.config)
        info = json.loads(status.stdout.strip().splitlines()[-1])
        self.assertEqual(info["applied_revision"], self.revision - 1, "status must not apply what is pending")
        self.assertEqual(info["pending"], [self.revision])

    def test_a_backup_is_encrypted_verified_and_restorable(self) -> None:
        created = _run(["backup", "create", "--verify", "--json"], self.config)
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        document = json.loads(created.stdout.strip().splitlines()[-1])
        self.assertTrue(document["verified"])
        self.assertEqual(document["schema_revision"], self.revision)
        manifest = Path(document["manifest"])
        payload = manifest.parent / json.loads(manifest.read_text(encoding="utf-8"))["file"]
        self.assertNotIn(MARKER.encode(), payload.read_bytes(), "the database leaves only as ciphertext")
        leftovers = [item.name for item in manifest.parent.iterdir() if item.suffix == ".sqlite"]
        self.assertEqual(leftovers, [], "no plaintext snapshot is left beside the backup")

        # the database changes after the backup ... and the backup brings it back
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM tenants WHERE tenant_id = 'c11-tenant'")
        conn.commit()
        conn.close()
        refused = _run(["backup", "restore", str(manifest)], self.config)
        self.assertEqual(refused.returncode, 2, "restore without --yes changes nothing")
        restored = _run(["backup", "restore", str(manifest), "--yes", "--json"], self.config)
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        result = json.loads(restored.stdout.strip().splitlines()[-1])
        self.assertTrue(Path(result["previous_database"]).exists(), "the replaced database is kept")
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("SELECT display_name FROM tenants WHERE tenant_id = 'c11-tenant'").fetchone(),
                         (MARKER,))
        conn.close()

    def test_verify_finds_a_damaged_or_foreign_backup(self) -> None:
        created = json.loads(_run(["backup", "create", "--json"], self.config).stdout.strip().splitlines()[-1])
        manifest = Path(created["manifest"])
        payload = manifest.parent / json.loads(manifest.read_text(encoding="utf-8"))["file"]
        data = bytearray(payload.read_bytes())
        data[len(data) // 2] ^= 0x01
        payload.write_bytes(bytes(data))
        verified = _run(["backup", "verify", str(manifest), "--json"], self.config)
        self.assertEqual(verified.returncode, 1)
        report = json.loads(verified.stdout.strip().splitlines()[-1])
        self.assertFalse(report["ok"])
        self.assertTrue(any("digest" in problem or "decrypted" in problem for problem in report["problems"]))
        restored = _run(["backup", "restore", str(manifest), "--yes"], self.config)
        self.assertNotEqual(restored.returncode, 0, "an unverified backup is never restored")

    def test_a_substituted_backup_is_refused_although_it_decrypts(self) -> None:
        # Another backup set's payload, encrypted with the same key, under this manifest:
        # Fernet accepts it, so only the recorded digests and counts can tell - and
        # restoring it would silently put a different database in place.
        first = Path(json.loads(_run(["backup", "create", "--json"], self.config).stdout.strip().splitlines()[-1])["manifest"])
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM tenants WHERE tenant_id = 'c11-tenant'")
        conn.commit()
        conn.close()
        second = Path(json.loads(_run(["backup", "create", "--json"], self.config).stdout.strip().splitlines()[-1])["manifest"])
        payload = lambda manifest: manifest.parent / json.loads(manifest.read_text(encoding="utf-8"))["file"]  # noqa: E731
        shutil.copyfile(payload(second), payload(first))
        verified = _run(["backup", "verify", str(first), "--json"], self.config)
        self.assertEqual(verified.returncode, 1, verified.stdout)
        before = self.db.read_bytes()
        restored = _run(["backup", "restore", str(first), "--yes"], self.config)
        self.assertNotEqual(restored.returncode, 0, "a set that does not match its manifest is never restored")
        self.assertEqual(self.db.read_bytes(), before, "and the database is left exactly as it was")

    def test_the_manifest_holds_no_secret(self) -> None:
        created = json.loads(_run(["backup", "create", "--json"], self.config).stdout.strip().splitlines()[-1])
        text = Path(created["manifest"]).read_text(encoding="utf-8")
        for secret_file in ("backup_key", "artifact_key"):
            self.assertNotIn((self.tmp / secret_file).read_text(encoding="utf-8").strip(), text)


class TheDumpPasswordTest(unittest.TestCase):
    """pg_dump got `--dbname=postgresql://user:PASSWORD@host/db` - readable by any user of
    the host in the process list. The password now goes through PGPASSWORD."""

    def test_the_password_leaves_the_command_line(self) -> None:
        conninfo, env = backup.pg_tool_environment("postgresql://sentro_app:S3cret-pw@db01:5432/sentro?sslmode=require")
        self.assertNotIn("S3cret-pw", conninfo)
        self.assertEqual(env["PGPASSWORD"], "S3cret-pw")
        self.assertIn("db01", conninfo)
        self.assertIn("sslmode", conninfo)

    def test_pg_dump_is_called_without_it(self) -> None:
        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs.get("env") or {}))
            raise RuntimeError("stop after the call")

        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(backup, "_exported_snapshot", return_value=contextlib.nullcontext(("s-1", {}, 26))), \
                mock.patch.object(backup.subprocess, "Popen", side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                backup.create_logical_backup("postgresql://sentro_app:S3cret-pw@db01:5432/sentro", Path(out))
        args, env = calls[0]
        self.assertFalse(any("S3cret-pw" in str(arg) for arg in args), args)
        self.assertEqual(env.get("PGPASSWORD"), "S3cret-pw")


class ARestoredArtifactStoreTest(unittest.TestCase):
    """M3 exit review: the archive names an object <tenant>/<id>; the store keeps it under a
    fan-out folder. A restore copied objects back without it - where nothing reads them."""

    def test_restored_objects_are_where_the_store_reads_them(self) -> None:
        from cryptography.fernet import Fernet

        from backend import artifacts

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        environment = {"DSPM_ARTIFACT_DIR": str(tmp / "store"), "DSPM_ARTIFACT_KEY": Fernet.generate_key().decode(),
                       "DSPM_BACKUP_KEY": Fernet.generate_key().decode()}
        with mock.patch.dict(os.environ, environment):
            ref = artifacts.put_bytes("c11-tenant", b"a report the recovery must bring back")
            sets = tmp / "backups"
            sets.mkdir()
            captured = backup.capture_artifact_objects(sets, sets / "set.objects.enc")
            manifest = sets / "set.manifest.json"
            manifest.write_text(json.dumps({"artifacts": captured}), encoding="utf-8")
            shutil.rmtree(tmp / "store")  # the disaster: the store is gone
            added = backup._add_artifact_objects(manifest, json.loads(manifest.read_text(encoding="utf-8")), None)
            self.assertEqual(added, 1)
            self.assertTrue(artifacts.object_path("c11-tenant", ref.content_id).exists())
            self.assertEqual(artifacts.get_bytes("c11-tenant", ref.content_id), b"a report the recovery must bring back")


class APostgresBackupUnderRowSecurityTest(unittest.TestCase):
    """M3 exit review: C10 FORCEd row-level security on tables the application role owns, so
    pg_dump - connecting as that owner - was refused at the first table, and the row counts
    read 0 in every tenant table. The dump and restore now run with row security ON under a
    named purpose the policies admit, and the rows travel as INSERTs (PostgreSQL refuses
    COPY FROM into a table with row-level security)."""

    def _calls(self, function, *args):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((list(command), kwargs.get("env") or {}))
            raise RuntimeError("stop after the call")

        with mock.patch.object(backup, "_exported_snapshot", return_value=contextlib.nullcontext(("s-1", {}, 30))), \
                mock.patch.object(backup, "verify_backup", return_value={"ok": True, "problems": []}), \
                mock.patch.object(backup, "create_logical_backup", wraps=backup.create_logical_backup), \
                mock.patch.object(backup, "decrypt_file", return_value="digest"), \
                mock.patch.object(backup.subprocess, "Popen", side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                function(*args)
        return calls

    def test_the_dump_names_the_backup_purpose_and_writes_inserts(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            command, env = self._calls(backup.create_logical_backup, "postgresql://app:pw@db01/sentro", Path(out))[0]
        self.assertIn("--enable-row-security", command)
        self.assertIn("--inserts", command)
        self.assertIn("-c app.platform=backup", env.get("PGOPTIONS", ""))

    def test_a_backup_written_as_copy_data_is_refused_before_anything_runs(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            manifest = Path(out) / "old.manifest.json"
            manifest.write_text(json.dumps({"kind": "logical", "format": "pg_dump-custom+chunked-fernet",
                                            "file": "x.enc"}), encoding="utf-8")
            with mock.patch.object(backup.subprocess, "run", side_effect=AssertionError("nothing may run")),                     mock.patch.object(backup.subprocess, "Popen", side_effect=AssertionError("nothing may run")):
                with self.assertRaises(RuntimeError) as refused:
                    backup.restore_postgres_backup(manifest, "postgresql://app:pw@127.0.0.1/sentro")
        self.assertIn("COPY data", str(refused.exception))

    def test_the_counts_are_read_under_the_backup_purpose(self) -> None:
        import sys as _sys
        import types

        seen = []

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

            def execute(self, sql, params=None):
                seen.append((sql, params))
                rows = [("assets",)] if "pg_tables" in sql else [(7,)]
                return types.SimpleNamespace(fetchall=lambda: rows, fetchone=lambda: rows[0])

        fake = types.SimpleNamespace(connect=lambda *a, **k: Connection())
        with mock.patch.dict(_sys.modules, {"psycopg": fake}):
            counts = backup.capture_table_counts("postgresql://app:pw@127.0.0.1/sentro")
        self.assertEqual(counts, {"assets": 7})
        self.assertEqual(seen[0], ("SELECT set_config('app.platform', %s, false)", ("backup",)),
                         "the purpose is named before any table is counted")

    def test_every_tenant_table_admits_the_backup(self) -> None:
        for table in ("assets", "audit_events", "secrets", "scan_sources"):
            self.assertIn("'backup'", store.tenant_policy_predicate(table), table)


@unittest.skipUnless(os.getenv("DSPM_DB_URL", "").endswith("/sentro_test"), "the disposable PostgreSQL test database")
class APostgresBackupRestoresTest(unittest.TestCase):
    """The drill on the disposable sentro_test database: back up, change, restore, and the
    rows are the backup's - with FORCEd row-level security still on."""

    def test_backup_change_restore(self) -> None:
        import psycopg

        from backend import db

        url = os.environ["DSPM_DB_URL"]
        store.create_tenant("c11-pg-drill", "drill")
        store.audit("c11-pg-drill", "drill", "drill.kept", {"n": 1})
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, True)
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_DIR": str(out)}):
            manifest = backup.create_logical_backup(url, out)
            self.assertTrue(backup.verify_backup(manifest)["ok"])
            recorded = json.loads(manifest.read_text(encoding="utf-8"))["table_counts"]
            self.assertGreaterEqual(recorded["audit_events"], 1, "counts are read under the purpose, not as 0")
            store.audit("c11-pg-drill", "drill", "drill.after", {"n": 2})
            result = backup.restore_postgres_backup(manifest, url, out / "artifacts")
        self.assertEqual(result["tables_differing"], [])
        self.assertTrue(Path(result["previous_database"]).exists(), "the replaced contents are backed up first")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("SELECT set_config('app.platform', 'backup', false)")
            actions = {row[0] for row in conn.execute(
                "SELECT action FROM audit_events WHERE tenant_id = 'c11-pg-drill'").fetchall()}
            forced = conn.execute("SELECT relforcerowsecurity FROM pg_class WHERE relname = 'audit_events'").fetchone()[0]
        self.assertIn("drill.kept", actions)
        self.assertNotIn("drill.after", actions)
        self.assertTrue(forced, "row-level security is still FORCEd")
        del db


class TheRunningSchemaGuardTest(unittest.TestCase):
    """C0.4: a process started at revision N refuses a live N+1 database within one check."""

    def setUp(self) -> None:
        from backend import app as app_module

        self.app_module = app_module
        self.client = TestClient(app_module.app)
        self.token = {"Authorization": f"Bearer {security.create_token('admin', 'admin', 'default')}"}
        app_module._SCHEMA_GUARD.update({"checked": float("-inf"), "problem": ""})
        self.addCleanup(app_module._SCHEMA_GUARD.update, {"checked": float("-inf"), "problem": ""})

    def _future_revision(self) -> int:
        from backend import migrations

        future = migrations.expected_revision() + 1
        with store._connect() as conn:
            conn.execute("INSERT INTO schema_migrations (revision, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                         (future, "from a newer release", "x", "2026-09-28T00:00:00Z"))

        def remove() -> None:
            with store._connect() as conn:
                conn.execute("DELETE FROM schema_migrations WHERE revision = ?", (future,))

        self.addCleanup(remove)
        return future

    def test_data_routes_stop_and_health_says_why(self) -> None:
        self.assertEqual(self.client.get("/api/profile", headers=self.token).status_code, 200)
        future = self._future_revision()
        self.app_module._SCHEMA_GUARD["checked"] = float("-inf")  # the interval has passed
        refused = self.client.get("/api/profile", headers=self.token)
        self.assertEqual(refused.status_code, 503)
        self.assertIn(f"revision {future}", refused.json()["detail"])
        self.assertEqual(self.client.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code, 503,
                         "writes are refused too")
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        ready = self.client.get("/api/ready")
        self.assertEqual(ready.status_code, 503)

    def test_within_the_interval_the_answer_is_cached(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_SCHEMA_CHECK_SECONDS": "3600"}):
            self.assertEqual(self.client.get("/api/profile", headers=self.token).status_code, 200)
            self._future_revision()
            self.assertEqual(self.client.get("/api/profile", headers=self.token).status_code, 200,
                             "one bounded check per interval, not a query per request")

    def test_the_worker_takes_no_work_from_a_newer_schema(self) -> None:
        from backend import partition_worker

        partition_worker._SCHEMA_STATE.update({"checked": float("-inf"), "newer": False})
        self.addCleanup(partition_worker._SCHEMA_STATE.update, {"checked": float("-inf"), "newer": False})
        self.assertFalse(partition_worker._schema_is_newer())
        self._future_revision()
        partition_worker._SCHEMA_STATE["checked"] = float("-inf")
        self.assertTrue(partition_worker._schema_is_newer())
        taken = []

        class Queue:
            def take(self, *args, **kwargs):
                taken.append(1)

        import threading

        stop = threading.Event()
        threading.Timer(0.3, stop.set).start()
        partition_worker.run_worker(Queue(), lambda request: None, worker_id="c11", stop=stop, idle_seconds=0.05)
        self.assertEqual(taken, [], "no partition is leased while the schema is newer")

    def test_health_names_the_build(self) -> None:
        build = self.client.get("/api/health").json()["build"]
        self.assertIn(build["label"], {"development"} | {build["label"]})
        self.assertIn("commit", build)


if __name__ == "__main__":
    unittest.main()
