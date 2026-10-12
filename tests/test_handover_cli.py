"""The operator commands a fresh install is brought up with: `main.py version` says what is
installed and which schema it needs without touching the database, `main.py admin
set-password` sets the built-in administrator's password without it ever reaching a
command line or the output, and a bare `main.py` serves.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import migrations, security

ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str], config: Path, stdin: str | None = None) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
    env["DSPM_CONFIG_FILE"] = str(config)
    return subprocess.run([sys.executable, str(ROOT / "main.py"), *args], cwd=ROOT, env=env, input=stdin,
                          capture_output=True, encoding="utf-8", errors="replace", timeout=300)


def _new_password() -> str:
    return "Hx7!" + secrets.token_urlsafe(18)


class FreshInstallCommandsTest(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = self.tmp / "db" / "dspm.sqlite"
        self.db.parent.mkdir()
        self.config = self.tmp / "sentro.toml"
        self.config.write_text("\n".join([
            "[settings]",
            f"DSPM_DB_PATH = '{self.db}'",
            f"DSPM_BACKUP_DIR = '{self.tmp / 'backups'}'",
            f"DSPM_ARTIFACT_DIR = '{self.tmp / 'artifacts'}'",
            f"DSPM_SCAN_CACHE_DIR = '{self.tmp / 'cache'}'",
            f"DSPM_LOCAL_JWT_SECRET_PATH = '{self.tmp / 'jwt'}'",
            f"DSPM_LOCAL_VAULT_KEY_PATH = '{self.tmp / 'vault.key'}'",
            f"DSPM_LOCAL_ARTIFACT_KEY_PATH = '{self.tmp / 'artifact.key'}'",
            f"DSPM_LOCAL_BACKUP_KEY_PATH = '{self.tmp / 'backup.key'}'",
            f"DSPM_LOCAL_EVIDENCE_KEY_PATH = '{self.tmp / 'evidence.key'}'",
            "",
        ]), encoding="utf-8")

    def _admin_hash(self) -> str:
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute("SELECT password_hash FROM users WHERE username = 'admin'").fetchone()[0]
        finally:
            conn.close()

    def test_version_reports_the_schema_without_upgrading_the_database(self) -> None:
        shown = _run(["version", "--json"], self.config)
        self.assertEqual(shown.returncode, 0, shown.stderr)
        info = json.loads(shown.stdout)
        self.assertEqual(info["schema_supported"], migrations.expected_revision())
        self.assertEqual(info["schema_applied"], 0)
        self.assertEqual(info["database"]["backend"], "sqlite")
        self.assertTrue(info["version"])
        conn = sqlite3.connect(self.db)
        try:
            tables = conn.execute("SELECT count(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(tables, 0, "version created tables: it upgraded the database")

    def test_set_password_from_standard_input(self) -> None:
        migrated = _run(["migrate", "upgrade", "--json"], self.config)
        self.assertEqual(migrated.returncode, 0, migrated.stderr)
        password = _new_password()
        changed = _run(["admin", "set-password"], self.config, stdin=password + "\n")
        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.assertNotIn(password, changed.stdout + changed.stderr)
        self.assertTrue(security.verify_password(password, self._admin_hash()))

        conn = sqlite3.connect(self.db)
        try:
            details = [row[0] for row in conn.execute(
                "SELECT detail_json FROM audit_events WHERE action = 'user.password_changed'")]
        finally:
            conn.close()
        self.assertEqual(len(details), 1)
        self.assertNotIn(password, details[0])

        second = _new_password()
        again = _run(["admin", "set-password"], self.config, stdin=second + "\n")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertTrue(security.verify_password(second, self._admin_hash()))
        self.assertFalse(security.verify_password(password, self._admin_hash()))

    def test_a_password_the_policy_refuses_changes_nothing(self) -> None:
        password = _new_password()
        first = _run(["admin", "set-password"], self.config, stdin=password + "\n")
        self.assertEqual(first.returncode, 0, first.stderr)
        before = self._admin_hash()
        refused = _run(["admin", "set-password"], self.config, stdin="short\n")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("password policy", refused.stderr)
        self.assertEqual(self._admin_hash(), before)

    def test_ensure_creates_the_administrator_once_and_never_resets_it(self) -> None:
        password = _new_password()
        secret = self.tmp / "admin_password"
        secret.write_text(password + "\n", encoding="utf-8")
        with self.config.open("a", encoding="utf-8") as handle:
            handle.write(f"DSPM_DEV_ADMIN_PASSWORD_FILE = '{secret}'\n")
        created = _run(["admin", "ensure"], self.config)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertIn("was created", created.stdout)
        self.assertNotIn(password, created.stdout + created.stderr)
        self.assertTrue(security.verify_password(password, self._admin_hash()))

        changed = _new_password()
        self.assertEqual(_run(["admin", "set-password"], self.config, stdin=changed + "\n").returncode, 0)
        again = _run(["admin", "ensure"], self.config)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("already exists", again.stdout)
        self.assertTrue(security.verify_password(changed, self._admin_hash()), "ensure reset a changed password")

    def test_the_password_comes_from_a_file_never_an_argument(self) -> None:
        password = _new_password()
        secret = self.tmp / "new_password.txt"
        secret.write_text(password + "\n", encoding="utf-8")
        changed = _run(["admin", "set-password", "--password-file", str(secret)], self.config)
        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.assertTrue(security.verify_password(password, self._admin_hash()))
        refused = _run(["admin", "set-password", "--password", password], self.config)
        self.assertNotEqual(refused.returncode, 0)


class SourceInstallPreparationTest(unittest.TestCase):
    """scripts/init_install.py (run by scripts/setup.ps1): the folders, generated secrets
    and configuration of a source install - written once, never printed, never replaced."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / "data"

    def _prepare(self, *extra: str) -> subprocess.CompletedProcess:
        env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "init_install.py"),
                               "--data-root", str(self.data), *extra], cwd=ROOT, env=env,
                              capture_output=True, encoding="utf-8", errors="replace", timeout=120)

    def test_a_local_install_is_prepared_once_and_its_configuration_is_valid(self) -> None:
        first = self._prepare()
        self.assertEqual(first.returncode, 0, first.stderr)
        summary = json.loads(first.stdout)
        self.assertTrue(summary["config_written"])
        self.assertEqual(sorted(summary["created_secrets"]), sorted(
            ["secret_key", "vault_key", "artifact_key", "backup_key", "evidence_hmac_key", "admin_password"]))
        secrets_dir = self.data / "secrets"
        values = {path.name: path.read_text(encoding="utf-8").strip() for path in secrets_dir.iterdir()}
        for name, value in values.items():
            self.assertGreaterEqual(len(value), 20, name)
            self.assertNotIn(value, first.stdout + first.stderr, f"{name} was printed")
        config_text = (self.data / "config" / "sentro.toml").read_text(encoding="utf-8")
        for value in values.values():
            self.assertNotIn(value, config_text, "a secret value was written into the configuration")
        self.assertIn('DSPM_ENV = "local"', config_text)
        self.assertIn("DSPM_DEV_ADMIN_PASSWORD_FILE", config_text)

        second = self._prepare()
        self.assertEqual(second.returncode, 0, second.stderr)
        again = json.loads(second.stdout)
        self.assertFalse(again["config_written"])
        self.assertEqual(again["created_secrets"], [])
        self.assertEqual({path.name: path.read_text(encoding="utf-8").strip() for path in secrets_dir.iterdir()},
                         values, "a second run replaced a key")

        checked = _run(["config", "check"], self.data / "config" / "sentro.toml")
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for value in values.values():
            self.assertNotIn(value, checked.stdout)

    def test_production_needs_postgresql_and_the_public_name(self) -> None:
        refused = self._prepare("--mode", "production")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("-PublicHostName", refused.stderr)
        refused = self._prepare("--mode", "production", "--public-host", "sentro.corp.example")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("-DatabaseUrlFile", refused.stderr)
        self.assertFalse((self.data / "config" / "sentro.toml").exists())


class ReadinessRuntimeFoldersTest(unittest.TestCase):
    """/api/ready tells an operator the folders this instance writes are usable - created
    on a fresh install, refused when one cannot be written - without naming their paths."""

    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from backend.app import app

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.client = TestClient(app)

    def test_health_names_the_version_build_and_schema(self) -> None:
        from backend import migrations, runtime_identity

        payload = self.client.get("/api/health").json()
        self.assertEqual(payload["version"], runtime_identity.APP_VERSION)
        self.assertIn("label", payload["build"])
        self.assertEqual(payload["database"]["schema_revision"]["expected"], migrations.expected_revision())

    def test_missing_folders_are_created_and_reported_usable(self) -> None:
        artifacts = self.tmp / "fresh" / "artifacts"
        with mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(artifacts)}):
            payload = self.client.get("/api/ready").json()
        self.assertTrue(artifacts.is_dir())
        self.assertEqual(payload["database"]["runtime_directories"]["artifacts"], "ok")
        self.assertEqual(list(artifacts.iterdir()), [], "the probe file is removed")

    def test_a_folder_that_cannot_be_written_fails_readiness(self) -> None:
        blocker = self.tmp / "a-file"
        blocker.write_text("not a folder", encoding="utf-8")
        with mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(blocker / "artifacts")}):
            response = self.client.get("/api/ready")
        payload = response.json()
        self.assertEqual(response.status_code, 503, payload)
        self.assertIn("the artifacts folder cannot be created", payload["failures"])
        self.assertNotIn(str(self.tmp), json.dumps(payload), "paths stay out of an unauthenticated answer")

    def test_an_unusable_log_folder_is_a_warning(self) -> None:
        blocker = self.tmp / "a-file"
        blocker.write_text("not a folder", encoding="utf-8")
        with mock.patch.dict(os.environ, {"DSPM_LOG_DIR": str(blocker / "logs")}):
            payload = self.client.get("/api/ready").json()
        self.assertIn("the logs folder cannot be created", payload["warnings"])
        self.assertNotIn("the logs folder cannot be created", payload["failures"])


class DisposableTestDatabaseTest(unittest.TestCase):
    """What a destructive benchmark or test may write to: a *_test database on this host,
    whatever its port - never the application's, a benchmark's or a remote one."""

    def test_only_a_local_test_database_is_disposable(self) -> None:
        from backend.db import is_disposable_test_url

        cases = {
            "postgresql://sentro_test_app@127.0.0.1:5442/sentro_test": True,
            "postgresql://app@localhost:5432/qa_test": True,
            "postgres://app@[::1]:5432/sentro_test": True,
            "postgresql://app@127.0.0.1:5432/sentro": False,
            "postgresql://app@127.0.0.1:5441/sentro_bench": False,
            "postgresql://app@127.0.0.1:5442/sentro_dev": False,
            "postgresql://app@db01.corp.example:5432/sentro_test": False,
            "postgresql://app@127.0.0.1:5432/_test": False,
            "postgresql://app@127.0.0.1:5432/sentro_test_copy": False,
            "sqlite:///C:/data/x_test": False,
            "": False,
        }
        self.assertEqual({url: is_disposable_test_url(url) for url in cases}, cases)


class BareCommandServesTest(unittest.TestCase):

    def test_no_command_is_serve_with_its_defaults(self) -> None:
        import main

        with mock.patch.object(main, "serve", return_value=0) as served:
            self.assertEqual(main.main([]), 0)
        self.assertEqual(served.call_count, 1)
        args = served.call_args.args[0]
        self.assertEqual(args.command, "serve")
        self.assertTrue(hasattr(args, "port"))


if __name__ == "__main__":
    unittest.main()
