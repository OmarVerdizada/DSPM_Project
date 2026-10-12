"""Backend audit, 2026-10 (operations): backups, configuration, reports, metrics and logs.

Each test pins the behaviour a review found wrong, and fails on the code before its fix.
PostgreSQL itself is not run here: the pg_dump / snapshot tests drive the code with a fake
driver and a fake pg_dump, and the live check is the restore drill (scripts/db_restore_drill.py).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet

from backend import backup, housekeeping, migrations, ops_alerts, schema_guard, store

ROOT = Path(__file__).resolve().parents[1]


class _Install(unittest.TestCase):
    """A SQLite install of its own: database, artifact store, backup directory and key."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sentro-audit-ops-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.backups = self.tmp / "backups"
        self.staging_root = self.tmp / "temp"
        self.staging_root.mkdir()
        environment = {
            "DSPM_DB_URL": "", "DSPM_ENV": "local", "DSPM_BACKUP_DIR": str(self.backups),
            "DSPM_BACKUP_KEY": Fernet.generate_key().decode(), "DSPM_ARTIFACT_DIR": str(self.tmp / "artifacts"),
            "DSPM_ARTIFACT_KEY": Fernet.generate_key().decode(), "DSPM_BACKUP_SCHEDULE_HOURS": "24",
            "DSPM_BACKUP_COPY_DIR": "", "DSPM_RETAIN_BACKUP_SETS": "7", "DSPM_RETAIN_BACKUP_DAYS": "0",
            "DSPM_BACKUP_MAX_AGE_HOURS": "26", "DSPM_BACKUP_READY_MAX_AGE_HOURS": "48",
        }
        patcher = mock.patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)
        # The staging folders go to this test's own temporary root.
        temp = mock.patch.object(backup.tempfile, "tempdir", str(self.staging_root))
        temp.start()
        self.addCleanup(temp.stop)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "dspm.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", original)
        migrations.upgrade()
        if store.get_tenant("default") is None:
            store.create_tenant("default", "Default")
        schema_guard.reset()
        self.addCleanup(schema_guard.reset)

    def manifest(self, name: str, *, age_hours: float, verified: bool = True, kind: str = "sqlite",
                 file: str | None = None) -> Path:
        """A set on disk as retention, readiness and the age see it (its payload is not a real dump)."""
        self.backups.mkdir(parents=True, exist_ok=True)
        payload = self.backups / f"{name}.enc"
        payload.write_bytes(b"ciphertext")
        document = {"created_at": (datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat(),
                    "kind": kind, "file": file or payload.name, "table_counts": {}}
        if verified:
            document["verified_at"] = document["created_at"]
        path = self.backups / f"{name}{backup.MANIFEST_SUFFIX}"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def names(self) -> list[str]:
        return sorted(path.name for path in self.backups.iterdir()) if self.backups.exists() else []


# ── 2: `backup create --keep N` ──────────────────────────────────────────────────────
class KeepIsRetentionTest(_Install):

    def test_after_a_move_to_postgresql_the_new_sets_are_kept(self) -> None:
        for name, age in (("sentro_sqlite_a", 96), ("sentro_sqlite_b", 72), ("sentro_sqlite_c", 48)):
            self.manifest(name, age_hours=age)
        self.manifest("sentro_20261001T000000Z", age_hours=2, kind="logical")
        self.manifest("sentro_20261002T000000Z", age_hours=0.1, kind="logical")   # the one just taken
        self.assertEqual(backup.prune_backups(keep=3), 2)
        kept = [item["manifest"].name for item in backup.backup_sets()]
        self.assertEqual(kept, ["sentro_20261002T000000Z.manifest.json", "sentro_20261001T000000Z.manifest.json",
                                "sentro_sqlite_c.manifest.json"])

    def test_a_failed_verify_removes_nothing_that_restores(self) -> None:
        import main

        good = self.manifest("sentro_sqlite_19990101T000000000000Z", age_hours=5)
        with mock.patch.object(backup, "verify_backup", return_value={"ok": False, "problems": ["digest"]}), \
                mock.patch.dict(os.environ), contextlib.redirect_stdout(io.StringIO()):
            code = main.backup_command(mock.Mock(backup_command="create", json=True, verify=True, keep=1))
        self.assertEqual(code, 1)
        self.assertTrue(good.exists(), "--keep 1 after a failed verify deleted the only verified set")

    def test_a_manifest_cannot_make_keep_delete_a_file_outside_its_folder(self) -> None:
        victim = self.tmp / "dspm-victim.sqlite"
        victim.write_text("not a backup", encoding="utf-8")
        self.manifest("sentro_sqlite_hostile", age_hours=96, file="..\\dspm-victim.sqlite")
        self.manifest("sentro_sqlite_new", age_hours=1)
        backup.prune_backups(keep=1)
        self.assertTrue(victim.exists())


# ── 4: the plaintext a backup works from ─────────────────────────────────────────────
class PlaintextIsStagedOutsideTheBackupDirectoryTest(_Install):

    def test_the_sqlite_snapshot_never_sits_in_the_backup_directory(self) -> None:
        seen: list = []
        real = backup.encrypt_file

        def watching(source, dest):
            # The moment a stop or a reboot would leave the snapshot behind.
            seen.append((Path(source).parent, backup.plaintext_dumps(self.backups)))
            return real(source, dest)

        with mock.patch.object(backup, "encrypt_file", side_effect=watching):
            backup.create_sqlite_backup(store.DB_PATH)
        folder, found = seen[0]
        self.assertEqual(found, [], "a stop now would leave production unable to start")
        self.assertNotEqual(folder.resolve(), self.backups.resolve())
        # W3.5: nor in %TEMP% - beside the database, which holds the same bytes in clear.
        self.assertFalse(folder.resolve().is_relative_to(self.staging_root.resolve()), "staged in %TEMP%")
        self.assertEqual(folder.resolve().parent, Path(store.DB_PATH).resolve().parent)
        self.assertEqual(list(self.staging_root.iterdir()), [], "the staging folder goes with the backup")
        self.assertEqual([path for path in self.tmp.iterdir() if path.name.startswith(backup.STAGING_PREFIX)], [],
                         "the staging folder goes with the backup")

    def test_pg_dump_writes_into_a_pipe_and_no_plaintext_file_exists(self) -> None:
        """W3.5: pg_dump has no --file. Its archive is encrypted as it is read from the pipe,
        so no copy in clear exists anywhere for a stop to leave behind."""
        dump = b"PGDMP" + b"\x01" * (3 * 1024 * 1024)
        commands, seen = [], []
        real_encrypt = backup.encrypt_stream

        def watching(fernet, src, out):
            # The moment a stop would leave whatever is staged: nothing in clear anywhere.
            seen.extend(path for path in self.tmp.rglob("*") if path.is_file() and
                        path.read_bytes()[:5] == b"PGDMP")
            return real_encrypt(fernet, src, out)

        class Process:
            def __init__(self, command, **_kwargs):
                commands.append(list(command))
                self.stdin, self.stdout, self.stderr = None, io.BytesIO(dump), io.BytesIO(b"")

            def wait(self):
                return 0

            def kill(self):
                pass

        with mock.patch.object(backup, "_exported_snapshot", return_value=contextlib.nullcontext(("s-1", {}, 30))), \
                mock.patch.object(backup.subprocess, "Popen", side_effect=Process), \
                mock.patch.object(backup, "encrypt_stream", side_effect=watching):
            manifest = backup.create_logical_backup("postgresql://app:pw@127.0.0.1/sentro", self.backups)
        self.assertNotIn("--file", commands[0])
        self.assertEqual(seen, [], "a plaintext dump was on disk while the backup ran")
        self.assertEqual(backup.plaintext_dumps(self.backups), [])
        self.assertEqual(list(self.staging_root.iterdir()), [], "nothing was staged in %TEMP%")
        document = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(document["plaintext_bytes"], len(dump))
        recovered = io.BytesIO()
        with open(self.backups / document["file"], "rb") as src:
            backup.decrypt_stream(Fernet(backup.backup_key()), src, recovered)
        self.assertEqual(recovered.getvalue(), dump)

    def test_a_failing_pg_dump_leaves_no_encrypted_part_either(self) -> None:
        class Process:
            def __init__(self, command, **_kwargs):
                self.stdin, self.stdout, self.stderr = None, io.BytesIO(b"PGDMP partial"), io.BytesIO(b"boom")

            def wait(self):
                return 1

            def kill(self):
                pass

        with mock.patch.object(backup, "_exported_snapshot", return_value=contextlib.nullcontext(("s-1", {}, 30))), \
                mock.patch.object(backup.subprocess, "Popen", side_effect=Process):
            with self.assertRaises(RuntimeError) as failed:
                backup.create_logical_backup("postgresql://app:pw@127.0.0.1/sentro", self.backups)
        self.assertIn("boom", str(failed.exception))
        self.assertEqual(self.names(), [], "a part of the dump was left in the backup directory")

    def test_an_interrupted_backups_folder_is_swept_and_a_running_one_is_not(self) -> None:
        stale = self.staging_root / f"{backup.STAGING_PREFIX}dead"
        running = self.staging_root / f"{backup.STAGING_PREFIX}alive"
        for folder in (stale, running):
            folder.mkdir()
            (folder / "sentro.dump").write_bytes(b"PGDMP plaintext")
        old = time.time() - backup.STAGING_STALE_SECONDS - 60
        os.utime(stale / "sentro.dump", (old, old))
        os.utime(stale, (old, old))
        self.assertEqual(backup.sweep_staging(self.staging_root), 1)
        self.assertFalse(stale.exists())
        self.assertTrue(running.exists())

    def test_startup_sweeps_them(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_RETENTION_INTERVAL_SECONDS": "0", "DSPM_BACKUP_SCHEDULE_HOURS": "0"}), \
                mock.patch.object(backup, "sweep_staging") as sweep:
            housekeeping.start_housekeeping(None)
        sweep.assert_called_once()

    def test_the_database_a_restore_replaces_is_backed_up_here_not_beside_the_copy(self) -> None:
        offhost = self.tmp / "offhost"
        offhost.mkdir()
        manifest = offhost / "sentro_x.manifest.json"
        manifest.write_text(json.dumps({"kind": "logical", "format": backup.INSERT_FORMAT, "file": "x.enc"}),
                            encoding="utf-8")
        with mock.patch.object(backup, "verify_backup", return_value={"ok": True, "problems": []}), \
                mock.patch.object(backup, "create_logical_backup", return_value=self.backups / "prev") as before, \
                mock.patch.object(backup, "_pipe_plaintext", side_effect=RuntimeError("stop")):
            with self.assertRaises(RuntimeError):
                backup.restore_postgres_backup(manifest, "postgresql://app:pw@127.0.0.1/sentro")
        targets = [call.args[1] if len(call.args) > 1 else call.kwargs.get("out_dir") for call in before.call_args_list]
        self.assertNotIn(offhost, targets, "the pre-restore dump went to the off-host share")


# ── 6: failed attempts do not fill the disk ──────────────────────────────────────────
class FailedAttemptsLeaveNothingBehindTest(_Install):

    def test_only_the_newest_set_that_failed_verify_is_kept(self) -> None:
        with mock.patch.object(backup, "verify_backup", return_value={"ok": False, "problems": ["digest"]}):
            first = backup.run_backup_set()
            second = backup.run_backup_set()
        self.assertEqual((first["stage"], second["stage"]), ("verify", "verify"))
        sets = backup.backup_sets()
        self.assertEqual([item["manifest"].name for item in sets], [Path(second["manifest"]).name])
        self.assertTrue(sets[0]["data"].get("verify_failed_at"))
        self.assertFalse(Path(first["manifest"]).exists())
        # One set's files: its database and its artifact inventory (W3.5), nothing of the first.
        kept = Path(second["manifest"]).name[: -len(backup.MANIFEST_SUFFIX)]
        encrypted = [name for name in self.names() if name.endswith(".enc")]
        self.assertEqual(len(encrypted), 2, encrypted)
        self.assertTrue(all(name.startswith(kept) for name in encrypted), encrypted)

    def test_a_create_that_fails_after_encrypting_leaves_no_orphan(self) -> None:
        with mock.patch.object(backup, "capture_artifact_objects", side_effect=OSError("disk full")):
            outcome = backup.run_backup_set()
        self.assertEqual(outcome["stage"], "create")
        self.assertEqual(self.names(), [], "an encrypted database without a manifest was left")

    def test_verify_reads_the_artifact_objects_without_restoring_them(self) -> None:
        from backend import artifacts

        (self.tmp / "artifacts").mkdir()
        artifacts.put_bytes("default", b"a report body the recovery needs")
        manifest = backup.create_backup()
        with mock.patch.object(backup, "restore_artifacts", side_effect=AssertionError("extracted")), \
                mock.patch.object(backup, "_add_artifact_objects", side_effect=AssertionError("restored")):
            report = backup.verify_backup(manifest)
        self.assertTrue(report["ok"], report)
        document = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual((document["artifacts"]["format"], document["artifacts"]["objects"]), (backup.OBJECTS_FORMAT, 1))
        [stored] = list((self.backups / backup.OBJECTS_DIR).glob("*/*/*.enc"))
        stored.write_bytes(stored.read_bytes()[:-10])
        self.assertFalse(backup.verify_backup(manifest)["ok"], "a damaged object still fails")


# ── 7: the age of the newest backup ──────────────────────────────────────────────────
class TheBackupAgeTest(_Install):

    def test_it_reads_when_sets_were_taken_and_skips_a_half_written_manifest(self) -> None:
        self.manifest("sentro_sqlite_20260801T000000000000Z", age_hours=1392)
        self.manifest("sentro_20261002T000000Z", age_hours=1, kind="logical")
        (self.backups / f"sentro_zz_half{backup.MANIFEST_SUFFIX}").write_text('{"created_at": "2026-', encoding="utf-8")
        age = backup.latest_backup_age_seconds()
        self.assertAlmostEqual(age, 3600, delta=120)

    def test_sets_that_failed_verify_do_not_keep_the_stale_alert_quiet(self) -> None:
        self.manifest("sentro_sqlite_good", age_hours=30)
        self.manifest("sentro_sqlite_failed", age_hours=1, verified=False)
        self.assertAlmostEqual(backup.latest_backup_age_seconds(verified=True), 30 * 3600, delta=120)
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production"}):
            self.assertIn("backup_stale", ops_alerts.conditions())
        rules = (ROOT / "deploy" / "monitoring" / "sentro-alerts.yml").read_text(encoding="utf-8")
        stale = rules[rules.index("alert: SentroBackupStale"):].split("- alert:")[0]
        self.assertIn("sentro_backup_verified_age_seconds", stale)

    def test_a_manifest_appears_whole_or_not_at_all(self) -> None:
        with mock.patch.object(backup.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                backup.create_sqlite_backup(store.DB_PATH)
        self.assertEqual(self.names(), [], "a manifest was written in place, or a set without one was left")


# ── 8: row counts and the dump from one snapshot ─────────────────────────────────────
class _FakeConnection:
    def __init__(self, events: list) -> None:
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def close(self) -> None:
        self.events.append(("close", ""))

    def execute(self, sql, params=None):
        self.events.append(("sql", " ".join(sql.split())))
        if "pg_export_snapshot" in sql:
            rows = [("00000003-0000001B-1",)]
        elif "pg_tables" in sql:
            rows = [("assets",)]
        elif "to_regclass" in sql:
            rows = [("schema_migrations",)]
        else:
            rows = [(7,)]
        return types.SimpleNamespace(fetchall=lambda: rows, fetchone=lambda: rows[0])


class OneSnapshotTest(unittest.TestCase):

    def test_pg_dump_dumps_the_snapshot_the_counts_were_read_in(self) -> None:
        events: list = []
        fake = types.SimpleNamespace(connect=lambda *a, **k: _FakeConnection(events))

        def fake_run(command, **_kwargs):
            events.append(("pg_dump", list(command)))
            raise RuntimeError("stop after the call")

        with tempfile.TemporaryDirectory() as out, mock.patch.dict(sys.modules, {"psycopg": fake}), \
                mock.patch.object(backup.subprocess, "Popen", side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                backup.create_logical_backup("postgresql://app:pw@127.0.0.1/sentro", Path(out))
        statements = [text for kind, text in events if kind == "sql"]
        [command] = [args for kind, args in events if kind == "pg_dump"]
        self.assertIn("--snapshot=00000003-0000001B-1", command)
        self.assertTrue(statements[0].startswith("BEGIN ISOLATION LEVEL REPEATABLE READ"), statements)
        dumped_at = events.index(("pg_dump", command))
        counted_at = events.index(("sql", 'SELECT COUNT(*) FROM "assets"'))
        exported_at = events.index(("sql", "SELECT pg_export_snapshot()"))
        self.assertLess(exported_at, counted_at)
        self.assertLess(counted_at, dumped_at, "the counts are read in the snapshot, before the dump")
        self.assertEqual(events[-2:], [("sql", "ROLLBACK"), ("close", "")], "the snapshot is held until pg_dump is done")
        self.assertLess(dumped_at, len(events) - 2)

    def test_restore_says_which_tables_differ_and_fails(self) -> None:
        import main

        result = {"restored": "m", "previous_database": "p", "schema_revision": 30, "tables_differing": ["assets"]}
        printed = io.StringIO()
        with mock.patch.object(backup, "restore_backup", return_value=result), mock.patch.dict(os.environ), \
                contextlib.redirect_stdout(printed):
            code = main.backup_command(mock.Mock(backup_command="restore", manifest="m", yes=True, json=False))
        self.assertEqual(code, 1)
        self.assertIn("assets", printed.getvalue())


# ── 10: a failed manual backup does not fail readiness for a day ─────────────────────
class AFailedManualBackupTest(_Install):

    def attempt(self, at: datetime, trigger: str = "command line") -> None:
        store.set_app_setting(backup.ATTEMPT_SETTING, json.dumps(
            {"at": at.isoformat(), "ok": False, "error": "OSError", "stage": "create", "trigger": trigger}))

    def test_a_verified_set_taken_after_it_clears_readiness(self) -> None:
        now = datetime.now(timezone.utc)
        self.attempt(now - timedelta(hours=2))
        self.manifest("sentro_sqlite_later", age_hours=1)
        ready = backup.readiness(production=True, now=now)
        self.assertEqual(ready["failures"], [], ready)
        self.manifest("sentro_sqlite_later", age_hours=3)    # the set was older than the failure
        self.assertTrue(backup.readiness(production=True, now=now)["failures"])

    def test_the_schedule_retries_it_within_the_hour(self) -> None:
        now = datetime.now(timezone.utc)
        self.manifest("sentro_sqlite_yesterday", age_hours=10)
        interval = backup.schedule_seconds()
        check = housekeeping.backup_check_seconds(interval)
        # The day's scheduled run was claimed an hour ago; the operator's run failed since.
        self.assertTrue(store.claim_housekeeping_run("backup", interval_seconds=interval - check,
                                                     now=now - timedelta(hours=1)))
        self.attempt(now - timedelta(minutes=70))
        with mock.patch.object(backup, "run_backup_set", return_value={"ok": True}) as run:
            self.assertEqual(housekeeping.run_backup_if_due(now=now), {"ok": True})
        run.assert_called_once()


# ── 1: an empty switch ───────────────────────────────────────────────────────────────
PRODUCTION = {
    "DSPM_ENV": "production", "DSPM_SECRET_KEY": "jwt-secret-" + "k" * 40, "DSPM_VAULT_KEY": "vault-key-" + "v" * 34,
    "DSPM_ARTIFACT_KEY": "artifact-key-" + "a" * 31, "DSPM_BACKUP_KEY": "backup-key-" + "b" * 33,
    "DSPM_EVIDENCE_HMAC_KEY": "evidence-key-" + "e" * 30, "DSPM_ADMIN_PASSWORD": "Kestrel-admin-pass-4471",
    "DSPM_DB_URL": "postgresql://sentro_app:db-pass-9922@127.0.0.1:5432/sentro",
}


class AnEmptySwitchTest(unittest.TestCase):
    """bootstrap() rewrote a switch set to nothing as 0 - after production_problems had read
    it as the default. The scan cache was then written in clear, WinRM allowed cleartext in
    production, and report bodies went back into the database."""

    def test_it_reaches_its_readers_as_unset(self) -> None:
        from backend import config
        from collectors import winrm_endpoint_scanner
        from discovery import scan_cache

        environ = dict(PRODUCTION, DSPM_REQUIRE_WINRM_SSL="", DSPM_REPORT_ARTIFACTS="", DSPM_SQLITE_HOLD_OPEN="true")
        config.bootstrap(None, environ)
        self.assertEqual((environ["DSPM_REQUIRE_WINRM_SSL"], environ["DSPM_REPORT_ARTIFACTS"]), ("", ""))
        self.assertEqual(environ["DSPM_SQLITE_HOLD_OPEN"], "1", "a switch that says something is still 1 or 0")
        with mock.patch.dict(os.environ, environ):
            self.assertTrue(winrm_endpoint_scanner._winrm_ssl_required(), "cleartext WinRM in production")
            self.assertTrue(store.report_artifacts_enabled())
        local = {"DSPM_SCAN_CACHE_ENCRYPT": ""}
        config.bootstrap(None, local)
        with mock.patch.dict(os.environ, local):
            self.assertTrue(scan_cache.encryption_enabled(), "the scan cache was written in clear")

    def test_production_refuses_one_that_is_on_by_default(self) -> None:
        from backend import config

        refused = config.resolve(dict(PRODUCTION, DSPM_SCAN_CACHE_ENCRYPT=""), None).errors
        self.assertTrue(any(error.startswith("DSPM_SCAN_CACHE_ENCRYPT is set to nothing") for error in refused), refused)
        with self.assertRaises(config.ConfigError):
            config.bootstrap(None, dict(PRODUCTION, DSPM_SCAN_CACHE_ENCRYPT=""))
        self.assertEqual(config.resolve(dict(PRODUCTION), None).errors, [])


# ── 3: a SIEM URL with a bad port ────────────────────────────────────────────────────
class ABadSiemUrlTest(unittest.TestCase):
    """The first audit write imports DSPM_SIEM_URL as the SIEM configuration. A port out of
    range or not a number raised ValueError there - in every audit write, so nobody could
    sign in - and `config check` still called the configuration valid."""

    BAD = ("tls://siem.corp.local:70000", "tcp://siem.corp.local:6514x")

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sentro-audit-siem-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "siem.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", original)
        store.init_db()
        store.create_tenant("t-siem-url", "t")

    def test_audit_writes_go_on_and_nothing_is_forwarded(self) -> None:
        from backend import siem_settings

        refused = mock.patch.object(siem_settings, "_REFUSED_URLS", set())
        refused.start()
        self.addCleanup(refused.stop)
        for url in self.BAD:
            with self.subTest(url=url), mock.patch.dict(os.environ, {"DSPM_SIEM_URL": url}), \
                    self.assertLogs("backend.siem_settings", "WARNING") as logged:
                store.audit("t-siem-url", "alice", "auth.login", {})
                store.audit("t-siem-url", "alice", "auth.login", {})
                self.assertEqual(store.audit_outbox_status()["pending"], 0)
                self.assertIsNone(siem_settings.target())
            self.assertEqual(len(logged.records), 1, "once, not at every audit write")
            self.assertNotIn("siem.corp.local", logged.output[0])
        self.assertEqual(len([row for row in store.read_audit_log("t-siem-url", 20)]), 4)

    def test_config_check_refuses_it(self) -> None:
        from backend import config

        for url in self.BAD + ("http://siem.corp.local:514", "tls://:6514", "tcp://siem.corp.local:0"):
            with self.subTest(url=url):
                errors = config.resolve({"DSPM_SIEM_URL": url}, None).errors
                self.assertTrue(any(error.startswith("DSPM_SIEM_URL must be") for error in errors), errors)
                self.assertNotIn(url, repr(errors))
        for url in ("tls://siem.corp.local:6514", "udp://10.0.0.5", "tcp://[fd00::5]:1514", ""):
            with self.subTest(url=url):
                self.assertEqual(config.resolve({"DSPM_SIEM_URL": url}, None).errors, [])


# ── 11: one reading of DSPM_ENV ──────────────────────────────────────────────────────
class ProductionWithATrailingSpaceTest(unittest.TestCase):
    """config strips DSPM_ENV, so "production " enforced production's rules - while `serve`
    and the vault, reading it unstripped, treated the install as a development one."""

    def serve(self, **overrides):
        import argparse

        import main

        args = argparse.Namespace(**{"host": "127.0.0.1", "port": 8000, "reload": False, "workers": 1, **overrides})
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production ", "DSPM_ALLOW_EXTERNAL_BIND": ""}), \
                mock.patch("backend.logging_setup.configure"), mock.patch.object(main.uvicorn, "run") as run:
            with self.assertRaises(SystemExit) as refused:
                main.serve(args)
        run.assert_not_called()
        return str(refused.exception)

    def test_serve_refuses_reload(self) -> None:
        self.assertIn("--reload", self.serve(reload=True))

    def test_serve_checks_where_it_listens(self) -> None:
        self.assertIn("not loopback", self.serve(host="0.0.0.0"))

    def test_the_vault_needs_its_key(self) -> None:
        from backend import vault

        with mock.patch.dict(os.environ, {"DSPM_ENV": "production "}):
            self.assertTrue(vault._is_production())


if __name__ == "__main__":
    unittest.main()
