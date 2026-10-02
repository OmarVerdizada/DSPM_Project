"""C0.3 and C0.4: backups nobody has to remember, and a server that stops writing - and says
why - when the database moves past it.

C0.3 gate: "an unattended day produces a manifest and encrypted backup; ... readiness
becomes unhealthy on a stale or failed backup; off-host copy and key recovery are
demonstrated." Here: the backend's own schedule takes a verified set, claimed once however
many backends run; retention keeps the newest verified sets; a failure is audited (its type,
never its text) and fails production readiness; the off-host copy receives the encrypted set
and its manifest - and no key. The restore drill on the pilot's topology and the approved
off-host location are live infrastructure.

C0.4 gate: "a process started at revision N refuses a live N+1 database within one bounded
check interval; no further writes land; the console shows the cause." Here: /api/ready
writes nothing, the refusal names its reason and revisions in fields, and the console turns
that into one notice.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from backend import backup, housekeeping, migrations, schema_guard, security, store

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
SMOKE = ROOT / "tests" / "js" / "refresh_retry_smoke.js"
DAY = 24 * 3600


class _Install(unittest.TestCase):
    """A SQLite install of its own: database, artifact store, backup directory and key."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sentro-c03-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.key = Fernet.generate_key().decode()
        self.backups = self.tmp / "backups"
        environment = {
            "DSPM_DB_URL": "", "DSPM_ENV": "local", "DSPM_BACKUP_DIR": str(self.backups),
            "DSPM_BACKUP_KEY": self.key, "DSPM_ARTIFACT_DIR": str(self.tmp / "artifacts"),
            "DSPM_ARTIFACT_KEY": Fernet.generate_key().decode(), "DSPM_BACKUP_SCHEDULE_HOURS": "24",
            "DSPM_BACKUP_COPY_DIR": "", "DSPM_RETAIN_BACKUP_SETS": "7", "DSPM_RETAIN_BACKUP_DAYS": "0",
            "DSPM_BACKUP_MAX_AGE_HOURS": "26", "DSPM_BACKUP_READY_MAX_AGE_HOURS": "48",
        }
        patcher = mock.patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "dspm.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", original)
        migrations.upgrade()
        if store.get_tenant("default") is None:
            store.create_tenant("default", "Default")
        # The process's schema state is shared (backend.schema_guard): ask the database afresh.
        schema_guard.reset()
        self.addCleanup(schema_guard.reset)

    def manifest(self, name: str, *, age_hours: float, verified: bool = True, directory: Path | None = None) -> Path:
        """A set on disk as retention and readiness see it (its payload is not a real dump)."""
        folder = directory or self.backups
        folder.mkdir(parents=True, exist_ok=True)
        payload = folder / f"{name}.sqlite.enc"
        payload.write_bytes(b"ciphertext")
        document = {"created_at": (datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat(),
                    "kind": "sqlite", "file": payload.name, "table_counts": {}}
        if verified:
            document["verified_at"] = document["created_at"]
        path = folder / f"{name}{backup.MANIFEST_SUFFIX}"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def audit_rows(self, action: str) -> list[dict]:
        return [row for row in store.read_audit_log("default", 200) if row["action"] == action]


class TheScheduleTest(_Install):

    def test_an_unattended_run_produces_a_verified_encrypted_set_and_says_so(self) -> None:
        outcome = housekeeping.run_backup_if_due()
        self.assertTrue(outcome and outcome["ok"], outcome)
        [item] = backup.backup_sets()
        self.assertTrue(item["verified"], "the set is marked verified only after verify_backup passed")
        self.assertTrue(backup.verify_backup(item["manifest"])["ok"])
        payload = self.backups / item["data"]["file"]
        self.assertTrue(payload.name.endswith(".enc"))
        self.assertNotIn(b"SQLite format 3", payload.read_bytes()[:64], "the database leaves only as ciphertext")
        [row] = self.audit_rows("backup.created")
        self.assertEqual((row["detail"]["trigger"], row["detail"]["verified"]), ("schedule", True))
        self.assertNotIn(self.key, json.dumps(row))
        self.assertTrue(backup.last_attempt()["ok"])

    def test_a_second_backend_does_not_take_the_set_the_first_claimed(self) -> None:
        # The last attempt failed, so a set is due whatever its age: only the claim decides.
        backup.record_attempt(False, "OSError", stage="create")
        now = datetime.now(timezone.utc)
        with mock.patch.object(backup, "run_backup_set", return_value={"ok": True}) as run:
            self.assertEqual(housekeeping.run_backup_if_due(now=now), {"ok": True})
            self.assertIsNone(housekeeping.run_backup_if_due(now=now + timedelta(minutes=5)),
                              "two backends both took the day's backup")
        self.assertEqual(run.call_count, 1)

    def test_two_backend_processes_take_one_set_between_them(self) -> None:
        script = ("import json; from backend import housekeeping; "
                  "print(json.dumps(housekeeping.run_backup_if_due()))")
        env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
        env.update({key: value for key, value in os.environ.items()
                    if key.startswith(("DSPM_BACKUP", "DSPM_ARTIFACT", "DSPM_RETAIN"))})
        env.update({"DSPM_DB_PATH": str(store.DB_PATH), "DSPM_ENV": "local", "DSPM_PBKDF2_ROUNDS": "210000",
                    "DSPM_SCAN_CACHE_DIR": str(self.tmp / "cache"),
                    # Every local key the import could reach for stays in this test's folder.
                    "DSPM_LOCAL_JWT_SECRET_PATH": str(self.tmp / "jwt_secret"),
                    "DSPM_LOCAL_VAULT_KEY_PATH": str(self.tmp / "vault.key"),
                    "DSPM_LOCAL_EVIDENCE_KEY_PATH": str(self.tmp / "evidence.key"),
                    "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(self.tmp / "artifact_key")})
        processes = [subprocess.Popen([sys.executable, "-c", script], cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) for _ in range(2)]
        outputs = [process.communicate(timeout=300) for process in processes]
        for process, (_out, err) in zip(processes, outputs):
            self.assertEqual(process.returncode, 0, err[-600:])
        results = [json.loads(out.strip().splitlines()[-1]) for out, _err in outputs]
        self.assertEqual(sorted(result is None for result in results), [False, True], results)
        self.assertEqual(len(backup.backup_sets()), 1, "one set between two backends")

    def test_a_set_the_upgrade_or_an_operator_took_counts(self) -> None:
        self.manifest("sentro_sqlite_fresh", age_hours=2)
        with mock.patch.object(backup, "run_backup_set") as run:
            self.assertIsNone(housekeeping.run_backup_if_due())
            run.assert_not_called()
        self.manifest("sentro_sqlite_fresh", age_hours=24)   # the same set, a day on
        with mock.patch.object(backup, "run_backup_set", return_value={"ok": True}) as run:
            self.assertEqual(housekeeping.run_backup_if_due(), {"ok": True})

    def test_a_failed_run_is_retried_within_the_hour_not_the_next_day(self) -> None:
        now = datetime.now(timezone.utc)
        with mock.patch.object(backup, "create_backup", side_effect=OSError("disk full")):
            self.assertFalse(housekeeping.run_backup_if_due(now=now)["ok"])
        with mock.patch.object(backup, "run_backup_set", return_value={"ok": True}) as run:
            self.assertIsNone(housekeeping.run_backup_if_due(now=now + timedelta(minutes=30)))
            self.assertEqual(housekeeping.run_backup_if_due(now=now + timedelta(minutes=61)), {"ok": True})
        self.assertEqual(run.call_count, 1)

    def test_it_can_be_turned_off_and_needs_a_named_key_outside_production(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_SCHEDULE_HOURS": "0"}):
            self.assertIsNone(housekeeping.run_backup_if_due())
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_KEY": "", "DSPM_LOCAL_BACKUP_KEY_PATH": ""}):
            self.assertFalse(housekeeping.backup_schedule_active(), "a key made up on the spot is nobody's escrow")
            with mock.patch.dict(os.environ, {"DSPM_ENV": "production"}):
                self.assertTrue(housekeeping.backup_schedule_active(), "production fails loudly instead")
        self.assertEqual(backup.backup_sets(), [])

    def test_nothing_runs_on_a_database_a_newer_release_upgraded(self) -> None:
        with store._connect() as conn:
            conn.execute("INSERT INTO schema_migrations (revision, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                         (migrations.expected_revision() + 1, "from a newer release", "x", "2026-10-01T00:00:00+00:00"))
        schema_guard.reset()
        with mock.patch.object(backup, "run_backup_set") as run, \
                mock.patch.object(housekeeping, "run_if_due") as retention:
            self.assertIn("skipped", housekeeping.run_due_jobs())
        run.assert_not_called()
        retention.assert_not_called()


class TheRetentionTest(_Install):

    def test_the_newest_verified_sets_are_kept(self) -> None:
        for name, age in (("a", 96), ("b", 72), ("c", 48), ("d", 24)):
            self.manifest(f"sentro_sqlite_{name}", age_hours=age)
        removed = backup.apply_retention(keep_sets=2)
        self.assertEqual(sorted(removed), ["sentro_sqlite_a.manifest.json", "sentro_sqlite_b.manifest.json"])
        self.assertEqual([item["manifest"].name for item in backup.backup_sets()],
                         ["sentro_sqlite_d.manifest.json", "sentro_sqlite_c.manifest.json"])
        self.assertFalse((self.backups / "sentro_sqlite_a.sqlite.enc").exists(), "the payload goes with its manifest")

    def test_failed_or_unverified_sets_never_cost_a_verified_one(self) -> None:
        self.manifest("sentro_sqlite_good", age_hours=72)
        for index in range(5):
            self.manifest(f"sentro_sqlite_bad{index}", age_hours=48 - index, verified=False)
        self.assertEqual(backup.apply_retention(keep_sets=1), [])
        kept = {item["manifest"].name for item in backup.backup_sets()}
        self.assertIn("sentro_sqlite_good.manifest.json", kept, "the newest verified set was removed")
        self.assertEqual(len(kept), 6, "sets newer than the newest verified one stay until a newer one verifies")

    def test_days_keep_young_sets_whatever_the_count(self) -> None:
        for name, age in (("a", 24 * 10), ("b", 24 * 3), ("c", 24 * 2), ("d", 24)):
            self.manifest(f"sentro_sqlite_{name}", age_hours=age)
        removed = backup.apply_retention(keep_sets=1, keep_days=5)
        self.assertEqual(removed, ["sentro_sqlite_a.manifest.json"])

    def test_a_manifest_cannot_name_a_file_outside_its_folder(self) -> None:
        victim = self.tmp / "victim.txt"
        victim.write_text("not a backup", encoding="utf-8")
        path = self.manifest("sentro_sqlite_hostile", age_hours=96)
        document = json.loads(path.read_text(encoding="utf-8"))
        document["file"] = "..\\victim.txt"
        path.write_text(json.dumps(document), encoding="utf-8")
        self.manifest("sentro_sqlite_new", age_hours=1)
        backup.apply_retention(keep_sets=1)
        self.assertTrue(victim.exists())

    def test_the_scheduled_run_applies_it(self) -> None:
        for name, age in (("a", 96), ("b", 72)):
            self.manifest(f"sentro_sqlite_{name}", age_hours=age)
        with mock.patch.dict(os.environ, {"DSPM_RETAIN_BACKUP_SETS": "2"}):
            outcome = backup.run_backup_set()
        self.assertTrue(outcome["ok"], outcome)
        self.assertEqual(outcome["removed"], ["sentro_sqlite_a.manifest.json"])


class TheFailureTest(_Install):

    def test_a_failed_run_is_audited_by_type_and_fails_production_readiness(self) -> None:
        secret = "pg_dump: connection to postgresql://app:hunter2@db01 failed"
        with mock.patch.object(backup, "create_backup", side_effect=RuntimeError(secret)):
            outcome = backup.run_backup_set()
        self.assertEqual((outcome["ok"], outcome["stage"], outcome["error"]), (False, "create", "RuntimeError"))
        [row] = self.audit_rows("backup.failed")
        self.assertEqual((row["detail"]["stage"], row["detail"]["error"]), ("create", "RuntimeError"))
        self.assertNotIn("hunter2", json.dumps(row), "the error's text stays out of the audit trail")
        self.assertNotIn(self.key, json.dumps(row))
        self.assertEqual(backup.last_attempt()["ok"], False)

        client = TestClient(__import__("backend.app", fromlist=["app"]).app)
        self.manifest("sentro_sqlite_recent", age_hours=1)      # a recent good set does not excuse it
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production"}):
            refused = client.get("/api/ready")
        self.assertEqual(refused.status_code, 503, refused.json())
        self.assertTrue(any("last backup attempt" in item for item in refused.json()["failures"]))
        relaxed = client.get("/api/ready")
        self.assertEqual(relaxed.status_code, 200, "outside production it stays a warning")
        self.assertTrue(any("last backup attempt" in item for item in relaxed.json()["warnings"]))

    def test_a_set_that_does_not_verify_is_a_failure_and_never_counts(self) -> None:
        with mock.patch.object(backup, "verify_backup", return_value={"ok": False, "problems": ["digest"]}):
            outcome = backup.run_backup_set()
        self.assertEqual((outcome["ok"], outcome["stage"]), (False, "verify"))
        self.assertEqual([item["verified"] for item in backup.backup_sets()], [False])


class TheReadinessTest(_Install):

    def ready(self, production: bool = True):
        client = TestClient(__import__("backend.app", fromlist=["app"]).app)
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production" if production else "local"}):
            return client.get("/api/ready")

    def test_a_stale_verified_backup_fails_production_and_a_fresh_one_does_not(self) -> None:
        self.manifest("sentro_sqlite_fresh", age_hours=3)
        self.assertEqual(self.ready().status_code, 200)
        self.manifest("sentro_sqlite_fresh", age_hours=30)
        warned = self.ready()
        self.assertEqual(warned.status_code, 200, "past the warning, before the failure threshold")
        self.assertTrue(any("30.0h old (threshold 26h)" in item for item in warned.json()["warnings"]))
        self.manifest("sentro_sqlite_fresh", age_hours=50)
        failed = self.ready()
        self.assertEqual(failed.status_code, 503)
        self.assertTrue(any("threshold 48h" in item for item in failed.json()["failures"]))
        self.assertEqual(self.ready(production=False).status_code, 200, "a warning outside production")

    def test_only_a_verified_set_counts(self) -> None:
        self.manifest("sentro_sqlite_unchecked", age_hours=1, verified=False)
        self.manifest("sentro_sqlite_old", age_hours=60)
        self.assertEqual(self.ready().status_code, 503)
        self.assertEqual(self.ready().json()["database"]["backup_age_seconds"] // 3600, 1)

    def test_a_fresh_install_is_ready_before_its_first_backup_and_an_old_one_is_not(self) -> None:
        fresh = self.ready()
        self.assertEqual(fresh.status_code, 200, fresh.json())
        self.assertIn("no backup manifest found", fresh.json()["warnings"])
        with store._connect() as conn:
            conn.execute("UPDATE schema_migrations SET applied_at = ?",
                         ((datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),))
        old = self.ready()
        self.assertEqual(old.status_code, 503)
        self.assertTrue(any("no verified backup" in item for item in old.json()["failures"]))

    def test_the_metrics_show_the_verified_age_and_the_failure(self) -> None:
        from backend import metrics

        self.manifest("sentro_sqlite_fresh", age_hours=2)
        backup.record_attempt(False, "OSError", stage="copy", trigger="schedule")
        text = metrics.render(ready=False, build={})
        self.assertIn("sentro_backup_last_attempt_success 0", text)
        age = float(next(line for line in text.splitlines()
                         if line.startswith("sentro_backup_verified_age_seconds ")).split()[1])
        self.assertAlmostEqual(age, 7200, delta=120)


class TheOffHostCopyTest(_Install):

    def test_the_copy_holds_the_encrypted_set_and_no_key(self) -> None:
        (self.tmp / "artifacts").mkdir()
        from backend import artifacts

        artifacts.put_bytes("default", b"a report body the recovery needs")
        offhost = self.tmp / "offhost" / "sentro"
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_COPY_DIR": str(offhost)}):
            outcome = backup.run_backup_set()
        self.assertTrue(outcome["ok"], outcome)
        names = sorted(path.name for path in offhost.iterdir())
        manifests = [name for name in names if name.endswith(backup.MANIFEST_SUFFIX)]
        self.assertEqual(len(manifests), 1)
        self.assertEqual(len(names), 3, f"database, artifact archive, manifest - and nothing else: {names}")
        self.assertTrue(all(name.endswith((".enc", backup.MANIFEST_SUFFIX)) for name in names), names)
        for path in offhost.iterdir():
            content = path.read_bytes()
            self.assertNotIn(self.key.encode(), content, f"{path.name} carries the backup key")
            self.assertNotIn(os.environ["DSPM_ARTIFACT_KEY"].encode(), content)
            self.assertNotIn(b"a report body the recovery needs", content)
        copied = offhost / manifests[0]
        self.assertTrue(json.loads(copied.read_text(encoding="utf-8")).get("verified_at"))
        self.assertTrue(backup.verify_backup(copied)["ok"], "the off-host copy restores with the escrowed key")
        self.assertTrue(self.audit_rows("backup.created")[0]["detail"]["copied_off_host"])
        self.assertNotIn(str(offhost), json.dumps(self.audit_rows("backup.created")))

    def test_a_copy_that_does_not_match_its_digest_never_lands(self) -> None:
        backup.run_backup_set()
        [item] = backup.backup_sets()
        document = dict(item["data"], ciphertext_sha256="0" * 64)
        item["manifest"].write_text(json.dumps(document), encoding="utf-8")
        offhost = self.tmp / "offhost"
        with self.assertRaises(ValueError):
            backup.copy_set(item["manifest"], offhost)
        self.assertEqual(list(offhost.iterdir()), [], "no manifest, no partial file")

    def test_an_unreachable_copy_location_is_a_failed_backup(self) -> None:
        blocker = self.tmp / "not-a-folder"
        blocker.write_text("x", encoding="utf-8")
        self.manifest("sentro_sqlite_last_week", age_hours=24 * 7)
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_COPY_DIR": str(blocker / "sentro"),
                                          "DSPM_RETAIN_BACKUP_SETS": "1"}):
            outcome = backup.run_backup_set()
        self.assertEqual((outcome["ok"], outcome["stage"]), (False, "copy"))
        self.assertEqual(self.audit_rows("backup.failed")[0]["detail"]["stage"], "copy")
        [item] = backup.backup_sets()
        self.assertTrue(item["verified"], "the local set is still good; only its copy failed")
        self.assertNotEqual(item["manifest"].name, "sentro_sqlite_last_week.manifest.json",
                            "hourly retries while the share is down must not fill the local disk")


class TheReadOnlyReadinessTest(_Install):
    """C0.4: readiness is open while the schema guard has stopped the data routes, so it
    must not write: a probe row was a write landing on a database a newer release owns."""

    def test_readiness_writes_nothing_even_on_a_newer_schema(self) -> None:
        from backend import app as app_module

        client = TestClient(app_module.app)
        watcher = sqlite3.connect(store.DB_PATH)
        self.addCleanup(watcher.close)

        def version() -> int:
            return watcher.execute("PRAGMA data_version").fetchone()[0]

        before = version()
        ready = client.get("/api/ready")
        self.assertEqual(ready.status_code, 200, ready.json())
        self.assertLess(ready.json()["database"]["probe_seconds"], 5)
        self.assertEqual(version(), before, "readiness committed a write")
        self.assertIsNone(store.get_app_setting("ops.readiness_probe"))

        future = migrations.expected_revision() + 1
        with store._connect() as conn:
            conn.execute("INSERT INTO schema_migrations (revision, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                         (future, "from a newer release", "x", "2026-10-01T00:00:00+00:00"))
        before = version()
        refused = client.get("/api/ready")
        self.assertEqual(refused.status_code, 503)
        self.assertEqual(version(), before, "a write landed on the N+1 database")

    def test_the_refusal_names_its_reason_and_revisions(self) -> None:
        from backend import app as app_module

        app_module._SCHEMA_GUARD.update({"checked": float("-inf"), "problem": "", "revision": None})
        self.addCleanup(app_module._SCHEMA_GUARD.update, {"checked": float("-inf"), "problem": "", "revision": None})
        future = migrations.expected_revision() + 1
        with store._connect() as conn:
            conn.execute("INSERT INTO schema_migrations (revision, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                         (future, "from a newer release", "x", "2026-10-01T00:00:00+00:00"))
        token = {"Authorization": f"Bearer {security.create_token('admin', 'admin', 'default')}"}
        refused = TestClient(app_module.app).get("/api/profile", headers=token)
        self.assertEqual(refused.status_code, 503)
        body = refused.json()
        self.assertEqual((body["reason"], body["applied"], body["expected"]),
                         ("schema_mismatch", future, migrations.expected_revision()))
        self.assertIn(f"revision {future}", body["detail"])


class TheConsoleShowsTheCauseTest(unittest.TestCase):
    """The real frontend/app.js in Node (tests/js/refresh_retry_smoke.js): every panel is
    refused at once, and the operator gets one notice that says what to do."""

    EXPRESSION = """(async () => {
      const shown = [];
      showToast = (title, message, tone) => { shown.push({ title, message, tone }); return null; };
      const refuse = (payload) => async () => ({
        ok: false, status: 503, headers: { get: () => null }, clone() { return this; },
        json: async () => payload, text: async () => JSON.stringify(payload) });
      fetch = refuse({ detail: "Service Unavailable" });
      try { await api("/api/elsewhere", null, "GET"); } catch (error) { /* refused */ }
      const before = shown.length;
      fetch = refuse({ detail: "The database schema is at revision 36", reason: "schema_mismatch",
                       applied: 36, expected: 35 });
      const failures = [];
      for (const path of ["/api/a", "/api/b", "/api/c"]) {
        try { await api(path, null, "GET"); } catch (error) { failures.push(String(error.message)); }
      }
      return { before, shown, failures };
    })()"""

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_one_notice_names_both_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "scenario.json"
            fixture.write_text(json.dumps({"drive": "evaluate", "evaluate": {"run": self.EXPRESSION}}),
                               encoding="utf-8")
            result = subprocess.run([NODE, str(SMOKE), str(fixture)], cwd=ROOT, capture_output=True, text=True,
                                    timeout=180, check=False)
        self.assertTrue(result.stdout.strip(), result.stderr[-400:])
        report = json.loads(result.stdout.strip().splitlines()[-1])
        run = report["values"]["run"]
        self.assertIsInstance(run, dict, run)
        self.assertEqual(run["before"], 0, "a 503 for another reason raises no schema notice")
        self.assertEqual(len(run["shown"]), 1, "one notice, not one per refused request")
        notice = run["shown"][0]
        self.assertEqual(notice["tone"], "danger")
        self.assertIn("revision 36", notice["message"])
        self.assertIn("revision 35", notice["message"])
        self.assertIn("Restart the Sentro service", notice["title"] + notice["message"])
        self.assertEqual(len(run["failures"]), 3, "the calls still fail; the notice explains why")


if __name__ == "__main__":
    unittest.main()
