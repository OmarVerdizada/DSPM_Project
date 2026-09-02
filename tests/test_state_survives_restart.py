"""Phase 2.2 - security & durable state must survive an app restart (and thus
the SQLite -> PostgreSQL migration).

A restart wipes all in-memory state (the job executor's ``_jobs`` dict, any
per-process counters). The login throttle, JWT revocation list, and scan-job
records are DB-backed precisely so they do NOT reset across a restart or a
database failover. These tests assert that on whichever backend ``DSPM_DB_URL``
selects:

  * on SQLite each class isolates itself with a temp DB file;
  * on PostgreSQL the conftest fixture truncates + re-seeds per test (the temp
    DB_PATH patch is ignored), so the same tests validate the migrated backend.
"""

from __future__ import annotations

import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from backend import jobs, store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _TempStore(unittest.TestCase):
    """Clean store per test: a temp SQLite file (ignored under Postgres, where the
    conftest fixture provides the clean slate instead)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db_path = store.DB_PATH
        store.DB_PATH = Path(self._tmp.name) / "state.sqlite"
        store.init_db()

    def tearDown(self) -> None:
        store.DB_PATH = self._orig_db_path
        self._tmp.cleanup()


class LoginThrottleSurvivesRestart(_TempStore):
    def test_failure_count_persists_across_restart(self) -> None:
        key = f"user:{uuid4().hex[:8]}"
        for _ in range(6):
            store.record_login_failure(key, 900)
        # A restart drops in-memory state; the throttle decision reads the DB,
        # so the accumulated count (and the lockout it drives) is unchanged.
        self.assertEqual(store.count_login_failures(key, 900), 6)

    def test_clear_is_durable(self) -> None:
        key = f"user:{uuid4().hex[:8]}"
        store.record_login_failure(key, 900)
        store.clear_login_failures(key)
        self.assertEqual(store.count_login_failures(key, 900), 0)


class TokenRevocationSurvivesRestart(_TempStore):
    def test_revoked_jti_stays_revoked_across_restart(self) -> None:
        jti = f"jti-{uuid4().hex}"
        store.revoke_token_jti(jti, int(time.time()) + 3600)
        # There is no in-memory revocation cache; a fresh check still sees it.
        self.assertTrue(store.is_token_revoked(jti))

    def test_expired_revocation_is_pruned(self) -> None:
        jti = f"jti-{uuid4().hex}"
        store.revoke_token_jti(jti, int(time.time()) - 1)  # already past expiry
        # Once the token itself has expired there is nothing left to revoke, so
        # the row is pruned and the jti reads as not-revoked.
        self.assertFalse(store.is_token_revoked(jti))

    def test_unrevoked_jti_is_not_revoked(self) -> None:
        self.assertFalse(store.is_token_revoked(f"jti-{uuid4().hex}"))


class JobStateSurvivesRestart(_TempStore):
    def test_running_job_recovered_after_restart(self) -> None:
        jid = f"job-{uuid4().hex[:12]}"
        store.record_job(
            {"id": jid, "tenant_id": "default", "status": "running", "progress": 40, "created_at": _now()}
        )
        # Simulate a restart: the in-memory executor state is gone.
        with jobs._lock:
            jobs._jobs.clear()
        self.assertIsNone(jobs.get_job(jid))  # no longer in memory

        recovered = store.recover_interrupted_jobs()  # runs once at startup
        self.assertEqual(recovered, 1)

        rec = store.read_job("default", jid)
        self.assertIsNotNone(rec)                  # the durable record survived
        self.assertEqual(rec["status"], "failed")  # recovered, not stuck "running"
        self.assertTrue(rec["error"])              # carries the interruption reason

    def test_terminal_job_is_not_recovered(self) -> None:
        jid = f"job-{uuid4().hex[:12]}"
        store.record_job(
            {"id": jid, "tenant_id": "default", "status": "completed", "progress": 100,
             "created_at": _now(), "finished_at": _now()}
        )
        # Recovery must only touch queued/running jobs, never rewrite a finished one.
        self.assertEqual(store.recover_interrupted_jobs(), 0)
        self.assertEqual(store.read_job("default", jid)["status"], "completed")

    def test_job_record_readable_after_memory_eviction(self) -> None:
        # A completed job whose in-memory entry was evicted (retention cleanup or
        # a restart) is still served from the durable record.
        jid = f"job-{uuid4().hex[:12]}"
        store.record_job(
            {"id": jid, "tenant_id": "default", "status": "completed", "progress": 100,
             "created_at": _now(), "finished_at": _now()}
        )
        with jobs._lock:
            jobs._jobs.pop(jid, None)
        self.assertIsNone(jobs.get_job(jid))
        rec = store.read_job("default", jid)
        self.assertEqual(rec["status"], "completed")
        self.assertEqual(rec["result"], None)  # heavy payload is deliberately not persisted


class ScanStatusEndpointFallsBackToDurableRecord(unittest.TestCase):
    """The /api/scans/{id} read path must serve the durable record when the
    in-memory job is gone (retention cleanup or a restart). Uses the shared DB so
    the built-in admin exists (SQLite: from startup; Postgres: conftest re-seed)."""

    def setUp(self) -> None:
        from fastapi.testclient import TestClient
        from backend.app import app
        from backend.security import create_token

        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}

    def test_status_after_restart_reads_durable_record(self) -> None:
        jid = f"job-{uuid4().hex[:12]}"
        store.record_job(
            {"id": jid, "tenant_id": "default", "status": "failed", "progress": 100,
             "created_at": _now(), "finished_at": _now(), "error": "Interrupted by restart"}
        )
        with jobs._lock:
            jobs._jobs.pop(jid, None)  # not in memory (post-restart)

        resp = self.client.get(f"/api/scans/{jid}", headers=self.headers)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["error"], "Interrupted by restart")


if __name__ == "__main__":
    unittest.main()
