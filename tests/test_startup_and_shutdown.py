"""The backend starts, and stops, with everything Phase B hung on it.

Every other test calls the application without ever starting it: `TestClient(app)` only
runs the routes. Startup is where B2.4's resume sweep, B3's scan scheduler and B5's
housekeeping are attached, and shutdown is where they have to let go. Nothing tested
that, so a backend that would not boot - or would not stop - could have left here with a
green suite.

The schema is not startup's job and this pins that too: `backend.store` converges it when
it is imported (`ensure_schema_ready`), which upgrades on a development install and
**verifies** on a production one, so a build whose migrations have not been run refuses
to serve rather than half-migrating itself while answering requests.

The database here is this test's own, migrated the way an install is, so the sweeps find
an empty install and do nothing - and are required not to fail while doing it.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import migrations, store
from backend.app import app

BACKGROUND_THREADS = ("scan-resumer", "scan-scheduler", "housekeeping")
SWEEP_LOGGERS = ("backend.scan_resumer", "backend.scan_scheduler", "backend.housekeeping")


def _named_threads() -> set[str]:
    return {thread.name for thread in threading.enumerate()}


class TheSchemaIsReadyBeforeAnythingServesTest(unittest.TestCase):
    def test_importing_the_store_left_the_schema_at_this_builds_revision(self) -> None:
        status = migrations.status()
        self.assertEqual(status["applied_revision"], status["expected_revision"],
                         "the schema this build expects is not the one it would serve")
        self.assertEqual(status.get("pending") or [], [])


class TheBackendStartsAndStopsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        base = Path(self._dir.name)
        self._previous_path = store.DB_PATH
        self._env = mock.patch.dict(os.environ, {
            "DSPM_DB_PATH": str(base / "boot.sqlite"),
            "DSPM_ARTIFACT_DIR": str(base / "artifacts"),
            "DSPM_SCAN_CACHE_DIR": str(base / "cache"),
            # Long enough that neither unattended half does a second pass while this
            # test runs, short enough that both are configured to start at all.
            "DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS": "3600",
            "DSPM_RETENTION_INTERVAL_SECONDS": "86400",
        })
        self._env.start()
        store.DB_PATH = base / "boot.sqlite"
        # What an install has before it serves: the schema, at this build's revision.
        store.init_db()
        migrations.upgrade()

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def test_startup_attaches_the_unattended_halves_and_shutdown_lets_go(self) -> None:
        before = _named_threads()

        with self.assertNoLogs(SWEEP_LOGGERS[0], "WARNING"), \
                self.assertNoLogs(SWEEP_LOGGERS[1], "WARNING"), \
                self.assertNoLogs(SWEEP_LOGGERS[2], "WARNING"), \
                TestClient(app) as client:
            self.assertEqual(client.get("/api/health").status_code, 200)
            running = _named_threads()
            for name in BACKGROUND_THREADS:
                self.assertIn(name, running, f"{name} was not started by startup")

        # Shutdown asks them to stop; they are allowed a moment to notice.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and any(name in _named_threads() for name in BACKGROUND_THREADS):
            time.sleep(0.1)
        left = [name for name in BACKGROUND_THREADS if name in _named_threads() and name not in before]
        self.assertEqual(left, [], "a background thread outlived the backend that started it")


if __name__ == "__main__":
    unittest.main()
