"""Deployment-shaped migration tests (roadmap Phase 6, DB-13).

The migration runner is already tested for a fresh database (see
`test_schema_migrations.py`). These cover the two situations that only occur
during a real deployment, and that a clean-install test cannot reach:

- **Upgrade from a prior release.** Every intermediate revision must be a
  serving state: an operator upgrading from any older build stops at the
  revision that build expected, so a revision that only works when applied
  immediately after the one before it is a broken upgrade path.
- **Concurrent deployment.** Two application instances starting at once, or a
  deploy racing a health check, must not both apply the same revision. On
  PostgreSQL an advisory lock serializes them; this proves it rather than
  assuming it.
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from backend import db, migrations, store


class _TempDatabase(unittest.TestCase):
    def setUp(self) -> None:
        if db.is_postgres():
            self.skipTest("these drive a private database file")
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self._orig = store.DB_PATH
        store.DB_PATH = Path(self._tmp.name) / "deploy.sqlite"

        def _restore() -> None:
            store.DB_PATH = self._orig

        self.addCleanup(_restore)

    def _applied(self) -> int:
        with store._connect() as conn:
            return migrations.current_revision(conn)

    def _history(self) -> list[int]:
        with store._connect() as conn:
            return [
                int(r["revision"]) for r in conn.execute(
                    "SELECT revision FROM schema_migrations ORDER BY revision"
                ).fetchall()
            ]


class UpgradeFromEveryPriorRelease(_TempDatabase):
    def test_each_revision_is_a_serving_state(self) -> None:
        """Apply revisions one at a time, checking the database is usable at
        every step - each is a version some deployed build expects."""
        revisions = migrations._revisions()
        original = migrations._revisions

        for stop_at in range(1, len(revisions) + 1):
            with self.subTest(revision=stop_at):
                # Present the runner with only the revisions a build of that
                # vintage knew about, exactly as an older release would.
                subset = revisions[:stop_at]
                migrations._revisions = lambda subset=subset: subset
                try:
                    final = migrations.upgrade()
                    self.assertEqual(final, stop_at)
                    self.assertEqual(self._applied(), stop_at)
                    # A serving state: the core tables answer queries.
                    with store._connect() as conn:
                        conn.execute("SELECT COUNT(*) AS n FROM tenants").fetchone()
                        conn.execute("SELECT COUNT(*) AS n FROM scan_reports").fetchone()
                    # And the build of that vintage passes its own gate.
                    migrations.verify_or_raise()
                finally:
                    migrations._revisions = original

    def test_upgrading_from_an_older_release_applies_only_what_is_missing(self) -> None:
        revisions = migrations._revisions()
        self.assertGreaterEqual(len(revisions), 2, "needs at least two revisions")
        original = migrations._revisions

        # Deploy an older build...
        older = revisions[:-1]
        migrations._revisions = lambda: older
        try:
            migrations.upgrade()
            self.assertEqual(self._history(), [r[0] for r in older])
        finally:
            migrations._revisions = original

        # ...then upgrade to this one. Only the new revision runs, and the
        # already-recorded ones are not re-applied.
        final = migrations.upgrade()
        self.assertEqual(final, migrations.expected_revision())
        self.assertEqual(self._history(), [r[0] for r in revisions])

    def test_a_build_older_than_the_database_refuses_to_serve(self) -> None:
        """The rollback direction: deploying an older application against an
        already-upgraded database must refuse, not silently misread it."""
        migrations.upgrade()
        revisions = migrations._revisions()
        original = migrations._revisions
        migrations._revisions = lambda: revisions[:-1]
        try:
            with self.assertRaisesRegex(RuntimeError, "NEWER"):
                migrations.verify_or_raise()
        finally:
            migrations._revisions = original


class ConcurrentDeployment(_TempDatabase):
    def test_racing_starters_apply_each_revision_once(self) -> None:
        """Two instances starting together must not both run the migrations.

        SQLite serializes on the process lock the store already holds;
        PostgreSQL uses a cluster-wide advisory lock. Either way the recorded
        history must contain each revision exactly once - a duplicate would
        mean a revision ran twice.
        """
        results: list = []
        errors: list = []

        def deploy() -> None:
            try:
                results.append(migrations.upgrade())
            except Exception as exc:  # pragma: no cover - failure surfaces below
                errors.append(exc)

        threads = [threading.Thread(target=deploy) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)

        self.assertEqual(errors, [], f"a concurrent starter failed: {errors}")
        expected = migrations.expected_revision()
        self.assertEqual(results, [expected] * 4, "every starter must observe the final revision")
        history = self._history()
        self.assertEqual(history, sorted(set(history)), "a revision was recorded twice")
        self.assertEqual(history, [number for number, _n, _f in migrations._revisions()])


@unittest.skipUnless(db.is_postgres(), "the advisory lock is a PostgreSQL control")
class ConcurrentDeploymentOnPostgres(unittest.TestCase):
    """The lock that matters in production, exercised where it exists.

    The suite's database is already at the expected revision, so this proves
    the property that holds for every restart after the first: concurrent
    starters serialize on the advisory lock, none deadlock, none time out, and
    the recorded history gains no duplicate rows.
    """

    def test_racing_starters_serialize_without_deadlock(self) -> None:
        results: list = []
        errors: list = []

        def deploy() -> None:
            try:
                results.append(migrations.upgrade())
            except Exception as exc:  # pragma: no cover - failure surfaces below
                errors.append(exc)

        threads = [threading.Thread(target=deploy) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        self.assertFalse(any(t.is_alive() for t in threads), "a starter never returned")

        self.assertEqual(errors, [], f"a concurrent starter failed: {errors}")
        expected = migrations.expected_revision()
        self.assertEqual(results, [expected] * 6)

        with store._connect() as conn:
            history = [
                int(r["revision"]) for r in conn.execute(
                    "SELECT revision FROM schema_migrations ORDER BY revision"
                ).fetchall()
            ]
        self.assertEqual(history, sorted(set(history)), "a revision was recorded twice")

    def test_the_advisory_lock_is_released_after_an_upgrade(self) -> None:
        """A lock left held would block every later deployment on the cluster."""
        migrations.upgrade()
        with store._connect() as conn:
            held = conn.execute(
                "SELECT COUNT(*) AS n FROM pg_locks "
                "WHERE locktype = 'advisory' AND objid = ?",
                (migrations._ADVISORY_LOCK_KEY,),
            ).fetchone()
        self.assertEqual(int(held["n"]), 0, "the migration advisory lock is still held")


if __name__ == "__main__":
    unittest.main()
