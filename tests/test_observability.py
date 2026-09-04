"""Operational metrics (roadmap Phase 6, DB-09/DB-12).

`/api/health` says the process is up; `/api/ready` says it can serve. These
pin the third surface: the signals that say whether the installation is
heading for trouble, and the rules that turn them into a short list an
operator should act on.

The properties that matter here are as much about *not* misleading as about
reporting: an absent standby must not read as zero lag, a lazily-opened pool
must not read as saturated, and one unavailable signal must not take the whole
endpoint down.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

from backend import db, observability


class MetricCollection(unittest.TestCase):
    def test_collect_returns_every_family_and_never_raises(self) -> None:
        metrics = observability.collect()
        for family in ("pool", "storage", "backup", "wal_archive",
                       "replication", "activity", "database_activity_monitoring",
                       "schema_revision"):
            self.assertIn(family, metrics)
        self.assertIn("warnings", metrics)
        self.assertIsInstance(metrics["unavailable"], list)
        self.assertLess(metrics["collection_seconds"], 30)

    def test_one_broken_collector_does_not_break_the_endpoint(self) -> None:
        """A metrics surface that dies because one optional signal is
        unavailable is worse than one that reports the rest and says so."""
        with mock.patch.object(
            observability, "storage_metrics", side_effect=RuntimeError("disk gone")
        ):
            metrics = observability.collect()
        self.assertNotIn("storage", metrics)
        self.assertTrue(any(item.startswith("storage:") for item in metrics["unavailable"]))
        self.assertIn("schema_revision", metrics, "other families still collected")

    def test_storage_reports_database_artifacts_and_headroom(self) -> None:
        storage = observability.storage_metrics()
        self.assertGreaterEqual(storage["database_bytes"], 0)
        self.assertGreaterEqual(storage["artifact_objects"], 0)
        self.assertGreater(storage["disk_total_bytes"], 0)
        self.assertGreaterEqual(storage["disk_free_ratio"], 0.0)
        self.assertLessEqual(storage["disk_free_ratio"], 1.0)

    def test_schema_revision_matches_the_build(self) -> None:
        from backend import migrations

        revision = observability.schema_metrics()
        self.assertEqual(revision["expected"], migrations.expected_revision())


class WarningRules(unittest.TestCase):
    """The warnings list is the actionable part, so its rules are pinned."""

    def test_stale_backup_and_low_disk_are_flagged(self) -> None:
        warnings = observability._warnings({
            "backup": {"age_seconds": 60 * 60 * 100, "max_age_hours": 26},
            "storage": {"disk_free_ratio": 0.03},
            "schema_revision": {"applied": 5, "expected": 5},
        })
        self.assertTrue(any("backup is" in w for w in warnings))
        self.assertTrue(any("disk free" in w for w in warnings))

    def test_missing_backup_is_flagged_not_silently_healthy(self) -> None:
        warnings = observability._warnings({
            "backup": {"age_seconds": None, "max_age_hours": 26},
            "schema_revision": {"applied": 5, "expected": 5},
        })
        self.assertIn("no backup manifest found", warnings)

    def test_a_failed_collector_does_not_become_a_false_claim(self) -> None:
        """No `backup` family means its collector failed - which `unavailable`
        reports - not that the installation has no backups."""
        warnings = observability._warnings({"schema_revision": {"applied": 5, "expected": 5}})
        self.assertNotIn("no backup manifest found", warnings)

    def test_absent_standby_is_reported_rather_than_looking_healthy(self) -> None:
        warnings = observability._warnings({
            "replication": {"applicable": True, "configured": False},
            "schema_revision": {"applied": 5, "expected": 5},
        })
        self.assertTrue(any("standby" in w for w in warnings))

    def test_archiving_off_and_archive_failures_are_flagged(self) -> None:
        warnings = observability._warnings({
            "wal_archive": {"applicable": True, "archive_mode": "off", "failed_count": 3},
            "schema_revision": {"applied": 5, "expected": 5},
        })
        self.assertTrue(any("point-in-time recovery" in w for w in warnings))
        self.assertTrue(any("failure" in w for w in warnings))

    def test_pool_saturation_measures_capacity_not_current_size(self) -> None:
        """A lazily-opened pool holding its only connection is not saturated;
        measuring against current size instead of capacity cried wolf."""
        quiet = observability._warnings({
            "pool": {"pooled": True, "utilization": 0.1, "waiting": 0},
            "schema_revision": {"applied": 5, "expected": 5},
        })
        self.assertEqual(quiet, [])
        loud = observability._warnings({
            "pool": {"pooled": True, "utilization": 0.95, "waiting": 4},
            "schema_revision": {"applied": 5, "expected": 5},
        })
        self.assertTrue(any("utilized" in w for w in loud))
        self.assertTrue(any("waiting" in w for w in loud))

    def test_schema_drift_is_flagged(self) -> None:
        warnings = observability._warnings({"schema_revision": {"applied": 4, "expected": 5}})
        self.assertTrue(any("schema revision" in w for w in warnings))

    def test_a_healthy_installation_warns_about_nothing(self) -> None:
        self.assertEqual(observability._warnings({
            "backup": {"age_seconds": 120, "max_age_hours": 26},
            "storage": {"disk_free_ratio": 0.5},
            "pool": {"pooled": True, "utilization": 0.2, "waiting": 0},
            "wal_archive": {"applicable": True, "archive_mode": "on", "failed_count": 0},
            "activity": {"long_running_transactions": 0, "waiting_locks": 0},
            "replication": {"applicable": True, "configured": True},
            "schema_revision": {"applied": 5, "expected": 5},
        }), [])


class SlowQueries(unittest.TestCase):
    @unittest.skipIf(db.is_postgres(), "checks the SQLite refusal path")
    def test_unavailable_on_sqlite(self) -> None:
        result = observability.slow_queries()
        self.assertFalse(result["available"])
        self.assertIn("PostgreSQL", result["reason"])


class MetricsRoutes(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient
        from backend.app import app
        from backend.security import create_token

        self.client = TestClient(app)
        self.admin = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}

    def test_metrics_require_admin(self) -> None:
        for path in (
            "/api/admin/db-metrics",
            "/api/admin/db-slow-queries",
            "/api/admin/db-activity",
        ):
            anonymous = self.client.get(path)
            self.assertIn(anonymous.status_code, (401, 403), path)

    def test_admin_sees_metrics(self) -> None:
        response = self.client.get("/api/admin/db-metrics", headers=self.admin)
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertIn("warnings", payload)
        self.assertIn("storage", payload)

    def test_slow_queries_route_answers_on_both_backends(self) -> None:
        response = self.client.get("/api/admin/db-slow-queries?limit=5", headers=self.admin)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("available", response.json())

    def test_activity_route_is_aggregate_and_admin_only(self) -> None:
        response = self.client.get("/api/admin/db-activity", headers=self.admin)
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertIn("enabled", payload)
        rendered = json.dumps(payload).lower()
        for sensitive_field in ("query", "client_addr", "tenant_id", "role_name"):
            self.assertNotIn(sensitive_field, rendered)


if __name__ == "__main__":
    unittest.main()
