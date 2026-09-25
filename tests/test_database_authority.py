"""Phase 0 of the enterprise database roadmap (DB-01): one authority.

Production must refuse SQLite, a configured expected identity must refuse a
mis-pointed DSN, and operators must be able to see which database an instance
serves. Two supported launch paths silently serving different estates was the
assessment's top critical finding.
"""

from __future__ import annotations

import unittest
from unittest import mock

from backend import db


# These three are about the SQLite path, so they take it even when the suite runs on
# PostgreSQL: the backend is chosen by DSPM_DB_URL at each call.
_ON_SQLITE = {"DSPM_DB_URL": ""}


class DatabaseAuthorityTests(unittest.TestCase):
    def test_sqlite_identity_names_the_file(self) -> None:
        with mock.patch.dict("os.environ", _ON_SQLITE):
            identity = db.database_identity()
        self.assertEqual(identity["backend"], "sqlite")
        self.assertTrue(identity["identity"].lower().endswith(".sqlite"))

    def test_production_refuses_sqlite(self) -> None:
        with mock.patch.dict("os.environ", _ON_SQLITE):
            with self.assertRaisesRegex(RuntimeError, "production requires PostgreSQL"):
                db.enforce_database_authority(True)

    def test_development_allows_sqlite(self) -> None:
        with mock.patch.dict("os.environ", _ON_SQLITE):
            identity = db.enforce_database_authority(False)
        self.assertEqual(identity["backend"], "sqlite")

    def test_expected_identity_mismatch_refuses_in_any_environment(self) -> None:
        with mock.patch.dict("os.environ", {"DSPM_DB_EXPECTED_IDENTITY": "1234/other_db"}):
            with self.assertRaisesRegex(RuntimeError, "does not match DSPM_DB_EXPECTED_IDENTITY"):
                db.enforce_database_authority(False)

    def test_expected_identity_match_passes(self) -> None:
        actual = db.database_identity()["identity"]
        with mock.patch.dict("os.environ", {"DSPM_DB_EXPECTED_IDENTITY": actual}):
            identity = db.enforce_database_authority(False)
        self.assertEqual(identity["identity"], actual)

    def test_health_payload_carries_the_database_identity(self) -> None:
        from fastapi.testclient import TestClient
        from backend.app import app

        payload = TestClient(app).get("/api/health").json()
        self.assertIn("database", payload)
        self.assertIn(payload["database"]["backend"], ("sqlite", "postgres"))
        self.assertTrue(payload["database"]["identity"])

    def test_readiness_probes_the_database_and_schema_revision(self) -> None:
        """/api/ready (Phase 6, DB-09) is the truthful gate: a bounded DB
        read+write probe plus a schema-revision match, 503 when unservable."""
        from fastapi.testclient import TestClient
        from backend.app import app
        from backend import migrations

        response = TestClient(app).get("/api/ready")
        payload = response.json()
        self.assertEqual(response.status_code, 200, payload)
        self.assertTrue(payload["ready"])
        self.assertEqual(payload["failures"], [])
        revision = payload["database"]["schema_revision"]
        self.assertEqual(revision["applied"], revision["expected"])
        self.assertEqual(revision["expected"], migrations.expected_revision())
        self.assertLess(payload["database"]["probe_seconds"], 5)

    def test_readiness_refuses_on_schema_mismatch(self) -> None:
        from fastapi.testclient import TestClient
        from backend.app import app

        with mock.patch("backend.migrations.expected_revision", return_value=99):
            response = TestClient(app).get("/api/ready")
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json()["ready"])
        self.assertTrue(any("schema revision" in item for item in response.json()["failures"]))


if __name__ == "__main__":
    unittest.main()
