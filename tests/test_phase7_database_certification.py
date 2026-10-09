"""Phase 7 scale, corruption, monitoring and evidence-package controls."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from backend import db_certification, observability
from scripts import db_corruption_drill, inventory_benchmark


NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)


def _profile() -> dict:
    return {
        "profile_version": 1,
        "name": "test regulated profile",
        "projection": {
            "documents": 5_000_000,
            "concurrent_workers": 4,
            "soak_seconds": 60,
            "query_p95_ms": 300,
            "lock_timeout_ms": 500,
        },
        "database": {
            "approved_major": 18,
            "minimum_version": "18.4",
            "patch_baseline_reviewed_at": "2026-09-01T00:00:00Z",
            "patch_review_max_age_days": 90,
        },
        "regional_recovery": {"required": False, "reason": "not contracted"},
        "activity_monitoring": {"required": False, "reason": "not contracted"},
        "evidence_max_age_days": {
            category: 90 for category in db_certification.required_evidence_categories()
        },
    }


class ProfileContract(unittest.TestCase):
    def test_checked_in_profile_is_valid_and_drives_five_million_rows(self) -> None:
        profile = db_certification.load_profile(
            Path("docs/database/P7_CERTIFICATION_PROFILE.json")
        )
        self.assertEqual(profile["projection"]["documents"], 5_000_000)
        self.assertGreaterEqual(profile["projection"]["concurrent_workers"], 2)

    def test_not_applicable_control_requires_an_explicit_reason(self) -> None:
        profile = _profile()
        profile["regional_recovery"] = {"required": False, "reason": ""}
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "reason"):
                db_certification.load_profile(path)


class ControlSnapshot(unittest.TestCase):
    def test_optional_contract_controls_are_explicitly_not_applicable(self) -> None:
        with (
            mock.patch("backend.db.is_postgres", return_value=True),
            mock.patch("backend.db.database_identity", return_value={"identity": "safe-id"}),
            mock.patch("backend.migrations.expected_revision", return_value=8),
            mock.patch.object(
                observability,
                "schema_metrics",
                return_value={"applied": 8, "expected": 8, "checksum_drift": [1]},
            ),
            mock.patch.object(
                observability,
                "replication_metrics",
                return_value={"applicable": True, "configured": False, "standbys": []},
            ),
            mock.patch.object(
                observability,
                "database_activity_monitoring",
                return_value={"applicable": True, "enabled": False},
            ),
            mock.patch.object(db_certification, "migration_history", return_value=[]),
            mock.patch.object(db_certification, "server_version", return_value="18.4"),
        ):
            result = db_certification.collect_control_snapshot(_profile(), now=NOW)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["regional_recovery"]["result"], "NOT_APPLICABLE")
        self.assertEqual(result["activity_monitoring"]["result"], "NOT_APPLICABLE")
        self.assertNotIn("dsn", json.dumps(result).lower())

    def test_required_regional_topology_fails_without_synchronous_standby(self) -> None:
        profile = _profile()
        profile["regional_recovery"] = {
            "required": True,
            "minimum_synchronous_standbys": 1,
        }
        with (
            mock.patch("backend.db.is_postgres", return_value=True),
            mock.patch("backend.db.database_identity", return_value={"identity": "safe-id"}),
            mock.patch("backend.migrations.expected_revision", return_value=8),
            mock.patch.object(observability, "schema_metrics", return_value={"applied": 8}),
            mock.patch.object(
                observability,
                "replication_metrics",
                return_value={"applicable": True, "configured": False, "standbys": []},
            ),
            mock.patch.object(observability, "database_activity_monitoring", return_value={}),
            mock.patch.object(db_certification, "migration_history", return_value=[]),
            mock.patch.object(db_certification, "server_version", return_value="18.4"),
        ):
            result = db_certification.collect_control_snapshot(profile, now=NOW)
        self.assertEqual(result["regional_recovery"]["result"], "FAIL")
        self.assertEqual(result["result"], "FAIL")


class CorruptionGameDay(unittest.TestCase):
    def test_both_corruption_modes_are_detected_and_recoverable(self) -> None:
        result = db_corruption_drill.run_drill()
        self.assertEqual(result["result"], "PASS")
        self.assertIn("no live data modified", result["scope"])
        for scenario in result["scenarios"].values():
            self.assertTrue(scenario["corruption_detected"])
            self.assertTrue(scenario["original_recovery_ok"])


class EvidencePackage(unittest.TestCase):
    def _write(self, directory: Path, name: str, payload: dict) -> Path:
        path = directory / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_package_is_complete_hash_manifested_and_excludes_backup_payload(self) -> None:
        stamp = "20260902T120000Z"
        generated = NOW.isoformat()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            evidence = root / "evidence"
            backups = root / "backups"
            evidence.mkdir()
            backups.mkdir()

            encrypted = backups / "sentro.dump.enc"
            encrypted.write_bytes(b"encrypted database")
            self._write(backups, f"sentro_{stamp}.manifest.json", {
                "created_at": generated,
                "file": encrypted.name,
                "ciphertext_sha256": hashlib.sha256(encrypted.read_bytes()).hexdigest(),
                "artifacts": {"objects": 0, "file": None},
            })
            self._write(evidence, f"restore_drill_{stamp}.json", {"drill_at": generated, "result": "PASS"})
            self._write(evidence, f"db_roles_{stamp}.json", {"applied_at": generated, "result": "PASS"})
            self._write(evidence, f"retention_{stamp}.json", {"generated_at": generated, "result": "PASS"})
            self._write(evidence, f"capacity_soak_{stamp}.json", {"generated_at": generated, "result": "PASS"})
            self._write(evidence, f"corruption_game_day_{stamp}.json", {"generated_at": generated, "result": "PASS"})
            self._write(evidence, f"db_controls_{stamp}.json", {
                "generated_at": generated,
                "result": "PASS",
                "schema_changes": {"result": "PASS"},
                "patch_compliance": {"result": "PASS"},
                "regional_recovery": {"result": "NOT_APPLICABLE"},
                "activity_monitoring": {"result": "NOT_APPLICABLE"},
            })
            output = root / "package.zip"
            manifest = db_certification.build_evidence_package(
                _profile(), evidence, backups, output, now=NOW
            )
            self.assertEqual(manifest["result"], "PASS", manifest["failures"])
            self.assertEqual(
                {item["category"] for item in manifest["categories"]},
                set(db_certification.required_evidence_categories()),
            )
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                self.assertIn("manifest.json", names)
                self.assertIn("profile.json", names)
                self.assertNotIn(f"evidence/{encrypted.name}", names)

    def test_missing_control_fails_closed_but_still_creates_auditable_package(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            evidence = root / "evidence"
            backups = root / "backups"
            evidence.mkdir()
            backups.mkdir()
            output = root / "failed.zip"
            manifest = db_certification.build_evidence_package(
                _profile(), evidence, backups, output, now=NOW
            )
            self.assertEqual(manifest["result"], "FAIL")
            self.assertTrue(output.is_file())
            self.assertTrue(any("evidence missing" in item for item in manifest["failures"]))


class MonitoringAndHarnessContracts(unittest.TestCase):
    def test_activity_monitoring_is_explicitly_disabled_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_DB_ACTIVITY_MONITORING", None)
            result = observability.database_activity_monitoring()
        self.assertFalse(result["enabled"])

    def test_scale_harness_keeps_destructive_guards_and_adds_soak_and_lock(self) -> None:
        source = Path(inventory_benchmark.__file__).read_text(encoding="utf-8")
        self.assertIn("DSPM_INVENTORY_BENCHMARK_ALLOW_WRITE", source)
        self.assertIn("name must contain test or bench", source)
        self.assertIn("_concurrent_soak", source)
        self.assertIn("_lock_contention_probe", source)
        self.assertIn("DROP TABLE IF EXISTS", source)


if __name__ == "__main__":
    unittest.main()
