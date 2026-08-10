"""Track P-A durable, tenant-scoped incremental scanning contracts."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from backend import store
from collectors import file_scanner
from collectors.winrm_endpoint_scanner import _scan_script
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.incremental import incremental_scope_key


class IncrementalScanningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.root = Path(self.temp.name)
        self.data = self.root / "estate"
        self.data.mkdir()
        for index in range(3):
            (self.data / f"file-{index}.txt").write_text(
                f"owner{index}@example.com password=secret-{index}\n",
                encoding="utf-8",
            )
        self.original_db = store.DB_PATH
        store.DB_PATH = self.root / "incremental.sqlite"
        store.init_db()
        self.tenant = f"pa-{uuid4().hex[:10]}"
        store.create_tenant(self.tenant, "P-A")
        self.scope = incremental_scope_key("local", str(self.data), {"max_depth": 4})
        self.skip_patch = patch.object(file_scanner, "is_skipped_scan_path", return_value=False)
        self.owner = MagicMock(return_value="tester")
        self.owner_patch = patch.object(file_scanner, "file_owner", self.owner)
        self.skip_patch.start()
        self.owner_patch.start()

    def tearDown(self) -> None:
        self.owner_patch.stop()
        self.skip_patch.stop()
        store.DB_PATH = self.original_db
        self.temp.cleanup()

    def _config(
        self,
        *,
        enabled: bool = True,
        overrides: list[dict] | None = None,
        inspect_archives: bool = False,
    ) -> ScanConfig:
        return ScanConfig(
            tenant_id=self.tenant,
            local_path=str(self.data),
            use_sample_when_empty=True,
            persistent_cache_enabled=False,
            max_workers=1,
            incremental_enabled=enabled,
            incremental_scope=self.scope,
            baseline_probe=(
                lambda key, size, mtime, version: store.probe_incremental_object(
                    self.tenant, self.scope, key, size, mtime, version
                )
            ) if enabled else None,
            asset_overrides=overrides or [],
            inspect_archives=inspect_archives,
        )

    def _run_and_save(self, **kwargs) -> dict:
        data = DSPMDiscoveryEngine(self._config(**kwargs)).run().to_dict()
        store.save_scan_history(self.tenant, data)
        return data

    def test_cold_cache_rescan_uses_durable_findings_without_content_io(self) -> None:
        first = self._run_and_save()
        first_accuracy = {
            item["path"]: (item.get("findings"), item.get("risk"), item.get("preview"))
            for item in first["files"]
        }
        self.owner.reset_mock()
        reader = MagicMock(side_effect=AssertionError("unchanged content was read"))
        with patch.object(file_scanner, "read_text_preview_and_sha256", reader):
            second = self._run_and_save()

        reader.assert_not_called()
        self.owner.assert_not_called()
        self.assertEqual(second["scan_diagnostics"]["incremental"]["durable_baseline_hits"], 3)
        self.assertEqual(second["scan_diagnostics"]["incremental"]["content_reads"], 0)
        self.assertEqual(second["scan_diagnostics"]["incremental"]["delta_ratio"], 0.0)
        self.assertTrue(second["scan_diagnostics"]["incremental"]["baseline_committed"])
        self.assertEqual(
            first_accuracy,
            {
                item["path"]: (item.get("findings"), item.get("risk"), item.get("preview"))
                for item in second["files"]
            },
        )

    def test_changed_and_deleted_objects_advance_generation(self) -> None:
        self._run_and_save()
        changed_path = self.data / "file-0.txt"
        changed_path.write_text("clean replacement with a different length\n", encoding="utf-8")
        (self.data / "file-2.txt").unlink()
        second = self._run_and_save()

        metrics = second["scan_diagnostics"]["incremental"]
        self.assertEqual(metrics["content_reads"], 1)
        self.assertEqual(metrics["unchanged_objects"], 1)
        self.assertEqual(metrics["changed_objects"], 1)
        self.assertEqual(metrics["deleted_objects"], 1)
        changed = next(item for item in second["files"] if item["path"] == str(changed_path.resolve()))
        self.assertFalse(changed.get("incremental_reused"))
        self.assertEqual(changed.get("findings"), [])
        with store._connect() as conn:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM scan_object_baselines WHERE tenant_id = ? AND scope_key = ?",
                (self.tenant, self.scope),
            ).fetchone()[0]
        self.assertEqual(remaining, 2)

    def test_partial_scan_never_prunes_a_good_generation(self) -> None:
        first = self._run_and_save()
        partial = {
            **first,
            "scan_id": "partial-scan",
            "files": first["files"][:1],
            "summary": {**first["summary"], "total_files": 1},
        }
        partial["scan_diagnostics"] = {
            **first["scan_diagnostics"],
            "incremental": {
                **first["scan_diagnostics"]["incremental"],
                "complete": False,
                "baseline_committed": False,
            },
        }
        store.save_scan_history(self.tenant, partial)
        self.assertTrue(partial["scan_diagnostics"]["incremental"]["prune_skipped"])
        with store._connect() as conn:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM scan_object_baselines WHERE tenant_id = ? AND scope_key = ?",
                (self.tenant, self.scope),
            ).fetchone()[0]
        self.assertEqual(remaining, 3)

    def test_policy_change_and_full_scan_force_content_reads(self) -> None:
        self._run_and_save()
        changed_policy = self._run_and_save(
            overrides=[{"pattern": "*.txt", "level": "HIGH", "reason": "policy change"}]
        )
        self.assertEqual(changed_policy["scan_diagnostics"]["incremental"]["changed_objects"], 3)
        self.assertEqual(changed_policy["scan_diagnostics"]["incremental"]["content_reads"], 3)

        reader = MagicMock(wraps=file_scanner.read_text_preview_and_sha256)
        with patch.object(file_scanner, "read_text_preview_and_sha256", reader):
            full = self._run_and_save(enabled=False)
        self.assertEqual(reader.call_count, 3)
        self.assertEqual(full["mode"], "full")
        self.assertFalse(full["scan_diagnostics"]["incremental"]["enabled"])

    def test_tenant_and_scope_are_isolated(self) -> None:
        first = self._run_and_save()
        record = first["files"][0]
        version = first["scan_diagnostics"]["incremental"]["version_signature"]
        key = record["reuse_key"]
        size = record["size"]
        mtime = record["modified_at"]
        self.assertEqual(
            store.probe_incremental_object("another-tenant", self.scope, key, size, mtime, version)["state"],
            "new",
        )
        self.assertEqual(
            store.probe_incremental_object(self.tenant, "another-scope", key, size, mtime, version)["state"],
            "new",
        )

    def test_historical_resave_cannot_roll_back_active_snapshot(self) -> None:
        historical = self._run_and_save()
        target = self.data / "file-0.txt"
        target.write_text("current clean generation with a new byte length\n", encoding="utf-8")
        current = self._run_and_save()
        current_record = next(item for item in current["files"] if item["path"] == str(target.resolve()))

        # Simulate a workflow update that re-saves the older report after a new
        # generation has already become active.
        store.save_scan_history(self.tenant, historical)
        result = store.probe_incremental_object(
            self.tenant,
            self.scope,
            current_record["reuse_key"],
            current_record["size"],
            current_record["modified_at"],
            current["scan_diagnostics"]["incremental"]["version_signature"],
        )
        self.assertEqual(result["state"], "unchanged")
        self.assertEqual(result["snapshot"]["baseline_result"].get("findings"), [])

    def test_unchanged_archive_restores_entries_without_opening_archive(self) -> None:
        archive_path = self.data / "evidence.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("inside.txt", "archive.user@example.com password=archive-secret")
        first = self._run_and_save(inspect_archives=True)
        self.assertTrue(any("::inside.txt" in item["path"] for item in first["files"]))

        outer_reader = MagicMock(side_effect=AssertionError("unchanged archive file was read"))
        entry_reader = MagicMock(side_effect=AssertionError("unchanged archive entry was read"))
        with (
            patch.object(file_scanner, "read_text_preview_and_sha256", outer_reader),
            patch.object(file_scanner, "read_zip_entry_preview_and_sha256", entry_reader),
        ):
            second = self._run_and_save(inspect_archives=True)
        outer_reader.assert_not_called()
        entry_reader.assert_not_called()
        self.assertEqual(second["scan_diagnostics"]["incremental"]["content_reads"], 0)
        self.assertTrue(any("::inside.txt" in item["path"] for item in second["files"]))

    def test_winrm_metadata_pass_disables_hash_and_owner_reads(self) -> None:
        script = _scan_script(
            [r"C:\\Users\\alice\\Documents"],
            max_depth=3,
            read_content=False,
            max_read_bytes=1024,
            allowed_extensions=[".txt"],
            extension_filter_enabled=True,
            include_hidden=True,
            include_system=False,
            hidden_filter_enabled=False,
            system_filter_enabled=False,
            read_acl=False,
            inspect_archives=False,
            hash_files=False,
            read_owner=False,
        )
        self.assertIn("$ownerAcl = if ($false -or $false)", script)
        self.assertIn("if ($false) {", script)


if __name__ == "__main__":
    unittest.main()
