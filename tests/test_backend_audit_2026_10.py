"""Backend audit, 2026-10: the defects the tool sweep and the review found, each pinned by
the behaviour that was wrong.
"""
from __future__ import annotations

import tempfile
import unittest
from contextlib import suppress
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from backend.compliance_service import allowed_framework_ids
from classification.compliance.canonical_model import apply_canonical_finding_model
from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class EveryAcceptedFrameworkCanBeScannedTest(unittest.TestCase):
    """The scan API accepts every profile in compliance_profiles.json. HIPAA, NIST CSF and
    ISO 27001 have no keyword catalog, and the engine asked the keyword library for one:
    the scan walked the whole estate and then failed at 95% with "Unsupported compliance
    framework"."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.estate = root / "estate"
        self.estate.mkdir()
        (self.estate / "patients.txt").write_text(
            "patient alice@example.com\nmedical record number MRN 448812\ncard 4111 1111 1111 1111\n", encoding="utf-8")
        self.cache = root / "cache"
        for patcher in (patch.object(file_scanner, "is_skipped_scan_path", return_value=False),
                        patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _scan(self, frameworks: list[str]) -> dict:
        config = ScanConfig(tenant_id="audit-frameworks", local_path=str(self.estate), walk_local_path=True,
                            persistent_cache_enabled=True, cache_dir=str(self.cache), max_workers=1,
                            compliance_enabled=True, compliance_frameworks=frameworks)
        return DSPMDiscoveryEngine(config).run().to_dict()

    def test_the_overlay_frameworks_scan_on_their_own(self) -> None:
        for framework in ("hipaa", "nist_csf", "iso27001"):
            with self.subTest(framework=framework):
                report = self._scan([framework])
                self.assertEqual(report["summary"]["total_files"], 1)

    def test_every_framework_the_api_accepts_scans_together(self) -> None:
        report = self._scan(sorted(allowed_framework_ids()))
        self.assertEqual(report["summary"]["total_files"], 1)
        found = {finding.get("type") for item in report["files"] for finding in item.get("findings") or []}
        self.assertTrue(found, "the detectors still ran beside the overlays")


    def test_a_first_sighting_starts_in_one_state_whatever_found_it(self) -> None:
        report = self._scan(["gdpr", "pci_dss", "nist_sp800_60_enterprise"])
        statuses = {(finding.get("framework"), finding.get("status"))
                    for item in report["files"] for finding in item.get("findings") or []}
        self.assertIn("pci_dss", {framework for framework, _ in statuses})
        self.assertEqual({status for _, status in statuses}, {"OPEN"}, statuses)


class AScanNeverDecidesTriageTest(unittest.TestCase):
    """A detector's review_status was read as the analyst lifecycle: PCI's "unreviewed"
    landed as NEW beside OPEN GDPR findings, and a NIST match scoring 85+ as CONFIRMED -
    a state that says a person validated it."""

    def test_a_detectors_review_state_is_not_the_lifecycle(self) -> None:
        for review in ("unreviewed", "CONFIRMED", "NEEDS_REVIEW"):
            with self.subTest(review_status=review):
                finding = apply_canonical_finding_model(
                    {"type": "pan", "risk": "HIGH", "review_status": review},
                    {"path": "C:/share/x.txt", "name": "x.txt", "source": "local"})
                self.assertEqual(finding["status"], "OPEN")
                self.assertEqual(finding["review_status"], review, "the detector's own reading is kept")


class DemoDataNeverReplacesWhatItDidNotWriteTest(unittest.TestCase):
    """POST /api/demo-data/generate (scan.run) took any project-local folder and the
    generator rmtree'd it: "." was the install, "data" the database and its backups."""

    def test_the_install_and_its_data_folder_are_refused(self) -> None:
        from fastapi import HTTPException

        from backend.app import _safe_demo_output

        for output in (".", "data", "data/backups", "./"):
            with self.subTest(output=output), self.assertRaises(HTTPException) as refused:
                _safe_demo_output(output)
            self.assertEqual(refused.exception.status_code, 400)

    def test_a_folder_of_other_files_is_refused(self) -> None:
        from fastapi import HTTPException

        from backend.app import _safe_demo_output

        for output in ("backend", "frontend", "docs"):
            with self.subTest(output=output), self.assertRaises(HTTPException) as refused:
                _safe_demo_output(output)
            self.assertEqual(refused.exception.status_code, 409)

    def test_a_new_folder_and_a_generated_one_are_allowed(self) -> None:
        from backend.app import _safe_demo_output

        self.assertTrue(str(_safe_demo_output("audit-demo-not-created")).endswith("audit-demo-not-created"))

    def test_the_generator_itself_will_not_replace_a_foreign_folder(self) -> None:
        from scripts.generate_enterprise_test_data import NotAGeneratedDataset, generate, is_generated_dataset

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "share"
            root.mkdir()
            keep = root / "quarterly.xlsx"
            keep.write_bytes(b"real data")
            with self.assertRaises(NotAGeneratedDataset):
                generate(root, 1)
            self.assertTrue(keep.exists(), "the generator deleted a folder it did not write")
            keep.unlink()
            self.assertTrue(is_generated_dataset(root), "an empty folder may be filled")
            (root / "_manifest.json").write_text("{}", encoding="utf-8")
            (root / "old.csv").write_text("x", encoding="utf-8")
            self.assertTrue(is_generated_dataset(root), "a dataset it wrote may be replaced")
            with suppress(OSError):
                (root / "_manifest.json").unlink()
            self.assertFalse(is_generated_dataset(root))


class AStreamedStoreGeneratorKeepsItsTenantTest(unittest.TestCase):
    """A store generator held its tenant scope across `yield`. Starlette resumes each step of
    a streamed response in a fresh copy of the request's context, so from the second batch
    on the export ran with no tenant - on PostgreSQL RLS returned nothing and the inventory
    export stopped at 1,000 rows - and the final reset raised ValueError."""

    def _drain_like_starlette(self, iterator) -> list:
        import asyncio

        from starlette.concurrency import iterate_in_threadpool

        async def drain():
            return [item async for item in iterate_in_threadpool(iterator)]

        return asyncio.run(drain())

    def test_every_step_runs_in_the_callers_tenant(self) -> None:
        from backend import db, store

        def steps(tenant_id: str):
            for _ in range(4):
                yield db.current_tenant_scope()

        scoped = store._tenant_scoped(steps)
        self.assertEqual(self._drain_like_starlette(scoped("tenant-a")), ["tenant-a"] * 4)
        self.assertIsNone(db.current_tenant_scope(), "the scope leaked out of the generator")

    def test_a_platform_generator_names_its_purpose_on_every_step(self) -> None:
        from backend import db, store

        purpose = sorted(db.PLATFORM_PURPOSES)[0]

        def steps():
            for _ in range(3):
                yield db.current_platform_scope()

        scoped = store._platform_scoped(purpose)(steps)
        self.assertEqual(self._drain_like_starlette(scoped()), [purpose] * 3)

    def test_the_inventory_export_streams_every_batch(self) -> None:
        from backend import db, store

        seen = []
        real_connect = store._connect

        def watching_connect(*args, **kwargs):
            seen.append(db.current_tenant_scope())
            return real_connect(*args, **kwargs)

        tenant = f"audit-export-{uuid4().hex[:8]}"
        store.create_tenant(tenant, "Export")
        files = [{"path": f"/share/file_{index:03d}.txt", "name": f"file_{index:03d}.txt", "extension": ".txt",
                  "size": 10, "modified_at": "2026-09-01T00:00:00+00:00", "risk": {"level": "LOW", "score": 5},
                  "findings": []} for index in range(25)]
        store.save_scan_history(tenant, {"scan_id": "export-1", "source": "local", "summary": {}, "files": files})
        with patch.object(store, "_connect", watching_connect):
            rows = self._drain_like_starlette(store.iter_inventory_export_rows(tenant, batch_size=10))
        self.assertEqual(len(rows), 25)
        self.assertGreaterEqual(len(seen), 4, "one query per batch")
        self.assertEqual(set(seen), {tenant}, f"scopes seen per query: {seen}")


def _file(path: str, finding_type: str, risk: str = "HIGH") -> dict:
    return {"path": path, "name": path.rsplit("/", 1)[-1], "extension": ".txt", "size": 10,
            "modified_at": "2026-09-01T00:00:00+00:00", "risk": {"level": risk, "score": 80},
            "findings": [{"finding_id": f"f-{path.rsplit('/', 1)[-1]}", "type": finding_type, "risk": risk,
                          "framework": "gdpr", "count": 1, "status": "OPEN"}]}


class AnOlderReportNeverOverwritesANewerFindingTest(unittest.TestCase):
    """Scan s1 saw a.txt and b.txt, scan s2 only a.txt. An analyst resolves a.txt's finding;
    then any action on b.txt's finding re-saves s1 - and s1's copy of a.txt's finding was
    written over the row s2 owns: resolved went back to OPEN with s1's last_seen."""

    def setUp(self) -> None:
        from backend import store

        self.store = store
        self.tenant = f"audit-older-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Older report")
        store.save_scan_history(self.tenant, {"scan_id": "s1", "source": "local", "summary": {},
                                              "timestamp": "2026-09-01T00:00:00+00:00",
                                              "files": [_file("/share/a.txt", "email"), _file("/share/b.txt", "phone")]})
        store.save_scan_history(self.tenant, {"scan_id": "s2", "source": "local", "summary": {},
                                              "timestamp": "2026-09-02T00:00:00+00:00",
                                              "files": [_file("/share/a.txt", "email")]})

    def _rows(self) -> dict:
        with self.store._connect() as conn:
            rows = conn.execute("SELECT id, file_path, status, scan_id, last_seen FROM findings WHERE tenant_id = ?",
                                (self.tenant,)).fetchall()
        return {row["file_path"]: dict(row) for row in rows}

    def test_an_action_on_an_older_scans_finding_keeps_the_newer_triage(self) -> None:
        before = self._rows()
        a, b = before["/share/a.txt"], before["/share/b.txt"]
        self.assertEqual((a["scan_id"], b["scan_id"]), ("s2", "s1"))
        self.store.update_finding_lifecycle(self.tenant, a["id"], "resolve", {"comment": "fixed"}, "analyst")
        self.assertEqual(self._rows()["/share/a.txt"]["status"], "RESOLVED")

        self.store.update_finding_lifecycle(self.tenant, b["id"], "comment", {"comment": "looked at it"}, "analyst")
        after = self._rows()
        self.assertEqual(after["/share/a.txt"]["status"], "RESOLVED", "an older report undid the triage")
        self.assertEqual(after["/share/a.txt"]["scan_id"], "s2")
        self.assertEqual(after["/share/a.txt"]["last_seen"], a["last_seen"])

    def test_the_owning_scan_still_writes_its_own_rows(self) -> None:
        b = self._rows()["/share/b.txt"]
        self.store.update_finding_lifecycle(self.tenant, b["id"], "assign", {"owner": "hr-team"}, "analyst")
        with self.store._connect() as conn:
            owner = conn.execute("SELECT owner FROM findings WHERE tenant_id = ? AND id = ?",
                                 (self.tenant, b["id"])).fetchone()["owner"]
        self.assertEqual(owner, "hr-team")


class ByteCountsAre64BitTest(unittest.TestCase):
    """assets.size, asset_versions.size, scan_reports.report_bytes and
    scan_partitions.records_bytes were 32-bit on PostgreSQL: one file of 2 GiB failed the
    authoritative asset insert and the whole scan was not saved."""

    def test_the_revision_widens_every_byte_count_on_postgresql(self) -> None:
        from backend import db, store

        statements = []
        conn = MagicMock()
        conn.execute.side_effect = lambda sql, *args: statements.append(sql)
        with patch.object(db, "is_postgres", return_value=True):
            store.widen_byte_counts(conn)
        for table, column in (("assets", "size"), ("asset_versions", "size"),
                              ("scan_reports", "report_bytes"), ("scan_partitions", "records_bytes")):
            self.assertIn(f"ALTER TABLE {table} ALTER COLUMN {column} TYPE BIGINT", statements)

    def test_sqlite_is_left_alone(self) -> None:
        from backend import db, store

        conn = MagicMock()
        with patch.object(db, "is_postgres", return_value=False):
            store.widen_byte_counts(conn)
        conn.execute.assert_not_called()

    def test_a_file_over_2_gib_is_stored_with_its_size(self) -> None:
        from backend import store

        tenant = f"audit-big-{uuid4().hex[:8]}"
        store.create_tenant(tenant, "Big")
        big = 5 * 1024 ** 3
        store.save_scan_history(tenant, {"scan_id": "big-1", "source": "local", "summary": {}, "files": [
            {"path": "/share/mailbox.pst", "name": "mailbox.pst", "extension": ".pst", "size": big,
             "modified_at": "2026-09-01T00:00:00+00:00", "risk": {"level": "LOW", "score": 5}, "findings": []}]})
        with store._connect() as conn:
            row = conn.execute("SELECT size FROM assets WHERE tenant_id = ?", (tenant,)).fetchone()
        self.assertEqual(int(row["size"]), big)


if __name__ == "__main__":
    unittest.main()
