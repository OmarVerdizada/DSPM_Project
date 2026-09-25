"""Regression tests for the Phase 0/1 audit fixes."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import unittest
from uuid import uuid4

from backend import jobs, store
from backend.domain import normalize_scan_report
from classification.regex_classifier import classify_content
from discovery.discovery_engine import _safe_preview


def _swift_hits(text: str) -> int:
    return sum(f["count"] for f in classify_content(text) if f["type"] == "swift_bic")


def _save_one_scan(tenant: str, scan_id: str) -> None:
    store.save_scan_history(tenant, {
        "scan_id": scan_id, "source": "local", "timestamp": "2026-07-23T00:00:00Z",
        "summary": {"total_files": 1},
        "files": [{"name": "f.txt", "path": "/f.txt", "size": 1, "findings": [
            {"finding_id": "fa", "type": "password", "risk": "HIGH"},
            {"finding_id": "fb", "type": "email", "risk": "LOW"}]}],
    })


class SanitizerLargeKeyTests(unittest.TestCase):
    def test_large_private_key_is_masked_in_preview(self) -> None:
        # FINDING 1: a 4096-ish RSA body (>2000 chars) must not leak past the
        # length-capped detection rule into the preview.
        body = "MIIE" + "Zz09" * 900  # ~3600 char base64-ish body
        key = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
        blob = "\n".join(_safe_preview(key)["lines"])
        self.assertNotIn(body[:40], blob)
        self.assertIn("[redacted:private_key]", blob)


class NormalizeStatusTests(unittest.TestCase):
    def test_lifecycle_status_is_carried_not_forced_open(self) -> None:
        # F1: a RESOLVED finding must not be normalized as OPEN.
        report = {
            "scan_id": "s1", "source": "local", "timestamp": "2026-07-23T00:00:00Z",
            "summary": {"total_files": 1},
            "files": [{"name": "f.txt", "path": "/f.txt", "size": 1, "findings": [
                {"type": "password", "risk": "HIGH", "status": "RESOLVED"},
                {"type": "email", "risk": "LOW", "review_status": "suppressed"},
            ]}],
        }
        scan = normalize_scan_report("t", report)
        by_rule = {f.rule: f.status for f in scan.findings}
        self.assertEqual(by_rule["password"], "RESOLVED")
        self.assertEqual(by_rule["email"], "SUPPRESSED")


class TenantErasureTests(unittest.TestCase):
    def test_delete_tenant_clears_normalized_and_job_tables(self) -> None:
        # F7: erasure must remove the normalized tables (finding_index holds the
        # full finding evidence) and durable job records.
        tenant = f"erase-{uuid4().hex[:8]}"
        store.create_tenant(tenant, "Erase")
        store.save_scan_history(tenant, {
            "scan_id": f"{tenant}-s1", "source": "local", "timestamp": "2026-07-23T00:00:00Z",
            "summary": {"total_files": 1},
            "files": [{"name": "f.txt", "path": "/f.txt", "size": 1, "findings": [
                {"finding_id": "f1", "type": "password", "risk": "HIGH"}]}],
        })
        store.record_job({"id": f"{tenant}-j", "tenant_id": tenant, "status": "completed",
                          "created_at": "2026-07-23T00:00:00Z"})

        store.delete_tenant_with_data(tenant)
        with store._connect() as conn:
            for table in ("scan_runs", "assets", "asset_versions", "findings", "finding_occurrences", "finding_index", "scan_jobs"):
                count = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE tenant_id = ?", (tenant,)).fetchone()[0]
                self.assertEqual(count, 0, f"{table} not erased")


class JobPruneTests(unittest.TestCase):
    def test_prune_removes_old_terminal_keeps_running(self) -> None:
        # F8: bound scan_jobs growth.
        tenant = f"prune-{uuid4().hex[:8]}"
        old_id, run_id = f"{tenant}-old", f"{tenant}-run"
        store.create_tenant(tenant, tenant)
        with store._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_jobs (id, tenant_id, status, progress, message, created_at, finished_at, error, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (old_id, tenant, "completed", 100, "Completed", "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z", None, "2020-01-01T00:00:00Z"),
            )
        store.record_job({"id": run_id, "tenant_id": tenant, "status": "running", "created_at": "2020-01-01T00:00:00Z"})

        store.prune_job_records(86400)  # 1 day
        self.assertIsNone(store.read_job(tenant, old_id))       # old terminal -> pruned
        self.assertIsNotNone(store.read_job(tenant, run_id))    # running -> kept


class SwiftBicPrecisionTests(unittest.TestCase):
    def test_real_bic_detected_prose_and_bad_country_rejected(self) -> None:
        # FINDING 3: context + uppercase-token + ISO-country validation.
        self.assertEqual(_swift_hits("Beneficiary SWIFT: DEUTDEFF for the wire"), 1)
        self.assertEqual(_swift_hits("BIC code DEUTDEFF500 on file"), 1)
        # lowercase prose after the word "swift" is no longer a capture
        self.assertEqual(_swift_hits("our swift customer service team"), 0)
        # structurally sound but positions 5-6 ('ZZ') are not a real country
        self.assertEqual(_swift_hits("SWIFT: ABCDZZ12"), 0)
        # bare token with no swift/bic anchor
        self.assertEqual(_swift_hits("CUSTOMER records attached"), 0)


class NormalizedReadinessTests(unittest.TestCase):
    def test_incomplete_or_stale_mirror_falls_back_to_blob(self) -> None:
        # F2: the read-switch must serve the blob unless the mirror is provably
        # complete (every scan mirrored) and current (index_version matches).
        tenant = f"f2-{uuid4().hex[:8]}"
        store.create_tenant(tenant, "F2")
        _save_one_scan(tenant, f"{tenant}-s1")

        def ids() -> list[str]:
            return sorted(f.get("finding_id") for f in store.list_findings(tenant))

        prev = os.environ.get("DSPM_READ_FROM_NORMALIZED")
        os.environ["DSPM_READ_FROM_NORMALIZED"] = "1"
        try:
            self.assertTrue(store._normalized_ready(tenant))
            self.assertEqual(ids(), ["fa", "fb"])

            # (a) completeness: drop the scan_run the dual-write would have written.
            # The readiness answer is cached per tenant and every in-process
            # transition invalidates it; editing the rows underneath is the one
            # route that cannot, so the reset is explicit here.
            with store._connect() as conn:
                conn.execute("DELETE FROM scan_runs WHERE tenant_id = ?", (tenant,))
            store.refresh_read_model_state(tenant)
            self.assertFalse(store._normalized_ready(tenant))
            self.assertEqual(ids(), ["fa", "fb"])  # blob fallback, nothing dropped

            store.backfill_normalized_scans(tenant)
            store.refresh_read_model_state(tenant)
            self.assertTrue(store._normalized_ready(tenant))

            # (b) currency: stamp an older logic version
            with store._connect() as conn:
                conn.execute("UPDATE finding_index SET index_version = 'OLD' WHERE tenant_id = ?", (tenant,))
            store.refresh_read_model_state(tenant)
            self.assertFalse(store._normalized_ready(tenant))
            self.assertEqual(ids(), ["fa", "fb"])  # blob fallback again
        finally:
            if prev is None:
                os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)
            else:
                os.environ["DSPM_READ_FROM_NORMALIZED"] = prev


class JobFinalizeRaceTests(unittest.TestCase):
    def test_first_terminal_writer_wins(self) -> None:
        # F5: heartbeat(deadline->failed) vs worker(->completed) must not clobber.
        done = jobs.ScanJob(id=f"j-{uuid4().hex[:6]}", tenant_id="t")
        self.assertTrue(jobs._finalize(done, "completed", message="Completed", progress=100, result={"ok": 1}))
        self.assertFalse(jobs._finalize(done, "failed", message="Failed", error="late deadline"))
        self.assertEqual(done.status, "completed")

        failed = jobs.ScanJob(id=f"j-{uuid4().hex[:6]}", tenant_id="t")
        self.assertTrue(jobs._finalize(failed, "failed", message="Failed", error="deadline"))
        self.assertFalse(jobs._finalize(failed, "completed", message="Completed", progress=100, result={}))
        self.assertEqual(failed.status, "failed")


class RecordJobRetryTests(unittest.TestCase):
    def test_transient_lock_is_retried(self) -> None:
        # F6: a lock that outlives SQLite's busy-timeout must not silently drop
        # the terminal write.
        tenant = f"lock-{uuid4().hex[:8]}"
        job_id = f"{tenant}-j"
        store.create_tenant(tenant, tenant)
        real_connect = store._connect
        calls = {"n": 0}

        @contextlib.contextmanager
        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                # A transient "database is locked" - caught by db.OperationalError
                # (which includes sqlite3.OperationalError) in store.record_job.
                raise sqlite3.OperationalError("database is locked")
            with real_connect() as conn:
                yield conn

        store._connect = flaky
        try:
            store.record_job({"id": job_id, "tenant_id": tenant, "status": "completed", "created_at": "2020-01-01T00:00:00Z"})
        finally:
            store._connect = real_connect
        self.assertGreaterEqual(calls["n"], 2)  # retried past the injected lock
        self.assertIsNotNone(store.read_job(tenant, job_id))


if __name__ == "__main__":
    unittest.main()
