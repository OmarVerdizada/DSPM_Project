"""ARCH-003 durable job state: records survive, orphans recover to failed."""

from __future__ import annotations

import unittest
from uuid import uuid4

from backend import store


def _job(tenant_id: str, job_id: str, status: str, **extra) -> dict:
    base = {
        "id": job_id,
        "tenant_id": tenant_id,
        "status": status,
        "progress": 42,
        "message": status.title(),
        "created_at": "2026-07-23T00:00:00Z",
    }
    base.update(extra)
    return base


class DurableJobTests(unittest.TestCase):
    def test_record_and_read_roundtrip(self) -> None:
        tid, jid = f"jt-{uuid4().hex[:8]}", f"j-{uuid4().hex[:8]}"
        store.create_tenant(tid, tid)
        store.record_job(_job(tid, jid, "running", progress=55))
        rec = store.read_job(tid, jid)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "running")
        self.assertEqual(rec["progress"], 55)
        self.assertIsNone(rec["result"])  # result payload is never persisted
        self.assertIn("elapsed_seconds", rec)

    def test_read_missing_is_none(self) -> None:
        self.assertIsNone(store.read_job("no-tenant", "no-job"))

    def test_read_is_tenant_scoped(self) -> None:
        tid, jid = f"jt-{uuid4().hex[:8]}", f"j-{uuid4().hex[:8]}"
        store.create_tenant(tid, tid)
        store.record_job(_job(tid, jid, "completed", finished_at="2026-07-23T00:01:00Z"))
        self.assertIsNone(store.read_job("other-tenant", jid))

    def test_recover_marks_orphan_running_as_failed(self) -> None:
        tid, jid = f"jt-{uuid4().hex[:8]}", f"j-{uuid4().hex[:8]}"
        store.create_tenant(tid, tid)
        store.record_job(_job(tid, jid, "running"))
        store.recover_interrupted_jobs()
        rec = store.read_job(tid, jid)
        self.assertEqual(rec["status"], "failed")
        self.assertIn("restart", (rec["error"] or "").lower())

    def test_recover_leaves_terminal_jobs_untouched(self) -> None:
        tid, jid = f"jt-{uuid4().hex[:8]}", f"j-{uuid4().hex[:8]}"
        store.create_tenant(tid, tid)
        store.record_job(_job(tid, jid, "completed", finished_at="2026-07-23T00:01:00Z"))
        store.recover_interrupted_jobs()
        self.assertEqual(store.read_job(tid, jid)["status"], "completed")


if __name__ == "__main__":
    unittest.main()
