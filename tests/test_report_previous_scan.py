"""A report's "Previous" column is the scan saved immediately before the one reported on.

The comparison looked for the reported scan among the workspace's five newest. A report
on an older scan did not find it there and took the newest scan instead - a LATER scan,
printed as "Previous" - and the oldest scan, which has no previous one, was compared
against the newest too.
"""
from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from backend import db, store
from backend.reporting import artifacts
from backend.security import Principal

SCANS = 7


def _scan(number: int, *, critical: int | None = None) -> dict:
    """Scan `number`, whose summary says which scan it is: critical = 100 + number."""
    return {
        "scan_id": f"scan-{number:02d}",
        "timestamp": f"2026-09-{number:02d}T09:00:00+00:00",
        "source": "local",
        "summary": {"total_files": 1, "critical": 100 + number if critical is None else critical},
        "files": [{
            "name": f"file-{number}.csv", "path": rf"C:\Share\file-{number}.csv", "source": "local",
            "risk": {"level": "HIGH", "score": 70, "reasons": ["Personal data"],
                     "remediation": {"actions": ["Review access"]}},
            "findings": [{"type": "pii_name", "count": 1}],
        }],
    }


class _History(unittest.TestCase):
    """Scans 1..7 of one workspace, saved in order; another workspace saves a scan between
    the first two."""

    retention = "1000"

    def setUp(self) -> None:
        environment = mock.patch.dict(os.environ, {"DSPM_SCAN_RETENTION_PER_LABEL": self.retention})
        environment.start()
        self.addCleanup(environment.stop)
        tag = uuid4().hex[:8]
        self.tenant, self.other = f"rep-prev-{tag}", f"rep-prev-other-{tag}"
        store.create_tenant(self.tenant, "Previous scan")
        store.create_tenant(self.other, "Another workspace")
        store.save_scan_history(self.tenant, _scan(1))
        store.save_scan_history(self.other, _scan(50, critical=999))
        for number in range(2, SCANS + 1):
            store.save_scan_history(self.tenant, _scan(number))

    def _previous(self, number: int) -> int | None:
        """Which scan the comparison of scan `number` reads as its previous one."""
        summary = artifacts._previous_scan_summary(self.tenant, f"scan-{number:02d}")
        return None if summary is None else int(summary["critical"]) - 100


class ThePreviousScanTest(_History):

    def test_a_report_on_an_older_scan_compares_against_the_scan_before_it(self) -> None:
        for number in range(2, SCANS + 1):
            with self.subTest(scan=number):
                self.assertEqual(self._previous(number), number - 1)

    def test_the_oldest_scan_has_none(self) -> None:
        self.assertIsNone(self._previous(1))

    def test_another_workspaces_scan_is_never_the_previous(self) -> None:
        self.assertEqual(self._previous(2), 1, "the other workspace saved its scan between scans 1 and 2")

    def test_it_is_the_entry_before_it_in_the_workspace_history(self) -> None:
        # Scan 5 saved at the same instant as scan 3: the history orders the two by scan
        # id, and so does the comparison - 1, 2, 3, 5, 4, 6, 7.
        with db.tenant_scope(self.tenant), store._connect() as conn:
            stamp = conn.execute("SELECT created_at FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
                                 (self.tenant, "scan-03")).fetchone()["created_at"]
            conn.execute("UPDATE scan_reports SET created_at = ? WHERE tenant_id = ? AND scan_id = ?",
                         (stamp, self.tenant, "scan-05"))
        history = store.read_scan_history(self.tenant)
        self.assertEqual([entry["scan_id"][-1] for entry in history], list("1235467"))
        for index, entry in enumerate(history):
            with self.subTest(scan=entry["scan_id"]):
                expected = history[index - 1]["summary"] if index else None
                self.assertEqual(artifacts._previous_scan_summary(self.tenant, entry["scan_id"]), expected)

    def test_a_scan_the_workspace_does_not_have_has_none(self) -> None:
        self.assertIsNone(artifacts._previous_scan_summary(self.tenant, "scan-50"))
        self.assertIsNone(artifacts._previous_scan_summary(self.tenant, "no-such-scan"))


class _Printed(_History):

    def _printed_previous(self, number: int) -> int:
        """The "Previous" critical count the filed report on scan `number` prints."""
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(artifacts, "ARTIFACT_ROOT", Path(temp.name) / "artifacts"):
            principal = Principal("analyst", "analyst", self.tenant)
            artifact = artifacts.create_report_artifact(principal, {}, scan_id=f"scan-{number:02d}")
            located = artifacts.artifact_file(principal, artifact["artifact_id"], "html")
            assert located is not None
            page = located[0].read_text(encoding="utf-8")
        match = re.search(r"<tr><td>Critical</td><td>\d+</td><td>(\d+)</td>", page)
        assert match is not None, "the report has a scan comparison"
        return int(match.group(1)) - 100


class TheReportPrintsTheScanBeforeItTest(_Printed):

    def test_a_report_on_an_older_scan(self) -> None:
        self.assertEqual(self._printed_previous(2), 1)


class APreviousScanPastRetentionTest(_Printed):
    """W3.5 keeps the three newest scans of a name whole; an older one keeps only its
    summary - which is all the comparison reads."""

    retention = "3"

    def test_still_serves_as_the_previous_scan(self) -> None:
        with db.tenant_scope(self.tenant), store._connect() as conn:
            states = {row["scan_id"]: row["retention_state"] or "" for row in conn.execute(
                "SELECT scan_id, retention_state FROM scan_reports WHERE tenant_id = ?", (self.tenant,)).fetchall()}
        self.assertEqual(states["scan-04"], "summary")
        self.assertEqual(states["scan-05"], "")
        self.assertEqual(self._previous(5), 4)
        self.assertEqual(self._printed_previous(5), 4)


if __name__ == "__main__":
    unittest.main()
