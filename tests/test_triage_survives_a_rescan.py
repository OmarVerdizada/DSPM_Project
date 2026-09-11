"""A scheduled scan must not undo an analyst's work.

Every finding that reaches the estate write has been through
`apply_canonical_finding_model`, which stamps a status, an owner and a due date
onto it - "OPEN", the file's owner, and this scan's clock plus the severity's
allowance. Those are sensible values for a finding nobody has looked at yet, and
ruinous ones for a finding somebody has: written unconditionally they reset the
whole estate every night, and they push every due date forward far enough that
nothing can ever be overdue.

These tests drive the real lifecycle API rather than updating the row directly,
because the question is whether triage survives the round trip a product
actually makes: analyst acts -> report is re-saved -> tonight's scan runs.
"""

from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from backend import store
from classification.compliance.canonical_model import apply_canonical_finding_model


PATH = "//fs01/finance/payroll.xlsx"


def _scan_report(scan_id: str, *, timestamp: str, severity: str = "HIGH") -> dict:
    """A report the way the discovery engine hands one over - canonicalized.

    Skipping `apply_canonical_finding_model` here would skip the entire defect:
    a hand-built finding carries no status, so the carry-forward looks like it
    works.
    """

    finding = {
        "type": "credit_card",
        "risk": severity,
        "count": 3,
        "description": "PAN in a payroll export",
        "samples": ["4111111111111111"],
    }
    file_obj = {
        "path": PATH,
        "name": "payroll.xlsx",
        "extension": ".xlsx",
        "size": 40960,
        "source": "smb",
        "share": "finance",
        "owner": "CORP/fileserver-svc",
        "content_status": "scanned",
        "risk": {"level": severity, "score": 70, "reasons": ["PAN"],
                 "dlp_recommendations": ["Restrict share"]},
    }
    apply_canonical_finding_model(finding, file_obj, seen_at=timestamp)
    file_obj["findings"] = [finding]
    return {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "source": "smb",
        "scan_label": "nightly",
        "summary": {"total_files": 1, "critical": 0, "high": 1, "medium": 0,
                    "low": 0, "sensitive_files": 1},
        "files": [file_obj],
    }


class TriageSurvivesARescanTest(unittest.TestCase):

    def setUp(self):
        self._previous = os.environ.get("DSPM_DB_PATH")
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_DB_PATH"] = os.path.join(self._dir.name, "triage.sqlite")
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.init_db()
        self.day_one = "2026-09-01T02:00:00+00:00"
        store.save_scan_history(self.tenant, _scan_report("night-1", timestamp=self.day_one))
        self.finding_id = self._only_finding()["id"]

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("DSPM_DB_PATH", None)
        else:
            os.environ["DSPM_DB_PATH"] = self._previous
        self._dir.cleanup()

    def _only_finding(self):
        with store._connect() as conn:
            return conn.execute(
                "SELECT id, status, owner, sla_due, severity, is_current FROM findings "
                "WHERE tenant_id = ?", (self.tenant,),
            ).fetchone()

    def _indexed_status(self):
        """What the drawer sees, as opposed to what the list sees."""

        with store._connect() as conn:
            row = conn.execute(
                "SELECT status FROM finding_index WHERE tenant_id = ? AND finding_id = ? "
                "ORDER BY rowid DESC LIMIT 1", (self.tenant, self.finding_id),
            ).fetchone()
        return None if row is None else str(row["status"])

    def _rescan(self, scan_id="night-2", *, timestamp="2026-09-02T02:00:00+00:00", severity="HIGH"):
        store.save_scan_history(
            self.tenant, _scan_report(scan_id, timestamp=timestamp, severity=severity)
        )

    def test_a_confirmed_finding_is_still_confirmed_tomorrow(self):
        store.update_finding_lifecycle(
            self.tenant, self.finding_id, "status", {"status": "CONFIRMED"}, "analyst@example.com",
        )
        self.assertEqual(self._only_finding()["status"], "CONFIRMED")

        self._rescan()
        self.assertEqual(
            self._only_finding()["status"], "CONFIRMED",
            "the nightly scan reset a confirmed finding to its canonical default",
        )

    def test_an_assigned_finding_keeps_its_assignee(self):
        store.update_finding_lifecycle(
            self.tenant, self.finding_id, "assign",
            {"owner": "hasan@example.com"}, "lead@example.com",
        )
        self.assertEqual(self._only_finding()["owner"], "hasan@example.com")

        self._rescan()
        self.assertEqual(
            self._only_finding()["owner"], "hasan@example.com",
            "the nightly scan reassigned the finding to the file's owner",
        )

    def test_a_suppressed_finding_does_not_come_back(self):
        store.update_finding_lifecycle(
            self.tenant, self.finding_id, "suppress",
            {"reason": "Test data, not real cardholder data",
             "expiration_date": "2027-01-01"},
            "analyst@example.com",
        )
        self.assertEqual(self._only_finding()["status"], "SUPPRESSED")

        self._rescan()
        self.assertEqual(
            self._only_finding()["status"], "SUPPRESSED",
            "a suppressed finding reappeared as OPEN after the next scan",
        )

    def test_the_due_date_does_not_move_every_night(self):
        """An SLA computed from each scan's clock is an SLA that never expires."""

        first = self._only_finding()["sla_due"]
        self.assertTrue(first, "the first scan should have set a due date")

        for day, scan_id in enumerate(("night-2", "night-3", "night-4"), start=2):
            self._rescan(scan_id, timestamp=f"2026-09-{day:02d}T02:00:00+00:00")

        self.assertEqual(
            self._only_finding()["sla_due"], first,
            "each scan pushed the deadline forward, so the finding can never be overdue",
        )

    def test_the_due_date_still_becomes_overdue(self):
        """The point of holding the date: the deadline is allowed to pass."""

        due = datetime.fromisoformat(self._only_finding()["sla_due"])
        # A HIGH finding is given three days from the scan that found it.
        self.assertEqual(due, datetime.fromisoformat(self.day_one) + timedelta(days=3))

        self._rescan(timestamp="2026-09-30T02:00:00+00:00")
        self.assertLess(
            datetime.fromisoformat(self._only_finding()["sla_due"]),
            datetime(2026, 9, 30, tzinfo=timezone.utc),
            "a month later the deadline had moved with the scan instead of passing",
        )

    def test_a_worse_finding_gets_the_shorter_clock(self):
        """The one thing a scan may still say about a deadline."""

        before = self._only_finding()
        self._rescan(timestamp="2026-09-02T02:00:00+00:00", severity="CRITICAL")
        after = self._only_finding()

        self.assertEqual(after["severity"], "CRITICAL")
        self.assertNotEqual(
            after["sla_due"], before["sla_due"],
            "a finding that escalated kept the deadline its old severity earned",
        )
        self.assertEqual(
            datetime.fromisoformat(after["sla_due"]),
            datetime.fromisoformat("2026-09-02T02:00:00+00:00") + timedelta(days=1),
        )

    def test_an_analysts_own_due_date_survives(self):
        store.update_finding_lifecycle(
            self.tenant, self.finding_id, "status",
            {"status": "IN_PROGRESS", "due_date": "2026-12-24T00:00:00+00:00",
             "sla_due": "2026-12-24T00:00:00+00:00"},
            "analyst@example.com",
        )
        self.assertEqual(self._only_finding()["sla_due"], "2026-12-24T00:00:00+00:00")

        self._rescan()
        self.assertEqual(
            self._only_finding()["sla_due"], "2026-12-24T00:00:00+00:00",
            "the scan overwrote a deadline a person had chosen",
        )

    def test_the_list_and_the_drawer_agree_after_a_rescan(self):
        """`findings` feeds the list; `finding_index` feeds the drawer.

        The resolved lifecycle is written back onto the finding dict before the
        index is built precisely so these two cannot disagree - a finding that
        reads CONFIRMED in the table and OPEN when opened is worse than either.
        """

        store.update_finding_lifecycle(
            self.tenant, self.finding_id, "status", {"status": "CONFIRMED"}, "analyst@example.com",
        )
        self._rescan()
        self.assertEqual(self._only_finding()["status"], "CONFIRMED")
        self.assertEqual(self._indexed_status(), "CONFIRMED")

    def test_a_reopened_finding_is_reopened(self):
        """Preserving state must not mean freezing it."""

        store.update_finding_lifecycle(
            self.tenant, self.finding_id, "status", {"status": "RESOLVED"}, "analyst@example.com",
        )
        self.assertEqual(self._only_finding()["status"], "RESOLVED")

        store.update_finding_lifecycle(
            self.tenant, self.finding_id, "reopen", {"comment": "seen again"}, "analyst@example.com",
        )
        reopened = self._only_finding()["status"]
        self.assertNotEqual(reopened, "RESOLVED", "reopening did not change the state")

        self._rescan()
        self.assertEqual(
            self._only_finding()["status"], reopened,
            "the scan undid the reopen",
        )

    def test_a_brand_new_finding_still_gets_its_defaults(self):
        """Nothing here should stop a first sighting from being filled in."""

        row = self._only_finding()
        self.assertEqual(row["status"], "OPEN")
        self.assertEqual(row["owner"], "CORP/fileserver-svc")
        self.assertTrue(row["sla_due"])


if __name__ == "__main__":
    unittest.main()
