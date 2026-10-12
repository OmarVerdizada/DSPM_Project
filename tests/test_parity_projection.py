"""The shared Track-P semantic-parity projection (discovery/parity.py). Every
performance benchmark + the perf gate compares scans through this one function,
so its contract is locked here: volatile per-run fields are dropped (recursively),
the real result fields are kept, and two reports that differ only in volatile
fields are equal."""

from __future__ import annotations

import unittest

from discovery import parity


class ParityProjectionTests(unittest.TestCase):
    def test_sla_due_is_dropped_but_findings_kept(self) -> None:
        report = {"files": [{
            "path": "/a.txt",
            "findings": [{"type": "email", "sla_due": "2026-01-02", "first_seen": "2026-01-01"}],
            "risk": {"level": "MEDIUM"},
        }]}
        proj = parity.accuracy_projection(report)
        finding = proj["/a.txt"]["findings"][0]
        self.assertEqual(finding, {"type": "email"})  # sla_due + first_seen removed, type kept
        self.assertEqual(proj["/a.txt"]["risk"], {"level": "MEDIUM"})

    def test_two_reports_differing_only_in_volatile_fields_are_equal(self) -> None:
        base = lambda due: {"files": [{
            "path": "/a.txt",
            "findings": [{"type": "ssn", "sla_due": due, "count": 3}],
            "risk": {"level": "HIGH", "last_scanned_at": due},
        }]}
        self.assertTrue(parity.reports_equal(base("2026-01-02"), base("2027-09-09")))

    def test_a_real_finding_change_is_not_equal(self) -> None:
        a = {"files": [{"path": "/a.txt", "findings": [{"type": "email", "count": 1}]}]}
        b = {"files": [{"path": "/a.txt", "findings": [{"type": "email", "count": 2}]}]}
        self.assertFalse(parity.reports_equal(a, b))  # count is a semantic result, not volatile

    def test_sla_due_is_in_the_volatile_set(self) -> None:
        # Guards the drift bug that motivated this module: an incomplete set that
        # omits sla_due causes false parity failures.
        self.assertIn("sla_due", parity.VOLATILE_KEYS)
        self.assertIn("first_seen", parity.VOLATILE_KEYS)


if __name__ == "__main__":
    unittest.main()
