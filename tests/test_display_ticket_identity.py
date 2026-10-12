"""M0/Q5: the ticket printed beside a file's remediation identifies that file.

It is the only identifier an operator can read out loud - it goes into their own
tracker, an email, a screenshot - so two files sharing one is worse than having no
ticket at all. The old derivation folded a SHA-1 into 100,000 numbers, which by the
birthday bound hands two files the same ticket at even odds in an estate of ~370.
Every customer estate is larger than that.

What must hold: the same path always gets the same ticket (across scans, processes
and installs), and different paths get different tickets at estate scale.
"""

from __future__ import annotations

import hashlib
import re
import unittest

from risk.risk_engine import calculate_risk, display_ticket

TICKET = re.compile(r"^DSPM-[0-9A-F]{12}$")


class ATicketIsStableTest(unittest.TestCase):

    def test_the_same_path_always_gets_the_same_ticket(self) -> None:
        path = r"\\fs01\Finance\Q3\cards.csv"
        self.assertEqual(display_ticket(path), display_ticket(path))
        # No salt, no clock, no process state: an operator quoting a ticket from
        # last month must still be pointing at this file.
        expected = "DSPM-" + hashlib.sha256(path.encode()).hexdigest()[:12].upper()
        self.assertEqual(display_ticket(path), expected)

    def test_the_ticket_does_not_move_when_the_risk_does(self) -> None:
        # The same file rescanned after its score changed. (A file with nothing
        # found carries no remediation at all, so both runs need a finding.)
        file_obj = {"name": "cards.csv", "path": r"C:\Finance\cards.csv"}
        quieter = calculate_risk(dict(file_obj), [{"type": "pci_chd_pan", "count": 1, "severity": "HIGH"}])
        louder = calculate_risk(dict(file_obj), [{"type": "pci_chd_pan", "count": 9, "severity": "CRITICAL"}])
        self.assertRegex(quieter.remediation["ticket"], TICKET)
        self.assertEqual(quieter.remediation["ticket"], louder.remediation["ticket"])

    def test_a_file_with_no_path_is_identified_by_its_name(self) -> None:
        by_name = calculate_risk({"name": "orphan.csv"}, [{"type": "pci_chd_pan", "count": 1, "severity": "HIGH"}])
        self.assertEqual(by_name.remediation["ticket"], display_ticket("orphan.csv"))


class ATicketIdentifiesOneFileTest(unittest.TestCase):

    def test_the_format_is_a_wide_hex_namespace(self) -> None:
        self.assertRegex(display_ticket("anything"), TICKET)
        # The defect this replaces: five decimal digits, 100,000 values in total.
        self.assertNotRegex(display_ticket("anything"), r"^DSPM-\d{5}$")

    def test_different_paths_do_not_collide_at_estate_scale(self) -> None:
        # 50,000 files is a small estate for this product. The old namespace was
        # exhausted five times over by this set; every ticket here is distinct.
        paths = [rf"\\fs01\share{index % 40}\dept\folder{index % 700}\file{index}.csv"
                 for index in range(50_000)]
        tickets = {display_ticket(path) for path in paths}
        self.assertEqual(len(tickets), len(paths), "two files were handed the same ticket")

    def test_neighbouring_paths_are_not_neighbouring_tickets(self) -> None:
        # A directory listing must not look like a run of consecutive tickets.
        first = display_ticket(r"C:\share\file1.csv")
        second = display_ticket(r"C:\share\file2.csv")
        self.assertNotEqual(first, second)
        self.assertNotEqual(first[:8], second[:8])

    def test_a_name_that_is_not_utf8_clean_still_yields_a_ticket(self) -> None:
        # Scanned names arrive from SMB in whatever encoding the share used.
        for seed in ("müştəri.csv", "\udcff\udcfe.csv", 1234, "", None):
            with self.subTest(seed=seed):
                self.assertRegex(display_ticket(seed), TICKET)


if __name__ == "__main__":
    unittest.main()
