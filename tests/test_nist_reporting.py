import unittest

from backend.compliance_service import build_nist_sp800_60_report


class NISTReportingTests(unittest.TestCase):
    def test_report_contains_required_disclaimers(self):
        report = build_nist_sp800_60_report([])

        self.assertIn("Handling tier is product-defined.", report["disclaimers"])
        self.assertIn("Automated detection is not authoritative CUI determination.", report["disclaimers"])


if __name__ == "__main__":
    unittest.main()

