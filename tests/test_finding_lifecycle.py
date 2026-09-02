import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


class FindingLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db = None

        import backend.store as store

        self.store = store
        self.original_db = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "lifecycle.sqlite"
        store.init_db()
        self.tenant_id = "tenant_lifecycle"
        self.actor = "analyst"
        store.create_tenant(self.tenant_id, "Lifecycle Tenant")
        self.finding_id = "finding_lifecycle_001"
        self.report = {
            "scan_id": "scan_lifecycle_001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "unit",
            "summary": {"total_files": 1},
            "files": [
                {
                    "name": "cards.csv",
                    "path": r"C:\PCI\cards.csv",
                    "source": "local",
                    "findings": [
                        {
                            "finding_id": self.finding_id,
                            "type": "pci_chd_pan",
                            "rule_id": "PCI-PAN-001",
                            "status": "OPEN",
                            "risk": "CRITICAL",
                            "occurrences": [
                                {
                                    "occurrence_id": "occurrence_lifecycle_001",
                                    "finding_id": self.finding_id,
                                    "file_id": "file_lifecycle_001",
                                    "page": None,
                                    "row": 18,
                                    "column": "card_number",
                                    "offset_start": 810,
                                    "offset_end": 826,
                                    "secure_fingerprint": "fp",
                                    "redacted_sample": "411111******1111",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        store.save_scan_history(self.tenant_id, self.report)

    def tearDown(self):
        self.store.DB_PATH = self.original_db
        self.temp_dir.cleanup()

    def test_lists_details_updates_history_and_occurrences(self):
        findings = self.store.list_findings(self.tenant_id)
        self.assertEqual(findings[0]["finding_id"], self.finding_id)

        assigned = self.store.update_finding_lifecycle(
            self.tenant_id,
            self.finding_id,
            "assign",
            {"owner": "Payment Security", "comment": "Routing to PCI owner"},
            self.actor,
        )
        self.assertEqual(assigned["status"], "ASSIGNED")
        self.assertEqual(assigned["owner"], "Payment Security")

        self.store.update_finding_lifecycle(self.tenant_id, self.finding_id, "comment", {"comment": "Evidence reviewed"}, self.actor)
        history = self.store.get_finding_history(self.tenant_id, self.finding_id)
        occurrences = self.store.get_finding_occurrences(self.tenant_id, self.finding_id)

        self.assertGreaterEqual(len(history), 2)
        self.assertEqual(occurrences[0]["occurrence_id"], "occurrence_lifecycle_001")
        self.assertEqual(occurrences[0]["redacted_sample"], "411111******1111")

    def test_risk_acceptance_requires_expiring_complete_payload(self):
        with self.assertRaises(ValueError):
            self.store.update_finding_lifecycle(self.tenant_id, self.finding_id, "risk-acceptance", {"approver": "CISO"}, self.actor)

        expiration = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
        review = (datetime.now(timezone.utc) + timedelta(days=15)).date().isoformat()
        accepted = self.store.update_finding_lifecycle(
            self.tenant_id,
            self.finding_id,
            "risk-acceptance",
            {
                "business_justification": "Legacy processor migration window",
                "approver": "CISO",
                "expiration_date": expiration,
                "compensating_controls": ["Restricted share", "Daily review"],
                "affected_assets": ["asset_payment"],
                "accepted_volume": 25,
                "review_date": review,
            },
            self.actor,
        )

        self.assertEqual(accepted["status"], "RISK_ACCEPTED")
        self.assertEqual(accepted["risk_acceptance"]["accepted_volume"], 25)

    def test_suppression_requires_expiration(self):
        with self.assertRaises(ValueError):
            self.store.update_finding_lifecycle(self.tenant_id, self.finding_id, "suppress", {"reason": "Noisy"}, self.actor)


if __name__ == "__main__":
    unittest.main()
