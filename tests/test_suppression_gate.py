"""B6's gate, end to end: a rule from a FALSE_POSITIVE prevents recreation next scan.

Everything here is real - files on disk, the discovery engine, the estate write, the
lifecycle API's own rule builder, and the store. Nothing is mocked except the two
Windows facts a temp directory gets wrong (owner lookup, and %TEMP% being a path the
scanner skips on purpose).

The shape of the gate:

1. a scan finds a card number in a file and the estate has the finding;
2. the analyst dismisses it, and the dismissal writes the rule;
3. the next scan - configured the way a scan is configured, from the store - does not
   create it again, and the estate does not carry it as current;
4. withdrawing the rule brings it back, because a suppressed finding was never a
   deleted one.
"""

from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend import app as app_module, store
from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

CARD = "4111 1111 1111 1111"


class TheSuppressionGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.local = root / "estate"
        self.local.mkdir()
        (self.local / "customers.csv").write_text(f"name,card\nana,{CARD}\n", encoding="utf-8")
        self.cache = root / "cache"
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "suppression gate")
        self.skip_patch = patch.object(file_scanner, "is_skipped_scan_path", return_value=False)
        self.owner_patch = patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))
        self.skip_patch.start()
        self.owner_patch.start()

    def tearDown(self) -> None:
        self.owner_patch.stop()
        self.skip_patch.stop()
        for rule in store.list_suppression_rules(self.tenant):
            store.delete_suppression_rule(self.tenant, rule["rule_id"])
        store.delete_tenant_with_data(self.tenant)
        self.temp.cleanup()

    def _scan(self, scan_id: str) -> dict:
        """One scan, configured the way the backend configures one - rules and all."""
        engine = DSPMDiscoveryEngine(
            ScanConfig(
                tenant_id=self.tenant,
                local_path=str(self.local),
                # The flag that means "walk this local path"; the tree is not empty,
                # so no sample data is used.
                use_sample_when_empty=True,
                persistent_cache_enabled=True,
                cache_dir=str(self.cache),
                incremental_enabled=False,
                max_workers=1,
                suppression_rules=store.suppression_rules_for_scan(self.tenant),
            )
        )
        report = engine.run().to_dict()
        report["scan_id"] = scan_id
        report["scan_label"] = "gate"
        store.save_scan_history(self.tenant, report)
        return report

    def _reported_types(self, report: dict) -> set[str]:
        return {
            str(finding.get("type") or "")
            for file_obj in report.get("files") or []
            for finding in file_obj.get("findings") or []
        }

    def _estate_types(self) -> set[str]:
        page = store.list_remediation_findings(self.tenant, status="all", limit=50)
        rows = page.get("items") or page.get("findings") or []
        return {str(row.get("data_type") or row.get("display_name") or "") for row in rows}

    def test_a_dismissed_finding_is_not_created_again(self) -> None:
        first = self._scan("gate-1")
        self.assertIn("credit_card", self._reported_types(first), "the fixture found nothing to dismiss")
        self.assertTrue(self._estate_types(), "the first scan wrote nothing to the estate")

        carrier = next(
            file_obj for file_obj in first["files"]
            if any(item.get("type") == "credit_card" for item in file_obj.get("findings") or [])
        )
        finding = next(item for item in carrier["findings"] if item.get("type") == "credit_card")
        # The path as the scan reports it, which is what the console builds the rule
        # from: a temp directory is reached by two spellings and the scan resolves one.
        dismissed = dict(finding, file={"path": carrier["path"], "source": carrier.get("source") or ""})
        rule = store.create_suppression_rule(
            self.tenant,
            **app_module._suppression_rule_from_finding(dismissed, "file", "synthetic test data"),
            created_by="ana",
        )
        self.assertEqual(rule["finding_type"], "credit_card")

        second = self._scan("gate-2")
        self.assertNotIn("credit_card", self._reported_types(second),
                         "the next scan created the finding the analyst dismissed")
        self.assertEqual(second["scan_diagnostics"]["suppression"]["suppressed_findings"], 1)
        self.assertNotIn("credit_card", self._estate_types(), "the estate carries a suppressed finding as current")

        store.delete_suppression_rule(self.tenant, rule["rule_id"])
        third = self._scan("gate-3")
        self.assertIn("credit_card", self._reported_types(third),
                      "withdrawing the rule must bring the finding back - it was hidden, not deleted")


if __name__ == "__main__":
    unittest.main()
