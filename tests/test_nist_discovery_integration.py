import unittest
from unittest.mock import patch

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class NISTDiscoveryIntegrationTests(unittest.TestCase):
    def test_nist_detector_runs_when_selected(self):
        record = {"source": "local", "path": "identity.txt", "name": "identity.txt", "extension": ".txt", "content": "CUI NIST SP 800-60 Identity Management Type 1 user id", "acl": {}}
        analyzed = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["nist_sp800_60_enterprise"], persistent_cache_enabled=False))._analyze_record(record)

        self.assertTrue(any(item["framework"] == "nist_sp800_60_enterprise" for item in analyzed["findings"]))
        self.assertIn("nist_sp800_60_enterprise", analyzed["keyword_catalog_status"])

    def test_nist_detector_does_not_run_when_not_selected(self):
        record = {"source": "local", "path": "identity.txt", "name": "identity.txt", "extension": ".txt", "content": "CUI NIST SP 800-60 Identity Management Type 1 user id", "acl": {}}
        engine = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["gdpr"], persistent_cache_enabled=False))

        with patch("discovery.discovery_engine.classify_nist_content") as detector:
            engine._analyze_record(record)

        detector.assert_not_called()


if __name__ == "__main__":
    unittest.main()

