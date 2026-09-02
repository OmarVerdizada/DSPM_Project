import unittest

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class EnterpriseArchitectureTests(unittest.TestCase):
    def test_canonical_entity_detected_once_then_mapped_to_gdpr_and_pci(self):
        record = {
            "source": "local",
            "path": "exports/cardholder-record.txt",
            "name": "cardholder-record.txt",
            "size": 160,
            "extension": ".txt",
            "content": "\n".join(
                [
                    "Full name: Omar Verdizada",
                    "cardholder name: Omar Verdizada",
                    "card number: 4111111111111111",
                ]
            ),
            "acl": {},
        }
        engine = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["gdpr", "pci_dss"]))

        analyzed = engine._analyze_record(record)

        person_entities = [entity for entity in analyzed["canonical_entities"] if entity["entity_type"] == "PERSON_NAME"]
        self.assertEqual(len(person_entities), 1)
        person = person_entities[0]
        self.assertIn("GDPR", person["framework_mappings"])
        self.assertIn("PCI DSS", person["framework_mappings"])
        self.assertTrue(person["detected_once_mapped_many"])

        gdpr_name = next(finding for finding in analyzed["findings"] if finding["type"] == "gdpr_full_name")
        pci_name = next(finding for finding in analyzed["findings"] if finding["type"] == "pci_chd_cardholder_name")
        self.assertEqual(gdpr_name["canonical_entity_id"], person["entity_id"])
        self.assertEqual(pci_name["canonical_entity_id"], person["entity_id"])
        self.assertIn("GDPR", pci_name["framework_mappings"])
        self.assertIn("PCI DSS", gdpr_name["framework_mappings"])

        pan = next(finding for finding in analyzed["findings"] if finding["type"] == "pci_chd_pan")
        pan_entity = next(entity for entity in analyzed["canonical_entities"] if entity["entity_id"] == pan["canonical_entity_id"])
        self.assertEqual(pan_entity["entity_type"], "PAN")
        self.assertIn("PCI DSS", pan_entity["framework_mappings"])
        self.assertIn("GDPR", pan_entity["framework_mappings"])


if __name__ == "__main__":
    unittest.main()
