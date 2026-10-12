import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from classification.compliance import nist_catalog


class NISTCatalogRollbackTests(unittest.TestCase):
    def test_import_activate_and_rollback_are_atomic(self):
        catalog = nist_catalog.load_nist_catalog()
        upgraded = copy.deepcopy(catalog)
        upgraded["catalog"]["catalog_version"] = "test-upgrade"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with patch.object(nist_catalog, "STATE_DIR", root), patch.object(nist_catalog, "ACTIVE_PATH", root / "active.json"), patch.object(nist_catalog, "LAST_GOOD_PATH", root / "last_good.json"), patch.object(nist_catalog, "AUDIT_PATH", root / "audit.jsonl"):
                preview = nist_catalog.import_nist_catalog(upgraded, dry_run=False, actor="admin")
                activated = nist_catalog.activate_nist_catalog(preview["catalog_hash"], actor="admin")
                rolled_back = nist_catalog.rollback_nist_catalog(actor="admin")

                self.assertTrue(preview["imported"])
                self.assertTrue(activated["activated"])
                self.assertTrue(rolled_back["rolled_back"])
                self.assertEqual(nist_catalog.nist_catalog_status()["catalog_status"], "OK")

    def test_invalid_upgrade_does_not_replace_active_catalog(self):
        catalog = nist_catalog.load_nist_catalog()
        invalid = copy.deepcopy(catalog)
        invalid["rules"][0]["framework"] = "gdpr"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with patch.object(nist_catalog, "STATE_DIR", root), patch.object(nist_catalog, "ACTIVE_PATH", root / "active.json"), patch.object(nist_catalog, "LAST_GOOD_PATH", root / "last_good.json"), patch.object(nist_catalog, "AUDIT_PATH", root / "audit.jsonl"):
                result = nist_catalog.import_nist_catalog(invalid, dry_run=False, actor="admin")

                self.assertFalse(result["valid"])
                self.assertFalse((root / "active.json").exists())


if __name__ == "__main__":
    unittest.main()

