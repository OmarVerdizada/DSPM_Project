import tempfile
import unittest
from pathlib import Path

from classification.compliance import keyword_library


class NISTTenantIsolationTests(unittest.TestCase):
    def test_nist_overlay_is_tenant_scoped(self):
        original_dir = keyword_library.CUSTOM_KEYWORD_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            keyword_library.CUSTOM_KEYWORD_DIR = Path(temp_dir)
            try:
                keyword_library.import_keyword_groups("tenant_a", {"framework": "nist_sp800_60_enterprise", "keywords": [{"type": "nist_privacy_pii_type_01", "category": "nist_privacy_pii", "terms": ["tenant a nist marker"]}]})
                keyword_library.import_keyword_groups("tenant_b", {"framework": "nist_sp800_60_enterprise", "keywords": [{"type": "nist_privacy_pii_type_01", "category": "nist_privacy_pii", "terms": ["tenant b nist marker"]}]})

                tenant_a = keyword_library.custom_keyword_groups_for_scan("tenant_a", "nist_sp800_60_enterprise")[0]["terms"]
                tenant_b = keyword_library.custom_keyword_groups_for_scan("tenant_b", "nist_sp800_60_enterprise")[0]["terms"]

                self.assertEqual(tenant_a, ["tenant a nist marker"])
                self.assertEqual(tenant_b, ["tenant b nist marker"])
            finally:
                keyword_library.CUSTOM_KEYWORD_DIR = original_dir


if __name__ == "__main__":
    unittest.main()

