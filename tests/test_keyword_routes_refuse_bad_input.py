"""M2 polish: what the local DAST run (Wapiti, as a viewer) found in the keyword routes.

`GET /api/compliance-keywords?framework=<a URL>` answered 500: an unknown framework raised
ValueError inside the library and nothing turned it into the caller's error. The export
had the same hole, and built its download name from the raw `language`, `source` and
`format`, so a crafted value could close the quoted name in Content-Disposition and add
a `filename*` of its own.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import security, store
from backend.app import app


class KeywordRoutesRefuseBadInputTest(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "keywords.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for username, role in (("kw-viewer", "viewer"), ("kw-analyst", "analyst")):
            store.create_user(username, security.hash_password(f"{username}-pw-12"), role, "default")
        self.client = TestClient(app, raise_server_exceptions=False)
        self.viewer = {"Authorization": f"Bearer {security.create_token('kw-viewer', 'viewer', 'default')}"}
        self.analyst = {"Authorization": f"Bearer {security.create_token('kw-analyst', 'analyst', 'default')}"}

    def test_an_unknown_framework_is_the_callers_error(self) -> None:
        for framework in ("https://wapiti3.ovh//e.php", "nope", "../../etc"):
            with self.subTest(framework=framework):
                listed = self.client.get("/api/compliance-keywords", params={"framework": framework},
                                         headers=self.viewer)
                self.assertEqual(listed.status_code, 400, listed.text[:200])
                exported = self.client.get("/api/compliance-keywords/export", params={"framework": framework},
                                           headers=self.analyst)
                self.assertEqual(exported.status_code, 400, exported.text[:200])
        self.assertEqual(self.client.get("/api/compliance-keywords", params={"framework": "gdpr"},
                                         headers=self.viewer).status_code, 200)

    def test_an_unknown_export_format_is_refused(self) -> None:
        response = self.client.get("/api/compliance-keywords/export", params={"framework": "gdpr", "format": "exe"},
                                   headers=self.analyst)
        self.assertEqual(response.status_code, 400)

    def test_the_download_name_cannot_be_steered(self) -> None:
        for field, value in (("language", "x\"; filename*=UTF-8''evil.exe"), ("source", "a\";x=\"b"),
                             ("language", "../../boot")):
            with self.subTest(field=field, value=value):
                response = self.client.get("/api/compliance-keywords/export",
                                           params={"framework": "gdpr", "format": "csv", field: value},
                                           headers=self.analyst)
                self.assertEqual(response.status_code, 200, response.text[:200])
                disposition = response.headers["content-disposition"]
                # One quoted name of safe characters: the value's letters may remain, but it
                # can no longer close the quote or add a filename* of its own.
                self.assertRegex(disposition, r'^attachment; filename="[A-Za-z0-9_.-]+\.csv"$')
                self.assertEqual(disposition.count("filename="), 1)
                self.assertNotIn("filename*", disposition)

    def test_an_ordinary_export_keeps_its_name(self) -> None:
        response = self.client.get("/api/compliance-keywords/export",
                                   params={"framework": "gdpr", "format": "json", "language": "az"},
                                   headers=self.analyst)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(re.fullmatch(r'attachment; filename="[A-Za-z0-9_]+_keywords_az\.json"',
                                     response.headers["content-disposition"]), response.headers["content-disposition"])


if __name__ == "__main__":
    unittest.main()
