"""C7: every major page renders from representative responses, and a hostile file name
never becomes markup.

The responses are the real backend's, for a scan whose file names, paths and owners are
HTML - what anyone who can create a file on a scanned share can choose. The real
frontend/app.js renders each page in a stand-in DOM (tests/js/page_render_smoke.js), which
records every HTML string the page writes. A page that throws fails; a hostile name that
reaches the markup unescaped fails; and the escaped form must be there, so a page that
drew nothing cannot pass.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import permissions, store
from backend.app import app
from backend.security import create_token

ROOT = Path(__file__).resolve().parent.parent
SMOKE = ROOT / "tests" / "js" / "page_render_smoke.js"
NODE = shutil.which("node")

HOSTILE_NAME = "<img src=x onerror=alert(1)>.txt"
HOSTILE_FOLDER = '"><script>alert(2)</script>'
HOSTILE_OWNER = "<b onmouseover=alert(3)>boss</b>"
# No angle bracket at all: harmless as text, but it leaves a quoted attribute and adds a
# handler unless the quote itself is escaped.
HOSTILE_ATTRIBUTE = 'hr" onfocus="alert(4)'
RAW = ["<img src=x onerror", "<script>alert(2)", "<b onmouseover", '" onfocus="alert(4)']


def _hostile_scan() -> dict:
    files = []
    for index, (name, folder) in enumerate(((HOSTILE_NAME, "finance"), ("ledger.xlsx", HOSTILE_FOLDER),
                                            ("notes.txt", HOSTILE_ATTRIBUTE))):
        files.append({
            "path": f"/share/{folder}/{name}", "name": name, "extension": Path(name).suffix, "size": 10 + index,
            "owner": HOSTILE_OWNER, "modified_at": "2026-06-01T00:00:00+00:00",
            "risk": {"level": "HIGH", "score": 80 - index},
            "findings": [{"type": "Email", "risk": "HIGH", "count": 1, "framework": "GDPR",
                          "samples": [f"{HOSTILE_OWNER}@example.com"]}],
        })
    return {"scan_id": "render-scan", "source": "local", "scan_label": "render check",
            "timestamp": "2026-09-28T00:00:00+00:00", "summary": {"total_files": 3, "high": 3}, "files": files}


@unittest.skipUnless(NODE, "Node.js runs the console's own code")
class EveryPageRendersTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        store.save_scan_history("default", _hostile_scan())
        headers = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        paths = ["/api/history", "/api/executive-dashboard", "/api/inventory/facets", "/api/scan-profiles",
                 "/api/inventory", "/api/audit", "/api/tenants", "/api/findings", "/api/roles", "/api/users",
                 "/api/scan-targets", "/api/history/hash-changes"]
        responses = {}
        for path in paths:
            response = self.client.get(path, headers=headers)
            self.assertEqual(response.status_code, 200, f"{path}: {response.text[:200]}")
            responses[path] = response.json()
        report = self.client.get("/api/history/render-scan/report?include_files=1", headers=headers)
        self.assertEqual(report.status_code, 200, report.text[:200])
        responses["/api/history/render-scan/report"] = report.json()
        self.fixture = {"responses": responses, "scan_id": "render-scan",
                        "permissions": sorted(permissions.PERMISSIONS)}

    def _render(self) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.json"
            path.write_text(json.dumps(self.fixture), encoding="utf-8")
            run = subprocess.run([NODE, str(SMOKE), str(path)], capture_output=True, text=True,
                                 encoding="utf-8", timeout=180, cwd=str(ROOT))
        lines = [line for line in run.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"the smoke printed nothing:\n{run.stdout}\n{run.stderr}")
        return json.loads(lines[-1])

    def test_every_major_page_renders_what_the_backend_answers(self) -> None:
        result = self._render()
        self.assertNotIn("error", result)
        failed = {name: page["error"] for name, page in result["pages"].items() if not page["ok"]}
        self.assertEqual(failed, {})
        self.assertEqual(len(result["pages"]), 11)
        self.assertEqual(result["unanswered"], [], "a page asked for something the fixture does not hold")
        rendered = "\n".join(result["html"])
        self.assertIn("ledger.xlsx", rendered, "the pages drew the scan")

    def test_a_hostile_file_name_is_text_never_markup(self) -> None:
        rendered = "\n".join(self._render()["html"])
        for raw in RAW:
            with self.subTest(raw=raw):
                self.assertNotIn(raw.lower(), rendered.lower())
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", rendered, "the hostile name was drawn, escaped")
        self.assertIn("&lt;b onmouseover=alert(3)&gt;", rendered, "the hostile owner was drawn, escaped")
        self.assertIn("hr&quot; onfocus=&quot;alert(4)", rendered, "the hostile folder was drawn, escaped")


if __name__ == "__main__":
    unittest.main()
