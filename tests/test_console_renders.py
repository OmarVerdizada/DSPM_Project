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
from urllib.parse import quote

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
HOSTILE_ALERT = "<i onclick=alert(5)>Critical</i>"
HOSTILE_PRINCIPAL = "CORP\\<u onclick=alert(6)>Everyone</u>"
HOSTILE_SET = "<s onclick=alert(7)>customers</s>"
# Revision 0055: a permission change whose path and summary are hostile.
HOSTILE_CHANGE_PATH = "C:\\<em onclick=alert(8)>x</em>.txt"
HOSTILE_CHANGE = "<q onclick=alert(9)>Everyone</q>: gained read"
RAW = ["<img src=x onerror", "<script>alert(2)", "<b onmouseover", '" onfocus="alert(4)', "<i onclick", "<u onclick",
       "<s onclick", "<em onclick", "<q onclick"]


def _hostile_scan() -> dict:
    files = []
    for index, (name, folder) in enumerate(((HOSTILE_NAME, "finance"), ("ledger.xlsx", HOSTILE_FOLDER),
                                            ("notes.txt", HOSTILE_ATTRIBUTE))):
        files.append({
            "path": f"/share/{folder}/{name}", "name": name, "extension": Path(name).suffix, "size": 10 + index,
            "owner": HOSTILE_OWNER, "modified_at": "2026-06-01T00:00:00+00:00",
            "acl": {"entries": [{"principal": HOSTILE_PRINCIPAL, "sid": "S-1-5-21-1-2-3-4242", "rights": ["read"],
                                 "type": "allow", "mask": 0x120089}]},
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
        store.save_alerts("default", "render-scan", [{"severity": "CRITICAL", "title": HOSTILE_ALERT,
                                                      "message": "2 critical files found"}])
        headers = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        created = self.client.post("/api/exact-match/sets", json={"name": HOSTILE_SET, "entity_type": "EMAIL_ADDRESS",
                                                                  "values": ["ana@example.com"]},
                                   headers={"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"})
        self.assertEqual(created.status_code, 200, created.text[:200])
        self.addCleanup(lambda: store.delete_edm_set("default", created.json()["set_id"]))
        with store._connect() as conn:
            conn.execute("INSERT INTO asset_acl_changes (tenant_id, id, asset_id, scan_id, detected_at, path, severity, "
                         "summary) VALUES ('default', 'render-change', 'render-asset', 'render-scan', "
                         "'2026-10-10T00:00:00Z', ?, 'high', ?) ON CONFLICT (tenant_id, id) DO NOTHING",
                         (HOSTILE_CHANGE_PATH, HOSTILE_CHANGE))

        def _drop_change() -> None:
            with store._connect() as conn:
                conn.execute("DELETE FROM asset_acl_changes WHERE tenant_id = 'default' AND id = 'render-change'")

        self.addCleanup(_drop_change)
        paths = ["/api/history", "/api/executive-dashboard", "/api/inventory/facets", "/api/scan-profiles",
                 "/api/inventory", "/api/audit", "/api/tenants", "/api/findings", "/api/roles", "/api/users",
                 "/api/scan-targets", "/api/history/hash-changes", "/api/alerts", "/api/access/principals",
                 "/api/access/summary", "/api/access/changes", "/api/exact-match/sets"]
        responses = {}
        for path in paths:
            response = self.client.get(path, headers=headers)
            self.assertEqual(response.status_code, 200, f"{path}: {response.text[:200]}")
            responses[path] = response.json()
        report = self.client.get("/api/history/render-scan/report?include_files=1", headers=headers)
        self.assertEqual(report.status_code, 200, report.text[:200])
        responses["/api/history/render-scan/report"] = report.json()
        principals = responses["/api/access/principals"]["principals"]
        access_key = next(row["key"] for row in principals if "alert(6)" in row["principal"])
        files = self.client.get(f"/api/access/files?key={quote(access_key)}&sensitive_only=false", headers=headers)
        self.assertEqual(files.status_code, 200, files.text[:200])
        responses["/api/access/files"] = files.json()
        self.fixture = {"responses": responses, "scan_id": "render-scan", "access_key": access_key,
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
        self.assertEqual(len(result["pages"]), 14)
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
        self.assertIn("&lt;i onclick=alert(5)&gt;Critical&lt;/i&gt;", rendered, "the hostile alert was drawn, escaped")
        self.assertIn("&lt;u onclick=alert(6)&gt;Everyone&lt;/u&gt;", rendered, "the hostile principal was drawn, escaped")
        self.assertIn("&lt;s onclick=alert(7)&gt;customers&lt;/s&gt;", rendered, "the hostile set name was drawn, escaped")
        self.assertIn("&lt;q onclick=alert(9)&gt;Everyone&lt;/q&gt;", rendered, "the hostile change was drawn, escaped")
        self.assertIn("&lt;em onclick=alert(8)&gt;", rendered, "the hostile changed path was drawn, escaped")
        self.assertIn("ledger.xlsx", rendered)


if __name__ == "__main__":
    unittest.main()
