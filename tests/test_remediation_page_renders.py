"""The Remediation page renders what /api/findings returns, in the page's own code.

On 2026-09-18 the page showed "Unable to load remediation findings" while every
/api/findings request in the server log answered 200. The fault was in the browser:
Phase A (3e7a69e) deleted REMEDIATION_LIFECYCLE_STATUSES and REMEDIATION_TERMINAL_STATUSES
with some dead dashboard code, the two functions that label a row's status still used
them, and the first row drawn threw a ReferenceError - which the page reports with the
same banner as a failed request. CI checked the frontend with `node --check`, which
only finds syntax errors, so nothing noticed for eight days.

This builds findings in several lifecycle states, fetches them through the real API with
the query the page sends, and runs the real frontend/app.js on the response in Node
(tests/js/remediation_render_smoke.js, dependency-free). It skips where Node is absent;
GitHub's runners have it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from backend import db, store
from backend.app import app
from backend.security import create_token, hash_password
from tests.test_estate_write_is_batched import _report

ROOT = Path(__file__).resolve().parent.parent
SMOKE = ROOT / "tests" / "js" / "remediation_render_smoke.js"
NODE = shutil.which("node")
# The query frontend/app.js sends on first load (remediationQueryParams with no filter).
PAGE_QUERY = "scope=current&status=active&limit=50&sort=risk_score&direction=desc"


@unittest.skipUnless(NODE, "Node.js is needed to run the page's own renderer")
class TheRemediationPageRendersTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)
        cls._seed()

    def setUp(self) -> None:
        # On PostgreSQL the suite has one database and empties it before every test.
        if db.is_postgres():
            type(self)._seed()

    @classmethod
    def _seed(cls) -> None:
        cls.tenant = f"rp{uuid4().hex[:8]}"
        cls.user = f"rp-admin-{uuid4().hex[:6]}"
        store.create_tenant(cls.tenant, "remediation page")
        store.create_user(cls.user, hash_password("x9!RemediationPage"), "admin", cls.tenant)
        store.save_scan_history(cls.tenant, _report(f"rp-{uuid4().hex[:6]}", 12, findings_per_file=2))
        cls.headers = {"Authorization": f"Bearer {create_token(cls.user, 'admin', cls.tenant)}"}
        cls._move_through_the_lifecycle()

    @classmethod
    def tearDownClass(cls) -> None:
        store.delete_user(cls.user)

    @classmethod
    def _get(cls, query: str) -> dict:
        response = cls.client.get(f"/api/findings?{query}", headers=cls.headers)
        assert response.status_code == 200, response.text
        return response.json()

    def _findings(self, query: str) -> dict:
        return self._get(query)

    def _render(self, body: dict) -> dict:
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / "findings.json"
            fixture.write_text(json.dumps(body), encoding="utf-8")
            run = subprocess.run([NODE, str(SMOKE), str(fixture)], capture_output=True, text=True,
                                 timeout=120, cwd=str(ROOT))
        lines = [line for line in run.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"the render smoke printed no result:\n{run.stdout}\n{run.stderr}")
        return json.loads(lines[-1])

    @classmethod
    def _move_through_the_lifecycle(cls) -> None:
        items = cls._get("scope=current&status=all&limit=50")["items"]
        assert len(items) >= 8, "the fixture scan produced too few findings to cover the states"
        actions = [
            ("assign", {"owner": "analyst@corp"}),
            ("false-positive", {"reason": "synthetic"}),
            ("resolve", {"resolution": "removed from the share"}),
            ("risk-acceptance", {"business_justification": "legacy archive", "approver": "ciso",
                                 "expiration_date": "2027-01-01", "compensating_controls": ["share is read-only"],
                                 "affected_assets": ["archive"], "accepted_volume": 1, "review_date": "2026-12-01"}),
            ("suppress", {"reason": "test data", "expiration_date": "2027-01-01"}),
            ("comment", {"comment": "looking at it"}),
        ]
        for item, (action, body) in zip(items, actions):
            finding_id = item.get("finding_id") or item.get("id")
            response = cls.client.post(f"/api/findings/{finding_id}/{action}", json=body, headers=cls.headers)
            assert response.status_code == 200, f"{action}: {response.text}"

    def test_the_first_page_load_renders_every_row(self) -> None:
        body = self._findings(PAGE_QUERY)
        self.assertTrue(body["items"], "nothing to render")
        result = self._render(body)
        self.assertEqual(result["error"], "", f"the page would show its error banner: {result}")
        self.assertTrue(result["loaded"])
        self.assertEqual(result["rows"], len(body["items"]))
        self.assertEqual(result["console_errors"], [])

    def test_every_status_including_the_finished_ones_renders(self) -> None:
        body = self._findings("scope=current&status=all&limit=50&sort=risk_score&direction=desc")
        statuses = {str(item.get("status") or "").upper() for item in body["items"]}
        self.assertTrue({"FALSE_POSITIVE", "RESOLVED"} <= statuses, f"the terminal states were not reached: {statuses}")
        result = self._render(body)
        self.assertEqual(result["error"], "", f"the page would show its error banner: {result}")
        self.assertEqual(result["rows"], len(body["items"]))

    def test_the_smoke_itself_fails_when_the_page_would(self) -> None:
        # A smoke that always passes proves nothing: break the page the way it was
        # actually broken, and the smoke has to say so.
        source = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const REMEDIATION_LIFECYCLE_STATUSES", source)
        broken = source.replace("const REMEDIATION_LIFECYCLE_STATUSES", "const REMEDIATION_LIFECYCLE_STATUSES_GONE", 1)
        with tempfile.TemporaryDirectory() as temp:
            frontend = Path(temp) / "frontend"
            frontend.mkdir()
            (frontend / "app.js").write_text(broken, encoding="utf-8")
            smoke_dir = Path(temp) / "tests" / "js"
            smoke_dir.mkdir(parents=True)
            shutil.copy(SMOKE, smoke_dir / SMOKE.name)
            fixture = Path(temp) / "findings.json"
            fixture.write_text(json.dumps(self._findings(PAGE_QUERY)), encoding="utf-8")
            run = subprocess.run([NODE, str(smoke_dir / SMOKE.name), str(fixture)], capture_output=True,
                                 text=True, timeout=120)
        result = json.loads([line for line in run.stdout.splitlines() if line.startswith("{")][-1])
        self.assertIn("REMEDIATION_LIFECYCLE_STATUSES", result["error"])
        self.assertNotEqual(run.returncode, 0)


if __name__ == "__main__":
    unittest.main()
