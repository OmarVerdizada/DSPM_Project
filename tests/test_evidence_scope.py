"""M2/C3: a role without `evidence.view` sees what a scan found, not what it read.

The gate's words are "scan operator cannot see evidence". Evidence is the part of a scan
result that was read out of the document: the preview lines around a match, the matched
values (masked, but derived - a masked card keeps six digits and four, a record number in
a preview line may not be masked at all) and each occurrence's redacted sample. A scan
operator needs to know that a file holds cardholder data, and where; an analyst confirming
the finding needs to see it.

These tests run the real engine over a small synthetic file once, persist the result the
way the scan route does, and read it back through every route that can return it - as a
scan operator, a viewer, an auditor and an analyst.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from backend import app as app_module
from backend import security, store
from backend.app import app
from backend.evidence import REDACTED_PREVIEW, redact_evidence, without_evidence

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
SMOKE = ROOT / "tests" / "js" / "refresh_retry_smoke.js"
TENANT = "tenant-evidence"
PASSWORD = "an-evidence-pass-9"
FRAMEWORKS = ["gdpr", "pci_dss", "nist_sp800_60_enterprise"]
# Synthetic content. Each marker below survives the scanners' own masking somewhere in
# the evidence - so its absence from a response is what proves the evidence is gone.
CONTENT = (
    "Employee salary list. Contact jane.doe@example.com, phone +994 50 123 45 67.\n"
    "Card 4111 1111 1111 1111 exp 12/29 cvv 123. Passport AA1234567. IBAN AZ21NABZ00000000137010001944\n"
    "Diagnosis: diabetes, patient record MRN 55512.\n"
)
MARKERS = ("55512", "example.com", "411111", "AZ21NABZ")
EVIDENCE_KEYS = {"samples", "sample", "redacted_sample", "masked_preview", "Masked preview", "iin_bin"}


def _scan_report() -> dict:
    """The real engine and the scan route's own compliance step, over one synthetic file."""
    from discovery.discovery_engine import DSPMDiscoveryEngine

    with tempfile.TemporaryDirectory(prefix="sentro-evidence-", ignore_cleanup_errors=True) as tmp:
        folder = Path(tmp)
        (folder / "payroll.txt").write_text(CONTENT, encoding="utf-8")
        payload = app_module.ScanRequest(save_report=True, compliance_enabled=True, compliance_frameworks=FRAMEWORKS)
        config = app_module._to_config(payload, TENANT)
        config.local_path = str(folder)
        config.persistent_cache_enabled = False
        config.extension_filter_enabled = False
        # The collector skips AppData\\Temp by design - that is where a temp folder lives here.
        with mock.patch("collectors.file_scanner.is_skipped_scan_path", return_value=False):
            report = DSPMDiscoveryEngine(config).run().to_dict()
    app_module._apply_compliance(report, payload)
    return report


def _evidence_keys_in(value) -> set[str]:
    found = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in EVIDENCE_KEYS:
                found.add(key)
            if key == "preview" and isinstance(item, dict) and item.get("lines"):
                found.add("preview.lines")
            found |= _evidence_keys_in(item)
    elif isinstance(value, list):
        for item in value:
            found |= _evidence_keys_in(item)
    return found


class TheRedactionItselfTest(unittest.TestCase):

    RECORD = {
        "path": "\\\\fs01\\hr\\payroll.xlsx",
        "preview": {"available": True, "lines": ["Card 411111******1111"], "truncated": False},
        "findings": [{
            "type": "pci_chd_pan", "count": 1, "samples": ["411111******1111"], "matched_keywords": ["card"],
            "occurrences": [{"occurrence_id": "o1", "offset_start": 5, "redacted_sample": "411111******1111"}],
            "masked_preview": "411111******1111", "context": "Card 4111 1111 1111 1111 exp 12/29",
            "secure_fingerprints": ["f1"], "iin_bin": "41111111",
        }],
        "compliance": {"evidence": [{"type": "email", "keywords": ["j***@example.com"], "samples": ["j***@example.com"]}]},
        "remediation": {"context": {"owner": "HR"}},
    }

    def test_evidence_goes_and_the_finding_stays(self) -> None:
        redacted, removed = redact_evidence(self.RECORD)
        self.assertEqual(removed, 8)
        self.assertEqual(redacted["preview"], REDACTED_PREVIEW)
        finding = redacted["findings"][0]
        self.assertEqual(set(finding), {"type", "count", "matched_keywords", "occurrences", "secure_fingerprints"})
        self.assertEqual(finding["occurrences"], [{"occurrence_id": "o1", "offset_start": 5}])
        self.assertEqual(redacted["compliance"]["evidence"], [{"type": "email"}])
        self.assertEqual(redacted["remediation"], {"context": {"owner": "HR"}}, "a context that is not text stays")
        self.assertEqual(redacted["path"], self.RECORD["path"], "where the data is, is not evidence")

    def test_the_original_is_untouched(self) -> None:
        before = json.dumps(self.RECORD, sort_keys=True)
        redact_evidence(self.RECORD)
        self.assertEqual(json.dumps(self.RECORD, sort_keys=True), before)

    def test_the_response_says_why(self) -> None:
        self.assertTrue(without_evidence({"asset": self.RECORD})["evidence_hidden"])
        self.assertEqual(without_evidence("text"), "text")

    def test_a_call_it_cannot_attribute_gets_no_evidence(self) -> None:
        route = app_module.evidence_scoped(lambda **_: {"samples": ["411111******1111"]})
        self.assertEqual(route(), {"evidence_hidden": True})
        self.assertEqual(route(principal="not-a-principal"), {"evidence_hidden": True})
        analyst = security.Principal("someone", "analyst", TENANT)
        self.assertEqual(route(principal=analyst), {"samples": ["411111******1111"]})

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_the_console_says_why_it_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "scenario.json"
            fixture.write_text(json.dumps({"drive": "evaluate", "permissions": ["inventory.view"], "evaluate": {
                "preview": "renderPreview({available: false, lines: [], redacted: true})",
                "samples": "renderFindingEvidenceSections({type: 'email', samples: []})",
            }}), encoding="utf-8")
            result = subprocess.run([NODE, str(SMOKE), str(fixture)], cwd=ROOT, capture_output=True,
                                    text=True, timeout=180, check=False)
        values = json.loads(result.stdout.strip().splitlines()[-1])["values"]
        self.assertIn("your role does not include evidence", values["preview"])
        self.assertIn("your role does not include evidence", values["samples"])


class EveryRouteThatReturnsARecordIsScopedTest(unittest.TestCase):

    SCOPED = {
        ("POST", "/api/scan"), ("POST", "/api/endpoint/scan"), ("GET", "/api/scans/{job_id}"),
        ("GET", "/api/history/latest/report"), ("GET", "/api/history/{scan_id}/report"),
        ("GET", "/api/inventory/{asset_id}"), ("GET", "/api/findings/{finding_id}"),
        ("GET", "/api/findings/{finding_id}/occurrences"), ("PATCH", "/api/history/{scan_id}/findings/workflow"),
        ("PATCH", "/api/findings/{finding_id}/status"), ("POST", "/api/findings/{finding_id}/assign"),
        ("POST", "/api/findings/{finding_id}/comment"), ("POST", "/api/findings/{finding_id}/suppress"),
        ("POST", "/api/findings/{finding_id}/resolve"), ("POST", "/api/findings/{finding_id}/reopen"),
        ("POST", "/api/findings/{finding_id}/risk-acceptance"), ("POST", "/api/findings/{finding_id}/false-positive"),
        ("POST", "/api/findings/{finding_id}/validate"),
    }

    def test_the_scoped_set_is_exactly_these(self) -> None:
        scoped = set()
        for route in app.routes:
            if isinstance(route, APIRoute) and getattr(route.endpoint, "evidence_scoped", False):
                scoped |= {(method, route.path) for method in route.methods}
        self.assertEqual(scoped, self.SCOPED)


class _ScannedCase(unittest.TestCase):
    report: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _scan_report()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "evidence.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant(TENANT, "Evidence")
        password_hash = security.hash_password(PASSWORD)
        for role in ("viewer", "auditor", "scan_operator", "analyst"):
            store.create_user(f"ev-{role}", password_hash, role, TENANT)
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        payload = app_module.ScanRequest(save_report=True, compliance_enabled=True, compliance_frameworks=FRAMEWORKS)
        data = json.loads(json.dumps(self.report))
        app_module._persist_compliance_scan(data, payload, security.Principal("ev-analyst", "analyst", TENANT))
        self.scan_id = data["scan_id"]
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        items = self.client.get("/api/inventory", headers=self._as("analyst")).json()["items"]
        self.assertEqual(len(items), 1, "the synthetic file should be in the estate")
        self.asset_id = items[0]["id"]
        findings = self.client.get("/api/findings?limit=50", headers=self._as("analyst")).json()["items"]
        self.finding_id = next(item["finding_id"] for item in findings if item["type"] == "pci_chd_pan")

    def _as(self, role: str) -> dict:
        return {"Authorization": f"Bearer {security.create_token(f'ev-{role}', role, TENANT)}"}

    def _read(self, role: str, path: str) -> dict:
        response = self.client.get(path, headers=self._as(role))
        self.assertEqual(response.status_code, 200, f"{role} {path}: {response.text[:200]}")
        return response.json()

    def _routes(self) -> list[str]:
        return [
            f"/api/inventory/{self.asset_id}",
            f"/api/findings/{self.finding_id}",
            f"/api/findings/{self.finding_id}/occurrences",
            "/api/history/latest/report",
            f"/api/history/{self.scan_id}/report",
        ]


class AScanOperatorCannotSeeEvidenceTest(_ScannedCase):

    def test_the_analyst_does_so_the_test_can_tell(self) -> None:
        # Without this, every assertion below would pass on a scan that found nothing.
        for path in self._routes():
            with self.subTest(path=path):
                body = self._read("analyst", path)
                self.assertTrue(_evidence_keys_in(body), f"{path} carried no evidence even for an analyst")
                self.assertNotIn("evidence_hidden", body)
        asset = json.dumps(self._read("analyst", f"/api/inventory/{self.asset_id}"))
        for marker in MARKERS:
            self.assertIn(marker, asset)

    def test_nor_does_any_role_without_the_permission(self) -> None:
        for role in ("scan_operator", "viewer", "auditor"):
            for path in self._routes():
                with self.subTest(role=role, path=path):
                    body = self._read(role, path)
                    self.assertEqual(_evidence_keys_in(body), set())
                    self.assertTrue(body.get("evidence_hidden"))
                    text = json.dumps(body)
                    for marker in MARKERS:
                        self.assertNotIn(marker, text)

    def test_the_finding_itself_is_still_there(self) -> None:
        asset = self._read("scan_operator", f"/api/inventory/{self.asset_id}")["asset"]
        self.assertEqual(asset["preview"], REDACTED_PREVIEW)
        types = {finding["type"] for finding in asset["findings"]}
        self.assertIn("pci_chd_pan", types)
        self.assertIn("email", types)
        self.assertTrue(all(finding.get("count") for finding in asset["findings"]))
        self.assertEqual(asset["path"], self._read("analyst", f"/api/inventory/{self.asset_id}")["asset"]["path"])

    def test_a_scan_job_result_is_scoped_too(self) -> None:
        job = SimpleNamespace(tenant_id=TENANT, to_dict=lambda: {"id": "job-1", "status": "completed", "result": self.report})
        with mock.patch("backend.app.get_job", return_value=job):
            operator = self._read("scan_operator", "/api/scans/job-1")
            analyst = self._read("analyst", "/api/scans/job-1")
        self.assertEqual(_evidence_keys_in(operator), set())
        self.assertTrue(_evidence_keys_in(analyst))

    def test_the_scan_the_operator_runs_comes_back_without_it(self) -> None:
        engine = mock.MagicMock()
        engine.return_value.run.return_value.to_dict.return_value = json.loads(json.dumps(self.report))
        with mock.patch("backend.app.DSPMDiscoveryEngine", engine), \
                mock.patch("backend.app.partitioned_scans_enabled", return_value=False):
            response = self.client.post("/api/scan", headers=self._as("scan_operator"), json={
                "async_scan": False, "save_report": False, "compact_result": False,
                "compliance_enabled": True, "compliance_frameworks": FRAMEWORKS,
            })
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        self.assertTrue(body["files"], "the scan's result is returned")
        self.assertEqual(_evidence_keys_in(body), set())
        for marker in MARKERS:
            self.assertNotIn(marker, json.dumps(body))


class AFiledReportCarriesNoEvidenceTest(_ScannedCase):
    """An auditor files reports (`report.create`) without `evidence.view`, so the report
    itself - the HTML and the PDF, as downloaded - must not be a way round the scope.
    It carries none for anyone: the register names a file, its types, counts and risk."""

    def _filed(self, role: str) -> tuple[str, str]:
        from io import BytesIO

        from pypdf import PdfReader

        headers = self._as(role)
        created = self.client.post("/api/v1/reports", headers=headers, json={"scan_id": self.scan_id})
        self.assertEqual(created.status_code, 200, created.text[:300])
        path = f"/api/v1/reports/artifacts/{created.json()['artifact_id']}"
        html = self.client.get(f"{path}?format=html", headers=headers)
        pdf = self.client.get(f"{path}?format=pdf", headers=headers)
        self.assertEqual((html.status_code, pdf.status_code), (200, 200))
        text = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(pdf.content)).pages)
        return html.text, text + pdf.content.decode("latin-1")

    def setUp(self) -> None:
        super().setUp()
        from backend.reporting import artifacts

        # ARTIFACT_ROOT is resolved at import; without this the reports land in data/.
        root = mock.patch.object(artifacts, "ARTIFACT_ROOT", Path(self.temp_dir.name) / "artifacts")
        root.start()
        self.addCleanup(root.stop)

    def test_an_auditors_report_names_the_finding_and_not_what_was_read(self) -> None:
        html, pdf = self._filed("auditor")
        for label, body in (("html", html), ("pdf", pdf)):
            with self.subTest(format=label):
                # It is the right report: the file and what was found in it are there...
                self.assertIn("payroll.txt", body)
                self.assertIn("pci_chd_pan", body)
                # ...and nothing read out of the document is.
                for marker in MARKERS:
                    self.assertNotIn(marker, body)

    def test_nor_does_an_analysts(self) -> None:
        # The report is not scoped per role - it never holds evidence - so the analyst's
        # is the same shape; were it to start carrying samples, this is where it shows.
        html, pdf = self._filed("analyst")
        for body in (html, pdf):
            self.assertIn("payroll.txt", body)
            for marker in MARKERS:
                self.assertNotIn(marker, body)


if __name__ == "__main__":
    unittest.main()
