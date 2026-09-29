"""D2: GDPR confidence tiers, then exact-data matching from an approved reference set.

Gate line: "Labelled corpus precision/recall and false-positive delta recorded; reference
rows match exactly and do not reveal raw source data or unsalted value hashes."
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import security, store
from backend.app import app
from classification import exact_match
from classification.compliance.gdpr_classifier import classify_gdpr_content
from classification.compliance.gdpr_rules import detect_fin
from classification.confidence import UNSCORED, confidence_label, confidence_score, stated_confidence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def gdpr(text: str, tenant: str = "t-d2") -> dict:
    return {item["type"]: item for item in classify_gdpr_content(text, {"tenant_id": tenant, "path": "doc.txt"})}


class TheConfidenceTest(unittest.TestCase):

    def test_every_gdpr_finding_states_its_confidence_tier_and_why(self) -> None:
        found = gdpr("Customer list\nana@example.com, bob@example.org, cara@example.net\nFIN: 5ZX8K2P\n")
        self.assertTrue(found)
        for item in found.values():
            self.assertIsInstance(item["confidence"], int)
            self.assertIn(item["confidence_tier"], {"LOW", "MEDIUM", "HIGH"})
            self.assertTrue(item["confidence_basis"])
            self.assertEqual(item["confidence_version"], "gdpr-confidence-1")
        self.assertEqual(found["gdpr_fin_pin"]["confidence_tier"], "HIGH", "a validated FIN with its keyword")

    def test_only_an_exact_match_is_confirmed(self) -> None:
        found = gdpr("Customer list\nana@example.com, bob@example.org, cara@example.net, dan@example.com\n"
                     "FIN: 5ZX8K2P, FIN: 7XK2P9Q, FIN: 3PQ7ZZ1\nnational ID, identity card, FIN code\n")
        self.assertTrue(found)
        for finding_type, finding in found.items():
            with self.subTest(finding_type):
                self.assertLessEqual(finding["confidence"], 95, "the ceiling below CONFIRMED")
                self.assertNotEqual(finding["confidence_tier"], "CONFIRMED")
        self.assertEqual(max(item["confidence"] for item in found.values()), 95, "the strongest evidence reaches it")

    def test_a_secret_needs_a_secret_shaped_value(self) -> None:
        prose = gdpr("Password guidance\nNever share your password. The password field below is required.\n")
        if "gdpr_password_secret" in prose:
            self.assertEqual(prose["gdpr_password_secret"]["confidence_tier"], "LOW")
        real = gdpr("[database]\nuser = app_rw\npassword = Tr0ub4dor&3xYz!\n")
        self.assertIn(real["gdpr_password_secret"]["confidence_tier"], {"MEDIUM", "HIGH"})

    def test_a_special_category_is_personal_when_the_file_names_a_person(self) -> None:
        runbook = gdpr("Service runbook\nThe /health endpoint returns 200 when healthy. Diagnosis: check the logs.\n")
        note = gdpr("Occupational health - sick leave certificate\nPatient: Leyla Aliyeva\n"
                    "Diagnosis: type 2 diabetes, prescribed metformin; medical leave 5 days\n")
        self.assertIn(note["gdpr_health_medical_record"]["confidence_tier"], {"MEDIUM", "HIGH"})
        self.assertIn("about a named person", note["gdpr_health_medical_record"]["confidence_basis"])
        if "gdpr_health_medical_record" in runbook:
            self.assertEqual(runbook["gdpr_health_medical_record"]["confidence_tier"], "LOW")
            self.assertLess(runbook["gdpr_health_medical_record"]["confidence"],
                            note["gdpr_health_medical_record"]["confidence"])

    def test_one_reading_of_confidence_everywhere(self) -> None:
        from backend.compliance_service import _confidence_score
        from classification.compliance.canonical_model import _confidence
        from risk.risk_engine import _extract_confidence_score

        for finding, expected in (({}, UNSCORED), ({"confidence": "high"}, 90), ({"detection_confidence": 55}, 55),
                                  ({"confidence": "low"}, 40), ({"confidence": "unheard-of"}, UNSCORED)):
            with self.subTest(finding=finding):
                self.assertEqual(_confidence(finding), expected, "canonical model")
                self.assertEqual(_confidence_score(finding), expected, "compliance service")
                self.assertEqual(confidence_score(finding), expected)
                if stated_confidence(finding) is not None:
                    self.assertEqual(_extract_confidence_score(finding), expected, "risk engine")
        self.assertIsNone(_extract_confidence_score({}), "the risk engine reads 'none stated' as MEDIUM itself")
        self.assertIsNone(stated_confidence({"confidence": True}))
        self.assertEqual(confidence_label(confidence_score({})), "MEDIUM", "stating nothing reads as MEDIUM")


class TheFinDetectorTest(unittest.TestCase):
    """The corpus found seven-letter words and a surname reported as FINs at confidence 95."""

    def test_words_and_surnames_are_not_fins(self) -> None:
        self.assertEqual(detect_fin("Travel desk - passport details for visa application", {}), [])
        self.assertEqual(detect_fin("Applicant: Sevda Karimova, national ID number\nApplicant: Orkhan Babayev", {}), [])
        self.assertEqual(detect_fin("Meeting notes - parking, network cabling. ID card desk", {}), [])
        self.assertEqual(detect_fin("ID card FIN: pending", {}), [], "a word after the label, not in capitals")

    def test_real_fins_are_still_found(self) -> None:
        self.assertEqual(detect_fin("FIN: 5ZX8K2P", {}), ["5ZX8K2P"])
        self.assertEqual(detect_fin("FIN code: 5VBK5VR", {}), ["5VBK5VR"])
        self.assertEqual(detect_fin("FIN: ABCDEFG", {}), ["ABCDEFG"], "an all-letter FIN right after its label")


class TheLabelledCorpusTest(unittest.TestCase):
    """What the tiers are worth - measured, and held so a change that makes them worth
    less is seen. The numbers are recorded in docs/evidence/d2-gdpr-confidence-2026-09-29.json."""

    @classmethod
    def setUpClass(cls) -> None:
        import gdpr_confidence_eval

        cls.report = gdpr_confidence_eval.evaluate()

    def test_the_medium_threshold_removes_false_positives_and_keeps_true_ones(self) -> None:
        every, medium = self.report["thresholds"]["all"], self.report["thresholds"]["medium_and_above"]
        self.assertGreater(medium["precision"], every["precision"])
        self.assertGreaterEqual(self.report["false_positive_delta_at_medium"], 10)
        self.assertLessEqual(self.report["true_positives_lost_at_medium"], 2)

    def test_the_high_tier_is_precise(self) -> None:
        self.assertGreaterEqual(self.report["thresholds"]["high_and_above"]["precision"], 0.75)

    def test_the_recorded_evidence_is_this_measurement(self) -> None:
        recorded = json.loads((ROOT / "docs" / "evidence" / "d2-gdpr-confidence-2026-09-29.json").read_text(encoding="utf-8"))
        self.assertEqual(recorded["thresholds"], self.report["thresholds"])


class ExactMatchCase(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d2.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in ("t-edm", "t-other"):
            store.create_tenant(tenant, tenant)
        store.create_user("edm-admin", security.hash_password("Kestrel-lantern-4471"), "admin", "t-edm")
        store.create_user("other-admin", security.hash_password("Kestrel-lantern-4471"), "admin", "t-other")
        self.client = TestClient(app)
        self.relative = Path("tmp") / f"d2-estate-{os.getpid()}-{id(self)}"
        self.folder = ROOT / self.relative
        self.folder.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.folder, True)
        (self.folder / "customers.txt").write_text(
            "Customer contact sheet\nEmail: ana.mammadova@example.com\nEmail: stranger@example.org\n"
            "Phone: +994 50 123 45 67\n", encoding="utf-8")

    def as_(self, user: str, tenant: str, *, mfa: bool = True) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, 'admin', tenant, mfa_verified=mfa)}"}

    def upload(self, values, entity_type="EMAIL_ADDRESS", tenant="t-edm", user="edm-admin", name="Customers"):
        return self.client.post("/api/exact-match/sets", headers=self.as_(user, tenant),
                                json={"name": name, "entity_type": entity_type, "values": list(values)})

    def scan(self) -> dict:
        with mock.patch("backend.app.partitioned_scans_enabled", return_value=False):
            response = self.client.post("/api/scan", headers=self.as_("edm-admin", "t-edm"), json={
                "local_path": self.relative.as_posix(), "async_scan": False, "save_report": True,
                "compact_result": False, "incremental_enabled": False, "compliance_enabled": True,
                "compliance_frameworks": ["gdpr"]})
        self.assertEqual(response.status_code, 200, response.text[:400])
        return response.json()

    def gdpr_finding(self, report: dict, finding_type: str) -> dict:
        # B7 merges what several detectors found in one value into one finding of the
        # strongest type ("email"), and records each detector in detected_by.
        for file_obj in report.get("files") or []:
            for finding in file_obj.get("findings") or []:
                if finding_type in (finding.get("type"), *(finding.get("detected_by") or ())):
                    return finding
        self.fail(f"no {finding_type} finding")


class TheReferenceSetTest(ExactMatchCase):

    def test_a_listed_value_is_confirmed_and_an_unlisted_one_is_not(self) -> None:
        self.assertEqual(self.upload(["Ana.Mammadova@Example.com "]).status_code, 200)
        report = self.scan()
        email = self.gdpr_finding(report, "gdpr_email_address")
        self.assertEqual(email["confidence_tier"], "CONFIRMED")
        self.assertEqual(email["exact_match"], {"sets": ["Customers"], "matched_values": 1},
                         "one of the file's two addresses is listed")
        self.assertEqual(report["scan_diagnostics"]["exact_match"]["confirmed_findings"], 1)

    def test_a_phone_matches_whatever_its_formatting(self) -> None:
        self.assertEqual(self.upload(["00994 (50) 123-45-67"], entity_type="PHONE_NUMBER").status_code, 200)
        self.assertEqual(self.gdpr_finding(self.scan(), "gdpr_phone_number")["confidence_tier"], "CONFIRMED")

    def test_no_set_confirms_nothing(self) -> None:
        self.assertNotEqual(self.gdpr_finding(self.scan(), "gdpr_email_address")["confidence_tier"], "CONFIRMED")

    def test_the_matching_fingerprints_reach_no_report_or_row(self) -> None:
        self.upload(["ana.mammadova@example.com"])
        report = self.scan()
        self.assertNotIn("edm_fingerprints", json.dumps(report, default=str), "the scan's response")
        stored = store.read_scan_report("t-edm", report.get("scan_id"))
        self.assertIsNotNone(stored)
        self.assertNotIn("edm_fingerprints", json.dumps(stored, default=str), "the stored report body")
        with store._connect() as conn:
            dumped = json.dumps([dict(row) for table in ("findings", "finding_index", "assets", "scan_reports")
                                 for row in conn.execute(f"SELECT * FROM {table}").fetchall()], default=str)
        self.assertNotIn("edm_fingerprints", dumped)

    def test_deleting_the_set_ends_the_confirmation(self) -> None:
        set_id = self.upload(["ana.mammadova@example.com"]).json()["set_id"]
        self.assertEqual(self.client.delete(f"/api/exact-match/sets/{set_id}", headers=self.as_("edm-admin", "t-edm")).status_code, 200)
        self.assertNotEqual(self.gdpr_finding(self.scan(), "gdpr_email_address")["confidence_tier"], "CONFIRMED")

    def test_a_set_built_with_another_key_is_shown_stale_and_matches_nothing(self) -> None:
        self.upload(["ana.mammadova@example.com"])
        with mock.patch.object(exact_match, "key_digest", return_value="another-key-000"):
            listed = self.client.get("/api/exact-match/sets", headers=self.as_("edm-admin", "t-edm")).json()["sets"]
            self.assertEqual([item["current"] for item in listed], [False])
            self.assertEqual(store.exact_match_index_for_scan("t-edm", "another-key-000"), {})

    def test_the_set_changes_the_reuse_signature(self) -> None:
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        before = DSPMDiscoveryEngine(ScanConfig(tenant_id="t-edm", local_path=".")).version_signature()
        self.upload(["ana.mammadova@example.com"])
        index = store.exact_match_index_for_scan("t-edm", exact_match.key_digest())
        after = DSPMDiscoveryEngine(ScanConfig(tenant_id="t-edm", local_path=".", exact_match=index)).version_signature()
        self.assertNotEqual(before, after)


class TheScanKeysWithItsWorkspaceTest(ExactMatchCase):
    """The detectors were given the collector record, which carries no workspace, and
    fingerprinted every value in every workspace with "default"."""

    def fingerprints(self, tenant: str) -> set[str]:
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        report = DSPMDiscoveryEngine(ScanConfig(
            tenant_id=tenant, local_path=str(self.folder),
            compliance_enabled=True, compliance_frameworks=["gdpr"], incremental_enabled=False,
            persistent_cache_enabled=False)).run().to_dict()
        # The canonical entity fingerprints are the workspace-keyed ones; the generic
        # detector's counting fingerprints are keyed by the install alone (SC-3).
        prints = {str(item) for file_obj in report["files"] for finding in file_obj.get("findings") or []
                  for item in finding.get("canonical_entity_fingerprints") or []}
        self.assertTrue(prints, "the file's values were fingerprinted")
        return prints

    def test_the_same_file_fingerprints_differently_in_each_workspace(self) -> None:
        self.assertEqual(self.fingerprints("t-edm") & self.fingerprints("t-other"), set())

    def test_the_stage_is_given_the_scans_workspace_not_the_records(self) -> None:
        from discovery.detector_stage import run_detector_stage

        def prints(payload: dict) -> set[str]:
            found = run_detector_stage({"content": "Email: ana.mammadova@example.com", "record": {"path": "a.txt"},
                                        "framework_ids": ["gdpr"], "compliance_enabled": True, **payload})["findings"]
            return {str(item) for finding in found for item in finding.get("secure_fingerprints") or []}

        self.assertEqual(prints({"tenant_id": "t-edm"}) & prints({}), set())
        self.assertEqual(prints({"tenant_id": "default"}), prints({}))

    def test_findings_cached_by_the_old_stage_are_not_replayed(self) -> None:
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        def signature() -> str:
            return DSPMDiscoveryEngine(ScanConfig(tenant_id="t-edm", local_path=".")).version_signature()

        current = signature()
        with mock.patch("discovery.discovery_engine.DETECTOR_STAGE_VERSION", "detector-stage-record-tenant"):
            self.assertNotEqual(signature(), current)


class NothingOfTheValuesIsKeptTest(ExactMatchCase):

    def test_no_value_and_no_unsalted_hash_is_stored_returned_or_audited(self) -> None:
        values = ["ana.mammadova@example.com", "leyla.aliyeva@example.org"]
        created = self.upload(values)
        self.assertEqual(created.status_code, 200)
        self.assertEqual(created.json()["values"], 2)
        listed = self.client.get("/api/exact-match/sets", headers=self.as_("edm-admin", "t-edm")).text
        with store._connect() as conn:
            dumped = json.dumps([dict(row) for table in ("edm_sets", "edm_fingerprints", "audit_events")
                                 for row in conn.execute(f"SELECT * FROM {table}").fetchall()], default=str)
        with store._connect() as conn:
            kept = [row["fingerprint"] for row in conn.execute("SELECT fingerprint FROM edm_fingerprints").fetchall()]
            audited = json.dumps([dict(row) for row in conn.execute("SELECT * FROM audit_events").fetchall()], default=str)
        self.assertEqual(len(kept), 2)
        for fingerprint in kept:
            for text in (created.text, listed, audited):
                self.assertNotIn(fingerprint, text, "a keyed fingerprint is not returned or audited either")
        for value in values:
            normalized = exact_match.normalize("EMAIL_ADDRESS", value)
            for text in (created.text, listed, dumped):
                self.assertNotIn(value, text)
                self.assertNotIn(hashlib.sha256(value.encode()).hexdigest(), text)
                self.assertNotIn(hashlib.sha256(normalized.encode()).hexdigest(), text)
                self.assertNotIn(hashlib.md5(normalized.encode()).hexdigest(), text)  # noqa: S324 - looking for one
        self.assertNotIn("fingerprint", listed)

    def test_the_same_value_fingerprints_differently_in_each_workspace(self) -> None:
        self.assertNotEqual(exact_match.fingerprint("EMAIL_ADDRESS", "a@example.com", "t-edm"),
                            exact_match.fingerprint("EMAIL_ADDRESS", "a@example.com", "t-other"))

    def test_another_workspaces_set_neither_matches_nor_shows(self) -> None:
        self.upload(["ana.mammadova@example.com"], tenant="t-other", user="other-admin", name="Theirs")
        self.assertNotEqual(self.gdpr_finding(self.scan(), "gdpr_email_address")["confidence_tier"], "CONFIRMED")
        self.assertEqual(self.client.get("/api/exact-match/sets", headers=self.as_("edm-admin", "t-edm")).json()["sets"], [])

    def test_uploading_needs_a_verified_session_and_a_known_type(self) -> None:
        response = self.client.post("/api/exact-match/sets", headers=self.as_("edm-admin", "t-edm", mfa=False),
                                    json={"name": "x", "entity_type": "EMAIL_ADDRESS", "values": ["a@example.com"]})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.upload(["x"], entity_type="SHOE_SIZE").status_code, 400)

    def test_a_workspace_holds_no_more_values_than_configured(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_EDM_MAX_ROWS": "2"}):
            self.assertEqual(self.upload(["a@example.com", "b@example.com"]).status_code, 200)
            self.assertEqual(self.upload(["c@example.com"], name="More").status_code, 400)
        self.assertEqual(len(store.list_edm_sets("t-edm")), 1)

    def test_erasing_the_workspace_erases_its_sets(self) -> None:
        self.upload(["ana.mammadova@example.com"])
        with store._connect() as conn:
            store._delete_tenant_scoped_data(conn, "t-edm")
        self.assertEqual(store.list_edm_sets("t-edm"), [])
        with store._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) AS n FROM edm_fingerprints WHERE tenant_id = 't-edm'").fetchone()["n"], 0)


if __name__ == "__main__":
    unittest.main()
