"""Specifications written in the 2026-10 detection audit and not yet implemented (see the skip).
"""
from __future__ import annotations

import re
import time
import unittest

from backend.reporting.posture import PostureInputs, compute_posture
from backend.reporting.remediation_policy import categorize_risk_types, has_credential_type
from backend.reporting.report_model import build_report_model
from classification import masking
from classification.compliance.canonical_model import apply_canonical_finding_model
from classification.compliance.gdpr_classifier import classify_gdpr_content
from classification.compliance.gdpr_rules import detect_payment_card_data
from classification.compliance.nist_classifier import _masked_preview, classify_nist_content
from classification.compliance.pci_classifier import classify_pci_content
from classification.compliance.validators import DATABASE_URI_RE, DB_KV_CONNECTION_RE
from classification.pan_validator import pan_hits
from classification.regex_classifier import RULES, classify_content
from discovery.finding_merge import merge_findings
from risk.risk_engine import RISK_RULE_DESCRIPTIONS, calculate_risk, get_level

FILE = {"name": "notes.txt", "path": r"C:\Data\notes.txt", "extension": ".txt", "size": 4096}


def _types(findings: list[dict]) -> dict[str, dict]:
    return {finding["type"]: finding for finding in findings}


def _cards(text: str) -> list[str]:
    return [hit.verdict.digits for hit in pan_hits(text)]


import pytest

pytest.skip("Deferred from the 2026-10 detection audit: file risk-score bands, remediation categories, PCI composites, report posture and value counting change scores across the product and are scheduled as their own change, not Wave 1 (docs/SCALING_ROADMAP_2026-10.md).", allow_module_level=True)

class AFilesScoreSaysWhatItsFindingsSayTest(unittest.TestCase):
    """CRITICAL findings were floored at 90 and then capped by min(sensitivity, 80), so no
    file could be CRITICAL from its content - while LOW findings added without a cap and
    twenty of them made a file HIGH. RISK_RULE_DESCRIPTIONS documented "Minimum 90"."""

    def _risk(self, findings: list[dict], acl: dict | None = None) -> dict:
        return calculate_risk(dict(FILE), findings, acl or {}).to_dict()

    def test_a_private_key_alone_is_critical(self) -> None:
        risk = self._risk([{"type": "private_key", "risk": "CRITICAL", "count": 1}])
        self.assertEqual(risk["level"], "CRITICAL")
        self.assertGreaterEqual(risk["score"], 90)

    def test_card_and_cvv_are_critical(self) -> None:
        risk = self._risk([
            {"type": "pci_chd_pan", "risk": "CRITICAL", "framework": "pci_dss", "category": "pci_cardholder_data"},
            {"type": "pci_sad_cvv", "risk": "CRITICAL", "framework": "pci_dss", "category": "pci_sensitive_authentication_data"},
            {"type": "pci_composite_sad", "risk": "CRITICAL", "framework": "pci_dss", "category": "pci_sensitive_authentication_data"},
        ])
        self.assertEqual(risk["level"], "CRITICAL")

    def test_a_pile_of_low_findings_stays_low(self) -> None:
        risk = self._risk([{"type": f"low_signal_{index}", "risk": "LOW", "count": 1} for index in range(20)])
        self.assertEqual(risk["level"], "LOW")

    def test_a_pile_of_medium_findings_stays_medium(self) -> None:
        risk = self._risk([{"type": f"medium_signal_{index}", "risk": "MEDIUM", "count": 5} for index in range(20)])
        self.assertEqual(risk["level"], "MEDIUM")

    def test_a_high_finding_is_high(self) -> None:
        risk = self._risk([{"type": "password", "risk": "HIGH", "count": 1}])
        self.assertEqual(risk["level"], "HIGH")

    def test_access_can_still_raise_a_file_above_its_content(self) -> None:
        risk = self._risk([{"type": "email", "risk": "LOW", "count": 1}], {"score": 90, "issues": ["Everyone has write access"]})
        self.assertEqual(risk["level"], "CRITICAL")

    def test_every_documented_minimum_90_holds(self) -> None:
        for rule in RISK_RULE_DESCRIPTIONS:
            if rule["score"] != "Minimum 90":
                continue
            for finding_type in rule["findings"]:
                with self.subTest(finding_type=finding_type):
                    risk = self._risk([{"type": finding_type, "risk": "CRITICAL", "count": 1}])
                    self.assertGreaterEqual(risk["score"], 90)


class RemediationKnowsTheTypesTheDetectorsEmitTest(unittest.TestCase):
    """The policy's category sets named types the detectors never emit, so a GitHub token
    got the cautious "unknown" steps and so did every pci_* and gdpr_* finding."""

    def test_credentials(self) -> None:
        self.assertEqual(categorize_risk_types(["github_token", "aws_secret_key", "stripe_key", "database_uri", "slack_token"]),
                         ["credential"])

    def test_payment_and_banking(self) -> None:
        for name in ("pci_chd_pan", "pci_sad_cvv", "pci_composite_sad", "swift_bic", "routing_account", "iban"):
            with self.subTest(name=name):
                self.assertEqual(categorize_risk_types([name]), ["financial"])

    def test_personal(self) -> None:
        for name in ("gdpr_email_address", "passport_number", "azerbaijan_fin", "gdpr_passport_number"):
            with self.subTest(name=name):
                self.assertEqual(categorize_risk_types([name]), ["personal"])

    def test_a_personal_type_is_no_credential(self) -> None:
        self.assertFalse(has_credential_type(["gdpr_email_address", "confidential_keyword", "board_context"]))

    def test_an_unknown_type_is_still_unknown(self) -> None:
        self.assertEqual(categorize_risk_types(["something_new"]), ["unknown"])


class AFilesActionsFollowItsFindingsTest(unittest.TestCase):
    """`"key" in type` told a document marked CONFIDENTIAL to rotate secrets, and a file
    holding only PCI findings got no regulated-data actions at all."""

    def _actions(self, findings: list[dict]) -> list[str]:
        return calculate_risk(dict(FILE), findings, {}).to_dict()["remediation"]["actions"]

    def test_a_confidential_document_has_no_secret_to_rotate(self) -> None:
        actions = self._actions([{"type": "confidential_keyword", "risk": "MEDIUM"}, {"type": "board_context", "risk": "MEDIUM"}])
        self.assertNotIn("Rotate exposed secret", actions)

    def test_credentials_are_rotated(self) -> None:
        for finding_type in ("private_key", "connection_string", "github_token", "mfa_recovery_context"):
            with self.subTest(finding_type=finding_type):
                self.assertIn("Rotate exposed secret", self._actions([{"type": finding_type, "risk": "HIGH"}]))

    def test_payment_data_is_regulated_data(self) -> None:
        actions = self._actions([{"type": "pci_chd_pan", "risk": "CRITICAL", "framework": "pci_dss",
                                  "category": "pci_cardholder_data"}])
        self.assertIn("Apply regulated-data label", actions)


class AFindingsRiskScoreStaysInItsBandTest(unittest.TestCase):
    """risk_score was max(severity score, confidence) - two scales in one number - and the
    remediation queue sorts on it, so a LOW finding at confidence 92 outranked a HIGH one."""

    def _score(self, severity: str, confidence: int) -> int:
        finding = {"type": "x", "risk": severity, "confidence": confidence}
        return apply_canonical_finding_model(finding, dict(FILE))["risk_score"]

    def test_severity_orders_the_queue(self) -> None:
        self.assertLess(self._score("LOW", 92), self._score("HIGH", 60))
        self.assertLess(self._score("MEDIUM", 95), self._score("CRITICAL", 40))

    def test_confidence_orders_within_a_severity(self) -> None:
        self.assertGreater(self._score("HIGH", 95), self._score("HIGH", 40))

    def test_a_score_never_leaves_its_band(self) -> None:
        for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            for confidence in (0, 40, 60, 70, 85, 100):
                with self.subTest(severity=severity, confidence=confidence):
                    self.assertEqual(get_level(self._score(severity, confidence)), severity)


class ACompositeIsNoSurerThanItsCardTest(unittest.TestCase):
    """A number with no issuer, guessed at LOW confidence and capped at MEDIUM, came back
    as a CRITICAL PAN+SAD composite at confidence 90 - undoing the cap."""

    def test_a_guessed_card_makes_a_capped_composite(self) -> None:
        findings = _types(classify_pci_content("card 1234 5678 9012 3452 cvv 123 cardholder name: John Smith",
                                               {"name": "a.txt", "extension": ".txt"}))
        pan = findings["pci_chd_pan"]
        self.assertEqual(pan["pan_confidence"], "LOW")
        for composite in ("pci_composite_sad", "pci_enriched_chd_record"):
            with self.subTest(composite=composite):
                self.assertEqual(findings[composite]["risk"], "MEDIUM")
                self.assertEqual(findings[composite]["confidence"], pan["confidence"])

    def test_a_confirmed_card_still_makes_a_critical_composite(self) -> None:
        findings = _types(classify_pci_content("card number 4111 1111 1111 1111 cvv 123",
                                               {"name": "a.txt", "extension": ".txt"}))
        self.assertEqual(findings["pci_composite_sad"]["risk"], "CRITICAL")


class TheReportScoresPostureLikeTheConsoleTest(unittest.TestCase):
    """The report called every CRITICAL or HIGH file broadly readable, so the same estate
    scored 35 in the PDF and 60 in the console; and its detail line called weighted points
    "critical-equivalents" when a critical weighs eight."""

    def _files(self, exposed: int) -> list[dict]:
        files = []
        for index in range(10):
            state = "BROAD_INTERNAL" if index < exposed else "UNKNOWN"
            files.append({"name": f"f{index}.txt", "path": f"/f{index}.txt", "risk": {"level": "HIGH", "score": 80},
                          "findings": [{"type": "email", "exposure_state": state}]})
        for index in range(10):
            files.append({"name": f"g{index}.txt", "path": f"/g{index}.txt", "risk": {"level": "NONE", "score": 0},
                          "findings": []})
        return files

    def _expected(self, exposed: int) -> int:
        return compute_posture(PostureInputs(analysed_files=20, findings_by_severity={"high": 10}, sensitive_files=10,
                                             exposed_sensitive_files=exposed, active_findings=10)).total_score

    def test_only_exposed_files_cost_exposure_points(self) -> None:
        for exposed in (0, 4, 10):
            with self.subTest(exposed=exposed):
                self.assertEqual(build_report_model({"files": self._files(exposed)})["posture"]["score"], self._expected(exposed))
        self.assertGreater(self._expected(0), self._expected(10))

    def test_critical_equivalents_are_criticals(self) -> None:
        posture = compute_posture(PostureInputs(analysed_files=1000, findings_by_severity={"critical": 5}))
        detail = next(term.detail for term in posture.terms if term.key == "findings")
        self.assertIn("(5.0 critical-equivalents per 1,000 files)", detail)


class AStructuredFileCountsEachValueOnceTest(unittest.TestCase):
    """For CSV, TSV and XLSX the content pass and the structured-row pass both read every
    row, and their counts were added: two cards counted four, two CVVs three."""

    def test_two_cards_and_two_cvvs(self) -> None:
        csv = "name,card_number,expiry,cvv\nJohn Smith,4111111111111111,12/27,123\nJane Doe,5555555555554444,11/28,456\n"
        findings = _types(classify_pci_content(csv, {"name": "cards.csv", "extension": ".csv"}))
        self.assertEqual(findings["pci_chd_pan"]["count"], 2)
        self.assertEqual(findings["pci_sad_cvv"]["count"], 2)

    def test_cvv_as_the_last_column(self) -> None:
        csv = "card_number,cvv\n4111111111111111,123\n5555555555554444,456\n"
        findings = _types(classify_pci_content(csv, {"name": "cards.csv", "extension": ".csv"}))
        self.assertEqual(findings["pci_chd_pan"]["count"], 2)
        self.assertEqual(findings["pci_sad_cvv"]["count"], 2)


class UniqueValuesAreCountedOverEveryMatchTest(unittest.TestCase):
    """The distinct count came from the fingerprints of the first ten samples only."""

    def _unique(self, text: str) -> int:
        return _types(classify_content(text))["email"]["unique_value_count"]

    def test_fifty_distinct_emails(self) -> None:
        self.assertEqual(self._unique(" ".join(f"user{index}@example.com" for index in range(50))), 50)

    def test_ten_copies_then_forty_distinct(self) -> None:
        text = " ".join(["same@example.com"] * 10 + [f"user{index}@example.com" for index in range(40)])
        self.assertEqual(self._unique(text), 41)

    def test_samples_are_still_capped(self) -> None:
        finding = _types(classify_content(" ".join(f"user{index}@example.com" for index in range(50))))["email"]
        self.assertEqual(len(finding["samples"]), 10)
        self.assertEqual(finding["count"], 50)
