"""M0/Q4: what an exported report contains today, written down before C9 changes it.

The PDF is the artifact that leaves the building. It is attached to tickets, mailed to
auditors and filed by customers, so what is NOT in it matters as much as what is: no
cardholder data, no full share paths. Those two exclusions are not obvious from reading
the renderer - they come from the report model only carrying a whitelist of fields - so
they are asserted here against a real generated file rather than against the model.

These go through the whole path (a saved scan in the database -> create_report_artifact
-> a file on disk read back with pypdf) because that is the path C9 will refactor, and a
test of the renderer alone would not notice if the caller started handing it more.

Tests marked GAP pin behaviour a C-item is meant to change.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pypdf import PdfReader

from backend import security, store
from backend.reporting import artifacts
from backend.reporting.report_model import report_title
from backend.reporting.report_pdf import (
    HEADLINE_WIDTH,
    REPORT_TEMPLATE_ID,
    _fitted_headline,
)
from backend.security import Principal, verify_artifact_download_token

PAN = "4111111111111111"
SHARE_FOLDER = "PayrollVault"
TENANT = "tenant-report"
SCAN_ID = "scan-report-001"


def _report() -> dict:
    return {
        "scan_id": SCAN_ID,
        "timestamp": "2026-09-22T09:00:00+00:00",
        "source": "local",
        "summary": {"total_files": 3},
        "files": [
            {
                "name": "cards.csv",
                "path": rf"C:\{SHARE_FOLDER}\Q3\cards.csv",
                "source": "local",
                # A preview is what the scanner actually carries around; the report
                # model must not forward it into the export.
                "preview": f"card_number,{PAN},Jane Roe",
                "risk": {
                    "level": "CRITICAL",
                    "score": 94,
                    "reasons": ["Cardholder data in an open share"],
                    "remediation": {"actions": ["Restrict the share", "Tokenise the column"]},
                },
                "findings": [{"type": "pci_chd_pan", "count": 2, "redacted_sample": "411111******1111"}],
            },
            {
                "name": "müştəri_siyahısı.csv",
                "path": r"\\fs01\HR\müştəri_siyahısı.csv",
                "source": "smb",
                "risk": {"level": "HIGH", "score": 71, "reasons": ["Personal data"],
                         "remediation": {"actions": ["Review access"]}},
                "findings": [{"type": "pii_name", "count": 5}],
            },
            {
                "name": "отчет_2026.csv",
                "path": r"\\fs01\HR\отчет_2026.csv",
                "source": "smb",
                "risk": {"level": "MEDIUM", "score": 44, "reasons": ["Internal data"],
                         "remediation": {"actions": ["Review owner"]}},
                "findings": [{"type": "pii_email", "count": 1}],
            },
        ],
    }


class _ExportCase(unittest.TestCase):
    """One saved scan, one analyst, an artifact directory of this test's own."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)

        original_db = store.DB_PATH
        store.DB_PATH = root / "reports.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original_db))
        store.init_db()
        store.create_tenant(TENANT, "Report")
        store.save_scan_history(TENANT, _report())

        # ARTIFACT_ROOT is resolved at import from DATA_DIR, so it has to be patched
        # rather than pointed at with an environment variable.
        patcher = mock.patch.object(artifacts, "ARTIFACT_ROOT", root / "artifacts")
        patcher.start()
        self.addCleanup(patcher.stop)

        # C8: a download token is bound to the account and the session that minted it,
        # so the principal behind an export is a real account with a live session.
        store.create_user("analyst-1", security.hash_password("an-analyst-1"), "analyst", TENANT)
        session = security.create_token("analyst-1", "analyst", TENANT)
        self.principal = security.verify_token(session)
        self.session = session

    def _export(self, **kwargs) -> dict:
        return artifacts.create_report_artifact(self.principal, {}, scan_id=SCAN_ID, **kwargs)

    def _files(self, artifact_id: str) -> tuple[Path, Path, Path]:
        directory = artifacts.ARTIFACT_ROOT / TENANT / "artifacts" / "analyst-1"
        return (directory / f"{artifact_id}.pdf",
                directory / f"{artifact_id}.html",
                directory / f"{artifact_id}.json")

    def _pdf_text(self, pdf: Path) -> str:
        reader = PdfReader(str(pdf))
        self.pages_read = len(reader.pages)
        return "\n".join(page.extract_text() or "" for page in reader.pages)


class AnExportedReportTest(_ExportCase):

    def setUp(self) -> None:
        super().setUp()
        self.artifact = self._export()
        self.pdf, self.html, self.metadata_file = self._files(self.artifact["artifact_id"])

    def test_all_three_files_are_written(self) -> None:
        self.assertRegex(self.artifact["artifact_id"], r"^[a-f0-9]{32}$")
        for path in (self.pdf, self.html, self.metadata_file):
            with self.subTest(path.suffix):
                self.assertTrue(path.is_file(), f"{path.name} was not written")
        self.assertTrue(self.pdf.read_bytes().startswith(b"%PDF-1.4"))

    def test_the_pdf_opens_and_has_the_pages_the_metadata_claims(self) -> None:
        text = self._pdf_text(self.pdf)
        self.assertEqual(self.pages_read, self.artifact["page_count"])
        self.assertGreaterEqual(self.pages_read, 3, "summary, response plan, evidence register")
        self.assertTrue(text.strip(), "a PDF that opens but has no extractable text is not a report")

    def test_it_names_every_scanned_file_with_its_risk_and_signals(self) -> None:
        text = self._pdf_text(self.pdf)
        for expected in ("Evidence register", "cards.csv", "CRITICAL", "Score 94",
                         "pci_chd_pan: 2", "Restrict the share", "pii_name: 5"):
            with self.subTest(expected):
                self.assertIn(expected, text)
        self.assertIn("rows 1-3 of 3", text, "every scoped file belongs in the register")

    def test_no_scanned_value_and_no_share_path_reaches_the_export(self) -> None:
        raw = self.pdf.read_bytes()
        text = self._pdf_text(self.pdf)
        self.assertNotIn(PAN, text)
        self.assertNotIn(PAN.encode(), raw, "the sample must not survive anywhere in the file")
        self.assertNotIn("Jane Roe", text, "the preview line must not be forwarded")
        self.assertNotIn(SHARE_FOLDER, text)
        self.assertNotIn(SHARE_FOLDER.encode(), raw, "SC-13: file names only, never the full path")
        self.assertNotIn(b"fs01", raw)

    def test_the_html_twin_shows_the_same_and_no_more(self) -> None:
        html = self.html.read_text(encoding="utf-8")
        self.assertIn("cards.csv", html)
        self.assertNotIn(PAN, html)
        self.assertNotIn(SHARE_FOLDER, html)
        # Unlike the PDF, the HTML is UTF-8 and keeps the name as it was scanned.
        self.assertIn("müştəri_siyahısı.csv", html)

    def test_the_metadata_names_the_one_shared_template(self) -> None:
        self.assertEqual(self.artifact["template_id"], REPORT_TEMPLATE_ID)
        self.assertEqual(self.artifact["render_style"], "visual_composer")
        self.assertEqual(self.artifact["source_scan_id"], SCAN_ID)
        self.assertEqual(self.artifact["scope"]["kind"], "full")
        self.assertFalse(self.artifact["truncated"])
        self.assertEqual(self.artifact["original_line_count"], 3)
        self.assertEqual(self.artifact["included_line_count"], 3)
        self.assertEqual(self.artifact["filename"], f"dspm_report_{SCAN_ID}.pdf")
        self.assertRegex(self.artifact["filename"], r"^[A-Za-z0-9_.-]+$")


class TheDocumentIsNamedTest(_ExportCase):
    """M0/Q5: the title the code composes reaches the document.

    It used to be built in `create_report_artifact` and dropped on the floor: the
    model hard-coded an unscoped title, the PDF hard-coded the same string on its
    cover, and the file itself carried no title at all - so a reader showed the
    32-character storage id, and so did anything that indexed the file.
    """

    def setUp(self) -> None:
        super().setUp()
        self.artifact = self._export()
        self.pdf, self.html, _ = self._files(self.artifact["artifact_id"])

    def test_the_metadata_carries_the_title(self) -> None:
        self.assertEqual(self.artifact["title"], report_title(self.artifact["scope"]))
        self.assertEqual(self.artifact["title"], "DSPM Assessment Report")

    def test_the_pdf_says_what_it_is_in_its_own_information_dictionary(self) -> None:
        reader = PdfReader(str(self.pdf))
        self.assertEqual(reader.metadata.title, self.artifact["title"])
        self.assertEqual(reader.metadata.author, "SENTRO DSPM")
        self.assertIn(SCAN_ID, reader.metadata.subject)
        self.assertIn(REPORT_TEMPLATE_ID, reader.metadata.creator)

    def test_the_cover_prints_the_same_title(self) -> None:
        self.assertIn(self.artifact["title"], self._pdf_text(self.pdf))

    def test_the_html_head_and_heading_carry_it_too(self) -> None:
        html = self.html.read_text(encoding="utf-8")
        self.assertIn(f"<title>{self.artifact['title']}</title>", html)
        self.assertIn(f"<h1>{self.artifact['title']}</h1>", html)

    def test_a_scoped_export_is_a_differently_named_document(self) -> None:
        scoped = self._export(filter_severity="CRITICAL")
        self.assertNotEqual(scoped["title"], self.artifact["title"])
        self.assertIn(scoped["scope_label"], scoped["title"])
        pdf, html, _ = self._files(scoped["artifact_id"])
        self.assertEqual(PdfReader(str(pdf)).metadata.title, scoped["title"])
        self.assertIn(f"<title>{scoped['title']}</title>", html.read_text(encoding="utf-8"))

    def test_a_long_scope_name_does_not_run_into_the_scan_id(self) -> None:
        # The cover headline shrinks to fit its band rather than wrapping into the
        # line below it or colliding with the block on the right, and a title too
        # long even at the smallest size is cut rather than allowed to overlap.
        for label in ("Full scan", "Critical severity", "A" * 70):
            with self.subTest(label=label):
                title = report_title({"label": label})
                headline, size = _fitted_headline(title, HEADLINE_WIDTH, 25, 14)
                self.assertLessEqual(len(headline) * size * 0.52, HEADLINE_WIDTH + 0.01)
                self.assertGreaterEqual(size, 14)
                self.assertTrue(title.startswith(headline.rstrip('.')),
                                "the headline must be the title, not a different string")


class TheDownloadCredentialTest(_ExportCase):

    def test_the_token_it_hands_back_opens_this_artifact_and_no_other(self) -> None:
        artifact = self._export()
        self.assertIsNone(verify_artifact_download_token(artifact["download_token"], "c" * 32))
        principal = verify_artifact_download_token(artifact["download_token"], artifact["artifact_id"])
        self.assertIsNotNone(principal)
        self.assertEqual((principal.subject, principal.tenant_id, principal.role),
                         ("analyst-1", TENANT, "analyst"))

    def test_it_opens_the_artifact_once(self) -> None:
        # C8: single use. The console fetches exactly once, with the header.
        artifact = self._export()
        self.assertIsNotNone(verify_artifact_download_token(artifact["download_token"], artifact["artifact_id"]))
        self.assertIsNone(verify_artifact_download_token(artifact["download_token"], artifact["artifact_id"]))

    def test_it_is_bound_to_the_session_that_asked_for_the_report(self) -> None:
        artifact = self._export()
        security.revoke_token(self.session)
        store._forget_revocation()
        self.assertIsNone(verify_artifact_download_token(artifact["download_token"], artifact["artifact_id"]),
                          "signing out must end the link as well")

    def test_no_url_it_returns_carries_the_token(self) -> None:
        # C8, the opposite of what Q4 pinned: a query string is written to every proxy
        # and access log on the path, so the addresses are plain and the token travels
        # only in the X-Artifact-Token header.
        artifact = self._export()
        path = f"/api/v1/reports/artifacts/{artifact['artifact_id']}"
        self.assertEqual(artifact["artifact_path"], path)
        self.assertEqual(artifact["download_url"], path)
        self.assertEqual(artifact["preview_url"], f"{path}?inline=1")
        self.assertEqual(artifact["html_download_url"], f"{path}?format=html")
        for key in ("download_url", "preview_url", "html_download_url", "artifact_path"):
            with self.subTest(key):
                self.assertNotIn("dl_token", artifact[key])
                self.assertNotIn(artifact["download_token"], artifact[key])

    def test_the_token_is_never_written_beside_the_artifact(self) -> None:
        # It is a five-minute credential. On disk it would outlive its purpose in a
        # file anyone with read access to the data directory can open.
        artifact = self._export()
        persisted_text = self._files(artifact["artifact_id"])[2].read_text(encoding="utf-8")
        self.assertNotIn(artifact["download_token"], persisted_text)
        self.assertNotIn("dl_token", persisted_text)
        persisted = json.loads(persisted_text)
        self.assertEqual([key for key in persisted if key.endswith("_url")], [])
        self.assertEqual(persisted["artifact_path"], artifact["artifact_path"])

    def test_the_caller_is_not_told_where_the_files_are_stored(self) -> None:
        artifact = self._export()
        for hidden in ("storage_filename", "html_storage_filename", "media_type"):
            with self.subTest(hidden):
                self.assertNotIn(hidden, artifact)
        stored = artifacts.load_artifact_metadata(self.principal, artifact["artifact_id"])
        self.assertEqual(stored["storage_filename"], f"{artifact['artifact_id']}.pdf")


class WhoCanReadAnArtifactTest(_ExportCase):

    def test_the_owner_resolves_the_file(self) -> None:
        artifact = self._export()
        path, metadata = artifacts.artifact_file(self.principal, artifact["artifact_id"])
        self.assertTrue(path.is_file())
        self.assertEqual(metadata["artifact_id"], artifact["artifact_id"])
        html_path, _ = artifacts.artifact_file(self.principal, artifact["artifact_id"], format="html")
        self.assertEqual(html_path.suffix, ".html")

    def test_another_tenant_and_another_user_find_nothing(self) -> None:
        artifact = self._export()
        for description, principal in (
            ("another tenant", Principal("analyst-1", "analyst", "tenant-b")),
            ("another user in the same tenant", Principal("analyst-2", "admin", TENANT)),
        ):
            with self.subTest(description):
                self.assertIsNone(artifacts.load_artifact_metadata(principal, artifact["artifact_id"]))
                self.assertIsNone(artifacts.artifact_file(principal, artifact["artifact_id"]))

    def test_an_artifact_id_that_is_not_one_is_refused_before_touching_the_disk(self) -> None:
        for bogus in ("", "../../etc/passwd", "a" * 31, "A" * 32, "g" * 32, "../" + "a" * 29):
            with self.subTest(bogus=bogus):
                self.assertIsNone(artifacts.load_artifact_metadata(self.principal, bogus))


class AScopedExportTest(_ExportCase):

    def test_a_severity_scope_narrows_the_register_and_is_said_in_the_name(self) -> None:
        artifact = self._export(filter_severity="CRITICAL")
        self.assertEqual(artifact["scope"]["kind"], "severity")
        self.assertTrue(artifact["filter_severity"], "a scoped export has to say what it left out")
        self.assertIn("critical", artifact["filename"].lower())
        text = self._pdf_text(self._files(artifact["artifact_id"])[0])
        self.assertIn("cards.csv", text)
        self.assertIn("rows 1-1 of 1", text)
        self.assertNotIn("siyahisi", text, "a HIGH file has no place in a CRITICAL-scoped export")

    def test_the_full_picture_is_still_reported_alongside_the_scope(self) -> None:
        # The scoped register is not the whole estate, and the summary page must not
        # let a reader mistake one for the other.
        artifact = self._export(filter_severity="CRITICAL")
        text = self._pdf_text(self._files(artifact["artifact_id"])[0])
        self.assertIn("ALL FILES", text)
        self.assertIn("IN SCOPE", text)

    def test_exporting_without_a_scan_is_an_error_the_caller_can_show(self) -> None:
        with self.assertRaises(artifacts.ArtifactError) as failed:
            artifacts.create_report_artifact(Principal("analyst-1", "analyst", "tenant-empty"), {})
        self.assertIn("No DSPM scan report", str(failed.exception))


class WhatTheFontsCannotPrintTest(_ExportCase):
    """GAP (C9). The PDF is built on the base-14 fonts, which are Latin-1 only."""

    def test_azerbaijani_and_turkish_names_are_transliterated(self) -> None:
        # Deliberate, and the reason the export is readable for this customer at all:
        # the letters outside Latin-1 are mapped to their nearest ASCII form.
        text = self._pdf_text(self._files(self._export()["artifact_id"])[0])
        self.assertIn("musteri_siyahisi.csv", text)
        self.assertNotIn("müştəri", text)

    def test_any_other_script_becomes_question_marks(self) -> None:
        # A Cyrillic, Greek or CJK file name is unreadable in the export: it is
        # replaced character by character. C9 is where an embedded font decides
        # whether this stays a documented limit or becomes a bug.
        text = self._pdf_text(self._files(self._export()["artifact_id"])[0])
        self.assertNotIn("отчет", text)
        self.assertIn("_2026.csv", text)
        self.assertRegex(text, r"\?{3,}_2026\.csv")


if __name__ == "__main__":
    unittest.main()
