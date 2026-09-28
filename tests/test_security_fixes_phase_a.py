"""Six security fixes, one regression test each (A7).

Each of these is something a competent evaluator would have found in a week.
None is a remote takeover on its own; together they are the report a customer's
security team writes.
"""

from __future__ import annotations

import json
import os
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

import backend.security as security
from backend.security import create_token, verify_token
from backend.store import read_audit_log

def _age_session(jti: str) -> None:
    """Make a session look untouched for longer than the idle window.

    C1 moved last-seen into `user_sessions`, so the row is what a process reads the
    first time it sees a session - ageing the row and dropping the in-process record
    is what a restart into an abandoned session actually looks like.
    """
    from backend import store

    store.touch_session(jti, int(time.time() - (security.SESSION_IDLE_SECONDS + 60)))
    security._session_last_seen.pop(jti, None)


FRONTEND = Path("frontend")
APP_JS = (FRONTEND / "app.js").read_text(encoding="utf-8")
INDEX = (FRONTEND / "index.html").read_text(encoding="utf-8")


class S1LoginByLinkTests(unittest.TestCase):
    """A session token arriving in a URL fragment let anyone who could get a
    victim to open a link sign them into a session of the attacker's choosing."""

    def test_the_fragment_handoff_is_gone(self) -> None:
        self.assertFalse((FRONTEND / "sso-handoff.js").exists())

    def test_no_document_loads_it(self) -> None:
        for document in FRONTEND.glob("*.html"):
            with self.subTest(document=document.name):
                self.assertNotIn("sso-handoff", document.read_text(encoding="utf-8"))

    def test_nothing_reads_a_token_out_of_the_url(self) -> None:
        for script in FRONTEND.glob("*.js"):
            with self.subTest(script=script.name):
                text = script.read_text(encoding="utf-8")
                self.assertNotIn("#sso=", text)
                self.assertNotIn('params.get("sso")', text)


class S2FormulaInjectionTests(unittest.TestCase):
    """Report cells are built from names on the scanned share. Excel executes a
    cell that begins with =, +, - or @.

    C9 moved the guard to the server: the workbook is a real .xlsx whose text cells
    are inline strings - which Excel never evaluates - and whose formula-looking text
    also carries the quote-prefix style, so editing a cell keeps it text. The page no
    longer builds a report file at all."""

    def _cells(self, values: list) -> dict:
        import io
        import zipfile
        from xml.etree import ElementTree

        from backend.reporting.office import render_xlsx

        data, _stats = render_xlsx({"title": "t", "blocks": [
            {"label": "Cells", "table": {"headers": ["Value"], "rows": [[value] for value in values]}}]})
        main = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            sheet = ElementTree.fromstring(package.read("xl/worksheets/sheet2.xml"))
            styles = ElementTree.fromstring(package.read("xl/styles.xml"))
        quoted = {str(index) for index, xf in enumerate(styles.find(f"{main}cellXfs"))
                  if xf.get("quotePrefix") == "1"}
        cells = {}
        for cell in sheet.iter(f"{main}c"):
            if cell.get("r") == "A1":
                continue
            self.assertIsNone(cell.find(f"{main}f"), "a cell holds a formula")
            text = "".join(node.text or "" for node in cell.iter(f"{main}t"))
            cells[text or cell.findtext(f"{main}v")] = (cell.get("t"), cell.get("s") in quoted)
        return cells

    def test_the_guard_neutralises_a_formula_and_leaves_a_number_alone(self) -> None:
        cells = self._cells(['=HYPERLINK("http://x","x").txt', "@SUM(A1)", "-file.txt", "+cmd", "-12", "1,234",
                             "45%", "invoice.pdf"])
        for formula in ('=HYPERLINK("http://x","x").txt', "@SUM(A1)", "-file.txt", "+cmd"):
            with self.subTest(formula=formula):
                self.assertEqual(cells[formula], ("inlineStr", True))
        self.assertEqual(cells["invoice.pdf"], ("inlineStr", False))
        for figure in ("-12", "1234", "0.45"):
            with self.subTest(figure=figure):
                self.assertEqual(cells[figure][0], None, "a figure is a number, not quoted text")

    def test_the_console_no_longer_builds_a_spreadsheet_itself(self) -> None:
        self.assertNotIn("function reportCell(value)", APP_JS)
        self.assertNotIn("application/vnd.ms-excel", APP_JS)
        self.assertNotIn("application/msword", APP_JS)
        self.assertIn('fetch("/api/v1/reports/office"', APP_JS)


class S3AuditTests(unittest.TestCase):
    """A trail that records only successful sign-ins cannot show an attempt to
    break in, and one with no source address cannot answer the first question
    anyone asks of it."""

    def test_a_refused_sign_in_is_recorded_with_its_origin(self) -> None:
        from fastapi.testclient import TestClient

        from backend.app import app

        client = TestClient(app)
        client.post("/api/auth/login", json={"username": "admin", "password": "not-the-password"})
        failures = [row for row in read_audit_log("default", 50) if row["action"] == "auth.login_failed"]
        self.assertTrue(failures, "a failed sign-in produced no audit row")
        detail = failures[-1].get("detail") or {}
        self.assertEqual(detail.get("username"), "admin")
        self.assertTrue(detail.get("client_ip"))
        self.assertTrue(detail.get("user_agent"))

    def test_every_new_action_has_a_plain_language_label(self) -> None:
        """The audit view renders the dotted identifier when a label is missing."""
        for action in (
            "auth.login_failed",
            "auth.login_blocked",
            "compliance_keywords.exported",
            "nist.catalog.exported",
        ):
            with self.subTest(action=action):
                self.assertIn(f'"{action}":', APP_JS)

    def test_an_export_is_an_event(self) -> None:
        source = Path("backend/app.py").read_text(encoding="utf-8")
        for action in ("inventory.export.started", "compliance_keywords.exported", "nist.catalog.exported"):
            with self.subTest(action=action):
                self.assertIn(f'"{action}"', source)


class S4IdleSessionTests(unittest.TestCase):
    """An 8-hour token with no idle timeout means a console left open on an
    unlocked machine at 09:00 is still signed in at 17:00."""

    def setUp(self) -> None:
        security._session_last_seen.clear()

    def test_a_session_in_use_keeps_working(self) -> None:
        token = create_token("admin", "admin", "default")
        self.assertEqual(verify_token(token).subject, "admin")
        self.assertEqual(verify_token(token).subject, "admin")

    def test_a_session_left_idle_stops_working(self) -> None:
        token = create_token("admin", "admin", "default")
        verify_token(token)
        jti = json.loads(security._b64url_decode(token.split(".")[1]))["jti"]
        _age_session(jti)
        with self.assertRaises(HTTPException) as refused:
            verify_token(token)
        self.assertEqual(refused.exception.status_code, 401)

    def test_going_idle_revokes_the_token_rather_than_just_refusing_it(self) -> None:
        """Detection is per process; the CONSEQUENCE must not be."""
        from backend.store import is_token_revoked

        token = create_token("admin", "admin", "default")
        verify_token(token)
        jti = json.loads(security._b64url_decode(token.split(".")[1]))["jti"]
        _age_session(jti)
        with self.assertRaises(HTTPException) as refused:
            verify_token(token)
        self.assertEqual(refused.exception.status_code, 401)
        self.assertTrue(is_token_revoked(jti))

    def test_a_token_this_process_has_never_seen_is_admitted_once(self) -> None:
        """Otherwise a restart signs every operator out."""
        token = create_token("admin", "admin", "default")
        security._session_last_seen.clear()
        self.assertEqual(verify_token(token).subject, "admin")

    def test_the_check_can_be_turned_off(self) -> None:
        with mock.patch.object(security, "SESSION_IDLE_SECONDS", 0):
            token = create_token("admin", "admin", "default")
            verify_token(token)
            jti = json.loads(security._b64url_decode(token.split(".")[1]))["jti"]
            security._session_last_seen[jti] = time.time() - 100_000
            self.assertEqual(verify_token(token).subject, "admin")


class S6DownloadTokenTests(unittest.TestCase):
    """A query string is written to every proxy and web-server access log."""

    def test_the_token_is_accepted_in_a_header(self) -> None:
        source = Path("backend/security.py").read_text(encoding="utf-8")
        self.assertIn('Header(alias="X-Artifact-Token")', source)

    def test_the_query_form_can_be_switched_off(self) -> None:
        source = Path("backend/security.py").read_text(encoding="utf-8")
        self.assertIn("DSPM_ALLOW_DL_TOKEN_QUERY", source)

    def test_the_console_fetches_with_the_header(self) -> None:
        self.assertIn('"X-Artifact-Token": token', APP_JS)

    def test_the_token_is_not_written_beside_the_artifact(self) -> None:
        source = Path("backend/reporting/artifacts.py").read_text(encoding="utf-8")
        persisted = source[source.index("persisted = {"):source.index("metadata_path.write_text")]
        self.assertIn('not key.endswith("_url")', persisted)


class S7PlaintextAtRestTests(unittest.TestCase):
    """The encrypted artifact tier supersedes a directory of reports in clear."""

    def test_the_plaintext_report_directory_is_off_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_PLAINTEXT_REPORT_EXPORT", None)
            source = Path("backend/app.py").read_text(encoding="utf-8")
            self.assertIn('os.getenv("DSPM_PLAINTEXT_REPORT_EXPORT", "0")', source)
            self.assertIn("if payload.save_report and PLAINTEXT_REPORT_EXPORT:", source)

    def test_a_failed_dump_cannot_leave_an_unencrypted_copy(self) -> None:
        """The `finally` was already there. `pg_dump` ran OUTSIDE it, so a dump
        that succeeded and then failed its returncode check stayed on disk."""
        source = Path("backend/backup.py").read_text(encoding="utf-8")
        body = source[source.index("counts = capture_table_counts(dsn)"):source.index("return manifest_path")]
        self.assertLess(body.index("try:"), body.index("subprocess.run"))
        self.assertIn("plain.unlink(missing_ok=True)", body)

    def test_the_documented_variables_exist(self) -> None:
        env = Path(".env.example").read_text(encoding="utf-8")
        for name in (
            "DSPM_PLAINTEXT_REPORT_EXPORT",
            "DSPM_SESSION_IDLE_SECONDS",
            "DSPM_ALLOW_DL_TOKEN_QUERY",
        ):
            with self.subTest(name=name):
                self.assertIn(f"{name}=", env)


if __name__ == "__main__":
    unittest.main()
