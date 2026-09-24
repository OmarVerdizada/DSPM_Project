"""M2/C8: what a client is told when a request fails.

Routes did `HTTPException(400, detail=str(exc))` for any ValueError. That shows the
operator the sentence a validator wrote for them - and equally shows anyone the server
path a `Path.relative_to` put in its message, the byte offset and input a JSON parser
echoed, or the table a driver named. ASVS V7.4.1: a generic message with a reference
support can find in the log, and the detail in the log, not the response.

`backend.errors.client_message` makes the distinction by TYPE (a plain ValueError is the
store's convention for a deliberate refusal; a class may declare `client_safe = True`;
library subclasses such as JSONDecodeError do not qualify) and then by CONTENT (nothing
that looks like a path, a traceback, a parser position, SQL or a driver). An error
nobody anticipated gets the same treatment from an application-wide handler.
"""

from __future__ import annotations

import ast
import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import errors, security, store
from backend.app import app
from backend.reporting.artifacts import ArtifactError

ROOT = Path(__file__).resolve().parent.parent
TENANT = "tenant-errors"
USER = "errors-analyst"
PASSWORD = "an-errors-analyst-7"


class ADeliberateRefusalIsShownTest(unittest.TestCase):

    def test_a_plain_value_error_keeps_its_sentence(self) -> None:
        message = "A suppression rule needs a reason"
        self.assertEqual(errors.client_message(ValueError(message), "fallback"), message)

    def test_the_two_product_exceptions_declare_themselves(self) -> None:
        hold = store.LegalHoldActive("Refusing to delete tenant 'acme': a legal hold is in force")
        self.assertEqual(errors.client_message(hold, "fallback"), str(hold))
        artifact = ArtifactError("No DSPM scan report is available to export.")
        self.assertEqual(errors.client_message(artifact, "fallback"), str(artifact))

    def test_any_class_may_opt_in(self) -> None:
        class Refusal(RuntimeError):
            client_safe = True

        self.assertEqual(errors.client_message(Refusal("Lift the hold first"), "fallback"), "Lift the hold first")


class AnythingElseIsReplacedTest(unittest.TestCase):

    def _hidden(self, exc: BaseException, secret: str) -> str:
        shown = errors.client_message(exc, "The request could not be processed")
        self.assertNotIn(secret, shown)
        self.assertTrue(shown.startswith("The request could not be processed (reference "), shown)
        return shown

    def test_a_windows_path_in_a_value_error(self) -> None:
        # What Path.relative_to says when a resolved path escapes its root.
        exc = ValueError(r"'C:\Sentro\data\reports_artifacts\x' is not in the subpath of 'D:\share'")
        self._hidden(exc, "Sentro")

    def test_a_unc_path_and_a_posix_path(self) -> None:
        self._hidden(ValueError(r"cannot read \\fileserver01\finance$\q3.xlsx"), "fileserver01")
        self._hidden(ValueError("cannot read /var/lib/sentro/dspm.sqlite"), "/var/lib")

    def test_a_parser_position(self) -> None:
        self._hidden(ValueError("Expecting value: line 1 column 12 (char 11)"), "column 12")

    def test_sql_and_driver_names(self) -> None:
        self._hidden(ValueError("UPDATE findings SET status = ? WHERE id = ? failed"), "findings")
        self._hidden(ValueError("sqlite3 said: database is locked"), "sqlite3")

    def test_a_library_subclass_is_not_a_refusal_whatever_it_says(self) -> None:
        # JSONDecodeError IS a ValueError, and its text echoes the caller's input;
        # the type alone keeps it out, even when the text would pass the pattern.
        try:
            json.loads("{catalog")
        except json.JSONDecodeError as exc:
            decode_error = exc
        self._hidden(decode_error, "catalog")
        self._hidden(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"), "invalid start byte")

    def test_other_exception_types(self) -> None:
        self._hidden(RuntimeError("the vault key is missing"), "vault")
        self._hidden(KeyError("tenant_id"), "tenant_id")

    def test_an_empty_or_overlong_message(self) -> None:
        self._hidden(ValueError(""), "()")
        self._hidden(ValueError("x" * 400), "x" * 301)

    def test_the_reference_is_logged_with_what_actually_happened(self) -> None:
        exc = ValueError(r"'C:\Sentro\data' is not in the subpath of 'D:\share'")
        with self.assertLogs("sentro.errors", level="WARNING") as captured:
            shown = errors.client_message(exc, "The request could not be processed")
        reference = shown.rsplit("reference ", 1)[1].rstrip(")")
        logged = "\n".join(captured.output)
        self.assertIn(reference, logged)
        self.assertIn(r"C:\Sentro\data", logged, "support needs the detail - in the log")

    def test_each_refusal_gets_its_own_reference(self) -> None:
        exc = RuntimeError("boom")
        with self.assertLogs("sentro.errors", level="WARNING"):
            first = errors.client_message(exc, "f")
            second = errors.client_message(exc, "f")
        self.assertNotEqual(first, second)


class _RouteCase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "errors.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant(TENANT, "Errors")
        store.create_user(USER, security.hash_password(PASSWORD), "analyst", TENANT)
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        self.headers = {"Authorization": f"Bearer {security.create_token(USER, 'analyst', TENANT)}"}


class TheRoutesUseTheFilterTest(_RouteCase):

    def setUp(self) -> None:
        super().setUp()
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def test_a_validator_sentence_still_reaches_the_operator(self) -> None:
        response = self.client.post("/api/suppression-rules", json={"finding_type": "email"}, headers=self.headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "A suppression rule needs a reason")

    def test_a_path_inside_a_value_error_does_not(self) -> None:
        leak = ValueError(r"'C:\Sentro\data\keywords\acme.json' is not in the subpath of 'C:\Sentro\data\imports'")
        with mock.patch("backend.app.import_keyword_groups", side_effect=leak), \
                self.assertLogs("sentro.errors", level="WARNING") as captured:
            response = self.client.post("/api/compliance-keywords/import", json={"keywords": []}, headers=self.headers)
        self.assertEqual(response.status_code, 400, "the status is unchanged; only the words are")
        detail = response.json()["detail"]
        self.assertNotIn("Sentro", detail)
        self.assertIn("The keyword import could not be processed (reference ", detail)
        reference = detail.rsplit("reference ", 1)[1].rstrip(")")
        self.assertIn(reference, "\n".join(captured.output))

    def test_a_parser_error_from_the_scan_profile_route(self) -> None:
        try:
            json.loads('{"roots": [')
        except json.JSONDecodeError as exc:
            parse_error = exc
        with mock.patch("backend.app.save_scan_profile", side_effect=parse_error), \
                self.assertLogs("sentro.errors", level="WARNING"):
            response = self.client.post(
                "/api/scan-profiles",
                json={"kind": "file-server", "name": "Finance", "config": {}},
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("column", response.json()["detail"])
        self.assertIn("The scan profile could not be saved", response.json()["detail"])

    def test_the_report_route_keeps_its_own_sentence(self) -> None:
        # No scan saved in this tenant: the artifact module's refusal is written for
        # the operator and declares itself safe to show.
        response = self.client.post("/api/v1/reports", json={}, headers=self.headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "No DSPM scan report is available to export.")


class AnUnexpectedErrorTest(_RouteCase):

    def setUp(self) -> None:
        super().setUp()
        # The handler answers; the exception still propagates to the server's own log,
        # which a TestClient would otherwise re-raise into the test.
        self.client = TestClient(app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)

    def test_is_a_generic_500_with_a_reference_and_the_detail_goes_to_the_log(self) -> None:
        boom = RuntimeError(r"unable to open database file C:\Sentro\data\dspm.sqlite")
        with mock.patch("backend.app.get_user", side_effect=boom), \
                self.assertLogs("backend.app", level="ERROR") as captured:
            response = self.client.get("/api/profile", headers=self.headers)
        self.assertEqual(response.status_code, 500)
        body = response.json()
        self.assertEqual(body["detail"], "The server could not complete this request.")
        self.assertRegex(body["reference"], r"^[0-9a-f]{12}$")
        self.assertNotIn("Sentro", response.text)
        logged = "\n".join(captured.output)
        self.assertIn(body["reference"], logged)
        self.assertIn("dspm.sqlite", logged, "the traceback is logged under the reference")
        self.assertIn("/api/profile", logged)

    def test_an_http_error_is_not_turned_into_a_500(self) -> None:
        response = self.client.get("/api/profile", headers={"Authorization": "Bearer nonsense"})
        self.assertEqual(response.status_code, 401)


def _raw_exception_details(tree: ast.AST) -> list[int]:
    """Line numbers of `HTTPException(..., detail=<the exception's own text>)`."""

    def shows_exception(node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"str", "repr"}:
            return bool(node.args) and isinstance(node.args[0], ast.Name)
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name)
                       and part.value.id in {"exc", "err", "error", "e"} for part in node.values)
        return False

    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "HTTPException":
            for keyword in node.keywords:
                if keyword.arg == "detail" and shows_exception(keyword.value):
                    found.append(node.lineno)
    return found


class NoRouteShowsARawExceptionTest(unittest.TestCase):

    def test_the_guard_recognises_the_old_form(self) -> None:
        old = ast.parse('raise HTTPException(status_code=400, detail=str(exc)) from exc\n'
                        'raise HTTPException(status_code=400, detail=f"failed: {exc}")\n')
        self.assertEqual(_raw_exception_details(old), [1, 2])

    def test_no_backend_module_uses_it(self) -> None:
        offenders = {}
        for path in sorted((ROOT / "backend").rglob("*.py")):
            lines = _raw_exception_details(ast.parse(path.read_text(encoding="utf-8")))
            if lines:
                offenders[str(path.relative_to(ROOT))] = lines
        self.assertEqual(offenders, {}, "route through backend.errors.client_message instead")


if __name__ == "__main__":
    logging.basicConfig()
    unittest.main()
