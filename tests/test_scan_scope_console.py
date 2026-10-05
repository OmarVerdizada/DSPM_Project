"""Advanced scan scope in the console: what the wizard sends is what the server accepts.

The console's own frontend/console/scan-scope.js runs in Node against stand-in fields
(tests/js/scan_scope_harness.js). Every scope it refuses, the API refuses too, and every
scope it sends, the API accepts and reads the same way - so a mistake is named beside its
field, never first as a refused request. A saved scan's scope comes back into the card
exactly as it was saved.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tests" / "js" / "scan_scope_harness.js"
NODE = shutil.which("node")
TOMORROW = (datetime.now(timezone.utc).date() + timedelta(days=2)).isoformat()

# (kind, fields, units, server) the console refuses - and the API must refuse too.
REFUSED = [
    ("file-server", {"exclude_extensions": ".iso, iso$"}, {}, ""),
    ("file-server", {"min_size": "5", "max_size": "1"}, {"min_size": "MB", "max_size": "MB"}, ""),
    ("file-server", {"max_size": "0"}, {}, ""),
    ("file-server", {"modified_after": TOMORROW}, {}, ""),
    ("file-server", {"exclude_paths": "Finance/*/Archive"}, {}, ""),
    ("file-server", {"exclude_paths": "../elsewhere"}, {}, ""),
    ("file-server", {"exclude_paths": "C:\\Shares\\Finance"}, {}, ""),
    ("file-server", {"exclude_paths": "\\\\fs01\\Finance"}, {}, ""),
    ("file-server", {"include_paths": "\\\\other\\Finance"}, {}, "fs01"),
    ("file-server", {"exclude_folder_patterns": "a/b"}, {}, ""),
    ("file-server", {"exclude_folder_patterns": "*"}, {}, ""),
    ("endpoint", {"exclude_paths": "Downloads\\ISOs"}, {}, ""),
]
ACCEPTED = [
    ("file-server", {"exclude_extensions": "ISO; *.vhdx, .Mp4", "exclude_paths": "Finance/Archive\nIT/Software",
                     "exclude_folder_patterns": "backup*, ~snapshot", "min_size": "1", "max_size": "1.5",
                     "modified_after": "2024-01-31", "skip_hidden": True},
     {"min_size": "KB", "max_size": "GB"}, ""),
    ("file-server", {"include_paths": "\\\\FS01\\Finance\\Reports\nHR"}, {}, "fs01"),
    ("endpoint", {"exclude_paths": "C:\\Users\\ana\\Downloads\\ISOs\n\\\\nas\\vms", "exclude_extensions": ".iso"},
     {}, ""),
    ("file-server", {}, {}, ""),
]


def _harness(payload: dict) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(payload, handle)
        name = handle.name
    try:
        run = subprocess.run([NODE, str(HARNESS), name], capture_output=True, text=True, timeout=60)
    finally:
        Path(name).unlink(missing_ok=True)
    if run.returncode != 0:
        raise AssertionError(run.stderr[:800])
    return json.loads(run.stdout)


def _cases(rows) -> list[dict]:
    return [{"kind": kind, "fields": fields, "units": units, "server": server} for kind, fields, units, server in rows]


def _request(kind: str, scope: dict, server: str = ""):
    from backend.app import EndpointScanRequest, ScanRequest

    if kind == "endpoint":
        return EndpointScanRequest.model_validate({"host": "ws-17", "scope": scope})
    body = {"scope": scope}
    if server:
        body["server"] = server
    return ScanRequest.model_validate(body)


@unittest.skipUnless(NODE, "Node.js runs the console's own code")
class TheConsoleAndTheServerAgreeTest(unittest.TestCase):

    def test_what_the_console_refuses_the_server_refuses_and_it_says_where(self) -> None:
        results = _harness({"cases": _cases(REFUSED)})["cases"]
        for (kind, fields, _units, server), result in zip(REFUSED, results):
            with self.subTest(fields=fields):
                problem = result["problem"]
                self.assertIsNotNone(problem, "the console let it through")
                self.assertTrue(problem["field"].startswith(f"#{kind}-scope-"), problem)
                self.assertTrue(problem["message"])
                with self.assertRaises(ValidationError):
                    _request(kind, result["scope"], server)

    def test_what_the_console_sends_the_server_accepts_and_reads_the_same(self) -> None:
        from collectors import scan_scope

        results = _harness({"cases": _cases(ACCEPTED)})["cases"]
        first = results[0]
        self.assertIsNone(first["problem"])
        self.assertEqual(first["scope"]["exclude_extensions"], [".iso", ".vhdx", ".mp4"])
        self.assertEqual(first["scope"]["exclude_paths"], ["Finance/Archive", "IT/Software"])
        self.assertEqual(first["scope"]["min_size_bytes"], 1024)
        self.assertEqual(first["scope"]["max_size_bytes"], int(1.5 * 1024 ** 3))
        self.assertTrue(first["skipHidden"])
        self.assertEqual(first["count"], 11, "3 types + 2 folders + 2 patterns + 2 sizes + a date + hidden")
        for (kind, _fields, _units, server), result in zip(ACCEPTED, results):
            with self.subTest(kind=kind, scope=result["scope"]):
                self.assertIsNone(result["problem"])
                request = _request(kind, result["scope"], server)
                canonical = request.scope.canonical(absolute=kind == "endpoint")
                self.assertEqual(scan_scope.rule_count(canonical), result["count"] - (1 if result["skipHidden"] else 0))
        self.assertEqual(_request("file-server", results[1]["scope"], "fs01").scope.include_paths,
                         ["Finance/Reports", "HR"], "a UNC path naming the server becomes share-relative")
        self.assertEqual(results[3]["scope"], {}, "no rule sends an empty scope")
        self.assertIn("No scope rules", results[3]["review"])

    def test_a_saved_scope_comes_back_into_the_card_as_it_was(self) -> None:
        saved = {"exclude_extensions": [".iso", ".vhdx"], "exclude_paths": ["Finance/Archive"],
                 "include_paths": ["Finance", "HR/Contracts"], "exclude_folder_patterns": ["backup*"],
                 "min_size_bytes": 2048, "max_size_bytes": 100 * 1024 ** 2, "modified_after": "2025-01-01"}
        results = _harness({"apply": [
            {"kind": "file-server", "scope": saved, "include_hidden": False},
            {"kind": "file-server", "scope": None, "include_hidden": True},
            {"kind": "file-server", "scope": {"max_size_bytes": 1536}, "include_hidden": True},
        ]})["apply"]
        restored, cleared, odd = results
        self.assertEqual(restored["scope"], saved)
        self.assertTrue(restored["skipHidden"])
        self.assertTrue(restored["open"], "a saved scan with rules opens on them")
        self.assertEqual(restored["units"], {"min": "KB", "max": "MB"})
        self.assertEqual(cleared["scope"], {})
        self.assertFalse(cleared["skipHidden"])
        self.assertFalse(cleared["open"])
        self.assertEqual(odd["scope"], {"max_size_bytes": 1536}, "a size that is no whole unit survives the round trip")

    def test_the_history_says_a_scan_was_scoped(self) -> None:
        note = _harness({"summary": {"excluded_by_scope": 1250, "folders_skipped_by_scope": 3,
                                     "scope": {"rule_count": 4, "rules": {}}}})["historyNote"]
        self.assertEqual(note, "scoped (4 rules), 1,250 files left out, 3 folders skipped")
        self.assertEqual(_harness({"summary": {"total_files": 10}})["historyNote"], "")


class TheWizardIsWiredTest(unittest.TestCase):
    """The card is in both wizards, its module loads before app.js, and the request,
    the review, the saved scan and the history all go through it."""

    def test_the_markup_and_the_wiring(self) -> None:
        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        app = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn('data-scan-scope="file-server"', html)
        self.assertIn('data-scan-scope="endpoint"', html)
        self.assertIn('id="scan-summary-scope"', html)
        self.assertLess(html.index("console/scan-scope.js"), html.index("/static/app.js"))
        for wiring in ('scope: readScanScope("file-server")', 'scope: readScanScope("endpoint")',
                       'applyScanScope("file-server", config.scope, config.include_hidden)',
                       'applyScanScope("endpoint", config.scope, config.include_hidden)',
                       "scanScopeProblem(kind, { server })", "scanScopeHistoryNote(summary)",
                       'add("left out by scope", number(scope.excluded_files), { always: true })',
                       "Left out by scope: ",
                       'include_hidden: !scanScopeSkipsHidden("file-server")'):
            self.assertIn(wiring, app)
        summary = (ROOT / "frontend" / "scan-summary.js").read_text(encoding="utf-8")
        self.assertIn('setText("scan-summary-scope", scanScopeReviewText("file-server"))', summary)


if __name__ == "__main__":
    unittest.main()
