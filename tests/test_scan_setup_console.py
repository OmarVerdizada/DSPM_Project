"""The file-server scan's Configuration step: one panel, a manifest, a footer in reach.

The step grew as four cards (behaviour, extension policy, a folded scope card,
compliance) under each other, taller than a laptop screen with Back and Next at the
very bottom. Its type list scrolled inside the page, so the wheel stopped moving the
page over it, and its head lay under the console's header. Hidden and system files
were pseudo file types in that list, and "All extensions" sent a list of every type
Sentro knows - leaving out every type it does not.

The logic runs here in Node from the console's own frontend/console/scan-setup.js
(tests/js/scan_setup_harness.js); the structure is checked in the markup and styles.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tests" / "js" / "scan_setup_harness.js"
NODE = shutil.which("node")
INDEX = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
APP = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
SETUP_CSS = (ROOT / "frontend" / "styles" / "scan-setup.css").read_text(encoding="utf-8")
STEP_2 = INDEX[INDEX.index('<div class="wizard-step hidden" data-wizard-step="2">'):
               INDEX.index('<div class="wizard-step hidden" data-wizard-step="3">')]


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


def _controls(**overrides) -> dict:
    controls = {
        "#fs-hidden-files": {"value": "include"}, "#fs-system-files": {"value": "skip"},
        "#server": {"value": ""}, "#max_depth": {"value": "4"}, "#smb_encryption": {"checked": False},
        "#smb_shares": {"value": ""}, "input[name='ext-type-mode']:checked": {"value": "selected"},
        "#ext-advanced-mode": {"hidden": True},
        "input[name='ext-preset']:checked": {"value": "recommended", "label": "Recommended"},
    }
    controls.update(overrides)
    return controls


@unittest.skipUnless(NODE, "Node.js runs the console's own code")
class TheStepsLogicTest(unittest.TestCase):

    def test_hidden_and_system_files_are_two_plain_choices_mapped_to_the_request(self) -> None:
        cases, expected = [], []
        for hidden, (include_hidden, hidden_only) in {"include": (True, False), "skip": (False, False),
                                                      "only": (True, True)}.items():
            for system, (include_system, system_only) in {"skip": (False, False), "include": (True, False),
                                                          "only": (True, True)}.items():
                cases.append({"controls": _controls(**{"#fs-hidden-files": {"value": hidden},
                                                       "#fs-system-files": {"value": system}})})
                expected.append({"include_hidden": include_hidden, "hidden_filter_enabled": hidden_only,
                                 "include_system": include_system, "system_filter_enabled": system_only})
        results = _harness({"cases": cases, "restore": [{"config": item} for item in expected]})
        self.assertEqual([case["special"] for case in results["cases"]], expected)
        # ...and a saved scan's four flags come back as the same two choices.
        self.assertEqual([(item["hidden"], item["system"]) for item in results["restore"]],
                         [(hidden, system) for hidden in ("include", "skip", "only")
                          for system in ("skip", "include", "only")])

    def test_the_type_mode_says_what_the_scan_will_read(self) -> None:
        results = _harness({"cases": [
            {"controls": _controls(), "selected": [".pdf", ".docx", "__hidden__"]},
            {"controls": _controls(**{"#ext-advanced-mode": {"hidden": False}}), "selected": [".pdf"]},
            {"controls": _controls(**{"input[name='ext-type-mode']:checked": {"value": "all"}})},
        ]})["cases"]
        self.assertEqual(results[0]["label"], "Recommended (2 types)", "a pseudo type is not a file type")
        self.assertEqual(results[1]["label"], "Custom (1 types)")
        self.assertEqual((results[2]["mode"], results[2]["label"]), ("all", "All file types"))

    def test_the_step_names_every_problem_it_would_refuse_beside_its_field(self) -> None:
        results = _harness({"cases": [
            {"controls": _controls(), "selected": [".pdf"]},
            {"controls": _controls(**{"#max_depth": {"value": "13"}}), "selected": [".pdf"]},
            {"controls": _controls(**{"#server": {"value": "fs01"}, "#smb_encryption": {"checked": True}}),
             "selected": [".pdf"]},
            {"controls": _controls(**{"#server": {"value": "fs01"}, "#smb_encryption": {"checked": True},
                                      "#smb_shares": {"value": "Finance"}}), "selected": [".pdf"]},
            {"controls": _controls(**{"#ext-advanced-mode": {"hidden": False}}), "selected": []},
            {"controls": _controls(), "selected": [".pdf"],
             "scopeProblem": {"field": "#file-server-scope-min_size", "message": "min above max"}},
        ]})["cases"]
        fields = [[problem["field"] for problem in case["problems"]] for case in results]
        self.assertEqual(fields, [[], ["#max_depth"], ["#smb_shares"], [], ["#extension-search"],
                                  ["#file-server-scope-min_size"]])


class TheStepsStructureTest(unittest.TestCase):

    def test_one_panel_in_three_parts_beside_a_manifest(self) -> None:
        for part in ('id="cfg-scope"', 'id="cfg-method"', 'id="cfg-compliance"', 'class="cfg-manifest"',
                     'aria-label="Compliance mapping"', 'data-scan-scope="file-server"'):
            self.assertIn(part, STEP_2)
        self.assertNotIn("scan-card", STEP_2, "the four stacked cards are gone")
        # Every control the request, a saved scan and the review read is still there, once.
        for control in ("async_scan", "incremental_enabled", "inspect_archives", "include_admin_shares",
                        "smb_encryption", "max_depth", "local_path", "smb_shares", "allowed_extensions",
                        "extension-search", "ext-advanced-mode", "custom-extension-input", "compliance-enabled"):
            self.assertEqual(STEP_2.count(f'id="{control}"'), 1, control)
        self.assertEqual(len(re.findall(r'name="scan_level"', STEP_2)), 3)

    def test_every_button_opts_out_of_the_primary_style(self) -> None:
        # The console's primary button rule is a long :not() chain; .plain-btn is its opt-out.
        for button in re.findall(r"<button[^>]*>", STEP_2):
            self.assertTrue("plain-btn" in button or "secondary-btn" in button, button)

    def test_one_scrollbar_a_footer_in_reach_and_a_head_clear_of_the_header(self) -> None:
        self.assertNotIn("overflow-y: auto", SETUP_CSS, "a list that scrolls inside the page traps the wheel")
        self.assertNotIn("max-height", SETUP_CSS)
        footer = SETUP_CSS[SETUP_CSS.index("#fs-wizard .scan-wizard-footer {"):]
        self.assertIn("position: sticky", footer[:footer.index("}")])
        self.assertIn("bottom: 0", footer[:footer.index("}")])
        self.assertIn("#tab-file-servers:has(#fs-wizard:not(.hidden)) > .section-header {\n  display: block;",
                      SETUP_CSS)
        self.assertIsNone(re.search(r"!important\s*;", SETUP_CSS), "the legacy rules are outranked, not out-shouted")

    def test_all_file_types_sends_no_type_filter(self) -> None:
        start = APP.index("function readPayload()")
        body = APP[start:APP.index("\n}\n", start)]
        self.assertIn('scanTypeMode() === "all"', body)
        self.assertIn("...specialFiles", body)
        self.assertNotIn("readSearchExtension", body, "a search term is not a choice")


if __name__ == "__main__":
    unittest.main()
