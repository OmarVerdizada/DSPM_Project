"""The product owner's console review (2026-10-02), and the Low review items on its pages.

- The header (search, New Scan, theme, workspace) was the dashboard's alone; it is on every
  page and carries the page's title (tests/test_console_standard.py pins the header).
- "Who can read" showed an empty Files panel: the panel's `hidden` lost to a page rule's
  display:flex. `hidden` now always hides, and the page opens on its most exposed principal.
- The refresh arrow on Who can read and Alerts was a solid black blob: the stroke icons had
  no fill:none outside the pages that styled them. One refresh control, the Remediation
  page's, everywhere.
- A checkbox clicked with the mouse drew the legacy 4px focus ring round a box stretched
  to 36px - "something around the tick".
- Pages started their first box 70, 74, 90 or 98px down; one rhythm now.
- Review (Low): a stale files answer could replace the current one, a workspace switch left
  the old workspace's principals and typed reference values on screen, and the CSV import
  split "Aliyeva, Leyla" and semicolon exports wrongly.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
INDEX = (FRONTEND / "index.html").read_text(encoding="utf-8")
APP_JS = (FRONTEND / "app.js").read_text(encoding="utf-8")
SHELL = (FRONTEND / "styles" / "shell.css").read_text(encoding="utf-8")
COMPONENTS = (FRONTEND / "styles" / "components.css").read_text(encoding="utf-8")
ACCESS = (FRONTEND / "console" / "access.js").read_text(encoding="utf-8")
EXACT = (FRONTEND / "console" / "exact-match.js").read_text(encoding="utf-8")


class GlobalGuaranteesTest(unittest.TestCase):
    def test_hidden_hides_and_icons_are_drawn_not_filled(self) -> None:
        self.assertIn("@layer components {", COMPONENTS)
        self.assertIn("[hidden] { display: none !important; }", COMPONENTS)
        icon = COMPONENTS[COMPONENTS.index(".f-ico {"):]
        icon = icon[:icon.index("}")]
        self.assertIn("fill: none;", icon)
        self.assertIn("stroke: currentColor;", icon)

    def test_one_refresh_control(self) -> None:
        buttons = re.findall(r'<button type="button" id="refresh-[\w-]+-btn" class="([^"]+)"><svg class="f-ico btn-ico" '
                             r'aria-hidden="true"><use href="(#li-[\w-]+)"/>', INDEX)
        self.assertGreaterEqual(len(buttons), 8)
        for classes, icon in buttons:
            self.assertEqual((classes, icon), ("secondary-btn mini-btn refresh-btn", "#li-rotate-ccw"))
        self.assertNotIn('<use href="#li-refresh-cw"/></svg>Refresh', INDEX)
        self.assertIn(".refresh-btn.secondary-btn {", SHELL)

    def test_a_clicked_checkbox_draws_no_ring_but_the_keyboard_keeps_one(self) -> None:
        self.assertIn(':root input:is([type="checkbox"], [type="radio"]):focus:not(:focus-visible) {', SHELL)
        rule = SHELL[SHELL.index(':root input:is([type="checkbox"], [type="radio"]):focus:not(:focus-visible) {'):]
        self.assertIn("box-shadow: none !important;", rule[:200])
        history = (FRONTEND / "styles" / "history.css").read_text(encoding="utf-8")
        self.assertIn('.access-toggle input[type="checkbox"] {\n  width: 15px;\n  height: 15px;', history)

    def test_every_page_starts_on_the_same_line(self) -> None:
        self.assertIn(".tab-panel.active > :is(.section-header, .asset-header) { margin-bottom: var(--space-4); }", SHELL)
        reports = (FRONTEND / "styles" / "reports.css").read_text(encoding="utf-8")
        panel = reports[reports.index("#tab-reports.tab-panel.active {"):]
        self.assertIn("gap: var(--space-4);", panel[:160])
        self.assertIn("#tab-risk .remediation-page-content { gap: var(--space-4); }", SHELL)


class WhoCanReadTest(unittest.TestCase):
    def test_it_opens_on_the_most_exposed_principal(self) -> None:
        render = ACCESS[ACCESS.index("function renderAccessPrincipals("):]
        render = render[:render.index("\n}\n")]
        self.assertIn("if (!accessChosen && !kind) {", render)
        self.assertIn("accessChosen = { key: rows[0].key", render)
        load = ACCESS[ACCESS.index("async function loadAccessPrincipals("):]
        self.assertIn("if (accessChosen) loadAccessFiles();", load[:900])

    def test_an_older_answer_never_replaces_a_newer_one(self) -> None:
        files = ACCESS[ACCESS.index("async function loadAccessFiles("):]
        files = files[:files.index("\n}\n")]
        self.assertIn("const request = ++accessFilesRequest;", files)
        self.assertIn("if (request !== accessFilesRequest || !isCurrentTenantContext(context) || !parts.files) return;", files)
        self.assertIn("if (parts.more) parts.more.disabled = true;", files)

    def test_a_workspace_switch_leaves_nothing_of_the_old_one(self) -> None:
        switch = APP_JS[APP_JS.index('tenantSwitcher.addEventListener("change", async () => {'):]
        switch = switch[:switch.index("await Promise.all(")]
        self.assertIn("resetAccessPage();", switch)
        self.assertIn("resetExactMatchForm();", switch)
        reset = ACCESS[ACCESS.index("function resetAccessPage("):]
        self.assertIn("accessChosen = null;", reset[:400])
        self.assertIn("accessFilesRequest += 1;", reset[:400])
        form = EXACT[EXACT.index("function resetExactMatchForm("):]
        self.assertIn('if (parts.values) parts.values.value = "";', form[:400])


@unittest.skipUnless(shutil.which("node"), "node is needed to run the console's own parser")
class ExactMatchCsvTest(unittest.TestCase):
    def parse(self, name: str, text: str) -> list[str]:
        script = (
            "const vm = require('vm');"
            "const source = require('fs').readFileSync(process.argv[1], 'utf8');"
            "const context = { document: { querySelector: () => null }, console };"
            "vm.createContext(context); vm.runInContext(source, context);"
            "const out = vm.runInContext(`exactMatchValues(exactMatchFileText(${JSON.stringify(process.argv[2])}, "
            "${JSON.stringify(process.argv[3])}))`, context);"
            "process.stdout.write(JSON.stringify(out));"
        )
        run = subprocess.run(["node", "-e", script, str(FRONTEND / "console" / "exact-match.js"), name, text],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_a_quoted_name_with_a_comma_stays_whole(self) -> None:
        self.assertEqual(self.parse("people.csv", '"Aliyeva, Leyla",1990\n"Mammadov, Rauf",1985\n'),
                         ["Aliyeva, Leyla", "Mammadov, Rauf"])

    def test_a_semicolon_export_gives_its_first_column(self) -> None:
        self.assertEqual(self.parse("export.csv", "AZ1234567;Leyla;Baku\nAZ7654321;Rauf;Ganja\n"),
                         ["AZ1234567", "AZ7654321"])

    def test_escaped_quotes_and_plain_files(self) -> None:
        self.assertEqual(self.parse("x.csv", '"O""Brien",x\n'), ['O"Brien'])
        self.assertEqual(self.parse("list.txt", "Aliyeva, Leyla\nRauf\n"), ["Aliyeva, Leyla", "Rauf"])


if __name__ == "__main__":
    unittest.main()
