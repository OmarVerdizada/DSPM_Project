"""D4: the console carries no DaisyUI - no sheet, no build, no dependency and no class.

DaisyUI came in for the Remediation page's drawer, menus and dialogs and stayed as a
125 KB generated sheet in a cascade layer beneath every page rule. Measured before it
went (computed styles with the sheet on and off, every page, the drawer, a menu and each
dialog open), it supplied three things the page relied on - the dialog and drawer
mechanics, the workflow steps' dots and lines, and a few properties of buttons, fields,
badges and alerts - and two it should not have: each dialog opened over a SOLID INDIGO
screen, because its full-window "Close" button took the shell's primary-button chrome,
and inside a 3 px frame, the browser's own dialog border it never reset. What the page
relied on is now in remediation.css and styles/components.css; the two defects are not.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
MARKUP_FILES = [FRONTEND / name for name in ("index.html", "app.js", "profile.html", "profile.js", "login.html",
                                              "register.html", "scan-summary.js")]
OWN_SHEETS = sorted(path for path in (FRONTEND / "styles").glob("*.css")) + [FRONTEND / "styles.css", FRONTEND / "login.css"]

# DaisyUI's own component parts and modifiers: names the console has no rules of its own
# for, and which only ever meant "DaisyUI styles this".
DAISY_ONLY = {
    "drawer", "drawer-end", "drawer-content", "drawer-side", "drawer-toggle", "drawer-overlay", "drawer-button",
    "drawer-open", "dropdown", "dropdown-end", "dropdown-content", "dropdown-open", "dropdown-hover", "dropdown-top",
    "dropdown-bottom", "dropdown-left", "dropdown-right", "modal", "modal-box", "modal-action", "modal-backdrop",
    "modal-open", "modal-toggle", "modal-top", "modal-middle", "modal-bottom", "steps", "steps-horizontal",
    "steps-vertical", "step", "step-primary", "step-secondary", "step-accent", "badge-sm", "badge-xs", "badge-md",
    "badge-lg", "badge-soft", "badge-outline", "badge-dash", "badge-ghost", "badge-primary", "alert-soft", "alert-error",
    "alert-warning", "alert-info", "alert-success", "alert-outline", "alert-dash", "btn-xs", "btn-sm", "btn-md",
    "btn-lg", "btn-xl", "btn-circle", "btn-square", "btn-outline", "btn-soft", "btn-dash", "btn-link", "btn-wide",
    "btn-block", "btn-active", "btn-disabled", "input-xs", "input-sm", "input-md", "input-lg", "input-bordered",
    "input-ghost", "textarea-xs", "textarea-sm", "textarea-md", "textarea-lg", "textarea-bordered", "select-sm",
    "select-bordered", "join", "join-item", "card-body", "card-title", "card-actions", "menu-title", "tab-active",
    "tabs-boxed", "tabs-border", "tabs-lift", "collapse-title", "collapse-content", "loading-spinner", "stat-title",
    "stat-value", "stat-desc",
}
# Generic names both used and defined by the console itself.
OWN_PRIMITIVES = {"btn", "btn-primary", "btn-ghost", "btn-icon", "input", "textarea", "badge", "alert", "sr-only"}


def class_tokens(text: str) -> set[str]:
    """Every class named in a class attribute or a classList call, template expressions removed."""
    tokens: set[str] = set()
    for attribute in re.findall(r'class="([^"]*)"', text):
        tokens.update(re.sub(r"\$\{[^}]*\}", " ", attribute).split())
    for call in re.findall(r"classList\.(?:add|remove|toggle|contains)\(([^)]*)\)", text):
        tokens.update(re.findall(r'["\']([A-Za-z0-9_-]+)["\']', call))
    return tokens


def defined_classes() -> set[str]:
    names: set[str] = set()
    for sheet in OWN_SHEETS:
        text = re.sub(r"/\*.*?\*/", " ", sheet.read_text(encoding="utf-8"), flags=re.DOTALL)
        names.update(re.findall(r"\.([A-Za-z][A-Za-z0-9_-]*)", text))
    return names


class TheDependencyIsGoneTest(unittest.TestCase):

    def test_no_sheet_no_source_no_link(self) -> None:
        self.assertFalse((FRONTEND / "styles" / "daisyui.css").exists())
        self.assertFalse((FRONTEND / "styles" / "daisyui.input.css").exists())
        index = (FRONTEND / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("daisyui", index.lower())
        self.assertIn('href="/static/styles/components.css', index)

    def test_no_build_and_no_dependency(self) -> None:
        package = json.loads((FRONTEND / "package.json").read_text(encoding="utf-8"))
        self.assertNotIn("build:css", package.get("scripts", {}))
        for name in ("daisyui", "tailwindcss", "@tailwindcss/cli"):
            self.assertNotIn(name, package.get("devDependencies", {}))
            self.assertNotIn(f'"node_modules/{name}"', (FRONTEND / "package-lock.json").read_text(encoding="utf-8"))
        gate = (ROOT / "scripts" / "check_frontend_tokens.py").read_text(encoding="utf-8")
        self.assertNotIn("daisyui.css", gate.split("GENERATED_CSS_FILES", 1)[1].split("\n", 1)[0])


class NoClassIsDaisyTest(unittest.TestCase):

    def test_no_daisyui_class_is_used(self) -> None:
        for path in MARKUP_FILES:
            with self.subTest(file=path.name):
                self.assertEqual(sorted(class_tokens(path.read_text(encoding="utf-8")) & DAISY_ONLY), [])

    def test_every_primitive_used_is_defined_by_the_console(self) -> None:
        used = set().union(*(class_tokens(path.read_text(encoding="utf-8")) for path in MARKUP_FILES))
        self.assertTrue(OWN_PRIMITIVES & used, "the console still uses its shared primitives")
        self.assertEqual(sorted((OWN_PRIMITIVES & used) - defined_classes()), [])

    def test_the_primitives_sit_beneath_every_page_rule(self) -> None:
        sheet = (FRONTEND / "styles" / "components.css").read_text(encoding="utf-8")
        body = re.sub(r"/\*.*?\*/", " ", sheet, flags=re.DOTALL).strip()
        self.assertTrue(body.startswith("@layer components {") and body.endswith("}"),
                        "every rule inside the components layer, so an unlayered page rule wins")


class TheDialogsTest(unittest.TestCase):

    def test_a_dialogs_dismiss_layer_is_invisible_and_out_of_the_tab_order(self) -> None:
        index = (FRONTEND / "index.html").read_text(encoding="utf-8")
        layers = re.findall(r'<form method="dialog" class="remediation-dialog-dismiss">(.*?)</form>', index)
        self.assertEqual(len(layers), 5, "one per dialog")
        for layer in layers:
            # plain-btn is the shell's opt-out from the primary-button chrome that painted it indigo.
            self.assertIn('class="plain-btn"', layer)
            self.assertIn('tabindex="-1"', layer)
            self.assertIn('aria-label="Close"', layer)
        css = (FRONTEND / "styles" / "remediation.css").read_text(encoding="utf-8")
        rule = css[css.index(".remediation-dialog-dismiss .plain-btn,"):]
        rule = rule[:rule.index("}")]
        for declaration in ("color: transparent;", "background: transparent;", "border: 0;", "transform: none;"):
            self.assertIn(declaration, rule)

    def test_the_dialog_paints_the_dim_and_no_frame(self) -> None:
        css = (FRONTEND / "styles" / "remediation.css").read_text(encoding="utf-8")
        closed = css[css.index(".remediation-center .remediation-dialog {"):]
        closed = closed[:closed.index("}")]
        self.assertIn("border: 0;", closed, "the browser's own 3 px dialog border is reset")
        opened = css[css.index(".remediation-center .remediation-dialog[open],"):]
        opened = opened[:opened.index("}")]
        self.assertIn("background-color: var(--scrim);", opened)
        self.assertIn("--scrim:", (FRONTEND / "styles" / "tokens.css").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
