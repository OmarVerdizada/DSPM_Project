"""D4: every page passes light and dark, keyboard and 1366x768 - and Risk logic is one page, not nine.

The gate was run in a browser over all thirteen console pages at 1366x768 in both themes:
axe-core (WCAG 2.1 AA and best practice), horizontal overflow, and a keyboard pass that tabs
through each page and checks every stop draws a focus ring. Before this change it found
contrast failures on seven pages (severity chips from two legacy palettes at 3.9-4.3:1, white
on the dark accent at 4.46:1), five h4s directly under a page's h2, three unnamed controls,
aria-selected="null" on the "Who can read" rows, and a report preview that scrolled but
could not be reached by keyboard. Risk logic measured 8.8 screens, three-quarters of it 27
signal cards printing every finding, keyword and action in full.

The contrast pairs here are COMPUTED from the stylesheets' own values, both themes, so a
token change that breaks one fails this file rather than waiting for the next audit.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
TOKENS = (FRONTEND / "styles" / "tokens.css").read_text(encoding="utf-8")
LEGACY = (FRONTEND / "styles.css").read_text(encoding="utf-8")
APP_JS = (FRONTEND / "app.js").read_text(encoding="utf-8")
INDEX = (FRONTEND / "index.html").read_text(encoding="utf-8")
PAGES = (FRONTEND / "styles" / "pages.css").read_text(encoding="utf-8")
SEVERITIES = ("critical", "high", "medium", "low")


def block(css: str, opener: str) -> str:
    start = css.index(opener) + len(opener)
    depth = 1
    for index in range(start, len(css)):
        if css[index] == "{":
            depth += 1
        elif css[index] == "}":
            depth -= 1
            if depth == 0:
                return css[start:index]
    raise AssertionError(opener)


def variables(body: str) -> dict[str, str]:
    return {name: value.strip() for name, value in re.findall(r"(--[\w-]+):\s*([^;]+);", body)}


LIGHT = variables(block(TOKENS, ":root {"))
DARK = {**LIGHT, **variables(block(TOKENS, ':root[data-theme="dark"] {'))}


def rgb(value: str, theme: dict[str, str]) -> tuple[float, float, float, float]:
    value = value.strip()
    if value.startswith("var("):
        return rgb(theme[value[4:-1].strip()], theme)
    if value.startswith("#"):
        digits = value[1:]
        if len(digits) == 3:
            digits = "".join(ch * 2 for ch in digits)
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16), 1.0)
    parts = [float(part) for part in re.findall(r"[\d.]+", value)]
    return (parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else 1.0)


def mix(first, second, share: float):
    """color-mix(in srgb, first share, second): per channel, in encoded sRGB."""
    return tuple(a * share + b * (1 - share) for a, b in zip(first[:3], second[:3])) + (1.0,)


def over(top, ground):
    alpha = top[3]
    return tuple(t * alpha + g * (1 - alpha) for t, g in zip(top[:3], ground[:3])) + (1.0,)


def contrast(first, second) -> float:
    def lum(color):
        channels = []
        for channel in color[:3]:
            c = channel / 255
            channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
    high, low = sorted((lum(first), lum(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


class ContrastTests(unittest.TestCase):
    def assertReadable(self, ink, ground, what: str) -> None:
        ratio = contrast(ink, ground)
        self.assertGreaterEqual(ratio, 4.5, f"{what}: {ratio:.2f}:1")

    def test_severity_chips_on_their_wash(self) -> None:
        """Findings and Risk logic: 82% severity into the text colour, on a 10% wash."""
        for name, theme in (("light", LIGHT), ("dark", DARK)):
            ink, surface = rgb(theme["--ink"], theme), rgb(theme["--surface"], theme)
            for level in SEVERITIES:
                sev = rgb(theme[f"--sev-{level}"], theme)
                self.assertReadable(mix(sev, ink, .82), mix(sev, surface, .10), f"{name} {level} chip")
        for level in SEVERITIES:
            self.assertIn(f"#results-body .badge.{level.upper()},\n#risk-rules-body .logic-signal-card .badge.{level.upper()}"
                          f" {{ --pill: var(--sev-{level}); }}", PAGES)

    def test_remediation_severity_on_its_wash(self) -> None:
        remediation = (FRONTEND / "styles" / "remediation.css").read_text(encoding="utf-8")
        for name, theme in (("light", LIGHT), ("dark", DARK)):
            ink, surface = rgb(theme["--ink"], theme), rgb(theme["--surface"], theme)
            for level in SEVERITIES:
                sev = rgb(theme[f"--sev-{level}"], theme)
                self.assertReadable(mix(sev, ink, .85), mix(sev, surface, .08), f"{name} remediation {level}")
                self.assertIn(f'.remediation-severity[data-severity="{level.upper()}"] {{ color: color-mix(in srgb, '
                              f'var(--sev-{level}) 85%, var(--ink));', remediation)

    def test_alert_chips_on_the_surface(self) -> None:
        dark_status = variables(block(LEGACY, ':root[data-theme="dark"] {\n  --bg: #0b0f1a;'))
        for level in SEVERITIES:
            self.assertReadable(rgb(LIGHT[f"--sev-{level}"], LIGHT), rgb(LIGHT["--surface"], LIGHT), f"light alert {level}")
            self.assertReadable(rgb(dark_status[f"--status-{level}"], DARK), rgb(DARK["--surface"], DARK), f"dark alert {level}")
        self.assertIn("#tab-alerts .badge,\n#tab-access .badge,\n#risk-rules-body .logic-asset .badge {\n  background: var(--surface) !important;", PAGES)

    def test_white_on_the_accent(self) -> None:
        white = (255, 255, 255, 1.0)
        for name, theme in (("light", LIGHT), ("dark", DARK)):
            self.assertReadable(white, rgb(theme["--indigo"], theme), f"{name} filled control")
        # The legacy layer's accent IS the token now, not a copy of its old value.
        legacy_dark = block(LEGACY, ':root[data-theme="dark"] {\n  --bg: #0b0f1a;')
        self.assertIn("--accent: var(--indigo);", legacy_dark)

    def test_quiet_text_on_tinted_rows(self) -> None:
        for name, theme in (("light", LIGHT), ("dark", DARK)):
            surface = rgb(theme["--surface"], theme)
            chosen_row = over(rgb(theme["--indigo-wash"], theme), surface)
            blurb = mix(rgb(theme["--ink-muted"], theme), rgb(theme["--ink"], theme), .70)
            self.assertReadable(blurb, chosen_row, f"{name} chosen report blurb")
        reports = (FRONTEND / "styles" / "reports.css").read_text(encoding="utf-8")
        chosen_rule = block(reports, '.report-type[aria-checked="true"] .report-type-blurb {')
        self.assertIn("color: color-mix(in srgb, var(--ink-muted) 70%, var(--ink));", chosen_rule)
        pill_ground = mix(rgb(DARK["--indigo"], DARK), rgb(DARK["--surface"], DARK), .12)
        self.assertReadable(rgb(DARK["--indigo-ink"], DARK), pill_ground, "dark source pill")
        self.assertIn(':root[data-theme="dark"] .source-pill { color: var(--indigo-ink); }', PAGES)


class NamesAndStructureTests(unittest.TestCase):
    def test_no_heading_skips_a_level_under_a_page_title(self) -> None:
        for title in ("User management", "API key management", "Custom roles", "Scan targets", "DLP policy export", "Add tenant"):
            line = next(line for line in INDEX.splitlines() if f"</span>{title}</h4>" in line)
            self.assertIn('<h4 aria-level="3">', line, title)
        for rendered in ("${escapeHtml(band.level)} - ${escapeHtml(band.title)}</h4>", "${escapeHtml(title)}</h4>",
                         "${escapeHtml(asset.pattern)}</h4>", "${escapeHtml(item.pattern)}</h4>", "${escapeHtml(rule.signal)}</h4>"):
            self.assertIn(f'<h4 aria-level="3">{rendered}', APP_JS)

    def test_every_control_has_a_name_and_a_valid_state(self) -> None:
        self.assertIn('data-user-tenant="${escapeHtml(user.username)}" aria-label="Tenant of ${escapeHtml(user.username)}"', APP_JS)
        self.assertIn('data-user-role="${escapeHtml(user.username)}" aria-label="Role of ${escapeHtml(user.username)}"', APP_JS)
        self.assertIn('tenant-code-input" aria-label="Registration code for ${escapeHtml(tenantLabel(tenant))}"', APP_JS)
        access = (FRONTEND / "console" / "access.js").read_text(encoding="utf-8")
        self.assertIn("const chosen = Boolean(accessChosen && accessChosen.key === row.key);", access)
        self.assertIn('id="report-preview" role="region" tabindex="0" aria-label="Report preview"', INDEX)


class RiskLogicCompactionTests(unittest.TestCase):
    def test_a_signal_shows_what_it_is_and_opens_the_rest(self) -> None:
        card = APP_JS[APP_JS.index("function renderLogicRuleCard("):]
        card = card[:card.index("\n}\n")]
        head, more = card.split('<details class="logic-signal-more">')
        # What it is, its level, score and reason stay on the card...
        for always in ('class="logic-signal-head"', "${escapeHtml(rule.signal)}", "${escapeHtml(rule.reason)}"):
            self.assertIn(always, head)
        # ...what it matches and what to do open on demand.
        self.assertIn("<summary>What it matches and what to do</summary>", more)
        for detail in ('renderLogicRuleList("Findings"', 'renderLogicRuleList("Keywords"', "DLP action", "Control guidance"):
            self.assertIn(detail, more)
            self.assertNotIn(detail, head)

    def test_one_control_opens_them_all(self) -> None:
        self.assertIn('data-logic-expand-all aria-pressed="false">Show all details</button>', APP_JS)
        handler = APP_JS[APP_JS.index('const toggle = event.target.closest?.("[data-logic-expand-all]");'):]
        handler = handler[:handler.index("\n});")]
        self.assertIn('document.querySelectorAll("#risk-rules-body .logic-signal-more").forEach((item) => { item.open = open; });', handler)
        self.assertIn('toggle.setAttribute("aria-pressed", String(open));', handler)
        self.assertIn("#risk-rules-body .logic-signal-grid {\n  align-items: start;", PAGES)
        self.assertIn("#risk-rules-body .logic-signal-card { min-height: 0; }", PAGES)
        self.assertIn(".logic-signal-more > summary:focus-visible {", PAGES)


if __name__ == "__main__":
    unittest.main()
