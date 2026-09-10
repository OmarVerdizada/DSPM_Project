"""A notification you cannot dismiss is an obstacle, not a notification.

Three faults shipped together and each has its own lock here:

  * the element class was `.toast`, which daisyui.css already defines as a
    fixed-position CONTAINER component - so every notification inherited a
    vendor sheet's width and insets and floated away from its corner;
  * the host was `pointer-events: none` and nothing turned it back on for the
    notice, so the dismiss button could not be clicked at all;
  * the enter and exit animations named keyframes that were never defined
    anywhere, so neither had ever run.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

FRONTEND = Path("frontend")
SHEET = (FRONTEND / "styles" / "toast.css").read_text(encoding="utf-8")
TOKENS = (FRONTEND / "styles" / "tokens.css").read_text(encoding="utf-8")
LEGACY = (FRONTEND / "styles.css").read_text(encoding="utf-8")
VENDOR = (FRONTEND / "styles" / "daisyui.css").read_text(encoding="utf-8")
MARKUP = (FRONTEND / "index.html").read_text(encoding="utf-8")
SCRIPT = (FRONTEND / "app.js").read_text(encoding="utf-8")


def uncommented(text: str, block: str = "css") -> str:
    """The sheet or script with its comments removed.

    These tests assert on what the rules say. A comment that names `.toast` or
    `!important` in order to explain why neither is used must not read as a
    violation of the thing it is explaining.
    """
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    if block == "js":
        text = re.sub(r"//.*", " ", text)
    return text


def rule(selector: str) -> str:
    """The body of the first rule whose selector list is exactly `selector`."""
    match = re.search(re.escape(selector) + r"\s*\{([^{}]*)\}", SHEET)
    assert match, f"no rule for {selector}"
    return match.group(1)


class VendorCollisionTests(unittest.TestCase):
    def test_the_collision_this_sheet_exists_to_avoid_is_real(self) -> None:
        """If daisyUI ever drops `.toast`, this rename can be reconsidered.

        Until then the reason has to stay visible, because `.toast` is the
        obvious name and someone will reach for it again.
        """
        toast = re.search(r"\.toast\s*\{([^{}]*)\}", VENDOR)
        self.assertIsNotNone(toast, "daisyui.css no longer defines .toast")
        self.assertIn("position:fixed", toast.group(1).replace(" ", ""))

    def test_the_console_does_not_use_the_vendor_class(self) -> None:
        self.assertNotIn('class="toast', MARKUP)
        self.assertNotIn("`toast ${", SCRIPT)
        self.assertNotRegex(uncommented(SHEET), r"(?<![\w-])\.toast(?![\w-])")

    def test_the_legacy_sheet_kept_no_toast_rules(self) -> None:
        """Four generations of overrides went with the class they argued over."""
        self.assertNotRegex(uncommented(LEGACY), r"(?<![\w-])\.toast(?![\w-])")


class DismissabilityTests(unittest.TestCase):
    def test_the_layer_is_transparent_but_a_notice_is_not(self) -> None:
        """The half that was missing.

        The host stops swallowing clicks meant for the page, and each notice
        turns the pointer back on for itself.
        """
        self.assertIn("pointer-events: none", rule(".notice-host"))
        self.assertIn("pointer-events: auto", rule(".notice"))

    def test_there_is_a_close_control_and_it_is_wired(self) -> None:
        self.assertIn('class="notice-close plain-btn"', SCRIPT)
        self.assertIn('aria-label="Dismiss notification"', SCRIPT)
        self.assertIn('.querySelector(".notice-close").addEventListener("click"', SCRIPT)

    def test_the_close_control_opts_out_of_the_button_chrome_by_class(self) -> None:
        """`plain-btn` is this codebase's existing opt-out from the app-wide
        button rules. Using it is what keeps the sheet free of !important."""
        self.assertIn('class="notice-close plain-btn"', SCRIPT)
        self.assertNotIn("!important", uncommented(SHEET))

    def test_the_target_is_large_enough_to_hit(self) -> None:
        close = rule(".notice button.notice-close")
        self.assertIn("width: 30px", close)
        # A 30px control plus a 7px bleed on each side is a 44px target.
        self.assertIn("inset: -7px", rule(".notice button.notice-close::after"))

    def test_escape_dismisses_without_stealing_the_key(self) -> None:
        handler = SCRIPT[SCRIPT.index('if (event.key !== "Escape"'):]
        handler = uncommented(handler[:handler.index("});")], "js")
        self.assertIn("dismissNotice", handler)
        # A modal or a menu still gets the same keypress.
        self.assertNotIn("preventDefault", handler)


class LifetimeTests(unittest.TestCase):
    def test_a_failure_outlives_a_confirmation(self) -> None:
        """A failure carries the sentence that says what went wrong; taking it
        away on the same timer as an "it worked" is how an operator ends up
        re-running a scan to find out why the first one failed."""
        table = SCRIPT[SCRIPT.index("const NOTICE_LIFETIMES"):]
        table = table[:table.index("\n")]
        lifetimes = {k: int(v) for k, v in re.findall(r"(\w+): (\d+)", table)}
        self.assertGreater(lifetimes["danger"], lifetimes["success"])
        self.assertGreater(lifetimes["warning"], lifetimes["info"])

    def test_the_timer_pauses_while_it_is_being_read(self) -> None:
        """Without this a notice can expire between reading its first line and
        reaching for its close button, which reads as a refusal to close."""
        for event in ("mouseenter", "mouseleave", "focusin", "focusout"):
            self.assertIn(f'addEventListener("{event}", () => holdNotice', SCRIPT)
        self.assertIn("animation-play-state: paused", SHEET)

    def test_a_burst_cannot_bury_the_page_it_reports_on(self) -> None:
        self.assertIn("const NOTICE_LIMIT = 4;", SCRIPT)
        self.assertIn("live.length - NOTICE_LIMIT", SCRIPT)


class SheetIntegrityTests(unittest.TestCase):
    def test_every_animation_it_names_actually_exists(self) -> None:
        """The old sheet animated `toastIn`, `toastOut` and `mc-toast-in`, none
        of which were defined anywhere - so no notification had ever animated,
        in or out, and the `leaving` class was decoration."""
        defined = set(re.findall(r"@keyframes\s+([\w-]+)", SHEET))
        used = set(re.findall(r"animation:\s*([\w-]+)", SHEET))
        used.discard("none")
        self.assertTrue(used)
        self.assertEqual(used - defined, set())

    def test_every_token_it_names_actually_exists(self) -> None:
        """A var() that resolves to nothing drops the whole declaration, and
        the failure is silent."""
        declared = set(re.findall(r"(--[\w-]+)\s*:", TOKENS))
        # --notice-life is per-element state written by showToast, not a token;
        # its var() carries a fallback for the moment before that happens.
        declared.add("--notice-life")
        for name in set(re.findall(r"var\((--[\w-]+)", SHEET)):
            with self.subTest(token=name):
                self.assertIn(name, declared)

    def test_it_clears_the_legacy_profile_panel(self) -> None:
        """The panel is still one of the ad-hoc z-index values the token ladder
        has yet to replace; a notice behind it would be invisible."""
        self.assertIn("z-index: var(--z-toast)", rule(".notice-host"))
        z_toast = int(re.search(r"--z-toast:\s*(\d+)", TOKENS).group(1))
        panel = max(int(v) for v in re.findall(r"z-index:\s*(\d+)", LEGACY) if int(v) < 20000)
        self.assertGreater(z_toast, panel)

    def test_it_hugs_a_corner(self) -> None:
        """`bottom: 96px` used to hold the stack clear of an action stack that
        no longer exists, which left it floating in open space - which the
        operator read as "it appears in the centre of the window"."""
        host = rule(".notice-host")
        self.assertIn("position: fixed", host)
        for edge in ("right: 20px", "bottom: 20px"):
            self.assertIn(edge, host)

    def test_the_sheet_is_loaded_and_owns_the_layer(self) -> None:
        self.assertIn("/static/styles/toast.css", MARKUP)
        # Last, so a tie on specificity with the legacy button chrome resolves
        # in this sheet's favour without reaching for !important.
        sheets = re.findall(r'href="/static/([\w./-]+\.css)', MARKUP)
        self.assertEqual(sheets[-1], "styles/toast.css")

    def test_the_markup_and_the_script_agree_on_the_host(self) -> None:
        self.assertIn('id="notice-host"', MARKUP)
        self.assertIn('document.querySelector("#notice-host")', SCRIPT)


class ReducedMotionTests(unittest.TestCase):
    def test_a_countdown_that_cannot_count_is_removed_not_frozen(self) -> None:
        block = SHEET[SHEET.index("@media (prefers-reduced-motion: reduce)"):]
        self.assertIn("display: none", block)
        self.assertIn(".notice-life", block)


if __name__ == "__main__":
    unittest.main()
