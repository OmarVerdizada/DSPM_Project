"""C6: the console needs nothing from the Internet, and its CSP can say so.

The gate: "Full console works with Internet disconnected; CSP tests pass; cache headers
apply only to versioned static resources." The fonts came from Google, which the CSP
had to name, and style attributes and a <style> block needed 'unsafe-inline'. Now
every asset is served by the install, the policy names no other origin and has no
'unsafe-inline', and only a URL that carries its version is cached for good.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import CONTENT_SECURITY_POLICY, app

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
PAGES = sorted(FRONTEND.glob("*.html"))
SCRIPTS = sorted(FRONTEND.glob("*.js"))
STYLESHEETS = [FRONTEND / "styles.css", FRONTEND / "login.css", FRONTEND / "fonts" / "fonts.css",
               *sorted((FRONTEND / "styles").glob("*.css"))]
# An XML namespace is an identifier, not a request.
NAMESPACES = {"http://www.w3.org/2000/svg", "http://www.w3.org/1999/xlink"}


class NothingComesFromElsewhereTest(unittest.TestCase):

    def test_no_page_script_or_stylesheet_names_another_origin(self) -> None:
        # Any absolute URL at all, not only in src/href/url()/@import: a fetch("https://..."),
        # a string a script later assigns, or a protocol-relative "//host". The only ones
        # allowed are XML namespaces (identifiers, never requested) and licence comments.
        found = []
        for path in PAGES + SCRIPTS + STYLESHEETS:
            text = re.sub(r"/\*!.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
            for url in re.findall(r"https?://[^\s\"'`)>;]+", text):
                if url not in NAMESPACES:
                    found.append(f"{path.name}: {url}")
            for url in re.findall(r"""["'`(]\s*(//[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)""", text):
                found.append(f"{path.name}: {url}")
        self.assertEqual(found, [])
        self.assertTrue(PAGES and SCRIPTS, "the scan must find the files it is about")

    def test_the_fonts_are_served_by_the_install(self) -> None:
        css = (FRONTEND / "fonts" / "fonts.css").read_text(encoding="utf-8")
        families = set(re.findall(r"font-family: '([^']+)'", css))
        self.assertEqual(families, {"Inter", "Space Grotesk", "JetBrains Mono", "Audiowide"})
        for url in re.findall(r"url\(\./([^)?]+)\?v=\d+\)", css):
            with self.subTest(url=url):
                self.assertTrue((FRONTEND / "fonts" / url).is_file())
        self.assertEqual(len(re.findall(r"@font-face", css)), 22)
        for family in ("inter", "space-grotesk", "jetbrains-mono", "audiowide"):
            self.assertIn("SIL OPEN FONT LICENSE", (FRONTEND / "fonts" / family / "OFL.txt").read_text(encoding="utf-8").upper())
        # Azerbaijani's letters are in the Latin Extended range each family loads.
        self.assertIn("U+0100-02BA", css)
        for page in PAGES:
            with self.subTest(page=page.name):
                self.assertIn("/static/fonts/fonts.css?v=", page.read_text(encoding="utf-8"))


class TheCspNeedsNoExceptionsTest(unittest.TestCase):

    def test_the_policy_names_only_the_install_and_allows_no_inline_style(self) -> None:
        policy = dict(item.strip().split(" ", 1) for item in CONTENT_SECURITY_POLICY.split(";") if item.strip())
        self.assertNotIn("unsafe-inline", CONTENT_SECURITY_POLICY)
        self.assertNotIn("unsafe-eval", CONTENT_SECURITY_POLICY)
        self.assertNotRegex(CONTENT_SECURITY_POLICY, r"https?:")
        self.assertEqual(policy["style-src"], "'self'")
        self.assertEqual(policy["font-src"], "'self'")
        self.assertEqual(policy["object-src"], "'none'")
        client = TestClient(app)
        for path in ("/", "/static/app.js?v=1", "/api/ready"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).headers.get("content-security-policy"), CONTENT_SECURITY_POLICY)

    def test_no_page_carries_a_style_attribute_or_block(self) -> None:
        for page in PAGES:
            text = page.read_text(encoding="utf-8")
            with self.subTest(page=page.name):
                self.assertIsNone(re.search(r"\sstyle\s*=", text), "a style attribute needs 'unsafe-inline'")
                self.assertNotIn("<style", text.lower())

    def test_no_script_writes_one_into_markup(self) -> None:
        for script in SCRIPTS:
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                self.assertIsNone(re.search(r"""(?<![-\w])style=\\?["']""", text), "use data-style: the CSP refuses style attributes")
                self.assertNotRegex(text, r"setAttribute\(\s*[\"']style[\"']")
                self.assertNotIn("cssText", text)

    @unittest.skipUnless(shutil.which("node"), "Node.js runs the console's own code")
    def test_what_data_style_says_is_applied_through_the_cssom(self) -> None:
        # The console's own applier and observer, run in Node on stand-in elements: a node
        # added under the document has each declaration set through style.setProperty (which
        # the CSP allows) and its data-style removed - including a value with a colon in it.
        source = (FRONTEND / "app.js").read_text(encoding="utf-8")
        start = source.index("function dataStyleDeclarations(")
        end = source.index("}).observe(document.documentElement", start)
        end = source.index("\n}\n", end) + 3
        harness = """
const set = [];
function element(style, children = []) {
  const attributes = { "data-style": style };
  return {
    nodeType: 1,
    matches: (selector) => selector === "[data-style]" && "data-style" in attributes,
    querySelectorAll: () => children.filter((child) => "data-style" in child.attributes),
    getAttribute: (name) => attributes[name],
    removeAttribute: (name) => { delete attributes[name]; },
    style: { setProperty: (property, value) => set.push([property, value]) },
    attributes,
  };
}
let observed = null;
globalThis.MutationObserver = class { constructor(callback) { observed = callback; } observe() {} };
globalThis.document = { documentElement: {} };
""" + source[start:end] + """
const child = element("width: 42%; background-image: url(data:image/png;base64,AAAA)");
const parent = element("--bar-color: var(--accent)", [child]);
observed([{ addedNodes: [parent, { nodeType: 3 }] }]);
console.log(JSON.stringify({ set, left: [parent.attributes, child.attributes] }));
"""
        run = subprocess.run([shutil.which("node"), "-e", harness], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout.strip().splitlines()[-1])
        self.assertEqual(result["set"], [["--bar-color", "var(--accent)"], ["width", "42%"],
                                         ["background-image", "url(data:image/png;base64,AAAA)"]])
        self.assertEqual(result["left"], [{}, {}], "data-style is removed once applied")
        self.assertGreaterEqual(source.count('data-style="'), 10)


class OnlyAVersionedFileIsKeptTest(unittest.TestCase):

    def test_cache_headers(self) -> None:
        client = TestClient(app)
        cases = {
            "/static/app.js?v=251": "public, max-age=31536000, immutable",
            "/static/fonts/inter/inter-latin-400-normal.woff2?v=1": "public, max-age=31536000, immutable",
            "/static/app.js": "no-cache",
            "/static/fonts/fonts.css": "no-cache",
            "/static/no-such-file.js?v=9": "no-cache",
            "/": "no-cache",
            "/api/ready": "no-store",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(client.get(path).headers.get("cache-control"), expected)


class TheVersionIsTheFilesOwnTest(unittest.TestCase):
    """A year-long cache is only safe if the URL changes when the file does. The pages
    are served with every /static/ reference versioned by the file's content digest, so
    no one has to remember to bump a number - C9 found app.js about to ship under the
    version its previous content was cached with."""

    def test_every_page_names_each_file_by_its_digest(self) -> None:
        import hashlib

        client = TestClient(app)
        for page in ("/", "/register", "/profile", "/dashboard"):
            html = client.get(page).text
            references = re.findall(r'/static/([A-Za-z0-9_./-]+)\?v=([^"\']+)', html)
            self.assertTrue(references, page)
            for name, version in references:
                with self.subTest(page=page, file=name):
                    expected = hashlib.sha256((FRONTEND / name).read_bytes()).hexdigest()[:12]
                    self.assertEqual(version, expected)

    def test_a_changed_file_gets_a_new_version(self) -> None:
        from unittest import mock

        import backend.app as app_module

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text('<script src="/static/app.js?v=1"></script>'
                                             '<link href="/static/../secret.css?v=1">', encoding="utf-8")
            (root / "app.js").write_text("one", encoding="utf-8")
            with mock.patch.object(app_module, "FRONTEND_DIR", root):
                first = app_module._page("index.html").body.decode()
                (root / "app.js").write_text("two, and longer", encoding="utf-8")
                second = app_module._page("index.html").body.decode()
        version = re.compile(r"app\.js\?v=([0-9a-f]{12})")
        self.assertNotEqual(version.search(first).group(1), version.search(second).group(1))
        self.assertIn("/static/../secret.css?v=1", second, "a path out of frontend/ is left alone")


class TheSignInPageTest(unittest.TestCase):

    def test_landmarks_labels_and_a_live_status(self) -> None:
        page = (FRONTEND / "login.html").read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"<main\b", page)), 1)
        self.assertIn('<aside class="right" aria-hidden="true">', page, "the illustration is decoration")
        for field in ("login-username", "login-password"):
            with self.subTest(field=field):
                self.assertRegex(page, rf'<label class="sr-only" for="{field}">')
        self.assertIn('id="login-status" class="status-msg" role="status" aria-live="polite"', page)
        self.assertIn('/static/login.css?v=', page)
        fx = (FRONTEND / "login-fx.js").read_text(encoding="utf-8")
        self.assertNotRegex(fx, r"style\.display\s*=", "an inline display would fall back to the class")

    @unittest.skipUnless(shutil.which("node"), "Node.js runs the page's own script")
    def test_the_eye_shows_the_password_and_offers_to_hide_it(self) -> None:
        """The page's own toggle, run against stand-in elements: the icon shown is the action
        the next click takes."""
        harness = """
const vm = require('vm'), fs = require('fs');
function el(id, hidden) { const set = new Set(hidden ? ['is-hidden'] : []);
  return { id, type: 'password', classList: { toggle: (c, on) => on ? set.add(c) : set.delete(c), has: (c) => set.has(c) },
           addEventListener() {} }; }
const nodes = { 'login-password': el('login-password'), eyeA: el('eyeA', false), eyeB: el('eyeB', true) };
const context = { document: { getElementById: (id) => nodes[id] || null, querySelector: () => null,
  querySelectorAll: () => [], documentElement: { setAttribute() {}, getAttribute() {} }, addEventListener() {} },
  window: { addEventListener() {}, matchMedia: () => ({ matches: false }) }, localStorage: { getItem() {}, setItem() {} },
  setInterval() {}, setTimeout() {}, requestAnimationFrame() {}, console };
vm.createContext(context);
try { vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context); } catch (e) {}
const states = [];
for (let i = 0; i < 2; i++) { vm.runInContext('sentroEyeToggle()', context);
  states.push([nodes['login-password'].type, nodes.eyeA.classList.has('is-hidden'), nodes.eyeB.classList.has('is-hidden')]); }
console.log(JSON.stringify(states));
"""
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "eye.js"
            script.write_text(harness, encoding="utf-8")
            run = subprocess.run([shutil.which("node"), str(script), str(FRONTEND / "login-fx.js")],
                                 capture_output=True, text=True, timeout=60)
        states = json.loads(run.stdout.strip().splitlines()[-1])
        # Revealed: open eye hidden, slashed eye shown. Hidden again: the reverse.
        self.assertEqual(states, [["text", True, False], ["password", False, True]])


if __name__ == "__main__":
    unittest.main()
