"""The compliance detectors, made fast without changing what they find.

Scanning with GDPR, PCI DSS and NIST enabled cost 240ms per file against 8ms
for the generic detector alone - a full estate scan spent 97% of itself in the
compliance catalogs. None of that was the matching; it was work rebuilt on
every call:

* a rule's 600-to-1,000-term catalog was lower-cased, escaped, sorted, joined
  and compiled into an alternation on each of the 828 calls a single file made;
* PCI built an Aho-Corasick automaton - with a json dump and a sha256 over it -
  145 times per file, for keyword sets of 7 to 92 terms;
* NIST re-read, deep-copied, schema-validated and hashed its whole catalog per
  file, and re-normalized every catalog term against every file;
* three loop invariants - a 12KB string slice, a case-fold of the evidence
  blob, and a compiled boundary pattern - were recomputed per rule.

The tests below pin the two things that matter: the answers did not change,
and the work is not rebuilt.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from classification.compliance import keyword_index, validators  # noqa: E402
from classification.compliance.nist_catalog import nist_catalog_readonly, nist_catalog_status  # noqa: E402

NIST_CLASSIFIER = Path("classification/compliance/nist_classifier.py").read_text(encoding="utf-8")
VALIDATORS = Path("classification/compliance/validators.py").read_text(encoding="utf-8")
KEYWORD_INDEX = Path("classification/compliance/keyword_index.py").read_text(encoding="utf-8")

SAMPLES = [
    "Full name: Aysel Mammadova, email aysel@example.az, phone +994 50 123 45 67",
    "Release notes: the deploy step retries three times. Nothing sensitive here.",
    "cardholder name / PAN 4111 1111 1111 1111 exp 09/28 cvv 123",
    "salary 4200 AZN monthly bonus 15% -- see the compensation review",
    "musteri adi: Rashad; unvan: Nizami kucesi 41; dogum tarixi 1988-04-12",
    "",
    "a" * 4000,
]

CATALOGS = [
    ("name", ("full name", "legal name", "customer name", "ad soyad")),
    ("money", ("salary", "compensation", "bonus", "maas")),
    ("empty", ()),
    ("blank-term", ("", "salary")),
    ("punctuated", ("e-mail", "e-poct", "d.o.b.")),
]


class NarrowingIsEquivalentTests(unittest.TestCase):
    """The optimization rests on one claim: a term that is nowhere in the file
    cannot be in a window of it, and cannot be the term an alternation matches.
    These check that claim against the code it replaced."""

    @staticmethod
    def _naive_has_keyword_context(content, value_start, keywords, window=80):
        left = content[max(0, value_start - window):value_start].lower()
        return any(str(keyword or "").lower() in left for keyword in keywords)

    @staticmethod
    def _naive_context_values(content, keywords, max_chars=140):
        values = []
        keyword_pattern = "|".join(sorted((re.escape(item) for item in keywords if item), key=len, reverse=True))
        if not keyword_pattern:
            return values
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_])(?:{keyword_pattern})(?![A-Za-z0-9_])\s*(?:[:=,-]|\bis\b)?\s*([^\r\n;]{{1,{max_chars}}})",
            re.IGNORECASE,
        )
        for match in pattern.finditer(content):
            value = match.group(1).strip(" \t:=-,")
            if value:
                values.append(value)
            if len(values) >= 20:
                break
        return values

    def test_has_keyword_context_answers_the_same(self) -> None:
        for text in SAMPLES:
            for label, catalog in CATALOGS:
                for start in range(0, len(text) + 1, 17):
                    with self.subTest(catalog=label, start=start, text=text[:20]):
                        self.assertEqual(
                            validators.has_keyword_context(text, start, catalog, window=40),
                            self._naive_has_keyword_context(text, start, catalog, window=40),
                        )

    def test_context_values_answer_the_same(self) -> None:
        for text in SAMPLES:
            for label, catalog in CATALOGS:
                with self.subTest(catalog=label, text=text[:20]):
                    self.assertEqual(
                        validators.context_values(text, catalog, max_chars=60),
                        self._naive_context_values(text, catalog, max_chars=60),
                    )

    def test_a_blank_term_still_matches_everything(self) -> None:
        """"" is a substring of every string, which is what the any()-over-`in`
        form answered. Dropping blank terms as noise would change that."""
        self.assertTrue(validators.has_keyword_context("anything at all", 8, ("",)))
        self.assertFalse(validators.has_keyword_context("anything at all", 8, ()))

    def test_the_narrowed_set_is_exactly_what_is_present(self) -> None:
        text = "Salary review for the customer name on file"
        present = validators._present_keywords(text, ("salary", "customer name", "passport", ""))
        self.assertEqual(present, ("salary", "customer name", ""))


class AdHocKeywordHitsTests(unittest.TestCase):
    """PCI asks for 7 to 92 terms, 145 times a file. The automaton is the right
    answer for the 46,000-term GDPR catalog and the wrong one here, so both
    paths exist - and they have to agree."""

    def test_both_paths_agree(self) -> None:
        blob = "cardholder name and the PAN with an expiry date, plus a cvv code"
        terms = ("pan", "cvv", "cardholder name", "expiry", "iban", "sort code")
        direct = keyword_index.keyword_hits_indexed(blob, terms)
        original = keyword_index._ADHOC_TRIE_THRESHOLD
        try:
            keyword_index._ADHOC_TRIE_THRESHOLD = 0  # force the automaton
            trie = keyword_index.keyword_hits_indexed(blob, terms)
        finally:
            keyword_index._ADHOC_TRIE_THRESHOLD = original
        self.assertEqual(direct, trie)
        self.assertEqual(direct, ["cardholder name", "pan", "expiry", "cvv"])

    def test_word_boundaries_still_hold(self) -> None:
        self.assertEqual(keyword_index.keyword_hits_indexed("expansion of the pantry", ("pan",)), [])
        self.assertEqual(keyword_index.keyword_hits_indexed("the pan is hot", ("pan",)), ["pan"])

    def test_a_term_set_is_cleaned_once(self) -> None:
        self.assertIn("def _adhoc_terms(keywords: tuple)", KEYWORD_INDEX)
        self.assertIn("@functools.lru_cache(maxsize=512)", KEYWORD_INDEX)


class NistCatalogTests(unittest.TestCase):
    def test_the_catalog_is_read_in_place_when_nothing_overlays_it(self) -> None:
        """Copying it was 18 to 49ms of every file - the whole catalog
        serialized and reparsed so that a caller WITH overlays could write into
        it. A scan without overlays writes nothing."""
        self.assertIn("def nist_catalog_readonly()", Path("classification/compliance/nist_catalog.py").read_text(encoding="utf-8"))
        self.assertIn("catalog = load_nist_catalog() if custom_rule_overlays else nist_catalog_readonly()", NIST_CLASSIFIER)
        first, second = nist_catalog_readonly(), nist_catalog_readonly()
        self.assertIs(first, second, "the read-only accessor must not copy")
        self.assertTrue(first.get("rules"))

    def test_the_status_is_not_revalidated_per_file(self) -> None:
        self.assertIn("_STATUS_CACHE", Path("classification/compliance/nist_catalog.py").read_text(encoding="utf-8"))
        self.assertEqual(nist_catalog_status(), nist_catalog_status())
        # Cached by the file's identity and mtime, so a swapped catalog is seen.
        source = Path("classification/compliance/nist_catalog.py").read_text(encoding="utf-8")
        self.assertIn("stat.st_mtime_ns", source[source.index("def nist_catalog_status"):])

    def test_loop_invariants_are_out_of_the_rule_loop(self) -> None:
        regex_hits = NIST_CLASSIFIER[NIST_CLASSIFIER.index("def _regex_hits("):]
        regex_hits = regex_hits[:regex_hits.index(chr(10) + "def ", 10)]
        # The slice was taken per pattern, copying the file's text 154 times.
        self.assertIn("scanned = content[:250_000]", regex_hits)
        self.assertNotIn("content[:250_000])", regex_hits.replace("scanned = content[:250_000]", ""))
        # And the pattern was compiled per pattern per rule per file.
        self.assertIn("_compiled_rule_pattern(raw,", regex_hits)
        # The evidence blob was case-folded on all 984 calls that read it.
        self.assertIn("text_lower = _lowered_once(text)", NIST_CLASSIFIER)
        self.assertIn("def _term_boundary_pattern(term: str)", NIST_CLASSIFIER)


class HelperRebuildTests(unittest.TestCase):
    def test_no_helper_compiles_a_catalog_alternation_per_call(self) -> None:
        for name in ("context_values", "context_keyword_values", "has_keyword_context"):
            with self.subTest(helper=name):
                body = VALIDATORS[VALIDATORS.index(f"def {name}("):]
                body = body[:body.index(chr(10) + "def ", 10)]
                self.assertNotIn("re.compile", body)
                self.assertNotIn("re.escape", body)
        self.assertIn("def _present_keywords(content: str, keywords: tuple[str, ...])", VALIDATORS)
        self.assertIn("@functools.lru_cache(maxsize=2048)", VALIDATORS)

    def test_the_catalog_tuples_are_cached_by_identity_not_by_hash(self) -> None:
        """Hashing a 1,000-item tuple on every call costs about what the work
        it saves costs - measured, and the reason lru_cache is not used here."""
        self.assertIn("_LOWERED_CACHE: dict[int, tuple[tuple[str, ...], tuple[str, ...]]]", VALIDATORS)
        self.assertIn("cached[0] is keywords", VALIDATORS)
        # The tuple is held alongside so its id cannot be reused underneath us.
        self.assertIn("_LOWERED_CACHE[key] = (keywords, lowered)", VALIDATORS)

    def test_the_one_catalog_built_per_match_is_built_once(self) -> None:
        rules = Path("classification/compliance/gdpr_rules.py").read_text(encoding="utf-8")
        self.assertIn("_FORECAST_CONTEXT_KEYWORDS = PRERELEASE_FINANCIAL_KEYWORDS + PRICING_MARGIN_FORECAST_KEYWORDS", rules)
        salary = rules[rules.index("def detect_salary_compensation("):]
        salary = salary[:salary.index(chr(10) + "def ", 10)]
        self.assertNotIn("KEYWORDS + ", salary, "a fresh tuple per match defeats the identity cache")


if __name__ == "__main__":
    unittest.main()
