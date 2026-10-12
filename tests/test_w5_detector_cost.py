"""W5: the detectors answer each question about a file once, and the same answers as before.

Profiled on a 16 MiB card-free CSV with every framework (and the GDPR and NIST budgets
lifted, so the whole work is measured): 127 s, and on a 2 MiB CSV with personal data 53 s.
The causes were questions asked of the whole file again and again:

- PCI asked thirty-odd protection markers of every card candidate's
  ``f"{local} {file}"`` - and so of the whole file, per candidate (34 s of 2 MiB);
- PCI lowered the whole file to find each candidate's context; GDPR lowered it per keyword
  inside an ``any()`` and per context value; three GDPR rules ran the same assignment regex;
- PCI's EMV check stripped the file to hex digits with a regex (2.1 s of 16 MiB);
- NIST's per-text slots held one text, and every rule alternated the file with its path,
  so each rule found the file evicted - its lowering and its term answers redone;
- NIST and GDPR scanned the whole file once per catalog term (622 signature keywords).

Each is now answered once per file, or ruled out by the file's character triples first.
The findings over the benchmark corpora are identical (554 inputs, 4,671 findings), and so
are a 2 MiB CSV's; these tests hold the equivalences and the once-per-file answers.
"""
from __future__ import annotations

import random
import re
import string
import unittest

from classification.compliance import gdpr_rules, nist_classifier, validators
from classification.compliance.joined_text import FileEvidence, Joined
from classification.compliance.keywords import PRIVATE_KEY_CERT_KEYWORDS, SIGNATURE_KEYWORDS
from classification.compliance.pci_validators import _hex_digits_upper

_ALPHABET = string.ascii_letters + string.digits + " \n\t,;:=%^-_" + "éİΣ漢٠０"


def _random_text(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(length))


class TheFileIsAskedOnceTest(unittest.TestCase):

    def test_a_marker_is_looked_for_in_the_file_once(self) -> None:
        evidence = FileEvidence("Tokenized vault entries follow\n" + "row,1,2\n" * 1000)
        joined = Joined("local context", evidence)
        self.assertTrue(joined.contains_lowered("tokenized"))
        self.assertFalse(joined.contains_lowered("hmac"))
        self.assertEqual(evidence._contains, {"tokenized": True, "hmac": False},
                         "the markers were not answered once for the file")

    def test_markers_answer_as_the_joined_string_does(self) -> None:
        rng = random.Random(41)
        for _ in range(300):
            evidence = FileEvidence(_random_text(rng, rng.randint(0, 300)))
            local = _random_text(rng, rng.randint(0, 40))
            joined = Joined(local, evidence)
            whole = f"{local} {evidence.text}".lower()
            for _ in range(5):
                marker = whole[rng.randint(0, max(0, len(whole) - 3)):][:rng.randint(1, 6)] or "x"
                self.assertEqual(joined.contains_lowered(marker), marker in whole, marker)
                self.assertEqual(joined.contains_lowered(marker + "q~"), (marker + "q~") in whole)

    def test_the_file_is_lowered_once_and_shared_answers_computed_once(self) -> None:
        content = "Password = hunter2\napi_token: abc\n" * 50
        self.assertIs(validators.lowered_content(content), validators.lowered_content(content))
        calls = []
        first = validators.per_content(content, "probe", lambda: calls.append(1) or ["answer"])
        second = validators.per_content(content, "probe", lambda: calls.append(1) or ["other"])
        self.assertEqual((first, second, len(calls)), (["answer"], ["answer"], 1))

    def test_the_hex_digits_are_the_regexs(self) -> None:
        rng = random.Random(7)
        for _ in range(500):
            text = _random_text(rng, rng.randint(0, 200))
            self.assertEqual(_hex_digits_upper(text), re.sub(r"[^A-Fa-f0-9]", "", text).upper())


class NistKeepsTheFileWhileItAsksAboutThePathTest(unittest.TestCase):

    def test_a_short_text_does_not_evict_the_files_slot(self) -> None:
        big = "routine entry " * 50_000
        lowered = nist_classifier._lowered_once(big)
        nist_classifier._present_in(big, lowered, "routine")
        nist_classifier._lowered_once("some/path/file.csv")
        nist_classifier._present_in("some/path/file.csv", "some/path/file.csv", "csv")
        self.assertIs(nist_classifier._lowered_once(big), lowered, "the path evicted the file's lowered text")
        self.assertIs(nist_classifier._TERM_PRESENCE.slot[0], big, "the path evicted the file's answers")

    def test_presence_is_the_scans_answer_on_a_large_text(self) -> None:
        rng = random.Random(3)
        words = ["employee", "dept", "routine", "entry", "amount", "tax", "salary", "nist", "cui"]
        text = " ".join(rng.choice(words) + str(rng.randint(0, 99)) for _ in range(60_000))
        lowered = text.lower()
        self.assertGreater(len(lowered), nist_classifier._TRIGRAM_PREFILTER_CHARS)
        terms = ["routine entry", "salary", "social security", "cui", "date of birth", "ab", "tax9", "zz top",
                 "employee12 ", "ent", "nist sp 800-60"]
        for term in terms:
            self.assertEqual(nist_classifier._present_in(text, lowered, term), term in lowered, term)


class GdprAsksTheIndexWhatTheLoopAskedTest(unittest.TestCase):

    def test_signature_and_key_context_as_before(self) -> None:
        rng = random.Random(11)
        # "signingDate" is a keyword only with its capital: lowered, it never matched the
        # lowered file, and no lowercase keyword is inside it.
        samples = ["nothing to see here", "The document was signed by the CFO", "signatureValue=abc",
                   "signingDate=2026-01-01", "privateKey stored", "ssh private key in vault", "PEM KEY attached", ""]
        samples += [_random_text(rng, 2000) + " " + rng.choice(SIGNATURE_KEYWORDS) for _ in range(10)]
        for content in samples:
            lowered = content.lower()
            old_signature = any(keyword in "" or keyword in lowered for keyword in SIGNATURE_KEYWORDS)
            new_signature = (any(keyword in "" for keyword in SIGNATURE_KEYWORDS)
                             or bool(gdpr_rules._present_keywords(content, gdpr_rules._SIGNATURE_KEYWORDS_LOWER)))
            self.assertEqual(new_signature, old_signature, content[-60:])
            old_context = any(keyword.lower() in "" or keyword.lower() in lowered for keyword in PRIVATE_KEY_CERT_KEYWORDS)
            self.assertEqual(gdpr_rules._has_any_context("", content, PRIVATE_KEY_CERT_KEYWORDS), old_context,
                             content[-60:])


if __name__ == "__main__":
    unittest.main()
