"""W4.3: a candidate's context and the whole file are searched without building the two.

The PCI detectors decided every candidate from ``f"{context} {whole file}"``: per row of a
spreadsheet and per expiry, name, code or card - a card-free 16 MiB CSV took 168 s in the PCI
detector alone (MEASURED). ``Joined`` answers the same questions about that string - its
keywords in order, and whether a marker is in it - without the copy. These tests hold it to
the string it stands for, on random and on hostile inputs, and hold a large card-free CSV to
a bound the old code missed by 4x.
"""
from __future__ import annotations

import random
import time
import unittest

from classification.compliance import classify_pci_content
from classification.compliance.joined_text import FileEvidence, Joined
from classification.compliance.keyword_index import keyword_hits_indexed
from classification.compliance.pci_keywords import (
    EXPIRATION_DATE_KEYWORDS,
    PAN_KEYWORDS,
    PAYMENT_CONTEXT_KEYWORDS,
    PIN_KEYWORDS,
)

_ALPHABET = list("abcdefghijk xyz_-:0123456789") + ["Σ", "İ", "ß", "\n", "\t", "é"]
_KEYWORD_LISTS = [EXPIRATION_DATE_KEYWORDS, PAN_KEYWORDS, PAYMENT_CONTEXT_KEYWORDS, PIN_KEYWORDS,
                  ("key id", "hsm key", "exp", "a", "x y", "Σa", "ab cd")]
_MARKERS = ["key id", "hsm key", "zpk", "encrypted", "pin block", "prod", "a b", "Σ", "i̇", "dev", " "]


def _random_text(rng: random.Random, length: int) -> str:
    words = [*_KEYWORD_LISTS[4], "card number", "expiry", "exp date", "pin", "security code"]
    out = []
    while sum(len(part) for part in out) < length:
        out.append(rng.choice(words) if rng.random() < 0.3 else "".join(rng.choice(_ALPHABET)
                                                                         for _ in range(rng.randint(1, 8))))
    return rng.choice(["", " ", "\n"]).join(out)[:length]


class JoinedIsTheStringItStandsForTest(unittest.TestCase):

    def test_keyword_hits_and_markers_on_random_text(self) -> None:
        rng = random.Random(4302)
        for case in range(400):
            evidence = FileEvidence(_random_text(rng, rng.choice([0, 3, 40, 400])))
            local = _random_text(rng, rng.choice([0, 1, 5, 60]))
            joined, built = evidence.after(local), f"{local} {evidence.text}"
            for keywords in _KEYWORD_LISTS:
                for limit in (1, 3, 10):
                    with self.subTest(case=case, limit=limit):
                        self.assertEqual(joined.keyword_hits(keywords, limit=limit),
                                         keyword_hits_indexed(built, keywords, limit=limit))
            for marker in _MARKERS:
                self.assertEqual(marker in joined.lower(), marker in built.lower(), (case, marker, local))

    def test_a_term_across_the_join_and_at_the_edges(self) -> None:
        evidence = FileEvidence("id card number exp")
        for local in ("key", "hsm", "x key", "ab", "", "key id"):
            built = f"{local} {evidence.text}"
            joined = evidence.after(local)
            self.assertEqual(joined.keyword_hits(_KEYWORD_LISTS[4]), keyword_hits_indexed(built, _KEYWORD_LISTS[4]))
            for marker in ("key id", "hsm key", "b id", "y id"):
                self.assertEqual(marker in joined.lower(), marker in built.lower(), (local, marker))

    def test_a_tie_between_a_term_across_the_join_and_one_in_the_file_keeps_its_order(self) -> None:
        # "a bcdef" starts in the context and ends where "bcdef" ends in the file: both end at
        # 7, so the catalogue's order decides - the file's match is at its offset, exactly.
        evidence = FileEvidence("bcdef")
        terms = ("a bcdef", "bcdef")
        self.assertEqual(keyword_hits_indexed("a bcdef", terms), ["a bcdef", "bcdef"])
        self.assertEqual(evidence.after("a").keyword_hits(terms), ["a bcdef", "bcdef"])
        reversed_terms = ("bcdef", "a bcdef")
        self.assertEqual(evidence.after("a").keyword_hits(reversed_terms),
                         keyword_hits_indexed("a bcdef", reversed_terms))

    def test_several_parts_with_the_evidence_twice(self) -> None:
        evidence = FileEvidence("staging export of prod")
        for parts in (("row", evidence, "row row", evidence), (evidence, "dev", evidence), (evidence, "", evidence)):
            built = " ".join(part.text if isinstance(part, FileEvidence) else part for part in parts)
            joined = Joined(*parts)
            self.assertEqual(str(joined), built)
            for marker in ("prod", "dev", "row staging", "prod dev", "prod  prod", "w r"):
                self.assertEqual(marker in joined.lower(), marker in built.lower(), (parts, marker))
        # A marker across a short part between two long ones: the short part is taken whole.
        long_evidence = FileEvidence("start " + "q" * 40 + " end")
        joined = Joined(long_evidence, "x", long_evidence)
        self.assertIn("end x start", str(joined).lower())
        self.assertIn("end x start", joined.lower())

    def test_the_file_is_lowered_and_each_term_found_once(self) -> None:
        evidence = FileEvidence("Card Number on file; EXPIRY follows")
        for local in ("a", "b", "c"):
            evidence.after(local).keyword_hits(EXPIRATION_DATE_KEYWORDS)
        self.assertIsNotNone(evidence._lower)
        terms_asked = len(evidence._first_end)
        evidence.after("d").keyword_hits(EXPIRATION_DATE_KEYWORDS)
        self.assertEqual(len(evidence._first_end), terms_asked, "a term was searched in the file again")


def _card_free_csv(size: int) -> str:
    rows = ["id,name,department,amount,date,notes"]
    index, total = 0, len(rows[0])
    while total < size:
        line = (f"{index},Employee {index % 997},Dept {index % 37},{(index * 7919) % 100000}.{index % 100:02d},"
                f"2026-{1 + index % 12:02d}-{1 + index % 28:02d},routine entry {index % 13}")
        rows.append(line)
        total += len(line) + 1
        index += 1
    return "\n".join(rows)[:size]


class ALargeCardFreeCsvTest(unittest.TestCase):

    def test_four_mib_in_well_under_the_old_time(self) -> None:
        # MEASURED before W4.3: 42.9 s for 4 MiB (10.5 s a MiB, every row and expiry joined
        # to the whole file); after: about 4.5 s. The bound leaves room for a slow machine.
        text = _card_free_csv(4 * 1024 * 1024)
        started = time.perf_counter()
        findings = classify_pci_content(text, {"name": "export.csv", "path": "export.csv", "extension": ".csv",
                                               "tenant_id": "w43"}, [])
        elapsed = time.perf_counter() - started
        self.assertEqual(findings, [])
        self.assertLess(elapsed, 20.0, f"PCI took {elapsed:.1f} s on a card-free 4 MiB CSV")


if __name__ == "__main__":
    unittest.main()
