"""M2/P3: the compiled keyword index answers exactly as the automaton it replaced.

The GDPR catalog's Aho-Corasick trie was 277,280 Python objects - 100 MiB and 1.3
CPU-seconds in every detector worker. It is now a rarest-trigram index (see
classification/compliance/keyword_index.py). Its answers reach findings as
`matched_keywords` and decide which GDPR rules run at all, so the replacement has to be
the same answer, in the same order, for every text: the automaton is kept here, verbatim
from before P3, and the two are compared on the real catalogs and the demo dataset.
"""

from __future__ import annotations

import json
import random
import tracemalloc
import unittest
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

from classification.compliance import gdpr_classifier, keyword_index
from classification.compliance.keyword_index import _normalize_term, _word_boundary

ROOT = Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {".txt", ".csv", ".md", ".log", ".json", ".xml", ".ini", ".cfg", ".conf", ".yaml", ".yml"}


# ── The automaton, as it was before P3 ─────────────────────────────────────────────
@dataclass(slots=True)
class _Node:
    children: dict[str, int] = field(default_factory=dict)
    fail: int = 0
    outputs: list[tuple[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class _Automaton:
    nodes: list[_Node]

    def search(self, text: str, limit_per_type: int = 10) -> dict[str, list[str]]:
        lowered = str(text or "").lower()
        if not lowered:
            return {}
        state = 0
        matches: dict[str, list[str]] = {}
        for index, char in enumerate(lowered):
            while state and char not in self.nodes[state].children:
                state = self.nodes[state].fail
            state = self.nodes[state].children.get(char, 0)
            for keyword, finding_type in self.nodes[state].outputs:
                start = index - len(keyword) + 1
                if not _word_boundary(lowered, start, index + 1, keyword):
                    continue
                bucket = matches.setdefault(finding_type, [])
                if keyword not in bucket and len(bucket) < limit_per_type:
                    bucket.append(keyword)
        return matches


def _compile_automaton(groups: list[dict]) -> _Automaton:
    nodes = [_Node()]
    for group in groups:
        finding_type = str(group.get("type") or "").strip()
        if not finding_type:
            continue
        for raw_term in group.get("terms") or []:
            term = _normalize_term(raw_term)
            if not term:
                continue
            state = 0
            for char in term:
                state = nodes[state].children.setdefault(char, len(nodes))
                if state == len(nodes):
                    nodes.append(_Node())
            output = (term, finding_type)
            if output not in nodes[state].outputs:
                nodes[state].outputs.append(output)
    queue: deque[int] = deque()
    for child in nodes[0].children.values():
        queue.append(child)
        nodes[child].fail = 0
    while queue:
        current = queue.popleft()
        for char, child in nodes[current].children.items():
            queue.append(child)
            fail = nodes[current].fail
            while fail and char not in nodes[fail].children:
                fail = nodes[fail].fail
            nodes[child].fail = nodes[fail].children.get(char, 0)
            for output in nodes[nodes[child].fail].outputs:
                if output not in nodes[child].outputs:
                    nodes[child].outputs.append(output)
    return _Automaton(nodes)
# ─────────────────────────────────────────────────────────────────────────────────────


def _texts() -> list[str]:
    texts = [path.read_text(encoding="utf-8", errors="replace")
             for path in sorted((ROOT / "enterprise_test_data").rglob("*")) if path.suffix.lower() in TEXT_SUFFIXES]
    texts += [f"Customer record {i}\nPayment card: 4111 1111 1111 1111\nContact email: c{i}@example.com\n"
              for i in range(3)]
    return texts


def _same(index, automaton, text: str, limit: int = 10) -> tuple:
    return list(index.search(text, limit).items()), list(automaton.search(text, limit).items())


class TheGdprCatalogTest(unittest.TestCase):
    """The catalog the audit measured: every term the GDPR classifier indexes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.groups = gdpr_classifier._gdpr_keyword_groups([])
        cls.index = keyword_index._compile_index("gdpr", "test", "all", cls.groups)
        cls.automaton = _compile_automaton(cls.groups)
        cls.texts = _texts()

    def test_it_is_the_catalog_the_audit_measured(self) -> None:
        self.assertGreater(self.index.term_count, 30_000)
        self.assertGreater(len(self.automaton.nodes), 200_000)

    def test_every_demo_text_gets_the_automatons_answer_in_its_order(self) -> None:
        found = 0
        for text in self.texts:
            mine, reference = _same(self.index, self.automaton, text)
            self.assertEqual(mine, reference)
            found += bool(reference)
        self.assertGreater(found, len(self.texts) // 2, "most demo texts should match something")

    def test_the_file_name_and_path_the_classifier_appends(self) -> None:
        for text in self.texts[:40]:
            blob = " ".join([text, "Maaş cədvəli 2024.xlsx", r"\\fs01\HR\Personal\Maaş cədvəli 2024.xlsx", ".xlsx"]).lower()
            self.assertEqual(*_same(self.index, self.automaton, blob))

    def test_the_per_type_limit_and_its_order(self) -> None:
        # Every term of one type, shuffled, in one text: the limit picks the same ten.
        rng = random.Random(7)
        terms = [term for group in self.groups[:6] for term in group.get("terms") or []][:400]
        rng.shuffle(terms)
        text = " , ".join(terms)
        for limit in (1, 3, 10, 50):
            with self.subTest(limit=limit):
                self.assertEqual(*_same(self.index, self.automaton, text, limit))

    def test_random_windows_of_real_text(self) -> None:
        rng = random.Random(20260924)
        corpus = "\n".join(self.texts)
        for _ in range(300):
            start = rng.randrange(0, max(1, len(corpus) - 400))
            window = corpus[start:start + rng.randint(1, 400)]
            self.assertEqual(*_same(self.index, self.automaton, window))

    def test_the_gdpr_classifier_finds_the_same_either_way(self) -> None:
        def classify(text: str) -> str:
            record = {"name": "a.txt", "path": "a.txt", "extension": ".txt", "tenant_id": "p3"}
            findings = gdpr_classifier.classify_gdpr_content(text, record, [])
            for finding in findings:
                finding.pop("detector_metrics", None)
            return json.dumps(findings, sort_keys=True, default=str)

        indexed = [classify(text) for text in self.texts]
        automaton = mock.Mock(wraps=self.automaton, created_at="t", catalog_version="v")
        with mock.patch.object(gdpr_classifier, "_gdpr_keyword_index", return_value=automaton):
            reference = [classify(text) for text in self.texts]
        self.assertTrue(any(result != "[]" for result in reference))
        self.assertEqual(indexed, reference)

    def test_a_text_tests_only_the_terms_its_trigrams_allow(self) -> None:
        consulted: list[str] = []

        class Counting(dict):
            def __getitem__(self, key):
                consulted.append(key)
                return super().__getitem__(key)

        index = keyword_index._compile_index("gdpr", "count", "all", self.groups)
        index.buckets = Counting(index.buckets)
        index.search("salary")
        self.assertLessEqual(len(consulted), 4, "a six-letter text has four trigrams")

    def test_it_holds_a_fraction_of_the_memory(self) -> None:
        tracemalloc.start()
        try:
            index = keyword_index._compile_index("gdpr", "memory", "all", self.groups)
            retained = tracemalloc.get_traced_memory()[0]
        finally:
            tracemalloc.stop()
        self.assertTrue(index.term_count)
        self.assertLess(retained, 25 * 2**20, "the trie it replaced held about 100 MiB")


class EdgesTest(unittest.TestCase):
    """Terms that overlap, contain each other, sit at the text's ends, are shorter than
    a trigram, or are not words at all - where an index and an automaton could differ."""

    GROUPS = [
        {"type": "card", "terms": ["card", "cardholder", "card holder", "holder", "CARD", "  card  "]},
        {"type": "id", "terms": ["id", "fin", "fın", "şəxsiyyət vəsiqəsi", "i", "", "ab", "a"]},
        {"type": "odd", "terms": ["c++", "a.b", "(x)", "#tag", "e-mail", "e-mail:", "mail"]},
        {"type": "card", "terms": ["holder", "number"]},
        {"type": "dup", "terms": ["card", "number"]},
        {"type": "", "terms": ["ignored"]},
    ]
    TEXTS = (
        "", "card", "cardholder", "card holder number", "The CARDHOLDER's card", "xcard cardx _card card_",
        "an id, a fin and a FIN", "şƏxsiyyət vəsiqəsi", "c++ a.b (x) #tag e-mail: mail@x", "e-mailing",
        "holder holder holder", "number card holder cardholder", "İd İD id", "a b ab abc", "ignored",
        "card\nholder", "card  holder",
    )

    def test_each_text_gets_the_automatons_answer(self) -> None:
        index = keyword_index._compile_index("t", "v", "all", self.GROUPS)
        automaton = _compile_automaton(self.GROUPS)
        for text in self.TEXTS:
            for limit in (1, 2, 10):
                with self.subTest(text=text, limit=limit):
                    self.assertEqual(*_same(index, automaton, text, limit))

    def test_ad_hoc_keyword_sets_above_the_threshold(self) -> None:
        terms = tuple(f"term{n}" for n in range(250)) + ("salary", "passport", "pass")
        blob = "The salary and passport numbers; term12, term7x and pass."
        groups = [{"framework": "adhoc", "language": "all", "type": "hit", "terms": list(dict.fromkeys(terms))}]
        expected = _compile_automaton(groups).search(blob, 10).get("hit", [])[:10]
        self.assertEqual(keyword_index.keyword_hits_indexed(blob, terms), expected)


if __name__ == "__main__":
    unittest.main()
