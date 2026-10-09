"""M2/P1: three per-file costs from the quality audit, each answered once instead.

The audit profiled a 3,083-file compliance scan (docs/QUALITY_AUDIT_2026-09-18.md §5.2):
narrowing a keyword catalog to the terms a file contains was 15% of all CPU, the NIST
catalog's "which file is in force" check was 16% of the main process, and the scan
cache re-resolved its directory for every file, ~10%. Each fix has to give exactly the
answer it replaces, so most of this file is about sameness, not speed.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from classification.compliance import (
    classify_gdpr_content,
    classify_nist_content,
    classify_pci_content,
    nist_catalog,
    validators,
)
from discovery import scan_cache
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

ROOT = Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {".txt", ".csv", ".md", ".log", ".json", ".xml", ".ini", ".cfg", ".conf", ".yaml", ".yml"}


def _fixture_texts() -> list[str]:
    """The bundled demo dataset's text files - the labelled fixture the audit scanned -
    plus the card-and-email records that made up the rest of its estate."""
    texts = [path.read_text(encoding="utf-8", errors="replace")
             for path in sorted((ROOT / "enterprise_test_data").rglob("*")) if path.suffix.lower() in TEXT_SUFFIXES]
    texts += [f"Customer record {i}\nPayment card: 4111 1111 1111 1111\nContact email: c{i}@example.com\n"
              for i in range(5)]
    return texts


def _classify(text: str) -> list[dict]:
    record = {"name": "fixture.txt", "path": "fixture.txt", "extension": ".txt", "tenant_id": "p1"}
    findings = classify_gdpr_content(text, record, []) + classify_pci_content(text, record, []) \
        + classify_nist_content(text, record, [])
    for finding in findings:
        # Timings are the one thing expected to differ.
        finding.pop("detector_metrics", None)
        for key in [key for key in finding if "elapsed" in key]:
            finding.pop(key)
    return findings


def _loop(content: str, keywords: tuple[str, ...]) -> tuple[str, ...]:
    """What _present_keywords answered before P1, verbatim."""
    lowered = content.lower()
    return tuple(term for term in (str(item or "").lower() for item in keywords) if term in lowered)


class KeywordPresenceIsTheSameAnswerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.texts = _fixture_texts()
        cls.catalogs: dict[int, tuple] = {}
        real = validators._present_keywords

        def capture(content, keywords):
            cls.catalogs[id(keywords)] = keywords
            return real(content, keywords)

        with mock.patch.object(validators, "_present_keywords", capture):
            for text in cls.texts:
                _classify(text)

    def _fresh(self, content: str, keywords: tuple[str, ...]) -> tuple[str, ...]:
        validators._PRESENT_STATE.slot = None
        return validators._present_keywords(content, keywords)

    def test_the_fixture_reaches_the_catalogs_the_audit_measured(self) -> None:
        # Without this, every comparison below could be a handful of tiny catalogs.
        self.assertGreaterEqual(len(self.catalogs), 20)
        self.assertGreaterEqual(max(len(catalog) for catalog in self.catalogs.values()), 1000)

    def test_every_catalog_on_every_fixture_text(self) -> None:
        compared = 0
        for text in self.texts:
            for catalog in self.catalogs.values():
                expected = _loop(text, catalog)
                self.assertEqual(self._fresh(text, catalog), expected)
                compared += bool(expected)
        self.assertGreater(compared, 500, "most comparisons should have found something")

    def test_terms_that_contain_overlap_or_are_too_short_to_index(self) -> None:
        catalog = ("card", "cardholder", "holder", "Card Holder", "c++", "a.b", "(x)", "[y]", "a|b", "\\d",
                   "şəxsiyyət vəsiqəsi", "fin", "fın", "ı", "", "card", "CARD", "  spaced  term ", "id", "pi",
                   "car", "ca")
        for text in ("The CARDHOLDER name", "card holder", "no match here", "", "şƏxsiyyət vəsiqəsi FIN",
                     "c++ and a.b and (x) and [y] and a|b and \\d", "an id and pi", "ca", "car", "cardholdercard",
                     "  spaced  term ", "İstanbul"):
            with self.subTest(text=text):
                self.assertEqual(self._fresh(text, catalog), _loop(text, catalog))

    def test_the_classifiers_give_the_same_findings_either_way(self) -> None:
        indexed = [_classify(text) for text in self.texts]
        with mock.patch.object(validators, "_present_keywords", _loop):
            looped = [_classify(text) for text in self.texts]
        self.assertTrue(any(looped), "the fixture should produce findings")
        self.assertEqual(json.dumps(indexed, sort_keys=True, default=str),
                         json.dumps(looped, sort_keys=True, default=str))

    def test_a_file_tests_only_the_terms_its_trigrams_allow(self) -> None:
        # The point of the index: a catalog of a thousand terms against a file that
        # shares a trigram with three of them tests three, not a thousand.
        catalog = tuple(f"zq{n:04d}x" for n in range(1000)) + ("salary", "salaried", "passport")
        index = validators._trigram_index(catalog)
        consulted: list[str] = []

        class Counting(dict):
            def __getitem__(self, trigram):
                consulted.append(trigram)
                return super().__getitem__(trigram)

        index.by_trigram = Counting(index.by_trigram)
        self.assertEqual(self._fresh("salary and passport numbers", catalog), ("salary", "passport"))
        self.assertEqual(sorted(consulted), ["pas", "sal"], "only the trigrams the file contains")


class _CountingResolve:
    def __init__(self) -> None:
        self.calls = 0
        self.real = Path.resolve

    def __call__(self, path, *args, **kwargs):
        self.calls += 1
        return self.real(path, *args, **kwargs)


class TheNistCatalogIsLookedUpOnceASecondTest(unittest.TestCase):

    def setUp(self) -> None:
        nist_catalog._invalidate_cache()
        self.addCleanup(nist_catalog._invalidate_cache)

    def test_a_file_asks_the_filesystem_nothing_it_asked_a_moment_ago(self) -> None:
        nist_catalog.nist_catalog_status()
        nist_catalog.nist_catalog_readonly()
        counter = _CountingResolve()
        with mock.patch.object(Path, "resolve", counter), mock.patch.object(Path, "exists") as exists:
            for _ in range(200):
                nist_catalog.nist_catalog_status()
                nist_catalog.nist_catalog_readonly()
        self.assertEqual((counter.calls, exists.call_count), (0, 0))

    def test_a_catalog_swapped_on_disk_is_seen_within_the_second(self) -> None:
        catalog = nist_catalog.load_nist_catalog()
        with tempfile.TemporaryDirectory() as temp_dir:
            active = Path(temp_dir) / "active.json"
            with mock.patch.object(nist_catalog, "ACTIVE_PATH", active):
                builtin = nist_catalog.nist_catalog_status()["catalog_version"]
                swapped = json.loads(json.dumps(catalog))
                swapped["catalog"]["catalog_version"] = "swapped-by-another-process"
                active.write_text(json.dumps(swapped), encoding="utf-8")
                # Written behind this process's back: no invalidation, only the clock.
                self.assertEqual(nist_catalog.nist_catalog_status()["catalog_version"], builtin)
                later = time.monotonic() + nist_catalog._IDENTITY_SECONDS + 0.1
                with mock.patch.object(nist_catalog.time, "monotonic", return_value=later):
                    self.assertEqual(nist_catalog.nist_catalog_status()["catalog_version"],
                                     "swapped-by-another-process")
                    self.assertEqual(nist_catalog.nist_catalog_readonly()["catalog"]["catalog_version"],
                                     "swapped-by-another-process")

    def test_a_catalog_activated_here_is_seen_at_once(self) -> None:
        catalog = nist_catalog.load_nist_catalog()
        upgraded = json.loads(json.dumps(catalog))
        upgraded["catalog"]["catalog_version"] = "activated-here"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with mock.patch.object(nist_catalog, "STATE_DIR", root), \
                    mock.patch.object(nist_catalog, "ACTIVE_PATH", root / "active.json"), \
                    mock.patch.object(nist_catalog, "LAST_GOOD_PATH", root / "last_good.json"), \
                    mock.patch.object(nist_catalog, "AUDIT_PATH", root / "audit.jsonl"), \
                    mock.patch.object(nist_catalog.time, "monotonic", return_value=time.monotonic()):
                # The clock is held still: activating validates the catalog, which takes
                # longer than the second the answer is kept, and would hide a missing
                # invalidation behind an expiry.
                nist_catalog.nist_catalog_status()
                preview = nist_catalog.import_nist_catalog(upgraded, dry_run=False, actor="p1")
                nist_catalog.activate_nist_catalog(preview["catalog_hash"], actor="p1")
                self.assertEqual(nist_catalog.nist_catalog_status()["catalog_version"], "activated-here")


class TheScanCacheDirectoryIsResolvedOnceTest(unittest.TestCase):

    def test_the_path_of_every_file_does_not_resolve_the_directory_again(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = DSPMDiscoveryEngine(ScanConfig(local_path=temp_dir, cache_dir=os.path.join(temp_dir, "cache")))
            first = engine._cache_path(("a", 1))
            counter = _CountingResolve()
            with mock.patch.object(Path, "resolve", counter):
                paths = [engine._cache_path(("file", n)) for n in range(100)]
            self.assertEqual(counter.calls, 0)
            # The workspace's own directory of the cache (C0.2).
            self.assertEqual(first.parent, scan_cache.tenant_cache_dir(os.path.join(temp_dir, "cache"), "default"))
            self.assertTrue(all(path.parent == first.parent for path in paths))
            self.assertEqual(len(set(paths)), 100)


if __name__ == "__main__":
    unittest.main()
