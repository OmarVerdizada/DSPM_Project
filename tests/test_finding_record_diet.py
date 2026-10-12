"""B7c (B1.4): an occurrence stops repeating its parent, and an entity stops indexing forever.

§7.4 measured where an analyzed record's bytes went: `findings` were 62% of it and half of
that was `occurrences`, where every row repeated its parent's `finding_id`, `file_id` and
`location_id`, and five of eleven keys were null for any plain-text file. The canonical
entities beside them carried the same three constants on every framework mapping, and an
id list that grew with every occurrence of the value.

None of it had a reader. What a record says about a finding is unchanged; what it repeats
is gone.
"""

from __future__ import annotations

import unittest

from classification.compliance.canonical_entities import ENTITY_ID_CAP, apply_canonical_entity_registry
from classification.compliance.canonical_model import apply_canonical_finding_model

FILE = {"path": r"C:\Data\customers.csv", "name": "customers.csv", "source": "local", "tenant_id": "t"}


def _finding(**overrides) -> dict:
    finding = {
        "type": "credit_card",
        "data_class": "pan",
        "risk": "HIGH",
        "count": 1,
        "samples": ["411111******1111"],
        "secure_value_fingerprints": ["[redacted:aa]"],
        "canonical_entity_fingerprints": ["cv-1"],
    }
    finding.update(overrides)
    return finding


class AnOccurrenceCarriesOnlyWhatIsTrueOfItTest(unittest.TestCase):

    def _occurrence(self, **overrides) -> dict:
        finding = _finding(occurrences=[{"offset_start": 16, "offset_end": 32,
                                         "redacted_sample": "411111******1111",
                                         "secure_fingerprint": "[redacted:aa]", **overrides}])
        apply_canonical_finding_model(finding, FILE, seen_at="2026-09-17T00:00:00+00:00")
        return finding["occurrences"][0]

    def test_it_does_not_repeat_its_parents_ids(self) -> None:
        occurrence = self._occurrence()
        for repeated in ("finding_id", "file_id", "location_id"):
            with self.subTest(key=repeated):
                self.assertNotIn(repeated, occurrence)

    def test_a_text_file_carries_no_page_row_or_column(self) -> None:
        occurrence = self._occurrence()
        for empty in ("page", "row", "column"):
            with self.subTest(key=empty):
                self.assertNotIn(empty, occurrence, "a null said nothing and was stored on every row")

    def test_where_the_value_is_survives_when_it_is_known(self) -> None:
        occurrence = self._occurrence()
        self.assertEqual((occurrence["offset_start"], occurrence["offset_end"]), (16, 32))
        self.assertEqual(occurrence["redacted_sample"], "411111******1111")

    def test_a_spreadsheet_keeps_its_row_and_column(self) -> None:
        occurrence = self._occurrence(offset_start=0, offset_end=0, row=200, column="B200")
        self.assertEqual((occurrence["row"], occurrence["column"]), (200, "B200"))
        self.assertNotIn("offset_start", occurrence, "a cell has no offset into a byte stream")

    def test_the_finding_is_still_the_way_back(self) -> None:
        finding = _finding(occurrences=[{"offset_start": 16, "offset_end": 32, "redacted_sample": "x"}])
        apply_canonical_finding_model(finding, FILE, seen_at="2026-09-17T00:00:00+00:00")
        self.assertEqual(finding["evidence_ids"], [item["occurrence_id"] for item in finding["occurrences"]])
        self.assertTrue(finding["finding_id"] and finding["location_id"],
                        "what the occurrence stopped repeating has to be on the finding")


class AnEntityStopsRepeatingItselfTest(unittest.TestCase):

    def _entities(self, findings: list[dict]) -> list[dict]:
        for finding in findings:
            apply_canonical_finding_model(finding, FILE, seen_at="2026-09-17T00:00:00+00:00")
        return apply_canonical_entity_registry(findings, FILE)

    def test_a_framework_mapping_says_what_it_is_and_nothing_constant(self) -> None:
        entity = self._entities([_finding()])[0]
        mapping = entity["framework_mapping_details"][0]
        self.assertEqual(sorted(mapping.keys()), ["data_class", "framework", "title"])
        self.assertIn("PCI DSS", entity["framework_mappings"])

    def test_it_indexes_ids_up_to_a_cap_rather_than_forever(self) -> None:
        occurrences = [{"offset_start": index * 10, "offset_end": index * 10 + 4,
                        "redacted_sample": f"v{index}", "secure_fingerprint": f"fp{index}"}
                       for index in range(ENTITY_ID_CAP + 15)]
        entity = self._entities([_finding(occurrences=occurrences, count=len(occurrences))])[0]
        self.assertEqual(len(entity["occurrence_ids"]), ENTITY_ID_CAP)
        self.assertGreaterEqual(entity["occurrence_count"], len(occurrences),
                                "the count is still the truth about how many there were")


if __name__ == "__main__":
    unittest.main()
