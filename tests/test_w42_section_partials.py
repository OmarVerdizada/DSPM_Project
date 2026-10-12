"""W4.2: a scan's report sections from the units' partial folds equal one pass over every record.

Finalize folded every record a partitioned scan stored, reading each unit back - the whole
estate again on every scan, unchanged or not. Each unit now states what it folded when it
is written; finalize merges the states in unit order. The merge must be exact: counts add,
a first-N queue keeps the earliest arrivals, a top-N list the best by key with ties to the
earliest arrival, Counter ties in most_common() by first appearance, and an asset key several
files share (an endpoint's host) is counted once across units.
"""
from __future__ import annotations

import copy
import json
import unittest

from backend.compliance_service import ComplianceReportAccumulator, load_compliance_profiles
from tests.test_partitioned_local_scan import _LocalTest

ALL_FRAMEWORKS = [profile["id"] for profile in load_compliance_profiles()]


def _fold_whole(records: list[dict], frameworks) -> dict:
    accumulator = ComplianceReportAccumulator(True, frameworks)
    for record in records:
        accumulator.add(record)
    return accumulator.apply({})


def _fold_in_units(records: list[dict], frameworks, size: int) -> dict:
    partials = []
    for start in range(0, len(records), size):
        unit = ComplianceReportAccumulator(True, frameworks)
        for record in records[start:start + size]:
            unit.add(record)
        partials.append(json.loads(json.dumps(unit.partial())))  # as stored, and read back
    merged = ComplianceReportAccumulator(True, frameworks)
    for ordinal, partial in enumerate(partials):
        merged.merge(partial, ordinal)
    return merged.apply({})


class TheMergedSectionsAreOnePassTest(_LocalTest):

    def _records(self) -> list[dict]:
        from discovery.discovery_engine import DSPMDiscoveryEngine

        config = self._config("partials", compliance_enabled=True, compliance_frameworks=ALL_FRAMEWORKS)
        records = DSPMDiscoveryEngine(config).run().to_dict()["files"]
        preparer = ComplianceReportAccumulator(True, ALL_FRAMEWORKS)
        for record in records:
            preparer.prepare(record)
        self.assertTrue(any(record.get("findings") for record in records), "nothing to fold")
        # An endpoint's files share their host's key: counted once however they are cut.
        hosted = []
        for index, record in enumerate(records[:6]):
            twin = copy.deepcopy(record)
            twin["path"] = f"C:\\Users\\a\\copy{index}_{record.get('name')}"
            twin["host_id"] = "host-1" if index % 2 else "host-2"
            hosted.append(twin)
        return records + hosted

    def test_every_cut_merges_to_the_whole_fold(self) -> None:
        records = self._records()
        whole = _fold_whole(records, ALL_FRAMEWORKS)
        self.assertGreater(whole["compliance_summary"]["affected_file_count"], 0)
        for size in (1, 2, 3, 5, 7, len(records)):
            self.assertEqual(_fold_in_units(records, ALL_FRAMEWORKS, size), whole, f"units of {size}")

    def test_a_unit_folded_under_other_frameworks_is_refused(self) -> None:
        unit = ComplianceReportAccumulator(True, ["gdpr"])
        merged = ComplianceReportAccumulator(True, ["gdpr", "pci_dss"])
        with self.assertRaises(ValueError):
            merged.merge(json.loads(json.dumps(unit.partial())), 0)

    def test_disabled_compliance_has_nothing_to_merge(self) -> None:
        unit = ComplianceReportAccumulator(False, [])
        merged = ComplianceReportAccumulator(False, [])
        merged.merge(unit.partial(), 0)
        self.assertEqual(merged.apply({}), ComplianceReportAccumulator(False, []).apply({}))


class FinalizeMergesTheUnitsFoldsTest(_LocalTest):
    """A partitioned scan's units state their folds; finalize merges them and reads no records."""

    def _scan(self, name: str):
        from backend import partitioned_scan

        self._use_database(name)
        config = self._config(name)
        return partitioned_scan.run_partitioned_scan(
            "partitioned-local", config, scan_label="estate", compliance_enabled=True,
            compliance_frameworks=ALL_FRAMEWORKS, max_files=3)

    def test_the_merge_reads_nothing_back_and_equals_the_read_back(self) -> None:
        from unittest import mock

        from backend import partitioned_scan, store

        read_back = mock.Mock(side_effect=AssertionError("finalize read the units' records back"))
        with mock.patch.object(partitioned_scan, "_stored_files_alive", read_back):
            merged = self._scan("merged")
        self.assertIsNotNone(merged)
        units = store.list_scan_partitions("partitioned-local", str(merged["scan_id"]))
        self.assertTrue(len(units) > 1 and all(unit["fold"] for unit in units), "a unit stated no fold")
        with mock.patch.object(partitioned_scan, "_merged_folds", return_value=None):
            folded = self._scan("read-back")
        sections = [key for key in ("compliance_summary", "pci_scope_summary", "gdpr_report",
                                    "nist_sp800_60_enterprise_report") if key in folded]
        self.assertTrue(sections)
        for key in sections:
            self.assertEqual(merged.get(key), folded.get(key), key)
        self.assertEqual(merged["summary"], folded["summary"])


if __name__ == "__main__":
    unittest.main()
