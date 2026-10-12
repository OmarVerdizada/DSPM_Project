"""W4.1 step 3: an unchanged unit points at the records it already stored.

Each partition stores its records as one content-addressed artifact (named by the SHA-256 of
its plaintext), and a scan's manifest names them. An unchanged rescan still stored every
unit again - 3.3 MiB per 6,000 files per scan (amplification probe, 2026-10-08) - because
a replayed record carried the moment of its replay, and the reuse index's carrier of the
preview, which changed whenever the index was written back. The stored form leaves the
moment out (the read gives back the scan's) and a replay no longer carries the preview
twice, so an unchanged unit's records are the same bytes and the store names the object
it holds.
"""
from __future__ import annotations

import os
import unittest

from backend import partitioned_scan, store
from tests.test_partitioned_local_scan import TENANT, _LocalTest


class AnUnchangedUnitIsStoredOnceTest(_LocalTest):

    def setUp(self) -> None:
        super().setUp()
        # W4.2: an unchanged unit is now skipped whole; this proves the path a unit that is
        # read takes - per-file reuse - so every unit here is read (the skip has its own
        # parity tests, test_w42_*).
        os.environ["DSPM_UNCHANGED_UNIT_SKIP"] = "0"

    def _scan(self, cache: bool) -> tuple[str, dict]:
        config = self._config(
            "units", persistent_cache_enabled=cache, incremental_enabled=True, incremental_scope="scope-units",
            baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                TENANT, "scope-units", key, size, mtime, version))
        compact = partitioned_scan.run_partitioned_scan(TENANT, config, scan_label="estate",
                                                        compliance_enabled=True, compliance_frameworks=["gdpr"],
                                                        max_files=3)
        self.assertIsNotNone(compact, "the estate was not partitioned")
        return str(compact["scan_id"]), (compact.get("scan_diagnostics") or {}).get("incremental") or {}

    def _refs(self, scan_id: str) -> list[str]:
        with store._connect() as conn:
            return [str(row["records_ref"]) for row in conn.execute(
                "SELECT records_ref FROM scan_records WHERE tenant_id = ? AND scan_id = ? ORDER BY ordinal",
                (TENANT, scan_id)).fetchall()]

    def _assert_stored_once(self, cache: bool) -> None:
        self._scan(cache)
        if cache:
            # The reuse index lost (a new worker, an evicted cache): the next scan replays from
            # the durable baseline and writes the index back, and the one after replays that.
            evicted = list((self.base / "units-cache").rglob("meta_index.sqlite*"))
            self.assertTrue(evicted, "no reuse index to lose")
            for path in evicted:
                path.unlink()
        (second, second_counts), (third, third_counts) = self._scan(cache), self._scan(cache)
        total = int(second_counts.get("total_objects") or 0)
        self.assertEqual(second_counts.get("durable_baseline_hits"), total)
        self.assertEqual(third_counts.get("sidecar_hits" if cache else "durable_baseline_hits"), total)
        refs = self._refs(second)
        self.assertTrue(refs and all(refs), "the units were not stored as artifacts")
        self.assertEqual(self._refs(third), refs, "an unchanged unit was stored again")

        with store._connect() as conn:
            stamp = str(conn.execute("SELECT timestamp FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
                                     (TENANT, third)).fetchone()["timestamp"])
        records = [record for _ordinal, unit in store.iter_scan_records(TENANT, third) for record in unit]
        self.assertTrue(records)
        self.assertTrue(all(record.get("incremental_reused") for record in records), "a file was read again")
        self.assertEqual({record.get("last_scanned_at") for record in records}, {stamp},
                         "a replayed record does not say it was seen by this scan")
        self.assertFalse([record["path"] for record in records if "reused_preview" in record])

    def test_with_the_reuse_index(self) -> None:
        self._use_database("units-l1")
        self._assert_stored_once(cache=True)

    def test_from_the_durable_baseline(self) -> None:
        self._use_database("units-durable")
        self._assert_stored_once(cache=False)


if __name__ == "__main__":
    unittest.main()
