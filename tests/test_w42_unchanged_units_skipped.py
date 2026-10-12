"""W4.2: a unit whose listing is what its last read saw is skipped whole - and a scan that
skips answers exactly what a scan that reads everything answers.

Roadmap W4.2 ("unchanged costs nothing"). The planner digests each unit - names, sizes,
modified times, attributes and folder ACLs of everything it walks - and a unit whose digest
and policy are its last read's is not run: the scan reports that read's records, summary,
diagnostics and section fold, and the files its coverage holds count as seen, though no row
of them is written. The proof is parity: each step runs the same estate into two tenants of
one database - one skipping, one reading every unit with per-file reuse as before - and
their estate rows, current findings, baselines, report summary, sections and file records
must be equal. Steps: a first scan, an unchanged rescan, one file changed, several changed,
a folder deleted, a folder renamed, a folder's ACL changed, the policy changed, everything
changed.
"""
from __future__ import annotations

import json
import os
import shutil
import time
import unittest
from pathlib import Path
from unittest import mock

from backend import partitioned_scan, store
from collectors import file_scanner
from discovery.parity import semantic
from tests.test_partitioned_local_scan import _LocalTest

SKIP, READ = "w42-skip", "w42-read"
SCOPE = "scope-w42"


def _incremental(compact: dict) -> dict:
    return (compact.get("scan_diagnostics") or {}).get("incremental") or {}


def _without_ids(value):
    """The two tenants' identifiers are hashed with the tenant's name: compared as what they
    are - an id - everything else as it is."""
    if isinstance(value, dict):
        return {key: ("<ids>" if key.endswith("_ids") else "<id>")
                if (key == "id" or key.endswith("_id") or key.endswith("_ids")) and key != "stable_object_id"
                else _without_ids(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_without_ids(item) for item in value]
    if isinstance(value, str) and value.startswith("entity_"):
        return "<entity>"
    if isinstance(value, str) and len(value) >= 16 and all(char in "0123456789abcdef" for char in value):
        return "<hex>"  # a digest or fingerprint - salted with the tenant
    return value


class _Parity(_LocalTest):

    frameworks = ["gdpr"]

    def setUp(self) -> None:
        super().setUp()
        # Folders the walk meets and does not enter make a scan's coverage partial, and a
        # partial scan prunes nothing (W3.6): parity has to hold with the prunes running.
        for never_entered in ("node_modules", "i_only_folders/inner/node_modules", ".hidden_dir"):
            shutil.rmtree(self.estate / never_entered, ignore_errors=True)
        self._use_database("w42")
        for tenant in (SKIP, READ):
            try:
                store.create_tenant(tenant, tenant)
            except Exception:  # noqa: BLE001 - there already on a shared database
                pass

    def _scan(self, tenant: str) -> dict:
        config = self._config(
            tenant, tenant_id=tenant, persistent_cache_enabled=False, max_depth=None, incremental_enabled=True,
            incremental_scope=SCOPE, baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                tenant, SCOPE, key, size, mtime, version))
        with mock.patch.dict(os.environ, {"DSPM_UNCHANGED_UNIT_SKIP": "1" if tenant == SKIP else "0"}):
            compact = partitioned_scan.run_partitioned_scan(tenant, config, scan_label="estate",
                                                            compliance_enabled=True,
                                                            compliance_frameworks=list(self.frameworks), max_files=3)
        partitioned_scan.join_planners(60)
        self.assertIsNotNone(compact, "the estate was not partitioned")
        return compact

    def _state(self, tenant: str, compact: dict) -> dict:
        with store._connect() as conn:
            assets = sorted(
                (str(row["path"]), str(row["scan_label"]), str(row["risk_level"]), int(row["risk_score"] or 0),
                 int(row["finding_count"] or 0), str(row["folder_key"]), str(row["entry_key"]),
                 json.dumps(_without_ids(semantic(json.loads(store.unpack_json_text(row["detail_json"]) or "{}"))),
                            sort_keys=True, default=str))
                for row in conn.execute("SELECT * FROM assets WHERE tenant_id = ?", (tenant,)).fetchall())
            findings = sorted(
                (str(row["file_path"]), str(row["rule"]), str(row["severity"]), str(row["status"]), str(row["owner"]),
                 str(row["first_seen"])[:0])
                for row in conn.execute("SELECT * FROM findings WHERE tenant_id = ? AND is_current = 1",
                                        (tenant,)).fetchall())
            baselines = sorted(
                (str(row["object_key"]), int(row["size"] or 0), str(row["mtime"]), str(row["content_hash"]),
                 str(row["folder_key"]), str(row["entry_key"]))
                for row in conn.execute("SELECT * FROM scan_object_baselines WHERE tenant_id = ?", (tenant,)).fetchall())
        records = [_without_ids(semantic({key: value for key, value in record.items()
                             if key not in ("incremental_reused", "cache_reused", "incremental_scan_reason",
                                            "detector_metrics", "detector_elapsed_ms")}))
                   for _ordinal, unit in store.iter_scan_records(tenant, str(compact["scan_id"])) for record in unit]
        sections = {key: _without_ids(compact.get(key)) for key in ("compliance_summary", "pci_scope_summary", "gdpr_report",
                                                       "nist_sp800_60_enterprise_report")}
        coverage = (compact.get("scan_diagnostics") or {}).get("scope")
        # The views of the scan built from what it saw (W3.3): its hash changes - their
        # duplicate groups count every file of the scan - its named-scan inventory, and what
        # a filed report reads of it. A skipped unit's files are in each, though not written.
        changes = store.read_hash_changes(tenant)
        named = store.scan_report_inventory_rows_by_label(tenant, "estate")
        source = store.read_report_source(tenant, str(compact["scan_id"])) or {}
        totals = source.get("totals") or {}
        views = _without_ids({
            "duplicates": json.dumps(changes.get("duplicate_hash_paths"), sort_keys=True, default=str),
            "duplicate_count": changes.get("duplicate_hash_path_count"),
            "changed": sorted(str(item.get("path")) for item in changes.get("changed") or []),
            "counts": [changes.get(key) for key in ("changed_count", "added_count", "removed_count")],
            "named": sorted((row.get("path"), row.get("risk_level"), row.get("finding_count"))
                            for row in (named[1] if named else [])),
            "totals": {key: totals.get(key) for key in ("scoped_counts", "scoped_total", "files_kept", "total_files")},
            "report_files": sorted(str(item.get("path") or "") for item in (source.get("report") or {}).get("files")
                                   or []),
        })
        return {"assets": assets, "findings": findings, "baselines": baselines,
                "records": sorted(json.dumps(record, sort_keys=True, default=str) for record in records),
                "summary": compact.get("summary"), "sections": sections, "coverage": coverage, "views": views}

    def _step(self, name: str) -> tuple[dict, dict]:
        skipping, reading = self._scan(SKIP), self._scan(READ)
        mine, theirs = self._state(SKIP, skipping), self._state(READ, reading)
        for key in mine:
            self.assertEqual(mine[key], theirs[key], f"{name}: {key} differs from a scan that reads every unit")
        return skipping, reading

    def _refs(self, scan_id: str) -> list[str]:
        with store._connect() as conn:
            return [str(row[0]) for row in conn.execute(
                "SELECT records_ref FROM scan_records WHERE tenant_id = ? AND scan_id = ? ORDER BY ordinal",
                (SKIP, scan_id)).fetchall()]

    def _assert_seen_by(self, scan_id: str) -> None:
        """A file whose unit the scan skipped is the scan's: the run's drawer answers from its
        row, last scanned is the scan's time, and a reveal reads it with the scan's source."""
        with store._connect() as conn:
            asset = conn.execute("SELECT id FROM assets WHERE tenant_id = ? AND path LIKE ?",
                                 (SKIP, "%b_dept%b2.txt")).fetchone()
            finding = conn.execute("SELECT id FROM findings WHERE tenant_id = ? AND is_current = 1 "
                                   "AND file_path LIKE ? ORDER BY id LIMIT 1", (SKIP, "%d_flat%")).fetchone()
            stamp = str(conn.execute("SELECT timestamp FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
                                     (SKIP, scan_id)).fetchone()[0])
        detail = store.get_inventory_asset(SKIP, str(asset["id"]), scan_id=scan_id)
        self.assertEqual(detail["scan_id"], scan_id)
        self.assertNotEqual(detail.get("detail_available"), False, "the run's drawer lost the file's record")
        self.assertEqual(store.get_inventory_asset(SKIP, str(asset["id"]))["last_scanned_at"], stamp)
        self.assertEqual(store.finding_location(SKIP, str(finding["id"]))["scan_id"], scan_id)

    def _touch(self, relative: str, extra: str) -> None:
        path = self.estate / relative
        time.sleep(0.02)
        path.write_text(path.read_text(encoding="utf-8") + extra, encoding="utf-8")


class AScanThatSkipsAnswersAsOneThatReadsTest(_Parity):

    def test_every_step_matches_a_scan_that_reads_every_unit(self) -> None:
        first, _ = self._step("first scan")
        units = int(((first.get("scan_diagnostics") or {}).get("partitioned") or {}).get("partitions") or 0)
        self.assertGreater(units, 2)

        unchanged, _ = self._step("unchanged rescan")
        counts = _incremental(unchanged)
        self.assertEqual(counts.get("content_reads"), 0)
        self.assertEqual((unchanged.get("scan_diagnostics") or {}).get("units_skipped"), units,
                         "an unchanged unit was read")
        self._assert_seen_by(str(unchanged["scan_id"]))
        # Nothing is stored again: the scan names the very objects its units' last reads stored.
        self.assertEqual(self._refs(str(unchanged["scan_id"])), self._refs(str(first["scan_id"])))

        self._touch("b_dept/b1.txt", "\nand maria.lopez@example.com too\n")
        one, _ = self._step("one file changed")
        # Only the changed unit is read - and of it only the changed file: per-file reuse
        # replays the other two.
        self.assertEqual(_incremental(one).get("content_reads"), 1)
        self.assertEqual((one.get("scan_diagnostics") or {}).get("units_skipped"), units - 1)

        for relative in ("a_root.txt", "d_flat/f04.txt", "h_mixed/sub_b/s3.txt"):
            self._touch(relative, "\nquarterly budget notes, nothing sensitive\n")
        self._step("several files changed")

        shutil.rmtree(self.estate / "b_dept" / "nested")
        deleted, _ = self._step("a folder deleted")
        self.assertTrue((deleted.get("scan_diagnostics") or {}).get("incremental", {}).get("complete"))
        with store._connect() as conn:
            for tenant in (SKIP, READ):
                left = conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id = ? AND path LIKE ?",
                                    (tenant, "%nested%")).fetchone()[0]
                self.assertEqual(left, 0, f"{tenant}: the deleted folder's rows were not pruned")

        (self.estate / "h_mixed" / "sub_a").rename(self.estate / "h_mixed" / "sub_z")
        self._step("a folder renamed")

        self._step("unchanged after the moves")

    def test_a_folders_acl_changing_reads_its_unit_again(self) -> None:
        self._step("first scan")
        real = file_scanner.local_acl
        changed = str((self.estate / "d_flat").resolve())  # %TEMP% is spelled short; the planner resolves

        def acl(path):
            value = real(path)
            if str(Path(path).resolve()) == changed:
                return {**(value or {}), "owner": "CORP\\someone-else"}
            return value

        with mock.patch.object(file_scanner, "local_acl", side_effect=acl):
            skipping, _ = self._step("d_flat's ACL changed")
        diagnostics = skipping.get("scan_diagnostics") or {}
        units = int((diagnostics.get("partitioned") or {}).get("partitions") or 0)
        # d_flat's three runs are read again - their files' ACLs, not their content (E14).
        self.assertEqual(diagnostics.get("units_skipped"), units - 3, "the changed ACL was not noticed")
        self.assertEqual((diagnostics.get("acl_refresh") or {}).get("files_reread_total"), 8)
        self.assertEqual(_incremental(skipping).get("content_reads"), 0)


class APolicyChangeReadsEverythingTest(_Parity):

    def test_new_frameworks_read_every_unit(self) -> None:
        self._step("first scan")
        self.frameworks = ["gdpr", "pci_dss"]
        skipping, _ = self._step("frameworks changed")
        self.assertFalse((skipping.get("scan_diagnostics") or {}).get("units_skipped"),
                         "a unit was skipped under another policy")


class EverythingChangedTest(_Parity):

    def test_every_file_rewritten(self) -> None:
        first, _ = self._step("first scan")
        for path in sorted(self.estate.rglob("*.txt")):
            time.sleep(0.001)
            path.write_text(path.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
        skipping, _ = self._step("everything changed")
        # Every file read again; a unit holding only folders with no file in them is still skipped.
        self.assertEqual(_incremental(skipping).get("content_reads"), _incremental(first).get("content_reads"))


if __name__ == "__main__":
    unittest.main()
