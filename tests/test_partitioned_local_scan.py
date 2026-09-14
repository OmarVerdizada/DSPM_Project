"""B2.2b-3: a real local scan, run in partitions, reports what one scan reports.

B2.2b-1 and -2 proved the storage half: the same records written as partitions and
finalized leave the same rows and the same report as one save. This proves the
other half on the real engine over real files: a target cut into partitions is
scanned into the same records, in the same order, with the same summary, report
sections and estate - while no partition ever holds more than its share.

The order is the hard part. A scan's file order is its walk's, files and subfolders
interleaved as each folder lists them, and several report sections keep the first 25
items or break ties by arrival.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

from backend import partitioned_scan, store
from backend.compliance_service import enrich_report_with_compliance, load_compliance_profiles
from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.parity import accuracy_projection
from discovery.partition import plan_bounded_partitions

ALL_FRAMEWORKS = [profile["id"] for profile in load_compliance_profiles()]
TENANT = "partitioned-local"
_VOLATILE_COLUMNS = {
    "current_scan_id", "scan_id", "last_scan_id", "observed_at", "first_seen", "last_seen",
    "sla_due", "last_seen_at", "updated_at", "seq",
}
_TABLES = ("assets", "asset_versions", "findings", "finding_occurrences", "finding_index", "scan_object_baselines")

CONTENT = [
    "contact {n}@example.com about the invoice",
    "card 4111 1111 1111 1111 exp 09/29 for customer {n}",
    "ssn 123-45-67{n:02d} employee record",
    "password=Secret{n}Value on the shared drive",
    "quarterly budget notes, nothing sensitive {n}",
]


def _write(path: Path, index: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(line.format(n=index % 97) for line in (CONTENT[index % 5], CONTENT[(index + 2) % 5])),
                    encoding="utf-8")


def build_estate(root: Path) -> int:
    """Files and folders interleaved at every level, so order is actually tested."""
    layout = [
        "a_root.txt",
        "b_dept/b1.txt", "b_dept/b2.txt", "b_dept/nested/n1.txt", "b_dept/nested/n2.txt", "b_dept/b3.txt",
        "c_root.txt",
        *[f"d_flat/f{i:02d}.txt" for i in range(8)],
        "e_deep/l1/l2/l3/l4/too_deep.txt",
        "g_root.txt",
        "h_mixed/h1.txt", "h_mixed/sub_a/s1.txt", "h_mixed/h2.txt", "h_mixed/sub_b/s2.txt", "h_mixed/sub_b/s3.txt",
        "h_mixed/sub_b/s4.txt", "h_mixed/sub_b/s5.txt", "h_mixed/h3.txt",
        ".hidden_dir/secret.txt",
        "node_modules/package.txt",
    ]
    for index, relative in enumerate(layout):
        _write(root / relative, index)
    (root / "f_empty").mkdir()
    return len(layout)


class _LocalTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.base = Path(self._temp.name)
        self.estate = self.base / "estate"
        build_estate(self.estate)
        # %TEMP% is skipped by the collector on purpose; keep only the node_modules rule
        # so skipped folders are exercised too.
        self.skip = patch.object(file_scanner, "is_skipped_scan_path",
                                 side_effect=lambda path: "node_modules" in str(path).lower())
        self.owner = patch.object(file_scanner, "file_owner", MagicMock(return_value="CORP\\owner"))
        self.skip.start()
        self.owner.start()
        self._previous_path = store.DB_PATH
        self._env = mock.patch.dict(os.environ, {})
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self.owner.stop()
        self.skip.stop()
        self._temp.cleanup()

    def _use_database(self, name: str) -> None:
        store.DB_PATH = self.base / f"{name}.sqlite"
        os.environ["DSPM_ARTIFACT_DIR"] = str(self.base / f"{name}-artifacts")
        store.init_db()
        try:
            store.create_tenant(TENANT, TENANT)
        except Exception:
            pass

    def _config(self, name: str = "db", **overrides) -> ScanConfig:
        settings = dict(
            tenant_id=TENANT, local_path=str(self.estate), max_depth=4, use_sample_when_empty=True,
            persistent_cache_enabled=False, incremental_enabled=False, max_workers=2,
            cache_dir=str(self.base / f"{name}-cache"),
        )
        settings.update(overrides)
        return ScanConfig(**settings)

    def _rows(self) -> dict:
        """The estate, less what differs between any two runs of the same scan.

        Two scans of the same files have different scan ids, clocks and detector
        timings whether or not either is partitioned - inside the stored record and the
        materialized finding response too. Those come out with the definition the
        findings-parity projection uses, plus the scan id, and nothing else does.
        """
        from discovery.parity import semantic

        def without_run_fields(value):
            value = semantic(value)
            if isinstance(value, dict):
                return {k: without_run_fields(v) for k, v in value.items() if k != "scan_id"}
            if isinstance(value, list):
                return [without_run_fields(v) for v in value]
            return value

        def comparable(column: str, value) -> str:
            if column in ("detail_json", "response_json", "snapshot_json"):
                try:
                    parsed = json.loads(store.unpack_json_text(value) or "null")
                except (TypeError, ValueError):
                    return str(value)
                return json.dumps(without_run_fields(parsed), sort_keys=True)
            return str(value)

        state = {}
        with store._connect() as conn:
            for table in _TABLES:
                rows = conn.execute(f"SELECT * FROM {table} WHERE tenant_id = ?", (TENANT,)).fetchall()
                serialised = sorted(
                    json.dumps({k: comparable(k, row[k]) for k in row.keys() if k not in _VOLATILE_COLUMNS},
                               sort_keys=True)
                    for row in rows
                )
                state[table] = (len(rows), hashlib.sha256("\n".join(serialised).encode()).hexdigest())
            state["finding_order"] = [str(r["finding_id"]) for r in conn.execute(
                "SELECT finding_id FROM finding_index WHERE tenant_id = ? ORDER BY scan_id DESC, seq", (TENANT,),
            ).fetchall()]
        return state


class ThePlanIsTheWalkCutIntoPiecesTest(_LocalTest):

    def test_units_in_order_collect_exactly_the_single_walk(self) -> None:
        single = [r["path"] for r in DSPMDiscoveryEngine(self._config())._collect_records()]
        self.assertGreater(len(single), 15)
        plan = plan_bounded_partitions(self._config(), max_files=3)
        self.assertIsNotNone(plan)
        kinds = {unit["kind"] for unit in plan["units"]}
        self.assertEqual(kinds, {"files", "subtree"}, "the estate should need both kinds of unit")

        pieced: list[str] = []
        for unit in plan["units"]:
            records = DSPMDiscoveryEngine(partitioned_scan._unit_config(self._config(), unit))._collect_records()
            self.assertLessEqual(len(records), 3, f"a unit holds more than the budget: {unit}")
            self.assertGreater(len(records), 0, f"a unit with nothing to scan: {unit}")
            pieced.extend(r["path"] for r in records)
        self.assertEqual(pieced, single, "the partitions do not reproduce the walk's order")
        self.assertEqual(plan["files"], len(single))
        self.assertEqual(plan["skipped_dirs"], 2, "the hidden folder and node_modules are skipped at the root")

    def test_a_target_that_fits_one_partition_is_not_partitioned(self) -> None:
        self.assertIsNone(plan_bounded_partitions(self._config(), max_files=10_000))

    def test_a_depth_limit_is_honoured_by_every_unit(self) -> None:
        for depth in (0, 1, 2):
            config = self._config(max_depth=depth)
            single = [r["path"] for r in DSPMDiscoveryEngine(config)._collect_records()]
            plan = plan_bounded_partitions(config, max_files=2)
            if plan is None:
                continue
            pieced = [r["path"] for unit in plan["units"]
                      for r in DSPMDiscoveryEngine(partitioned_scan._unit_config(config, unit))._collect_records()]
            self.assertEqual(pieced, single, f"max_depth={depth}")


class APartitionedScanReportsWhatOneScanReportsTest(_LocalTest):

    def _single(self, config: ScanConfig, *, label: str, frameworks) -> dict:
        data = DSPMDiscoveryEngine(config).run().to_dict()
        enrich_report_with_compliance(data, bool(frameworks), frameworks)
        data["scan_label"] = label
        store.save_scan_history(TENANT, data)
        return store.read_scan_report(TENANT, data["scan_id"])

    def _partitioned(self, config: ScanConfig, *, label: str, frameworks, max_files: int = 3) -> dict:
        compact = partitioned_scan.run_partitioned_local_scan(
            TENANT, config, scan_label=label, compliance_enabled=bool(frameworks),
            compliance_frameworks=frameworks, max_files=max_files,
        )
        self.assertIsNotNone(compact, "the estate was not partitioned")
        self.assertTrue(compact["files_omitted"])
        return store.read_scan_report(TENANT, compact["scan_id"])

    def test_the_same_records_order_summary_sections_and_estate(self) -> None:
        self._use_database("single")
        single = self._single(self._config("single"), label="estate", frameworks=ALL_FRAMEWORKS)
        single_rows = self._rows()

        self._use_database("partitioned")
        seen: list[int] = []
        real_persist = store.persist_partition

        def watching(*args, **kwargs):
            seen.append(len(args[5]))
            return real_persist(*args, **kwargs)

        with patch.object(store, "persist_partition", side_effect=watching):
            partitioned = self._partitioned(self._config("partitioned"), label="estate", frameworks=ALL_FRAMEWORKS)
        partitioned_rows = self._rows()

        self.assertGreater(len(seen), 4, "the scan was not really partitioned")
        self.assertLessEqual(max(seen), 3, "a partition was handed more records than the budget")
        self.assertEqual([f["path"] for f in partitioned["files"]], [f["path"] for f in single["files"]])
        self.assertEqual(accuracy_projection(partitioned), accuracy_projection(single))
        self.assertEqual(partitioned["summary"], single["summary"])
        for key in ("compliance_summary", "pci_scope_summary", "gdpr_report", "nist_sp800_60_enterprise_report"):
            self.assertIn(key, single)
            self.assertEqual(partitioned[key], single[key], f"{key} differs")
        for key in ("records", "skipped_dirs", "files_discovered"):
            self.assertEqual(partitioned["scan_diagnostics"].get(key), single["scan_diagnostics"].get(key), key)
        self.assertEqual(partitioned["scan_diagnostics"]["local_path"], single["scan_diagnostics"]["local_path"])
        single_incremental = single["scan_diagnostics"]["incremental"]
        partitioned_incremental = partitioned["scan_diagnostics"]["incremental"]
        for key in ("total_objects", "content_reads", "complete"):
            self.assertEqual(partitioned_incremental[key], single_incremental[key], key)
        self.assertEqual(partitioned_rows, single_rows, "the estate differs")
        self.assertGreater(single_rows["findings"][0], 0)

    def test_an_unchanged_rescan_reuses_everything_under_the_scans_own_scope(self) -> None:
        self._use_database("rescan")

        def config() -> ScanConfig:
            return self._config(
                "rescan", persistent_cache_enabled=True, incremental_enabled=True, incremental_scope="scope-local",
                baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                    TENANT, "scope-local", key, size, mtime, version),
            )

        first = self._partitioned(config(), label="estate", frameworks=["gdpr"])
        second = self._partitioned(config(), label="estate", frameworks=["gdpr"])
        incremental = second["scan_diagnostics"]["incremental"]
        self.assertEqual(incremental["unchanged_objects"], incremental["total_objects"])
        self.assertEqual(incremental["content_reads"], 0)
        self.assertTrue(incremental["complete"])
        self.assertEqual(incremental["deleted_objects"], 0)
        self.assertEqual(accuracy_projection(second), accuracy_projection(first))
        with store._connect() as conn:
            baselines = conn.execute("SELECT COUNT(*) FROM scan_object_baselines WHERE tenant_id = ?", (TENANT,)).fetchone()[0]
        self.assertEqual(baselines, incremental["total_objects"])


class WhenNotToPartitionTest(_LocalTest):

    def test_a_small_target_runs_as_one_scan(self) -> None:
        self._use_database("small")
        self.assertIsNone(partitioned_scan.run_partitioned_local_scan(TENANT, self._config("small"), max_files=10_000))

    def test_the_demo_dataset_is_never_partitioned(self) -> None:
        self._use_database("demo")
        for index in range(6):
            _write(self.estate / "enterprise_test_data" / f"sample{index}.txt", index)
        self.assertIsNone(partitioned_scan.run_partitioned_local_scan(TENANT, self._config("demo"), max_files=3))

    def test_the_flag_is_off_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_PARTITIONED_SCANS", None)
            self.assertFalse(partitioned_scan.partitioned_scans_enabled())
        with mock.patch.dict(os.environ, {"DSPM_PARTITIONED_SCANS": "1"}):
            self.assertTrue(partitioned_scan.partitioned_scans_enabled())


class ACancelledScanStopsTest(_LocalTest):

    def test_it_stops_marks_its_unit_failed_and_writes_no_report(self) -> None:
        self._use_database("cancel")
        job = MagicMock(id="job-cancel", cancel_requested=False, progress=0, message="")
        real_persist = store.persist_partition

        def persist_then_cancel(*args, **kwargs):
            result = real_persist(*args, **kwargs)
            job.cancel_requested = True
            return result

        with patch.object(store, "persist_partition", side_effect=persist_then_cancel):
            with self.assertRaises(RuntimeError):
                partitioned_scan.run_partitioned_local_scan(TENANT, self._config("cancel"), job=job, max_files=3)
        with store._connect() as conn:
            scans = [r["scan_id"] for r in conn.execute(
                "SELECT DISTINCT scan_id FROM scan_partitions WHERE tenant_id = ?", (TENANT,)).fetchall()]
            reports = conn.execute("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (TENANT,)).fetchone()[0]
        self.assertEqual(len(scans), 1)
        self.assertEqual(reports, 0)
        summary = store.scan_partition_summary(TENANT, scans[0])
        self.assertEqual(summary["done"], 1)
        self.assertEqual(summary["running"], 0, "the scan left a unit claimed")


class TheApiRunsItTest(_LocalTest):

    def test_the_payload_runner_returns_the_compact_report_and_alerts(self) -> None:
        from backend import app as app_module

        self._use_database("api")
        payload = MagicMock(scan_label="api-scan", compliance_enabled=True, compliance_frameworks=["gdpr", "pci_dss"])
        principal = MagicMock(tenant_id=TENANT, subject="tester")
        with patch.object(partitioned_scan, "partition_max_files", return_value=3):
            data = app_module._run_partitioned_scan_payload(self._config("api"), payload, principal)
        self.assertTrue(data["files_omitted"])
        self.assertEqual(data["scan_label"], "api-scan")
        self.assertIn("alerts", data)
        stored = store.read_scan_report(TENANT, data["scan_id"])
        self.assertEqual(len(stored["files"]), data["file_count"])
        self.assertTrue(stored["scan_diagnostics"]["partitioned"]["enabled"])


if __name__ == "__main__":
    unittest.main()
