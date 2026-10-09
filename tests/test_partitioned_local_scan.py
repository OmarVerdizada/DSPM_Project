"""B2.2b-3: a real local scan, run in partitions, reports what one scan reports.

B2.2b-1 and -2 proved the storage half: the same records written as partitions and
finalized leave the same rows and the same report as one save. This proves the
other half on the real engine over real files: a target cut into partitions is
scanned into the same records, in the same order, with the same summary, report
sections and estate - while no partition ever holds more than its share.

The order is the hard part. A scan's file order is its walk's, files and subfolders
interleaved as each folder lists them, and several report sections keep the first 25
items or break ties by arrival. The other hard part is what a walk observes without
producing a record - an unreadable folder, a skipped one - because a plan that drops
one makes a scan look complete when it was not, and finalize then prunes.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

from backend import db, partitioned_scan, store
from backend.compliance_service import enrich_report_with_compliance, load_compliance_profiles
from collectors import file_scanner
from discovery import discovery_engine
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.parity import accuracy_projection
from discovery.partition import plan_bounded_partitions

ALL_FRAMEWORKS = [profile["id"] for profile in load_compliance_profiles()]
TENANT = "partitioned-local"
_VOLATILE_COLUMNS = {
    "current_scan_id", "scan_id", "last_scan_id", "observed_at", "first_seen", "last_seen",
    "sla_due", "last_seen_at", "updated_at", "seq",
    # W2.1: digests of what a row says, over the run's own record - a cache key, like updated_at.
    "row_digest", "snapshot_digest",
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
        "i_only_folders/inner/node_modules/hidden_by_rule.txt",
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
            tenant_id=TENANT, local_path=str(self.estate), max_depth=4, walk_local_path=True,
            persistent_cache_enabled=False, incremental_enabled=False, max_workers=2,
            cache_dir=str(self.base / f"{name}-cache"),
        )
        settings.update(overrides)
        return ScanConfig(**settings)

    def _root(self, config: ScanConfig) -> str:
        return str(Path(config.local_path).resolve())

    def _single_walk(self, config: ScanConfig) -> tuple[list[str], dict]:
        engine = DSPMDiscoveryEngine(config)
        return [r["path"] for r in engine._collect_records()], engine.last_scan_diagnostics

    def _pieced_walk(self, config: ScanConfig, plan: dict, *, limit: int | None = None) -> tuple[list[str], int, list]:
        paths: list[str] = []
        skipped = 0
        unreadable: list = []
        for unit in plan["units"]:
            engine = DSPMDiscoveryEngine(partitioned_scan._unit_config(config, unit, self._root(config)))
            records = engine._collect_records()
            if limit is not None:
                self.assertLessEqual(len(records), limit, f"a unit holds more than the budget: {unit}")
            paths.extend(r["path"] for r in records)
            skipped += int(engine.last_scan_diagnostics.get("skipped_dirs") or 0)
            unreadable.extend(engine.last_scan_diagnostics.get("unreadable_dirs") or [])
        return paths, skipped, unreadable

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

    def test_runs_in_order_collect_exactly_the_single_walk(self) -> None:
        config = self._config()
        single, diagnostics = self._single_walk(config)
        self.assertGreater(len(single), 15)
        plan = plan_bounded_partitions(config, max_files=3)
        self.assertIsNotNone(plan)
        self.assertEqual({unit["kind"] for unit in plan["units"]}, {"run"})
        pieced, skipped, _unreadable = self._pieced_walk(config, plan, limit=3)
        self.assertEqual(pieced, single, "the partitions do not reproduce the walk's order")
        self.assertEqual(plan["files"], len(single))
        self.assertEqual(skipped, diagnostics.get("skipped_dirs"),
                         "a skipped folder was dropped from the plan, so no partition reports it")

    def test_a_target_that_fits_one_partition_is_not_partitioned(self) -> None:
        self.assertIsNone(plan_bounded_partitions(self._config(), max_files=10_000))

    def test_every_depth_limit_is_honoured(self) -> None:
        for depth in (0, 1, 2, 3, 4):
            with self.subTest(max_depth=depth):
                config = self._config(max_depth=depth)
                single, diagnostics = self._single_walk(config)
                plan = plan_bounded_partitions(config, max_files=2)
                if plan is None:
                    continue
                pieced, skipped, _ = self._pieced_walk(config, plan, limit=2)
                self.assertEqual(pieced, single)
                self.assertEqual(skipped, diagnostics.get("skipped_dirs"))


class APlanNeverLosesWhatAWalkObservesTest(_LocalTest):

    def test_an_unreadable_folder_is_still_walked_and_the_scan_is_not_complete(self) -> None:
        """A folder holding only an unreadable subfolder used to vanish from the plan.

        The partitioned scan then reported no unreadable folder, called itself complete,
        and finalize pruned whatever had been under it on the previous scan.
        """
        denied = self.estate / "j_parent" / "denied"
        _write(denied / "payroll.txt", 3)
        real_iterdir = Path.iterdir

        def refusing(path):
            if path.name == "denied":
                raise PermissionError(13, "Access is denied", str(path))
            return real_iterdir(path)

        with patch.object(Path, "iterdir", refusing):
            config = self._config()
            single, diagnostics = self._single_walk(config)
            plan = plan_bounded_partitions(config, max_files=3)
            pieced, skipped, unreadable = self._pieced_walk(config, plan, limit=3)
        self.assertEqual(pieced, single)
        self.assertTrue(diagnostics.get("unreadable_dirs"))
        self.assertEqual(len(unreadable), len(diagnostics["unreadable_dirs"]),
                         "the unreadable folder was dropped from the plan")

        self._use_database("unreadable-single")
        with patch.object(Path, "iterdir", refusing):
            one = DSPMDiscoveryEngine(self._config("unreadable-single")).run().to_dict()
        self._use_database("unreadable-partitioned")
        with patch.object(Path, "iterdir", refusing):
            compact = partitioned_scan.run_partitioned_scan(
                TENANT, self._config("unreadable-partitioned"), max_files=3)
        stored = store.read_scan_report(TENANT, compact["scan_id"])
        self.assertFalse(one["scan_diagnostics"]["incremental"]["complete"])
        self.assertFalse(stored["scan_diagnostics"]["incremental"]["complete"],
                         "a partitioned scan that could not read a folder called itself complete")

    @unittest.skipUnless(os.name == "nt", "junctions are a Windows feature")
    def test_a_junction_to_a_sibling_folder_is_walked_as_a_single_scan_walks_it(self) -> None:
        link = self.estate / "h_mixed" / "k_link"
        created = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(self.estate / "b_dept")],
                                 capture_output=True, text=True)
        if created.returncode != 0:
            self.skipTest(f"could not create a junction: {created.stderr.strip()}")
        try:
            config = self._config()
            single, diagnostics = self._single_walk(config)
            self.assertTrue(any("k_link" in path for path in single), "the single walk did not follow the junction")
            plan = plan_bounded_partitions(config, max_files=3)
            pieced, skipped, _ = self._pieced_walk(config, plan)
            self.assertEqual(pieced, single, "files reached through a junction were lost or reordered")
            self.assertEqual(skipped, diagnostics.get("skipped_dirs"))
        finally:
            os.rmdir(link)

    def test_a_wide_tree_of_small_folders_packs_into_few_units(self) -> None:
        wide = self.base / "wide"
        for index in range(60):
            _write(wide / f"folder{index:02d}" / "only.txt", index)
        config = self._config(local_path=str(wide))
        single, _ = self._single_walk(config)
        plan = plan_bounded_partitions(config, max_files=10)
        self.assertIsNotNone(plan)
        self.assertLessEqual(len(plan["units"]), 7, "sixty one-file folders were not packed")
        pieced, _, _ = self._pieced_walk(config, plan, limit=10)
        self.assertEqual(pieced, single)

    def test_a_flat_folder_is_listed_once_not_once_per_run(self) -> None:
        self._use_database("listing")
        flat = self.estate / "d_flat"
        real_iterdir = Path.iterdir
        listed = {"n": 0}

        def counting(path):
            if path.name == "d_flat":
                listed["n"] += 1
            return real_iterdir(path)

        with patch.object(Path, "iterdir", counting):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("listing"), max_files=3)
        self.assertIsNotNone(compact)
        self.assertTrue(flat.is_dir())
        self.assertEqual(listed["n"], 1, "each run of the flat folder listed the whole folder again")


class APartitionedScanReportsWhatOneScanReportsTest(_LocalTest):

    def _single(self, config: ScanConfig, *, label: str, frameworks) -> dict:
        data = DSPMDiscoveryEngine(config).run().to_dict()
        enrich_report_with_compliance(data, bool(frameworks), frameworks)
        data["scan_label"] = label
        store.save_scan_history(TENANT, data)
        return store.read_scan_report(TENANT, data["scan_id"])

    def _partitioned(self, config: ScanConfig, *, label: str, frameworks, max_files: int = 3) -> dict:
        compact = partitioned_scan.run_partitioned_scan(
            TENANT, config, scan_label=label, compliance_enabled=bool(frameworks),
            compliance_frameworks=frameworks, max_files=max_files,
        )
        self.assertIsNotNone(compact, "the estate was not partitioned")
        self.assertTrue(compact["files_omitted"])
        return store.read_scan_report(TENANT, compact["scan_id"])

    @unittest.skipIf(db.is_postgres(), "compares two databases; on PostgreSQL the suite has one")
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
        for key in ("records", "skipped_dirs", "files_discovered", "unreadable_dirs"):
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

    def test_a_folder_that_disappears_after_planning_does_not_stop_the_scan(self) -> None:
        self._use_database("vanish")
        real_plan = partitioned_scan.plan_bounded_partitions

        def plan_then_delete(*args, **kwargs):
            plan = real_plan(*args, **kwargs)
            shutil.rmtree(self.estate / "d_flat")
            return plan

        with patch.object(partitioned_scan, "plan_bounded_partitions", side_effect=plan_then_delete):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("vanish"), max_files=3)
        stored = store.read_scan_report(TENANT, compact["scan_id"])
        after, _ = self._single_walk(self._config("vanish"))
        self.assertEqual([f["path"] for f in stored["files"]], after)
        # A walk that cannot list a folder reports it and is not complete; neither is
        # this scan, so finalize does not prune what the folder held (B3 review).
        self.assertFalse(stored["scan_diagnostics"]["incremental"]["complete"])
        self.assertTrue(any("d_flat" in entry for entry in stored["scan_diagnostics"]["unreadable_dirs"]))


class WhenNotToPartitionTest(_LocalTest):

    def test_a_small_target_runs_as_one_scan(self) -> None:
        self._use_database("small")
        self.assertIsNone(partitioned_scan.run_partitioned_scan(TENANT, self._config("small"), max_files=10_000))

    def test_the_demo_dataset_is_never_partitioned(self) -> None:
        self._use_database("demo")
        for index in range(6):
            _write(self.estate / "enterprise_test_data" / f"sample{index}.txt", index)
        self.assertIsNone(partitioned_scan.run_partitioned_scan(TENANT, self._config("demo"), max_files=3))

    def test_the_flag_is_on_by_default_since_g0(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_PARTITIONED_SCANS", None)
            self.assertTrue(partitioned_scan.partitioned_scans_enabled())
        with mock.patch.dict(os.environ, {"DSPM_PARTITIONED_SCANS": "0"}):
            self.assertFalse(partitioned_scan.partitioned_scans_enabled())


class StoppingTest(_LocalTest):

    def test_a_cancelled_scan_stops_marks_its_unit_failed_and_writes_no_report(self) -> None:
        self._use_database("cancel")
        job = MagicMock(id="job-cancel", cancel_requested=False, progress=0, message="")
        real_persist = store.persist_partition

        def persist_then_cancel(*args, **kwargs):
            result = real_persist(*args, **kwargs)
            job.cancel_requested = True
            return result

        with patch.object(store, "persist_partition", side_effect=persist_then_cancel):
            with self.assertRaises(RuntimeError):
                partitioned_scan.run_partitioned_scan(TENANT, self._config("cancel"), job=job, max_files=3)
        with store._connect() as conn:
            scans = [r["scan_id"] for r in conn.execute(
                "SELECT DISTINCT scan_id FROM scan_partitions WHERE tenant_id = ?", (TENANT,)).fetchall()]
            reports = conn.execute("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (TENANT,)).fetchone()[0]
        self.assertEqual(len(scans), 1)
        self.assertEqual(reports, 0)
        summary = store.scan_partition_summary(TENANT, scans[0])
        self.assertEqual(summary["done"], 1)
        self.assertEqual(summary["running"], 0, "the scan left a unit claimed")

    def test_no_wall_clock_ends_the_scan_or_its_planning(self) -> None:
        # The whole scan had a time budget - a day since audit 2026-10 finding 11 - and past
        # it the scan was failed for good. Since W1.1 it has none: each unit has a budget, and
        # a scan that stops making progress is paused (tests/test_w11_partitioned_path.py).
        self._use_database("deadline")
        with patch.object(partitioned_scan, "queue_wait_seconds", return_value=1e-9):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("deadline"), max_files=3)
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")

    def test_a_scan_root_out_of_reach_fails_its_partitions_instead_of_writing_them_empty(self) -> None:
        # A worker on another host, or a root taken away mid-scan: written as empty
        # partitions, finalize would prune everything under it (B3 review).
        self._use_database("unreachable")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("unreachable"),
                                                         request={"local_path": "estate"}, max_files=3)
        shutil.rmtree(self.estate)
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "1"}):
            with self.assertRaisesRegex(partitioned_scan.ScanStopped, "FileNotFoundError"):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("unreachable"))
        self.assertNotIn("done", {unit["status"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])})


class TheApiRunsItTest(_LocalTest):

    def test_the_payload_runner_returns_the_compact_report_and_alerts(self) -> None:
        from backend import app as app_module

        self._use_database("api")
        payload = MagicMock(scan_label="api-scan", compliance_enabled=True, compliance_frameworks=["gdpr", "pci_dss"],
                            save_report=False)
        principal = MagicMock(tenant_id=TENANT, subject="tester")
        with patch.object(partitioned_scan, "partition_max_files", return_value=3):
            data = app_module._run_partitioned_scan_payload(self._config("api"), payload, principal)
        self.assertTrue(data["files_omitted"])
        self.assertEqual(data["scan_label"], "api-scan")
        self.assertIn("alerts", data)
        self.assertNotIn("scan_warnings", data)
        stored = store.read_scan_report(TENANT, data["scan_id"])
        self.assertEqual(len(stored["files"]), data["file_count"])
        self.assertTrue(stored["scan_diagnostics"]["partitioned"]["enabled"])


if __name__ == "__main__":
    unittest.main()
