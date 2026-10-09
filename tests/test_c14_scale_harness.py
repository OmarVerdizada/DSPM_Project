"""C14: the scale harness measures what the gate is decided on, and never fills a disk.

The 200,000-file run needs a host with room for it; these tests prove the harness that
will run there - the reserve it keeps, the refusal and the bounded mode on a host below
it, the process-tree memory it samples, and a small real run with its parity checks.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import unittest
from collections import namedtuple
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import c14_scale_harness as harness  # noqa: E402

GIB = harness.GIB
Usage = namedtuple("Usage", "total used free")
# this host when C14 ran: a 78.7 GiB system volume with 3.8 GiB free
SMALL_HOST = Usage(int(78.7 * GIB), int(74.9 * GIB), int(3.8 * GIB))
SCALE_HOST = Usage(500 * GIB, 100 * GIB, 400 * GIB)


class TheReserveTest(unittest.TestCase):

    def test_ten_gib_or_a_fifth_whichever_is_greater(self) -> None:
        self.assertEqual(harness.reserve_bytes(20 * GIB), 10 * GIB)
        self.assertEqual(harness.reserve_bytes(int(78.7 * GIB)), int(78.7 * GIB * 0.20))

    def test_the_gate_does_not_fit_this_host_and_fits_a_scale_host(self) -> None:
        with mock.patch.object(harness.shutil, "disk_usage", return_value=SMALL_HOST):
            small = harness.plan(200_000, Path("C:/SentroScale"))
        with mock.patch.object(harness.shutil, "disk_usage", return_value=SCALE_HOST):
            large = harness.plan(200_000, Path("C:/SentroScale"))
        self.assertFalse(small["within_reserve"])
        self.assertTrue(large["within_reserve"])
        self.assertEqual(small["basis"], "quality audit")
        # 200,000 files at the audit's 157 KB for each of four saved scans, plus margin: ~150 GiB
        self.assertGreater(small["projected_gib"], 100)

    def test_a_bounded_run_writes_at_most_a_small_share_of_what_is_free(self) -> None:
        free = int(3.8 * GIB)
        self.assertEqual(harness.bounded_cap(free, 100), 100 * harness.MIB)
        self.assertEqual(harness.bounded_cap(free, 100_000), int(free * 0.15))

    def test_the_largest_safe_corpus_fits_and_one_step_more_does_not(self) -> None:
        cap, per_file = 500 * harness.MIB, 60_000
        files = harness.largest_safe_files(per_file, cap)
        self.assertGreater(files, 0)
        self.assertEqual(files % 500, 0)
        self.assertLessEqual(harness.projected_bytes(files, per_file), cap)
        self.assertGreater(harness.projected_bytes(files + 500, per_file), cap)
        self.assertEqual(harness.largest_safe_files(per_file, cap, ceiling=1000), 1000)


class OnAHostBelowItsReserveTest(unittest.TestCase):

    def setUp(self) -> None:
        self.root = ROOT / "tmp" / f"c14-guard-{os.getpid()}"
        self.addCleanup(lambda: self.root.exists() and harness.shutil.rmtree(self.root, ignore_errors=True))

    def run_main(self, *argv: str) -> tuple[int, dict]:
        out = io.StringIO()
        with mock.patch.object(harness.shutil, "disk_usage", return_value=SMALL_HOST), redirect_stdout(out):
            code = harness.main(["--root", str(self.root), *argv])
        return code, json.loads(out.getvalue())

    def test_plan_only_says_held_for_scale_host_and_writes_nothing(self) -> None:
        with mock.patch.object(harness, "measure") as measure:
            code, report = self.run_main("--files", "200000", "--plan-only", "--allow-below-reserve-mb", "400")
        self.assertEqual(code, 3)
        self.assertTrue(report["held"][0].startswith("HELD FOR SCALE HOST"), report["held"])
        measure.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_without_permission_for_a_bounded_run_nothing_runs(self) -> None:
        with mock.patch.object(harness, "measure") as measure:
            code, report = self.run_main("--files", "200000")
        self.assertEqual(code, 3)
        measure.assert_not_called()

    def test_a_cap_too_small_for_even_the_calibration_runs_nothing(self) -> None:
        with mock.patch.object(harness, "measure") as measure:
            code, report = self.run_main("--files", "200000", "--allow-below-reserve-mb", "5")
        self.assertEqual(code, 3)
        measure.assert_not_called()
        self.assertIn("calibration", report["held"][-1])

    def test_a_bounded_run_is_reported_as_held_never_as_the_gate(self) -> None:
        def fake_measure(files, *_args):
            # the scan's peak grows by 1 MiB per 100 files
            runs = [{"mode": mode, "seconds": 1.0, "files": files, "peak_combined_mib": 900.0,
                     "peak_by_tree_mib": {"scan": 100.0 + files / 100}}
                    for mode, _tenant in harness.MODES]
            return {"files": files, "runs": runs, "parity": {"all": True},
                    "disk": {"state_bytes_per_file": 40_000}}

        with mock.patch.object(harness, "measure", side_effect=fake_measure) as measure:
            code, report = self.run_main("--files", "200000", "--allow-below-reserve-mb", "400")
        self.assertEqual(code, 3, "a bounded run never exits as a passed gate")
        self.assertTrue(report["held"][0].startswith("HELD FOR SCALE HOST"))
        sizes = [call.args[0] for call in measure.call_args_list]
        self.assertEqual(sizes[0], harness.CALIBRATION_FILES)
        self.assertEqual(sizes[-1], report["bounded"]["largest_safe_files"])
        self.assertLessEqual(harness.projected_bytes(sizes[-1], 40_000), 400 * harness.MIB)
        self.assertFalse(report["gate"]["peak combined working set < 2 GiB"]["at_gate_size"])
        self.assertEqual(report["projection_to_requested_size"]["files"], 200_000)
        memory = report["projection_to_requested_size"]["unpartitioned_memory"]
        self.assertEqual(memory["full"]["kib_per_file"], 10.24)
        # 100 MiB + 2,000 MiB at 200,000 files
        self.assertEqual(memory["full"]["projected_scan_peak_gib"], round(2100 / 1024, 2))

    def test_a_corpus_under_appdata_is_refused(self) -> None:
        with self.assertRaises(SystemExit) as refused:
            harness.main(["--files", "10", "--root", str(Path.home() / "AppData" / "Local" / "c14")])
        self.assertIn("AppData", str(refused.exception))


class ThePartitionSizeTest(unittest.TestCase):

    def test_the_product_default_unless_it_would_not_split_the_corpus(self) -> None:
        self.assertEqual(harness.partition_size(10_000, None), (2000, "the product default"))
        self.assertEqual(harness.partition_size(10_000, 500), (500, "requested"))
        size, why = harness.partition_size(200, None)
        self.assertEqual(size, 50, "the 200-file calibration still runs as a partitioned scan")
        self.assertIn("would not split", why)

    def test_the_harness_knows_the_products_default(self) -> None:
        from backend import partitioned_scan

        with mock.patch.dict(os.environ):
            os.environ.pop("DSPM_PARTITION_MAX_FILES", None)
            self.assertEqual(partitioned_scan.partition_max_files(), harness.PRODUCT_PARTITION_MAX_FILES)

    def test_a_failed_scan_still_removes_what_it_wrote(self) -> None:
        root = ROOT / "tmp" / f"c14-fail-{os.getpid()}"
        self.addCleanup(lambda: root.exists() and harness.shutil.rmtree(root, ignore_errors=True))
        with mock.patch.object(harness, "run_mode", side_effect=SystemExit("partitioned run failed")):
            with self.assertRaises(SystemExit):
                harness.measure(10, root, 5, False, False)
        self.assertEqual(list(root.iterdir()), [])


class TheParityChecksTest(unittest.TestCase):
    """Each parity line fails on the defect it names - a check that cannot fail is not one."""

    FILES = 100

    def runs(self, **changes) -> dict:
        good = {"files": self.FILES, "findings": 150, "digest": "d1", "duplicate_files": 0, "duplicate_finding_ids": 0,
                "cache_reused_files": 0, "content_reads": self.FILES}
        by_mode = {"full": dict(good), "partitioned": dict(good),
                   "incremental": dict(good, cache_reused_files=self.FILES, content_reads=0)}
        for key, value in changes.items():
            mode, field = key.split("__")
            by_mode[mode][field] = value
        return by_mode

    def failing(self, **changes) -> list[str]:
        return [line for line, ok in harness.parity(self.FILES, self.runs(**changes)).items() if not ok]

    def test_a_good_run_passes_every_line(self) -> None:
        self.assertEqual(self.failing(), [])

    def test_each_defect_fails_its_line(self) -> None:
        self.assertIn("the corpus was scanned", self.failing(full__files=0, partitioned__files=0, incremental__files=0))
        self.assertIn("partitioned reports the same files", self.failing(partitioned__files=99))
        self.assertIn("partitioned reports the same findings per file", self.failing(partitioned__digest="d2"))
        self.assertIn("no finding lost or added", self.failing(partitioned__findings=149))
        self.assertIn("no file twice", self.failing(partitioned__duplicate_files=1))
        self.assertIn("no finding id twice", self.failing(partitioned__duplicate_finding_ids=1))
        self.assertIn("unchanged incremental gives the same answer", self.failing(incremental__digest="d3"))
        self.assertIn("unchanged incremental reads no file again", self.failing(incremental__content_reads=100))


@unittest.skipUnless(sys.platform == "win32", "the sampler reads Windows process counters")
class TheSamplerTest(unittest.TestCase):

    def test_it_sums_a_process_and_its_children(self) -> None:
        # a parent that starts a child holding 64 MiB; the sum must include the child
        script = ("import subprocess, sys, time; "
                  "c = subprocess.Popen([sys.executable, '-c', "
                  "'import time; b = bytearray(64 * 1024 * 1024); b[::4096] = b\"x\" * len(b[::4096]); time.sleep(6)']); "
                  "time.sleep(6); c.kill()")
        parent = subprocess.Popen([sys.executable, "-c", script])
        self.addCleanup(parent.kill)
        sampler = harness.Sampler({"parent": parent.pid}, interval=0.2)
        sampler.start()
        time.sleep(4)
        sampler.stop()
        self.assertGreaterEqual(sampler.peak_processes, 2, "the child is part of the tree")
        self.assertGreater(sampler.peak, 64 * harness.MIB)
        self.assertEqual(sampler.peak_by_root["parent"], sampler.peak)

    def test_the_scan_peak_stops_when_the_scan_says_it_is_done(self) -> None:
        # what the harness does afterwards (reading the report back) is not the product's footprint
        marker = ROOT / "tmp" / f"c14-marker-{os.getpid()}"
        marker.parent.mkdir(exist_ok=True)
        marker.touch()
        self.addCleanup(marker.unlink, True)
        sampler = harness.Sampler({"self": os.getpid()}, marker=marker)
        sampler.sample()
        self.assertEqual(sampler.peak, 0)
        self.assertGreater(sampler.peak_with_verification, 0)
        marker.unlink()
        sampler.sample()
        self.assertGreater(sampler.peak, 0)


class APartitionIsReleasedWhenItIsWrittenTest(unittest.TestCase):
    """C14 found the partitioned scan's peak growing with the corpus (37 KiB a file) at a
    fixed partition size: each partition's engine left its records, findings and futures in
    reference cycles, and full collections grew rarer as the heap grew. A full collection
    after every partition keeps the peak on the partition size."""

    def test_every_partition_ends_with_a_full_collection(self) -> None:
        from backend import partitioned_scan, store
        from discovery.discovery_engine import ScanConfig

        root = ROOT / "tmp" / f"c14-gc-{os.getpid()}"
        self.addCleanup(lambda: root.exists() and harness.shutil.rmtree(root, ignore_errors=True))
        harness.write_corpus(root, 60)
        store.create_tenant("t-c14-gc", "gc")
        config = ScanConfig(tenant_id="t-c14-gc", local_path=str(root), walk_local_path=True,
                            persistent_cache_enabled=False, incremental_enabled=False)
        with mock.patch.object(partitioned_scan.gc, "collect", wraps=partitioned_scan.gc.collect) as collect:
            compact = partitioned_scan.run_partitioned_scan("t-c14-gc", config, max_files=20)
        self.assertIsNotNone(compact)
        partitions = len(store.list_scan_partitions("t-c14-gc", compact["scan_id"]))
        self.assertGreaterEqual(partitions, 3)
        self.assertGreaterEqual(collect.call_count, partitions, "one full collection per written partition")


class ASmallRealRunTest(unittest.TestCase):
    """The whole harness on 60 files: four real scans in child processes, parity, disk."""

    def test_four_scans_measured_and_the_partitioned_one_matches(self) -> None:
        root = ROOT / "tmp" / f"c14-run-{os.getpid()}"
        self.addCleanup(lambda: root.exists() and harness.shutil.rmtree(root, ignore_errors=True))
        with redirect_stdout(io.StringIO()):
            measured = harness.measure(60, root, 20, False, False)
        self.assertEqual([run["mode"] for run in measured["runs"]], [mode for mode, _ in harness.MODES])
        self.assertTrue(all(measured["parity"].values()), measured["parity"])
        by_mode = {run["mode"]: run for run in measured["runs"]}
        self.assertEqual(by_mode["partitioned"]["partitions"], 3, "60 files at 20 a partition")
        self.assertGreater(by_mode["full"]["findings"], 0)
        self.assertGreater(measured["disk"]["state_bytes_per_file"], 0)
        if sys.platform == "win32":
            self.assertGreater(by_mode["full"]["peak_combined_mib"], 20)
            for run in measured["runs"]:
                self.assertLessEqual(run["peak_combined_mib"], run["peak_with_verification_mib"])
        self.assertEqual(list(root.iterdir()), [], "everything written is removed")


if __name__ == "__main__":
    unittest.main()
