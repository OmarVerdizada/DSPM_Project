"""Performance guardrails for the scan pipeline.

Owner/ACL resolution used to spawn one ``powershell.exe`` per file. Measured,
that was 91% of total scan time (143 s of a 157 s local scan; ~11 of the 13
minutes of a 421-file SMB scan) while all content classification cost 0.9 s.
These tests exist so the pattern cannot quietly come back:

* the collector must resolve owners in-process, spawning nothing per file,
* the in-process reader must return exactly what Get-Acl returned (owner
  string form and .NET FileSystemRights names),
* a full local scan must finish inside a wall-clock budget,
* an unchanged rescan must reuse its cache rather than re-reading everything.
"""

from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from collectors import win_security
from collectors.file_scanner import file_owner

IS_WINDOWS = platform.system().lower() == "windows"


class OwnerResolutionCostTests(unittest.TestCase):
    """The 90%: no process may be spawned to answer "who owns this file"."""

    @unittest.skipUnless(IS_WINDOWS, "Windows security descriptors")
    def test_owner_lookup_spawns_no_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for index in range(12):
                path = Path(tmp) / f"probe_{index}.txt"
                path.write_text("x", encoding="utf-8")
                paths.append(path)

            with patch.object(subprocess, "run", side_effect=AssertionError(
                "owner resolution spawned a subprocess - the per-file PowerShell "
                "regression is back"
            )):
                owners = [file_owner(path) for path in paths]

        self.assertTrue(all(owners), "every owner should resolve in-process")

    @unittest.skipUnless(IS_WINDOWS, "Windows security descriptors")
    def test_owner_lookup_is_fast_enough_to_be_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "timing.txt"
            path.write_text("x", encoding="utf-8")
            # Warm the SID cache so this measures the steady state.
            win_security.owner_for_path(str(path))
            start = time.perf_counter()
            for _ in range(50):
                win_security.owner_for_path(str(path))
            per_call_ms = (time.perf_counter() - start) / 50 * 1000
        # The subprocess it replaced cost ~490 ms; 10 ms is a very loose ceiling
        # that still fails instantly if a spawn-per-call creeps back in.
        self.assertLess(per_call_ms, 10.0, f"owner lookup took {per_call_ms:.2f} ms/call")


class SecurityDescriptorFidelityTests(unittest.TestCase):
    """Speed must not cost detail: the in-process read is byte-compatible."""

    def test_rights_render_like_dotnet_filesystemrights(self) -> None:
        # Ground truth captured from .NET itself:
        #   [System.Security.AccessControl.FileSystemRights]$mask).ToString()
        cases = {
            2032127: "FullControl",
            1179817: "ReadAndExecute, Synchronize",
            1245631: "Modify, Synchronize",
            1179785: "Read, Synchronize",
            278: "Write",
            0: "0",
        }
        for mask, expected in cases.items():
            self.assertEqual(win_security.rights_to_names(mask), expected, f"mask {mask}")

    @unittest.skipUnless(IS_WINDOWS, "Windows security descriptors")
    def test_matches_get_acl_owner_and_access_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fidelity.txt"
            target.write_text("x", encoding="utf-8")
            literal = str(target.resolve()).replace("'", "''")
            script = (
                "$ErrorActionPreference='Stop'; "
                f"$a = Get-Acl -LiteralPath '{literal}'; $a.Owner; "
                "(($a.Access | ForEach-Object { $_.IdentityReference.Value + '|' + "
                "$_.FileSystemRights.ToString() }) -join ';')"
            )
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=60, check=False,
            )
            if completed.returncode != 0:
                self.skipTest("PowerShell reference unavailable on this host")
            lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
            if not lines:
                self.skipTest("PowerShell returned no ACL to compare against")

            ours = win_security.security_for_path(str(target.resolve()))

        self.assertEqual(ours.get("owner"), lines[0])
        if len(lines) > 1:
            expected = [entry for entry in lines[1].split(";") if entry]
            actual = [
                f"{principal}|{rights}"
                for principal, rights in zip(ours.get("principals", []), ours.get("permissions", []))
            ]
            self.assertEqual(actual, expected)


class ScanBudgetTests(unittest.TestCase):
    """A full local scan of the bundled dataset stays inside a wall-clock budget."""

    DATASET = Path("enterprise_test_data")
    BUDGET_SECONDS = 60.0

    @unittest.skipUnless(Path("enterprise_test_data").is_dir(), "sample dataset not present")
    def test_local_scan_finishes_inside_budget_and_reuses_on_rescan(self) -> None:
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        with tempfile.TemporaryDirectory() as cache_dir:
            def scan() -> tuple[float, dict]:
                config = ScanConfig(
                    tenant_id="perf-budget",
                    local_path=str(self.DATASET),
                    cache_dir=cache_dir,
                )
                start = time.perf_counter()
                report = DSPMDiscoveryEngine(config).run()
                elapsed = time.perf_counter() - start
                return elapsed, report.to_dict()

            first_elapsed, first = scan()
            self.assertGreater(first["summary"]["total_files"], 50, "dataset should be substantial")
            self.assertLess(
                first_elapsed, self.BUDGET_SECONDS,
                f"cold scan took {first_elapsed:.1f}s (budget {self.BUDGET_SECONDS}s) - "
                "a per-file subprocess or synchronous I/O regression is likely",
            )

            second_elapsed, second = scan()
            incremental = second.get("scan_diagnostics", {}).get("incremental", {})
            self.assertTrue(incremental.get("enabled"), "incremental scanning should be on")
            self.assertGreater(
                int(incremental.get("unchanged_objects") or 0), 0,
                "an unchanged rescan must reuse cached results, not re-read every file",
            )
            self.assertEqual(
                second["summary"]["total_files"], first["summary"]["total_files"],
                "reuse must not change what the scan reports",
            )
            self.assertLess(second_elapsed, self.BUDGET_SECONDS)


class ReportSerializationTests(unittest.TestCase):
    """The report is written compactly - the pretty-printer cost 4.1 s a scan."""

    def test_report_is_written_without_pretty_print_padding(self) -> None:
        from scripts.report import generate_report

        payload = {"summary": {"total_files": 2}, "files": [{"path": "a"}, {"path": "b"}]}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            generate_report(payload, out)
            text = out.read_text(encoding="utf-8")

        self.assertNotIn("\n  ", text, "report should not be indent-padded")
        self.assertNotIn(", ", text, "report should use compact separators")
        import json

        self.assertEqual(json.loads(text), payload, "compact output must round-trip identically")


if __name__ == "__main__":
    unittest.main()
