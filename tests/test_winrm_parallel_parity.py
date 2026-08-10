"""Track P-B.2 - the WinRM remote scan script parallelizes the expensive
per-file work (content read + SHA256 + ACL/owner) across a PowerShell runspace
pool inside its single remote session. The parallel result MUST be byte-identical
to the serial one (semantic parity is mandatory for scans).

The WinRM transport is separable from the generated script, so this validates
the script directly by executing it with the LOCAL powershell.exe against a
synthetic corpus - no WinRM endpoint required. Windows + Windows PowerShell only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from collectors.file_scanner import normalize_extension_filter
from collectors.winrm_endpoint_scanner import _scan_script

_POWERSHELL = shutil.which("powershell.exe")
# The scan script skips noise roots incl. %TEMP% (it is under \AppData\), so the
# corpus must live at a non-excluded path. A drive-root temp dir is safe.
_CORPUS_BASE = "C:\\" if os.name == "nt" else None


def _run(script: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as fh:
        fh.write(script)
        path = fh.name
    try:
        proc = subprocess.run(
            [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True, timeout=180,
        )
        out = proc.stdout.decode("utf-8", errors="replace").strip()
        if proc.returncode != 0:
            raise AssertionError(f"script rc={proc.returncode}: {proc.stderr.decode('utf-8', 'replace')[:500]}")
        return json.loads(out) if out else {}
    finally:
        os.unlink(path)


def _canon(records: list[dict]) -> dict:
    out = {}
    for r in records:
        r = dict(r)
        for k in ("principals", "permissions"):
            if isinstance(r.get(k), list):
                r[k] = sorted(str(x) for x in r[k])
        out[str(r.get("path"))] = r
    return out


@unittest.skipUnless(
    os.name == "nt" and _POWERSHELL, "needs Windows + powershell.exe to execute the generated script"
)
class WinRmScriptParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = os.path.join(_CORPUS_BASE, f"dspm_winrm_parity_{os.getpid()}")
        shutil.rmtree(cls.root, ignore_errors=True)
        # A small but varied corpus: nested dirs, a couple sizes, an empty file,
        # and a real .zip (its entries are emitted by the SERIAL phase-1 walk, so
        # parity must hold with the parallel phase-2 present).
        for d in ("a", "b/c"):
            os.makedirs(os.path.join(cls.root, d.replace("/", os.sep)), exist_ok=True)
        files = {
            "a/notes.txt": "ssn 123-45-6789\nemail a@b.com\n" * 40,
            "a/empty.txt": "",
            "a/data.csv": "id,secret\n1,hunter2\n" * 120,
            "b/c/config.json": '{"token":"abc","ip":"10.0.0.1"}\n' * 60,
            "b/c/report.log": "INFO ok\n" * 400,
        }
        for rel, content in files.items():
            with open(os.path.join(cls.root, rel.replace("/", os.sep)), "w", encoding="utf-8") as f:
                f.write(content)
        import zipfile
        with zipfile.ZipFile(os.path.join(cls.root, "a", "arc.zip"), "w") as z:
            z.writestr("inner/x.txt", "confidential 999-88-7777\n" * 30)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.root, ignore_errors=True)

    def _script(self, workers: int) -> str:
        return _scan_script(
            [self.root],
            max_depth=6,
            read_content=True,
            max_read_bytes=1_000_000,
            allowed_extensions=sorted(normalize_extension_filter([])),
            extension_filter_enabled=False,
            include_hidden=True,
            include_system=True,
            hidden_filter_enabled=False,
            system_filter_enabled=False,
            read_acl=True,
            inspect_archives=True,
            hash_files=True,
            read_owner=True,
            parallel_workers=workers,
        )

    def test_parallel_output_is_byte_identical_to_serial(self) -> None:
        serial = _run(self._script(1))
        parallel = _run(self._script(6))

        s_recs = serial.get("records", [])
        p_recs = parallel.get("records", [])
        self.assertGreater(len(s_recs), 5)  # corpus actually scanned
        self.assertFalse(serial["diagnostics"].get("io_parallel_active"))
        self.assertTrue(parallel["diagnostics"].get("io_parallel_active"))
        self.assertEqual(parallel["diagnostics"].get("parallel_workers"), 6)
        self.assertFalse(parallel["diagnostics"].get("worker_errors"))

        sc, pc = _canon(s_recs), _canon(p_recs)
        self.assertEqual(set(sc), set(pc), "record path set differs between serial and parallel")
        for path in sc:
            self.assertEqual(sc[path], pc[path], f"record fields differ for {path}")

        # Diagnostics parity (excluding the parallelism markers).
        markers = {"io_parallel_active", "parallel_workers", "worker_errors"}
        ds = {k: v for k, v in serial["diagnostics"].items() if k not in markers}
        dp = {k: v for k, v in parallel["diagnostics"].items() if k not in markers}
        self.assertEqual(ds, dp, "diagnostics differ between serial and parallel")


if __name__ == "__main__":
    unittest.main()
