"""P1 SMB metadata/acquisition pipeline tests.

Runs the real two-phase walker against isolated in-memory SMB connections. The
tests prove exact legacy record parity, bounded per-file concurrency, batched
full ACL detail, credential hygiene, and fail-safe per-file ACL fallback.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
import unittest
from unittest import mock

from collectors.smb_scanner import SMBConfig, SMBScanner
from discovery.parallelism import reset_host_admission_budget


class _Share:
    name = "Docs"


class _Entry:
    def __init__(self, filename: str, size: int) -> None:
        self.filename = filename
        self.file_size = size
        self.isDirectory = False
        self.isHidden = False
        self.isSystem = False
        self.create_time = 1_750_000_000.0
        self.last_write_time = 1_750_000_100.0


class _State:
    def __init__(self, contents: dict[str, bytes], delay: float = 0.0) -> None:
        self.contents = contents
        self.delay = delay
        self.lock = threading.Lock()
        self.active_retrievals = 0
        self.peak_retrievals = 0
        self.retrieve_calls = 0
        self.connection_count = 0


class _Connection:
    def __init__(self, state: _State, tag: int) -> None:
        self.state = state
        self.tag = tag

    def listShares(self):
        return [_Share()]

    def listPath(self, share_name: str, folder: str):
        assert share_name == "Docs"
        assert folder == "/"
        return [
            _Entry(path.rsplit("/", 1)[-1], len(data))
            for path, data in self.state.contents.items()
        ]

    def retrieveFileFromOffset(
        self,
        share_name: str,
        path: str,
        buffer,
        offset: int = 0,
        max_length: int = 0,
    ) -> None:
        assert share_name == "Docs"
        with self.state.lock:
            self.state.retrieve_calls += 1
            self.state.active_retrievals += 1
            self.state.peak_retrievals = max(
                self.state.peak_retrievals,
                self.state.active_retrievals,
            )
        try:
            if self.state.delay:
                time.sleep(self.state.delay)
            data = self.state.contents[path]
            chunk = data[offset:offset + max_length] if max_length else data[offset:]
            buffer.write(chunk)
        finally:
            with self.state.lock:
                self.state.active_retrievals -= 1

    def close(self) -> None:
        return None


def _acl_value() -> dict:
    return {
        "owner": r"CORP\analyst",
        "principals": [r"CORP\analyst", r"BUILTIN\Administrators"],
        "permissions": ["ReadAndExecute", "FullControl"],
    }


def _build_scanner(
    state: _State,
    *,
    emitted: list[dict] | None = None,
) -> tuple[SMBScanner, list[tuple[str, ...]]]:
    scanner = SMBScanner(
        SMBConfig(
            server="fs",
            username="analyst",
            password="secret",
            domain="CORP",
            io_workers=4,
            max_read_bytes=1024,
            record_callback=emitted.append if emitted is not None else None,
        )
    )
    batch_calls: list[tuple[str, ...]] = []

    def connect() -> bool:
        with state.lock:
            state.connection_count += 1
            tag = state.connection_count
        scanner.connection = _Connection(state, tag)
        scanner.server_used = "fs"
        return True

    def batch_acl(_share_name: str, paths: list[str]) -> dict[str, dict]:
        with state.lock:
            batch_calls.append(tuple(paths))
        return {path: _acl_value() for path in paths}

    scanner.connect = connect  # type: ignore[assignment]
    scanner._acl_batch_for_paths = batch_acl  # type: ignore[assignment]
    return scanner, batch_calls


class P1SmbAcquisitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = mock.patch.dict(
            os.environ,
            {
                "DSPM_SMB_PARALLEL": "1",
                "DSPM_SMB_FILE_PARALLEL": "1",
                "DSPM_SMB_ACL_BATCH": "1",
                "DSPM_SMB_ACL_BATCH_SIZE": "3",
            },
        )
        self.env.start()
        reset_host_admission_budget(4)

    def tearDown(self) -> None:
        reset_host_admission_budget()
        self.env.stop()

    def test_parallel_pipeline_preserves_exact_legacy_records_and_acl_detail(self) -> None:
        contents = {
            f"/file{i:02d}.txt": f"record-{i} person{i}@example.com\n".encode()
            for i in range(12)
        }
        emitted: list[dict] = []
        state = _State(contents, delay=0.012)
        scanner, batch_calls = _build_scanner(state, emitted=emitted)

        records = scanner.scan()

        self.assertEqual([row["path"] for row in records], list(contents))
        self.assertEqual(emitted, records)
        self.assertGreaterEqual(state.peak_retrievals, 2)
        self.assertEqual(len(batch_calls), 4)
        self.assertEqual(sum(len(batch) for batch in batch_calls), len(contents))
        self.assertTrue(all(1 <= len(batch) <= 3 for batch in batch_calls))
        self.assertEqual(state.connection_count, 6)  # listing + enumeration + 4 chunks

        for row in records:
            payload = contents[row["path"]]
            self.assertEqual(row["content"], payload.decode())
            self.assertEqual(row["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(row["owner"], r"CORP\analyst")
            self.assertEqual(row["acl"], _acl_value())

        phases = scanner.last_scan_diagnostics["smb_phases"]
        self.assertEqual(phases["mode"], "metadata_then_acquire")
        self.assertEqual(phases["file_work_items"], len(contents))
        self.assertEqual(phases["file_workers"], 4)
        self.assertTrue(phases["file_parallel_active"])
        self.assertEqual(phases["acquisition_chunks"], 4)
        self.assertEqual(phases["acl_batch_size"], 3)
        self.assertEqual(scanner.last_scan_diagnostics["owner_read_attempts"], len(contents))
        self.assertEqual(scanner.last_scan_diagnostics["acl_batch_paths"], len(contents))

        legacy_state = _State(contents)
        legacy, _unused_batches = _build_scanner(legacy_state)
        legacy._acl_for_path = lambda _share, _path: _acl_value()  # type: ignore[assignment]
        with mock.patch.dict(os.environ, {"DSPM_SMB_PARALLEL": "0"}):
            legacy_records = legacy.scan()
        self.assertEqual(records, legacy_records)

    def test_500_files_use_well_below_ten_percent_as_many_acl_processes(self) -> None:
        contents = {
            f"/file{i:03d}.txt": f"row-{i}\n".encode()
            for i in range(500)
        }
        state = _State(contents)
        scanner, batch_calls = _build_scanner(state)
        scanner.config.io_workers = 64
        reset_host_admission_budget(64)
        with mock.patch.dict(os.environ, {"DSPM_SMB_ACL_BATCH_SIZE": "32"}):
            records = scanner.scan()

        self.assertEqual(len(records), 500)
        self.assertEqual(len(batch_calls), 16)
        self.assertLessEqual(len(batch_calls), len(records) // 10)
        # P2: each small text file is transferred once for preview + full hash;
        # the previous reader required 1,000 remote fetches for these 500 files.
        self.assertEqual(state.retrieve_calls, 500)
        self.assertEqual(scanner.last_scan_diagnostics["single_pass_files"], 500)
        self.assertEqual(scanner.last_scan_diagnostics["single_pass_avoided_fetches"], 500)
        phases = scanner.last_scan_diagnostics["smb_phases"]
        self.assertEqual(phases["acl_batch_size"], 32)
        self.assertEqual(phases["acquisition_chunks"], 16)

    def test_batch_acl_keeps_password_off_argv_and_normalizes_full_detail(self) -> None:
        scanner = SMBScanner(
            SMBConfig(
                server="fs",
                username="analyst",
                password="Sup3rSecretPW",
                domain="CORP",
            )
        )
        captured: dict = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["env"] = kwargs["env"]
            return mock.Mock(
                returncode=0,
                stdout=json.dumps(
                    {
                        "results": [
                            {
                                "path": "/a.txt",
                                "ok": True,
                                "owner": r"CORP\analyst",
                                "principals": r"CORP\analyst",
                                "permissions": "ReadAndExecute",
                            },
                            {
                                "path": "/b.txt",
                                "ok": False,
                                "owner": "",
                                "principals": [],
                                "permissions": [],
                            },
                        ]
                    }
                ),
                stderr="",
            )

        with mock.patch("collectors.smb_scanner.subprocess.run", side_effect=fake_run):
            result = scanner._acl_batch_for_paths("Docs", ["/a.txt", "/b.txt"])

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["/a.txt"], {
            "owner": r"CORP\analyst",
            "principals": [r"CORP\analyst"],
            "permissions": ["ReadAndExecute"],
        })
        self.assertNotIn("/b.txt", result)
        decoded_script = base64.b64decode(captured["args"][-1]).decode("utf-16le")
        self.assertNotIn("Sup3rSecretPW", decoded_script)
        self.assertNotIn("Sup3rSecretPW", " ".join(captured["args"]))
        self.assertEqual(captured["env"]["DSPM_SMB_ACL_PW"], "Sup3rSecretPW")
        self.assertEqual(scanner.last_scan_diagnostics["acl_batch_processes"], 1)
        self.assertEqual(scanner.last_scan_diagnostics["acl_batch_item_failures"], 1)

    def test_batch_failure_falls_back_to_exact_per_file_acl_reader(self) -> None:
        scanner = SMBScanner(SMBConfig(server="fs"))
        scanner._acl_batch_for_paths = mock.MagicMock(return_value=None)  # type: ignore[assignment]
        scanner._acl_for_path = mock.MagicMock(return_value=_acl_value())  # type: ignore[assignment]

        scanner._prefetch_acl_paths("Docs", ["/a.txt", "/b.txt"])

        self.assertEqual(
            scanner._acl_for_path.call_args_list,
            [mock.call("Docs", "/a.txt"), mock.call("Docs", "/b.txt")],
        )
        self.assertEqual(scanner.last_scan_diagnostics["acl_batch_fallback_paths"], 2)


if __name__ == "__main__":
    unittest.main()
