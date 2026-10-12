"""P2 SMB single-pass content/hash/archive acquisition tests."""
from __future__ import annotations

import hashlib
import io
import os
import unittest
import zipfile
from unittest import mock

from collectors.smb_scanner import SMBConfig, SMBScanner, _SMBFileWork, _SmbConnectionLost


_MIB = 1024 * 1024


class _TrackingConnection:
    def __init__(
        self,
        contents: dict[str, bytes],
        *,
        failures: int = 0,
        failure_type: type[Exception] = ConnectionError,
    ) -> None:
        self.contents = contents
        self.failures = failures
        self.failure_type = failure_type
        self.calls: list[tuple[str, int, int]] = []
        self.bytes_returned = 0

    def retrieveFileFromOffset(
        self,
        _share_name: str,
        path: str,
        buffer,
        offset: int = 0,
        max_length: int = 0,
    ) -> None:
        self.calls.append((path, offset, max_length))
        if self.failures:
            self.failures -= 1
            raise self.failure_type("transient test read failure")
        data = self.contents[path]
        chunk = data[offset:offset + max_length] if max_length else data[offset:]
        self.bytes_returned += len(chunk)
        buffer.write(chunk)

    def close(self) -> None:
        return None


def _acl() -> dict:
    return {
        "owner": r"CORP\analyst",
        "principals": [r"CORP\analyst", r"BUILTIN\Administrators"],
        "permissions": ["ReadAndExecute", "FullControl"],
    }


def _work(path: str, data: bytes, extension: str, *, inspect_archive: bool = False) -> _SMBFileWork:
    return _SMBFileWork(
        share_name="Docs",
        remote_path=path,
        name=path.rsplit("/", 1)[-1],
        file_size=len(data),
        extension=extension,
        is_hidden=False,
        is_system=False,
        created_at="2026-08-27T00:00:00+00:00",
        modified_at="2026-08-27T00:01:00+00:00",
        attributes="Normal",
        reuse_key=f"smb://fs/Docs{path}",
        include_top=True,
        inspect_archive_entries=inspect_archive,
    )


def _scanner(
    data: bytes,
    path: str,
    *,
    inspect_archives: bool = False,
    failures: int = 0,
    failure_type: type[Exception] = ConnectionError,
):
    scanner = SMBScanner(
        SMBConfig(
            server="fs",
            read_content=True,
            inspect_archives=inspect_archives,
            max_read_bytes=_MIB,
        )
    )
    connection = _TrackingConnection(
        {path: data},
        failures=failures,
        failure_type=failure_type,
    )
    scanner.connection = connection
    scanner.server_used = "fs"
    scanner._acl_for_path = lambda _share, _path: _acl()  # type: ignore[assignment]
    return scanner, connection


class P2SmbSinglePassTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = mock.patch.dict(os.environ, {"DSPM_SMB_SINGLE_PASS": "1"})
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()

    def _text_over_the_cap(self):
        # The preview ends inside a UTF-8 sequence. P2 must decode the accumulated
        # byte prefix once, exactly like the old preview reader, not per chunk.
        data = b"A" * (_MIB - 1) + "€".encode("utf-8") + b"tail-data"
        work = _work("/large.txt", data, ".txt")

        optimized, optimized_conn = _scanner(data, work.remote_path)
        optimized_records = optimized._build_work_records(work)

        legacy, legacy_conn = _scanner(data, work.remote_path)
        with mock.patch.dict(os.environ, {"DSPM_SMB_SINGLE_PASS": "0"}):
            legacy_records = legacy._build_work_records(work)

        self.assertEqual(optimized_records, legacy_records)
        row = optimized_records[0]
        self.assertEqual(row["content"], data[:_MIB].decode("utf-8", errors="replace"))
        self.assertEqual(optimized.last_scan_diagnostics["single_pass_avoided_fetches"], 1)
        self.assertEqual(optimized.last_scan_diagnostics["single_pass_avoided_transfer_bytes"], _MIB)
        return data, row, optimized_conn, legacy_conn

    def test_a_text_past_its_cap_is_read_to_the_cap_and_named_by_those_bytes(self) -> None:
        # W2.2: nothing past the cap is read; the identity is the digest of the bytes the
        # findings came from, which the evidence reveal reads again.
        data, row, optimized_conn, legacy_conn = self._text_over_the_cap()
        self.assertEqual(row["sha256"], f"head:{_MIB}:" + hashlib.sha256(data[:_MIB]).hexdigest())
        self.assertEqual((row["scan_completeness"], row["truncated"]), ("PARTIAL", True))
        self.assertEqual(len(optimized_conn.calls), 1)  # the cap, one 1 MiB chunk
        self.assertEqual(len(legacy_conn.calls), 2)  # preview + the same prefix, hashed
        self.assertEqual(optimized_conn.bytes_returned, _MIB)
        self.assertEqual(legacy_conn.bytes_returned, 2 * _MIB)

    def test_text_preview_and_full_hash_have_exact_legacy_parity_with_one_less_fetch(self) -> None:
        # DSPM_HASH_POLICY=full keeps the whole-file hash of before W2.2.
        with mock.patch.dict(os.environ, {"DSPM_HASH_POLICY": "full"}):
            data, row, optimized_conn, legacy_conn = self._text_over_the_cap()
        self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest())
        # One open: a file is one request whatever its size (scaling roadmap §25 W4.3, "SMB opens
        # a file once"); before, one request - one open and close - per MiB.
        self.assertEqual(len(optimized_conn.calls), 1)
        self.assertEqual(len(legacy_conn.calls), 3)  # preview + the same two chunks
        self.assertEqual(optimized_conn.bytes_returned, len(data))
        self.assertEqual(legacy_conn.bytes_returned, len(data) + _MIB)

    def test_zip_entries_protection_and_hash_reuse_one_captured_stream(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("folder/a.txt", "alice@example.com\n")
            archive.writestr("b.json", '{"card":"4111111111111111"}')
        data = buffer.getvalue()
        work = _work("/bundle.zip", data, ".zip", inspect_archive=True)

        optimized, optimized_conn = _scanner(data, work.remote_path, inspect_archives=True)
        optimized_records = optimized._build_work_records(work)

        legacy, legacy_conn = _scanner(data, work.remote_path, inspect_archives=True)
        with mock.patch.dict(os.environ, {"DSPM_SMB_SINGLE_PASS": "0"}):
            legacy_records = legacy._build_work_records(work)

        self.assertEqual(optimized_records, legacy_records)
        self.assertEqual([row["path"] for row in optimized_records], [
            "/bundle.zip::folder/a.txt",
            "/bundle.zip::b.json",
            "/bundle.zip",
        ])
        self.assertEqual(optimized_records[-1]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(len(optimized_conn.calls), 1)
        self.assertEqual(len(legacy_conn.calls), 3)  # hash + entry read + protection read
        # The captured stream serves the entries; the protection check reads the
        # directory from it too, so neither fetches again.
        self.assertEqual(optimized.last_scan_diagnostics["single_pass_avoided_fetches"], 2)
        self.assertEqual(
            optimized.last_scan_diagnostics["single_pass_avoided_transfer_bytes"],
            len(data) * 2,
        )

    def test_transport_failure_retries_with_original_preview_and_hash_readers(self) -> None:
        data = b"sensitive@example.com\n" * 100
        # A failure of this one read - not a ConnectionError, which is a lost session and
        # is retried on a fresh connection instead (backend audit 2026-10).
        scanner, connection = _scanner(data, "/retry.txt", failures=1, failure_type=OSError)

        acquired = scanner._acquire_file_data("Docs", "/retry.txt", ".txt", len(data))

        self.assertEqual(acquired.content, data.decode())
        self.assertEqual(acquired.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(len(connection.calls), 3)  # failed combined + preview + hash
        self.assertEqual(scanner.last_scan_diagnostics["single_pass_fallbacks"], 1)

    def test_connection_reset_is_escalated_to_existing_reconnect_logic(self) -> None:
        data = b"retry me"
        scanner, _connection = _scanner(
            data,
            "/reset.txt",
            failures=1,
            failure_type=ConnectionResetError,
        )

        with self.assertRaises(_SmbConnectionLost):
            scanner._acquire_file_data("Docs", "/reset.txt", ".txt", len(data))

        self.assertNotIn("single_pass_fallbacks", scanner.last_scan_diagnostics)

    def test_metadata_only_file_is_not_read_to_name_it(self) -> None:
        # W2.2: a file whose content is not inspected is named by its metadata - no byte
        # of it is read.
        data = os.urandom(_MIB + 17)
        scanner, connection = _scanner(data, "/blob.dat")

        acquired = scanner._acquire_file_data("Docs", "/blob.dat", ".dat", len(data),
                                              modified_at="2026-10-01T00:00:00+00:00", file_id="42")

        self.assertEqual(acquired.content, "")
        self.assertTrue(acquired.sha256.startswith("meta:"))
        self.assertIsNone(acquired.archive_bytes)
        self.assertEqual(connection.calls, [])
        changed = scanner._acquire_file_data("Docs", "/blob.dat", ".dat", len(data),
                                             modified_at="2026-10-02T00:00:00+00:00", file_id="42")
        self.assertNotEqual(changed.sha256, acquired.sha256, "a new mtime is a new identity")

    def test_sampled_policy_reads_the_first_and_last_mib(self) -> None:
        data = os.urandom(3 * _MIB)
        scanner, connection = _scanner(data, "/blob.dat")
        with mock.patch.dict(os.environ, {"DSPM_HASH_POLICY": "sampled"}):
            acquired = scanner._acquire_file_data("Docs", "/blob.dat", ".dat", len(data))
        self.assertTrue(acquired.sha256.startswith("sampled:"))
        self.assertEqual(connection.bytes_returned, 2 * _MIB)

    def test_metadata_only_file_is_hashed_once_without_allocating_a_preview(self) -> None:
        # DSPM_HASH_POLICY=full: hashed whole, once, as before W2.2.
        data = os.urandom(_MIB + 17)
        scanner, connection = _scanner(data, "/blob.dat")

        with mock.patch.dict(os.environ, {"DSPM_HASH_POLICY": "full"}):
            acquired = scanner._acquire_file_data("Docs", "/blob.dat", ".dat", len(data))

        self.assertEqual(acquired.content, "")
        self.assertEqual(acquired.sha256, hashlib.sha256(data).hexdigest())
        self.assertIsNone(acquired.archive_bytes)
        self.assertEqual(len(connection.calls), 1)  # one open for the whole file (§25 W4.3)
        self.assertEqual(scanner.last_scan_diagnostics["single_pass_avoided_fetches"], 0)


if __name__ == "__main__":
    unittest.main()
