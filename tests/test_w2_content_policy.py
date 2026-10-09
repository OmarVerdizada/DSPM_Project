"""W2.2: bytes read follow bytes inspected, and coverage never claims more than was read.

Before W2.2 every fresh file was read whole for its SHA-256 - a disk image as much as a
note - a text file was decoded up to 100 MiB, a document was extracted and then read
again to hash, and several records said FULL for content nobody read: a docx whose body
part was dropped as too large, a zip entry that is not text.
"""
from __future__ import annotations

import hashlib
import io
import os
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

from collectors import binary_extractor, content_policy, file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.incremental import record_analysis_failed

_MIB = 1024 * 1024
EMAIL_LINE = b"contact alice.martin@example.com about the invoice\n"


def _docx(path: Path, body: str, extra_parts: dict[str, bytes] | None = None) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml",
                         f'<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body></w:document>')
        for name, data in (extra_parts or {}).items():
            archive.writestr(name, data)


class _Estate(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.estate = self.root / "estate"
        self.estate.mkdir()
        # The temp directory is under AppData, which a local walk skips.
        for patcher in (patch.object(file_scanner, "is_skipped_scan_path", return_value=False),
                        patch.object(file_scanner, "file_owner", MagicMock(return_value="tester")),
                        patch.object(file_scanner, "local_acl", MagicMock(return_value={}))):
            patcher.start()
            self.addCleanup(patcher.stop)
        env = mock.patch.dict(os.environ, {"DSPM_HASH_POLICY": "", "DSPM_TEXT_SCAN_MAX_BYTES": "",
                                           "DSPM_DOCUMENT_SCAN_MAX_BYTES": ""})
        env.start()
        self.addCleanup(env.stop)
        file_scanner.take_read_bytes()

    def walk(self, **kwargs) -> tuple[dict[str, dict], dict]:
        diagnostics: dict = {}
        records = file_scanner.scan_directory(self.estate, diagnostics=diagnostics, **kwargs)
        return {record["name"]: record for record in file_scanner.normalize_records(records)}, diagnostics


class ATextFileIsReadOnceToItsCapTest(_Estate):

    def test_within_the_cap_one_read_gives_text_and_whole_file_digest(self) -> None:
        data = EMAIL_LINE * 1000
        (self.estate / "notes.txt").write_bytes(data)
        records, diagnostics = self.walk()
        record = records["notes.txt"]
        self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(record["content_coverage"], content_policy.FULL_CONTENT)
        self.assertEqual(diagnostics["content_bytes_read"], len(data), "read more than once")

    def test_past_the_cap_only_the_cap_is_read_and_named(self) -> None:
        data = EMAIL_LINE * 3000  # about 150 KB
        cap = 64 * 1024
        (self.estate / "export.txt").write_bytes(data)
        with mock.patch.dict(os.environ, {"DSPM_TEXT_SCAN_MAX_BYTES": str(cap)}):
            records, diagnostics = self.walk()
        record = records["export.txt"]
        self.assertEqual(record["sha256"], f"head:{cap}:" + hashlib.sha256(data[:cap]).hexdigest())
        self.assertEqual((record["scan_completeness"], record["content_coverage"]), ("PARTIAL", "PARTIAL_CONTENT"))
        self.assertEqual(diagnostics["content_bytes_read"], cap + 1, "read past the cap")

    def test_full_policy_still_names_it_by_its_whole_file_digest(self) -> None:
        data = EMAIL_LINE * 3000
        (self.estate / "export.txt").write_bytes(data)
        with mock.patch.dict(os.environ, {"DSPM_TEXT_SCAN_MAX_BYTES": str(64 * 1024), "DSPM_HASH_POLICY": "full"}):
            records, _diagnostics = self.walk()
        self.assertEqual(records["export.txt"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(records["export.txt"]["content_coverage"], content_policy.PARTIAL_CONTENT)


class AFileNotInspectedIsNotReadTest(_Estate):

    def test_meta_policy_reads_nothing_and_says_metadata_only(self) -> None:
        (self.estate / "disk.vhdx").write_bytes(os.urandom(3 * _MIB))
        records, diagnostics = self.walk()
        record = records["disk.vhdx"]
        self.assertTrue(record["sha256"].startswith("meta:"), record["sha256"])
        self.assertEqual(record["content_coverage"], content_policy.METADATA_ONLY)
        self.assertEqual(diagnostics["content_bytes_read"], 0)

    def test_sampled_policy_reads_two_mib(self) -> None:
        (self.estate / "disk.vhdx").write_bytes(os.urandom(3 * _MIB))
        with mock.patch.dict(os.environ, {"DSPM_HASH_POLICY": "sampled"}):
            records, diagnostics = self.walk()
        self.assertTrue(records["disk.vhdx"]["sha256"].startswith("sampled:"))
        self.assertEqual(diagnostics["content_bytes_read"], 2 * _MIB)

    def test_full_policy_reads_every_byte(self) -> None:
        data = os.urandom(3 * _MIB)
        (self.estate / "disk.vhdx").write_bytes(data)
        with mock.patch.dict(os.environ, {"DSPM_HASH_POLICY": "full"}):
            records, diagnostics = self.walk()
        self.assertEqual(records["disk.vhdx"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(diagnostics["content_bytes_read"], len(data))

    def test_a_meta_identity_changes_with_the_file(self) -> None:
        target = self.estate / "disk.vhdx"
        target.write_bytes(b"\0" * 4096)
        first = self.walk()[0]["disk.vhdx"]["sha256"]
        os.utime(target, ns=(time.time_ns(), time.time_ns() + 5_000_000_000))
        self.assertNotEqual(self.walk()[0]["disk.vhdx"]["sha256"], first)


class ADocumentIsReadOnceOrNotAtAllTest(_Estate):

    def test_within_its_cap_one_read_gives_text_and_digest(self) -> None:
        path = self.estate / "letter.docx"
        _docx(path, "IBAN DE89370400440532013000")
        data = path.read_bytes()
        records, diagnostics = self.walk()
        record = records["letter.docx"]
        self.assertIn("DE89370400440532013000", record["content"])
        self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(diagnostics["content_bytes_read"], len(data), "extracted, then read again to hash")
        self.assertEqual(record["content_coverage"], content_policy.FULL_CONTENT)

    def test_over_its_cap_it_is_skipped_by_policy_not_failed(self) -> None:
        path = self.estate / "huge.docx"
        _docx(path, "IBAN DE89370400440532013000", {"word/media/blob.bin": os.urandom(256 * 1024)})
        with mock.patch.dict(os.environ, {"DSPM_DOCUMENT_SCAN_MAX_BYTES": str(64 * 1024)}):
            records, diagnostics = self.walk()
        record = records["huge.docx"]
        self.assertEqual((record["content"], record["content_status"]), ("", "over_size_cap"))
        self.assertEqual(record["content_coverage"], content_policy.SKIPPED_POLICY)
        self.assertIn("DSPM_DOCUMENT_SCAN_MAX_BYTES", record["skip_reason"])
        self.assertEqual(record["scan_error"], "")
        self.assertFalse(record_analysis_failed(record), "a policy skip must stay reusable")
        self.assertEqual(diagnostics["content_bytes_read"], 0)

    def test_a_part_dropped_as_too_large_makes_it_partial_not_full(self) -> None:
        # Two ways a part is dropped: cut at the per-part cap (incompressible text), and
        # refused before reading as inflating like a bomb (very compressible text).
        # Under the 120,000-character text budget, so only the part cap can cut it.
        fillers = {"cut at the cap": os.urandom(40 * 1024).hex().encode("ascii"),
                   "refused as a bomb": b"x" * (200 * 1024)}
        for case, filler in fillers.items():
            with self.subTest(case):
                path = self.estate / "report.docx"
                big = b'<w:hdr xmlns:w="w"><w:t>' + filler + b"</w:t></w:hdr>"
                _docx(path, "IBAN DE89370400440532013000", {"word/header1.xml": big})
                with patch.object(binary_extractor, "MAX_DOC_ENTRY_BYTES", 64 * 1024):
                    records, _diagnostics = self.walk()
                record = records["report.docx"]
                self.assertIn("DE89370400440532013000", record["content"])
                self.assertEqual((record["scan_completeness"], record["content_coverage"]),
                                 ("PARTIAL", "PARTIAL_CONTENT"))

    def test_extraction_from_bytes_matches_extraction_from_the_file(self) -> None:
        path = self.estate / "letter.docx"
        _docx(path, "card 4111 1111 1111 1111")
        self.assertEqual(binary_extractor.extract_binary_text_detail(path),
                         binary_extractor.extract_binary_bytes_detail(path.read_bytes(), ".docx"))


class AnArchiveEntryIsNotFullUnlessReadTest(_Estate):

    def test_a_binary_entry_is_metadata_only(self) -> None:
        with zipfile.ZipFile(self.estate / "bundle.zip", "w") as archive:
            archive.writestr("notes.txt", EMAIL_LINE.decode())
            archive.writestr("photo.jpg", os.urandom(4096))
        records, _diagnostics = self.walk(inspect_archives=True)
        self.assertEqual(records["photo.jpg"]["content_coverage"], content_policy.METADATA_ONLY)
        self.assertEqual(records["photo.jpg"]["bytes_scanned"], 0)
        self.assertEqual(records["notes.txt"]["content_coverage"], content_policy.FULL_CONTENT)


class TheCoverageStatesTest(unittest.TestCase):

    def test_each_state(self) -> None:
        cases = [
            ({"content_status": "unreadable", "scan_error": "The file could not be read (OSError)"}, "FAILED"),
            ({"content_status": "not_extracted"}, "FAILED"),
            ({"content_status": "over_size_cap", "size": 10}, "SKIPPED_POLICY"),
            ({"content_status": "not_requested", "size": 10}, "SKIPPED_POLICY"),
            ({"content_status": "password_protected", "protected": True, "scan_error": "sealed"}, "METADATA_ONLY"),
            ({"content_status": "no_text_layer", "scan_completeness": "NONE", "size": 10}, "METADATA_ONLY"),
            ({"content_status": "metadata_only", "scan_completeness": "NONE", "size": 10}, "METADATA_ONLY"),
            ({"scan_completeness": "PARTIAL", "bytes_scanned": 5, "size": 10}, "PARTIAL_CONTENT"),
            ({"scan_completeness": "FULL", "bytes_scanned": 10, "size": 10}, "FULL_CONTENT"),
            ({"scan_completeness": "FULL", "size": 0}, "FULL_CONTENT"),
            ({"scan_completeness": "COMPLETE", "content": "x", "size": 1}, "FULL_CONTENT"),
            ({"is_dir": True}, ""),
        ]
        for record, expected in cases:
            with self.subTest(record=record):
                self.assertEqual(content_policy.coverage_state(record), expected)

    def test_a_full_without_bytes_is_not_full_content(self) -> None:
        # A record that says FULL but read nothing of a non-empty file is not trusted.
        self.assertEqual(content_policy.coverage_state({"scan_completeness": "FULL", "size": 10}), "METADATA_ONLY")


class TheEngineStampsCoverageTest(_Estate):

    def test_every_file_of_a_scan_says_its_coverage_and_a_rescan_keeps_it(self) -> None:
        (self.estate / "notes.txt").write_bytes(EMAIL_LINE)
        (self.estate / "disk.vhdx").write_bytes(b"\0" * 4096)
        config = ScanConfig(tenant_id="w22-coverage", local_path=str(self.estate), walk_local_path=True,
                            persistent_cache_enabled=False, cache_dir=str(self.root / "cache"), max_workers=1)
        report = DSPMDiscoveryEngine(config).run().to_dict()
        coverage = {item["name"]: item.get("content_coverage") for item in report["files"]}
        self.assertEqual(coverage, {"notes.txt": "FULL_CONTENT", "disk.vhdx": "METADATA_ONLY"})


class TheRevealReadsTheBytesItsFindingCameFromTest(_Estate):

    def _asset(self, path: Path) -> dict:
        records, _diagnostics = self.walk()
        record = records[path.name]
        return {"source": "local", "path": str(path), "sha256": record["sha256"], "size": record["size"]}

    def test_a_partially_inspected_file_is_revealed_from_its_inspected_bytes(self) -> None:
        from backend import evidence_reveal

        path = self.estate / "export.txt"
        path.write_bytes(EMAIL_LINE + b"filler line\n" * 20_000)
        with mock.patch.dict(os.environ, {"DSPM_TEXT_SCAN_MAX_BYTES": str(64 * 1024)}):
            asset = self._asset(path)
        self.assertTrue(asset["sha256"].startswith("head:65536:"))
        # The cap is read back from the identity, not from today's setting.
        text = evidence_reveal.reread("t", asset, None)
        self.assertIn("alice.martin@example.com", text)
        self.assertLessEqual(len(text), 64 * 1024)
        path.write_bytes(EMAIL_LINE.replace(b"alice", b"bobby") + b"filler line\n" * 20_000)
        with self.assertRaises(evidence_reveal.RevealRefused) as refused:
            evidence_reveal.reread("t", asset, None)
        self.assertEqual(refused.exception.code, "file_changed")

    def test_a_file_named_by_its_metadata_is_not_revealed(self) -> None:
        from backend import evidence_reveal

        path = self.estate / "export.txt"
        path.write_bytes(EMAIL_LINE)
        asset = {"source": "local", "path": str(path), "sha256": content_policy.meta_identity(len(EMAIL_LINE), 1),
                 "size": len(EMAIL_LINE)}
        with self.assertRaises(evidence_reveal.RevealRefused) as refused:
            evidence_reveal.reread("t", asset, None)
        self.assertEqual(refused.exception.code, "no_identity")


class TheSmbCaptureBudgetTest(unittest.TestCase):

    def test_readers_wait_for_room_and_never_exceed_the_budget(self) -> None:
        from collectors.smb_scanner import _ByteBudget

        budget = _ByteBudget(100)
        held, peak, lock = [0], [0], threading.Lock()

        def reader(amount: int) -> None:
            with budget.take(amount):
                with lock:
                    held[0] += amount
                    peak[0] = max(peak[0], held[0])
                time.sleep(0.01)
                with lock:
                    held[0] -= amount

        threads = [threading.Thread(target=reader, args=(amount,)) for amount in (60, 60, 30, 100, 250)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertFalse(any(thread.is_alive() for thread in threads), "a reader never got its share")
        self.assertLessEqual(peak[0], 100 + 150, peak)  # the 250 request is held to the whole budget
        self.assertLessEqual(budget._free, 100)


class TheEndpointIdentityTest(unittest.TestCase):

    def test_a_file_the_endpoint_did_not_hash_gets_a_meta_identity(self) -> None:
        from collectors.winrm_endpoint_scanner import (
            _endpoint_identity,
            _endpoint_skip_reason,
        )

        item = {"size": 10, "modified_at": "2026-10-01T00:00:00Z", "sha256": "", "hash_skipped": True}
        self.assertTrue(_endpoint_identity(item).startswith("meta:"))
        self.assertEqual(_endpoint_identity({"sha256": "ab" * 32}), "ab" * 32)
        self.assertEqual(_endpoint_identity({"sha256": ""}), "", "a failed hash stays a failed hash")
        self.assertIn("DSPM_DOCUMENT_SCAN_MAX_BYTES", _endpoint_skip_reason({"content_status": "over_size_cap"}))

    def test_the_endpoint_script_hashes_only_what_it_reads_whole(self) -> None:
        from collectors.winrm_endpoint_scanner import _scan_script

        script = _scan_script(["C:/Data"], 4, True, 1024, [], False, True, False, False, False, True, False)
        self.assertIn('$contentStatus = "over_size_cap"', script)
        self.assertIn("$hashSkipped = $true", script)
        with mock.patch.dict(os.environ, {"DSPM_HASH_POLICY": "full"}):
            self.assertIn("if ($true -or $readWhole)", _scan_script(["C:/Data"], 4, True, 1024, [], False, True,
                                                                     False, False, False, True, False))


class TheZipEntryCaptureTest(unittest.TestCase):
    """A zip whose entries are not inspected is no longer captured whole: its protection
    comes from its directory, read by range."""

    def _zip(self, encrypted: bool = False) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("blob.bin", os.urandom(512 * 1024))
            archive.writestr("notes.txt", "alice@example.com")
        data = bytearray(buffer.getvalue())
        if encrypted:
            entry = data.rindex(zipfile.stringCentralDir)
            data[entry + 8] |= 0x1
        return bytes(data)

    def test_protection_is_read_from_the_directory_without_capturing_the_zip(self) -> None:
        from tests.test_p2_smb_single_pass import _scanner, _work

        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                data = self._zip(encrypted)
                scanner, connection = _scanner(data, "/bundle.zip")
                record = scanner._build_work_records(_work("/bundle.zip", data, ".zip"))[-1]
                self.assertEqual(record["protected"], encrypted)
                self.assertTrue(record["sha256"].startswith("meta:"))
                self.assertLess(connection.bytes_returned, 64 * 1024, "the directory, not the archive")


if __name__ == "__main__":
    unittest.main()
