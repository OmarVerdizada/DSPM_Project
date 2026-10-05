"""Backend audit, 2026-10 - the collectors: what each one read, and what its record said
it read, pinned by the file that showed the difference.
"""
from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from collectors import binary_extractor, file_scanner
from collectors.text_decode import TextDecoder, decode_text
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

CUSTOMERS = "Customer: Alice Smith\r\nEmail: alice.smith@example.com\r\nIBAN: DE89370400440532013000\r\n"


class _LocalEstate(unittest.TestCase):
    """A folder in the system temp directory, walked as a local scan walks it."""

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

    def walk(self) -> dict[str, dict]:
        return {record["name"]: record for record in file_scanner.scan_directory(self.estate)}

    def engine_scan(self) -> dict[str, dict]:
        config = ScanConfig(tenant_id="audit-collectors", local_path=str(self.estate), walk_local_path=True,
                            persistent_cache_enabled=False, cache_dir=str(self.root / "cache"), max_workers=1)
        report = DSPMDiscoveryEngine(config).run().to_dict()
        return {item["name"]: item for item in report["files"]}


class Utf16TextIsReadAsTextTest(_LocalEstate):
    """A UTF-16 file - a regedit export, a PowerShell 5.1 log, Excel's "Unicode Text" - was
    decoded as UTF-8: a NUL between every character, so triage skipped it as binary while
    its record said scanned and FULL, and no detector ran."""

    def test_a_utf16_customer_list_is_read_and_its_values_found(self) -> None:
        (self.estate / "customers.txt").write_bytes(CUSTOMERS.encode("utf-16"))
        record = self.walk()["customers.txt"]
        self.assertEqual(record["content"], CUSTOMERS)
        self.assertEqual(record["sha256"], hashlib.sha256(CUSTOMERS.encode("utf-16")).hexdigest(),
                         "the hash is still the raw bytes'")
        found = {finding.get("type") for finding in self.engine_scan()["customers.txt"].get("findings") or []}
        self.assertTrue({"email", "iban"} <= found, found)

    def test_every_byte_order_mark_and_utf16_without_one(self) -> None:
        for encoding in ("utf-16", "utf-16-le", "utf-16-be", "utf-8-sig", "utf-8", "utf-32"):
            with self.subTest(encoding=encoding):
                self.assertEqual(decode_text(CUSTOMERS.encode(encoding)), CUSTOMERS)

    def test_a_character_split_between_two_chunks_survives(self) -> None:
        text = "Müller € 😀 ünïcödé " * 50
        (self.estate / "names.txt").write_text(text, encoding="utf-8")
        (self.estate / "names16.txt").write_bytes(text.encode("utf-16"))
        with patch.object(file_scanner, "TEXT_SCAN_CHUNK_BYTES", 7):
            records = self.walk()
        self.assertEqual(records["names.txt"]["content"], text)
        self.assertEqual(records["names16.txt"]["content"], text)

    def test_a_decoder_fed_byte_by_byte_reads_what_a_whole_buffer_reads(self) -> None:
        data = ("Grüße, " * 2000).encode("utf-16-be")
        decoder = TextDecoder()
        text = "".join(decoder.decode(data[index:index + 1]) for index in range(len(data))) + decoder.decode(b"", True)
        self.assertEqual(text, "Grüße, " * 2000)

    def test_a_utf16_entry_in_a_zip_is_read_as_text(self) -> None:
        with zipfile.ZipFile(self.estate / "export.zip", "w") as archive:
            archive.writestr("customers.txt", CUSTOMERS.encode("utf-16"))
        records = {record["path"].rsplit("::", 1)[-1]: record
                   for record in file_scanner.scan_directory(self.estate, inspect_archives=True)}
        self.assertEqual(records["customers.txt"]["content"], CUSTOMERS)


class AFailedLocalReadIsSaidTest(_LocalEstate):
    """A text file that could not be opened was recorded as "empty_or_unreadable", FULL,
    with its whole size scanned and no error: an empty file, and eligible for reuse."""

    def test_a_file_that_cannot_be_opened_is_unreadable_and_read_nothing(self) -> None:
        (self.estate / "locked.log").write_text("alice@example.com\n" * 20, encoding="utf-8")
        real_open = Path.open

        def refuse(path, *args, **kwargs):
            if path.name == "locked.log":
                raise PermissionError(13, "The process cannot access the file", str(path))
            return real_open(path, *args, **kwargs)

        with patch.object(Path, "open", refuse):
            record = self.walk()["locked.log"]
        self.assertEqual(record["content_status"], "unreadable")
        self.assertEqual(record["scan_completeness"], "NONE")
        self.assertEqual(record["bytes_scanned"], 0)
        self.assertEqual(record["scan_error"], "The file could not be read (PermissionError)")
        self.assertNotIn(str(self.estate), record["scan_error"], "no path in the error")

    def test_an_empty_file_is_still_an_empty_file(self) -> None:
        (self.estate / "empty.txt").write_bytes(b"")
        record = self.walk()["empty.txt"]
        self.assertEqual((record["content_status"], record["scan_completeness"], record["scan_error"]),
                         ("empty_or_unreadable", "FULL", ""))


def _pdf(path: Path, *, title: str = "", text: str = "", password: str = "") -> None:
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    writer = PdfWriter()
    page = writer.add_blank_page(width=200, height=200)
    if text:
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                                 NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject(
            {NameObject("/F1"): writer._add_object(font)})})
        stream = DecodedStreamObject()
        stream.set_data(f"BT /F1 12 Tf 10 100 Td ({text}) Tj ET".encode("latin-1"))
        page[NameObject("/Contents")] = writer._add_object(stream)
    if title:
        writer.add_metadata({"/Title": title})
    if password:
        writer.encrypt(user_password=password, owner_password=password + "-owner", algorithm="RC4-128")
    with path.open("wb") as handle:
        writer.write(handle)


class APdfWithoutTextIsNotScannedTest(_LocalEstate):
    """When pypdf found no text the extractor fell back to a regex over the raw bytes, which
    finds the uncompressed metadata: a blank scan titled "Scanned passport" came out as
    "Scanned passport", scanned and FULL; an encrypted PDF took the same path."""

    def test_a_scan_with_no_text_layer_says_so(self) -> None:
        _pdf(self.estate / "passport.pdf", title="Scanned passport")
        text, reason = binary_extractor.extract_binary_text_with_status(self.estate / "passport.pdf")
        self.assertEqual((text, reason), ("", "no_text_layer"))
        record = self.walk()["passport.pdf"]
        self.assertEqual((record["content"], record["content_status"], record["scan_completeness"],
                          record["bytes_scanned"]), ("", "no_text_layer", "NONE", 0))

    def test_an_encrypted_pdf_is_protected_not_scanned(self) -> None:
        _pdf(self.estate / "salaries.pdf", title="Salaries 2026", text="IBAN DE89370400440532013000",
             password="s3cret")
        record = self.walk()["salaries.pdf"]
        self.assertEqual((record["content"], record["content_status"], record["scan_completeness"]),
                         ("", "password_protected", "NONE"))
        self.assertTrue(record["protected"])

    def test_a_pdf_with_text_is_still_read(self) -> None:
        _pdf(self.estate / "invoice.pdf", title="Invoice", text="Contact alice.smith@example.com")
        record = self.walk()["invoice.pdf"]
        self.assertIn("alice.smith@example.com", record["content"])
        self.assertEqual((record["content_status"], record["scan_completeness"]), ("scanned", "FULL"))

    def test_the_pdf_is_never_loaded_whole(self) -> None:
        _pdf(self.estate / "scan.pdf", title="Scanned passport")
        real = Path.read_bytes
        with patch.object(Path, "read_bytes", autospec=True, side_effect=real) as read_bytes:
            binary_extractor.extract_binary_text(self.estate / "scan.pdf")
        read_bytes.assert_not_called()


class _SmbEntry:
    def __init__(self, name: str, size: int = 0, directory: bool = False) -> None:
        self.filename, self.file_size, self.isDirectory = name, size, directory
        self.isHidden = self.isSystem = False
        self.create_time, self.last_write_time = 1_750_000_000.0, 1_750_000_100.0


class _SmbShare:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeSmbServer:
    """Shares of files ({share: {"/dir/name": bytes}}) as pysmb's calls serve them, with a
    hook that can make any call fail. No socket is opened."""

    def __init__(self, shares: dict[str, dict[str, bytes]], fail=None) -> None:
        self.shares, self.fail, self.connections = shares, fail, 0

    def listShares(self):
        return [_SmbShare(name) for name in self.shares]

    def listPath(self, share: str, folder: str):
        self._maybe_fail("list", share, folder)
        prefix = folder.rstrip("/") + "/"
        children: dict[str, _SmbEntry] = {}
        for path, data in self.shares[share].items():
            if not path.startswith(prefix):
                continue
            head, _, rest = path[len(prefix):].partition("/")
            children.setdefault(head, _SmbEntry(head, directory=True) if rest else _SmbEntry(head, len(data)))
        return list(children.values())

    def retrieveFileFromOffset(self, share: str, path: str, buffer, offset: int = 0, max_length: int = -1):
        self._maybe_fail("read", share, path)
        data = self.shares[share][path]
        buffer.write(data[offset:] if max_length is None or max_length < 0 else data[offset:offset + max_length])
        return 0, 0

    def close(self) -> None:
        return None

    def _maybe_fail(self, operation: str, share: str, path: str) -> None:
        error = self.fail(operation, share, path) if self.fail else None
        if error is not None:
            raise error


def _smb_scanner(server: _FakeSmbServer, **config):
    from collectors.smb_scanner import SMBConfig, SMBScanner

    scanner = SMBScanner(SMBConfig(server="fs", io_workers=1, max_read_bytes=1024 * 1024, **config))

    def connect() -> bool:
        server.connections += 1
        scanner.connection = server
        scanner.server_used = "fs"
        return True

    scanner.connect = connect  # type: ignore[assignment]
    # Owners and ACLs are read through Windows by UNC path: never asked for here.
    scanner._acl_for_path = lambda _share, _path: {"owner": "", "principals": [], "permissions": []}  # type: ignore[assignment]
    scanner._prefetch_acl_paths = lambda _share, _paths: None  # type: ignore[assignment]
    return scanner


def _smb_records(scanner) -> dict[str, dict]:
    return {f"{record['share']}:{record['path']}": record for record in scanner.scan()}


class SmbReadsTextAsTextTest(unittest.TestCase):

    def test_a_utf16_file_on_a_share_is_read_as_text(self) -> None:
        from collectors.smb_scanner import SMBScanner

        self.assertEqual(SMBScanner._preview_content_from_bytes(CUSTOMERS.encode("utf-16"), ".txt"), CUSTOMERS)
        server = _FakeSmbServer({"Docs": {"/customers.txt": CUSTOMERS.encode("utf-16")}})
        record = _smb_records(_smb_scanner(server))["Docs:/customers.txt"]
        self.assertEqual(record["content"], CUSTOMERS)
        self.assertEqual(record["sha256"], hashlib.sha256(CUSTOMERS.encode("utf-16")).hexdigest())

    def test_a_utf16_entry_in_a_zip_on_a_share_is_read_as_text(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("customers.txt", CUSTOMERS.encode("utf-16"))
        server = _FakeSmbServer({"Docs": {"/export.zip": buffer.getvalue()}})
        records = _smb_records(_smb_scanner(server, inspect_archives=True))
        self.assertEqual(records["Docs:/export.zip::customers.txt"]["content"], CUSTOMERS)


class SmbConnectionLossIsALostConnectionTest(unittest.TestCase):
    """smbprotocol's SMBConnectionClosed and pysmb's SMBTimeout read as one file's failure:
    the rest of the chunk went to fallback readers on the dead socket and came back as
    records with no content and no hash, and the scan counted as complete."""

    def test_each_way_a_session_dies_is_recognised(self) -> None:
        from smb.base import NotConnectedError, SMBTimeout
        from smb.smb_structs import OperationFailure
        from smbprotocol.exceptions import SMBConnectionClosed

        from collectors.smb_scanner import _is_access_denied, _is_connection_error

        for lost in (SMBConnectionClosed("SMB socket was closed, cannot send or receive any more data"),
                     SMBConnectionClosed("Connection timed out. Server did not respond within timeout."),
                     SMBTimeout(), NotConnectedError(), TimeoutError("timed out"), ConnectionError("gone")):
            with self.subTest(error=type(lost).__name__):
                self.assertTrue(_is_connection_error(lost))
                self.assertFalse(_is_access_denied(lost))
        refused = OperationFailure("Failed to list / on Finance: Unable to open directory", [])
        self.assertFalse(_is_connection_error(refused))

    def test_an_smb3_answer_that_ends_the_session_is_a_lost_connection(self) -> None:
        from collectors import smb3_transport
        from collectors.smb_scanner import _is_connection_error

        for status in (0xC00000B5, 0xC0000203, 0xC000035C):  # IO timeout, session deleted, session expired
            with self.subTest(status=hex(status)):
                self.assertTrue(_is_connection_error(smb3_transport._translate(MagicMock(status=status), "HR", "/")))
        self.assertFalse(_is_connection_error(smb3_transport._translate(MagicMock(status=0xC0000043), "HR", "/x")),
                         "a sharing violation is this file's, not the session's")

    def test_a_timeout_while_reading_retries_the_chunk_and_reports_the_share(self) -> None:
        from smb.base import SMBTimeout

        server = _FakeSmbServer({"Docs": {"/a.txt": b"alice@example.com\n", "/b.txt": b"bob@example.com\n"}},
                                fail=lambda op, share, path: SMBTimeout() if op == "read" else None)
        scanner = _smb_scanner(server)
        records = scanner.scan()
        self.assertEqual(records, [], "no record claims a file it did not read")
        self.assertEqual(scanner.last_scan_diagnostics["shares_connection_reset"], ["Docs"])
        self.assertGreaterEqual(server.connections, 3, "the listing, then the chunk and its retry")

    def test_a_closed_session_while_listing_is_not_access_denied(self) -> None:
        from smbprotocol.exceptions import SMBConnectionClosed

        server = _FakeSmbServer(
            {"Finance": {"/pay.txt": b"x"}, "Public": {"/readme.txt": b"hello"}},
            fail=lambda op, share, path: SMBConnectionClosed("SMB socket was closed, cannot send or receive any "
                                                             "more data") if (op, share) == ("list", "Finance") else None)
        scanner = _smb_scanner(server)
        records = _smb_records(scanner)
        diagnostics = scanner.last_scan_diagnostics
        self.assertEqual(diagnostics["shares_access_denied"], [])
        self.assertEqual(diagnostics["shares_connection_reset"], ["Finance"])
        self.assertIn("Public:/readme.txt", records)


class AFailedSmbReadIsSaidTest(unittest.TestCase):

    def test_a_file_the_share_will_not_serve_is_unreadable_and_the_scan_incomplete(self) -> None:
        from smb.smb_structs import OperationFailure

        server = _FakeSmbServer(
            {"Docs": {"/locked.txt": b"alice@example.com\n" * 10, "/open.txt": b"bob@example.com\n"}},
            fail=lambda op, share, path: OperationFailure(
                f"Failed to retrieve {path} on {share}: Unable to open file", []) if path == "/locked.txt" else None)
        scanner = _smb_scanner(server)
        records = _smb_records(scanner)
        locked = records["Docs:/locked.txt"]
        self.assertEqual((locked["content_status"], locked["scan_completeness"], locked["bytes_scanned"]),
                         ("unreadable", "NONE", 0))
        self.assertEqual(locked["scan_error"], "The file could not be read (OperationFailure)")
        self.assertEqual(scanner.last_scan_diagnostics["scan_errors"],
                         [{"share": "Docs", "path": "/locked.txt", "error": "OperationFailure"}])
        self.assertEqual(records["Docs:/open.txt"]["content_status"], "scanned")


class SmbPdfWithoutTextIsNotScannedTest(unittest.TestCase):

    def test_a_scanned_pdf_and_an_encrypted_one_on_a_share(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            _pdf(Path(folder) / "scan.pdf", title="Scanned passport")
            _pdf(Path(folder) / "sealed.pdf", text="IBAN DE89370400440532013000", password="s3cret")
            files = {f"/{name}": (Path(folder) / name).read_bytes() for name in ("scan.pdf", "sealed.pdf")}
        records = _smb_records(_smb_scanner(_FakeSmbServer({"Docs": files})))
        scan, sealed = records["Docs:/scan.pdf"], records["Docs:/sealed.pdf"]
        self.assertEqual((scan["content"], scan["content_status"], scan["scan_completeness"]),
                         ("", "no_text_layer", "NONE"))
        self.assertEqual((sealed["content"], sealed["content_status"], sealed["scan_completeness"], sealed["protected"]),
                         ("", "password_protected", "NONE", True))


class HiddenSharesAreScannedWhenAskedForTest(unittest.TestCase):
    """Every share ending in $ that was not a drive letter was skipped whatever
    include_admin_shares said, and before the named shares were looked at: Payroll$, HR$
    and Finance$ were never scanned, even named, and only showed up in shares_skipped."""

    SHARES = {"Payroll$": {"/june.txt": b"IBAN DE89370400440532013000\n"}, "Public": {"/readme.txt": b"hello"},
              "C$": {"/boot.txt": b"x"}, "IPC$": {}, "ADMIN$": {}, "print$": {}}

    def _scan(self, **config) -> tuple[set[str], dict]:
        scanner = _smb_scanner(_FakeSmbServer(self.SHARES), **config)
        shares = {record["share"] for record in scanner.scan()}
        return shares, scanner.last_scan_diagnostics

    def test_a_named_hidden_share_is_scanned(self) -> None:
        shares, diagnostics = self._scan(allowed_shares=("payroll$", "Public"))
        self.assertEqual(shares, {"Payroll$", "Public"})
        self.assertNotIn("Payroll$", diagnostics["shares_skipped"])
        self.assertEqual(diagnostics["shares_scanned"], ["Payroll$", "Public"])

    def test_hidden_shares_are_scanned_with_include_admin_shares(self) -> None:
        shares, diagnostics = self._scan(include_admin_shares=True)
        self.assertEqual(shares, {"Payroll$", "Public", "C$"})
        self.assertEqual(diagnostics["shares_skipped"], ["IPC$", "ADMIN$", "print$"], "never data")

    def test_by_default_only_the_ordinary_shares_are_scanned(self) -> None:
        shares, diagnostics = self._scan()
        self.assertEqual(shares, {"Public"})
        self.assertEqual(diagnostics["shares_skipped"], ["Payroll$", "C$", "IPC$", "ADMIN$", "print$"])

    def test_a_drive_share_still_needs_include_admin_shares(self) -> None:
        shares, diagnostics = self._scan(allowed_shares=("C$", "Public"))
        self.assertEqual(shares, {"Public"})
        self.assertIn("C$", diagnostics["shares_skipped"])

    def test_the_partition_plan_keeps_a_named_hidden_share(self) -> None:
        scanner = _smb_scanner(_FakeSmbServer(self.SHARES), allowed_shares=("Payroll$", "Public"))
        self.assertEqual(scanner.plan_share_groups(), [["Payroll$"], ["Public"]])


class _CountingSmbServer(_FakeSmbServer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.served = 0

    def retrieveFileFromOffset(self, share, path, buffer, offset=0, max_length=-1):
        before = buffer.tell()
        result = super().retrieveFileFromOffset(share, path, buffer, offset, max_length)
        self.served += buffer.tell() - before
        return result


class ALargeZipOnAShareIsOpenedAtItsEndTest(unittest.TestCase):
    """The SMB collector kept the first 200 MB of a .zip and opened that as a zip, but a
    zip's directory is at its end: every zip over 200 MB was reported protected,
    "bad_archive", "could not be opened". The limit is patched down to 64 KB here."""

    LIMIT = 256 * 1024

    def setUp(self) -> None:
        patcher = patch("collectors.smb_scanner.MAX_ARCHIVE_TOTAL_BYTES", self.LIMIT)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _zip(self, *, encrypted: bool = False) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("photos/raw.bin", os.urandom(3 * self.LIMIT))
            archive.writestr("export/customers.txt", CUSTOMERS.encode("utf-8"))
        data = bytearray(buffer.getvalue())
        if encrypted:
            # zipfile writes no encrypted entries; the flag in the directory is what the
            # protection check reads.
            entry = data.rindex(zipfile.stringCentralDir)
            data[entry + 8] |= 0x1
        return bytes(data)

    def test_a_zip_larger_than_the_capture_is_not_called_protected(self) -> None:
        data = self._zip()
        self.assertGreater(len(data), self.LIMIT)
        record = _smb_records(_smb_scanner(_FakeSmbServer({"Docs": {"/big.zip": data}})))["Docs:/big.zip"]
        self.assertEqual((record["protected"], record["content_status"], record["scan_error"]),
                         (False, "metadata_only", ""))
        # W2.2: a zip whose entries are not inspected is named by its metadata, not read
        # whole; DSPM_HASH_POLICY=full still hashes it whole.
        self.assertTrue(record["sha256"].startswith("meta:"), record["sha256"])
        with patch.dict(os.environ, {"DSPM_HASH_POLICY": "full"}):
            record = _smb_records(_smb_scanner(_FakeSmbServer({"Docs": {"/big.zip": data}})))["Docs:/big.zip"]
        self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest(), "still hashed whole")

    def test_an_encrypted_entry_past_the_capture_is_found(self) -> None:
        records = _smb_records(_smb_scanner(_FakeSmbServer({"Docs": {"/big.zip": self._zip(encrypted=True)}})))
        self.assertEqual((records["Docs:/big.zip"]["protected"], records["Docs:/big.zip"]["content_status"]),
                         (True, "password_protected"))

    def test_its_entries_are_listed_and_read_by_range(self) -> None:
        data = self._zip()
        server = _CountingSmbServer({"Docs": {"/big.zip": data}})
        with patch.dict(os.environ, {"DSPM_SMB_SINGLE_PASS": "0"}):
            records = _smb_records(_smb_scanner(server, inspect_archives=True))
        entry = records["Docs:/big.zip::export/customers.txt"]
        self.assertEqual(entry["content"], CUSTOMERS)
        # The hash reads the file once; the entries took the directory and one entry, not
        # the archive again from its first byte.
        self.assertLess(server.served, 2 * len(data))

    def test_a_directory_beyond_the_budget_is_not_inspected_not_protected(self) -> None:
        with patch("collectors.smb_scanner.MAX_ARCHIVE_TOTAL_BYTES", 64):
            record = _smb_records(_smb_scanner(_FakeSmbServer({"Docs": {"/big.zip": self._zip()}})))["Docs:/big.zip"]
        self.assertEqual((record["protected"], record["content_status"]), (False, "not_inspected"))


def _docx(text: str, padding: int) -> bytes:
    """A .docx whose text is at its start and whose zip directory is at its end, past
    ``padding`` bytes of picture."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", f'<w:document xmlns:w="urn:w"><w:body><w:p><w:r><w:t>{text}</w:t>'
                                              "</w:r></w:p></w:body></w:document>")
        archive.writestr("word/media/image1.png", os.urandom(padding))
    return buffer.getvalue()


class _SftpAttributes:
    def __init__(self, name: str, mode: int, size: int = 0, uid: int = 1000, gid: int = 1000) -> None:
        self.filename, self.st_mode, self.st_size = name, mode, size
        self.st_uid, self.st_gid, self.st_mtime = uid, gid, 1_750_000_000


class _FakeSftp:
    """A tree as paramiko's SFTPClient serves it: {path: (mode, gid, bytes or None)}. No
    socket is opened."""

    def __init__(self, tree: dict[str, tuple[int, int, bytes | None]]) -> None:
        self.tree = {"/": (0o40755, 0, None), **tree}

    def stat(self, path: str):
        mode, gid, data = self.tree[path]
        return _SftpAttributes(path.rsplit("/", 1)[-1], mode, len(data or b""), gid=gid)

    def listdir_attr(self, folder: str):
        prefix = folder.rstrip("/") + "/"
        return [self.stat(path) for path in self.tree
                if path.startswith(prefix) and "/" not in path[len(prefix):] and path != folder]

    def open(self, path: str, _mode: str):
        return io.BytesIO(self.tree[path][2])


def _sftp_source(**overrides):
    from collectors import sftp_scanner

    return sftp_scanner.SftpSource(host="linux01.corp.test", username="alice", host_key_fingerprint="SHA256:x",
                                   **{"paths": ["/home"], **overrides})


def _sftp_records(tree: dict, read_text="smb", **overrides) -> dict[str, dict]:
    from collectors import sftp_scanner
    from collectors.smb_scanner import SMBScanner

    reader = SMBScanner._preview_content_from_bytes if read_text == "smb" else read_text
    records, _ = sftp_scanner.scan(_sftp_source(**overrides), read_text=reader, sftp=_FakeSftp(tree))
    return {record["path"].split("linux01.corp.test", 1)[1]: record for record in records}


def _broad_readers(record: dict) -> set[str]:
    return {entry["principal"] for entry in record["acl"]["entries"] if "read" in entry["rights"]}


class AFileBehindAClosedFolderIsNotWorldReadableTest(unittest.TestCase):
    """SFTP granted Everyone read from the file's own world-read bit, ignoring whether
    others could enter the folders above it: every 0644 file under a 0700 or 0750 home
    folder was "Broad group access detected"."""

    def test_the_folders_above_decide_who_reaches_the_file(self) -> None:
        records = _sftp_records({
            "/home": (0o40755, 0, None),
            "/home/alice": (0o40700, 1000, None),
            "/home/alice/notes.txt": (0o100644, 1000, b"private"),
            "/home/team": (0o40750, 2000, None),
            "/home/team/plan.txt": (0o100644, 2000, b"team"),
            "/home/team/other.txt": (0o100644, 3000, b"other group"),
            "/home/shared": (0o40755, 0, None),
            "/home/shared/readme.txt": (0o100644, 1000, b"everyone"),
        })
        self.assertEqual(_broad_readers(records["/home/alice/notes.txt"]), {"uid:1000"})
        self.assertEqual(_broad_readers(records["/home/team/plan.txt"]), {"uid:1000", "gid:2000"})
        self.assertEqual(_broad_readers(records["/home/team/other.txt"]), {"uid:1000"},
                         "group 3000 cannot pass a folder only group 2000 may enter")
        self.assertEqual(_broad_readers(records["/home/shared/readme.txt"]), {"uid:1000", "gid:1000", "Everyone"})

    def test_a_closed_folder_above_the_scanned_root_counts_too(self) -> None:
        records = _sftp_records({"/home": (0o40711, 0, None), "/home/alice": (0o40755, 1000, None),
                                 "/home/alice/a.txt": (0o100644, 1000, b"x")}, paths=["/home/alice"])
        self.assertIn("Everyone", _broad_readers(records["/home/alice/a.txt"]), "0711 lets others through")
        records = _sftp_records({"/home": (0o40700, 0, None), "/home/alice": (0o40755, 1000, None),
                                 "/home/alice/a.txt": (0o100644, 1000, b"x")}, paths=["/home/alice"])
        self.assertNotIn("Everyone", _broad_readers(records["/home/alice/a.txt"]))


class ADocumentIsReadWholeTest(unittest.TestCase):
    """SharePoint and SFTP read the first 5 MB of every file and handed it to the Office
    extractors, which need the zip directory at the end: a .docx/.xlsx/.pptx over 5 MB gave
    no text, and the record said PARTIAL with 5 MB scanned. Sizes are patched down here."""

    def test_sftp_reads_a_document_whole_and_says_when_it_could_not(self) -> None:
        doc = _docx("Contact alice.smith@example.com", padding=8192)
        tree = {"/home": (0o40755, 0, None), "/home/report.docx": (0o100644, 1000, doc),
                "/home/notes.txt": (0o100644, 1000, b"x" * 8192)}
        records = _sftp_records(tree, max_read_bytes=1024)
        report = records["/home/report.docx"]
        self.assertIn("alice.smith@example.com", report["content"])
        self.assertEqual(report["scan_completeness"], "COMPLETE")
        self.assertEqual((records["/home/notes.txt"]["scan_completeness"], records["/home/notes.txt"]["bytes_scanned"]),
                         ("PARTIAL", 1024), "a text file keeps the text limit")
        cut = _sftp_records(tree, max_read_bytes=1024, max_document_bytes=2048)["/home/report.docx"]
        self.assertEqual((cut["content"], cut["content_status"], cut["scan_completeness"], cut["bytes_scanned"]),
                         ("", "not_extracted", "NONE", 0))

    def test_sharepoint_reads_a_document_whole_and_says_when_it_could_not(self) -> None:
        from collectors import graph_scanner
        from collectors.smb_scanner import SMBScanner

        doc = _docx("Contact alice.smith@example.com", padding=8192)
        files = {"item-1": ("report.docx", doc), "item-2": ("customers.txt", CUSTOMERS.encode("utf-16"))}
        asked: list[int] = []

        class FakeClient:
            def __init__(self, source, cancel_check=None) -> None:
                pass

            def site_id(self):
                return "site-1"

            def drives(self, _site):
                return [{"id": "drive-1", "name": "Documents"}]

            def delta(self, _drive, _link=""):
                return ([{"id": "root", "root": {}}] +
                        [{"id": item, "name": name, "file": {}, "size": len(data), "parentReference": {"id": "root"},
                          "lastModifiedDateTime": "2026-10-01T00:00:00Z"} for item, (name, data) in files.items()],
                        "delta-link")

            def download_url(self, _drive, item):
                return f"https://contoso.sharepoint.com/download/{item}"

            def download(self, url, limit):
                asked.append(limit)
                return files[url.rsplit("/", 1)[1]][1][:limit]

        def scan(**limits):
            source = graph_scanner.GraphSource(tenant="t", client_id="c", client_secret="s",
                                               site="contoso.sharepoint.com:/sites/x", **limits)
            with patch.object(graph_scanner, "GraphClient", FakeClient):
                records, _, _ = graph_scanner.scan(source, None, read_text=SMBScanner._preview_content_from_bytes)
            return {record["name"]: record for record in records}

        records = scan(max_read_bytes=1024)
        self.assertIn("alice.smith@example.com", records["report.docx"]["content"])
        self.assertEqual(records["report.docx"]["scan_completeness"], "COMPLETE")
        self.assertEqual(records["customers.txt"]["content"], CUSTOMERS[:512], "the text limit, in the file's encoding")
        cut = scan(max_read_bytes=1024, max_document_bytes=2048)["report.docx"]
        self.assertEqual((cut["content"], cut["content_status"], cut["scan_completeness"], cut["bytes_scanned"]),
                         ("", "not_extracted", "NONE", 0))

    def test_without_a_reader_text_is_still_decoded_in_its_encoding(self) -> None:
        records = _sftp_records({"/home": (0o40755, 0, None),
                                 "/home/c.txt": (0o100644, 1000, CUSTOMERS.encode("utf-16"))}, read_text=None)
        self.assertEqual(records["/home/c.txt"]["content"], CUSTOMERS)


def _xlsx_text_after_the_cap(path: Path, cells: int = 80_000) -> None:
    """A workbook laid out as Excel writes it: theme, styles and the worksheet - indices
    into the shared strings only - before sharedStrings.xml, which holds every text."""
    rows = "".join(f'<row r="{row}"><c r="A{row}" t="s"><v>{row % 3}</v></c></row>' for row in range(1, cells + 1))
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/theme/theme1.xml", "<a:theme><a:font typeface=\"Calibri\">Office Theme</a:font></a:theme>")
        archive.writestr("xl/styles.xml", "<styleSheet><fonts><font><name val=\"Calibri\"/></font></fonts></styleSheet>")
        archive.writestr("xl/workbook.xml", '<workbook><sheets><sheet name="Customers" sheetId="1"/></sheets></workbook>')
        archive.writestr("xl/worksheets/sheet1.xml", f"<worksheet><sheetData>{rows}</sheetData></worksheet>")
        archive.writestr("xl/sharedStrings.xml",
                         "<sst><si><t>Customer Alice Smith</t></si><si><t>alice.smith@example.com</t></si>"
                         "<si><t>DE89370400440532013000</t></si></sst>")


@unittest.skipUnless(os.name == "nt" and __import__("shutil").which("powershell.exe"),
                     "runs the generated endpoint script with the local Windows PowerShell")
class TheEndpointScriptReadsWhatItSaysTest(unittest.TestCase):
    """The WinRM collector's script, run here by the local powershell.exe on a folder of this
    machine - the transport is not part of it, and no endpoint is contacted."""

    # Compresses well, not so well that the script skips it as a zip bomb.
    ENTRY = "".join(f"{hashlib.sha256(str(index).encode()).hexdigest()} {CUSTOMERS}" for index in range(400))

    @classmethod
    def setUpClass(cls) -> None:
        import shutil

        # The script skips noise roots, %TEMP% among them (it is under AppData).
        cls.root = Path("C:\\") / f"dspm_audit_collectors_{os.getpid()}"
        shutil.rmtree(cls.root, ignore_errors=True)
        cls.root.mkdir()
        (cls.root / "customers16.txt").write_bytes(CUSTOMERS.encode("utf-16"))
        (cls.root / "nobom16.txt").write_bytes(CUSTOMERS.encode("utf-16-le"))
        (cls.root / "names8.txt").write_bytes("Müller, Grüße € 😀\n".encode("utf-8"))
        with zipfile.ZipFile(cls.root / "export.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("customers.txt", cls.ENTRY.encode("utf-16"))
        _pdf(cls.root / "scan.pdf", title="Scanned passport")
        _xlsx_text_after_the_cap(cls.root / "customers.xlsx")
        cls.records = cls._run()

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil

        shutil.rmtree(cls.root, ignore_errors=True)

    @classmethod
    def _run(cls) -> dict[str, dict]:
        import subprocess

        from collectors.winrm_endpoint_scanner import _read_json, _scan_script

        script = _scan_script([str(cls.root)], max_depth=2, read_content=True, max_read_bytes=1_000_000,
                              allowed_extensions=[], extension_filter_enabled=False, include_hidden=True,
                              include_system=True, hidden_filter_enabled=False, system_filter_enabled=False,
                              read_acl=True, inspect_archives=True, hash_files=True, read_owner=True,
                              parallel_workers=1)
        script_path = cls.root.parent / f"dspm_audit_collectors_{os.getpid()}.ps1"
        script_path.write_text(script, encoding="utf-8-sig")
        try:
            run = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                  str(script_path)], capture_output=True, timeout=300, check=False)
        finally:
            script_path.unlink(missing_ok=True)
        assert run.returncode == 0, run.stderr.decode("utf-8", "replace")[:500]
        return {Path(str(record["path"]).split("::")[0]).name + ("::" + record["path"].split("::", 1)[1]
                                                                  if "::" in record["path"] else ""): record
                for record in (_read_json(run.stdout) or {}).get("records", [])}

    def test_utf16_with_and_without_a_mark_and_utf8_are_read_as_text(self) -> None:
        self.assertEqual(self.records["customers16.txt"]["content"], CUSTOMERS)
        self.assertEqual(self.records["nobom16.txt"]["content"], CUSTOMERS)
        self.assertEqual(self.records["names8.txt"]["content"], "Müller, Grüße € 😀\n")

    def test_a_zip_entry_is_read_whole_and_in_its_encoding(self) -> None:
        entry = self.records["export.zip::customers.txt"]
        self.assertEqual(entry["content"], self.ENTRY, "every block of the entry, not the first")

    def test_a_pdf_is_said_to_be_not_extracted(self) -> None:
        record = self.records["scan.pdf"]
        self.assertEqual((record["content"], record["content_status"], record["scan_completeness"],
                          record["bytes_scanned"]), ("", "not_extracted", "NONE", 0))

    def test_a_large_workbook_keeps_its_text_cells_and_says_it_was_cut(self) -> None:
        record = self.records["customers.xlsx"]
        self.assertIn("alice.smith@example.com", record["content"])
        self.assertIn("DE89370400440532013000", record["content"])
        self.assertNotIn("Office Theme", record["content"], "theme and styles hold no content")
        self.assertEqual((record["scan_completeness"], record["truncated"]), ("PARTIAL", True))

    def test_each_access_entry_carries_its_type_inheritance_and_sid(self) -> None:
        record = self.records["customers16.txt"]
        count = len(record["principals"])
        self.assertTrue(count, "the file has an ACL")
        self.assertEqual([len(record[key]) for key in ("permissions", "types", "inherited", "sids")], [count] * 4)
        self.assertTrue(set(record["types"]) <= {"Allow", "Deny"})
        self.assertTrue(all(str(sid).startswith("S-1-") for sid in record["sids"]), record["sids"])


class EndpointAccessEntriesAreReadAsWindowsReadsThemTest(unittest.TestCase):
    """The endpoint sent only names and rights: every entry read as an explicit Allow, so
    "Everyone: Deny Read" was broad read access (risk +20), and a broad group was known
    only by its English name - "Jeder" and "Все" never were."""

    def _scan(self, item: dict) -> dict:
        import json
        from types import SimpleNamespace

        from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner

        base = {"path": "C:\\Users\\a\\Documents\\x.txt", "name": "x.txt", "size": 1, "extension": ".txt",
                "content": "x", "owner": "PC\\a"}
        payload = json.dumps({"records": [{**base, **item}], "diagnostics": {}}).encode("utf-8")
        scanner = WinRMEndpointScanner(WinRMEndpointConfig(host="endpoint-01", username="scan", password="pw"))
        with patch.object(scanner, "_run_ps_file", return_value=SimpleNamespace(status_code=0, std_out=payload,
                                                                                 std_err=b"")), \
                patch.object(scanner, "_connection_hosts", return_value=["endpoint-01"]), \
                patch.object(scanner, "_connection_host", return_value="endpoint-01"):
            return scanner.scan()[0]["acl"]

    def test_a_deny_is_a_deny_and_a_broad_group_is_known_by_its_sid(self) -> None:
        from permissions.acl_analyzer import analyze_acl

        denied = self._scan({"principals": ["Everyone", "PC\\a"], "permissions": ["Read", "FullControl"],
                             "types": ["Deny", "Allow"], "inherited": [False, False], "sids": ["S-1-1-0", "S-1-5-21-1-2-3-1001"]})
        self.assertFalse(analyze_acl(denied)["wide_access"], "Everyone: Deny Read is not broad read access")
        german = self._scan({"principals": ["Jeder"], "permissions": ["ReadAndExecute, Synchronize"],
                             "types": ["Allow"], "inherited": [True], "sids": ["S-1-1-0"]})
        self.assertTrue(analyze_acl(german)["wide_access"], "Jeder is Everyone")
        self.assertEqual(german["entries"][0], {"principal": "Jeder", "sid": "S-1-1-0", "rights": "ReadAndExecute, Synchronize",
                                                "type": "allow", "inherited": True})

    def test_an_older_answer_without_entry_details_reads_as_before(self) -> None:
        acl = self._scan({"principals": "Everyone", "permissions": "Read"})
        self.assertEqual(acl, {"owner": "PC\\a", "principals": ["Everyone"], "permissions": ["Read"]})


if __name__ == "__main__":
    unittest.main()
