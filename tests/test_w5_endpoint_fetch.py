"""W5: an endpoint scan's content commands - fewer, overlapped, and reading each file once.

Measured on the replica of a real endpoint workload (2,467 selected files: 917 PDFs, 478 slide
decks, 334 Word and 257 Excel binaries the endpoint does not read text from, 469 text
files): the first scan took 105 commands, 309 s, 282 s of the endpoint's CPU and 896 MiB of
its disk reads to inspect 144 MiB of text. Four causes, each a test here:

- the fetch budget counted every file at its size up to the read cap, so a batch of PDFs
  and slide decks - none read - filled 32 MiB with five files;
- each batch was fetched, then analyzed, then the next fetched: the endpoint and this
  host each idle while the other worked;
- the endpoint read a text file twice (its text, then Get-FileHash) and read every PDF
  whole only to hash it, though it extracts nothing from one;
- a named file was resolved with Test-Path and Get-Item twice, and Get-Item without
  -Force returns nothing for a hidden file, which then never came back.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from backend import app as app_module
from collectors.winrm_endpoint_scanner import WINRM_GZIP_RESPONSE_PREFIX, WinRMEndpointConfig, _read_json, _scan_script

MB = 1024 * 1024
_POWERSHELL = shutil.which("powershell.exe")


class ABatchIsCountedByWhatItCarriesTest(unittest.TestCase):

    def test_files_the_endpoint_does_not_read_do_not_fill_the_budget(self) -> None:
        documents = [f"C:\\Users\\ana\\Documents\\deck-{index}.{ext}"
                     for index in range(600) for ext in ("pdf", "ppt", "doc")][:600]
        texts = [f"C:\\Users\\ana\\Documents\\notes-{index}.txt" for index in range(40)]
        sizes = {path.casefold(): 9 * MB for path in documents} | {path.casefold(): 400 * 1024 for path in texts}
        with mock.patch.dict(os.environ, {"DSPM_ENDPOINT_FETCH_BATCH_BYTES": str(16 * MB),
                                          "DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": str(5 * MB)}):
            batches = app_module._endpoint_fetch_batches(documents + texts, sizes)
        # 640 files of which 40 carry 16 MB of text: the count ends the batches, not 600 x 5 MB.
        self.assertEqual([len(batch) for batch in batches], [256, 256, 128])
        self.assertEqual([path for batch in batches for path in batch], documents + texts)

    def test_a_text_file_and_an_office_document_count_what_they_carry(self) -> None:
        cap = 5 * MB
        self.assertEqual(app_module._endpoint_fetch_bytes("C:\\a\\big.csv", 900 * MB, cap),
                         app_module.ENDPOINT_RECORD_BYTES + cap)
        self.assertEqual(app_module._endpoint_fetch_bytes("C:\\a\\book.xlsx", 30 * MB, cap),
                         app_module.ENDPOINT_RECORD_BYTES + app_module.ENDPOINT_EXTRACTED_TEXT_BYTES)
        self.assertEqual(app_module._endpoint_fetch_bytes("C:\\a\\scan.pdf", 30 * MB, cap),
                         app_module.ENDPOINT_RECORD_BYTES)
        self.assertEqual(app_module._endpoint_fetch_bytes("C:\\a\\deck.ppt", 30 * MB, cap),
                         app_module.ENDPOINT_RECORD_BYTES)


class TheNextBatchArrivesWhileThisOneIsAnalyzedTest(unittest.TestCase):

    def _run(self, batches: int, analyze, scan_seconds: float = 0.0):
        events: list[tuple[str, int, float]] = []
        lock = threading.Lock()
        fetched = {"n": 0}

        class Scanner:
            config = None
            last_scan_diagnostics: dict = {}

            def scan(self):
                index = fetched["n"]
                fetched["n"] += 1
                events.append(("fetch-start", index, time.monotonic()))
                time.sleep(scan_seconds)
                events.append(("fetch-end", index, time.monotonic()))
                return [{"path": f"C:\\f{index}.txt", "content": "x"}]

        paths = [f"C:\\f{index}.txt" for index in range(batches)]
        job = SimpleNamespace(progress=0, message="", cancel_requested=False, status="running", id="j")
        config = WinRMEndpointConfig(host="ep1", username="u", password="")
        with mock.patch.object(app_module, "_endpoint_fetch_batches", lambda wanted, _sizes: [[p] for p in wanted]), \
                mock.patch.object(app_module, "_analyze_endpoint_records", analyze(events, lock)):
            result = app_module._fetch_endpoint_content_in_batches(
                Scanner(), config, SimpleNamespace(), job, "host", paths, {}, message="Reading", session_lock=lock)
        return result, events

    def test_the_fetch_runs_ahead_and_the_session_is_free_meanwhile(self) -> None:
        def analyze(events, lock):
            def run(_report, batch, _job, **_kwargs):
                index = int(batch[0]["path"][4:-4])
                started = time.monotonic()
                # The fetch of the next batch starts while this one is analyzed ...
                while index + 1 < 3 and not any(e[0] == "fetch-start" and e[1] == index + 1 for e in events):
                    self.assertLess(time.monotonic() - started, 10, "the next batch was not fetched meanwhile")
                    time.sleep(0.01)
                # ... and the session is not held by the analysis.
                self.assertTrue(lock.acquire(timeout=10), "the analysis held the session")
                lock.release()
                events.append(("analyzed", index, time.monotonic()))
                return batch
            return run

        (analyzed, _archives, commands, errors, _fields), events = self._run(3, analyze)
        self.assertEqual(sorted(analyzed), ["c:\\f0.txt", "c:\\f1.txt", "c:\\f2.txt"])
        self.assertEqual(commands, 3)
        self.assertEqual(errors, [])

    def test_never_more_than_one_batch_ahead(self) -> None:
        def analyze(events, _lock):
            def run(_report, batch, _job, **_kwargs):
                index = int(batch[0]["path"][4:-4])
                time.sleep(0.2)
                # While batch i is analyzed, batch i+1 may be fetched, never i+2.
                self.assertFalse(any(e[0] == "fetch-start" and e[1] >= index + 2 for e in events),
                                 f"batch {index + 2} was fetched while {index} was analyzed")
                events.append(("analyzed", index, time.monotonic()))
                return batch
            return run

        (analyzed, *_rest), _events = self._run(5, analyze)
        self.assertEqual(len(analyzed), 5)

    def test_a_cancel_stops_the_fetch(self) -> None:
        def analyze(_events, _lock):
            def run(_report, batch, job, **_kwargs):
                job.cancel_requested = True
                return batch
            return run

        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            self._run(6, analyze, scan_seconds=0.05)


@unittest.skipUnless(os.name == "nt" and _POWERSHELL, "runs the collector's script with the local powershell.exe")
class TheEndpointReadsAFileOnceTest(unittest.TestCase):
    """The collector's own script, run here: what it reads and what it names a file."""

    @classmethod
    def setUpClass(cls) -> None:
        # Outside %TEMP%: the script skips AppData as a system location.
        cls.root = os.path.join("C:\\", f"dspm_w5_fetch_{os.getpid()}")
        shutil.rmtree(cls.root, ignore_errors=True)
        os.makedirs(cls.root)
        cls.text = os.path.join(cls.root, "notes.txt")
        with open(cls.text, "wb") as handle:
            handle.write(b"contact ana@example.com\n" * 500)
        cls.pdf = os.path.join(cls.root, "scan.pdf")
        with open(cls.pdf, "wb") as handle:
            handle.write(b"%PDF-1.4\n" + os.urandom(64 * 1024))
        cls.hidden = os.path.join(cls.root, "hidden.txt")
        with open(cls.hidden, "wb") as handle:
            handle.write(b"secret 4111 1111 1111 1111\n")
        subprocess.run(["attrib", "+H", cls.hidden], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        subprocess.run(["attrib", "-H", cls.hidden], capture_output=True)
        shutil.rmtree(cls.root, ignore_errors=True)

    def _fetch(self, paths: list[str]) -> dict:
        script = _scan_script(paths, max_depth=1, read_content=True, max_read_bytes=5 * MB, allowed_extensions=[],
                              extension_filter_enabled=False, include_hidden=True, include_system=False,
                              hidden_filter_enabled=False, system_filter_enabled=False, read_acl=True,
                              inspect_archives=False, hash_files=True, read_owner=True, parallel_workers=1)
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
                                  capture_output=True, timeout=180)
        finally:
            os.unlink(path)
        self.assertTrue(done.stdout.strip().startswith(WINRM_GZIP_RESPONSE_PREFIX), done.stderr[:400])
        return {record["path"]: record for record in (_read_json(done.stdout) or {}).get("records") or []}

    def test_a_text_file_is_named_by_the_bytes_it_was_read_for(self) -> None:
        record = self._fetch([self.text])[self.text]
        with open(self.text, "rb") as handle:
            data = handle.read()
        self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(record["content"], data.decode("utf-8"))
        self.assertFalse(record.get("hash_skipped"))
        # Its ACL, one entry per rule across the parallel lists (built by foreach, W5) - since
        # revision 0055 as collectors.acl_powershell sends it, masks instead of rights names.
        fields = record["acl_fields"]
        principals = fields["principals"] if isinstance(fields["principals"], list) else [fields["principals"]]
        self.assertIn("NT AUTHORITY\\SYSTEM", principals)
        for field in ("sids", "masks", "types", "inherited", "aflags"):
            values = fields[field] if isinstance(fields[field], list) else [fields[field]]
            self.assertEqual(len(values), len(principals), field)

    def test_a_file_being_written_is_still_hashed_from_its_one_read(self) -> None:
        # A log another process holds open for writing: the content read shares the file,
        # Get-FileHash (a second open, without FILE_SHARE_WRITE) does not - the file came
        # back with its text and no identity.
        with open(self.text, "ab") as writer:
            record = self._fetch([self.text])[self.text]
            writer.flush()
        with open(self.text, "rb") as handle:
            data = handle.read()
        self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())

    def test_a_pdf_the_endpoint_cannot_extract_is_not_read_to_hash_it(self) -> None:
        record = self._fetch([self.pdf])[self.pdf]
        self.assertEqual(record["content_status"], "not_extracted")
        self.assertEqual(record["sha256"], "")
        self.assertTrue(record["hash_skipped"], "a PDF was read whole only to be hashed")

    def test_a_hidden_file_named_in_a_fetch_comes_back(self) -> None:
        records = self._fetch([self.hidden, self.text])
        self.assertIn(self.hidden, records, "a hidden file the listing included was not fetched")
        self.assertIn("4111", records[self.hidden]["content"])
        self.assertTrue(records[self.hidden]["is_hidden"])


if __name__ == "__main__":
    unittest.main()


class AnSmbReadIsOneRequestTest(unittest.TestCase):
    """W5 (SMB): a file is read with one request - one open - and the sink takes nothing past
    what was asked for, however much a transport returns."""

    def test_the_sink_hashes_and_keeps_only_what_was_asked_for(self) -> None:
        from collectors.smb_scanner import _DigestSink

        sink = _DigestSink(read_limit=10, capture_limit=4)
        sink.write(b"0123456")
        sink.write(b"789ABCDEF")
        self.assertEqual(sink.written, 10)
        self.assertEqual(bytes(sink.captured), b"0123")
        self.assertEqual(sink.digest.hexdigest(), hashlib.sha256(b"0123456789").hexdigest())


@unittest.skipUnless(os.name == "nt" and _POWERSHELL, "runs the collector's script with the local powershell.exe")
class APageListsThroughDotNetTest(unittest.TestCase):
    """W5: a page lists a folder with GetFileSystemInfos - every entry, hidden ones too, as
    Get-ChildItem -Force did - and a folder it cannot list is still said to be unreadable."""

    def setUp(self) -> None:
        self.root = os.path.join("C:\\", f"dspm_w5_page_{os.getpid()}")
        shutil.rmtree(self.root, ignore_errors=True)
        os.makedirs(os.path.join(self.root, "open", "sub"))
        for name in ("a.txt", "b.txt"):
            with open(os.path.join(self.root, "open", name), "w", encoding="utf-8") as handle:
                handle.write("x")
        hidden = os.path.join(self.root, "open", "c.txt")
        with open(hidden, "w", encoding="utf-8") as handle:
            handle.write("x")
        subprocess.run(["attrib", "+H", hidden], check=True, capture_output=True)
        self.addCleanup(self._clean)

    def _clean(self) -> None:
        subprocess.run(["attrib", "-H", os.path.join(self.root, "open", "c.txt")], capture_output=True)
        shutil.rmtree(self.root, ignore_errors=True)

    def _page(self, folder: str) -> dict:
        page = {"folders": [{"path": folder, "depth": 1, "after": "", "root": False}],
                "page_size": 100, "max_folders": 10}
        script = _scan_script([], max_depth=None, read_content=False, max_read_bytes=MB, allowed_extensions=[],
                              extension_filter_enabled=False, include_hidden=True, include_system=False,
                              hidden_filter_enabled=False, system_filter_enabled=False, read_acl=False,
                              inspect_archives=False, hash_files=False, read_owner=False, parallel_workers=1,
                              page=page)
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
                                  capture_output=True, timeout=180)
        finally:
            os.unlink(path)
        return _read_json(done.stdout) or {}

    def test_every_entry_of_a_folder_hidden_included(self) -> None:
        data = self._page(os.path.join(self.root, "open"))
        names = sorted(record["name"] for record in data.get("records") or [])
        self.assertEqual(names, ["a.txt", "b.txt", "c.txt"])
        # A subfolder is handed on to be paged, not listed as a file.
        folders = data.get("folders") or []
        folders = [folders] if isinstance(folders, dict) else folders
        self.assertEqual([folder["path"] for folder in folders], [os.path.join(self.root, "open", "sub")])

    def test_a_folder_it_cannot_list_is_said_to_be_unreadable(self) -> None:
        # Gone by the time its page runs - a folder deleted, or a share that went away.
        closed = os.path.join(self.root, "closed")
        data = self._page(closed)
        unreadable = (data.get("diagnostics") or {}).get("unreadable_dirs") or []
        if isinstance(unreadable, str):
            unreadable = [unreadable]
        self.assertTrue(any(str(entry).startswith(closed) for entry in unreadable), unreadable)


class TheResponseIsParsedAtCSpeedTest(unittest.TestCase):
    """W5: a raw control character in the endpoint's JSON still reads as a space - by a
    translate table, not a Python generator over every character of a 16 MiB response."""

    def test_control_characters_are_spaces_as_before(self) -> None:
        from collectors.winrm_endpoint_scanner import _parse_json_text

        self.assertEqual(_parse_json_text('{"a": "x\x02y",\r\n"b": [1,\t2]}\x01'), {"a": "x y", "b": [1, 2]})
        self.assertEqual(_parse_json_text(b'\r\n{"c": "\xc3\xa9"}'), {"c": "\u00e9"})


from tests.test_w13_endpoint_frontier import _Endpoint, _EndpointTest  # noqa: E402


class ThePoolWarmsFromTheListingTest(_EndpointTest):
    """W5: an endpoint page that will read large texts starts the detector pool from its
    listing, so the warm-up overlaps the first content command instead of its analysis."""

    def test_the_pool_is_started_before_the_first_content_arrives(self) -> None:
        from backend.security import Principal
        from discovery import detector_pool

        started = threading.Event()
        at_fetch: list[bool] = []
        endpoint = _Endpoint({f"C:\\Data\\big{index}.txt": "plain words " * 7000 for index in range(5)})

        def serve(scanner, script):
            scanner.last_connection_host = "fs-endpoint"
            if '"page_size"' not in _page_of(script):
                at_fetch.append(started.is_set())
            return endpoint.run(script)

        payload = self._payload()
        principal = Principal(subject="tester", role="admin", tenant_id=self.tenant, auth_type="session")
        config = app_module._to_endpoint_config(payload, self.tenant)
        with mock.patch.object(detector_pool.DetectorPool, "start", lambda *_a, **_k: started.set()), \
                mock.patch.object(detector_pool.PoolLease, "start", lambda *_a, **_k: started.set()), \
                mock.patch.object(app_module.WinRMEndpointScanner, "_run_ps_file", serve):
            app_module._run_endpoint_scan_payload(config, payload, principal)
        self.assertTrue(at_fetch, "no content command ran")
        self.assertTrue(at_fetch[0], "the pool was started only after the first content arrived")


def _page_of(script: str) -> str:
    """The page a collector script was given, as JSON text ('{}' for a content command)."""
    import base64
    import re

    match = re.search(r'ConvertFrom-Json \(\[Text\.Encoding\]::UTF8\.GetString\(\[Convert\]::FromBase64String'
                      r'\("([A-Za-z0-9+/=]*)"\)\)\)', script)
    return base64.b64decode(match.group(1)).decode("utf-8") if match else ""
