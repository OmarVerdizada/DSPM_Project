"""C0.2: the sensitive data a scan leaves at rest, and how long it stays.

Gate lines: "synthetic PAN/secret/path strings cannot be recovered by searching cache and
sidecar files; cache reuse and incremental parity remain correct; erasure removes the
tenant's cache; production refuses a planted plaintext dump; a restore still succeeds
after cleanup". With them: the CLI's plaintext report obeys the export policy, plaintext
report files are aged out by default, and the cache's envelope refuses what it cannot
vouch for.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
import zlib
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

from backend import backup, config, housekeeping, store
from collectors import file_scanner
from discovery import scan_cache
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.parity import accuracy_projection

ROOT = Path(__file__).resolve().parents[1]

PAN_SPACED = "4111 1111 1111 1111"
PAN = "4111111111111111"
SECRET = "Zq9vC02CanarySecretValue7731"
FOLDER = "zz-c02-payroll-canary-folder"
STEM = "q3-salaries-c02-canary"
FILES = 6


def _plant_estate(root: Path) -> None:
    folder = root / FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    for index in range(FILES):
        (folder / f"{STEM}-{index}.txt").write_text(
            f"employee{index}@example.com\ncard {PAN_SPACED}\npassword={SECRET}{index}\n"
            f"aws_secret_access_key = {SECRET}{index}ABCDEFGHIJ\n",
            encoding="utf-8",
        )


def _needles() -> list[bytes]:
    found = []
    for text in (PAN_SPACED, PAN, SECRET, FOLDER, STEM):
        found.extend((text.encode("utf-8"), text.encode("utf-16-le")))
    return found


def _inflated(data: bytes) -> list[bytes]:
    """What someone holding the files, and not the key, could make of them: the bytes as
    they are, and inflated wherever they inflate - so compression alone does not pass."""
    readings = [data]
    for start in (0, len(scan_cache.ENVELOPE_MAGIC)):
        try:
            readings.append(zlib.decompress(data[start:]))
        except zlib.error:
            continue
    return readings


def _recoverable_readings(cache: Path) -> list[tuple[str, bytes]]:
    """Every file under the cache, and every value in every SQLite table there."""
    readings: list[tuple[str, bytes]] = []
    for path in sorted(item for item in cache.rglob("*") if item.is_file()):
        data = path.read_bytes()
        readings.extend((path.name, reading) for reading in _inflated(data))
        if data.startswith(b"SQLite format 3\x00"):
            conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
            try:
                tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
                for table in tables:
                    for row in conn.execute(f'SELECT * FROM "{table}"'):  # noqa: S608 - names read from the file itself
                        for value in row:
                            raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
                            readings.extend((f"{path.name}:{table}", reading) for reading in _inflated(raw))
            finally:
                conn.close()
    return readings


class _ScanTest(unittest.TestCase):
    tenant = "c02-gate"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.estate = self.root / "estate"
        self.cache = self.root / "cache"
        _plant_estate(self.estate)
        # Temp directories sit under %TEMP%, which the scanner skips on purpose.
        for patcher in (patch.object(file_scanner, "is_skipped_scan_path", return_value=False),
                        patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self.temp.cleanup)

    def _config(self, tenant: str | None = None, **overrides) -> ScanConfig:
        settings = dict(tenant_id=tenant or self.tenant, local_path=str(self.estate), walk_local_path=True,
                        persistent_cache_enabled=True, cache_dir=str(self.cache), max_workers=1)
        settings.update(overrides)
        return ScanConfig(**settings)

    def _run(self, tenant: str | None = None, **overrides) -> dict:
        return DSPMDiscoveryEngine(self._config(tenant, **overrides)).run().to_dict()

    def _cache_files(self) -> list[Path]:
        return sorted(path for path in self.cache.rglob("*") if path.is_file())


class NothingIsRecoverableFromTheCacheTest(_ScanTest):
    """The gate: every byte the cache leaves on disk, searched for what was planted."""

    def test_planted_values_and_paths_are_not_in_any_cache_file(self) -> None:
        first = self._run()
        self.assertEqual(len(first["files"]), FILES)
        self.assertTrue(all(item.get("findings") for item in first["files"]), "the planted values were not found")
        second = self._run()
        files = self._cache_files()
        self.assertTrue(any(path.name.endswith(".enc") for path in files), "no findings entry was written")
        self.assertTrue(any(path.name == "meta_index.sqlite" for path in files), "no reuse index was written")
        readings = _recoverable_readings(self.cache)
        self.assertGreater(len(readings), len(files), "the index's rows were not searched")
        for where, data in readings:
            for needle in _needles():
                self.assertNotIn(needle, data, f"{needle!r} is recoverable from {where}")
        # ... and the cache still does its job, verbatim.
        incremental = second["scan_diagnostics"]["incremental"]
        self.assertEqual(incremental["sidecar_hits"], FILES)
        self.assertEqual(second["scan_diagnostics"]["cache_reused_files"], FILES)
        self.assertEqual(accuracy_projection(first), accuracy_projection(second))

    def test_the_entries_do_hold_the_data_the_search_did_not_find(self) -> None:
        """Without this, an empty cache would pass the search above."""
        self._run()
        codec = scan_cache.codec_from_environment()
        directory = scan_cache.tenant_cache_dir(self.cache, self.tenant)
        opened = [codec.open(path.read_bytes()) for path in directory.glob("*.enc")]
        self.assertEqual(len(opened), FILES)
        self.assertTrue(all(FOLDER.encode() in plain for plain in opened), "an entry does not name its file")
        rows = sqlite3.connect(directory / "meta_index.sqlite")
        try:
            payloads = [row[0] for row in rows.execute("SELECT payload FROM entries")]
        finally:
            rows.close()
        self.assertEqual(len(payloads), FILES)
        self.assertTrue(all(payload.startswith(scan_cache.ENVELOPE_MAGIC) for payload in payloads))
        self.assertTrue(all(STEM.encode() in codec.open(payload) for payload in payloads))

    def test_no_staging_file_outlives_a_scan(self) -> None:
        self._run()
        self.assertEqual([path.name for path in self._cache_files() if path.name.endswith(".tmp")], [])

    def test_a_scan_without_a_key_writes_no_cache_at_all(self) -> None:
        with patch.object(scan_cache, "codec_from_environment",
                          side_effect=scan_cache.CacheKeyUnavailable("no key")):
            report = self._run()
        self.assertEqual(len(report["files"]), FILES)
        self.assertTrue(all(item.get("findings") for item in report["files"]))
        self.assertEqual(self._cache_files(), [], "a cache it could not seal was written anyway")


class TheEnvelopeTest(unittest.TestCase):

    def setUp(self) -> None:
        self.codec = scan_cache.CacheCodec(Fernet(Fernet.generate_key()))

    def test_a_sealed_entry_opens_and_names_its_format(self) -> None:
        sealed = self.codec.seal(b'{"path": "C:/x"}')
        self.assertTrue(sealed.startswith(scan_cache.ENVELOPE_MAGIC))
        self.assertNotIn(b"C:/x", sealed)
        self.assertEqual(self.codec.open(sealed), b'{"path": "C:/x"}')

    def test_what_it_cannot_vouch_for_is_a_miss(self) -> None:
        sealed = bytearray(self.codec.seal(b"entry"))
        sealed[-1] ^= 0x01
        other = scan_cache.CacheCodec(Fernet(Fernet.generate_key()))
        for stored, why in ((bytes(sealed), "altered"),
                            (other.seal(b"entry"), "another key"),
                            (zlib.compress(b'{"path": "C:/x"}'), "a plaintext entry"),
                            (b"", "empty"),
                            (scan_cache.ENVELOPE_MAGIC + b"\x00" * 10, "truncated")):
            with self.subTest(why=why):
                self.assertIsNone(self.codec.open(stored))

    def test_reads_and_inflation_are_bounded(self) -> None:
        oversized = self.codec.seal(b"x" * 200)
        with patch.object(scan_cache, "MAX_SEALED_BYTES", len(oversized) - 1):
            self.assertIsNone(self.codec.open(oversized), "an entry past the read bound was opened")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "entry.enc"
            path.write_bytes(oversized)
            with patch.object(scan_cache, "MAX_SEALED_BYTES", 16):
                self.assertIsNone(scan_cache.read_entry(path))
            self.assertFalse(path.exists(), "an oversized entry was left to be read again")
        bomb = Fernet(Fernet.generate_key())
        codec = scan_cache.CacheCodec(bomb)
        stored = scan_cache.ENVELOPE_MAGIC + base64.urlsafe_b64decode(bomb.encrypt(zlib.compress(b"\x00" * 4096)))
        with patch.object(scan_cache, "MAX_PLAIN_BYTES", 1024):
            self.assertIsNone(codec.open(stored), "an entry inflating past the bound was read")
            with self.assertRaises(scan_cache.EntryTooLarge):
                codec.seal(b"\x00" * 2048)

    def test_a_failed_write_leaves_the_previous_entry_whole(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / f"{'b' * 64}.enc"
            scan_cache.write_entry(path, b"previous entry")
            with patch.object(scan_cache.os, "replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    scan_cache.write_entry(path, b"the next entry, never finished")
            self.assertEqual(path.read_bytes(), b"previous entry", "a reader could have seen half an entry")
            self.assertEqual(sorted(item.name for item in Path(temp).iterdir()), [path.name],
                             "the staging file was left behind")

    def test_the_plain_codec_reads_only_plain_entries(self) -> None:
        plain = scan_cache.CacheCodec(None)
        self.assertEqual(plain.open(plain.seal(b"entry")), b"entry")
        self.assertIsNone(plain.open(self.codec.seal(b"entry")))


class TheOldPlaintextCacheIsDiscardedTest(_ScanTest):

    def test_the_pre_c02_layout_is_removed_by_name_and_nothing_else(self) -> None:
        self.cache.mkdir(parents=True)
        digest = "a" * 64
        legacy = [self.cache / f"{digest}.json", self.cache / f"{digest}.meta.json", self.cache / f"{digest}.tmp",
                  self.cache / "meta_index.sqlite", self.cache / "meta_index.sqlite-wal"]
        for path in legacy:
            path.write_text(json.dumps({"path": f"C:/{FOLDER}/old.txt"}), encoding="utf-8")
        foreign = [self.cache / "notes.json", self.cache / f"{digest}.json.keep"]
        for path in foreign:
            path.write_text("someone else's", encoding="utf-8")
        self._run()
        self.assertEqual([path.name for path in legacy if path.exists()], [], "plaintext entries survived")
        self.assertEqual([path.name for path in foreign if not path.exists()], [], "a file not ours was deleted")

    def test_a_directory_sealed_under_another_key_is_emptied_not_read(self) -> None:
        self._run()
        directory = scan_cache.tenant_cache_dir(self.cache, self.tenant)
        old_entries = {path.name for path in directory.glob("*.enc")}
        self.assertEqual(len(old_entries), FILES)
        rotated = Fernet.generate_key()
        with patch.object(scan_cache, "codec_from_environment",
                          return_value=scan_cache.CacheCodec(Fernet(rotated))):
            report = self._run()
        self.assertEqual(report["scan_diagnostics"]["incremental"]["sidecar_hits"], 0)
        self.assertNotIn("reuse_index", report["scan_diagnostics"], "a key change read as damage")
        self.assertTrue(all(item.get("findings") for item in report["files"]))
        marker = (directory / scan_cache.FORMAT_FILENAME).read_bytes()
        self.assertTrue(scan_cache.CacheCodec(Fernet(rotated)).marker_matches(marker))

    def test_turning_sealing_off_and_on_never_mixes_the_formats(self) -> None:
        self._run()
        with mock.patch.dict(os.environ, {"DSPM_SCAN_CACHE_ENCRYPT": "0"}):
            plain = self._run()
        self.assertEqual(plain["scan_diagnostics"]["incremental"]["sidecar_hits"], 0)
        sealed = self._run()
        self.assertEqual(sealed["scan_diagnostics"]["incremental"]["sidecar_hits"], 0)
        directory = scan_cache.tenant_cache_dir(self.cache, self.tenant)
        codec = scan_cache.codec_from_environment()
        for path in directory.glob("*.enc"):
            self.assertIsNotNone(codec.open(path.read_bytes()), f"{path.name} is not sealed")

    def test_an_entry_that_does_not_open_is_removed_and_the_file_read_again(self) -> None:
        first = self._run(incremental_enabled=False)
        directory = scan_cache.tenant_cache_dir(self.cache, self.tenant)
        entries = sorted(directory.glob("*.enc"))
        entries[0].write_bytes(zlib.compress(json.dumps({"findings": []}).encode()))
        second = self._run(incremental_enabled=False)
        self.assertEqual(accuracy_projection(first), accuracy_projection(second))
        self.assertIsNotNone(scan_cache.codec_from_environment().open(entries[0].read_bytes()),
                             "the plaintext entry was neither removed nor replaced by a sealed one")

    def test_a_findings_entry_that_does_not_open_is_removed_on_the_spot(self) -> None:
        engine = DSPMDiscoveryEngine(self._config())
        key = ("c02-gate", "C:/x.txt", "hash", 1, "mtime")
        path = engine._cache_path(key)
        path.write_bytes(json.dumps({"cache_key": "anything", "findings": [{"value": PAN}]}).encode())
        self.assertIsNone(engine._load_cached_findings(key))
        self.assertFalse(path.exists(), "an entry that cannot be vouched for was left on disk")

    def test_an_entry_moved_under_another_files_name_does_not_answer_for_it(self) -> None:
        self._run()
        directory = scan_cache.tenant_cache_dir(self.cache, self.tenant)
        conn = sqlite3.connect(directory / "meta_index.sqlite")
        try:
            rows = conn.execute("SELECT digest, payload FROM entries ORDER BY digest").fetchall()
            # Every row now holds the first row's (authentic) payload.
            conn.executemany("UPDATE entries SET payload = ? WHERE digest = ?",
                             [(rows[0][1], digest) for digest, _payload in rows[1:]])
            conn.commit()
        finally:
            conn.close()
        report = self._run()
        self.assertEqual(report["scan_diagnostics"]["incremental"]["sidecar_hits"], 1,
                         "an entry answered for a file it does not describe")


class ACacheBelongsToOneWorkspaceTest(_ScanTest):

    def setUp(self) -> None:
        super().setUp()
        self._previous_db = store.DB_PATH
        store.DB_PATH = self.root / "c02.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", self._previous_db)
        env = mock.patch.dict(os.environ, {"DSPM_SCAN_CACHE_DIR": str(self.cache),
                                           "DSPM_ARTIFACT_DIR": str(self.root / "artifacts")})
        env.start()
        self.addCleanup(env.stop)
        store.init_db()
        suffix = uuid.uuid4().hex[:8]
        self.a, self.b = f"c02-a-{suffix}", f"c02-b-{suffix}"
        for tenant in (self.a, self.b):
            store.create_tenant(tenant, tenant)

    def _scan(self, tenant: str) -> dict:
        # The cache directory comes from DSPM_SCAN_CACHE_DIR, as it does for the console.
        return DSPMDiscoveryEngine(self._config(tenant, cache_dir=scan_cache.default_cache_dir())).run().to_dict()

    def test_two_workspaces_scanning_one_folder_share_nothing(self) -> None:
        self._scan(self.a)
        b = self._scan(self.b)
        self.assertEqual(b["scan_diagnostics"]["incremental"]["sidecar_hits"], 0,
                         "a workspace reused another workspace's analysis")
        self.assertEqual(b["scan_diagnostics"]["cache_reused_files"], 0)
        dir_a, dir_b = (scan_cache.tenant_cache_dir(self.cache, tenant) for tenant in (self.a, self.b))
        self.assertNotEqual(dir_a, dir_b)
        self.assertEqual(len(list(dir_a.glob("*.enc"))), FILES)
        self.assertEqual(len(list(dir_b.glob("*.enc"))), FILES)
        self.assertEqual(self._scan(self.a)["scan_diagnostics"]["incremental"]["sidecar_hits"], FILES)

    def test_erasing_a_workspace_removes_its_cache_and_leaves_the_others(self) -> None:
        self._scan(self.a)
        self._scan(self.b)
        usage = store.delete_tenant_with_data(self.a)
        self.assertFalse(scan_cache.tenant_cache_dir(self.cache, self.a).exists(), "the erased workspace's cache remains")
        self.assertGreaterEqual(usage["scan_cache_files_removed"], FILES)
        self.assertTrue(scan_cache.tenant_cache_dir(self.cache, self.b).exists())
        self.assertEqual(self._scan(self.b)["scan_diagnostics"]["incremental"]["sidecar_hits"], FILES,
                         "erasing one workspace cost another its cache")

    def test_an_erasure_that_cannot_remove_the_cache_fails_loudly(self) -> None:
        self._scan(self.a)
        with patch.object(scan_cache.shutil, "rmtree", side_effect=PermissionError("held open")):
            with self.assertRaises(PermissionError):
                store.delete_tenant_with_data(self.a)
        self.assertTrue(store.tenant_exists(self.a), "the erasure reported success with the cache still on disk")
        self.assertTrue(scan_cache.tenant_cache_dir(self.cache, self.a).exists())

    def test_resetting_the_default_workspace_empties_its_cache(self) -> None:
        with suppress(Exception):
            store.create_tenant("default", "Default")
        store.create_user("admin", "kept-hash", "admin", "default", "Admin")
        self._scan("default")
        self.assertTrue(scan_cache.tenant_cache_dir(self.cache, "default").exists())
        usage = store.reset_default_tenant_data()
        self.assertFalse(scan_cache.tenant_cache_dir(self.cache, "default").exists())
        self.assertGreaterEqual(usage["scan_cache_files_removed"], FILES)

    def test_a_workspace_id_never_reaches_outside_its_directory(self) -> None:
        for tenant in ("../../escape", "Acme", "acme", "C:\\x", "\u00e9quipe"):
            name = scan_cache.tenant_dir_name(tenant)
            self.assertRegex(name, r"^[a-z0-9_-]+-[0-9a-f]{16}$")
        self.assertNotEqual(scan_cache.tenant_dir_name("Acme").lower(), scan_cache.tenant_dir_name("acme").lower(),
                            "two workspaces differing in case share one directory on Windows")


class TheCommandLineScanObeysTheExportPolicyTest(unittest.TestCase):

    def _args(self, output: Path) -> argparse.Namespace:
        import main

        return main.build_parser().parse_args(["scan", "--local-path", str(output.parent), "--output", str(output)])

    @staticmethod
    def _report() -> MagicMock:
        report = MagicMock()
        report.to_dict.return_value = {"summary": {"total_files": 0}, "files": []}
        report.summary.total_files = 0
        return report

    def test_a_plaintext_report_is_refused_before_anything_is_scanned(self) -> None:
        import main

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            for env in ({"DSPM_PLAINTEXT_REPORT_EXPORT": "0"},
                        {"DSPM_PLAINTEXT_REPORT_EXPORT": "1", "DSPM_ENV": "production"}):
                with self.subTest(env=env), mock.patch.dict(os.environ, env), \
                        patch.object(main, "DSPMDiscoveryEngine") as engine:
                    engine.return_value.run.return_value = self._report()
                    with self.assertRaises(SystemExit) as refused:
                        main.run_scan(self._args(output))
                    self.assertIn("DSPM_PLAINTEXT_REPORT_EXPORT", str(refused.exception.code))
                    engine.assert_not_called()
                    self.assertFalse(output.exists())

    def test_an_install_that_allows_plaintext_exports_still_gets_its_file(self) -> None:
        import main

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            with mock.patch.dict(os.environ, {"DSPM_PLAINTEXT_REPORT_EXPORT": "1", "DSPM_ENV": "local"}), \
                    patch.object(main, "DSPMDiscoveryEngine") as engine:
                engine.return_value.run.return_value = self._report()
                main.run_scan(self._args(output))
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["files"], [])

    def test_one_policy_for_every_plaintext_copy(self) -> None:
        self.assertFalse(config.plaintext_export_allowed({}))
        self.assertTrue(config.plaintext_export_allowed({"DSPM_PLAINTEXT_REPORT_EXPORT": "1"}))
        self.assertFalse(config.plaintext_export_allowed({"DSPM_PLAINTEXT_REPORT_EXPORT": "1", "DSPM_ENV": "prod"}))


class ProductionRefusesAPlaintextCacheTest(unittest.TestCase):

    def test_turning_the_cache_encryption_off_is_refused_in_production(self) -> None:
        refused = config.production_problems(config.resolve({"DSPM_SCAN_CACHE_ENCRYPT": "0"}, None))
        self.assertTrue(any(problem.startswith("DSPM_SCAN_CACHE_ENCRYPT=0") for problem in refused), refused)
        allowed = config.production_problems(config.resolve({}, None))
        self.assertFalse(any("DSPM_SCAN_CACHE_ENCRYPT" in problem for problem in allowed))
        local = config.resolve({"DSPM_SCAN_CACHE_ENCRYPT": "0"}, None)
        self.assertFalse(any("DSPM_SCAN_CACHE_ENCRYPT" in error for error in local.errors))


class ThePlaintextReportFilesAreAgedOutTest(unittest.TestCase):

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self._previous_db = store.DB_PATH
        store.DB_PATH = base / "housekeeping.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", self._previous_db)
        env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(base / "artifacts")})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("DSPM_RETAIN_REPORT_FILE_DAYS", None)
        store.init_db()
        self.now = datetime(2026, 10, 1, 3, 0, tzinfo=timezone.utc)
        self.reports = base / "reports"
        self.reports.mkdir()
        self.held = f"held{uuid.uuid4().hex[:6]}"
        store.create_tenant(self.held, "held")
        store.set_legal_hold(self.held, True, "litigation")

    def _file(self, name: str, age_days: int) -> Path:
        path = self.reports / name
        path.write_text("{}", encoding="utf-8")
        stamp = (self.now - timedelta(days=age_days)).timestamp()
        os.utime(path, (stamp, stamp))
        return path

    def test_the_default_keeps_a_quarter_and_never_a_held_workspaces_files(self) -> None:
        self.assertEqual(housekeeping.report_file_days(), 90)
        old = self._file("acme_1.json", 91)
        recent = self._file("acme_2.json", 89)
        held = self._file(f"{self.held}_3.json", 400)
        summary = housekeeping.run_retention(now=self.now, report_dir=self.reports)
        classes = {row["data_class"]: row for row in summary["data_classes"]}
        self.assertEqual(classes["report_files"]["retention_days"], 90)
        self.assertEqual(classes["report_files"]["removed_rows"], 1)
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists())
        self.assertTrue(held.exists(), "a held workspace's report file was deleted")

    def test_zero_still_keeps_them_and_a_typo_keeps_the_default(self) -> None:
        old = self._file("acme_1.json", 400)
        with mock.patch.dict(os.environ, {"DSPM_RETAIN_REPORT_FILE_DAYS": "0"}):
            housekeeping.run_retention(now=self.now, report_dir=self.reports)
        self.assertTrue(old.exists())
        with mock.patch.dict(os.environ, {"DSPM_RETAIN_REPORT_FILE_DAYS": "ninety"}):
            self.assertEqual(housekeeping.report_file_days(), 90)

    def test_the_default_is_the_documented_one(self) -> None:
        self.assertEqual(config.SETTINGS["DSPM_RETAIN_REPORT_FILE_DAYS"].default, "90")
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("DSPM_RETAIN_REPORT_FILE_DAYS=90", example)


class APlaintextDumpIsRecognisedTest(unittest.TestCase):

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _write(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def test_what_it_is_decides_not_what_it_is_called(self) -> None:
        tar_header = b"report.json".ljust(257, b"\x00") + b"ustar\x0000" + b"\x00" * 300
        cases = {
            "sentro_20260902T060717Z.dump": (b"PGDMP\x01\x0e\x00" + b"\x00" * 64, "pg_dump"),
            "copy.bin": (b"SQLite format 3\x00" + b"\x00" * 84, "SQLite"),
            "old.db": (b"SQLite format 3\x00" + b"\x00" * 84, "SQLite"),
            "plain.txt": (b"--\n-- PostgreSQL database dump\n--\nCREATE TABLE tenants (id text);\n", "SQL"),
            "export.sql": (b"PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\nINSERT INTO t VALUES(1);\n", "SQL"),
            "acme_1.json": (b'{"scan_id": "1", "files": [{"path": "C:/x"}]}', "scan report"),
            "estate.tar": (tar_header, "tar"),
            "renamed.backup": (b"just bytes", "named as a dump"),
        }
        for name, (data, kind) in cases.items():
            with self.subTest(name=name):
                self.assertIn(kind, backup.plaintext_dump_kind(self._write(name, data)) or "")

    def test_what_belongs_there_is_left_alone(self) -> None:
        source = self._write("plain.sqlite", b"SQLite format 3\x00" + b"\x00" * 200)
        key = Fernet.generate_key().decode()
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_KEY": key}):
            backup.encrypt_file(source, self.dir / "sentro_sqlite_x.sqlite.enc")
        source.unlink()
        self._write("sentro_sqlite_x.manifest.json", json.dumps({"file": "sentro_sqlite_x.sqlite.enc"}).encode())
        self._write("Thumbs.db", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100)
        self._write("README.txt", b"Backups of the Sentro database.")
        self._write("sentro_x.artifacts.tar", b"objects".ljust(257, b"\x00") + b"ustar\x0000" + b"\x00" * 300)
        self.assertEqual(backup.plaintext_dumps(self.dir), [])
        self.assertIsNone(backup.plaintext_dump_problem(self.dir))


class ProductionRefusesAPlantedDumpTest(unittest.TestCase):

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dump = self.dir / "sentro_20260902T060717Z.dump"
        self.dump.write_bytes(b"PGDMP" + b"\x00" * 128)

    def test_startup_refuses_and_names_the_file(self) -> None:
        from fastapi.testclient import TestClient

        from backend import app as app_module

        with mock.patch.dict(os.environ, {"DSPM_BACKUP_DIR": str(self.dir)}), \
                mock.patch.object(app_module, "ENVIRONMENT", "production"):
            with self.assertRaises(RuntimeError) as refused:
                with TestClient(app_module.app):
                    pass
        self.assertIn(self.dump.name, str(refused.exception))
        self.assertIn("pg_dump", str(refused.exception))

    def test_without_the_dump_or_outside_production_it_starts(self) -> None:
        from fastapi.testclient import TestClient

        from backend import app as app_module

        with mock.patch.dict(os.environ, {"DSPM_BACKUP_DIR": str(self.dir)}), \
                mock.patch.object(app_module, "ENVIRONMENT", "local"):
            with TestClient(app_module.app) as client:
                self.assertEqual(client.get("/api/health").status_code, 200)
        self.dump.unlink()
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_DIR": str(self.dir)}), \
                mock.patch.object(app_module, "ENVIRONMENT", "production"):
            with TestClient(app_module.app) as client:
                self.assertEqual(client.get("/api/health").status_code, 200)


def _main(args: list[str], config_file: Path) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
    env["DSPM_CONFIG_FILE"] = str(config_file)
    return subprocess.run([sys.executable, str(ROOT / "main.py"), *args], cwd=ROOT, env=env,
                          capture_output=True, encoding="utf-8", errors="replace", timeout=300)


class TheCleanupProcedureTest(unittest.TestCase):
    """The documented procedure, end to end: production refuses the dump, an encrypted
    backup is taken and restored, the dump is removed, production accepts, and the backup
    still restores after the cleanup."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.backups = self.tmp / "backups"
        self.backups.mkdir()
        for name in ("backup_key", "artifact_key"):
            (self.tmp / name).write_text(Fernet.generate_key().decode(), encoding="utf-8")
        self.db = self.tmp / "db" / "dspm.sqlite"
        self.db.parent.mkdir()
        self.local = self.tmp / "local.toml"
        self.local.write_text("\n".join([
            "[settings]",
            f"DSPM_DB_PATH = '{self.db}'",
            f"DSPM_BACKUP_DIR = '{self.backups}'",
            f"DSPM_ARTIFACT_DIR = '{self.tmp / 'artifacts'}'",
            f"DSPM_BACKUP_KEY_FILE = '{self.tmp / 'backup_key'}'",
            f"DSPM_ARTIFACT_KEY_FILE = '{self.tmp / 'artifact_key'}'",
            f"DSPM_LOCAL_JWT_SECRET_PATH = '{self.tmp / 'jwt'}'",
            f"DSPM_LOCAL_VAULT_KEY_PATH = '{self.tmp / 'vault.key'}'",
            f"DSPM_LOCAL_EVIDENCE_KEY_PATH = '{self.tmp / 'evidence.key'}'",
            f"DSPM_SCAN_CACHE_DIR = '{self.tmp / 'cache'}'",
            f"DSPM_REPORT_DIR = '{self.tmp / 'reports'}'",
            "",
        ]), encoding="utf-8")
        secrets = []
        for name, value in (("DSPM_SECRET_KEY", "jwt-" + "k" * 40), ("DSPM_VAULT_KEY", Fernet.generate_key().decode()),
                            ("DSPM_ARTIFACT_KEY", Fernet.generate_key().decode()),
                            ("DSPM_BACKUP_KEY", Fernet.generate_key().decode()),
                            ("DSPM_EVIDENCE_HMAC_KEY", "evidence-" + "e" * 30),
                            ("DSPM_ADMIN_PASSWORD", "Kestrel-admin-pass-4471"),
                            ("DSPM_DB_URL", "postgresql://sentro_app:pw@127.0.0.1:5432/sentro")):
            path = self.tmp / f"prod_{name.lower()}"
            path.write_text(value, encoding="utf-8")
            secrets.append(f"{name}_FILE = '{path}'")
        self.production = self.tmp / "production.toml"
        self.production.write_text("\n".join(["[settings]", 'DSPM_ENV = "production"', *secrets,
                                              f"DSPM_BACKUP_DIR = '{self.backups}'", ""]), encoding="utf-8")
        migrated = _main(["migrate", "upgrade", "--json"], self.local)
        self.assertEqual(migrated.returncode, 0, migrated.stderr)
        conn = sqlite3.connect(self.db)
        conn.execute("INSERT INTO tenants (tenant_id, display_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
                     ("c02-kept", "kept across the drill", "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z"))
        conn.commit()
        conn.close()
        # The known plaintext dump, as it was found on a real install.
        self.dump = self.backups / "sentro_20260902T060717Z.dump"
        self.dump.write_bytes(b"PGDMP\x01\x0e\x00" + PAN.encode() + b"\x00" * 64)

    def _restore_drill(self) -> None:
        manifest = sorted(self.backups.glob("*.manifest.json"))[-1]
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM tenants WHERE tenant_id = 'c02-kept'")
        conn.commit()
        conn.close()
        restored = _main(["backup", "restore", str(manifest), "--yes", "--json"], self.local)
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        conn = sqlite3.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT display_name FROM tenants WHERE tenant_id = 'c02-kept'").fetchone(),
                             ("kept across the drill",))
        finally:
            conn.close()

    def test_refuse_then_back_up_restore_clean_and_restore_again(self) -> None:
        checked = _main(["config", "check"], self.production)
        self.assertEqual(checked.returncode, 1, checked.stdout + checked.stderr)
        self.assertIn(self.dump.name, checked.stdout)
        self.assertIn("will not start", checked.stdout)

        created = _main(["backup", "create", "--verify", "--json"], self.local)
        self.assertEqual(created.returncode, 0, "a backup must be possible beside the dump: " + created.stdout + created.stderr)
        self.assertTrue(json.loads(created.stdout.strip().splitlines()[-1])["verified"])
        self._restore_drill()

        self.dump.unlink()  # the operator's step, after the drill
        checked = _main(["config", "check"], self.production)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertEqual(backup.plaintext_dumps(self.backups), [], "the encrypted backup set reads as a dump")
        self._restore_drill()


if __name__ == "__main__":
    unittest.main()
