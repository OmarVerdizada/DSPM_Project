"""The report body must never exist as one string.

`json.dumps(report)` was the tallest single thing in a save: 4.63 KB per file of
text, handed to `_store_report_body`, which peaked at 9.00 KB per file because
it encoded and compressed the body while the original was still alive. On a
million-file scan that is a gigabyte of JSON built only to be written once.

It is produced in pieces now and streamed into the artifact tier. Two properties
have to hold for that to be a refactor rather than a migration: the text must be
byte-for-byte what `json.dumps` produced, and the object must land under the
same content id - an artifact is named by the SHA-256 of its plaintext, so a
different-but-equivalent encoding would silently re-store every report in the
install on its next lifecycle update.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from unittest import mock

from backend import artifacts, store


def _report(scan_id: str, files: int = 40) -> dict:
    return {
        "scan_id": scan_id,
        "timestamp": "2026-09-11T00:00:00Z",
        "source": "smb",
        "scan_label": "streamed-body",
        "summary": {"total_files": files, "critical": 0, "high": files,
                    "medium": 0, "low": 0, "sensitive_files": files},
        "files": [
            {
                "path": f"//fs01/share/f{index}.txt", "name": f"f{index}.txt",
                "extension": ".txt", "size": 1000 + index, "source": "smb",
                "share": "share", "owner": "CORP/svc", "content_status": "scanned",
                "risk": {"level": "HIGH", "score": 70, "reasons": ["r"],
                         "dlp_recommendations": ["a"]},
                "findings": [{
                    "type": "credit_card", "finding_id": f"body-{index}",
                    "risk": "HIGH", "count": 1, "description": "d",
                    "samples": ["x"], "category": "pii", "framework": "gdpr",
                }],
            }
            for index in range(files)
        ],
    }


class TheBodyIsTheSameTextTest(unittest.TestCase):
    """Byte-identical, or every stored report gets a new name."""

    def test_it_matches_json_dumps_for_a_scan_report(self):
        for files in (0, 1, 3, 40):
            report = _report("s1", files)
            self.assertEqual(
                "".join(store.iter_report_json(report)),
                json.dumps(report, ensure_ascii=False),
                f"the streamed body diverged at {files} files",
            )

    def test_it_matches_json_dumps_for_awkward_shapes(self):
        shapes = [
            {},
            {"a": 1},
            {"files": []},
            {"files": [{}, {"a": None}]},
            # Non-ASCII has to survive: `ensure_ascii=False` is what keeps
            # Azerbaijani paths and owner names readable in a stored report.
            {"scan_id": "s", "note": "Şəmsi — «ünvan»", "files": [{"path": "//fs/İdarə/х.txt"}]},
            {"nested": {"a": [1, 2, {"b": None, "c": True}]}, "files": [{"x": 1}]},
            # "files" that is not a list falls through to the ordinary path.
            {"files": {"not": "a list"}},
            {"files": None},
        ]
        for shape in shapes:
            self.assertEqual(
                "".join(store.iter_report_json(shape)),
                json.dumps(shape, ensure_ascii=False),
                f"diverged on {shape!r}",
            )

    def test_key_order_is_preserved(self):
        """`json.dumps` emits insertion order, and so must this."""

        report = {"z": 1, "files": [{"a": 1}], "a": 2, "m": 3}
        streamed = "".join(store.iter_report_json(report))
        self.assertEqual(streamed, json.dumps(report, ensure_ascii=False))
        self.assertLess(streamed.index('"z"'), streamed.index('"files"'))
        self.assertLess(streamed.index('"files"'), streamed.index('"a"'))


class TheObjectKeepsItsNameTest(unittest.TestCase):
    """An artifact is named by the hash of its plaintext."""

    def setUp(self):
        self._previous = os.environ.get("DSPM_ARTIFACT_DIR")
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_ARTIFACT_DIR"] = self._dir.name

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("DSPM_ARTIFACT_DIR", None)
        else:
            os.environ["DSPM_ARTIFACT_DIR"] = self._previous
        self._dir.cleanup()

    def test_streaming_a_body_lands_where_writing_it_whole_did(self):
        report = _report("s1", 30)
        whole = artifacts.put_text("default", json.dumps(report, ensure_ascii=False))
        streamed = artifacts.put_stream("default", store.iter_report_json(report))
        self.assertEqual(streamed.content_id, whole.content_id)
        self.assertEqual(streamed.size_bytes, whole.size_bytes)

    def test_a_streamed_object_reads_back_through_the_ordinary_path(self):
        payload = "".join(f"line {index}\n" for index in range(5000))
        ref = artifacts.put_stream("default", (f"line {index}\n" for index in range(5000)))
        self.assertEqual(artifacts.get_bytes("default", ref.content_id).decode(), payload)

    def test_bytes_and_str_chunks_agree(self):
        as_text = artifacts.put_stream("default", ["alpha", "beta", "gamma"])
        as_bytes = artifacts.put_stream("default", [b"alpha", b"beta", b"gamma"])
        self.assertEqual(as_text.content_id, as_bytes.content_id)
        self.assertEqual(as_text.content_id, artifacts.put_bytes("default", b"alphabetagamma").content_id)

    def test_empty_chunks_are_not_part_of_the_content(self):
        self.assertEqual(
            artifacts.put_stream("default", ["a", "", b"", "b"]).content_id,
            artifacts.put_bytes("default", b"ab").content_id,
        )

    def test_a_failure_partway_leaves_no_object_behind(self):
        """The name promises the whole body; a truncated object must not take it."""

        def explode():
            yield "the beginning"
            raise RuntimeError("the scan died here")

        before = sorted(p.name for p in nested_files(self._dir.name))
        with self.assertRaises(RuntimeError):
            artifacts.put_stream("default", explode())
        self.assertEqual(sorted(p.name for p in nested_files(self._dir.name)), before,
                         "a partial write left a file in the artifact tier")


def nested_files(root):
    import pathlib

    return [p for p in pathlib.Path(root).rglob("*") if p.is_file()]


class KeysAreEncodedTheWayJsonDumpsEncodesThemTest(unittest.TestCase):
    """A top-level key goes through JSON's key coercion, not its value encoding."""

    def test_non_string_keys_match_json_dumps(self):
        for shape in ({1: "a"}, {None: "c", 2.5: "d", False: "e"}, {"files": [], 7: {"x": 1}}):
            with self.subTest(shape=shape):
                self.assertEqual(
                    "".join(store.iter_report_json(shape)), json.dumps(shape, ensure_ascii=False),
                )

    def test_a_key_json_dumps_refuses_is_refused(self):
        with self.assertRaises(TypeError):
            json.dumps({(1, 2): 1})
        with self.assertRaises(TypeError):
            "".join(store.iter_report_json({(1, 2): 1}))


class NothingReadableReachesTheDiskTest(unittest.TestCase):
    """The artifact tier is encrypted at rest, and that includes a write in progress.

    A stream is compressed into a scratch file before its name is known. If that
    file held gzip of the plaintext, a process killed mid-save - an OOM kill, a
    service stop, a power cut, all likelier on a large scan - would leave a
    readable copy of the report in the tenant directory for good.
    """

    def setUp(self):
        self._previous = os.environ.get("DSPM_ARTIFACT_DIR")
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_ARTIFACT_DIR"] = self._dir.name

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("DSPM_ARTIFACT_DIR", None)
        else:
            os.environ["DSPM_ARTIFACT_DIR"] = self._previous
        self._dir.cleanup()

    def test_a_write_in_progress_holds_no_recoverable_plaintext(self):
        import hashlib
        import pathlib
        import zlib

        marker = "PLAINTEXT-MARKER-4111111111111111"
        inspected = {}

        def body():
            # Hex digests barely compress, so the scratch file really fills up.
            for index in range(40_000):
                yield f"{marker} {hashlib.sha256(str(index).encode()).hexdigest()}\n"
            tenant_dir = pathlib.Path(self._dir.name) / "default"
            scratch = [p for p in tenant_dir.rglob("*") if p.is_file() and not p.name.endswith(".enc")]
            raw = b"".join(p.read_bytes() for p in scratch)
            try:
                recovered = zlib.decompressobj(31).decompress(raw)
            except zlib.error:
                recovered = b""
            inspected.update(files=len(scratch), size=len(raw), recovered=recovered)
            yield "end\n"

        with mock.patch.object(artifacts, "_STREAM_FRAME_BYTES", 64 * 1024):
            ref = artifacts.put_stream("default", body())

        self.assertEqual(inspected["files"], 1, "expected exactly one scratch file mid-stream")
        self.assertGreater(inspected["size"], 0, "nothing had been written yet, so this proves nothing")
        self.assertNotIn(marker.encode(), inspected["recovered"], "the scratch file is readable plaintext")
        self.assertIn(marker.encode(), artifacts.get_bytes("default", ref.content_id))

    def test_prune_sweeps_what_an_interrupted_write_left_behind(self):
        import pathlib
        import time as _time

        tenant_dir = pathlib.Path(self._dir.name) / "default"
        (tenant_dir / "ab").mkdir(parents=True)
        old = [tenant_dir / ".streaming-dead.gz", tenant_dir / ".streaming-dead.part",
               tenant_dir / "ab" / ("a" * 64 + ".123.partial")]
        fresh = tenant_dir / ".streaming-live.part"
        for path in (*old, fresh):
            path.write_bytes(b"leftover")
        stale = _time.time() - 7200
        for path in old:
            os.utime(path, (stale, stale))

        artifacts.prune(set(), grace_seconds=3600)

        self.assertEqual([p for p in old if p.exists()], [], "a crashed write's leftovers survived prune")
        self.assertTrue(fresh.exists(), "a write still in progress was swept")


class TwoWritersOfTheSameContentTest(unittest.TestCase):

    def setUp(self):
        self._previous = os.environ.get("DSPM_ARTIFACT_DIR")
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_ARTIFACT_DIR"] = self._dir.name

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("DSPM_ARTIFACT_DIR", None)
        else:
            os.environ["DSPM_ARTIFACT_DIR"] = self._previous
        self._dir.cleanup()

    def test_both_succeed_and_the_object_reads_back(self):
        """They used to share one staging name, so on Windows one of them failed."""
        import threading

        from backend import backup

        barrier = threading.Barrier(2, timeout=10)
        real_encrypt = backup.encrypt_stream

        def meet_then_encrypt(fernet, src, out):
            barrier.wait()
            return real_encrypt(fernet, src, out)

        payload = b"the same report body, twice " * 2000
        errors: list[BaseException] = []

        def writer():
            try:
                artifacts.put_bytes("default", payload)
            except BaseException as exc:  # noqa: BLE001 - the test reports it
                errors.append(exc)

        with mock.patch.object(artifacts, "encrypt_stream", meet_then_encrypt):
            threads = [threading.Thread(target=writer) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
        self.assertEqual(errors, [])
        import hashlib

        self.assertEqual(artifacts.get_bytes("default", hashlib.sha256(payload).hexdigest()), payload)


class TheSaveNeverBuildsTheWholeBodyTest(unittest.TestCase):

    def setUp(self):
        self._previous = {key: os.environ.get(key) for key in ("DSPM_DB_PATH", "DSPM_ARTIFACT_DIR")}
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_DB_PATH"] = os.path.join(self._dir.name, "body.sqlite")
        os.environ["DSPM_ARTIFACT_DIR"] = os.path.join(self._dir.name, "artifacts")
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.init_db()
        store.create_tenant(self.tenant, self.tenant)

    def tearDown(self):
        for key, value in self._previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._dir.cleanup()

    def test_the_whole_body_entry_point_is_never_called(self):
        """`put_text` takes a finished string; the save must not have one."""

        with mock.patch.object(
            artifacts, "put_text",
            side_effect=AssertionError("the save built the report body as one string"),
        ):
            store.save_scan_history(self.tenant, _report("s1", 40))

        with store._connect() as conn:
            row = conn.execute(
                "SELECT report_ref, report_bytes, report_json FROM scan_reports "
                "WHERE tenant_id = ?", (self.tenant,),
            ).fetchone()
        self.assertTrue(row["report_ref"], "the body should be in the artifact tier")
        self.assertEqual(str(row["report_json"] or ""), "", "and not also inline")
        self.assertGreater(row["report_bytes"], 0)

    def test_a_saved_report_reads_back_exactly(self):
        """What comes back is what was stored - enrichment included.

        The save deliberately writes resolved lifecycle values back onto the
        findings before serialising, so the comparison is against the report as
        it left the save, not as it arrived.
        """

        report = _report("s1", 60)
        store.save_scan_history(self.tenant, report)
        self.assertEqual(
            json.dumps(store.read_scan_report(self.tenant, "s1"), ensure_ascii=False),
            json.dumps(report, ensure_ascii=False),
        )

    def test_re_saving_the_same_report_reuses_the_same_object(self):
        """Lifecycle updates re-save a report repeatedly; that must be free."""

        store.save_scan_history(self.tenant, _report("s1", 40))
        with store._connect() as conn:
            first = conn.execute(
                "SELECT report_ref FROM scan_reports WHERE tenant_id = ?", (self.tenant,)
            ).fetchone()["report_ref"]
        store.save_scan_history(self.tenant, _report("s1", 40))
        with store._connect() as conn:
            again = conn.execute(
                "SELECT report_ref FROM scan_reports WHERE tenant_id = ?", (self.tenant,)
            ).fetchone()["report_ref"]
        self.assertEqual(first, again)
        self.assertEqual(
            len(nested_files(os.path.join(os.environ["DSPM_ARTIFACT_DIR"], self.tenant))), 1,
            "an identical body was stored twice",
        )

    def test_the_inline_path_still_works_when_the_artifact_tier_is_off(self):
        """`DSPM_REPORT_ARTIFACTS=0` is the pre-Phase-5 behaviour and stays."""

        report = _report("s1", 30)
        with mock.patch.dict(os.environ, {"DSPM_REPORT_ARTIFACTS": "0"}):
            store.save_scan_history(self.tenant, report)
            with store._connect() as conn:
                row = conn.execute(
                    "SELECT report_ref, report_json FROM scan_reports WHERE tenant_id = ?",
                    (self.tenant,),
                ).fetchone()
            self.assertEqual(str(row["report_ref"] or ""), "")
            self.assertEqual(str(row["report_json"]), json.dumps(report, ensure_ascii=False))
            self.assertEqual(store.read_scan_report(self.tenant, "s1"), report)


if __name__ == "__main__":
    unittest.main()
