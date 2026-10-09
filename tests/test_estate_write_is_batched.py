"""The estate write must not scale its statement count with the file count.

Before this, `save_scan_history` issued about nine statements per file: an
upsert per asset, one per asset version, an `UPDATE ... WHERE asset_id = ?` per
asset to retire its old findings, a SELECT and an upsert per finding, one insert
per occurrence, and one per finding-index row. Nine million round trips on the
million-file scan this product is meant to survive.

These tests measure the statement count rather than the wall clock, because the
clock is dominated by whichever machine happens to run the suite while the
count is a property of the code.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
import uuid

from backend import store


def _report(scan_id: str, files: int, *, findings_per_file: int = 2, prefix: str = "b",
            scan_label: str = "batched") -> dict:
    """A report shaped like the discovery engine's output.

    The explicit `finding_id` matters: without one `_write_finding_index` skips
    every row, and the sixth of the six loops is never exercised at all.
    """

    rows = []
    for index in range(files):
        findings = [
            {
                "type": ("credit_card", "email", "password")[which % 3],
                "finding_id": f"{prefix}-f{index}-{which}",
                "risk": "HIGH",
                "count": 1 + which,
                "occurrence_count": 1 + which,
                "description": "d",
                "samples": ["x"],
                "category": "pii",
                "framework": "gdpr",
            }
            for which in range(findings_per_file)
        ]
        rows.append({
            "path": f"//fs01/share/dir{index % 50}/{prefix}{index}.txt",
            "name": f"{prefix}{index}.txt",
            "extension": ".txt",
            "size": 1000 + index,
            "source": "smb",
            "share": "share",
            "owner": "CORP/svc",
            "content_status": "scanned",
            "sha256": f"{index:064x}",
            "modified_at": "2026-01-01T00:00:00Z",
            "risk": {
                "level": ("HIGH", "MEDIUM", "LOW", "CRITICAL")[index % 4],
                "score": 40 + index % 50,
                "reasons": ["r"],
                "dlp_recommendations": ["a"],
            },
            "findings": findings,
        })
    return {
        "scan_id": scan_id,
        "timestamp": "2026-09-11T00:00:00Z",
        "source": "smb",
        "scan_label": scan_label,
        "summary": {
            "total_files": files, "critical": 0, "high": files,
            "medium": 0, "low": 0, "sensitive_files": files,
        },
        "files": rows,
    }


class _CountingConn:
    """Wraps a connection and counts what is asked of the database."""

    def __init__(self, inner, counts):
        self._inner = inner
        self._counts = counts

    def execute(self, sql, params=()):
        self._counts["execute"] += 1
        return self._inner.execute(sql, params)

    def executemany(self, sql, seq):
        seq = list(seq)
        self._counts["executemany"] += 1
        self._counts["rows"] += len(seq)
        self._counts["batch_sizes"].append(len(seq))
        return self._inner.executemany(sql, seq)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class EstateWriteBatchingTest(unittest.TestCase):
    """Every test gets its own database; none of them touch the live one."""

    def setUp(self):
        self._previous = os.environ.get("DSPM_DB_PATH")
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_DB_PATH"] = os.path.join(self._dir.name, "batched.sqlite")
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.init_db()
        store.create_tenant(self.tenant, self.tenant)

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("DSPM_DB_PATH", None)
        else:
            os.environ["DSPM_DB_PATH"] = self._previous
        self._dir.cleanup()

    @contextlib.contextmanager
    def _counting(self):
        counts = {"execute": 0, "executemany": 0, "rows": 0, "batch_sizes": []}
        original = store.db.connect

        @contextlib.contextmanager
        def _wrapped(path):
            with original(path) as conn:
                yield _CountingConn(conn, counts)

        store.db.connect = _wrapped
        try:
            yield counts
        finally:
            store.db.connect = original

    def _fingerprint(self, tables=("assets", "findings", "asset_versions",
                                   "finding_occurrences", "finding_index")):
        """A content hash per table, order-independent."""

        out = {}
        with store._connect() as conn:
            for table in tables:
                rows = conn.execute(
                    f"SELECT * FROM {table} WHERE tenant_id = ?", (self.tenant,)
                ).fetchall()
                serialised = sorted(
                    json.dumps([str(value) for value in tuple(row)]) for row in rows
                )
                out[table] = (len(rows), hashlib.sha256("\n".join(serialised).encode()).hexdigest())
        return out

    def test_statement_count_barely_moves_as_the_scan_grows(self):
        """Eight times the files must not mean eight times the statements."""

        measured = {}
        for files in (125, 250, 500, 1000):
            self.tenant = f"t{uuid.uuid4().hex[:8]}"
            store.create_tenant(self.tenant, self.tenant)
            with self._counting() as counts:
                store.save_scan_history(self.tenant, _report(f"s{files}", files))
            measured[files] = counts["execute"]

        # The only statement count that still grows is the chunked `IN (...)`
        # retirement, at one statement per 900 assets. Everything else is fixed.
        growth = measured[1000] - measured[125]
        self.assertLess(
            growth, 12,
            f"statement count grew by {growth} over 875 extra files: {measured}",
        )
        # And the absolute number stays far below the per-file regime, which
        # would have been ~9,000 statements for the largest scan here.
        self.assertLess(measured[1000], 60, measured)

    def test_rows_are_written_in_bounded_batches(self):
        """A scan larger than one batch must flush more than once.

        The flush inside `_executemany` only runs when a batch fills, so this
        deliberately writes more rows than `_WRITE_BATCH` holds.
        """

        files = store._WRITE_BATCH + 50
        with self._counting() as counts:
            store.save_scan_history(self.tenant, _report("big", files, findings_per_file=1))

        self.assertGreater(
            max(counts["batch_sizes"]), 0, "no batched write happened at all"
        )
        self.assertLessEqual(
            max(counts["batch_sizes"]), store._WRITE_BATCH,
            f"a batch exceeded the cap: {max(counts['batch_sizes'])}",
        )
        self.assertGreaterEqual(
            len([size for size in counts["batch_sizes"] if size == store._WRITE_BATCH]), 1,
            "no batch filled, so the flush path never ran",
        )

        with store._connect() as conn:
            assets = conn.execute(
                "SELECT COUNT(*) AS n FROM assets WHERE tenant_id = ?", (self.tenant,)
            ).fetchone()["n"]
            findings = conn.execute(
                "SELECT COUNT(*) AS n FROM findings WHERE tenant_id = ?", (self.tenant,)
            ).fetchone()["n"]
        self.assertEqual(assets, files, "a row was lost across the batch boundary")
        self.assertEqual(findings, files, "a finding was lost across the batch boundary")

    def test_id_chunking_stays_inside_the_bind_parameter_limit(self):
        """`IN (...)` must never be built wider than a statement can carry.

        SQLite is compiled here with a limit of 32,766 and PostgreSQL documents
        65,535, but older SQLite builds ship 999 and this product is installed
        on machines we do not choose.
        """

        self.assertLessEqual(store._ID_CHUNK, 999)
        chunks = list(store._id_chunks(f"id-{index}" for index in range(2500)))
        self.assertEqual(sum(len(chunk) for chunk in chunks), 2500)
        self.assertTrue(all(len(chunk) <= store._ID_CHUNK for chunk in chunks))
        # Blank ids are dropped and repeats collapse, because the caller passes
        # a path->id mapping that may contain either.
        self.assertEqual(list(store._id_chunks(["a", "", "a", None, "b"])), [["a", "b"]])

    def test_a_rescan_writes_the_same_rows_as_the_first(self):
        """Batching must not have made the write non-idempotent."""

        store.save_scan_history(self.tenant, _report("s1", 200))
        before = self._fingerprint()
        store.save_scan_history(self.tenant, _report("s1", 200))
        self.assertEqual(before, self._fingerprint())

    def test_retirement_is_scoped_to_the_assets_this_scan_saw(self):
        """The chunked `UPDATE ... IN (...)` must retire what the loop did.

        Retiring an asset's findings was one statement per asset - the single
        largest saving in the change - so it is worth pinning that the set
        operation still touches exactly the same rows.

        These reports carry no scan label on purpose. A *named* complete scan is
        an authoritative inventory scope and prunes assets it did not see, which
        would retire findings for a different reason entirely and hide whether
        the per-asset retirement still works.
        """

        store.save_scan_history(self.tenant, _report("s1", 40, scan_label=""))
        with store._connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM findings WHERE tenant_id = ? AND is_current = 1",
                    (self.tenant,),
                ).fetchone()["n"],
                80,
            )

        # A second scan revisits the first 20 files and finds nothing in them.
        empty = _report("s2", 20, scan_label="")
        for file_obj in empty["files"]:
            file_obj["findings"] = []
        store.save_scan_history(self.tenant, empty)

        with store._connect() as conn:
            rows = conn.execute(
                "SELECT id, is_current FROM findings WHERE tenant_id = ?", (self.tenant,)
            ).fetchall()
        retired = {str(row["id"]) for row in rows if not row["is_current"]}
        current = {str(row["id"]) for row in rows if row["is_current"]}

        self.assertEqual(
            retired, {f"b-f{index}-{which}" for index in range(20) for which in range(2)},
            "retirement did not cover exactly the re-scanned assets",
        )
        self.assertEqual(
            current, {f"b-f{index}-{which}" for index in range(20, 40) for which in range(2)},
            "retirement reached assets this scan never saw",
        )

    def test_a_finding_still_present_is_re_asserted_after_retirement(self):
        """Retire-then-re-assert has to end with the finding current.

        Every finding row is written twice per scan: once set historical by the
        retirement above, once re-asserted by the upsert. If the batching had
        reordered those two, every finding in the product would read as history.
        """

        store.save_scan_history(self.tenant, _report("s1", 30, scan_label=""))
        store.save_scan_history(self.tenant, _report("s2", 30, scan_label=""))
        with store._connect() as conn:
            counts = conn.execute(
                "SELECT is_current, COUNT(*) AS n FROM findings WHERE tenant_id = ? "
                "GROUP BY is_current", (self.tenant,),
            ).fetchall()
        self.assertEqual({int(row["is_current"]): row["n"] for row in counts}, {1: 60})


class FindingLifecycleSnapshotTest(unittest.TestCase):
    """What a repeated finding id inherits, now that the read happens once.

    The lifecycle read used to sit inside the write loop, so a finding id that
    appeared twice in one report had its second occurrence read back the row the
    first had just written. The read is now a single snapshot taken before any
    write, so both occurrences see the same prior state - and since a scan takes
    the row's lifecycle rather than the report's, order stopped mattering at all.
    """

    def setUp(self):
        self._previous = os.environ.get("DSPM_DB_PATH")
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_DB_PATH"] = os.path.join(self._dir.name, "lifecycle.sqlite")
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.init_db()
        store.create_tenant(self.tenant, self.tenant)

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("DSPM_DB_PATH", None)
        else:
            os.environ["DSPM_DB_PATH"] = self._previous
        self._dir.cleanup()

    def _save(self, scan_id, findings):
        store.save_scan_history(self.tenant, {
            "scan_id": scan_id,
            "timestamp": "2026-09-11T00:00:00Z",
            "source": "smb",
            "scan_label": "lifecycle",
            "summary": {"total_files": 1, "critical": 0, "high": 1,
                        "medium": 0, "low": 0, "sensitive_files": 1},
            "files": [{
                "path": "//fs01/share/dupe.txt", "name": "dupe.txt", "extension": ".txt",
                "size": 10, "source": "smb", "share": "share", "owner": "o",
                "content_status": "scanned",
                "risk": {"level": "HIGH", "score": 70, "reasons": ["r"],
                         "dlp_recommendations": []},
                "findings": findings,
            }],
        })

    def _row(self):
        with store._connect() as conn:
            return conn.execute(
                "SELECT status, owner FROM findings WHERE tenant_id = ? AND id = ?",
                (self.tenant, "dupe-1"),
            ).fetchone()

    def test_the_first_sighting_takes_the_reports_values(self):
        """There is no row to preserve yet, so the report is all there is."""

        self._save("s1", [{"type": "credit_card", "finding_id": "dupe-1", "risk": "HIGH",
                           "count": 1, "status": "CONFIRMED", "owner": "analyst@example.com",
                           "description": "d", "samples": ["x"]}])
        row = self._row()
        self.assertEqual(row["status"], "CONFIRMED")
        self.assertEqual(row["owner"], "analyst@example.com")

    def test_neither_occurrence_of_a_repeated_id_can_reset_the_row(self):
        """Order stopped mattering once the row owns the lifecycle.

        Both occurrences see the same pre-scan snapshot, and a scan takes the
        row's state over the report's, so it makes no difference which of them
        is written last or what either of them claims.
        """

        self._save("s1", [{"type": "credit_card", "finding_id": "dupe-1", "risk": "HIGH",
                           "count": 1, "status": "CONFIRMED", "owner": "analyst@example.com",
                           "description": "d", "samples": ["x"]}])
        self._save("s2", [
            {"type": "credit_card", "finding_id": "dupe-1", "risk": "HIGH", "count": 1,
             "status": "RESOLVED", "owner": "second@example.com",
             "description": "first occurrence", "samples": ["x"]},
            {"type": "credit_card", "finding_id": "dupe-1", "risk": "MEDIUM", "count": 9,
             "description": "second occurrence", "samples": ["y"]},
        ])
        row = self._row()
        self.assertEqual(row["status"], "CONFIRMED")
        self.assertEqual(row["owner"], "analyst@example.com")


class BindParameterLimitTest(unittest.TestCase):
    """`_ID_CHUNK` has to hold on the SQLite this machine actually runs."""

    def test_a_full_chunk_binds(self):
        with sqlite3.connect(":memory:") as conn:
            conn.execute("CREATE TABLE t (id TEXT)")
            placeholders = ",".join("?" for _ in range(store._ID_CHUNK))
            conn.execute(
                f"SELECT id FROM t WHERE id IN ({placeholders})",
                tuple(str(index) for index in range(store._ID_CHUNK)),
            ).fetchall()


if __name__ == "__main__":
    unittest.main()
