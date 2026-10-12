"""W4.1 step 2: the baseline keeps the fingerprint and digest; the snapshot is read from assets.

``scan_object_baselines.snapshot_json`` held the record ``assets.detail_json`` holds, byte for
byte: 2.5 KB of every file's 3 KB baseline row (amplification probe, 2026-10-08). The row
now keeps the size, modified time, hash, signature and the record's digest, marked as a
reference (``ref:``); the probe reads the record from the asset and replays it only when
its digest is the one the baseline wrote. Anything else - the asset gone, or holding what
another scope's scan wrote under other rules - is a read, never a replay of the wrong record.

Two scopes that cover the same files under different rules each write the asset in turn.
A scope that finds its reference holding the other's record keeps its own copy from then
on (``baseline_inline`` on the record), so the two do not re-read each other's files on
every scan. The durable baseline is what answers when the node's reuse cache (L1) is
absent - a new worker, an evicted cache - so these tests turn L1 off.
"""
from __future__ import annotations

import json
import os
import unittest

from backend import db, store
from discovery.parity import semantic
from tests.test_partitioned_local_scan import TENANT, _LocalTest


def _incremental(compact: dict) -> dict:
    return (compact.get("scan_diagnostics") or {}).get("incremental") or {}


class _DurableOnly(_LocalTest):

    def setUp(self) -> None:
        super().setUp()
        # W4.2: an unchanged unit is now skipped whole; this proves the path a unit that is
        # read takes - per-file reuse - so every unit here is read (the skip has its own
        # parity tests, test_w42_*).
        os.environ["DSPM_UNCHANGED_UNIT_SKIP"] = "0"
    def _scan(self, scope: str, frameworks: list[str], folder: str = "", label: str = "estate") -> dict:
        from backend import partitioned_scan

        config = super()._config(
            scope, persistent_cache_enabled=False, incremental_enabled=True, incremental_scope=scope,
            local_path=str(self.estate / folder) if folder else str(self.estate),
            baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                TENANT, scope, key, size, mtime, version))
        compact = partitioned_scan.run_partitioned_scan(TENANT, config, scan_label=label,
                                                        compliance_enabled=True, compliance_frameworks=frameworks,
                                                        max_files=3)
        self.assertIsNotNone(compact, "the estate was not partitioned")
        return compact

    def _baselines(self, scope: str) -> dict[str, tuple[str, str]]:
        with store._connect() as conn:
            return {str(row["object_key"]): (str(row["snapshot_json"] or ""), str(row["snapshot_digest"] or ""))
                    for row in conn.execute(
                        "SELECT object_key, snapshot_json, snapshot_digest FROM scan_object_baselines "
                        "WHERE tenant_id = ? AND scope_key = ?", (TENANT, scope)).fetchall()}

    def _records(self, *, as_stored: bool = False) -> dict[str, str]:
        """asset id -> a digest of what the record its row holds says, less what differs
        between two runs of one scan (a re-read finding's first and last seen, its due date).
        ``as_stored``: the digest the probe compares, which a re-read changes."""
        with store._connect() as conn:
            rows = conn.execute("SELECT id, detail_json FROM assets WHERE tenant_id = ?", (TENANT,)).fetchall()
        project = (lambda record: record) if as_stored else semantic
        return {str(row["id"]): store._material_digest(project(json.loads(store.unpack_json_text(row["detail_json"]))))
                for row in rows}

    def _findings(self) -> set[tuple]:
        """The current findings - what a rule set found, less what another one found before."""
        with store._connect() as conn:
            return {tuple(row) for row in conn.execute(
                "SELECT id, rule, severity, category, frameworks_json FROM findings "
                "WHERE tenant_id = ? AND is_current = 1", (TENANT,)).fetchall()}


class TheBaselineHoldsNoSecondCopyTest(_DurableOnly):

    def test_the_snapshot_is_read_from_the_asset_and_replays_the_same_record(self) -> None:
        self._use_database("by-reference")
        first = self._scan("scope-a", ["gdpr"])
        total = int(_incremental(first).get("total_objects") or 0)
        self.assertGreater(total, 0)
        baselines = self._baselines("scope-a")
        self.assertEqual(len(baselines), total)
        self.assertEqual({text for text, _ in baselines.values()}, {""}, "a baseline row still holds the record")
        self.assertTrue(all(digest.startswith(store.BASELINE_BY_REFERENCE) for _, digest in baselines.values()))
        records, findings = self._records(), self._findings()

        again = _incremental(self._scan("scope-a", ["gdpr"]))
        self.assertEqual((again.get("content_reads"), again.get("durable_baseline_hits")), (0, total),
                         "an unchanged file was read again: its reference did not answer")
        self.assertEqual(self._records(), records, "a replay from the asset is not the record the scan wrote")
        self.assertEqual(self._findings(), findings)
        self.assertEqual(self._baselines("scope-a"), baselines, "an unchanged rescan rewrote its baseline")

    def test_a_gone_asset_is_read_again_not_replayed(self) -> None:
        self._use_database("gone")
        total = int(_incremental(self._scan("scope-a", ["gdpr"])).get("total_objects") or 0)
        with store._connect() as conn:
            conn.execute("DELETE FROM asset_access WHERE tenant_id = ?", (TENANT,))
            conn.execute("DELETE FROM assets WHERE tenant_id = ?", (TENANT,))
        again = _incremental(self._scan("scope-a", ["gdpr"]))
        self.assertEqual((again.get("content_reads"), again.get("durable_baseline_hits")), (total, 0))
        self.assertEqual(len(self._records()), total)


class ATriagedFileStillReplaysTest(_DurableOnly):
    """A save writes each finding's lifecycle from its row into the record - after the
    asset row was written from it. The reference has to hold through that: a changed file
    whose findings already had rows, and findings an analyst acted on, still replay."""

    def test_a_changed_then_triaged_file_is_not_read_again(self) -> None:
        self._use_database("triaged")
        self._scan("scope-a", ["gdpr"])
        path = self.estate / "b_dept" / "b1.txt"
        path.write_text(path.read_text(encoding="utf-8") + "\nand maria.lopez@example.com too\n", encoding="utf-8")
        changed = _incremental(self._scan("scope-a", ["gdpr"]))
        self.assertEqual(changed.get("content_reads"), 1)
        with store._connect() as conn:
            ids = [str(row["id"]) for row in conn.execute(
                "SELECT id FROM findings WHERE tenant_id = ? AND is_current = 1 AND file_path LIKE ? ORDER BY id",
                (TENANT, "%b1.txt")).fetchall()]
        self.assertGreaterEqual(len(ids), 2)
        store.update_finding_lifecycle(TENANT, ids[0], "assign", {"owner": "hr-team"}, "analyst")
        store.update_finding_lifecycle(TENANT, ids[1], "status", {"status": "CONFIRMED"}, "analyst")
        total = int(changed.get("total_objects") or 0)
        for step in ("after the actions", "again"):
            counts = _incremental(self._scan("scope-a", ["gdpr"]))
            self.assertEqual((counts.get("content_reads"), counts.get("durable_baseline_hits")), (0, total), step)
            self.assertEqual({text for text, _ in self._baselines("scope-a").values()}, {""}, step)
        self.assertEqual((self._row(ids[0])["owner"], self._row(ids[1])["status"]), ("hr-team", "CONFIRMED"))

    def _row(self, finding_id: str) -> dict:
        with store._connect() as conn:
            return dict(conn.execute("SELECT * FROM findings WHERE tenant_id = ? AND id = ?",
                                     (TENANT, finding_id)).fetchone())


class AnUpgradedInstallConvertsOnItsNextScanTest(_DurableOnly):
    """Before W4.1 each baseline row held its record and a digest of all of it. The first
    scan after the upgrade replays those rows as they are and writes each once more, as a
    reference (the digest no longer covers what a save fills in from the rows); nothing is
    read again, and the scan after writes nothing."""

    def test_rows_written_by_the_older_build_replay_then_become_references(self) -> None:
        self._use_database("upgraded")
        total = int(_incremental(self._scan("scope-a", ["gdpr"])).get("total_objects") or 0)
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT b.object_key, b.asset_id, b.size, b.mtime, b.content_hash, b.version_signature, "
                "a.detail_json FROM scan_object_baselines b JOIN assets a "
                "ON a.tenant_id = b.tenant_id AND a.id = b.asset_id WHERE b.tenant_id = ?", (TENANT,)).fetchall()
            self.assertEqual(len(rows), total)
            for row in rows:
                record = json.loads(store.unpack_json_text(row["detail_json"]))
                old_digest = store._material_digest(record, str(row["asset_id"]), int(row["size"]), str(row["mtime"]),
                                                    str(row["content_hash"]), str(row["version_signature"]))
                conn.execute("UPDATE scan_object_baselines SET snapshot_json = ?, snapshot_digest = ? "
                             "WHERE tenant_id = ? AND scope_key = 'scope-a' AND object_key = ?",
                             (row["detail_json"], old_digest, TENANT, row["object_key"]))
        self.assertEqual(sum(1 for text, _ in self._baselines("scope-a").values() if text), total)
        first = _incremental(self._scan("scope-a", ["gdpr"]))
        self.assertEqual((first.get("content_reads"), first.get("durable_baseline_hits")), (0, total))
        converted = self._baselines("scope-a")
        self.assertEqual({text for text, _ in converted.values()}, {""})
        again = _incremental(self._scan("scope-a", ["gdpr"]))
        self.assertEqual((again.get("content_reads"), again.get("durable_baseline_hits")), (0, total))
        self.assertEqual(self._baselines("scope-a"), converted)

class ScopesThatShareFilesKeepTheirOwnAnswersTest(_DurableOnly):
    """Scope A covers the estate under one rule set; scope B one of its folders under
    another. Each writes the folder's asset rows with its own records in turn."""

    _B = ("scope-b", ["gdpr", "pci_dss", "hipaa"], "b_dept", "dept")

    def test_two_rule_sets_over_one_folder_never_replay_each_other(self) -> None:
        self._use_database("shared")
        a_first = self._scan("scope-a", ["gdpr"])
        a_records, a_findings, a_stored = self._records(), self._findings(), self._records(as_stored=True)
        b_first = self._scan(*self._B)
        b_records, b_findings, b_stored = self._records(), self._findings(), self._records(as_stored=True)
        total, shared = (int(_incremental(compact).get("total_objects") or 0) for compact in (a_first, b_first))
        # The folder's asset rows now hold B's records (another rule set's stamps, at least).
        rewritten = {key for key in a_stored if a_stored[key] != b_stored.get(key)}
        self.assertEqual(len(rewritten), shared)
        self.assertLess(shared, total)
        self.assertNotEqual(b_records, a_records)

        # A's references into the folder hold B's records: A reads those files again rather
        # than replaying B's findings as its own - and from then on keeps its own copy.
        a_again = _incremental(self._scan("scope-a", ["gdpr"]))
        self.assertEqual((a_again.get("content_reads"), a_again.get("durable_baseline_hits")),
                         (shared, total - shared))
        self.assertEqual(self._records(), a_records)
        self.assertEqual(self._findings(), a_findings)
        b_again = _incremental(self._scan(*self._B))
        self.assertEqual((b_again.get("content_reads"), b_again.get("durable_baseline_hits")), (shared, 0))
        self.assertEqual(self._records(), b_records)
        self.assertEqual(self._findings(), b_findings)

        # Each holds its own copy of the folder's files: neither reads them again.
        for args, files, findings in ((("scope-a", ["gdpr"]), total, a_findings), (self._B, shared, b_findings)):
            counts = _incremental(self._scan(*args))
            self.assertEqual((counts.get("content_reads"), counts.get("durable_baseline_hits")), (0, files), args[0])
            self.assertEqual(self._findings(), findings, args[0])
            inline = [key for key, (text, _) in self._baselines(args[0]).items() if text]
            self.assertEqual(len(inline), shared, f"{args[0]}: only the shared files keep a copy")


class AScanOutsideTheEstateKeepsItsSnapshotTest(unittest.TestCase):
    """The demo dataset's records get no asset rows, so its baseline keeps the snapshot."""

    def test_a_demo_scan_writes_its_snapshot_inline_and_replays_it(self) -> None:
        import tempfile
        from pathlib import Path

        if not db.is_postgres():
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "demo.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
        store.init_db()
        tenant = "w41-demo-baseline"
        store.create_tenant(tenant, "demo")
        path = "enterprise_test_data/finance/payroll.txt"
        record = {"name": "payroll.txt", "path": path, "size": 10, "modified_at": "2026-10-01T00:00:00Z",
                  "content_hash": "c" * 64, "findings": []}
        store.save_scan_history(tenant, {
            "scan_id": "demo-b1", "source": "local", "timestamp": "2026-10-08T00:00:00Z",
            "summary": {"total_files": 1}, "files": [record],
            "scan_diagnostics": {"incremental": {"enabled": True, "baseline_update": True, "scope_key": "demo",
                                                 "version_signature": "v1", "complete": True}},
        })
        with store._connect() as conn:
            self.assertEqual(int(conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id = ?",
                                              (tenant,)).fetchone()[0]), 0)
            row = conn.execute("SELECT snapshot_json, snapshot_digest FROM scan_object_baselines "
                               "WHERE tenant_id = ? AND scope_key = 'demo'", (tenant,)).fetchone()
        self.assertNotEqual(str(row["snapshot_json"] or ""), "")
        self.assertFalse(str(row["snapshot_digest"]).startswith(store.BASELINE_BY_REFERENCE))
        probe = store.probe_incremental_object(tenant, "demo", path, 10, "2026-10-01T00:00:00Z", "v1")
        self.assertEqual(probe["state"], "unchanged")
        self.assertEqual(probe["snapshot"]["content_hash"], "c" * 64)


class AnArchiveMemberWithNothingToReplayTest(unittest.TestCase):
    """An archive replays as a bundle - itself and every member. A member whose reference has
    nothing to replay (its asset gone) makes the bundle a read, not a bundle short of that
    member's findings."""

    def test_a_member_whose_asset_is_gone_makes_the_archive_a_read(self) -> None:
        import tempfile
        from pathlib import Path

        if not db.is_postgres():
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "archive.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
        store.init_db()
        tenant = "w41-archive"
        store.create_tenant(tenant, "archive")
        stamp = "2026-10-01T00:00:00Z"
        outer = {"name": "evidence.zip", "path": "//fs01/hr/evidence.zip", "extension": ".zip", "size": 20,
                 "modified_at": stamp, "content_hash": "a" * 64, "findings": []}
        member = {"name": "inside.txt", "path": "//fs01/hr/evidence.zip::inside.txt", "extension": ".txt", "size": 10,
                  "modified_at": stamp, "content_hash": "b" * 64,
                  "findings": [{"finding_id": "m1", "type": "email", "risk": "HIGH", "count": 1}]}
        store.save_scan_history(tenant, {
            "scan_id": "arc-1", "source": "smb", "scan_label": "hr", "timestamp": stamp,
            "summary": {"total_files": 2}, "files": [outer, member],
            "scan_diagnostics": {"incremental": {"enabled": True, "baseline_update": True, "scope_key": "hr",
                                                 "version_signature": "v1", "complete": True}},
        })

        def probe() -> dict:
            return store.probe_incremental_object(tenant, "hr", outer["path"], 20, stamp, "v1")

        whole = probe()
        self.assertEqual(whole["state"], "unchanged")
        self.assertEqual([item["path"] for item in whole["snapshot"]["archive_records"]], [member["path"]])
        with store._connect() as conn:
            conn.execute("DELETE FROM asset_access WHERE tenant_id = ? AND asset_id IN "
                         "(SELECT id FROM assets WHERE tenant_id = ? AND path = ?)", (tenant, tenant, member["path"]))
            conn.execute("DELETE FROM assets WHERE tenant_id = ? AND path = ?", (tenant, member["path"]))
        self.assertEqual(probe()["state"], "changed")


if __name__ == "__main__":
    unittest.main()
