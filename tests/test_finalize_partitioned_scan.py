"""B2.2b-2: a partitioned scan finalizes into exactly what one save writes.

Partitions write their own rows as they finish (B2.2b-1). Finalize writes what
needs the whole scan: the scan run, the prunes, finding-index retention, the report
body and the report row. The gate is strict because a partitioned scan is only an
implementation detail if nobody can tell: the same records, written as partitions
and finalized, must leave the same rows and the same stored report - the same body
bytes, not an equivalent one - as ``save_scan_history`` of the whole report.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from backend import artifacts, db, partitioned_scan, store
from backend.compliance_service import (
    ComplianceReportAccumulator,
    enrich_report_with_compliance,
    load_compliance_profiles,
)
from discovery.discovery_engine import DSPMDiscoveryEngine

SCAN = "scan-b"
PRIOR = "scan-a"
LABEL = "finance-share"
_TABLES = ("assets", "asset_versions", "findings", "finding_occurrences", "finding_index", "scan_object_baselines")
_VOLATILE = {"scan_object_baselines": {"last_seen_at", "updated_at"}, "findings": {"seq"}, "finding_index": {"seq"}}
ALL_FRAMEWORKS = [profile["id"] for profile in load_compliance_profiles()]


def _records(indices, *, variant: int = 0) -> list[dict]:
    """Analyzed records dense enough to fill every compliance section."""
    records = []
    for index in indices:
        kind = index % 4
        findings = [
            {"type": "email", "finding_id": f"g-{index}", "risk": ("LOW", "MEDIUM", "HIGH")[(index + variant) % 3],
             "count": 1 + index % 3, "occurrence_count": 1 + index % 3, "samples": [f"user{index}@example.com"],
             "category": "pii", "framework": "generic", "description": "email address"},
        ]
        if kind == 0:
            findings.append({
                "type": "pci_pan", "finding_id": f"p-{index}", "framework": "pci_dss", "category": "pci_chd",
                "pci_category": ("CHD", "SAD")[index % 2], "risk": "CRITICAL", "count": 2,
                "samples": ["card 4111111111111111 on file"], "storage_state": "stored",
                "exception_required": index % 3 == 0, "description": "PAN 4111111111111111",
            })
        elif kind == 1:
            findings.append({
                "type": "gdpr_email", "finding_id": f"d-{index}", "framework": "gdpr", "category": "pii",
                "personal_data_type": "email", "risk": "HIGH", "count": 12, "retention_expired": index % 2 == 0,
                "special_category": index % 5 == 0, "data_subject_type": "customer", "samples": ["x"],
            })
        elif kind == 2:
            findings.append({
                "type": "nist_rule", "finding_id": f"n-{index}", "framework": "nist_sp800_60_enterprise",
                "rule_id": f"nist_rule_{index % 4}", "category_id": "C.2.8", "handling_tier": "RESTRICTED",
                "needs_review": index % 2 == 1, "final_risk_score": 20 + index % 30, "risk": "MEDIUM", "samples": ["y"],
            })
        records.append({
            "path": f"//fs01/finance/dept{index % 6}/file{index}.txt",
            "name": f"file{index}.txt",
            "extension": ".txt",
            "size": 2000 + index,
            "source": "smb",
            "share": "finance",
            "owner": ("CORP/alice", "CORP/bob")[index % 2],
            "content_status": "scanned",
            "sha256": f"{index + variant:064x}",
            "content_hash": f"{index + variant:064x}",
            "modified_at": f"2026-0{1 + variant}-01T00:00:00Z",
            "reuse_key": f"smb://fs01/finance/dept{index % 6}/file{index}.txt",
            "permissions": {"public": index % 7 == 0, "wide_access": index % 3 == 0},
            "is_hidden": index % 11 == 0,
            "risk": {"level": ("HIGH", "LOW", "MEDIUM", "CRITICAL", "NONE")[(index + variant) % 5],
                     "score": 30 + (index * 7) % 60, "reasons": ["r"], "dlp_recommendations": ["a"]},
            "findings": findings if kind != 3 else [],
            "canonical_entities": [{"entity_id": f"e-{index}", "framework_mappings": ["gdpr"]}],
        })
    return records


def _diagnostics(count: int, *, complete: bool = True) -> dict:
    return {
        "mode": "remote",
        "records": count,
        "incremental": {
            "enabled": True, "baseline_update": True, "mode": "full", "scope_key": "scope-finance",
            "version_signature": "v1", "complete": complete, "total_objects": count, "unchanged_objects": 0,
            "new_objects": count, "changed_objects": 0, "unclassified_fresh_objects": 0, "content_reads": count,
            "delta_ratio": 1.0 if count else 0.0, "sidecar_hits": 0, "durable_baseline_hits": 0,
            "probe_errors": 0, "baseline_committed": False, "deleted_objects": 0,
        },
        "triage": {"records_full": count, "records_skipped_non_text": 0, "records_sampled": 0},
    }


def _copy(value):
    return json.loads(json.dumps(value))


class _FinalizeTest(unittest.TestCase):
    TIMESTAMP = "2026-09-14T08:00:00Z"

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._db_path = Path(self._dir.name) / "finalize.sqlite"
        self._previous_path = store.DB_PATH
        store.DB_PATH = self._db_path
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "finalize")

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def _snapshot(self) -> Path:
        target = Path(self._dir.name) / f"snapshot-{uuid.uuid4().hex[:6]}.sqlite"
        source = sqlite3.connect(str(self._db_path))
        copy = sqlite3.connect(str(target))
        source.backup(copy)
        source.close()
        copy.close()
        return target

    def _restore(self, snapshot: Path) -> None:
        source = sqlite3.connect(str(snapshot))
        live = sqlite3.connect(str(self._db_path))
        source.backup(live)
        source.close()
        live.close()
        store._forget_scan_report_rows(self.tenant)

    def _state(self) -> dict:
        state = {}
        with store._connect() as conn:
            for table in _TABLES:
                rows = conn.execute(f"SELECT * FROM {table} WHERE tenant_id = ?", (self.tenant,)).fetchall()
                skip = _VOLATILE.get(table, set())
                serialised = sorted(
                    json.dumps({k: str(row[k]) for k in row.keys() if k not in skip}, sort_keys=True) for row in rows
                )
                state[table] = (len(rows), hashlib.sha256("\n".join(serialised).encode()).hexdigest())
            run = conn.execute("SELECT * FROM scan_runs WHERE tenant_id = ? AND id = ?", (self.tenant, SCAN)).fetchone()
            state["scan_run"] = {k: run[k] for k in run.keys()} if run else None
            report = conn.execute(
                "SELECT timestamp, source, scan_label, summary_json, report_json, report_ref, report_bytes, compact_json "
                "FROM scan_reports WHERE tenant_id = ? AND scan_id = ?", (self.tenant, SCAN),
            ).fetchone()
            state["scan_report"] = (
                {k: (store.unpack_json_text(report[k]) if k == "compact_json" else report[k]) for k in report.keys()}
                if report else None
            )
            state["index_order"] = [str(r["finding_id"]) for r in conn.execute(
                "SELECT finding_id FROM finding_index WHERE tenant_id = ? AND scan_id = ? ORDER BY seq",
                (self.tenant, SCAN),
            ).fetchall()]
        state["body"] = json.dumps(store.read_scan_report(self.tenant, SCAN), ensure_ascii=False)
        return state

    # -- the two ways to write the same scan --------------------------------------------------------------------
    def _parts(self, records: list[dict], sizes) -> list[list[dict]]:
        parts, start = [], 0
        for size in sizes:
            parts.append(records[start:start + size])
            start += size
        self.assertEqual(start, len(records))
        return parts

    def _save_single(self, parts, *, enabled, frameworks, label=LABEL, complete=True) -> None:
        records = [record for part in parts for record in _copy(part)]
        units = [{"diagnostics": _diagnostics(len(part), complete=complete), "files": len(part)} for part in parts]
        report = {
            "timestamp": self.TIMESTAMP,
            "source": "smb",
            "mode": "full",
            "summary": DSPMDiscoveryEngine._build_summary(_copy(records)).to_dict(),
            "files": records,
            "scan_diagnostics": partitioned_scan.scan_diagnostics_for(units),
        }
        enrich_report_with_compliance(report, enabled, frameworks)
        if label:
            report["scan_label"] = label
        store.save_scan_history(self.tenant, {**report, "scan_id": SCAN})

    def _save_partitioned(self, parts, *, enabled, frameworks, label=LABEL, complete=True) -> dict:
        store.create_scan_partitions(self.tenant, SCAN, "job-b", [{"part": i} for i in range(len(parts))])
        for part in parts:
            records = _copy(part)
            summary = DSPMDiscoveryEngine._build_summary(_copy(records)).to_dict()
            sections = ComplianceReportAccumulator(enabled, frameworks)
            for record in records:
                sections.prepare(record)
            unit = store.claim_next_partition(self.tenant, SCAN)
            header = {"timestamp": self.TIMESTAMP, "source": "smb", "mode": "full", "summary": summary,
                      "scan_diagnostics": _diagnostics(len(part), complete=complete)}
            if label:
                header["scan_label"] = label
            store.persist_partition(self.tenant, SCAN, unit["partition_id"], unit["attempt"], header, records,
                                    write_estate=True)
        return partitioned_scan.finalize_scan(
            self.tenant, SCAN, timestamp=self.TIMESTAMP, source="smb", scan_label=label,
            compliance_enabled=enabled, compliance_frameworks=frameworks,
        )

    def _prior_scan(self) -> None:
        records = _records(range(0, 30))
        report = {"timestamp": "2026-09-01T00:00:00Z", "source": "smb", "mode": "full",
                  "summary": DSPMDiscoveryEngine._build_summary(_copy(records)).to_dict(),
                  "files": records, "scan_diagnostics": _diagnostics(len(records))}
        enrich_report_with_compliance(report, True, ALL_FRAMEWORKS)
        report["scan_label"] = LABEL
        store.save_scan_history(self.tenant, {**report, "scan_id": PRIOR})
        with store._connect() as conn:
            conn.execute(
                "UPDATE findings SET status = 'CONFIRMED', owner = 'analyst@corp' "
                "WHERE tenant_id = ? AND id IN ('g-12', 'p-16', 'd-13')", (self.tenant,),
            )


@unittest.skipIf(db.is_postgres(), "restores a SQLite snapshot between the two runs it compares")
class FinalizeWritesWhatOneSaveWritesTest(_FinalizeTest):

    def _assert_parity(self, *, enabled: bool, frameworks, sizes=(9, 14, 7, 10), label=LABEL, complete=True):
        self._prior_scan()
        prior = self._snapshot()
        # Drops the prior scan's first ten files, keeps and changes the rest, adds new ones.
        parts = self._parts(_records(range(10, 50), variant=1), sizes)

        self._save_single(parts, enabled=enabled, frameworks=frameworks, label=label, complete=complete)
        single = self._state()
        single_rows = store.scan_report_inventory_rows_by_label(self.tenant, label) if label else None

        self._restore(prior)
        compact = self._save_partitioned(parts, enabled=enabled, frameworks=frameworks, label=label, complete=complete)
        partitioned = self._state()

        for key in single:
            self.assertEqual(partitioned[key], single[key], f"{key} differs between one save and partitions")
        self.assertTrue(single["scan_report"]["report_ref"], "the parity check needs the artifact tier on")
        self.assertEqual(compact["file_count"], 40)
        self.assertEqual(compact["scan_id"], SCAN)
        if label:
            store._forget_scan_report_rows(self.tenant)
            self.assertEqual(store.scan_report_inventory_rows_by_label(self.tenant, label), single_rows,
                             "the inventory projection of a partitioned scan differs")
        return single

    def test_with_every_framework_selected(self) -> None:
        single = self._assert_parity(enabled=True, frameworks=ALL_FRAMEWORKS)
        body = json.loads(single["body"])
        for key in ("compliance_summary", "pci_scope_summary", "gdpr_report", "nist_sp800_60_enterprise_report"):
            self.assertIn(key, body)
        self.assertGreater(body["compliance_summary"]["affected_file_count"], 0)
        incremental = body["scan_diagnostics"]["incremental"]
        self.assertEqual(incremental["deleted_objects"], 10, "the baseline prune never ran")
        self.assertFalse(incremental["prune_skipped"])

    def test_with_compliance_off(self) -> None:
        body = json.loads(self._assert_parity(enabled=False, frameworks=[])["body"])
        self.assertFalse(body["compliance_summary"]["enabled"])

    def test_an_incomplete_unnamed_scan_prunes_nothing_either_way(self) -> None:
        body = json.loads(self._assert_parity(enabled=True, frameworks=["gdpr"], label="", complete=False)["body"])
        self.assertTrue(body["scan_diagnostics"]["incremental"]["prune_skipped"])

    def test_one_partition_and_many_small_ones_agree(self) -> None:
        self._assert_parity(enabled=True, frameworks=["pci_dss", "gdpr"], sizes=(40,))

    def test_the_prior_scans_unseen_assets_leave_and_triage_stays(self) -> None:
        self._prior_scan()
        parts = self._parts(_records(range(10, 50), variant=1), (20, 20))
        self._save_partitioned(parts, enabled=True, frameworks=ALL_FRAMEWORKS)
        with store._connect() as conn:
            unseen = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE tenant_id = ? AND path LIKE '%/file3.txt'", (self.tenant,),
            ).fetchone()[0]
            kept = conn.execute(
                "SELECT status, owner FROM findings WHERE tenant_id = ? AND id = 'g-12'", (self.tenant,),
            ).fetchone()
        self.assertEqual(unseen, 0)
        self.assertEqual((kept["status"], kept["owner"]), ("CONFIRMED", "analyst@corp"))


class FinalizeIsSafeTest(_FinalizeTest):

    def test_it_refuses_while_a_partition_is_not_done_and_writes_nothing(self) -> None:
        store.create_scan_partitions(self.tenant, SCAN, "job-b", [{"part": 0}, {"part": 1}])
        unit = store.claim_next_partition(self.tenant, SCAN)
        store.persist_partition(self.tenant, SCAN, unit["partition_id"], unit["attempt"],
                                {"timestamp": self.TIMESTAMP, "source": "smb", "scan_diagnostics": _diagnostics(3)},
                                _records(range(3)), write_estate=True)
        with self.assertRaises(store.PartitionsNotFinished):
            partitioned_scan.finalize_scan(self.tenant, SCAN, timestamp=self.TIMESTAMP, source="smb")
        with store._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (self.tenant,)).fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_runs WHERE tenant_id = ?", (self.tenant,)).fetchone()[0], 0)

    def test_finalizing_twice_changes_nothing(self) -> None:
        parts = self._parts(_records(range(12)), (6, 6))
        first = self._save_partitioned(parts, enabled=False, frameworks=[], label="")
        state = self._state()
        again = partitioned_scan.finalize_scan(self.tenant, SCAN, timestamp=self.TIMESTAMP, source="smb")
        self.assertEqual(self._state(), state)
        self.assertEqual(again["file_count"], first["file_count"])

    def test_after_finalize_the_partition_records_can_be_collected_and_the_report_cannot(self) -> None:
        parts = self._parts(_records(range(12)), (6, 6))
        store.create_scan_partitions(self.tenant, SCAN, "job-b", [{"part": 0}, {"part": 1}])
        refs = []
        for part in parts:
            unit = store.claim_next_partition(self.tenant, SCAN)
            store.persist_partition(self.tenant, SCAN, unit["partition_id"], unit["attempt"],
                                    {"timestamp": self.TIMESTAMP, "source": "smb", "scan_diagnostics": _diagnostics(6)},
                                    _copy(part), write_estate=True)
        refs = [unit["records_ref"] for unit in store.list_scan_partitions(self.tenant, SCAN)]
        self.assertTrue(all(refs))
        partitioned_scan.finalize_scan(self.tenant, SCAN, timestamp=self.TIMESTAMP, source="smb")

        self.assertTrue(all(not unit["has_records"] for unit in store.list_scan_partitions(self.tenant, SCAN)))
        referenced = store.referenced_artifact_ids()
        artifacts.prune(referenced, grace_seconds=0)
        for ref in refs:
            self.assertFalse(artifacts.exists(self.tenant, ref), "a finalized partition's records were kept forever")
        self.assertEqual(len(store.read_scan_report(self.tenant, SCAN)["files"]), 12)


class ASingleScanKeepsVersionHistoryTest(_FinalizeTest):
    """The unseen-asset prune moved after the rows (B2.2b-2).

    Before, a named complete re-scan deleted and re-inserted every asset it saw again
    and threw away their versions. Now only unseen assets leave.
    """

    def test_a_complete_named_rescan_keeps_the_versions_of_files_it_saw_again(self) -> None:
        first = {"timestamp": "2026-09-01T00:00:00Z", "source": "smb", "mode": "full", "summary": {},
                 "files": _records(range(4)), "scan_diagnostics": _diagnostics(4), "scan_label": LABEL}
        store.save_scan_history(self.tenant, {**first, "scan_id": PRIOR})
        second = {"timestamp": "2026-09-02T00:00:00Z", "source": "smb", "mode": "full", "summary": {},
                  "files": _records(range(1, 4), variant=1), "scan_diagnostics": _diagnostics(3), "scan_label": LABEL}
        store.save_scan_history(self.tenant, {**second, "scan_id": SCAN})
        with store._connect() as conn:
            versions = {
                str(row["name"]): int(row["n"]) for row in conn.execute(
                    "SELECT a.name AS name, COUNT(v.version) AS n FROM assets a "
                    "LEFT JOIN asset_versions v ON v.tenant_id = a.tenant_id AND v.asset_id = a.id "
                    "WHERE a.tenant_id = ? GROUP BY a.name", (self.tenant,),
                ).fetchall()
            }
            orphaned = conn.execute(
                "SELECT COUNT(*) FROM asset_versions v WHERE v.tenant_id = ? AND NOT EXISTS "
                "(SELECT 1 FROM assets a WHERE a.tenant_id = v.tenant_id AND a.id = v.asset_id)", (self.tenant,),
            ).fetchone()[0]
        self.assertNotIn("file0.txt", versions, "an unseen asset stayed in the estate")
        self.assertEqual(versions, {"file1.txt": 2, "file2.txt": 2, "file3.txt": 2},
                         "a re-scan threw away the version history of files it saw again")
        self.assertEqual(orphaned, 0, "the unseen asset's versions were left behind")


class TheDiagnosticsMergeTest(unittest.TestCase):

    def test_counts_add_flags_combine_and_completeness_needs_every_partition(self) -> None:
        a = {"mode": "local", "local_path": "C:/a", "records": 3, "max_depth": 3, "unreadable_dirs": ["x"],
             "archive_timed_out": False, "allowed_extensions": [".txt"],
             "incremental": {"enabled": True, "complete": True, "total_objects": 4, "content_reads": 1,
                             "delta_ratio": 0.25, "scope_key": "s", "baseline_committed": True},
             "parallelism": {"analysis_workers": 4}, "triage": {"records_full": 3},
             "reuse_index": {"state": "ok", "read_errors": 0}}
        b = {"mode": "local", "local_path": "C:/b", "records": 5, "max_depth": 2, "unreadable_dirs": ["y", "x"],
             "archive_timed_out": True, "allowed_extensions": [".txt"],
             "incremental": {"enabled": True, "complete": False, "total_objects": 6, "content_reads": 4,
                             "delta_ratio": 0.666667, "scope_key": "s", "baseline_committed": True},
             "parallelism": {"analysis_workers": 2}, "triage": {"records_full": 5},
             "reuse_index": {"state": "read_only", "read_errors": 2}}
        merged = store.merge_partition_diagnostics([a, b])
        self.assertEqual(list(merged), list(a))
        self.assertEqual(merged["records"], 8)
        self.assertEqual(merged["local_path"], "C:/a")
        self.assertEqual(merged["unreadable_dirs"], ["x", "y"])
        self.assertEqual(merged["allowed_extensions"], [".txt"])
        self.assertTrue(merged["archive_timed_out"])
        self.assertEqual(merged["incremental"]["total_objects"], 10)
        self.assertFalse(merged["incremental"]["complete"], "one incomplete partition makes the scan incomplete")
        self.assertEqual(merged["incremental"]["delta_ratio"], 0.5)
        self.assertEqual(merged["incremental"]["scope_key"], "s")
        self.assertEqual(merged["parallelism"], {"analysis_workers": 2})
        self.assertEqual(merged["triage"], {"records_full": 8})
        self.assertEqual(merged["reuse_index"], {"state": "read_only", "read_errors": 2})

    def test_a_long_list_stays_bounded(self) -> None:
        parts = [{"unreadable_dirs": [f"d{i}-{j}" for j in range(20)]} for i in range(5)]
        self.assertEqual(len(store.merge_partition_diagnostics(parts)["unreadable_dirs"]), 20)

    def test_the_summary_is_the_sum(self) -> None:
        units = [{"summary": {"total_files": 2, "high": 1, "clear": 1}}, {"summary": {"total_files": 3, "high": 2, "clear": 0}}]
        self.assertEqual(partitioned_scan.summed_summary(units), {"total_files": 5, "high": 3, "clear": 1})


class TheEnrichmentSplitTest(unittest.TestCase):

    def test_per_file_preparation_plus_the_sections_is_the_whole_enrichment(self) -> None:
        for enabled, frameworks in ((True, ALL_FRAMEWORKS), (True, ["gdpr"]), (True, ["pci_dss", "nist_sp800_60_enterprise"]),
                                    (False, ALL_FRAMEWORKS), (False, [])):
            with self.subTest(enabled=enabled, frameworks=frameworks):
                whole = {"timestamp": "t", "files": _records(range(25))}
                enrich_report_with_compliance(whole, enabled, frameworks)
                split = {"timestamp": "t", "files": _records(range(25))}
                sections = ComplianceReportAccumulator(enabled, frameworks)
                for record in split["files"]:
                    sections.prepare(record)
                folded = ComplianceReportAccumulator(enabled, frameworks)
                for record in split["files"]:
                    folded.add(record)
                folded.apply(split)
                self.assertEqual(json.dumps(split, ensure_ascii=False), json.dumps(whole, ensure_ascii=False))


class TheStreamedBodyTest(unittest.TestCase):

    def test_streamed_files_write_the_same_bytes_and_cannot_be_dumped_whole(self) -> None:
        records = _records(range(7))
        report = {"timestamp": "t", "summary": {"total_files": 7}, "files": records, "scan_id": "s"}
        streamed = {**report, "files": store.StreamedFiles(lambda: iter(records))}
        self.assertEqual("".join(store.iter_report_json(streamed)), json.dumps(report, ensure_ascii=False))
        self.assertEqual("".join(store.iter_report_json(streamed)), json.dumps(report, ensure_ascii=False),
                         "a second pass must stream the same body")
        with self.assertRaises(TypeError):
            json.dumps(streamed)

    def test_the_compact_report_from_counts_is_the_compact_report(self) -> None:
        for records in ([], _records(range(5)), [{"path": "C:/enterprise_test_data/a.txt"}, {"path": "C:/x.txt"}]):
            report = {"summary": {"total_files": 9}, "files": records, "scan_id": "s"}
            samples = sum(1 for record in records if store.is_sample_data_path(record))
            self.assertEqual(store.compact_scan_report_from_counts(report, len(records), samples),
                             store.compact_scan_report(report))


if __name__ == "__main__":
    unittest.main()
