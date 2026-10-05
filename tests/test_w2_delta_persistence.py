"""W2.1: an unchanged rescan writes what changed, not the estate again.

A rescan of 4,000 unchanged files wrote 109 MiB of WAL - more than the first scan -
because every file rewrote its asset row and detail, its findings twice (retired, then
re-asserted), its version, its access rows and its baseline snapshot. Now a row whose
content is what is stored is left alone and only its presence marker moves, set-based;
what changed is written as before, and what the scan did not see is still pruned.
"""
from __future__ import annotations

import re
import unittest
from unittest.mock import patch
from uuid import uuid4

from backend import store
from tests.test_w14_postgres_correctness import _tracing_connect

LABEL = "finance-share"
SCOPE = "scope-finance"
_WRITE = re.compile(r"^\s*(INSERT\s+(?:OR\s+\w+\s+)?INTO|UPDATE|DELETE\s+FROM)\s+(\w+)", re.IGNORECASE)


def _file(index: int, *, risk: str = "HIGH", findings: tuple[str, ...] = ("email", "iban"),
          principals: tuple[str, ...] = ("CORP\\finance", "CORP\\auditors"), volatile: str = "") -> dict:
    name = f"f{index:03d}.txt"
    path = f"//fs01/finance/{name}"
    record = {
        "path": path, "name": name, "extension": ".txt", "size": 100 + index, "source": "smb",
        "share": "finance", "owner": "CORP\\owner", "reuse_key": f"smb://fs01/finance/{name}",
        "modified_at": "2026-09-01T00:00:00+00:00", "sha256": f"{index:064x}", "content_status": "scanned",
        "risk": {"level": risk, "score": 80 if risk == "HIGH" else 30},
        "acl": {"owner": "CORP\\owner", "principals": list(principals),
                "permissions": ["Read"] * len(principals), "types": ["Allow"] * len(principals)},
        "findings": [{"finding_id": f"f-{index}-{kind}", "type": kind, "risk": risk, "framework": "gdpr",
                      "count": 1, "status": "OPEN", "first_seen": "2026-09-01T00:00:00+00:00",
                      "last_seen": "2026-09-01T00:00:00+00:00"} for kind in findings],
    }
    if volatile:
        # What a reuse changes on every scan: none of it is about the file.
        record.update(last_scanned_at=volatile, incremental_scan_reason="durable_baseline_unchanged_file",
                      cache_reused=True, incremental_reused=True, detector_elapsed_ms=0,
                      detector_metrics={"cache_hit": True})
    return record


def _report(scan_id: str, files: list[dict], timestamp: str) -> dict:
    return {"scan_id": scan_id, "source": "smb", "summary": {"total_files": len(files)}, "scan_label": LABEL,
            "timestamp": timestamp, "completed_at": timestamp, "files": files,
            "scan_diagnostics": {"incremental": {"enabled": True, "baseline_update": True, "complete": True,
                                                 "scope_key": SCOPE, "version_signature": "rules-v1"}}}


class _Estate(unittest.TestCase):
    FILES = 20

    def setUp(self) -> None:
        self.tenant = f"w21-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Delta")
        store.save_scan_history(self.tenant, _report("scan-a", [_file(i) for i in range(self.FILES)],
                                                     "2026-10-01T00:00:00+00:00"))

    def _rescan(self, files: list[dict], scan_id: str = "scan-b", timestamp: str = "2026-10-02T00:00:00+00:00"):
        log: list = []
        with patch.object(store, "_connect", _tracing_connect(log)):
            store.save_scan_history(self.tenant, _report(scan_id, files, timestamp))
        writes: dict[tuple[str, str], int] = {}
        for sql, rows in log:
            match = _WRITE.match(sql)
            if match:
                key = (match.group(1).split()[0].upper() + (" SET " + sql.split(" SET ", 1)[1].split(" ")[0]
                                                            if match.group(1).upper() == "UPDATE" else ""),
                       match.group(2).lower())
                writes[key] = writes.get(key, 0) + max(0, int(rows or 0))
        return writes

    def _rows(self, sql: str, *params) -> list[dict]:
        with store._connect() as conn:
            return [dict(row) for row in conn.execute(sql, (self.tenant, *params)).fetchall()]


class AnUnchangedRescanWritesOnlyPresenceTest(_Estate):

    def test_nothing_but_presence_markers_is_written(self) -> None:
        before = {row["id"]: row for row in self._rows("SELECT id, detail_json, row_digest FROM assets WHERE tenant_id = ?")}
        writes = self._rescan([_file(i, volatile="2026-10-02T00:00:00+00:00") for i in range(self.FILES)])
        whole = {key: rows for key, rows in writes.items()
                 if key[1] in {"assets", "findings", "asset_access", "scan_object_baselines"}
                 and key[0] in {"INSERT", "DELETE"} and rows}
        self.assertEqual(whole, {}, "an unchanged file was written whole")
        self.assertEqual(writes.get(("UPDATE SET current_scan_id", "assets")), self.FILES)
        self.assertEqual(writes.get(("UPDATE SET scan_id", "findings")), 2 * self.FILES)
        self.assertNotIn(("UPDATE SET is_current", "findings"), writes, "a current finding was retired")
        self.assertEqual(writes.get(("UPDATE SET last_scan_id", "scan_object_baselines")), self.FILES)

        after = {row["id"]: row for row in self._rows(
            "SELECT id, detail_json, row_digest, current_scan_id FROM assets WHERE tenant_id = ?")}
        self.assertEqual({row["current_scan_id"] for row in after.values()}, {"scan-b"})
        self.assertEqual({key: (row["detail_json"], row["row_digest"]) for key, row in after.items()},
                         {key: (row["detail_json"], row["row_digest"]) for key, row in before.items()})
        findings = self._rows("SELECT scan_id, is_current FROM findings WHERE tenant_id = ?")
        self.assertEqual({(row["scan_id"], row["is_current"]) for row in findings}, {("scan-b", 1)})
        self.assertEqual(len(findings), 2 * self.FILES)
        baselines = self._rows("SELECT last_scan_id FROM scan_object_baselines WHERE tenant_id = ?")
        self.assertEqual({row["last_scan_id"] for row in baselines}, {"scan-b"})

    def test_the_file_view_says_the_scan_that_last_saw_it(self) -> None:
        self._rescan([_file(i, volatile="2026-10-02T00:00:00+00:00") for i in range(self.FILES)],
                     timestamp="2026-10-02T00:00:00+00:00")
        asset_id = self._rows("SELECT id FROM assets WHERE tenant_id = ? AND name = 'f003.txt'")[0]["id"]
        detail = store.get_inventory_asset(self.tenant, asset_id)
        self.assertEqual(detail["last_scanned_at"], "2026-10-02T00:00:00+00:00")


class WhatChangedIsWrittenTest(_Estate):

    def test_a_changed_file_is_rewritten_and_its_removed_finding_retired(self) -> None:
        files = [_file(i, volatile="v") for i in range(self.FILES)]
        files[3] = _file(3, risk="LOW", findings=("email",))
        self._rescan(files)
        asset = self._rows("SELECT risk_level, current_scan_id FROM assets WHERE tenant_id = ? AND name = 'f003.txt'")[0]
        self.assertEqual((asset["risk_level"], asset["current_scan_id"]), ("LOW", "scan-b"))
        states = {row["rule"]: row["is_current"] for row in self._rows(
            "SELECT rule, is_current FROM findings WHERE tenant_id = ? AND file_name = 'f003.txt'")}
        self.assertEqual(states, {"email": 1, "iban": 0})
        others = self._rows("SELECT COUNT(*) AS n FROM findings WHERE tenant_id = ? AND is_current = 1 "
                            "AND file_name <> 'f003.txt'")[0]["n"]
        self.assertEqual(others, 2 * (self.FILES - 1))

    def test_access_is_rewritten_only_where_it_changed(self) -> None:
        files = [_file(i, volatile="v") for i in range(self.FILES)]
        files[5] = _file(5, principals=("CORP\\finance", "Everyone"))
        self._rescan(files)
        by_file = {}
        for row in self._rows("SELECT a.name, x.principal, x.scan_id FROM asset_access x JOIN assets a "
                              "ON a.tenant_id = x.tenant_id AND a.id = x.asset_id WHERE x.tenant_id = ?"):
            by_file.setdefault(row["name"], set()).add((row["principal"], row["scan_id"]))
        self.assertIn(("Everyone", "scan-b"), by_file["f005.txt"])
        self.assertNotIn("CORP\\auditors", {principal for principal, _scan in by_file["f005.txt"]})
        self.assertEqual({scan for principal, scan in by_file["f006.txt"]}, {"scan-a"},
                         "an unchanged file's access rows were rewritten")

    def test_a_file_the_scan_did_not_see_is_pruned(self) -> None:
        self._rescan([_file(i, volatile="v") for i in range(self.FILES) if i != 9])
        self.assertEqual(self._rows("SELECT id FROM assets WHERE tenant_id = ? AND name = 'f009.txt'"), [])
        self.assertEqual({row["is_current"] for row in self._rows(
            "SELECT is_current FROM findings WHERE tenant_id = ? AND file_name = 'f009.txt'")}, {0})
        self.assertEqual(len(self._rows("SELECT id FROM assets WHERE tenant_id = ?")), self.FILES - 1)

    def test_a_decision_on_a_finding_survives_an_unchanged_rescan(self) -> None:
        finding_id = self._rows("SELECT id FROM findings WHERE tenant_id = ? AND file_name = 'f002.txt' "
                                "AND rule = 'email'")[0]["id"]
        store.update_finding_lifecycle(self.tenant, finding_id, "assign", {"owner": "privacy-team"}, "analyst")
        self._rescan([_file(i, volatile="v") for i in range(self.FILES)])
        row = self._rows("SELECT owner, is_current, scan_id FROM findings WHERE tenant_id = ? AND id = ?",
                         finding_id)[0]
        self.assertEqual((row["owner"], row["is_current"], row["scan_id"]), ("privacy-team", 1, "scan-b"))

    def test_a_changed_object_rewrites_its_baseline_and_the_rest_keep_theirs(self) -> None:
        before = {row["object_key"]: row["snapshot_digest"] for row in self._rows(
            "SELECT object_key, snapshot_digest FROM scan_object_baselines WHERE tenant_id = ?")}
        files = [_file(i, volatile="v") for i in range(self.FILES)]
        files[4] = _file(4, risk="LOW")
        self._rescan(files)
        after = {row["object_key"]: row["snapshot_digest"] for row in self._rows(
            "SELECT object_key, snapshot_digest FROM scan_object_baselines WHERE tenant_id = ?")}
        changed = {key for key in after if after[key] != before.get(key)}
        self.assertEqual(changed, {"smb://fs01/finance/f004.txt"})


if __name__ == "__main__":
    unittest.main()
