"""W4.4: the console's counts, maintained - always what the direct aggregates say.

The remediation summary and facets, the inventory facets and the posture inputs are read
from ``estate_counts`` (backend/estate_counts.py), kept by triggers on ``findings`` and
``assets``. Every step here writes through a different path - a scan saved, a rescan that
makes findings historical, a rescan that no longer sees some files, triage, an SLA or an
exposure changed by plain SQL, another workspace erased - and after each, every counted
answer in every scope must equal the direct aggregate's, and a reconcile must find no
drift. Both engines (the suite runs on PostgreSQL too).
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from backend import db, estate_counts, store

LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
TYPES = ("email", "phone", "iban", "credit_card", "passport_number", "national_id")
FRAMEWORKS = ("gdpr", "pci_dss", "hipaa", "nist")
SOURCES = ("smb", "local", "endpoint-winrm")


def _report(scan_id: str, label: str, indexes: range, stamp: str) -> dict:
    files = []
    for index in indexes:
        level = LEVELS[index % len(LEVELS)]
        findings = [{
            "finding_id": f"w44-{index}-{k}", "type": TYPES[(index + k) % len(TYPES)], "risk": level,
            "framework": FRAMEWORKS[(index + k) % len(FRAMEWORKS)], "count": 1 + k, "status": "OPEN",
            "confidence": 60 + index % 40, "owner": f"owner{index % 5}",
        } for k in range(index % 4)]
        name = f"file_{index:05d}.txt"
        files.append({
            "path": f"//fs01/share{index % 3}/dept{index % 7:02d}/{name}", "name": name, "extension": ".txt",
            "size": 1000 + index, "owner": f"CORP\\user{index % 9}", "source": SOURCES[index % len(SOURCES)],
            # some modified today, some years ago, some never known
            "modified_at": "" if index % 11 == 0 else (
                datetime.now(timezone.utc) - timedelta(days=(index * 37) % 900, hours=index % 5)).isoformat(),
            "share": "" if index % 13 == 0 else f"share{index % 3}", "content_hash": f"{index:064x}",
            "content_status": "scanned", "protected": index % 17 == 0, "hidden": index % 19 == 0,
            "risk": {"level": level, "score": 100 - LEVELS.index(level) * 25 - index % 20}, "findings": findings,
        })
    return {"scan_id": scan_id, "source": "smb", "scan_label": label, "summary": {"total_files": len(files)},
            "timestamp": stamp, "files": files}


class TheCountsAreTheAggregatesTest(unittest.TestCase):

    def setUp(self) -> None:
        self.tenant = f"w44-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "W4.4 counts")
        self.addCleanup(self._erase, self.tenant)

    @staticmethod
    def _erase(tenant: str) -> None:
        try:
            store.delete_tenant_with_data(tenant)
        except Exception:  # noqa: BLE001 - a test's tenant, best effort
            pass

    def _assert_counts_match(self, step: str) -> None:
        tenant = self.tenant
        with db.tenant_scope(tenant):
            for scope in ("current", "historical", "all"):
                self.assertEqual(store._counted_remediation_summary(tenant, scope),
                                 store._build_remediation_summary(tenant, scope), f"{step}: summary, {scope}")
                counted, direct = store._counted_remediation_facets(tenant, scope), \
                    store._build_remediation_facets(tenant, scope)
                for facets in (counted, direct):
                    facets["frameworks"] = sorted(facets["frameworks"], key=lambda item: item["value"])
                self.assertEqual(counted, direct, f"{step}: facets, {scope}")
            with store._connect() as conn:
                direct_inventory = store._inventory_facets_from(store._inventory_facet_rows(conn, tenant))
                counted_inventory = store._inventory_facets_from(store._counted_inventory_facet_rows(conn, tenant))
            self.assertAlmostEqual(counted_inventory.pop("avg_risk_score"), direct_inventory.pop("avg_risk_score"),
                                   places=6, msg=f"{step}: average risk")
            self.assertEqual(counted_inventory, direct_inventory, f"{step}: inventory facets")
            self.assertEqual(store._counted_posture_inputs(tenant), store._posture_inputs(tenant), f"{step}: posture")
        drift = store.reconcile_estate_counts(tenant, repair=False)["drift"]
        self.assertEqual(drift["keys"], 0, f"{step}: drift {drift}")

    def _finding_ids(self, where: str = "1 = 1") -> list[str]:
        with db.tenant_scope(self.tenant), store._connect() as conn:
            return [str(row["id"]) for row in conn.execute(
                f"SELECT id FROM findings WHERE tenant_id = ? AND is_current = 1 AND {where} ORDER BY id",  # noqa: S608
                (self.tenant,)).fetchall()]

    def test_every_write_path_keeps_them_exact(self) -> None:
        tenant = self.tenant
        store.save_scan_history(tenant, _report("w44-a1", "alpha", range(0, 60), "2026-10-01T00:00:00+00:00"))
        store.save_scan_history(tenant, _report("w44-b1", "beta", range(60, 100), "2026-10-02T00:00:00+00:00"))
        self._assert_counts_match("two scans saved")

        # A rescan of one label sees fewer files and different findings: findings go historical.
        store.save_scan_history(tenant, _report("w44-a2", "alpha", range(0, 45), "2026-10-03T00:00:00+00:00"))
        self._assert_counts_match("rescan")

        # Triage through the product.
        ids = self._finding_ids()
        self.assertGreater(len(ids), 12)
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        for finding_id, action, payload in (
                (ids[0], "assign", {"owner": "analyst-1"}), (ids[1], "resolve", {}),
                (ids[2], "suppress", {"reason": "test data", "expiration_date": future}),
                (ids[3], "status", {"status": "IN_PROGRESS"}), (ids[4], "validate", {}),
                (ids[5], "status", {"status": "PENDING_VALIDATION"}), (ids[6], "false-positive", {}),
                (ids[1], "reopen", {})):
            store.update_finding_lifecycle(tenant, finding_id, action, payload, "tester")
        self._assert_counts_match("triage")

        # Plain SQL: due dates around "now" and exposure - the triggers count any writer.
        now = datetime.now(timezone.utc)
        dues = [(now - timedelta(days=3)).isoformat(), (now - timedelta(minutes=5)).isoformat(),
                (now + timedelta(minutes=5)).isoformat(), (now + timedelta(days=3)).isoformat(), ""]
        with db.tenant_scope(tenant), store._connect() as conn:
            for position, finding_id in enumerate(ids[7:]):
                conn.execute("UPDATE findings SET sla_due = ?, exposure = ? WHERE tenant_id = ? AND id = ?",
                             (dues[position % len(dues)], ("PUBLIC", "BROAD_INTERNAL", "PRIVATE")[position % 3],
                              tenant, finding_id))
            # Past due but no longer active (resolved, suppressed, false positive): not overdue.
            for finding_id in (ids[2], ids[6]):
                conn.execute("UPDATE findings SET sla_due = ? WHERE tenant_id = ? AND id = ?",
                             (dues[0], tenant, finding_id))
            # Files modified a minute either side of each age cutoff: their own day decides.
            cutoffs = [value for _name, value in store._age_cutoffs()[:3]]
            sensitive = [str(row["id"]) for row in conn.execute(
                "SELECT id FROM assets WHERE tenant_id = ? AND finding_count > 0 ORDER BY id DESC LIMIT 6",
                (tenant,)).fetchall()]
            for position, asset_id in enumerate(sensitive):
                moment = datetime.fromisoformat(cutoffs[position // 2]) + timedelta(minutes=1 if position % 2 else -1)
                conn.execute("UPDATE assets SET modified_at = ? WHERE tenant_id = ? AND id = ?",
                             (moment.isoformat(), tenant, asset_id))
        store._invalidate_inventory_query_cache(tenant)
        self._assert_counts_match("sla and exposure by SQL")
        # Not vacuous: what was compared has something in it everywhere.
        with db.tenant_scope(tenant):
            current = store._counted_remediation_summary(tenant, "current")
            historical = store._counted_remediation_summary(tenant, "historical")
            posture = store._counted_posture_inputs(tenant)
            with store._connect() as conn:
                inventory = store._inventory_facets_from(store._counted_inventory_facet_rows(conn, tenant))
        self.assertGreater(current["overdue"], 0)
        self.assertGreater(current["affected_files"], 0)
        self.assertGreater(historical["total_findings"], 0, "the rescan left nothing historical")
        self.assertGreater(posture["exposed_sensitive_files"], 0)
        self.assertGreater(len(current["findings_by_status"]), 4)
        for bucket in ("fresh", "recent", "ageing", "stale", "unknown"):
            self.assertGreater(inventory["sensitive_age"][bucket], 0, bucket)
        self.assertTrue(inventory["locations"])
        self.assertTrue(inventory["finding_types"])

        # Assets changed by SQL: risk, share, folder, modified time, protection.
        with db.tenant_scope(tenant), store._connect() as conn:
            conn.execute("UPDATE assets SET risk_level = 'HIGH', share = 'share9', is_protected = 1, "
                         "path = '//fs01/share9/new/x.txt', modified_at = '' WHERE tenant_id = ? AND id IN "
                         "(SELECT id FROM assets WHERE tenant_id = ? ORDER BY id LIMIT 5)", (tenant, tenant))
            conn.execute("DELETE FROM findings WHERE tenant_id = ? AND id = ?", (tenant, ids[8]))
        store._invalidate_inventory_query_cache(tenant)
        self._assert_counts_match("assets by SQL, a finding deleted")

        # Another workspace erased: these counts stay, theirs go.
        other = f"w44-other-{uuid4().hex[:6]}"
        store.create_tenant(other, "W4.4 other")
        store.save_scan_history(other, _report("w44-o1", "other", range(0, 20), "2026-10-04T00:00:00+00:00"))
        store.delete_tenant_with_data(other)
        self._assert_counts_match("another workspace erased")
        with store._connect() as conn, db.platform_scope("migration"):
            left = conn.execute("SELECT COUNT(*) AS n FROM estate_counts WHERE tenant_id = ?", (other,)).fetchone()
        self.assertEqual(int(left["n"] or 0), 0, "an erased workspace's counts were kept")

    def test_unfolded_deltas_are_read_exactly(self) -> None:
        """W4.5: a read never folds - it adds the deltas not yet folded to the counts, and a
        count of files adds the crossings those make. Every write here leaves its deltas
        pending; every answer must still be the rows'."""
        from unittest import mock

        tenant = self.tenant
        # Counted before the writes: a first read of an uncounted workspace recounts it from
        # its rows, which would fold the deltas this test leaves pending.
        store.remediation_summary(tenant)
        with mock.patch.object(store, "_fold_estate_counts", lambda _tenant: None):
            store.save_scan_history(tenant, _report("w44-p1", "alpha", range(0, 40), "2026-10-01T00:00:00+00:00"))
            store.save_scan_history(tenant, _report("w44-p2", "alpha", range(0, 25), "2026-10-02T00:00:00+00:00"))
            ids = self._finding_ids()
            store.update_finding_lifecycle(tenant, ids[0], "resolve", {}, "tester")
            with db.tenant_scope(tenant), store._connect() as conn:
                conn.execute("UPDATE findings SET exposure = 'PUBLIC' WHERE tenant_id = ? AND id IN (?, ?)",
                             (tenant, ids[1], ids[2]))
            with db.tenant_scope(tenant), store._connect() as conn:
                pending = int(conn.execute("SELECT COUNT(*) AS n FROM estate_count_deltas WHERE tenant_id = ?",
                                           (tenant,)).fetchone()["n"] or 0)
            if db.is_postgres():
                self.assertGreater(pending, 0, "nothing was left pending - the merge was not exercised")
            with db.tenant_scope(tenant):
                for scope in ("current", "historical", "all"):
                    self.assertEqual(store._counted_remediation_summary(tenant, scope),
                                     store._build_remediation_summary(tenant, scope), scope)
                    counted, direct = store._counted_remediation_facets(tenant, scope), \
                        store._build_remediation_facets(tenant, scope)
                    for facets in (counted, direct):
                        facets["frameworks"] = sorted(facets["frameworks"], key=lambda item: item["value"])
                    self.assertEqual(counted, direct, scope)
                self.assertEqual(store._counted_posture_inputs(tenant), store._posture_inputs(tenant))
                with store._connect() as conn:
                    counted_inventory = store._inventory_facets_from(store._counted_inventory_facet_rows(conn, tenant))
                    direct_inventory = store._inventory_facets_from(store._inventory_facet_rows(conn, tenant))
                counted_inventory.pop("avg_risk_score")
                direct_inventory.pop("avg_risk_score")
                self.assertEqual(counted_inventory, direct_inventory)
                with store._connect() as conn:
                    still = int(conn.execute("SELECT COUNT(*) AS n FROM estate_count_deltas WHERE tenant_id = ?",
                                             (tenant,)).fetchone()["n"] or 0)
            self.assertEqual(still, pending, "the reads folded or recounted - the merge was not what they read")

    def test_a_reader_never_folds(self) -> None:
        """W4.5: a console read takes no lock a scan's fold holds - it reads past the deltas."""
        from unittest import mock

        tenant = self.tenant
        store.remediation_summary(tenant)  # a first read may count an uncounted workspace, once
        with mock.patch.object(store, "_fold_estate_counts", lambda _tenant: None):
            store.save_scan_history(tenant, _report("w45-n1", "alpha", range(0, 20), "2026-10-01T00:00:00+00:00"))
        refuse = AssertionError("a read folded the counts or took their lock")
        with mock.patch.object(estate_counts, "fold", side_effect=refuse), \
                mock.patch.object(estate_counts, "_lock", side_effect=refuse), db.tenant_scope(tenant):
            for scope in ("current", "historical", "all"):
                store._counted_remediation_summary(tenant, scope)
                store._counted_remediation_facets(tenant, scope)
            store._counted_posture_inputs(tenant)
            with store._connect() as conn:
                store._counted_inventory_facet_rows(conn, tenant)

    def test_drift_is_found_recorded_and_repaired(self) -> None:
        tenant = self.tenant
        store.save_scan_history(tenant, _report("w44-d1", "delta", range(0, 30), "2026-10-01T00:00:00+00:00"))
        with db.tenant_scope(tenant), store._connect() as conn:
            estate_counts.fold(conn, tenant)
            conn.execute("UPDATE estate_counts SET n = n + 7 WHERE tenant_id = ? AND dim = 'f.status'", (tenant,))
        found = store.reconcile_estate_counts(tenant, repair=False)
        self.assertGreater(found["drift"]["keys"], 0)
        self.assertIn("f.status", found["drift"]["by_dim"])
        self.assertFalse(found["repaired"])
        self.assertEqual(store.estate_counts_state(tenant)["drift"]["keys"], found["drift"]["keys"])
        repaired = store.reconcile_estate_counts(tenant)
        self.assertTrue(repaired["repaired"])
        self.assertEqual(store.reconcile_estate_counts(tenant, repair=False)["drift"]["keys"], 0)
        self._assert_counts_match("after repair")

    def test_the_readers_answer_from_the_counts(self) -> None:
        store.save_scan_history(self.tenant, _report("w44-r1", "read", range(0, 12), "2026-10-01T00:00:00+00:00"))
        summary = store.remediation_summary(self.tenant, "current")
        with db.tenant_scope(self.tenant):
            self.assertEqual(summary, store._build_remediation_summary(self.tenant, "current"))
        page = store.list_remediation_findings(self.tenant, limit=5)
        self.assertEqual(page["summary"], summary)
        self.assertEqual(page["freshness"].get("state", "current"), "current")

    def test_a_counted_answer_is_never_cached_nor_stale(self) -> None:
        """W4.4: no previous value is served - the answer is computed, cheaply, every time."""
        tenant = self.tenant
        store.save_scan_history(tenant, _report("w44-n1", "never", range(0, 12), "2026-10-01T00:00:00+00:00"))
        from backend import live_cache

        with live_cache.collecting() as fresh:
            before = store.remediation_summary(tenant, "current")
            store.inventory_facets(tenant)
            store.posture_inputs(tenant)
        self.assertFalse(fresh.summary().get("stale"))
        store.save_scan_history(tenant, _report("w44-n2", "never-2", range(12, 30), "2026-10-02T00:00:00+00:00"))
        with live_cache.collecting() as fresh:
            after = store.remediation_summary(tenant, "current")
        self.assertFalse(fresh.summary().get("stale"), "a counted answer was served stale")
        self.assertGreater(after["total_findings"], before["total_findings"], "the scan just saved was not counted")
        with db.tenant_scope(tenant), store._connect() as conn:
            cached = conn.execute("SELECT COUNT(*) AS n FROM derived_cache WHERE tenant_id = ? AND (cache_key LIKE "
                                  "'remediation_summary%' OR cache_key LIKE 'posture_inputs%' OR cache_key LIKE "
                                  "'inventory_facets%')", (tenant,)).fetchone()
        self.assertEqual(int(cached["n"] or 0), 0, "a counted answer was written to the cache")

    def test_housekeeping_checks_every_workspace_once_a_day(self) -> None:
        from unittest import mock

        from backend import housekeeping

        tenant = self.tenant
        store.save_scan_history(tenant, _report("w44-h1", "house", range(0, 15), "2026-10-01T00:00:00+00:00"))
        with db.tenant_scope(tenant), store._connect() as conn:
            estate_counts.fold(conn, tenant)
            conn.execute("UPDATE estate_counts SET n = n + 3 WHERE tenant_id = ? AND dim = 'f.severity'", (tenant,))
        moment = datetime.now(timezone.utc) + timedelta(days=400)  # past any earlier test's claim
        with mock.patch.dict("os.environ", {"DSPM_COUNTS_RECONCILE_SECONDS": "86400"}):
            ran = housekeeping.run_counts_reconcile_if_due(now=moment)
            again = housekeeping.run_counts_reconcile_if_due(now=moment + timedelta(hours=1))
        self.assertIsNotNone(ran)
        self.assertGreaterEqual(ran["drifted"], 1)
        self.assertIsNone(again, "a second backend ran the daily check again within the day")
        # ... and it is one of the jobs the housekeeping pass runs.
        with mock.patch.object(housekeeping, "run_counts_reconcile_if_due", return_value={"workspaces": 0}) as job, \
                mock.patch.object(housekeeping, "run_if_due", return_value=None), \
                mock.patch.object(housekeeping, "run_backup_if_due", return_value=None):
            self.assertIn("counts", housekeeping.run_due_jobs())
        job.assert_called_once()
        self.assertEqual(store.reconcile_estate_counts(tenant, repair=False)["drift"]["keys"], 0, "not repaired")
        page = store.list_remediation_findings(tenant, limit=5)
        self.assertTrue(page["counts"]["maintained"])
        self.assertTrue(page["counts"]["reconciled_at"])
        with mock.patch.dict("os.environ", {"DSPM_COUNTS_RECONCILE_SECONDS": "0"}):
            self.assertIsNone(housekeeping.run_counts_reconcile_if_due(now=moment + timedelta(days=2)))

    def test_a_remediation_page_counts_its_matches_to_a_cap(self) -> None:
        from unittest import mock

        store.save_scan_history(self.tenant, _report("w44-c1", "cap", range(0, 40), "2026-10-01T00:00:00+00:00"))
        with mock.patch.object(store, "REMEDIATION_COUNT_CAP", 7):
            store._invalidate_remediation_query_cache(self.tenant)
            capped = store.list_remediation_findings(self.tenant, status="all", limit=5)
        self.assertEqual((capped["total"], capped["total_is_estimate"]), (7, True))
        store._invalidate_remediation_query_cache(self.tenant)
        exact = store.list_remediation_findings(self.tenant, status="all", limit=5)
        self.assertFalse(exact["total_is_estimate"])
        self.assertEqual(exact["total"], store._counted_remediation_summary(self.tenant, "current")["total_findings"])

    def test_a_workspace_that_arrives_uncounted_is_counted_on_its_first_read(self) -> None:
        """A copy that left the derived tables behind, or a TRUNCATE (which fires no trigger):
        no counts and no record of a count. The first read counts the rows."""
        tenant = self.tenant
        store.save_scan_history(tenant, _report("w44-u1", "uncounted", range(0, 20), "2026-10-01T00:00:00+00:00"))
        with db.tenant_scope(tenant):
            expected = store._build_remediation_summary(tenant, "current")
            with store._connect() as conn:
                for table in ("estate_counts", "estate_count_deltas", "estate_count_state"):
                    conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant,))  # noqa: S608 - fixed names
        with store._counts_known_lock:
            store._COUNTS_KNOWN.clear()
        self.assertGreater(expected["total_findings"], 0)
        self.assertEqual(store.remediation_summary(tenant, "current"), expected)

    def test_the_sort_indexes_are_the_sorts(self) -> None:
        for _name, expression in store.REMEDIATION_SORT_INDEXES.items():
            self.assertIn(expression, {spec[0] for spec in store.REMEDIATION_SORTS.values() if spec[1]})
        self.assertEqual(len(store.REMEDIATION_SORT_INDEXES),
                         len([spec for spec in store.REMEDIATION_SORTS.values() if spec[1]]))

    def test_the_count_module_knows_the_store_s_active_statuses(self) -> None:
        self.assertEqual(set(estate_counts.ACTIVE_STATUSES), set(store.REMEDIATION_ACTIVE_STATUSES))


class PendingDeltasAreReadPastTest(unittest.TestCase):
    """W4.5: the top of a per-file dimension and a count of files, read with deltas pending.

    A reader no longer folds. ``top`` takes the counts' top ``limit`` plus one key per
    pending key, the counted keys the pending ones move, and the pending keys - so a key
    that pending deltas lift from deep in the counts, or a head key they empty, is still
    ranked right. ``files`` adds the zero-crossings the pending per-file deltas make."""

    def setUp(self) -> None:
        self.tenant = f"w45r-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "W4.5 readers")
        self.addCleanup(TheCountsAreTheAggregatesTest._erase, self.tenant)

    def _write(self, table: str, rows: list[tuple[str, str, int]]) -> None:
        with db.tenant_scope(self.tenant), store._connect() as conn:
            conn.executemany(f"INSERT INTO {table} (tenant_id, dim, k1, k2, k3, n, occ) "  # noqa: S608 - test tables
                             "VALUES (?, ?, ?, '', ?, ?, 0)",
                             [(self.tenant, dim, key, "1", n) for dim, key, n in rows])

    def _top(self, limit: int) -> list[tuple[str, int]]:
        with db.tenant_scope(self.tenant), store._connect() as conn:
            return estate_counts.top(conn, self.tenant, "f.asset", "1", limit)

    def test_a_key_lifted_from_deep_in_the_counts_is_ranked_with_its_whole_count(self) -> None:
        self._write(estate_counts.COUNTS_TABLE, [("f.asset", key, n) for key, n in
                                                 (("a", 9), ("b", 8), ("c", 7), ("e", 6), ("f", 5), ("d", 1))])
        self._write(estate_counts.DELTAS_TABLE, [("f.asset", "d", 20), ("f.asset", "x", 1)])
        self.assertEqual(self._top(1), [("d", 21)])
        self.assertEqual(self._top(3), [("d", 21), ("a", 9), ("b", 8)])

    def test_a_head_key_the_deltas_empty_gives_way(self) -> None:
        self._write(estate_counts.COUNTS_TABLE, [("f.asset", key, n) for key, n in (("a", 9), ("b", 8), ("c", 7))])
        self._write(estate_counts.DELTAS_TABLE, [("f.asset", "a", -9)])
        self.assertEqual(self._top(1), [("b", 8)])

    @unittest.skipUnless(db.is_postgres(), "SQLite counts its per-file rows; nothing is pending there")
    def test_a_count_of_files_adds_the_crossings(self) -> None:
        # Kept: files a, b, c have findings - 3. Pending: a loses all (-1), d and e gain their
        # first (+2), b gains more (no crossing) - 4.
        self._write(estate_counts.COUNTS_TABLE, [("f.active_asset", key, n) for key, n in (("a", 2), ("b", 1), ("c", 4))]
                    + [(estate_counts.DISTINCT["f.active_asset"], "", 3)])
        self._write(estate_counts.DELTAS_TABLE, [("f.active_asset", "a", -2), ("f.active_asset", "d", 1),
                                                 ("f.active_asset", "e", 3), ("f.active_asset", "b", 2)])
        with db.tenant_scope(self.tenant), store._connect() as conn:
            self.assertEqual(estate_counts.files(conn, self.tenant, "f.active_asset", "1"), 4)


if __name__ == "__main__":
    unittest.main()
