"""Phase B where its steps meet - the checks no single step's suite can make.

Each step of Phase B was delivered with its own tests, and each of those tests knows
only its own step. These are the seams between them, which is where the defects that
survive a green suite live:

- a rule written in B6 has to reach every kind of scan B2, B3 and B4 introduced - a
  partitioned one, a rebuilt one a worker or a resume starts, an endpoint one, and the
  one nobody starts;
- a partitioned scan reports **one scan's** rules, not one per partition. The merge adds
  up what its partitions counted, and the number of rules is not a count;
- retention (B5) removes events, never policy: a suppression rule is a decision somebody
  made, and nothing deletes it on a timer.
"""

from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

from backend import app as app_module, partitioned_scan, store
from backend.security import Principal
from collectors import file_scanner
from collectors.winrm_endpoint_scanner import WinRMEndpointConfig
from discovery.discovery_engine import ScanConfig

TENANT = "default"


class TheRulesReachEveryKindOfScanTest(unittest.TestCase):
    """A rule the console writes is only worth writing if every scan reads it."""

    def setUp(self) -> None:
        self.rule = store.create_suppression_rule(
            TENANT, finding_type="credit_card", reason="seam test", created_by="ana",
        )
        self.addCleanup(store.delete_suppression_rule, TENANT, self.rule["rule_id"])

    def _rule_ids(self, config: ScanConfig) -> list[str]:
        return [str(item.get("rule_id") or "") for item in config.suppression_rules]

    def test_a_scan_from_the_console_carries_them(self) -> None:
        config = app_module._to_config(app_module.ScanRequest(local_path="enterprise_test_data"), TENANT)
        self.assertIn(self.rule["rule_id"], self._rule_ids(config))

    def test_a_scan_a_worker_or_a_resume_rebuilds_carries_them(self) -> None:
        record = {"tenant_id": TENANT, "request": {"local_path": "enterprise_test_data"}}
        config = app_module.rebuild_scan_config(record)
        self.assertIn(self.rule["rule_id"], self._rule_ids(config),
                      "a partition run by a worker would report what the console suppressed")

    def test_an_endpoint_scan_carries_them(self) -> None:
        endpoint = WinRMEndpointConfig(host="endpoint-01", username="scan", password="secret", paths=["documents"])
        payload = app_module.EndpointScanRequest(host="endpoint-01", username="scan", password="secret")
        principal = Principal(subject="ana", role="analyst", tenant_id=TENANT)
        engine = app_module._endpoint_analysis_engine(endpoint, payload, principal, baseline_available=False)
        self.assertIn(self.rule["rule_id"], self._rule_ids(engine.config))
        self.assertTrue(engine._suppression, "the endpoint engine compiled no rules")

    def test_the_scan_nobody_starts_carries_them(self) -> None:
        schedule = {
            "tenant_id": TENANT,
            "schedule_id": "sch_seam",
            "name": "nightly",
            "request": {"local_path": "enterprise_test_data"},
        }
        captured: list[ScanConfig] = []

        def run_now(_tenant, runner):
            runner(MagicMock(progress=0, cancel_requested=False))
            return MagicMock(id="job-seam")

        with patch.object(app_module, "create_job", side_effect=run_now), \
                patch.object(app_module, "_scheduled_scan_payload",
                             side_effect=lambda _s, config, *a, **k: captured.append(config) or {}), \
                patch.object(app_module, "_prepare_local_scan_data"):
            app_module._start_scheduled_scan(schedule)

        self.assertEqual(len(captured), 1)
        self.assertIn(self.rule["rule_id"], self._rule_ids(captured[0]))


class APartitionedScanReportsOneScansRulesTest(unittest.TestCase):
    """B2 cuts a scan into partitions; B6's counts have to survive being put back together."""

    def test_what_the_rules_did_adds_up_and_how_many_there_were_does_not(self) -> None:
        merged = store.merge_partition_diagnostics([
            {"suppression": {"rules": 2, "suppressed_findings": 3, "files_affected": 2}},
            {"suppression": {"rules": 2, "suppressed_findings": 1, "files_affected": 1}},
            {"suppression": {"rules": 2, "suppressed_findings": 0, "files_affected": 0}},
        ])
        self.assertEqual(
            merged["suppression"],
            {"rules": 2, "suppressed_findings": 4, "files_affected": 3},
            "a tenant with two rules was reported as a tenant with six",
        )

    def test_a_partition_that_saw_no_rules_does_not_lower_the_count(self) -> None:
        merged = store.merge_partition_diagnostics([
            {"suppression": {"rules": 0, "suppressed_findings": 0, "files_affected": 0}},
            {"suppression": {"rules": 3, "suppressed_findings": 2, "files_affected": 1}},
        ])
        self.assertEqual(merged["suppression"]["rules"], 3)


class APartitionedScanAppliesTheRulesEverywhereTest(unittest.TestCase):
    """The real thing: nine files, six partitions, one rule - and one answer."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.base = Path(self._temp.name)
        self.estate = self.base / "estate"
        for index in range(9):
            folder = self.estate / f"sub{index % 3}"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"f{index}.txt").write_text(
                f"card 4111 1111 1111 1111 for customer {index}\ncontact user{index}@example.com\n",
                encoding="utf-8",
            )
        self.skip = patch.object(file_scanner, "is_skipped_scan_path", return_value=False)
        self.owner = patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))
        self.skip.start()
        self.owner.start()
        self._previous_path = store.DB_PATH
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(self.base / "artifacts")})
        self._env.start()
        store.DB_PATH = self.base / "seams.sqlite"
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "seams")

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self.owner.stop()
        self.skip.stop()
        self._temp.cleanup()

    def test_every_partition_applies_the_rule_and_the_scan_reports_one_set(self) -> None:
        store.create_suppression_rule(self.tenant, finding_type="credit_card",
                                      reason="synthetic estate", created_by="ana")
        config = ScanConfig(
            tenant_id=self.tenant,
            local_path=str(self.estate),
            use_sample_when_empty=True,
            persistent_cache_enabled=False,
            incremental_enabled=False,
            max_workers=1,
            cache_dir=str(self.base / "cache"),
            suppression_rules=store.suppression_rules_for_scan(self.tenant),
        )
        compact = partitioned_scan.run_partitioned_scan(self.tenant, config, max_files=2)
        report = store.read_scan_report(self.tenant, compact["scan_id"])

        types = {
            str(finding.get("type") or "")
            for file_obj in report.get("files") or []
            for finding in file_obj.get("findings") or []
        }
        diagnostics = report["scan_diagnostics"]
        self.assertGreater(diagnostics["partitioned"]["partitions"], 1, "the scan ran as one partition")
        self.assertEqual(len(report["files"]), 9, "a partition lost a file")
        self.assertNotIn("credit_card", types, "a partition reported what the tenant suppressed")
        self.assertIn("email", types, "the rule took something it was not given")
        self.assertEqual(
            diagnostics["suppression"],
            {"rules": 1, "suppressed_findings": 9, "files_affected": 9},
        )


class RetentionRemovesEventsAndNeverPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.base = Path(self._dir.name)
        self._previous_path = store.DB_PATH
        store.DB_PATH = self.base / "retention.sqlite"
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(self.base / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "retention seam")
        self.now = datetime(2026, 9, 17, 3, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def test_a_sweep_takes_the_old_events_and_leaves_the_rules(self) -> None:
        rule = store.create_suppression_rule(self.tenant, finding_type="credit_card",
                                             reason="older than any retention window", created_by="ana")
        with store._connect() as conn:
            conn.execute(
                "INSERT INTO audit_events (tenant_id, actor, action, detail_json, timestamp) VALUES (?, ?, ?, ?, ?)",
                (self.tenant, "ana", "scan.completed", "{}", (self.now - timedelta(days=900)).isoformat()),
            )

        results = store.prune_event_tables(now=self.now, apply=True, overrides={"audit_events": 30})

        self.assertTrue(any(item["data_class"] == "audit_events" and item["removed_rows"] for item in results),
                        "the sweep removed no event at all, so it proves nothing about the rule")
        self.assertIsNotNone(store.get_suppression_rule(self.tenant, rule["rule_id"]),
                             "retention deleted a decision somebody made")
        self.assertTrue(store.suppression_rules_for_scan(self.tenant), "the next scan lost its rules to a timer")


if __name__ == "__main__":
    unittest.main()
