"""Canonical remediation counts, current scope and bounded paging regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend import store


def _finding(index: int, *, frameworks=None, occurrences: int = 1) -> dict:
    return {
        "finding_id": f"finding_metric_{index:05d}",
        "type": f"detector_{index:05d}",
        "display_name": f"Metric finding {index}",
        "status": "OPEN",
        "risk": {"level": "HIGH", "score": 80},
        "frameworks": frameworks or ["GDPR"],
        "occurrence_count": occurrences,
    }


def _file(index: int, findings: list[dict]) -> dict:
    return {
        "path": f"/metrics/file_{index:05d}.txt",
        "name": f"file_{index:05d}.txt",
        "source": "local",
        "risk": {"level": "HIGH", "score": 80},
        "findings": findings,
    }


def _report(scan_id: str, files: list[dict], *, label: str = "Metrics scope") -> dict:
    return {
        "scan_id": scan_id,
        "timestamp": "2026-09-04T12:00:00+00:00",
        "source": "local",
        "scan_label": label,
        "summary": {"total_files": len(files)},
        "files": files,
    }


class RemediationMetricsPaginationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "remediation.sqlite"
        store.init_db()
        self.tenant_id = "tenant_remediation_metrics"
        store.create_tenant(self.tenant_id, "Metrics Tenant")

    def tearDown(self) -> None:
        store.DB_PATH = self.original_db
        self.temp_dir.cleanup()

    def test_file_finding_and_occurrence_counts_are_distinct(self) -> None:
        findings = [_finding(index, occurrences=index + 1) for index in range(5)]
        store.save_scan_history(self.tenant_id, _report("metric-a", [_file(1, findings)]))

        summary = store.remediation_summary(self.tenant_id)

        self.assertEqual(summary["affected_files"], 1)
        self.assertEqual(summary["total_findings"], 5)
        self.assertEqual(summary["open"], 5)
        self.assertEqual(summary["total_occurrences"], 15)

    def test_exact_total_is_independent_of_page_size_and_old_cap(self) -> None:
        findings = [_finding(index) for index in range(1248)]
        store.save_scan_history(self.tenant_id, _report("metric-b", [_file(1, findings)]))

        page = store.list_remediation_findings(self.tenant_id, limit=50)

        self.assertEqual(len(page["items"]), 50)
        self.assertEqual(page["total"], 1248)
        self.assertTrue(page["has_more"])
        self.assertTrue(page["next_cursor"])
        self.assertEqual(page["summary"]["open"], 1248)
        self.assertNotEqual(page["total"], len(page["items"]))
        self.assertGreater(page["total"], 1000)

        second = store.list_remediation_findings(
            self.tenant_id, limit=50, after=page["next_cursor"]
        )
        self.assertEqual(len(second["items"]), 50)
        self.assertTrue(
            {item["finding_id"] for item in page["items"]}.isdisjoint(
                {item["finding_id"] for item in second["items"]}
            )
        )

    def test_missing_finding_moves_out_of_current_scope(self) -> None:
        store.save_scan_history(
            self.tenant_id,
            _report("metric-history-1", [_file(1, [_finding(1)])], label="Authoritative HR"),
        )
        store.save_scan_history(
            self.tenant_id,
            _report("metric-history-2", [], label="Authoritative HR"),
        )

        current = store.list_remediation_findings(
            self.tenant_id, scope="current", status="all", limit=50
        )
        historical = store.list_remediation_findings(
            self.tenant_id, scope="historical", status="all", limit=50
        )

        self.assertEqual(current["total"], 0)
        self.assertEqual(historical["total"], 1)
        self.assertEqual(historical["items"][0]["scope"], "historical")
        with self.assertRaisesRegex(ValueError, "Historical findings are read-only"):
            store.update_finding_lifecycle(
                self.tenant_id, "finding_metric_00001", "reopen", {}, "analyst"
            )

    def test_rescan_preserves_existing_assignment_state(self) -> None:
        first = _report("metric-state-1", [_file(1, [_finding(1)])], label="State scope")
        store.save_scan_history(self.tenant_id, first)
        store.update_finding_lifecycle(
            self.tenant_id,
            "finding_metric_00001",
            "assign",
            {"owner": "Security Operations"},
            "analyst",
        )
        rescanned_finding = _finding(1)
        rescanned_finding.pop("status")
        second = _report("metric-state-2", [_file(1, [rescanned_finding])], label="State scope")
        store.save_scan_history(self.tenant_id, second)

        page = store.list_remediation_findings(self.tenant_id, status="all")
        detail = store.get_finding(self.tenant_id, "finding_metric_00001")

        self.assertEqual(page["items"][0]["status"], "ASSIGNED")
        self.assertEqual(page["items"][0]["owner"], "Security Operations")
        self.assertEqual(detail["status"], "ASSIGNED")
        self.assertEqual(detail["owner"], "Security Operations")

    def test_framework_facets_count_unique_current_files(self) -> None:
        files = [_file(index, [_finding(index, frameworks=["GDPR"])]) for index in range(463)]
        store.save_scan_history(self.tenant_id, _report("metric-gdpr", files))

        facets = store.inventory_facets(self.tenant_id)
        gdpr = next(item for item in facets["frameworks"] if item["value"] == "gdpr")

        self.assertEqual(facets["total"], 463)
        self.assertEqual(gdpr["file_count"], 463)
        self.assertEqual(gdpr["count"], 463)

    def test_one_file_can_count_once_in_multiple_frameworks(self) -> None:
        store.save_scan_history(
            self.tenant_id,
            _report("metric-multi", [_file(1, [_finding(1, frameworks=["GDPR", "NIST"])])]),
        )

        facets = store.inventory_facets(self.tenant_id)
        framework_files = {item["value"]: item["file_count"] for item in facets["frameworks"]}

        self.assertEqual(facets["total"], 1)
        self.assertEqual(framework_files["gdpr"], 1)
        self.assertEqual(framework_files["nist_sp800_60_enterprise"], 1)


class RemediationFrontendDataFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = Path("frontend/app.js").read_text(encoding="utf-8")

    def test_initial_queue_is_bounded_and_never_counts_page_rows(self) -> None:
        self.assertIn("const REMEDIATION_PAGE_SIZE = 50", self.script)
        self.assertIn("Array.isArray(data?.items)", self.script)
        self.assertIn("Number(data?.total || 0)", self.script)
        self.assertIn("Number(remediationSummary.open || 0)", self.script)
        self.assertNotIn("/api/findings?limit=1000", self.script)
        self.assertNotIn("filteredRemediationFindings", self.script)

    def test_search_is_debounced_abortable_and_server_filtered(self) -> None:
        self.assertIn("debounce(() =>", self.script)
        self.assertIn("}, 300)", self.script)
        self.assertIn("remediationListAbortController?.abort()", self.script)
        self.assertIn("signal: remediationListAbortController.signal", self.script)
        for parameter in ("owner", "framework", "data_type", "asset", "sla"):
            self.assertIn(f'["{parameter}",', self.script)
        # Severity is the inventory's pill row now, so it comes from state
        # rather than off a select - but it still goes to the server.
        self.assertIn('params.set("severity", remediationSeverityChoice)', self.script)
        self.assertIn('params.set("sort", remediationSortKey)', self.script)

    def test_windowed_dashboard_uses_inventory_facets_not_preview_files(self) -> None:
        start = self.script.index("function frameworkBreakdown()")
        body = self.script[start:self.script.index("function buildStack", start)]
        self.assertIn("estateFacets.frameworks", body)
        self.assertIn("file_count", body)
        self.assertNotIn("latestFiles", body)

    def test_drawer_details_remain_lazy(self) -> None:
        start = self.script.index("async function openRemediationFinding")
        body = self.script[start:self.script.index("function remediationFindingById", start)]
        self.assertIn("/history", body)
        self.assertIn("/occurrences", body)
        initial = self.script[self.script.index("async function loadRemediationFindings"):start]
        self.assertNotIn("/history", initial)
        self.assertNotIn("/occurrences", initial)


if __name__ == "__main__":
    unittest.main()
