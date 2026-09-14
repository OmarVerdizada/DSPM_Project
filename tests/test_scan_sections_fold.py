"""Every per-scan section must be computable one file at a time.

The compliance summary, the PCI, GDPR and NIST reports and the scan summary each
took the whole file list, appended to unbounded lists, and returned only a slice.
A partitioned scan has to finalize those sections from records streamed back out
of storage, so each is now an accumulator the old function loops over.

The two ways a slice can come out differently are the ordering rules, so those
are tested against the operation they replace - a stable descending sort then a
slice, and a plain slice - on data full of ties. The accumulators are then checked
for the property that matters: their internals stay bounded however many files
arrive, while every count still sees every file.
"""

from __future__ import annotations

import random
import unittest

from backend import compliance_service as service
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanSummaryAccumulator


def synthetic_files(seed: int, count: int = 400) -> list[dict]:
    """An estate dense enough to overflow every 10- and 25-item slice, with few
    distinct scores so that ties decide what survives."""
    rng = random.Random(seed)
    files = []
    for index in range(count):
        findings = []
        for _ in range(rng.randint(1, 3)):
            kind = rng.choice(["pci", "gdpr", "nist"])
            finding = {
                "risk": rng.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                "count": rng.randint(1, 15),
                "samples": [f"sample-{rng.randint(0, 4)}"],
            }
            if kind == "pci":
                finding.update(
                    framework="pci_dss", type=rng.choice(["pci_pan", "pci_track_data"]),
                    category="pci_chd", pci_category=rng.choice(["CHD", "SAD", "CONTEXT"]),
                    exception_required=rng.random() < 0.4,
                    storage_state=rng.choice(["stored", "transient"]),
                    environment=rng.choice(["production", "development"]),
                    protection_state=rng.choice(["NONE", "ENCRYPTED"]),
                    entity_role=rng.choice(["merchant", "processor"]),
                    authorization_state=rng.choice(["pre", "post"]),
                )
            elif kind == "gdpr":
                finding.update(
                    framework="gdpr", type="gdpr_email", category="pii",
                    personal_data_type=rng.choice(["email", "name", "phone"]),
                    special_category=rng.random() < 0.2,
                    retention_expired=rng.random() < 0.3,
                    lawful_basis=rng.choice(["", "contract"]),
                    processing_purpose=rng.choice(["", "billing"]),
                    data_subject_type=rng.choice(["customer", "employee"]),
                    data_residency=rng.choice(["", "EU", "US"]),
                    cross_border_transfer=rng.random() < 0.2,
                )
            else:
                finding.update(
                    framework="nist_sp800_60_enterprise", type="nist_rule",
                    rule_id=f"nist_rule_{rng.randint(1, 20)}", category_id=f"C.{rng.randint(1, 6)}",
                    source_kind=rng.choice(["keyword", "pattern"]),
                    handling_tier=rng.choice(["RESTRICTED", "INTERNAL"]),
                    product_severity=rng.choice(["LOW", "HIGH"]),
                    overall_impact=rng.choice(["LOW", "MODERATE", "HIGH"]),
                    confidence=rng.choice(["high", "low"]),
                    needs_review=rng.random() < 0.4,
                    final_risk_score=rng.choice([10, 20, 30]),
                    protection_state=rng.choice(["UNKNOWN", "ENCRYPTED"]),
                )
            findings.append(finding)
        files.append({
            "path": f"//fs01/share/dept{index % 7}/file{index}.txt",
            "name": f"file{index}.txt",
            "owner": rng.choice(["finance", "hr", "it"]),
            "permissions": {"public": rng.random() < 0.3, "wide_access": rng.random() < 0.4},
            "risk": {"level": rng.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"])},
            "is_hidden": rng.random() < 0.1,
            "findings": findings,
            "compliance": {
                "matched_frameworks": ["pci_dss", "gdpr"],
                "matched_framework_names": ["PCI DSS", "GDPR"],
                "compliance_score": rng.choice([10, 20, 30, 40]),
                "compliance_severity": rng.choice(["LOW", "HIGH"]),
                "data_categories": rng.sample(["pii", "financial_records", "customer_data"], 2),
                "relevant_controls": rng.sample(["encrypt", "restrict", "retain"], 2),
                "remediation": "Restrict access",
            },
        })
    return files


class OrderingRulesTest(unittest.TestCase):
    """The two slice rules, against the operations they replace."""

    def test_top_n_is_a_stable_descending_sort_then_a_slice(self) -> None:
        rng = random.Random(7)
        for trial in range(60):
            items = [{"score": rng.choice([1, 2, 3]), "tie": rng.choice([0, 1]), "id": index}
                     for index in range(rng.randint(0, 120))]
            for limit in (1, 3, 10, 25):
                for key in (lambda item: item["score"], lambda item: (item["score"], item["tie"])):
                    collector = service._TopN(limit, key)
                    for item in items:
                        collector.add(item)
                    expected = sorted(items, key=key, reverse=True)[:limit]
                    self.assertEqual([item["id"] for item in collector.result()],
                                     [item["id"] for item in expected],
                                     f"trial {trial}, limit {limit}")
                    self.assertEqual(collector.count, len(items))
                    self.assertLessEqual(len(collector.heap), limit)

    def test_first_n_is_a_plain_slice(self) -> None:
        for size in (0, 1, 24, 25, 26, 300):
            collector = service._FirstN(25)
            items = list(range(size))
            for item in items:
                collector.add(item)
            self.assertEqual(collector.result(), items[:25])
            self.assertEqual(collector.count, size)


class SectionsStayBoundedTest(unittest.TestCase):
    """However many files arrive, what an accumulator keeps does not grow with them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.files = synthetic_files(seed=11)

    def _feed(self, accumulator):
        for file_obj in self.files:
            accumulator.add(file_obj)
        return accumulator

    def test_the_compliance_summary(self) -> None:
        profiles = [{"id": "pci_dss", "name": "PCI DSS"}, {"id": "gdpr", "name": "GDPR"}]
        accumulator = self._feed(service.ComplianceSummaryAccumulator(profiles))
        self.assertLessEqual(len(accumulator.top_files.heap), 10)
        result = accumulator.result()
        self.assertEqual(result["affected_file_count"], len(self.files))
        self.assertEqual(len(result["top_risky_files"]), 10)
        self.assertEqual(result, service.build_compliance_summary(self.files, profiles))

    def test_the_pci_scope_summary(self) -> None:
        accumulator = self._feed(service.PciScopeSummaryAccumulator())
        result = accumulator.result()
        self.assertGreater(result["cde_candidate_count"], 25, "the estate did not overflow the PCI slice")
        self.assertGreater(result["exception_required_count"], 25)
        for collector in (accumulator.scope_candidates, accumulator.sad_retention_candidates, accumulator.exception_queue):
            self.assertLessEqual(len(collector.heap), 25)
        self.assertEqual(result, service.build_pci_scope_summary(self.files))

    def test_the_gdpr_report(self) -> None:
        accumulator = self._feed(service.GdprReportAccumulator())
        self.assertGreater(accumulator.data_subject_request_search.count, 25,
                           "the estate did not overflow the GDPR queues")
        for name in ("retention_violations", "public_exposure", "non_production_copies",
                     "lawful_basis_review_queue", "dpia_candidates", "minimization_candidates",
                     "data_subject_request_search"):
            self.assertLessEqual(len(getattr(accumulator, name).items), 25, name)
        self.assertEqual(accumulator.result(), service.build_gdpr_report(self.files))

    def test_the_nist_report(self) -> None:
        accumulator = self._feed(service.NistSp80060ReportAccumulator())
        self.assertGreater(accumulator.top_assets.count, 10, "the estate did not overflow the NIST top assets")
        self.assertGreater(accumulator.needs_review.count, 25)
        self.assertLessEqual(len(accumulator.top_assets.heap), 10)
        self.assertEqual(accumulator.result(), service.build_nist_sp800_60_report(self.files))

    def test_the_scan_summary(self) -> None:
        accumulator = ScanSummaryAccumulator()
        for file_obj in self.files:
            accumulator.add(file_obj)
        self.assertEqual(accumulator.result(), DSPMDiscoveryEngine._build_summary(self.files))
        self.assertEqual(accumulator.result().total_files, len(self.files))


if __name__ == "__main__":
    unittest.main()
