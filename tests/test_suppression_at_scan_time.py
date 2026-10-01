"""B6: a rule is applied where the scan emits, so the finding is never created again.

The gate: a finding dismissed as a false positive, turned into a rule, is not recreated
by the next scan. This is the engine half of it - the rule reaches the analysis, the
finding does not reach the report, and the estate therefore has nothing to dismiss.

Two things this must not break, and both are tested here:

- the findings cache keeps what the **detectors** found, not what the rules allowed
  through, so withdrawing a rule brings the finding back without re-reading the file;
- a rule written or withdrawn changes the reuse version signature, so an unchanged file
  cannot replay the findings of the previous policy.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

PAN = "4111 1111 1111 1111"


def _record(path: str = r"C:\Data\customers.csv", content: str = f"card {PAN} on file") -> dict:
    return {
        "source": "local",
        "share": "local",
        "path": path,
        "name": Path(path).name,
        "size": len(content),
        "extension": ".csv",
        "modified_at": "2026-09-01T00:00:00Z",
        "content": content,
    }


class ARuleAppliesWhereTheScanEmitsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.cache_dir = str(Path(self._dir.name) / "cache")
        self._env = mock.patch.dict(os.environ, {"DSPM_SCAN_CACHE_DIR": self.cache_dir})
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self._dir.cleanup()

    def _engine(self, rules: list[dict] | None = None, *, cache: bool = False) -> DSPMDiscoveryEngine:
        return DSPMDiscoveryEngine(
            ScanConfig(
                tenant_id="tenant-b6",
                walk_local_path=False,
                incremental_enabled=False,
                persistent_cache_enabled=cache,
                cache_dir=self.cache_dir,
                suppression_rules=rules or [],
            )
        )

    def _types(self, analyzed: dict) -> set[str]:
        return {str(finding.get("type") or "") for finding in analyzed.get("findings") or []}

    def test_without_a_rule_the_file_reports_its_card_number(self) -> None:
        analyzed = self._engine()._analyze_record(_record())
        self.assertIn("credit_card", self._types(analyzed), "the fixture has to find something to suppress")

    def test_a_rule_keeps_the_finding_out_of_the_scan(self) -> None:
        engine = self._engine([
            {"rule_id": "sup_a", "finding_type": "credit_card", "path_pattern": r"C:\Data\*", "active": True},
        ])
        analyzed = engine._analyze_record(_record())

        self.assertNotIn("credit_card", self._types(analyzed), "the rule did not reach the analysis")
        self.assertEqual(analyzed.get("suppressed_findings"), [{"type": "credit_card", "rule_id": "sup_a"}],
                         "a scan that reported less than it found must say so")
        engine._finalize_incremental_diagnostics([analyzed])
        self.assertEqual(
            engine.last_scan_diagnostics["suppression"],
            {"rules": 1, "suppressed_findings": 1, "files_affected": 1},
        )

    def test_a_rule_for_another_folder_leaves_this_file_alone(self) -> None:
        engine = self._engine([
            {"rule_id": "sup_a", "finding_type": "credit_card", "path_pattern": r"D:\Elsewhere\*", "active": True},
        ])
        analyzed = engine._analyze_record(_record())
        self.assertIn("credit_card", self._types(analyzed))
        self.assertNotIn("suppressed_findings", analyzed)

    def test_the_risk_of_a_file_follows_what_it_reports(self) -> None:
        rules = [{"rule_id": "sup_a", "finding_type": "credit_card", "active": True}]
        reported = self._engine()._analyze_record(_record())
        suppressed = self._engine(rules)._analyze_record(_record())
        self.assertGreater(reported["risk"]["score"], suppressed["risk"]["score"],
                           "a file whose only finding is suppressed still scored as if it had one")

    def test_withdrawing_a_rule_brings_the_finding_back_without_re_reading(self) -> None:
        rules = [{"rule_id": "sup_a", "finding_type": "credit_card", "active": True}]
        record = _record()
        suppressed = self._engine(rules, cache=True)._analyze_record(dict(record))
        self.assertNotIn("credit_card", self._types(suppressed))

        # Same cache directory, no rules: the detectors are not run again - the cache
        # kept what they found - and the finding is reported.
        again = self._engine(cache=True)._analyze_record(dict(record))
        self.assertIn("credit_card", self._types(again))
        self.assertTrue(again["detector_metrics"]["cache_hit"],
                        "the cache stored the filtered result, so withdrawing a rule costs a re-read")

    def test_a_rule_changes_what_may_be_reused(self) -> None:
        plain = self._engine().version_signature()
        ruled = self._engine([{"rule_id": "sup_a", "finding_type": "credit_card", "active": True}]).version_signature()
        other = self._engine([{"rule_id": "sup_b", "finding_type": "email", "active": True}]).version_signature()
        self.assertNotEqual(plain, ruled, "an unchanged file would have replayed the old policy")
        self.assertNotEqual(ruled, other)
        self.assertEqual(plain, self._engine([]).version_signature())

    def test_an_inactive_rule_is_not_carried_by_the_scan(self) -> None:
        engine = self._engine([{"rule_id": "sup_a", "finding_type": "credit_card", "active": False}])
        self.assertFalse(engine._suppression)
        self.assertIn("credit_card", self._types(engine._analyze_record(_record())))
        self.assertEqual(engine.version_signature(), self._engine().version_signature(),
                         "a rule that covers nothing must not invalidate the estate's reuse")

    def test_a_replayed_record_is_filtered_too(self) -> None:
        """The belt to the version signature's brace: a replay never smuggles a covered finding."""
        engine = self._engine([{"rule_id": "sup_a", "finding_type": "credit_card", "active": True}])
        baseline = {
            "path": r"C:\Data\customers.csv",
            "findings": [{"type": "credit_card", "secure_value_fingerprints": ["fp-1"]}],
            "risk": {"score": 90, "level": "HIGH"},
        }
        record = dict(_record(), incremental_reused=True, baseline_result=baseline)
        analyzed = engine._analyze_record(record)
        self.assertEqual(analyzed.get("findings"), [], "a reused record replayed a suppressed finding")


if __name__ == "__main__":
    unittest.main()
