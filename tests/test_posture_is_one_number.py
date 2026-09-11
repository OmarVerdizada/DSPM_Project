"""The posture score: one formula, density-normalised, and it adds up.

Three formulas used to compute this number and they disagreed on the same data.
The one in `backend/reporting/posture.py` had **no test coverage at all** - a
grep of tests/ for `compute_posture_score`, `PostureScore` or `finding_score`
returned nothing - which is how it kept a term that awarded 25 points for
remediation progress, scoring a fresh install 25 points down for having had
nothing to remediate yet.
"""

from __future__ import annotations

import unittest

from backend.reporting.posture import (
    PostureInputs,
    compute_posture,
    posture_from_summary,
)


def score(**kwargs) -> int:
    return compute_posture(PostureInputs(**kwargs)).total_score


class ACleanEstateScoresOneHundredTests(unittest.TestCase):
    def test_a_scanned_estate_with_no_findings_is_perfect(self) -> None:
        self.assertEqual(score(analysed_files=500), 100)

    def test_size_does_not_change_a_clean_score(self) -> None:
        self.assertEqual(score(analysed_files=2), score(analysed_files=500_000))

    def test_nothing_scanned_is_not_a_posture(self) -> None:
        """100 because no deduction applies, not because the estate is clean -
        and `measured` is how the interface tells those apart."""
        empty = compute_posture(PostureInputs())
        self.assertEqual(empty.total_score, 100)
        self.assertFalse(empty.measured)
        self.assertTrue(compute_posture(PostureInputs(analysed_files=1)).measured)


class DensityNormalisationTests(unittest.TestCase):
    """The property that stops a smaller scan flattering the score."""

    def test_the_same_finding_density_scores_the_same(self) -> None:
        small = score(analysed_files=2, findings_by_severity={"low": 1}, sensitive_files=1)
        large = score(analysed_files=500, findings_by_severity={"low": 250}, sensitive_files=250)
        self.assertLessEqual(abs(small - large), 5)

    def test_scanning_a_smaller_clean_folder_cannot_improve_the_score(self) -> None:
        """The old dashboard formula - 100 minus the mean asset risk - went UP
        when the next scan covered somewhere smaller and cleaner."""
        estate = score(analysed_files=1000, findings_by_severity={"critical": 5}, sensitive_files=5)
        half_as_many_files_same_findings = score(
            analysed_files=500, findings_by_severity={"critical": 5}, sensitive_files=5,
        )
        self.assertLess(half_as_many_files_same_findings, estate)

    def test_five_criticals_in_a_thousand_files_costs_half_the_finding_weight(self) -> None:
        """The calibration point. At the original constant the term saturated
        here, spending all 40 points before the scale said anything."""
        terms = {t.key: t.points for t in compute_posture(
            PostureInputs(analysed_files=1000, findings_by_severity={"critical": 5}, sensitive_files=5)
        ).terms}
        self.assertEqual(terms["findings"], 20)

    def test_the_term_saturates_rather_than_running_away(self) -> None:
        catastrophic = compute_posture(PostureInputs(
            analysed_files=100, findings_by_severity={"critical": 10_000},
        ))
        self.assertEqual({t.key: t.points for t in catastrophic.terms}["findings"], 40)


class TheBreakdownAddsUpTests(unittest.TestCase):
    def test_the_printed_terms_sum_to_the_printed_score(self) -> None:
        for inputs in (
            PostureInputs(analysed_files=1000, findings_by_severity={"critical": 3, "high": 9, "low": 40},
                          sensitive_files=52, exposed_sensitive_files=17,
                          active_findings=52, overdue_findings=11, uninspected_files=90),
            PostureInputs(analysed_files=7, findings_by_severity={"medium": 2}, sensitive_files=2),
            PostureInputs(analysed_files=500_000, findings_by_severity={"high": 1200},
                          sensitive_files=1200, exposed_sensitive_files=1200,
                          active_findings=1200, overdue_findings=1200, uninspected_files=250_000),
        ):
            with self.subTest(inputs=inputs):
                posture = compute_posture(inputs)
                self.assertEqual(posture.total_score, 100 - sum(t.points for t in posture.terms))

    def test_every_term_explains_itself(self) -> None:
        posture = compute_posture(PostureInputs(
            analysed_files=1000, findings_by_severity={"critical": 2}, sensitive_files=2,
            exposed_sensitive_files=1, active_findings=2, overdue_findings=1, uninspected_files=3,
        ))
        self.assertEqual([t.key for t in posture.terms], ["findings", "exposure", "remediation", "coverage"])
        for term in posture.terms:
            with self.subTest(term=term.key):
                self.assertTrue(term.detail.strip())
                self.assertLessEqual(term.points, term.max_points)

    def test_the_four_weights_are_the_whole_score(self) -> None:
        worst = compute_posture(PostureInputs(
            analysed_files=100, findings_by_severity={"critical": 10_000}, sensitive_files=100,
            exposed_sensitive_files=100, active_findings=100, overdue_findings=100, uninspected_files=100,
        ))
        self.assertEqual(worst.total_score, 0)


class AFreshInstallIsNotPunishedTests(unittest.TestCase):
    def test_having_remediated_nothing_yet_costs_nothing(self) -> None:
        """The term this replaced awarded 25 points for remediation PROGRESS, so
        a customer who had not started lost all 25."""
        terms = {t.key: t.points for t in compute_posture(PostureInputs(
            analysed_files=1000, findings_by_severity={"low": 4}, sensitive_files=4, active_findings=4,
        )).terms}
        self.assertEqual(terms["remediation"], 0)

    def test_overdue_work_is_what_costs(self) -> None:
        terms = {t.key: t.points for t in compute_posture(PostureInputs(
            analysed_files=1000, findings_by_severity={"low": 4}, sensitive_files=4,
            active_findings=4, overdue_findings=4,
        )).terms}
        self.assertEqual(terms["remediation"], 20)


class CoverageIsPartOfPostureTests(unittest.TestCase):
    def test_what_was_not_read_costs_points(self) -> None:
        read_everything = score(analysed_files=1000)
        read_half = score(analysed_files=1000, uninspected_files=500)
        self.assertGreater(read_everything, read_half)

    def test_a_scan_that_read_nothing_cannot_report_a_perfect_score(self) -> None:
        self.assertEqual(score(analysed_files=1000, uninspected_files=1000), 85)


class OneImplementationTests(unittest.TestCase):
    """The dashboard, the executive API and the report must agree."""

    def test_the_executive_api_delegates_to_the_shared_formula(self) -> None:
        from backend.app import _posture_score

        summary = {"total_files": 400, "critical": 2, "high": 5, "medium": 1, "low": 9,
                   "sensitive_files": 17, "protected_files": 3}
        self.assertEqual(_posture_score(summary), posture_from_summary(summary).total_score)

    def test_the_report_model_uses_the_same_module(self) -> None:
        from backend.reporting import report_model

        self.assertTrue(hasattr(report_model, "compute_posture_score"))

    def test_the_console_no_longer_carries_its_own_formula(self) -> None:
        """Three of the four formulas lived in frontend/app.js."""
        from pathlib import Path

        script = Path("frontend/app.js").read_text(encoding="utf-8")
        for gone in ("calculatePostureScore", "buildPostureTrend"):
            with self.subTest(symbol=gone):
                self.assertNotIn(gone, script)
        self.assertNotIn("100 - Math.round(Number(facets.avg_risk_score", script)

    def test_the_trend_arrives_already_scored(self) -> None:
        """The posture wave was a fourth formula, run per history entry."""
        from pathlib import Path

        script = Path("frontend/app.js").read_text(encoding="utf-8")
        self.assertIn("item.posture_score", script)


class EstateInputsTests(unittest.TestCase):
    def test_the_store_reports_every_input_the_formula_needs(self) -> None:
        from backend.store import posture_inputs

        inputs = posture_inputs("default")
        for key in PostureInputs.__dataclass_fields__:
            with self.subTest(key=key):
                self.assertIn(key, inputs)
        # It has to construct without a TypeError - that is the contract.
        compute_posture(PostureInputs(**inputs))


if __name__ == "__main__":
    unittest.main()
