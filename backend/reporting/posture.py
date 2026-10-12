"""One posture score, and four sentences saying where it came from.

Three formulas used to compute this number and they disagreed. The dashboard
showed `100 - mean(file risk score)`; `/api/executive-dashboard` divided a
severity-weighted sum by the file count; this module subtracted ABSOLUTE
weighted counts from 40, so five critical findings zeroed the finding term
whether the estate was five files or five hundred thousand - and then awarded 25
points for remediation progress, which is zero on a fresh install, so a customer
was punished for being new.

The score below has four properties the old ones did not:

  * a clean estate scores 100. Not 77;
  * finding pressure is measured PER THOUSAND ANALYSED FILES, so a two-file spot
    check and a half-million-file estate are on the same scale and the score
    cannot be improved by pointing the scanner at a smaller folder;
  * a fresh install is not penalised for having remediated nothing yet - the
    remediation term measures OVERDUE work, not completed work;
  * what has not been looked at costs points. A scan that could not read half
    the estate should not report a perfect score for the half it could.

Each term carries the sentence that explains it and the query that produced it,
so the number is auditable in the interface rather than asserted.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Mapping

# What one finding of each severity costs, in "critical-equivalents".
SEVERITY_WEIGHTS = {"critical": 8.0, "high": 4.0, "medium": 1.5, "low": 0.5}

# Weight of each term. They sum to 100, so a perfect estate scores 100 and the
# four contributions printed in the interface add up to the number beside them.
WEIGHT_FINDINGS = 40
WEIGHT_EXPOSURE = 25
WEIGHT_REMEDIATION = 20
WEIGHT_COVERAGE = 15

# Finding pressure saturates: the difference between a bad estate and a
# catastrophic one is not worth 40 points of resolution, and a linear term would
# let one enormous scan swamp everything else. K is set so FIVE CRITICAL
# findings per thousand analysed files - 40 critical-equivalents - costs exactly
# half the finding weight. Calibrated rather than guessed: at K = 5/ln2 the term
# saturated at five criticals in a thousand files, which spent the whole 40
# points before the scale had said anything useful.
SATURATION_K = (5.0 * SEVERITY_WEIGHTS["critical"]) / math.log(2.0)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _count(counts: Mapping[str, int | float] | None, severity: str) -> float:
    counts = counts or {}
    return float(counts.get(severity, counts.get(severity.upper(), 0)) or 0)


@dataclass(frozen=True, slots=True)
class PostureInputs:
    """Everything the score is made of, and nothing else.

    Kept separate from the arithmetic so the same numbers can come from a live
    estate query, from a saved scan report, or from a test - and produce the
    same score in all three.
    """

    analysed_files: int = 0
    findings_by_severity: Mapping[str, int | float] = field(default_factory=dict)
    sensitive_files: int = 0
    exposed_sensitive_files: int = 0
    active_findings: int = 0
    overdue_findings: int = 0
    uninspected_files: int = 0


@dataclass(frozen=True, slots=True)
class PostureTerm:
    """One subtraction, in the words an operator would use for it."""

    key: str
    label: str
    points: int
    max_points: int
    detail: str
    measured: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PostureScore:
    total_score: int
    grade: str
    terms: tuple[PostureTerm, ...]
    trend_direction: str
    summary_en: str
    summary_az: str

    @property
    def measured(self) -> bool:
        """Whether anything was actually looked at.

        An unmeasured score is 100 because no deduction applies, not because the
        estate is clean. The two are different claims and the interface has to
        be able to tell them apart.
        """
        # The finding term is the one gated on "were any files analysed", so it
        # is the one that answers this. Exposure and remediation legitimately
        # read zero on an estate that WAS scanned and came back clean.
        return any(term.measured for term in self.terms if term.key == "findings")

    @property
    def breakdown(self) -> dict:
        """The four terms as `{key: points}`, for callers that only want numbers."""
        return {term.key: term.points for term in self.terms}

    def to_dict(self) -> dict:
        return {
            "total_score": self.total_score,
            "grade": self.grade,
            "measured": self.measured,
            "terms": [term.to_dict() for term in self.terms],
            "breakdown": self.breakdown,
            "trend_direction": self.trend_direction,
            "summary_en": self.summary_en,
            "summary_az": self.summary_az,
        }


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _trend_direction(score: int, previous_score: int | float | None) -> str:
    if previous_score is None:
        return "unknown"
    delta = score - int(previous_score)
    if delta >= 5:
        return "better"
    if delta <= -5:
        return "worse"
    return "stable"


def _finding_term(inputs: PostureInputs) -> PostureTerm:
    counts = inputs.findings_by_severity
    weighted = sum(_count(counts, name) * weight for name, weight in SEVERITY_WEIGHTS.items())
    analysed = max(0, int(inputs.analysed_files or 0))
    if analysed <= 0:
        return PostureTerm(
            key="findings", label="Finding pressure", points=0, max_points=WEIGHT_FINDINGS,
            detail="No files have been analysed yet.", measured=False,
        )
    per_thousand = weighted * 1000.0 / analysed
    points = round(WEIGHT_FINDINGS * (1.0 - math.exp(-per_thousand / SATURATION_K)))
    total = int(sum(_count(counts, name) for name in SEVERITY_WEIGHTS))
    return PostureTerm(
        key="findings",
        label="Finding pressure",
        points=int(points),
        max_points=WEIGHT_FINDINGS,
        detail=(
            f"{total:,} findings across {analysed:,} analysed files "
            f"({per_thousand:.1f} critical-equivalents per 1,000 files)."
            if total
            else f"No findings across {analysed:,} analysed files."
        ),
    )


def _exposure_term(inputs: PostureInputs) -> PostureTerm:
    sensitive = max(0, int(inputs.sensitive_files or 0))
    exposed = _clamp(int(inputs.exposed_sensitive_files or 0), 0, sensitive)
    if sensitive <= 0:
        return PostureTerm(
            key="exposure", label="Exposure", points=0, max_points=WEIGHT_EXPOSURE,
            detail="No file carrying sensitive data was found, so none is exposed.",
        )
    share = exposed / sensitive
    return PostureTerm(
        key="exposure",
        label="Exposure",
        points=int(round(WEIGHT_EXPOSURE * share)),
        max_points=WEIGHT_EXPOSURE,
        detail=f"{int(exposed):,} of {sensitive:,} files with sensitive data are broadly readable.",
    )


def _remediation_term(inputs: PostureInputs) -> PostureTerm:
    active = max(0, int(inputs.active_findings or 0))
    overdue = _clamp(int(inputs.overdue_findings or 0), 0, active)
    if active <= 0:
        return PostureTerm(
            key="remediation", label="Remediation debt", points=0, max_points=WEIGHT_REMEDIATION,
            detail="Nothing is open, so nothing is overdue.",
        )
    share = overdue / active
    return PostureTerm(
        key="remediation",
        label="Remediation debt",
        points=int(round(WEIGHT_REMEDIATION * share)),
        max_points=WEIGHT_REMEDIATION,
        detail=(
            f"{int(overdue):,} of {active:,} open findings are past their SLA."
            if overdue
            else f"None of the {active:,} open findings is past its SLA yet."
        ),
    )


def _coverage_term(inputs: PostureInputs) -> PostureTerm:
    analysed = max(0, int(inputs.analysed_files or 0))
    uninspected = _clamp(int(inputs.uninspected_files or 0), 0, analysed)
    if analysed <= 0:
        # Nothing scanned is not a bad posture, it is an ABSENT one. Charging
        # the coverage gap here made a brand-new tenant open at 85/100, which
        # says "we looked and it is nearly fine" about an estate nobody has
        # looked at. `PostureScore.measured` is how the interface says so.
        return PostureTerm(
            key="coverage", label="Coverage gap", points=0, max_points=WEIGHT_COVERAGE,
            detail="Nothing has been scanned yet.", measured=False,
        )
    share = uninspected / analysed
    return PostureTerm(
        key="coverage",
        label="Coverage gap",
        points=int(round(WEIGHT_COVERAGE * share)),
        max_points=WEIGHT_COVERAGE,
        detail=(
            f"{int(uninspected):,} of {analysed:,} files could not be read - sealed, "
            "an unsupported format, or a failed read."
            if uninspected
            else f"All {analysed:,} files in scope were readable."
        ),
    )


def compute_posture(inputs: PostureInputs, previous_score: int | float | None = None) -> PostureScore:
    """100 minus four explained subtractions."""

    terms = (
        _finding_term(inputs),
        _exposure_term(inputs),
        _remediation_term(inputs),
        _coverage_term(inputs),
    )
    # Round each term before summing so the four numbers printed in the
    # interface add up to the total beside them. A breakdown that does not add
    # up is worse than one point of precision.
    total = int(_clamp(100 - sum(term.points for term in terms), 0, 100))
    grade = _grade(total)
    critical = int(_count(inputs.findings_by_severity, "critical"))
    high = int(_count(inputs.findings_by_severity, "high"))
    return PostureScore(
        total_score=total,
        grade=grade,
        terms=terms,
        trend_direction=_trend_direction(total, previous_score),
        summary_en=(
            f"DSPM posture score is {total}/100 (grade {grade}). "
            f"Critical findings: {critical}, high findings: {high}, "
            f"exposed files: {int(inputs.exposed_sensitive_files or 0)}."
        ),
        summary_az=(
            f"DSPM təhlükəsizlik balı {total}/100-dür (dərəcə {grade}). "
            f"kritik tapıntı: {critical}, yüksək riskli tapıntı: {high}, "
            f"açıq aktiv: {int(inputs.exposed_sensitive_files or 0)}."
        ),
    )


def posture_from_summary(summary: Mapping[str, int | float] | None, previous_score: int | float | None = None) -> PostureScore:
    """The score for one saved scan, from the summary it stored.

    A scan report knows its own severity counts, how many files it analysed and
    how many it could not read. It does not know the estate's remediation state,
    so that term reads zero rather than guessing - which is the honest answer
    for a document about one scan.
    """

    summary = summary or {}
    counts = {name: summary.get(name, 0) for name in SEVERITY_WEIGHTS}
    return compute_posture(
        PostureInputs(
            analysed_files=int(summary.get("total_files") or 0),
            findings_by_severity=counts,
            sensitive_files=int(summary.get("sensitive_files") or 0),
            exposed_sensitive_files=int(summary.get("exposed_files") or 0),
            active_findings=0,
            overdue_findings=0,
            uninspected_files=int(summary.get("protected_files") or 0),
        ),
        previous_score,
    )


def compute_posture_score(
    findings_by_severity: Mapping[str, int | float] | None,
    total_assets: int,
    exposed_assets: int,
    remediated_count: int,
    total_actionable: int,
    previous_score: int | float | None = None,
) -> PostureScore:
    """The pre-A5 signature, kept so existing callers need no edit.

    `remediated_count` is ignored: rewarding completed work meant a fresh
    install started 25 points down for having done nothing yet. What replaced it
    measures OVERDUE work, which a caller passing these arguments does not know,
    so that term reads zero here.
    """

    counts = findings_by_severity or {}
    sensitive = int(sum(_count(counts, name) for name in SEVERITY_WEIGHTS))
    return compute_posture(
        PostureInputs(
            analysed_files=int(total_assets or 0),
            findings_by_severity=counts,
            sensitive_files=sensitive,
            exposed_sensitive_files=min(int(exposed_assets or 0), sensitive),
            active_findings=int(total_actionable or 0),
            overdue_findings=0,
            uninspected_files=0,
        ),
        previous_score,
    )
