from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping


SEVERITY_WEIGHTS = {
    "critical": 8,
    "high": 4,
    "medium": 1.5,
    "low": 0.5,
}


@dataclass(frozen=True)
class PostureBreakdown:
    finding_score: int
    remediation_score: int
    exposure_score: int
    trend_score: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class PostureScore:
    total_score: int
    grade: str
    breakdown: PostureBreakdown
    trend_direction: str
    summary_en: str
    summary_az: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["breakdown"] = self.breakdown.to_dict()
        return data


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _severity_count(counts: Mapping[str, int | float], severity: str) -> float:
    return float(counts.get(severity, counts.get(severity.upper(), 0)) or 0)


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


def compute_posture_score(
    findings_by_severity: Mapping[str, int | float] | None,
    total_assets: int,
    exposed_assets: int,
    remediated_count: int,
    total_actionable: int,
    previous_score: int | float | None = None,
) -> PostureScore:
    """Compute a deterministic 0-100 DSPM posture score.

    Formula:
    - Finding risk: 40 points, reduced by weighted severity pressure.
    - Remediation progress: 25 points, proportional to remediated/actionable items.
    - Exposure: 20 points, reduced by exposed asset ratio.
    - Trend: 15 points, derived from previous score when available; neutral when absent.
    """

    counts = findings_by_severity or {}
    critical = _severity_count(counts, "critical")
    high = _severity_count(counts, "high")
    medium = _severity_count(counts, "medium")
    low = _severity_count(counts, "low")

    safe_total_assets = max(0, int(total_assets or 0))
    safe_exposed_assets = max(0, int(exposed_assets or 0))
    safe_total_actionable = max(0, int(total_actionable or 0))
    safe_remediated = max(0, min(int(remediated_count or 0), safe_total_actionable))

    weighted_findings = (
        critical * SEVERITY_WEIGHTS["critical"]
        + high * SEVERITY_WEIGHTS["high"]
        + medium * SEVERITY_WEIGHTS["medium"]
        + low * SEVERITY_WEIGHTS["low"]
    )
    finding_score = round(_clamp(40 - weighted_findings, 0, 40))

    if safe_total_actionable == 0:
        remediation_score = 25
    else:
        remediation_score = round(_clamp((safe_remediated / safe_total_actionable) * 25, 0, 25))

    if safe_total_assets == 0:
        exposure_score = 20
    else:
        exposure_ratio = _clamp(safe_exposed_assets / safe_total_assets, 0, 1)
        exposure_score = round(_clamp(20 - (exposure_ratio * 20), 0, 20))

    if previous_score is None:
        trend_score = 15
    else:
        delta = _clamp(float(previous_score) - (finding_score + remediation_score + exposure_score), -30, 30)
        trend_score = round(_clamp(15 - (delta / 2), 0, 15))

    total = int(_clamp(finding_score + remediation_score + exposure_score + trend_score, 0, 100))
    grade = _grade(total)
    trend = _trend_direction(total, previous_score)

    summary_en = (
        f"DSPM posture score is {total}/100 (grade {grade}). "
        f"Critical findings: {int(critical)}, high findings: {int(high)}, exposed assets: {safe_exposed_assets}."
    )
    summary_az = (
        f"DSPM təhlükəsizlik balı {total}/100-dür (dərəcə {grade}). "
        f"kritik tapıntı: {int(critical)}, yüksək riskli tapıntı: {int(high)}, açıq aktiv: {safe_exposed_assets}."
    )

    return PostureScore(
        total_score=total,
        grade=grade,
        breakdown=PostureBreakdown(
            finding_score=int(finding_score),
            remediation_score=int(remediation_score),
            exposure_score=int(exposure_score),
            trend_score=int(trend_score),
        ),
        trend_direction=trend,
        summary_en=summary_en,
        summary_az=summary_az,
    )
