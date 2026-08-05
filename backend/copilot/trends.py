from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from backend.copilot.posture import compute_posture_score


@dataclass(frozen=True)
class TrendPoint:
    scan_id: str
    timestamp: str | None
    posture_score: int
    critical_count: int
    high_count: int
    exposed_assets: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TrendAnalysis:
    direction: str
    score_delta: int
    critical_delta: int
    points: list[TrendPoint]
    summary_en: str
    summary_az: str
    recommendations: list[str]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["points"] = [point.to_dict() for point in self.points]
        return data


def _count(scan: dict, severity: str) -> int:
    counts = scan.get("findings_by_severity") or {}
    return int(counts.get(severity, counts.get(severity.upper(), 0)) or 0)


def _direction(score_delta: int, critical_delta: int) -> str:
    if score_delta >= 5 and critical_delta <= 0:
        return "improving"
    if score_delta <= -5 or critical_delta > 0:
        return "worsening"
    return "stable"


def _recommendations(direction: str, critical_delta: int) -> list[str]:
    if direction == "improving":
        return ["Continue validating remediation in the next scan.", "Focus next on remaining critical and high findings."]
    if critical_delta > 0:
        return ["Prioritize newly introduced critical findings.", "Compare ownership and access changes between the affected scans."]
    if direction == "worsening":
        return ["Review exposure and remediation backlog before the next scan.", "Assign owners to high-risk assets."]
    return ["Monitor the next scan for drift.", "Keep remediation evidence tied to scan IDs."]


def compute_trend_analysis(scans: Iterable[dict]) -> TrendAnalysis:
    points: list[TrendPoint] = []
    previous_score: int | None = None
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        score = compute_posture_score(
            scan.get("findings_by_severity") or {},
            total_assets=int(scan.get("total_assets") or 0),
            exposed_assets=int(scan.get("exposed_assets") or 0),
            remediated_count=int(scan.get("remediated_count") or 0),
            total_actionable=int(scan.get("total_actionable") or 0),
            previous_score=previous_score,
        )
        previous_score = score.total_score
        points.append(
            TrendPoint(
                scan_id=str(scan.get("scan_id") or "unknown"),
                timestamp=scan.get("timestamp"),
                posture_score=score.total_score,
                critical_count=_count(scan, "critical"),
                high_count=_count(scan, "high"),
                exposed_assets=int(scan.get("exposed_assets") or 0),
            )
        )

    if len(points) < 2:
        summary_en = "Trend analysis needs at least two scans; only one scan is available."
        summary_az = "Trend analizi üçün ən azı iki scan lazımdır; hazırda yalnız bir scan var."
        return TrendAnalysis("unknown", 0, 0, points, summary_en, summary_az, _recommendations("unknown", 0))

    first = points[0]
    latest = points[-1]
    score_delta = latest.posture_score - first.posture_score
    critical_delta = latest.critical_count - first.critical_count
    direction = _direction(score_delta, critical_delta)
    summary_en = (
        f"Trend is {direction}: posture score changed by {score_delta} points and "
        f"critical findings changed by {critical_delta} across {len(points)} scans."
    )
    summary_az = (
        f"Trend {direction}: təhlükəsizlik balı {score_delta} bal dəyişib və "
        f"kritik tapıntı sayı {critical_delta} dəyişib ({len(points)} scan üzrə)."
    )
    return TrendAnalysis(direction, score_delta, critical_delta, points, summary_en, summary_az, _recommendations(direction, critical_delta))
