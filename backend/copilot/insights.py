from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class InsightSeverity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    SUCCESS = "success"


class InsightType(str, Enum):
    NEW_CRITICAL = "new_critical"
    POSTURE_DRIFT = "posture_drift"
    EXPOSURE_SPIKE = "exposure_spike"
    REMEDIATION_STALE = "remediation_stale"
    SCAN_COMPLETE = "scan_complete"
    MILESTONE = "milestone"


@dataclass
class InsightCard:
    insight_id: str
    insight_type: InsightType
    severity: InsightSeverity
    title_en: str
    title_az: str
    body_en: str
    body_az: str
    created_at: str
    action_label_en: str | None = None
    action_label_az: str | None = None
    action_query: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    dismissed: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["insight_type"] = self.insight_type.value
        data["severity"] = self.severity.value
        return data


def _severity_counts(scan: dict) -> dict[str, int]:
    raw = scan.get("findings_by_severity") or {}
    return {
        "critical": int(raw.get("critical", raw.get("CRITICAL", 0)) or 0),
        "high": int(raw.get("high", raw.get("HIGH", 0)) or 0),
        "medium": int(raw.get("medium", raw.get("MEDIUM", 0)) or 0),
        "low": int(raw.get("low", raw.get("LOW", 0)) or 0),
    }


def _plural(value: int, singular: str, plural: str) -> str:
    return singular if value == 1 else plural


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_insights(
    current_scan: dict,
    previous_scan: dict | None,
    current_posture_score: int,
    previous_posture_score: int | None,
) -> list[InsightCard]:
    insights: list[InsightCard] = []
    now = _now()
    scan_id = str(current_scan.get("scan_id") or "")
    curr_sev = _severity_counts(current_scan)
    curr_critical = curr_sev["critical"]
    curr_high = curr_sev["high"]

    if previous_scan:
        prev_sev = _severity_counts(previous_scan)
        prev_critical = prev_sev["critical"]
        new_critical = curr_critical - prev_critical
        if new_critical > 0:
            insights.append(
                InsightCard(
                    insight_id=f"new_critical_{scan_id}",
                    insight_type=InsightType.NEW_CRITICAL,
                    severity=InsightSeverity.CRITICAL,
                    title_en=f"{new_critical} New Critical {_plural(new_critical, 'Finding', 'Findings')}",
                    title_az=f"{new_critical} yeni kritik tapıntı",
                    body_en=f"{new_critical} new critical {_plural(new_critical, 'finding was', 'findings were')} detected since the last scan. Immediate review is recommended.",
                    body_az=f"Son skandan bəri {new_critical} yeni kritik tapıntı aşkar edilib. Dərhal nəzərdən keçirmək tövsiyə olunur.",
                    created_at=now,
                    action_label_en="View critical findings",
                    action_label_az="Kritik tapıntılara bax",
                    action_query="show me new critical findings",
                    metadata={"new_count": new_critical, "previous_count": prev_critical, "current_count": curr_critical},
                )
            )
    elif curr_critical > 0:
        insights.append(
            InsightCard(
                insight_id=f"initial_critical_{scan_id}",
                insight_type=InsightType.NEW_CRITICAL,
                severity=InsightSeverity.CRITICAL,
                title_en=f"{curr_critical} Critical {_plural(curr_critical, 'Finding', 'Findings')} Detected",
                title_az=f"{curr_critical} kritik tapıntı aşkar edilib",
                body_en=f"Initial scan found {curr_critical} critical {_plural(curr_critical, 'finding', 'findings')}. Review and remediate immediately.",
                body_az=f"İlk scan {curr_critical} kritik tapıntı aşkar etdi. Dərhal nəzərdən keçirin və düzəldin.",
                created_at=now,
                action_label_en="View critical findings",
                action_label_az="Kritik tapıntılara bax",
                action_query="list critical findings",
                metadata={"count": curr_critical},
            )
        )

    if previous_posture_score is not None:
        drift = int(current_posture_score) - int(previous_posture_score)
        if abs(drift) >= 10:
            if drift < 0:
                insights.append(
                    InsightCard(
                        insight_id=f"posture_drop_{scan_id}",
                        insight_type=InsightType.POSTURE_DRIFT,
                        severity=InsightSeverity.WARNING,
                        title_en=f"Posture Score Dropped by {abs(drift)} Points",
                        title_az=f"Təhlükəsizlik balı {abs(drift)} xal azalıb",
                        body_en=f"Your posture score dropped from {previous_posture_score} to {current_posture_score}. Investigate recent changes.",
                        body_az=f"Təhlükəsizlik balınız {previous_posture_score}-dən {current_posture_score}-ə düşüb. Son dəyişiklikləri araşdırın.",
                        created_at=now,
                        action_label_en="View posture details",
                        action_label_az="Posture detallarına bax",
                        action_query="show my posture score breakdown",
                        metadata={"previous": previous_posture_score, "current": current_posture_score, "drift": drift},
                    )
                )
            else:
                insights.append(
                    InsightCard(
                        insight_id=f"posture_improve_{scan_id}",
                        insight_type=InsightType.POSTURE_DRIFT,
                        severity=InsightSeverity.SUCCESS,
                        title_en=f"Posture Score Improved by {abs(drift)} Points",
                        title_az=f"Təhlükəsizlik balı {abs(drift)} xal yaxşılaşıb",
                        body_en=f"Your posture score improved from {previous_posture_score} to {current_posture_score}. Keep validating remediation in future scans.",
                        body_az=f"Təhlükəsizlik balınız {previous_posture_score}-dən {current_posture_score}-ə yüksəlib. Növbəti scan-larda remediation nəticələrini yoxlamağa davam edin.",
                        created_at=now,
                        metadata={"previous": previous_posture_score, "current": current_posture_score, "drift": drift},
                    )
                )

    if curr_critical == 0 and previous_scan:
        prev_critical = _severity_counts(previous_scan)["critical"]
        if prev_critical > 0:
            insights.append(
                InsightCard(
                    insight_id=f"milestone_zero_critical_{scan_id}",
                    insight_type=InsightType.MILESTONE,
                    severity=InsightSeverity.SUCCESS,
                    title_en="Zero Critical Findings!",
                    title_az="Sıfır kritik tapıntı!",
                    body_en=f"All {prev_critical} critical {_plural(prev_critical, 'finding', 'findings')} from the previous scan have been resolved or no longer appear in this scan.",
                    body_az=f"Əvvəlki scandakı {prev_critical} kritik tapıntının hamısı bu scanda artıq görünmür.",
                    created_at=now,
                    metadata={"previous_critical": prev_critical},
                )
            )

    total = curr_critical + curr_high + curr_sev["medium"] + curr_sev["low"]
    insights.append(
        InsightCard(
            insight_id=f"scan_complete_{scan_id}",
            insight_type=InsightType.SCAN_COMPLETE,
            severity=InsightSeverity.INFO,
            title_en="Scan Complete",
            title_az="Scan tamamlandı",
            body_en=f"Scan finished: {total} total findings ({curr_critical} critical, {curr_high} high). Posture score: {current_posture_score}/100.",
            body_az=f"Scan tamamlandı: {total} ümumi tapıntı ({curr_critical} kritik, {curr_high} yüksək). Təhlükəsizlik balı: {current_posture_score}/100.",
            created_at=now,
            action_label_en="View full report",
            action_label_az="Tam hesabata bax",
            action_query="show scan summary",
            metadata={"total": total, "critical": curr_critical, "high": curr_high, "posture_score": current_posture_score},
        )
    )

    severity_order = {"critical": 0, "warning": 1, "info": 2, "success": 3}
    insights.sort(key=lambda item: severity_order.get(item.severity.value, 99))
    return insights
