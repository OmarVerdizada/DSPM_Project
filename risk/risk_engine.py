from __future__ import annotations

from dataclasses import dataclass, field


FILENAME_KEYWORDS = {
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "confidential",
    "salary",
    "finance",
    "hr",
}

EXTENSION_RISK = {
    ".env": 25,
    ".bak": 20,
    ".sql": 20,
    ".log": 10,
    ".txt": 10,
    ".csv": 10,
    ".xlsx": 10,
    ".docx": 10,
}

FINDING_WEIGHTS = {
    "CRITICAL": 45,
    "HIGH": 35,
    "MEDIUM": 20,
    "LOW": 5,
}

RISK_RULE_DESCRIPTIONS = [
    {
        "signal": "Password, token, API key, secret",
        "base_risk": "HIGH",
        "score": "Minimum 70",
        "reason": "Credentials or access tokens can directly enable account takeover or unauthorized system access.",
        "dlp_action": "Block, quarantine, or require approval before external sharing.",
    },
    {
        "signal": "Email address",
        "base_risk": "MEDIUM",
        "score": "+20",
        "reason": "Personal data can create privacy exposure when copied or shared outside approved locations.",
        "dlp_action": "Detect and alert when bulk email data leaves trusted shares.",
    },
    {
        "signal": "Credit card pattern",
        "base_risk": "HIGH",
        "score": "+35",
        "reason": "Payment data is regulated and usually requires strict handling controls.",
        "dlp_action": "Block external transfer and notify data owner.",
    },
    {
        "signal": "Confidential keywords",
        "base_risk": "MEDIUM",
        "score": "+20",
        "reason": "Business-sensitive labels indicate documents that should be reviewed before broad access.",
        "dlp_action": "Apply warning, classification label, or owner review workflow.",
    },
    {
        "signal": "Sensitive filename/path",
        "base_risk": "MEDIUM",
        "score": "+15",
        "reason": "Names like password, finance, HR, secret, salary, or credential often reveal high-value files.",
        "dlp_action": "Add filename and path conditions to DLP policies.",
    },
    {
        "signal": "Risky file extension",
        "base_risk": "LOW-MEDIUM",
        "score": "+10 to +25",
        "reason": "Files such as .env, .bak, .sql, .log, .csv, and .txt commonly contain exported data or secrets.",
        "dlp_action": "Increase inspection depth for these extensions.",
    },
    {
        "signal": "Broad or writable permissions",
        "base_risk": "MEDIUM-HIGH",
        "score": "+15 to +40",
        "reason": "Wide AD group access increases the blast radius if sensitive data exists in the share.",
        "dlp_action": "Review share ACLs and reduce access to business owners.",
    },
    {
        "signal": "SMB share exposure",
        "base_risk": "LOW",
        "score": "+5",
        "reason": "Network-share data is easier to discover, copy, or sync than isolated local files.",
        "dlp_action": "Monitor share access and file movement.",
    },
]


@dataclass(slots=True)
class RiskAssessment:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)
    dlp_recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
            "dlp_recommendations": self.dlp_recommendations,
        }


def calculate_risk(file_obj: dict, findings: list[dict] | None = None, acl_assessment: dict | None = None) -> RiskAssessment:
    findings = findings or []
    acl_assessment = acl_assessment or {}

    score = 0
    reasons: list[str] = []
    recommendations: list[str] = []

    for finding in findings:
        finding_level = str(finding.get("risk", "LOW")).upper()
        finding_type = finding.get("type", "sensitive_data")
        score += FINDING_WEIGHTS.get(finding_level, 5)
        if finding_level == "CRITICAL":
            score = max(score, 90)
        elif finding_level == "HIGH":
            score = max(score, 70)
        reasons.append(f"{finding.get('description', finding_type)} ({finding.get('count', 1)} match)")
        recommendations.append(f"Create DLP detection rule for {finding_type}")

    path = str(file_obj.get("path", "")).lower()
    extension = str(file_obj.get("extension", "")).lower()
    size = int(file_obj.get("size") or 0)

    if any(keyword in path for keyword in FILENAME_KEYWORDS):
        score += 15
        reasons.append("Sensitive keyword found in file path or name")
        recommendations.append("Add filename/path condition to DLP policy")

    extension_score = EXTENSION_RISK.get(extension, 0)
    if extension_score:
        score += extension_score
        reasons.append(f"High-value extension for data leakage review: {extension}")

    if 0 < size < 256 and findings:
        score += 10
        reasons.append("Small sensitive file may contain credentials or exported secrets")

    permission_score = int(acl_assessment.get("score", 0) or 0)
    if permission_score:
        score += permission_score
        reasons.extend(acl_assessment.get("issues", []))
        recommendations.append("Review AD group membership and share permissions")

    if file_obj.get("source") == "smb":
        score += 5
        reasons.append("Data is exposed through an SMB share")

    score = min(score, 100)
    level = get_level(score)

    if not recommendations and score > 0:
        recommendations.append("Monitor this file class and validate business ownership")

    return RiskAssessment(
        score=score,
        level=level,
        reasons=_dedupe(reasons) or ["No sensitive signal detected"],
        dlp_recommendations=_dedupe(recommendations),
    )


def get_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def get_risk_rules() -> list[dict]:
    return RISK_RULE_DESCRIPTIONS


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))
