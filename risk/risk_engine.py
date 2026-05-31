from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


FILENAME_KEYWORDS = {
    "access",
    "admin",
    "backup",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "creds",
    "confidential",
    "contract",
    "customer",
    "database",
    "db",
    "export",
    "salary",
    "finance",
    "invoice",
    "legal",
    "payroll",
    "hr",
    "vpn",
}

EXTENSION_RISK = {
    ".env": 25,
    ".pem": 25,
    ".key": 25,
    ".p12": 25,
    ".pfx": 25,
    ".kdbx": 25,
    ".bak": 20,
    ".sql": 20,
    ".sqlite": 20,
    ".db": 20,
    ".dump": 20,
    ".zip": 15,
    ".rar": 15,
    ".7z": 15,
    ".tar": 15,
    ".gz": 15,
    ".pst": 15,
    ".ost": 15,
    ".log": 10,
    ".txt": 10,
    ".csv": 10,
    ".tsv": 10,
    ".xlsx": 10,
    ".xls": 10,
    ".docx": 10,
    ".doc": 10,
    ".pdf": 10,
    ".json": 10,
    ".xml": 10,
    ".yaml": 10,
    ".yml": 10,
}

FINDING_WEIGHTS = {
    "CRITICAL": 45,
    "HIGH": 35,
    "MEDIUM": 20,
    "LOW": 5,
}

RISK_RULE_DESCRIPTIONS = [
    {
        "signal": "Private keys, cloud access keys, JWTs",
        "base_risk": "CRITICAL",
        "score": "Minimum 90",
        "reason": "Secrets that authenticate systems or cloud accounts can cause immediate compromise if copied from a share.",
        "dlp_action": "Quarantine, rotate the secret, and alert the security owner.",
    },
    {
        "signal": "SaaS and developer tokens",
        "base_risk": "CRITICAL",
        "score": "Minimum 90",
        "reason": "GitHub, Slack, Google, Azure, and source-code secret tokens can expose production systems or collaboration data.",
        "dlp_action": "Block movement, rotate the token, and create a security incident task.",
    },
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
        "signal": "IBAN, SWIFT, passport, national ID",
        "base_risk": "HIGH",
        "score": "+35",
        "reason": "Financial and government identifiers increase regulatory exposure and require evidence-backed access control.",
        "dlp_action": "Apply regulated-data label, restrict sharing, and require owner attestation.",
    },
    {
        "signal": "Confidential keywords",
        "base_risk": "MEDIUM",
        "score": "+20",
        "reason": "Business-sensitive labels indicate documents that should be reviewed before broad access.",
        "dlp_action": "Apply warning, classification label, or owner review workflow.",
    },
    {
        "signal": "HR, legal, customer, finance, PHI context",
        "base_risk": "MEDIUM-HIGH",
        "score": "+20 to +35",
        "reason": "Context classifiers identify regulated business domains even when the file has few explicit identifiers.",
        "dlp_action": "Route to the correct data owner and tune policies by business domain.",
    },
    {
        "signal": "Sensitive filename/path",
        "base_risk": "MEDIUM",
        "score": "+15",
        "reason": "Names like password, backup, finance, HR, contract, database, salary, secret, or credential often reveal high-value files.",
        "dlp_action": "Add filename and path conditions to DLP policies.",
    },
    {
        "signal": "Risky file extension",
        "base_risk": "LOW-MEDIUM",
        "score": "+10 to +25",
        "reason": "Secrets, backups, databases, archives, mailboxes, office documents, structured exports, and logs often need deeper inspection.",
        "dlp_action": "Increase inspection depth for these extensions.",
    },
    {
        "signal": "MSSP asset override",
        "base_risk": "Manual",
        "score": "Forced level",
        "reason": "Every customer has different crown-jewel assets, so analysts can manually raise or lower risk for matching asset names or paths.",
        "dlp_action": "Use customer-specific context before creating or tuning DLP policy.",
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
    remediation: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
            "dlp_recommendations": self.dlp_recommendations,
            "remediation": self.remediation,
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

    override = _match_asset_override(file_obj)
    if override:
        level = override["level"]
        score = _score_for_level(level)
        reasons.insert(0, f"MSSP asset override: {override['reason']}")
        recommendations.insert(0, "Validate this customer-specific asset classification with the data owner")

    if not recommendations and score > 0:
        recommendations.append("Monitor this file class and validate business ownership")

    return RiskAssessment(
        score=score,
        level=level,
        reasons=_dedupe(reasons) or ["No sensitive signal detected"],
        dlp_recommendations=_dedupe(recommendations),
        remediation=_build_remediation(level, score, file_obj, findings, acl_assessment),
    )


def get_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _score_for_level(level: str) -> int:
    return {
        "CRITICAL": 95,
        "HIGH": 80,
        "MEDIUM": 55,
        "LOW": 20,
    }.get(level, 20)


def _match_asset_override(file_obj: dict) -> dict | None:
    path = str(file_obj.get("path", "")).lower()
    name = str(file_obj.get("name", "")).lower()
    signals = " ".join(str(item).lower() for item in file_obj.get("finding_signals") or [])

    for override in file_obj.get("asset_overrides") or []:
        pattern = str(override.get("pattern", "")).strip().lower()
        level = str(override.get("level", "")).strip().upper()
        if not pattern or level not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            continue
        if pattern in path or pattern in name or pattern in signals:
            return {
                "level": level,
                "reason": override.get("reason") or f"{pattern} is marked as {level}",
            }

    return None


def get_risk_rules() -> list[dict]:
    return RISK_RULE_DESCRIPTIONS


def _build_remediation(level: str, score: int, file_obj: dict, findings: list[dict], acl_assessment: dict) -> dict:
    finding_types = {str(finding.get("type", "")).lower() for finding in findings}
    has_secret = any("key" in item or "token" in item or "secret" in item or "password" in item for item in finding_types)
    has_regulated = any(item in finding_types for item in {"credit_card", "iban", "swift_bic", "passport_number", "national_id"})
    has_acl_issue = bool(acl_assessment.get("issues"))

    if level == "CRITICAL":
        sla = "24 hours"
        owner = "Security owner"
        status = "Open - urgent"
    elif level == "HIGH":
        sla = "3 business days"
        owner = "Data owner"
        status = "Open"
    elif level == "MEDIUM":
        sla = "14 days"
        owner = "Business owner"
        status = "Needs review"
    else:
        sla = "30 days"
        owner = "IT operations"
        status = "Monitor"

    actions: list[str] = []
    if has_secret:
        actions.extend(["Quarantine file copy", "Rotate exposed secret", "Invalidate tokens and review access logs"])
    if has_regulated:
        actions.extend(["Apply regulated-data label", "Restrict external sharing", "Create DLP block rule for matching identifiers"])
    if has_acl_issue:
        actions.extend(["Remove broad or writable groups", "Confirm least-privilege access with the data owner"])
    if not actions and level in {"HIGH", "CRITICAL"}:
        actions.append("Create remediation ticket and request owner attestation")
    if not actions:
        actions.append("Monitor movement and validate business ownership")

    ticket_seed = str(file_obj.get("path") or file_obj.get("name") or score).encode("utf-8", errors="ignore")
    ticket_id = int(hashlib.sha1(ticket_seed).hexdigest()[:8], 16) % 100000

    return {
        "status": status,
        "owner": owner,
        "sla": sla,
        "ticket": f"DSPM-{ticket_id:05d}",
        "actions": _dedupe(actions),
    }


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))
