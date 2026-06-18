from __future__ import annotations

import re
from dataclasses import dataclass

from classification.ml_classifier import classify_with_ml


@dataclass(frozen=True, slots=True)
class DetectionRule:
    name: str
    pattern: re.Pattern[str]
    risk: str
    description: str
    redact: bool = True


RULES = [
    DetectionRule(
        name="private_key",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,2000}?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        risk="CRITICAL",
        description="Private cryptographic key detected",
    ),
    DetectionRule(
        name="aws_access_key",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        risk="CRITICAL",
        description="AWS access key identifier detected",
    ),
    DetectionRule(
        name="aws_secret_key",
        pattern=re.compile(r"\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[A-Za-z0-9/+=]{35,}\b", re.IGNORECASE),
        risk="CRITICAL",
        description="AWS secret access key assignment detected",
    ),
    DetectionRule(
        name="jwt",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        risk="HIGH",
        description="JSON Web Token detected",
    ),
    DetectionRule(
        name="connection_string",
        pattern=re.compile(
            r"\b(?:server|host|data source)\s*=\s*[^;\n]{2,};(?:[^;\n=]+\s*=\s*[^;\n]+;?){2,}",
            re.IGNORECASE,
        ),
        risk="HIGH",
        description="Database or service connection string detected",
    ),
    DetectionRule(
        name="azure_storage_key",
        pattern=re.compile(r"\b(?:DefaultEndpointsProtocol|AccountName|AccountKey|BlobEndpoint)\s*=\s*[^;\n]{4,}", re.IGNORECASE),
        risk="CRITICAL",
        description="Azure storage connection secret detected",
    ),
    DetectionRule(
        name="azure_sas_token",
        pattern=re.compile(r"\bsv=\d{4}-\d{2}-\d{2}&[^ \n\r]{20,}sig=[A-Za-z0-9%+/=]{20,}", re.IGNORECASE),
        risk="CRITICAL",
        description="Azure shared access signature token detected",
    ),
    DetectionRule(
        name="google_api_key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        risk="CRITICAL",
        description="Google API key detected",
    ),
    DetectionRule(
        name="gcp_service_account",
        pattern=re.compile(r"\"type\"\s*:\s*\"service_account\"[\s\S]{0,1200}?\"private_key_id\"\s*:\s*\"[a-f0-9]{16,}\"", re.IGNORECASE),
        risk="CRITICAL",
        description="Google Cloud service-account credential block detected",
    ),
    DetectionRule(
        name="slack_token",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        risk="CRITICAL",
        description="Slack token detected",
    ),
    DetectionRule(
        name="github_token",
        pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b"),
        risk="CRITICAL",
        description="GitHub access token detected",
    ),
    DetectionRule(
        name="gitlab_token",
        pattern=re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
        risk="CRITICAL",
        description="GitLab personal access token detected",
    ),
    DetectionRule(
        name="npm_token",
        pattern=re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
        risk="CRITICAL",
        description="NPM registry token detected",
    ),
    DetectionRule(
        name="stripe_key",
        pattern=re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        risk="CRITICAL",
        description="Stripe secret or restricted key detected",
    ),
    DetectionRule(
        name="sendgrid_key",
        pattern=re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
        risk="CRITICAL",
        description="SendGrid API key detected",
    ),
    DetectionRule(
        name="twilio_key",
        pattern=re.compile(r"\b(?:AC|SK)[a-f0-9]{32}\b", re.IGNORECASE),
        risk="HIGH",
        description="Twilio account or API key identifier detected",
    ),
    DetectionRule(
        name="datadog_key",
        pattern=re.compile(r"\b(?:DD_API_KEY|DD_APP_KEY|datadog[_-]?(?:api|app)[_-]?key)\s*[:=]\s*[a-f0-9]{32,40}\b", re.IGNORECASE),
        risk="HIGH",
        description="Datadog API or application key detected",
    ),
    DetectionRule(
        name="sentry_dsn",
        pattern=re.compile(r"\bhttps://[a-f0-9]{16,}@[A-Za-z0-9.-]*sentry\.io/\d+\b", re.IGNORECASE),
        risk="HIGH",
        description="Sentry DSN detected",
    ),
    DetectionRule(
        name="pagerduty_key",
        pattern=re.compile(r"\b(?:pagerduty|pd[_-]?routing[_-]?key|pd[_-]?integration[_-]?key)\s*[:=]\s*[A-Za-z0-9]{20,40}\b", re.IGNORECASE),
        risk="HIGH",
        description="PagerDuty routing or integration key detected",
    ),
    DetectionRule(
        name="splunk_token",
        pattern=re.compile(r"\b(?:splunk[_-]?token|hec[_-]?token)\s*[:=]\s*[A-Fa-f0-9-]{32,64}\b", re.IGNORECASE),
        risk="HIGH",
        description="Splunk HEC or API token detected",
    ),
    DetectionRule(
        name="newrelic_key",
        pattern=re.compile(r"\b(?:NEW_RELIC_LICENSE_KEY|newrelic[_-]?(?:license|api)[_-]?key)\s*[:=]\s*[A-Za-z0-9]{30,50}\b", re.IGNORECASE),
        risk="HIGH",
        description="New Relic license or API key detected",
    ),
    DetectionRule(
        name="okta_token",
        pattern=re.compile(r"\b(?:okta[_-]?token|SSWS)\s*[:=]?\s*[A-Za-z0-9_\-]{20,}\b", re.IGNORECASE),
        risk="HIGH",
        description="Okta API token context detected",
    ),
    DetectionRule(
        name="auth0_secret",
        pattern=re.compile(r"\b(?:auth0[_-]?client[_-]?secret|AUTH0_CLIENT_SECRET)\s*[:=]\s*[A-Za-z0-9_\-./+=]{20,}\b", re.IGNORECASE),
        risk="HIGH",
        description="Auth0 client secret detected",
    ),
    DetectionRule(
        name="email",
        pattern=re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
        risk="MEDIUM",
        description="Email address detected",
    ),
    DetectionRule(
        name="password",
        pattern=re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s'\"]+", re.IGNORECASE),
        risk="HIGH",
        description="Password-like secret detected",
    ),
    DetectionRule(
        name="api_key",
        pattern=re.compile(r"\b(?:api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_\-]{12,}", re.IGNORECASE),
        risk="HIGH",
        description="Token or API key pattern detected",
    ),
    DetectionRule(
        name="oauth_client_secret",
        pattern=re.compile(r"\b(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*[A-Za-z0-9_\-./+=]{16,}", re.IGNORECASE),
        risk="HIGH",
        description="OAuth client secret assignment detected",
    ),
    DetectionRule(
        name="bearer_token",
        pattern=re.compile(r"\bauthorization\s*[:=]\s*bearer\s+[A-Za-z0-9_\-./+=]{20,}", re.IGNORECASE),
        risk="HIGH",
        description="Bearer authorization token detected",
    ),
    DetectionRule(
        name="database_uri",
        pattern=re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|mssql|sqlserver)://[^:\s/@]+:[^@\s]+@[^ \n\r]+", re.IGNORECASE),
        risk="HIGH",
        description="Database URI with embedded credentials detected",
    ),
    DetectionRule(
        name="jdbc_connection",
        pattern=re.compile(r"\bjdbc:[a-z0-9]+://[^;\s]+(?:;[^;\n=]+\s*=\s*[^;\n]+){1,}", re.IGNORECASE),
        risk="HIGH",
        description="JDBC connection configuration detected",
    ),
    DetectionRule(
        name="basic_auth_url",
        pattern=re.compile(r"\bhttps?://[^:\s/@]{2,}:[^@\s]{4,}@[^ \n\r]+", re.IGNORECASE),
        risk="HIGH",
        description="URL containing embedded username and password detected",
    ),
    DetectionRule(
        name="docker_auth_config",
        pattern=re.compile(r"\"auths\"\s*:\s*\{[\s\S]{0,1000}?\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{20,}\"", re.IGNORECASE),
        risk="HIGH",
        description="Docker registry authentication config detected",
    ),
    DetectionRule(
        name="kubeconfig_secret",
        pattern=re.compile(r"\b(?:apiVersion:\s*v1|kind:\s*Config)[\s\S]{0,2000}?(?:client-key-data|token):\s*[A-Za-z0-9+/=._-]{20,}", re.IGNORECASE),
        risk="HIGH",
        description="Kubernetes kubeconfig credential detected",
    ),
    DetectionRule(
        name="terraform_state_secret",
        pattern=re.compile(r"\"(?:sensitive|secret|password|private_key)\"\s*:\s*(?:true|\"[^\"]{8,}\")", re.IGNORECASE),
        risk="HIGH",
        description="Terraform state or variables with sensitive material detected",
    ),
    DetectionRule(
        name="saml_private_key",
        pattern=re.compile(r"\b(?:saml|signing|idp)[\s\S]{0,500}?-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", re.IGNORECASE),
        risk="HIGH",
        description="SAML or IdP signing private key context detected",
    ),
    DetectionRule(
        name="mfa_recovery_context",
        pattern=re.compile(r"\b(?:mfa|2fa|totp|webauthn|recovery code|backup code)\b[\s\S]{0,160}?\b[A-Z0-9]{4,}(?:[-\s][A-Z0-9]{4,}){1,6}\b", re.IGNORECASE),
        risk="HIGH",
        description="MFA recovery or backup-code context detected",
    ),
    DetectionRule(
        name="credit_card",
        pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        risk="HIGH",
        description="Possible payment card number detected",
    ),
    DetectionRule(
        name="swift_bic",
        pattern=re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
        risk="HIGH",
        description="Possible SWIFT/BIC bank identifier detected",
    ),
    DetectionRule(
        name="iban",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        risk="HIGH",
        description="Possible IBAN bank account identifier detected",
    ),
    DetectionRule(
        name="passport_number",
        pattern=re.compile(r"\b(?:passport|pass\.?|pasport)\s*(?:no\.?|number|#)?\s*[:=]?\s*[A-Z0-9]{6,12}\b", re.IGNORECASE),
        risk="HIGH",
        description="Passport identifier context detected",
    ),
    DetectionRule(
        name="national_id",
        pattern=re.compile(r"\b(?:national id|tax id|tin|ssn|social security)\s*[:=]?\s*[A-Z0-9\-]{6,18}\b", re.IGNORECASE),
        risk="HIGH",
        description="Government identifier context detected",
    ),
    DetectionRule(
        name="ssn",
        pattern=re.compile(r"\b(?:ssn|social security(?: number)?)\s*[:=]?\s*\d{3}-\d{2}-\d{4}\b", re.IGNORECASE),
        risk="HIGH",
        description="US social security number context detected",
    ),
    DetectionRule(
        name="routing_account",
        pattern=re.compile(r"\b(?:routing|aba|account(?: number)?)\s*[:=]?\s*\d{8,17}\b", re.IGNORECASE),
        risk="HIGH",
        description="Bank routing or account number context detected",
    ),
    DetectionRule(
        name="employee_id",
        pattern=re.compile(r"\b(?:employee id|emp id|personnel no\.?)\s*[:=]?\s*[A-Z0-9\-]{4,16}\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Employee identifier context detected",
    ),
    DetectionRule(
        name="phone_number",
        pattern=re.compile(r"(?:\+994|0)(?:\s|-)?(?:50|51|55|70|77|99|10|12)(?:\s|-)?\d{3}(?:\s|-)?\d{2}(?:\s|-)?\d{2}\b"),
        risk="MEDIUM",
        description="Azerbaijan phone number detected",
    ),
    DetectionRule(
        name="azerbaijan_fin",
        pattern=re.compile(r"\b[A-Z0-9]{7}\b"),
        risk="MEDIUM",
        description="Possible Azerbaijan FIN-like identifier detected",
    ),
    DetectionRule(
        name="confidential_keyword",
        pattern=re.compile(r"\b(confidential|restricted|internal use only|secret|nda|non-disclosure|board only|privileged|highly confidential|need to know)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Confidentiality keyword detected",
        redact=False,
    ),
    DetectionRule(
        name="source_code_secret_context",
        pattern=re.compile(r"\b(?:client_secret|private_token|auth_token|db_password|encryption_key)\b\s*[:=]", re.IGNORECASE),
        risk="HIGH",
        description="Source-code secret assignment detected",
    ),
    DetectionRule(
        name="legal_contract_context",
        pattern=re.compile(r"\b(?:contract|statement of work|master service agreement|msa|nda|legal hold)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Legal or contract context detected",
        redact=False,
    ),
    DetectionRule(
        name="phi_context",
        pattern=re.compile(r"\b(?:patient|diagnosis|medical record|health insurance|treatment plan|clinical|prescription)\b", re.IGNORECASE),
        risk="HIGH",
        description="Healthcare or PHI context detected",
        redact=False,
    ),
    DetectionRule(
        name="payroll_context",
        pattern=re.compile(r"\b(?:payroll|salary|bonus|compensation|payslip|employee benefit|performance review|disciplinary)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="HR or payroll context detected",
        redact=False,
    ),
    DetectionRule(
        name="customer_context",
        pattern=re.compile(r"\b(?:customer list|client list|crm export|account list|support export|vendor payment|invoice register)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Customer, vendor, or commercial export context detected",
        redact=False,
    ),
    DetectionRule(
        name="board_context",
        pattern=re.compile(r"\b(?:board pack|board minutes|executive committee|exco|strategy deck|pricing strategy|forecast|merger|acquisition|due diligence)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Executive, strategy, or M&A context detected",
        redact=False,
    ),
    DetectionRule(
        name="security_ops_context",
        pattern=re.compile(r"\b(?:incident response|vulnerability|cve-\d{4}-\d+|edr export|siem export|access review|soc2|penetration test|pentest)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Security operations or vulnerability context detected",
        redact=False,
    ),
    DetectionRule(
        name="repo_archive_context",
        pattern=re.compile(r"\b(?:git bundle|repository export|source archive|\\.git/config|\\.git-credentials|repo backup)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Repository export or source archive context detected",
        redact=False,
    ),
    DetectionRule(
        name="build_log_context",
        pattern=re.compile(r"\b(?:build log|pipeline trace|ci job log|deploy log|artifact upload|runner token|release bundle)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Build, CI/CD, or artifact context detected",
        redact=False,
    ),
    DetectionRule(
        name="special_category_context",
        pattern=re.compile(r"\b(?:biometric|fingerprint|face id|facial recognition|gps|precise location|religion|political opinion|union membership|background check)\b", re.IGNORECASE),
        risk="HIGH",
        description="Special-category or high-sensitivity privacy context detected",
        redact=False,
    ),
    DetectionRule(
        name="retention_policy_context",
        pattern=re.compile(r"\b(?:retention schedule|records retention|legal hold|litigation hold|audit evidence|control testing|workpaper|access review)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Governance, retention, or audit-evidence context detected",
        redact=False,
    ),
]


def _redact(value: str) -> str:
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}***{value[-2:]}"


def classify_content(content: str) -> list[dict]:
    if not content:
        return []

    findings: list[dict] = []
    for rule in RULES:
        matches = []
        for match in rule.pattern.finditer(content):
            value = match.group(0)
            matches.append(_redact(value) if rule.redact else value)
            if len(matches) >= 10:
                break

        if not matches:
            continue

        findings.append(
            {
                "type": rule.name,
                "risk": rule.risk,
                "description": rule.description,
                "count": len(matches),
                "samples": matches,
            }
        )

    existing = {finding["type"] for finding in findings}
    for finding in classify_with_ml(content):
        if finding["type"] not in existing:
            findings.append(finding)

    return findings
