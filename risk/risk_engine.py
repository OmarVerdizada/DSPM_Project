from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


FILENAME_KEYWORDS = {
    "access",
    "admin",
    "administrator",
    "adfs",
    "audit",
    "backup",
    "bak",
    "board",
    "budget",
    "biometric",
    "client",
    "compensation",
    "cookie",
    "confidential",
    "contract",
    "customer",
    "datadog",
    "database",
    "db",
    "deal",
    "due diligence",
    "dump",
    "employee",
    "evidence",
    "export",
    "finance",
    "forecast",
    "gdpr",
    "hipaa",
    "hr",
    "incident",
    "identity",
    "invoice",
    "jira",
    "legal",
    "litigation",
    "merger",
    "mfa",
    "okta",
    "payroll",
    "pci",
    "phi",
    "pii",
    "password",
    "passwd",
    "privileged",
    "prod",
    "production",
    "recovery",
    "restricted",
    "retention",
    "salary",
    "saml",
    "secret",
    "settlement",
    "soc2",
    "sourcecode",
    "tax",
    "token",
    "webauthn",
    "vault",
    "vpn",
    "apikey",
    "api_key",
    "credential",
    "creds",
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
    ".dmp": 20,
    ".bakup": 20,
    ".backup": 20,
    ".ps1": 15,
    ".sh": 15,
    ".cmd": 15,
    ".bat": 15,
    ".config": 15,
    ".conf": 15,
    ".ini": 15,
    ".properties": 15,
    ".tfvars": 20,
    ".tfstate": 20,
    ".kubeconfig": 25,
    ".ovpn": 20,
    ".rdp": 15,
    ".har": 20,
    ".pcap": 15,
    ".pcapng": 15,
    ".saz": 15,
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
        "signal": "Private keys and certificate material",
        "base_risk": "CRITICAL",
        "score": "Minimum 90",
        "reason": "Private keys, PGP keys, SSH keys, PKCS certificates, and keystores can authenticate services, decrypt traffic, or enable lateral movement if copied from a share.",
        "dlp_action": "Quarantine the copy, rotate or revoke the key pair, open an incident, and require owner attestation before restoring access.",
        "findings": ["private_key", "certificate_private_key", "p12_pfx_keystore", "ssh_private_key"],
        "keywords": ["BEGIN PRIVATE KEY", "OPENSSH PRIVATE KEY", ".pem", ".key", ".p12", ".pfx", ".kdbx"],
        "control": "Block external transfer, alert security operations, and require encrypted vault storage for any approved exception.",
    },
    {
        "signal": "Cloud access keys and platform secrets",
        "base_risk": "CRITICAL",
        "score": "Minimum 90",
        "reason": "AWS, Azure, Google Cloud, OCI, and service-account keys can expose production infrastructure, storage buckets, pipelines, and customer data.",
        "dlp_action": "Block movement, rotate the credential, invalidate active sessions, and review cloud audit logs for use after exposure.",
        "findings": ["aws_access_key", "aws_secret_key", "azure_storage_key", "azure_sas_token", "google_api_key", "gcp_service_account"],
        "keywords": ["AKIA", "ASIA", "AccountKey", "SharedAccessSignature", "client_email", "private_key_id"],
        "control": "Create cloud-secret DLP classifiers and route confirmed matches to cloud security and platform owners.",
    },
    {
        "signal": "Developer, CI/CD, and SaaS tokens",
        "base_risk": "CRITICAL",
        "score": "Minimum 90",
        "reason": "Source-control, package-registry, messaging, payment, and CI/CD tokens can expose code, deployment pipelines, and customer-facing services.",
        "dlp_action": "Block upload or email movement, rotate the token, disable leaked token scopes, and create a remediation ticket for the owning team.",
        "findings": ["github_token", "gitlab_token", "slack_token", "npm_token", "stripe_key", "sendgrid_key", "twilio_key"],
        "keywords": ["ghp_", "glpat-", "xoxb-", "npm_", "sk_live_", "SG.", "AC[a-f0-9]"],
        "control": "Tune by token prefix and minimum entropy, then add allowlists for test fixtures and generated documentation.",
    },
    {
        "signal": "Observability, ITSM, and security-tool tokens",
        "base_risk": "HIGH",
        "score": "Minimum 70",
        "reason": "Monitoring, incident, ticketing, logging, and security-platform tokens can expose telemetry, incidents, vulnerabilities, customer tickets, and operational secrets.",
        "dlp_action": "Block movement, rotate the token, review downstream integrations, and notify the owning platform administrator.",
        "findings": ["datadog_key", "sentry_dsn", "pagerduty_key", "jira_token", "splunk_token", "newrelic_key"],
        "keywords": ["DD_API_KEY", "sentry.io", "PagerDuty", "JIRA_TOKEN", "Splunk", "NEW_RELIC_LICENSE_KEY"],
        "control": "Route confirmed matches to platform owners because these tools often contain incident, log, and customer-support evidence.",
    },
    {
        "signal": "Identity provider, OAuth, and SAML configuration",
        "base_risk": "HIGH",
        "score": "+25 to minimum 70",
        "reason": "IdP metadata, OAuth clients, SAML signing material, Okta/Auth0/Azure AD settings, and MFA recovery artifacts can help attackers bypass or abuse identity controls.",
        "dlp_action": "Restrict to identity administrators, rotate client secrets, and validate redirect URIs and signing certificates.",
        "findings": ["okta_token", "auth0_secret", "saml_private_key", "oauth_client_secret", "mfa_recovery_context"],
        "keywords": ["okta", "auth0", "saml", "client_secret", "redirect_uri", "mfa recovery"],
        "control": "Treat identity configuration as privileged infrastructure data even when it does not contain a raw password.",
    },
    {
        "signal": "Repository, artifact, and build-system leakage",
        "base_risk": "MEDIUM-HIGH",
        "score": "+20 to +35",
        "reason": "Repository exports, package artifacts, build logs, dependency manifests, and CI traces can expose source code, secrets, SBOM data, and deployment topology.",
        "dlp_action": "Limit to engineering owners, scan artifacts before sharing, and remove embedded credentials from build outputs.",
        "findings": ["repo_archive_context", "build_log_context", "artifact_registry_context", "dependency_manifest_context"],
        "keywords": [".git", "build log", "artifact", "pipeline", "package-lock", "pom.xml", "sbom"],
        "control": "Use repository and build context as boosters, especially when paired with secrets or production hostnames.",
    },
    {
        "signal": "Passwords and generic secret assignments",
        "base_risk": "HIGH",
        "score": "Minimum 70",
        "reason": "Password-like assignments, bearer tokens, client secrets, and API keys commonly appear in scripts, exports, runbooks, and shared troubleshooting files.",
        "dlp_action": "Block external sharing, require owner approval for internal movement, and rotate the exposed credential when confirmed.",
        "findings": ["password", "api_key", "oauth_client_secret", "bearer_token", "source_code_secret_context"],
        "keywords": ["password=", "client_secret", "api_key", "authorization: bearer", "db_password", "encryption_key"],
        "control": "Use contextual detection near assignment operators and credential nouns to reduce false positives.",
    },
    {
        "signal": "Database, queue, and service connection strings",
        "base_risk": "HIGH",
        "score": "Minimum 70",
        "reason": "Connection strings often combine hostnames, usernames, passwords, database names, and service endpoints that can be reused by attackers.",
        "dlp_action": "Quarantine, rotate embedded passwords, move secrets to a vault, and create a secure-configuration remediation task.",
        "findings": ["connection_string", "database_uri", "jdbc_connection", "redis_uri", "mongodb_uri"],
        "keywords": ["Server=", "Data Source=", "jdbc:", "mongodb://", "postgres://", "redis://"],
        "control": "Detect URI credentials and semicolon-delimited connection strings in code, config, spreadsheet, and runbook files.",
    },
    {
        "signal": "Endpoint, infrastructure, and remote-access configs",
        "base_risk": "HIGH",
        "score": "+25 to minimum 70",
        "reason": "VPN profiles, RDP files, kubeconfigs, Terraform state, and shell scripts can expose internal topology or privileged automation paths.",
        "dlp_action": "Restrict to platform teams, remove broad access, and require secrets to be separated from configuration exports.",
        "findings": ["kubeconfig_secret", "terraform_state_secret", "basic_auth_url", "docker_auth_config"],
        "keywords": [".kube/config", "kubeconfig", ".tfstate", ".tfvars", ".ovpn", ".rdp", "auths"],
        "control": "Raise inspection depth for infrastructure-as-code and endpoint-admin file types.",
    },
    {
        "signal": "Bulk personal data and contact lists",
        "base_risk": "MEDIUM",
        "score": "+20",
        "reason": "Email addresses, phone numbers, addresses, employee IDs, and contact exports create privacy exposure when moved outside approved business systems.",
        "dlp_action": "Alert on bulk movement, apply privacy label, and require business justification for exports.",
        "findings": ["email", "phone_number", "postal_address_context", "employee_id"],
        "keywords": ["email", "phone", "mobile", "employee id", "customer list", "contacts.csv"],
        "control": "Use match-count thresholds and file context to distinguish one-off contact details from bulk personal data.",
    },
    {
        "signal": "Payment card and PCI data",
        "base_risk": "HIGH",
        "score": "+35",
        "reason": "Payment card numbers, cardholder data, payment exports, and processor tokens are regulated and should not live on broad shares.",
        "dlp_action": "Block external transfer, notify PCI owner, validate storage justification, and create a PCI remediation ticket.",
        "findings": ["credit_card", "payment_card_context", "stripe_key"],
        "keywords": ["card number", "pan", "cvv", "cardholder", "payment export", "sk_live_"],
        "control": "Pair card-number detection with Luhn/context checks and payment-domain keywords to reduce false positives.",
    },
    {
        "signal": "Banking and financial identifiers",
        "base_risk": "HIGH",
        "score": "+35",
        "reason": "IBAN, SWIFT/BIC, routing numbers, account numbers, tax IDs, and finance exports can expose customers, vendors, and treasury operations.",
        "dlp_action": "Apply regulated-data label, restrict sharing, and require finance owner attestation.",
        "findings": ["iban", "swift_bic", "routing_account", "tax_id", "bank_account_context"],
        "keywords": ["IBAN", "SWIFT", "routing", "account number", "treasury", "vendor payment"],
        "control": "Route confirmed matches to finance data owners and limit access to approved finance groups.",
    },
    {
        "signal": "Government IDs and identity documents",
        "base_risk": "HIGH",
        "score": "+35",
        "reason": "National IDs, passport numbers, SSNs, tax IDs, and identity-document scans require strict access controls and retention evidence.",
        "dlp_action": "Restrict sharing, tag as identity data, and verify lawful basis or retention requirement.",
        "findings": ["passport_number", "national_id", "ssn", "azerbaijan_fin", "driver_license_context"],
        "keywords": ["passport", "national id", "ssn", "social security", "FIN", "driver license"],
        "control": "Combine country-specific regex with identity keywords and document naming context.",
    },
    {
        "signal": "Health and regulated privacy data",
        "base_risk": "HIGH",
        "score": "+35",
        "reason": "PHI, patient data, health insurance IDs, diagnosis references, and medical exports carry high regulatory exposure.",
        "dlp_action": "Apply PHI label, block external sharing, and route to privacy or compliance owner.",
        "findings": ["phi_context", "medical_record_context", "insurance_id_context"],
        "keywords": ["patient", "diagnosis", "medical record", "insurance id", "HIPAA", "treatment"],
        "control": "Use domain context and regulated keyword proximity because health identifiers differ by country and system.",
    },
    {
        "signal": "Special-category, biometric, and high-sensitivity privacy data",
        "base_risk": "HIGH",
        "score": "+35",
        "reason": "Biometric, precise location, union, religion, political, background-check, and special-category privacy data usually requires heightened legal basis and strict retention control.",
        "dlp_action": "Apply special-category label, restrict sharing, and route to privacy/legal for lawful-basis validation.",
        "findings": ["biometric_context", "geolocation_context", "special_category_context", "background_check_context"],
        "keywords": ["biometric", "fingerprint", "face id", "gps", "precise location", "background check", "religion", "union"],
        "control": "Keep these rules context-driven to avoid false positives while still catching high-impact privacy exports.",
    },
    {
        "signal": "Legal privilege and contract records",
        "base_risk": "MEDIUM-HIGH",
        "score": "+20 to +35",
        "reason": "Contracts, NDAs, litigation holds, settlement drafts, and privileged legal communications require need-to-know access.",
        "dlp_action": "Apply legal/confidential label and route owner review to legal operations.",
        "findings": ["legal_contract_context", "privileged_legal_context", "nda_context"],
        "keywords": ["NDA", "MSA", "statement of work", "legal hold", "settlement", "privileged"],
        "control": "Use folder and filename context to avoid blocking ordinary public templates.",
    },
    {
        "signal": "Confidential business strategy and board data",
        "base_risk": "MEDIUM",
        "score": "+20",
        "reason": "Board packs, M&A materials, forecasts, pricing, strategy, and executive updates can materially impact the business if exposed.",
        "dlp_action": "Apply confidential label, limit to executive or deal teams, and alert on external movement.",
        "findings": ["confidential_keyword", "board_context", "ma_context", "pricing_strategy_context"],
        "keywords": ["board only", "M&A", "merger", "acquisition", "forecast", "pricing", "strategy"],
        "control": "Combine confidentiality labels with folder ownership and business-unit context.",
    },
    {
        "signal": "HR, payroll, and employee relations",
        "base_risk": "MEDIUM-HIGH",
        "score": "+20 to +35",
        "reason": "Payroll, compensation, performance, disciplinary, recruitment, and employee-benefit records are sensitive even without explicit national IDs.",
        "dlp_action": "Apply HR restricted label, limit access to HR/payroll owners, and monitor bulk export.",
        "findings": ["hr_context", "payroll_context", "salary_context", "employee_relation_context"],
        "keywords": ["payroll", "salary", "bonus", "performance review", "disciplinary", "candidate"],
        "control": "Use department context and file naming to identify HR data that generic PII rules miss.",
    },
    {
        "signal": "Customer, vendor, and commercial records",
        "base_risk": "MEDIUM-HIGH",
        "score": "+20 to +35",
        "reason": "Customer lists, vendor contracts, invoices, support exports, and CRM dumps expose commercial relationships and personal data.",
        "dlp_action": "Apply business-confidential label and require sales, procurement, or customer-success owner approval.",
        "findings": ["customer_context", "vendor_context", "invoice_context", "crm_export_context"],
        "keywords": ["customer", "vendor", "invoice", "CRM", "support export", "account list"],
        "control": "Treat high-row-count spreadsheets and CSV exports as higher risk when paired with customer/vendor context.",
    },
    {
        "signal": "Sensitive filename, path, and share names",
        "base_risk": "MEDIUM",
        "score": "+15",
        "reason": "Paths containing finance, HR, legal, backups, passwords, database dumps, incident response, or production names often identify high-value data before content is inspected.",
        "dlp_action": "Add filename and path conditions to DLP policies.",
        "findings": ["sensitive_path_keyword"],
        "keywords": ["password", "backup", "finance", "HR", "contract", "database", "incident", "prod"],
        "control": "Use path-based rules as boosters, not sole blockers, unless paired with sensitive content or broad access.",
    },
    {
        "signal": "Risky file extensions and structured exports",
        "base_risk": "LOW-MEDIUM",
        "score": "+10 to +25",
        "reason": "Backups, database dumps, logs, mailboxes, archives, office documents, JSON/XML/YAML, and CSV/XLSX exports often carry concentrated sensitive data.",
        "dlp_action": "Increase inspection depth, unpack archives, and prioritize owner review for high-risk export formats.",
        "findings": ["extension_risk"],
        "keywords": [".bak", ".sql", ".db", ".pst", ".zip", ".csv", ".xlsx", ".json", ".xml"],
        "control": "Use extension risk with size, content, and location to prioritize review without over-blocking.",
    },
    {
        "signal": "MSSP asset override",
        "base_risk": "Manual",
        "score": "Forced level",
        "reason": "Every customer has different crown-jewel assets, so analysts can manually raise or lower risk for matching asset names or paths.",
        "dlp_action": "Use customer-specific context before creating or tuning DLP policy.",
        "findings": ["customer_asset_override"],
        "keywords": ["customer-defined pattern", "tenant crown jewel", "business exception"],
        "control": "Keep overrides tenant-scoped and require a business reason for auditability.",
    },
    {
        "signal": "Broad or writable permissions",
        "base_risk": "MEDIUM-HIGH",
        "score": "+15 to +40",
        "reason": "Everyone, Authenticated Users, Domain Users, broad nested groups, or writable shares increase blast radius for any sensitive content.",
        "dlp_action": "Remove broad or writable groups, confirm least privilege, and alert if critical data remains broadly readable.",
        "findings": ["broad_acl", "writable_share", "everyone_access"],
        "keywords": ["Everyone", "Authenticated Users", "Domain Users", "Write", "Modify"],
        "control": "Treat ACL exposure as a multiplier, especially for secrets, regulated data, and executive content.",
    },
    {
        "signal": "SMB share exposure",
        "base_risk": "LOW",
        "score": "+5",
        "reason": "Network-share data is easier to discover, copy, or sync than isolated local files.",
        "dlp_action": "Monitor share access and file movement.",
        "findings": ["smb_source"],
        "keywords": ["SMB", "share", "UNC path", "\\\\server\\share"],
        "control": "Pair share exposure with access logs, owner mapping, and sensitive-content thresholds.",
    },
    {
        "signal": "Encrypted, locked, or unreadable content",
        "base_risk": "HIGH",
        "score": "Minimum 70",
        "reason": "Password-protected archives, encrypted vaults, and unreadable files can conceal sensitive data and prevent automated validation.",
        "dlp_action": "Request owner attestation, collect password escrow or decrypted copy, and document exception if content must remain sealed.",
        "findings": ["protected_file", "password_protected_archive", "encrypted_vault", "metadata_only"],
        "keywords": ["password protected", "encrypted", ".zip", ".7z", ".kdbx", ".gpg"],
        "control": "Do not treat unscannable content as safe; route for manual review when location or extension is sensitive.",
    },
    {
        "signal": "Security operations, incident, and vulnerability exports",
        "base_risk": "MEDIUM-HIGH",
        "score": "+20 to +35",
        "reason": "Incident reports, vulnerability exports, SIEM data, EDR logs, and access reviews can expose weaknesses, usernames, hostnames, and investigation details.",
        "dlp_action": "Apply security-restricted label and keep access limited to security operations and system owners.",
        "findings": ["security_ops_context", "vulnerability_context", "incident_response_context"],
        "keywords": ["incident", "CVE", "vulnerability", "EDR", "SIEM", "access review", "SOC2"],
        "control": "Classify security exports separately from ordinary logs because they reveal defensive posture.",
    },
    {
        "signal": "Governance, retention, and legal-hold evidence",
        "base_risk": "MEDIUM-HIGH",
        "score": "+20 to +35",
        "reason": "Retention schedules, legal-hold exports, audit evidence, access reviews, and compliance workpapers can expose control gaps and regulated processing records.",
        "dlp_action": "Apply governance-restricted label, keep evidence in approved repositories, and block ad-hoc external transfer.",
        "findings": ["retention_policy_context", "legal_hold_context", "audit_evidence_context", "access_review_context"],
        "keywords": ["retention schedule", "legal hold", "audit evidence", "access review", "control testing", "workpaper"],
        "control": "Route governance evidence to compliance owners and preserve audit trail for any approved movement.",
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
        reasons.append(_finding_reason(finding))
        recommendations.extend(_finding_recommendations(finding, finding_level))

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

    protection_status = str(file_obj.get("content_status") or file_obj.get("scan_error") or file_obj.get("protection_type") or "").lower()
    protected_content = bool(file_obj.get("protected")) or any(
        marker in protection_status
        for marker in ("protected", "password", "encrypted", "locked", "unreadable", "unsupported_archive", "bad_archive")
    )
    if protected_content:
        score = max(score, 70)
        reasons.append("File is encrypted, password-protected, or could not be inspected")
        recommendations.append("Request owner attestation, password escrow, or a decrypted inspection copy")

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
    finding_categories = {str(finding.get("category", "")).lower().replace("-", "_").replace(" ", "_") for finding in findings if finding.get("category")}
    has_secret = any("key" in item or "token" in item or "secret" in item or "password" in item for item in finding_types)
    has_secret = has_secret or any("secret" in item or "credential" in item for item in finding_categories)
    has_regulated = any(item in finding_types for item in {"credit_card", "iban", "swift_bic", "passport_number", "national_id"})
    has_regulated = has_regulated or bool(finding_categories & {"pii", "personal_data", "government_ids", "phi", "health", "medical", "financial", "financial_records", "pci_payment", "special_category", "biometric_data", "genetic_data"})
    has_compliance_category = bool(finding_categories & {"legal", "contracts", "hr", "hr_documents", "confidential_business", "custom"})
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
    if has_compliance_category:
        actions.extend(["Apply custom GDPR/category label", "Route category-specific owner review", "Validate retention and business need"])
    protected_content = bool(file_obj.get("protected")) or any(
        marker in str(file_obj.get("content_status") or file_obj.get("scan_error") or "").lower()
        for marker in ("protected", "password", "encrypted", "locked", "unreadable", "unsupported_archive", "bad_archive")
    )
    if has_acl_issue:
        actions.extend(["Remove broad or writable groups", "Confirm least-privilege access with the data owner"])
    if protected_content:
        actions.extend(["Confirm business owner", "Collect password or decrypted copy for inspection", "Document exception if content must remain sealed"])
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


def _finding_reason(finding: dict) -> str:
    finding_type = str(finding.get("type") or "sensitive_data")
    count = int(finding.get("count") or 1)
    description = str(finding.get("description") or finding_type.replace("_", " "))
    suffix = f"{count} match" if count == 1 else f"{count} matches"
    enterprise_reasons = {
        "private_key": "Cryptographic private key material can authenticate systems, decrypt traffic, or enable lateral movement if copied from this location.",
        "aws_access_key": "AWS access key identifier indicates potential cloud credential exposure and should be validated against active IAM principals.",
        "aws_secret_key": "AWS secret access key assignment can allow direct cloud API access if the paired access key is present or recoverable.",
        "jwt": "JSON Web Token may carry reusable session, service, or authorization claims and should be treated as active credential material until expiry and scope are verified.",
        "azure_storage_key": "Azure storage key or connection secret may grant direct access to storage accounts and customer data containers.",
        "azure_sas_token": "Azure SAS token can grant scoped but direct access to storage resources until expiry or revocation.",
        "google_api_key": "Google API key can expose cloud or application services depending on project restrictions and allowed APIs.",
        "gcp_service_account": "Google Cloud service-account credential block can authenticate workloads and access cloud resources.",
        "github_token": "GitHub token can expose source code, actions workflows, packages, or deployment secrets.",
        "gitlab_token": "GitLab token can expose repositories, CI/CD variables, runners, or package artifacts.",
        "npm_token": "NPM registry token can publish, pull, or tamper with packages depending on assigned scope.",
        "slack_token": "Slack token may expose collaboration data, internal channels, files, or automation capabilities.",
        "stripe_key": "Stripe secret or restricted key can expose payment operations and must be treated as PCI-adjacent credential material.",
        "sendgrid_key": "SendGrid key can enable unauthorized email sending and customer communication abuse.",
        "twilio_key": "Twilio key or account identifier can expose messaging, voice, or OTP workflows.",
        "datadog_key": "Datadog key can expose telemetry and operational metadata that may include secrets or incident context.",
        "sentry_dsn": "Sentry DSN can expose application telemetry paths and error-reporting project identifiers.",
        "pagerduty_key": "PagerDuty routing or integration key can manipulate alerting workflows and incident response routing.",
        "splunk_token": "Splunk token can expose logging ingestion paths or security telemetry integrations.",
        "newrelic_key": "New Relic key can expose observability integrations and production telemetry metadata.",
        "okta_token": "Okta token or identity-provider token context can expose administrative identity workflows.",
        "auth0_secret": "Auth0 client secret can compromise application authentication or token exchange flows.",
        "oauth_client_secret": "OAuth client secret can be used to impersonate an application in authorization flows.",
        "bearer_token": "Bearer token can provide direct account or API access without proof-of-possession controls.",
        "password": "Password-like assignment indicates reusable credential material stored outside an approved vault.",
        "api_key": "API key or generic token assignment indicates credential material that should be vaulted and rotated if confirmed.",
        "connection_string": "Connection string combines endpoint and authentication context that can be reused to access databases or services.",
        "database_uri": "Database URI includes embedded credentials and infrastructure location in a portable format.",
        "jdbc_connection": "JDBC configuration may expose database endpoint, schema, username, or password material.",
        "basic_auth_url": "URL contains embedded credentials that can leak through logs, screenshots, tickets, and browser history.",
        "docker_auth_config": "Docker auth config can expose registry credentials and software supply-chain access.",
        "kubeconfig_secret": "Kubernetes config contains cluster access material that can expose workloads and secrets.",
        "terraform_state_secret": "Terraform state or variables may contain provider secrets, generated passwords, or infrastructure topology.",
        "saml_private_key": "SAML or IdP signing key context can undermine federation trust if exposed.",
        "mfa_recovery_context": "MFA recovery or backup-code context can bypass strong authentication controls.",
        "credit_card": "Payment card pattern indicates potential PCI data requiring strict storage and sharing controls.",
        "iban": "IBAN pattern indicates regulated banking data and potential customer/vendor financial exposure.",
        "swift_bic": "SWIFT/BIC context indicates banking or treasury data that should be limited to finance owners.",
        "routing_account": "Bank routing or account number context indicates financial account data requiring owner validation.",
        "passport_number": "Passport identifier context indicates identity-document data requiring strict privacy controls.",
        "national_id": "Government identifier context indicates regulated identity data and potential privacy exposure.",
        "ssn": "Social Security Number context indicates high-sensitivity identity data.",
        "azerbaijan_fin": "Azerbaijan FIN-like identifier may indicate local identity data and should be reviewed with country context.",
        "email": "Email address match contributes personal-data context, especially when repeated or paired with exports.",
        "phone_number": "Phone number match contributes personal-data context and may indicate customer or employee records.",
        "employee_id": "Employee identifier context indicates HR or workforce data.",
        "phi_context": "Healthcare or PHI context indicates regulated health data or medical operational records.",
        "payroll_context": "Payroll or compensation context indicates HR restricted data even without explicit national identifiers.",
        "customer_context": "Customer, vendor, CRM, or invoice context indicates commercial records and possible personal data.",
        "board_context": "Executive, strategy, forecast, or M&A context indicates confidential business material.",
        "legal_contract_context": "Legal, contract, NDA, or legal-hold context indicates privileged or need-to-know business records.",
        "security_ops_context": "Security operations or vulnerability context exposes defensive posture, incidents, or control gaps.",
        "repo_archive_context": "Repository export or source archive context may expose code, secrets, and software supply-chain metadata.",
        "build_log_context": "Build or CI/CD context may expose pipeline traces, artifact locations, deployment tokens, or production topology.",
        "special_category_context": "Special-category privacy context indicates biometric, location, background-check, or other high-sensitivity personal data.",
        "retention_policy_context": "Governance or retention context indicates audit evidence, legal-hold, or compliance workpapers.",
        "confidential_keyword": "Confidentiality keyword indicates business-sensitive content that needs owner and access review.",
        "source_code_secret_context": "Source-code secret assignment indicates credential material embedded in code or configuration.",
    }
    reason = enterprise_reasons.get(finding_type)
    if not reason:
        reason = _dynamic_finding_reason(finding, description)
    return f"{reason} ({suffix})"


def _dynamic_finding_reason(finding: dict, fallback: str) -> str:
    label = str(finding.get("label") or finding.get("type") or "Sensitive data").replace("_", " ").strip()
    category = str(finding.get("category") or "custom").strip().lower().replace("-", "_").replace(" ", "_")
    keywords = finding.get("matched_keywords") or finding.get("keywords") or finding.get("samples") or []
    keyword_hint = ""
    if keywords:
        keyword_hint = f" Matched evidence includes {', '.join(str(item) for item in keywords[:3])}."
    category_reasons = {
        "pii": f"{label} indicates GDPR personal data and should be handled with privacy controls, purpose limitation, and owner review.",
        "personal_data": f"{label} indicates GDPR personal data and should be handled with privacy controls, purpose limitation, and owner review.",
        "government_ids": f"{label} indicates government or identity-document data that needs strict access control, lawful-basis validation, and retention review.",
        "phi": f"{label} indicates health or medical privacy data that requires strict access control and privacy/compliance owner review.",
        "health": f"{label} indicates health or medical privacy data that requires strict access control and privacy/compliance owner review.",
        "medical": f"{label} indicates health or medical privacy data that requires strict access control and privacy/compliance owner review.",
        "financial": f"{label} indicates financial data that should be restricted to approved finance or compliance owners.",
        "financial_records": f"{label} indicates financial data that should be restricted to approved finance or compliance owners.",
        "credentials": f"{label} indicates credential or access material that should be validated, vaulted, and rotated if active.",
        "credentials_secrets": f"{label} indicates credential or access material that should be validated, vaulted, and rotated if active.",
        "legal": f"{label} indicates legal or contractual data that should be limited to legal owners and need-to-know reviewers.",
        "contracts": f"{label} indicates legal or contractual data that should be limited to legal owners and need-to-know reviewers.",
        "hr": f"{label} indicates workforce or HR data that should be restricted to HR/payroll owners.",
        "hr_documents": f"{label} indicates workforce or HR data that should be restricted to HR/payroll owners.",
        "custom": f"{label} matched a custom GDPR keyword group and should be reviewed according to the configured category and risk.",
    }
    return f"{category_reasons.get(category, fallback)}{keyword_hint}"


def _finding_recommendations(finding: dict | str, finding_level: str) -> list[str]:
    if isinstance(finding, dict):
        finding_type = str(finding.get("type") or "sensitive_data")
    else:
        finding_type = str(finding or "sensitive_data")
    recommendations_by_type = {
        "private_key": ["Quarantine the exposed key file, rotate the key pair, and verify no dependent service still trusts the leaked material.", "Move approved key material into a managed vault or HSM-backed storage path."],
        "aws_access_key": ["Validate the AWS key owner, rotate the credential, and review CloudTrail activity for use after exposure.", "Create a DLP block rule for AWS key prefixes outside approved vault exports."],
        "aws_secret_key": ["Rotate the AWS secret immediately and review IAM policy scope for the associated principal.", "Open a cloud-security incident if the credential belongs to production or privileged accounts."],
        "jwt": ["Invalidate or let-expire the token, review issuer/audience/scope, and check access logs for replay.", "Block JWT movement in shared files unless it is documented test data with expired claims."],
        "azure_storage_key": ["Rotate the affected storage account key and review blob/container access logs.", "Replace shared keys with managed identity or scoped SAS where business use is required."],
        "azure_sas_token": ["Revoke or expire the SAS token and validate whether it grants write, delete, or list permissions.", "Block SAS-token movement outside approved engineering and platform repositories."],
        "google_api_key": ["Restrict the API key by project, API, referrer, and IP, then rotate if exposure is confirmed.", "Alert the cloud owner and review GCP audit logs for suspicious use."],
        "gcp_service_account": ["Disable or rotate the service-account key and move workload authentication to managed identity where possible.", "Review service-account IAM roles for privilege reduction."],
        "github_token": ["Revoke the GitHub token, rotate dependent automation secrets, and review repository/audit activity.", "Block developer-token patterns in shared drives and report exports."],
        "gitlab_token": ["Revoke the GitLab token and review project, group, runner, and CI variable access.", "Restrict personal access tokens to approved vault-backed workflows."],
        "npm_token": ["Revoke the NPM token and review package publish/download activity for the associated account.", "Require registry tokens to be stored in CI secret stores only."],
        "slack_token": ["Revoke the Slack token and review bot/user scopes and workspace audit logs.", "Block Slack token movement through file shares and email attachments."],
        "stripe_key": ["Rotate the Stripe key and notify the payment owner for PCI-impact review.", "Block payment-secret movement and require a PCI exception for any retained export."],
        "sendgrid_key": ["Rotate the SendGrid key and review outbound email activity for abuse.", "Move email-service credentials to an approved application secret store."],
        "twilio_key": ["Rotate the Twilio credential and review messaging, voice, and OTP activity.", "Limit telecom API keys to owned automation repositories or vaults."],
        "datadog_key": ["Rotate the Datadog key and confirm whether telemetry ingestion or query scopes were exposed.", "Treat observability tokens as production secrets in DLP policy."],
        "sentry_dsn": ["Validate Sentry project exposure and rotate DSN or client keys if project policy requires it.", "Review whether error payloads contain personal data or secrets."],
        "pagerduty_key": ["Rotate the PagerDuty integration key and review incident routing changes.", "Restrict incident tooling tokens to platform-owned secret stores."],
        "splunk_token": ["Rotate the Splunk token and review HEC ingestion paths or API access.", "Classify SIEM credentials as security-restricted material."],
        "newrelic_key": ["Rotate the New Relic key and validate application telemetry scope.", "Move APM credentials out of shared files and into deployment secrets."],
        "okta_token": ["Revoke the Okta token and review admin/audit events for suspicious identity changes.", "Restrict IdP API tokens to identity-admin vault paths."],
        "auth0_secret": ["Rotate the Auth0 client secret and review application redirect URI and grant configuration.", "Block identity-provider secrets in shared folders and reports."],
        "oauth_client_secret": ["Rotate the OAuth client secret and validate application ownership and grant type.", "Create an identity-secret DLP rule for OAuth/SAML configuration exports."],
        "bearer_token": ["Invalidate the bearer token and review logs for replay or unusual access.", "Block bearer-token movement outside approved troubleshooting windows."],
        "password": ["Rotate the password if active and remove it from the file or replace it with a vault reference.", "Block password-like assignments in exports, scripts, and runbooks."],
        "api_key": ["Validate the API key owner, rotate if active, and move it into a managed secret store.", "Tune DLP detection by assignment context and entropy to reduce false positives."],
        "connection_string": ["Rotate embedded credentials and move connection secrets to a vault-backed configuration mechanism.", "Create a DLP rule for connection strings in documents, spreadsheets, and scripts."],
        "database_uri": ["Rotate database credentials and review database access logs for use after exposure.", "Block URI credentials in shared exports and code attachments."],
        "jdbc_connection": ["Move JDBC credentials to a secure configuration store and rotate embedded passwords.", "Require owner review for database configuration files on broad shares."],
        "basic_auth_url": ["Remove embedded credentials from URLs and rotate the exposed password or token.", "Block basic-auth URLs in documents, logs, and tickets."],
        "docker_auth_config": ["Rotate registry credentials and validate image/package access after exposure.", "Store Docker auth in approved CI/CD secret stores only."],
        "kubeconfig_secret": ["Rotate kubeconfig tokens or certificates and review cluster audit logs.", "Restrict kubeconfig files to platform administrators and approved encrypted storage."],
        "terraform_state_secret": ["Move Terraform state to encrypted remote backend and rotate any exposed provider secrets.", "Block Terraform state sharing through file shares and email."],
        "saml_private_key": ["Rotate SAML signing material and validate IdP/SP trust configuration.", "Restrict federation metadata and signing keys to identity administrators."],
        "mfa_recovery_context": ["Invalidate recovery codes and force regeneration for the affected account or app.", "Block MFA recovery artifacts outside identity-admin vaults."],
        "credit_card": ["Apply PCI label, block external transfer, and notify the payment data owner.", "Validate whether storage is approved under PCI scope and retention policy."],
        "iban": ["Apply regulated financial-data label and restrict sharing to finance owners.", "Review business justification and retention for bank-account exports."],
        "swift_bic": ["Route to treasury or finance owner for access review.", "Restrict bank identifier files to approved finance groups."],
        "routing_account": ["Apply financial-data controls and validate whether account data should remain on this share.", "Require finance owner attestation for continued storage."],
        "passport_number": ["Apply identity-data label and restrict access to approved HR, legal, or compliance owners.", "Validate lawful basis and retention requirement for identity documents."],
        "national_id": ["Apply regulated identity-data label and remove broad access.", "Route to privacy owner for lawful-basis and retention review."],
        "ssn": ["Block external sharing and route to privacy/compliance owner.", "Validate approved storage location and delete unnecessary copies."],
        "azerbaijan_fin": ["Review with local privacy owner to confirm whether this is a true FIN identifier.", "Apply country-specific identity-data controls when confirmed."],
        "email": ["Apply personal-data monitoring when email addresses appear in bulk or export files.", "Alert on external transfer of contact lists outside approved systems."],
        "phone_number": ["Treat as personal data when paired with names, customer records, or employee files.", "Apply privacy label and monitor bulk movement."],
        "employee_id": ["Route to HR data owner and restrict access to workforce-data groups.", "Monitor bulk export of employee identifiers."],
        "phi_context": ["Apply PHI label, block external sharing, and route to privacy/compliance owner.", "Validate storage location, access scope, and retention requirements."],
        "payroll_context": ["Apply HR restricted label and limit access to HR/payroll owners.", "Monitor payroll and compensation exports for external movement."],
        "customer_context": ["Route to customer-data owner and validate access for sales/support/procurement groups.", "Apply business-confidential label and monitor bulk exports."],
        "board_context": ["Apply executive-confidential label and restrict to approved leadership or deal-team groups.", "Alert on external movement of board, strategy, pricing, or M&A material."],
        "legal_contract_context": ["Route to legal operations and apply legal/confidential label.", "Restrict access to contract owners and legal reviewers."],
        "security_ops_context": ["Apply security-restricted label and limit to security operations and system owners.", "Avoid exporting vulnerability or incident evidence outside approved repositories."],
        "repo_archive_context": ["Scan repository artifacts for embedded secrets and restrict source archives to engineering owners.", "Remove broad access to repo backup folders."],
        "build_log_context": ["Review build logs for secrets and production topology before sharing.", "Restrict CI/CD traces and artifacts to engineering/platform owners."],
        "special_category_context": ["Route to privacy/legal for special-category data review.", "Apply strict sharing controls and validate lawful basis before retention."],
        "retention_policy_context": ["Keep governance evidence in approved repositories and block ad-hoc external transfer.", "Route access review or legal-hold evidence to compliance owners."],
        "confidential_keyword": ["Apply classification label and route owner review before broad sharing.", "Use confidentiality keyword context as a booster with path and access signals."],
        "source_code_secret_context": ["Remove the hardcoded secret and replace it with a vault reference.", "Create a secure-code remediation task for the owning engineering team."],
    }
    if isinstance(finding, dict):
        dynamic = _dynamic_finding_recommendations(finding, finding_level)
        if dynamic:
            return dynamic

    generic = ["Create or tune a DLP detection rule for this finding type and route owner review based on data domain."]
    if finding_level in {"CRITICAL", "HIGH"}:
        generic.append("Block external movement until the owner confirms business need and remediation status.")
    else:
        generic.append("Monitor movement and validate whether the file belongs in an approved repository.")
    return recommendations_by_type.get(finding_type, generic)


def _dynamic_finding_recommendations(finding: dict, finding_level: str) -> list[str]:
    finding_type = str(finding.get("type") or "").lower()
    if finding_type in {
        "private_key", "aws_access_key", "aws_secret_key", "jwt", "azure_storage_key", "azure_sas_token",
        "google_api_key", "gcp_service_account", "github_token", "gitlab_token", "npm_token", "slack_token",
        "stripe_key", "sendgrid_key", "twilio_key", "datadog_key", "sentry_dsn", "pagerduty_key",
        "splunk_token", "newrelic_key", "okta_token", "auth0_secret", "oauth_client_secret", "bearer_token",
        "password", "api_key", "connection_string", "database_uri", "jdbc_connection", "basic_auth_url",
        "docker_auth_config", "kubeconfig_secret", "terraform_state_secret", "saml_private_key",
        "mfa_recovery_context", "credit_card", "iban", "swift_bic", "routing_account", "passport_number",
        "national_id", "ssn", "azerbaijan_fin", "email", "phone_number", "employee_id", "phi_context",
        "payroll_context", "customer_context", "board_context", "legal_contract_context", "security_ops_context",
        "repo_archive_context", "build_log_context", "special_category_context", "retention_policy_context",
        "confidential_keyword", "source_code_secret_context",
    }:
        return []
    if str(finding.get("framework") or "").lower() != "gdpr" and not finding.get("category"):
        return []

    label = str(finding.get("label") or finding.get("type") or "custom finding").replace("_", " ").strip()
    category = str(finding.get("category") or "custom").strip().lower().replace("-", "_").replace(" ", "_")
    actions_by_category = {
        "pii": [f"Apply a GDPR personal-data label for {label} and route review to the privacy or data owner.", "Validate lawful basis, retention need, and whether the file belongs in an approved system."],
        "personal_data": [f"Apply a GDPR personal-data label for {label} and route review to the privacy or data owner.", "Validate lawful basis, retention need, and whether the file belongs in an approved system."],
        "government_ids": [f"Apply an identity-data label for {label} and restrict access to approved HR, legal, or compliance owners.", "Validate lawful basis and retention requirement before keeping this copy."],
        "phi": [f"Apply a health/privacy label for {label} and block external sharing until the privacy owner reviews it.", "Validate storage location, access scope, and retention requirements."],
        "health": [f"Apply a health/privacy label for {label} and block external sharing until the privacy owner reviews it.", "Validate storage location, access scope, and retention requirements."],
        "medical": [f"Apply a health/privacy label for {label} and block external sharing until the privacy owner reviews it.", "Validate storage location, access scope, and retention requirements."],
        "financial": [f"Apply a financial-data label for {label} and restrict sharing to finance owners.", "Review business justification and retention for this financial export."],
        "financial_records": [f"Apply a financial-data label for {label} and restrict sharing to finance owners.", "Review business justification and retention for this financial export."],
        "credentials": [f"Validate whether {label} is active credential material, then rotate and move it to a managed secret store if confirmed.", "Block movement of this custom credential marker outside approved vault-backed workflows."],
        "credentials_secrets": [f"Validate whether {label} is active credential material, then rotate and move it to a managed secret store if confirmed.", "Block movement of this custom credential marker outside approved vault-backed workflows."],
        "legal": [f"Apply legal/confidential handling for {label} and route owner review to legal operations.", "Restrict access to contract owners and need-to-know reviewers."],
        "contracts": [f"Apply legal/confidential handling for {label} and route owner review to legal operations.", "Restrict access to contract owners and need-to-know reviewers."],
        "hr": [f"Apply HR restricted handling for {label} and limit access to HR/payroll owners.", "Monitor bulk export or external movement of this workforce-data marker."],
        "hr_documents": [f"Apply HR restricted handling for {label} and limit access to HR/payroll owners.", "Monitor bulk export or external movement of this workforce-data marker."],
    }
    actions = actions_by_category.get(category, [
        f"Create or tune a DLP rule for custom GDPR finding '{label}' in category '{category}'.",
        "Route owner review based on the configured custom category and validate business need.",
    ])
    if finding_level in {"CRITICAL", "HIGH"}:
        actions.append("Block external movement until the owner confirms remediation or an approved exception.")
    else:
        actions.append("Monitor movement and confirm the file remains in an approved repository.")
    return actions


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))
