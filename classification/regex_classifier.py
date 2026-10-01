from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Callable
from dataclasses import dataclass

from classification.ml_classifier import classify_with_ml
from classification import masking
from classification.masking import data_class_for_rule, mask
from classification.pan_validator import cap_severity, pan_hits


@dataclass(frozen=True, slots=True)
class DetectionRule:
    name: str
    pattern: re.Pattern[str]
    risk: str
    description: str
    redact: bool = True
    # Optional structural validator applied to each raw match. When set, only
    # matches for which validator(value) is True are emitted. This is how we
    # stop "any 16 digits" being a card, "any 7-letter word" being a FIN, etc.
    # Rules without a validator behave exactly as before.
    validator: Callable[[str], bool] | None = None
    # Which capture group carries the sensitive value. 0 (the whole match) by
    # default; context-anchored rules set this to the group holding the value
    # alone (e.g. the BIC after a "SWIFT:" label) so the validator, redaction,
    # and unique-value fingerprint all operate on the value, not the label.
    value_group: int = 0
    # A rule whose decision needs more than the matched value - the words around
    # it, or how many times it occurs in the file - supplies a finder instead of
    # a validator. It returns (value, extra_fields) pairs and OWNS the match
    # loop; `pattern` stays in place because evidence masking redacts from it.
    finder: Callable[[str], list[tuple[str, dict]]] | None = None


def _card_finder(content: str) -> list[tuple[str, dict]]:
    """Payment cards, decided by the shared validator.

    This rule used to ask for a Luhn checksum and nothing else. Luhn accepts one
    in ten random digit strings and is the checksum IMEI numbers use, so
    `Device IMEI: 490154203237518` was reported as a payment card - measured, on
    this tree, at HIGH.
    """
    return [(hit.raw, hit.verdict.to_fields()) for hit in pan_hits(content)]


def _iban_ok(value: str) -> bool:
    """IBAN: country+length shape AND the ISO 7064 mod-97 checksum."""
    compact = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _fin_ok(value: str) -> bool:
    """Azerbaijan FIN: 7 alphanumerics containing BOTH a letter and a digit, so
    ordinary 7-letter words (PROJECT, COMPANY) and 7-digit runs are not FINs."""
    token = value.strip()
    return len(token) == 7 and any(ch.isalpha() for ch in token) and any(ch.isdigit() for ch in token)


# ISO 3166-1 alpha-2 country codes. A real BIC embeds one of these at positions
# 5-6; a lookalike word such as "CUSTOMER" (CUST-OM-ER) can collide, so this is
# a filter, not a full guarantee - paired with the uppercase-token requirement
# below it removes the common prose false positives ("swift customer service").
_ISO_COUNTRY = frozenset(
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ "
    "BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR "
    "CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR "
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU "
    "ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ "
    "LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ "
    "MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF "
    "PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI "
    "SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR "
    "TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW".split()
)


def _bic_ok(value: str) -> bool:
    """SWIFT/BIC: exactly 8 or 11 chars, uppercase, with a valid ISO country
    code at positions 5-6. Receives the BIC alone (rule.value_group=1), never
    the surrounding label."""
    token = value.strip().upper()
    if not re.fullmatch(r"[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?", token):
        return False
    return token[4:6] in _ISO_COUNTRY


RULES = [
    DetectionRule(
        name="private_key",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,12000}?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
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
        # The local part starts where its run of characters starts, with a letter, digit or
        # "_" after any leading ".+-", and is taken whole: a \b start re-read the rest of
        # the run from every boundary in it ("x-x-x...").
        pattern=re.compile(r"(?<![a-zA-Z0-9_.+-])[.+-]*+(?=[a-zA-Z0-9_])[a-zA-Z0-9_.+-]++@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
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
        description="Payment card number detected",
        finder=_card_finder,
    ),
    DetectionRule(
        name="swift_bic",
        # Context-anchored AND structurally validated. The label (swift/bic/code)
        # is case-insensitive via inline (?i:...), but the BIC itself is matched
        # case-SENSITIVELY as uppercase only - so lowercase prose after the word
        # "swift" ("swift customer service") no longer captures a token. The
        # captured group (value_group=1) is the BIC alone; _bic_ok then requires
        # a valid ISO country code at positions 5-6.
        pattern=re.compile(
            r"\b(?i:swift|bic)\b(?i:\s*code)?[\s:=#.\-]{0,4}([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
        ),
        risk="HIGH",
        description="SWIFT/BIC bank identifier detected in context",
        validator=_bic_ok,
        value_group=1,
    ),
    DetectionRule(
        name="iban",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        risk="HIGH",
        description="IBAN bank account identifier detected (mod-97 valid)",
        validator=_iban_ok,
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
        description="Azerbaijan FIN-like identifier detected",
        validator=_fin_ok,
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


def _entity_type_for_rule(rule_name: str, data_class: str) -> str:
    """What this rule's values are, in the canonical vocabulary - "" when nothing names it."""
    from classification.compliance.canonical_entities import canonical_entity_type_for_finding

    return canonical_entity_type_for_finding({"type": rule_name, "data_class": data_class})


def _add_entity_fingerprint(prints: list[str], entity_type: str, value: str, redact: bool, tenant_id: str) -> None:
    """The same value's canonical fingerprint, computed the way every detector computes it.

    Without this the generic detector's email and the GDPR detector's email were two
    entities: the registry falls back to hashing whatever fingerprint a finding carries,
    and those were a masked token here and a digest of the raw value there (B7).
    """
    if not redact or not entity_type or not value:
        return
    from classification.compliance.canonical_entities import canonical_entity_fingerprint

    fingerprint = canonical_entity_fingerprint(entity_type, value, tenant_id)
    if fingerprint not in prints:
        prints.append(fingerprint)


def _add_fingerprint(fingerprints: list[str], value: str, redact: bool) -> None:
    """Context rules match a KEYWORD, not a value, so they have nothing to
    fingerprint - their sample is the keyword and it is shown as it was."""

    if redact:
        fingerprints.append(_fingerprint(value))


_CONFIDENCE_STRENGTH = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _merge_rule_extra(current: dict, incoming: dict) -> dict:
    """One finding covers every match of its rule, so the fields it carries have
    to describe the STRONGEST match - otherwise a file whose first card is a
    guess and whose second is confirmed reports the guess."""

    if not current:
        return dict(incoming)
    here = _CONFIDENCE_STRENGTH.get(str(current.get("pan_confidence") or "LOW").upper(), 0)
    there = _CONFIDENCE_STRENGTH.get(str(incoming.get("pan_confidence") or "LOW").upper(), 0)
    return dict(incoming) if there > here else current


def _fingerprint(value: str) -> str:
    """A keyed, non-reversible fingerprint of a matched value.

    SC-3. This is how distinct values are COUNTED without any being stored, and
    it is what `canonical_model._unique_value_count` and its two siblings read.
    It used to be the displayed sample as well, which is why an analyst saw
    `[redacted:30840604a1b4]` and had to open the file to learn anything.
    """

    from classification.compliance.evidence_keys import evidence_hmac_key

    digest = hmac.new(
        evidence_hmac_key().encode("utf-8"),
        value.encode("utf-8", "ignore"),
        hashlib.sha256,
    ).hexdigest()[:12]
    return f"[redacted:{digest}]"


def _redact(value: str, data_class: str = masking.GENERIC) -> str:
    """What a person is shown: a partial value, masked for its class."""

    return mask(value, data_class)


# SC/SCAN-003: samples are capped for evidence hygiene, but the occurrence
# COUNT must not be capped with them - otherwise 10 and 1,000,000 matches look
# identical and risk prioritisation / DLP thresholds are wrong. Count is bounded
# only by COUNT_CAP as a safety limit against pathological inputs.
SAMPLE_CAP = 10
COUNT_CAP = 10_000
# Hard ceiling on candidates EXAMINED per rule. Validated rules (card/iban/fin)
# skip invalid matches without incrementing `total`, so a pathological input
# with millions of near-miss candidates would otherwise never hit COUNT_CAP and
# iterate unbounded. This bounds the work regardless of validity.
MATCH_SCAN_CAP = 200_000


# Track P-D: necessary-substring prefilter. For each rule listed here, ANY match
# requires at least one of these lowercased literals to be present in the content
# (they are mandatory literals in the rule's pattern). When none is present the
# rule is skipped WITHOUT running its `finditer` - which is exactly equivalent to
# running it and getting zero matches (the rule would `continue` at total==0), so
# the output is byte-identical. Rules absent from this map (the numeric rules with
# no fixed literal - credit_card, iban, azerbaijan_fin, phone_number - and a few
# whose only necessary literal is too common to help) are always run. Substring
# presence is a valid necessary condition even for \b-anchored keyword rules: if
# the word matches with a boundary, the word is a substring. Case-insensitive by
# construction (we lowercase both sides), which stays a correct necessary
# condition for the case-sensitive token rules too (an uppercase AKIA present
# implies "akia" present in the lowercased content).
_RULE_PREFILTER: dict[str, tuple[str, ...]] = {
    "private_key": ("private key",),
    "saml_private_key": ("private key",),
    "aws_access_key": ("akia", "asia"),
    "aws_secret_key": ("aws_secret_access_key",),
    "jwt": ("eyj",),
    "connection_string": ("server", "host", "data source"),
    "azure_storage_key": ("defaultendpointsprotocol", "accountname", "accountkey", "blobendpoint"),
    "azure_sas_token": ("sv=",),
    "google_api_key": ("aiza",),
    "gcp_service_account": ("service_account",),
    "slack_token": ("xox",),
    "github_token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "gitlab_token": ("glpat-",),
    "npm_token": ("npm_",),
    "stripe_key": ("sk_live", "sk_test", "rk_live", "rk_test"),
    "sendgrid_key": ("sg.",),
    "datadog_key": ("dd_api_key", "dd_app_key", "datadog"),
    "sentry_dsn": ("sentry.io",),
    "okta_token": ("okta", "ssws"),
    "auth0_secret": ("auth0",),
    "newrelic_key": ("new_relic_license_key", "newrelic"),
    "database_uri": ("postgres", "mysql", "mariadb", "mongodb", "redis", "mssql", "sqlserver"),
    "jdbc_connection": ("jdbc:",),
    "basic_auth_url": ("@",),
    "docker_auth_config": ("auths",),
    "kubeconfig_secret": ("apiversion", "config"),
    "terraform_state_secret": ("sensitive", "secret", "password", "private_key"),
    "source_code_secret_context": ("client_secret", "private_token", "auth_token", "db_password", "encryption_key"),
    "mfa_recovery_context": ("mfa", "2fa", "totp", "webauthn", "recovery code", "backup code"),
    "swift_bic": ("swift", "bic"),
    "email": ("@",),
    "password": ("password", "passwd", "pwd"),
    "bearer_token": ("authorization",),
    "confidential_keyword": ("confidential", "restricted", "internal use only", "secret", "nda", "non-disclosure", "board only", "privileged", "need to know"),
    "legal_contract_context": ("contract", "statement of work", "master service agreement", "msa", "nda", "legal hold"),
    "phi_context": ("patient", "diagnosis", "medical record", "health insurance", "treatment plan", "clinical", "prescription"),
    "payroll_context": ("payroll", "salary", "bonus", "compensation", "payslip", "employee benefit", "performance review", "disciplinary"),
    "customer_context": ("customer list", "client list", "crm export", "account list", "support export", "vendor payment", "invoice register"),
    "board_context": ("board pack", "board minutes", "executive committee", "exco", "strategy deck", "pricing strategy", "forecast", "merger", "acquisition", "due diligence"),
    "security_ops_context": ("incident response", "vulnerability", "cve-", "edr export", "siem export", "access review", "soc2", "penetration test", "pentest"),
    "repo_archive_context": ("git bundle", "repository export", "source archive", ".git/config", ".git-credentials", "repo backup"),
    "build_log_context": ("build log", "pipeline trace", "ci job log", "deploy log", "artifact upload", "runner token", "release bundle"),
    "special_category_context": ("biometric", "fingerprint", "face id", "facial recognition", "gps", "precise location", "religion", "political opinion", "union membership", "background check"),
    "retention_policy_context": ("retention schedule", "records retention", "legal hold", "litigation hold", "audit evidence", "control testing", "workpaper", "access review"),
}


def _prefilter_active() -> bool:
    return os.getenv("DSPM_DETECTOR_PREFILTER", "1").strip().lower() not in {"0", "false", "no", "off"}


def classify_content(content: str, *, tenant_id: str = "default", _prefilter: bool | None = None) -> list[dict]:
    """Every generic rule over one file's text.

    ``tenant_id`` salts the canonical entity fingerprints (B7) exactly as the
    compliance detectors salt theirs, which is what lets one value found by two
    detectors register as one entity rather than two.
    """
    if not content:
        return []

    # P-D: skip rules whose necessary literal is absent (recall-exact). `_prefilter`
    # is an internal override used by the parity harness/tests to force the full
    # (un-prefiltered) scan for comparison; production callers pass nothing.
    use_prefilter = _prefilter_active() if _prefilter is None else _prefilter
    content_lower = content.lower() if use_prefilter else ""

    findings: list[dict] = []
    for rule in RULES:
        if use_prefilter:
            anchors = _RULE_PREFILTER.get(rule.name)
            if anchors and not any(anchor in content_lower for anchor in anchors):
                continue  # necessary literal absent -> this rule cannot match
        samples: list[str] = []
        total = 0
        examined = 0
        count_capped = False
        extra_fields: dict = {}
        data_class = data_class_for_rule(rule.name)
        fingerprints: list[str] = []
        entity_prints: list[str] = []
        entity_type = _entity_type_for_rule(rule.name, data_class)
        if rule.finder is not None:
            produced = rule.finder(content)
            for value, extra in produced[:COUNT_CAP]:
                if len(samples) < SAMPLE_CAP:
                    samples.append(_redact(value, data_class) if rule.redact else value)
                    _add_fingerprint(fingerprints, value, rule.redact)
                    _add_entity_fingerprint(entity_prints, entity_type, value, rule.redact, tenant_id)
                total += 1
                extra_fields = _merge_rule_extra(extra_fields, extra)
            count_capped = len(produced) > COUNT_CAP
            if total:
                findings.append({
                    "type": rule.name,
                    "risk": cap_severity(rule.risk, str(extra_fields.get("pan_confidence") or "LOW")),
                    "description": rule.description,
                    "count": total,
                    "occurrence_count": total,
                    "sample_count": len(samples),
                    "occurrence_truncated": total > len(samples),
                    "count_capped": count_capped,
                    "samples": samples,
                    "data_class": data_class,
                    "secure_value_fingerprints": fingerprints,
                    "canonical_entity_type": entity_type,
                    "canonical_entity_fingerprints": entity_prints,
                    "unique_value_count": len(set(fingerprints)) or len(set(samples)),
                    **extra_fields,
                })
            continue
        for match in rule.pattern.finditer(content):
            examined += 1
            # value_group isolates the sensitive value from any anchoring label,
            # so validation/redaction/unique-count all key off the value alone.
            value = match.group(rule.value_group) if rule.value_group else match.group(0)
            if value is None:
                value = match.group(0)
            if rule.validator is None or rule.validator(value):
                if len(samples) < SAMPLE_CAP:
                    samples.append(_redact(value, data_class) if rule.redact else value)
                    _add_fingerprint(fingerprints, value, rule.redact)
                    _add_entity_fingerprint(entity_prints, entity_type, value, rule.redact, tenant_id)
                total += 1
            if total >= COUNT_CAP or examined >= MATCH_SCAN_CAP:
                count_capped = True
                break

        if total == 0:
            continue

        findings.append(
            {
                "type": rule.name,
                "risk": rule.risk,
                "description": rule.description,
                "count": total,
                "occurrence_count": total,
                "sample_count": len(samples),
                "occurrence_truncated": total > len(samples),
                "count_capped": count_capped,
                "samples": samples,
                "data_class": data_class,
                # The masked sample is for READING. Distinct-value counting keys
                # off these instead, so two different cards that mask to the
                # same first-six/last-four are still two values.
                "secure_value_fingerprints": fingerprints,
                "canonical_entity_type": entity_type,
                "canonical_entity_fingerprints": entity_prints,
                "unique_value_count": len(set(fingerprints)) or len(set(samples)),
            }
        )

    existing = {finding["type"] for finding in findings}
    for finding in classify_with_ml(content):
        if finding["type"] not in existing:
            findings.append(finding)

    return findings
