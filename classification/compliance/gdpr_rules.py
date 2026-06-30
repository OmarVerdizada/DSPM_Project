from __future__ import annotations

import re
from pathlib import PurePath

from classification.compliance.keywords import (
    ACCOUNT_RECOVERY_KEYWORDS,
    ACCOUNT_USERNAME_KEYWORDS,
    ADDRESS_KEYWORDS,
    BIRTH_KEYWORDS,
    BIOMETRIC_SPECIAL_KEYWORDS,
    BROWSING_HISTORY_KEYWORDS,
    BANK_ACCOUNT_KEYWORDS,
    BACKGROUND_DRUG_TEST_KEYWORDS,
    BENEFITS_INSURANCE_KEYWORDS,
    BOARD_MATERIALS_KEYWORDS,
    COOKIE_DEVICE_ID_KEYWORDS,
    CONTRACT_NDA_LEGAL_KEYWORDS,
    CREDIT_SCORE_REPORT_KEYWORDS,
    CRIMINAL_RECORD_KEYWORDS,
    DATABASE_CONNECTION_KEYWORDS,
    DEVICE_HARDWARE_KEYWORDS,
    DISABILITY_STATUS_KEYWORDS,
    DISASTER_RECOVERY_BCP_KEYWORDS,
    EMAIL_KEYWORDS,
    ENCRYPTION_KEY_MATERIAL_KEYWORDS,
    EMERGENCY_CONTACT_KEYWORDS,
    GEOLOCATION_KEYWORDS,
    GENETIC_DNA_KEYWORDS,
    GOVERNMENT_ID_KEYWORDS,
    HEALTH_MEDICAL_KEYWORDS,
    HR_EMPLOYEE_FILE_KEYWORDS,
    IMMIGRATION_CITIZENSHIP_KEYWORDS,
    INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS,
    INVOICE_BILLING_TRANSACTION_KEYWORDS,
    IP_IDENTIFIER_KEYWORDS,
    LITIGATION_PRIVILEGED_LEGAL_KEYWORDS,
    MENTAL_HEALTH_KEYWORDS,
    MFA_RECOVERY_KEYWORDS,
    NAME_KEYWORDS,
    MA_DUE_DILIGENCE_KEYWORDS,
    NETWORK_ARCHITECTURE_KEYWORDS,
    API_TOKEN_SECRET_KEYWORDS,
    PAYMENT_CARD_KEYWORDS,
    PASSWORD_SECRET_KEYWORDS,
    PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS,
    PHONE_KEYWORDS,
    PHOTO_FACE_KEYWORDS,
    POLITICAL_AFFILIATION_KEYWORDS,
    PRERELEASE_FINANCIAL_KEYWORDS,
    PRICING_MARGIN_FORECAST_KEYWORDS,
    PRIVATE_KEY_CERT_KEYWORDS,
    PATENT_PENDING_KEYWORDS,
    RACE_ETHNICITY_KEYWORDS,
    RELIGIOUS_BELIEF_KEYWORDS,
    SEXUAL_ORIENTATION_KEYWORDS,
    SESSION_TOKEN_JWT_KEYWORDS,
    SECURITY_CONFIG_FIREWALL_KEYWORDS,
    SIGNATURE_KEYWORDS,
    SALARY_COMPENSATION_KEYWORDS,
    SOURCE_CODE_ALGORITHM_KEYWORDS,
    STRATEGY_ROADMAP_PLAN_KEYWORDS,
    TAX_RECORD_KEYWORDS,
    TERMINATION_LAYOFF_KEYWORDS,
    TIMESHEET_ATTENDANCE_KEYWORDS,
    TRADE_UNION_KEYWORDS,
    ORG_CHART_DIRECTORY_KEYWORDS,
    TRADE_SECRET_DESIGN_KEYWORDS,
    VENDOR_SUPPLIER_TERMS_KEYWORDS,
    VEHICLE_KEYWORDS,
    VULNERABILITY_PENTEST_KEYWORDS,
)
from classification.compliance.models import GDPRRule
from classification.compliance.validators import (
    AZ_PLATE_RE,
    ALIEN_NUMBER_RE,
    AWS_ACCESS_KEY_RE,
    BASE64_IMAGE_RE,
    CARD_CVV_RE,
    CARD_EXPIRY_RE,
    CASE_RECORD_RE,
    CLICK_ID_RE,
    COORDINATE_PAIR_RE,
    COOKIE_VALUE_RE,
    CPT_CODE_RE,
    DATE_RE,
    DATABASE_URI_RE,
    DB_KV_CONNECTION_RE,
    DIGITAL_SIGNATURE_RE,
    DNA_SEQUENCE_RE,
    DS160_RE,
    EMAIL_RE,
    ESN_RE,
    FIN_RE,
    GA_CLIENT_ID_RE,
    GENETIC_VARIANT_RE,
    GITHUB_TOKEN_RE,
    HASHED_IP_RE,
    ICCID_RE,
    ICD_CODE_RE,
    I94_RE,
    IMAGE_MIME_RE,
    IBAN_RE,
    IMEI_RE,
    IMEISV_RE,
    IMSI_RE,
    IPV4_CANDIDATE_RE,
    IPV6_CANDIDATE_RE,
    KARYOTYPE_RE,
    LAT_FIELD_RE,
    LNG_FIELD_RE,
    MAC_ADDRESS_RE,
    MAC_DOTTED_RE,
    MASKED_IPV4_RE,
    MASKED_CARD_RE,
    MEDICAL_RECORD_ID_RE,
    MONEY_AMOUNT_RE,
    MEID_RE,
    MFA_RECOVERY_CODE_RE,
    MRZ_RE,
    NATIONAL_ID_RE,
    PASSPORT_RE,
    PHOTO_EXTENSIONS,
    PHONE_RE,
    PAYMENT_CARD_RE,
    PASSWORD_HASH_RE,
    PRIVATE_KEY_BLOCK_RE,
    OTPAUTH_URI_RE,
    PUSH_TOKEN_RE,
    SEARCH_QUERY_RE,
    SEVIS_RE,
    SECRET_ASSIGNMENT_RE,
    SLACK_TOKEN_RE,
    SWIFT_BIC_RE,
    TCF_STRING_RE,
    UUID_RE,
    JWT_RE,
    OPENAI_KEY_RE,
    URL_RE,
    USERNAME_VALUE_RE,
    VEHICLE_SERIAL_RE,
    VISA_PERMIT_RE,
    VIDEO_EXTENSIONS,
    VIDEO_MIME_RE,
    VIN_RE,
    BIOMETRIC_HASH_RE,
    BIOMETRIC_VECTOR_RE,
    CHROMOSOME_RE,
    RSID_RE,
    CREDIT_SCORE_RE,
    ROUTING_ACCOUNT_RE,
    context_values,
    context_keyword_values,
    has_keyword_context,
    is_relationship_value,
    is_valid_imei,
    is_luhn_valid,
    is_valid_address,
    is_valid_contextual_text,
    is_valid_date,
    is_valid_email,
    is_valid_free_text_secret,
    is_valid_ip,
    is_valid_iban,
    is_valid_mac,
    is_valid_name,
    is_valid_phone,
    is_valid_coordinate_pair,
    is_valid_username_value,
    is_valid_secret_value,
    looks_like_base64,
)


def detect_names(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for keyword, value in context_keyword_values(content, NAME_KEYWORDS, max_chars=100):
        lowered_keyword = keyword.lower()
        if any(marker in lowered_keyword for marker in ("username", "user name", "login", "handle", "slug", "user id", "profile id", "account id")):
            continue
        candidate = re.split(r"[,;|]", value, maxsplit=1)[0].strip()
        if is_valid_name(candidate):
            matches.append(candidate)
    return matches


def detect_emails(content: str, _: dict) -> list[str]:
    matches = []
    for match in EMAIL_RE.finditer(content):
        value = match.group(0)
        if is_valid_email(value):
            matches.append(value)
    return matches


def detect_phones(content: str, _: dict) -> list[str]:
    matches = []
    for match in PHONE_RE.finditer(content):
        value = match.group(0)
        if is_valid_phone(value) and has_keyword_context(content, match.start(), PHONE_KEYWORDS, window=70):
            matches.append(value)
    return matches


def detect_addresses(content: str, _: dict) -> list[str]:
    matches = []
    for value in context_values(content, ADDRESS_KEYWORDS, max_chars=180):
        candidate = re.split(r"[;\r\n]", value, maxsplit=1)[0].strip()
        if is_valid_address(candidate):
            matches.append(candidate)
    return matches


def detect_birth_details(content: str, _: dict) -> list[str]:
    matches = []
    for value in context_values(content, BIRTH_KEYWORDS, max_chars=120):
        for date_match in DATE_RE.finditer(value):
            candidate = date_match.group(0)
            if is_valid_date(candidate):
                matches.append(candidate)
        place_candidate = re.split(r"[,;|]", value, maxsplit=1)[0].strip()
        if is_valid_name(place_candidate) and any(marker in value.lower() for marker in ("city", "country", "place", "yer", "seher", "olke", "rayon")):
            matches.append(place_candidate)
    return matches


def detect_fin(content: str, _: dict) -> list[str]:
    matches = []
    for match in FIN_RE.finditer(content):
        value = match.group(0).upper()
        if any(char.isalpha() for char in value) and any(char.isdigit() for char in value) and has_keyword_context(content, match.start(), GOVERNMENT_ID_KEYWORDS, window=80):
            matches.append(value)
    return matches


def detect_national_ids(content: str, _: dict) -> list[str]:
    return [match.group(0).upper().replace(" ", "").replace("-", "") for match in NATIONAL_ID_RE.finditer(content)]


def detect_passports(content: str, _: dict) -> list[str]:
    matches = [match.group(0)[:40] for match in MRZ_RE.finditer(content)]
    passport_context_keywords = ("passport", "pasport", "mrz", "travel document")
    for match in PASSPORT_RE.finditer(content):
        left = content[max(0, match.start() - 80):match.start()].lower()
        if any(keyword in left for keyword in passport_context_keywords):
            matches.append(match.group(0).upper())
    return matches


def detect_signatures(content: str, metadata: dict) -> list[str]:
    matches: list[str] = []
    path_blob = " ".join(str(metadata.get(key) or "") for key in ("path", "name", "extension")).lower()
    signature_context = any(keyword in path_blob or keyword in content.lower() for keyword in SIGNATURE_KEYWORDS)
    image_extension = str(metadata.get("extension") or "").lower() in {".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff", ".bmp", ".pdf"}
    if signature_context and image_extension:
        matches.append(str(metadata.get("name") or PurePath(str(metadata.get("path") or "signature file")).name))
    for pattern in (BASE64_IMAGE_RE, DIGITAL_SIGNATURE_RE):
        for match in pattern.finditer(content):
            if signature_context or "signature" in match.group(0).lower():
                matches.append(match.group(0)[:80])
    for value in context_values(content, SIGNATURE_KEYWORDS, max_chars=220):
        if looks_like_base64(value) or re.fullmatch(r"[A-Fa-f0-9]{32,}", value.strip()):
            matches.append(value[:80])
    return matches


def _metadata_blob(metadata: dict) -> str:
    return " ".join(str(metadata.get(key) or "") for key in ("path", "name", "extension", "content_status", "scan_error")).lower()


def _has_any_context(blob: str, content: str, keywords: tuple[str, ...]) -> bool:
    lowered = content.lower()
    return any(keyword.lower() in blob or keyword.lower() in lowered for keyword in keywords)


def detect_photo_face(content: str, metadata: dict) -> list[str]:
    matches: list[str] = []
    blob = _metadata_blob(metadata)
    extension = str(metadata.get("extension") or "").lower()
    has_context = _has_any_context(blob, content, PHOTO_FACE_KEYWORDS)
    image_like = extension in PHOTO_EXTENSIONS or extension in VIDEO_EXTENSIONS or IMAGE_MIME_RE.search(content) or VIDEO_MIME_RE.search(content)
    if has_context and image_like:
        matches.append(str(metadata.get("name") or PurePath(str(metadata.get("path") or "photo artifact")).name))
    for pattern in (BASE64_IMAGE_RE, IMAGE_MIME_RE, VIDEO_MIME_RE):
        for match in pattern.finditer(content):
            if has_context or has_keyword_context(content, match.start(), PHOTO_FACE_KEYWORDS, window=90):
                matches.append(match.group(0)[:80])
    for value in context_values(content, PHOTO_FACE_KEYWORDS, max_chars=220):
        lowered = value.lower()
        if (
            any(ext in lowered for ext in (".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tiff", ".heic", ".mp4", ".mov"))
            or looks_like_base64(value)
            or IMAGE_MIME_RE.search(value)
            or VIDEO_MIME_RE.search(value)
        ):
            matches.append(value[:100])
        elif re.search(r"\[\s*-?\d+\.\d+(?:\s*,\s*-?\d+\.\d+){3,}", value) and any(marker in lowered for marker in ("face", "facial", "biometric", "embedding", "vector", "template", "uz", "sifet")):
            matches.append(value[:100])
    return matches


def detect_vehicle_identifiers(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for match in AZ_PLATE_RE.finditer(content):
        if has_keyword_context(content, match.start(), VEHICLE_KEYWORDS, window=90):
            matches.append(match.group(0).upper().replace(" ", "").replace("-", ""))
    for match in VIN_RE.finditer(content):
        if has_keyword_context(content, match.start(), VEHICLE_KEYWORDS, window=90):
            matches.append(match.group(0).upper())
    for value in context_values(content, VEHICLE_KEYWORDS, max_chars=80):
        candidate = re.split(r"[,;|]", value, maxsplit=1)[0].strip()
        if AZ_PLATE_RE.fullmatch(candidate) or VIN_RE.fullmatch(candidate) or VEHICLE_SERIAL_RE.fullmatch(candidate):
            matches.append(candidate.upper())
    return matches


def detect_account_recovery(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for value in context_values(content, ACCOUNT_RECOVERY_KEYWORDS, max_chars=180):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        if is_valid_free_text_secret(candidate):
            matches.append(candidate)
    return matches


def detect_emergency_contacts(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for value in context_values(content, EMERGENCY_CONTACT_KEYWORDS, max_chars=250):
        candidate = re.split(r"[\r\n]", value, maxsplit=1)[0].strip(" :=,-")
        if not 2 <= len(candidate) <= 250 or candidate.lower() in {"unknown", "null", "none", "test", "demo", "sample", "n/a", "na"}:
            continue
        components = 0
        if EMAIL_RE.search(candidate):
            components += 1
        if PHONE_RE.search(candidate):
            components += 1
        if is_valid_address(candidate):
            components += 1
        if any(is_relationship_value(part) for part in re.split(r"[,;|/-]", candidate)):
            components += 1
        name_candidate = re.split(r"[,;|/-]", candidate, maxsplit=1)[0].strip()
        if is_valid_name(name_candidate):
            components += 1
        if components >= 1:
            matches.append(candidate[:160])
    return matches


def detect_ip_identifiers(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (IPV4_CANDIDATE_RE, IPV6_CANDIDATE_RE):
        for match in pattern.finditer(content):
            value = match.group(0).strip("[]")
            if is_valid_ip(value) and has_keyword_context(content, match.start(), IP_IDENTIFIER_KEYWORDS, window=90):
                matches.append(value)
    for match in MASKED_IPV4_RE.finditer(content):
        if has_keyword_context(content, match.start(), IP_IDENTIFIER_KEYWORDS, window=90):
            matches.append(match.group(0))
    for match in HASHED_IP_RE.finditer(content):
        if has_keyword_context(content, match.start(), IP_IDENTIFIER_KEYWORDS, window=80):
            matches.append(match.group(0))
    return matches


def detect_cookie_device_ids(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (UUID_RE, GA_CLIENT_ID_RE, CLICK_ID_RE, PUSH_TOKEN_RE, TCF_STRING_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), COOKIE_DEVICE_ID_KEYWORDS, window=100):
                matches.append(match.group(0)[:100])
    for value in context_values(content, COOKIE_DEVICE_ID_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        if UUID_RE.fullmatch(candidate) or GA_CLIENT_ID_RE.fullmatch(candidate) or COOKIE_VALUE_RE.fullmatch(candidate):
            matches.append(candidate[:100])
    return matches


def detect_device_hardware_ids(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (MAC_ADDRESS_RE, MAC_DOTTED_RE):
        for match in pattern.finditer(content):
            value = match.group(0)
            if is_valid_mac(value) and has_keyword_context(content, match.start(), DEVICE_HARDWARE_KEYWORDS, window=90):
                matches.append(value.upper())
    for match in IMEI_RE.finditer(content):
        value = match.group(0)
        if is_valid_imei(value) and has_keyword_context(content, match.start(), DEVICE_HARDWARE_KEYWORDS, window=90):
            matches.append(value)
    for pattern in (IMEISV_RE, MEID_RE, ESN_RE, IMSI_RE, ICCID_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), DEVICE_HARDWARE_KEYWORDS, window=90):
                matches.append(match.group(0).upper())
    for value in context_values(content, DEVICE_HARDWARE_KEYWORDS, max_chars=100):
        candidate = re.split(r"[,;|]", value, maxsplit=1)[0].strip()
        if (MAC_ADDRESS_RE.fullmatch(candidate) and is_valid_mac(candidate)) or (MAC_DOTTED_RE.fullmatch(candidate) and is_valid_mac(candidate)):
            matches.append(candidate.upper())
        elif IMEI_RE.fullmatch(candidate) and is_valid_imei(candidate):
            matches.append(candidate)
        elif IMEISV_RE.fullmatch(candidate) or MEID_RE.fullmatch(candidate) or ESN_RE.fullmatch(candidate) or IMSI_RE.fullmatch(candidate) or ICCID_RE.fullmatch(candidate):
            matches.append(candidate.upper())
    return matches


def detect_geolocation(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for match in COORDINATE_PAIR_RE.finditer(content):
        if is_valid_coordinate_pair(match.group(1), match.group(2)) and has_keyword_context(content, match.start(), GEOLOCATION_KEYWORDS, window=140):
            matches.append(match.group(0))
    for value in context_values(content, GEOLOCATION_KEYWORDS, max_chars=260):
        pair = COORDINATE_PAIR_RE.search(value)
        if pair and is_valid_coordinate_pair(pair.group(1), pair.group(2)):
            matches.append(pair.group(0))
            continue
        lat = LAT_FIELD_RE.search(value)
        lng = LNG_FIELD_RE.search(value)
        if lat and lng and is_valid_coordinate_pair(lat.group(1), lng.group(1)):
            matches.append(f"{lat.group(1)}, {lng.group(1)}")
            continue
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if 4 <= len(candidate) <= 160 and any(marker in lowered for marker in ("street", "road", "baku", "airport", "hospital", "hotel", "school", "mall", "kuce", "seher", "xestexana")):
            matches.append(candidate[:120])
    return matches


def detect_browsing_history(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for match in URL_RE.finditer(content):
        if has_keyword_context(content, match.start(), BROWSING_HISTORY_KEYWORDS, window=120):
            matches.append(match.group(0)[:160])
    for match in SEARCH_QUERY_RE.finditer(content):
        if has_keyword_context(content, match.start(), BROWSING_HISTORY_KEYWORDS, window=100):
            query = match.group(1).strip(" :=,-")
            if 2 <= len(query) <= 160:
                matches.append(query)
    for value in context_values(content, BROWSING_HISTORY_KEYWORDS, max_chars=260):
        url = URL_RE.search(value)
        if url:
            matches.append(url.group(0)[:160])
            continue
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if 3 <= len(candidate) <= 180 and (
            any(marker in lowered for marker in ("click", "page", "search", "query", "referrer", "referer", "utm_", "visited", "session"))
            or len(candidate.split()) >= 2
            or re.search(r"\b/[A-Za-z0-9._~/?#\[\]@!$&'()*+,;=-]{3,}", candidate)
        ):
            matches.append(candidate[:160])
    return matches


def detect_account_usernames(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for value in context_values(content, ACCOUNT_USERNAME_KEYWORDS, max_chars=180):
        for part in re.split(r"[,;|\r\n]", value):
            candidate = part.strip(" :=,-")
            url = URL_RE.search(candidate)
            if url:
                slug = url.group(0).rstrip("/").rsplit("/", 1)[-1]
                if is_valid_username_value(slug):
                    matches.append(slug)
                continue
            username = USERNAME_VALUE_RE.search(candidate)
            if username and is_valid_username_value(username.group(0)):
                matches.append(username.group(0))
                break
    return matches


def detect_health_medical(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    genetic_markers = ("genetic", "genomic", "gene", "dna", "brca", "genotype", "allele", "chromosome", "haplogroup", "pgx")
    for pattern in (MEDICAL_RECORD_ID_RE, ICD_CODE_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), HEALTH_MEDICAL_KEYWORDS, window=110) and not has_keyword_context(content, match.start(), BACKGROUND_DRUG_TEST_KEYWORDS, window=140):
                matches.append(match.group(0).upper())
    for match in CPT_CODE_RE.finditer(content):
        if has_keyword_context(content, match.start(), HEALTH_MEDICAL_KEYWORDS, window=90) and not has_keyword_context(content, match.start(), BACKGROUND_DRUG_TEST_KEYWORDS, window=140):
            matches.append(match.group(0))
    for keyword, value in context_keyword_values(content, HEALTH_MEDICAL_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if any(marker in f"{keyword.lower()} {lowered}" for marker in ("background check", "drug test", "drug screening", "toxicology", "employment screening")):
            continue
        if any(marker in f"{keyword.lower()} {lowered}" for marker in genetic_markers):
            continue
        if (
            ICD_CODE_RE.search(candidate)
            or MEDICAL_RECORD_ID_RE.search(candidate)
            or any(marker in lowered for marker in ("positive", "negative", "diagnosed", "diagnosis", "mg", "ml", "mmhg", "bpm", "icd", "cpt", "xeste", "diaqnoz", "derman"))
            or is_valid_contextual_text(candidate, min_length=5, max_length=180)
        ):
            matches.append(candidate[:160])
    return matches


def detect_mental_health(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    strong_markers = (
        "depression", "anxiety", "ptsd", "ocd", "adhd", "autism", "bipolar", "schizophrenia",
        "suicidal", "self-harm", "substance", "addiction", "opioid", "cocaine", "heroin",
        "methadone", "buprenorphine", "naloxone", "overdose", "rehab", "detox", "psixi",
        "psixiatriya", "depressiya",
    )
    for keyword, value in context_keyword_values(content, MENTAL_HEALTH_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if any(marker in f"{keyword.lower()} {lowered}" for marker in ("background check", "drug test", "drug screening", "toxicology", "employment screening")):
            continue
        if any(marker in lowered for marker in strong_markers) or is_valid_contextual_text(candidate, min_length=5, max_length=180):
            matches.append(candidate[:160])
    for marker in strong_markers:
        for match in re.finditer(rf"\b{re.escape(marker)}\b", content, re.IGNORECASE):
            if has_keyword_context(content, match.start(), MENTAL_HEALTH_KEYWORDS, window=120):
                matches.append(match.group(0))
    return matches


def detect_disability_status(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    disability_markers = (
        "certificate", "card", "benefit", "allowance", "pension", "assessment", "impairment",
        "wheelchair", "hearing aid", "prosthesis", "orthosis", "screen reader", "braille",
        "sign language", "accommodation", "restriction", "incapacity", "elillik", "elil",
    )
    for value in context_values(content, DISABILITY_STATUS_KEYWORDS, max_chars=240):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if any(marker in lowered for marker in disability_markers) or is_valid_contextual_text(candidate, min_length=5, max_length=170):
            matches.append(candidate[:150])
    return matches


def detect_biometric_special(content: str, metadata: dict) -> list[str]:
    matches: list[str] = []
    blob = _metadata_blob(metadata)
    has_context = _has_any_context(blob, content, BIOMETRIC_SPECIAL_KEYWORDS)
    if has_context and str(metadata.get("extension") or "").lower() in PHOTO_EXTENSIONS | VIDEO_EXTENSIONS | {".wav", ".mp3", ".m4a", ".flac"}:
        matches.append(str(metadata.get("name") or PurePath(str(metadata.get("path") or "biometric artifact")).name))
    for pattern in (BIOMETRIC_HASH_RE, BIOMETRIC_VECTOR_RE, BASE64_IMAGE_RE, IMAGE_MIME_RE, VIDEO_MIME_RE):
        for match in pattern.finditer(content):
            if has_context or has_keyword_context(content, match.start(), BIOMETRIC_SPECIAL_KEYWORDS, window=120):
                matches.append(match.group(0)[:120])
    for value in context_values(content, BIOMETRIC_SPECIAL_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        if (
            BIOMETRIC_HASH_RE.search(candidate)
            or BIOMETRIC_VECTOR_RE.search(candidate)
            or looks_like_base64(candidate)
            or is_valid_contextual_text(candidate, min_length=5, max_length=160)
        ):
            matches.append(candidate[:120])
    return matches


def detect_genetic_dna(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (RSID_RE, GENETIC_VARIANT_RE, CHROMOSOME_RE, KARYOTYPE_RE, DNA_SEQUENCE_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), GENETIC_DNA_KEYWORDS, window=140):
                matches.append(match.group(0)[:120])
    for value in context_values(content, GENETIC_DNA_KEYWORDS, max_chars=280):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if (
            RSID_RE.search(candidate)
            or GENETIC_VARIANT_RE.search(candidate)
            or CHROMOSOME_RE.search(candidate)
            or KARYOTYPE_RE.search(candidate)
            or DNA_SEQUENCE_RE.search(candidate)
            or any(marker in lowered for marker in ("brca", "genotype", "allele", "mutation", "variant", "carrier", "haplogroup", "pgx", "genom", "dna"))
            or is_valid_contextual_text(candidate, min_length=5, max_length=180)
        ):
            matches.append(candidate[:160])
    return matches


def detect_race_ethnicity(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for value in context_values(content, RACE_ETHNICITY_KEYWORDS, max_chars=220):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        if is_valid_contextual_text(candidate, min_length=3, max_length=160):
            matches.append(candidate[:140])
    return matches


def detect_religious_beliefs(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for value in context_values(content, RELIGIOUS_BELIEF_KEYWORDS, max_chars=220):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        if is_valid_contextual_text(candidate, min_length=3, max_length=160):
            matches.append(candidate[:140])
    return matches


def _detect_special_context_values(content: str, keywords: tuple[str, ...], max_chars: int = 220) -> list[str]:
    matches: list[str] = []
    for value in context_values(content, keywords, max_chars=max_chars):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        if is_valid_contextual_text(candidate, min_length=3, max_length=170):
            matches.append(candidate[:150])
    return matches


def detect_political_affiliation(content: str, _: dict) -> list[str]:
    return _detect_special_context_values(content, POLITICAL_AFFILIATION_KEYWORDS)


def detect_sexual_orientation(content: str, _: dict) -> list[str]:
    return _detect_special_context_values(content, SEXUAL_ORIENTATION_KEYWORDS)


def detect_trade_union(content: str, _: dict) -> list[str]:
    return _detect_special_context_values(content, TRADE_UNION_KEYWORDS)


def detect_immigration_citizenship(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (ALIEN_NUMBER_RE, I94_RE, SEVIS_RE, DS160_RE, VISA_PERMIT_RE, CASE_RECORD_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), IMMIGRATION_CITIZENSHIP_KEYWORDS, window=130):
                matches.append(match.group(0)[:120])
    matches.extend(_detect_special_context_values(content, IMMIGRATION_CITIZENSHIP_KEYWORDS, max_chars=260))
    return matches


def detect_criminal_records(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    explicit_criminal_markers = ("criminal record", "criminal history", "conviction", "criminal charge", "arrest", "court record", "criminal proceedings")
    incident_security_markers = ("security incident", "incident report", "ioc", "root cause analysis", "dfir", "incident response", "audit logs", "access logs")
    for pattern in (CASE_RECORD_RE, NATIONAL_ID_RE, FIN_RE):
        for match in pattern.finditer(content):
            left = content[max(0, match.start() - 140):match.start()].lower()
            if has_keyword_context(content, match.start(), CRIMINAL_RECORD_KEYWORDS, window=130) and (
                not has_keyword_context(content, match.start(), BACKGROUND_DRUG_TEST_KEYWORDS, window=140)
                or any(marker in left for marker in explicit_criminal_markers)
            ):
                matches.append(match.group(0)[:120])
    for keyword, value in context_keyword_values(content, CRIMINAL_RECORD_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        context_blob = f"{keyword.lower()} {candidate.lower()}"
        if any(marker in context_blob for marker in incident_security_markers) and not any(marker in context_blob for marker in explicit_criminal_markers):
            continue
        if any(marker in context_blob for marker in ("background check", "background screening", "employment screening", "police clearance")) and not any(marker in context_blob for marker in explicit_criminal_markers):
            continue
        if is_valid_contextual_text(candidate, min_length=3, max_length=170):
            matches.append(candidate[:150])
    return matches


def detect_payment_card_data(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for match in PAYMENT_CARD_RE.finditer(content):
        value = match.group(0)
        if is_luhn_valid(value) and has_keyword_context(content, match.start(), PAYMENT_CARD_KEYWORDS, window=120):
            matches.append(value)
    for pattern in (MASKED_CARD_RE, CARD_EXPIRY_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), PAYMENT_CARD_KEYWORDS, window=100):
                matches.append(match.group(0))
    for value in context_values(content, PAYMENT_CARD_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        if PAYMENT_CARD_RE.search(candidate) and is_luhn_valid(candidate):
            matches.append(PAYMENT_CARD_RE.search(candidate).group(0))
        elif MASKED_CARD_RE.search(candidate) or CARD_EXPIRY_RE.search(candidate):
            matches.append(candidate[:140])
        elif CARD_CVV_RE.fullmatch(candidate) and len(candidate) in (3, 4):
            matches.append(candidate)
        elif is_valid_contextual_text(candidate, min_length=5, max_length=160) and any(
            marker in candidate.lower() for marker in ("token", "vault", "track", "emv", "auth", "cvv", "cvc", "pin", "last4", "card")
        ):
            matches.append(candidate[:140])
    return matches


def detect_bank_account_data(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for match in IBAN_RE.finditer(content):
        value = match.group(0)
        if is_valid_iban(value) and has_keyword_context(content, match.start(), BANK_ACCOUNT_KEYWORDS, window=120):
            matches.append(value.upper())
    for pattern in (SWIFT_BIC_RE, ROUTING_ACCOUNT_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), BANK_ACCOUNT_KEYWORDS, window=120):
                matches.append(match.group(0)[:120])
    for value in context_values(content, BANK_ACCOUNT_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        iban = IBAN_RE.search(candidate)
        if iban and is_valid_iban(iban.group(0)):
            matches.append(iban.group(0).upper())
        elif SWIFT_BIC_RE.search(candidate) or ROUTING_ACCOUNT_RE.search(candidate) or is_valid_contextual_text(candidate, min_length=5, max_length=170):
            matches.append(candidate[:150])
    return matches


def detect_tax_records(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    secret_context = PASSWORD_SECRET_KEYWORDS + API_TOKEN_SECRET_KEYWORDS + PRIVATE_KEY_CERT_KEYWORDS
    for pattern in (FIN_RE, NATIONAL_ID_RE, CASE_RECORD_RE, MONEY_AMOUNT_RE):
        for match in pattern.finditer(content):
            value = match.group(0)
            if pattern is FIN_RE and not (any(char.isalpha() for char in value) and any(char.isdigit() for char in value)):
                continue
            if has_keyword_context(content, match.start(), TAX_RECORD_KEYWORDS, window=120) and not has_keyword_context(content, match.start(), secret_context, window=120):
                matches.append(value[:120])
    matches.extend(_detect_special_context_values(content, TAX_RECORD_KEYWORDS, max_chars=260))
    return matches


def detect_salary_compensation(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for match in MONEY_AMOUNT_RE.finditer(content):
        if (
            has_keyword_context(content, match.start(), SALARY_COMPENSATION_KEYWORDS, window=120)
            and not has_keyword_context(content, match.start(), PRERELEASE_FINANCIAL_KEYWORDS + PRICING_MARGIN_FORECAST_KEYWORDS, window=120)
            and not has_keyword_context(content, match.start(), TERMINATION_LAYOFF_KEYWORDS, window=120)
            and not has_keyword_context(content, match.start(), TIMESHEET_ATTENDANCE_KEYWORDS, window=120)
        ):
            matches.append(match.group(0).strip())
    for keyword, value in context_keyword_values(content, SALARY_COMPENSATION_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        context_blob = f"{keyword} {candidate}".lower()
        if any(marker in context_blob for marker in ("income statement", "revenue", "forecast", "pricing", "price list", "financial statement", "termination", "layoff", "final pay", "severance", "timesheet", "overtime hours", "hours worked", "clock in", "clock out")):
            continue
        if is_valid_contextual_text(candidate, min_length=3, max_length=170):
            matches.append(candidate[:150])
    return matches


def detect_credit_score_report(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for match in CREDIT_SCORE_RE.finditer(content):
        if has_keyword_context(content, match.start(), CREDIT_SCORE_REPORT_KEYWORDS, window=120):
            matches.append(match.group(0))
    for value in context_values(content, CREDIT_SCORE_REPORT_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        if CREDIT_SCORE_RE.search(candidate) or MONEY_AMOUNT_RE.search(candidate) or is_valid_contextual_text(candidate, min_length=4, max_length=180):
            matches.append(candidate[:160])
    return matches


def detect_invoice_billing_transaction(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    corporate_ip_context = SOURCE_CODE_ALGORITHM_KEYWORDS + TRADE_SECRET_DESIGN_KEYWORDS + PATENT_PENDING_KEYWORDS + MA_DUE_DILIGENCE_KEYWORDS
    for pattern in (CASE_RECORD_RE, MONEY_AMOUNT_RE, UUID_RE):
        for match in pattern.finditer(content):
            if (
                has_keyword_context(content, match.start(), INVOICE_BILLING_TRANSACTION_KEYWORDS, window=130)
                and not has_keyword_context(content, match.start(), corporate_ip_context, window=150)
            ):
                matches.append(match.group(0)[:120])
    for keyword, value in context_keyword_values(content, INVOICE_BILLING_TRANSACTION_KEYWORDS, max_chars=280):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        context_blob = f"{keyword.lower()} {candidate.lower()}"
        if any(marker in context_blob for marker in ("source code", "trade secret", "patent pending", "invention disclosure", "due diligence", "data room", "loi", "qoe")):
            continue
        if is_valid_contextual_text(candidate, min_length=4, max_length=180):
            matches.append(candidate[:160])
    return matches


def detect_prerelease_financial(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (MONEY_AMOUNT_RE, CASE_RECORD_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), PRERELEASE_FINANCIAL_KEYWORDS, window=140):
                matches.append(match.group(0)[:120])
    matches.extend(_detect_special_context_values(content, PRERELEASE_FINANCIAL_KEYWORDS, max_chars=280))
    return matches


def detect_pricing_margin_forecast(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    percent_re = re.compile(r"(?<!\w)\d{1,3}(?:\.\d+)?\s*%(?!\w)")
    legal_vendor_context = CONTRACT_NDA_LEGAL_KEYWORDS + LITIGATION_PRIVILEGED_LEGAL_KEYWORDS + VENDOR_SUPPLIER_TERMS_KEYWORDS + BOARD_MATERIALS_KEYWORDS
    for pattern in (MONEY_AMOUNT_RE, percent_re, CASE_RECORD_RE):
        for match in pattern.finditer(content):
            if (
                has_keyword_context(content, match.start(), PRICING_MARGIN_FORECAST_KEYWORDS, window=140)
                and not has_keyword_context(content, match.start(), legal_vendor_context, window=150)
            ):
                matches.append(match.group(0)[:120])
    for keyword, value in context_keyword_values(content, PRICING_MARGIN_FORECAST_KEYWORDS, max_chars=280):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        context_blob = f"{keyword.lower()} {candidate.lower()}"
        if any(marker in context_blob for marker in ("contract", "agreement", "nda", "legal hold", "litigation", "vendor terms", "supplier agreement", "payment terms", "approved vendor", "vendor scorecard", "supplier scorecard", "board minutes")):
            continue
        if is_valid_contextual_text(candidate, min_length=4, max_length=180):
            matches.append(candidate[:160])
    return matches


def _secret_assignment_values(content: str, keywords: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for match in SECRET_ASSIGNMENT_RE.finditer(content):
        if has_keyword_context(content, match.start(), keywords, window=80) or any(keyword.lower() in match.group(0).lower() for keyword in keywords):
            value = match.group(1).strip().strip("'\"")
            if is_valid_secret_value(value):
                matches.append(value[:160])
    return matches


def detect_password_secrets(content: str, _: dict) -> list[str]:
    matches = _secret_assignment_values(content, PASSWORD_SECRET_KEYWORDS)
    for pattern in (PASSWORD_HASH_RE,):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), PASSWORD_SECRET_KEYWORDS, window=120):
                matches.append(match.group(0)[:160])
    for value in context_values(content, PASSWORD_SECRET_KEYWORDS, max_chars=220):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-'\"")
        if is_valid_secret_value(candidate) or PASSWORD_HASH_RE.fullmatch(candidate):
            matches.append(candidate[:160])
    return matches


def detect_api_token_secrets(content: str, _: dict) -> list[str]:
    matches = _secret_assignment_values(content, API_TOKEN_SECRET_KEYWORDS)
    for pattern in (JWT_RE, AWS_ACCESS_KEY_RE, GITHUB_TOKEN_RE, OPENAI_KEY_RE, SLACK_TOKEN_RE, PUSH_TOKEN_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), API_TOKEN_SECRET_KEYWORDS, window=120) or pattern in (JWT_RE, AWS_ACCESS_KEY_RE, GITHUB_TOKEN_RE, OPENAI_KEY_RE, SLACK_TOKEN_RE):
                matches.append(match.group(0)[:180])
    for keyword, value in context_keyword_values(content, API_TOKEN_SECRET_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-'\"")
        keyword_l = keyword.lower()
        if not any(marker in keyword_l for marker in ("api", "token", "oauth", "bearer", "jwt", "client secret", "webhook", "provider", "github", "gitlab", "openai", "slack", "aws", "azure", "google")):
            continue
        if is_valid_secret_value(candidate):
            matches.append(candidate[:180])
    return matches


def detect_private_key_cert_secrets(content: str, metadata: dict) -> list[str]:
    matches: list[str] = []
    blob = _metadata_blob(metadata)
    has_context = _has_any_context(blob, content, PRIVATE_KEY_CERT_KEYWORDS)
    for match in PRIVATE_KEY_BLOCK_RE.finditer(content):
        matches.append(match.group(0)[:180])
    for keyword, value in context_keyword_values(content, PRIVATE_KEY_CERT_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-'\"")
        context_blob = f"{keyword} {candidate}".lower()
        if not any(marker in context_blob for marker in ("private", "ssh", "pem", ".key", "id_rsa", "id_ed25519", "pfx", "p12", "pkcs12", "jks", "keystore", "truststore", "certificate", "cert", "signing key", "saml", "hmac", "symmetric")):
            continue
        lowered = candidate.lower()
        if PRIVATE_KEY_BLOCK_RE.search(candidate) or any(marker in lowered for marker in (".pem", ".key", "id_rsa", "id_ed25519", "privkey", "server.key", "client.key")):
            matches.append(candidate[:160])
        elif has_context and is_valid_secret_value(candidate) and any(marker in lowered for marker in ("key", "pfx", "p12", "jks", "keystore", "passphrase")):
            matches.append(candidate[:160])
    return matches


def detect_database_connections(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (DATABASE_URI_RE, DB_KV_CONNECTION_RE):
        for match in pattern.finditer(content):
            value = match.group(0)
            if has_keyword_context(content, match.start(), DATABASE_CONNECTION_KEYWORDS, window=120) or "://" in value or "password" in value.lower() or "pwd" in value.lower():
                matches.append(value[:180])
    matches.extend(_secret_assignment_values(content, DATABASE_CONNECTION_KEYWORDS))
    for value in context_values(content, DATABASE_CONNECTION_KEYWORDS, max_chars=320):
        candidate = re.split(r"[\r\n|]", value, maxsplit=1)[0].strip(" :=,-'\"")
        if DATABASE_URI_RE.search(candidate) or DB_KV_CONNECTION_RE.search(candidate) or (";" in candidate and any(marker in candidate.lower() for marker in ("password", "pwd", "user id", "database"))):
            matches.append(candidate[:180])
    return matches


def detect_encryption_key_material(content: str, _: dict) -> list[str]:
    matches = [value for value in _secret_assignment_values(content, ENCRYPTION_KEY_MATERIAL_KEYWORDS) if not JWT_RE.fullmatch(value)]
    for value in context_values(content, ENCRYPTION_KEY_MATERIAL_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-'\"")
        if JWT_RE.fullmatch(candidate):
            continue
        if is_valid_secret_value(candidate) or re.fullmatch(r"[A-Fa-f0-9]{32,128}", candidate):
            matches.append(candidate[:180])
    return matches


def detect_session_tokens(content: str, _: dict) -> list[str]:
    matches = _secret_assignment_values(content, SESSION_TOKEN_JWT_KEYWORDS)
    for pattern in (JWT_RE, UUID_RE, COOKIE_VALUE_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), MFA_RECOVERY_KEYWORDS, window=120):
                continue
            if has_keyword_context(content, match.start(), SESSION_TOKEN_JWT_KEYWORDS, window=100) or pattern is JWT_RE:
                matches.append(match.group(0)[:180])
    for value in context_values(content, SESSION_TOKEN_JWT_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-'\"")
        if JWT_RE.fullmatch(candidate) or is_valid_secret_value(candidate):
            matches.append(candidate[:180])
    return matches


def detect_mfa_recovery(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (OTPAUTH_URI_RE, MFA_RECOVERY_CODE_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), MFA_RECOVERY_KEYWORDS, window=120):
                matches.append(match.group(0)[:180])
    matches.extend(_secret_assignment_values(content, MFA_RECOVERY_KEYWORDS))
    for value in context_values(content, MFA_RECOVERY_KEYWORDS, max_chars=260):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-'\"")
        if OTPAUTH_URI_RE.fullmatch(candidate) or MFA_RECOVERY_CODE_RE.fullmatch(candidate) or is_valid_secret_value(candidate):
            matches.append(candidate[:180])
    return matches


def detect_hr_employee_file(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    dedicated_hr_context = TIMESHEET_ATTENDANCE_KEYWORDS + ORG_CHART_DIRECTORY_KEYWORDS + TERMINATION_LAYOFF_KEYWORDS
    for keyword, value in context_keyword_values(content, HR_EMPLOYEE_FILE_KEYWORDS, max_chars=280):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        context_blob = f"{keyword.lower()} {lowered}"
        if any(marker in context_blob for marker in ("timesheet", "clock in", "org chart", "termination plan", "layoff plan", "final pay")):
            continue
        if any(keyword.lower() in context_blob for keyword in dedicated_hr_context):
            continue
        if is_valid_contextual_text(candidate, min_length=4, max_length=190) or any(marker in lowered for marker in ("review", "warning", "grievance", "disciplinary", "terminated", "pip", "complaint")):
            matches.append(candidate[:170])
    return matches


def detect_benefits_insurance(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    corporate_ip_context = (
        SOURCE_CODE_ALGORITHM_KEYWORDS + TRADE_SECRET_DESIGN_KEYWORDS + PATENT_PENDING_KEYWORDS + MA_DUE_DILIGENCE_KEYWORDS
        + BOARD_MATERIALS_KEYWORDS + STRATEGY_ROADMAP_PLAN_KEYWORDS + CONTRACT_NDA_LEGAL_KEYWORDS
        + LITIGATION_PRIVILEGED_LEGAL_KEYWORDS + VENDOR_SUPPLIER_TERMS_KEYWORDS
    )
    for pattern in (CASE_RECORD_RE, MONEY_AMOUNT_RE):
        for match in pattern.finditer(content):
            if (
                has_keyword_context(content, match.start(), BENEFITS_INSURANCE_KEYWORDS, window=130)
                and not has_keyword_context(content, match.start(), corporate_ip_context, window=150)
            ):
                matches.append(match.group(0)[:120])
    for keyword, value in context_keyword_values(content, BENEFITS_INSURANCE_KEYWORDS, max_chars=280):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        context_blob = f"{keyword.lower()} {candidate.lower()}"
        if any(marker in context_blob for marker in ("source code", "trade secret", "patent pending", "invention disclosure", "prior art", "due diligence", "data room", "loi", "qoe", "contract", "agreement", "legal hold", "litigation", "settlement", "privilege", "vendor terms", "supplier agreement", "board minutes", "roadmap")):
            continue
        if is_valid_contextual_text(candidate, min_length=4, max_length=190):
            matches.append(candidate[:170])
    return matches


def detect_background_drug_tests(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (CASE_RECORD_RE, DATE_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), BACKGROUND_DRUG_TEST_KEYWORDS, window=130):
                matches.append(match.group(0)[:120])
    for value in context_values(content, BACKGROUND_DRUG_TEST_KEYWORDS, max_chars=280):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if is_valid_contextual_text(candidate, min_length=4, max_length=190) or any(marker in lowered for marker in ("positive", "negative", "clear", "failed", "passed", "pending", "toxicology")):
            matches.append(candidate[:170])
    return matches


def detect_timesheet_attendance(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (DATE_RE, MONEY_AMOUNT_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), TIMESHEET_ATTENDANCE_KEYWORDS, window=130):
                matches.append(match.group(0)[:120])
    for value in context_values(content, TIMESHEET_ATTENDANCE_KEYWORDS, max_chars=280):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if is_valid_contextual_text(candidate, min_length=3, max_length=190) or any(marker in lowered for marker in ("clock", "shift", "late", "absent", "hours", "overtime", "pto")):
            matches.append(candidate[:170])
    return matches


def detect_org_chart_directory(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for value in context_values(content, ORG_CHART_DIRECTORY_KEYWORDS, max_chars=280):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if lowered == "plan" or any(marker in lowered for marker in ("disaster recovery", "business continuity", "bcp", "rto", "rpo", "failover", "physical security", "badge", "cctv", "floor plan")):
            continue
        if EMAIL_RE.search(candidate) or PHONE_RE.search(candidate) or is_valid_contextual_text(candidate, min_length=3, max_length=190) or any(marker in lowered for marker in ("manager", "department", "reports to", "director", "team")):
            matches.append(candidate[:170])
    return matches


def detect_termination_layoff(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    legal_vendor_context = CONTRACT_NDA_LEGAL_KEYWORDS + VENDOR_SUPPLIER_TERMS_KEYWORDS + LITIGATION_PRIVILEGED_LEGAL_KEYWORDS
    for pattern in (DATE_RE, MONEY_AMOUNT_RE, CASE_RECORD_RE):
        for match in pattern.finditer(content):
            if (
                has_keyword_context(content, match.start(), TERMINATION_LAYOFF_KEYWORDS, window=140)
                and not has_keyword_context(content, match.start(), legal_vendor_context, window=150)
            ):
                matches.append(match.group(0)[:120])
    for value in context_values(content, TERMINATION_LAYOFF_KEYWORDS, max_chars=300):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if any(marker in lowered for marker in ("termination clause", "contract termination", "agreement termination", "vendor termination", "supplier termination", "limitation of liability", "governing law", "legal agreement")):
            continue
        if is_valid_contextual_text(candidate, min_length=4, max_length=200) or any(marker in lowered for marker in ("layoff", "severance", "notice", "exit", "offboarding", "role eliminated")):
            matches.append(candidate[:180])
    return matches


def detect_source_code_algorithm(content: str, metadata: dict) -> list[str]:
    matches: list[str] = []
    extension = str(metadata.get("extension") or "").lower()
    code_extensions = {".py", ".js", ".ts", ".java", ".cs", ".cpp", ".c", ".go", ".rs", ".php", ".rb", ".swift", ".kt", ".sql", ".ipynb"}
    blob = _metadata_blob(metadata)
    if extension in code_extensions and _has_any_context(blob, content, SOURCE_CODE_ALGORITHM_KEYWORDS):
        matches.append(str(metadata.get("name") or PurePath(str(metadata.get("path") or "source artifact")).name))
    for value in context_values(content, SOURCE_CODE_ALGORITHM_KEYWORDS, max_chars=300):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if (
            re.search(r"\b(?:def|class|function|import|package|public|private|select|create table)\b", candidate)
            or any(marker in lowered for marker in (".py", ".js", ".ts", ".java", ".sql", "git", "repo", "algorithm", "model", "schema"))
            or is_valid_contextual_text(candidate, min_length=4, max_length=200)
        ):
            matches.append(candidate[:180])
    return matches


def detect_trade_secret_design(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for value in context_values(content, TRADE_SECRET_DESIGN_KEYWORDS, max_chars=320):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if is_valid_contextual_text(candidate, min_length=4, max_length=220) or any(marker in lowered for marker in ("formula", "prototype", "blueprint", "cad", "schematic", "bom", "process", "design")):
            matches.append(candidate[:200])
    return matches


def detect_patent_pending(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    for pattern in (CASE_RECORD_RE, DATE_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), PATENT_PENDING_KEYWORDS, window=140):
                matches.append(match.group(0)[:120])
    for value in context_values(content, PATENT_PENDING_KEYWORDS, max_chars=320):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        lowered = candidate.lower()
        if is_valid_contextual_text(candidate, min_length=4, max_length=220) or any(marker in lowered for marker in ("claim", "invention", "filing", "prior art", "provisional", "patent")):
            matches.append(candidate[:200])
    return matches


def detect_ma_due_diligence(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    security_context = (
        NETWORK_ARCHITECTURE_KEYWORDS + VULNERABILITY_PENTEST_KEYWORDS + SECURITY_CONFIG_FIREWALL_KEYWORDS
        + INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS + DISASTER_RECOVERY_BCP_KEYWORDS + PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS
    )
    ma_markers = (
        "m&a", "merger", "acquisition", "divestiture", "due diligence", "data room",
        "virtual data room", "target company", "buyer", "seller", "loi",
        "term sheet", "spa", "purchase agreement", "valuation", "ebitda",
        "synergy", "qoe", "cap table", "deal memo", "cim", "merger control",
    )
    for pattern in (MONEY_AMOUNT_RE, CASE_RECORD_RE, DATE_RE):
        for match in pattern.finditer(content):
            start = match.start()
            left = content[max(0, start - 150):start].lower()
            right = content[start:min(len(content), start + 150)].lower()
            if (
                has_keyword_context(content, start, MA_DUE_DILIGENCE_KEYWORDS, window=150)
                and any(marker in f"{left} {right}" for marker in ma_markers)
                and not has_keyword_context(content, start, security_context, window=150)
            ):
                matches.append(match.group(0)[:120])
    for keyword, value in context_keyword_values(content, MA_DUE_DILIGENCE_KEYWORDS, max_chars=340):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        context_blob = f"{keyword.lower()} {candidate.lower()}"
        start = content.lower().find(candidate.lower())
        if start >= 0 and has_keyword_context(content, start, security_context, window=150):
            continue
        if any(marker in context_blob for marker in ma_markers) and (
            is_valid_contextual_text(candidate, min_length=4, max_length=230)
            or any(marker in context_blob for marker in ("valuation", "ebitda", "synergy", "data room", "loi", "term sheet", "qoe"))
        ):
            matches.append(candidate[:210])
    return matches


def _detect_business_context(
    content: str,
    keywords: tuple[str, ...],
    markers: tuple[str, ...],
    *,
    max_chars: int = 320,
    pattern_window: int = 150,
) -> list[str]:
    matches: list[str] = []
    for pattern in (CASE_RECORD_RE, MONEY_AMOUNT_RE, DATE_RE):
        for match in pattern.finditer(content):
            start = match.start()
            left = content[max(0, start - pattern_window):start].lower()
            right = content[start:min(len(content), start + pattern_window)].lower()
            context_blob = f"{left} {right}"
            if has_keyword_context(content, start, keywords, window=pattern_window) and any(marker in context_blob for marker in markers):
                matches.append(match.group(0)[:120])
    for keyword, value in context_keyword_values(content, keywords, max_chars=max_chars):
        candidate = re.split(r"[\r\n;|]", value, maxsplit=1)[0].strip(" :=,-")
        context_blob = f"{keyword.lower()} {candidate.lower()}"
        if not any(marker in context_blob for marker in markers):
            continue
        if is_valid_contextual_text(candidate, min_length=4, max_length=230) or any(marker in keyword.lower() for marker in markers):
            matches.append(candidate[:210])
    return matches


def detect_board_materials(content: str, _: dict) -> list[str]:
    markers = (
        "board", "committee", "director", "governance", "minutes", "agenda",
        "resolution", "consent", "approval", "vote", "reserved matters",
        "company secretary", "corporate secretary", "idare heyeti",
        "direktor", "iclas protokolu", "komite",
    )
    return _detect_business_context(content, BOARD_MATERIALS_KEYWORDS, markers, max_chars=340)


def detect_strategy_roadmap_plan(content: str, _: dict) -> list[str]:
    markers = (
        "strategy", "strategic", "roadmap", "plan", "okr", "initiative",
        "growth", "expansion", "launch", "transformation", "operating plan",
        "market", "product", "competitive", "forecast", "strategiya",
        "yol xeritesi", "inkisaf plani",
    )
    return _detect_business_context(content, STRATEGY_ROADMAP_PLAN_KEYWORDS, markers, max_chars=340)


def detect_contract_nda_legal(content: str, _: dict) -> list[str]:
    markers = (
        "contract", "agreement", "nda", "confidentiality", "legal", "clause",
        "liability", "indemnity", "termination", "governing law",
        "jurisdiction", "dpa", "msa", "sow", "sla", "redline",
        "signed", "muqavile", "sazis", "huquqi",
    )
    return _detect_business_context(content, CONTRACT_NDA_LEGAL_KEYWORDS, markers, max_chars=340)


def detect_litigation_privileged_legal(content: str, _: dict) -> list[str]:
    markers = (
        "litigation", "lawsuit", "dispute", "claim", "complaint", "court",
        "subpoena", "deposition", "arbitration", "settlement", "legal hold",
        "privileged", "privilege", "attorney", "counsel", "work product",
        "case strategy", "discovery", "evidence", "witness", "mehkeme", "iddia",
    )
    return _detect_business_context(content, LITIGATION_PRIVILEGED_LEGAL_KEYWORDS, markers, max_chars=340)


def detect_vendor_supplier_terms(content: str, _: dict) -> list[str]:
    markers = (
        "vendor", "supplier", "procurement", "purchase order", "po",
        "payment terms", "delivery terms", "rebate", "discount", "sla",
        "service level", "third party", "scorecard", "onboarding",
        "preferred supplier", "approved vendor", "techizatci", "tedarukcu",
    )
    security_context = (
        NETWORK_ARCHITECTURE_KEYWORDS + VULNERABILITY_PENTEST_KEYWORDS + SECURITY_CONFIG_FIREWALL_KEYWORDS
        + INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS + DISASTER_RECOVERY_BCP_KEYWORDS + PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS
    )
    matches: list[str] = []
    for value in _detect_business_context(content, VENDOR_SUPPLIER_TERMS_KEYWORDS, markers, max_chars=340):
        start = content.lower().find(value.lower())
        if start >= 0 and has_keyword_context(content, start, security_context, window=150):
            continue
        matches.append(value)
    return matches


def detect_network_architecture(content: str, _: dict) -> list[str]:
    markers = (
        "network", "topology", "architecture", "diagram", "infrastructure",
        "subnet", "cidr", "vpc", "vnet", "routing", "vlan", "dmz",
        "firewall", "vpn", "zero trust", "ztna", "data flow", "dfd",
        "hld", "lld", "cloud", "kubernetes", "siem", "soc", "ot",
        "ics", "scada", "sebeke", "arxitektura", "diaqram",
    )
    return _detect_business_context(content, NETWORK_ARCHITECTURE_KEYWORDS, markers, max_chars=360)


def detect_vulnerability_pentest(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    cvss_re = re.compile(r"\bCVSS\s*(?:v[23](?:\.\d)?)?\s*[:=]?\s*(?:10(?:\.0)?|[0-9](?:\.\d)?)\b", re.IGNORECASE)
    for pattern in (cve_re, cvss_re, CASE_RECORD_RE, DATE_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), VULNERABILITY_PENTEST_KEYWORDS, window=150):
                matches.append(match.group(0)[:120])
    markers = (
        "vulnerability", "pentest", "penetration", "security assessment",
        "finding", "weakness", "exploit", "cve", "cvss", "severity",
        "critical", "high", "remediation", "attack surface", "exposure",
        "poc", "proof of concept", "nessus", "qualys", "rapid7", "burp",
        "zaafliq",
    )
    matches.extend(_detect_business_context(content, VULNERABILITY_PENTEST_KEYWORDS, markers, max_chars=360))
    return matches


def detect_security_config_firewall(content: str, _: dict) -> list[str]:
    markers = (
        "security config", "configuration", "hardening", "baseline",
        "firewall", "rule", "policy", "acl", "nacl", "security group",
        "nsg", "allow", "deny", "permit", "block", "ingress", "egress",
        "nat", "waf", "iptables", "ufw", "cisco", "palo alto",
        "fortigate", "checkpoint", "cis benchmark", "konfiqurasiya",
        "qayda",
    )
    return _detect_business_context(content, SECURITY_CONFIG_FIREWALL_KEYWORDS, markers, max_chars=360)


def detect_incident_access_audit_log(content: str, _: dict) -> list[str]:
    markers = (
        "incident", "security incident", "breach", "compromise", "unauthorized access",
        "suspicious", "ioc", "indicator", "threat actor", "forensic", "dfir",
        "incident response", "evidence", "chain of custody", "affected",
        "exfiltration", "malware", "ransomware", "phishing", "authentication logs",
        "login logs", "access logs", "audit logs", "event logs", "cloudtrail",
        "edr telemetry", "root cause", "postmortem", "sev1", "sev2",
        "insident", "tehlukesizlik", "giris loglari",
    )
    return _detect_business_context(content, INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS, markers, max_chars=380)


def detect_disaster_recovery_bcp(content: str, _: dict) -> list[str]:
    markers = (
        "disaster recovery", "dr", "drp", "business continuity", "bcp",
        "bcm", "continuity", "operational resilience", "cyber resilience",
        "crisis", "recovery plan", "failover", "backup", "restore", "rto",
        "rpo", "runbook", "tabletop", "alternate site", "hot site",
        "cold site", "fovqelade", "davamlılıq",
    )
    return _detect_business_context(content, DISASTER_RECOVERY_BCP_KEYWORDS, markers, max_chars=360)


def detect_physical_security_badge_cctv(content: str, _: dict) -> list[str]:
    matches: list[str] = []
    badge_re = re.compile(r"\b(?:badge|card|rfid|acs)[- _]?(?:id|no|number)?[- :]?[A-Za-z0-9-]{4,30}\b", re.IGNORECASE)
    for pattern in (badge_re, DATE_RE, CASE_RECORD_RE):
        for match in pattern.finditer(content):
            if has_keyword_context(content, match.start(), PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS, window=150):
                matches.append(match.group(0)[:120])
    markers = (
        "physical security", "physical access", "facility", "site", "building",
        "office", "badge", "access badge", "badge id", "badge log",
        "access card", "key card", "smart card", "rfid", "door access",
        "access control system", "acs", "cctv", "camera", "surveillance",
        "video footage", "floor plan", "visitor log", "entry log",
        "exit log", "turnstile", "server room", "data center access",
        "fiziki", "giris karti", "kamera",
    )
    matches.extend(_detect_business_context(content, PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS, markers, max_chars=360))
    return matches


GDPR_RULES: tuple[GDPRRule, ...] = (
    GDPRRule(
        finding_type="gdpr_full_name",
        label="Full name, maiden name, or alias",
        tier="Internal-Confidential",
        category="pii",
        risk="MEDIUM",
        description="GDPR personal identifier context with a valid person-name value",
        keywords=NAME_KEYWORDS,
        detector=detect_names,
    ),
    GDPRRule(
        finding_type="gdpr_email_address",
        label="Email address",
        tier="Confidential",
        category="pii",
        risk="MEDIUM",
        description="GDPR personal contact email address detected",
        keywords=EMAIL_KEYWORDS,
        detector=detect_emails,
    ),
    GDPRRule(
        finding_type="gdpr_phone_number",
        label="Phone number",
        tier="Confidential",
        category="pii",
        risk="MEDIUM",
        description="GDPR personal phone number detected with contact context",
        keywords=PHONE_KEYWORDS,
        detector=detect_phones,
    ),
    GDPRRule(
        finding_type="gdpr_postal_address",
        label="Postal or physical address",
        tier="Confidential",
        category="pii",
        risk="MEDIUM",
        description="GDPR postal or physical address context detected",
        keywords=ADDRESS_KEYWORDS,
        detector=detect_addresses,
    ),
    GDPRRule(
        finding_type="gdpr_birth_details",
        label="Date or place of birth",
        tier="Confidential-Restricted",
        category="pii",
        risk="HIGH",
        description="GDPR birth date or birth-place identity context detected",
        keywords=BIRTH_KEYWORDS,
        detector=detect_birth_details,
    ),
    GDPRRule(
        finding_type="gdpr_fin_pin",
        label="FIN or PIN",
        tier="Restricted",
        category="government_ids",
        risk="HIGH",
        description="Azerbaijan FIN/PIN-like identifier detected with government-ID context",
        keywords=GOVERNMENT_ID_KEYWORDS,
        detector=detect_fin,
    ),
    GDPRRule(
        finding_type="gdpr_national_id",
        label="National ID serial number",
        tier="Restricted",
        category="government_ids",
        risk="HIGH",
        description="National identity document serial number detected",
        keywords=GOVERNMENT_ID_KEYWORDS,
        detector=detect_national_ids,
    ),
    GDPRRule(
        finding_type="gdpr_passport_number",
        label="Passport number",
        tier="Restricted",
        category="government_ids",
        risk="HIGH",
        description="Passport number or MRZ passport context detected",
        keywords=GOVERNMENT_ID_KEYWORDS,
        detector=detect_passports,
    ),
    GDPRRule(
        finding_type="gdpr_signature",
        label="Physical or digital signature",
        tier="Confidential",
        category="biometric_data",
        risk="HIGH",
        description="Signature image, digital signature, or signing artifact context detected",
        keywords=SIGNATURE_KEYWORDS,
        detector=detect_signatures,
    ),
    GDPRRule(
        finding_type="gdpr_photo_face_image",
        label="Photograph, face image, or biometric face artifact",
        tier="Confidential-Restricted",
        category="biometric_data",
        risk="HIGH",
        description="Photograph, face image, selfie, KYC image, liveness, or biometric face artifact context detected",
        keywords=PHOTO_FACE_KEYWORDS,
        detector=detect_photo_face,
    ),
    GDPRRule(
        finding_type="gdpr_vehicle_identifier",
        label="Vehicle plate, VIN, or vehicle identifier",
        tier="Confidential",
        category="pii",
        risk="MEDIUM",
        description="Vehicle plate, VIN, chassis, engine, parking, toll, or vehicle registration identifier detected",
        keywords=VEHICLE_KEYWORDS,
        detector=detect_vehicle_identifiers,
    ),
    GDPRRule(
        finding_type="gdpr_account_recovery_secret",
        label="Mother's maiden name, security answer, or account recovery secret",
        tier="Restricted",
        category="identity_access",
        risk="HIGH",
        description="Account recovery question, answer, password hint, memorable word, or mother's maiden name context detected",
        keywords=ACCOUNT_RECOVERY_KEYWORDS,
        detector=detect_account_recovery,
    ),
    GDPRRule(
        finding_type="gdpr_emergency_contact",
        label="Next-of-kin or emergency contact",
        tier="Confidential",
        category="pii",
        risk="MEDIUM",
        description="Third-party emergency contact or next-of-kin personal data context detected",
        keywords=EMERGENCY_CONTACT_KEYWORDS,
        detector=detect_emergency_contacts,
    ),
    GDPRRule(
        finding_type="gdpr_ip_identifier",
        label="IP address or online network identifier",
        tier="Confidential",
        category="online_identifiers",
        risk="MEDIUM",
        description="GDPR online identifier detected from IP address, proxy chain, masked IP, or hashed IP context",
        keywords=IP_IDENTIFIER_KEYWORDS,
        detector=detect_ip_identifiers,
    ),
    GDPRRule(
        finding_type="gdpr_cookie_device_identifier",
        label="Cookie, advertising, tracking, or device identifier",
        tier="Confidential",
        category="online_identifiers",
        risk="MEDIUM",
        description="Tracking cookie, advertising ID, analytics ID, click ID, push token, consent string, or pseudonymous device identifier detected",
        keywords=COOKIE_DEVICE_ID_KEYWORDS,
        detector=detect_cookie_device_ids,
    ),
    GDPRRule(
        finding_type="gdpr_device_hardware_identifier",
        label="MAC address, IMEI, IMSI, or mobile hardware identifier",
        tier="Confidential",
        category="device_identifiers",
        risk="MEDIUM",
        description="Device-level hardware or mobile network identifier detected",
        keywords=DEVICE_HARDWARE_KEYWORDS,
        detector=detect_device_hardware_ids,
    ),
    GDPRRule(
        finding_type="gdpr_geolocation",
        label="Geolocation or GPS trail",
        tier="Confidential",
        category="location_data",
        risk="HIGH",
        description="Location, GPS coordinate, movement trail, route history, check-in, or geofence context detected",
        keywords=GEOLOCATION_KEYWORDS,
        detector=detect_geolocation,
    ),
    GDPRRule(
        finding_type="gdpr_browsing_history",
        label="Browsing, search, or clickstream history",
        tier="Confidential",
        category="behavioral_data",
        risk="HIGH",
        description="Browsing history, visited URL, search query, clickstream, referrer, or web analytics activity context detected",
        keywords=BROWSING_HISTORY_KEYWORDS,
        detector=detect_browsing_history,
    ),
    GDPRRule(
        finding_type="gdpr_account_username",
        label="Account username, handle, or profile identifier",
        tier="Internal-Confidential",
        category="online_identifiers",
        risk="MEDIUM",
        description="Username, login name, handle, screen name, profile slug, or account identifier context detected",
        keywords=ACCOUNT_USERNAME_KEYWORDS,
        detector=detect_account_usernames,
    ),
    GDPRRule(
        finding_type="gdpr_health_medical_record",
        label="Health, diagnosis, or medical record",
        tier="Restricted",
        category="phi",
        risk="HIGH",
        description="GDPR special-category health data, diagnosis, medical record, lab, prescription, claim, or clinical context detected",
        keywords=HEALTH_MEDICAL_KEYWORDS,
        detector=detect_health_medical,
    ),
    GDPRRule(
        finding_type="gdpr_mental_health_substance_use",
        label="Mental health or substance-use data",
        tier="Restricted",
        category="phi",
        risk="HIGH",
        description="GDPR special-category mental health, psychiatric, therapy, self-harm, substance-use, addiction, or treatment context detected",
        keywords=MENTAL_HEALTH_KEYWORDS,
        detector=detect_mental_health,
    ),
    GDPRRule(
        finding_type="gdpr_disability_status",
        label="Disability status or accessibility need",
        tier="Restricted",
        category="phi",
        risk="HIGH",
        description="GDPR special-category disability status, impairment, accommodation, assistive device, or accessibility support context detected",
        keywords=DISABILITY_STATUS_KEYWORDS,
        detector=detect_disability_status,
    ),
    GDPRRule(
        finding_type="gdpr_biometric_special_category",
        label="Biometric identifier or biometric template",
        tier="Restricted",
        category="biometric_data",
        risk="HIGH",
        description="GDPR special-category biometric identifier, fingerprint, iris, voiceprint, gait, liveness, template, vector, or biometric hash context detected",
        keywords=BIOMETRIC_SPECIAL_KEYWORDS,
        detector=detect_biometric_special,
    ),
    GDPRRule(
        finding_type="gdpr_genetic_dna_data",
        label="Genetic or DNA data",
        tier="Restricted",
        category="genetic_data",
        risk="HIGH",
        description="GDPR special-category genetic data, DNA sample, DNA sequence, genetic marker, variant, genotype, or genetic test context detected",
        keywords=GENETIC_DNA_KEYWORDS,
        detector=detect_genetic_dna,
    ),
    GDPRRule(
        finding_type="gdpr_race_ethnicity",
        label="Race, ethnicity, or racial/ethnic origin",
        tier="Restricted",
        category="special_category_context",
        risk="HIGH",
        description="GDPR special-category race, ethnicity, racial origin, ethnic origin, ancestry, minority, or diversity declaration context detected",
        keywords=RACE_ETHNICITY_KEYWORDS,
        detector=detect_race_ethnicity,
    ),
    GDPRRule(
        finding_type="gdpr_religious_philosophical_belief",
        label="Religious or philosophical belief",
        tier="Restricted",
        category="special_category_context",
        risk="HIGH",
        description="GDPR special-category religious, faith, spiritual, sect, denomination, philosophical, worldview, or conscience belief context detected",
        keywords=RELIGIOUS_BELIEF_KEYWORDS,
        detector=detect_religious_beliefs,
    ),
    GDPRRule(
        finding_type="gdpr_political_affiliation",
        label="Political opinion or affiliation",
        tier="Restricted",
        category="special_category_context",
        risk="HIGH",
        description="GDPR special-category political opinion, affiliation, party membership, voting preference, campaign, donor, activism, or voter profile context detected",
        keywords=POLITICAL_AFFILIATION_KEYWORDS,
        detector=detect_political_affiliation,
    ),
    GDPRRule(
        finding_type="gdpr_sexual_orientation_sex_life",
        label="Sexual orientation, sex life, or gender identity",
        tier="Restricted",
        category="special_category_context",
        risk="HIGH",
        description="GDPR special-category sexual orientation, sex life, intimate relationship, gender identity, reproductive, STI/HIV, or related declaration context detected",
        keywords=SEXUAL_ORIENTATION_KEYWORDS,
        detector=detect_sexual_orientation,
    ),
    GDPRRule(
        finding_type="gdpr_trade_union_membership",
        label="Trade-union membership",
        tier="Restricted",
        category="special_category_context",
        risk="HIGH",
        description="GDPR special-category trade-union membership, affiliation, dues, representative, collective bargaining, strike, or union register context detected",
        keywords=TRADE_UNION_KEYWORDS,
        detector=detect_trade_union,
    ),
    GDPRRule(
        finding_type="gdpr_immigration_citizenship_status",
        label="Immigration, citizenship, or residency status",
        tier="Restricted",
        category="government_ids",
        risk="HIGH",
        description="Immigration, citizenship, nationality, visa, residency, work permit, asylum, refugee, border, or immigration case context detected",
        keywords=IMMIGRATION_CITIZENSHIP_KEYWORDS,
        detector=detect_immigration_citizenship,
    ),
    GDPRRule(
        finding_type="gdpr_criminal_record_background_check",
        label="Criminal record or background check",
        tier="Restricted",
        category="special_category_context",
        risk="HIGH",
        description="Criminal record, background check, conviction, charge, arrest, court, police, sanctions, watchlist, or due-diligence screening context detected",
        keywords=CRIMINAL_RECORD_KEYWORDS,
        detector=detect_criminal_records,
    ),
    GDPRRule(
        finding_type="gdpr_payment_card_data",
        label="Payment card data, PAN, CVV, expiry, or track data",
        tier="Restricted",
        category="pci_payment",
        risk="HIGH",
        description="Payment card, PAN, masked card, expiry, CVV/CVC, card token, track, EMV, vault, or card transaction context detected",
        keywords=PAYMENT_CARD_KEYWORDS,
        detector=detect_payment_card_data,
    ),
    GDPRRule(
        finding_type="gdpr_bank_account_data",
        label="Bank account, IBAN, routing, or SWIFT/BIC",
        tier="Restricted",
        category="financial_records",
        risk="HIGH",
        description="Bank account, IBAN, SWIFT/BIC, routing, beneficiary, wire transfer, account statement, or balance context detected",
        keywords=BANK_ACCOUNT_KEYWORDS,
        detector=detect_bank_account_data,
    ),
    GDPRRule(
        finding_type="gdpr_tax_record",
        label="Tax record, tax filing, or taxpayer financial data",
        tier="Confidential-Restricted",
        category="financial_records",
        risk="HIGH",
        description="Tax record, tax return, tax filing, taxpayer identifier, tax year, taxable income, withholding, refund, liability, or audit context detected",
        keywords=TAX_RECORD_KEYWORDS,
        detector=detect_tax_records,
    ),
    GDPRRule(
        finding_type="gdpr_salary_compensation",
        label="Salary, compensation, payroll, bonus, or benefits",
        tier="Confidential",
        category="hr_documents",
        risk="MEDIUM",
        description="Salary, pay, wage, compensation, payroll, payslip, bonus, commission, equity, allowance, deduction, or benefits context detected",
        keywords=SALARY_COMPENSATION_KEYWORDS,
        detector=detect_salary_compensation,
    ),
    GDPRRule(
        finding_type="gdpr_credit_score_report",
        label="Credit score, credit report, or credit-risk profile",
        tier="Restricted",
        category="financial_records",
        risk="HIGH",
        description="Credit score, credit report, bureau file, credit history, inquiry, risk grade, affordability, debt, delinquency, default, or credit decision context detected",
        keywords=CREDIT_SCORE_REPORT_KEYWORDS,
        detector=detect_credit_score_report,
    ),
    GDPRRule(
        finding_type="gdpr_invoice_billing_transaction_log",
        label="Invoice, billing, transaction, investment, or brokerage log",
        tier="Confidential",
        category="financial_records",
        risk="MEDIUM",
        description="Invoice, billing, receipt, transaction log, investment account, brokerage, trading history, portfolio, holdings, statement, PnL, or settlement context detected",
        keywords=INVOICE_BILLING_TRANSACTION_KEYWORDS,
        detector=detect_invoice_billing_transaction,
    ),
    GDPRRule(
        finding_type="gdpr_prerelease_financial_statement",
        label="Pre-release or nonpublic financial statement",
        tier="Confidential-Restricted",
        category="financial_records",
        risk="HIGH",
        description="Draft, unreleased, internal, nonpublic, preliminary, board, earnings, balance sheet, income statement, cash flow, close, audit, or MNPI financial context detected",
        keywords=PRERELEASE_FINANCIAL_KEYWORDS,
        detector=detect_prerelease_financial,
    ),
    GDPRRule(
        finding_type="gdpr_pricing_margin_forecast",
        label="Pricing, margin, budget, or forecast data",
        tier="Confidential",
        category="confidential_business",
        risk="MEDIUM",
        description="Pricing, discount, quote, bid, tender, margin, cost, markup, revenue forecast, budget, AOP, scenario, quota, sales plan, competitor pricing, or financial model context detected",
        keywords=PRICING_MARGIN_FORECAST_KEYWORDS,
        detector=detect_pricing_margin_forecast,
    ),
    GDPRRule(
        finding_type="gdpr_password_secret",
        label="Password, passphrase, or password hash",
        tier="Restricted",
        category="credentials_secrets",
        risk="HIGH",
        description="Password, passphrase, privileged password, database/mail/SSH/VPN password, password hash, shadow/htpasswd, or credential hash context detected",
        keywords=PASSWORD_SECRET_KEYWORDS,
        detector=detect_password_secrets,
    ),
    GDPRRule(
        finding_type="gdpr_api_token_oauth_secret",
        label="API key, access token, OAuth secret, or service token",
        tier="Restricted",
        category="credentials_secrets",
        risk="HIGH",
        description="API key, access token, bearer token, OAuth secret, client secret, JWT, cloud token, provider token, webhook secret, or integration secret context detected",
        keywords=API_TOKEN_SECRET_KEYWORDS,
        detector=detect_api_token_secrets,
    ),
    GDPRRule(
        finding_type="gdpr_private_key_certificate_secret",
        label="Private key, certificate secret, SSH key, or keystore material",
        tier="Restricted",
        category="credentials_secrets",
        risk="HIGH",
        description="Private key, SSH key, PEM key, certificate private key, PFX/P12/JKS, keystore password, TLS/SSL key, signing key, SAML key, or cryptographic key material context detected",
        keywords=PRIVATE_KEY_CERT_KEYWORDS,
        detector=detect_private_key_cert_secrets,
    ),
    GDPRRule(
        finding_type="gdpr_database_connection_string",
        label="Database connection string or database URI",
        tier="Restricted",
        category="credentials_secrets",
        risk="HIGH",
        description="Database connection string, JDBC/ODBC DSN, database URI, host/user/password connection config, or datasource secret context detected",
        keywords=DATABASE_CONNECTION_KEYWORDS,
        detector=detect_database_connections,
    ),
    GDPRRule(
        finding_type="gdpr_encryption_key_material",
        label="Encryption key or cryptographic key material",
        tier="Restricted",
        category="credentials_secrets",
        risk="HIGH",
        description="Encryption/decryption key, HMAC/symmetric key, KMS/CMK/DEK/KEK, raw/base64/hex key material, IV, nonce, pepper, or key vault secret context detected",
        keywords=ENCRYPTION_KEY_MATERIAL_KEYWORDS,
        detector=detect_encryption_key_material,
    ),
    GDPRRule(
        finding_type="gdpr_session_token_jwt",
        label="Session token, JWT, refresh token, or auth cookie",
        tier="Restricted",
        category="credentials_secrets",
        risk="HIGH",
        description="Session token, session ID, JWT, bearer/access/refresh token, SSO/SAML token, CSRF token, auth cookie, or remember-me token context detected",
        keywords=SESSION_TOKEN_JWT_KEYWORDS,
        detector=detect_session_tokens,
    ),
    GDPRRule(
        finding_type="gdpr_mfa_seed_recovery_code",
        label="MFA seed, authenticator secret, or recovery code",
        tier="Restricted",
        category="credentials_secrets",
        risk="HIGH",
        description="MFA/2FA/TOTP/HOTP seed, authenticator secret, otpauth URI, recovery/backup/bypass code, or emergency code context detected",
        keywords=MFA_RECOVERY_KEYWORDS,
        detector=detect_mfa_recovery,
    ),
    GDPRRule(
        finding_type="gdpr_hr_employee_file",
        label="HR file, performance review, discipline, or grievance",
        tier="Confidential",
        category="hr_documents",
        risk="MEDIUM",
        description="HR file, employee/personnel record, review, appraisal, discipline, grievance, complaint, investigation, termination, PIP, or employee relations context detected",
        keywords=HR_EMPLOYEE_FILE_KEYWORDS,
        detector=detect_hr_employee_file,
    ),
    GDPRRule(
        finding_type="gdpr_benefits_insurance_enrollment",
        label="Benefits or insurance enrollment",
        tier="Confidential",
        category="hr_documents",
        risk="MEDIUM",
        description="Employee benefits, insurance enrollment, health/life/dental/vision coverage, beneficiary, dependent, pension, retirement, open enrollment, policy, premium, or deduction context detected",
        keywords=BENEFITS_INSURANCE_KEYWORDS,
        detector=detect_benefits_insurance,
    ),
    GDPRRule(
        finding_type="gdpr_background_check_drug_test",
        label="Background check, employment screening, or drug test",
        tier="Confidential-Restricted",
        category="hr_documents",
        risk="HIGH",
        description="Background screening, criminal background, police clearance, reference/education/employment verification, right-to-work, sanctions/watchlist, drug/toxicology/alcohol test, or screening result context detected",
        keywords=BACKGROUND_DRUG_TEST_KEYWORDS,
        detector=detect_background_drug_tests,
    ),
    GDPRRule(
        finding_type="gdpr_timesheet_attendance",
        label="Timesheet, attendance, work hours, or shift data",
        tier="Internal-Confidential",
        category="hr_documents",
        risk="LOW",
        description="Timesheet, timecard, attendance record, clock-in/out, work hours, shift, overtime, absence, leave, PTO, badge swipe, or attendance exception context detected",
        keywords=TIMESHEET_ATTENDANCE_KEYWORDS,
        detector=detect_timesheet_attendance,
    ),
    GDPRRule(
        finding_type="gdpr_org_chart_directory",
        label="Org chart, employee directory, or reporting hierarchy",
        tier="Internal-Confidential",
        category="hr_documents",
        risk="LOW",
        description="Organization chart, employee/staff directory, reporting line, manager, direct report, department, role, work contact, office, hierarchy, or cost center context detected",
        keywords=ORG_CHART_DIRECTORY_KEYWORDS,
        detector=detect_org_chart_directory,
    ),
    GDPRRule(
        finding_type="gdpr_termination_layoff_plan",
        label="Termination, layoff, redundancy, or offboarding plan",
        tier="Confidential",
        category="hr_documents",
        risk="MEDIUM",
        description="Termination, layoff, redundancy, separation, dismissal, offboarding, notice, severance, final pay, RIF, restructuring, impacted employee, or workforce reduction context detected",
        keywords=TERMINATION_LAYOFF_KEYWORDS,
        detector=detect_termination_layoff,
    ),
    GDPRRule(
        finding_type="gdpr_source_code_algorithm",
        label="Source code, codebase, or algorithm",
        tier="Confidential-Restricted",
        category="source_code",
        risk="HIGH",
        description="Source code, repository, codebase, algorithm, model logic, schema, stored procedure, or proprietary implementation context detected",
        keywords=SOURCE_CODE_ALGORITHM_KEYWORDS,
        detector=detect_source_code_algorithm,
    ),
    GDPRRule(
        finding_type="gdpr_trade_secret_design",
        label="Trade secret, formula, design, or confidential know-how",
        tier="Restricted",
        category="intellectual_property",
        risk="HIGH",
        description="Trade secret, formula, confidential know-how, prototype, design document, CAD, blueprint, schematic, BOM, process, R&D, or proprietary specification context detected",
        keywords=TRADE_SECRET_DESIGN_KEYWORDS,
        detector=detect_trade_secret_design,
    ),
    GDPRRule(
        finding_type="gdpr_patent_pending_unfiled",
        label="Patent-pending or unfiled invention material",
        tier="Restricted",
        category="intellectual_property",
        risk="HIGH",
        description="Patent pending, unfiled patent, provisional application, invention disclosure, claim draft, prior art, patentability, filing strategy, or confidential invention context detected",
        keywords=PATENT_PENDING_KEYWORDS,
        detector=detect_patent_pending,
    ),
    GDPRRule(
        finding_type="gdpr_ma_due_diligence",
        label="M&A, due diligence, data room, or deal material",
        tier="Restricted",
        category="confidential_business",
        risk="HIGH",
        description="M&A, merger, acquisition, due diligence, data room, target, buyer/seller, term sheet, LOI, SPA, valuation, synergy, QoE, cap table, or deal memo context detected",
        keywords=MA_DUE_DILIGENCE_KEYWORDS,
        detector=detect_ma_due_diligence,
    ),
    GDPRRule(
        finding_type="gdpr_board_materials_minutes",
        label="Board materials, minutes, or governance records",
        tier="Confidential",
        category="confidential_business",
        risk="MEDIUM",
        description="Board pack, board minutes, agenda, resolution, consent, committee materials, governance report, reserved matter, or director decision context detected",
        keywords=BOARD_MATERIALS_KEYWORDS,
        detector=detect_board_materials,
    ),
    GDPRRule(
        finding_type="gdpr_strategy_roadmap_plan",
        label="Strategy, roadmap, or business plan",
        tier="Confidential",
        category="confidential_business",
        risk="MEDIUM",
        description="Strategy, roadmap, operating plan, business plan, OKR, strategic initiative, growth, market expansion, transformation, launch, or competitive plan context detected",
        keywords=STRATEGY_ROADMAP_PLAN_KEYWORDS,
        detector=detect_strategy_roadmap_plan,
    ),
    GDPRRule(
        finding_type="gdpr_contract_nda_legal",
        label="Contract, NDA, or legal agreement",
        tier="Confidential",
        category="legal_documents",
        risk="MEDIUM",
        description="Contract, agreement, NDA, confidentiality agreement, legal terms, clause, liability, indemnity, DPA, MSA, SOW, SLA, redline, or signed legal document context detected",
        keywords=CONTRACT_NDA_LEGAL_KEYWORDS,
        detector=detect_contract_nda_legal,
    ),
    GDPRRule(
        finding_type="gdpr_litigation_privileged_legal",
        label="Litigation or privileged legal material",
        tier="Restricted",
        category="legal_documents",
        risk="HIGH",
        description="Litigation, lawsuit, dispute, claim, court filing, subpoena, deposition, settlement, legal hold, attorney-client privilege, work product, or counsel strategy context detected",
        keywords=LITIGATION_PRIVILEGED_LEGAL_KEYWORDS,
        detector=detect_litigation_privileged_legal,
    ),
    GDPRRule(
        finding_type="gdpr_vendor_supplier_terms",
        label="Vendor, supplier, procurement, or third-party terms",
        tier="Confidential",
        category="confidential_business",
        risk="MEDIUM",
        description="Vendor, supplier, procurement, purchase order, supplier agreement, vendor contract, payment terms, delivery terms, rebate, SLA, third-party risk, or scorecard context detected",
        keywords=VENDOR_SUPPLIER_TERMS_KEYWORDS,
        detector=detect_vendor_supplier_terms,
    ),
    GDPRRule(
        finding_type="gdpr_network_architecture_diagram",
        label="Network diagram, topology, or technical architecture",
        tier="Confidential-Restricted",
        category="security_operations",
        risk="HIGH",
        description="Network diagram, topology, architecture, subnet, routing, VLAN, DMZ, VPN, cloud network, data-flow, HLD/LLD, or security architecture context detected",
        keywords=NETWORK_ARCHITECTURE_KEYWORDS,
        detector=detect_network_architecture,
    ),
    GDPRRule(
        finding_type="gdpr_vulnerability_pentest_report",
        label="Vulnerability scan, pentest report, or security finding",
        tier="Restricted",
        category="security_operations",
        risk="HIGH",
        description="Vulnerability scan, pentest report, CVE/CVSS, security assessment, exploit proof, attack surface, exposure, remediation, or security finding context detected",
        keywords=VULNERABILITY_PENTEST_KEYWORDS,
        detector=detect_vulnerability_pentest,
    ),
    GDPRRule(
        finding_type="gdpr_security_config_firewall_rule",
        label="Security configuration, firewall rule, or access policy",
        tier="Confidential",
        category="security_operations",
        risk="HIGH",
        description="Security config, hardening baseline, firewall rule, ACL, security group, NSG, allow/deny/permit/block rule, NAT, WAF, or cloud firewall policy context detected",
        keywords=SECURITY_CONFIG_FIREWALL_KEYWORDS,
        detector=detect_security_config_firewall,
    ),
    GDPRRule(
        finding_type="gdpr_incident_access_audit_log",
        label="Incident report, access log, audit trail, or DFIR evidence",
        tier="Confidential",
        category="security_operations",
        risk="HIGH",
        description="Incident report, security event, breach, compromise, IOC, DFIR evidence, access log, audit log, CloudTrail, EDR telemetry, postmortem, RCA, or affected asset context detected",
        keywords=INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS,
        detector=detect_incident_access_audit_log,
    ),
    GDPRRule(
        finding_type="gdpr_disaster_recovery_bcp_plan",
        label="Disaster recovery, BCP, or resilience plan",
        tier="Confidential",
        category="security_operations",
        risk="MEDIUM",
        description="Disaster recovery, DRP, business continuity, BCP/BCM, operational resilience, crisis plan, recovery runbook, RTO/RPO, failover, backup, or restore plan context detected",
        keywords=DISASTER_RECOVERY_BCP_KEYWORDS,
        detector=detect_disaster_recovery_bcp,
    ),
    GDPRRule(
        finding_type="gdpr_physical_security_badge_cctv",
        label="Physical security, badge, CCTV, or floor-plan record",
        tier="Confidential",
        category="security_operations",
        risk="MEDIUM",
        description="Physical access, badge ID/log, access card, RFID, door access, ACS, CCTV, camera, surveillance footage, floor plan, visitor log, or facility security context detected",
        keywords=PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS,
        detector=detect_physical_security_badge_cctv,
    ),
)
