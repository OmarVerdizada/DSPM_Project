from __future__ import annotations

import csv
import io
import re

from classification.compliance.canonical_entities import canonical_entity_fingerprint
from classification.compliance.pci_keywords import (
    CARDHOLDER_NAME_KEYWORDS,
    CARDHOLDER_NAME_NEGATIVE_CONTEXT_KEYWORDS,
    CVV_KEYWORDS,
    CVV_NEGATIVE_CONTEXT_KEYWORDS,
    EXPIRATION_DATE_KEYWORDS,
    EXPIRATION_DATE_NEGATIVE_CONTEXT_KEYWORDS,
    GENERIC_NAME_KEYWORDS,
    PAN_KEYWORDS,
    PAN_NEGATIVE_CONTEXT_KEYWORDS,
    PAN_PROTECTION_KEYWORDS,
    PAYMENT_CONTEXT_KEYWORDS,
    PIN_KEYWORDS,
    PIN_NEGATIVE_CONTEXT_KEYWORDS,
    SERVICE_CODE_KEYWORDS,
    SERVICE_CODE_NEGATIVE_CONTEXT_KEYWORDS,
    TRACK_DATA_KEYWORDS,
    TRACK_DATA_NEGATIVE_CONTEXT_KEYWORDS,
)
from classification.compliance.pci_models import PCIFinding
from classification.compliance.pci_validators import (
    CIPHERTEXT_RE,
    EXPIRY_COMPACT_RE,
    EXPIRY_DELIMITED_RE,
    EXPIRY_MONTH_FIELD_RE,
    EXPIRY_YEAR_FIELD_RE,
    HASH_RE,
    MASKED_PAN_RE,
    PAN_CANDIDATE_RE,
    analyze_pin_block_value,
    card_brand_info,
    claimed_protection_state,
    classify_protection_state,
    is_valid_cardholder_name,
    keyword_hits,
    local_context,
    mask_cardholder_name,
    mask_cvv_value,
    mask_fragment,
    mask_pan,
    mask_track_data,
    normalize_cardholder_name,
    normalize_pan_candidate,
    parse_track_data,
    parse_expiration_value,
    parse_cvv_value,
    parse_pin_block_value,
    parse_pin_value,
    parse_service_code_value,
    mask_pin_block_value,
    mask_pin_value,
    secure_text_fingerprint,
    secure_fingerprint,
)
from classification.compliance.pci_requirements import requirement_mappings_for_finding
from classification.compliance.validators import context_keyword_values


def classify_pci_content(content: str, metadata: dict | None = None, custom_keyword_groups: list[dict] | None = None) -> list[dict]:
    if not content and not metadata:
        return []

    metadata = metadata or {}
    findings: dict[tuple[str, str], dict] = {}
    pan_contexts: list[dict] = []
    evidence_blob = " ".join(
        [
            content or "",
            str(metadata.get("name") or ""),
            str(metadata.get("path") or ""),
            str(metadata.get("extension") or ""),
        ]
    )
    _detect_track_data(content or "", evidence_blob, findings)

    for match in PAN_CANDIDATE_RE.finditer(content or ""):
        raw_value = match.group(0)
        normalized = normalize_pan_candidate(raw_value)
        if not normalized:
            continue
        context = local_context(content or "", match.start(), 150)
        finding = _build_pan_finding(raw_value, context, evidence_blob, metadata)
        if not finding:
            continue
        _merge_finding(findings, finding)
        pan_contexts.append(
            {
                "context": context,
                "protection_state": finding.protection_state,
                "fingerprint": finding.secure_fingerprints[0] if finding.secure_fingerprints else "",
                "readable_full": finding.protection_state == "READABLE_FULL",
            }
        )

    for match in MASKED_PAN_RE.finditer(content or ""):
        context = local_context(content or "", match.start(), 150)
        matched_keywords = keyword_hits(f"{context} {evidence_blob}", (*PAN_KEYWORDS, *PAN_PROTECTION_KEYWORDS, *PAYMENT_CONTEXT_KEYWORDS))
        if not matched_keywords:
            continue
        finding = PCIFinding(
            finding_type="pci_chd_masked_pan",
            label="Masked Primary Account Number",
            risk="LOW",
            description="Masked or display-only PAN representation detected with payment-card context.",
            pci_category="CHD",
            pci_treatment="Masked PAN is still PCI-relevant evidence, but it is lower risk when no reconstruction path is visible.",
            protection_state="MASKED_DISPLAY",
            confidence=70,
            count=1,
            samples=[mask_fragment(match.group(0))],
            matched_keywords=matched_keywords,
            secure_fingerprints=[secure_fingerprint(match.group(0))],
        )
        _merge_finding(findings, finding)
        pan_contexts.append(
            {
                "context": context,
                "protection_state": "MASKED_DISPLAY",
                "fingerprint": finding.secure_fingerprints[0] if finding.secure_fingerprints else "",
                "readable_full": False,
            }
        )

    _detect_transformed_pan_artifacts(content or "", evidence_blob, metadata, findings)
    _detect_cardholder_names(content or "", evidence_blob, metadata, pan_contexts, findings)
    _detect_expiration_dates(content or "", evidence_blob, metadata, pan_contexts, findings)
    _detect_service_codes(content or "", evidence_blob, metadata, pan_contexts, findings)
    _detect_cvv_values(content or "", evidence_blob, metadata, pan_contexts, findings)
    _detect_pin_values(content or "", evidence_blob, metadata, pan_contexts, findings)
    _detect_pan_reconstruction_risk(content or "", evidence_blob, metadata, findings)
    _detect_custom_pci_context(content or "", evidence_blob, custom_keyword_groups or [], findings)
    _detect_structured_payment_rows(content or "", evidence_blob, metadata, findings)
    _apply_enterprise_context(findings, metadata, content or "")
    _apply_pci_hierarchy(findings)
    return list(findings.values())


def _build_pan_finding(raw_value: str, context: str, evidence_blob: str, metadata: dict) -> PCIFinding | None:
    normalized = normalize_pan_candidate(raw_value)
    luhn_pass = _luhn_pass(normalized)
    if not luhn_pass:
        return None
    context_blob = f"{context} {evidence_blob}"
    schema_hits = keyword_hits(context_blob, PAN_KEYWORDS)
    payment_hits = keyword_hits(context_blob, PAYMENT_CONTEXT_KEYWORDS)
    protection_hits = keyword_hits(context_blob, PAN_PROTECTION_KEYWORDS)
    negative_hits = keyword_hits(context_blob, PAN_NEGATIVE_CONTEXT_KEYWORDS)

    score = 20
    if schema_hits:
        score += 25
    if payment_hits:
        score += 20
    if luhn_pass:
        score += 40
    if protection_hits:
        score += 8
    if _path_has_payment_context(metadata):
        score += 5
    if negative_hits and not (schema_hits or payment_hits):
        score -= 35
    elif negative_hits:
        score -= 12
    if not luhn_pass and not schema_hits:
        score -= 25
    score = max(0, min(100, score))
    if score < 55:
        return None

    tenant_id = _tenant_id(metadata)
    brand = card_brand_info(raw_value)
    claimed_state = claimed_protection_state(context_blob, raw_value)
    protection_state = classify_protection_state(context_blob, raw_value)
    validation_status = "CONFIRMED" if luhn_pass and (schema_hits or payment_hits or _path_has_payment_context(metadata)) else "NEEDS_REVIEW"
    finding_type = _finding_type_for_state(protection_state)
    risk = _risk_for_state(protection_state, score)
    label = "Primary Account Number" if finding_type == "pci_chd_pan" else "Protected or transformed Primary Account Number"
    description = _description_for_state(protection_state)
    return PCIFinding(
        finding_type=finding_type,
        label=label,
        risk=risk,
        description=description,
        pci_category="CHD",
        pci_treatment="PAN may only be retained for documented business, legal, or regulatory need and must be rendered unreadable at rest.",
        protection_state=protection_state,
        confidence=score,
        count=1,
        samples=[mask_pan(raw_value)],
        matched_keywords=[*schema_hits, *payment_hits, *protection_hits][:10],
        secure_fingerprints=[secure_fingerprint(raw_value, tenant_id)],
        canonical_entity_type="PAN",
        canonical_entity_fingerprints=[canonical_entity_fingerprint("PAN", normalized, tenant_id)],
        claimed_protection_state=claimed_state,
        verified_protection_state=protection_state,
        impact_severity="CRITICAL",
        detection_confidence=score,
        validation_status=validation_status,
        operational_risk_score=_operational_risk_score("CRITICAL", score, protection_state),
        tenant_id=tenant_id,
        card_brand=str(brand.get("card_brand") or "unknown"),
        pan_length_valid_for_brand=bool(brand.get("pan_length_valid_for_brand")),
        test_card=bool(brand.get("test_card")),
        test_card_label=str(brand.get("test_card_label") or ""),
        iin_bin=str(brand.get("iin_bin") or ""),
        bin_metadata_version=str(brand.get("bin_metadata_version") or ""),
        synthetic_value=bool(brand.get("test_card")),
        synthetic_value_confidence_reduction=20 if brand.get("test_card") else 0,
        production_test_pan_policy=bool(brand.get("test_card") and _environment(f"{evidence_blob} {context_blob}".lower()) == "production"),
    )


def _detect_transformed_pan_artifacts(content: str, evidence_blob: str, metadata: dict, findings: dict[tuple[str, str], dict]) -> None:
    tenant_id = _tenant_id(metadata)
    for pattern, state, finding_type in (
        (HASH_RE, "HASHED_UNKEYED_OR_UNKNOWN", "pci_hashed_pan"),
        (CIPHERTEXT_RE, "ENCRYPTED", "pci_encrypted_pan"),
    ):
        for match in pattern.finditer(content):
            raw_artifact = match.group(0)
            if state == "ENCRYPTED" and HASH_RE.fullmatch(raw_artifact):
                context = local_context(content, match.start(), 140)
                if not any(marker in context.lower() for marker in ("encrypted", "cipher", "ciphertext", "decrypt")):
                    continue
            context = local_context(content, match.start(), 140)
            context_blob = f"{context} {evidence_blob}"
            protection_hits = keyword_hits(context_blob, PAN_PROTECTION_KEYWORDS)
            schema_hits = keyword_hits(context_blob, PAN_KEYWORDS)
            if not protection_hits:
                continue
            if state == "HASHED_UNKEYED_OR_UNKNOWN" and not any("hash" in hit or "digest" in hit or "fingerprint" in hit for hit in protection_hits):
                continue
            if state == "ENCRYPTED" and not any("encrypt" in hit or "cipher" in hit or "cryptogram" in hit for hit in protection_hits):
                continue
            finding = PCIFinding(
                finding_type=finding_type,
                label="Transformed Primary Account Number",
                risk="HIGH",
                description="Hashed or encrypted PAN artifact detected; protection effectiveness and key separation require validation.",
                pci_category="CHD",
                pci_treatment="Transformed PAN remains PCI-relevant until hashing, encryption, tokenization, and key-management evidence is validated.",
                protection_state=state,
                confidence=78,
                count=1,
                samples=[mask_fragment(raw_artifact)],
                matched_keywords=[*schema_hits, *protection_hits][:10],
                secure_fingerprints=[secure_fingerprint(raw_artifact, tenant_id)],
                tenant_id=tenant_id,
            )
            _merge_finding(findings, finding)


def _detect_track_data(content: str, evidence_blob: str, findings: dict[tuple[str, str], dict]) -> None:
    parsed_tracks = parse_track_data(content)
    for track in parsed_tracks:
        context = _context_around_value(content, str(track.get("raw") or ""), window=220)
        context_blob = f"{context} {evidence_blob}"
        negative_hits = keyword_hits(context_blob, TRACK_DATA_NEGATIVE_CONTEXT_KEYWORDS)
        if negative_hits and not keyword_hits(context_blob, TRACK_DATA_KEYWORDS):
            continue
        matched_keywords = keyword_hits(context_blob, (*TRACK_DATA_KEYWORDS, *PAYMENT_CONTEXT_KEYWORDS))
        fingerprint_seed = f"{track.get('track_type')}:{track.get('pan')}:{track.get('expiry')}:{track.get('service_code')}:{track.get('discretionary_length')}"
        finding = PCIFinding(
            finding_type="pci_sad_track_data",
            label="Full Track Data",
            risk="CRITICAL",
            description="Full magnetic-stripe or chip-equivalent track data detected through structural parser validation.",
            pci_category="SAD",
            pci_treatment="Sensitive authentication data must not be retained after authorization for merchants or ordinary service providers, even if encrypted.",
            protection_state="READABLE_FULL",
            confidence=int(track.get("confidence") or 90),
            count=1,
            samples=[mask_track_data(track)],
            matched_keywords=matched_keywords,
            secure_fingerprints=[secure_text_fingerprint(fingerprint_seed, "pci-track-data-v1")],
            pci_requirements=["3.2.1", "3.3"],
            severity_rationale="Full track data carries PAN, expiry, service code, and discretionary authentication data that can enable cloning or transaction abuse.",
            remediation="Stop persisting raw track payloads, securely delete retained copies including logs, queues, backups, and exports, and retain only permitted CHD fields required for business processing.",
            correlated_elements=["pan", "expiration_date", "service_code", "discretionary_data"],
        )
        data = finding.to_dict()
        data["track_parser"] = {
            "track_type": track.get("track_type"),
            "encoding": track.get("encoding"),
            "separator": track.get("separator"),
            "discretionary_length": track.get("discretionary_length"),
            "emv_parser": track.get("emv_parser", ""),
            "tag": track.get("tag", ""),
            "tag_length_nibbles": track.get("tag_length_nibbles"),
            "padding_nibble_valid": track.get("padding_nibble_valid"),
        }
        _merge_finding_dict(findings, data)

    _detect_encrypted_track_artifacts(content, evidence_blob, findings)


def _detect_encrypted_track_artifacts(content: str, evidence_blob: str, findings: dict[tuple[str, str], dict]) -> None:
    for keyword, value in context_keyword_values(content, TRACK_DATA_KEYWORDS, max_chars=220):
        context_blob = f"{keyword} {value} {evidence_blob}"
        if not any(marker in context_blob.lower() for marker in ("encrypted", "cipher", "ciphertext")):
            continue
        if not CIPHERTEXT_RE.search(value):
            continue
        finding = PCIFinding(
            finding_type="pci_sad_track_data",
            label="Encrypted Full Track Data",
            risk="CRITICAL",
            description="Encrypted or encoded track-data artifact detected; encryption does not make post-authorization SAD retention permitted.",
            pci_category="SAD",
            pci_treatment="Encrypted full track data is still sensitive authentication data retention evidence and requires issuer-role exception review if retained.",
            protection_state="ENCRYPTED",
            confidence=78,
            count=1,
            samples=[mask_fragment(value)],
            matched_keywords=keyword_hits(context_blob, TRACK_DATA_KEYWORDS),
            secure_fingerprints=[secure_text_fingerprint(value, "pci-track-data-v1")],
            pci_requirements=["3.2.1"],
            severity_rationale="Encrypted full track fields can remain recoverable and are prohibited for default merchant/service-provider post-authorization retention.",
            remediation="Remove encrypted track retention unless an approved issuing exception exists, and validate downstream logs, queues, backups, and exports.",
            correlated_elements=["track_data"],
        )
        _merge_finding(findings, finding)


def _detect_cardholder_names(
    content: str,
    evidence_blob: str,
    metadata: dict,
    pan_contexts: list[dict],
    findings: dict[tuple[str, str], dict],
) -> None:
    candidates: list[tuple[str, str, str]] = []
    for keyword, value in context_keyword_values(content, CARDHOLDER_NAME_KEYWORDS, max_chars=120):
        candidate = _clean_name_candidate(value)
        if candidate and is_valid_cardholder_name(candidate):
            candidates.append((candidate, keyword, "explicit"))
    for keyword, value in context_keyword_values(content, GENERIC_NAME_KEYWORDS, max_chars=120):
        candidate = _clean_name_candidate(value)
        if candidate and is_valid_cardholder_name(candidate):
            candidates.append((candidate, keyword, "generic"))

    seen: set[tuple[str, str]] = set()
    for candidate, keyword, source in candidates:
        normalized = normalize_cardholder_name(candidate)
        if (normalized.lower(), keyword.lower()) in seen:
            continue
        seen.add((normalized.lower(), keyword.lower()))
        context = _context_around_value(content, candidate)
        context_blob = f"{keyword} {candidate} {context} {evidence_blob}"
        negative_hits = keyword_hits(context_blob, CARDHOLDER_NAME_NEGATIVE_CONTEXT_KEYWORDS)
        explicit_hits = keyword_hits(context_blob, CARDHOLDER_NAME_KEYWORDS)
        payment_hits = keyword_hits(context_blob, PAYMENT_CONTEXT_KEYWORDS)
        linked_pan = _best_linked_pan(context, pan_contexts)

        if negative_hits and not explicit_hits:
            continue
        if source == "generic" and not (linked_pan and payment_hits):
            continue
        if not linked_pan and not explicit_hits:
            continue

        protection_state = linked_pan.get("protection_state") if linked_pan else "STANDALONE_EXPLICIT"
        readable_pan = bool(linked_pan.get("readable_full")) if linked_pan else False
        risk = "HIGH" if readable_pan else "MEDIUM" if linked_pan else "LOW"
        confidence = 82 if readable_pan else 68 if linked_pan else 58
        fingerprint_seed = f"{normalized}:{linked_pan.get('fingerprint', '') if linked_pan else 'standalone'}"
        finding = PCIFinding(
            finding_type="pci_chd_cardholder_name",
            label="Cardholder Name",
            risk=risk,
            description="Cardholder name detected through explicit name-on-card context or correlation with PAN-bearing payment data.",
            pci_category="CHD",
            pci_treatment="Cardholder name is CHD when linked to PAN; PAN defines PCI scope, while name increases identity linkage and fraud impact.",
            protection_state=f"LINKED_{protection_state}" if linked_pan else protection_state,
            confidence=confidence,
            count=1,
            samples=[mask_cardholder_name(candidate)],
            matched_keywords=[keyword, *explicit_hits, *payment_hits][:10],
            secure_fingerprints=[secure_text_fingerprint(fingerprint_seed, "pci-cardholder-name-v1")],
            canonical_entity_type="PERSON_NAME",
            canonical_entity_fingerprints=[canonical_entity_fingerprint("PERSON_NAME", normalized, _tenant_id(metadata))],
            pci_requirements=["3.3"],
            severity_rationale="Cardholder name alone does not define PCI scope, but linkage to PAN enriches CHD and increases fraud and identity exposure.",
            remediation="Avoid collecting name-on-card unless needed, separate identity metadata from PAN-bearing records where possible, and remove name + PAN combinations from logs, exports, tickets, and analytics events.",
            correlated_elements=["pan"] if linked_pan else [],
        )
        _merge_finding(findings, finding)


def _detect_expiration_dates(
    content: str,
    evidence_blob: str,
    metadata: dict,
    pan_contexts: list[dict],
    findings: dict[tuple[str, str], dict],
) -> None:
    candidates: list[tuple[str, str, str, str]] = []
    for keyword, value in context_keyword_values(content, EXPIRATION_DATE_KEYWORDS, max_chars=80):
        context = f"{keyword} {value} {_context_around_value(content, value, 140)}"
        parsed = _parse_expiry_with_context(value, context)
        if parsed:
            candidates.append((parsed, keyword, value, "explicit"))

    for match in EXPIRY_DELIMITED_RE.finditer(content):
        context = local_context(content, match.start(), 140)
        parsed = parse_expiration_value(match.group(0))
        if parsed:
            candidates.append((parsed, "delimited expiry", match.group(0), "contextual"))

    paired = _paired_month_year_expiry(content)
    if paired:
        candidates.append((paired[0], paired[1], paired[2], "explicit"))

    seen: set[tuple[str, str]] = set()
    for normalized_expiry, keyword, raw_value, source in candidates:
        if (normalized_expiry, keyword.lower()) in seen:
            continue
        seen.add((normalized_expiry, keyword.lower()))
        context = _context_around_value(content, raw_value)
        context_blob = f"{keyword} {raw_value} {context} {evidence_blob}"
        explicit_hits = keyword_hits(context_blob, EXPIRATION_DATE_KEYWORDS)
        payment_hits = keyword_hits(context_blob, PAYMENT_CONTEXT_KEYWORDS)
        negative_hits = keyword_hits(context_blob, EXPIRATION_DATE_NEGATIVE_CONTEXT_KEYWORDS)
        linked_pan = _best_linked_pan(context, pan_contexts)

        if negative_hits and not (linked_pan or payment_hits):
            continue
        if source == "contextual" and not (linked_pan or explicit_hits or payment_hits):
            continue
        if not linked_pan and not explicit_hits:
            continue

        protection_state = linked_pan.get("protection_state") if linked_pan else "STANDALONE_EXPLICIT"
        readable_pan = bool(linked_pan.get("readable_full")) if linked_pan else False
        risk = "HIGH" if readable_pan else "MEDIUM" if linked_pan else "LOW"
        confidence = 82 if readable_pan else 68 if linked_pan else 58
        fingerprint_seed = f"{normalized_expiry}:{linked_pan.get('fingerprint', '') if linked_pan else 'standalone'}"
        finding = PCIFinding(
            finding_type="pci_chd_expiration_date",
            label="Expiration Date",
            risk=risk,
            description="Payment card expiration date detected through explicit expiry context or correlation with PAN-bearing payment data.",
            pci_category="CHD",
            pci_treatment="Expiration date is CHD when linked to PAN; it is allowed to store for business need but should inherit CDE controls.",
            protection_state=f"LINKED_{protection_state}" if linked_pan else protection_state,
            confidence=confidence,
            count=1,
            samples=[normalized_expiry],
            matched_keywords=[keyword, *explicit_hits, *payment_hits][:10],
            secure_fingerprints=[secure_text_fingerprint(fingerprint_seed, "pci-expiration-date-v1")],
            pci_requirements=["3.3"],
            severity_rationale="Expiration date does not define PCI scope alone, but with PAN it enriches CHD and increases card-not-present fraud utility.",
            remediation="Remove expiry from logs, analytics payloads, support exports, and unnecessary PAN-bearing records; use tokenized payment references where possible.",
            correlated_elements=["pan"] if linked_pan else [],
        )
        _merge_finding(findings, finding)


def _detect_service_codes(
    content: str,
    evidence_blob: str,
    metadata: dict,
    pan_contexts: list[dict],
    findings: dict[tuple[str, str], dict],
) -> None:
    candidates: list[tuple[str, str, str]] = []
    for keyword, value in context_keyword_values(content, SERVICE_CODE_KEYWORDS, max_chars=50):
        parsed = parse_service_code_value(value)
        if parsed:
            candidates.append((parsed, keyword, value))

    seen: set[tuple[str, str]] = set()
    for service_code, keyword, raw_value in candidates:
        if (service_code, keyword.lower()) in seen:
            continue
        seen.add((service_code, keyword.lower()))
        context = _context_around_value(content, raw_value)
        context_blob = f"{keyword} {raw_value} {context} {evidence_blob}"
        explicit_hits = keyword_hits(context_blob, SERVICE_CODE_KEYWORDS)
        payment_hits = keyword_hits(context_blob, PAYMENT_CONTEXT_KEYWORDS)
        negative_hits = keyword_hits(context_blob, SERVICE_CODE_NEGATIVE_CONTEXT_KEYWORDS)
        linked_pan = _best_linked_pan(context, pan_contexts)

        if negative_hits and not (linked_pan or explicit_hits):
            continue
        if not linked_pan and not explicit_hits:
            continue

        protection_state = linked_pan.get("protection_state") if linked_pan else "STANDALONE_EXPLICIT"
        readable_pan = bool(linked_pan.get("readable_full")) if linked_pan else False
        risk = "HIGH" if readable_pan else "MEDIUM" if linked_pan else "LOW"
        confidence = 80 if readable_pan else 66 if linked_pan else 58
        fingerprint_seed = f"{service_code}:{linked_pan.get('fingerprint', '') if linked_pan else 'standalone'}"
        finding = PCIFinding(
            finding_type="pci_chd_service_code",
            label="Service Code",
            risk=risk,
            description="Payment card service code detected through explicit service-code context or correlation with PAN-bearing payment data.",
            pci_category="CHD",
            pci_treatment="Service code is CHD when linked to PAN; full track storage rules apply if it is part of stored track data.",
            protection_state=f"LINKED_{protection_state}" if linked_pan else protection_state,
            confidence=confidence,
            count=1,
            samples=[service_code],
            matched_keywords=[keyword, *explicit_hits, *payment_hits][:10],
            secure_fingerprints=[secure_text_fingerprint(fingerprint_seed, "pci-service-code-v1")],
            pci_requirements=["3.3"],
            severity_rationale="Service code does not define PCI scope alone, but with PAN it enriches CHD and is a strong structural marker for track data.",
            remediation="Do not retain raw track payloads just to store service code; remove service code from debug or processor logs unless a documented business need exists.",
            correlated_elements=["pan"] if linked_pan else [],
        )
        _merge_finding(findings, finding)


def _detect_cvv_values(
    content: str,
    evidence_blob: str,
    metadata: dict,
    pan_contexts: list[dict],
    findings: dict[tuple[str, str], dict],
) -> None:
    candidates: list[tuple[str, str, str]] = []
    for keyword, value in context_keyword_values(content, CVV_KEYWORDS, max_chars=40):
        parsed = parse_cvv_value(value, explicit=True)
        if parsed:
            candidates.append((parsed, keyword, value))

    seen: set[tuple[str, str]] = set()
    for cvv_value, keyword, raw_value in candidates:
        if (cvv_value, keyword.lower()) in seen:
            continue
        seen.add((cvv_value, keyword.lower()))
        context = _context_around_value(content, raw_value)
        context_blob = f"{keyword} {raw_value} {context} {evidence_blob}"
        explicit_hits = keyword_hits(context_blob, CVV_KEYWORDS)
        payment_hits = keyword_hits(context_blob, PAYMENT_CONTEXT_KEYWORDS)
        negative_hits = keyword_hits(context_blob, CVV_NEGATIVE_CONTEXT_KEYWORDS)
        linked_pan = _best_linked_pan(context, pan_contexts)

        if negative_hits and not (linked_pan or _is_strong_cvv_keyword(keyword)):
            continue
        if not linked_pan and not (_is_strong_cvv_keyword(keyword) or payment_hits):
            continue

        confidence = 94 if linked_pan else 82 if _is_strong_cvv_keyword(keyword) else 64
        fingerprint_seed = f"{keyword.lower()}:{len(cvv_value)}:{linked_pan.get('fingerprint', '') if linked_pan else 'standalone'}"
        finding = PCIFinding(
            finding_type="pci_sad_cvv",
            label="Card Verification Code / Value",
            risk="CRITICAL",
            description="Card verification code/value detected with CVV-family semantic context.",
            pci_category="SAD",
            pci_treatment="CVV/CVC/CID values must not be retained after authorization; customer consent and encryption do not permit storage.",
            protection_state="READABLE_FULL",
            confidence=confidence,
            count=1,
            samples=[mask_cvv_value(cvv_value)],
            matched_keywords=[keyword, *explicit_hits, *payment_hits][:10],
            secure_fingerprints=[secure_text_fingerprint(fingerprint_seed, "pci-cvv-v1")],
            pci_requirements=["3.2.2"],
            severity_rationale="CVV-family values authenticate card-not-present transactions and retained values materially increase fraud risk.",
            remediation="Purge CVV from databases, logs, backups, CRM/support tools, analytics, messages, and recordings; drop CVV fields before serialization or storage.",
            correlated_elements=["pan"] if linked_pan else [],
        )
        _merge_finding(findings, finding)


def _detect_pin_values(
    content: str,
    evidence_blob: str,
    metadata: dict,
    pan_contexts: list[dict],
    findings: dict[tuple[str, str], dict],
) -> None:
    candidates: list[tuple[str, str, str, str]] = []
    for keyword, value in context_keyword_values(content, PIN_KEYWORDS, max_chars=100):
        normalized_keyword = keyword.lower().replace("-", "_").replace(" ", "_")
        if "pin_block" in normalized_keyword or "pinblock" in normalized_keyword:
            parsed_block = parse_pin_block_value(value)
            if parsed_block:
                candidates.append((parsed_block, keyword, value, "pin_block"))
            continue
        parsed_pin = parse_pin_value(value)
        if parsed_pin:
            candidates.append((parsed_pin, keyword, value, "pin"))

    seen: set[tuple[str, str, str]] = set()
    for secret_value, keyword, raw_value, kind in candidates:
        if (secret_value, keyword.lower(), kind) in seen:
            continue
        seen.add((secret_value, keyword.lower(), kind))
        context = _context_around_value(content, raw_value)
        context_blob = f"{keyword} {raw_value} {context} {evidence_blob}"
        explicit_hits = keyword_hits(context_blob, PIN_KEYWORDS)
        payment_hits = keyword_hits(context_blob, PAYMENT_CONTEXT_KEYWORDS)
        negative_hits = keyword_hits(context_blob, PIN_NEGATIVE_CONTEXT_KEYWORDS)
        linked_pan = _best_linked_pan(context, pan_contexts)

        if negative_hits and not (linked_pan or _is_strong_pin_keyword(keyword)):
            continue
        if kind == "pin_block" and not (_has_pin_crypto_context(context_blob) or linked_pan):
            continue
        if kind == "pin" and not (linked_pan or _is_strong_pin_keyword(keyword) or payment_hits):
            continue

        finding_type = "pci_sad_pin_block" if kind == "pin_block" else "pci_sad_pin"
        label = "PIN Block" if kind == "pin_block" else "Payment Card PIN"
        protection_state = "ENCRYPTED_OR_ENCODED" if kind == "pin_block" and any(marker in context_blob.lower() for marker in ("encrypted", "zpk", "pek", "tpk", "hsm")) else "READABLE_FULL"
        pin_block_meta = analyze_pin_block_value(secret_value) if kind == "pin_block" else {}
        if kind == "pin_block" and pin_block_meta.get("pin_block_test_vector_excluded"):
            continue
        sample = mask_pin_block_value(secret_value) if kind == "pin_block" else mask_pin_value(secret_value)
        fingerprint_seed = f"{kind}:{keyword.lower()}:{len(secret_value)}:{linked_pan.get('fingerprint', '') if linked_pan else 'standalone'}"
        finding = PCIFinding(
            finding_type=finding_type,
            label=label,
            risk="CRITICAL",
            description="Payment-card PIN or PIN block detected with payment, ATM, issuer, terminal, HSM, or PAN context.",
            pci_category="SAD",
            pci_treatment="PIN and PIN block values must not be retained outside approved issuing/PIN-processing lifecycle; encryption alone does not permit retention.",
            protection_state=protection_state,
            confidence=94 if linked_pan else 84 if _is_strong_pin_keyword(keyword) else 72,
            count=1,
            samples=[sample],
            matched_keywords=[keyword, *explicit_hits, *payment_hits][:10],
            secure_fingerprints=[secure_text_fingerprint(fingerprint_seed, f"pci-{kind}-v1")],
            pci_requirements=["3.2.3"],
            severity_rationale="PIN/PIN block compromise can enable unauthorized cash withdrawal or transaction authorization.",
            remediation="Remove PIN/PIN-block persistence from merchant applications, logs, queues, diagnostics, support artifacts, and recordings; use approved PIN-entry devices and HSM-controlled workflows.",
            correlated_elements=["pan"] if linked_pan else [],
        )
        data = finding.to_dict()
        data.update(pin_block_meta)
        data["key_co_location_risk"] = kind == "pin_block" and any(marker in context_blob.lower() for marker in ("zpk", "tpk", "pek", "key_id", "key id", "hsm key"))
        _merge_finding_dict(findings, data)


def _detect_custom_pci_context(content: str, evidence_blob: str, custom_keyword_groups: list[dict], findings: dict[tuple[str, str], dict]) -> None:
    if not custom_keyword_groups:
        return
    searchable = f"{content} {evidence_blob}"
    for group in custom_keyword_groups:
        terms = [str(term or "").strip() for term in group.get("terms") or [] if str(term or "").strip()]
        if not terms:
            continue
        matched_terms = [term for term in terms if _term_matches(searchable, term)]
        if not matched_terms:
            continue
        finding_type = str(group.get("type") or "pci_custom_context").strip() or "pci_custom_context"
        if not finding_type.startswith("pci_"):
            finding_type = f"pci_custom_{finding_type}"
        label = str(group.get("label") or finding_type.replace("_", " ").title()).strip()
        risk = str(group.get("risk") or "MEDIUM").upper()
        if risk not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            risk = "MEDIUM"
        data = {
            "type": finding_type,
            "framework": "pci_dss",
            "risk": risk,
            "category": _normalize_custom_pci_category(str(group.get("category") or "pci_scope_context")),
            "pci_category": "CONTEXT",
            "pci_treatment": "Tenant-defined PCI context marker. It supports triage and scope review, but does not by itself confirm CHD or SAD storage.",
            "label": label,
            "description": "Tenant-defined PCI keyword context matched in file content or metadata.",
            "count": len(matched_terms),
            "samples": [f"CUSTOM_TERM:{term[:64]}" for term in matched_terms[:5]],
            "matched_keywords": matched_terms[:10],
            "confidence": 45,
            "protection_state": "CONTEXT_ONLY",
            "secure_fingerprints": [secure_text_fingerprint(f"{finding_type}:{term}", "pci-custom-keyword-v1") for term in matched_terms[:10]],
            "pci_requirements": ["12.5", "12.6"],
            "severity_rationale": "Custom context helps identify payment workflows, processors, exports, or tenant-specific PCI vocabulary for analyst review.",
            "remediation": "Validate whether this file participates in payment processing or stores CHD/SAD; tune custom terms if this is expected non-payment content.",
            "correlated_elements": [],
            "scope_candidate": False,
            "finding_role": "custom_context_observation",
        }
        _merge_finding_dict(findings, data)


def _detect_structured_payment_rows(content: str, evidence_blob: str, metadata: dict, findings: dict[tuple[str, str], dict]) -> None:
    extension = str(metadata.get("extension") or "").lower()
    if extension not in {".csv", ".tsv", ".xlsx", ".xlsm"}:
        return
    rows = _structured_rows(content, extension)
    for row in rows[:5000]:
        row_text = " ".join(f"{cell.get('column_name') or cell.get('cell_address')}: {cell.get('value')}" for cell in row["cells"] if cell.get("value"))
        if not row_text.strip():
            continue
        row_context = f"{row_text} {evidence_blob}"
        pan_values: list[str] = []
        for match in PAN_CANDIDATE_RE.finditer(row_text):
            normalized = normalize_pan_candidate(match.group(0))
            if normalized and _luhn_pass(normalized) and normalized not in pan_values:
                pan_values.append(normalized)
        if not pan_values:
            continue
        pan_context = {
            "context": row_text,
            "protection_state": "READABLE_FULL",
            "fingerprint": secure_fingerprint(pan_values[0], _tenant_id(metadata)),
            "readable_full": True,
        }
        for pan in pan_values[:5]:
            finding = _build_pan_finding(pan, row_text, row_context, metadata)
            if finding:
                data = finding.to_dict()
                _add_structured_location(data, row)
                _merge_finding_dict(findings, data)

        cvv_values = _structured_values_for_keywords(row, CVV_KEYWORDS, parse_cvv_value)
        for cvv_value, keyword, cell in cvv_values[:5]:
            data = PCIFinding(
                finding_type="pci_sad_cvv",
                label="Card Verification Code / Value",
                risk="CRITICAL",
                description="Card verification code/value detected in the same structured row as PAN.",
                pci_category="SAD",
                pci_treatment="CVV/CVC/CID values must not be retained after authorization; customer consent and encryption do not permit storage.",
                protection_state="READABLE_FULL",
                confidence=96,
                count=1,
                samples=[mask_cvv_value(cvv_value)],
                matched_keywords=[keyword],
                secure_fingerprints=[secure_text_fingerprint(f"row:{_row_key(row)}:cvv:{len(cvv_value)}:{pan_context['fingerprint']}", "pci-cvv-v1")],
                pci_requirements=["3.2.2"],
                severity_rationale="CVV is present in the same structured row as readable PAN, which is strong evidence of prohibited SAD retention.",
                remediation="Purge CVV from structured exports, source tables, logs, and downstream copies; retain only non-sensitive authorization metadata.",
                correlated_elements=["pan"],
                logical_boundary="structured_row",
                source_format="spreadsheet" if extension in {".xlsx", ".xlsm"} else "csv",
            ).to_dict()
            _add_structured_location(data, row, cell)
            _merge_finding_dict(findings, data)

        expiry_values = _structured_values_for_keywords(row, EXPIRATION_DATE_KEYWORDS, parse_expiration_value)
        for expiry, keyword, cell in expiry_values[:5]:
            data = PCIFinding(
                finding_type="pci_chd_expiration_date",
                label="Expiration Date",
                risk="HIGH",
                description="Payment card expiration date detected in the same structured row as PAN.",
                pci_category="CHD",
                pci_treatment="Expiration date is CHD when linked to PAN and should inherit CDE controls.",
                protection_state="LINKED_READABLE_FULL",
                confidence=88,
                count=1,
                samples=[expiry],
                matched_keywords=[keyword],
                secure_fingerprints=[secure_text_fingerprint(f"row:{_row_key(row)}:expiry:{expiry}:{pan_context['fingerprint']}", "pci-expiration-date-v1")],
                pci_requirements=["3.3"],
                severity_rationale="Expiry in the same structured row as PAN enriches cardholder data and increases fraud utility.",
                remediation="Minimize expiry retention and remove it from unnecessary exports, logs, and analytics datasets.",
                correlated_elements=["pan"],
                logical_boundary="structured_row",
                source_format="spreadsheet" if extension in {".xlsx", ".xlsm"} else "csv",
            ).to_dict()
            _add_structured_location(data, row, cell)
            _merge_finding_dict(findings, data)

        name_values = _structured_values_for_keywords(row, CARDHOLDER_NAME_KEYWORDS, lambda value: normalize_cardholder_name(value) if is_valid_cardholder_name(_clean_name_candidate(value)) else "")
        for name_value, keyword, cell in name_values[:5]:
            candidate = _clean_name_candidate(name_value)
            data = PCIFinding(
                finding_type="pci_chd_cardholder_name",
                label="Cardholder Name",
                risk="HIGH",
                description="Cardholder name detected in the same structured row as PAN.",
                pci_category="CHD",
                pci_treatment="Cardholder name is CHD when linked to PAN; PAN defines PCI scope while name increases identity linkage.",
                protection_state="LINKED_READABLE_FULL",
                confidence=86,
                count=1,
                samples=[mask_cardholder_name(candidate)],
                matched_keywords=[keyword],
                secure_fingerprints=[secure_text_fingerprint(f"row:{_row_key(row)}:name:{normalize_cardholder_name(candidate)}:{pan_context['fingerprint']}", "pci-cardholder-name-v1")],
                canonical_entity_type="PERSON_NAME",
                canonical_entity_fingerprints=[canonical_entity_fingerprint("PERSON_NAME", normalize_cardholder_name(candidate), _tenant_id(metadata))],
                pci_requirements=["3.3"],
                severity_rationale="Cardholder name in the same structured row as PAN enriches CHD and increases identity exposure.",
                remediation="Avoid retaining name-on-card where not needed and separate identity metadata from PAN-bearing records.",
                correlated_elements=["pan"],
                logical_boundary="structured_row",
                source_format="spreadsheet" if extension in {".xlsx", ".xlsm"} else "csv",
            ).to_dict()
            _add_structured_location(data, row, cell)
            _merge_finding_dict(findings, data)


def _detect_pan_reconstruction_risk(content: str, evidence_blob: str, metadata: dict, findings: dict[tuple[str, str], dict]) -> None:
    lowered = content.lower()
    if not any(marker in lowered for marker in ("first_six", "first six", "first8", "first_8", "middle_six", "last_four", "last four", "last8", "last_8")):
        return
    pieces: dict[str, str] = {}
    patterns = {
        "first": r"(?:first[_ -]?(?:six|6|eight|8)|bin|iin)\s*[:=]\s*(\d{6,8})",
        "middle": r"middle[_ -]?(?:six|6)\s*[:=]\s*(\d{4,6})",
        "last": r"(?:last[_ -]?(?:four|4|eight|8))\s*[:=]\s*(\d{4,8})",
    }
    for name, pattern in patterns.items():
        match = re.search(pattern, content, flags=re.IGNORECASE)
        if match:
            pieces[name] = match.group(1)
    candidate = f"{pieces.get('first', '')}{pieces.get('middle', '')}{pieces.get('last', '')}"
    if not (12 <= len(candidate) <= 19 and _luhn_pass(candidate)):
        return
    tenant_id = _tenant_id(metadata)
    data = {
        "type": "pci_pan_reconstruction_risk",
        "framework": "pci_dss",
        "risk": "CRITICAL",
        "category": "pci_cardholder_data",
        "pci_category": "CHD",
        "pci_treatment": "PAN fragments can reconstruct a full account number and must be protected as PAN when correlated by a record identifier.",
        "label": "PAN Reconstruction Risk",
        "description": "PAN fragments in the same logical artifact can reconstruct a Luhn-valid PAN.",
        "count": 1,
        "samples": [mask_pan(candidate)],
        "matched_keywords": ["pan fragments", "reconstruction"],
        "confidence": 82,
        "protection_state": "RECONSTRUCTABLE",
        "secure_fingerprints": [secure_fingerprint(candidate, tenant_id)],
        "pci_requirements": [],
        "severity_rationale": "Separated PAN fragments can still recreate full PAN when joined through a common record or customer identifier.",
        "remediation": "Treat correlated PAN fragments as PAN, reduce fragment retention, and prevent joins that reconstruct full account numbers.",
        "correlated_elements": ["pan_fragments"],
        "logical_boundary": _logical_boundary(str(metadata.get("extension") or "").lower()),
        "source_format": _source_format(str(metadata.get("extension") or "").lower()),
        "scope_candidate": True,
        "tenant_id": tenant_id,
        "reconstruction_parts": sorted(pieces.keys()),
    }
    _merge_finding_dict(findings, data)


def _apply_enterprise_context(findings: dict[tuple[str, str], dict], metadata: dict, content: str) -> None:
    context = _enterprise_context(metadata, content)
    tenant_id = _tenant_id(metadata)
    for finding in findings.values():
        for key, value in context.items():
            if key in {"logical_boundary", "source_format"} and finding.get("logical_boundary") == "structured_row":
                continue
            finding[key] = value
        _apply_pci_taxonomy(finding)
        _apply_pci_operational_defaults(finding, tenant_id)
        finding["exception_required"] = _exception_required(finding)
        finding["exception_status"] = "required" if finding["exception_required"] else finding.get("exception_status", "not_required")
        finding["sad_lifecycle_status"] = _sad_lifecycle_status(finding)
        if finding["exception_required"]:
            finding.setdefault("exception_reason", "SAD retention is prohibited after authorization; lifecycle evidence and approved issuer/service-provider justification require review.")
        finding.setdefault("review_status", "unreviewed")
        finding.setdefault("scope_candidate", str(finding.get("pci_category") or "").upper() in {"CHD", "SAD"})
        finding.setdefault("display_state", "primary")
        finding.setdefault("parent_finding_type", "")
        finding.setdefault("child_finding_types", [])
        finding.setdefault("suppressed_by", [])


def _apply_pci_hierarchy(findings: dict[tuple[str, str], dict]) -> None:
    by_type: dict[str, list[dict]] = {}
    for finding in findings.values():
        by_type.setdefault(str(finding.get("type") or ""), []).append(finding)

    if "pci_sad_track_data" in by_type:
        child_types = [
            "pci_chd_pan",
            "pci_chd_cardholder_name",
            "pci_chd_expiration_date",
            "pci_chd_service_code",
            "pci_chd_masked_pan",
            "pci_chd_truncated_pan",
        ]
        present_children: list[str] = []
        for child_type in child_types:
            for child in by_type.get(child_type, []):
                present_children.append(child_type)
                _mark_child(child, "pci_sad_track_data")
        for parent in by_type["pci_sad_track_data"]:
            parent["child_finding_types"] = _dedupe([*(parent.get("child_finding_types") or []), *present_children])

    has_readable_pan = bool(by_type.get("pci_chd_pan"))
    sad_children = [
        item
        for type_name in ("pci_sad_cvv", "pci_sad_pin", "pci_sad_pin_block")
        for item in by_type.get(type_name, [])
        if "pan" in (item.get("correlated_elements") or [])
    ]
    if has_readable_pan and sad_children:
        correlated = _dedupe(["pan", *(element for child in sad_children for element in child.get("correlated_elements") or []), "sensitive_authentication_data"])
        template = dict(by_type["pci_chd_pan"][0])
        if any(child.get("logical_boundary") == "structured_row" for child in sad_children):
            template["logical_boundary"] = "structured_row"
            template["source_format"] = next((child.get("source_format") for child in sad_children if child.get("logical_boundary") == "structured_row"), template.get("source_format"))
        _add_composite_finding(
            findings,
            finding_type="pci_composite_sad",
            label="Composite PAN + Sensitive Authentication Data",
            risk="CRITICAL",
            pci_category="SAD",
            protection_state="COMPOSITE_SAD",
            description="Readable PAN is co-located with CVV, PIN, or PIN block evidence in the same logical artifact.",
            pci_treatment="Composite PAN + SAD evidence is a highest-priority PCI DSS retention violation candidate unless an approved issuing lifecycle exception exists.",
            samples=["PAN+SAD_COMPOSITE"],
            correlated_elements=correlated,
            child_finding_types=_dedupe(["pci_chd_pan", *(child.get("type") for child in sad_children if child.get("type"))]),
            pci_requirements=["3.2", "3.2.2", "3.2.3", "3.3"],
            severity_rationale="PAN plus retained authentication data can enable direct transaction abuse and expands the scope of affected systems.",
            remediation="Purge SAD, block serialization of CVV/PIN/PIN-block fields, rotate downstream exports/logs/backups, and validate payment flow boundaries.",
            template=template,
        )
        for child in [*by_type.get("pci_chd_pan", []), *sad_children]:
            _mark_child(child, "pci_composite_sad")

    enriched_children = [
        item for type_name in ("pci_chd_cardholder_name", "pci_chd_expiration_date", "pci_chd_service_code") for item in by_type.get(type_name, [])
    ]
    if has_readable_pan and enriched_children:
        _add_composite_finding(
            findings,
            finding_type="pci_enriched_chd_record",
            label="Enriched Cardholder Data Record",
            risk="CRITICAL",
            pci_category="CHD",
            protection_state="ENRICHED_CHD",
            description="Readable PAN is co-located with additional CHD elements such as cardholder name, expiration date, or service code.",
            pci_treatment="Enriched CHD records are in PCI DSS scope and should be minimized, protected at rest, and removed from logs/exports where not required.",
            samples=["PAN+CHD_ENRICHED"],
            correlated_elements=_dedupe(["pan", *(element for child in enriched_children for element in child.get("correlated_elements") or []), "cardholder_data"]),
            child_finding_types=_dedupe(["pci_chd_pan", *(child.get("type") for child in enriched_children if child.get("type"))]),
            pci_requirements=["3.3", "3.4", "3.5"],
            severity_rationale="Additional CHD next to readable PAN increases fraud impact and strengthens evidence that the artifact belongs in the CDE.",
            remediation="Minimize CHD fields, tokenize or encrypt retained PAN, and remove enriched cardholder records from logs, debug payloads, exports, and broad shares.",
            template=by_type["pci_chd_pan"][0],
        )
        for child in [*by_type.get("pci_chd_pan", []), *enriched_children]:
            _mark_child(child, "pci_enriched_chd_record")


def _add_composite_finding(
    findings: dict[tuple[str, str], dict],
    *,
    finding_type: str,
    label: str,
    risk: str,
    pci_category: str,
    protection_state: str,
    description: str,
    pci_treatment: str,
    samples: list[str],
    correlated_elements: list[str],
    child_finding_types: list[str],
    pci_requirements: list[str],
    severity_rationale: str,
    remediation: str,
    template: dict,
) -> None:
    data = {
        "type": finding_type,
        "framework": "pci_dss",
        "risk": risk,
        "category": _pci_data_category(pci_category),
        "pci_category": pci_category,
        "pci_treatment": pci_treatment,
        "label": label,
        "description": description,
        "count": 1,
        "samples": samples,
        "matched_keywords": template.get("matched_keywords") or [],
        "confidence": max(90, int(template.get("confidence") or 0)),
        "protection_state": protection_state,
        "secure_fingerprints": [secure_text_fingerprint(f"{finding_type}:{template.get('secure_fingerprints')}", "pci-composite-v1")],
        "pci_requirements": pci_requirements,
        "severity_rationale": severity_rationale,
        "remediation": remediation,
        "correlated_elements": correlated_elements,
        "logical_boundary": template.get("logical_boundary") or "text_proximity_window",
        "source_format": template.get("source_format") or "unstructured_text",
        "environment": template.get("environment") or "unknown",
        "storage_state": template.get("storage_state") or "unknown",
        "entity_role": template.get("entity_role") or "unknown",
        "authorization_state": template.get("authorization_state") or "unknown",
        "scope_candidate": True,
        "exception_required": pci_category == "SAD",
        "exception_status": "required" if pci_category == "SAD" else "not_required",
        "exception_reason": "Composite SAD requires approved issuer/service-provider retention exception." if pci_category == "SAD" else "",
        "review_status": "unreviewed",
        "display_state": "primary",
        "parent_finding_type": "",
        "child_finding_types": child_finding_types,
        "suppressed_by": [],
    }
    _merge_finding_dict(findings, data)


def _mark_child(finding: dict, parent_type: str) -> None:
    finding["display_state"] = "child_evidence"
    finding["parent_finding_type"] = finding.get("parent_finding_type") or parent_type
    finding["suppressed_by"] = _dedupe([*(finding.get("suppressed_by") or []), parent_type])


def _apply_pci_taxonomy(finding: dict) -> None:
    finding_type = str(finding.get("type") or "")
    protection_state = str(finding.get("protection_state") or "")
    taxonomy = {
        "pci_chd_pan": ("PCI-PAN-001" if protection_state == "READABLE_FULL" else "PCI-PAN-002", "PAN", "Protection Failure" if protection_state == "READABLE_FULL" else "Data Presence"),
        "pci_chd_masked_pan": ("PCI-MSK-001", "PAN", "Data Presence"),
        "pci_chd_truncated_pan": ("PCI-TRN-001", "PAN", "Data Presence"),
        "pci_tokenized_pan": ("PCI-TOK-001", "PAN Token", "Protection State"),
        "pci_hashed_pan": ("PCI-PAN-002", "PAN Hash", "Protection State"),
        "pci_encrypted_pan": ("PCI-PAN-002", "Encrypted PAN", "Protection State"),
        "pci_chd_cardholder_name": ("PCI-CHD-001" if "pan" in finding.get("correlated_elements", []) else "PCI-CTX-001", "Cardholder Name", "Data Presence" if "pan" in finding.get("correlated_elements", []) else "Contextual Signal"),
        "pci_chd_expiration_date": ("PCI-CHD-002" if "pan" in finding.get("correlated_elements", []) else "PCI-CTX-002", "Expiration Date", "Data Presence" if "pan" in finding.get("correlated_elements", []) else "Contextual Signal"),
        "pci_chd_service_code": ("PCI-CHD-003" if "pan" in finding.get("correlated_elements", []) else "PCI-CTX-003", "Service Code", "Data Presence" if "pan" in finding.get("correlated_elements", []) else "Contextual Signal"),
        "pci_enriched_chd_record": ("PCI-CHD-004", "Complete CHD Record", "Data Presence"),
        "pci_sad_track_data": ("PCI-SAD-001", "Full Track Data", "Prohibited Storage"),
        "pci_sad_cvv": ("PCI-SAD-002", "CVV/CVC/CID", "Prohibited Storage"),
        "pci_sad_pin": ("PCI-SAD-003", "PIN", "Prohibited Storage"),
        "pci_sad_pin_block": ("PCI-SAD-004", "PIN Block", "Prohibited Storage"),
        "pci_composite_sad": ("PCI-SAD-005", "PAN + SAD", "Prohibited Storage"),
        "pci_payment_context": ("PCI-CTX-000", "Payment Context", "Contextual Signal"),
    }
    rule_id, data_element, finding_category = taxonomy.get(finding_type, ("PCI-CTX-000", "PCI Context", "Contextual Signal"))
    if not finding.get("rule_id"):
        finding["rule_id"] = rule_id
    if not finding.get("data_element"):
        finding["data_element"] = data_element
    if not finding.get("finding_category") or finding.get("finding_category") == "Data Presence":
        finding["finding_category"] = finding_category
    official = "Sensitive Authentication Data" if str(finding.get("pci_category") or "").upper() == "SAD" else "Cardholder Data" if str(finding.get("pci_category") or "").upper() == "CHD" else "Contextual PCI Signal"
    finding["official_category"] = official


def _pci_data_category(pci_category: str) -> str:
    category = str(pci_category or "").upper()
    if category == "SAD":
        return "pci_sensitive_authentication_data"
    if category == "CHD":
        return "pci_cardholder_data"
    return "pci_scope_context"


def _normalize_custom_pci_category(category: str) -> str:
    normalized = category.strip().lower().replace("-", "_").replace(" ", "_") or "pci_scope_context"
    aliases = {
        "pci": "pci_scope_context",
        "pci_payment": "pci_scope_context",
        "cardholder_data": "pci_cardholder_data",
        "chd": "pci_cardholder_data",
        "sensitive_authentication_data": "pci_sensitive_authentication_data",
        "sad": "pci_sensitive_authentication_data",
    }
    return aliases.get(normalized, normalized if normalized.startswith("pci_") else f"pci_{normalized}")


def _enterprise_context(metadata: dict, content: str) -> dict:
    extension = str(metadata.get("extension") or "").lower()
    blob = " ".join(str(metadata.get(key) or "").lower() for key in ("name", "path", "share", "source", "storage", "owner"))
    evidence = f"{blob} {content[:2000].lower()}"
    return {
        "logical_boundary": _logical_boundary(extension),
        "source_format": _source_format(extension),
        "environment": _environment(evidence),
        "storage_state": _storage_state(extension, evidence),
        "entity_role": _entity_role(evidence),
        "authorization_state": _authorization_state(evidence),
    }


def _logical_boundary(extension: str) -> str:
    if extension in {".csv", ".tsv", ".xlsx", ".xls"}:
        return "row_or_sheet_record"
    if extension in {".json", ".jsonl", ".ndjson"}:
        return "json_object_or_event"
    if extension in {".xml"}:
        return "xml_element"
    if extension in {".log", ".txt"}:
        return "log_event_or_text_window"
    if extension in {".sql", ".db", ".sqlite"}:
        return "table_row_or_dump_statement"
    return "text_proximity_window"


def _source_format(extension: str) -> str:
    return {
        ".csv": "csv",
        ".tsv": "tsv",
        ".xlsx": "spreadsheet",
        ".xls": "spreadsheet",
        ".json": "json",
        ".jsonl": "jsonl",
        ".ndjson": "jsonl",
        ".xml": "xml",
        ".log": "log",
        ".sql": "sql_dump",
        ".db": "database_file",
        ".sqlite": "database_file",
        ".txt": "text",
    }.get(extension, "unstructured_text")


def _environment(evidence: str) -> str:
    if any(marker in evidence for marker in ("prod", "production", "live", "settlement", "clearing")):
        return "production"
    if any(marker in evidence for marker in ("stage", "staging", "uat", "preprod")):
        return "staging"
    if any(marker in evidence for marker in ("dev", "development", "sandbox", "test", "qa")):
        return "non_production"
    return "unknown"


def _storage_state(extension: str, evidence: str) -> str:
    if any(marker in evidence for marker in ("backup", ".bak", "archive", "zip", "7z", "rar")):
        return "backup_or_archive"
    if extension in {".log", ".txt"} or any(marker in evidence for marker in ("log", "debug", "trace", "request", "response")):
        return "log_or_diagnostic"
    if any(marker in evidence for marker in ("export", "extract", "download", "report", "csv", "xlsx")):
        return "export_or_report"
    if any(marker in evidence for marker in ("queue", "kafka", "event", "message", "payload")):
        return "message_or_event"
    if any(marker in evidence for marker in ("db", "database", "table", "vault")) or extension in {".db", ".sqlite", ".sql"}:
        return "database_or_vault"
    return "persisted_or_unknown"


def _entity_role(evidence: str) -> str:
    if any(marker in evidence for marker in ("issuer", "issuing bank", "card issuer", "issuing_processor")):
        return "issuer_or_issuing_processor"
    if any(marker in evidence for marker in ("acquirer", "merchant acquirer", "acquiring")):
        return "acquirer"
    if any(marker in evidence for marker in ("processor", "gateway", "psp", "payment service provider", "switch")):
        return "processor_or_service_provider"
    if any(marker in evidence for marker in ("merchant", "shop", "checkout", "pos", "ecommerce")):
        return "merchant"
    return "unknown"


def _authorization_state(evidence: str) -> str:
    if any(marker in evidence for marker in ("preauth", "pre_auth", "pre-authorization", "before authorization", "auth request")):
        return "pre_authorization"
    if any(marker in evidence for marker in ("postauth", "post_auth", "post-authorization", "settlement", "clearing", "chargeback", "capture", "reconciliation")):
        return "post_authorization"
    if "authorization" in evidence or "authorisation" in evidence:
        return "authorization_flow"
    return "unknown"


def _exception_required(finding: dict) -> bool:
    if str(finding.get("pci_category") or "").upper() != "SAD":
        return False
    return True


def _sad_lifecycle_status(finding: dict) -> str:
    if str(finding.get("pci_category") or "").upper() != "SAD":
        return "NOT_SAD"
    role = str(finding.get("entity_role") or "").lower()
    auth_state = str(finding.get("authorization_state") or "").lower()
    if auth_state == "post_authorization":
        return "POST_AUTH_CONFIRMED"
    if "issuer" in role and auth_state in {"pre_authorization", "authorization_flow"}:
        return "ISSUER_LEGITIMATE_NEED_REVIEW"
    if auth_state == "pre_authorization":
        return "PRE_AUTH_TRANSIENT_PROCESSING"
    if auth_state == "unknown":
        return "AUTHORIZATION_STATE_UNKNOWN"
    return "LIFECYCLE_EVIDENCE_REQUIRED"


def _term_matches(text: str, term: str) -> bool:
    pattern = rf"(?<!\w){re.escape(term)}(?!\w)"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def _dedupe(items) -> list[str]:
    return list(dict.fromkeys(str(item) for item in items if item))


def _is_strong_cvv_keyword(keyword: str) -> bool:
    normalized = str(keyword or "").strip().lower().replace("-", "_").replace(" ", "_")
    strong = {
        "cvv", "cvv2", "cvc", "cvc2", "cid", "cav2", "cvn2", "csc",
        "card_cvv", "card_cvc", "cc_cvv", "cc_cvc", "cvv_value", "cvc_value",
        "card_security_code", "card_verification_code", "card_verification_value",
        "payment_security_code", "credit_card_security_code", "debit_card_security_code",
    }
    return normalized in strong or "security_code" in normalized and "card" in normalized


def _is_strong_pin_keyword(keyword: str) -> bool:
    normalized = str(keyword or "").strip().lower().replace("-", "_").replace(" ", "_")
    strong_markers = (
        "card_pin", "payment_card_pin", "debit_card_pin", "atm_pin", "cardholder_pin",
        "payment_pin", "transaction_pin", "clear_pin", "cleartext_pin", "plaintext_pin",
        "pin_value", "pin_data", "pin_block", "pinblock", "iso_pin_block", "encrypted_pin_block",
        "pin_encryption_key", "zone_pin_key", "terminal_pin_key",
    )
    return any(marker in normalized for marker in strong_markers)


def _has_pin_crypto_context(context: str) -> bool:
    lowered = context.lower()
    return any(marker in lowered for marker in ("pin block", "pin_block", "pinblock", "iso 9564", "hsm", "zpk", "pek", "tpk", "pin encryption key", "terminal pin key"))


def _structured_rows(content: str, extension: str) -> list[dict]:
    if extension in {".xlsx", ".xlsm"}:
        return _xlsx_marker_rows(content)
    return _csv_rows(content, delimiter="\t" if extension == ".tsv" else ",")


def _csv_rows(content: str, delimiter: str = ",") -> list[dict]:
    text = (content or "").lstrip("\ufeff")
    if not text.strip():
        return []
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel_tab if delimiter == "\t" else csv.excel
    try:
        reader = csv.reader(io.StringIO(text), dialect)
        raw_rows = []
        for index, values in enumerate(reader, start=1):
            raw_rows.append((index, values))
            if len(raw_rows) >= 5001:
                break
    except csv.Error:
        return []
    if not raw_rows:
        return []
    headers = [str(value or "").strip() for value in raw_rows[0][1]]
    has_header = any(keyword_hits(" ".join(headers), (*PAN_KEYWORDS, *CVV_KEYWORDS, *EXPIRATION_DATE_KEYWORDS, *CARDHOLDER_NAME_KEYWORDS)) for _ in [0])
    rows: list[dict] = []
    data_rows = raw_rows[1:] if has_header else raw_rows
    for row_number, values in data_rows:
        cells = []
        for offset, value in enumerate(values):
            column_number = offset + 1
            column_name = headers[offset] if has_header and offset < len(headers) else f"Column {column_number}"
            cells.append(
                {
                    "sheet_name": "",
                    "row_number": row_number,
                    "column_number": column_number,
                    "column_name": column_name,
                    "cell_address": f"{_excel_column_name(column_number)}{row_number}",
                    "value": str(value or "").strip(),
                }
            )
        rows.append({"sheet_name": "", "row_number": row_number, "cells": cells})
    return rows


def _xlsx_marker_rows(content: str) -> list[dict]:
    rows: list[dict] = []
    headers_by_sheet: dict[str, dict[str, str]] = {}
    pattern = re.compile(r"^\[xlsx sheet=(?P<sheet>.*?) row=(?P<row>\d*)\]\s*(?P<cells>.*)$")
    for line in (content or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        sheet_name = match.group("sheet") or "Sheet"
        row_number = int(match.group("row") or 0)
        cells = []
        parsed = _parse_xlsx_marker_cells(match.group("cells"))
        if row_number == 1:
            headers_by_sheet.setdefault(sheet_name, {}).update({column: value for column, _, value in parsed if value})
        headers = headers_by_sheet.get(sheet_name, {})
        for column, address, value in parsed:
            column_number = _excel_column_number(column)
            cells.append(
                {
                    "sheet_name": sheet_name,
                    "row_number": row_number,
                    "column_number": column_number,
                    "column_name": headers.get(column, column),
                    "cell_address": address,
                    "value": value,
                }
            )
        rows.append({"sheet_name": sheet_name, "row_number": row_number, "cells": cells})
    return rows


def _parse_xlsx_marker_cells(value: str) -> list[tuple[str, str, str]]:
    cells: list[tuple[str, str, str]] = []
    for part in str(value or "").split(" | "):
        if "=" not in part:
            continue
        address, cell_value = part.split("=", 1)
        address = address.strip()
        column_match = re.match(r"([A-Za-z]+)", address)
        if not column_match:
            continue
        cells.append((column_match.group(1).upper(), address, cell_value.strip()))
    return cells


def _structured_values_for_keywords(row: dict, keywords: tuple[str, ...], parser) -> list[tuple[str, str, dict]]:
    values: list[tuple[str, str, dict]] = []
    for cell in row.get("cells") or []:
        raw_value = str(cell.get("value") or "").strip()
        if not raw_value:
            continue
        context = f"{cell.get('column_name') or ''} {cell.get('cell_address') or ''} {raw_value}"
        hits = keyword_hits(context, keywords, limit=3)
        if not hits:
            continue
        parsed = parser(raw_value)
        if parsed:
            values.append((parsed, hits[0], cell))
    return values


def _add_structured_location(data: dict, row: dict, cell: dict | None = None) -> None:
    cell = cell or ((row.get("cells") or [{}])[0])
    data["logical_boundary"] = "structured_row"
    data["structured_location"] = {
        "sheet_name": row.get("sheet_name") or cell.get("sheet_name") or "",
        "row_number": row.get("row_number") or cell.get("row_number") or 0,
        "column_number": cell.get("column_number") or 0,
        "column_name": cell.get("column_name") or "",
        "cell_address": cell.get("cell_address") or "",
    }


def _row_key(row: dict) -> str:
    return f"{row.get('sheet_name') or ''}:{row.get('row_number') or 0}"


def _excel_column_name(number: int) -> str:
    name = ""
    while number > 0:
        number, remainder = divmod(number - 1, 26)
        name = chr(65 + remainder) + name
    return name or "A"


def _excel_column_number(name: str) -> int:
    number = 0
    for char in str(name or "").upper():
        if not ("A" <= char <= "Z"):
            continue
        number = number * 26 + (ord(char) - 64)
    return number


def _merge_finding(findings: dict[tuple[str, str], dict], finding: PCIFinding) -> None:
    data = finding.to_dict()
    _merge_finding_dict(findings, data)


def _merge_finding_dict(findings: dict[tuple[str, str], dict], data: dict) -> None:
    key = (data["type"], data["protection_state"])
    existing = findings.get(key)
    if not existing:
        findings[key] = data
        return
    existing["count"] = int(existing.get("count") or 0) + data["count"]
    existing["confidence"] = max(int(existing.get("confidence") or 0), data["confidence"])
    for field in ("samples", "matched_keywords", "secure_fingerprints", "correlated_elements", "pci_requirements", "requirement_mappings", "child_finding_types", "suppressed_by"):
        current = list(existing.get(field) or [])
        for item in data.get(field) or []:
            if item not in current:
                current.append(item)
        existing[field] = current[:10]
    existing["exception_required"] = bool(existing.get("exception_required") or data.get("exception_required"))
    if existing["exception_required"]:
        existing["exception_status"] = "required"


def _clean_name_candidate(value: str) -> str:
    candidate = str(value or "").strip(" \t:=-,")
    candidate = re.split(r"\s+(?:card_?number|pan|expiry|expiration|cvv|cvc|cid|service_code|svc_code)\b", candidate, maxsplit=1, flags=re.IGNORECASE)[0]
    return candidate.strip(" \t:=-,")


def _parse_expiry_with_context(value: str, context: str) -> str:
    context_hint = "track" if any(marker in context.lower() for marker in ("track", "track1", "track2", "emv", "service code")) else "display"
    return parse_expiration_value(value, context_hint=context_hint)


def _paired_month_year_expiry(content: str) -> tuple[str, str, str] | None:
    month_match = EXPIRY_MONTH_FIELD_RE.search(content)
    year_match = EXPIRY_YEAR_FIELD_RE.search(content)
    if not month_match or not year_match:
        return None
    distance = abs(month_match.start() - year_match.start())
    if distance > 220:
        return None
    parsed = parse_expiration_value(f"{month_match.group(1)}/{year_match.group(1)}")
    if not parsed:
        return None
    raw = f"{month_match.group(0)} {year_match.group(0)}"
    return parsed, "expiry month/year", raw


def _context_around_value(content: str, value: str, window: int = 160) -> str:
    index = content.lower().find(str(value or "").lower())
    if index < 0:
        return content[:window]
    return local_context(content, index, window)


def _best_linked_pan(context: str, pan_contexts: list[dict]) -> dict:
    if not pan_contexts:
        return {}
    normalized_context = " ".join(context.lower().split())
    for pan_context in pan_contexts:
        pan_blob = " ".join(str(pan_context.get("context") or "").lower().split())
        if normalized_context and pan_blob and (normalized_context in pan_blob or pan_blob in normalized_context or _has_context_overlap(normalized_context, pan_blob)):
            return pan_context
    return {}


def _has_context_overlap(left: str, right: str) -> bool:
    left_tokens = {token for token in left.split() if len(token) > 2}
    right_tokens = {token for token in right.split() if len(token) > 2}
    return len(left_tokens & right_tokens) >= 2


def _luhn_pass(normalized: str) -> bool:
    from classification.compliance.validators import is_luhn_valid

    return is_luhn_valid(normalized)


def _path_has_payment_context(metadata: dict) -> bool:
    blob = " ".join(str(metadata.get(key) or "").lower() for key in ("path", "name", "share"))
    return any(marker in blob for marker in ("payment", "card", "cardholder", "pci", "cde", "merchant", "processor"))


def _finding_type_for_state(protection_state: str) -> str:
    if protection_state == "READABLE_FULL":
        return "pci_chd_pan"
    if protection_state == "TRUNCATED_AT_REST":
        return "pci_chd_truncated_pan"
    if protection_state.startswith("TOKENIZED"):
        return "pci_tokenized_pan"
    if protection_state.startswith("HASHED"):
        return "pci_hashed_pan"
    if protection_state == "ENCRYPTED":
        return "pci_encrypted_pan"
    return "pci_chd_pan"


def _risk_for_state(protection_state: str, confidence: int) -> str:
    if protection_state == "READABLE_FULL":
        return "CRITICAL"
    if protection_state in {"ENCRYPTED", "HASHED_UNKEYED_OR_UNKNOWN", "TOKENIZED_NONREVERSIBLE_OR_OUT_OF_SCOPE_CANDIDATE"}:
        return "HIGH"
    if protection_state in {"TRUNCATED_AT_REST", "HASHED_KEYED"}:
        return "MEDIUM"
    return "LOW"


def _description_for_state(protection_state: str) -> str:
    if protection_state == "READABLE_FULL":
        return "Readable full Primary Account Number detected with PCI payment-card evidence."
    return f"PAN candidate detected with protection state {protection_state}; PCI scope and protection effectiveness require validation."


def _tenant_id(metadata: dict) -> str:
    return str(metadata.get("tenant_id") or metadata.get("tenant") or "default")


def _operational_risk_score(impact_severity: str, confidence: int, protection_state: str) -> int:
    severity_weight = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10}.get(str(impact_severity).upper(), 20)
    protection_weight = 35 if protection_state == "READABLE_FULL" else 25 if protection_state in {"ENCRYPTED", "HASHED_UNKEYED_OR_UNKNOWN"} else 12
    confidence_weight = min(max(int(confidence or 0), 0), 100) // 4
    return min(100, severity_weight + protection_weight + confidence_weight)


def _apply_pci_operational_defaults(finding: dict, tenant_id: str) -> None:
    protection_state = str(finding.get("protection_state") or "UNKNOWN")
    claimed_state = str(finding.get("claimed_protection_state") or ("NOT_CLAIMED" if protection_state == "READABLE_FULL" else protection_state))
    finding.setdefault("claimed_protection_state", claimed_state)
    finding.setdefault("verified_protection_state", protection_state)
    finding.setdefault("impact_severity", "CRITICAL" if str(finding.get("risk") or "").upper() == "CRITICAL" else str(finding.get("risk") or "MEDIUM").upper())
    finding.setdefault("detection_confidence", int(finding.get("confidence") or 0))
    finding.setdefault("validation_status", "CONFIRMED" if int(finding.get("confidence") or 0) >= 75 else "NEEDS_REVIEW")
    finding.setdefault("operational_risk_score", _operational_risk_score(finding["impact_severity"], int(finding.get("confidence") or 0), protection_state))
    finding.setdefault("fingerprint_algorithm", "HMAC-SHA-256")
    finding.setdefault("fingerprint_key_version", "tenant-evidence-v1")
    finding.setdefault("tenant_id", tenant_id)
    finding.setdefault("rotation_version", "v1")
    mappings = requirement_mappings_for_finding(str(finding.get("type") or ""))
    finding["requirement_mappings"] = mappings
    finding["pci_requirements"] = [item["requirement_id"] for item in mappings]
    _apply_protection_control_defaults(finding)


def _apply_protection_control_defaults(finding: dict) -> None:
    defaults = {
        "encryption_algorithm": "unknown",
        "encryption_mode": "unknown",
        "key_length": "unknown",
        "key_id": "unknown",
        "key_location": "unknown",
        "key_rotation_date": "unknown",
        "key_owner": "unknown",
        "token_provider": "unknown",
        "token_vault": "unknown",
        "token_reversibility": "unknown",
        "hash_algorithm": "unknown",
        "keyed_hash": "unknown",
        "salted": "unknown",
        "truncation_format": "unknown",
        "masking_format": "unknown",
        "control_verified_at": "",
    }
    for key, value in defaults.items():
        finding.setdefault(key, value)
