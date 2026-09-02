from __future__ import annotations

import hashlib
import hmac
import os

from classification.compliance.evidence_keys import evidence_hmac_key


ENTITY_TYPE_BY_FINDING = {
    "gdpr_full_name": "PERSON_NAME",
    "gdpr_email_address": "EMAIL_ADDRESS",
    "gdpr_phone_number": "PHONE_NUMBER",
    "gdpr_postal_address": "POSTAL_ADDRESS",
    "gdpr_birth_details": "DATE_OF_BIRTH",
    "gdpr_fin_pin": "GOVERNMENT_ID",
    "gdpr_national_id": "GOVERNMENT_ID",
    "gdpr_passport_number": "PASSPORT_NUMBER",
    "gdpr_payment_card_data": "PAN",
    "pci_chd_pan": "PAN",
    "pci_chd_truncated_pan": "PAN",
    "pci_tokenized_pan": "PAN",
    "pci_hashed_pan": "PAN",
    "pci_encrypted_pan": "PAN",
    "pci_chd_masked_pan": "PAN",
    "pci_chd_cardholder_name": "PERSON_NAME",
    "pci_chd_expiration_date": "CARD_EXPIRATION_DATE",
    "pci_chd_service_code": "SERVICE_CODE",
    "pci_sad_cvv": "CVV",
    "pci_sad_pin": "PIN",
    "pci_sad_pin_block": "PIN_BLOCK",
    "pci_sad_track_data": "TRACK_DATA",
}


def canonical_entity_fingerprint(entity_type: str, value: str, tenant_id: str = "default") -> str:
    secret = evidence_hmac_key()
    normalized = _normalize_entity_value(entity_type, value)
    payload = f"canonical-entity-v1:{str(entity_type or '').upper()}:{normalized}"
    return hmac.new(f"{secret}:{tenant_id}".encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_entity_type_for_finding(finding: dict) -> str:
    explicit = str(finding.get("canonical_entity_type") or "").strip().upper()
    if explicit:
        return explicit
    finding_type = str(finding.get("type") or "").lower()
    if finding_type in ENTITY_TYPE_BY_FINDING:
        return ENTITY_TYPE_BY_FINDING[finding_type]
    entity_type = str(finding.get("entity_type") or "").strip().upper()
    if entity_type and entity_type != "SENSITIVE_DATA":
        return entity_type
    return ""


def apply_canonical_entity_registry(findings: list[dict], file_obj: dict) -> list[dict]:
    entities: dict[str, dict] = {}
    tenant_id = str(file_obj.get("tenant_id") or file_obj.get("tenant") or "default")
    for finding in findings:
        # Tenant keyword overlays and context-only PCI/NIST observations are
        # routing evidence, not detected values. Registering them as entities
        # creates framework-specific duplicates of the real canonical value.
        if (
            finding.get("scope_candidate") is False
            or str(finding.get("custom_rule_mode") or finding.get("protection_state") or "").upper() == "CONTEXT_ONLY"
            or str(finding.get("finding_role") or "").lower() == "custom_context_observation"
        ):
            continue
        entity_type = canonical_entity_type_for_finding(finding)
        if not entity_type:
            continue
        fingerprints = _entity_fingerprints(finding)
        if not fingerprints:
            fingerprints = _fallback_fingerprints(finding, entity_type, tenant_id)
        entity_ids: list[str] = []
        for fingerprint in fingerprints:
            entity_id = _stable_id("entity", entity_type, fingerprint)
            entity = entities.setdefault(
                entity_id,
                {
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "secure_fingerprint": fingerprint,
                    "framework_mappings": [],
                    "framework_mapping_details": [],
                    "occurrence_count": 0,
                    "unique_value_count": 1,
                    "finding_ids": [],
                    "occurrence_ids": [],
                    "asset_ids": [],
                    "location_ids": [],
                    "correlation_context": [],
                    "detected_once_mapped_many": True,
                },
            )
            _merge_entity_from_finding(entity, finding)
            entity_ids.append(entity_id)
        if entity_ids:
            finding["canonical_entity_type"] = entity_type
            finding["canonical_entity_ids"] = list(dict.fromkeys([*finding.get("canonical_entity_ids", []), *entity_ids]))
            finding["canonical_entity_id"] = finding["canonical_entity_ids"][0]
            finding["entity_registry_source"] = "canonical_entity_detector"
    for finding in findings:
        for entity_id in finding.get("canonical_entity_ids") or []:
            entity = entities.get(entity_id)
            if entity:
                _merge_finding_frameworks_from_entity(finding, entity)
    return list(entities.values())


def _merge_entity_from_finding(entity: dict, finding: dict) -> None:
    entity["occurrence_count"] += max(int(finding.get("occurrence_count") or finding.get("count") or 1), 1)
    for field, value in (
        ("finding_ids", finding.get("finding_id")),
        ("asset_ids", finding.get("asset_id")),
        ("location_ids", finding.get("location_id")),
    ):
        if value and value not in entity[field]:
            entity[field].append(value)
    for occurrence in finding.get("occurrences") or []:
        occurrence_id = occurrence.get("occurrence_id")
        if occurrence_id and occurrence_id not in entity["occurrence_ids"]:
            entity["occurrence_ids"].append(occurrence_id)
    for mapping in _entity_framework_mapping_details(entity["entity_type"], finding):
        if mapping not in entity["framework_mapping_details"]:
            entity["framework_mapping_details"].append(mapping)
    entity["framework_mappings"] = list(
        dict.fromkeys([mapping["framework"] for mapping in entity["framework_mapping_details"]])
    )
    for context in _correlation_context(finding):
        if context not in entity["correlation_context"]:
            entity["correlation_context"].append(context)


def _merge_finding_frameworks_from_entity(finding: dict, entity: dict) -> None:
    existing = list(finding.get("framework_mappings") or [])
    for framework in entity.get("framework_mappings") or []:
        if framework not in existing:
            existing.append(framework)
    finding["framework_mappings"] = existing
    details = list(finding.get("entity_framework_mapping_details") or [])
    for mapping in entity.get("framework_mapping_details") or []:
        if mapping not in details:
            details.append(mapping)
    finding["entity_framework_mapping_details"] = details


def _entity_framework_mapping_details(entity_type: str, finding: dict) -> list[dict]:
    finding_type = str(finding.get("type") or "")
    mappings: list[dict] = []
    if entity_type == "PERSON_NAME":
        mappings.append(_mapping("GDPR", "personal_data", "Personal data"))
        if finding_type.startswith("pci_") or "pan" in [str(item).lower() for item in finding.get("correlated_elements") or []]:
            mappings.append(_mapping("PCI DSS", "cardholder_data", "Cardholder Data"))
    elif entity_type == "PAN":
        mappings.append(_mapping("PCI DSS", "cardholder_data", "Primary Account Number"))
        mappings.append(_mapping("GDPR", "personal_data", "Payment card data"))
    elif entity_type in {"EMAIL_ADDRESS", "PHONE_NUMBER", "POSTAL_ADDRESS", "DATE_OF_BIRTH", "GOVERNMENT_ID", "PASSPORT_NUMBER"}:
        mappings.append(_mapping("GDPR", "personal_data", entity_type.replace("_", " ").title()))
    elif entity_type in {"CVV", "PIN", "PIN_BLOCK", "TRACK_DATA", "SERVICE_CODE", "CARD_EXPIRATION_DATE"}:
        pci_area = "sensitive_authentication_data" if entity_type in {"CVV", "PIN", "PIN_BLOCK", "TRACK_DATA"} else "cardholder_data"
        mappings.append(_mapping("PCI DSS", pci_area, entity_type.replace("_", " ").title()))
    else:
        for framework in finding.get("framework_mappings") or []:
            mappings.append(_mapping(str(framework), "classification", entity_type.replace("_", " ").title()))
    return mappings


def _mapping(framework: str, data_class: str, title: str) -> dict:
    return {
        "framework": framework,
        "data_class": data_class,
        "title": title,
        "mapping_type": "entity_projection",
        "mapping_confidence": "high",
        "source": "canonical_entity_registry",
    }


def _entity_fingerprints(finding: dict) -> list[str]:
    fingerprints = finding.get("canonical_entity_fingerprints") or []
    return list(dict.fromkeys(str(item) for item in fingerprints if item))


def _fallback_fingerprints(finding: dict, entity_type: str, tenant_id: str) -> list[str]:
    values = finding.get("secure_value_fingerprints") or finding.get("secure_fingerprints") or finding.get("samples") or []
    return [
        canonical_entity_fingerprint(entity_type, str(value), tenant_id)
        for value in values[:10]
        if str(value or "")
    ]


def _correlation_context(finding: dict) -> list[str]:
    context = []
    if finding.get("type"):
        context.append(str(finding["type"]))
    for item in finding.get("correlated_elements") or []:
        context.append(f"linked_to_{item}")
    return context


def _normalize_entity_value(entity_type: str, value: str) -> str:
    text = " ".join(str(value or "").strip().split()).lower()
    if str(entity_type or "").upper() in {"PAN", "CVV", "PIN", "PIN_BLOCK", "SERVICE_CODE"}:
        return "".join(ch for ch in text if ch.isdigit() or ("a" <= ch <= "f"))
    return text


def _stable_id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8', errors='ignore')).hexdigest()[:24]}"
