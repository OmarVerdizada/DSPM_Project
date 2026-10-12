from __future__ import annotations


PCI_DSS_VERSION = "4.0.1"
PCI_DSS_EFFECTIVE_FROM = "2024-06-11"
PCI_DSS_SOURCE_REFERENCE = "PCI SSC Document Library: PCI DSS v4.0.1"


_CATALOG = {
    "pan_display": {
        "requirement_id": "3.3.1",
        "requirement_title": "PAN is masked when displayed.",
        "mapping_type": "direct",
        "mapping_confidence": "high",
    },
    "pan_unreadable": {
        "requirement_id": "3.5.1",
        "requirement_title": "PAN is rendered unreadable anywhere it is stored.",
        "mapping_type": "direct",
        "mapping_confidence": "high",
    },
    "sad_storage": {
        "requirement_id": "3.3.1",
        "requirement_title": "Sensitive authentication data is not stored after authorization.",
        "mapping_type": "direct",
        "mapping_confidence": "high",
    },
    "key_management": {
        "requirement_id": "3.6.1",
        "requirement_title": "Cryptographic keys used to protect stored account data are secured.",
        "mapping_type": "inferred_control",
        "mapping_confidence": "medium",
    },
    "scope_review": {
        "requirement_id": "12.5.2",
        "requirement_title": "PCI DSS scope is documented and confirmed.",
        "mapping_type": "scope_context",
        "mapping_confidence": "medium",
    },
}


FINDING_REQUIREMENT_KEYS = {
    "pci_chd_pan": ("pan_unreadable", "pan_display"),
    "pci_chd_masked_pan": ("pan_display",),
    "pci_chd_truncated_pan": ("pan_unreadable",),
    "pci_tokenized_pan": ("pan_unreadable", "key_management"),
    "pci_hashed_pan": ("pan_unreadable", "key_management"),
    "pci_encrypted_pan": ("pan_unreadable", "key_management"),
    "pci_chd_cardholder_name": ("scope_review",),
    "pci_chd_expiration_date": ("scope_review",),
    "pci_chd_service_code": ("scope_review",),
    "pci_enriched_chd_record": ("pan_unreadable", "scope_review"),
    "pci_sad_track_data": ("sad_storage",),
    "pci_sad_cvv": ("sad_storage",),
    "pci_sad_pin": ("sad_storage",),
    "pci_sad_pin_block": ("sad_storage", "key_management"),
    "pci_composite_sad": ("sad_storage", "pan_unreadable"),
    "pci_pan_reconstruction_risk": ("pan_unreadable", "scope_review"),
}


def requirement_mappings_for_finding(finding_type: str) -> list[dict]:
    mappings: list[dict] = []
    for key in FINDING_REQUIREMENT_KEYS.get(str(finding_type or ""), ("scope_review",)):
        item = _CATALOG[key]
        mappings.append(
            {
                "framework": "PCI DSS",
                "framework_version": PCI_DSS_VERSION,
                "requirement_id": item["requirement_id"],
                "requirement_title": item["requirement_title"],
                "mapping_type": item["mapping_type"],
                "mapping_confidence": item["mapping_confidence"],
                "effective_from": PCI_DSS_EFFECTIVE_FROM,
                "source_reference": PCI_DSS_SOURCE_REFERENCE,
            }
        )
    return mappings
