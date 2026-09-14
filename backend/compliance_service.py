from __future__ import annotations

import json
from collections import Counter
import heapq
from copy import deepcopy
from pathlib import Path
from typing import Iterable

from backend.compliance_rules import CRITICALITY_WEIGHTS, FINDING_CATEGORY_MAP, PATH_CATEGORY_KEYWORDS
from backend.finding_contracts import get_finding_display_name
from classification.compliance.nist_catalog import nist_catalog_status
from classification.compliance.nist_mappings import nist_data_categories_for_finding, nist_framework_mapping_row

PROFILE_PATH = Path(__file__).with_name("compliance_profiles.json")


def load_compliance_profiles() -> list[dict]:
    with PROFILE_PATH.open("r", encoding="utf-8") as handle:
        profiles = json.load(handle)
    return profiles


def allowed_framework_ids() -> set[str]:
    return {profile["id"] for profile in load_compliance_profiles()}


def normalize_framework_ids(frameworks: Iterable[str] | None) -> list[str]:
    allowed = allowed_framework_ids()
    normalized: list[str] = []
    for item in frameworks or []:
        framework_id = str(item or "").strip().lower().replace("-", "_")
        if not framework_id:
            continue
        if framework_id not in allowed:
            raise ValueError(f"Unsupported compliance framework: {item}")
        if framework_id not in normalized:
            normalized.append(framework_id)
    return normalized


def selected_profiles(frameworks: Iterable[str] | None) -> list[dict]:
    requested = normalize_framework_ids(frameworks)
    profile_map = {profile["id"]: profile for profile in load_compliance_profiles()}
    return [profile_map[item] for item in requested if item in profile_map]


def enrich_report_with_compliance(report: dict, enabled: bool, frameworks: Iterable[str] | None) -> dict:
    framework_ids = normalize_framework_ids(frameworks)
    if not enabled or not framework_ids:
        for file_obj in report.get("files") or []:
            file_obj.pop("compliance", None)
            file_obj["findings"] = [finding for finding in file_obj.get("findings") or [] if not _is_framework_only_finding(finding)]
            for finding in file_obj["findings"]:
                _strip_compliance_projection(finding)
                finding["display_name"] = finding.get("display_name") or get_finding_display_name(finding)
            for entity in file_obj.get("canonical_entities") or []:
                entity["framework_mappings"] = []
                entity["framework_mapping_details"] = []
        report["compliance_summary"] = {
            "enabled": False,
            "selected_frameworks": [],
            "affected_asset_count": 0,
            "affected_file_count": 0,
            "finding_group_count": 0,
            "occurrence_count": 0,
            "unique_sensitive_value_count": 0,
            "total_compliance_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "top_violated_categories": [],
            "top_risky_files": [],
            "remediation_priorities": [],
        }
        report.pop("pci_scope_summary", None)
        report.pop("gdpr_report", None)
        report.pop("nist_sp800_60_enterprise_report", None)
        return report

    profiles = selected_profiles(framework_ids)
    files = report.get("files") or []
    sanitize_pci_sensitive_report(report)
    for file_obj in files:
        for finding in file_obj.get("findings") or []:
            finding["display_name"] = finding.get("display_name") or get_finding_display_name(finding)
        compliance = evaluate_file(file_obj, profiles)
        if compliance["matched_frameworks"]:
            file_obj["compliance"] = compliance

    report["compliance_summary"] = build_compliance_summary(files, profiles)
    if "pci_dss" in framework_ids:
        report["pci_scope_summary"] = build_pci_scope_summary(files)
    if "gdpr" in framework_ids:
        report["gdpr_report"] = build_gdpr_report(files)
    if "nist_sp800_60_enterprise" in framework_ids:
        report["nist_sp800_60_enterprise_report"] = build_nist_sp800_60_report(files)
    return report


def _is_framework_only_finding(finding: dict) -> bool:
    """Identify findings emitted only by an opted-in compliance detector."""
    framework = str(finding.get("framework") or "").strip().lower().replace("-", "_")
    finding_type = str(finding.get("type") or finding.get("rule_id") or "").strip().lower()
    category = str(finding.get("category_id") or finding.get("category") or "").strip().lower()
    return (
        framework in {"gdpr", "pci_dss", "nist_sp800_60_enterprise"}
        or finding_type.startswith(("gdpr_", "pci_", "nist_"))
        or category.startswith(("gdpr_", "pci_", "nist_"))
    )


def _strip_compliance_projection(finding: dict) -> None:
    """Keep generic detection evidence while removing opt-in framework labels."""
    finding["framework"] = "generic"
    finding["frameworks"] = []
    finding["framework_mappings"] = []
    finding["entity_framework_mapping_details"] = []
    for key in (
        "gdpr_article_mappings",
        "requirement_mappings",
        "pci_requirements",
        "nist_mappings",
        "framework_mapping",
    ):
        finding.pop(key, None)


def evaluate_file(file_obj: dict, profiles: list[dict]) -> dict:
    categories = infer_data_categories(file_obj)
    base_score = min(int(file_obj.get("risk", {}).get("score") or 0), 100)
    permissions = file_obj.get("permissions") or {}
    matched_profiles: list[dict] = []
    framework_mapping: list[dict] = []
    reasons: list[str] = []
    reason_details: list[dict] = []
    remediations: list[str] = []
    controls: list[str] = []
    score_candidates: list[int] = []
    evidence = _finding_evidence(file_obj)

    for profile in profiles:
        critical_categories = set(profile.get("critical_data_categories") or [])
        matched_categories = sorted(categories & critical_categories)
        exposure_match = permissions.get("wide_access") or permissions.get("writable")
        if not matched_categories and not (profile["id"] in {"nist_csf", "iso27001"} and exposure_match and categories):
            continue

        matched_profiles.append(profile)
        data_weight = _data_weight(matched_categories)
        finding_weight = _finding_weight(file_obj, matched_categories)
        exposure_weight = _exposure_weight(file_obj)
        location_weight = _location_weight(file_obj)
        protection_weight = _protection_weight(file_obj, categories)
        base_component = round(min(base_score, 90) * 0.35)
        score = max(1, min(100, base_component + data_weight + finding_weight + exposure_weight + location_weight + protection_weight))
        score_candidates.append(score)

        category_label = _control_category(profile, matched_categories, exposure_match)
        controls.append(category_label)
        reason = (
            f"{profile['name']}: {', '.join(_category_labels(matched_categories or sorted(categories)))} matched {category_label}; "
            f"risk +{base_component}, data +{data_weight}, evidence +{finding_weight}, exposure +{exposure_weight}, location +{location_weight}."
        )
        reasons.append(reason)
        reason_details.append(
            {
                "framework": profile["name"],
                "category": category_label,
                "data_types": _category_labels(matched_categories or sorted(categories)),
                "reason": reason,
                "score_parts": {
                    "risk": base_component,
                    "data": data_weight,
                    "evidence": finding_weight,
                    "exposure": exposure_weight,
                    "location": location_weight,
                    "protection": protection_weight,
                },
            }
        )
        remediations.append(profile.get("remediation", "Restrict access and validate business need."))
        framework_mapping.append(
            nist_framework_mapping_row({"category": next(iter(matched_categories), ""), "category_id": "", "framework_mappings": []})
            if profile["id"] == "nist_sp800_60_enterprise"
            else {
                "framework": profile["name"],
                "framework_id": profile["id"],
                "category": category_label,
                "matched_data_categories": matched_categories or sorted(categories),
                "source_basis": profile.get("source_basis", []),
                "confidence": profile.get("confidence", "medium"),
                "evidence": evidence,
            }
        )

    final_score = max(score_candidates, default=0)
    severity = _severity(final_score)
    return {
        "matched_frameworks": [profile["id"] for profile in matched_profiles],
        "matched_framework_names": [profile["name"] for profile in matched_profiles],
        "data_categories": sorted(categories),
        "compliance_score": final_score,
        "compliance_severity": severity,
        "compliance_criticality": _criticality_label(categories, permissions),
        "relevant_controls": _dedupe(controls),
        "explanation": " ".join(reasons) if reasons else "",
        "remediation": " ".join(_dedupe(remediations)),
        "framework_mapping": framework_mapping,
        "reason_for_score": reasons,
        "reason_details": reason_details,
        "evidence": evidence,
    }


def infer_data_categories(file_obj: dict) -> set[str]:
    categories: set[str] = set()
    for finding in file_obj.get("findings") or []:
        if str(finding.get("framework") or "").lower() == "nist_sp800_60_enterprise":
            categories.update(nist_data_categories_for_finding(finding))
        categories.update(FINDING_CATEGORY_MAP.get(str(finding.get("type") or "").lower(), []))
        categories.update(FINDING_CATEGORY_MAP.get(str(finding.get("label") or "").lower(), []))
        if finding.get("category"):
            categories.update(_categories_from_finding_category(str(finding.get("category") or "")))
    path_blob = " ".join(str(file_obj.get(key) or "").lower() for key in ("name", "path", "share", "extension"))
    for keyword, keyword_categories in PATH_CATEGORY_KEYWORDS:
        if keyword in path_blob:
            categories.update(keyword_categories)
    return categories


class _FirstN:
    """The first ``limit`` items in arrival order, and how many arrived.

    Equivalent to appending every item to a list and slicing ``[:limit]``, without
    keeping the items that would be sliced away.
    """

    __slots__ = ("limit", "items", "count")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.items: list = []
        self.count = 0

    def add(self, item) -> None:
        self.count += 1
        if len(self.items) < self.limit:
            self.items.append(item)

    def result(self) -> list:
        return list(self.items)


class _TopN:
    """What ``sorted(items, key=key, reverse=True)[:limit]`` returns, without keeping every item.

    Python's sort stays stable in reverse, so among equal keys the earliest arrivals
    come first and survive the slice. The heap holds ``(key, -arrival, item)``: its
    smallest entry is the lowest key and, among equal keys, the latest arrival -
    exactly the entry a stable sort would drop first. Arrival numbers are unique, so
    two entries never get as far as comparing their items.
    """

    __slots__ = ("limit", "key", "heap", "count")

    def __init__(self, limit: int, key) -> None:
        self.limit = limit
        self.key = key
        self.heap: list = []
        self.count = 0

    def add(self, item) -> None:
        entry = (self.key(item), -self.count, item)
        self.count += 1
        if len(self.heap) < self.limit:
            heapq.heappush(self.heap, entry)
        elif entry[:2] > self.heap[0][:2]:
            heapq.heapreplace(self.heap, entry)

    def result(self) -> list:
        ordered = sorted(self.heap, key=lambda entry: entry[:2], reverse=True)
        return [item for _key, _arrival, item in ordered]


class ComplianceSummaryAccumulator:
    """``build_compliance_summary``, one file at a time.

    Holds counters, the set of affected asset keys and the ten highest-scoring
    files - not a row per affected file. The asset set is bounded by the number of
    sensitive assets rather than by the scan, which is the one thing here that is
    not constant-size.
    """

    def __init__(self, profiles: list[dict]) -> None:
        self.profiles = profiles
        self.profile_ids = {str(profile.get("id") or "") for profile in profiles}
        self.severity_counts = Counter()
        self.category_counts = Counter()
        self.remediation_counts = Counter()
        self.affected_assets: set[str] = set()
        self.affected_file_count = 0
        self.finding_group_count = 0
        self.occurrence_count = 0
        self.unique_sensitive_value_count = 0
        self.top_files = _TopN(10, key=lambda item: int(item.get("score") or 0))

    def add(self, file_obj: dict) -> None:
        compliance = file_obj.get("compliance") or {}
        if not compliance.get("matched_frameworks"):
            return
        self.affected_file_count += 1
        self.affected_assets.add(_asset_key(file_obj))
        file_findings = _compliance_findings_for_file(file_obj, self.profile_ids)
        for finding in file_findings:
            severity = str(finding.get("risk") or finding.get("severity") or compliance.get("compliance_severity") or "LOW").lower()
            self.severity_counts[severity] += 1
            self.finding_group_count += 1
            self.occurrence_count += _finding_occurrence_count(finding)
            self.unique_sensitive_value_count += _finding_unique_value_count(finding)
        for category in compliance.get("data_categories") or []:
            self.category_counts[category] += max(1, len(file_findings))
        for control in compliance.get("relevant_controls") or []:
            self.remediation_counts[control] += 1
        self.top_files.add(
            {
                "file": file_obj.get("name") or file_obj.get("path") or "",
                "path": file_obj.get("path") or "",
                "score": compliance.get("compliance_score", 0),
                "severity": compliance.get("compliance_severity", "LOW"),
                "frameworks": compliance.get("matched_framework_names") or compliance.get("matched_frameworks") or [],
                "categories": compliance.get("data_categories") or [],
                "remediation": compliance.get("remediation", ""),
            }
        )

    def result(self) -> dict:
        return {
            "enabled": True,
            "selected_frameworks": [profile["id"] for profile in self.profiles],
            "selected_framework_names": [profile["name"] for profile in self.profiles],
            "affected_asset_count": len(self.affected_assets),
            "affected_file_count": self.affected_file_count,
            "finding_group_count": self.finding_group_count,
            "occurrence_count": self.occurrence_count,
            "unique_sensitive_value_count": self.unique_sensitive_value_count,
            "total_compliance_findings": self.finding_group_count,
            "files_with_compliance_matches": self.affected_file_count,
            "critical": self.severity_counts["critical"],
            "high": self.severity_counts["high"],
            "medium": self.severity_counts["medium"],
            "low": self.severity_counts["low"],
            "top_violated_categories": [{"category": item, "count": count} for item, count in self.category_counts.most_common(8)],
            "top_risky_files": self.top_files.result(),
            "remediation_priorities": [{"control": item, "count": count} for item, count in self.remediation_counts.most_common(8)],
        }


def build_compliance_summary(files: list[dict], profiles: list[dict]) -> dict:
    accumulator = ComplianceSummaryAccumulator(profiles)
    for file_obj in files:
        accumulator.add(file_obj)
    return accumulator.result()


class PciScopeSummaryAccumulator:
    """``build_pci_scope_summary``, one file at a time; the three lists are top-25 by score."""

    def __init__(self) -> None:
        self.category_counts = Counter()
        self.category_occurrence_counts = Counter()
        self.storage_counts = Counter()
        self.environment_counts = Counter()
        self.protection_counts = Counter()
        self.entity_role_counts = Counter()
        self.authorization_counts = Counter()
        self.scope_candidates = _TopN(25, key=lambda item: (item["score"], item["sad_findings"], item["chd_findings"]))
        self.sad_retention_candidates = _TopN(25, key=lambda item: item["score"])
        self.exception_queue = _TopN(25, key=lambda item: item["score"])

    def add(self, file_obj: dict) -> None:
        pci_findings = [
            finding
            for finding in file_obj.get("findings") or []
            if _is_pci_scope_finding(finding)
        ]
        if not pci_findings:
            return

        file_categories = sorted({str(finding.get("pci_category") or "").upper() for finding in pci_findings if finding.get("pci_category")})
        highest_score = max((_score_for_severity(str(finding.get("risk") or "LOW")) for finding in pci_findings), default=0)
        highest_severity = _highest_finding_severity(pci_findings)
        for finding in pci_findings:
            category = str(finding.get("pci_category") or "CONTEXT").upper()
            self.category_counts[category] += 1
            self.category_occurrence_counts[category] += _finding_occurrence_count(finding)
            self.storage_counts[str(finding.get("storage_state") or "unknown")] += 1
            self.environment_counts[str(finding.get("environment") or "unknown")] += 1
            self.protection_counts[str(finding.get("protection_state") or "unknown")] += 1
            self.entity_role_counts[str(finding.get("entity_role") or "unknown")] += 1
            self.authorization_counts[str(finding.get("authorization_state") or "unknown")] += 1
            if finding.get("exception_required"):
                self.exception_queue.add(_pci_scope_row(file_obj, [finding], highest_score, highest_severity, reason="SAD exception required"))

        has_chd = "CHD" in file_categories
        has_sad = "SAD" in file_categories
        if has_chd or has_sad:
            reason = "SAD retention candidate" if has_sad else "Cardholder data environment candidate"
            row = _pci_scope_row(file_obj, pci_findings, highest_score, highest_severity, reason=reason)
            self.scope_candidates.add(row)
            if has_sad:
                self.sad_retention_candidates.add(row)

    def result(self) -> dict:
        return {
            "enabled": True,
            "cde_candidate_count": self.scope_candidates.count,
            "sad_retention_candidate_count": self.sad_retention_candidates.count,
            "exception_required_count": self.exception_queue.count,
            "category_counts": dict(self.category_counts),
            "category_finding_group_counts": dict(self.category_counts),
            "category_occurrence_counts": dict(self.category_occurrence_counts),
            "storage_state_finding_group_counts": dict(self.storage_counts),
            "environment_finding_group_counts": dict(self.environment_counts),
            "protection_state_finding_group_counts": dict(self.protection_counts),
            "entity_role_finding_group_counts": dict(self.entity_role_counts),
            "authorization_state_finding_group_counts": dict(self.authorization_counts),
            "storage_state_counts": dict(self.storage_counts),
            "environment_counts": dict(self.environment_counts),
            "protection_state_counts": dict(self.protection_counts),
            "entity_role_counts": dict(self.entity_role_counts),
            "authorization_state_counts": dict(self.authorization_counts),
            "scope_candidates": self.scope_candidates.result(),
            "sad_retention_candidates": self.sad_retention_candidates.result(),
            "exception_queue": self.exception_queue.result(),
        }


def build_pci_scope_summary(files: list[dict]) -> dict:
    accumulator = PciScopeSummaryAccumulator()
    for file_obj in files:
        accumulator.add(file_obj)
    return accumulator.result()


class GdprReportAccumulator:
    """``build_gdpr_report``, one file at a time; every queue is the first 25 in arrival order."""

    def __init__(self) -> None:
        self.personal_data_by_category = Counter()
        self.special_category_data = Counter()
        self.data_subjects = Counter()
        self.owners = Counter()
        self.retention_violations = _FirstN(25)
        self.public_exposure = _FirstN(25)
        self.cross_border_locations = Counter()
        self.non_production_copies = _FirstN(25)
        self.lawful_basis_review_queue = _FirstN(25)
        self.dpia_candidates = _FirstN(25)
        self.minimization_candidates = _FirstN(25)
        self.data_subject_request_search = _FirstN(25)

    def add(self, file_obj: dict) -> None:
        gdpr_findings = [finding for finding in file_obj.get("findings") or [] if _is_gdpr_finding(finding)]
        if not gdpr_findings:
            return
        owner = str(file_obj.get("owner") or file_obj.get("department") or "unknown")
        exposed = bool((file_obj.get("permissions") or {}).get("wide_access") or (file_obj.get("permissions") or {}).get("public"))
        non_prod = _is_non_production(file_obj)
        for finding in gdpr_findings:
            category = str(finding.get("personal_data_type") or finding.get("category") or finding.get("type") or "personal_data")
            count = _finding_occurrence_count(finding)
            self.personal_data_by_category[category] += count
            self.owners[owner] += 1
            self.data_subjects[str(finding.get("data_subject_type") or "unknown")] += count
            if finding.get("special_category"):
                self.special_category_data[category] += count
            if finding.get("retention_expired"):
                self.retention_violations.add(_gdpr_queue_row(file_obj, finding, "Retention expired"))
            if exposed:
                self.public_exposure.add(_gdpr_queue_row(file_obj, finding, "Public or broad access"))
            if finding.get("cross_border_transfer") or finding.get("data_residency"):
                self.cross_border_locations[str(finding.get("data_residency") or "unknown")] += count
            if non_prod:
                self.non_production_copies.add(_gdpr_queue_row(file_obj, finding, "Non-production copy"))
            if not finding.get("lawful_basis"):
                self.lawful_basis_review_queue.add(_gdpr_queue_row(file_obj, finding, "Lawful basis missing"))
            if finding.get("DPIA_required") or finding.get("dpia_required") or finding.get("special_category"):
                self.dpia_candidates.add(_gdpr_queue_row(file_obj, finding, "DPIA review candidate"))
            if count >= 10 or finding.get("retention_expired") or not finding.get("processing_purpose"):
                self.minimization_candidates.add(_gdpr_queue_row(file_obj, finding, "Data minimization review"))
            self.data_subject_request_search.add(_gdpr_queue_row(file_obj, finding, "DSR searchable evidence"))

    def result(self) -> dict:
        return {
            "enabled": True,
            "personal_data_by_category": _counter_rows(self.personal_data_by_category, "category"),
            "special_category_data": _counter_rows(self.special_category_data, "category"),
            "data_subjects": _counter_rows(self.data_subjects, "data_subject_type"),
            "departments_business_owners": _counter_rows(self.owners, "owner"),
            "retention_violations": self.retention_violations.result(),
            "public_exposure": self.public_exposure.result(),
            "cross_border_locations": _counter_rows(self.cross_border_locations, "location"),
            "non_production_copies": self.non_production_copies.result(),
            "lawful_basis_review_queue": self.lawful_basis_review_queue.result(),
            "dpia_candidates": self.dpia_candidates.result(),
            "data_minimization_candidates": self.minimization_candidates.result(),
            "data_subject_request_search": self.data_subject_request_search.result(),
        }


def build_gdpr_report(files: list[dict]) -> dict:
    accumulator = GdprReportAccumulator()
    for file_obj in files:
        accumulator.add(file_obj)
    return accumulator.result()


class NistSp80060ReportAccumulator:
    """``build_nist_sp800_60_report``, one file at a time.

    Top assets are the ten highest by score; the four review queues are the first
    25 in arrival order, exactly as the list version sliced them.
    """

    def __init__(self) -> None:
        self.category_counts = Counter()
        self.rule_counts = Counter()
        self.source_kind_counts = Counter()
        self.handling_counts = Counter()
        self.severity_counts = Counter()
        self.cia_counts = Counter()
        self.confidence_counts = Counter()
        self.needs_review = _FirstN(25)
        self.public_exposure = _FirstN(25)
        self.broad_access = _FirstN(25)
        self.unprotected_restricted = _FirstN(25)
        self.top_assets = _TopN(10, key=lambda item: item["score"])
        self.status = nist_catalog_status()

    def add(self, file_obj: dict) -> None:
        nist_findings = [finding for finding in file_obj.get("findings") or [] if _is_nist_finding(finding)]
        if not nist_findings:
            return
        permissions = file_obj.get("permissions") or {}
        file_score = max((int(finding.get("final_risk_score") or finding.get("risk_score") or 0) for finding in nist_findings), default=0)
        self.top_assets.add({"file": file_obj.get("name") or file_obj.get("path") or "", "path": file_obj.get("path") or "", "score": file_score, "finding_count": len(nist_findings)})
        for finding in nist_findings:
            self.category_counts[str(finding.get("category_id") or finding.get("category") or "unknown")] += 1
            self.rule_counts[str(finding.get("rule_id") or finding.get("type") or "unknown")] += 1
            self.source_kind_counts[str(finding.get("source_kind") or "unknown")] += 1
            self.handling_counts[str(finding.get("handling_tier") or "UNKNOWN")] += 1
            self.severity_counts[str(finding.get("product_severity") or finding.get("risk") or "LOW")] += 1
            self.cia_counts[str(finding.get("overall_impact") or "UNKNOWN")] += 1
            self.confidence_counts[str(finding.get("confidence") or "unknown")] += 1
            if finding.get("needs_review"):
                self.needs_review.add(_nist_queue_row(file_obj, finding, "Review required"))
            if permissions.get("public"):
                self.public_exposure.add(_nist_queue_row(file_obj, finding, "Public exposure"))
            if permissions.get("wide_access"):
                self.broad_access.add(_nist_queue_row(file_obj, finding, "Broad access"))
            if finding.get("handling_tier") == "RESTRICTED" and str(finding.get("protection_state") or "UNKNOWN").upper() in {"UNKNOWN", "NONE", "UNPROTECTED"}:
                self.unprotected_restricted.add(_nist_queue_row(file_obj, finding, "Restricted handling without protection evidence"))

    def result(self) -> dict:
        status = self.status
        return {
            "enabled": True,
            "catalog": status,
            "total_nist_findings": sum(self.rule_counts.values()),
            "category_distribution": _counter_rows(self.category_counts, "category"),
            "rule_coverage": {"covered_rules": len(self.rule_counts), "catalog_rules": status.get("rule_count", 0), "top_rules": _counter_rows(self.rule_counts, "rule_id")},
            "source_kind_distribution": dict(self.source_kind_counts),
            "handling_tier_distribution": dict(self.handling_counts),
            "product_severity_distribution": dict(self.severity_counts),
            "overall_impact_distribution": dict(self.cia_counts),
            "confidence_distribution": dict(self.confidence_counts),
            "needs_review_findings": self.needs_review.result(),
            "publicly_exposed_findings": self.public_exposure.result(),
            "broad_access_findings": self.broad_access.result(),
            "unencrypted_restricted_findings": self.unprotected_restricted.result(),
            "top_risky_assets": self.top_assets.result(),
            "disclaimers": [
                "Handling tier is product-defined.",
                "Product severity is not a NIST-defined severity.",
                "CIA defaults may be provisional.",
                "Automated detection is not authoritative CUI determination.",
            ],
        }


def build_nist_sp800_60_report(files: list[dict]) -> dict:
    accumulator = NistSp80060ReportAccumulator()
    for file_obj in files:
        accumulator.add(file_obj)
    return accumulator.result()


def sanitize_pci_sensitive_report(report: dict) -> dict:
    files = report.get("files") if isinstance(report, dict) else None
    if isinstance(files, list):
        for file_obj in files:
            _sanitize_pci_file(file_obj)
    return report


def _sanitize_pci_file(file_obj: dict) -> None:
    for key in ("preview",):
        if key in file_obj:
            file_obj[key] = _sanitize_pci_value(file_obj[key])
    for finding in file_obj.get("findings") or []:
        for key in ("samples", "matched_keywords", "description", "severity_rationale", "remediation", "pci_treatment"):
            if key in finding:
                finding[key] = _sanitize_pci_value(finding[key])


def _sanitize_pci_value(value):
    if isinstance(value, dict):
        return {key: _sanitize_pci_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_pci_value(item) for item in value]
    if not isinstance(value, str) or not value:
        return value
    from classification.compliance.pci_keywords import CVV_KEYWORDS, PIN_KEYWORDS
    from classification.compliance.pci_validators import PAN_CANDIDATE_RE, is_valid_pan, mask_pan, mask_track_data, parse_track_data, redact_cvv_fields, redact_pin_fields

    def replace_candidate(match) -> str:
        raw = match.group(0)
        return mask_pan(raw) if is_valid_pan(raw) else raw

    redacted = redact_pin_fields(redact_cvv_fields(value, CVV_KEYWORDS), PIN_KEYWORDS)
    for track in parse_track_data(value):
        raw = str(track.get("raw") or "")
        if raw:
            redacted = redacted.replace(raw, mask_track_data(track))
    return PAN_CANDIDATE_RE.sub(replace_candidate, redacted)


def _pci_scope_row(file_obj: dict, findings: list[dict], score: int, severity: str, reason: str) -> dict:
    types = _dedupe([str(finding.get("type") or "") for finding in findings])
    categories = [str(finding.get("pci_category") or "").upper() for finding in findings]
    representative = sorted(findings, key=lambda item: _score_for_severity(str(item.get("risk") or "LOW")), reverse=True)[0] if findings else {}
    return {
        "file": file_obj.get("name") or file_obj.get("path") or "",
        "path": file_obj.get("path") or "",
        "score": score,
        "severity": severity,
        "reason": reason,
        "finding_types": types,
        "chd_findings": categories.count("CHD"),
        "sad_findings": categories.count("SAD"),
        "storage_state": representative.get("storage_state") or "unknown",
        "environment": representative.get("environment") or "unknown",
        "entity_role": representative.get("entity_role") or "unknown",
        "authorization_state": representative.get("authorization_state") or "unknown",
        "logical_boundary": representative.get("logical_boundary") or "text_proximity_window",
        "exception_required": any(bool(finding.get("exception_required")) for finding in findings),
        "exception_status": "required" if any(bool(finding.get("exception_required")) for finding in findings) else "not_required",
        "samples": _dedupe([sample for finding in findings for sample in finding.get("samples") or []])[:5],
    }


def _compliance_findings_for_file(file_obj: dict, profile_ids: set[str]) -> list[dict]:
    findings: list[dict] = []
    for finding in file_obj.get("findings") or []:
        framework = str(finding.get("framework") or "").lower()
        finding_type = str(finding.get("type") or "").lower()
        categories = set(FINDING_CATEGORY_MAP.get(finding_type, []))
        if finding.get("category"):
            categories.update(_categories_from_finding_category(str(finding.get("category") or "")))
        is_match = False
        if framework in profile_ids:
            is_match = True
        if "pci_dss" in profile_ids and (framework == "pci_dss" or finding_type.startswith("pci_") or any(item.startswith("pci_") for item in categories)):
            is_match = True
        if "gdpr" in profile_ids and (framework == "gdpr" or categories & {"pii", "personal_data", "government_ids", "health_data", "biometric_data", "genetic_data", "financial_records", "customer_data", "hr_documents", "online_identifiers", "location_data", "behavioral_data"}):
            is_match = True
        if "nist_sp800_60_enterprise" in profile_ids and (framework == "nist_sp800_60_enterprise" or finding_type.startswith("nist_") or any(item.startswith("nist_") for item in categories)):
            is_match = True
        if is_match:
            findings.append(finding)
    return findings


def _finding_occurrence_count(finding: dict) -> int:
    return max(int(finding.get("occurrence_count") or finding.get("count") or 1), 1)


def _finding_unique_value_count(finding: dict) -> int:
    if finding.get("unique_value_count") is not None:
        return max(int(finding.get("unique_value_count") or 0), 0)
    fingerprints = finding.get("secure_value_fingerprints") or finding.get("value_fingerprints") or []
    if isinstance(fingerprints, list) and fingerprints:
        return len(set(str(item) for item in fingerprints))
    samples = finding.get("samples") or []
    if isinstance(samples, list) and samples:
        return len(set(str(item) for item in samples))
    return 1


def _asset_key(file_obj: dict) -> str:
    for key in ("asset_id", "host_id", "source_id", "device_id", "path"):
        value = file_obj.get(key)
        if value:
            return str(value)
    return str(file_obj.get("name") or id(file_obj))


def _is_pci_scope_finding(finding: dict) -> bool:
    framework = str(finding.get("framework") or "").lower()
    finding_type = str(finding.get("type") or "").lower()
    pci_category = str(finding.get("pci_category") or "").upper()
    category = str(finding.get("category") or "").lower()
    if framework != "pci_dss" and not finding_type.startswith("pci_") and not category.startswith("pci_"):
        return False
    if pci_category not in {"CHD", "SAD"}:
        return False
    if finding.get("scope_candidate") is False:
        return False
    if str(finding.get("display_state") or "").lower() == "child_evidence":
        return False
    if str(finding.get("custom_rule_mode") or "").upper() == "CONTEXT_ONLY":
        return False
    return _confidence_score(finding) >= 60


def _confidence_score(finding: dict) -> int:
    value = finding.get("detection_confidence")
    if value is None:
        value = finding.get("confidence")
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    normalized = str(value or "").strip().lower()
    if normalized in {"high", "confirmed", "verified"}:
        return 90
    if normalized in {"medium", "review", "needs_review", "probable"}:
        return 70
    if normalized in {"low", "context", "context_only", "possible"}:
        return 40
    return 70


def _highest_finding_severity(findings: list[dict]) -> str:
    if not findings:
        return "LOW"
    return max((str(finding.get("risk") or "LOW").upper() for finding in findings), key=_score_for_severity)


def _score_for_severity(severity: str) -> int:
    return {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 55, "LOW": 20}.get(str(severity or "LOW").upper(), 20)


def _is_gdpr_finding(finding: dict) -> bool:
    framework = str(finding.get("framework") or "").lower()
    if framework == "gdpr":
        return True
    categories = set()
    finding_type = str(finding.get("type") or "").lower()
    categories.update(FINDING_CATEGORY_MAP.get(finding_type, []))
    if finding.get("category"):
        categories.update(_categories_from_finding_category(str(finding.get("category") or "")))
    return bool(categories & {"pii", "personal_data", "government_ids", "health_data", "biometric_data", "genetic_data", "financial_records", "customer_data", "hr_documents", "online_identifiers", "location_data", "behavioral_data"})


def _is_nist_finding(finding: dict) -> bool:
    framework = str(finding.get("framework") or "").lower()
    finding_type = str(finding.get("type") or "").lower()
    category_id = str(finding.get("category_id") or "").lower()
    return framework == "nist_sp800_60_enterprise" or finding_type.startswith("nist_") or category_id.startswith("nist_")


def _nist_queue_row(file_obj: dict, finding: dict, reason: str) -> dict:
    return {
        "file": file_obj.get("name") or file_obj.get("path") or "",
        "path": file_obj.get("path") or "",
        "rule_id": finding.get("rule_id") or "",
        "category_id": finding.get("category_id") or "",
        "handling_tier": finding.get("handling_tier") or "",
        "overall_impact": finding.get("overall_impact") or "",
        "severity": finding.get("product_severity") or finding.get("risk") or "LOW",
        "confidence": finding.get("confidence") or "",
        "score": finding.get("final_risk_score") or finding.get("risk_score") or 0,
        "reason": reason,
    }


def _is_non_production(file_obj: dict) -> bool:
    blob = " ".join(str(file_obj.get(key) or "").lower() for key in ("name", "path", "environment"))
    return any(marker in blob for marker in ("dev", "test", "qa", "uat", "sandbox", "staging", "nonprod", "non-prod"))


def _gdpr_queue_row(file_obj: dict, finding: dict, reason: str) -> dict:
    return {
        "file": file_obj.get("name") or file_obj.get("path") or "",
        "path": file_obj.get("path") or "",
        "finding_type": finding.get("type") or "",
        "category": finding.get("personal_data_type") or finding.get("category") or "",
        "risk": finding.get("risk") or "LOW",
        "count": _finding_occurrence_count(finding),
        "owner": file_obj.get("owner") or file_obj.get("department") or finding.get("data_owner") or "unknown",
        "reason": reason,
    }


def _counter_rows(counter: Counter, label_key: str) -> list[dict]:
    return [{label_key: item, "count": count} for item, count in counter.most_common(12)]


def _exposure_weight(file_obj: dict) -> int:
    permissions = file_obj.get("permissions") or {}
    weight = min(round(int(permissions.get("score") or 0) * 0.35), 12)
    if permissions.get("wide_access"):
        weight += 8
    if permissions.get("writable"):
        weight += 5
    return min(weight, 20)


def _data_weight(categories: list[str]) -> int:
    if not categories:
        return 8
    strongest = max((CRITICALITY_WEIGHTS.get(item, 0) for item in categories), default=8)
    breadth = min(max(len(categories) - 1, 0) * 3, 9)
    return min(strongest + breadth, 30)


def _finding_weight(file_obj: dict, matched_categories: list[str]) -> int:
    weights = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 9, "LOW": 4}
    score = 0
    relevant = set(matched_categories)
    for finding in file_obj.get("findings") or []:
        finding_categories = set(FINDING_CATEGORY_MAP.get(str(finding.get("type") or "").lower(), []))
        if finding.get("category"):
            finding_categories.update(_categories_from_finding_category(str(finding.get("category") or "")))
        if relevant and not (finding_categories & relevant):
            continue
        count = max(int(finding.get("count") or 1), 1)
        score += weights.get(str(finding.get("risk") or "LOW").upper(), 4)
        score += min(count - 1, 4)
    return min(score, 25)


def _location_weight(file_obj: dict) -> int:
    path = str(file_obj.get("path") or file_obj.get("name") or "").lower()
    extension = str(file_obj.get("extension") or "").lower()
    score = 0
    if any(marker in path for marker in ("downloads", "desktop", "temp", "export", "backup", "share")):
        score += 5
    if extension in {".csv", ".xlsx", ".xls", ".zip", ".pst", ".ost", ".sql", ".db", ".bak", ".json"}:
        score += 5
    if file_obj.get("is_hidden") or file_obj.get("is_system"):
        score += 2
    return min(score, 10)


def _protection_weight(file_obj: dict, categories: set[str]) -> int:
    if not categories:
        return 0
    if file_obj.get("protected") or "encrypted" in str(file_obj.get("content_status") or "").lower():
        return -5
    return 5


def _control_category(profile: dict, categories: list[str], exposure_match: bool) -> str:
    controls = profile.get("control_categories") or {}
    if exposure_match and controls.get("exposure"):
        return controls["exposure"]
    if "phi" in categories and controls.get("phi"):
        return controls["phi"]
    if ("pci_sensitive_authentication_data" in categories or "sensitive_authentication_data" in categories) and controls.get("sensitive_authentication_data"):
        return controls["sensitive_authentication_data"]
    if ("pci_cardholder_data" in categories or "cardholder_data" in categories) and controls.get("cardholder_data"):
        return controls["cardholder_data"]
    if ("credentials_secrets" in categories or "identity_access" in categories) and controls.get("access"):
        return controls["access"]
    if categories and controls:
        return next(iter(controls.values()))
    return "Compliance Exposure Risk"


def _finding_evidence(file_obj: dict) -> list[dict]:
    evidence: list[dict] = []
    for finding in file_obj.get("findings") or []:
        finding_type = str(finding.get("type") or finding.get("label") or "finding")
        categories = FINDING_CATEGORY_MAP.get(finding_type.lower(), [])
        if finding.get("category"):
            categories = _dedupe([*categories, *_categories_from_finding_category(str(finding.get("category") or ""))])
        evidence.append(
            {
                "type": finding_type,
                "label": finding.get("label") or finding_type.replace("_", " ").title(),
                "description": finding.get("description") or "",
                "risk": finding.get("risk") or "",
                "count": finding.get("count") or 1,
                "data_types": _category_labels(categories),
                "keywords": finding.get("matched_keywords") or finding.get("keywords") or finding.get("samples") or [],
                "samples": finding.get("samples") or [],
            }
        )
    return evidence


def _categories_from_finding_category(category: str) -> list[str]:
    normalized = category.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in CRITICALITY_WEIGHTS:
        return [normalized]
    category_map = {
        "personal_data": ["pii"],
        "identifier": ["pii"],
        "identity": ["pii", "government_ids"],
        "special_category": ["special_category_context"],
        "health": ["phi"],
        "medical": ["phi"],
        "financial": ["financial_records"],
        "employment": ["hr_documents", "pii"],
        "hr": ["hr_documents", "pii"],
        "security": ["security_operations"],
        "secret": ["credentials_secrets"],
        "pci": ["pci_scope_context"],
        "pci_payment": ["pci_scope_context"],
        "pci_scope_context": ["pci_scope_context"],
        "pci_payment_secret": ["pci_payment_secret"],
        "cardholder_data": ["pci_cardholder_data"],
        "pci_cardholder_data": ["pci_cardholder_data"],
        "sensitive_authentication_data": ["pci_sensitive_authentication_data"],
        "pci_sensitive_authentication_data": ["pci_sensitive_authentication_data"],
    }
    return category_map.get(normalized, [])


def _category_labels(categories: Iterable[str]) -> list[str]:
    labels = {
        "pii": "Personal data",
        "government_ids": "Government ID",
        "phi": "Health / PHI",
        "biometric_data": "Biometric data",
        "genetic_data": "Genetic data",
        "special_category_context": "Special-category data",
        "financial_records": "Financial records",
        "customer_data": "Customer data",
        "hr_documents": "HR / employee data",
        "online_identifiers": "Online identifier",
        "device_identifiers": "Device identifier",
        "location_data": "Location data",
        "behavioral_data": "Behavioral data",
        "credentials_secrets": "Credentials / secrets",
        "identity_access": "Identity access",
        "security_operations": "Security operations",
        "confidential_business": "Confidential business data",
        "source_code": "Source code",
        "legal_documents": "Legal documents",
        "contracts": "Contracts",
        "audit_accounting": "Audit evidence",
        "pci_scope_context": "PCI scope context",
        "pci_payment_secret": "PCI payment secret",
        "pci_cardholder_data": "PCI Cardholder Data (CHD)",
        "pci_sensitive_authentication_data": "PCI Sensitive Authentication Data (SAD)",
    }
    return [labels.get(str(item), str(item).replace("_", " ").title()) for item in categories if item]


def _criticality_label(categories: set[str], permissions: dict) -> str:
    if permissions.get("wide_access") and categories:
        return "Sensitive or regulated data with broad access"
    if {"pci_cardholder_data", "pci_sensitive_authentication_data", "pci_payment_secret", "phi", "credentials_secrets", "government_ids"} & categories:
        return "High-impact regulated or security-sensitive data"
    if categories:
        return "Compliance-relevant data detected"
    return "No compliance match"


def _severity(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))
