"""The detector stage, as a function of its inputs and nothing else.

Classification is the scan's whole cost and it is pure Python, so the GIL
serializes it: the engine's ThreadPoolExecutor overlaps a file's I/O with
another file's analysis, but never two analyses. Six cores run one.

Lifting the detectors out of the engine and into a plain function - content and
metadata in, findings out, no engine state touched - is what lets them run in
another process. The engine keeps everything that is not pure: triage counters,
the finding cache, the scan diagnostics.

This module is imported by worker processes, so it stays cheap to import and
free of side effects.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from classification.compliance import classify_gdpr_content, classify_nist_content, classify_pci_content
from classification.compliance.nist_models import NIST_FRAMEWORK_ID
from classification.regex_classifier import classify_content
from discovery.finding_merge import merge_findings


def timed_detector(name: str, detector: Callable[[], list[dict]], timeout_seconds: float) -> tuple[list[dict], dict]:
    started = time.perf_counter()
    try:
        findings = detector()
        error = ""
    except Exception as exc:
        findings = []
        error = str(exc)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    timed_out = bool(timeout_seconds and elapsed_ms > timeout_seconds * 1000)
    row = {
        "name": name,
        "elapsed_ms": elapsed_ms,
        "finding_groups": len(findings),
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "degraded_mode": timed_out or bool(error),
    }
    if error:
        row["error"] = error
    return findings, row


def run_detector_stage(payload: dict[str, Any]) -> dict[str, Any]:
    """Every detector for one file, in the order the engine ran them.

    The payload is everything the detectors read: the content, the record they
    annotate, which frameworks are on, and the tenant's custom keyword groups
    (which the engine resolves once per scan). Nothing here reaches back into
    the engine, which is what makes it safe to run anywhere.
    """
    content: str = payload.get("content") or ""
    record: dict = payload.get("record") or {}
    framework_ids: set[str] = set(payload.get("framework_ids") or ())
    compliance_enabled: bool = bool(payload.get("compliance_enabled"))
    timeout_seconds: float = float(payload.get("timeout_seconds") or 0)
    custom_keywords: dict[str, list[dict]] = payload.get("custom_keywords") or {}

    detector_rows: list[dict] = []
    findings: list[dict] = []

    tenant_id = str(record.get("tenant_id") or record.get("tenant") or "default")
    generic_findings, row = timed_detector(
        "generic", lambda: classify_content(content, tenant_id=tenant_id), timeout_seconds,
    )
    detector_rows.append(row)
    findings.extend(generic_findings)

    if compliance_enabled:
        existing = {finding.get("type") for finding in findings}
        if "gdpr" in framework_ids:
            groups = custom_keywords.get("gdpr") or []
            gdpr_findings, row = timed_detector("gdpr", lambda: classify_gdpr_content(content, record, groups), timeout_seconds)
            detector_rows.append(row)
            for finding in gdpr_findings:
                if finding.get("type") not in existing:
                    findings.append(finding)
                    existing.add(finding.get("type"))
        if "pci_dss" in framework_ids:
            groups = custom_keywords.get("pci_dss") or []
            pci_findings, row = timed_detector("pci_dss", lambda: classify_pci_content(content, record, groups), timeout_seconds)
            detector_rows.append(row)
            for finding in pci_findings:
                dedupe_key = (
                    finding.get("type"),
                    finding.get("protection_state"),
                    tuple(finding.get("secure_fingerprints") or []),
                )
                existing_keys = {
                    (
                        item.get("type"),
                        item.get("protection_state"),
                        tuple(item.get("secure_fingerprints") or []),
                    )
                    for item in findings
                }
                if dedupe_key not in existing_keys:
                    findings.append(finding)
        if NIST_FRAMEWORK_ID in framework_ids:
            groups = custom_keywords.get(NIST_FRAMEWORK_ID) or []
            nist_findings, row = timed_detector(NIST_FRAMEWORK_ID, lambda: classify_nist_content(content, record, groups), timeout_seconds)
            detector_rows.append(row)
            existing_keys = {
                (
                    item.get("framework"),
                    item.get("rule_id") or item.get("type"),
                    item.get("logical_boundary_id") or item.get("location_id"),
                )
                for item in findings
            }
            for finding in nist_findings:
                dedupe_key = (
                    finding.get("framework"),
                    finding.get("rule_id") or finding.get("type"),
                    finding.get("logical_boundary_id") or finding.get("location_id"),
                )
                if dedupe_key not in existing_keys:
                    findings.append(finding)
                    existing_keys.add(dedupe_key)

    # B7: three detectors reading one file found one card three times. What they
    # found is merged here, where every detector's output is in one list and
    # nothing downstream has looked at it yet.
    return {"findings": merge_findings(findings), "detector_rows": detector_rows, "record": record}


def warm_up() -> bool:
    """Build the catalogs a worker will need, before it is given real work.

    A cold process pays about a second on its first file: importing the
    detectors, then indexing the 46,000-term GDPR keyword catalog (0.65 CPU-s
    since P3) and reading and validating the NIST catalog. Paid here,
    while the collector is still walking the tree, it costs the scan nothing.
    """
    sample = "warm up: name, email a@b.test, card 4111 1111 1111 1111, salary 1 AZN"
    record = {"name": "warmup.txt", "path": "warmup.txt", "extension": ".txt", "tenant_id": "warmup"}
    run_detector_stage({
        "content": sample,
        "record": record,
        "framework_ids": {"gdpr", "pci_dss", NIST_FRAMEWORK_ID},
        "compliance_enabled": True,
        "timeout_seconds": 0,
        "custom_keywords": {},
    })
    return True
