"""Normalized domain model + report mapper (Phase 1, DATA-001).

Pure data structures and one pure function (`normalize_scan_report`) that
decomposes the existing ``report_json`` blob into immutable scan runs,
append-only occurrences and a stable-identity finding aggregate. This is the
building block a dual-write persistence path will call; it is deliberately not
wired into any runtime path yet (see docs/phase1_kickoff_rfc.md).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field


def _sha(*parts: str, length: int = 24) -> str:
    raw = "|".join(str(p or "") for p in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:length]


def _asset_risk(record: dict) -> tuple[str, int]:
    """(risk_level, risk_score) from a file record. The file-level ``risk`` is a
    ``{level, score}`` dict; tolerate a bare string or missing value."""
    risk = record.get("risk")
    if isinstance(risk, dict):
        level = str(risk.get("level") or "").upper()
        try:
            score = int(risk.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        return level, score
    if isinstance(risk, str):
        return risk.strip().upper(), 0
    return "", 0


def _asset_top_frameworks(record: dict, limit: int = 3) -> str:
    """Comma-joined most-common compliance frameworks across a file's findings
    (from each finding's ``framework`` + ``frameworks`` list), for the inventory
    row's at-a-glance column."""
    counter: Counter = Counter()
    for finding in record.get("findings") or []:
        for framework in _finding_framework_values(finding):
            label = str(framework).strip()
            if label:
                counter[label] += 1
    return ",".join(name for name, _ in counter.most_common(limit))


def _framework_key(value: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
    aliases = {
        "pci": "pci_dss", "pcidss": "pci_dss", "pci_dss_4_0": "pci_dss",
        "nist": "nist_sp800_60_enterprise", "nist_sp_800_60": "nist_sp800_60_enterprise",
        "nist_sp800_60": "nist_sp800_60_enterprise",
    }
    return aliases.get(key, key)


def _asset_framework_keys(record: dict) -> str:
    """JSON array of exact, UI-compatible framework keys for server filtering."""
    keys: set[str] = set()
    for finding in record.get("findings") or []:
        values = _finding_framework_values(finding)
        keys.update(key for key in (_framework_key(value) for value in values) if key)
    if not keys:
        keys.add("standard_scan")
    return json.dumps(sorted(keys), ensure_ascii=False, separators=(",", ":"))


def _finding_label(finding: dict) -> str:
    raw = (
        finding.get("display_name") or finding.get("label") or finding.get("data_type")
        or finding.get("service") or finding.get("type") or finding.get("rule_id")
        or "Unnamed rule"
    )
    label = re.sub(r"\bType\s+\d+\b", "", str(raw).replace("_", " "), flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", label).strip() or "Unnamed rule"


def _asset_finding_types(record: dict) -> str:
    labels = sorted({_finding_label(finding) for finding in record.get("findings") or []}, key=str.lower)
    return json.dumps(labels, ensure_ascii=False, separators=(",", ":"))


def _finding_framework_values(finding: dict) -> list:
    """Return framework values without splitting a scalar string into letters."""
    values = [finding.get("framework")]
    additional = finding.get("frameworks")
    if isinstance(additional, (list, tuple, set)):
        values.extend(additional)
    elif additional:
        values.append(additional)
    return [value for value in values if value is not None and str(value).strip()]


def asset_identity(tenant_id: str, source: str, stable_object_id: str, path: str) -> str:
    """Stable asset id. Uses the connector's stable_object_id when available so a
    rename/move does not create a new asset; falls back to path until connectors
    provide stable ids (Phase 2)."""
    return _sha(tenant_id, source, stable_object_id or path)


def finding_identity(tenant_id: str, asset_id: str, rule: str, locator: str) -> str:
    """Stable finding id from tenant + asset + rule + normalized locator -
    never the sample value - so re-scans update the same finding."""
    return _sha(tenant_id, asset_id, rule, locator)


def _finding_lifecycle_status(finding: dict) -> str:
    """Real lifecycle status carried into the normalized Finding aggregate, so a
    RESOLVED/SUPPRESSED finding is not silently stored as OPEN (F1)."""
    raw = str(finding.get("status") or finding.get("review_status") or "").strip().upper()
    if raw == "UNREVIEWED":
        return "NEW"
    return raw or "OPEN"


# --- Immutable / append-only entities ---------------------------------------


@dataclass(frozen=True, slots=True)
class ScanRun:
    id: str
    tenant_id: str
    source: str
    mode: str
    policy_version: str
    started_at: str
    ended_at: str
    status: str
    total_files: int
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Asset:
    id: str
    tenant_id: str
    source: str
    stable_object_id: str
    path: str
    name: str
    # S-B queryable-inventory columns: denormalized from the file record so the
    # inventory list can filter / sort / search in the DB without loading blobs.
    extension: str = ""
    share: str = ""
    risk_level: str = ""
    risk_score: int = 0
    size: int = 0
    owner: str = ""
    modified_at: str = ""
    finding_count: int = 0
    top_frameworks: str = ""
    is_hidden: int = 0
    is_system: int = 0
    is_protected: int = 0
    search_text: str = ""
    # S-E on-demand read model. List responses omit detail_json; a single asset
    # detail endpoint reads it without loading/parsing the full report blob.
    finding_types: str = "[]"
    framework_keys: str = "[]"
    detail_json: str = "{}"
    # The scan a customer named and configured ("HR file share"), not the
    # collector protocol. Blank for assets written before scans carried a name.
    scan_label: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AssetVersion:
    asset_id: str
    version: str
    size: int
    mtime: str
    content_hash: str
    coverage: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FindingOccurrence:
    finding_id: str
    scan_id: str
    locator: str
    fingerprint: str
    occurrence_count: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Event:
    source: str
    object_id: str
    version: str
    idempotency_key: str
    state: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Checkpoint:
    source: str
    partition: str
    cursor: str
    generation: int
    updated_at: str

    def to_dict(self) -> dict:
        return asdict(self)


# --- Mutable-lifecycle / graph entities -------------------------------------


@dataclass(slots=True)
class Finding:
    id: str
    tenant_id: str
    asset_id: str
    rule: str
    severity: str
    category: str
    framework: str
    status: str
    first_seen: str
    last_seen: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Identity:
    id: str
    type: str
    domain: str
    tenant_id: str
    status: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AccessEdge:
    identity_id: str
    asset_id: str
    permission: str
    inherited: bool
    source: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class NormalizedScan:
    scan_run: ScanRun
    assets: list[Asset] = field(default_factory=list)
    asset_versions: list[AssetVersion] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    occurrences: list[FindingOccurrence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scan_run": self.scan_run.to_dict(),
            "assets": [a.to_dict() for a in self.assets],
            "asset_versions": [v.to_dict() for v in self.asset_versions],
            "findings": [f.to_dict() for f in self.findings],
            "occurrences": [o.to_dict() for o in self.occurrences],
        }


def normalize_scan_report(tenant_id: str, report: dict) -> NormalizedScan:
    """Decompose an existing scan-report dict into normalized entities.

    Pure and defensive: every field is read with a fallback so it tolerates the
    real report shape from any collector (local/SMB/WinRM) and older stored
    reports. Findings are de-duplicated by stable identity within the scan, so a
    file with N matches of the same rule yields one Finding and one Occurrence
    carrying the true occurrence_count.
    """
    report = report or {}
    scan_id = str(report.get("scan_id") or "")
    source = str(report.get("source") or "local")
    scan_label = str(report.get("scan_label") or "").strip()[:80]
    timestamp = str(report.get("timestamp") or "")
    summary = dict(report.get("summary") or {})

    scan_run = ScanRun(
        id=scan_id,
        tenant_id=tenant_id,
        source=source,
        mode=str(report.get("mode") or "full"),
        policy_version=str(report.get("policy_version") or report.get("version_signature") or ""),
        started_at=timestamp,
        ended_at=str(report.get("completed_at") or timestamp),
        status=str(report.get("status") or "completed"),
        total_files=int(summary.get("total_files") or 0),
        summary=summary,
    )

    assets: list[Asset] = []
    asset_versions: list[AssetVersion] = []
    findings: list[Finding] = []
    occurrences: list[FindingOccurrence] = []
    seen_assets: set[str] = set()
    seen_findings: dict[str, Finding] = {}

    for record in report.get("files") or []:
        path = str(record.get("path") or record.get("name") or "")
        name = str(record.get("name") or path.replace("\\", "/").rsplit("/", 1)[-1])
        stable_object_id = str(record.get("stable_object_id") or record.get("asset_id") or "")
        asset_id = asset_identity(tenant_id, source, stable_object_id, path)

        if asset_id not in seen_assets:
            seen_assets.add(asset_id)
            extension = str(record.get("extension") or "").lower()
            owner = str(record.get("owner") or "")
            risk_level, risk_score = _asset_risk(record)
            share = str(record.get("share") or "")
            finding_types = _asset_finding_types(record)
            framework_keys = _asset_framework_keys(record)
            search_text = " ".join(
                str(part) for part in (
                    path, name, owner, extension, source, share, risk_level, scan_label,
                    *json.loads(finding_types), *json.loads(framework_keys),
                ) if part
            ).lower()
            assets.append(
                Asset(
                    id=asset_id,
                    tenant_id=tenant_id,
                    source=source,
                    stable_object_id=stable_object_id or path,
                    path=path,
                    name=name,
                    extension=extension,
                    share=share,
                    risk_level=risk_level,
                    risk_score=risk_score,
                    size=int(record.get("size") or record.get("total_bytes") or 0),
                    owner=owner,
                    modified_at=str(record.get("modified_at") or record.get("mtime") or record.get("last_write_time") or ""),
                    finding_count=len(record.get("findings") or []),
                    top_frameworks=_asset_top_frameworks(record),
                    is_hidden=1 if record.get("is_hidden") else 0,
                    is_system=1 if record.get("is_system") else 0,
                    is_protected=1 if record.get("protected") else 0,
                    scan_label=scan_label,
                    search_text=search_text,
                    finding_types=finding_types,
                    framework_keys=framework_keys,
                    detail_json=json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                )
            )
            asset_versions.append(
                AssetVersion(
                    asset_id=asset_id,
                    version=str(record.get("content_hash") or record.get("file_hash") or record.get("sha256") or record.get("mtime") or ""),
                    size=int(record.get("size") or record.get("total_bytes") or 0),
                    mtime=str(record.get("modified_at") or record.get("mtime") or record.get("last_write_time") or ""),
                    content_hash=str(record.get("content_hash") or record.get("file_hash") or record.get("sha256") or ""),
                    coverage=str(record.get("scan_completeness") or "UNKNOWN"),
                )
            )

        for finding in record.get("findings") or []:
            rule = str(finding.get("type") or "sensitive_data")
            # Canonical classifiers already emit a stable public Finding ID.
            # Preserve it so normalized lifecycle/occurrence rows address the
            # same object as /api/findings/{finding_id}; legacy findings still
            # receive the deterministic tenant+asset+rule+path identity.
            finding_id = str(finding.get("finding_id") or finding_identity(tenant_id, asset_id, rule, path))
            if finding_id not in seen_findings:
                obj = Finding(
                    id=finding_id,
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    rule=rule,
                    severity=str(finding.get("risk") or "LOW").upper(),
                    category=str(finding.get("category") or ""),
                    framework=str(finding.get("framework") or ""),
                    status=_finding_lifecycle_status(finding),
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                seen_findings[finding_id] = obj
                findings.append(obj)

            fingerprints = finding.get("secure_value_fingerprints") or finding.get("secure_fingerprints") or []
            occurrences.append(
                FindingOccurrence(
                    finding_id=finding_id,
                    scan_id=scan_id,
                    locator=path,
                    fingerprint=str(fingerprints[0]) if fingerprints else "",
                    occurrence_count=int(finding.get("occurrence_count") or finding.get("count") or 1),
                )
            )

    return NormalizedScan(
        scan_run=scan_run,
        assets=assets,
        asset_versions=asset_versions,
        findings=findings,
        occurrences=occurrences,
    )
