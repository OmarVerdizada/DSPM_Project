from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from classification.regex_classifier import classify_content
from collectors.file_scanner import normalize_records, scan_directory
from collectors.smb_scanner import SMBConfig, SMBScanner
from permissions.acl_analyzer import analyze_acl
from risk.risk_engine import RiskAssessment, calculate_risk
from scripts.logger import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class ScanConfig:
    server: str = ""
    username: str = ""
    password: str = ""
    domain: str = "WORKGROUP"
    local_path: str = "enterprise_test_data"
    max_depth: int = 4
    use_sample_when_empty: bool = True
    asset_overrides: list[dict] = field(default_factory=list)
    allowed_extensions: list[str] = field(default_factory=list)
    extension_filter_enabled: bool = False
    include_hidden: bool = False
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False


@dataclass(slots=True)
class ScanSummary:
    total_files: int
    critical: int
    high: int
    medium: int
    low: int
    sensitive_files: int
    hidden_files: int = 0

    def to_dict(self) -> dict:
        return {
            "total_files": self.total_files,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "sensitive_files": self.sensitive_files,
            "hidden_files": self.hidden_files,
        }


@dataclass(slots=True)
class ScanReport:
    timestamp: str
    source: str
    summary: ScanSummary
    files: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "summary": self.summary.to_dict(),
            "files": self.files,
        }


class DSPMDiscoveryEngine:
    def __init__(self, config: ScanConfig):
        self.config = config

    def test_connection(self) -> dict:
        if not self.config.server:
            return {
                "connected": True,
                "server": "local-sample",
                "domain": self.config.domain,
                "shares": [],
                "message": "Using local sample data because no SMB server was provided",
            }

        scanner = SMBScanner(
            SMBConfig(
                server=self.config.server,
                username=self.config.username,
                password=self.config.password,
                domain=self.config.domain,
                max_depth=self.config.max_depth,
                allowed_extensions=self.config.allowed_extensions,
                extension_filter_enabled=self.config.extension_filter_enabled,
                include_hidden=self.config.include_hidden,
                include_system=self.config.include_system,
                hidden_filter_enabled=self.config.hidden_filter_enabled,
                system_filter_enabled=self.config.system_filter_enabled,
            )
        )
        return scanner.test_connection()

    def run(self) -> ScanReport:
        records = self._collect_records()
        analyzed_files = [self._analyze_record(record) for record in normalize_records(records)]
        summary = self._build_summary(analyzed_files)

        return ScanReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source="smb" if self.config.server else "local",
            summary=summary,
            files=analyzed_files,
        )

    def _collect_records(self) -> list[dict]:
        if self.config.server:
            scanner = SMBScanner(
                SMBConfig(
                    server=self.config.server,
                    username=self.config.username,
                    password=self.config.password,
                    domain=self.config.domain,
                    max_depth=self.config.max_depth,
                    allowed_extensions=self.config.allowed_extensions,
                    extension_filter_enabled=self.config.extension_filter_enabled,
                    include_hidden=self.config.include_hidden,
                    include_system=self.config.include_system,
                    hidden_filter_enabled=self.config.hidden_filter_enabled,
                    system_filter_enabled=self.config.system_filter_enabled,
                )
            )
            return scanner.scan()

        if self.config.use_sample_when_empty:
            return scan_directory(
                self.config.local_path,
                allowed_extensions=self.config.allowed_extensions,
                extension_filter_enabled=self.config.extension_filter_enabled,
                include_hidden=self.config.include_hidden,
                include_system=self.config.include_system,
                hidden_filter_enabled=self.config.hidden_filter_enabled,
                system_filter_enabled=self.config.system_filter_enabled,
            )

        return []

    def _analyze_record(self, record: dict) -> dict:
        record["asset_overrides"] = self.config.asset_overrides
        findings = classify_content(record.get("content", ""))
        record["finding_signals"] = [
            f"{finding.get('type', '')} {finding.get('description', '')}".strip()
            for finding in findings
        ]
        acl_assessment = analyze_acl(record.get("acl") or {}, record)
        risk: RiskAssessment = calculate_risk(record, findings, acl_assessment)

        public_record = dict(record)
        content = public_record.pop("content", "")
        public_record.pop("asset_overrides", None)
        public_record.pop("finding_signals", None)
        public_record["preview"] = _safe_preview(content)
        public_record["findings"] = findings
        public_record["permissions"] = acl_assessment
        public_record["risk"] = risk.to_dict()
        return public_record

    @staticmethod
    def _build_summary(files: list[dict]) -> ScanSummary:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        sensitive_files = 0
        hidden_files = 0

        for item in files:
            level = item.get("risk", {}).get("level", "LOW")
            counts[level] = counts.get(level, 0) + 1
            if item.get("findings"):
                sensitive_files += 1
            if item.get("is_hidden"):
                hidden_files += 1

        return ScanSummary(
            total_files=len(files),
            critical=counts["CRITICAL"],
            high=counts["HIGH"],
            medium=counts["MEDIUM"],
            low=counts["LOW"],
            sensitive_files=sensitive_files,
            hidden_files=hidden_files,
        )


def _safe_preview(content: str, max_lines: int = 8, max_chars: int = 1800) -> dict:
    if not content:
        return {"available": False, "lines": [], "truncated": False}

    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    selected = lines[:max_lines]
    text = "\n".join(selected)
    truncated = len(lines) > max_lines or len(text) > max_chars

    if len(text) > max_chars:
        text = text[:max_chars]
        selected = text.split("\n")

    return {
        "available": True,
        "lines": selected,
        "truncated": truncated,
    }
