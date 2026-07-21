from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

CommandName = Literal[
    "help",
    "status",
    "capabilities",
    "latest-scan",
    "summary",
    "critical",
    "high",
    "medium",
    "low",
    "remediation",
    "report",
]


@dataclass(frozen=True)
class Command:
    name: CommandName
    aliases: tuple[str, ...]
    task_type: str
    requires_evidence: bool


COMMAND_REGISTRY: dict[str, Command] = {
    "/help": Command(
        "help",
        ("/help", "/commands", "/h"),
        "capability_help",
        False,
    ),
    "/status": Command(
        "status",
        ("/status", "/working", "/active"),
        "status_check",
        False,
    ),
    "/capabilities": Command(
        "capabilities",
        ("/capabilities", "/skills", "/what"),
        "capability_help",
        False,
    ),
    "/latest-scan": Command(
        "latest-scan",
        ("/latest-scan", "/scan", "/lastscan"),
        "scan_summary",
        True,
    ),
    "/summary": Command(
        "summary",
        ("/summary", "/dash", "/dashboard"),
        "scan_summary",
        True,
    ),
    "/critical": Command(
        "critical",
        ("/critical", "/alerts", "/critical-findings"),
        "critical_findings_list",
        True,
    ),
    "/high": Command(
        "high",
        ("/high", "/high-findings"),
        "high_findings_list",
        True,
    ),
    "/medium": Command(
        "medium",
        ("/medium", "/medium-findings"),
        "medium_findings_list",
        True,
    ),
    "/low": Command(
        "low",
        ("/low", "/low-findings"),
        "low_findings_list",
        True,
    ),
    "/remediation": Command(
        "remediation",
        ("/remediation", "/fix", "/recommend"),
        "remediation_advice",
        True,
    ),
    "/report": Command(
        "report",
        ("/report", "/export", "/pdf"),
        "artifact_export",
        True,
    ),
}


def parse_command(message: str) -> tuple[Command | None, str]:
    """Parse a command from message. Returns (command, remaining_message)."""
    stripped = message.strip()
    if not stripped.startswith("/"):
        return None, message
    for cmd, command in COMMAND_REGISTRY.items():
        if stripped == cmd or stripped.startswith(cmd + " "):
            remaining = stripped[len(cmd) :].strip()
            return command, remaining
    return None, message


def is_command(message: str) -> bool:
    """Check if message is a command."""
    return message.strip().startswith("/")