"""Deterministic intent parsing and rendering for scan file metadata queries."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping

from backend.copilot.language import normalize_message
from backend.copilot.severity import severity_from_text


FILE_QUERY_LIST = "list"
FILE_QUERY_COUNT = "count"
FILE_QUERY_EXISTENCE = "existence"
FILE_QUERY_EXTENSIONS = "extensions"
FILE_QUERY_EXPLANATION = "explanation"

_KNOWN_EXTENSIONS = {
    "7z", "adoc", "aws", "bak", "bat", "bin", "bmp", "bz2", "c", "cab",
    "cer", "cfg", "conf", "config", "cpp", "crt", "cs", "css", "csv", "dat",
    "db", "doc", "docm", "docx", "dockerfile", "dump", "dwg", "dxf", "eml",
    "env", "exe", "gif", "go", "gpg", "gz", "h", "hcl", "heic", "hpp",
    "htm", "html", "ics", "ini", "iso", "jar", "java", "jpeg", "jpg", "js",
    "json", "jsx", "key", "kdbx", "lnk", "log", "md", "mdb", "mkv", "mov",
    "mp3", "mp4", "msg", "netrc", "npmrc", "odt", "ods", "odp", "one", "ost",
    "ovpn", "p12", "pcf", "pdf", "pem", "pfx", "pgp", "php", "png", "ppt",
    "pptm", "pptx", "properties", "ps1", "psd1", "psm1", "pst", "py", "pypirc",
    "rar", "rdp", "reg", "rst", "rtf", "scss", "sh", "sql", "sqlite",
    "sqlite3", "svg", "sys", "tar", "temp", "tf", "tfstate", "tfvars", "tgz",
    "tif", "tiff", "tmp", "toml", "ts", "tsv", "tsx", "txt", "vhd", "vhdx",
    "vsd", "vsdx", "wav", "xls", "xlsb", "xlsm", "xlsx", "xml", "xz", "yaml",
    "yara", "yml", "zip",
}

_NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}

_FILE_CONTEXT_RE = re.compile(r"\b(?:files?|extensions?|file\s+types?)\b", re.IGNORECASE)
_DOTTED_EXTENSION_RE = re.compile(r"(?<![\w.])\.([a-z0-9][a-z0-9_+-]{0,15})\b", re.IGNORECASE)
_REPORT_RE = re.compile(r"\b(?:report|export|composer|hesabat)\b", re.IGNORECASE)
# Extensions that double as an output/report *format*. A bare mention of one of
# these ("give me a pdf", "as a pdf report", "pdf about medium alerts") means
# the output format, NOT a file-extension filter. It is only an extension when
# written as a dotted extension (".pdf") or immediately followed by a
# file-context noun ("pdf files", "pdf extension").
_FORMAT_AMBIGUOUS_EXTENSIONS = {"pdf"}
_FORMAT_EXT_AS_FILE_RE = re.compile(
    r"\b(?:pdf)\s+(?:files?|extensions?|file\s+types?|types?)\b", re.IGNORECASE
)
_REPORT_NEGATION_RE = re.compile(
    r"\b(?:do\s*not|dont|don't|not|instead\s+of)\b.{0,35}\b(?:report|export|composer)\b",
    re.IGNORECASE,
)
_CORRECTION_CUES = (
    "made them up", "made it up", "invented", "do not exist", "dont exist",
    "don't exist", "does not exist", "different extension", "wrong extension",
    "i wanted", "i asked for", "not what i asked", "not a report", "not report",
)
_EXPLANATION_MESSAGES = {"why", "why?", "explain", "explain?", "how", "how?"}


@dataclass(frozen=True)
class FileQueryIntent:
    action: str
    limit: int = 5
    extension: str | None = None
    severity: str | None = None
    sort: str = "risk_desc"
    scan_scope: str = "latest"
    correction: bool = False
    explain_previous: bool = False

    def state_payload(self) -> dict[str, Any]:
        return asdict(self)


def _previous_query(session_state: Mapping[str, Any] | None) -> FileQueryIntent | None:
    payload = (session_state or {}).get("last_file_query")
    if not isinstance(payload, Mapping):
        return None
    action = str(payload.get("action") or "")
    if action not in {FILE_QUERY_LIST, FILE_QUERY_COUNT, FILE_QUERY_EXISTENCE, FILE_QUERY_EXTENSIONS}:
        return None
    try:
        limit = max(1, min(int(payload.get("limit") or 5), 25))
    except (TypeError, ValueError):
        limit = 5
    extension = normalize_extension(payload.get("extension"))
    severity = str(payload.get("severity") or "").upper() or None
    return FileQueryIntent(action=action, limit=limit, extension=extension, severity=severity)


def normalize_extension(value: Any) -> str | None:
    token = str(value or "").strip().lower().lstrip(".")
    if not token or not re.fullmatch(r"[a-z0-9][a-z0-9_+-]{0,15}", token):
        return None
    return f".{token}"


def _extract_extension(message: str, normalized: str, has_file_context: bool, inherited: bool) -> str | None:
    dotted = _DOTTED_EXTENSION_RE.search(str(message or ""))
    if dotted:
        return normalize_extension(dotted.group(1))
    if not (has_file_context or inherited):
        return None
    raw = f"{normalized} {str(message or '').lower()}"
    tokens = re.findall(r"\b[a-z0-9][a-z0-9_+-]{0,15}\b", normalized)
    for token in tokens:
        if token not in _KNOWN_EXTENSIONS:
            continue
        # A format-ambiguous token ("pdf") only filters by extension when it is
        # written as a file noun ("pdf files"); otherwise it is a report format
        # and must fall through so the report route can own it.
        if token in _FORMAT_AMBIGUOUS_EXTENSIONS and not _FORMAT_EXT_AS_FILE_RE.search(raw):
            continue
        return normalize_extension(token)
    return None


def _extract_limit(normalized: str, previous: FileQueryIntent | None) -> int:
    numeric = re.search(r"\b(?:top\s+|show\s+|give(?:\s+me)?\s+|list\s+)?(\d{1,2})\b", normalized)
    if numeric:
        return max(1, min(int(numeric.group(1)), 25))
    for word, value in _NUMBER_WORDS.items():
        if re.search(rf"\b{word}\b", normalized):
            return value
    return previous.limit if previous else 5


def parse_file_query(
    message: str,
    session_state: Mapping[str, Any] | None = None,
) -> FileQueryIntent | None:
    """Parse a factual file metadata request without calling a provider."""
    normalized = normalize_message(message)
    raw = str(message or "").lower()
    if not normalized:
        return None

    previous = _previous_query(session_state)
    compact = normalized.strip()
    if previous and compact in _EXPLANATION_MESSAGES:
        return replace(previous, action=FILE_QUERY_EXPLANATION, explain_previous=True)

    has_file_context = bool(_FILE_CONTEXT_RE.search(raw))
    correction = any(cue in f"{normalized} {raw}" for cue in _CORRECTION_CUES)
    inherited = previous is not None and (
        correction
        or "what about" in normalized
        or "only" in normalized
        or bool(re.fullmatch(r"(?:now\s+)?top\s+\d{1,2}", normalized))
    )
    extension = _extract_extension(message, normalized, has_file_context, inherited)

    explicit_report = bool(_REPORT_RE.search(raw))
    # A bare "pdf" used as an output format ("as pdf", "pdf about ...") — not a
    # dotted extension and not a file noun ("pdf files") — is a report request.
    format_request = bool(
        re.search(r"\bpdf\b", raw)
        and not _FORMAT_EXT_AS_FILE_RE.search(raw)
        and not _DOTTED_EXTENSION_RE.search(str(message or ""))
    )
    report_negated = bool(_REPORT_NEGATION_RE.search(raw)) or correction
    # Report/export wording is an output-format request and always defers to the
    # report route (which now preserves extension and top-N scope itself) —
    # unless the user is explicitly correcting away from a report.
    if (explicit_report or format_request) and not report_negated:
        return None

    extension_summary = bool(re.search(
        r"\b(?:which|what|list|show)\s+(?:file\s+)?extensions?\b|\bfile\s+types?\s+(?:exist|available)",
        normalized,
    ))
    has_query_cue = bool(re.search(
        r"\b(?:top|give|show|list|find|highest|riskiest|most|what\s+are|which\s+are|"
        r"how\s+many|count|any|exist|exists|available)\b",
        normalized,
    ))
    if not extension_summary and not (has_file_context and has_query_cue) and not (inherited and extension):
        return None

    if extension_summary:
        action = FILE_QUERY_EXTENSIONS
    elif re.search(r"\b(?:how\s+many|count|number\s+of)\b", normalized):
        action = FILE_QUERY_COUNT
    elif re.search(r"\b(?:are|is|do|does)\b.{0,35}\b(?:any|exist|exists)\b|\bany\b.{0,35}\b(?:exist|exists|available)\b", normalized):
        action = FILE_QUERY_EXISTENCE
    else:
        action = FILE_QUERY_LIST

    explicit_new_action = bool(re.search(
        r"\b(?:top\s+\d+|give(?:\s+me)?|show|list|how\s+many|count|are\s+there\s+any|which\s+extensions?)\b",
        normalized,
    ))
    if correction and previous and not explicit_new_action:
        action = previous.action

    if inherited and extension is None and previous:
        extension = previous.extension
    severity = severity_from_text(message)
    if severity:
        severity = severity.upper()
    elif inherited and previous:
        severity = previous.severity
    return FileQueryIntent(
        action=action,
        limit=_extract_limit(normalized, previous),
        extension=extension,
        severity=severity,
        correction=correction,
    )


def _finding_types(item: Mapping[str, Any]) -> str:
    types = []
    for finding in item.get("findings") or []:
        if isinstance(finding, Mapping) and finding.get("type"):
            types.append(str(finding["type"]))
    return ", ".join(dict.fromkeys(types)) or "No classified finding signal"


def _recommended_action(item: Mapping[str, Any]) -> str:
    remediation = item.get("remediation") if isinstance(item.get("remediation"), Mapping) else {}
    actions = remediation.get("actions") if isinstance(remediation, Mapping) else []
    recommendations = item.get("dlp_recommendations") or []
    if actions:
        return str(actions[0])
    if recommendations:
        return str(recommendations[0])
    return "Review access, ownership, and retention with the data owner."


def render_file_query(intent: FileQueryIntent, payload: Mapping[str, Any]) -> str:
    extension = intent.extension or "all extensions"
    count = int(payload.get("count") or 0)
    scan_id = str(payload.get("scan_id") or "unknown")
    if not payload.get("evidence_available", True):
        return "File evidence is unavailable because no authorized scan report is available."

    if intent.action == FILE_QUERY_EXTENSIONS:
        counts = payload.get("extension_counts") if isinstance(payload.get("extension_counts"), Mapping) else {}
        if not counts:
            return f"I found 0 file extensions in the latest scan.\nEvidence: scan={scan_id}, source=latest scan report"
        rows = [f"- {key}: {value}" for key, value in counts.items()]
        return "Extensions in the latest scan:\n" + "\n".join(rows) + f"\nEvidence: scan={scan_id}, source=latest scan report"

    if intent.action == FILE_QUERY_COUNT:
        return f"I found {count} {extension} files in the latest scan.\nEvidence: scan={scan_id}, source=latest scan report"
    if intent.action == FILE_QUERY_EXISTENCE:
        if count == 0:
            return f"I found 0 {extension} files in the latest scan.\nEvidence: scan={scan_id}, source=latest scan report"
        return f"Yes. I found {count} {extension} files in the latest scan.\nEvidence: scan={scan_id}, source=latest scan report"

    prefix = "I re-checked the authorized scan evidence. " if intent.correction else ""
    if count == 0:
        explanation = "The extension filter was applied to every file row in the latest scan. " if intent.explain_previous else ""
        return (
            f"{prefix}{explanation}I found 0 {extension} files in the latest scan.\n"
            f"Evidence: scan={scan_id}, source=latest scan report"
        )

    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    header = f"{prefix}I found {count} matching {extension} files in the latest scan. Showing {len(items)}."
    lines = [header]
    for index, item in enumerate(items, 1):
        if not isinstance(item, Mapping):
            continue
        lines.extend([
            f"{index}. {item.get('name') or 'unknown'}",
            f"   Extension: {item.get('extension') or 'unknown'} | Severity: {item.get('severity') or 'UNKNOWN'} | Risk score: {item.get('risk_score') if item.get('risk_score') is not None else 'unknown'}",
            f"   Origin: {item.get('source') or 'unknown'} | Signals: {_finding_types(item)}",
            f"   Recommended action: {_recommended_action(item)} | Scan: {item.get('scan_id') or scan_id}",
        ])
    lines.append(f"Evidence: scan={scan_id}, source=latest scan report")
    return "\n".join(lines)
