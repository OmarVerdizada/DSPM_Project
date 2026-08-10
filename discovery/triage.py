"""Track P-C: cheap-signal triage for the detector pipeline.

Before the expensive detector catalog runs (58 generic regex rules + ML/NER, plus
the compliance catalogs), a cheap pass computes signals from content already in
hand and decides how much detection a record warrants.

Recall contract
---------------
The scanner already reads content ONLY for text/document extensions and never
scans binary-extension content (``read_text_preview_and_sha256`` returns ``""``
for anything else). P-C extends that SAME posture to content that is unambiguously
binary - compressed, encrypted, or binary data mislabeled with a text extension.
Such content cannot contain the plaintext structures the catalog matches, so
skipping it is consistent with the scanner's existing binary policy and loses no
plaintext finding.

The skip signal is a **NUL byte** in the sampled head - the same heuristic git
uses to classify a blob as binary. This is deliberately chosen over any
"replacement-char / low-text-ratio" heuristic, which would be a RECALL BUG:
content is read as UTF-8-with-replace, so legitimate **non-UTF-8 text** (a
windows-1252 / ISO-8859 file of Azerbaijani, Turkish, German, French, ...) turns
into many U+FFFD and would be wrongly skipped. Real text - in any encoding -
does not contain NUL bytes; only true binary does. ``text_ratio`` is still
computed, but ONLY as a score/diagnostic signal, never as a skip gate.

``DSPM_TRIAGE_ENABLED=0`` turns triage off entirely; ``DSPM_TRIAGE_BINARY_SKIP=0``
keeps the score/observability but never skips.

Because a skip changes WHICH detectors run without changing the content, the
active triage policy is folded into the detector version signature
(:func:`triage_signature`) so cached findings can never be reused across a policy
change.
"""

from __future__ import annotations

import os

TRIAGE_VERSION = "triage-v1"

# Routes.
ROUTE_FULL = "full"  # run the whole detector catalog (default for any real text)
ROUTE_SKIP_NON_TEXT = "skip_non_text"  # content did not decode as text -> no plaintext findings
ROUTE_SAMPLE = "sample_head_tail"  # very large text: scan head+tail only (opt-in, marks PARTIAL)

# How much of the content head to sample for the text-decode ratio. Bounds the
# triage cost to O(sample) regardless of file size; a binary body reliably shows
# up in its head (same rationale as the classic 8 KB binary sniff).
_HEAD_SAMPLE_CHARS = 65_536

# Filename tokens that indicate likely-sensitive content, used ONLY to raise the
# triage score (ranking/observability). They never cause a skip.
_SENSITIVE_NAME_TOKENS = (
    "secret", "password", "passwd", "credential", "token", "apikey", "api_key",
    "private", "key", "ssn", "salary", "payroll", "invoice", "passport", "kvkk",
    "gdpr", "pci", "confidential", ".env", "id_rsa", "backup", "dump",
)


def _enabled() -> bool:
    return os.getenv("DSPM_TRIAGE_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _binary_skip_enabled() -> bool:
    return os.getenv("DSPM_TRIAGE_BINARY_SKIP", "1").strip().lower() not in {"0", "false", "no", "off"}


def order_enabled() -> bool:
    """Whether to analyze higher-score records first. Recall-safe: it never
    changes a completed scan's findings, only which findings survive if the scan
    hits its wall-clock deadline. ``DSPM_TRIAGE_ORDER=0`` restores collector order."""
    if not _enabled():
        return False
    return os.getenv("DSPM_TRIAGE_ORDER", "1").strip().lower() not in {"0", "false", "no", "off"}


def _sample_chars() -> int:
    """Head+tail sampling budget for very large text, in characters. 0 (default)
    disables sampling entirely, so ordinary scans are byte-for-byte unchanged.
    When set, text longer than this is scanned as head+tail slices totalling this
    many chars, and the result is marked PARTIAL/truncated (a bounded-recall,
    opt-in tradeoff for very large files)."""
    try:
        return max(0, int(os.getenv("DSPM_TRIAGE_SAMPLE_BYTES", "0")))
    except (TypeError, ValueError):
        return 0


def is_binary(sample: str) -> bool:
    """True if the sampled head is unambiguously binary: it contains a NUL byte.
    Text - in ANY encoding, UTF-8 or not - never contains NUL; only compressed,
    encrypted, or binary data does. (Same rule git uses.)"""
    return "\x00" in sample


def text_ratio(sample: str) -> float:
    """Fraction of ``sample`` that is genuine text. The Unicode replacement char
    (U+FFFD, produced when bytes fail to decode as UTF-8) and control characters
    other than tab/newline/carriage-return count as NON-text. Plain text, base64,
    and minified content score ~1.0; a compressed/encrypted/binary blob decoded
    with ``errors='replace'`` scores near 0."""
    if not sample:
        return 1.0
    good = 0
    for ch in sample:
        if ch == "�":
            continue  # failed-decode byte: this is not text
        if ch in "\t\n\r" or ch.isprintable():
            good += 1
    return good / len(sample)


def triage_signature() -> str:
    """Opaque token for the active triage policy, folded into the detector
    version so cached findings are invalidated across a policy change. Includes
    the skip AND sample policy (both change which content the detectors see);
    score-ordering is NOT included because it never changes a file's findings."""
    if not _enabled():
        return "triage-off"
    parts = [TRIAGE_VERSION]
    parts.append("nul-skip" if _binary_skip_enabled() else "no-skip")
    sample = _sample_chars()
    if sample:
        parts.append(f"sample{sample}")
    return ":".join(parts)


def priority_score(record: dict, content: str) -> int:
    """Cheap sensitivity rank (0-100) for ordering analysis so the likeliest-
    sensitive files are scanned first - under a scan deadline that preserves
    recall on what matters. Never changes findings, only order."""
    sample = content[:_HEAD_SAMPLE_CHARS] if content else ""
    return _score(record, content, text_ratio(sample))


def _score(record: dict, content: str, ratio: float) -> int:
    """Cheap 0-100 sensitivity rank for ordering/observability (never a gate).
    Higher = more likely to hold sensitive data / more worth scanning first."""
    score = 0
    name = str(record.get("name") or record.get("path") or "").lower()
    if any(token in name for token in _SENSITIVE_NAME_TOKENS):
        score += 40
    if content:
        score += 30  # has scannable text at all
    if ratio >= 0.95:
        score += 20  # clean text
    size = int(record.get("size") or record.get("total_bytes") or 0)
    if 0 < size <= 1_000_000:
        score += 10  # small, cheap, and often config/secret files
    return min(100, score)


def triage_content(record: dict, content: str) -> dict:
    """Decide how much detection ``content`` warrants.

    Returns a dict with ``route`` (see ROUTE_*), a human ``reason``, the sampled
    ``text_ratio``, and a ``score``. The route is ``ROUTE_SKIP_NON_TEXT`` only for
    content that does not decode as text (recall-safe per the module contract);
    everything else is ``ROUTE_FULL``.
    """
    sample = content[:_HEAD_SAMPLE_CHARS] if content else ""
    ratio = text_ratio(sample)
    result = {
        "route": ROUTE_FULL,
        "reason": "",
        "text_ratio": round(ratio, 4),
        "score": _score(record, content, ratio),
    }
    if not _enabled():
        return result
    # Skip ONLY unambiguous binary (a NUL byte). Empty content is left to the
    # detectors' own empty-check so the diagnostics don't double-count it. The
    # binary skip takes precedence over sampling.
    if _binary_skip_enabled() and content and is_binary(sample):
        result["route"] = ROUTE_SKIP_NON_TEXT
        result["reason"] = "binary_content_nul_byte"
        return result
    # Opt-in: very large text is scanned as head+tail slices only (marks PARTIAL).
    limit = _sample_chars()
    if limit and content and len(content) > limit:
        half = max(1, limit // 2)
        result["route"] = ROUTE_SAMPLE
        result["reason"] = "large_text_head_tail_sample"
        result["sample"] = content[:half] + content[-half:]
        result["sampled_chars"] = len(result["sample"])
    return result
