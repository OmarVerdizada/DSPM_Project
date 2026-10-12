from __future__ import annotations

import functools
import hashlib
import hmac
import os
import threading
import re
import time
import unicodedata
from typing import Any

from classification import masking
from classification.compliance.canonical_entities import canonical_entity_fingerprint
from classification.compliance.evidence_keys import evidence_hmac_key
from classification.compliance.nist_catalog import load_nist_catalog, nist_catalog_readonly, nist_catalog_status
from classification.compliance.nist_mappings import nist_data_categories_for_finding
from classification.compliance.nist_models import NIST_DETECTOR_VERSION, NIST_FRAMEWORK_ID
from classification.compliance.validators import _content_trigrams, redact
from backend.finding_contracts import get_finding_display_name


NIST_DETECTOR_TIMEOUT_SECONDS = float(os.getenv("DSPM_NIST_DETECTOR_TIMEOUT_SECONDS", "8"))


def classify_nist_content(
    content: str,
    metadata: dict | None = None,
    custom_rule_overlays: list[dict] | None = None,
) -> list[dict]:
    if not content and not metadata:
        return []
    status = nist_catalog_status()
    if status.get("degraded_mode") and not status.get("scanner_available", True):
        return []

    metadata = metadata or {}
    tenant_id = str(metadata.get("tenant_id") or metadata.get("tenant") or "default")
    # Only an overlay writes into the catalog, and only then is a copy needed.
    catalog = load_nist_catalog() if custom_rule_overlays else nist_catalog_readonly()
    catalog_version = str((catalog.get("catalog") or {}).get("catalog_version") or "")
    catalog_hash = str(status.get("catalog_hash") or "")
    rules = _apply_overlays(catalog.get("rules") or [], custom_rule_overlays or [])
    evidence_blob = _normalize_text(
        " ".join(
            [
                content or "",
                str(metadata.get("name") or ""),
                str(metadata.get("path") or ""),
                str(metadata.get("extension") or ""),
                str(metadata.get("table") or ""),
                str(metadata.get("column") or ""),
                str(metadata.get("json_path") or metadata.get("JSONPath") or ""),
                str(metadata.get("xml_tag") or metadata.get("XPath") or ""),
                str(metadata.get("object_name") or ""),
            ]
        )
    )
    path_blob = _normalize_text(" ".join(str(metadata.get(key) or "") for key in ("name", "path", "extension", "share", "source")))
    started = time.perf_counter()
    findings: dict[tuple[str, str], dict] = {}
    skipped = 0
    timed_out = False
    for rule in rules:
        if time.perf_counter() - started > NIST_DETECTOR_TIMEOUT_SECONDS:
            timed_out = True
            break
        if _excluded_by_path(rule, path_blob):
            skipped += 1
            continue
        score_row = _score_rule(rule, content or "", evidence_blob, path_blob)
        if score_row["status"] == "rejected":
            skipped += 1
            continue
        finding = _finding_from_score(rule, score_row, metadata, tenant_id, catalog_version, catalog_hash)
        dedupe_key = (finding["rule_id"], finding["logical_boundary_id"])
        current = findings.get(dedupe_key)
        if not current or int(finding["confidence_score"]) > int(current.get("confidence_score") or 0):
            findings[dedupe_key] = finding
    rows = list(findings.values())
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    for finding in rows:
        finding["detector_metrics"] = {
            "elapsed_ms": elapsed_ms,
            "timed_out": timed_out,
            "prefilter_skipped_rules": skipped,
            "catalog_version": catalog_version,
            "catalog_hash": catalog_hash,
        }
    return rows


def _score_rule(rule: dict[str, Any], content: str, evidence_blob: str, path_blob: str) -> dict[str, Any]:
    detection = rule.get("detection") or {}
    groups = detection.get("keyword_groups") or {}
    score_model = detection.get("score_model") or {}
    weights = score_model.get("weights") or {}
    thresholds = score_model.get("thresholds") or {"confirmed": 85, "high": 70, "medium": 55, "low": 35}
    minimum_context_score = int(detection.get("minimum_context_score") or 0)
    positive: list[dict[str, Any]] = []
    negative: list[dict[str, Any]] = []
    score = 0

    signal_specs = [
        ("primary", "primary_and_aliases"),
        ("schema", "schema_and_field_names"),
        ("azerbaijani", "azerbaijani_terms"),
        ("supporting", "supporting_context"),
    ]
    matched_groups: set[str] = set()
    for signal, group_name in signal_specs:
        hits = _keyword_hits(evidence_blob, groups.get(group_name) or [])
        if not hits:
            continue
        matched_groups.add(group_name)
        delta = int(weights.get(signal, 15))
        score += delta
        positive.append({"group": group_name, "signals": hits[:10], "score": delta})

    path_hits = _keyword_hits(path_blob, [rule.get("category"), rule.get("label"), rule.get("type")])
    if path_hits:
        delta = int(weights.get("path", 8))
        score += delta
        positive.append({"group": "path_context", "signals": path_hits[:10], "score": delta})
        matched_groups.add("path_context")

    regex_hits = _regex_hits(content, detection.get("regex_patterns") or [], _value_data_class(rule))
    if regex_hits:
        delta = int(weights.get("regex", 25))
        score += delta
        positive.append({"group": "regex_patterns", "signals": [item["masked_preview"] for item in regex_hits[:5]], "score": delta})
        matched_groups.add("regex_patterns")

    negative_hits = _keyword_hits(evidence_blob, groups.get("negative_and_exclusion_context") or [])
    if negative_hits:
        delta = int(weights.get("negative", -35))
        score += delta
        negative.append({"group": "negative_and_exclusion_context", "signals": negative_hits[:10], "score": delta})

    mode = detection.get("mode")
    if mode == "DOCUMENT_MARKING_AND_CONTEXT" and _keyword_hits(evidence_blob, ["cui", "controlled unclassified", "nist sp 800-60", "fips 199"]):
        score += 20
        positive.append({"group": "document_marking", "signals": ["CUI/NIST/FIPS marking"], "score": 20})
        matched_groups.add("document_marking")
    elif mode == "SECRET_PATTERN_COMPOSITE" and regex_hits and _keyword_hits(evidence_blob, ["password", "token", "api key", "private key", "secret"]):
        score += 18
        positive.append({"group": "secret_context", "signals": ["secret assignment context"], "score": 18})
        matched_groups.add("secret_context")
    elif mode == "ENTITY_CONTEXT_COMPOSITE" and len(matched_groups) >= 2:
        score += 10
        positive.append({"group": "entity_context", "signals": ["multiple independent signal groups"], "score": 10})
    elif mode == "TECHNICAL_ARTIFACT_COMPOSITE" and _keyword_hits(path_blob, [".yaml", ".yml", ".json", ".py", ".ps1", ".cfg", ".conf", ".env"]):
        score += 10
        positive.append({"group": "technical_artifact", "signals": ["technical file/path context"], "score": 10})

    score = _clamp(score)
    keyword_only = matched_groups and matched_groups <= {"primary_and_aliases", "supporting_context"}
    if score < minimum_context_score:
        status = "rejected"
    elif negative_hits and score < int(thresholds.get("high", 70)):
        status = "low" if score >= int(thresholds.get("low", 35)) else "rejected"
    elif keyword_only and score >= int(thresholds.get("medium", 55)):
        status = str(score_model.get("keyword_only_max_status") or "low")
    elif score >= int(thresholds.get("confirmed", 85)):
        status = "confirmed"
    elif score >= int(thresholds.get("high", 70)):
        status = "high"
    elif score >= int(thresholds.get("medium", 55)):
        status = "medium"
    elif score >= int(thresholds.get("low", 35)):
        status = "low"
    else:
        status = "rejected"
    return {
        "score": score,
        "status": status,
        "matched_signal_groups": sorted(matched_groups),
        "contributing_signals": positive,
        "negative_signals": negative,
        "regex_hits": regex_hits,
        "keyword_only": bool(keyword_only),
    }


def _finding_from_score(rule: dict[str, Any], score_row: dict[str, Any], metadata: dict, tenant_id: str, catalog_version: str, catalog_hash: str) -> dict[str, Any]:
    classification = rule.get("classification") or {}
    confidence_score = int(score_row["score"])
    review_status = "CONFIRMED" if score_row["status"] == "confirmed" else "NEEDS_REVIEW"
    sample_seed = _sample_seed(rule, score_row)
    # A regex hit is a value and is masked for its class; without one the sample is a
    # catalog keyword, which is not.
    sample_class = _value_data_class(rule) if score_row.get("regex_hits") else masking.GENERIC
    secure_fp = _secure_fingerprint(sample_seed, tenant_id) if sample_seed else _secure_fingerprint(rule.get("rule_id", ""), tenant_id)
    canonical_entity_type = _canonical_type(rule)
    canonical_fingerprints = [canonical_entity_fingerprint(canonical_entity_type, secure_fp, tenant_id)] if canonical_entity_type else []
    base = int(classification.get("base_risk_score") or 0)
    final = _clamp(base + max(0, confidence_score - 60) // 2)
    if score_row["negative_signals"]:
        final = max(0, final - 12)
    finding = {
        "rule_id": rule.get("rule_id"),
        "canonical_finding_id": "",
        "framework": NIST_FRAMEWORK_ID,
        "catalog_version": catalog_version,
        "catalog_hash": catalog_hash,
        "source_kind": rule.get("source_kind"),
        "source_catalog": rule.get("source_catalog"),
        "source_version": rule.get("source_version"),
        "source_status": rule.get("source_status"),
        "category": rule.get("category"),
        "category_id": rule.get("category_id"),
        "data_type": rule.get("data_type"),
        "type": rule.get("type"),
        "label": get_finding_display_name(rule),
        "label_az": rule.get("label_az"),
        "source_label": rule.get("label"),
        "display_name": get_finding_display_name(rule),
        "display_name_az": get_finding_display_name(rule, "az"),
        "technical_type": rule.get("type"),
        "handling_tier": rule.get("handling_tier"),
        "product_severity": classification.get("product_severity"),
        "risk": classification.get("product_severity"),
        "impact_severity": classification.get("product_severity"),
        "base_risk_score": base,
        "final_risk_score": final,
        "risk_score": final,
        "confidentiality_impact": classification.get("confidentiality_impact"),
        "integrity_impact": classification.get("integrity_impact"),
        "availability_impact": classification.get("availability_impact"),
        "overall_impact": classification.get("overall_impact"),
        "impact_basis": classification.get("impact_basis"),
        "cui_control_type": rule.get("cui_control_type"),
        "confidence": score_row["status"],
        "confidence_score": confidence_score,
        "detection_confidence": confidence_score,
        "review_status": review_status,
        "needs_review": review_status != "CONFIRMED",
        "matched_signal_groups": score_row["matched_signal_groups"],
        "contributing_signals": score_row["contributing_signals"],
        "negative_signals": score_row["negative_signals"],
        "detection_mode": (rule.get("detection") or {}).get("mode"),
        "threshold": ((rule.get("detection") or {}).get("score_model") or {}).get("thresholds", {}),
        "matched_keywords": _matched_keywords(score_row),
        "protection_state": str(metadata.get("protection_state") or "NOT_ASSESSED").upper(),
        "exposure_state": str(metadata.get("exposure_state") or "UNKNOWN").upper(),
        "logical_boundary": _logical_boundary(metadata),
        "logical_boundary_id": _stable_id("nist_boundary", metadata.get("path") or metadata.get("name"), rule.get("rule_id")),
        "source_asset": metadata.get("asset_id") or metadata.get("host_id") or "",
        "source_path": metadata.get("path") or metadata.get("name") or "",
        "source_object": metadata.get("object_name") or "",
        "source_table": metadata.get("table") or "",
        "source_column": metadata.get("column") or "",
        "samples": [_masked_preview(sample_seed, sample_class)] if sample_seed else [],
        "masked_preview": _masked_preview(sample_seed, sample_class),
        "secure_value_fingerprints": [secure_fp],
        "canonical_entity_type": canonical_entity_type,
        "canonical_entity_fingerprints": canonical_fingerprints,
        "correlation_references": rule.get("correlation") or {},
        "correlation": rule.get("correlation") or {},
        "remediation": " ".join(rule.get("remediation") or []),
        "framework_mappings": rule.get("framework_mappings") or [],
        "governance": rule.get("governance") or {},
        "data_categories": nist_data_categories_for_finding(rule),
        "governance_status": (rule.get("governance") or {}).get("status", ""),
        "exception_status": "not_required",
        "raw_value_policy": (rule.get("evidence") or {}).get("raw_value_policy") or "MASK_OR_FINGERPRINT_ONLY",
        "evidence": rule.get("evidence") or {},
        "why": rule.get("why") or "",
        "detector_version": NIST_DETECTOR_VERSION,
        "rule_catalog_version": catalog_version,
        "count": 1,
        "occurrence_count": 1,
        "unique_value_count": 1,
        "risk_factor_breakdown": {
            "base": base,
            "confidence": max(0, confidence_score - 60) // 2,
            "negative_context": -12 if score_row["negative_signals"] else 0,
            "final": final,
        },
    }
    finding["framework_metadata"] = {
        "nist": {
            "rule_id": finding["rule_id"],
            "catalog_version": catalog_version,
            "catalog_hash": catalog_hash,
            "source_kind": finding.get("source_kind"),
            "category_id": finding.get("category_id"),
            "technical_type": finding.get("technical_type"),
            "detection_mode": finding.get("detection_mode"),
            "matched_signal_groups": finding.get("matched_signal_groups"),
            "classification": classification,
            "governance": finding.get("governance"),
            "evidence": finding.get("evidence"),
        }
    }
    return finding


def _apply_overlays(rules: list[dict[str, Any]], overlays: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not overlays:
        return rules
    by_type = {str(item.get("type") or ""): item for item in rules}
    for overlay in overlays:
        target = by_type.get(str(overlay.get("type") or ""))
        if not target:
            continue
        groups = target.setdefault("detection", {}).setdefault("keyword_groups", {})
        allowlist = {
            "terms": "primary_and_aliases",
            "positive_keywords": "primary_and_aliases",
            "structured_field_names": "schema_and_field_names",
            "negative_keywords": "negative_and_exclusion_context",
            "azerbaijani_terms": "azerbaijani_terms",
        }
        for source, dest in allowlist.items():
            values = overlay.get(source) or []
            if not isinstance(values, list):
                continue
            groups[dest] = list(dict.fromkeys([*groups.get(dest, []), *[str(item) for item in values if item]]))
        if overlay.get("allowed_file_types"):
            target["detection"]["allowed_file_types"] = list(dict.fromkeys([*target["detection"].get("allowed_file_types", []), *overlay["allowed_file_types"]]))
        if overlay.get("excluded_paths"):
            target["detection"]["excluded_paths"] = list(dict.fromkeys([*target["detection"].get("excluded_paths", []), *overlay["excluded_paths"]]))
        target.setdefault("tenant_overlay_metadata", []).append(
            {
                "owner": overlay.get("owner") or "",
                "status": overlay.get("status") or "draft",
                "language": overlay.get("language") or "custom",
            }
        )
    return rules


_LOWERED_TEXT = threading.local()


def _lowered_once(text: str) -> str:
    """`text.lower()` for a string this scan keeps asking about.

    _keyword_hits is called 984 times for one file and every call lowered the
    same evidence blob - 12MB of case-folding per file. The blob is one object
    for the length of a classify call, so it is folded once and held against
    its identity; the slot is replaced as soon as a different string arrives.

    W5: a short text - the path blob each rule also asks about - is lowered on the spot and
    does not take the slot. Every rule alternated the two, so the file's text was lowered
    again for every rule.
    """
    if len(text) < _SLOT_MIN_CHARS:
        return text.lower()
    slot = getattr(_LOWERED_TEXT, "slot", None)
    if slot is not None and slot[0] is text:
        return slot[1]
    lowered = text.lower()
    _LOWERED_TEXT.slot = (text, lowered)
    return lowered


_TERM_PRESENCE = threading.local()


# W5: from this length on, a text's character triples are collected once and a term with
# a triple the text lacks is absent without a scan.
_TRIGRAM_PREFILTER_CHARS = 256 * 1024
# W5: below this a text is searched directly and kept in no per-text slot.
_SLOT_MIN_CHARS = 4096


def _present_in(text: str, text_lower: str, normalized: str) -> bool:
    """Whether a term occurs in this text (W4.3): answered once per text. The rules of one
    file ask about the same terms again and again - 984 calls for one file - and each answer
    was a scan of the whole text.

    W5: once per term was still a scan of the whole text per term the catalog names: three
    quarters of NIST's 9 s on a 16 MiB CSV. A term occurs only where each of its character
    triples does, so on a large text a term with a triple the text lacks is absent without
    a scan - the rest are scanned, and the answers are what the scans give."""
    if len(text_lower) < _SLOT_MIN_CHARS:
        # A short text (the path blob every rule also asks about) is searched on the spot
        # and leaves the slot to the file's text: alternating the two emptied the slot,
        # and its answers, for every rule.
        return normalized in text_lower
    slot = getattr(_TERM_PRESENCE, "slot", None)
    if slot is None or slot[0] is not text:
        slot = (text, {}, [None])
        _TERM_PRESENCE.slot = slot
    answers = slot[1]
    present = answers.get(normalized)
    if present is None:
        if len(normalized) >= 3 and len(text_lower) >= _TRIGRAM_PREFILTER_CHARS:
            triples = slot[2][0]
            if triples is None:
                triples = slot[2][0] = _content_trigrams(text_lower)
            if any(normalized[index:index + 3] not in triples for index in range(len(normalized) - 2)):
                present = False
        if present is None:
            present = normalized in text_lower
        answers[normalized] = present
    return present


def _keyword_hits(text: str, terms: list[Any]) -> list[str]:
    hits = []
    # A word-boundary match requires the term to be present at all, so this
    # substring test correctly skips the expensive per-term regex for the ~99%
    # of a catalog that never appears in a given file.
    text_lower = _lowered_once(text)
    for term in terms:
        normalized = _normalize_term(str(term or ""))
        if not normalized:
            continue
        # _normalize_term casefolds, so the term is already lower - this used
        # to call .lower() on it 1.1 million times over one corpus.
        if not _present_in(text, text_lower, normalized):
            continue
        if _term_matches(text, normalized):
            hits.append(str(term))
    return list(dict.fromkeys(hits))


@functools.lru_cache(maxsize=2048)
def _compiled_rule_pattern(raw: str, ignore_case: bool):
    try:
        return re.compile(raw, re.IGNORECASE if ignore_case else 0)
    except re.error:
        return None


def _regex_hits(content: str, patterns: list[dict[str, Any]], data_class: str = masking.GENERIC) -> list[dict[str, str]]:
    hits = []
    # `content[:250_000]` is the same slice for every pattern of every rule, and
    # taking it inside the loop copied the file's text 154 times - the single
    # largest cost of a NIST pass over a file with nothing in it.
    scanned = content[:250_000]
    for pattern in patterns[:10]:
        raw = str(pattern.get("pattern") or "")
        if not raw or len(raw) > 500:
            continue
        compiled = _compiled_rule_pattern(raw, "i" in str(pattern.get("flags") or "").lower())
        if compiled is None:
            continue
        for match in compiled.finditer(scanned):
            value = match.group(0)
            hits.append({"pattern_id": str(pattern.get("id") or ""), "masked_preview": _masked_preview(value, data_class),
                         "fingerprint_seed": value})
            if len(hits) >= 10:
                return hits
    return hits


@functools.lru_cache(maxsize=16384)
def _term_boundary_pattern(term: str):
    """A term's word-boundary matcher, built once.

    This was re.escape plus a pattern string plus a module-cache lookup on
    every term of every rule of every file - 115,000 compiles and 66,000
    escapes over one corpus, all of them arriving at the same few thousand
    patterns."""
    return re.compile(rf"(?<![\w]){re.escape(term)}(?![\w])", re.IGNORECASE)


def _term_matches(text: str, term: str) -> bool:
    if not term:
        return False
    if term[0].isalnum() and term[-1].isalnum():
        return _term_boundary_pattern(term).search(text) is not None
    return term in text


def _excluded_by_path(rule: dict[str, Any], path_blob: str) -> bool:
    detection = rule.get("detection") or {}
    for excluded in detection.get("excluded_paths") or []:
        if _normalize_text(str(excluded)).strip("/") in path_blob:
            return True
    allowed = [str(item).lower() for item in detection.get("allowed_file_types") or [] if item]
    return bool(allowed) and not any(item in path_blob for item in allowed)


def _matched_keywords(score_row: dict[str, Any]) -> list[str]:
    values = []
    for item in score_row.get("contributing_signals") or []:
        values.extend(item.get("signals") or [])
    return list(dict.fromkeys(str(item) for item in values if item))[:20]


def _sample_seed(rule: dict[str, Any], score_row: dict[str, Any]) -> str:
    regex_hits = score_row.get("regex_hits") or []
    if regex_hits:
        return str(regex_hits[0].get("fingerprint_seed") or "")
    keywords = _matched_keywords(score_row)
    return keywords[0] if keywords else str(rule.get("rule_id") or "")


def _masked_preview(value: str, data_class: str = masking.GENERIC) -> str:
    """The value masked for its class. It used to keep the first three and last two
    characters of anything - an SSN read "123...89" - and that text reaches reports."""
    text = str(value or "")
    if not text:
        return ""
    return redact(text, data_class)


def _value_data_class(rule: dict[str, Any]) -> str:
    """What a rule's regex values are. Every NIST value pattern is an identifier (an id,
    token, account or passport number); a credential rule's is a secret."""
    canonical = _canonical_type(rule)
    if canonical == "SECRET":
        return masking.SECRET
    if canonical == "PASSPORT_NUMBER":
        return masking.PASSPORT
    return masking.GOVERNMENT_ID


def _secure_fingerprint(value: str, tenant_id: str) -> str:
    secret = evidence_hmac_key()
    return hmac.new(f"{secret}:{tenant_id}:nist".encode("utf-8"), str(value or "").encode("utf-8", errors="ignore"), hashlib.sha256).hexdigest()


def _canonical_type(rule: dict[str, Any]) -> str:
    blob = " ".join(str(rule.get(key) or "") for key in ("type", "label", "category")).lower()
    if "credential" in blob or "secret" in blob or "token" in blob or "password" in blob:
        return "SECRET"
    if "passport" in blob:
        return "PASSPORT_NUMBER"
    if "financial" in blob or "account" in blob:
        return "FINANCIAL_ACCOUNT"
    if "privacy" in blob or "pii" in blob:
        return "PERSONAL_DATA"
    return ""


def _logical_boundary(metadata: dict) -> str:
    extension = str(metadata.get("extension") or "").lower()
    if extension in {".csv", ".tsv", ".xlsx", ".xls"}:
        return "structured_row"
    if extension in {".json", ".jsonl", ".ndjson"}:
        return "json_object"
    if extension == ".xml":
        return "xml_subtree"
    if extension in {".log"}:
        return "log_event"
    return "text_proximity_window"


def _normalize_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    text = re.sub(r"[_/\\.\-]+", " ", text)
    return " ".join(text.split())


@functools.lru_cache(maxsize=16384)
def _normalize_term(value: str) -> str:
    """The same normalization, for catalog TERMS rather than file content.

    _keyword_hits normalized every term of every rule on every file - 4,828
    NFKC-and-regex passes for one file - to arrive at the same string each
    time. Content is never cached here: it is unbounded and never repeats."""
    return _normalize_text(value)


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8', errors='ignore')).hexdigest()[:24]}"


def _clamp(value: int) -> int:
    return max(0, min(100, int(value)))
