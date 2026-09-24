from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from classification.compliance.nist_models import NIST_FRAMEWORK_ID, NIST_DISPLAY_NAME
from classification.compliance.nist_validators import validate_nist_catalog_payload
from backend.finding_contracts import get_finding_display_name


BASE_DIR = Path(__file__).resolve().parents[2]
BUILT_IN_CATALOG_PATH = Path(__file__).with_name("catalogs") / "nist_sp800_60_enterprise.json"
SCHEMA_PATH = Path(__file__).with_name("schemas") / "nist_sp800_60_enterprise.schema.json"
STATE_DIR = BASE_DIR / "data" / "nist_catalogs"
ACTIVE_PATH = STATE_DIR / "nist_sp800_60_enterprise.active.json"
LAST_GOOD_PATH = STATE_DIR / "nist_sp800_60_enterprise.last_good.json"
AUDIT_PATH = STATE_DIR / "nist_sp800_60_enterprise.audit.jsonl"
MAX_CATALOG_BYTES = 10 * 1024 * 1024

_lock = threading.RLock()
_cache: dict[str, Any] = {"path": "", "mtime_ns": -1, "catalog": None, "status": None}


def load_nist_catalog() -> dict[str, Any]:
    """A private copy the caller may overlay rules onto."""
    status = nist_catalog_status()
    if status.get("degraded_mode") and not status.get("scanner_available"):
        return {}
    return _load_catalog_from_path(_active_or_builtin_path())


def nist_catalog_readonly() -> dict[str, Any]:
    """The cached catalog itself. The caller MUST NOT mutate it.

    Copying it was 18 to 49ms of every file's NIST pass - the whole catalog
    serialized and reparsed, or deep-copied node by node - purely so that a
    caller with custom rule overlays could write into it. A scan without
    overlays, which is the default, writes nothing and can read the cache.
    """
    status = nist_catalog_status()
    if status.get("degraded_mode") and not status.get("scanner_available"):
        return {}
    path, resolved, mtime_ns = _catalog_identity()
    with _lock:
        if _cache["catalog"] is not None and _cache["path"] == resolved and _cache["mtime_ns"] == mtime_ns:
            return _cache["catalog"]
    # A cold cache: loading fills it, and the caller gets the cached object like every
    # later caller does - not the private copy the loader hands back.
    catalog = _load_catalog_from_path(path)
    with _lock:
        if _cache["catalog"] is not None and _cache["path"] == resolved:
            return _cache["catalog"]
    return catalog


# Reading, deep-copying, schema-validating and hashing the whole catalog on
# every file was 60% of what the NIST detector cost, to re-learn something a
# stat() can answer. Only the success path is cached, and only against the
# file's identity and mtime, so a swapped catalog is still picked up on the
# next call.
_STATUS_CACHE: dict[tuple[str, int], dict[str, Any]] = {}


# P1 (2026-09-24). The status and the read-only catalog are asked for on every file, and
# each asked the filesystem which catalog is in force - an exists(), a resolve() and a
# stat(), twice - which was 16% of the main process in the quality audit. The answer is
# kept for a second: a catalog swapped on disk by another process is seen within that,
# and one activated or rolled back here at once (_invalidate_cache), as is a change to
# the configured paths.
_IDENTITY_SECONDS = 1.0
_identity: tuple | None = None


def _catalog_identity() -> tuple[Path, str, int]:
    """(the catalog file in force, its resolved path, its mtime); OSError if unreadable."""
    global _identity
    paths = (ACTIVE_PATH, BUILT_IN_CATALOG_PATH)
    now = time.monotonic()
    cached = _identity
    if cached is not None and cached[0] == paths and now - cached[1] < _IDENTITY_SECONDS:
        return cached[2]
    path = _active_or_builtin_path()
    resolved = path.resolve()
    answer = (path, str(resolved), resolved.stat().st_mtime_ns)
    _identity = (paths, now, answer)
    return answer


def nist_catalog_status() -> dict[str, Any]:
    try:
        path, resolved, mtime_ns = _catalog_identity()
        cache_key = (resolved, mtime_ns)
    except OSError:
        path = _active_or_builtin_path()
        cache_key = None
    if cache_key is not None:
        with _lock:
            cached = _STATUS_CACHE.get(cache_key)
        if cached is not None:
            return dict(cached)
    try:
        catalog = _load_catalog_from_path(path)
        result = validate_nist_catalog_payload(catalog)
        if not result.valid:
            raise ValueError("; ".join(result.errors))
        status = _status_from_catalog(catalog, result.catalog_hash, path, "active" if ACTIVE_PATH.exists() else "built-in")
        if cache_key is not None:
            with _lock:
                if len(_STATUS_CACHE) > 8:
                    _STATUS_CACHE.clear()
                _STATUS_CACHE[cache_key] = status
        return dict(status)
    except Exception as exc:
        _append_audit("nist.catalog.error", {"error": _safe_error(exc), "path": str(path)})
        if LAST_GOOD_PATH.exists():
            try:
                catalog = _load_catalog_from_path(LAST_GOOD_PATH, bypass_cache=True)
                result = validate_nist_catalog_payload(catalog)
                status = _status_from_catalog(catalog, result.catalog_hash, LAST_GOOD_PATH, "last-known-good")
                status["catalog_status"] = "DEGRADED"
                status["degraded_mode"] = True
                status["scanner_available"] = result.valid
                status["catalog_error"] = _safe_error(exc)
                return status
            except Exception:
                pass
        return {
            "framework": NIST_FRAMEWORK_ID,
            "name": NIST_DISPLAY_NAME,
            "catalog_status": "ERROR",
            "degraded_mode": True,
            "scanner_available": False,
            "catalog_error": _safe_error(exc),
            "catalog_version": "",
            "catalog_hash": "",
            "rule_count": 0,
            "category_count": 0,
        }


def validate_nist_catalog(catalog: dict[str, Any], *, probe_regexes: bool = False) -> dict[str, Any]:
    _enforce_catalog_size(catalog)
    active = _try_load_active()
    return validate_nist_catalog_payload(catalog, active_catalog=active, probe_regexes=probe_regexes).model_dump()


def import_nist_catalog(catalog: dict[str, Any], *, dry_run: bool = True, actor: str = "system") -> dict[str, Any]:
    # H4 (1.2): probe patterns for catastrophic backtracking at the import gate.
    preview = validate_nist_catalog(catalog, probe_regexes=True)
    if not preview["valid"]:
        return {**preview, "imported": False, "dry_run": dry_run}
    if dry_run:
        return {**preview, "imported": False, "dry_run": True}
    pending_path = _pending_path(preview["catalog_hash"])
    _atomic_write_json(pending_path, catalog)
    _append_audit("nist.catalog.imported", {"actor": actor, "catalog_hash": preview["catalog_hash"], "catalog_version": preview["catalog_version"]})
    return {**preview, "imported": True, "dry_run": False, "pending_path": str(pending_path)}


def activate_nist_catalog(catalog_hash: str, *, actor: str = "system") -> dict[str, Any]:
    safe_hash = _safe_hash(catalog_hash)
    pending = _pending_path(safe_hash)
    if not pending.exists():
        raise ValueError("Pending catalog not found")
    catalog = _load_catalog_from_path(pending, bypass_cache=True)
    preview = validate_nist_catalog(catalog, probe_regexes=True)
    if not preview["valid"]:
        raise ValueError("; ".join(preview["errors"]))
    if ACTIVE_PATH.exists():
        _atomic_write_json(LAST_GOOD_PATH, _load_catalog_from_path(ACTIVE_PATH, bypass_cache=True))
    else:
        _atomic_write_json(LAST_GOOD_PATH, _load_catalog_from_path(BUILT_IN_CATALOG_PATH, bypass_cache=True))
    _atomic_write_json(ACTIVE_PATH, catalog)
    _invalidate_cache()
    _append_audit("nist.catalog.activated", {"actor": actor, "catalog_hash": safe_hash, "catalog_version": preview["catalog_version"]})
    return {**preview, "activated": True}


def rollback_nist_catalog(*, actor: str = "system") -> dict[str, Any]:
    if not LAST_GOOD_PATH.exists():
        _atomic_write_json(LAST_GOOD_PATH, _load_catalog_from_path(BUILT_IN_CATALOG_PATH, bypass_cache=True))
    catalog = _load_catalog_from_path(LAST_GOOD_PATH, bypass_cache=True)
    preview = validate_nist_catalog(catalog)
    if not preview["valid"]:
        raise ValueError("Last-known-good catalog is invalid")
    _atomic_write_json(ACTIVE_PATH, catalog)
    _invalidate_cache()
    _append_audit("nist.catalog.rollback", {"actor": actor, "catalog_hash": preview["catalog_hash"], "catalog_version": preview["catalog_version"]})
    return {**preview, "rolled_back": True}


def export_nist_catalog() -> tuple[str, str, str]:
    catalog = load_nist_catalog()
    version = str((catalog.get("catalog") or {}).get("catalog_version") or "built-in")
    export_catalog = _catalog_export_view(catalog)
    return f"NIST_{version}.json", "application/json;charset=utf-8", json.dumps(export_catalog, ensure_ascii=False, indent=2)


def list_nist_rules(
    *,
    category: str = "",
    source_kind: str = "",
    handling_tier: str = "",
    severity: str = "",
    cia_impact: str = "",
    detection_mode: str = "",
    search: str = "",
    include_keywords: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    catalog = load_nist_catalog()
    rules = list(catalog.get("rules") or [])
    query = _normalize(search)
    rows = []
    for rule in rules:
        classification = rule.get("classification") or {}
        detection = rule.get("detection") or {}
        if category and rule.get("category_id") != category and rule.get("category") != category:
            continue
        if source_kind and str(rule.get("source_kind") or "").lower() != source_kind.lower():
            continue
        if handling_tier and str(rule.get("handling_tier") or "").upper() != handling_tier.upper():
            continue
        if severity and str(classification.get("product_severity") or "").upper() != severity.upper():
            continue
        if cia_impact and str(classification.get("overall_impact") or "").upper() != cia_impact.upper():
            continue
        if detection_mode and str(detection.get("mode") or "") != detection_mode:
            continue
        if query and query not in _rule_search_blob(rule):
            continue
        row = _compact_rule(rule, include_keywords=include_keywords)
        rows.append(row)
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda item: (severity_rank.get(str(item.get("product_severity") or "").upper(), 9), str(item.get("display_name") or item.get("label") or "").casefold()))
    return {
        "framework": NIST_FRAMEWORK_ID,
        "catalog_status": nist_catalog_status(),
        "total": len(rows),
        "limit": limit,
        "offset": offset,
        "rules": rows[max(offset, 0): max(offset, 0) + max(1, min(limit, 200))],
    }


def get_nist_rule(rule_id: str) -> dict[str, Any] | None:
    for rule in load_nist_catalog().get("rules") or []:
        if rule.get("rule_id") == rule_id or rule.get("type") == rule_id:
            return rule
    return None


def built_in_nist_keyword_groups() -> list[dict[str, Any]]:
    groups = []
    for rule in load_nist_catalog().get("rules") or []:
        keywords = rule.get("detection", {}).get("keyword_groups", {})
        terms = []
        for key in ("primary_and_aliases", "schema_and_field_names", "azerbaijani_terms", "supporting_context"):
            terms.extend(keywords.get(key) or [])
        groups.append(
            {
                "framework": NIST_FRAMEWORK_ID,
                "language": "built-in",
                "category": rule.get("category_id") or rule.get("category"),
                "type": rule.get("type"),
                "label": get_finding_display_name(rule),
                "display_name": get_finding_display_name(rule),
                "display_name_az": get_finding_display_name(rule, "az"),
                "technical_type": rule.get("type"),
                "rule_id": rule.get("rule_id"),
                "description": rule.get("why"),
                "handling_tier": rule.get("handling_tier"),
                "risk": rule.get("classification", {}).get("product_severity", "MEDIUM"),
                "source": "built-in",
                "terms": list(dict.fromkeys(str(item) for item in terms if item)),
                "count": len(terms),
                "updated_at": "",
            }
        )
    return groups


def _load_catalog_from_path(path: Path, *, bypass_cache: bool = False) -> dict[str, Any]:
    """A private copy of the catalog, because callers overlay rules onto it.

    The copy was a json.dumps followed by a json.loads of the whole catalog -
    18ms of every file's NIST pass, spent re-parsing text this process wrote a
    microsecond earlier. copy.deepcopy answers the same need directly.
    """
    resolved = path.resolve()
    stat = resolved.stat()
    with _lock:
        if not bypass_cache and _cache["catalog"] is not None and _cache["path"] == str(resolved) and _cache["mtime_ns"] == stat.st_mtime_ns:
            return json.loads(json.dumps(_cache["catalog"], ensure_ascii=False))
        data = json.loads(resolved.read_text(encoding="utf-8"))
        _cache.update({"path": str(resolved), "mtime_ns": stat.st_mtime_ns, "catalog": data})
        return json.loads(json.dumps(data, ensure_ascii=False))


def _status_from_catalog(catalog: dict[str, Any], catalog_hash: str, path: Path, source: str) -> dict[str, Any]:
    meta = catalog.get("catalog") or {}
    return {
        "framework": NIST_FRAMEWORK_ID,
        "name": "NIST",
        "catalog_status": "OK",
        "degraded_mode": False,
        "scanner_available": True,
        "catalog_source": source,
        "catalog_version": meta.get("catalog_version") or "",
        "schema_version": meta.get("schema_version") or "",
        "source_version": meta.get("source_version") or "",
        "source_status": meta.get("source_status") or "",
        "catalog_hash": catalog_hash,
        "rule_count": len(catalog.get("rules") or []),
        "category_count": len(catalog.get("categories") or []),
        "path": str(path),
    }


def _catalog_export_view(value: Any) -> Any:
    if isinstance(value, dict):
        exported = {}
        for key, item in value.items():
            if key == "framework" and item == NIST_FRAMEWORK_ID:
                exported[key] = "NIST"
            elif key == "name" and item == NIST_DISPLAY_NAME:
                exported[key] = "NIST"
            else:
                exported[key] = _catalog_export_view(item)
        return exported
    if isinstance(value, list):
        return [_catalog_export_view(item) for item in value]
    return value


def _compact_rule(rule: dict[str, Any], *, include_keywords: bool = False) -> dict[str, Any]:
    detection = rule.get("detection") or {}
    keywords = detection.get("keyword_groups") or {}
    row = {
        "display_name": get_finding_display_name(rule),
        "display_name_az": get_finding_display_name(rule, "az"),
        "technical_type": rule.get("type"),
        "rule_id": rule.get("rule_id"),
        "type": rule.get("type"),
        "category": rule.get("category"),
        "category_id": rule.get("category_id"),
        "label": get_finding_display_name(rule),
        "source_label": rule.get("label"),
        "label_az": rule.get("label_az"),
        "description": rule.get("why"),
        "source_kind": rule.get("source_kind"),
        "handling_tier": rule.get("handling_tier"),
        "product_severity": (rule.get("classification") or {}).get("product_severity"),
        "overall_impact": (rule.get("classification") or {}).get("overall_impact"),
        "detection_mode": detection.get("mode"),
        "threshold": (detection.get("score_model") or {}).get("thresholds", {}),
        "keyword_group_counts": {key: len(value or []) for key, value in keywords.items()},
        "test_case_count": len(rule.get("test_cases") or []),
    }
    if include_keywords:
        row["keyword_groups"] = keywords
    return row


def _rule_search_blob(rule: dict[str, Any]) -> str:
    fields = [rule.get("rule_id"), rule.get("type"), rule.get("label"), rule.get("label_az"), rule.get("category")]
    keywords = (rule.get("detection") or {}).get("keyword_groups") or {}
    for values in keywords.values():
        fields.extend(values or [])
    return _normalize(" ".join(str(item or "") for item in fields))


def _normalize(value: str) -> str:
    return " ".join(str(value or "").casefold().split())


def _active_or_builtin_path() -> Path:
    return ACTIVE_PATH if ACTIVE_PATH.exists() else BUILT_IN_CATALOG_PATH


def _try_load_active() -> dict[str, Any] | None:
    try:
        return _load_catalog_from_path(_active_or_builtin_path())
    except Exception:
        return None


def _enforce_catalog_size(catalog: dict[str, Any]) -> None:
    size = len(json.dumps(catalog, ensure_ascii=False).encode("utf-8"))
    if size > MAX_CATALOG_BYTES:
        raise ValueError(f"NIST catalog payload exceeds {MAX_CATALOG_BYTES} bytes")


def _pending_path(catalog_hash: str) -> Path:
    return STATE_DIR / f"nist_sp800_60_enterprise.pending.{_safe_hash(catalog_hash)}.json"


def _safe_hash(value: str) -> str:
    cleaned = "".join(ch for ch in str(value or "") if ch in "0123456789abcdefABCDEF").lower()
    if len(cleaned) != 64:
        raise ValueError("catalog_hash must be a SHA-256 hex digest")
    return cleaned


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)


def _invalidate_cache() -> None:
    global _identity
    with _lock:
        _cache.update({"path": "", "mtime_ns": -1, "catalog": None, "status": None})
        _identity = None


def _append_audit(action: str, detail: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    row = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action, "detail": detail}
    with _lock:
        with AUDIT_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _safe_error(exc: Exception) -> str:
    return str(exc or "")[:500]
