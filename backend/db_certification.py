"""Phase 7 database certification and evidence-package primitives.

The roadmap's regulated/high-scale tier is an evidence problem as much as a
code problem.  This module keeps the contract profile, live control snapshot,
artifact validation and package manifest in one testable place.  It never
accepts a DSN or secret as input and never records query text or tenant data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROFILE_VERSION = 1
PACKAGE_VERSION = 1
_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def load_profile(path: Path) -> dict:
    """Load and validate the operator-approved Phase 7 contract profile."""
    profile = json.loads(Path(path).read_text(encoding="utf-8"))
    if int(profile.get("profile_version") or 0) != PROFILE_VERSION:
        raise ValueError(f"profile_version must be {PROFILE_VERSION}")
    if not str(profile.get("name") or "").strip():
        raise ValueError("profile name is required")

    projection = profile.get("projection") or {}
    for key in ("documents", "concurrent_workers", "soak_seconds", "query_p95_ms", "lock_timeout_ms"):
        if float(projection.get(key) or 0) <= 0:
            raise ValueError(f"projection.{key} must be positive")

    database = profile.get("database") or {}
    if int(database.get("approved_major") or 0) <= 0:
        raise ValueError("database.approved_major must be positive")
    if not _VERSION_RE.match(str(database.get("minimum_version") or "")):
        raise ValueError("database.minimum_version must be a PostgreSQL version")
    _parse_time(database.get("patch_baseline_reviewed_at"), "database.patch_baseline_reviewed_at")
    if int(database.get("patch_review_max_age_days") or 0) <= 0:
        raise ValueError("database.patch_review_max_age_days must be positive")

    for section_name in ("regional_recovery", "activity_monitoring"):
        section = profile.get(section_name) or {}
        if not isinstance(section.get("required"), bool):
            raise ValueError(f"{section_name}.required must be true or false")
        if not section["required"] and not str(section.get("reason") or "").strip():
            raise ValueError(f"{section_name}.reason is required when the control is not applicable")
    regional = profile["regional_recovery"]
    if regional["required"] and int(regional.get("minimum_synchronous_standbys") or 0) <= 0:
        raise ValueError(
            "regional_recovery.minimum_synchronous_standbys must be positive when required"
        )

    ages = profile.get("evidence_max_age_days") or {}
    for category in required_evidence_categories():
        if int(ages.get(category) or 0) <= 0:
            raise ValueError(f"evidence_max_age_days.{category} must be positive")
    return profile


def required_evidence_categories() -> tuple[str, ...]:
    return (
        "backup_success",
        "restore_result",
        "access_review",
        "retention_run",
        "schema_changes",
        "patch_compliance",
        "capacity_soak",
        "corruption_game_day",
        "regional_recovery",
        "activity_monitoring",
    )


def _parse_time(value: Any, label: str = "timestamp") -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = _VERSION_RE.match(str(value or ""))
    if not match:
        return (0, 0, 0)
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def migration_history() -> list[dict]:
    """Recorded schema history, with no DDL text or connection information."""
    from backend import store

    with store._connect() as conn:
        rows = conn.execute(
            "SELECT revision, name, checksum, applied_at "
            "FROM schema_migrations ORDER BY revision"
        ).fetchall()
    return [
        {
            "revision": int(row["revision"]),
            "name": str(row["name"]),
            "checksum": str(row["checksum"]),
            "applied_at": str(row["applied_at"]),
        }
        for row in rows
    ]


def server_version() -> str:
    from backend import store

    with store._connect() as conn:
        row = conn.execute("SHOW server_version").fetchone()
    return str(row[0])


def collect_control_snapshot(profile: dict, *, now: datetime | None = None) -> dict:
    """Collect schema, patch, topology and activity-monitoring control proof."""
    from backend import db, migrations, observability

    captured = now or utc_now()
    if not db.is_postgres():
        return {
            "evidence_kind": "db_control_snapshot",
            "generated_at": _iso(captured),
            "result": "FAIL",
            "reason": "Phase 7 certification requires PostgreSQL",
        }

    schema = observability.schema_metrics()
    history = migration_history()
    # This repository's deliberately convergent/idempotent revisions make
    # checksum drift informational (roadmap section 0.4b).  The serving gate is
    # the applied revision; the snapshot still preserves drift for review.
    schema_ok = schema.get("applied") == migrations.expected_revision()
    schema_control = {
        **schema,
        "history": history,
        "result": "PASS" if schema_ok else "FAIL",
    }

    installed = server_version()
    policy = profile["database"]
    reviewed_at = _parse_time(policy["patch_baseline_reviewed_at"])
    review_age_days = max(0.0, (captured - reviewed_at).total_seconds() / 86_400)
    version_ok = (
        _version_tuple(installed) >= _version_tuple(str(policy["minimum_version"]))
        and _version_tuple(installed)[0] == int(policy["approved_major"])
    )
    patch_ok = version_ok and review_age_days <= int(policy["patch_review_max_age_days"])
    patch_control = {
        "installed_version": installed,
        "approved_major": int(policy["approved_major"]),
        "minimum_version": str(policy["minimum_version"]),
        "baseline_reviewed_at": _iso(reviewed_at),
        "review_age_days": round(review_age_days, 3),
        "review_max_age_days": int(policy["patch_review_max_age_days"]),
        "result": "PASS" if patch_ok else "FAIL",
    }

    topology = observability.replication_metrics()
    regional_policy = profile["regional_recovery"]
    if regional_policy["required"]:
        synchronous = sum(
            1
            for standby in topology.get("standbys") or []
            if standby.get("state") == "streaming"
            and standby.get("sync_state") in {"sync", "quorum"}
        )
        regional_ok = synchronous >= int(regional_policy["minimum_synchronous_standbys"])
        regional_control = {
            "required": True,
            "minimum_synchronous_standbys": int(regional_policy["minimum_synchronous_standbys"]),
            "synchronous_streaming_standbys": synchronous,
            "topology": topology,
            "result": "PASS" if regional_ok else "FAIL",
        }
    else:
        regional_ok = True
        regional_control = {
            "required": False,
            "reason": str(regional_policy["reason"]),
            "observed_topology": topology,
            "result": "NOT_APPLICABLE",
        }

    activity = observability.database_activity_monitoring()
    activity_policy = profile["activity_monitoring"]
    if activity_policy["required"]:
        activity_ok = bool(activity.get("applicable") and activity.get("enabled"))
        activity_control = {
            "required": True,
            "snapshot": activity,
            "result": "PASS" if activity_ok else "FAIL",
        }
    else:
        activity_ok = True
        activity_control = {
            "required": False,
            "reason": str(activity_policy["reason"]),
            "snapshot": activity,
            "result": "NOT_APPLICABLE",
        }

    overall = schema_ok and patch_ok and regional_ok and activity_ok
    return {
        "evidence_kind": "db_control_snapshot",
        "generated_at": _iso(captured),
        "profile": str(profile["name"]),
        "database_identity": db.database_identity(),
        "schema_changes": schema_control,
        "patch_compliance": patch_control,
        "regional_recovery": regional_control,
        "activity_monitoring": activity_control,
        "result": "PASS" if overall else "FAIL",
    }


def write_evidence(evidence_dir: Path, prefix: str, payload: dict) -> Path:
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stamp = _parse_time(payload.get("generated_at") or utc_now()).strftime("%Y%m%dT%H%M%SZ")
    destination = evidence_dir / f"{prefix}_{stamp}.json"
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_backup_manifest(path: Path) -> dict:
    """Verify the newest backup set without decrypting or recording its DSN."""
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    failures: list[str] = []
    payload = Path(path).parent / str(manifest.get("file") or "")
    if not payload.is_file():
        failures.append("encrypted database payload is missing")
    elif sha256_file(payload) != str(manifest.get("ciphertext_sha256") or ""):
        failures.append("database ciphertext SHA-256 mismatch")

    artifact = manifest.get("artifacts") or {}
    artifact_file = artifact.get("file")
    if artifact_file:
        archive = Path(path).parent / str(artifact_file)
        if not archive.is_file():
            failures.append("encrypted artifact archive is missing")
        elif sha256_file(archive) != str(artifact.get("archive_sha256") or ""):
            failures.append("artifact archive SHA-256 mismatch")
    elif int(artifact.get("objects") or 0):
        failures.append("artifact archive is absent despite a non-zero object count")
    return {
        "manifest": Path(path).name,
        "created_at": str(manifest.get("created_at") or ""),
        "failures": failures,
        "result": "PASS" if not failures else "FAIL",
    }


def _newest(directory: Path, pattern: str) -> Path | None:
    matches = list(Path(directory).glob(pattern)) if Path(directory).exists() else []
    if not matches:
        return None

    def evidence_time(path: Path) -> float:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            value = (
                payload.get("generated_at")
                or payload.get("drill_at")
                or payload.get("applied_at")
                or payload.get("run_at")
                or payload.get("created_at")
            )
            return _parse_time(value).timestamp()
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return path.stat().st_mtime

    return max(matches, key=evidence_time)


def _load_result(path: Path, block: str | None = None) -> tuple[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    selected = payload.get(block) if block else payload
    if not isinstance(selected, dict):
        return "FAIL", ""
    return str(selected.get("result") or "FAIL"), str(
        payload.get("generated_at")
        or payload.get("drill_at")
        or payload.get("applied_at")
        or payload.get("run_at")
        or ""
    )


def build_evidence_package(
    profile: dict,
    evidence_dir: Path,
    backup_directory: Path,
    output: Path,
    *,
    now: datetime | None = None,
) -> dict:
    """Build a hash-manifested ZIP and fail closed on missing/stale/failed proof."""
    captured = now or utc_now()
    evidence_dir = Path(evidence_dir)
    backup_directory = Path(backup_directory)
    controls = _newest(evidence_dir, "db_controls_*.json")
    specs: dict[str, tuple[Path | None, str | None]] = {
        "restore_result": (_newest(evidence_dir, "restore_drill_*.json"), None),
        "access_review": (_newest(evidence_dir, "db_roles_*.json"), None),
        "retention_run": (_newest(evidence_dir, "retention_*.json"), None),
        "schema_changes": (controls, "schema_changes"),
        "patch_compliance": (controls, "patch_compliance"),
        "capacity_soak": (_newest(evidence_dir, "capacity_soak_*.json"), None),
        "corruption_game_day": (_newest(evidence_dir, "corruption_game_day_*.json"), None),
        "regional_recovery": (controls, "regional_recovery"),
        "activity_monitoring": (controls, "activity_monitoring"),
    }
    entries: list[dict] = []
    source_files: set[Path] = set()
    failures: list[str] = []

    backup_manifest = _newest(backup_directory, "*.manifest.json")
    if backup_manifest is None:
        entries.append({"category": "backup_success", "result": "MISSING"})
        failures.append("backup_success: evidence missing")
    else:
        validation = validate_backup_manifest(backup_manifest)
        created_at = validation["created_at"]
        entry = {
            "category": "backup_success",
            "source": backup_manifest.name,
            "sha256": sha256_file(backup_manifest),
            "generated_at": created_at,
            "result": validation["result"],
            "validation_failures": validation["failures"],
        }
        entries.append(entry)
        source_files.add(backup_manifest)
        if validation["result"] != "PASS":
            failures.append("backup_success: backup-set validation failed")
        _check_freshness(entry, profile, captured, failures)

    for category, (path, block) in specs.items():
        if path is None:
            entries.append({"category": category, "result": "MISSING"})
            failures.append(f"{category}: evidence missing")
            continue
        result, generated_at = _load_result(path, block)
        entry = {
            "category": category,
            "source": path.name,
            "sha256": sha256_file(path),
            "generated_at": generated_at,
            "result": result,
        }
        entries.append(entry)
        source_files.add(path)
        if result not in {"PASS", "NOT_APPLICABLE"}:
            failures.append(f"{category}: result is {result}")
        _check_freshness(entry, profile, captured, failures)

    manifest: dict[str, Any] = {
        "package_version": PACKAGE_VERSION,
        "generated_at": _iso(captured),
        "profile": str(profile["name"]),
        "categories": entries,
        "failures": failures,
        "result": "PASS" if not failures else "FAIL",
    }
    signing_key = os.getenv("DSPM_DB_EVIDENCE_SIGNING_KEY", "").encode("utf-8")
    unsigned = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["integrity"] = {
        "manifest_sha256": hashlib.sha256(unsigned).hexdigest(),
        "hmac_sha256": hmac.new(signing_key, unsigned, hashlib.sha256).hexdigest()
        if signing_key
        else None,
        "signed": bool(signing_key),
    }

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        archive.writestr("profile.json", json.dumps(profile, indent=2, sort_keys=True) + "\n")
        for source in sorted(source_files, key=lambda item: item.name):
            archive.write(source, f"evidence/{source.name}")
    manifest["package"] = str(output)
    return manifest


def _check_freshness(
    entry: dict,
    profile: dict,
    captured: datetime,
    failures: list[str],
) -> None:
    category = str(entry["category"])
    try:
        generated = _parse_time(entry.get("generated_at"), f"{category}.generated_at")
    except ValueError as exc:
        failures.append(str(exc))
        return
    age_days = max(0.0, (captured - generated).total_seconds() / 86_400)
    entry["age_days"] = round(age_days, 3)
    maximum = int(profile["evidence_max_age_days"][category])
    entry["max_age_days"] = maximum
    if age_days > maximum:
        failures.append(f"{category}: evidence is {age_days:.1f}d old (maximum {maximum}d)")
