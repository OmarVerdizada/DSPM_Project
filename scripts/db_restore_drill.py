"""Timed restore drill (roadmap Phase 1, DB-02): prove the backup restores.

Restores the newest encrypted backup into a scratch database on the same
cluster, reconciles per-table row counts against the manifest captured at
dump time, restores and reconciles the artifact tier (Phase 5: report bodies
live outside the database, so a database-only drill would prove the wrong
thing), times every stage, and writes a sanitized evidence artifact (counts,
hashes, durations - no credentials, no data).

Usage (admin DSN via env, never on the command line):
    set DSPM_DB_URL=...app dsn...            # source identity for the report
    set DSPM_PG_ADMIN_URL=...superuser dsn...
    python scripts/db_restore_drill.py [--evidence-dir docs/database/evidence]

The drill database is created fresh and DROPPED afterwards.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import backup  # noqa: E402


def _run(cmd: list[str], timeout: int = 3600) -> subprocess.CompletedProcess:
    completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError(f"{Path(cmd[0]).name} failed: {completed.stderr.strip()[:500]}")
    return completed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", default="docs/database/evidence")
    parser.add_argument("--keep-drill-db", action="store_true",
                        help="Leave the drill database in place for inspection.")
    args = parser.parse_args()

    admin_dsn = os.getenv("DSPM_PG_ADMIN_URL", "").strip()
    if not admin_dsn:
        print("DSPM_PG_ADMIN_URL is required (a role able to CREATE DATABASE).", file=sys.stderr)
        return 2

    manifests = backup.list_manifests()
    if not manifests:
        print("No backup manifests found - run scripts/db_backup.py first.", file=sys.stderr)
        return 2
    manifest_path = manifests[-1]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    encrypted = manifest_path.parent / manifest["file"]

    import psycopg

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    drill_db = f"sentro_restore_drill_{stamp.lower()}"
    timings: dict[str, float] = {}
    overall_start = time.perf_counter()

    # 1. Decrypt and verify integrity against the manifest hash.
    t0 = time.perf_counter()
    plain = manifest_path.parent / (manifest["file"] + ".drill.tmp")
    try:
        plain_sha = backup.decrypt_file(encrypted, plain)
        timings["decrypt_seconds"] = round(time.perf_counter() - t0, 3)
        integrity_ok = plain_sha == manifest["plaintext_sha256"]

        # 2. Create the drill database and restore into it.
        t0 = time.perf_counter()
        with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=15) as admin:
            admin.execute(f'CREATE DATABASE "{drill_db}"')
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        drill_parts = conninfo_to_dict(admin_dsn)
        drill_parts["dbname"] = drill_db
        drill_dsn = make_conninfo(**drill_parts)
        _run([backup._pg_bin("pg_restore"), "--no-password", "--no-owner",
              f"--dbname={drill_dsn}", str(plain)])
        timings["restore_seconds"] = round(time.perf_counter() - t0, 3)

        # 3. Reconcile per-table counts against dump-time truth.
        t0 = time.perf_counter()
        restored_counts = backup.capture_table_counts(drill_dsn)
        expected = {k: int(v) for k, v in manifest["table_counts"].items()}
        mismatches = {
            table: {"expected": expected.get(table), "restored": restored_counts.get(table)}
            for table in set(expected) | set(restored_counts)
            if expected.get(table) != restored_counts.get(table)
        }
        timings["reconcile_seconds"] = round(time.perf_counter() - t0, 3)

        # 4. Restore the artifact tier and reconcile it against the manifest.
        # A restore that brings back rows referencing bodies that did not come
        # back is not a recovery, so this is a drill failure, not a warning.
        t0 = time.perf_counter()
        expected_artifacts = manifest.get("artifacts") or {}
        artifact_result: dict = {"expected": expected_artifacts.get("objects", 0)}
        archive_name = expected_artifacts.get("file")
        if archive_name:
            with tempfile.TemporaryDirectory(prefix="sentro-artifact-drill-") as scratch:
                restored = backup.restore_artifacts(
                    manifest_path.parent / str(archive_name), Path(scratch)
                )
            artifact_result["restored"] = restored["objects"]
            artifact_result["inventory_match"] = (
                restored["inventory_sha256"] == expected_artifacts.get("inventory_sha256")
            )
        else:
            artifact_result["restored"] = 0
            artifact_result["inventory_match"] = expected_artifacts.get("objects", 0) == 0
        artifacts_ok = (
            artifact_result["restored"] == artifact_result["expected"]
            and artifact_result["inventory_match"]
        )
        timings["artifact_restore_seconds"] = round(time.perf_counter() - t0, 3)
    finally:
        plain.unlink(missing_ok=True)
        if not args.keep_drill_db:
            try:
                with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=15) as admin:
                    admin.execute(f'DROP DATABASE IF EXISTS "{drill_db}" WITH (FORCE)')
            except Exception as exc:  # pragma: no cover
                print(f"warning: drill DB cleanup failed: {type(exc).__name__}", file=sys.stderr)

    total = round(time.perf_counter() - overall_start, 3)
    evidence = {
        "drill_at": datetime.now(timezone.utc).isoformat(),
        "backup_manifest": manifest_path.name,
        "backup_created_at": manifest["created_at"],
        "integrity_sha256_match": integrity_ok,
        "tables_expected": len(manifest["table_counts"]),
        "rows_expected": sum(int(v) for v in manifest["table_counts"].values()),
        "count_mismatches": mismatches,
        "artifacts": artifact_result,
        "timings": {**timings, "total_seconds": total},
        "result": "PASS" if integrity_ok and not mismatches and artifacts_ok else "FAIL",
    }
    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out = evidence_dir / f"restore_drill_{stamp}.json"
    out.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    print(f"\nevidence: {out}")
    return 0 if evidence["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
