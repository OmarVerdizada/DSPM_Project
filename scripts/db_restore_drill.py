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
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import backup  # noqa: E402


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

    # The newest PostgreSQL set by when it was taken. The last manifest by NAME was a SQLite
    # set (sentro_sqlite_... sorts after sentro_2026...) once an install had moved.
    newest = next((item for item in backup.backup_sets() if item["data"].get("kind") == "logical"), None)
    if newest is None:
        print("No PostgreSQL backup manifests found - run scripts/db_backup.py first.", file=sys.stderr)
        return 2
    manifest_path = newest["manifest"]
    manifest = newest["data"]
    encrypted = manifest_path.parent / manifest["file"]

    import psycopg

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    drill_db = f"sentro_restore_drill_{stamp.lower()}"
    timings: dict[str, float] = {}
    overall_start = time.perf_counter()

    # 1-2. Create the drill database and restore into it. W3.5: the archive is decrypted
    # into pg_restore's standard input - no plaintext file in the backup directory or in
    # %TEMP% - and the digest of the whole plaintext is checked on the way. The admin
    # password travels in pg_restore's environment, never on its command line.
    t0 = time.perf_counter()
    scratch_artifacts: Path | None = None
    try:
        with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=15) as admin:
            admin.execute(f'CREATE DATABASE "{drill_db}"')
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        drill_parts = conninfo_to_dict(admin_dsn)
        drill_parts["dbname"] = drill_db
        drill_dsn = make_conninfo(**drill_parts)
        drill_conninfo, drill_env = backup.pg_tool_environment(drill_dsn)
        restored_db = backup._pipe_plaintext(
            encrypted, [backup._pg_bin("pg_restore"), "--no-password", "--no-owner", f"--dbname={drill_conninfo}"],
            drill_env, timeout=3600)
        if restored_db["returncode"] != 0:
            raise RuntimeError(f"pg_restore failed: {restored_db['stderr'].strip()[:500]}")
        integrity_ok = restored_db["plaintext_sha256"] == manifest["plaintext_sha256"]
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
        if expected_artifacts.get("file") or expected_artifacts.get("format") == backup.OBJECTS_FORMAT:
            # Restored into a scratch store beside the backup directory - the objects are
            # ciphertext under the artifact key - and inventoried as the store reads them.
            scratch_artifacts = Path(tempfile.mkdtemp(prefix=backup.STAGING_PREFIX, dir=str(manifest_path.parent)))
            backup._add_artifact_objects(manifest_path, manifest, scratch_artifacts)
            names = [f"{path.parent.parent.name}/{path.name[:-len('.enc')]}"
                     for path in scratch_artifacts.glob("*/*/*.enc")]
            artifact_result["restored"] = len(names)
            artifact_result["inventory_match"] = (
                backup._names_digest(names) == expected_artifacts.get("inventory_sha256")
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
        if scratch_artifacts is not None:
            shutil.rmtree(scratch_artifacts, ignore_errors=True)
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
