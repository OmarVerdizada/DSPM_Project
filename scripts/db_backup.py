"""Create an encrypted PostgreSQL backup with a reconciliation manifest.

Usage (DSN via env, never on the command line):
    set DSPM_DB_URL=postgresql://...
    python scripts/db_backup.py [--keep 7]

See backend/backup.py for the format and key handling (Phase 1, DB-02).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import backup  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", type=int, default=7,
                        help="Backup sets to retain after this one (default 7).")
    args = parser.parse_args()

    app_dsn = os.getenv("DSPM_DB_URL", "").strip()
    if not app_dsn or not app_dsn.startswith(("postgres://", "postgresql://")):
        print("DSPM_DB_URL must point at PostgreSQL.", file=sys.stderr)
        return 2

    # Backups run as a backup-capable role (DSPM_BACKUP_DB_URL, falling back
    # to the admin URL), against the APPLICATION database from DSPM_DB_URL.
    # The runtime role deliberately cannot read every table - discovered live:
    # sentro_app lacked SELECT on scan_object_baselines (Phase 4 grant repair).
    backup_role_dsn = (os.getenv("DSPM_BACKUP_DB_URL") or os.getenv("DSPM_PG_ADMIN_URL") or "").strip()
    if backup_role_dsn:
        # Rebuild the DSN with the backup role's credentials but the APP
        # database - parsed properly so URL and keyword conninfo both work.
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        app_db = conninfo_to_dict(app_dsn).get("dbname")
        parts = conninfo_to_dict(backup_role_dsn)
        parts["dbname"] = app_db
        dsn = make_conninfo(**parts)
    else:
        dsn = app_dsn

    manifest = backup.create_logical_backup(dsn)
    removed = backup.prune_backups(keep=args.keep)
    age = backup.latest_backup_age_seconds()
    print(f"backup manifest: {manifest}")
    print(f"pruned older sets: {removed}")
    print(f"latest backup age: {age:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
