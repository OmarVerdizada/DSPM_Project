"""Versioned schema migrations (roadmap Phase 2, DB-05).

Replaces anonymous startup DDL with a recorded, ordered revision history:

- ``schema_migrations`` records every applied revision (number, name, source
  checksum, applied_at). The checksum makes silent edits to an already-applied
  revision detectable instead of quietly divergent.
- Revisions are Python callables applied in order inside the standard
  transaction-per-connection seam. PostgreSQL applications serialize on an
  advisory lock so concurrent starters cannot race the same revision.
- ``upgrade()`` (dev) converges; ``verify_or_raise()`` (production) refuses to
  serve on a schema that is behind or ahead of this build - DDL in production
  happens only through an operator-run ``python -m backend.migrations upgrade``.

Revision 0001 is the factored-out legacy baseline (store.apply_baseline_schema),
so a fresh database built through migrations is byte-for-byte the schema the
product has always built. New DDL lands here as numbered revisions - never in
store.init_db - using expand/contract discipline (additive first, backfill,
contract in a later release).
"""

from __future__ import annotations

import hashlib
import inspect
import os
import sys
from datetime import datetime, timezone

# One stable, project-specific advisory lock key (PostgreSQL only).
_ADVISORY_LOCK_KEY = 0x53454E54  # "SENT"


def _revisions() -> list[tuple[int, str, object]]:
    """Ordered (number, name, callable) revisions. Append-only by design.
    Phase 4 (integrity constraints, RLS/roles) lands here as 0002+."""
    from backend import store

    return [
        (1, "baseline_convergent_schema", store.apply_baseline_schema),
        (2, "saved_scan_labels", store.add_scan_report_labels),
        (3, "tenant_referential_integrity", store.add_tenant_integrity),
        (4, "tenant_row_level_security", store.add_tenant_rls),
        (5, "report_artifact_references", store.add_report_artifact_refs),
        (6, "tenant_rls_unscoped_guard", store.repair_tenant_rls_predicate),
    ]


def expected_revision() -> int:
    return _revisions()[-1][0]


def _checksum(func) -> str:
    try:
        source = inspect.getsource(func)
    except OSError:  # pragma: no cover - frozen/packed environments
        source = getattr(func, "__name__", "unknown")
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _ensure_table(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            revision INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );
        """
    )


def _table_exists(conn) -> bool:
    from backend import db

    if db.is_postgres():
        row = conn.execute("SELECT to_regclass('schema_migrations') AS t").fetchone()
        return row is not None and row["t"] is not None
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    return row is not None


def current_revision(conn) -> int:
    """Highest recorded revision; 0 for a database with no history. Pure
    read - the production verify gate runs as the runtime role, which must
    not need (or get) DDL privileges."""
    if not _table_exists(conn):
        return 0
    row = conn.execute("SELECT MAX(revision) AS r FROM schema_migrations").fetchone()
    return int(row["r"] or 0) if row and row["r"] is not None else 0


def status() -> dict:
    from backend import store, db

    with store._connect() as conn:
        applied = current_revision(conn)
    return {
        "backend": db.backend_name(),
        "applied_revision": applied,
        "expected_revision": expected_revision(),
        "pending": [
            {"revision": number, "name": name}
            for number, name, _ in _revisions() if number > applied
        ],
    }


def upgrade() -> int:
    """Apply pending revisions in order. Returns the resulting revision."""
    from backend import store, db

    with store._lock:
        with store._connect() as conn:
            if db.is_postgres():
                # Serialize concurrent starters/deployers cluster-wide.
                conn.execute("SELECT pg_advisory_lock(?)", (_ADVISORY_LOCK_KEY,))
            try:
                _ensure_table(conn)
                applied = current_revision(conn)
                for number, name, func in _revisions():
                    if number <= applied:
                        continue
                    func(conn)
                    conn.execute(
                        "INSERT INTO schema_migrations (revision, name, checksum, applied_at) "
                        "VALUES (?, ?, ?, ?)",
                        (number, name, _checksum(func), datetime.now(timezone.utc).isoformat()),
                    )
                    applied = number
                return applied
            finally:
                if db.is_postgres():
                    conn.execute("SELECT pg_advisory_unlock(?)", (_ADVISORY_LOCK_KEY,))


def verify_or_raise() -> None:
    """Production startup gate: schema must match this build exactly."""
    from backend import store

    with store._connect() as conn:
        applied = current_revision(conn)
    expected = expected_revision()
    if applied < expected:
        raise RuntimeError(
            f"Refusing to serve: database schema is at revision {applied}, this build "
            f"expects {expected}. Run `python -m backend.migrations upgrade` as the "
            "migration role, then restart (roadmap Phase 2, DB-05)."
        )
    if applied > expected:
        raise RuntimeError(
            f"Refusing to serve: database schema revision {applied} is NEWER than this "
            f"build's {expected}. Deploy the matching application version."
        )


def stamp(revision: int) -> None:
    """Record revisions as applied WITHOUT running them - for adopting an
    existing database whose schema was built by the legacy startup path."""
    from backend import store

    with store._connect() as conn:
        _ensure_table(conn)
        applied = current_revision(conn)
        for number, name, func in _revisions():
            if applied < number <= revision:
                conn.execute(
                    "INSERT INTO schema_migrations (revision, name, checksum, applied_at) "
                    "VALUES (?, ?, ?, ?)",
                    (number, f"{name} (stamped)", _checksum(func),
                     datetime.now(timezone.utc).isoformat()),
                )


def main(argv: list[str]) -> int:
    command = argv[0] if argv else "status"
    if command == "status":
        info = status()
        print(f"backend:  {info['backend']}")
        print(f"applied:  {info['applied_revision']}")
        print(f"expected: {info['expected_revision']}")
        for item in info["pending"]:
            print(f"pending:  {item['revision']:04d} {item['name']}")
        return 0
    if command == "upgrade":
        final = upgrade()
        print(f"schema at revision {final}")
        return 0
    if command == "stamp":
        target = int(argv[1]) if len(argv) > 1 else expected_revision()
        stamp(target)
        print(f"stamped through revision {target}")
        return 0
    print("usage: python -m backend.migrations [status|upgrade|stamp [N]]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    # Importing backend.store runs the startup schema policy, which in
    # production refuses to serve an unmigrated database - the exact state
    # this CLI exists to fix. Flag the bootstrap so the import stays inert
    # and the chosen command drives the migration explicitly.
    os.environ["DSPM_MIGRATIONS_CLI"] = "1"
    raise SystemExit(main(sys.argv[1:]))
