"""Versioned schema migrations (roadmap Phase 2, DB-05).

Replaces anonymous startup DDL with a recorded, ordered revision history:

- ``schema_migrations`` records every applied revision (number, name, source
  checksum, applied_at). The checksum is a forensic record of *which source*
  built this database, comparable via ``checksum_drift()``. It is reported,
  not enforced: every revision here is idempotent DDL (``IF NOT EXISTS`` and
  catalog checks) over a deliberately convergent baseline, so its source is
  expected to evolve - revision 0001 gains the columns that later revisions
  ALTER in, and 0006 re-runs 0004 on purpose. Drift means "this database was
  built by an older source", which is normal for convergent revisions and
  worth investigating for a revision that performs a one-way data change.
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
        (7, "tenant_legal_hold", store.add_legal_hold),
        (8, "inventory_filtered_search_scale_index", store.add_inventory_filtered_search_index),
        (9, "remediation_operational_index", store.add_remediation_operational_index),
        (10, "remediation_filter_indexes", store.add_remediation_filter_indexes),
        (11, "scan_partition_ledger", store.add_scan_partition_ledger),
        (12, "scan_partition_records", store.add_scan_partition_records),
        (13, "partition_write_indexes", store.add_partition_write_indexes),
        (14, "partitioned_scan_ledger", store.add_partitioned_scan_ledger),
        (15, "scan_schedules", store.add_scan_schedules),
        (16, "finding_suppression_rules", store.add_suppression_rules),
        (17, "derived_cache", store.add_derived_cache),
        (18, "durable_user_sessions", store.add_user_sessions),
        (19, "rotating_refresh_tokens", store.add_refresh_tokens),
        (20, "open_role_catalogue", store.open_role_catalogue),
        (21, "custom_roles", store.add_custom_roles),
        (22, "audit_chain", store.add_audit_chain),
        (23, "audit_outbox", store.add_audit_outbox),
        (24, "scan_targets", store.add_scan_targets),
        (25, "deny_unscoped_tenant_access", store.deny_unscoped_tenant_access),
        (26, "tenant_scoped_identities", store.add_tenant_scoped_identities),
    (27, "vault_key_lifecycle", store.add_vault_key_lifecycle),
    (28, "scan_sources", store.add_scan_sources),
    (29, "classify_directory_secrets", store.classify_directory_secrets),
    (30, "admit_whole_database_backup", store.admit_whole_database_backup),
    (31, "asset_access", store.add_asset_access),
    (32, "exact_data_match", store.add_exact_data_match),
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


def checksum_drift(conn) -> list[dict]:
    """Applied revisions whose source no longer matches what was recorded.

    Answers "was this database built by the source that is here now?" - a
    question worth being able to ask when diagnosing an install, and one the
    recorded checksum could not previously answer because nothing compared it.

    **Informational, not an alarm.** Every revision in this project is
    idempotent DDL layered on a convergent baseline, so drift is the normal
    result of a later revision adding columns that revision 0001 now creates
    directly. It is a signal to read, not a fault: `python -m backend.migrations
    status --strict` exits non-zero on drift for anyone who wants it enforced,
    and the metrics payload reports it as data rather than as a warning.

    A revision that performs a **one-way data change** is the case where drift
    does matter, because that step cannot re-converge. Such a revision should
    say so in its docstring.
    """
    if not _table_exists(conn):
        return []
    recorded = {
        int(row["revision"]): (str(row["name"]), str(row["checksum"]))
        for row in conn.execute(
            "SELECT revision, name, checksum FROM schema_migrations"
        ).fetchall()
    }
    drift: list[dict] = []
    for number, name, func in _revisions():
        if number not in recorded:
            continue
        applied_name, applied_checksum = recorded[number]
        # A stamped revision was never executed, so its source was never the
        # thing that built the schema; comparing it would be meaningless.
        if applied_name.endswith("(stamped)"):
            continue
        current = _checksum(func)
        if current != applied_checksum:
            drift.append({
                "revision": number,
                "name": name,
                "applied_checksum": applied_checksum[:12],
                "current_checksum": current[:12],
            })
    return drift


def status() -> dict:
    from backend import store, db

    with store._connect() as conn:
        applied = current_revision(conn)
        drift = checksum_drift(conn)
    return {
        "backend": db.backend_name(),
        "applied_revision": applied,
        "expected_revision": expected_revision(),
        "pending": [
            {"revision": number, "name": name}
            for number, name, _ in _revisions() if number > applied
        ],
        "checksum_drift": drift,
    }


def upgrade() -> int:
    """Apply pending revisions in order. Returns the resulting revision."""
    from backend import store, db

    # C10: revisions span tenants (backfills, re-sealing, policy rebuilds), so the
    # runner names its purpose; an unscoped transaction would see no tenant rows.
    with store._lock, db.platform_scope("migration"):
        with store._connect() as conn:
            if db.is_postgres():
                # Serialize concurrent starters/deployers cluster-wide - for exactly the
                # length of this transaction. C0.5 (2026-09-25): this was a SESSION lock
                # released in a `finally`. When a revision failed, that unlock ran inside
                # the aborted transaction and raised "current transaction is aborted",
                # which replaced the real error; and the lock stayed held by the pooled
                # connection, so the next upgrade from any other connection waited on it
                # forever. A transaction lock ends with the commit or the rollback.
                conn.execute("SELECT pg_advisory_xact_lock(?)", (_ADVISORY_LOCK_KEY,))
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
        for item in info["checksum_drift"]:
            print(f"drift:    {item['revision']:04d} {item['name']} "
                  f"(applied {item['applied_checksum']}, source now "
                  f"{item['current_checksum']}) - expected for convergent revisions")
        if info["checksum_drift"] and "--strict" in argv:
            return 1
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
    print("usage: python -m backend.migrations [status [--strict]|upgrade|stamp [N]]",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    # Importing backend.store runs the startup schema policy, which in
    # production refuses to serve an unmigrated database - the exact state
    # this CLI exists to fix. Flag the bootstrap so the import stays inert
    # and the chosen command drives the migration explicitly.
    os.environ["DSPM_MIGRATIONS_CLI"] = "1"
    raise SystemExit(main(sys.argv[1:]))
