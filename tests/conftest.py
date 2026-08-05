"""Pytest configuration for the test suite.

Per-test isolation on PostgreSQL
--------------------------------
The SQLite suite isolates each test by pointing ``store.DB_PATH`` at a fresh temp
file, so every test starts from an empty database. On PostgreSQL (``DSPM_DB_URL``
set) there is a single shared database and that file trick is a no-op, so tests
would otherwise bleed state into each other (a prior test's "latest scan", a
duplicate tenant PK, etc.).

This autouse fixture restores the clean-slate-per-test guarantee on Postgres by
truncating the application tables and re-seeding the two baseline rows the app
creates at startup and that many tests assume exist: the ``default`` tenant and
the built-in ``admin`` user (tests authenticate with ``create_token('admin', …)``,
which only needs the user row to be present). It is a strict **no-op on SQLite**,
so the default suite behaves exactly as before.

The admin password hash is computed once (PBKDF2 is deliberately slow; hashing it
per test would dominate the run) and the baseline is re-seeded with direct inserts
rather than a full ``init_db`` - the schema already exists, only the rows are gone.

To run the whole suite on Postgres:
    export DSPM_DB_URL='postgresql://sentro_app:<pw>@127.0.0.1:5432/sentro_dev'
    python -m pytest tests/ -q
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from backend import db


def pytest_configure(config: pytest.Config) -> None:
    """Fail fast rather than reset a possibly-production database.

    The per-test fixture TRUNCATEs the target Postgres database. A persistent
    install points DSPM_DB_URL at the real store, so running the suite with that
    env inherited would wipe it. Require an explicit DSPM_PG_TEST_RESET=1 opt-in
    to run the destructive suite against Postgres; otherwise abort before any
    test (or fixture) runs. SQLite is always fine (its isolation is a temp file)."""
    if db.is_postgres() and os.getenv("DSPM_PG_TEST_RESET") != "1":
        pytest.exit(
            "DSPM_DB_URL selects PostgreSQL, but this suite RESETS (truncates) the "
            "target database for per-test isolation. Refusing to run against a "
            "possibly-production DB. Set DSPM_PG_TEST_RESET=1 to allow (use a "
            "dedicated test database!), or unset DSPM_DB_URL to run on SQLite.",
            returncode=2,
        )

# Every application table (single TRUNCATE; there are no FK constraints between
# them). RESTART IDENTITY resets the audit_events / alert_events IDENTITY
# sequences so per-test id-ordering assertions are deterministic.
_APP_TABLES = (
    "finding_index", "finding_occurrences", "findings", "asset_versions",
    "assets", "scan_runs", "scan_jobs", "alert_events", "audit_events",
    "secrets", "scan_reports", "registration_invites", "api_keys",
    "login_failures", "revoked_tokens", "users", "tenants",
)

_admin_hash: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(autouse=True)
def _isolate_db_state():
    """Give each test a clean, baseline-seeded database on Postgres (no-op on SQLite)."""
    # pytest_configure has already aborted the session if this is Postgres without
    # the explicit reset opt-in; the flag check here is belt-and-suspenders.
    if not db.is_postgres() or os.getenv("DSPM_PG_TEST_RESET") != "1":
        yield
        return

    global _admin_hash
    from backend import store

    if _admin_hash is None:
        from backend.security import hash_password
        _admin_hash = hash_password("ConftestDevAdmin1")  # letters+digits (strength check)

    with store._connect() as conn:
        conn.execute("TRUNCATE TABLE " + ", ".join(_APP_TABLES) + " RESTART IDENTITY CASCADE")
        now = _now()
        conn.execute(
            "INSERT INTO tenants (tenant_id, display_name, registration_code, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("default", "Default", store.generate_registration_code(), now, now),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, role, tenant_id, full_name, is_active, created_at, updated_at) "
            "VALUES (?, ?, 'admin', 'default', 'Local Administrator', 1, ?, ?)",
            ("admin", _admin_hash, now, now),
        )
    yield
