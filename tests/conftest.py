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
import pathlib
import tempfile
from contextlib import contextmanager, suppress
from datetime import datetime, timezone

import pytest

from backend import db

# The database backend.store opened when this session first imported it. pytest_configure
# records it, and tests/test_suite_isolation.py checks it was never the developer's own.
STORE_IMPORTED_WITH: pathlib.Path | None = None
# The session's own directory (its database, artifacts and keys), removed at the end.
_SESSION_ROOT: pathlib.Path | None = None


def pytest_configure(config: pytest.Config) -> None:
    """Isolate the findings cache, then fail fast rather than reset a possibly-
    production database.

    The scan cache defaults to `data/scan_cache`, which on a developer machine or
    a real install holds thousands of entries from actual scans. Without this,
    every test that builds a DSPMDiscoveryEngine read and WROTE that directory:
    a test could pass because an earlier scan had cached the answer, fail
    because a stale entry predated a detector change, and pollute the install's
    cache on the way through. A temp directory per run removes all three.

    The per-test fixture TRUNCATEs the target Postgres database. A persistent
    install points DSPM_DB_URL at the real store, so running the suite with that
    env inherited would wipe it. Require an explicit DSPM_PG_TEST_RESET=1 opt-in
    to run the destructive suite against Postgres; otherwise abort before any
    test (or fixture) runs. SQLite is always fine (its isolation is a temp file)."""
    os.environ.setdefault(
        "DSPM_SCAN_CACHE_DIR",
        str(pathlib.Path(tempfile.mkdtemp(prefix="dspm-test-scan-cache-")).resolve()),
    )
    # C8 raised the production work factor to 600,000 PBKDF2 rounds (~0.34 s a hash on
    # this host). The suite hashes hundreds of fixture passwords, and none of those
    # tests is about the work factor, so it runs at the clamp floor - faster than the
    # suite ran before C8. The tests that ARE about the work factor set it themselves.
    os.environ.setdefault("DSPM_PBKDF2_ROUNDS", "210000")

    if db.is_postgres() and os.getenv("DSPM_PG_TEST_RESET") != "1":
        pytest.exit(
            "DSPM_DB_URL selects PostgreSQL, but this suite RESETS (truncates) the "
            "target database for per-test isolation. Refusing to run against a "
            "possibly-production DB. Set DSPM_PG_TEST_RESET=1 to allow (use a "
            "dedicated test database!), or unset DSPM_DB_URL to run on SQLite.",
            returncode=2,
        )

    # SQLite: give the whole session its own throwaway database so no test can
    # ever write into the developer's real data/dspm.sqlite. Modules that
    # manage their own temp DB still do; the ambient-relying modules (they
    # create tenants like gf-*/rs-*/victim-* directly) land here instead -
    # before this, every full-suite run leaked ~40 junk tenants into the dev
    # store. Set DSPM_TEST_KEEP_DB=1 to opt out (e.g. to debug against a copy).
    if not db.is_postgres() and not os.getenv("DSPM_TEST_KEEP_DB"):
        # `tempfile` and `pathlib` are imported at module scope; a local import
        # here would make them locals for the WHOLE function and break the cache
        # isolation above with UnboundLocalError.
        from pathlib import Path as _Path
        _session_root = _Path(tempfile.mkdtemp(prefix="sentro-test-session-"))
        _session_db = _session_root / "suite.sqlite"
        global _SESSION_ROOT
        _SESSION_ROOT = _session_root
        # All of this BEFORE the store is imported. Importing backend.store
        # reads DSPM_DB_PATH and converges that database's schema on the spot
        # (ensure_schema_ready), so an import that came first migrated the
        # developer's real data/dspm.sqlite on every run - and a backend left
        # running on the older code then found its database at a revision it
        # did not know, and stopped serving the Remediation page.
        os.environ["DSPM_DB_PATH"] = str(_session_db)
        # Phase 5: scan saves now write report bodies to the artifact store.
        # Without this the suite writes real objects into data/artifacts/ -
        # the same leak the session database above fixes, one tier down.
        os.environ.setdefault("DSPM_ARTIFACT_DIR", str(_session_root / "artifacts"))
        os.environ.setdefault("DSPM_LOCAL_ARTIFACT_KEY_PATH", str(_session_root / "artifact_key"))
        from backend import store as _store
        from backend import security as _security
        global STORE_IMPORTED_WITH
        STORE_IMPORTED_WITH = _store.DB_PATH
        _store.DB_PATH = _session_db
        # Build through the versioned runner (not legacy init_db) so the suite
        # database carries recorded revisions exactly like a real install -
        # the /api/ready schema gate is tested against truth, not a stub.
        from backend import migrations as _migrations
        _migrations.upgrade()
        try:
            _store.create_tenant("default", "Default")
        except Exception:
            pass
        _security.ensure_default_admin()
    # C2: a session must prove a second factor before it may use an MFA-scoped permission
    # (tenant.admin, platform.admin, credential.manage). The suite's tests mint sessions
    # directly with create_token for every role, so here - and only here - a minted token
    # counts as MFA-verified unless the test says otherwise; production callers always
    # state it (sign-in, MFA completion, refresh), and tests/test_c2_mfa.py passes
    # mfa_verified=False to prove the gate.
    from backend import security as _minting
    _minting.create_token.__kwdefaults__["mfa_verified"] = True


def pytest_unconfigure(config: pytest.Config) -> None:
    """Remove the session directory. Found 2026-09-28: every run left its ~24 MB behind -
    687 of them, on a disk with under 4 GB free. DSPM_TEST_KEEP_DB keeps it for debugging."""
    if _SESSION_ROOT is None or os.getenv("DSPM_TEST_KEEP_DB"):
        return
    with suppress(Exception):
        db.release_sqlite_anchor()
    import shutil

    shutil.rmtree(_SESSION_ROOT, ignore_errors=True)


# Every application table (single TRUNCATE; there are no FK constraints between
# them). RESTART IDENTITY resets the audit_events / alert_events IDENTITY
# sequences so per-test id-ordering assertions are deterministic.
_APP_TABLES = (
    "finding_index", "finding_occurrences", "findings", "asset_versions",
    "scan_object_baselines", "assets", "scan_runs", "scan_partitions", "partitioned_scans", "scan_schedules", "suppression_rules", "derived_cache", "scan_jobs", "alert_events", "audit_events",
    "secrets", "scan_reports", "scan_profiles", "registration_invites", "api_keys",
    "login_failures", "revoked_tokens", "user_sessions", "refresh_tokens", "custom_roles", "scan_targets", "audit_chain_heads", "audit_outbox", "user_mfa", "directory_settings", "scan_sources", "asset_access", "edm_fingerprints", "edm_sets", "alert_deliveries", "alert_channels", "finding_tickets", "users", "tenants",
    # Install-wide settings: the SIEM receiver, feature flags, housekeeping's last run.
    "app_settings",
)

_admin_hash: str | None = None

# C10, PostgreSQL only. The policies show a transaction that names no tenant and no
# purpose nothing - which product code must never rely on, and the suite is how that
# is caught. A TEST that opens store._connect() itself to look at what was written
# reads like an operator does, as the "migration" purpose; product code gets no such
# default. These modules are about unscoped access itself, so they get none either.
_SCOPE_OPT_OUT = {"tests.test_platform_scope", "tests.test_postgres_c05", "tests.test_tenant_rls"}


def _inspector_connect(real):
    import sys

    def connect():
        caller = sys._getframe(1).f_globals.get("__name__", "")
        name = caller.rsplit(".", 1)[-1]
        if (caller.startswith("tests.") and name.startswith("test_") and caller not in _SCOPE_OPT_OUT
                and db.current_tenant_scope() is None and db.current_platform_scope() is None):
            @contextmanager
            def inspecting():
                with db.platform_scope("migration"):
                    with real() as conn:
                        yield conn
            return inspecting()
        return real()

    connect._inspector = True
    return connect


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(autouse=True)
def _isolate_db_state():
    """Clean, baseline-seeded DB per test on Postgres; on SQLite, a snapshot/restore
    safety-net around the ambient DB globals so one leaky module can't cascade."""
    # pytest_configure has already aborted the session if this is Postgres without
    # the explicit reset opt-in; the flag check here is belt-and-suspenders.
    if not db.is_postgres() or os.getenv("DSPM_PG_TEST_RESET") != "1":
        # SQLite path: per-test isolation is DIY per module (each repoints
        # store.DB_PATH at its own temp DB, and some also set DSPM_DB_PATH for
        # subprocess workers). If a module forgets to restore those in tearDown,
        # every later test that relies on the ambient default DB opens a stale or
        # deleted path and hits "no such table". Snapshot + restore both globals
        # around each test so such a leak is contained to the one offending test
        # instead of cascading through the rest of the suite.
        from backend import store
        _saved_db_path = store.DB_PATH
        _saved_db_env = os.environ.get("DSPM_DB_PATH")
        # C8: the sign-in, registration and refresh throttles key on the client
        # address, which is "testclient" for every TestClient - so without this, one
        # test's refused attempts count against the next test in the ambient database.
        # The PostgreSQL path gets the same clean slate from its TRUNCATE.
        with suppress(Exception):
            with store._connect() as conn:
                conn.execute("DELETE FROM login_failures")
                # C4: the SIEM receiver is an install-wide setting now, so one test that
                # configures it would forward every later test's audit rows.
                conn.execute("DELETE FROM app_settings WHERE key LIKE 'siem.%'")
        try:
            yield
        finally:
            store.DB_PATH = _saved_db_path
            if _saved_db_env is None:
                os.environ.pop("DSPM_DB_PATH", None)
            else:
                os.environ["DSPM_DB_PATH"] = _saved_db_env
        return

    global _admin_hash
    from backend import store

    if _admin_hash is None:
        from backend.security import hash_password
        _admin_hash = hash_password("ConftestDevAdmin1")  # letters+digits (strength check)

    from backend import db as _db

    if not getattr(store._connect, "_inspector", False):
        store._connect = _inspector_connect(store._connect)
    # C10: the seed is the default tenant's; an unscoped insert is refused by the policies.
    with _db.tenant_scope("default"), store._connect() as conn:
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
