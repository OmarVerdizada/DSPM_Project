"""Which Sentro is this, and which database does it serve? (startup diagnostics)

Found 2026-10-05: a server started on 2 October from a checkout whose migrations ended
at revision 35 kept running while the same checkout moved on to revision 43. Development
commands run from that checkout imported ``backend.store`` with no database of their
own, and the import-time upgrade of a local install upgraded the server's database
under it, eight revisions in five steps. The server then refused every sign-in - rightly
(C0.4) - with a message that named two revision numbers and nothing else.

This module answers the questions that took an investigation to answer then:

- which build is running: version, git commit when it is a checkout, and the source
  tree its code was loaded from;
- the schema revision it supports, and the one the code on disk now supports - a
  process older than its own source tree says so;
- which database it serves: SQLite's file, or PostgreSQL's host, port and database
  name - never a password or a full connection string;
- which other servers and workers serve the same database, and which build each is.
  Each registers in ``app_settings`` while it runs and renews the row every minute, on
  the database's clock. An import-time upgrade refuses to upgrade a database a live
  server of an older build is serving (``store.ensure_schema_ready``).
"""

from __future__ import annotations

import os
import re
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from scripts.logger import get_logger

logger = get_logger(__name__)

APP_VERSION = "1.0.0"
# A registered process renews its row this often; one not renewed for STALE_SECONDS is
# taken to have stopped (a crash leaves its row behind, and it ages out).
HEARTBEAT_SECONDS = 60.0
STALE_SECONDS = 180.0

SOURCE_TREE = Path(__file__).resolve().parents[1]
STARTED_AT = datetime.now(timezone.utc).isoformat()
_REVISION_LINE = re.compile(r"^\s*\((\d+),\s*\"[a-z0-9_]+\",\s*store\.", re.MULTILINE)


def source_tree() -> str:
    return str(SOURCE_TREE)


def git_revision(root: Path = SOURCE_TREE) -> dict:
    """The checkout's commit and branch, read from ``.git`` without running git; empty
    for an installed build, which has no ``.git``."""
    git = root / ".git"
    try:
        if git.is_file():  # a worktree: ".git" names the real directory
            pointer = git.read_text(encoding="utf-8").strip()
            if pointer.startswith("gitdir:"):
                git = (root / pointer.split(":", 1)[1].strip()).resolve()
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return {"commit": head[:12], "branch": ""}
        ref = head.split(":", 1)[1].strip()
        common = git
        commondir = git / "commondir"
        if commondir.is_file():
            common = (git / commondir.read_text(encoding="utf-8").strip()).resolve()
        for base in (git, common):
            candidate = base / ref
            if candidate.is_file():
                return {"commit": candidate.read_text(encoding="utf-8").strip()[:12],
                        "branch": ref.rsplit("/", 1)[-1]}
        packed = common / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line.endswith(" " + ref):
                    return {"commit": line.split(" ", 1)[0][:12], "branch": ref.rsplit("/", 1)[-1]}
        return {"commit": "", "branch": ref.rsplit("/", 1)[-1]}
    except OSError:
        return {"commit": "", "branch": ""}


def supported_revision() -> int:
    """The schema revision this process's code supports - the code it loaded."""
    from backend import migrations

    return migrations.expected_revision()


def on_disk_revision(root: Path = SOURCE_TREE) -> int | None:
    """The schema revision the migrations file on disk supports now. Larger than
    ``supported_revision`` when the process is older than its own source tree."""
    try:
        text = (root / "backend" / "migrations.py").read_text(encoding="utf-8")
    except OSError:
        return None
    numbers = [int(match) for match in _REVISION_LINE.findall(text)]
    return max(numbers) if numbers else None


def database_location() -> dict:
    """Where the database is - never a password, a user name or a full connection string."""
    from backend import db

    if db.is_postgres():
        parts = urlsplit(db.db_url())
        try:
            port = parts.port or 5432
        except ValueError:
            port = None
        return {"backend": "postgres", "host": parts.hostname or "", "port": port,
                "database": parts.path.lstrip("/") or ""}
    store = sys.modules.get("backend.store")
    path = getattr(store, "DB_PATH", None)
    if path is None:
        path = os.getenv("DSPM_DB_PATH", "")
    return {"backend": "sqlite", "path": str(Path(path).resolve()) if path else ""}


def describe_location(location: dict | None = None) -> str:
    location = location or database_location()
    if location.get("backend") == "postgres":
        return f"postgres {location.get('host')}:{location.get('port')}/{location.get('database')}"
    return f"sqlite {location.get('path')}"


def instance_id() -> str:
    from backend import jobs

    return jobs.INSTANCE_ID


def identity(role: str = "server") -> dict:
    """This process, as it registers itself and as startup describes it."""
    git = git_revision()
    return {
        "instance_id": instance_id(), "role": role, "host": socket.gethostname(), "pid": os.getpid(),
        "started_at": STARTED_AT, "version": APP_VERSION, "commit": git["commit"], "branch": git["branch"],
        "source_tree": source_tree(), "schema_supported": supported_revision(),
        "database": database_location(), "mode": os.getenv("DSPM_ENV", "local").strip().lower() or "local",
    }


def describe_instance(item: dict) -> str:
    commit = f" commit {item['commit']}" if item.get("commit") else ""
    return (f"{item.get('role', 'server')} pid {item.get('pid')} on {item.get('host')} (build revision "
            f"{item.get('schema_supported')}{commit}, source {item.get('source_tree')}, started {item.get('started_at')})")


def banner(applied_revision: int | None) -> str:
    """One line for the log at startup: the build, the schema it supports, the database."""
    me = identity()
    commit = f", commit {me['commit']}" + (f" on {me['branch']}" if me["branch"] else "") if me["commit"] else ""
    applied = "unknown" if applied_revision is None else str(applied_revision)
    return (f"Sentro {me['version']}{commit} from {me['source_tree']} | supports schema revision "
            f"{me['schema_supported']} | database {describe_location(me['database'])} at revision {applied} | "
            f"mode {me['mode']} | pid {me['pid']} on {me['host']}")


def other_instances(*, live_only: bool = True) -> list[dict]:
    """The other servers and workers registered on this database (live ones by default)."""
    from backend import store

    mine = instance_id()
    return [item for item in store.runtime_instances(STALE_SECONDS if live_only else None)
            if item.get("instance_id") != mine]


def mismatch_diagnosis(applied: int, expected: int) -> str:
    """The server log's account of a schema mismatch: what the sign-in message cannot say
    to somebody who has not signed in - paths, hosts, and which build moved the database."""
    lines = [f"Schema mismatch: database {describe_location()} is at revision {applied}; this process "
             f"(pid {os.getpid()}, started {STARTED_AT}, source {source_tree()}) supports revision {expected}."]
    disk = on_disk_revision()
    if disk is not None and disk > expected:
        lines.append(f"The code now on disk at {source_tree()} supports revision {disk}: this process is older "
                     "than its own source tree. Restart it to run the current code.")
    try:
        from backend import store

        with store._connect() as conn:
            row = conn.execute("SELECT revision, name, applied_at FROM schema_migrations "
                               "ORDER BY revision DESC LIMIT 1").fetchone()
        if row is not None:
            lines.append(f"Revision {row['revision']} ({row['name']}) was applied at {row['applied_at']}.")
    except Exception:  # noqa: BLE001 - a diagnosis never fails what it diagnoses
        pass
    try:
        newer = [item for item in other_instances() if int(item.get("schema_supported") or 0) >= applied]
        for item in newer:
            lines.append("Registered on the same database: " + describe_instance(item) + ".")
    except Exception:  # noqa: BLE001
        pass
    return " ".join(lines)


_heartbeat_stop = threading.Event()
_heartbeat_thread: threading.Thread | None = None
_registered_role = ""


def register(role: str = "server") -> None:
    """Register this process on its database and keep the row fresh until ``deregister``.
    Best-effort: a registry that cannot be written never stops a server."""
    global _heartbeat_thread, _registered_role
    from backend import store

    _registered_role = role
    try:
        store.register_runtime_instance(identity(role))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not register this process on its database: %s", type(exc).__name__)
    if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
        return
    _heartbeat_stop.clear()
    _heartbeat_thread = threading.Thread(target=_heartbeat_loop, name="runtime-registry", daemon=True)
    _heartbeat_thread.start()


def _heartbeat_loop() -> None:
    from backend import store

    while not _heartbeat_stop.wait(HEARTBEAT_SECONDS):
        try:
            store.register_runtime_instance(identity(_registered_role or "server"))
        except Exception:  # noqa: BLE001 - the next beat tries again
            pass


def deregister() -> None:
    from backend import store

    _heartbeat_stop.set()
    try:
        store.forget_runtime_instance(instance_id())
    except Exception:  # noqa: BLE001
        pass


def log_startup(applied_revision: int | None) -> None:
    """The startup banner, and a warning for every other live process on the database
    whose build supports a different schema revision."""
    logger.info(banner(applied_revision))
    try:
        mine = supported_revision()
        for item in other_instances():
            if int(item.get("schema_supported") or 0) != mine:
                logger.warning("Another build serves this database: %s. This process supports revision %s.",
                               describe_instance(item), mine)
    except Exception:  # noqa: BLE001
        pass
