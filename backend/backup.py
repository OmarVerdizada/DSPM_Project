"""Encrypted database backups and recovery evidence (roadmap Phase 1, DB-02).

Design:

- Backups are ``pg_dump`` custom-format archives, encrypted at rest with a
  dedicated Fernet key (never the vault key - a backup escaping the host must
  not also unlock stored scan credentials).
- **The backup set covers the artifact tier too.** Once report bodies live
  outside the database (Phase 5), a database-only backup is no longer a
  product backup: it would restore an estate whose reports are all missing.
  Every backup therefore also captures the artifact store, and the manifest
  records its object count and digest so the restore drill can reconcile it.
- Every backup writes a manifest: UTC timestamp, database identity, sizes,
  SHA-256 of plaintext and ciphertext, and per-table row counts captured at
  dump time. The restore drill reconciles against these, so "the backup
  worked" is a checked claim, not an assumption.
- Encryption is chunked (Fernet token per 8 MiB, length-prefixed) so backups
  larger than memory stream on both sides.
- ``latest_backup_age_seconds`` feeds health/readiness: a backup that stopped
  happening must become visible before it becomes a recovery incident.

The key resolves from ``DSPM_BACKUP_KEY`` (required in production) or a local
dev keyfile outside ``data/`` (``~/.dspm/backup_key``), mirroring the JWT and
evidence key patterns so a data/ copy never contains its own backup key.

C0.3 (the end of this module): the backend takes a verified set on its own schedule,
copies it off the host when told where, keeps what retention says, and records every
outcome where /api/ready, /metrics and the installation's alerts read it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

CHUNK_BYTES = 8 * 1024 * 1024
MANIFEST_SUFFIX = ".manifest.json"
_IS_PRODUCTION = os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}


def backup_dir() -> Path:
    return Path(os.getenv("DSPM_BACKUP_DIR", "data/backups")).resolve()


def _local_key_path() -> Path:
    configured = os.getenv("DSPM_LOCAL_BACKUP_KEY_PATH", "").strip()
    return Path(configured) if configured else Path.home() / ".dspm" / "backup_key"


def backup_key() -> bytes:
    env_key = os.getenv("DSPM_BACKUP_KEY", "").strip()
    if env_key:
        return env_key.encode("ascii")
    if _IS_PRODUCTION:
        raise RuntimeError("DSPM_BACKUP_KEY must be set in production (Fernet key).")
    path = _local_key_path()
    if path.exists():
        return path.read_text(encoding="ascii").strip().encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    path.write_text(key.decode("ascii"), encoding="ascii")
    return key


# ---------------------------------------------------------------------------
# Chunked-Fernet framing. One Fernet token per CHUNK_BYTES of plaintext, each
# preceded by a 4-byte big-endian token length, so payloads larger than memory
# stream in both directions and a truncated file is detected rather than
# silently short-read. This framing is shared with the artifact store
# (backend/artifacts.py) - it is defined once, here.
# ---------------------------------------------------------------------------


def encrypt_stream(fernet: Fernet, src, out) -> tuple[str, str]:
    """Encrypt a readable into a writable; returns (plaintext, ciphertext) SHA-256."""
    plain_hash, cipher_hash = hashlib.sha256(), hashlib.sha256()
    while True:
        chunk = src.read(CHUNK_BYTES)
        if not chunk:
            break
        plain_hash.update(chunk)
        token = fernet.encrypt(chunk)
        header = struct.pack(">I", len(token))
        out.write(header)
        out.write(token)
        cipher_hash.update(header)
        cipher_hash.update(token)
    return plain_hash.hexdigest(), cipher_hash.hexdigest()


class EncryptingWriter:
    """The framing of :func:`encrypt_stream`, pushed one write at a time.

    ``encrypt_stream`` pulls from a readable. A producer that pushes - a gzip
    compressor fed from a generator - would otherwise have to write its output
    somewhere readable first, and for a streamed artifact that somewhere was a
    scratch file of compressed plaintext. :func:`decrypt_stream` reads the result
    whatever frame size is used.
    """

    def __init__(self, fernet: Fernet, out, frame_bytes: int = CHUNK_BYTES) -> None:
        self._fernet = fernet
        self._out = out
        self._frame_bytes = max(1, int(frame_bytes))
        self._buffer = bytearray()

    def write(self, data) -> int:
        self._buffer += data
        while len(self._buffer) >= self._frame_bytes:
            self._seal(bytes(self._buffer[: self._frame_bytes]))
            del self._buffer[: self._frame_bytes]
        return len(data)

    def flush(self) -> None:
        """Frames are written whole; a partial one waits for :meth:`finish`."""

    def finish(self) -> None:
        if self._buffer:
            self._seal(bytes(self._buffer))
            self._buffer.clear()

    def _seal(self, chunk: bytes) -> None:
        token = self._fernet.encrypt(chunk)
        self._out.write(struct.pack(">I", len(token)))
        self._out.write(token)


def decrypt_stream(fernet: Fernet, src, out) -> str:
    """Decrypt a readable into a writable; returns the plaintext SHA-256."""
    plain_hash = hashlib.sha256()
    while True:
        header = src.read(4)
        if not header:
            break
        if len(header) != 4:
            raise ValueError("Truncated payload: bad chunk header")
        (token_len,) = struct.unpack(">I", header)
        token = src.read(token_len)
        if len(token) != token_len:
            raise ValueError("Truncated payload: incomplete chunk")
        chunk = fernet.decrypt(token)
        plain_hash.update(chunk)
        out.write(chunk)
    return plain_hash.hexdigest()


def encrypt_file(source: Path, dest: Path) -> tuple[str, str]:
    """Chunked-Fernet encrypt; returns (plaintext_sha256, ciphertext_sha256)."""
    fernet = Fernet(backup_key())
    with open(source, "rb") as src, open(dest, "wb") as out:
        return encrypt_stream(fernet, src, out)


def decrypt_file(source: Path, dest: Path) -> str:
    """Decrypt a chunked-Fernet file; returns the plaintext SHA-256."""
    fernet = Fernet(backup_key())
    with open(source, "rb") as src, open(dest, "wb") as out:
        return decrypt_stream(fernet, src, out)


def _pg_bin(tool: str) -> str:
    root = os.getenv("DSPM_PG_BIN", r"C:\Program Files\PostgreSQL\18\bin")
    candidate = Path(root) / f"{tool}.exe"
    return str(candidate) if candidate.exists() else tool


# C10's policies admit a whole-database backup by name, as they admit a migration: the
# dump, the restore and the row counts run with row security ON under this purpose.
# Without it the table owner is itself subject to the FORCEd policies - pg_dump refused
# the first COPY, and the counts read 0 rows in every tenant table (M3 exit review).
BACKUP_PURPOSE = "backup"


def _backup_session(env: dict) -> dict:
    """The environment a pg_dump / pg_restore runs in: its session names the backup purpose."""
    env = dict(env)
    env["PGOPTIONS"] = (str(env.get("PGOPTIONS") or "") + f" -c app.platform={BACKUP_PURPOSE}").strip()
    return env


def capture_table_counts(dsn: str) -> dict[str, int]:
    """Per-table row counts at dump time - the drill's reconciliation basis."""
    counts: dict[str, int] = {}
    import psycopg

    with psycopg.connect(dsn, connect_timeout=15, autocommit=True) as conn:
        conn.execute("SELECT set_config('app.platform', %s, false)", (BACKUP_PURPOSE,))
        tables = [
            r[0] for r in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
            ).fetchall()
        ]
        for table in sorted(tables):
            counts[table] = conn.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone()[0]
    return counts


def capture_artifacts(archive_base: Path) -> dict:
    """Capture the artifact tier into the backup set.

    Objects are already individually encrypted with the artifact key, so the
    archive is a plain tar of ciphertext - it adds no plaintext exposure, and
    re-encrypting it would only mean a restore needs two keys where one will
    do. The manifest records the object count, byte total and a digest over the
    (tenant, content-id) set so a restore drill can prove the tier came back
    whole rather than merely present.
    """
    from backend import artifacts as _artifacts

    inventory: list[str] = []
    total = 0
    members: list[tuple[str, Path]] = []
    for tenant, content_id, path in _artifacts.iter_objects():
        inventory.append(f"{tenant}/{content_id}")
        total += path.stat().st_size
        members.append((f"{tenant}/{content_id}{_artifacts.OBJECT_SUFFIX}", path))

    digest = hashlib.sha256("\n".join(sorted(inventory)).encode("utf-8")).hexdigest()
    if not members:
        return {"objects": 0, "ciphertext_bytes": 0, "inventory_sha256": digest, "file": None}

    import tarfile

    archive = archive_base.with_suffix(archive_base.suffix + ".enc")
    plain_archive = archive_base
    try:
        with tarfile.open(plain_archive, "w") as tar:
            for name, path in members:
                tar.add(path, arcname=name)
        # The tar is encrypted like the dump so the whole backup set is uniform.
        _plain_sha, cipher_sha = encrypt_file(plain_archive, archive)
    finally:
        plain_archive.unlink(missing_ok=True)

    return {
        "objects": len(members),
        "ciphertext_bytes": total,
        "inventory_sha256": digest,
        "file": archive.name,
        "archive_sha256": cipher_sha,
    }


def restore_artifacts(archive: Path, destination: Path) -> dict:
    """Decrypt and unpack an artifact archive into ``destination``.

    Used by the restore drill and by a real recovery. Returns the object count
    and the inventory digest, so the caller can reconcile against the manifest.
    """
    import tarfile

    destination.mkdir(parents=True, exist_ok=True)
    plain = destination / "artifacts.tar.tmp"
    try:
        decrypt_file(archive, plain)
        inventory: list[str] = []
        with tarfile.open(plain, "r") as tar:
            for member in tar.getmembers():
                # capture_artifacts writes regular files and nothing else, so a
                # symlink, device or directory member means this archive is not
                # one of ours. Skipping such a member only kept it out of the
                # inventory - extraction still wrote it - so it is refused.
                if not member.isfile():
                    raise ValueError(f"Refusing non-file archive member: {member.name!r}")
                name = member.name.replace("\\", "/")
                if name.startswith("/") or ".." in name.split("/"):
                    raise ValueError(f"Refusing unsafe archive member: {member.name!r}")
                inventory.append(name.rsplit(".", 1)[0])
            # Belt and braces: every member was validated above, and the "data"
            # filter refuses absolute paths, traversal and special files again at
            # extraction time. It is always available - the supported floor is
            # Python 3.12 (main.MINIMUM_PYTHON).
            tar.extractall(destination, filter="data")
    finally:
        plain.unlink(missing_ok=True)
    digest = hashlib.sha256("\n".join(sorted(inventory)).encode("utf-8")).hexdigest()
    return {"objects": len(inventory), "inventory_sha256": digest}


def create_logical_backup(dsn: str, out_dir: Path | None = None) -> Path:
    """pg_dump -Fc -> encrypt -> manifest. Returns the manifest path."""
    directory = out_dir or backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    plain = directory / f"sentro_{stamp}.dump"
    encrypted = directory / f"sentro_{stamp}.dump.enc"
    manifest_path = directory / f"sentro_{stamp}{MANIFEST_SUFFIX}"

    counts = capture_table_counts(dsn)
    revision = _pg_schema_revision(dsn)
    # C11: the password goes to pg_dump through its environment, not its command line.
    conninfo, tool_env = pg_tool_environment(dsn)
    # The try starts BEFORE pg_dump, not after it. The finally below was already
    # here, but a dump that succeeded and then failed the returncode check - or
    # timed out after writing part of a file - left an unencrypted copy of the
    # whole database in the backup directory. One was sitting in data/backups on
    # this tree next to seven encrypted ones.
    try:
        # Row security stays on and the session names the backup purpose. The data is
        # written as INSERTs: PostgreSQL refuses COPY FROM into a table with row-level
        # security, so a COPY-format dump could not be restored under FORCEd policies.
        completed = subprocess.run(
            [_pg_bin("pg_dump"), "--format=custom", "--no-password", "--enable-row-security",
             "--inserts", "--rows-per-insert=500", f"--dbname={conninfo}", "--file", str(plain)],
            capture_output=True, text=True, timeout=3600, env=_backup_session(tool_env),
        )
        if completed.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {completed.stderr.strip()[:400]}")
        plain_sha, cipher_sha = encrypt_file(plain, encrypted)
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "kind": "logical",
            "format": INSERT_FORMAT,
            "file": encrypted.name,
            "plaintext_bytes": plain.stat().st_size,
            "ciphertext_bytes": encrypted.stat().st_size,
            "plaintext_sha256": plain_sha,
            "ciphertext_sha256": cipher_sha,
            "schema_revision": revision,
            "table_counts": counts,
            "artifacts": capture_artifacts(directory / f"sentro_{stamp}.artifacts.tar"),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    finally:
        # The unencrypted dump never stays on disk.
        plain.unlink(missing_ok=True)
    return manifest_path


# ---------------------------------------------------------------------------
# C0.2: a plaintext dump in the backup directory. Every backup this module writes is
# chunked Fernet beside a manifest, but the directory has held other things: a pg_dump
# that failed its returncode check before the finally above existed, a SQLite snapshot a
# killed process left, and whatever an operator copied there by hand. Any of them is the
# whole database - or the estate's findings - readable by anyone with the folder, and
# kept for as long as nobody looks. Production does not start beside one.
# ---------------------------------------------------------------------------

_SNIFF_BYTES = 64 * 1024
_MAX_FILES_EXAMINED = 10_000
# A token's version byte (0x80) and a timestamp's leading zero bytes, base64-encoded.
_FERNET_TOKEN_PREFIX = b"gAAAAA"
_DUMP_SUFFIXES = (".dump", ".sql", ".sqlite", ".sqlite3", ".backup", ".bak")
_SQL_STATEMENT = re.compile(rb"\b(?:CREATE TABLE|INSERT INTO|COPY [\w.\"]+ \()", re.IGNORECASE)
_SQL_OPENING = (b"--", b"/*", b"PRAGMA", b"BEGIN", b"SET ", b"CREATE ")
_REPORT_KEYS = (b'"files"', b'"findings"', b'"scan_id"')


def _chunked_fernet(head: bytes) -> bool:
    """The framing ``encrypt_stream`` writes: a 4-byte length, then a Fernet token."""
    if len(head) < 4 + len(_FERNET_TOKEN_PREFIX):
        return False
    (length,) = struct.unpack(">I", head[:4])
    return length > 0 and head[4:4 + len(_FERNET_TOKEN_PREFIX)] == _FERNET_TOKEN_PREFIX


def plaintext_dump_kind(path: Path) -> str | None:
    """What unencrypted copy of the data a file in the backup directory is, or None.

    Decided by content, not by name alone: a manifest and an encrypted payload are what
    belong there, a file that begins like a database or a dump does not, whatever it is
    called. A file that cannot be read is not judged.
    """
    name = path.name.lower()
    if name.endswith(MANIFEST_SUFFIX):
        return None
    try:
        with open(path, "rb") as handle:
            head = handle.read(_SNIFF_BYTES)
    except OSError:
        return None
    if _chunked_fernet(head):
        return None
    if head.startswith(b"PGDMP"):
        return "a pg_dump archive"
    if head.startswith(b"SQLite format 3\x00"):
        return "a SQLite database"
    if len(head) >= 262 and head[257:262] == b"ustar":
        # capture_artifacts' own staging tar holds objects that are each encrypted.
        return None if name.endswith(".artifacts.tar") else "a tar archive"
    if head.startswith(b"\x1f\x8b") and name.endswith(tuple(f"{suffix}.gz" for suffix in (*_DUMP_SUFFIXES, ".tar", ".db"))):
        return "a compressed dump"
    stripped = head.lstrip()
    if stripped.startswith(_SQL_OPENING) and _SQL_STATEMENT.search(head):
        return "a plain SQL dump"
    if name.endswith(".json") and stripped.startswith(b"{") and any(key in head for key in _REPORT_KEYS):
        return "a plaintext scan report"
    if name.endswith(_DUMP_SUFFIXES):
        return "a file named as a dump that is not encrypted"
    return None


def plaintext_dumps(directory: Path | None = None) -> list[tuple[Path, str]]:
    """The unencrypted copies of the data under the backup directory, with what each is."""
    directory = Path(directory) if directory is not None else backup_dir()
    found: list[tuple[Path, str]] = []
    examined = 0
    if not directory.is_dir():
        return found
    for folder, _subfolders, files in os.walk(directory):
        for filename in sorted(files):
            examined += 1
            if examined > _MAX_FILES_EXAMINED:
                return found
            path = Path(folder) / filename
            kind = plaintext_dump_kind(path)
            if kind:
                found.append((path, kind))
    return found


def plaintext_dump_problem(directory: Path | None = None) -> str | None:
    """Why production refuses to start beside the backup directory, or None."""
    directory = Path(directory) if directory is not None else backup_dir()
    found = plaintext_dumps(directory)
    if not found:
        return None
    named = "; ".join(f"{path.relative_to(directory)} ({kind})" for path, kind in found[:10])
    if len(found) > 10:
        named += f"; and {len(found) - 10} more"
    return (
        f"The backup directory {directory} holds {len(found)} unencrypted file(s) that can contain the "
        f"database or the estate's findings: {named}. Production does not run beside a plaintext copy of "
        "its data. Take an encrypted backup and prove it restores (main.py backup create --verify, then a "
        "restore drill), then delete these files - the procedure is 'Sensitive data at rest' in "
        "docs/DEPLOYMENT_WINDOWS.md."
    )


def list_manifests(directory: Path | None = None) -> list[Path]:
    directory = directory or backup_dir()
    if not directory.exists():
        return []
    return sorted(directory.glob(f"*{MANIFEST_SUFFIX}"))


def latest_backup_age_seconds(directory: Path | None = None) -> float | None:
    manifests = list_manifests(directory)
    if not manifests:
        return None
    newest = json.loads(manifests[-1].read_text(encoding="utf-8"))
    created = datetime.fromisoformat(newest["created_at"])
    return max(0.0, (datetime.now(timezone.utc) - created).total_seconds())


def prune_backups(keep: int = 7, directory: Path | None = None) -> int:
    """Keep the newest ``keep`` backup sets; remove older ones. Returns removed count."""
    manifests = list_manifests(directory)
    removed = 0
    for manifest_path in manifests[:-keep] if keep > 0 else []:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload = manifest_path.parent / str(data.get("file") or "")
        payload.unlink(missing_ok=True)
        artifact_file = (data.get("artifacts") or {}).get("file")
        if artifact_file:
            (manifest_path.parent / str(artifact_file)).unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        removed += 1
    return removed


# ---------------------------------------------------------------------------
# C11: the backup an upgrade takes first - for both backends - and its proof.
# ---------------------------------------------------------------------------


def pg_tool_environment(dsn: str) -> tuple[str, dict]:
    """(connection string without its password, environment carrying it).

    `pg_dump --dbname=<url with password>` put the database password on the process's
    command line, where any user of the host can read it. The password now travels in
    the child's environment (PGPASSWORD), which only the same account and
    Administrators can read.
    """
    env = dict(os.environ)
    try:
        from psycopg.conninfo import conninfo_to_dict, make_conninfo

        parts = conninfo_to_dict(dsn)
        password = parts.pop("password", None)
        if password:
            env["PGPASSWORD"] = str(password)
        return make_conninfo(**parts), env
    except ImportError:  # no psycopg: a URL is still parsed by hand
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(dsn)
        if parts.password:
            env["PGPASSWORD"] = parts.password
            netloc = parts.hostname or ""
            if parts.username:
                netloc = f"{parts.username}@{netloc}"
            if parts.port:
                netloc = f"{netloc}:{parts.port}"
            dsn = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        return dsn, env


def _pg_schema_revision(dsn: str) -> int | None:
    import psycopg

    with psycopg.connect(dsn, connect_timeout=15) as conn:
        row = conn.execute("SELECT to_regclass('schema_migrations')").fetchone()
        if row is None or row[0] is None:
            return None
        return int(conn.execute("SELECT COALESCE(MAX(revision), 0) FROM schema_migrations").fetchone()[0])


def _sqlite_facts(path: Path) -> dict:
    """Integrity, schema revision and per-table row counts of a SQLite file."""
    import sqlite3

    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        tables = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        counts = {table: conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] for table in tables}
        revision = None
        if "schema_migrations" in tables:
            revision = conn.execute("SELECT COALESCE(MAX(revision), 0) FROM schema_migrations").fetchone()[0]
        return {"integrity": integrity, "table_counts": counts, "schema_revision": revision}
    finally:
        conn.close()


def create_sqlite_backup(db_path: Path, out_dir: Path | None = None) -> Path:
    """SQLite's online backup -> integrity check -> encrypt -> manifest. The snapshot is
    consistent while the database is in use; its plaintext never outlives this call."""
    import sqlite3

    directory = out_dir or backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    snapshot = directory / f"sentro_sqlite_{stamp}.sqlite"
    encrypted = directory / f"sentro_sqlite_{stamp}.sqlite.enc"
    manifest_path = directory / f"sentro_sqlite_{stamp}{MANIFEST_SUFFIX}"
    if not Path(db_path).exists():
        raise RuntimeError(f"There is no database at {db_path} to back up.")
    try:
        source = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
        target = sqlite3.connect(snapshot)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        facts = _sqlite_facts(snapshot)
        if facts["integrity"] != "ok":
            raise RuntimeError(f"The database failed its integrity check: {facts['integrity']}")
        plain_sha, cipher_sha = encrypt_file(snapshot, encrypted)
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "kind": "sqlite",
            "format": "sqlite-online-backup+chunked-fernet",
            "file": encrypted.name,
            "plaintext_bytes": snapshot.stat().st_size,
            "ciphertext_bytes": encrypted.stat().st_size,
            "plaintext_sha256": plain_sha,
            "ciphertext_sha256": cipher_sha,
            "schema_revision": facts["schema_revision"],
            "table_counts": facts["table_counts"],
            "artifacts": capture_artifacts(directory / f"sentro_sqlite_{stamp}.artifacts.tar"),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    finally:
        snapshot.unlink(missing_ok=True)
    return manifest_path


def create_backup(out_dir: Path | None = None) -> Path:
    """The backup of whichever database this install is configured for."""
    dsn = os.getenv("DSPM_DB_URL", "").strip()
    if dsn:
        return create_logical_backup(dsn, out_dir)
    from backend import store

    return create_sqlite_backup(Path(store.DB_PATH), out_dir)


def verify_backup(manifest_path: Path) -> dict:
    """Decrypt a backup set into a temporary folder and check it against its manifest:
    every digest, and for SQLite the integrity check and every table's row count; for
    PostgreSQL that pg_restore can read the archive's table of contents. Nothing is kept."""
    import tempfile

    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    payload = manifest_path.parent / str(manifest.get("file") or "")
    if not payload.exists():
        return {"ok": False, "manifest": str(manifest_path), "problems": [f"{payload.name} is missing"]}
    if sha256_file(payload) != manifest.get("ciphertext_sha256"):
        problems.append(f"{payload.name} does not match its recorded digest")
    with tempfile.TemporaryDirectory(prefix="sentro-verify-") as scratch:
        plain = Path(scratch) / "payload"
        try:
            plain_sha = decrypt_file(payload, plain)
        except Exception as exc:  # wrong key, truncation, tampering
            problems.append(f"{payload.name} cannot be decrypted with this install's backup key ({type(exc).__name__})")
            plain_sha = None
        if plain_sha is not None and plain_sha != manifest.get("plaintext_sha256"):
            problems.append("the decrypted database does not match its recorded digest")
        if plain_sha is not None and manifest.get("kind") == "sqlite":
            facts = _sqlite_facts(plain)
            if facts["integrity"] != "ok":
                problems.append(f"integrity check: {facts['integrity']}")
            if facts["table_counts"] != manifest.get("table_counts"):
                problems.append("row counts differ from the ones recorded at backup time")
            if facts["schema_revision"] != manifest.get("schema_revision"):
                problems.append("the schema revision differs from the recorded one")
        elif plain_sha is not None:
            listed = subprocess.run([_pg_bin("pg_restore"), "--list", str(plain)], capture_output=True, text=True)
            if listed.returncode != 0:
                problems.append(f"pg_restore cannot read the archive: {listed.stderr.strip()[:300]}")
        artifacts = manifest.get("artifacts") or {}
        if artifacts.get("file"):
            archive = manifest_path.parent / artifacts["file"]
            if not archive.exists():
                problems.append(f"{archive.name} is missing")
            else:
                restored = restore_artifacts(archive, Path(scratch) / "artifacts")
                if restored["objects"] != artifacts.get("objects") or \
                        restored["inventory_sha256"] != artifacts.get("inventory_sha256"):
                    problems.append("the artifact archive does not hold the objects recorded")
    return {"ok": not problems, "manifest": str(manifest_path), "kind": manifest.get("kind"),
            "schema_revision": manifest.get("schema_revision"), "problems": problems}


INSERT_FORMAT = "pg_dump-custom-inserts+chunked-fernet"


def restore_postgres_backup(manifest_path: Path, dsn: str, artifact_dir: Path | None = None) -> dict:
    """Put a verified PostgreSQL backup in place of the database's contents, in ONE
    transaction: pg_restore --clean --single-transaction, row security on, the session
    naming the backup purpose. The database it replaces is backed up first and that
    backup's manifest returned, never discarded. Extensions are the database
    administrator's (the application role cannot create or drop them), so they are
    left as they are."""
    import re
    import tempfile

    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("kind") != "logical":
        raise RuntimeError("This is a SQLite backup; it restores into a SQLite install.")
    if manifest.get("format") != INSERT_FORMAT:
        raise RuntimeError("This backup holds its rows as COPY data, which PostgreSQL does not load into tables with "
                           "row-level security. Take a new backup with this release and restore that one.")
    report = verify_backup(manifest_path)
    if not report["ok"]:
        raise RuntimeError("The backup did not verify, so nothing was restored: " + "; ".join(report["problems"]))
    previous = create_logical_backup(dsn, manifest_path.parent)
    conninfo, tool_env = pg_tool_environment(dsn)
    with tempfile.TemporaryDirectory(prefix="sentro-restore-") as scratch:
        plain = Path(scratch) / "restore.dump"
        decrypt_file(manifest_path.parent / manifest["file"], plain)
        listed = subprocess.run([_pg_bin("pg_restore"), "--list", str(plain)], capture_output=True, text=True)
        if listed.returncode != 0:
            raise RuntimeError(f"pg_restore cannot read the archive: {listed.stderr.strip()[:300]}")
        entries = [line for line in listed.stdout.splitlines() if not re.search(r"\bEXTENSION\b", line)]
        order = Path(scratch) / "restore.list"
        order.write_text("\n".join(entries) + "\n", encoding="utf-8")
        completed = subprocess.run(
            [_pg_bin("pg_restore"), "--clean", "--if-exists", "--no-owner", "--single-transaction", "--exit-on-error",
             "--enable-row-security", "--no-password", "--use-list", str(order), f"--dbname={conninfo}", str(plain)],
            capture_output=True, text=True, timeout=3600, env=_backup_session(tool_env),
        )
        if completed.returncode != 0:
            raise RuntimeError(f"pg_restore failed; the transaction rolled back and nothing changed: "
                               f"{completed.stderr.strip()[:400]}")
    counts = capture_table_counts(dsn)
    recorded = manifest.get("table_counts") or {}
    differ = sorted(table for table, rows in recorded.items() if counts.get(table) != rows)
    return {"restored": str(manifest_path), "previous_database": str(previous),
            "schema_revision": _pg_schema_revision(dsn), "tables_differing": differ,
            "artifact_objects_added": _add_artifact_objects(manifest_path, manifest, artifact_dir)}


def _add_artifact_objects(manifest_path: Path, manifest: dict, artifact_dir: Path | None) -> int:
    """The backup's artifact objects that the store lacks. Objects are content-addressed
    and never change, so adding them loses nothing."""
    import tempfile

    added = 0
    artifacts = manifest.get("artifacts") or {}
    if not artifacts.get("file"):
        return 0
    from backend import artifacts as _artifacts

    target = Path(artifact_dir) if artifact_dir else _artifacts.artifact_root()
    with tempfile.TemporaryDirectory(prefix="sentro-restore-") as scratch:
        restore_artifacts(manifest_path.parent / artifacts["file"], Path(scratch))
        for item in Path(scratch).rglob(f"*{_artifacts.OBJECT_SUFFIX}"):
            # The archive names an object <tenant>/<content id>; the store keeps it under
            # one fan-out level, <tenant>/<first two hex>/<content id> (artifacts.object_path).
            # Copied back without that level it sat where nothing reads it (M3 exit review).
            tenant = item.relative_to(scratch).parts[0]
            content_id = item.name[: -len(_artifacts.OBJECT_SUFFIX)]
            destination = target / tenant / content_id[:2] / item.name
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, destination)
                added += 1
    return added


def restore_backup(manifest_path: Path) -> dict:
    """Restore whichever kind of backup this is, into the database this install uses."""
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    dsn = os.getenv("DSPM_DB_URL", "").strip()
    if manifest.get("kind") == "logical":
        if not dsn:
            raise RuntimeError("This is a PostgreSQL backup, and this install is configured for SQLite.")
        return restore_postgres_backup(Path(manifest_path), dsn)
    if dsn:
        raise RuntimeError("This is a SQLite backup, and this install is configured for PostgreSQL.")
    from backend import store

    return restore_sqlite_backup(Path(manifest_path), Path(store.DB_PATH))


def restore_sqlite_backup(manifest_path: Path, db_path: Path, artifact_dir: Path | None = None) -> dict:
    """Put a verified SQLite backup in place of the database. The database it replaces
    is kept beside it (…pre-restore-<stamp>), never deleted. The artifact store gains the
    backup's objects; objects are content-addressed and never change, so none is lost."""
    import tempfile

    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("kind") != "sqlite":
        raise RuntimeError("This is a PostgreSQL backup; it restores into a PostgreSQL install.")
    report = verify_backup(manifest_path)
    if not report["ok"]:
        raise RuntimeError("The backup did not verify, so nothing was restored: " + "; ".join(report["problems"]))
    db_path = Path(db_path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    kept = None
    staged = db_path.with_name(db_path.name + f".restoring-{stamp}")
    decrypt_file(manifest_path.parent / manifest["file"], staged)
    if db_path.exists():
        kept = db_path.with_name(db_path.name + f".pre-restore-{stamp}")
        os.replace(db_path, kept)
    for suffix in ("-wal", "-shm"):
        side = db_path.with_name(db_path.name + suffix)
        if side.exists() and kept is not None:
            os.replace(side, kept.with_name(kept.name + suffix))
    os.replace(staged, db_path)
    restored_objects = _add_artifact_objects(manifest_path, manifest, artifact_dir)
    return {"restored": str(db_path), "previous_database": str(kept) if kept else None,
            "schema_revision": manifest.get("schema_revision"), "artifact_objects_added": restored_objects}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# C0.3: backups nobody has to remember. backend.housekeeping runs run_backup_set on the
# DSPM_BACKUP_SCHEDULE_HOURS schedule, claimed through the database so several backends
# take one set between them. A set counts once it VERIFIED (mark_verified): retention
# keeps verified sets, and readiness measures the age of the newest verified one.
# ---------------------------------------------------------------------------

ATTEMPT_SETTING = "backup.last_attempt"
# The installation's own workspace: its audit trail and alerts are the installation's.
INSTALLATION_TENANT = "default"


class BackupVerifyError(RuntimeError):
    """A set was written and did not verify."""


def _number(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return max(0.0, float(raw))
    except ValueError:
        return default


def is_production() -> bool:
    """Read at the call, not at import: readiness and the schedule follow DSPM_ENV as it is."""
    return os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}


def schedule_seconds() -> int:
    """How often the backend takes a set itself: DSPM_BACKUP_SCHEDULE_HOURS (24 by default;
    0 turns the schedule off, for an install that backs up some other way). Less than an
    hour is read as an hour, more than 31 days as 31 days."""
    hours = _number("DSPM_BACKUP_SCHEDULE_HOURS", 24.0)
    if hours <= 0:
        return 0
    return int(min(max(hours, 1.0), 31 * 24.0) * 3600)


def retain_sets() -> int:
    """DSPM_RETAIN_BACKUP_SETS: how many verified sets retention keeps (7; at least 1)."""
    return max(1, int(_number("DSPM_RETAIN_BACKUP_SETS", 7)))


def retain_days() -> float:
    """DSPM_RETAIN_BACKUP_DAYS: a set younger than this is kept whatever the count (0: off)."""
    return _number("DSPM_RETAIN_BACKUP_DAYS", 0.0)


def copy_dir() -> Path | None:
    """DSPM_BACKUP_COPY_DIR: the off-host location each verified set is copied to (unset: none)."""
    raw = os.getenv("DSPM_BACKUP_COPY_DIR", "").strip()
    return Path(raw) if raw else None


def warn_age_hours() -> float:
    """DSPM_BACKUP_MAX_AGE_HOURS (26): a newest verified set older than this is a warning
    (and the installation's backup_stale alert); 0 turns the warning off."""
    return _number("DSPM_BACKUP_MAX_AGE_HOURS", 26.0)


def ready_age_hours() -> float:
    """DSPM_BACKUP_READY_MAX_AGE_HOURS (48, the roadmap's proposal): a newest verified set
    older than this FAILS readiness in production. Never below the warning threshold - an
    install that raised that one is not failed before it is warned - and 0 turns the
    failure off (the warning stays)."""
    hours = _number("DSPM_BACKUP_READY_MAX_AGE_HOURS", 48.0)
    return max(hours, warn_age_hours()) if hours > 0 else 0.0


def key_configured() -> bool:
    """Whether this install names its backup key: DSPM_BACKUP_KEY, or an existing key file at
    DSPM_LOCAL_BACKUP_KEY_PATH. Outside production the schedule needs one. backup_key()
    would otherwise make a key up on the spot, and sets only an un-escrowed key opens are
    not a recovery plan. Production refuses to run without DSPM_BACKUP_KEY at all."""
    if os.getenv("DSPM_BACKUP_KEY", "").strip():
        return True
    configured = os.getenv("DSPM_LOCAL_BACKUP_KEY_PATH", "").strip()
    return bool(configured) and Path(configured).is_file()


def _created_at(document: dict) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(document.get("created_at") or ""))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def backup_sets(directory: Path | None = None) -> list[dict]:
    """The readable sets in a directory, newest first: ``manifest`` (its path), ``created_at``,
    ``verified`` (a verification passed and was recorded) and ``data`` (the manifest).

    Ordered by when each was taken, not by name: a PostgreSQL set (``sentro_<stamp>``)
    sorts before a SQLite one (``sentro_sqlite_<stamp>``) whatever their times. A manifest
    that cannot be read - half written, or damaged - is left out, and so is never pruned.
    """
    found: list[dict] = []
    for path in list_manifests(directory):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        created = _created_at(document) if isinstance(document, dict) else None
        if created is None:
            continue
        found.append({"manifest": path, "created_at": created, "verified": bool(document.get("verified_at")),
                      "data": document})
    found.sort(key=lambda item: item["created_at"], reverse=True)
    return found


def _write_json_whole(path: Path, document: dict) -> None:
    """Write beside, then rename over: a reader sees the old manifest or the new one, never half."""
    staged = path.with_name(path.name + ".partial")
    staged.write_text(json.dumps(document, indent=2), encoding="utf-8")
    os.replace(staged, path)


def mark_verified(manifest_path: Path) -> None:
    """Record in a set's manifest that it verified (``verified_at``). Only such a set counts
    for retention and for readiness."""
    manifest_path = Path(manifest_path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    document["verified_at"] = datetime.now(timezone.utc).isoformat()
    _write_json_whole(manifest_path, document)


def _named_file(directory: Path, name) -> Path:
    """A file a manifest names: a plain name beside the manifest. A manifest is data, and
    one naming ..\\..\\something must not make retention delete, or the copy carry, it."""
    text = str(name or "")
    if not text or text in {".", ".."} or Path(text).name != text or "/" in text or "\\" in text:
        raise ValueError(f"The manifest names {text!r}, which is not a file beside it.")
    return directory / text


def set_files(manifest_path: Path, document: dict) -> list[tuple[Path, str | None]]:
    """A set's encrypted files - the database, and the artifact archive when there is one -
    each with the digest its manifest records."""
    manifest_path = Path(manifest_path)
    files = [(_named_file(manifest_path.parent, document.get("file")), document.get("ciphertext_sha256"))]
    artifacts = document.get("artifacts") or {}
    if artifacts.get("file"):
        files.append((_named_file(manifest_path.parent, artifacts["file"]), artifacts.get("archive_sha256")))
    return files


def _remove_set(item: dict) -> None:
    files = set_files(item["manifest"], item["data"])
    # The manifest goes first, so no reader finds a set whose files are already gone.
    item["manifest"].unlink(missing_ok=True)
    for path, _digest in files:
        path.unlink(missing_ok=True)


def apply_retention(directory: Path | None = None, *, keep_sets: int | None = None,
                    keep_days: float | None = None, now: datetime | None = None) -> list[str]:
    """Remove the sets retention no longer keeps; returns the names of the manifests removed.

    Kept: every set at least as new as the Nth-newest VERIFIED set (DSPM_RETAIN_BACKUP_SETS),
    and every set younger than DSPM_RETAIN_BACKUP_DAYS. Until N verified sets exist nothing
    is removed - so the newest verified set is never removed, and a run of failed or
    unverified sets never thins out the ones that still restore.
    """
    count = max(1, int(retain_sets() if keep_sets is None else keep_sets))
    days = float(retain_days() if keep_days is None else keep_days)
    moment = now or datetime.now(timezone.utc)
    sets = backup_sets(directory)
    verified = [item for item in sets if item["verified"]]
    if len(verified) < count:
        return []
    oldest_kept = verified[count - 1]["created_at"]
    young = moment - timedelta(days=days) if days > 0 else None
    removed: list[str] = []
    for item in sets:
        if item["created_at"] >= oldest_kept or (young is not None and item["created_at"] >= young):
            continue
        try:
            _remove_set(item)
        except (OSError, ValueError) as exc:
            logger.warning("Retention could not remove the backup set %s: %s", item["manifest"].name,
                           type(exc).__name__)
            continue
        removed.append(item["manifest"].name)
    return removed


def _copy_whole(source: Path, target: Path, digest: str | None) -> None:
    staged = target.with_name(target.name + ".partial")
    try:
        shutil.copyfile(source, staged)
        if digest and sha256_file(staged) != digest:
            raise ValueError(f"The copy of {source.name} does not match the digest its manifest records.")
        os.replace(staged, target)
    finally:
        staged.unlink(missing_ok=True)


def copy_set(manifest_path: Path, destination: Path) -> Path:
    """Copy a verified set off the host; returns the copied manifest.

    The encrypted files go first, each written under a temporary name, checked against the
    digest the manifest records and renamed into place; the manifest goes last. A reader of
    the destination therefore never finds a set it does not hold whole. Only the files the
    manifest names travel - never a key: the backup key is escrowed apart from the backups
    (docs/DEPLOYMENT_WINDOWS.md, "Off-host copies and key recovery").
    """
    manifest_path = Path(manifest_path)
    destination = Path(destination)
    if destination.resolve() == manifest_path.parent.resolve():
        raise ValueError("DSPM_BACKUP_COPY_DIR names the backup directory itself; name a location off this host.")
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    destination.mkdir(parents=True, exist_ok=True)
    for source, digest in set_files(manifest_path, document):
        _copy_whole(source, destination / source.name, digest)
    target = destination / manifest_path.name
    _copy_whole(manifest_path, target, None)
    return target


def record_attempt(ok: bool, error: str = "", *, stage: str = "", trigger: str = "") -> None:
    """What the last backup attempt did, for readiness, /metrics and the installation's
    alerts (D11): when, how far it got, and the error's TYPE - never its text, which for a
    failing pg_dump can echo a connection string."""
    try:
        from backend import store

        store.set_app_setting(ATTEMPT_SETTING, json.dumps({
            "at": datetime.now(timezone.utc).isoformat(), "ok": bool(ok), "error": str(error)[:80],
            "stage": str(stage)[:20], "trigger": str(trigger)[:20]}))
    except Exception as exc:  # recording must never change what the backup itself did
        logger.warning("Could not record the backup attempt: %s", type(exc).__name__)


def last_attempt() -> dict:
    from backend import store

    try:
        value = json.loads(store.get_app_setting(ATTEMPT_SETTING) or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


# Who the audit trail names for a scheduled backup: the product, as the other background
# writers are named ("sentro:delivery", ...).
ACTOR = "sentro:backup"


def _audit(action: str, detail: dict) -> None:
    try:
        from backend import store

        store.audit(INSTALLATION_TENANT, ACTOR, action, detail)
    except Exception as exc:
        logger.warning("Could not audit %s: %s", action, type(exc).__name__)


def _retain(directory: Path | None) -> tuple[list[str], str]:
    try:
        return apply_retention(directory), ""
    except Exception as exc:  # the set is taken; a retention fault must not undo that
        logger.warning("Backup retention failed: %s", type(exc).__name__)
        return [], type(exc).__name__


def run_backup_set(*, trigger: str = "schedule") -> dict:
    """Take one set unattended: create, verify, mark verified, copy it off the host when
    DSPM_BACKUP_COPY_DIR names where, then apply retention here and there.

    Every outcome is recorded (record_attempt) and audited in the installation's trail as
    ``backup.created`` or ``backup.failed``, naming the stage reached and the error's type.
    Neither names a key, a key's path, the off-host location or an error's text.
    """
    stage, manifest = "create", None
    destination = copy_dir()
    try:
        manifest = create_backup()
        stage = "verify"
        report = verify_backup(manifest)
        if not report["ok"]:
            logger.error("The backup set %s did not verify: %s", manifest.name, "; ".join(report["problems"])[:600])
            raise BackupVerifyError(f"{len(report['problems'])} problem(s)")
        mark_verified(manifest)
        if destination is not None:
            stage = "copy"
            copy_set(manifest, destination)
    except Exception as exc:
        error = type(exc).__name__
        record_attempt(False, error, stage=stage, trigger=trigger)
        failed = {"stage": stage, "error": error, "trigger": trigger, "manifest": manifest.name if manifest else ""}
        _audit("backup.failed", failed)
        logger.error("The %s backup failed at %s: %s", trigger, stage, error)
        if stage == "copy":
            # The local set verified. While the off-host location is down every retry adds
            # one, so local retention still runs; the copies are pruned once it is back.
            _retain(None)
        return {"ok": False, "stage": stage, "error": error, "manifest": str(manifest) if manifest else None}
    document = json.loads(manifest.read_text(encoding="utf-8"))
    removed, retention_error = _retain(None)
    removed_copies, copy_retention_error = _retain(destination) if destination is not None else ([], "")
    record_attempt(True, stage="done", trigger=trigger)
    detail = {"manifest": manifest.name, "kind": document.get("kind"), "schema_revision": document.get("schema_revision"),
              "ciphertext_bytes": document.get("ciphertext_bytes"),
              "artifact_objects": (document.get("artifacts") or {}).get("objects", 0), "verified": True,
              "copied_off_host": destination is not None, "sets_removed": len(removed),
              "copies_removed": len(removed_copies), "trigger": trigger}
    if retention_error or copy_retention_error:
        detail["retention_error"] = retention_error or copy_retention_error
    _audit("backup.created", detail)
    logger.info("Backup set %s taken and verified%s; retention removed %s set(s)", manifest.name,
                " and copied off the host" if destination is not None else "", len(removed))
    return {"ok": True, "manifest": str(manifest), "copied": destination is not None, "removed": removed,
            "removed_copies": removed_copies}


def readiness(*, production: bool, installed_at: str | None = None, now: datetime | None = None,
              directory: Path | None = None) -> dict:
    """The backup half of /api/ready: ``failures``, ``warnings`` and ``probe`` facts.

    In production a failed last attempt, or a newest VERIFIED set older than
    ready_age_hours(), fails readiness - and so does having no verified set at all once the
    database itself is older than that (``installed_at``, its first recorded revision), so a
    fresh install is not unready before its first backup could have run. Outside production
    each of these is a warning, as backup age always was. Reads files and one setting; writes
    nothing.
    """
    moment = now or datetime.now(timezone.utc)
    failures: list[str] = []
    warnings: list[str] = []
    serious = failures if production else warnings
    sets = backup_sets(directory)
    verified = next((item for item in sets if item["verified"]), None)

    def age_of(item: dict | None) -> float | None:
        return None if item is None else max(0.0, (moment - item["created_at"]).total_seconds())

    newest_age, verified_age = age_of(sets[0] if sets else None), age_of(verified)
    warn_hours, fail_hours = warn_age_hours(), ready_age_hours()
    attempt = last_attempt()
    if attempt and not attempt.get("ok"):
        serious.append(f"the last backup attempt ({attempt.get('at')}) failed at "
                       f"{attempt.get('stage') or 'create'}: {attempt.get('error') or 'see the backup log'}")
    if verified_age is None:
        database_age = None
        if installed_at:
            installed = _created_at({"created_at": installed_at})
            database_age = None if installed is None else (moment - installed).total_seconds()
        if fail_hours and database_age is not None and database_age > fail_hours * 3600:
            serious.append(f"no verified backup, and the database is {database_age / 3600:.0f}h old "
                           f"(threshold {fail_hours:g}h)")
        else:
            warnings.append("no verified backup yet" if sets else "no backup manifest found")
    elif fail_hours and verified_age > fail_hours * 3600:
        serious.append(f"newest verified backup is {verified_age / 3600:.1f}h old (threshold {fail_hours:g}h)")
    elif warn_hours and verified_age > warn_hours * 3600:
        warnings.append(f"newest verified backup is {verified_age / 3600:.1f}h old (threshold {warn_hours:g}h)")
    probe = {
        "backup_age_seconds": None if newest_age is None else round(newest_age, 1),
        "verified_backup_age_seconds": None if verified_age is None else round(verified_age, 1),
        "backup_last_attempt": ({key: attempt.get(key) for key in ("at", "ok", "stage", "trigger")}
                                if attempt else None),
    }
    return {"failures": failures, "warnings": warnings, "probe": probe}
