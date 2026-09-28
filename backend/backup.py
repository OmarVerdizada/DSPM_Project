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
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet

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
