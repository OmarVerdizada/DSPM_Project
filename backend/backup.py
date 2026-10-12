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

import contextlib
import hashlib
import io
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

CHUNK_BYTES = 8 * 1024 * 1024
MANIFEST_SUFFIX = ".manifest.json"
_IS_PRODUCTION = os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}


# The folder this install runs from: runtime defaults live under its data folder.
_INSTALL_ROOT = Path(__file__).resolve().parents[1]


def backup_dir() -> Path:
    # Under the install's own data folder when not configured (not the working directory's).
    return Path(os.getenv("DSPM_BACKUP_DIR") or (_INSTALL_ROOT / "data" / "backups")).resolve()


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


def _frames(fernet: Fernet, src):
    """The plaintext of a chunked-Fernet stream, one frame at a time."""
    while True:
        header = src.read(4)
        if not header:
            return
        if len(header) != 4:
            raise ValueError("Truncated payload: bad chunk header")
        (token_len,) = struct.unpack(">I", header)
        token = src.read(token_len)
        if len(token) != token_len:
            raise ValueError("Truncated payload: incomplete chunk")
        yield fernet.decrypt(token)


def decrypt_stream(fernet: Fernet, src, out) -> str:
    """Decrypt a readable into a writable; returns the plaintext SHA-256."""
    plain_hash = hashlib.sha256()
    for chunk in _frames(fernet, src):
        plain_hash.update(chunk)
        out.write(chunk)
    return plain_hash.hexdigest()


class _Discard:
    """A writable that keeps nothing: decrypting into it proves every frame opens."""

    def write(self, data) -> int:
        return len(data)


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


class _DecryptedReader(io.RawIOBase):
    """The plaintext of a chunked-Fernet stream, read on demand - one frame in memory at a
    time, nothing written anywhere. Lets tarfile list an artifact archive as it decrypts."""

    def __init__(self, fernet: Fernet, src) -> None:
        self._fernet, self._src = fernet, src
        self._frame, self._offset = b"", 0

    def readable(self) -> bool:
        return True

    def readinto(self, target) -> int:
        while self._offset >= len(self._frame):
            header = self._src.read(4)
            if not header:
                return 0
            if len(header) != 4:
                raise ValueError("Truncated payload: bad chunk header")
            (token_len,) = struct.unpack(">I", header)
            token = self._src.read(token_len)
            if len(token) != token_len:
                raise ValueError("Truncated payload: incomplete chunk")
            self._frame, self._offset = self._fernet.decrypt(token), 0
        count = min(len(target), len(self._frame) - self._offset)
        target[:count] = memoryview(self._frame)[self._offset:self._offset + count]
        self._offset += count
        return count


# ---------------------------------------------------------------------------
# W3.5: a backup stages nothing in plaintext. pg_dump writes its archive into a pipe that
# is encrypted as it is read, and verify and restore decrypt into pg_restore's standard
# input: no PostgreSQL backup puts its plaintext on any disk. SQLite's online backup needs
# a file, so its snapshot - and the copy verify checks - is written to a private folder
# beside the database it copies, which holds the same bytes in clear already.
#
# Before, all of it was staged in the service account's temporary directory: a process
# stopped mid-backup left a whole database in %TEMP% for whoever read that folder next,
# and a tar of the whole artifact store went through it once per set. Earlier still it
# was the backup directory, where production refuses to start beside a plaintext copy
# (plaintext_dump_problem). A folder a killed process left is swept by the next backup,
# and at startup - in the database's folder and, for what older releases left, in %TEMP%.
# ---------------------------------------------------------------------------

STAGING_PREFIX = "sentro-backup-staging-"
# Older than any backup can run (pg_dump's own timeout is an hour), so a sweep never takes
# a folder a backup in another process is still using.
STAGING_STALE_SECONDS = 6 * 3600
# What a backup tool may say on its standard error that is kept for the message.
_ERROR_BYTES = 64 * 1024


def _sqlite_staging_root() -> Path:
    """The folder of the SQLite database this install uses: where its snapshot is staged."""
    from backend import store

    return Path(store.DB_PATH).resolve().parent


def _sweep_folder(folder: Path, cutoff: float) -> int:
    removed = 0
    try:
        candidates = [path for path in folder.iterdir() if path.name.startswith(STAGING_PREFIX) and path.is_dir()]
    except OSError:
        return 0
    for path in candidates:
        try:
            newest = max([path.stat().st_mtime] + [item.stat().st_mtime for item in path.iterdir()])
        except OSError:
            continue
        if newest > cutoff:
            continue
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            removed += 1
    return removed


def sweep_staging(root: Path | None = None, *, older_than: float = STAGING_STALE_SECONDS) -> int:
    """Remove the staging folders of backups that never finished; returns how many. Without
    ``root``: the database's folder, and the temporary directory older releases staged in."""
    cutoff = time.time() - max(0.0, older_than)
    if root is not None:
        return _sweep_folder(Path(root), cutoff)
    roots = {Path(tempfile.gettempdir()).resolve()}
    with contextlib.suppress(Exception):
        roots.add(_sqlite_staging_root())
    return sum(_sweep_folder(folder, cutoff) for folder in sorted(roots))


@contextlib.contextmanager
def _staging(root: Path):
    """A private folder under ``root`` for one SQLite snapshot, removed when the work is done.
    mkdtemp creates it readable by this account only (on Windows from Python 3.13)."""
    root = Path(root)
    sweep_staging(root)
    folder = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=str(root)))
    try:
        yield folder
    finally:
        shutil.rmtree(folder, ignore_errors=True)


class _Counting:
    """A readable that counts the bytes read through it."""

    def __init__(self, src) -> None:
        self._src, self.count = src, 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._src.read(size)
        self.count += len(chunk)
        return chunk


def _collect(stream, sink: list, limit: int | None) -> threading.Thread:
    """Read a child's output on a thread of its own, so a full pipe never stalls the child.
    Keeps the first ``limit`` bytes (all of it with None) and reads the rest away."""
    def read() -> None:
        kept = 0
        for block in iter(lambda: stream.read(65536), b""):
            if limit is None or kept < limit:
                block = block if limit is None else block[: limit - kept]
                sink.append(block)
                kept += len(block)

    thread = threading.Thread(target=read, name="backup-pipe", daemon=True)
    thread.start()
    return thread


def _deadline(process, seconds: float) -> tuple[threading.Timer, threading.Event]:
    expired = threading.Event()

    def kill() -> None:
        expired.set()
        with contextlib.suppress(OSError):
            process.kill()

    timer = threading.Timer(seconds, kill)
    timer.daemon = True
    timer.start()
    return timer, expired


def _close_pipes(process) -> None:
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is not None:
            with contextlib.suppress(OSError):
                pipe.close()


def _text(chunks: list) -> str:
    return b"".join(chunks).decode("utf-8", "replace")


def _dump_into(command: list[str], env: dict, encrypted: Path, *, timeout: float = 3600) -> tuple[str, str, int]:
    """Run pg_dump with its archive on standard output and encrypt it as it arrives into
    ``encrypted``: (plaintext SHA-256, ciphertext SHA-256, plaintext bytes). The archive in
    clear never exists as a file, so no stop, crash or failed check can leave one behind."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,  # noqa: S603 - fixed tool, no shell
                               stderr=subprocess.PIPE, env=env)
    errors: list = []
    reader = _collect(process.stderr, errors, _ERROR_BYTES)
    timer, expired = _deadline(process, timeout)
    try:
        fernet = Fernet(backup_key())
        source = _Counting(process.stdout)
        with open(encrypted, "wb") as out:
            plain_sha, cipher_sha = encrypt_stream(fernet, source, out)
        returncode = process.wait()
    except BaseException:
        with contextlib.suppress(OSError):
            process.kill()
        process.wait()
        raise
    finally:
        timer.cancel()
        reader.join(timeout=10)
        _close_pipes(process)
    if expired.is_set():
        raise RuntimeError(f"pg_dump did not finish within {timeout:.0f} seconds")
    if returncode != 0:
        raise RuntimeError(f"pg_dump failed: {_text(errors).strip()[:400]}")
    return plain_sha, cipher_sha, source.count


def _pipe_plaintext(payload: Path, command: list[str], env: dict | None = None, *,
                    timeout: float = 3600) -> dict:
    """Run a tool with the plaintext of an encrypted payload on its standard input:
    ``returncode``, ``stdout``, ``stderr`` and the ``plaintext_sha256`` of every frame.

    The payload is decrypted to its end even when the tool stops reading early
    (``pg_restore --list`` reads only the table of contents), so the digest is of the whole
    plaintext and a damaged frame anywhere is found. Nothing of it is written to a disk.
    A payload that will not decrypt raises ValueError or InvalidToken."""
    fernet = Fernet(backup_key())
    with open(payload, "rb") as src:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # noqa: S603 - fixed tool, no shell
                                   stderr=subprocess.PIPE, env=env)
        output: list = []
        errors: list = []
        readers = [_collect(process.stdout, output, None), _collect(process.stderr, errors, _ERROR_BYTES)]
        timer, expired = _deadline(process, timeout)
        digest = hashlib.sha256()
        feeding = True
        try:
            for chunk in _frames(fernet, src):
                digest.update(chunk)
                if feeding:
                    try:
                        process.stdin.write(chunk)
                    except OSError:  # the tool stopped reading; the rest is still checked
                        feeding = False
            with contextlib.suppress(OSError):
                process.stdin.close()
            returncode = process.wait()
        except BaseException:
            with contextlib.suppress(OSError):
                process.kill()
            process.wait()
            raise
        finally:
            timer.cancel()
            for reader in readers:
                reader.join(timeout=10)
            _close_pipes(process)
    if expired.is_set():
        raise RuntimeError(f"{Path(command[0]).name} did not finish within {timeout:.0f} seconds")
    return {"returncode": returncode, "stdout": _text(output), "stderr": _text(errors),
            "plaintext_sha256": digest.hexdigest()}


def _discard(*paths: Path) -> None:
    """Remove what a backup that failed part-way had already written beside the manifest it
    never wrote: a set without its manifest is invisible to retention and to every tool, and
    each one was a whole encrypted database left until the disk filled."""
    for path in paths:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)


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


def capture_table_counts(dsn: str, *, conn=None) -> dict[str, int]:
    """Per-table row counts - the drill's reconciliation basis. Through ``conn`` when the
    caller holds the dump's snapshot (_exported_snapshot), else in a session of its own."""
    if conn is None:
        import psycopg

        with psycopg.connect(dsn, connect_timeout=15, autocommit=True) as own:
            own.execute("SELECT set_config('app.platform', %s, false)", (BACKUP_PURPOSE,))
            return capture_table_counts(dsn, conn=own)
    counts: dict[str, int] = {}
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


@contextlib.contextmanager
def _exported_snapshot(dsn: str):
    """One REPEATABLE READ transaction, held open while pg_dump runs: pg_dump dumps its
    exported snapshot (--snapshot), and the row counts and schema revision are read in it.

    Counted in a session of their own before pg_dump started, the counts were one moment and
    the dump another, so on a live server a row written in between made the restore drill
    fail a good backup. Yields (snapshot id, table counts, schema revision)."""
    import psycopg

    conn = psycopg.connect(dsn, connect_timeout=15, autocommit=True)
    try:
        conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        # pg_dump imports the snapshot when it starts; a server-side idle timeout must not
        # end this transaction before then.
        conn.execute("SET LOCAL idle_in_transaction_session_timeout = 0")
        conn.execute("SELECT set_config('app.platform', %s, false)", (BACKUP_PURPOSE,))
        snapshot = str(conn.execute("SELECT pg_export_snapshot()").fetchone()[0])
        counts = capture_table_counts(dsn, conn=conn)
        revision = _pg_schema_revision(dsn, conn=conn)
        yield snapshot, counts, revision
    finally:
        # Once pg_dump has imported the snapshot this session has done its work: a
        # connection lost meanwhile must not fail a dump that finished.
        with contextlib.suppress(Exception):
            conn.execute("ROLLBACK")
        conn.close()


def _member_name(member) -> str:
    """The name of a member of an artifact archive, or ValueError when it is not one ours.

    capture_artifacts writes regular files and nothing else, so a symlink, device or
    directory member means this archive is not one of ours. Skipping such a member only
    kept it out of the inventory - extraction still wrote it - so it is refused."""
    if not member.isfile():
        raise ValueError(f"Refusing non-file archive member: {member.name!r}")
    name = member.name.replace("\\", "/")
    if name.startswith("/") or ".." in name.split("/"):
        raise ValueError(f"Refusing unsafe archive member: {member.name!r}")
    return name


def artifact_inventory(archive: Path) -> dict:
    """The object count and inventory digest of an encrypted artifact archive, read as a
    stream. Verify needs only these, and extracting every object into the temporary folder
    to count them wrote the whole artifact store there once per backup."""
    import tarfile

    inventory: list[str] = []
    with open(archive, "rb") as src:
        plain = io.BufferedReader(_DecryptedReader(Fernet(backup_key()), src), buffer_size=1 << 20)
        with tarfile.open(fileobj=plain, mode="r|") as tar:
            for member in tar:
                inventory.append(_member_name(member).rsplit(".", 1)[0])
    digest = hashlib.sha256("\n".join(sorted(inventory)).encode("utf-8")).hexdigest()
    return {"objects": len(inventory), "inventory_sha256": digest}


# ---------------------------------------------------------------------------
# W3.5: the artifact tier is copied incrementally. Before, every set tarred the whole
# artifact store - staged in %TEMP% - and encrypted the tar again: seven sets held seven
# copies of every object, and each backup wrote the whole store twice. Objects are
# content-addressed and never change, so a set now copies only the objects the backup
# directory lacks into ``objects/<tenant>/<cc>/<content id>.enc`` (each encrypted with the
# backup key, so a backup copy is under one key as before), and records its inventory -
# every object it covers and that object's digest - encrypted beside its manifest.
# Retention removes what no remaining set's inventory names (collect_backup_objects).
# Sets written by older releases, with their artifact tar, still verify and restore.
# ---------------------------------------------------------------------------

OBJECTS_DIR = "objects"
OBJECTS_FORMAT = "objects-v1"
_OBJECT_SUFFIX = ".enc"
_TENANT_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
_CONTENT_ID = re.compile(r"[0-9a-f]{64}")


def _object_file(directory: Path, tenant: str, content_id: str) -> Path:
    """Where a backup directory keeps one object. An inventory is data: a name that is not
    a tenant and a content id is refused, never followed."""
    if not _TENANT_NAME.fullmatch(str(tenant)) or not _CONTENT_ID.fullmatch(str(content_id)):
        raise ValueError(f"Not an artifact object: {tenant!r}/{content_id!r}")
    return Path(directory) / OBJECTS_DIR / tenant / content_id[:2] / f"{content_id}{_OBJECT_SUFFIX}"


def _names_digest(names: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(names)).encode("utf-8")).hexdigest()


def read_object_inventory(directory: Path, artifacts: dict):
    """Yield one set's inventory entries - ``{"t", "id", "sha", "bytes", "new"}`` - decrypted as
    read. Raises ValueError or InvalidToken for an inventory that cannot be read."""
    path = _named_file(Path(directory), artifacts.get("inventory_file"))
    with open(path, "rb") as src:
        plain = io.TextIOWrapper(io.BufferedReader(_DecryptedReader(Fernet(backup_key()), src)), encoding="utf-8")
        for line in plain:
            if not line.strip():
                continue
            entry = json.loads(line)
            _object_file(directory, entry.get("t"), entry.get("id"))  # validates the names
            yield entry


def _known_objects(directory: Path) -> dict[tuple[str, str], dict]:
    """What the sets in a backup directory say about the objects in it, by (tenant, id)."""
    known: dict[tuple[str, str], dict] = {}
    for item in backup_sets(directory):
        artifacts = item["data"].get("artifacts") or {}
        if artifacts.get("format") != OBJECTS_FORMAT:
            continue
        try:
            for entry in read_object_inventory(directory, artifacts):
                known[(entry["t"], entry["id"])] = entry
        except (OSError, ValueError, InvalidToken):
            continue  # an object only that set knew is copied again
    return known


def _place_once(staging: Path, target: Path) -> bool:
    """Put a finished object in place unless one is there already; whether this one went in.
    Never over an existing object: another set's inventory records that one's digest."""
    try:
        os.link(staging, target)
        placed = True
    except FileExistsError:
        placed = False
    except OSError:  # a file system without hard links
        placed = not target.exists()
        if placed:
            os.replace(staging, target)
    finally:
        staging.unlink(missing_ok=True)
    return placed


def _sealed_digest(fernet: Fernet, path: Path) -> str | None:
    """The SHA-256 of an encrypted file when every frame of it opens with ``fernet``, else None."""
    digest = hashlib.sha256()

    class _Hashing:
        def __init__(self, handle) -> None:
            self._handle = handle

        def read(self, size: int = -1) -> bytes:
            chunk = self._handle.read(size)
            digest.update(chunk)
            return chunk

    try:
        with open(path, "rb") as handle:
            decrypt_stream(fernet, _Hashing(handle), _Discard())
    except (OSError, ValueError, InvalidToken):
        return None
    return digest.hexdigest()


def _touch(path: Path) -> None:
    """An object a set is about to name again is new again: collection's grace keeps it."""
    with contextlib.suppress(OSError):
        os.utime(path, None)


def capture_artifact_objects(directory: Path, inventory_file: Path) -> dict:
    """Copy the artifact objects the backup directory lacks, and write this set's inventory.

    An object already there is kept when its bytes still match the digest a set recorded
    for it, and written again when they do not - a damaged copy heals at the next backup
    instead of failing every verify after it. The manifest's block records the object
    count, the source bytes, a digest over the (tenant, content-id) set, the inventory's
    own digest and how much this set copied."""
    from backend import artifacts as _artifacts

    directory = Path(directory)
    fernet = Fernet(backup_key())
    known = _known_objects(directory)
    names: list[str] = []
    total = copied = copied_bytes = 0
    staged = inventory_file.with_name(inventory_file.name + ".partial")
    try:
        with open(staged, "wb") as raw:
            writer = EncryptingWriter(fernet, raw)
            for tenant, content_id, path in _artifacts.iter_objects():
                if not _TENANT_NAME.fullmatch(tenant) or not _CONTENT_ID.fullmatch(content_id):
                    continue
                target = _object_file(directory, tenant, content_id)
                recorded = known.get((tenant, content_id))
                new = False
                sha = None
                if target.exists():
                    if recorded is not None:
                        sha = recorded.get("sha") if sha256_file(target) == recorded.get("sha") else None
                    else:
                        # Copied by a set that never finished, or by one still being written in
                        # another process: kept when every frame of it opens.
                        sha = _sealed_digest(fernet, target)
                        new = sha is not None
                if sha is not None:
                    _touch(target)
                    size = target.stat().st_size
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    scratch = target.with_name(f"{target.name}.{uuid.uuid4().hex[:12]}.partial")
                    with open(path, "rb") as src, open(scratch, "wb") as out:
                        _plain, sha = encrypt_stream(fernet, src, out)
                    if target.exists():
                        target.unlink()  # a damaged copy: the one just written replaces it
                    if not _place_once(scratch, target):
                        sha = sha256_file(target)  # a backup in another process placed it first
                    size = target.stat().st_size
                    new = True
                    copied += 1
                    copied_bytes += size
                source_bytes = path.stat().st_size
                total += source_bytes
                names.append(f"{tenant}/{content_id}")
                line = json.dumps({"t": tenant, "id": content_id, "sha": sha, "bytes": size, "new": new})
                writer.write((line + "\n").encode("utf-8"))
            writer.finish()
        inventory_sha = sha256_file(staged)
        os.replace(staged, inventory_file)
    finally:
        staged.unlink(missing_ok=True)
    return {
        "format": OBJECTS_FORMAT,
        "objects": len(names),
        "ciphertext_bytes": total,
        "inventory_sha256": _names_digest(names),
        "inventory_file": inventory_file.name,
        "inventory_file_sha256": inventory_sha,
        "copied_objects": copied,
        "copied_bytes": copied_bytes,
        "file": None,
    }


def _verify_objects(directory: Path, artifacts: dict) -> list[str]:
    """A set's artifact objects against its inventory: the inventory's digest and that it
    opens with this install's key, every object present with the digest recorded for it,
    and every object this set copied decrypting frame by frame. Reads; writes nothing."""
    try:
        inventory = _named_file(directory, artifacts.get("inventory_file"))
    except ValueError as exc:
        return [str(exc)]
    if not inventory.exists():
        return [f"{inventory.name} is missing"]
    problems: list[str] = []
    if sha256_file(inventory) != artifacts.get("inventory_file_sha256"):
        problems.append(f"{inventory.name} does not match its recorded digest")
    try:
        entries = list(read_object_inventory(directory, artifacts))
    except (OSError, ValueError, InvalidToken) as exc:
        return problems + [f"{inventory.name} cannot be read with this install's backup key ({type(exc).__name__})"]
    if len(entries) != artifacts.get("objects") or \
            _names_digest([f"{entry['t']}/{entry['id']}" for entry in entries]) != artifacts.get("inventory_sha256"):
        problems.append("the artifact inventory does not hold the objects recorded")
    fernet = Fernet(backup_key())
    missing = damaged = 0
    for entry in entries:
        path = _object_file(directory, entry["t"], entry["id"])
        if not path.exists():
            missing += 1
        elif sha256_file(path) != entry.get("sha"):
            damaged += 1
        elif entry.get("new"):
            try:
                with open(path, "rb") as src:
                    decrypt_stream(fernet, src, _Discard())
            except (ValueError, InvalidToken):
                damaged += 1
    if missing:
        problems.append(f"{missing} artifact object(s) are missing")
    if damaged:
        problems.append(f"{damaged} artifact object(s) do not match their recorded digest")
    return problems


def collect_backup_objects(directory: Path | None = None, *, grace_seconds: float = STAGING_STALE_SECONDS) -> int:
    """Remove the objects no set in a backup directory names any more; returns how many.

    Nothing is removed while any manifest there cannot be read, or any set's inventory
    cannot be read: an object that set needs might look unnamed. An object younger than
    the grace period stays, since a backup still writing its set names it once its
    manifest is written; so does the scratch file of a copy in progress."""
    directory = Path(directory) if directory is not None else backup_dir()
    root = directory / OBJECTS_DIR
    if not root.is_dir():
        return 0
    sets = backup_sets(directory)
    if len(sets) != len(list_manifests(directory)):
        logger.warning("Backup object collection skipped: a manifest in %s cannot be read", directory)
        return 0
    named: set[tuple[str, str]] = set()
    for item in sets:
        artifacts = item["data"].get("artifacts") or {}
        if artifacts.get("format") != OBJECTS_FORMAT:
            continue
        try:
            named.update((entry["t"], entry["id"]) for entry in read_object_inventory(directory, artifacts))
        except (OSError, ValueError, InvalidToken) as exc:
            logger.warning("Backup object collection skipped: an inventory cannot be read (%s)", type(exc).__name__)
            return 0
    cutoff = time.time() - max(0.0, grace_seconds)
    removed = 0
    for path in root.glob(f"*/*/*{_OBJECT_SUFFIX}"):
        tenant, content_id = path.parent.parent.name, path.name[: -len(_OBJECT_SUFFIX)]
        if (tenant, content_id) in named:
            continue
        try:
            if path.stat().st_mtime > cutoff:
                continue
            path.unlink()
            removed += 1
        except OSError:
            continue
    for scratch in root.glob("*/*/*.partial"):
        with contextlib.suppress(OSError):
            if scratch.stat().st_mtime <= cutoff:
                scratch.unlink()
    return removed


def _validated_members(archive: Path) -> list[str]:
    """Every member of a legacy artifact archive, refused whole if one is not ours."""
    import tarfile

    names: list[str] = []
    with open(archive, "rb") as src:
        plain = io.BufferedReader(_DecryptedReader(Fernet(backup_key()), src), buffer_size=1 << 20)
        with tarfile.open(fileobj=plain, mode="r|") as tar:
            for member in tar:
                names.append(_member_name(member))
    return names


def restore_artifacts(archive: Path, destination: Path) -> dict:
    """Unpack a legacy artifact archive (the tar older releases wrote) into ``destination``.

    Read twice as a decrypting stream, never as a file in clear: once to refuse an archive
    with any member that is not ours before anything is unpacked, then to unpack it.
    Returns the object count and the inventory digest, to reconcile with the manifest."""
    import tarfile

    destination.mkdir(parents=True, exist_ok=True)
    inventory = [name.rsplit(".", 1)[0] for name in _validated_members(archive)]
    with open(archive, "rb") as src:
        plain = io.BufferedReader(_DecryptedReader(Fernet(backup_key()), src), buffer_size=1 << 20)
        with tarfile.open(fileobj=plain, mode="r|") as tar:
            for member in tar:
                _member_name(member)
                # Belt and braces: the "data" filter refuses absolute paths, traversal and
                # special files again at extraction time (the supported floor is 3.12).
                tar.extract(member, destination, filter="data")
    return {"objects": len(inventory), "inventory_sha256": _names_digest(inventory)}


def create_logical_backup(dsn: str, out_dir: Path | None = None) -> Path:
    """pg_dump -Fc -> encrypt -> manifest. Returns the manifest path."""
    directory = out_dir or backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    encrypted = directory / f"sentro_{stamp}.dump.enc"
    inventory = directory / f"sentro_{stamp}.objects.enc"
    manifest_path = directory / f"sentro_{stamp}{MANIFEST_SUFFIX}"

    # C11: the password goes to pg_dump through its environment, not its command line.
    conninfo, tool_env = pg_tool_environment(dsn)
    # W3.5: pg_dump writes to a pipe that is encrypted as it is read. A dump in clear never
    # exists as a file, so nothing - a failed returncode check, a timeout, a stopped service -
    # can leave one behind; one used to sit in data/backups beside seven encrypted sets,
    # and later in %TEMP%.
    try:
        with _exported_snapshot(dsn) as (snapshot, counts, revision):
            # Row security stays on and the session names the backup purpose. The data is
            # written as INSERTs: PostgreSQL refuses COPY FROM into a table with row-level
            # security, so a COPY-format dump could not be restored under FORCEd policies.
            plain_sha, cipher_sha, plain_bytes = _dump_into(
                [_pg_bin("pg_dump"), "--format=custom", "--no-password", "--enable-row-security",
                 "--inserts", "--rows-per-insert=500", f"--snapshot={snapshot}", f"--dbname={conninfo}"],
                _backup_session(tool_env), encrypted, timeout=3600,
            )
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "kind": "logical",
            "format": INSERT_FORMAT,
            "file": encrypted.name,
            "plaintext_bytes": plain_bytes,
            "ciphertext_bytes": encrypted.stat().st_size,
            "plaintext_sha256": plain_sha,
            "ciphertext_sha256": cipher_sha,
            "schema_revision": revision,
            "table_counts": counts,
            "artifacts": capture_artifact_objects(directory, inventory),
        }
        _write_json_whole(manifest_path, manifest)
    except BaseException:
        # Objects this set copied stay: unnamed, collection removes them past their grace.
        _discard(encrypted, inventory, manifest_path.with_name(manifest_path.name + ".partial"))
        raise
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
_OBJECT_NAME = re.compile(r"[0-9a-f]{64}\.enc")


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
    objects = (directory / OBJECTS_DIR).resolve()
    for folder, _subfolders, files in os.walk(directory):
        in_objects = Path(folder).resolve().is_relative_to(objects)
        for filename in sorted(files):
            # W3.5: the backup's object store holds one file per artifact object, each
            # encrypted by capture_artifact_objects and digest-checked by every verify.
            # Named as one, it is not read here - at startup, thousands of them would use
            # up the files examined before the rest of the directory was.
            if in_objects and _OBJECT_NAME.fullmatch(filename):
                continue
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


def latest_backup_age_seconds(directory: Path | None = None, *, verified: bool = False) -> float | None:
    """Age of the newest set - of the newest VERIFIED one with ``verified`` - or None.

    Read through backup_sets: by when each set was taken, a half-written or damaged
    manifest skipped. The last manifest by NAME was a SQLite set (``sentro_sqlite_...``
    sorts after ``sentro_2026...``) long after an install moved to PostgreSQL, so the age
    was weeks while an hour-old set existed, and one unreadable manifest raised."""
    sets = [item for item in backup_sets(directory) if item["verified"] or not verified]
    if not sets:
        return None
    return max(0.0, (datetime.now(timezone.utc) - sets[0]["created_at"]).total_seconds())


def prune_backups(keep: int = 7, directory: Path | None = None) -> int:
    """``backup create --keep N``: retention keeping the newest N VERIFIED sets; returns how
    many sets were removed.

    It is apply_retention - the schedule's own rule. Sorting by file name and keeping the
    last N removed the PostgreSQL sets (``sentro_2026...`` sorts before ``sentro_sqlite_...``)
    including the one just taken, counted unverified sets as kept ones, and deleted any
    path a manifest named."""
    if keep <= 0:
        return 0
    return len(apply_retention(directory, keep_sets=keep))


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


def _pg_schema_revision(dsn: str, *, conn=None) -> int | None:
    if conn is None:
        import psycopg

        with psycopg.connect(dsn, connect_timeout=15) as own:
            return _pg_schema_revision(dsn, conn=own)
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
    consistent while the database is in use; its plaintext never outlives this call, and is
    staged beside the database it copies (W3.5), never in %TEMP%."""
    import sqlite3

    directory = out_dir or backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    encrypted = directory / f"sentro_sqlite_{stamp}.sqlite.enc"
    inventory = directory / f"sentro_sqlite_{stamp}.objects.enc"
    manifest_path = directory / f"sentro_sqlite_{stamp}{MANIFEST_SUFFIX}"
    if not Path(db_path).exists():
        raise RuntimeError(f"There is no database at {db_path} to back up.")
    with _staging(Path(db_path).resolve().parent) as staging:
        snapshot = staging / f"sentro_sqlite_{stamp}.sqlite"
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
            plain_bytes = snapshot.stat().st_size
            snapshot.unlink(missing_ok=True)
            manifest = {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "kind": "sqlite",
                "format": "sqlite-online-backup+chunked-fernet",
                "file": encrypted.name,
                "plaintext_bytes": plain_bytes,
                "ciphertext_bytes": encrypted.stat().st_size,
                "plaintext_sha256": plain_sha,
                "ciphertext_sha256": cipher_sha,
                "schema_revision": facts["schema_revision"],
                "table_counts": facts["table_counts"],
                "artifacts": capture_artifact_objects(directory, inventory),
            }
            _write_json_whole(manifest_path, manifest)
        except BaseException:
            _discard(encrypted, inventory, manifest_path.with_name(manifest_path.name + ".partial"))
            raise
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


def _verify_sqlite_payload(payload: Path, manifest: dict) -> list[str]:
    """Decrypt a SQLite set beside this install's database - never into %TEMP% (W3.5) - and
    check its digest, its integrity, every table's row count and its schema revision."""
    problems: list[str] = []
    with _staging(_sqlite_staging_root()) as scratch:
        plain = scratch / "payload"
        try:
            plain_sha = decrypt_file(payload, plain)
        except Exception as exc:  # wrong key, truncation, tampering
            return [f"{payload.name} cannot be decrypted with this install's backup key ({type(exc).__name__})"]
        if plain_sha != manifest.get("plaintext_sha256"):
            problems.append("the decrypted database does not match its recorded digest")
        facts = _sqlite_facts(plain)
        if facts["integrity"] != "ok":
            problems.append(f"integrity check: {facts['integrity']}")
        if facts["table_counts"] != manifest.get("table_counts"):
            problems.append("row counts differ from the ones recorded at backup time")
        if facts["schema_revision"] != manifest.get("schema_revision"):
            problems.append("the schema revision differs from the recorded one")
    return problems


def _verify_logical_payload(payload: Path, manifest: dict) -> list[str]:
    """Decrypt a PostgreSQL set into ``pg_restore --list`` (W3.5: a pipe, no file in clear):
    the whole plaintext against its digest, and pg_restore able to read its contents."""
    try:
        listed = _pipe_plaintext(payload, [_pg_bin("pg_restore"), "--list"])
    except (ValueError, InvalidToken) as exc:  # wrong key, truncation, tampering
        return [f"{payload.name} cannot be decrypted with this install's backup key ({type(exc).__name__})"]
    problems: list[str] = []
    if listed["plaintext_sha256"] != manifest.get("plaintext_sha256"):
        problems.append("the decrypted database does not match its recorded digest")
    if listed["returncode"] != 0:
        problems.append(f"pg_restore cannot read the archive: {listed['stderr'].strip()[:300]}")
    return problems


def verify_backup(manifest_path: Path) -> dict:
    """Check a backup set against its manifest: every digest, and for SQLite the integrity
    check and every table's row count; for PostgreSQL that pg_restore can read the
    archive's table of contents; the artifact objects against the set's inventory. Nothing
    is kept, and nothing in clear is staged anywhere but beside a SQLite database."""
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    payload = manifest_path.parent / str(manifest.get("file") or "")
    if not payload.exists():
        return {"ok": False, "manifest": str(manifest_path), "problems": [f"{payload.name} is missing"]}
    if sha256_file(payload) != manifest.get("ciphertext_sha256"):
        problems.append(f"{payload.name} does not match its recorded digest")
    if manifest.get("kind") == "sqlite":
        problems += _verify_sqlite_payload(payload, manifest)
    else:
        problems += _verify_logical_payload(payload, manifest)
    artifacts = manifest.get("artifacts") or {}
    if artifacts.get("format") == OBJECTS_FORMAT:
        problems += _verify_objects(manifest_path.parent, artifacts)
    elif artifacts.get("file"):
        archive = manifest_path.parent / artifacts["file"]
        if not archive.exists():
            problems.append(f"{archive.name} is missing")
        else:
            try:
                listed_objects = artifact_inventory(archive)
            except Exception as exc:  # wrong key, truncation, tampering, a member not ours
                problems.append(f"{archive.name} cannot be read with this install's backup key "
                                f"({type(exc).__name__})")
            else:
                if listed_objects["objects"] != artifacts.get("objects") or \
                        listed_objects["inventory_sha256"] != artifacts.get("inventory_sha256"):
                    problems.append("the artifact archive does not hold the objects recorded")
    elif int(artifacts.get("objects") or 0):
        problems.append("the manifest records artifact objects and names no archive or inventory")
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
    # The database being replaced is backed up into this install's own backup directory.
    # Beside the restored manifest it went wherever that copy was - restoring from the
    # off-host copy wrote it to the off-host share.
    previous = create_logical_backup(dsn)
    conninfo, tool_env = pg_tool_environment(dsn)
    # W3.5: the archive reaches pg_restore through its standard input, decrypted as it is
    # read - twice, once for its table of contents and once to restore. Read from a pipe,
    # pg_restore restores in the archive's order, which is the order --use-list keeps.
    payload = manifest_path.parent / manifest["file"]
    listed = _pipe_plaintext(payload, [_pg_bin("pg_restore"), "--list"])
    if listed["returncode"] != 0:
        raise RuntimeError(f"pg_restore cannot read the archive: {listed['stderr'].strip()[:300]}")
    entries = [line for line in listed["stdout"].splitlines() if not re.search(r"\bEXTENSION\b", line)]
    # The list names the archive's objects and holds none of their rows; it is written
    # beside this install's backups and removed with the restore.
    order = backup_dir() / f".restore-{uuid.uuid4().hex[:12]}.list"
    order.parent.mkdir(parents=True, exist_ok=True)
    order.write_text("\n".join(entries) + "\n", encoding="utf-8")
    try:
        completed = _pipe_plaintext(
            payload,
            [_pg_bin("pg_restore"), "--clean", "--if-exists", "--no-owner", "--single-transaction", "--exit-on-error",
             "--enable-row-security", "--no-password", "--use-list", str(order), f"--dbname={conninfo}"],
            _backup_session(tool_env), timeout=3600,
        )
    finally:
        order.unlink(missing_ok=True)
    if completed["returncode"] != 0:
        raise RuntimeError(f"pg_restore failed; the transaction rolled back and nothing changed: "
                           f"{completed['stderr'].strip()[:400]}")
    counts = capture_table_counts(dsn)
    recorded = manifest.get("table_counts") or {}
    differ = sorted(table for table, rows in recorded.items() if counts.get(table) != rows)
    return {"restored": str(manifest_path), "previous_database": str(previous),
            "schema_revision": _pg_schema_revision(dsn), "tables_differing": differ,
            "artifact_objects_added": _add_artifact_objects(manifest_path, manifest, artifact_dir)}


def _add_artifact_objects(manifest_path: Path, manifest: dict, artifact_dir: Path | None) -> int:
    """The backup's artifact objects that the store lacks. Objects are content-addressed
    and never change, so adding them loses nothing. Each is decrypted from the backup's
    object store straight into its place in the artifact store (W3.5); a legacy set's tar
    is unpacked into a folder beside the artifact store, never %TEMP%."""
    artifacts = manifest.get("artifacts") or {}
    from backend import artifacts as _artifacts

    target = Path(artifact_dir) if artifact_dir else _artifacts.artifact_root()
    added = 0
    if artifacts.get("format") == OBJECTS_FORMAT:
        fernet = Fernet(backup_key())
        for entry in read_object_inventory(manifest_path.parent, artifacts):
            tenant, content_id = entry["t"], entry["id"]
            destination = target / tenant / content_id[:2] / f"{content_id}{_artifacts.OBJECT_SUFFIX}"
            if destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            # The store's own scratch suffix: its collection sweeps one a stop left behind.
            scratch = destination.with_name(f"{destination.name}.{uuid.uuid4().hex[:12]}.partial")
            try:
                with open(_object_file(manifest_path.parent, tenant, content_id), "rb") as src, \
                        open(scratch, "wb") as out:
                    decrypt_stream(fernet, src, out)
                os.replace(scratch, destination)
            finally:
                scratch.unlink(missing_ok=True)
            added += 1
        return added
    if not artifacts.get("file"):
        return 0
    target.mkdir(parents=True, exist_ok=True)
    # Beside the store, not in it: inside, the folder would read as a workspace of objects.
    scratch_root = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=str(target.parent)))
    try:
        restore_artifacts(manifest_path.parent / artifacts["file"], scratch_root)
        for item in scratch_root.rglob(f"*{_artifacts.OBJECT_SUFFIX}"):
            # The archive names an object <tenant>/<content id>; the store keeps it under
            # one fan-out level, <tenant>/<first two hex>/<content id> (artifacts.object_path).
            # Copied back without that level it sat where nothing reads it (M3 exit review).
            tenant = item.relative_to(scratch_root).parts[0]
            content_id = item.name[: -len(_artifacts.OBJECT_SUFFIX)]
            destination = target / tenant / content_id[:2] / item.name
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, destination)
                added += 1
    finally:
        shutil.rmtree(scratch_root, ignore_errors=True)
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


def keep_one_failed_set(manifest_path: Path) -> list[str]:
    """Record that a set did not verify (``verify_failed_at``) and remove the sets that
    failed before it; returns the names of the manifests removed.

    A failed set never counts, but it is newer than every verified set, so retention keeps
    it - and the schedule retries a failure hourly, each retry a whole database, until the
    disk filled. The newest failed set stays for whoever looks into why."""
    manifest_path = Path(manifest_path)
    removed: list[str] = []
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["verify_failed_at"] = datetime.now(timezone.utc).isoformat()
        _write_json_whole(manifest_path, document)
        for item in backup_sets(manifest_path.parent):
            if item["manifest"] != manifest_path and item["data"].get("verify_failed_at") and not item["verified"]:
                _remove_set(item)
                removed.append(item["manifest"].name)
    except (OSError, ValueError) as exc:
        logger.warning("Could not clear the backup sets that failed to verify: %s", type(exc).__name__)
    return removed


def _named_file(directory: Path, name) -> Path:
    """A file a manifest names: a plain name beside the manifest. A manifest is data, and
    one naming ..\\..\\something must not make retention delete, or the copy carry, it."""
    text = str(name or "")
    if not text or text in {".", ".."} or Path(text).name != text or "/" in text or "\\" in text:
        raise ValueError(f"The manifest names {text!r}, which is not a file beside it.")
    return directory / text


def set_files(manifest_path: Path, document: dict) -> list[tuple[Path, str | None]]:
    """A set's own encrypted files - the database, and its artifact inventory (or a legacy
    set's artifact archive) - each with the digest its manifest records. The objects an
    inventory names are shared between sets: collect_backup_objects removes them."""
    manifest_path = Path(manifest_path)
    files = [(_named_file(manifest_path.parent, document.get("file")), document.get("ciphertext_sha256"))]
    artifacts = document.get("artifacts") or {}
    if artifacts.get("format") == OBJECTS_FORMAT:
        files.append((_named_file(manifest_path.parent, artifacts.get("inventory_file")),
                      artifacts.get("inventory_file_sha256")))
    elif artifacts.get("file"):
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
        _collect_quietly(directory)
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
    _collect_quietly(directory)
    return removed


def _collect_quietly(directory: Path | None) -> None:
    """After retention: the objects no remaining set names (W3.5). A fault here never
    undoes what retention did; the next run collects."""
    try:
        collected = collect_backup_objects(directory)
        if collected:
            logger.info("Backup retention removed %s artifact object(s) no set names", collected)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Backup object collection failed: %s", type(exc).__name__)


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
    artifacts = document.get("artifacts") or {}
    if artifacts.get("format") == OBJECTS_FORMAT:
        # W3.5: only the objects the destination lacks travel; one it holds with the size
        # recorded is named again (its mtime refreshed, so its collection waits).
        for entry in read_object_inventory(manifest_path.parent, artifacts):
            source = _object_file(manifest_path.parent, entry["t"], entry["id"])
            copy = _object_file(destination, entry["t"], entry["id"])
            if copy.exists() and copy.stat().st_size == int(entry.get("bytes") or -1):
                _touch(copy)
                continue
            copy.parent.mkdir(parents=True, exist_ok=True)
            _copy_whole(source, copy, entry.get("sha"))
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
        if stage == "verify" and manifest is not None:
            keep_one_failed_set(manifest)
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

    In production a failed last attempt (unless a set taken after it has verified), or a
    newest VERIFIED set older than
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
    failed_at = _created_at({"created_at": attempt.get("at")}) if attempt else None
    # A failure a later verified set has made good is history, not the state of the backups.
    superseded = verified is not None and failed_at is not None and verified["created_at"] > failed_at
    if attempt and not attempt.get("ok") and not superseded:
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
