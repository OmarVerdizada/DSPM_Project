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


def capture_table_counts(dsn: str) -> dict[str, int]:
    """Per-table row counts at dump time - the drill's reconciliation basis."""
    from backend import db as _db  # local import to honour the caller's env

    counts: dict[str, int] = {}
    import psycopg

    with psycopg.connect(dsn, connect_timeout=15) as conn:
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
                if not member.isfile():
                    continue
                name = member.name.replace("\\", "/")
                if name.startswith("/") or ".." in name.split("/"):
                    raise ValueError(f"Refusing unsafe archive member: {member.name!r}")
                inventory.append(name.rsplit(".", 1)[0])
            try:
                # Belt and braces: members were validated above, and the "data"
                # filter refuses absolute paths, traversal and special files at
                # extraction time. The filter argument does not exist before
                # Python 3.12, where the manual check above stands alone.
                tar.extractall(destination, filter="data")
            except TypeError:
                tar.extractall(destination)
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
    # The try starts BEFORE pg_dump, not after it. The finally below was already
    # here, but a dump that succeeded and then failed the returncode check - or
    # timed out after writing part of a file - left an unencrypted copy of the
    # whole database in the backup directory. One was sitting in data/backups on
    # this tree next to seven encrypted ones.
    try:
        completed = subprocess.run(
            [_pg_bin("pg_dump"), "--format=custom", "--no-password", f"--dbname={dsn}",
             "--file", str(plain)],
            capture_output=True, text=True, timeout=3600,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {completed.stderr.strip()[:400]}")
        plain_sha, cipher_sha = encrypt_file(plain, encrypted)
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "kind": "logical",
            "format": "pg_dump-custom+chunked-fernet",
            "file": encrypted.name,
            "plaintext_bytes": plain.stat().st_size,
            "ciphertext_bytes": encrypted.stat().st_size,
            "plaintext_sha256": plain_sha,
            "ciphertext_sha256": cipher_sha,
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
