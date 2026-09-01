"""Encrypted database backups and recovery evidence (roadmap Phase 1, DB-02).

Design:

- Backups are ``pg_dump`` custom-format archives, encrypted at rest with a
  dedicated Fernet key (never the vault key - a backup escaping the host must
  not also unlock stored scan credentials).
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


def encrypt_file(source: Path, dest: Path) -> tuple[str, str]:
    """Chunked-Fernet encrypt; returns (plaintext_sha256, ciphertext_sha256)."""
    fernet = Fernet(backup_key())
    plain_hash, cipher_hash = hashlib.sha256(), hashlib.sha256()
    with open(source, "rb") as src, open(dest, "wb") as out:
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


def decrypt_file(source: Path, dest: Path) -> str:
    """Decrypt a chunked-Fernet file; returns the plaintext SHA-256."""
    fernet = Fernet(backup_key())
    plain_hash = hashlib.sha256()
    with open(source, "rb") as src, open(dest, "wb") as out:
        while True:
            header = src.read(4)
            if not header:
                break
            if len(header) != 4:
                raise ValueError("Truncated backup: bad chunk header")
            (token_len,) = struct.unpack(">I", header)
            token = src.read(token_len)
            if len(token) != token_len:
                raise ValueError("Truncated backup: incomplete chunk")
            chunk = fernet.decrypt(token)
            plain_hash.update(chunk)
            out.write(chunk)
    return plain_hash.hexdigest()


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


def create_logical_backup(dsn: str, out_dir: Path | None = None) -> Path:
    """pg_dump -Fc -> encrypt -> manifest. Returns the manifest path."""
    directory = out_dir or backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    plain = directory / f"sentro_{stamp}.dump"
    encrypted = directory / f"sentro_{stamp}.dump.enc"
    manifest_path = directory / f"sentro_{stamp}{MANIFEST_SUFFIX}"

    counts = capture_table_counts(dsn)
    completed = subprocess.run(
        [_pg_bin("pg_dump"), "--format=custom", "--no-password", f"--dbname={dsn}",
         "--file", str(plain)],
        capture_output=True, text=True, timeout=3600,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {completed.stderr.strip()[:400]}")
    try:
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
        manifest_path.unlink(missing_ok=True)
        removed += 1
    return removed
