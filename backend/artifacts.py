"""Immutable, encrypted, content-addressed artifact store (Phase 5, DB-07).

Scan report bodies are the single largest thing the database holds: measured on
this installation, 24 rows of ``scan_reports.report_json`` account for 251.6 MB
of a 679 MB SQLite file, the largest single body being 45 MB. Storing them as
row values makes every backup, restore, replication stream and page cache carry
document bodies that are only ever read whole, by id. They belong in an object
store; the database keeps the reference.

Design decisions worth stating, because each one has an alternative that looks
reasonable until it is examined:

- **Content-addressed.** An object's name is the SHA-256 of its plaintext. A
  body is therefore written once no matter how many times it is saved (finding
  lifecycle updates re-save the same report repeatedly), and a read verifies
  the hash, so silent corruption on disk surfaces as an error rather than as
  wrong data.
- **Immutable.** Objects are never modified in place. A changed report is a new
  object; the old one becomes unreferenced and is removed by ``prune()``, never
  overwritten.
- **Tenant-scoped paths, not a global content pool.** Global dedup would let
  one tenant's object satisfy another tenant's read, which turns erasure into a
  reference-counting problem and makes "delete this customer's data" something
  the filesystem layout cannot express. Tenant-scoped subtrees keep erasure a
  subtree delete, at the cost of storing an identical body twice for two
  tenants - a trade this product should always take.
- **Compressed, then encrypted.** Report bodies are JSON and compress by
  roughly an order of magnitude, while Fernet's base64 layer inflates whatever
  it wraps by a third. Storing them raw would make the object store *larger*
  than the database rows it replaced - 251 MB of bodies became 335 MB of
  ciphertext before compression was added. Compress-then-encrypt is safe here
  because these are whole documents written once, not a channel an attacker
  can influence adaptively.
- **Encrypted at rest with a dedicated key** (``DSPM_ARTIFACT_KEY``), distinct
  from the vault key and the backup key, so compromise of one does not cascade.
  **The artifact key joins the recovery inventory**: a database restore without
  it recovers metadata and no report bodies.

Writes are durable before the database row that references them, so the only
failure that can outlive a crash is an unreferenced object, which ``prune()``
collects. The reverse ordering would produce a reference to a body that does
not exist - a dangling report.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet

from backend.backup import decrypt_stream, encrypt_stream

OBJECT_SUFFIX = ".enc"
# Object format marker. "SA02" = gzip-compressed plaintext inside the chunked
# Fernet framing. A file without the marker is a pre-compression object and is
# read as the framing directly, so old objects keep working.
_MAGIC_GZIP = b"SA02"
_SAFE_TENANT = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_IS_PRODUCTION = os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}


class ArtifactMissing(RuntimeError):
    """A referenced artifact is not present in the store."""


class ArtifactCorrupted(RuntimeError):
    """A stored artifact did not hash to its content id."""


@dataclass(frozen=True)
class ArtifactRef:
    """What the database stores in place of the body."""

    tenant_id: str
    content_id: str  # SHA-256 hex of the plaintext
    size_bytes: int


def artifact_root() -> Path:
    return Path(os.getenv("DSPM_ARTIFACT_DIR", "data/artifacts")).resolve()


def _local_key_path() -> Path:
    configured = os.getenv("DSPM_LOCAL_ARTIFACT_KEY_PATH", "").strip()
    return Path(configured) if configured else Path.home() / ".dspm" / "artifact_key"


def artifact_key() -> bytes:
    """Resolve the artifact key: env in production, dev keyfile outside data/.

    The keyfile deliberately does not live under ``data/`` - a copy of the data
    directory must not contain the key that decrypts it.
    """
    env_key = os.getenv("DSPM_ARTIFACT_KEY", "").strip()
    if env_key:
        return env_key.encode("ascii")
    if _IS_PRODUCTION:
        raise RuntimeError(
            "DSPM_ARTIFACT_KEY must be set in production (Fernet key). It decrypts "
            "stored report bodies and belongs in the recovery inventory."
        )
    path = _local_key_path()
    if path.exists():
        return path.read_text(encoding="ascii").strip().encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    path.write_text(key.decode("ascii"), encoding="ascii")
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return key


def _safe_tenant(tenant_id: str) -> str:
    """Tenant ids reach the filesystem as directory names; anything outside the
    identifier charset is a path-traversal attempt, not a tenant."""
    tenant = str(tenant_id or "").strip()
    if not _SAFE_TENANT.match(tenant):
        raise ValueError(f"Unsafe tenant id for artifact storage: {tenant_id!r}")
    return tenant


def object_path(tenant_id: str, content_id: str) -> Path:
    tenant = _safe_tenant(tenant_id)
    cid = str(content_id or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise ValueError(f"Not a content id: {content_id!r}")
    # One fan-out level keeps directory sizes reasonable without deep nesting.
    return artifact_root() / tenant / cid[:2] / f"{cid}{OBJECT_SUFFIX}"


def put_bytes(tenant_id: str, payload: bytes) -> ArtifactRef:
    """Store a body and return its reference. Idempotent by construction."""
    content_id = hashlib.sha256(payload).hexdigest()
    destination = object_path(tenant_id, content_id)
    ref = ArtifactRef(_safe_tenant(tenant_id), content_id, len(payload))
    if destination.exists():
        return ref  # identical content is already stored

    destination.parent.mkdir(parents=True, exist_ok=True)
    fernet = Fernet(artifact_key())
    # Write to a temporary name and rename, so a crash mid-write cannot leave a
    # truncated object visible under a content id that promises the full body.
    staging = destination.with_suffix(f".{os.getpid()}.partial")
    try:
        import io as _io

        compressed = gzip.compress(payload, compresslevel=6)
        with open(staging, "wb") as out:
            out.write(_MAGIC_GZIP)
            encrypt_stream(fernet, _io.BytesIO(compressed), out)
        os.replace(staging, destination)
    finally:
        staging.unlink(missing_ok=True)
    try:
        os.chmod(destination, 0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return ref


def put_text(tenant_id: str, text: str) -> ArtifactRef:
    return put_bytes(tenant_id, text.encode("utf-8"))


def get_bytes(tenant_id: str, content_id: str) -> bytes:
    """Read a body, verifying it still hashes to its content id."""
    source = object_path(tenant_id, content_id)
    if not source.exists():
        raise ArtifactMissing(
            f"Artifact {content_id[:12]}... is referenced but not in the store. "
            "Restore the artifact tier alongside the database."
        )
    import io as _io

    buffer = _io.BytesIO()
    with open(source, "rb") as src:
        marker = src.read(len(_MAGIC_GZIP))
        if marker != _MAGIC_GZIP:
            src.seek(0)  # pre-compression object: the framing starts at byte 0
        decrypt_stream(Fernet(artifact_key()), src, buffer)
    payload = buffer.getvalue()
    if marker == _MAGIC_GZIP:
        payload = gzip.decompress(payload)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != str(content_id).lower():
        raise ArtifactCorrupted(
            f"Artifact {content_id[:12]}... hashed to {actual[:12]}...; the stored "
            "object does not match its content id."
        )
    return payload


def get_text(tenant_id: str, content_id: str) -> str:
    return get_bytes(tenant_id, content_id).decode("utf-8")


def exists(tenant_id: str, content_id: str) -> bool:
    try:
        return object_path(tenant_id, content_id).exists()
    except ValueError:
        return False


def delete_tenant(tenant_id: str) -> int:
    """Erase a tenant's whole subtree. Returns the number of objects removed.

    This is what makes tenant erasure whole once bodies leave the database.
    """
    tenant = _safe_tenant(tenant_id)
    root = artifact_root() / tenant
    if not root.exists():
        return 0
    removed = sum(1 for _ in root.rglob(f"*{OBJECT_SUFFIX}"))
    shutil.rmtree(root, ignore_errors=True)
    return removed


def iter_objects(tenant_id: str | None = None):
    """Yield (tenant_id, content_id, path) for every stored object."""
    root = artifact_root()
    if not root.exists():
        return
    tenants = [root / _safe_tenant(tenant_id)] if tenant_id else sorted(
        p for p in root.iterdir() if p.is_dir()
    )
    for tenant_dir in tenants:
        if not tenant_dir.exists():
            continue
        for path in sorted(tenant_dir.rglob(f"*{OBJECT_SUFFIX}")):
            yield tenant_dir.name, path.stem, path


def store_stats() -> dict:
    """Inventory for health, backup manifests and cutover evidence."""
    count = 0
    total = 0
    tenants: set[str] = set()
    for tenant, _cid, path in iter_objects():
        count += 1
        total += path.stat().st_size
        tenants.add(tenant)
    return {
        "objects": count,
        "ciphertext_bytes": total,
        "tenants": len(tenants),
        "root": str(artifact_root()),
    }


def prune(referenced: set[tuple[str, str]], grace_seconds: int = 3600) -> int:
    """Remove objects no database row references.

    ``referenced`` is the live set of ``(tenant_id, content_id)`` pairs. Objects
    younger than ``grace_seconds`` are always kept: a body is written before the
    row that references it, so a just-written object can legitimately look
    unreferenced for the width of a transaction.
    """
    cutoff = time.time() - max(0, grace_seconds)
    removed = 0
    for tenant, content_id, path in list(iter_objects()):
        if (tenant, content_id) in referenced:
            continue
        try:
            if path.stat().st_mtime > cutoff:
                continue
            path.unlink()
            removed += 1
        except OSError:  # pragma: no cover - concurrent removal
            continue

    # Directories a pruned object left behind are litter, and an empty tenant
    # subtree makes store_stats() overcount tenants. Remove the ones that are
    # now empty, deepest first; a non-empty directory raises and is skipped.
    root = artifact_root()
    if root.exists():
        for directory in sorted(
            (p for p in root.rglob("*") if p.is_dir()),
            key=lambda p: len(p.parts),
            reverse=True,
        ):
            try:
                directory.rmdir()
            except OSError:
                continue
    return removed
