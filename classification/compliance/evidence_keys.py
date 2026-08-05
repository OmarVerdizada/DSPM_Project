"""Central provider for the evidence-fingerprint HMAC key (SC-2).

Previously four modules independently fell back to the hardcoded literal
``dspm-local-evidence-key`` when ``DSPM_EVIDENCE_HMAC_KEY`` was unset. That made
evidence fingerprints forgeable and identical across every default deployment.

This module replaces that shared fallback with a single policy:

* Production (``DSPM_ENV`` in {prod, production}) is fail-closed: the key MUST be
  set explicitly, or fingerprint generation raises rather than use a shared key.
* Local/dev generates and persists a per-install key **outside** ``data/`` -
  default ``~/.dspm/evidence_hmac_key`` (M1, mirroring the vault key and the
  JWT-secret handling in ``backend/security.py``), so a ``data/`` backup never
  carries key material while fingerprints stay unique per install without env
  setup. An existing ``data/`` key is migrated (preserved) on first load.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

_ENV_VAR = "DSPM_EVIDENCE_HMAC_KEY"
_KEY_FILENAME = ".evidence_hmac_key"
_BASE_DIR = Path(__file__).resolve().parents[2]

_dev_key_cache: str | None = None


def _is_production() -> bool:
    return os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}


def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        # chmod is a no-op on Windows; host ACLs govern access there.
        pass


def _load_or_generate_dev_key() -> str:
    # M1 (Phase 1.1): the dev key lives OUTSIDE data/ so a data/ backup never
    # carries evidence key material (a key holder can otherwise de-anonymise
    # low-entropy masked evidence). Default ~/.dspm/ mirrors the vault key.
    key_path = Path(os.getenv("DSPM_LOCAL_EVIDENCE_KEY_PATH", str(Path.home() / ".dspm" / "evidence_hmac_key")))
    legacy_path = _BASE_DIR / "data" / _KEY_FILENAME
    try:
        if key_path.exists():
            existing = key_path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        key_path.parent.mkdir(parents=True, exist_ok=True)
        # Unlike the JWT secret, the evidence key is MIGRATED (preserved) out of
        # data/ so existing masked-evidence fingerprints stay consistent; the old
        # copy is then removed from the backup path.
        if legacy_path.exists():
            migrated = legacy_path.read_text(encoding="utf-8").strip()
            if migrated:
                key_path.write_text(migrated, encoding="utf-8")
                _chmod_600(key_path)
                legacy_path.unlink(missing_ok=True)
                return migrated
        generated = secrets.token_urlsafe(48)
        key_path.write_text(generated, encoding="utf-8")
        _chmod_600(key_path)
        return generated
    except OSError as exc:
        raise RuntimeError(f"Unable to load or persist {_ENV_VAR}") from exc


def evidence_hmac_key() -> str:
    """Return the evidence-fingerprint HMAC key.

    Reads ``DSPM_EVIDENCE_HMAC_KEY`` first (so operators and tests can pin it).
    In production an unset key is fatal. In dev it falls back to a generated,
    persisted, per-install key instead of a shared hardcoded constant.
    """
    configured = os.getenv(_ENV_VAR, "").strip()
    if configured:
        return configured
    if _is_production():
        raise RuntimeError(
            f"{_ENV_VAR} must be set in production; "
            "refusing to use a shared fallback evidence key"
        )
    global _dev_key_cache
    if _dev_key_cache is None:
        _dev_key_cache = _load_or_generate_dev_key()
    return _dev_key_cache
