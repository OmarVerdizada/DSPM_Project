from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from backend.store import delete_secret, read_secret, save_secret

_KEY_HELP = (
    "DSPM_VAULT_KEY must be a 32-byte urlsafe-base64 Fernet key. Generate one with: "
    'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
)


def _is_production() -> bool:
    return os.getenv("DSPM_ENV", "local").lower() in {"prod", "production"}


def _is_valid_fernet_key(key: bytes) -> bool:
    try:
        from cryptography.fernet import Fernet

        Fernet(key)
        return True
    except Exception:
        return False


def _vault_key() -> bytes:
    """The vault's Fernet key as raw bytes. M3: DSPM_VAULT_KEY must be a REAL
    urlsafe-base64 Fernet key - no passphrase, no PBKDF2, no salt. Production
    requires it; local/dev generates and persists a real Fernet key."""
    configured = os.getenv("DSPM_VAULT_KEY")
    if configured and configured.strip():
        return configured.strip().encode("ascii")
    if _is_production():
        raise RuntimeError(f"DSPM_VAULT_KEY must be set in production. {_KEY_HELP}")
    return _load_or_create_local_vault_key()


def _load_or_create_local_vault_key() -> bytes:
    """Local/dev only: read a persisted Fernet key, or generate + persist a real one.
    A pre-M3 key file (a PBKDF2 passphrase, not a Fernet key) is replaced with a
    fresh Fernet key - old dev credentials become unreadable, acceptable in dev."""
    from cryptography.fernet import Fernet

    key_path = Path(os.getenv("DSPM_LOCAL_VAULT_KEY_PATH", Path.home() / ".dspm" / "vault.key"))
    try:
        if key_path.exists():
            existing = key_path.read_text(encoding="utf-8").strip().encode("ascii")
            if _is_valid_fernet_key(existing):
                return existing
            # A legacy passphrase file, not a Fernet key -> regenerate below.
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        key_path.write_text(key.decode("ascii"), encoding="utf-8")
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return key
    except OSError:
        # Last-resort in-memory key keeps secrets encrypted even if it can't persist.
        return Fernet.generate_key()


def _fernet():
    try:
        from cryptography.fernet import Fernet
    except ModuleNotFoundError as exc:
        raise RuntimeError("Missing dependency 'cryptography'. Install requirements.txt to use the credential vault.") from exc
    key = _vault_key()
    try:
        return Fernet(key)
    except Exception as exc:  # short / garbage / wrong-format key
        raise RuntimeError(_KEY_HELP) from exc


def encrypt_text(plaintext: str) -> str:
    """A secret that is not a scan credential (an MFA seed) sealed with the vault key, so
    the vault's key lifecycle (C12) covers it too."""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")


def validate_vault_key() -> None:
    """Startup format-check (M3): fail CLOSED if the vault key is missing (prod) or
    not a valid Fernet key, so a bad key breaks startup rather than the first
    credential operation."""
    _fernet()


class CredentialVault:
    """AES-backed local vault for development; replace with HashiCorp Vault/AWS adapter in production."""

    def store(self, tenant_id: str, username: str, password: str, domain: str) -> str:
        secret_id = secrets.token_urlsafe(16)
        payload = json.dumps({"username": username, "password": password, "domain": domain}, separators=(",", ":")).encode()
        encrypted = _fernet().encrypt(payload).decode("ascii")
        save_secret(tenant_id, secret_id, encrypted)
        return secret_id

    def resolve(self, tenant_id: str, secret_ref: str) -> dict:
        ciphertext = read_secret(tenant_id, secret_ref)
        if ciphertext is None:
            raise KeyError("Credential reference not found")
        decrypted = _fernet().decrypt(ciphertext.encode())
        return json.loads(decrypted)

    def delete(self, tenant_id: str, secret_ref: str) -> None:
        delete_secret(tenant_id, secret_ref)
