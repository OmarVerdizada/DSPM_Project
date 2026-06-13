from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path

from backend.store import delete_secret, read_secret, save_secret


def _fernet():
    try:
        from cryptography.fernet import Fernet
    except ModuleNotFoundError as exc:
        raise RuntimeError("Missing dependency 'cryptography'. Install requirements.txt to use the credential vault.") from exc

    secret = os.getenv("DSPM_VAULT_KEY")
    if not secret:
        secret = _load_or_create_local_vault_secret()
    key = __import__("base64").urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def _load_or_create_local_vault_secret() -> str:
    key_path = Path(__file__).resolve().parent.parent / "data" / ".vault_key"
    try:
        if key_path.exists():
            return key_path.read_text(encoding="utf-8").strip()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        secret = secrets.token_urlsafe(48)
        key_path.write_text(secret, encoding="utf-8")
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return secret
    except OSError:
        # Last-resort in-memory key keeps secrets encrypted even if the local key cannot be persisted.
        return secrets.token_urlsafe(48)


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
