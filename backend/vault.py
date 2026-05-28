from __future__ import annotations

import hashlib
import json
import os
import secrets

from backend.store import tenant_dir, write_json


def _fernet():
    try:
        from cryptography.fernet import Fernet
    except ModuleNotFoundError as exc:
        raise RuntimeError("Missing dependency 'cryptography'. Install requirements.txt to use the credential vault.") from exc

    secret = os.getenv("DSPM_VAULT_KEY", "dev-vault-key-change-me")
    key = Fernet.generate_key() if not secret else __import__("base64").urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


class CredentialVault:
    """AES-backed local vault for development; replace with HashiCorp Vault/AWS adapter in production."""

    def store(self, tenant_id: str, username: str, password: str, domain: str) -> str:
        secret_id = secrets.token_urlsafe(16)
        payload = json.dumps({"username": username, "password": password, "domain": domain}, separators=(",", ":")).encode()
        encrypted = _fernet().encrypt(payload).decode("ascii")
        write_json(tenant_dir(tenant_id) / "secrets" / f"{secret_id}.json", {"ciphertext": encrypted})
        return secret_id

    def resolve(self, tenant_id: str, secret_ref: str) -> dict:
        path = tenant_dir(tenant_id) / "secrets" / f"{secret_ref}.json"
        if not path.exists():
            raise KeyError("Credential reference not found")
        envelope = json.loads(path.read_text(encoding="utf-8"))
        decrypted = _fernet().decrypt(envelope["ciphertext"].encode())
        return json.loads(decrypted)

    def delete(self, tenant_id: str, secret_ref: str) -> None:
        path = tenant_dir(tenant_id) / "secrets" / f"{secret_ref}.json"
        if path.exists():
            path.unlink()
