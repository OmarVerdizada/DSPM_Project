from __future__ import annotations

import json
import os
import secrets
from pathlib import Path


_KEY_HELP = (
    "DSPM_VAULT_KEY must be a 32-byte urlsafe-base64 Fernet key. Generate one with: "
    'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
)


def _is_production() -> bool:
    # backend.config's reading, which strips the value: "production " is production.
    from backend.config import is_production_value

    return is_production_value(os.getenv("DSPM_ENV"))


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


# ---- C12: versioned keys ----------------------------------------------------------
# Everything the vault seals goes through the key ring (backend/vault_keys): the active
# key seals, the key a value names opens it. Without DSPM_VAULT_KEYRING the ring is the
# one key above - the behaviour before C12.


def ring():
    from backend import vault_keys

    return vault_keys.load_ring(_vault_key)


def _seal(plaintext: bytes) -> str:
    return ring().seal(plaintext)


def _open(sealed: str) -> bytes:
    return ring().open(sealed)


def validate_vault_key() -> None:
    """Startup format-check (M3): fail CLOSED if the vault key is missing (prod) or
    not a valid Fernet key, so a bad key breaks startup rather than the first
    credential operation. With a key ring file present the ring is the key - its
    entries are checked as it loads - and DSPM_VAULT_KEY is not needed (C12)."""
    from backend import vault_keys

    path = vault_keys.ring_path()
    if path is None or not path.exists():
        _fernet()
    ring()


def rotation_days() -> int:
    """C12: the recommended interval between a credential's password changes (default 90
    days). A reminder, never an enforcement - the account's owner rotates it."""
    try:
        return max(1, int(os.getenv("DSPM_CREDENTIAL_ROTATION_DAYS", "90")))
    except ValueError:
        return 90


def credential_listing(tenant_id: str) -> list[dict]:
    """The workspace's saved credentials - labels, ages, key and privilege, never a secret."""
    from datetime import datetime, timedelta, timezone

    from backend.store import list_secret_metadata

    due_after = timedelta(days=rotation_days())
    today = datetime.now(timezone.utc)
    items = []
    for item in list_secret_metadata(tenant_id):
        since = item.get("rotated_at") or item.get("created_at")
        try:
            changed = datetime.fromisoformat(str(since))
            if changed.tzinfo is None:
                changed = changed.replace(tzinfo=timezone.utc)
            age_days = (today - changed).days
        except (TypeError, ValueError):
            age_days = None
        items.append({**item, "age_days": age_days, "rotation_days": rotation_days(),
                      "rotation_due": age_days is not None and age_days >= due_after.days})
    return items


class CredentialVault:
    """Saved credentials, sealed with the vault's key ring. A credential is a username,
    a password and a domain; only its label (DOMAIN\\username) and its dates are kept in
    the clear."""

    def store(self, tenant_id: str, username: str, password: str, domain: str, *, kind: str = "scan",
              label: str = "") -> str:
        from backend.store import save_secret

        secret_id = secrets.token_urlsafe(16)
        payload = json.dumps({"username": username, "password": password, "domain": domain}, separators=(",", ":")).encode()
        save_secret(tenant_id, secret_id, _seal(payload), kind=kind, label=label or _label(username, domain))
        return secret_id

    def resolve(self, tenant_id: str, secret_ref: str, *, kind: str | None = "scan") -> dict:
        """The credential behind a reference. `kind` is what the caller may use: a scan
        resolves only scan credentials, so the directory service account's password -
        which only a tenant administrator manages - can never be pointed at a target
        (M3 exit review). None means any kind (the privilege check reads the account name)."""
        from backend.store import read_secret_record, touch_secret_used

        record = read_secret_record(tenant_id, secret_ref)
        if record is None or (kind is not None and record["kind"] != kind):
            raise KeyError("Credential reference not found")
        ciphertext = record["ciphertext"]
        value = json.loads(_open(ciphertext))
        touch_secret_used(tenant_id, secret_ref)
        return value

    def replace(self, tenant_id: str, secret_ref: str, username: str, password: str, domain: str) -> bool:
        """The owner changed the account's password: seal the new one under the same
        reference (scan profiles and schedules keep working) and record when."""
        from backend.store import replace_secret

        payload = json.dumps({"username": username, "password": password, "domain": domain}, separators=(",", ":")).encode()
        return replace_secret(tenant_id, secret_ref, _seal(payload), _label(username, domain))

    def delete(self, tenant_id: str, secret_ref: str) -> None:
        from backend.store import delete_secret

        delete_secret(tenant_id, secret_ref)


def _label(username: str, domain: str) -> str:
    username = str(username or "").strip()
    domain = str(domain or "").strip()
    if not domain or domain.upper() == "WORKGROUP" or "\\" in username or "@" in username:
        return username
    return f"{domain}\\{username}"


# ---- C12: key operations (python main.py vault ...) ----------------------------------
def _ring_file() -> Path:
    from backend import vault_keys

    path = vault_keys.ring_path()
    if path is None:
        raise vault_keys.VaultKeyError(
            "Key rotation needs a key ring: set DSPM_VAULT_KEYRING in the services' configuration file "
            "([settings] in sentro.toml - not only in this shell, or the services never read the new ring) to a "
            "file in the protected secrets folder (for example C:\\ProgramData\\Sentro\\secrets\\"
            "vault_keyring.json), restart the services, and run this with --config pointing at that file. The "
            "ring starts from the current key.")
    return path


def _audit(actor: str, action: str, detail: dict) -> None:
    from backend.store import audit

    audit("default", actor, action, detail)


def _current_ring_for_change():
    """The ring to change, read from disk now (another process may have changed it): the
    file when it exists, else a new ring holding the single configured key (so the first
    rotation needs no separate step). Called with the ring lock held."""
    from backend import vault_keys

    path = _ring_file()
    vault_keys._CACHE.update({"stamp": None, "ring": None})
    ring_now = ring()
    if not path.exists():
        vault_keys.save_ring(ring_now, path)
        _audit("host", "vault.keyring_created", {"active": ring_now.active})
    return vault_keys.load_ring(_vault_key), path


def _unreadable(ring_now) -> list[str]:
    """Where a sealed value does not open with the ring: "table key=value" identifiers,
    never the value."""
    from cryptography.fernet import InvalidToken

    from backend import store
    from backend.vault_keys import VaultKeyError

    where = []
    for table, keys, value in store.vault_sealed_rows():
        try:
            ring_now.open(value)
        except (InvalidToken, VaultKeyError, ValueError):
            where.append(f"{table} " + " ".join(f"{name}={keys[name]}" for name in keys))
    return where


def _reseal_to(target_kid: str, ring_now, *, skip_unreadable: bool = False) -> tuple[int, list[str]]:
    """Re-seal every value not under `target_kid` with it - one transaction. A value no key
    in the ring opens stops it before anything is written (nothing could re-seal it), unless
    `skip_unreadable`: then it is left exactly as it is, and named."""
    from cryptography.fernet import Fernet

    from backend import store
    from backend.vault_keys import PREFIX, VaultKeyError

    unreadable = _unreadable(ring_now)
    if unreadable and not skip_unreadable:
        shown = "; ".join(unreadable[:10]) + (f"; and {len(unreadable) - 10} more" if len(unreadable) > 10 else "")
        raise VaultKeyError(
            f"{len(unreadable)} sealed value(s) open with no key in the ring ({shown}). Nothing was changed. Recover "
            "the missing key from its escrow, or run again with --skip-unreadable to leave those values as they are "
            "(they stay unreadable; replace or delete them).")
    target = Fernet(ring_now.keys[target_kid])

    def transform(value: str) -> str | None:
        if ring_now.key_of(value) == target_kid:
            return None
        try:
            plain = ring_now.open(value)
        except Exception:
            if skip_unreadable:
                return None
            raise
        return f"{PREFIX}{target_kid}.{target.encrypt(plain).decode('ascii')}"

    return store.reseal_vault_values(transform), unreadable


def rotate(*, resume: bool = False, actor: str = "host", skip_unreadable: bool = False) -> dict:
    """Add a key, make it active, re-seal everything with it; or finish one that stopped."""
    from backend import vault_keys

    with vault_keys.RingLock(_ring_file()):
        ring_now, path = _current_ring_for_change()
        rotation = dict(ring_now.rotation or {})
        if rotation.get("state") == "rekeying":
            if not resume:
                # An unfinished rotation is finished before another begins.
                resume = True
            source, target = rotation["from"], rotation["to"]
        else:
            if resume:
                raise vault_keys.VaultKeyError("There is no unfinished rotation to resume.")
            # Checked before the new key is written, so a ring that cannot finish a
            # rotation is never left half-way through one.
            unreadable = _unreadable(ring_now)
            if unreadable and not skip_unreadable:
                _reseal_to(ring_now.active, ring_now)  # raises, naming them
            key = vault_keys.new_key()
            target = vault_keys.key_id(key)
            source = ring_now.active
            ring_now.keys[target] = key
            ring_now.created[target] = vault_keys.now()
            ring_now.states[source] = "retired"
            ring_now.states[target] = "active"
            ring_now.active = target
            ring_now.rotation = {"state": "rekeying", "from": source, "to": target, "started_at": vault_keys.now(),
                                 "kind": "rotation"}
            vault_keys.save_ring(ring_now, path)  # new values are sealed with the new key from here on
        resealed, skipped = _reseal_to(target, vault_keys.load_ring(_vault_key), skip_unreadable=skip_unreadable)
        ring_now = vault_keys.load_ring(_vault_key)
        ring_now.rotation = {"state": "idle", "last": {"from": source, "to": target, "resealed": resealed,
                                                       "finished_at": vault_keys.now(),
                                                       "kind": rotation.get("kind", "rotation")}}
        vault_keys.save_ring(ring_now, path)
    action = "vault.key_rotation_resumed" if resume else "vault.key_rotated"
    if rotation.get("kind") == "rollback":
        action = "vault.key_rolled_back"
    _audit(actor, action, {"from": source, "to": target, "resealed": resealed, "left_unreadable": len(skipped)})
    return {"from": source, "to": target, "resealed": resealed, "resumed": resume, "left_unreadable": skipped}


def rollback(*, actor: str = "host", skip_unreadable: bool = False) -> dict:
    """Make the previous key active again and re-seal everything with it."""
    from backend import vault_keys

    with vault_keys.RingLock(_ring_file()):
        ring_now, path = _current_ring_for_change()
        if (ring_now.rotation or {}).get("state") == "rekeying":
            raise vault_keys.VaultKeyError("A rotation is unfinished; resume it (vault rotate --resume) before rolling back.")
        last = (ring_now.rotation or {}).get("last") or {}
        previous = last.get("from") if last.get("to") == ring_now.active else None
        if not previous or previous not in ring_now.keys:
            raise vault_keys.VaultKeyError("There is no previous key in the ring to roll back to.")
        if not skip_unreadable and _unreadable(ring_now):
            _reseal_to(previous, ring_now)  # raises, naming them
        current = ring_now.active
        ring_now.states[current] = "retired"
        ring_now.states[previous] = "active"
        ring_now.active = previous
        ring_now.rotation = {"state": "rekeying", "from": current, "to": previous, "started_at": vault_keys.now(),
                             "kind": "rollback"}
        vault_keys.save_ring(ring_now, path)
        resealed, skipped = _reseal_to(previous, vault_keys.load_ring(_vault_key), skip_unreadable=skip_unreadable)
        ring_now = vault_keys.load_ring(_vault_key)
        ring_now.rotation = {"state": "idle", "last": {"from": current, "to": previous, "resealed": resealed,
                                                       "finished_at": vault_keys.now(), "kind": "rollback"}}
        vault_keys.save_ring(ring_now, path)
    _audit(actor, "vault.key_rolled_back", {"from": current, "to": previous, "resealed": resealed,
                                            "left_unreadable": len(skipped)})
    return {"from": current, "to": previous, "resealed": resealed, "left_unreadable": skipped}


def status() -> dict:
    """Which key is active, which keys the ring holds, how many values each seals."""
    from collections import Counter

    from backend import store, vault_keys

    ring_now = ring()
    counts = Counter(vault_keys.split(value)[0] or "(no key id)" for value in store.vault_sealed_values())
    return {"active": ring_now.active, "keyring": str(vault_keys.ring_path() or ""),
            "keys": [{"kid": kid, "state": ring_now.states.get(kid, ""), "created_at": ring_now.created.get(kid, ""),
                      "values": counts.get(kid, 0)} for kid in ring_now.keys],
            "unkeyed_values": counts.get("(no key id)", 0), "rotation": ring_now.rotation}


def export_escrow(out: Path, passphrase: str, *, actor: str = "host") -> dict:
    from backend import vault_keys

    ring_now = ring()
    document = vault_keys.export_escrow(ring_now, passphrase)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    _audit(actor, "vault.escrow_exported", {"kids": document["kids"], "active": document["active"]})
    return {"escrow": str(out), "kids": document["kids"], "active": document["active"]}


def _coverage(recovered) -> dict:
    """What a recovered ring would open of what is sealed now: key ids in use it lacks, and
    how many values - with a key id or from before key ids - open with none of its keys."""
    from backend import store, vault_keys

    in_use = vault_keys.kids_in(store.vault_sealed_values()) - {""}
    return {"missing": sorted(in_use - set(recovered.keys)), "unopenable": len(_unreadable(recovered))}


def verify_escrow(path: Path, passphrase: str, *, actor: str = "host") -> dict:
    """The escrow opens with the passphrase, and its ring opens every value sealed now."""
    from backend import vault_keys

    recovered = vault_keys.open_escrow(json.loads(Path(path).read_text(encoding="utf-8")), passphrase)
    coverage = _coverage(recovered)
    report = {"ok": not coverage["missing"] and not coverage["unopenable"], "kids": sorted(recovered.keys),
              **coverage}
    _audit(actor, "vault.escrow_verified", {"ok": report["ok"], "missing": coverage["missing"],
                                            "unopenable": coverage["unopenable"]})
    return report


def recover_escrow(path: Path, passphrase: str, out: Path, *, force: bool = False, accept_missing: bool = False,
                   actor: str = "host") -> dict:
    """Write the key ring back from its escrow. An existing ring is replaced only with
    force, and is kept beside it first. An escrow that cannot open what is sealed now (one
    exported before the last rotation) is refused unless `accept_missing`."""
    from datetime import datetime, timezone

    from backend import vault_keys

    out = Path(out)
    with vault_keys.RingLock(out):
        if out.exists() and not force:
            raise vault_keys.VaultKeyError(f"{out} exists; recovering over a key ring needs --force.")
        recovered = vault_keys.open_escrow(json.loads(Path(path).read_text(encoding="utf-8")), passphrase)
        coverage = _coverage(recovered)
        if (coverage["missing"] or coverage["unopenable"]) and not accept_missing:
            raise vault_keys.VaultKeyError(
                f"This escrow cannot open what is sealed now: key(s) in use it lacks {coverage['missing'] or 'none'}, "
                f"{coverage['unopenable']} value(s) it cannot open. It predates a rotation - find a newer escrow. "
                "Nothing was written (--accept-missing recovers it anyway).")
        kept = ""
        if out.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = out.with_name(f"{out.stem}.replaced-{stamp}{out.suffix}")
            out.replace(backup)
            kept = str(backup)
        vault_keys.save_ring(recovered, out)
    _audit(actor, "vault.escrow_recovered", {"kids": sorted(recovered.keys), "active": recovered.active,
                                             "replaced_ring_kept": bool(kept), **coverage})
    return {"keyring": str(out), "kids": sorted(recovered.keys), "active": recovered.active,
            "replaced_ring_kept_at": kept, **coverage}
