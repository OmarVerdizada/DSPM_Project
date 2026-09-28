"""The vault's keys: versioned, rotated without a moment of unreadable data, escrowed (C12).

Every value the vault seals - a saved scan credential, a directory service account's
password, an MFA seed - is written as

    vk1.<kid>.<fernet token>

where `kid` names the key that sealed it (the first 12 hex digits of the key's SHA-256;
a name, not a secret). A value sealed before C12 has no prefix and is opened with
whichever key opens it.

With `DSPM_VAULT_KEYRING` set, the keys live in that file (readable by the services and
Administrators only), with one of them active:

    {"format": "sentro-vault-keyring/1", "active": "<kid>",
     "keys": [{"kid": "...", "key": "<fernet key>", "state": "active|retired", "created_at": "..."}],
     "rotation": {"state": "idle|rekeying", ...}}

Without it, the single key of `DSPM_VAULT_KEY` (or the local development key file) is a
ring of one - exactly the behaviour before C12.

Rotation (`python main.py vault rotate`):
  1. a new key is added and made active in the ring (written atomically); the old one is
     kept, retired, so everything sealed with it still opens;
  2. every sealed value not under the new key is re-sealed with it, in ONE database
     transaction - it commits whole or not at all;
  3. the ring records the rotation as finished.
A crash between any two steps leaves every value readable (the ring holds both keys and
each value names its key); `vault rotate --resume` finishes what was started, and
`vault rollback` makes the previous key active again and re-seals everything with it.
Nothing is half-rotated in the sense that matters: no value is ever sealed with a key
the ring does not hold.

Escrow (`vault escrow export|verify|recover`): the whole ring, encrypted with a key
derived by scrypt from a passphrase the operator supplies in a file or at a prompt - never
on a command line. The escrow file holds no key in the clear; losing both the ring and
the passphrase loses the credentials, which is the point.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets as _secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

PREFIX = "vk1."
RING_FORMAT = "sentro-vault-keyring/1"
ESCROW_FORMAT = "sentro-vault-escrow/1"
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
MIN_PASSPHRASE = 16


class VaultKeyError(RuntimeError):
    """A key operation that must not go ahead; the message says why and what to do."""

    client_safe = True


def key_id(key: bytes | str) -> str:
    raw = key.encode("ascii") if isinstance(key, str) else key
    return hashlib.sha256(raw.strip()).hexdigest()[:12]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fernet(key: bytes):
    from cryptography.fernet import Fernet

    return Fernet(key)


@dataclass
class Ring:
    active: str
    keys: dict[str, bytes]
    states: dict[str, str] = field(default_factory=dict)
    created: dict[str, str] = field(default_factory=dict)
    rotation: dict = field(default_factory=lambda: {"state": "idle"})
    path: Path | None = None

    # -- sealing ---------------------------------------------------------------
    def seal(self, plaintext: bytes) -> str:
        token = _fernet(self.keys[self.active]).encrypt(plaintext).decode("ascii")
        return f"{PREFIX}{self.active}.{token}"

    def open(self, sealed: str) -> bytes:
        kid, token = split(sealed)
        if kid:
            if kid not in self.keys:
                raise VaultKeyError(f"This value was sealed with vault key {kid}, which this install does not hold. "
                                    "Recover the key ring from its escrow (python main.py vault escrow recover).")
            return _fernet(self.keys[kid]).decrypt(token.encode("ascii"))
        from cryptography.fernet import InvalidToken

        # Sealed before key ids: the active key first, then the others.
        for candidate in [self.active, *[k for k in self.keys if k != self.active]]:
            try:
                return _fernet(self.keys[candidate]).decrypt(token.encode("ascii"))
            except InvalidToken:
                continue
        raise InvalidToken()

    def key_of(self, sealed: str) -> str:
        """The key id a value is sealed with ("" for a value sealed before key ids)."""
        return split(sealed)[0]

    # -- the file ----------------------------------------------------------------
    def document(self) -> dict:
        return {
            "format": RING_FORMAT,
            "active": self.active,
            "keys": [{"kid": kid, "key": key.decode("ascii"), "state": self.states.get(kid, "retired"),
                      "created_at": self.created.get(kid, "")} for kid, key in self.keys.items()],
            "rotation": self.rotation,
        }


def split(sealed: str) -> tuple[str, str]:
    if sealed.startswith(PREFIX):
        rest = sealed[len(PREFIX):]
        kid, _, token = rest.partition(".")
        return kid, token
    return "", sealed


def ring_from_document(document: dict, path: Path | None = None) -> Ring:
    if document.get("format") != RING_FORMAT:
        raise VaultKeyError("The vault key ring file is not a Sentro key ring.")
    keys: dict[str, bytes] = {}
    states: dict[str, str] = {}
    created: dict[str, str] = {}
    for item in document.get("keys") or []:
        key = str(item["key"]).strip().encode("ascii")
        _fernet(key)  # refuses a malformed key
        kid = key_id(key)
        if item.get("kid") and item["kid"] != kid:
            raise VaultKeyError(f"Key ring entry {item['kid']} does not match its key.")
        keys[kid] = key
        states[kid] = str(item.get("state") or "retired")
        created[kid] = str(item.get("created_at") or "")
    active = str(document.get("active") or "")
    if active not in keys:
        raise VaultKeyError("The vault key ring names an active key it does not hold.")
    return Ring(active, keys, states, created, dict(document.get("rotation") or {"state": "idle"}), path)


def ring_path() -> Path | None:
    raw = os.getenv("DSPM_VAULT_KEYRING", "").strip()
    return Path(raw) if raw else None


_CACHE: dict = {"stamp": None, "ring": None}


def load_ring(single_key: Callable[[], bytes]) -> Ring:
    """The ring in force: the key ring file when configured and present (re-read when it
    changes, so a running service sees a rotation), else the single configured key."""
    path = ring_path()
    if path is not None and path.exists():
        stat = path.stat()
        stamp = (str(path), stat.st_mtime_ns, stat.st_size)
        if _CACHE["stamp"] != stamp:
            _CACHE["ring"] = ring_from_document(json.loads(path.read_text(encoding="utf-8")), path)
            _CACHE["stamp"] = stamp
        return _CACHE["ring"]
    key = single_key()
    kid = key_id(key)
    return Ring(kid, {kid: key}, {kid: "active"}, {kid: ""})


def save_ring(ring: Ring, path: Path) -> None:
    """Write the ring atomically: a reader sees the old file or the new, never half."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{_secrets.token_hex(4)}.tmp")
    data = json.dumps(ring.document(), indent=2) + "\n"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    ring.path = path
    _CACHE["stamp"] = None


def new_key() -> bytes:
    from cryptography.fernet import Fernet

    return Fernet.generate_key()


# ---- escrow ----------------------------------------------------------------------
def _derive(passphrase: str, salt: bytes, params: dict) -> bytes:
    raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=params["n"], r=params["r"], p=params["p"],
                         maxmem=128 * 1024 * 1024, dklen=32)
    return base64.urlsafe_b64encode(raw)


def export_escrow(ring: Ring, passphrase: str) -> dict:
    if len(passphrase) < MIN_PASSPHRASE:
        raise VaultKeyError(f"An escrow passphrase needs at least {MIN_PASSPHRASE} characters.")
    salt = _secrets.token_bytes(16)
    token = _fernet(_derive(passphrase, salt, SCRYPT)).encrypt(json.dumps(ring.document()).encode("utf-8"))
    return {
        "format": ESCROW_FORMAT,
        "created_at": now(),
        "kdf": {"name": "scrypt", **SCRYPT, "salt": base64.b64encode(salt).decode("ascii")},
        # The key ids are names, not keys: they let an operator see what an escrow covers.
        "kids": sorted(ring.keys),
        "active": ring.active,
        "ring": token.decode("ascii"),
    }


def open_escrow(document: dict, passphrase: str) -> Ring:
    from cryptography.fernet import InvalidToken

    if document.get("format") != ESCROW_FORMAT:
        raise VaultKeyError("This file is not a Sentro vault escrow.")
    kdf = document.get("kdf") or {}
    try:
        key = _derive(passphrase, base64.b64decode(kdf["salt"]), {"n": int(kdf["n"]), "r": int(kdf["r"]), "p": int(kdf["p"])})
        plain = _fernet(key).decrypt(str(document["ring"]).encode("ascii"))
    except (InvalidToken, KeyError, ValueError) as exc:
        raise VaultKeyError("The passphrase does not open this escrow (or the file was altered).") from exc
    return ring_from_document(json.loads(plain.decode("utf-8")))


def read_passphrase(path: str | None, *, confirm: bool = False) -> str:
    """From a file (first line), or asked for - never taken from a command line."""
    if path:
        return Path(path).read_text(encoding="utf-8").splitlines()[0].strip()
    import getpass

    first = getpass.getpass("Escrow passphrase: ")
    if confirm and getpass.getpass("Again: ") != first:
        raise VaultKeyError("The two passphrases differ.")
    return first


def kids_in(values: Iterable[str]) -> set[str]:
    return {split(value)[0] for value in values if value}
