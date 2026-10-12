"""Signed documents from Sentro's publisher: update packages and licences (D10).

The publisher signs with an Ed25519 key it keeps offline; an install trusts only the
public keys in its trust file (``<DataRoot>\\trust\\publishers.json``, or
DSPM_TRUST_FILE), which the operator pins when installing and which a package can never
replace. A document is trusted when a key in that file, for that purpose, signed it.

Verification is the RFC 8032 reference algorithm in plain Python, so the installer -
which runs before anything is installed, on the standard library alone - can check a
package with the same code the product uses for a licence. It is checked against the
`cryptography` implementation (and the RFC's own test vectors) in the tests. It only
verifies: no secret key ever passes through it, so its speed and timing do not matter.

Signing is the publisher's, offline, with scripts/sentro_sign.py.

Standard library only: this module is loaded by path by the installer.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

# ── Ed25519 verification (RFC 8032, section 6) ─────────────────────────────────────
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inverse(value: int) -> int:
    return pow(value, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inverse(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _add(a: tuple, b: tuple) -> tuple:
    first = (a[1] - a[0]) * (b[1] - b[0]) % _P
    second = (a[1] + a[0]) * (b[1] + b[0]) % _P
    third = 2 * a[3] * b[3] * _D % _P
    fourth = 2 * a[2] * b[2] % _P
    e, f, g, h = second - first, fourth - third, fourth + third, second + first
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar: int, point: tuple) -> tuple:
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _same(a: tuple, b: tuple) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


_GY = 4 * _inverse(5) % _P
_GX = _recover_x(_GY, 0)
_BASE = (_GX, _GY, 1, _GX * _GY % _P)


def _decompress(data: bytes) -> tuple | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether `signature` is `public_key`'s Ed25519 signature of `message`."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = _decompress(public_key)
    point_r = _decompress(signature[:32])
    if point_a is None or point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    return _same(_multiply(s, _BASE), _add(point_r, _multiply(h, point_a)))


# ── Documents, keys and the trust file ─────────────────────────────────────────────
PURPOSES = ("package", "licence")


class TrustError(ValueError):
    """A document, signature or trust file that is refused. `str()` says why."""

    client_safe = True  # backend.errors: every message here is written for the person


def canonical(document: dict) -> bytes:
    """The bytes a signature covers: sorted keys, no spaces, UTF-8."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def fingerprint(public_key: bytes) -> str:
    """The key as a person compares it: SHA-256, in groups."""
    digest = hashlib.sha256(public_key).hexdigest().upper()
    return " ".join(digest[index:index + 4] for index in range(0, 64, 4))


def decode_public_key(text: str) -> bytes:
    try:
        raw = base64.b64decode(str(text or "").strip(), validate=True)
    except (ValueError, TypeError) as exc:
        raise TrustError("A public key must be 32 bytes, base64-encoded.") from exc
    if len(raw) != 32:
        raise TrustError("A public key must be 32 bytes, base64-encoded.")
    return raw


def load_trust(path: Path | str) -> dict[str, dict]:
    """The trust file's keys: {key_id: {"public_key": bytes, "purposes": set}}. A missing
    file trusts nothing."""
    target = Path(path)
    if not target.is_file():
        return {}
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TrustError(f"The trust file {target} cannot be read.") from exc
    keys: dict[str, dict] = {}
    for entry in data.get("keys") or []:
        public = decode_public_key(entry.get("public_key", ""))
        purposes = {item for item in entry.get("purposes") or [] if item in PURPOSES}
        keys[key_id(public)] = {"public_key": public, "purposes": purposes, "comment": str(entry.get("comment") or "")}
    return keys


def trust_entry(public_key: bytes, purposes, comment: str, added_at: str) -> dict:
    return {"key_id": key_id(public_key), "public_key": base64.b64encode(public_key).decode("ascii"),
            "fingerprint": fingerprint(public_key), "purposes": sorted(set(purposes) & set(PURPOSES)),
            "comment": comment, "added_at": added_at}


def add_to_trust(path: Path | str, public_key: bytes, purposes, comment: str, added_at: str) -> dict:
    """Pin a key (idempotent). The file is the operator's: nothing but this adds to it."""
    target = Path(path)
    data = {"keys": []}
    if target.is_file():
        data = json.loads(target.read_text(encoding="utf-8"))
    entry = trust_entry(public_key, purposes, comment, added_at)
    kept = [item for item in data.get("keys") or [] if item.get("key_id") != entry["key_id"]]
    data["keys"] = [*kept, entry]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return entry


def verify_signed(signed: dict, envelope: dict, trust: dict[str, dict], purpose: str) -> str:
    """Check `envelope` ({"key_id", "signature"}) signs `signed` with a key trusted for
    `purpose`. Returns the key id; raises TrustError with the reason otherwise."""
    wanted = str(envelope.get("key_id") or "")
    entry = trust.get(wanted)
    if entry is None:
        raise TrustError(f"It is signed by key {wanted or '(none)'}, which this install does not trust.")
    if purpose not in entry["purposes"]:
        raise TrustError(f"Key {wanted} is trusted, but not to sign a {purpose}.")
    try:
        signature = base64.b64decode(str(envelope.get("signature") or ""), validate=True)
    except (ValueError, TypeError) as exc:
        raise TrustError("The signature is not base64.") from exc
    if not verify_ed25519(entry["public_key"], canonical(signed), signature):
        raise TrustError("The signature does not match: the document was altered, or signed by another key.")
    return wanted


# ── Update packages ────────────────────────────────────────────────────────────────
# SIGNATURE.json signs a statement of what the package is - its label, commit, build time
# and schema revision - and the digest of SHA256SUMS, which names the digest of every
# other file. publisher.json is the key the package says signed it: shown to the
# operator at a first install, never trusted because the package carries it.
SIGNATURE_FILE = "SIGNATURE.json"
PUBLISHER_FILE = "publisher.json"
PACKAGE_FORMAT = "sentro-package-v1"
UNLISTED = ("SHA256SUMS", "lib/PackageDigest.ps1", SIGNATURE_FILE, PUBLISHER_FILE)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check_sums(package: Path) -> int:
    """Every file SHA256SUMS lists is there and matches, and nothing else is there."""
    sums = package / "SHA256SUMS"
    if not sums.is_file():
        raise TrustError("The package has no SHA256SUMS; it is incomplete.")
    listed = set()
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, _, relative = line.partition("  ")
        listed.add(relative)
        target = package / relative
        if not target.is_file():
            raise TrustError(f"{relative} is missing from the package.")
        if _sha256_file(target) != expected:
            raise TrustError(f"{relative} does not match SHA256SUMS; the package is damaged or altered.")
    for path in package.rglob("*"):
        if path.is_file():
            relative = path.relative_to(package).as_posix()
            if relative not in listed and relative not in UNLISTED:
                raise TrustError(f"{relative} is in the package but not in SHA256SUMS.")
    return len(listed)


def package_statement(manifest: dict, sums_sha256: str) -> dict:
    return {"format": PACKAGE_FORMAT, "label": manifest.get("label"), "commit": manifest.get("commit"),
            "commit_time": int(manifest.get("commit_time") or 0),
            "schema_revision": int(manifest.get("schema_revision") or 0), "sums_sha256": sums_sha256}


def verify_package(package: Path | str, trust: dict[str, dict], *, installed: dict | None = None,
                   allow_unsigned: bool = False, allow_downgrade: bool = False) -> dict:
    """Check an update package before anything in it runs: its files against SHA256SUMS,
    the publisher's signature over what it is (with a key from THIS install's trust file),
    and that it is not older than the release installed. Raises TrustError."""
    folder = Path(package)
    try:
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TrustError(f"{folder} is not a Sentro package (no readable manifest.json).") from exc
    files = check_sums(folder)
    statement = package_statement(manifest, _sha256_file(folder / "SHA256SUMS"))
    signed_by = ""
    signature = folder / SIGNATURE_FILE
    if signature.is_file():
        try:
            envelope = json.loads(signature.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise TrustError(f"{SIGNATURE_FILE} is not readable.") from exc
        if envelope.get("signed") != statement:
            raise TrustError("What the package says it is does not match what was signed: its manifest or "
                             "checksums were changed after signing.")
        signed_by = verify_signed(statement, envelope, trust, "package")
    elif not allow_unsigned:
        raise TrustError("The package is not signed by its publisher. Install only a signed package, or accept "
                         "this one explicitly (-AllowUnsigned) after checking its SHA-256 against the published value.")
    older = installed is not None and statement["commit_time"] < int(installed.get("commit_time") or 0)
    if older and not allow_downgrade:
        raise TrustError(f"Refusing a downgrade: package {statement['label']} was built before the installed release "
                         f"{installed.get('release') or installed.get('label') or ''}. An old signed package is still "
                         "old; go back only on purpose (-AllowDowngrade).")
    return {"label": statement["label"], "files": files, "signed_by": signed_by, "downgrade": older,
            "schema_revision": statement["schema_revision"]}
