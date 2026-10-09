"""The publisher's signing tool (D10): keys, licences and update packages.

Run by the publisher, on a machine that holds the private key - never on a customer's
install, and the key is never in the repository:

    python scripts/sentro_sign.py keygen --out D:\\keys\\sentro-2026    # writes .key (private) and .pub
    python scripts/sentro_sign.py pubkey --key D:\\keys\\sentro-2026.key
    python scripts/sentro_sign.py sign-licence --key ... --customer "Contoso" --expires 2027-10-01 \\
        --features scan,reports --out contoso.licence
    python scripts/sentro_sign.py sign-package --key ... dist\\sentro-r33-...-win64

The private key file is written with a passphrase when SENTRO_SIGNING_PASSPHRASE is set
(PKCS#8, best available encryption), and read with it. A customer's install trusts the
.pub - pinned in its trust file when it is installed - and nothing else.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend import signing  # noqa: E402


def _passphrase() -> bytes | None:
    value = os.getenv("SENTRO_SIGNING_PASSPHRASE", "")
    return value.encode("utf-8") if value else None


def load_private_key(path: Path):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(path.read_bytes(), password=_passphrase())


def public_raw(private_key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign(private_key, document: dict) -> dict:
    """The envelope fields for `document`: {"key_id", "signature"}."""
    return {"key_id": signing.key_id(public_raw(private_key)),
            "signature": base64.b64encode(private_key.sign(signing.canonical(document))).decode("ascii")}


def keygen(out: Path) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    passphrase = _passphrase()
    encryption = (serialization.BestAvailableEncryption(passphrase) if passphrase
                  else serialization.NoEncryption())
    private_path, public_path = out.with_suffix(".key"), out.with_suffix(".pub")
    if private_path.exists():
        raise SystemExit(f"{private_path} exists; a signing key is never overwritten.")
    out.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
    public_path.write_text(json.dumps(publisher_document(public_raw(key)), indent=2) + "\n", encoding="utf-8")
    return private_path, public_path


def publisher_document(public: bytes, purposes=("package", "licence")) -> dict:
    return {"publisher": "Sentro DSPM", "key_id": signing.key_id(public),
            "public_key": base64.b64encode(public).decode("ascii"), "fingerprint": signing.fingerprint(public),
            "purposes": list(purposes)}


def licence_document(customer: str, expires: str, *, features=(), limits=None, not_before: str | None = None,
                     licence_id: str | None = None, issued_at: datetime | None = None) -> dict:
    issued = issued_at or datetime.now(timezone.utc)
    return {"format": "sentro-licence-v1", "licence_id": licence_id or f"lic-{secrets.token_hex(6)}",
            "customer": customer, "issued_at": issued.isoformat(timespec="seconds"),
            "not_before": not_before or (issued - timedelta(days=1)).isoformat(timespec="seconds"),
            "expires_at": expires, "features": sorted(features), "limits": limits or {}}


def sign_licence(private_key, licence: dict) -> dict:
    return {"licence": licence, **sign(private_key, licence)}


def sign_package(private_key, package: Path) -> dict:
    """Write SIGNATURE.json and publisher.json into a built package folder."""
    manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    signing.check_sums(package)
    statement = signing.package_statement(manifest, signing._sha256_file(package / "SHA256SUMS"))
    envelope = {"signed": statement, **sign(private_key, statement)}
    (package / signing.SIGNATURE_FILE).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    (package / signing.PUBLISHER_FILE).write_text(
        json.dumps(publisher_document(public_raw(private_key)), indent=2) + "\n", encoding="utf-8")
    return envelope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    keygen_parser = commands.add_parser("keygen", help="Make a publisher key pair.")
    keygen_parser.add_argument("--out", type=Path, required=True, help="path without extension")
    pubkey_parser = commands.add_parser("pubkey", help="Show a private key's public half and fingerprint.")
    pubkey_parser.add_argument("--key", type=Path, required=True)
    licence_parser = commands.add_parser("sign-licence", help="Sign a licence.")
    licence_parser.add_argument("--key", type=Path, required=True)
    licence_parser.add_argument("--customer", required=True)
    licence_parser.add_argument("--expires", required=True, help="ISO date or time, e.g. 2027-10-01")
    licence_parser.add_argument("--not-before")
    licence_parser.add_argument("--features", default="")
    licence_parser.add_argument("--out", type=Path, required=True)
    package_parser = commands.add_parser("sign-package", help="Sign a built package folder.")
    package_parser.add_argument("--key", type=Path, required=True)
    package_parser.add_argument("package", type=Path)
    args = parser.parse_args(argv)

    if args.command == "keygen":
        private_path, public_path = keygen(args.out)
        document = json.loads(public_path.read_text(encoding="utf-8"))
        print(f"private key: {private_path} (keep it offline)\npublic key:  {public_path}\n"
              f"key id {document['key_id']}  fingerprint {document['fingerprint']}")
        return 0
    key = load_private_key(args.key)
    if args.command == "pubkey":
        print(json.dumps(publisher_document(public_raw(key)), indent=2))
        return 0
    if args.command == "sign-licence":
        expires = args.expires if "T" in args.expires else f"{args.expires}T00:00:00+00:00"
        features = [item.strip() for item in args.features.split(",") if item.strip()]
        envelope = sign_licence(key, licence_document(args.customer, expires, features=features,
                                                      not_before=args.not_before))
        args.out.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        print(f"licence {envelope['licence']['licence_id']} for {args.customer}, until {expires}: {args.out}")
        return 0
    envelope = sign_package(key, args.package)
    print(f"signed {envelope['signed']['label']} with key {envelope['key_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
