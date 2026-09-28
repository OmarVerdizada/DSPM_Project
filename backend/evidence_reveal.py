"""Reveal ONE value behind a finding, read again from its source (C13).

A scan keeps no raw sensitive value: it keeps a masked sample and a keyed fingerprint of
each value (`classification.regex_classifier._fingerprint`). Revealing therefore never
reads a stored secret - there is none. It reads the FILE again:

  1. the finding, and the fingerprint the person chose, which must be one of its own;
  2. the asset's recorded identity (whole-file SHA-256 and size);
  3. the file, from where the scan read it - the server's own disk for a local scan, or
     the SMB share with the saved credential the scan used. A scan run with a password
     typed at scan time kept no credential, so it cannot be read again: unrevealable;
  4. if the file changed since the scan (digest or size differ), nothing is revealed;
  5. detection again on the text, the same rules, and the one candidate whose
     fingerprint equals the chosen one is the value returned. Nothing else is returned,
     and nothing is written anywhere.

Every attempt - revealed or refused, and why - is audited by the route with the actor,
the workspace, the source, the file and the reason given; never the value.

Endpoint (WinRM) scans are not revealable yet: their re-read needs the endpoint session
the scan held, and a reveal must not open a remote shell on its own.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

REASON_MIN = 12
REASON_MAX = 500


class RevealRefused(Exception):
    """Nothing was revealed; `code` names why, the message says it to a person."""

    client_safe = True

    def __init__(self, code: str, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def _refuse(code: str, message: str, status: int = 409):
    raise RevealRefused(code, message, status)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _server_from_reuse_key(reuse_key: str) -> str:
    # smb://<server>/<share><path>
    if reuse_key.lower().startswith("smb://"):
        return reuse_key[len("smb://"):].split("/", 1)[0]
    return ""


def _identity(asset: dict) -> tuple[str, int]:
    digest = str(asset.get("sha256") or asset.get("file_hash") or "").lower()
    try:
        size = int(asset.get("size") or asset.get("size_bytes") or 0)
    except (TypeError, ValueError):
        size = 0
    return digest, size


def _read_local(asset: dict) -> tuple[str, str, int]:
    from collectors.file_scanner import read_text_preview_and_sha256

    path = Path(str(asset.get("path") or ""))
    if not path.is_file():
        _refuse("source_missing", "The file is no longer where the scan found it.")
    text, digest = read_text_preview_and_sha256(path)
    return text, digest, path.stat().st_size


def _read_smb(tenant_id: str, asset: dict, source: dict) -> tuple[str, str, int]:
    from backend.vault import CredentialVault
    from collectors.file_scanner import detect_extension
    from collectors.smb_scanner import SMBConfig, SMBScanner

    server = str(source.get("server") or _server_from_reuse_key(str(asset.get("reuse_key") or "")))
    share = str(asset.get("share") or "")
    path = str(asset.get("path") or "")
    if not (server and share and path):
        _refuse("no_location", "The scan did not record enough of where the file is to read it again.")
    try:
        account = CredentialVault().resolve(tenant_id, str(source["credential_ref"]))
    except KeyError:
        _refuse("credential_gone", "The saved credential this scan used has been deleted.")
    scanner = SMBScanner(SMBConfig(server=server, tenant_id=tenant_id, username=account.get("username", ""),
                                   password=account.get("password", ""), domain=account.get("domain", "WORKGROUP")))
    try:
        if not scanner.connect():
            _refuse("source_unreachable", "The file server could not be reached with the scan's saved credential.")
        _identity_digest, size = _identity(asset)
        data = scanner._acquire_file_data(share, path, detect_extension(Path(path)), size)
    finally:
        try:
            if scanner.connection is not None:
                scanner.connection.close()
        except Exception:
            pass
    return str(data.content or ""), str(data.sha256 or ""), size


def reread(tenant_id: str, asset: dict, source: dict | None) -> str:
    """The file's text as the scan saw it - or RevealRefused when that cannot be had."""
    kind = str(asset.get("source") or (source or {}).get("source_kind") or "").lower()
    if kind.startswith("endpoint"):
        _refuse("unsupported_source", "Values found on endpoint (WinRM) scans cannot be revealed yet.")
    if kind == "smb":
        if source is None:
            _refuse("no_scan_record", "This scan was run before reveal was possible and did not record its "
                                      "credential. Scan the share again with a saved credential.")
        if source.get("credential_kind") != "saved" or not source.get("credential_ref"):
            _refuse("typed_credential", "This scan used a password typed at scan time, which is never kept, so the "
                                        "file cannot be read again. Scan with a saved credential to reveal its values.")
        text, digest, size = _read_smb(tenant_id, asset, source)
    elif kind == "local":
        text, digest, size = _read_local(asset)
    else:
        _refuse("unsupported_source", f"Values from '{kind or 'unknown'}' sources cannot be revealed.")
    expected_digest, expected_size = _identity(asset)
    if not expected_digest:
        _refuse("no_identity", "The scan recorded no digest for this file, so a changed file could not be told "
                               "from the one scanned. Nothing is revealed.")
    if digest.lower() != expected_digest or (expected_size and size and size != expected_size):
        _refuse("file_changed", "The file has changed since the scan. Scan it again; nothing is revealed from a "
                                "file that is not the one the finding came from.")
    return text


def candidates(text: str):
    """Every value the redacting regex rules find in `text`, with the fingerprint a scan
    gives it - the same rules, validators and fingerprint the classifier uses."""
    from classification.regex_classifier import RULES, _fingerprint

    for rule in RULES:
        if not rule.redact:
            continue
        if rule.finder is not None:
            values = [value for value, _extra in rule.finder(text)]
        else:
            values = []
            for match in rule.pattern.finditer(text):
                value = match.group(rule.value_group) if rule.value_group else match.group(0)
                if value is None:
                    value = match.group(0)
                if rule.validator is None or rule.validator(value):
                    values.append(value)
        for value in values:
            yield rule.name, value, _fingerprint(value)


def reveal(tenant_id: str, finding_id: str, fingerprint: str, reason: str) -> dict:
    """The one value behind `fingerprint` in finding `finding_id`, read again now."""
    from backend import store
    from classification.masking import mask

    reason = " ".join(str(reason or "").split())
    if len(reason) < REASON_MIN:
        _refuse("reason_required", f"Say why the value is needed (at least {REASON_MIN} characters).", 400)
    finding = store.get_finding(tenant_id, finding_id)
    location = store.finding_location(tenant_id, finding_id)
    if finding is None or location is None:
        _refuse("not_found", "Finding not found.", 404)
    if fingerprint not in (finding.get("secure_value_fingerprints") or []):
        _refuse("unknown_occurrence", "That value is not one of this finding's.", 400)
    asset = store.get_inventory_asset(tenant_id, location["asset_id"])
    if asset is None:
        _refuse("asset_gone", "The file this finding came from is no longer in the inventory.")
    source = store.get_scan_source(tenant_id, location.get("scan_id") or "")
    text = reread(tenant_id, asset, source)
    for rule_name, value, candidate in candidates(text):
        if candidate == fingerprint:
            return {"finding_id": finding_id, "type": finding.get("type") or rule_name, "fingerprint": fingerprint,
                    "value": value, "masked": mask(value, str(finding.get("data_class") or "generic")),
                    "location": {"source": asset.get("source"), "path": asset.get("path"), "share": asset.get("share")}}
    _refuse("not_found_again", "The file is unchanged, but the value was not found in it again; nothing is revealed.")
    return {}  # unreachable
