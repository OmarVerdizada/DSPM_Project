"""Run the Phase 7 corruption game day entirely inside a temporary directory.

Two independent failure modes are injected: a modified encrypted backup and a
valid-but-wrong artifact object.  The drill proves both are refused and that
the untouched recovery copies still read successfully.  It never modifies a
live database, backup, artifact root or tenant object.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import artifacts, backup, db_certification  # noqa: E402


@contextmanager
def _temporary_environment(values: dict[str, str]):
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _flip_last_byte(source: Path, destination: Path) -> None:
    shutil.copyfile(source, destination)
    with destination.open("r+b") as stream:
        stream.seek(-1, 2)
        original = stream.read(1)
        stream.seek(-1, 2)
        stream.write(bytes([original[0] ^ 0x01]))


def run_drill() -> dict:
    generated_at = db_certification.utc_now().isoformat()
    with tempfile.TemporaryDirectory(prefix="sentro-corruption-game-day-") as raw_root:
        root = Path(raw_root)
        env = {
            "DSPM_BACKUP_KEY": Fernet.generate_key().decode("ascii"),
            "DSPM_ARTIFACT_KEY": Fernet.generate_key().decode("ascii"),
            "DSPM_ARTIFACT_DIR": str(root / "artifacts"),
        }
        with _temporary_environment(env):
            # Backup tampering must fail cryptographic verification, while the
            # untouched encrypted copy must remain recoverable.
            plain = root / "source.dump"
            encrypted = root / "source.dump.enc"
            corrupted = root / "corrupted.dump.enc"
            recovered = root / "recovered.dump"
            rejected = root / "must-not-recover.dump"
            payload = (b"sentro-phase-7-backup-game-day\n" * 4096)
            plain.write_bytes(payload)
            expected_sha, _ = backup.encrypt_file(plain, encrypted)
            recovered_sha = backup.decrypt_file(encrypted, recovered)
            _flip_last_byte(encrypted, corrupted)
            backup_corruption_detected = False
            try:
                backup.decrypt_file(corrupted, rejected)
            except Exception:
                backup_corruption_detected = True
            backup_recovery_ok = (
                recovered.read_bytes() == payload and recovered_sha == expected_sha
            )

            # Swapping two *valid* artifact ciphertexts bypasses encryption
            # integrity but must still fail the content-address check.
            first = artifacts.put_bytes("game-day", b"expected report body")
            second = artifacts.put_bytes("game-day", b"different valid report body")
            first_path = artifacts.object_path(first.tenant_id, first.content_id)
            second_path = artifacts.object_path(second.tenant_id, second.content_id)
            saved_first = root / "first-object.enc"
            shutil.copyfile(first_path, saved_first)
            shutil.copyfile(second_path, first_path)
            artifact_corruption_detected = False
            try:
                artifacts.get_bytes(first.tenant_id, first.content_id)
            except artifacts.ArtifactCorrupted:
                artifact_corruption_detected = True
            shutil.copyfile(saved_first, first_path)
            artifact_recovery_ok = (
                artifacts.get_bytes(first.tenant_id, first.content_id)
                == b"expected report body"
            )

    scenarios = {
        "backup_ciphertext_tamper": {
            "corruption_detected": backup_corruption_detected,
            "original_recovery_ok": backup_recovery_ok,
        },
        "artifact_object_substitution": {
            "corruption_detected": artifact_corruption_detected,
            "original_recovery_ok": artifact_recovery_ok,
        },
    }
    passed = all(
        scenario["corruption_detected"] and scenario["original_recovery_ok"]
        for scenario in scenarios.values()
    )
    return {
        "evidence_kind": "corruption_game_day",
        "generated_at": generated_at,
        "scope": "isolated temporary copies; no live data modified",
        "scenarios": scenarios,
        "result": "PASS" if passed else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=Path("docs/database/evidence"))
    args = parser.parse_args()
    payload = run_drill()
    output = db_certification.write_evidence(
        args.evidence_dir, "corruption_game_day", payload
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"\nevidence: {output}")
    return 0 if payload["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
