"""Build the Phase 7 regulated/high-scale database evidence package.

The ZIP contains only sanitized JSON control evidence, the approved profile and
a SHA-256 manifest.  Database dumps and artifact archives remain in the backup
store; their hashes are verified and referenced instead of duplicating those
large encrypted payloads into an audit bundle.  A configured
``DSPM_DB_EVIDENCE_SIGNING_KEY`` additionally HMAC-signs the manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import backup, db_certification  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path("docs/database/P7_CERTIFICATION_PROFILE.json"),
    )
    parser.add_argument("--evidence-dir", type=Path, default=Path("docs/database/evidence"))
    parser.add_argument("--backup-dir", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    profile = db_certification.load_profile(args.profile)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = args.output or args.evidence_dir / "packages" / f"p7_evidence_{stamp}.zip"
    manifest = db_certification.build_evidence_package(
        profile,
        args.evidence_dir,
        args.backup_dir or backup.backup_dir(),
        output,
    )
    display = {**manifest, "package": str(output)}
    print(json.dumps(display, indent=2, sort_keys=True))
    return 0 if manifest["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
