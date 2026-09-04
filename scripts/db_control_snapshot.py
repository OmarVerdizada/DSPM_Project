"""Capture Phase 7 schema, patch, regional and activity-monitoring evidence.

The database DSN is read only from ``DSPM_DB_URL``.  The output contains a
non-secret database identity and aggregate counters; it never contains the DSN,
query text, client addresses, role names or tenant identifiers.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import db_certification  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path("docs/database/P7_CERTIFICATION_PROFILE.json"),
    )
    parser.add_argument("--evidence-dir", type=Path, default=Path("docs/database/evidence"))
    args = parser.parse_args()

    # Operational evidence is read-only.  Keep importing store from trying to
    # auto-run development migrations as the DML-only runtime role.
    os.environ["DSPM_MIGRATIONS_CLI"] = "1"
    profile = db_certification.load_profile(args.profile)
    payload = db_certification.collect_control_snapshot(profile)
    output = db_certification.write_evidence(args.evidence_dir, "db_controls", payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"\nevidence: {output}")
    return 0 if payload["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
