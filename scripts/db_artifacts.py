"""Artifact tier maintenance (Phase 5, DB-07): inventory, verify, collect.

    python scripts/db_artifacts.py stats     # object count, bytes, tenants
    python scripts/db_artifacts.py verify    # every referenced body is readable
    python scripts/db_artifacts.py prune     # dry run: what is unreferenced
    python scripts/db_artifacts.py prune --apply
    python scripts/db_artifacts.py recompress --apply   # upgrade legacy objects

``verify`` is the one to run after a restore: it reads every body the database
references, through the same path the application uses, and reports any that
are missing or fail their content hash. A database that restored cleanly while
its artifact tier did not is exactly the failure this tier introduces, so it
gets a first-class check.

``recompress`` rewrites objects stored before the format gained compression.
They stay readable either way; this reclaims the space.

``prune`` removes objects no row references - superseded bodies from report
re-saves, and anything left by an interrupted write. Objects newer than the
grace window are always kept, because a body is written before the row that
references it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _referenced() -> set[tuple[str, str]]:
    from backend import store

    with store._connect() as conn:
        rows = conn.execute(
            "SELECT tenant_id, report_ref FROM scan_reports "
            "WHERE COALESCE(report_ref, '') <> ''"
        ).fetchall()
    return {(str(r["tenant_id"]), str(r["report_ref"])) for r in rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stats", "verify", "prune", "recompress"))
    parser.add_argument("--apply", action="store_true", help="prune: actually delete")
    parser.add_argument("--grace-seconds", type=int, default=3600,
                        help="prune: keep objects younger than this (default 3600)")
    args = parser.parse_args()

    from backend import artifacts

    if args.command == "stats":
        stats = artifacts.store_stats()
        referenced = _referenced()
        print(f"root:        {stats['root']}")
        print(f"objects:     {stats['objects']}")
        print(f"tenants:     {stats['tenants']}")
        print(f"ciphertext:  {stats['ciphertext_bytes'] / 1024 / 1024:.1f} MB")
        print(f"referenced:  {len(referenced)}")
        print(f"unreferenced:{stats['objects'] - len(referenced)}")
        return 0

    if args.command == "verify":
        referenced = _referenced()
        missing: list[str] = []
        corrupt: list[str] = []
        ok = 0
        for tenant, content_id in sorted(referenced):
            try:
                artifacts.get_bytes(tenant, content_id)
                ok += 1
            except artifacts.ArtifactMissing:
                missing.append(f"{tenant}/{content_id[:12]}")
            except artifacts.ArtifactCorrupted:
                corrupt.append(f"{tenant}/{content_id[:12]}")
        print(f"verified {ok}/{len(referenced)} referenced bodies")
        for label, items in (("MISSING", missing), ("CORRUPT", corrupt)):
            for item in items:
                print(f"  {label}: {item}", file=sys.stderr)
        return 0 if not missing and not corrupt else 1

    if args.command == "recompress":
        legacy = []
        for tenant, content_id, path in artifacts.iter_objects():
            with open(path, "rb") as handle:
                if handle.read(len(artifacts._MAGIC_GZIP)) != artifacts._MAGIC_GZIP:
                    legacy.append((tenant, content_id, path))
        before = artifacts.store_stats()["ciphertext_bytes"]
        print(f"{len(legacy)} object(s) predate compression "
              f"({before / 1024 / 1024:.1f} MB total on disk)")
        if not args.apply:
            print("\ndry run - re-run with --apply to rewrite them.")
            return 0
        rewritten = 0
        for tenant, content_id, path in legacy:
            # Read through the normal path (which verifies the content hash),
            # then re-store. The content id is the hash of the plaintext, so it
            # does not change - only the bytes on disk do.
            payload = artifacts.get_bytes(tenant, content_id)
            path.unlink()
            ref = artifacts.put_bytes(tenant, payload)
            assert ref.content_id == content_id, "content id must be stable"
            rewritten += 1
        after = artifacts.store_stats()["ciphertext_bytes"]
        print(f"rewrote {rewritten} object(s): "
              f"{before / 1024 / 1024:.1f} MB -> {after / 1024 / 1024:.1f} MB")
        return 0

    referenced = _referenced()
    if not args.apply:
        stats = artifacts.store_stats()
        unreferenced = [
            f"{tenant}/{cid[:12]}"
            for tenant, cid, _p in artifacts.iter_objects()
            if (tenant, cid) not in referenced
        ]
        print(f"{len(unreferenced)} of {stats['objects']} objects are unreferenced")
        for item in unreferenced[:15]:
            print(f"  would remove {item}")
        if len(unreferenced) > 15:
            print(f"  ... and {len(unreferenced) - 15} more")
        print("\ndry run - re-run with --apply to collect them.")
        return 0

    removed = artifacts.prune(referenced, grace_seconds=args.grace_seconds)
    stats = artifacts.store_stats()
    print(f"removed {removed} unreferenced objects; "
          f"{stats['objects']} remain ({stats['ciphertext_bytes'] / 1024 / 1024:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
