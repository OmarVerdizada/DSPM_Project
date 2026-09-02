"""Build, check, and reconcile the optional Track S-F Meilisearch asset index.

Credentials are read only from environment variables; never pass an API key on
the command line. The default action is read-only. ``--rebuild`` explicitly
deletes/recreates the configured search index, then streams normalized assets
from the primary database in bounded keyset batches.
"""

from __future__ import annotations

import argparse
import json

from backend import store
from backend.search import config_from_env, rebuild_index, run_search_reconciliation, search_health


def main() -> int:
    parser = argparse.ArgumentParser(description="Check or rebuild the optional Sentro search index")
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="delete/recreate the configured index and stream every normalized asset into it",
    )
    reconcile = parser.add_mutually_exclusive_group()
    reconcile.add_argument(
        "--check-drift",
        action="store_true",
        help="compare every authoritative asset with the search projection without changing either store",
    )
    reconcile.add_argument(
        "--repair-drift",
        action="store_true",
        help="repair missing/stale documents and delete search-only orphans in bounded batches",
    )
    args = parser.parse_args()

    if args.rebuild and (args.check_drift or args.repair_drift):
        parser.error("--rebuild cannot be combined with reconciliation options")

    if args.check_drift or args.repair_drift:
        result = run_search_reconciliation(repair=args.repair_drift)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("in_sync") else 2

    if not args.rebuild:
        print(json.dumps(search_health(), ensure_ascii=False, indent=2))
        return 0

    config = config_from_env()
    result = rebuild_index(store.iter_search_asset_batches(config.batch_size))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
