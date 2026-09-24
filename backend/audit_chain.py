"""The audit trail as a per-tenant hash chain (C4).

An audit table anybody with database access can edit is a record of what that person
chose to leave in it. Each tenant's rows now form a chain: row `seq` stores the hash
of row `seq - 1` (`prev_hash`) and its own `row_hash`, computed over its content and
that previous hash. Changing a row changes its hash, which no longer matches the next
row's `prev_hash`; deleting one leaves a gap in `seq`; cutting off the newest rows
leaves the chain shorter than the tenant's chain head says it is.

What a chain does NOT stop is someone with write access recomputing every hash after
an edit. The defence for that is a copy held elsewhere: the SIEM forwarder sends each
row's `seq` and `row_hash`, so the chain the SIEM received can be compared with the one
in the database. `audit verify` proves the database is internally consistent; the SIEM
copy proves it is the chain that was written.

Rows written before the chain existed are sealed at upgrade (revision 0022): chained in
their stored order, with the head recording how far the seal reaches, so verification
can say plainly that nothing proves those rows were untouched BEFORE the upgrade.
Retention pruning removes the oldest rows; the head keeps the seq and hash of the last
row removed, so the remaining chain still starts from a known point.
"""

from __future__ import annotations

import hashlib
import json
from typing import Iterable

CHAIN_VERSION = 1
# A chain broken everywhere names a problem per row; the report keeps this many and
# counts the rest, so verifying a million-row trail cannot build a million-entry list.
PROBLEM_LIMIT = 1000


def row_hash(prev_hash: str, tenant_id: str, seq: int, timestamp: str, actor: str, action: str,
             detail_json: str) -> str:
    """The hash of one audit row. `detail_json` is hashed as stored, byte for byte, so a
    row verifies against exactly what is in the database, not a re-serialisation."""
    payload = json.dumps(
        [CHAIN_VERSION, str(tenant_id), int(seq), str(timestamp), str(actor), str(action),
         str(detail_json), str(prev_hash or "")],
        ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain(tenant_id: str, rows: Iterable[dict], head: dict | None) -> dict:
    """Check one tenant's rows (ordered by seq) against each other and against its head.

    Returns {"tenant_id", "ok", "rows", "problems": [...], "problem_count",
    "sealed_through_seq", "sealed_at", "pruned_through_seq"}. A problem names the seq and
    what is wrong with it; verification does not stop at the first, so a report shows the
    extent - the first PROBLEM_LIMIT of them, and how many there were.

    `rows` is read once, in order, so a caller can stream it from a cursor: a tenant's
    whole trail is never held at once.
    """
    head = head or {}
    pruned_through = int(head.get("pruned_through_seq") or 0)
    expected_prev = str(head.get("pruned_through_hash") or "")
    expected_seq = pruned_through + 1
    problems = _Problems()
    count = 0
    for row in rows:
        count += 1
        seq = row.get("seq")
        if seq is None:
            problems.append({"seq": None, "id": row.get("id"), "problem": "row is not in the chain"})
            continue
        seq = int(seq)
        if seq != expected_seq:
            problems.append({"seq": seq, "problem": f"expected seq {expected_seq}: rows are missing or out of order"})
        if str(row.get("prev_hash") or "") != expected_prev:
            problems.append({"seq": seq, "problem": "does not follow the row before it (prev_hash differs)"})
        recomputed = row_hash(row.get("prev_hash") or "", tenant_id, seq, row.get("timestamp") or "",
                              row.get("actor") or "", row.get("action") or "", row.get("detail_json") or "")
        if recomputed != str(row.get("row_hash") or ""):
            problems.append({"seq": seq, "problem": "content does not match its hash (the row was changed)"})
        expected_prev = str(row.get("row_hash") or "")
        expected_seq = seq + 1
    last_seq = int(head.get("last_seq") or 0)
    if head and last_seq != expected_seq - 1:
        problems.append({"seq": last_seq, "problem":
                         f"the chain head records {last_seq} rows but the chain ends at {expected_seq - 1}: "
                         "the newest rows are missing"})
    if head and last_seq and str(head.get("last_hash") or "") != expected_prev:
        problems.append({"seq": last_seq, "problem": "the chain head's hash does not match the last row"})
    return {
        "tenant_id": tenant_id,
        "ok": not problems.count,
        "rows": count,
        "problems": problems.kept,
        "problem_count": problems.count,
        "sealed_through_seq": int(head.get("sealed_through_seq") or 0),
        "sealed_at": str(head.get("sealed_at") or ""),
        "pruned_through_seq": pruned_through,
    }


class _Problems:
    """What verify_chain found: every one counted, the first PROBLEM_LIMIT kept."""

    __slots__ = ("kept", "count")

    def __init__(self) -> None:
        self.kept: list[dict] = []
        self.count = 0

    def append(self, problem: dict) -> None:
        self.count += 1
        if len(self.kept) < PROBLEM_LIMIT:
            self.kept.append(problem)

    def insert(self, index: int, problem: dict) -> None:
        self.count += 1
        self.kept.insert(index, problem)
        del self.kept[PROBLEM_LIMIT:]
