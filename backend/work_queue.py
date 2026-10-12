"""B3 fundamentals: the queue partition workers take work from - the ledger stays the truth.

B2 made a partitioned scan's ledger complete enough to run from: every partition's
state, lease and attempts, and a record of the scan that rebuilds its engine. B3 puts
workers on it. A work queue only tells a worker which partition to look at; whether the
partition still needs doing, and who holds it, is always read from the ledger, and the
result is committed there before the queue hears that the partition is done.

:class:`LedgerQueue` is the queue: it reads queued partitions straight from the ledger,
so it needs nothing but the database, and several ``python main.py worker`` processes
share scans through it - claims are compare-and-set, and leases take back a dead
worker's partition. A Memurai (Redis Streams) delivery queue sat beside it until the
product owner removed Memurai on 2026-09-18; the ledger never depended on it.

:class:`PartitionQueue` stays the seam a delivery transport would plug into, and what
may travel through one is fixed here rather than left to callers: three identifiers. A
queue persisted outside the database would be one more place data at rest could
collect, so :func:`partition_payload` refuses anything else before it is sent, and
:func:`read_payload` refuses it again on the way back.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Iterable, Mapping, Protocol

from backend import store

logger = logging.getLogger(__name__)

PAYLOAD_FIELDS = ("tenant_id", "scan_id", "partition_id")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,199}")


class PayloadRefused(ValueError):
    """A queue message that is not exactly a partition's identifiers."""


def _text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PayloadRefused("a partition message field is not text") from exc
    raise PayloadRefused("a partition message field is not text")


def read_payload(fields: Mapping) -> dict[str, str]:
    """Check a message field by field; returns its identifiers as plain strings.

    Exactly the three identifier fields, each a short token of letters, digits and
    ``_ . : @ + -``. A preview, a path, a credential or a record cannot pass as one. The
    refusal never repeats the refused value: it may be the very thing that must not be
    written anywhere.
    """
    if not isinstance(fields, Mapping):
        raise PayloadRefused("a partition message is a set of fields")
    decoded = {_text(key): _text(value) for key, value in fields.items()}
    if set(decoded) != set(PAYLOAD_FIELDS):
        raise PayloadRefused(
            f"a partition message carries exactly {', '.join(PAYLOAD_FIELDS)}; "
            f"it had {len(decoded)} field(s), {len(set(decoded) - set(PAYLOAD_FIELDS))} of them unknown"
        )
    for key in PAYLOAD_FIELDS:
        if not _IDENTIFIER.fullmatch(decoded[key]):
            raise PayloadRefused(f"{key} is not an identifier")
    return {key: decoded[key] for key in PAYLOAD_FIELDS}


def partition_payload(tenant_id: str, scan_id: str, partition_id: str) -> dict[str, str]:
    """The one message a work queue carries: which partition, and nothing about it."""
    return read_payload({"tenant_id": tenant_id, "scan_id": scan_id, "partition_id": partition_id})


@dataclass(frozen=True)
class Delivery:
    """One partition handed to one worker. ``receipt`` is what its queue needs to acknowledge it."""

    tenant_id: str
    scan_id: str
    partition_id: str
    receipt: str = ""


class PartitionQueue(Protocol):
    def publish(self, tenant_id: str, scan_id: str, partition_ids: Iterable[str]) -> int: ...

    def take(self, worker_id: str, *, block_seconds: float = 0.0) -> Delivery | None: ...

    def ack(self, delivery: Delivery) -> None: ...

    def reclaim(self, worker_id: str, *, idle_seconds: float) -> list[Delivery]: ...

    def pass_over(self, delivery: Delivery, *, seconds: float) -> None: ...


class LedgerQueue:
    """Partitions queued in the ledger, taken straight from it.

    Nothing is published or acknowledged: a partition is queued in the ledger from the
    moment its scan is planned, and done once it is written there. ``take`` names a
    queued partition of a running, resumable scan this host can run, without claiming it
    - the worker's claim is the compare-and-set - so two workers may be handed the same
    partition and exactly one runs it. Scans take turns (W2.4): workspaces in rotation,
    and within one, its scans in rotation. It used to be the oldest scan's partition
    every time, so one large scan held every worker until its last partition was taken. A scan the worker passed over
    - planned on another host, or not rebuildable here - is skipped for a while, so it
    never hides the scans behind it. Expired leases are taken back by the worker's
    maintenance pass, for every kind of queue.
    """

    def __init__(self) -> None:
        self._passed: dict[tuple[str, str], float] = {}
        self._last_tenant = ""
        self._last_scan: dict[str, str] = {}

    def publish(self, tenant_id: str, scan_id: str, partition_ids: Iterable[str]) -> int:
        # Nothing to send: they are queued in the ledger already, and this says how many
        # the workers can now take - which is what the console reports and audits.
        return sum(1 for _ in partition_ids)

    def take(self, worker_id: str, *, block_seconds: float = 0.0) -> Delivery | None:
        from backend.partitioned_scan import runs_here

        now = time.monotonic()
        by_tenant: dict[str, list[str]] = {}
        for record in store.list_unfinished_partitioned_scans(resumable_only=True):
            key = (record["tenant_id"], record["scan_id"])
            if record["status"] != "running" or self._passed.get(key, 0.0) > now or not runs_here(record) \
                    or store.scan_is_paused(record):
                # A paused scan (W3.2) - its target's breaker, the disk floor - waits out its pause.
                continue
            by_tenant.setdefault(key[0], []).append(key[1])
        for tenant_id in _rotated(sorted(by_tenant), self._last_tenant):
            for scan_id in _rotated(by_tenant[tenant_id], self._last_scan.get(tenant_id, "")):
                partition_id = store.first_queued_partition(tenant_id, scan_id)
                if partition_id is not None:
                    self._last_tenant = tenant_id
                    self._last_scan[tenant_id] = scan_id
                    return Delivery(tenant_id=tenant_id, scan_id=scan_id, partition_id=partition_id)
        return None

    def ack(self, delivery: Delivery) -> None:
        return None

    def reclaim(self, worker_id: str, *, idle_seconds: float) -> list[Delivery]:
        return []

    def pass_over(self, delivery: Delivery, *, seconds: float) -> None:
        self._passed[(delivery.tenant_id, delivery.scan_id)] = time.monotonic() + max(0.0, seconds)


def _rotated(items: list[str], last: str) -> list[str]:
    """``items`` starting after ``last`` - the next turn - or from the start."""
    if last in items:
        index = items.index(last) + 1
        return items[index:] + items[:index]
    return list(items)


def work_queue_from_env() -> PartitionQueue:
    """The queue ``DSPM_WORK_QUEUE`` names. ``ledger`` is the only one.

    ``redis`` named the Memurai queue. An install whose environment still says so gets
    the ledger and a warning rather than a worker that will not start: the ledger was
    always the truth, and the stream only ever carried a copy of what it says.
    """
    kind = os.getenv("DSPM_WORK_QUEUE", "ledger").strip().lower() or "ledger"
    if kind == "ledger":
        return LedgerQueue()
    if kind == "redis":
        logger.warning("DSPM_WORK_QUEUE=redis: Memurai was removed, so workers take partitions from the ledger")
        return LedgerQueue()
    raise RuntimeError(f"DSPM_WORK_QUEUE must be ledger, not {kind!r}")
