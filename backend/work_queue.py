"""B3 fundamentals: the queue partition workers take work from - the ledger stays the truth.

B2 made a partitioned scan's ledger complete enough to run from: every partition's
state, lease and attempts, and a record of the scan that rebuilds its engine. B3 puts
workers on it. A work queue only tells a worker which partition to look at; whether the
partition still needs doing, and who holds it, is always read from the ledger, and the
result is committed there before the queue hears that the partition is done.

Two queues keep the same contract:

- :class:`LedgerQueue` reads queued partitions straight from the ledger. It needs
  nothing but the database, so several ``python main.py worker`` processes can share
  scans today: claims are compare-and-set, and leases take back a dead worker's partition.
- :class:`RedisStreamQueue` is Memurai delivery (plan §2): one stream entry per
  partition, one consumer group, ``XACK`` after the database commit and never before,
  and ``XAUTOCLAIM`` for entries a dead worker never acknowledged. It is written against
  a client object and tested against a fake; the ``redis`` package is imported only when
  a real connection is asked for.

What may travel through a queue is fixed here rather than left to callers: three
identifiers. Memurai must never hold raw content, previews, credentials or samples
(plan §2) - a queue persisted to disk is one more place data at rest could collect - so
:func:`partition_payload` refuses anything else before it is sent, and
:func:`read_payload` refuses it again on the way back.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Protocol

from backend import store

logger = logging.getLogger(__name__)

PAYLOAD_FIELDS = ("tenant_id", "scan_id", "partition_id")
DEFAULT_STREAM = "dspm:partitions"
DEFAULT_GROUP = "dspm-workers"
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


class LedgerQueue:
    """Partitions queued in the ledger, taken straight from it.

    Nothing is published or acknowledged: a partition is queued in the ledger from the
    moment its scan is planned, and done once it is written there. ``take`` names the
    oldest resumable scan's first queued partition without claiming it - the worker's
    claim is the compare-and-set - so two workers may be handed the same partition and
    exactly one runs it. ``reclaim`` takes back partitions whose lease ran out, which
    queues them again.
    """

    def publish(self, tenant_id: str, scan_id: str, partition_ids: Iterable[str]) -> int:
        return 0

    def take(self, worker_id: str, *, block_seconds: float = 0.0) -> Delivery | None:
        found = store.next_queued_partition()
        if found is None:
            return None
        tenant_id, scan_id, partition_id = found
        return Delivery(tenant_id=tenant_id, scan_id=scan_id, partition_id=partition_id)

    def ack(self, delivery: Delivery) -> None:
        return None

    def reclaim(self, worker_id: str, *, idle_seconds: float) -> list[Delivery]:
        store.requeue_expired_partitions()
        return []


class RedisStreamQueue:
    """Memurai (Redis Streams) delivery of partition identifiers; the ledger decides everything else.

    One stream entry per partition, read through one consumer group. A worker
    acknowledges an entry only after its database commit, so a worker that dies in
    between leaves the entry pending, and :meth:`reclaim` hands it to another worker once
    it has been idle long enough - whose claim then finds the partition done and simply
    acknowledges it. The stream is never trimmed: an unacknowledged entry is work, and
    Memurai runs ``noeviction`` (plan §4).
    """

    def __init__(self, client, *, stream: str = DEFAULT_STREAM, group: str = DEFAULT_GROUP) -> None:
        self.client = client
        self.stream = stream
        self.group = group
        self._group_ready = False

    @classmethod
    def from_url(cls, url: str, **kwargs) -> "RedisStreamQueue":
        try:
            import redis  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "DSPM_WORK_QUEUE=redis needs the redis Python package, which is not installed"
            ) from exc
        return cls(redis.Redis.from_url(url, decode_responses=True), **kwargs)

    def _ensure_group(self) -> None:
        if self._group_ready:
            return
        try:
            self.client.xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        self._group_ready = True

    def publish(self, tenant_id: str, scan_id: str, partition_ids: Iterable[str]) -> int:
        self._ensure_group()
        published = 0
        for partition_id in partition_ids:
            self.client.xadd(self.stream, partition_payload(tenant_id, scan_id, partition_id))
            published += 1
        return published

    def _delivery(self, entry_id, fields) -> Delivery | None:
        receipt = _text(entry_id)
        try:
            payload = read_payload(fields)
        except PayloadRefused as exc:
            # Something other than a partition message reached the stream. It is
            # acknowledged so it cannot circulate, and never handed to a worker.
            logger.warning("Dropped work queue entry %s: %s", receipt, exc)
            self.client.xack(self.stream, self.group, receipt)
            return None
        return Delivery(receipt=receipt, **payload)

    def take(self, worker_id: str, *, block_seconds: float = 0.0) -> Delivery | None:
        self._ensure_group()
        response = self.client.xreadgroup(
            self.group, worker_id, {self.stream: ">"}, count=1,
            block=int(block_seconds * 1000) if block_seconds > 0 else None,
        )
        for _stream, entries in response or []:
            for entry_id, fields in entries:
                return self._delivery(entry_id, fields)
        return None

    def ack(self, delivery: Delivery) -> None:
        self.client.xack(self.stream, self.group, delivery.receipt)

    def reclaim(self, worker_id: str, *, idle_seconds: float) -> list[Delivery]:
        self._ensure_group()
        response = self.client.xautoclaim(
            self.stream, self.group, worker_id, int(max(0.0, idle_seconds) * 1000), start_id="0-0", count=100,
        )
        entries = response[1] if isinstance(response, (list, tuple)) and len(response) > 1 else []
        deliveries = []
        for entry_id, fields in entries:
            if fields is None:
                continue
            delivery = self._delivery(entry_id, fields)
            if delivery is not None:
                deliveries.append(delivery)
        return deliveries


def work_queue_from_env() -> PartitionQueue:
    """The queue ``DSPM_WORK_QUEUE`` names: ``ledger`` (the default) or ``redis``."""
    kind = os.getenv("DSPM_WORK_QUEUE", "ledger").strip().lower() or "ledger"
    if kind == "ledger":
        return LedgerQueue()
    if kind == "redis":
        url = os.getenv("DSPM_REDIS_URL", "").strip()
        if not url:
            raise RuntimeError("DSPM_WORK_QUEUE=redis needs DSPM_REDIS_URL")
        return RedisStreamQueue.from_url(
            url,
            stream=os.getenv("DSPM_REDIS_STREAM", DEFAULT_STREAM).strip() or DEFAULT_STREAM,
            group=os.getenv("DSPM_REDIS_GROUP", DEFAULT_GROUP).strip() or DEFAULT_GROUP,
        )
    raise RuntimeError(f"DSPM_WORK_QUEUE must be ledger or redis, not {kind!r}")
