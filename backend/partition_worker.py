"""B3 fundamentals: a worker process that runs scan partitions from a work queue.

``python main.py worker`` runs :func:`run_worker`. A worker holds no scan of its own. It
takes a partition identifier from the queue, reads that partition's scan from the ledger,
rebuilds the engine from the recorded request - the same validation and credential
resolution a scan started from the console gets - runs the partition under a lease,
commits it, and only then acknowledges the queue. When it writes a scan's last partition,
it finalizes the scan unless another worker already is.

Every decision is the ledger's: a partition already done, or held by a live worker, is
not run again, and a message for a scan that finished or failed is acknowledged and
dropped. A crash anywhere leaves an unacknowledged message, which is reclaimed once idle,
or a partition whose lease runs out - and both come back to a worker.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from typing import Callable

from backend import partitioned_scan, store
from backend.work_queue import Delivery, PartitionQueue

logger = logging.getLogger(__name__)


def default_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"


def handle_delivery(queue: PartitionQueue, delivery: Delivery, rebuild: Callable[[dict], object], *,
                    worker_id: str) -> str:
    """Run one delivered partition; returns ``written``, ``finished``, ``held``, ``retry``, ``stopped`` or ``dropped``.

    The queue is acknowledged for every outcome but ``held``: a partition a live worker
    holds is left pending, so if that worker dies the message comes back once idle. A
    failed partition with attempts left is queued again - in the ledger, and as a new
    message - before its old message is acknowledged.
    """
    record = store.read_partitioned_scan(delivery.tenant_id, delivery.scan_id)
    if record is None or record["status"] in ("done", "failed") or not record["resumable"]:
        queue.ack(delivery)
        return "dropped"
    try:
        config = rebuild(record)
    except Exception as exc:
        store.mark_partitioned_scan(
            delivery.tenant_id, delivery.scan_id, "failed",
            error=f"Scan could not be rebuilt for a worker ({type(exc).__name__}). Run the scan again.",
        )
        queue.ack(delivery)
        return "dropped"
    outcome = partitioned_scan.run_queued_partition(record, config, delivery.partition_id, worker_id=worker_id)
    if outcome == "held":
        return outcome
    if outcome == "retry":
        queue.publish(delivery.tenant_id, delivery.scan_id, [delivery.partition_id])
    queue.ack(delivery)
    if outcome in ("written", "finished"):
        partitioned_scan.finalize_if_complete(record, config)
    return outcome


def run_worker(
    queue: PartitionQueue,
    rebuild: Callable[[dict], object],
    *,
    worker_id: str | None = None,
    stop: threading.Event | None = None,
    block_seconds: float = 5.0,
    idle_seconds: float = 1.0,
    stop_when_idle: bool = False,
) -> int:
    """Take and run partitions until ``stop`` is set; returns how many deliveries were handled.

    Every third of a lease the worker first reclaims what dead workers left: pending
    messages idle for a lease, or, on the ledger queue, partitions whose lease ran out.
    ``stop_when_idle`` returns as soon as the queue has nothing to hand out - for tests
    and one-shot runs.
    """
    worker_id = worker_id or default_worker_id()
    stop = stop or threading.Event()
    lease = partitioned_scan.partition_lease_seconds()
    handled = 0
    last_reclaim = float("-inf")
    while not stop.is_set():
        deliveries: list[Delivery] = []
        if time.monotonic() - last_reclaim >= lease / 3:
            last_reclaim = time.monotonic()
            deliveries = queue.reclaim(worker_id, idle_seconds=lease)
        if not deliveries:
            delivery = queue.take(worker_id, block_seconds=block_seconds)
            if delivery is None:
                if stop_when_idle:
                    break
                stop.wait(idle_seconds)
                continue
            deliveries = [delivery]
        for delivery in deliveries:
            try:
                handle_delivery(queue, delivery, rebuild, worker_id=worker_id)
            except Exception as exc:
                logger.warning(
                    "Partition %s of scan %s could not be handled: %s",
                    delivery.partition_id, delivery.scan_id, type(exc).__name__,
                )
            handled += 1
    return handled
