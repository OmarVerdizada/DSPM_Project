"""B3: a worker process that runs the scan partitions queued in the ledger.

``python main.py worker`` runs :func:`run_worker`. A worker holds no scan of its own. It
takes a partition from the queue - the ledger itself: the first queued partition of the
oldest running scan this host can run - reads that partition's scan, rebuilds the engine
from the recorded request - the same validation and credential resolution a scan started
from the console gets - claims the partition under a lease, runs it and commits it. When
nothing is left to run for a scan, it finalizes the scan unless someone else already is.

Every decision is the ledger's. Two workers can be handed the same partition; the claim
is a compare-and-set, so one runs it and the other finds it held or done. A partition of
a scan that finished or failed is dropped. A crash anywhere leaves a partition whose
lease runs out, or a scan with nothing left to run, and a worker's maintenance pass picks
up both. ``ack`` and ``reclaim`` belong to the :class:`PartitionQueue` seam and have
nothing to do on the ledger, where the commit is the acknowledgement.

What only concerns this worker never touches the scan: a scan it cannot rebuild - a
credential missing from this worker's vault - or a local scan planned on another host is
passed over, not failed.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from typing import Callable

from backend import partitioned_scan, schema_guard, store
from backend.work_queue import Delivery, PartitionQueue

logger = logging.getLogger(__name__)

# Outcomes that leave the partition queued, for another worker or a later pass.
_LEFT_PENDING = frozenset({"held", "elsewhere", "unbuildable"})


def default_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"


def handle_delivery(queue: PartitionQueue, delivery: Delivery, rebuild: Callable[[dict], object], *,
                    worker_id: str) -> str:
    """Run one delivered partition; returns what happened.

    ``written``, ``finished``, ``retry``, ``stopped`` and ``dropped`` are done with the
    delivery - ``retry`` only after the partition is queued again. ``held`` (a live worker
    holds it), ``elsewhere`` (a local scan of another host) and ``unbuildable`` (this
    worker cannot rebuild the scan) leave it queued, so another worker - or the console's
    own runner - can have it.
    """
    record = store.read_partitioned_scan(delivery.tenant_id, delivery.scan_id)
    if record is None or record["status"] in ("done", "failed") or not record["resumable"]:
        queue.ack(delivery)
        return "dropped"
    if not partitioned_scan.runs_here(record):
        return "elsewhere"
    try:
        config = rebuild(record)
    except Exception as exc:
        # This worker's problem - its vault, its configuration - and not the scan's.
        logger.warning("Scan %s cannot be rebuilt on this worker: %s", delivery.scan_id, type(exc).__name__)
        return "unbuildable"
    outcome = partitioned_scan.run_queued_partition(record, config, delivery.partition_id, worker_id=worker_id)
    if outcome in _LEFT_PENDING:
        return outcome
    if outcome == "retry":
        queue.publish(delivery.tenant_id, delivery.scan_id, [delivery.partition_id])
    queue.ack(delivery)
    if outcome in ("written", "finished"):
        settled = partitioned_scan.settle_if_finished(record, config)
        if settled:
            logger.info("Scan %s %s by worker %s", delivery.scan_id, settled, worker_id)
    return outcome


def _maintain(queue: PartitionQueue, rebuild: Callable[[dict], object], worker_id: str, lease: int) -> list[Delivery]:
    """Pick up what dead workers left; returns any deliveries the queue hands back.

    Partitions whose lease ran out go back in the ledger's queue - or fail, on their
    last attempt. Scans with nothing left to run are finalized or failed. The ledger
    queue hands nothing back: what a dead worker held is queued again by the first step.
    """
    store.requeue_expired_partitions(max_attempts=partitioned_scan.partition_max_attempts())
    for record in store.list_unfinished_partitioned_scans(resumable_only=True):
        if record["status"] != "running" or not partitioned_scan.runs_here(record):
            continue
        try:
            partitioned_scan.settle_if_finished(record, rebuild(record))
        except Exception as exc:
            logger.warning("Scan %s could not be settled: %s", record["scan_id"], type(exc).__name__)
    return queue.reclaim(worker_id, idle_seconds=lease)


# The process's one schema state (backend.schema_guard), under the name the worker used.
_SCHEMA_STATE = schema_guard.STATE


def _schema_is_newer() -> bool:
    """True while the database's schema revision is ahead of this build's (checked at most
    every DSPM_SCHEMA_CHECK_SECONDS). An unreachable database is not a mismatch: it is the
    queue's problem, handled in run_worker."""
    return schema_guard.stand_down("scan worker")


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

    Every third of a lease the worker first runs its maintenance pass. A queue or
    database that is briefly unavailable - SQLite busy behind a long finalize - is
    waited out rather than ending the process. ``stop_when_idle`` returns as soon as the
    queue has nothing to hand out - for tests and one-shot runs.
    """
    worker_id = worker_id or default_worker_id()
    stop = stop or threading.Event()
    lease = partitioned_scan.partition_lease_seconds()
    handled = 0
    last_maintenance = float("-inf")
    while not stop.is_set():
        # C0.4: a database upgraded under this worker is not written by it until the
        # matching release runs; the partitions wait in the ledger, leased by no one.
        if _schema_is_newer():
            stop.wait(max(idle_seconds, 5.0))
            continue
        try:
            deliveries: list[Delivery] = []
            if time.monotonic() - last_maintenance >= lease / 3:
                last_maintenance = time.monotonic()
                deliveries = _maintain(queue, rebuild, worker_id, lease)
            if not deliveries:
                delivery = queue.take(worker_id, block_seconds=block_seconds)
                deliveries = [delivery] if delivery is not None else []
        except Exception as exc:
            logger.warning("Work queue unavailable, waiting: %s", type(exc).__name__)
            stop.wait(idle_seconds)
            continue
        if not deliveries:
            if stop_when_idle:
                break
            stop.wait(idle_seconds)
            continue
        for delivery in deliveries:
            started = time.monotonic()
            try:
                outcome = handle_delivery(queue, delivery, rebuild, worker_id=worker_id)
            except Exception as exc:
                logger.warning(
                    "Partition %s of scan %s could not be handled: %s",
                    delivery.partition_id, delivery.scan_id, type(exc).__name__,
                )
                outcome = "unbuildable"
            handled += 1
            # The worker's log is where an operator sees what the workers are doing. A
            # partition another worker already holds or finished is the ledger queue's
            # ordinary race, and would drown the rest at INFO.
            logger.log(
                logging.DEBUG if outcome in ("held", "finished") else logging.INFO,
                "Partition %s of scan %s: %s in %.1f s",
                delivery.partition_id, delivery.scan_id, outcome, time.monotonic() - started,
            )
            # A partition another worker holds is an ordinary race: take the next one. A
            # scan this worker cannot run is not asked for again at once - a local scan
            # of another host for a lease, one it could not rebuild for a minute.
            if outcome == "elsewhere":
                queue.pass_over(delivery, seconds=lease)
            elif outcome == "unbuildable":
                queue.pass_over(delivery, seconds=min(lease, 60))
    return handled
