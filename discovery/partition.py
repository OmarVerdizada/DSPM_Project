"""Track P-E: namespace partitioning + a multi-process partition runner.

Split one scan target into INDEPENDENT units, run each in its own worker PROCESS
(true past-the-GIL parallelism plus concurrent collection I/O — the per-file
`Get-Acl` subprocess is the local bottleneck, so running partitions in parallel
processes attacks exactly that), and MERGE the partition reports into one report
that is *semantically identical* to a single-engine scan of the whole target.

This is the reusable core of P-E's "distributed collectors": today the executor is
a local ``ProcessPoolExecutor``; the Track O agent becomes a drop-in replacement
for that executor (same partition units, same merge) once it exists. Nothing here
is throwaway.

Why the merge can be exact
--------------------------
Persistence identities are pure hashes — ``asset_id = sha256(tenant, source, path)``
and ``finding_id = sha256(tenant, asset_id, rule, path)``, never sequential — so
disjoint partitions produce non-overlapping ids whose union equals the single scan.
The only things a single engine computes across its whole target are the summary
counts and (for SMB) the overlapping-share collapse; the merge recomputes those.
Local subtrees are disjoint, so there is nothing to collapse there.

Parity is enforced by ``tests/test_partition_parity.py``: a partitioned scan must
produce byte-identical findings/risk/permissions/preview to a single scan.
"""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from collectors.file_scanner import is_hidden_path, is_skipped_scan_path
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


def _partition_config(config: ScanConfig, *, local_path: str, max_depth: int) -> ScanConfig:
    """A partition's config: the SAME detection policy as the parent, but an
    isolated unit — no callbacks (it must pickle to a worker process), no
    incremental/cache state (a clean process boundary; the caller owns persistence
    via the merged report), and its own subtree + depth budget. ``use_sample_when_empty``
    is inherited unchanged: for a local scan it is the "scan the filesystem" flag,
    so a partition must keep it on to actually scan its subtree."""
    return replace(
        config,
        local_path=local_path,
        max_depth=max_depth,
        cancel_check=None,
        progress_callback=None,
        baseline_probe=None,
        incremental_enabled=False,
        incremental_scope="",
        persistent_cache_enabled=False,
    )


def plan_partitions(config: ScanConfig) -> list[ScanConfig] | None:
    """Split a LOCAL scan into per-top-level-subtree units + a root-files unit.

    Returns ``None`` when the target is not a partitionable local directory (SMB
    per-share and endpoint per-host partitioning reuse :func:`merge_reports` but
    need their own planners + an SMB ``allowed_shares`` knob — not built here).

    Parity rules, mirroring ``file_scanner.walk``:
    - a top-level subdir becomes a unit only if the single scan would descend into
      it (not a symlink, not ``is_skipped_scan_path``, not the cache dir, not a
      hidden dir when hidden is excluded);
    - ``max_depth`` is measured from each engine's own root, so a subtree gets the
      parent budget minus one (it starts one level deeper in the single scan);
    - the root's own loose files are a separate depth-0 (non-recursive) unit, or
      they would be dropped.
    """
    if config.server:
        return None
    root = Path(config.local_path)
    if not root.is_dir() or config.max_depth < 1:
        return None
    cache_dir = (
        Path(config.cache_dir).resolve()
        if config.persistent_cache_enabled and config.cache_dir
        else None
    )
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError:
        return None

    subtrees: list[ScanConfig] = []
    for entry in entries:
        try:
            if entry.is_symlink() or not entry.is_dir():
                continue
        except OSError:
            continue
        item = Path(entry.path)
        if is_skipped_scan_path(item):
            continue
        if cache_dir is not None:
            try:
                if item.resolve() == cache_dir:
                    continue
            except OSError:
                pass
        if is_hidden_path(item) and not (config.include_hidden or config.hidden_filter_enabled):
            continue
        subtrees.append(_partition_config(config, local_path=str(item), max_depth=config.max_depth - 1))

    if len(subtrees) < 2:
        return None  # not enough fan-out to be worth the process overhead
    subtrees.append(_partition_config(config, local_path=str(root), max_depth=0))
    return subtrees


def _merge_diagnostics(diags: list[dict], *, partitions: int, workers: int) -> dict:
    """Aggregate per-partition diagnostics: completeness is the AND (one failed
    partition must not look like a complete scan), record/triage counters sum."""
    incremental = [d.get("incremental") or {} for d in diags]
    complete = all(bool(inc.get("complete", True)) for inc in incremental) if incremental else True
    triage = {"records_full": 0, "records_skipped_non_text": 0, "records_sampled": 0}
    for d in diags:
        t = d.get("triage") or {}
        for key in triage:
            triage[key] += int(t.get(key) or 0)
    return {
        "partitioned": {
            "enabled": True,
            "partitions": partitions,
            "worker_processes": workers,
            "complete": complete,
        },
        "records": sum(int(d.get("records") or 0) for d in diags),
        "triage": triage,
    }


def merge_reports(reports: list[dict], *, source: str, workers: int = 1) -> dict:
    """Merge N partition reports into one semantically identical to a single scan:
    concatenate files, dedup by source-qualified identity, order deterministically,
    and recompute the summary. (SMB overlapping-share collapse would also re-run
    here; disjoint local subtrees have nothing to collapse.)"""
    files: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for report in reports:
        for record in report.get("files") or []:
            key = (
                str(record.get("source") or source),
                str(record.get("reuse_key") or record.get("path") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            files.append(record)
    files.sort(key=lambda r: (str(r.get("source") or ""), str(r.get("share") or ""), str(r.get("path") or "")))

    summary = DSPMDiscoveryEngine._build_summary(files).to_dict()
    diagnostics = _merge_diagnostics(
        [r.get("scan_diagnostics") or {} for r in reports],
        partitions=len(reports),
        workers=workers,
    )
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "mode": "full",
        "summary": summary,
        "files": files,
        "scan_diagnostics": diagnostics,
    }


def _partition_worker(config: ScanConfig) -> dict:
    """Run one partition to a report dict in an isolated worker process. Uses a
    throwaway per-process DB so the engine's ``store`` imports/access are
    self-contained; the engine itself neither reads nor writes scan results here
    (incremental + persistent cache are off), so nothing crosses process lines but
    the returned report."""
    import tempfile

    handle = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    handle.close()
    os.environ["DSPM_DB_PATH"] = handle.name
    from backend import store

    store.DB_PATH = Path(handle.name)
    store.init_db()
    try:
        store.create_tenant(config.tenant_id, config.tenant_id)
    except Exception:
        pass  # tenant may already exist on a reused interpreter; harmless
    try:
        return DSPMDiscoveryEngine(config).run().to_dict()
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass


def _resolve_workers(workers: int, partitions: int) -> int:
    if workers and workers > 0:
        chosen = workers
    else:
        env = os.getenv("DSPM_PARTITION_WORKERS", "").strip()
        if env.isdigit() and int(env) > 0:
            chosen = int(env)
        else:
            chosen = max(1, (os.cpu_count() or 1) - 1)
    return max(1, min(chosen, partitions, 32))


def run_partitioned(config: ScanConfig, *, workers: int = 0) -> dict:
    """Partition the target, scan the units (across worker processes when there is
    fan-out), and merge into one report. Falls back to a single in-process scan
    when the target is not partitionable. ``workers`` <= 0 auto-sizes to ~CPU-1,
    overridable via ``DSPM_PARTITION_WORKERS``."""
    partitions = plan_partitions(config)
    if not partitions:
        return DSPMDiscoveryEngine(config).run().to_dict()

    source = "smb" if config.server else "local"
    n = _resolve_workers(workers, len(partitions))
    if n <= 1:
        reports = [DSPMDiscoveryEngine(part).run().to_dict() for part in partitions]
    else:
        from concurrent.futures import ProcessPoolExecutor

        with ProcessPoolExecutor(max_workers=n) as executor:
            reports = list(executor.map(_partition_worker, partitions))
    return merge_reports(reports, source=source, workers=n)
