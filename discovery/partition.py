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

from collectors import file_scanner
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


# The collector's own rules, looked up on its module at call time, so the planner
# can never disagree with a walk - including one whose rules a test has replaced.
def _skipped(path: Path) -> bool:
    return file_scanner.is_skipped_scan_path(path)


def _hidden(path: Path) -> bool:
    return file_scanner.is_hidden_path(path)


def plan_bounded_partitions(config: ScanConfig, *, max_files: int, max_units: int | None = None) -> dict | None:
    """Cut a local scan into units that together are exactly one walk, in its order (B2.2b).

    A scan's file order is its walk's: each folder's entries in the order the folder
    lists them, descending into a subfolder the moment it is met. Several report
    sections keep the first 25 items or break ties by arrival, so a partitioned scan
    has to reproduce that order exactly - which a unit per top-level folder, with the
    root's loose files last, does not.

    Units are contiguous runs of the walk:

    - ``subtree``: a folder whose files fit the budget, walked whole with the depth it
      has left;
    - ``files``: a run of at most ``max_files`` loose files of a folder too large to
      keep whole, read in that folder's own order.

    A folder is split into its runs and subfolders only when it holds more than
    ``max_files`` files, so memory follows the largest unit rather than the estate.
    A subfolder the walk would find nothing in is not a unit at all; one that cannot
    be read still is, so its scan reports it. A folder whose listed path is not its
    real path - a junction - is never the root of a unit, because a walk rooted there
    would report different paths.

    Returns ``None`` when the target should simply be scanned whole: a remote target,
    a single file, a folder that fits the budget, or one that cannot be read.
    Otherwise ``{"units", "files", "skipped_dirs", "sample_paths"}``: ``skipped_dirs``
    counts skipped folders directly inside split folders, which no unit walks and so
    no unit's scan reports; ``sample_paths`` says whether any file belongs to the
    bundled demo dataset.
    """
    from backend.store import MAX_SCAN_PARTITIONS, is_sample_data_path

    if config.server:
        return None
    try:
        root = Path(config.local_path).expanduser().resolve()
    except OSError:
        return None
    if not root.is_dir() or _skipped(root):
        return None
    excluded: list[Path] = []
    if config.persistent_cache_enabled and config.cache_dir:
        try:
            excluded.append(Path(config.cache_dir).expanduser().resolve())
        except OSError:
            pass
    limit = max_units or MAX_SCAN_PARTITIONS
    budget = max(1, int(max_files))
    while True:
        plan = _plan_folders(config, root, excluded, budget, is_sample_data_path)
        if plan is None or len(plan["units"]) <= limit:
            return plan
        # More units than one scan can order: the same cut, with larger units.
        budget *= 2


def _plan_folders(config: ScanConfig, root: Path, excluded: list[Path], budget: int, is_sample) -> dict | None:
    include_hidden_dirs = bool(config.include_hidden or config.hidden_filter_enabled)
    sample = {"seen": False}

    def is_excluded(resolved: Path) -> bool:
        return any(resolved == item or item in resolved.parents for item in excluded)

    def subtree(folder: Path, depth: int) -> dict:
        return {"kind": "subtree", "local_path": str(folder), "max_depth": int(config.max_depth) - depth}

    def visit(folder: Path, resolved_folder: Path, depth: int):
        """(readable, file count, units - or None to keep this folder whole, skipped folders in split parts)."""
        try:
            entries = list(folder.iterdir())
        except OSError:
            return False, 0, None, 0
        count = 0
        units: list[dict] = []
        pending: list[str] = []
        skipped_here = 0
        skipped_below = 0
        splittable = True

        def flush() -> None:
            if pending:
                units.append({"kind": "files", "local_path": str(folder), "names": list(pending)})
                pending.clear()

        for item in entries:
            resolved_item = resolved_folder / item.name
            try:
                if item.is_symlink() or not resolved_item.is_relative_to(root):
                    continue
                is_dir = item.is_dir()
                is_file = item.is_file()
            except OSError:
                continue
            if is_dir:
                if _skipped(item) or (_hidden(item) and not include_hidden_dirs):
                    skipped_here += 1
                    continue
                if depth + 1 > config.max_depth:
                    continue
                if is_excluded(resolved_item):
                    skipped_here += 1
                    continue
                flush()
                try:
                    real = item.resolve()
                except OSError:
                    real = None
                if real != resolved_item:
                    # A walk rooted at this folder would report different paths, so it
                    # cannot be a unit - and neither can anything that would split its
                    # parent around it.
                    splittable = False
                    count += budget + 1
                    units.append(subtree(item, depth + 1))
                    continue
                readable, child_count, child_units, child_skipped = visit(item, resolved_item, depth + 1)
                count += child_count
                if child_units is not None:
                    units.extend(child_units)
                    skipped_below += child_skipped
                elif child_count or not readable:
                    units.append(subtree(item, depth + 1))
                continue
            if not is_file:
                continue
            count += 1
            if not sample["seen"] and is_sample({"path": str(resolved_item)}):
                sample["seen"] = True
            pending.append(item.name)
            if len(pending) >= budget:
                flush()
        flush()
        if count <= budget or not splittable:
            return True, count, None, 0
        return True, count, units, skipped_here + skipped_below

    readable, total, units, skipped = visit(root, root, 0)
    if not readable or units is None:
        return None
    return {"units": units, "files": total, "skipped_dirs": skipped, "sample_paths": sample["seen"]}


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
