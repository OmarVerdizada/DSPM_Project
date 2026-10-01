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
    via the merged report), and its own subtree + depth budget. ``walk_local_path``
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

    Returns ``None`` when the target is not a partitionable local directory. SMB
    scans are partitioned per group of shares by :func:`plan_share_partitions`
    (B2.3); endpoint per-host partitioning is not built.

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


def plan_bounded_partitions(
    config: ScanConfig,
    *,
    max_files: int,
    max_units: int | None = None,
    stop_check=None,
) -> dict | None:
    """Cut a local scan into runs that together are exactly one walk, in its order (B2.2b).

    A scan's file order is its walk's: each folder's entries in the order the folder
    lists them, descending into a subfolder the moment it is met. Several report
    sections keep the first 25 items or break ties by arrival, so a partitioned scan
    has to reproduce that order exactly.

    Every unit is a **run**: consecutive entries of one folder - files and whole
    subfolders alike - walked with the depth that folder has left. A folder whose walk
    holds at most ``max_files`` files stays inside its parent's run; a larger one is
    split into runs of its own entries, packed in order up to the budget, with any
    subfolder that is itself too large split in place. So a wide tree of small folders
    packs into few units and a deep one splits where it is heavy, and every unit holds
    at most ``max_files`` files - counting a zip's entries when archives are inspected -
    unless a single file alone is larger.

    Nothing a walk would observe is dropped: a folder that holds no files is left out
    only if its walk would report nothing either, so an unreadable or skipped folder
    always stays in some run and its scan still reports it (B2.2b review: dropping one
    let finalize prune what was under it). Containment is judged against the whole
    scan's root by each entry's real path, exactly as a walk judges it, so junctions
    need no special case.

    ``stop_check`` is called for every folder and, if it returns a reason, planning
    stops with that reason - the planning walk visits the whole estate.

    Returns ``None`` when the target should simply be scanned whole: a remote target,
    a single file, a folder that fits the budget, or one that cannot be read.
    Otherwise ``{"units", "files", "sample_paths"}``.
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
        plan = _plan_runs(config, root, excluded, budget, is_sample_data_path, stop_check)
        if plan is None or len(plan["units"]) <= limit:
            return plan
        # More units than one scan can order - reachable only at millions of files.
        budget *= 2


def plan_share_partitions(config: ScanConfig, *, stop_check=None) -> dict | None:
    """Cut an SMB scan into groups of shares that together are exactly one scan (B2.3).

    Each unit is a group of shares, walked in the order the server lists them; a group
    keeps together every pair of shares that can overlap, so the overlapping-share
    collapse happens inside one partition (see ``SMBScanner.plan_share_groups``). A
    share is never split: a partitioned SMB scan's memory follows its largest share,
    or group, and not yet its largest folder.

    Returns ``None`` when the scan should run whole: a local target, a server whose
    shares form a single group, or a plan that cannot be trusted. Otherwise
    ``{"units", "files", "sample_paths"}``, like :func:`plan_bounded_partitions`.
    """
    from collectors.smb_scanner import SMBConfig, SMBScanner

    if not config.server:
        return None
    scanner = SMBScanner(SMBConfig(
        server=config.server,
        tenant_id=config.tenant_id,
        username=config.username,
        password=config.password,
        domain=config.domain,
        include_admin_shares=config.include_admin_shares,
        allowed_shares=config.smb_shares,
        require_encryption=config.smb_require_encryption,
    ))
    groups = scanner.plan_share_groups(stop_check)
    if not groups or len(groups) < 2:
        return None
    return {"units": [{"kind": "shares", "shares": group} for group in groups], "files": 0, "sample_paths": []}


def _archive_weight(path: Path) -> int:
    """How many records a zip becomes when archives are inspected."""
    import zipfile

    from collectors.file_scanner import MAX_ARCHIVE_ENTRIES

    try:
        with zipfile.ZipFile(path) as archive:
            return 1 + min(len(archive.infolist()), MAX_ARCHIVE_ENTRIES)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return 1


def _plan_runs(config: ScanConfig, root: Path, excluded: list[Path], budget: int, is_sample, stop_check) -> dict | None:
    include_hidden_dirs = bool(config.include_hidden or config.hidden_filter_enabled)
    inspect_archives = bool(config.inspect_archives)
    sample = {"seen": False}

    def is_excluded(resolved: Path) -> bool:
        return any(resolved == item or item in resolved.parents for item in excluded)

    def visit(folder: Path, depth: int):
        """(files, units or None when the folder fits a run, whether its walk observes anything)."""
        if stop_check is not None:
            reason = stop_check()
            if reason:
                raise RuntimeError(reason)
        try:
            real_folder = folder.resolve()
            entries = list(folder.iterdir())
        except OSError:
            # Unreadable: its walk reports it, so it must be walked.
            return 0, None, True
        children: list[tuple[str, int, list | None]] = []
        weight = 0
        for item in entries:
            resolved_item = real_folder / item.name
            try:
                if item.is_symlink() or not resolved_item.is_relative_to(root):
                    continue
                is_dir = item.is_dir()
                is_file = item.is_file()
            except OSError:
                continue
            if is_dir:
                if _skipped(item) or (_hidden(item) and not include_hidden_dirs):
                    children.append((item.name, 0, None))  # the walk counts it as skipped
                    continue
                if depth + 1 > config.max_depth:
                    continue  # the walk returns at once and reports nothing
                if is_excluded(resolved_item):
                    children.append((item.name, 0, None))
                    continue
                child_weight, child_units, child_observed = visit(item, depth + 1)
                weight += child_weight
                if child_units is not None or child_observed:
                    children.append((item.name, child_weight, child_units))
                continue
            if not is_file:
                continue
            entry_weight = _archive_weight(item) if inspect_archives and item.suffix.lower() == ".zip" else 1
            weight += entry_weight
            if not sample["seen"] and is_sample({"path": str(resolved_item)}):
                sample["seen"] = True
            children.append((item.name, entry_weight, None))
        if weight <= budget:
            return weight, None, bool(children)
        units: list[dict] = []
        run: list[str] = []
        run_weight = 0

        def flush() -> None:
            nonlocal run, run_weight
            if run:
                units.append({
                    "kind": "run", "local_path": str(folder), "names": run,
                    "max_depth": int(config.max_depth) - depth,
                })
                run, run_weight = [], 0

        for name, entry_weight, child_units in children:
            if child_units is not None:
                flush()
                units.extend(child_units)
                continue
            if run and run_weight + entry_weight > budget:
                flush()
            run.append(name)
            run_weight += entry_weight
        flush()
        return weight, units, True

    total, units, _observed = visit(root, 0)
    if units is None:
        return None
    return {"units": units, "files": total, "sample_paths": sample["seen"]}


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
    # The throwaway file has to be the database this process uses. With DSPM_DB_URL
    # inherited, init_db() converged the SHARED PostgreSQL schema from every worker at
    # once, outside the migration lock - they deadlocked on its backfill (C0.5) - and
    # created tenants there. The backend is chosen per call, so this is enough.
    os.environ.pop("DSPM_DB_URL", None)
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
