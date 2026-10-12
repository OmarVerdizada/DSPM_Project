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

import hashlib
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from collectors import acl_refresh, file_scanner
from collectors.file_scanner import is_hidden_path, is_skipped_scan_path
from discovery.incremental import folder_key
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


def _relative_depth(max_depth: int | None, deeper_by: int) -> int | None:
    """A depth limit measured from a folder ``deeper_by`` levels below the scan's root - or
    None, no limit, for a scan without one (W3.6)."""
    return None if max_depth is None else int(max_depth) - deeper_by


def _partition_config(config: ScanConfig, *, local_path: str, max_depth: int | None,
                      entry_names: tuple[str, ...] | None = None) -> ScanConfig:
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
        local_entry_names=entry_names,
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
    - the root's own loose files are a separate unit of just those entries, or they
      would be dropped - with the folders the whole walk skips, which it meets and counts
      as skipped (W3.6: named, so it does not meet - and count as not entered - the
      folders the other units walk).
    """
    if config.server:
        return None
    root = Path(config.local_path)
    if not root.is_dir() or (config.max_depth is not None and config.max_depth < 1):
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
    loose_files: list[str] = []
    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if not entry.is_dir():
                if entry.is_file():
                    loose_files.append(entry.name)
                continue
        except OSError:
            continue
        item = Path(entry.path)
        # A folder the whole walk skips is met by the root unit instead, which skips and
        # counts it as the whole walk does.
        if is_skipped_scan_path(item):
            loose_files.append(entry.name)
            continue
        if cache_dir is not None:
            try:
                if item.resolve() == cache_dir:
                    loose_files.append(entry.name)
                    continue
            except OSError:
                pass
        if is_hidden_path(item) and not (config.include_hidden or config.hidden_filter_enabled):
            loose_files.append(entry.name)
            continue
        subtrees.append(_partition_config(config, local_path=str(item),
                                          max_depth=_relative_depth(config.max_depth, 1)))

    if len(subtrees) < 2:
        return None  # not enough fan-out to be worth the process overhead
    # The scan's own limit: the entries it names are met at the depth the whole walk meets them.
    subtrees.append(_partition_config(config, local_path=str(root), max_depth=config.max_depth,
                                      entry_names=tuple(loose_files)))
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
    max_bytes: int | None = None,
    stop_check=None,
    emit=None,
    cursor: tuple = (),
) -> dict | None:
    """Cut a local scan into runs that together are exactly one walk, in its order (B2.2b, W3.1).

    A scan's file order is its walk's: each folder's entries in case-folded name order,
    descending into a subfolder the moment it is met. Every unit is a **run**: consecutive
    entries of one folder - files and whole subfolders alike - walked with the depth that
    folder has left. A folder whose walk fits the budgets stays inside its parent's run; a
    larger one is split into runs of its own entries, with a subfolder that is itself too
    large split in place (:class:`discovery.cutter.Cutter`).

    The budgets are ``max_files`` files - a zip's entries count when archives are inspected
    - and ``max_bytes`` of what the scan will read (``file_scanner.inspected_bytes``: a text
    file up to its cap, a document within its cap, nothing for other types). A unit holds at
    most both unless a single file alone is larger. There is no ceiling on the number of
    units and no budget doubling: the plan order is 64-bit (W3.1).

    Units are handed to ``emit(unit, cursor)`` as soon as each is final - while the walk
    runs - or collected and returned when ``emit`` is ``None``. ``cursor`` continues an
    interrupted plan after the last unit it emitted. Nothing a walk would observe is
    dropped: a folder holding no files is left out only if its walk would report nothing.

    Returns ``None`` when the target fits one unit - a folder within both budgets, a single
    file, a skipped root: the one case a scan may run whole (W3.1). Otherwise ``{"units",
    "files", "bytes", "emitted"}``. The bundled demo dataset is planned like any folder: a
    file named ``_manifest.json`` no longer sends a scan down the unbounded path (W3.1).
    """
    from collectors.scan_scope import rules_for
    from discovery.cutter import Cutter, Entry, entries_digest

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
    include_hidden_dirs = bool(config.include_hidden or config.hidden_filter_enabled)
    inspect_archives = bool(config.inspect_archives)
    read_content = bool(getattr(config, "read_content", True))
    allowed = set(file_scanner.normalize_extension_filter(config.allowed_extensions)) \
        if config.extension_filter_enabled and config.allowed_extensions else None
    scope = rules_for(getattr(config, "scope", None))

    def scope_path(resolved: Path) -> str:
        if scope.absolute:
            return scope.path_of(str(resolved))
        try:
            return scope.path_of(str(resolved.relative_to(root)))
        except ValueError:
            return scope.path_of(resolved.name)

    def is_excluded(resolved: Path) -> bool:
        return any(resolved == item or item in resolved.parents for item in excluded)

    acl_digests: dict[str, str] = {}

    def parent_acl(folder: Path) -> str:
        """The folder's ACL digest, as the walk reads it for E14 (W3.6): a file's inherited
        access follows it, so a unit's digest moves when it does."""
        key = str(folder)
        if key not in acl_digests:
            acl_digests.clear()  # one folder at a time: the walk is depth-first
            try:
                acl_digests[key] = acl_refresh.acl_digest(file_scanner.local_acl(folder))
            except Exception:  # noqa: BLE001 - unknown, so the unit is never skipped
                acl_digests[key] = ""
        return acl_digests[key]

    acl_reads = os.name == "nt" and os.getenv("DSPM_LOCAL_ACL", "1").strip() != "0"

    def file_digest(name: str, stat, acl: str) -> str:
        """What a listing shows of a file (W4.2): what a per-file reuse probe compares - size
        and modified time - and its attributes and its folder's ACL. Where ACLs are read and
        the folder's could not be, the file is unknown, and its unit is never skipped."""
        if acl_reads and not acl:
            return ""
        raw = json.dumps([name, int(stat.st_size), int(stat.st_mtime_ns),
                          int(getattr(stat, "st_file_attributes", 0) or 0), acl], separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

    def list_folder(folder: Path, depth: int):
        real_folder = folder.resolve()
        acl = parent_acl(folder)
        for item in sorted(folder.iterdir(), key=lambda entry: entry.name.casefold()):
            key = item.name.casefold()
            resolved_item = real_folder / item.name
            try:
                if item.is_symlink() or not resolved_item.is_relative_to(root):
                    continue
                is_dir = item.is_dir()
                is_file = item.is_file()
            except OSError:
                continue
            if is_dir:
                # A folder the walk meets and does not enter says nothing more of itself than
                # that it is there (W4.2).
                if _skipped(item) or (_hidden(item) and not include_hidden_dirs):
                    yield Entry(key, item.name, True, digest=_NOT_ENTERED), None  # the walk counts it as skipped
                    continue
                if config.max_depth is not None and depth + 1 > config.max_depth:
                    # Past the configured limit (W3.6): not listed; the walk meets it, does not
                    # enter it and counts it as not entered, so it stays in a run.
                    yield Entry(key, item.name, True, digest=_NOT_ENTERED), None
                    continue
                if is_excluded(resolved_item) or (scope.active and scope.folder_reason(scope_path(resolved_item))):
                    # Out of scope or the cache: not listed; the walk meets it, skips it and
                    # counts it, so it stays in a run and weighs nothing.
                    yield Entry(key, item.name, True, digest=_NOT_ENTERED), None
                    continue
                yield Entry(key, item.name, True), item
                continue
            if not is_file:
                continue
            extension = file_scanner.detect_extension(item)
            if scope.active and scope.file_name_reason(scope_path(resolved_item), extension):
                yield Entry(key, item.name, digest=_LEFT_OUT), None  # listed and left: no weight
                continue
            files = _archive_weight(item) if inspect_archives and extension == ".zip" else 1
            try:
                stat = item.stat()
                size, digest = stat.st_size, file_digest(key, stat, acl)
            except OSError:
                size, digest = 0, ""
            weight = file_scanner.inspected_bytes(extension, size, read_content=read_content,
                                                  inspect_archives=inspect_archives, allowed=allowed)
            yield Entry(key, item.name, False, files, weight, digest=digest), None

    def make_unit(folder: Path, depth: int, entries: list, _low: str, _high: str) -> dict:
        unit = {"kind": "run", "local_path": str(folder), "names": [entry.name for entry in entries],
                "max_depth": _relative_depth(config.max_depth, depth),
                # W4.6: what the unit reads, for the pre-flight's projection.
                "files": sum(int(entry.files or 0) for entry in entries)}
        digest = entries_digest(entries, json.dumps([folder_key(str(folder)), unit["max_depth"]]))
        if digest:
            # W4.2: what the unit would find, and the files a scan that skips it still saw - its
            # folder's files among its entries, and every folder it walks whole.
            unit["digest"] = digest
            unit["unit_key"] = unit_key(unit)
            unit["coverage"] = {
                "folder": folder_key(str(folder)),
                "files": [entry.key for entry in entries if not entry.is_dir],
                "folders": [key for entry in entries for key in entry.folders],
            }
        return unit

    units: list[dict] = []
    cutter = Cutter(
        files_budget=max(1, int(max_files)), bytes_budget=_bytes_budget(max_bytes),
        list_folder=list_folder, make_unit=make_unit,
        emit=emit if emit is not None else (lambda unit, _cursor: units.append(unit)),
        cursor=tuple(cursor or ()), stop_check=stop_check,
        name_folder=lambda handle: folder_key(str(handle)),
    )
    files, size, cut = cutter.run(root)
    if not cut:
        return None
    return {"units": units, "files": files, "bytes": size, "emitted": cutter.emitted}


# W4.2: the digests of a listed entry the walk does not read.
_NOT_ENTERED = "not-entered"
_LEFT_OUT = "left-out"


def unit_key(unit: dict) -> str:
    """A unit's identity in its scope's manifest (W4.2): its folder, its entries and its depth."""
    raw = json.dumps([folder_key(str(unit.get("local_path") or "")), [str(name).casefold() for name in
                      unit.get("names") or []], unit.get("max_depth")], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _files_budget(max_files) -> int:
    """A unit's files: as given, or the partition budget (``DSPM_PARTITION_MAX_FILES``)."""
    if max_files:
        return max(1, int(max_files))
    from backend.partitioned_scan import partition_max_files

    return partition_max_files()


def _bytes_budget(max_bytes) -> int:
    """A unit's reads: as given, or the partition budget (``DSPM_PARTITION_MAX_BYTES``) - for
    local units too (W3.1); they used to be bounded by files alone."""
    if max_bytes:
        return max(1, int(max_bytes))
    from backend.partitioned_scan import partition_max_bytes

    return partition_max_bytes()


def share_nesting(shares: list[str], folders: dict[str, dict[str, str]]) -> dict:
    """Which shares reach which, from each share's root folders (W3.1).

    A share ``B`` whose root holds a folder named like share ``X`` reaches ``X``:
    ``B:/X/P`` may be ``X:/P``, the same physical file, and the scan collapses the pair.
    ``children[B]`` are the shares ``B`` reaches; ``pairs[X]`` every ``(share, prefix)``
    where ``share:prefix + P`` is ``X:P`` - through a chain of nested shares too. An edge
    that would close a cycle (two shares each holding a folder named like the other) is not
    followed: that folder is walked with its own share, and a file reached both ways is
    reported twice - as two scans of one share each would.
    """
    by_key = {share.casefold(): share for share in shares}
    edges: dict[str, list[str]] = {
        broad: [by_key[key] for key in sorted(folders.get(broad) or {})
                if key in by_key and by_key[key] != broad]
        for broad in shares
    }
    children: dict[str, list[str]] = {share: [] for share in shares}
    state: dict[str, int] = {}
    for start in shares:
        if state.get(start):
            continue
        stack = [(start, iter(edges[start]))]
        state[start] = 1
        while stack:
            node, pending = stack[-1]
            narrow = next(pending, None)
            if narrow is None:
                state[node] = 2
                stack.pop()
                continue
            if state.get(narrow) == 1:
                continue  # closes a cycle: not followed
            children[node].append(narrow)
            if not state.get(narrow):
                state[narrow] = 1
                stack.append((narrow, iter(edges[narrow])))
    parents: dict[str, list[str]] = {share: [] for share in shares}
    for broad in shares:
        for narrow in children[broad]:
            parents[narrow].append(broad)
    pairs: dict[str, list[tuple[str, str]]] = {}

    def pairs_of(share: str) -> list[tuple[str, str]]:
        if share not in pairs:
            found: list[tuple[str, str]] = []
            for broad in parents[share]:
                name = (folders.get(broad) or {}).get(share.casefold(), share)
                found.append((broad, "/" + name))
                found.extend((outer, prefix + "/" + name) for outer, prefix in pairs_of(broad))
            pairs[share] = found
        return pairs[share]

    for share in shares:
        pairs_of(share)
    return {"children": children, "pairs": pairs}


def _covered_for(share: str, nesting: dict, folders: dict[str, dict[str, str]]) -> dict[str, list[str]]:
    """What a share's units leave to other units: each share it reaches, in itself and in
    every place it is reached through."""
    nested = ["/" + child.casefold() for child in nesting["children"][share]]
    if not nested:
        return {}
    covered: dict[str, set[str]] = {share.casefold(): set(nested)}
    for outer, prefix in nesting["pairs"][share]:
        covered.setdefault(outer.casefold(), set()).update(prefix.casefold() + path for path in nested)
    return {key: sorted(paths) for key, paths in covered.items()}


def plan_share_partitions(
    config: ScanConfig, *, stop_check=None, max_files: int | None = None, max_bytes: int | None = None,
    emit=None, cursor: dict | None = None,
) -> dict | None:
    """Cut an SMB scan into units that together are exactly one scan (B2.3, W1.2, W3.1).

    Each share is cut, with ``max_files`` and ``max_bytes``, into ranges of its folders
    (``SMBScanner.plan_share_ranges``), in the order the server lists the shares. Shares
    that overlap - one's root holds a folder named like the other - are not walked as one
    unit any more: a nested share's units also hold the same ranges where the broader
    shares reach it, and the broader shares' own units leave that folder out
    (:func:`share_nesting`), so the overlapping-share collapse still happens inside one
    unit and no unit holds more than its budget. A share that fits one unit is one unit.

    There is no ceiling on the number of units and no budget doubling (W3.1). Units go to
    ``emit(unit, cursor)`` as soon as each is final, or are collected and returned;
    ``cursor`` (``{"share": index, "path": [...]}``) continues an interrupted plan.

    Returns ``None`` only when the scan comes to one unit, which may run whole. Raises
    ``_SmbConnectionLost`` when the plan cannot be trusted - the server cannot be reached
    or a connection dropped while it was listed: planning is retried, and a scan larger
    than one unit never runs unpartitioned (W3.1).
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
        max_depth=config.max_depth,
        include_hidden=config.include_hidden,
        hidden_filter_enabled=config.hidden_filter_enabled,
        include_admin_shares=config.include_admin_shares,
        allowed_shares=config.smb_shares,
        require_encryption=config.smb_require_encryption,
        allowed_extensions=list(config.allowed_extensions or []),
        extension_filter_enabled=config.extension_filter_enabled,
        inspect_archives=config.inspect_archives,
        read_content=config.read_content,
        scope=getattr(config, "scope", None),
    ))
    layout = scanner.plan_share_layout(stop_check)
    shares, folders = layout["shares"], layout["folders"]
    if not shares:
        return None
    nesting = share_nesting(shares, folders)
    units: list[dict] = []
    emitted = {"count": 0}

    def sink_for(index: int):
        def sink(unit: dict, path: tuple) -> None:
            emitted["count"] += 1
            if emit is not None:
                emit(unit, {"share": index, "path": list(path)})
            else:
                units.append(unit)
        return sink

    start = int((cursor or {}).get("share") or 0)
    for index, share in enumerate(shares):
        if index < start:
            continue
        resumed = tuple((cursor or {}).get("path") or ()) if index == start else ()
        scanner.plan_share_ranges(
            share, max_files=_files_budget(max_files), max_bytes=_bytes_budget(max_bytes),
            stop_check=stop_check, emit=sink_for(index), cursor=resumed,
            pairs=nesting["pairs"][share], covered=_covered_for(share, nesting, folders), whole_unit=True,
        )
    if emitted["count"] < 2 and not cursor:
        return None
    return {"units": units, "files": 0, "bytes": 0, "emitted": emitted["count"]}


def _archive_weight(path: Path) -> int:
    """How many records a zip becomes when archives are inspected."""
    import zipfile

    from collectors.file_scanner import MAX_ARCHIVE_ENTRIES

    try:
        with zipfile.ZipFile(path) as archive:
            return 1 + min(len(archive.infolist()), MAX_ARCHIVE_ENTRIES)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return 1


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
    merged = {
        "partitioned": {
            "enabled": True,
            "partitions": partitions,
            "worker_processes": workers,
            "complete": complete,
        },
        "records": sum(int(d.get("records") or 0) for d in diags),
        "triage": triage,
    }
    # W3.6: what the partitions left out or did not enter, added up.
    scopes = [d.get("scope") for d in diags if isinstance(d.get("scope"), dict)]
    if scopes:
        from collectors.scan_scope import merge_diagnostics

        merged["scope"] = merge_diagnostics(scopes)
    return merged


def merge_reports(reports: list[dict], *, source: str, workers: int = 1, depth_limit=None) -> dict:
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
    if "scope" in diagnostics:
        # The scan's own depth limit, and the coverage the merged counts give (W3.6).
        from collectors import scan_scope

        scan_scope.settle(diagnostics, depth_limit=depth_limit)
        summary.update(scan_scope.summary_fields(diagnostics))
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
    return merge_reports(reports, source=source, workers=n, depth_limit=config.max_depth)
