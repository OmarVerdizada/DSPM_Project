from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from collections import defaultdict, deque
import copy
from functools import lru_cache
import hashlib
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from classification.compliance import classify_gdpr_content, classify_nist_content, classify_pci_content
from classification.compliance.canonical_entities import apply_canonical_entity_registry
from classification.compliance.canonical_model import apply_canonical_finding_model
from classification.compliance.gdpr_classifier import GDPR_DETECTOR_VERSION, GDPR_RULE_CATALOG_VERSION
from classification.compliance.keyword_library import custom_keyword_groups_for_scan, keyword_catalog_status
from classification.compliance.nist_catalog import nist_catalog_status
from classification.compliance.nist_models import NIST_DETECTOR_VERSION, NIST_FRAMEWORK_ID
from classification.regex_classifier import RULES, classify_content
from collectors.file_scanner import normalize_records, scan_directory
from collectors.smb_scanner import SMBConfig, SMBScanner
from discovery import triage
from discovery.parallelism import ParallelismPlan, resolve_parallelism
from permissions.acl_analyzer import analyze_acl
from risk.risk_engine import RiskAssessment, calculate_risk
from scripts.logger import get_logger

logger = get_logger(__name__)
GENERIC_DETECTOR_VERSION = "generic-regex-ml-v1"
PCI_DETECTOR_VERSION = "pci-detector-v2"
# Bumped v2 -> v3 for SC-1: previews and the classification cache are now
# produced by the universal evidence sanitizer, so every pre-existing findings
# cache entry and preview sidecar must be regenerated rather than reused.
PARSER_VERSION = "content-parser-v3"


@dataclass(slots=True)
class ScanConfig:
    tenant_id: str = "default"
    server: str = ""
    username: str = ""
    password: str = ""
    domain: str = "WORKGROUP"
    local_path: str = "enterprise_test_data"
    max_depth: int = 4
    use_sample_when_empty: bool = True
    asset_overrides: list[dict] = field(default_factory=list)
    allowed_extensions: list[str] = field(default_factory=list)
    extension_filter_enabled: bool = False
    include_hidden: bool = False
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    include_admin_shares: bool = False
    inspect_archives: bool = False
    compliance_enabled: bool = False
    compliance_frameworks: list[str] = field(default_factory=list)
    cancel_check: Callable[[], bool] | None = None
    progress_callback: Callable[[str, int, int], None] | None = None
    # Zero means adaptive; a positive value remains an explicit operator/test cap.
    max_workers: int = 0
    io_workers: int = 0
    pipeline_buffer: int = 0
    pipeline_enabled: bool = True
    detector_timeout_seconds: float = 8.0
    persistent_cache_enabled: bool = True
    cache_dir: str = "data/scan_cache"
    incremental_enabled: bool = True
    incremental_scope: str = ""
    baseline_probe: Callable[[str, int, str, str], dict | None] | None = None


@dataclass(slots=True)
class ScanSummary:
    total_files: int
    critical: int
    high: int
    medium: int
    low: int
    sensitive_files: int
    hidden_files: int = 0
    protected_files: int = 0

    def to_dict(self) -> dict:
        return {
            "total_files": self.total_files,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "sensitive_files": self.sensitive_files,
            "hidden_files": self.hidden_files,
            "protected_files": self.protected_files,
        }


@dataclass(slots=True)
class ScanReport:
    timestamp: str
    source: str
    summary: ScanSummary
    files: list[dict] = field(default_factory=list)
    scan_diagnostics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = {
            "timestamp": self.timestamp,
            "source": self.source,
            "mode": str((self.scan_diagnostics.get("incremental") or {}).get("mode") or "full"),
            "summary": self.summary.to_dict(),
            "files": self.files,
        }
        if self.scan_diagnostics:
            data["scan_diagnostics"] = self.scan_diagnostics
        return data


# M14 (roadmap 1.2): a hard wall-clock budget for the whole scan (collection +
# analysis), shared with jobs.SCAN_MAX_SECONDS. When exceeded the engine stops,
# returns a partial/truncated report, and releases its worker slot instead of
# running (or hanging) unbounded. 0 disables it.
SCAN_MAX_SECONDS = int(os.getenv("DSPM_SCAN_MAX_SECONDS", "1800"))


class DSPMDiscoveryEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.last_scan_diagnostics: dict = {}
        self._custom_keywords_by_framework: dict[str, list[dict]] = {}
        self._keyword_catalog_version_cache: dict[tuple[str, ...], tuple[list[str], dict]] = {}
        self._finding_cache: dict[tuple, list[dict]] = {}
        self._cache_lock = threading.RLock()
        self._keyword_lock = threading.RLock()
        self._version_signature: tuple | None = None
        self._parallelism_plan: ParallelismPlan | None = None
        self._deadline: float | None = None
        self._incremental_lock = threading.Lock()
        self._meta_index_lock = threading.Lock()
        self._meta_index_cache: dict | None = None
        self._meta_pending: dict = {}
        self._finding_digests: set | None = None
        self._cache_root_path: Path | None = None
        self._incremental_counts = {
            "probes": 0,
            "unchanged": 0,
            "new": 0,
            "changed": 0,
            "errors": 0,
            "sidecar_hits": 0,
            "durable_hits": 0,
        }
        # P-C triage aggregate (analysis runs across worker threads, so guard it).
        self._triage_lock = threading.Lock()
        self._triage_counts = {"full": 0, "skipped_non_text": 0, "sampled": 0}

    def _cancelled(self) -> bool:
        """True if the caller cancelled (e.g. the job heartbeat set cancel) OR the
        engine's own wall-clock deadline has passed (M14). Polled in the collection
        and analysis loops so a hung/over-budget scan stops and frees its worker."""
        if self.config.cancel_check and self.config.cancel_check():
            return True
        return self._deadline is not None and time.monotonic() > self._deadline

    def _mark_truncated(self, analyzed_count: int, total: int) -> None:
        diagnostics = dict(self.last_scan_diagnostics or {})
        diagnostics["scan_truncated"] = True
        diagnostics["scan_truncated_analyzed"] = analyzed_count
        diagnostics["scan_truncated_total"] = total
        diagnostics["scan_truncated_reason"] = "scan exceeded the maximum time budget or was cancelled"
        self.last_scan_diagnostics = diagnostics

    def test_connection(self) -> dict:
        if not self.config.server:
            return {
                "connected": True,
                "server": "local-sample",
                "domain": self.config.domain,
                "shares": [],
                "message": "Using local sample data because no SMB server was provided",
            }

        scanner = SMBScanner(
            SMBConfig(
                server=self.config.server,
                username=self.config.username,
                password=self.config.password,
                domain=self.config.domain,
                max_depth=self.config.max_depth,
                allowed_extensions=self.config.allowed_extensions,
                extension_filter_enabled=self.config.extension_filter_enabled,
                include_hidden=self.config.include_hidden,
                include_system=self.config.include_system,
                hidden_filter_enabled=self.config.hidden_filter_enabled,
                system_filter_enabled=self.config.system_filter_enabled,
                include_admin_shares=self.config.include_admin_shares,
                inspect_archives=self.config.inspect_archives,
                cancel_check=self.config.cancel_check,
            )
        )
        return scanner.test_connection()

    def run(self) -> ScanReport:
        # M14: arm the wall-clock deadline for this scan (collection + analysis).
        self._deadline = (time.monotonic() + SCAN_MAX_SECONDS) if SCAN_MAX_SECONDS > 0 else None
        plan = self._parallelism()
        if plan.pipeline_enabled:
            records, analyzed_files = self._collect_and_analyze_pipelined(plan)
        else:
            records = self._collect_records()
            self._emit_progress("collected", len(records), len(records))
            analyzed_files = self._analyze_records(normalize_records(records))
        summary = self._build_summary(analyzed_files)
        self._finalize_incremental_diagnostics(analyzed_files)
        self.flush_meta_index()

        return ScanReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source="smb" if self.config.server else "local",
            summary=summary,
            files=analyzed_files,
            scan_diagnostics=self.last_scan_diagnostics,
        )

    def _parallelism(self) -> ParallelismPlan:
        if self._parallelism_plan is None:
            self._parallelism_plan = resolve_parallelism(
                analysis_workers=int(self.config.max_workers or 0),
                io_workers=int(self.config.io_workers or 0),
                pipeline_buffer=int(self.config.pipeline_buffer or 0),
                pipeline_enabled=bool(self.config.pipeline_enabled),
            )
        return self._parallelism_plan

    @staticmethod
    def _record_identity(record: dict) -> tuple[str, str, str]:
        return (
            str(record.get("source") or "unknown"),
            str(record.get("share") or ""),
            str(record.get("reuse_key") or record.get("path") or ""),
        )

    def _set_parallelism_diagnostics(
        self,
        plan: ParallelismPlan,
        *,
        records: int,
        workers: int,
        pipeline: dict | None = None,
    ) -> None:
        diagnostics = dict(self.last_scan_diagnostics or {})
        diagnostics["parallelism"] = {
            **plan.to_dict(),
            "analysis_workers_active": workers,
            # P-B.2: collectors now own independent, retry-safe per-share
            # connections, so parallel acquisition reflects whether the SMB
            # collector actually engaged its parallel path this scan.
            "io_parallel_enabled": bool(diagnostics.get("io_parallel_active", False)),
            "ocr_policy": "serialized_inference",
        }
        diagnostics["worker_pool"] = {
            "enabled": workers > 1,
            "max_workers": workers,
            "records": records,
            "adaptive": plan.analysis_source == "auto_cpu",
        }
        if pipeline is not None:
            diagnostics["pipeline"] = pipeline
        self.last_scan_diagnostics = diagnostics

    def _collect_and_analyze_pipelined(self, plan: ParallelismPlan) -> tuple[list[dict], list[dict]]:
        """Stream collector output into a bounded analysis pool.

        The collector owns the final record list, including SMB dedup and local
        cache exclusion. Results are joined by source-qualified identity, which
        preserves collector order even when workers finish out of order.
        """

        futures_by_identity: dict[tuple[str, str, str], deque] = defaultdict(deque)
        all_futures = []
        gate = threading.BoundedSemaphore(plan.pipeline_buffer)
        state_lock = threading.Lock()
        state = {
            "submitted": 0,
            "completed": 0,
            "in_flight": 0,
            "peak_in_flight": 0,
            "overlap_observed": False,
            "collection_finished": False,
        }

        with ThreadPoolExecutor(
            max_workers=plan.analysis_workers,
            thread_name_prefix="dspm-analysis",
        ) as executor:

            def submit(record: dict):
                if self._cancelled():
                    return None
                gate.acquire()
                if self._cancelled():
                    gate.release()
                    return None
                normalized = normalize_records([record])[0]
                future = executor.submit(self._analyze_record_safe, normalized)
                futures_by_identity[self._record_identity(normalized)].append(future)
                all_futures.append(future)
                with state_lock:
                    state["submitted"] += 1
                    state["in_flight"] += 1
                    state["peak_in_flight"] = max(state["peak_in_flight"], state["in_flight"])

                def completed(_future) -> None:
                    with state_lock:
                        state["completed"] += 1
                        state["in_flight"] = max(0, state["in_flight"] - 1)
                        if not state["collection_finished"]:
                            state["overlap_observed"] = True
                        completed_count = state["completed"]
                        submitted_count = state["submitted"]
                    gate.release()
                    self._emit_progress("pipelining", completed_count, submitted_count)

                future.add_done_callback(completed)
                return future

            records = self._collect_records(record_callback=submit)
            with state_lock:
                state["collection_finished"] = True
            self._emit_progress("collected", len(records), len(records))
            normalized_records = normalize_records(records)

            selected_futures = []
            for record in normalized_records:
                queue = futures_by_identity.get(self._record_identity(record))
                future = queue.popleft() if queue else None
                if future is None:
                    future = submit(record)
                if future is not None:
                    selected_futures.append(future)

            analyzed: list[dict] = []
            stopped = False
            for future in selected_futures:
                if self._cancelled() and not future.done():
                    stopped = True
                    break
                analyzed.append(future.result())
                self._emit_progress("analyzing", len(analyzed), len(selected_futures))
            if stopped:
                for future in all_futures:
                    future.cancel()
                self._mark_truncated(len(analyzed), len(normalized_records))

        with state_lock:
            pipeline_diagnostics = {
                "enabled": True,
                "buffer_limit": plan.pipeline_buffer,
                "records_submitted": state["submitted"],
                "records_selected": len(selected_futures),
                "peak_in_flight": state["peak_in_flight"],
                "collection_analysis_overlap": state["overlap_observed"],
                "output_order": "collector",
            }
        active_workers = max(1, min(plan.analysis_workers, len(selected_futures) or 1))
        self._set_parallelism_diagnostics(
            plan,
            records=len(normalized_records),
            workers=active_workers,
            pipeline=pipeline_diagnostics,
        )
        return records, analyzed

    def _analyze_records(self, records: list[dict]) -> list[dict]:
        plan = self._parallelism()
        worker_count = max(1, min(plan.analysis_workers, len(records) or 1))
        total_records = len(records)
        self._set_parallelism_diagnostics(
            plan,
            records=len(records),
            workers=worker_count,
            pipeline={"enabled": False},
        )
        # P-C: dispatch highest triage-score first so a deadline-truncated scan
        # keeps the likeliest-sensitive findings. Results are always stored by the
        # record's ORIGINAL index, so a fully-completed scan's output is identical
        # to collector order (parity) - only which records survive a truncation
        # differs (for the better).
        order = self._analysis_order(records)
        if worker_count <= 1 or len(records) <= 1:
            analyzed_by_index: list[dict | None] = [None] * len(records)
            done = 0
            for index in order:
                if self._cancelled():  # M14: stop and return what we have
                    self._mark_truncated(done, total_records)
                    break
                analyzed_by_index[index] = self._analyze_record_safe(records[index])
                done += 1
                self._emit_progress("analyzing", done, total_records)
            return [item for item in analyzed_by_index if item is not None]

        analyzed: list[dict | None] = [None] * len(records)
        completed = 0
        stopped = False
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="dspm-scan") as executor:
            futures = {executor.submit(self._analyze_record_safe, records[index]): index for index in order}
            for future in as_completed(futures):
                analyzed[futures[future]] = future.result()
                completed += 1
                self._emit_progress("analyzing", completed, total_records)
                if self._cancelled():  # M14: cancel pending work so the pool drains and the worker frees
                    stopped = True
                    for pending in futures:
                        pending.cancel()
                    break
        if stopped:
            self._mark_truncated(completed, total_records)
        return [item for item in analyzed if item is not None]

    def _analysis_order(self, records: list[dict]) -> list[int]:
        """Record indices ordered highest triage-score first (stable within a
        score). Natural order when ordering is disabled or there is nothing to
        reorder."""
        if not triage.order_enabled() or len(records) <= 1:
            return list(range(len(records)))
        scored = [
            (triage.priority_score(record, record.get("content", "") or ""), index)
            for index, record in enumerate(records)
        ]
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [index for _, index in scored]

    def _emit_progress(self, stage: str, completed: int, total: int) -> None:
        if not self.config.progress_callback:
            return
        try:
            self.config.progress_callback(stage, completed, total)
        except Exception:
            return

    def _collection_progress(self, visited: int, matched: int, reused: int) -> None:
        """Bridge the collector's (visited, matched, reused) counters to the job
        progress callback as a real ``collecting`` stage: ``completed`` is the
        number of files discovered, ``total`` is the number reused from cache."""
        self._emit_progress("collecting", matched, reused)

    def _version_sig(self) -> tuple:
        """Version signature of everything that can change a file's findings.

        Metadata-first reuse is only valid when this signature is unchanged, so a
        detector/parser/rule/framework upgrade forces a full re-read + re-classify.
        Mirrors the version components of :func:`_record_cache_key`.
        """
        if self._version_signature is not None:
            return self._version_signature
        framework_ids = {str(item).lower() for item in self.config.compliance_frameworks} if self.config.compliance_enabled else set()
        detector_version = _detector_version(framework_ids)
        catalog_versions, _ = self._keyword_catalog_versions(framework_ids)
        rule_catalog_version = "|".join(catalog_versions) if catalog_versions else GDPR_RULE_CATALOG_VERSION
        self._version_signature = (
            str(self.config.tenant_id),
            PARSER_VERSION,
            detector_version,
            rule_catalog_version,
            tuple(sorted(framework_ids)),
            (
                os.getenv("DSPM_OCR_ENABLED", "0"),
                os.getenv("DSPM_OCR_MAX_FILE_BYTES", ""),
                os.getenv("DSPM_OCR_MAX_PIXELS", ""),
                os.getenv("DSPM_OCR_MAX_DIMENSION", ""),
                os.getenv("DSPM_OCR_MIN_CONFIDENCE", ""),
            ),
            _cache_key_digest(
                (
                    json.dumps(self.config.asset_overrides, sort_keys=True, ensure_ascii=False, default=str),
                    float(self.config.detector_timeout_seconds or 0),
                )
            ),
        )
        return self._version_signature

    def version_signature(self) -> str:
        """Opaque durable-baseline invalidation token for the active policy."""

        return _cache_key_digest(self._version_sig())

    def _meta_digest(self, path: str, size: int, mtime: str) -> str:
        raw = json.dumps(
            [list(self._version_sig()), str(path), int(size), str(mtime)],
            sort_keys=True, default=str, ensure_ascii=False,
        )
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()

    def _cache_root(self) -> Path | None:
        """Resolved cache directory, resolved once (it was re-resolving per file)."""
        if self._cache_root_path is None:
            if not self.config.cache_dir:
                return None
            try:
                self._cache_root_path = Path(self.config.cache_dir).expanduser().resolve()
            except OSError:
                return None
        return self._cache_root_path

    def _meta_path(self, digest: str) -> Path:
        root = self._cache_root()
        return (root or Path(self.config.cache_dir)) / f"{digest}.meta.json"

    def _meta_index(self) -> dict:
        """Reuse metadata for the whole cache, loaded once into RAM.

        This used to be one small file open per scanned file inside the probe -
        ~33 ms each under real-time AV, 11.9 s of a 14 s scan. One consolidated
        manifest read replaces all of them. Per-file sidecars are still read as
        a fallback so caches written by older builds keep working.
        """
        if self._meta_index_cache is not None:
            return self._meta_index_cache
        with self._meta_index_lock:
            if self._meta_index_cache is not None:
                return self._meta_index_cache
            index: dict = {}
            root = self._cache_root()
            if root is not None:
                try:
                    raw = json.loads((root / "index.json").read_text(encoding="utf-8"))
                    entries = raw.get("entries") if isinstance(raw, dict) else None
                    if isinstance(entries, dict):
                        index = entries
                except (OSError, json.JSONDecodeError, ValueError):
                    index = {}
            self._meta_index_cache = index
            return index

    def _finding_digest_exists(self, digest: str) -> bool:
        """Fail-closed pairing check against a directory listing taken once,
        instead of a stat() per probed file."""
        if not digest:
            return True
        if self._finding_digests is None:
            with self._meta_index_lock:
                if self._finding_digests is None:
                    names: set[str] = set()
                    root = self._cache_root()
                    if root is not None:
                        try:
                            names = {
                                entry.name[:-5]
                                for entry in os.scandir(root)
                                if entry.name.endswith(".json") and not entry.name.endswith(".meta.json")
                            }
                        except OSError:
                            names = set()
                    self._finding_digests = names
        return digest in (self._finding_digests or set())

    def flush_meta_index(self) -> None:
        """Write the accumulated reuse metadata as one manifest.

        Replaces one sidecar write per file (724 writes, 2.7 s) with a single
        atomic file.
        """
        with self._meta_index_lock:
            pending = dict(self._meta_pending)
            self._meta_pending.clear()
        if not pending:
            return
        root = self._cache_root()
        if root is None:
            return
        merged = dict(self._meta_index())
        merged.update(pending)
        self._meta_index_cache = merged
        try:
            root.mkdir(parents=True, exist_ok=True)
            index_path = root / "index.json"
            tmp = index_path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps({"index_version": 1, "entries": merged}, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(tmp, index_path)
        except OSError:
            return

    def _reuse_probe(self, path: str, size: int, mtime: str) -> dict | None:
        """Cheap metadata lookup used during collection.

        Returns a stored snapshot when a prior scan cached this exact
        path+size+mtime under the current version signature, so the collector can
        skip the per-file owner lookup, content read, and full-file hash.

        Fail-closed: when the sidecar records which findings-cache entry it pairs
        with and that entry is gone, the probe misses so the file is fully
        re-read while the collector (and any remote connection) is still active.
        Remote sources have no post-collection re-read fallback, so this check is
        what keeps SMB reuse safe.
        """
        if not self.config.incremental_enabled:
            return None
        with self._incremental_lock:
            self._incremental_counts["probes"] += 1

        # The filesystem sidecar is a fast L1. The normalized asset + durable
        # database baseline below remains authoritative when this local cache is
        # absent (new worker, cache eviction, failover).
        archive_bundle_required = self.config.inspect_archives and str(path).lower().split("::", 1)[0].endswith(".zip")
        if self.config.persistent_cache_enabled and self.config.cache_dir and not archive_bundle_required:
            try:
                digest = self._meta_digest(path, size, mtime)
                data = self._meta_index().get(digest)
                if data is None:
                    # Legacy per-file sidecar (cache written by an older build).
                    data = json.loads(self._meta_path(digest).read_text(encoding="utf-8"))
                finding_digest = str(data.get("finding_cache_digest") or "")
                if finding_digest and not self._finding_digest_exists(finding_digest):
                    data = {}
                snapshot = data.get("snapshot")
                if isinstance(snapshot, dict):
                    with self._incremental_lock:
                        self._incremental_counts["unchanged"] += 1
                        self._incremental_counts["sidecar_hits"] += 1
                    return snapshot
            except (OSError, json.JSONDecodeError, ValueError):
                pass

        if self.config.baseline_probe is None or not self.config.incremental_scope:
            with self._incremental_lock:
                self._incremental_counts["new"] += 1
            return None
        try:
            result = self.config.baseline_probe(path, int(size), str(mtime), self.version_signature()) or {}
        except Exception:
            with self._incremental_lock:
                self._incremental_counts["errors"] += 1
            return None
        state = str(result.get("state") or "new").lower()
        snapshot = result.get("snapshot")
        with self._incremental_lock:
            if state in {"new", "changed"}:
                self._incremental_counts[state] += 1
            if state == "unchanged" and isinstance(snapshot, dict):
                self._incremental_counts["unchanged"] += 1
                self._incremental_counts["durable_hits"] += 1
        return snapshot if state == "unchanged" and isinstance(snapshot, dict) else None

    def _finalize_incremental_diagnostics(self, analyzed_files: list[dict]) -> None:
        diagnostics = dict(self.last_scan_diagnostics or {})
        counts = dict(self._incremental_counts)
        total = len(analyzed_files)
        reused = sum(1 for item in analyzed_files if item.get("cache_reused") or item.get("incremental_reused"))
        content_reads = max(0, total - reused)
        incomplete_markers = (
            diagnostics.get("scan_truncated"),
            diagnostics.get("list_errors"),
            diagnostics.get("unreadable_dirs"),
            diagnostics.get("scan_errors"),
            diagnostics.get("missing_roots"),
            diagnostics.get("missing_paths"),
            diagnostics.get("incremental_fetch_errors"),
            diagnostics.get("archive_errors"),
            diagnostics.get("archive_timed_out"),
        )
        complete = not any(incomplete_markers)
        diagnostics["incremental"] = {
            "enabled": bool(self.config.incremental_enabled),
            "baseline_update": bool(self.config.incremental_scope),
            "mode": "incremental" if self.config.incremental_enabled else "full",
            "scope_key": self.config.incremental_scope,
            "version_signature": self.version_signature(),
            "complete": complete,
            "total_objects": total,
            "unchanged_objects": reused,
            "new_objects": int(counts.get("new") or 0),
            "changed_objects": int(counts.get("changed") or 0),
            "unclassified_fresh_objects": max(
                0,
                content_reads - int(counts.get("new") or 0) - int(counts.get("changed") or 0),
            ),
            "content_reads": content_reads,
            "delta_ratio": round(content_reads / total, 6) if total else 0.0,
            "sidecar_hits": int(counts.get("sidecar_hits") or 0),
            "durable_baseline_hits": int(counts.get("durable_hits") or 0),
            "probe_errors": int(counts.get("errors") or 0),
            "baseline_committed": False,
            "deleted_objects": 0,
        }
        diagnostics["cache_reused_files"] = reused
        diagnostics["files_discovered"] = total
        diagnostics["triage"] = self._triage_diagnostics()
        self.last_scan_diagnostics = diagnostics

    def _write_meta_sidecar(self, record: dict, cache_key: tuple | None = None) -> None:
        """Persist the cheap-to-restore snapshot so an unchanged file can be
        reused (metadata-first) on the next scan without any file I/O.

        Local records are keyed by their filesystem path. SMB and endpoint
        records carry source-qualified ``reuse_key`` values so remote identities
        can never collide with local ones or across hosts."""
        if not self.config.persistent_cache_enabled or not self.config.cache_dir:
            return
        if str(record.get("source")) not in {"local", "smb", "endpoint-local", "endpoint-winrm"}:
            return
        path = str(record.get("path") or "")
        if not path or "::" in path or record.get("protected"):
            return
        identity = str(record.get("reuse_key") or "") or path
        if str(record.get("source")) == "smb" and not record.get("reuse_key"):
            # An SMB record without its qualified reuse key cannot be safely
            # re-identified on the next scan; skip rather than guess.
            return
        size = int(record.get("size") or record.get("total_bytes") or 0)
        mtime = str(record.get("modified_at") or record.get("mtime") or "")
        if not mtime:
            return
        content = record.get("content", "") or ""
        snapshot = {
            "owner": record.get("owner", ""),
            "acl": record.get("acl") or {},
            "content_status": record.get("content_status") or "",
            "content_scannable": bool(record.get("content_scannable", False)),
            "scan_error": record.get("scan_error", ""),
            "protected": bool(record.get("protected", False)),
            "protection_type": record.get("protection_type", ""),
            "sha256": record.get("sha256") or record.get("file_hash") or "",
            "content_hash": record.get("content_hash") or "",
            "scan_completeness": record.get("scan_completeness") or "UNKNOWN",
            "bytes_scanned": int(record.get("bytes_scanned") or 0),
            "total_bytes": int(record.get("total_bytes") or record.get("size") or 0),
            "truncated": bool(record.get("truncated", False)),
            "preview": (
                record.get("reused_preview")
                if isinstance(record.get("reused_preview"), dict)
                else record.get("preview")
                if isinstance(record.get("preview"), dict)
                else _safe_preview(content)
            ),
        }
        if isinstance(record.get("findings"), list) and isinstance(record.get("risk"), dict):
            # A shallow copy minus the heavy keys is enough: the snapshot is
            # serialized to JSON immediately and never mutated afterwards, so
            # the deep copy (2.5 s per scan) bought nothing.
            baseline_result = {
                key: value for key, value in record.items()
                if key not in ("content", "baseline_result", "asset_overrides")
            }
            snapshot["baseline_result"] = baseline_result
        payload = {
            "meta_version": 2,
            "path": path,
            "identity": identity,
            "source": str(record.get("source") or ""),
            "size": size,
            "modified_time": mtime,
            "version_signature": _cache_key_digest(self._version_sig()),
            "finding_cache_digest": _cache_key_digest(cache_key) if cache_key else "",
            "snapshot": snapshot,
        }
        with self._meta_index_lock:
            self._meta_pending[self._meta_digest(identity, size, mtime)] = payload

    def _read_full_content(self, record: dict) -> str:
        """Safety fallback: read a reused file's content when its findings cache
        entry is missing, so a metadata reuse can never produce empty findings."""
        from collectors.file_scanner import read_text_preview_and_sha256

        try:
            content, sha = read_text_preview_and_sha256(Path(str(record.get("path") or "")))
        except Exception:
            return ""
        if sha:
            record["sha256"] = sha
            record["file_hash"] = sha
        return content or ""

    def _analyze_record_safe(self, record: dict) -> dict:
        try:
            return self._analyze_record(record)
        except Exception as exc:
            public_record = dict(record)
            content = public_record.pop("content", "") or ""
            public_record.pop("asset_overrides", None)
            public_record["preview"] = _safe_preview(content)
            public_record["findings"] = []
            public_record["canonical_entities"] = []
            public_record["scan_error"] = _safe_scan_error(exc)
            public_record["detector_metrics"] = {
                "cache_hit": False,
                "elapsed_ms": 0,
                "slow_detector_degraded_mode": True,
                "record_failed": True,
                "error_code": "record_analysis_failed",
            }
            acl_assessment = analyze_acl(record.get("acl") or {}, record)
            public_record["permissions"] = acl_assessment
            public_record["risk"] = calculate_risk(record, [], acl_assessment).to_dict()
            return public_record

    def _collect_records(self, record_callback: Callable[[dict], None] | None = None) -> list[dict]:
        if self.config.server:
            scanner = SMBScanner(
                SMBConfig(
                    server=self.config.server,
                    username=self.config.username,
                    password=self.config.password,
                    domain=self.config.domain,
                    max_depth=self.config.max_depth,
                    allowed_extensions=self.config.allowed_extensions,
                    extension_filter_enabled=self.config.extension_filter_enabled,
                    include_hidden=self.config.include_hidden,
                    include_system=self.config.include_system,
                    hidden_filter_enabled=self.config.hidden_filter_enabled,
                    system_filter_enabled=self.config.system_filter_enabled,
                    include_admin_shares=self.config.include_admin_shares,
                    inspect_archives=self.config.inspect_archives,
                    cancel_check=self._cancelled,  # M14: job-cancel OR engine deadline stops a hung collection
                    reuse_probe=self._reuse_probe,
                    progress_callback=self._collection_progress,
                    record_callback=record_callback,
                    # P-B.2: bound parallel per-share acquisition to the same
                    # resolved I/O worker budget the pipeline uses.
                    io_workers=self._parallelism().io_workers,
                )
            )
            records = scanner.scan()
            self.last_scan_diagnostics = scanner.last_scan_diagnostics
            return records

        if self.config.use_sample_when_empty:
            walk_diagnostics: dict = {}
            records = scan_directory(
                self.config.local_path,
                allowed_extensions=self.config.allowed_extensions,
                extension_filter_enabled=self.config.extension_filter_enabled,
                include_hidden=self.config.include_hidden,
                include_system=self.config.include_system,
                hidden_filter_enabled=self.config.hidden_filter_enabled,
                system_filter_enabled=self.config.system_filter_enabled,
                max_depth=self.config.max_depth,
                inspect_archives=self.config.inspect_archives,
                diagnostics=walk_diagnostics,
                reuse_probe=self._reuse_probe,
                progress_callback=self._collection_progress,
                record_callback=record_callback,
                excluded_paths=[self.config.cache_dir] if self.config.persistent_cache_enabled and self.config.cache_dir else [],
            )
            diagnostics = {
                "mode": "local",
                "local_path": self.config.local_path,
                "records": len(records),
                "allowed_extensions": self.config.allowed_extensions,
                "extension_filter_enabled": self.config.extension_filter_enabled,
                "max_depth": self.config.max_depth,
                "inspect_archives": self.config.inspect_archives,
                "cache_reused_files": int(walk_diagnostics.get("reused_files") or 0),
                "files_discovered": int(walk_diagnostics.get("matched_files") or 0),
                "skipped_dirs": int(walk_diagnostics.get("skipped_dirs") or 0),
                "unreadable_dirs": list(walk_diagnostics.get("unreadable_dirs") or [])[:20],
                "archive_errors": list(walk_diagnostics.get("archive_errors") or [])[:20],
                "archive_timed_out": bool(walk_diagnostics.get("archive_timed_out", False)),
            }
            self.last_scan_diagnostics = diagnostics
            records = self._exclude_cache_records(records)
            self.last_scan_diagnostics["records"] = len(records)
            return records

        self.last_scan_diagnostics = {"mode": "disabled", "records": 0}
        return []

    def _exclude_cache_records(self, records: list[dict]) -> list[dict]:
        if not self.config.persistent_cache_enabled or not self.config.cache_dir:
            return records
        try:
            cache_root = Path(self.config.cache_dir).expanduser().resolve()
        except OSError:
            return records
        filtered = []
        skipped = 0
        for record in records:
            try:
                path = Path(str(record.get("path") or "")).expanduser().resolve()
            except OSError:
                filtered.append(record)
                continue
            if path == cache_root or cache_root in path.parents:
                skipped += 1
                continue
            filtered.append(record)
        if skipped:
            diagnostics = dict(self.last_scan_diagnostics or {})
            diagnostics["scan_cache_files_skipped"] = skipped
            self.last_scan_diagnostics = diagnostics
        return filtered

    def _analyze_record(self, record: dict) -> dict:
        baseline_result = record.get("baseline_result")
        if record.get("incremental_reused") and isinstance(baseline_result, dict):
            return self._reuse_analyzed_record(record, baseline_result)
        record["asset_overrides"] = self.config.asset_overrides
        framework_ids = {str(item).lower() for item in self.config.compliance_frameworks} if self.config.compliance_enabled else set()
        content = record.get("content", "") or ""
        content_hash = str(record.get("content_hash") or (hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest() if content else ""))
        file_hash = str(record.get("sha256") or record.get("file_hash") or content_hash or "")
        record["content_hash"] = content_hash
        record["detector_version"] = _detector_version(framework_ids)
        catalog_versions, keyword_catalog_statuses = self._keyword_catalog_versions(framework_ids)
        record["rule_catalog_version"] = "|".join(catalog_versions) if catalog_versions else GDPR_RULE_CATALOG_VERSION
        cache_key = _record_cache_key(
            tenant_id=self.config.tenant_id,
            record=record,
            file_hash=file_hash,
            content_hash=content_hash,
            parser_version=PARSER_VERSION,
            detector_version=record["detector_version"],
            rule_catalog_version=record["rule_catalog_version"],
            framework_ids=framework_ids,
        )
        cached = self._load_cached_findings(cache_key)
        if cached is None and record.get("cache_reused"):
            # Metadata said this file is unchanged, but its findings cache entry
            # is missing (evicted/corrupted). Re-read the real content now so a
            # reuse can never silently drop findings, then retry the cache with
            # the true hashes.
            if str(record.get("source")) != "local":
                # Remote sources cannot be re-read here (the scan connection is
                # gone). The reuse probe is fail-closed against exactly this, so
                # this is a rare eviction race — fail the record honestly instead
                # of classifying empty content as "no findings".
                raise RuntimeError("reuse cache entry missing for remote record; rescan required")
            content = self._read_full_content(record)
            content_hash = str(hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest() if content else "")
            file_hash = str(record.get("sha256") or record.get("file_hash") or content_hash or "")
            record["content"] = content
            record["content_hash"] = content_hash
            record["cache_reused"] = False
            cache_key = _record_cache_key(
                tenant_id=self.config.tenant_id,
                record=record,
                file_hash=file_hash,
                content_hash=content_hash,
                parser_version=PARSER_VERSION,
                detector_version=record["detector_version"],
                rule_catalog_version=record["rule_catalog_version"],
                framework_ids=framework_ids,
            )
            cached = self._load_cached_findings(cache_key)
        if cached is not None:
            findings = copy.deepcopy(cached)
            record["incremental_scan_reason"] = "cache_hit_unchanged_file"
            record["last_scanned_at"] = datetime.now(timezone.utc).isoformat()
            record["detector_elapsed_ms"] = 0
            record["detector_metrics"] = {
                "cache_hit": True,
                "cache_scope": "persistent_or_memory",
                "detector_timeout_seconds": float(self.config.detector_timeout_seconds or 0),
                "slow_detector_degraded_mode": False,
                "detectors": [],
            }
        else:
            findings, detector_metrics = self._run_detectors(content, record, framework_ids)
            record["incremental_scan_reason"] = "cache_miss_new_or_changed_file"
            record["last_scanned_at"] = datetime.now(timezone.utc).isoformat()
            record["detector_elapsed_ms"] = detector_metrics["elapsed_ms"]
            record["detector_metrics"] = detector_metrics
        if cached is None:
            self._store_cached_findings(cache_key, findings, record)
        scan_meta = {
            "scan_completeness": record.get("scan_completeness") or "UNKNOWN",
            "bytes_scanned": int(record.get("bytes_scanned") or 0),
            "total_bytes": int(record.get("total_bytes") or record.get("size") or 0),
            "truncated": bool(record.get("truncated")),
        }
        acl_assessment = analyze_acl(record.get("acl") or {}, record)
        canonical_record = {**record, "permissions": acl_assessment}
        seen_at = record.get("last_scanned_at") or datetime.now(timezone.utc).isoformat()
        for finding in findings:
            _decorate_finding_taxonomy(finding)
            apply_canonical_finding_model(finding, canonical_record, seen_at=seen_at)
            finding.setdefault("scan_completeness", scan_meta["scan_completeness"])
            finding.setdefault("bytes_scanned", scan_meta["bytes_scanned"])
            finding.setdefault("total_bytes", scan_meta["total_bytes"])
            finding.setdefault("truncated", scan_meta["truncated"])
        canonical_entities = apply_canonical_entity_registry(findings, canonical_record)
        record["finding_signals"] = [
            f"{finding.get('type', '')} {finding.get('description', '')}".strip()
            for finding in findings
        ]
        risk: RiskAssessment = calculate_risk(record, findings, acl_assessment)

        public_record = dict(record)
        content = public_record.pop("content", "")
        public_record.pop("asset_overrides", None)
        public_record.pop("finding_signals", None)
        reused_preview = public_record.pop("reused_preview", None)
        if record.get("cache_reused") and isinstance(reused_preview, dict):
            public_record["preview"] = reused_preview
        else:
            public_record["preview"] = _safe_preview(content)
        public_record["findings"] = findings
        public_record["canonical_entities"] = canonical_entities
        if keyword_catalog_statuses:
            public_record["keyword_catalog_status"] = keyword_catalog_statuses
            public_record["compliance_degraded_mode"] = any(status.get("degraded_mode") for status in keyword_catalog_statuses.values())
        if record.get("detector_metrics"):
            public_record["detector_metrics"] = record["detector_metrics"]
        public_record["permissions"] = acl_assessment
        public_record["risk"] = risk.to_dict()
        # Replace the collection-time low-level sidecar with the complete,
        # sanitized analyzed result. Both L1 and durable reuse now preserve the
        # exact same findings/risk/workflow snapshot (including stable SLA due
        # dates) instead of reconstructing one tier differently.
        self._write_meta_sidecar(public_record, cache_key)
        return public_record

    def _reuse_analyzed_record(self, record: dict, baseline_result: dict) -> dict:
        """Reuse prior findings/risk while refreshing current enumeration metadata."""

        public_record = copy.deepcopy(baseline_result)
        for key in (
            "source", "share", "path", "name", "size", "extension", "is_dir",
            "is_hidden", "is_system", "acl", "owner", "created_at", "modified_at",
            "accessed_at", "attributes", "sha256", "file_hash", "content_hash",
            "content_status", "content_scannable", "scan_error", "protected",
            "protection_type", "scan_completeness", "bytes_scanned", "total_bytes",
            "truncated", "reuse_key",
        ):
            if key in record:
                public_record[key] = copy.deepcopy(record[key])
        public_record.pop("content", None)
        public_record.pop("baseline_result", None)
        public_record.pop("asset_overrides", None)
        public_record["cache_reused"] = True
        public_record["incremental_reused"] = True
        public_record["incremental_scan_reason"] = "durable_baseline_unchanged_file"
        public_record["last_scanned_at"] = datetime.now(timezone.utc).isoformat()
        public_record["detector_elapsed_ms"] = 0
        public_record["detector_metrics"] = {
            "cache_hit": True,
            "cache_scope": "durable_baseline",
            "detector_timeout_seconds": float(self.config.detector_timeout_seconds or 0),
            "slow_detector_degraded_mode": False,
            "detectors": [],
        }

        # Rehydrate the L1 cache after a failover/cache eviction, so subsequent
        # unchanged scans avoid even the database lookup.
        framework_ids = {
            str(item).lower() for item in self.config.compliance_frameworks
        } if self.config.compliance_enabled else set()
        content_hash = str(public_record.get("content_hash") or "")
        file_hash = str(public_record.get("sha256") or public_record.get("file_hash") or content_hash)
        catalog_versions, _ = self._keyword_catalog_versions(framework_ids)
        cache_key = _record_cache_key(
            tenant_id=self.config.tenant_id,
            record=public_record,
            file_hash=file_hash,
            content_hash=content_hash,
            parser_version=PARSER_VERSION,
            detector_version=_detector_version(framework_ids),
            rule_catalog_version="|".join(catalog_versions) if catalog_versions else GDPR_RULE_CATALOG_VERSION,
            framework_ids=framework_ids,
        )
        cache_record = dict(public_record)
        cache_record["content"] = ""
        cache_record["reused_preview"] = public_record.get("preview")
        self._store_cached_findings(cache_key, copy.deepcopy(public_record.get("findings") or []), cache_record)
        return public_record

    def _record_triage(self, decision: dict) -> None:
        route = decision["route"]
        if route == triage.ROUTE_SKIP_NON_TEXT:
            key = "skipped_non_text"
        elif route == triage.ROUTE_SAMPLE:
            key = "sampled"
        else:
            key = "full"
        with self._triage_lock:
            self._triage_counts[key] += 1

    def _triage_diagnostics(self) -> dict:
        with self._triage_lock:
            counts = dict(self._triage_counts)
        return {
            "enabled": triage.triage_signature() != "triage-off",
            "policy": triage.triage_signature(),
            "records_full": counts["full"],
            "records_skipped_non_text": counts["skipped_non_text"],
            "records_sampled": counts["sampled"],
        }

    def _run_detectors(self, content: str, record: dict, framework_ids: set[str]) -> tuple[list[dict], dict]:
        started = time.perf_counter()
        timeout_seconds = float(self.config.detector_timeout_seconds or 0)
        detector_rows: list[dict] = []
        findings: list[dict] = []

        # P-C triage: skip the whole catalog for content that did not decode as
        # text (compressed/encrypted/binary mislabeled with a text extension) -
        # it cannot hold the plaintext the detectors match, so this is recall-safe
        # and consistent with the scanner's existing binary-content policy. Any
        # real text falls through to the full catalog below.
        decision = triage.triage_content(record, content)
        self._record_triage(decision)
        record["triage_score"] = decision["score"]  # surfaced for downstream ranking
        if decision["route"] == triage.ROUTE_SKIP_NON_TEXT:
            return [], {
                "cache_hit": False,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "detector_timeout_seconds": timeout_seconds,
                "triage_route": decision["route"],
                "triage_reason": decision["reason"],
                "triage_text_ratio": decision["text_ratio"],
                "triage_score": decision["score"],
                "slow_detector_degraded_mode": False,
                "detectors": [],
            }
        if decision["route"] == triage.ROUTE_SAMPLE:
            # Opt-in head/tail sampling of very large text: scan the sample and
            # mark the record PARTIAL so findings inherit the truncation contract.
            content = decision["sample"]
            record["scan_completeness"] = "PARTIAL"
            record["truncated"] = True
            record["bytes_scanned"] = decision.get("sampled_chars", len(content))

        generic_findings, row = self._timed_detector("generic", lambda: classify_content(content), timeout_seconds)
        detector_rows.append(row)
        findings.extend(generic_findings)

        if self.config.compliance_enabled:
            existing = {finding.get("type") for finding in findings}
            if "gdpr" in framework_ids:
                custom_keywords = self._custom_keywords_for_framework("gdpr")
                gdpr_findings, row = self._timed_detector("gdpr", lambda: classify_gdpr_content(content, record, custom_keywords), timeout_seconds)
                detector_rows.append(row)
                for finding in gdpr_findings:
                    if finding.get("type") not in existing:
                        findings.append(finding)
                        existing.add(finding.get("type"))
            if "pci_dss" in framework_ids:
                custom_keywords = self._custom_keywords_for_framework("pci_dss")
                pci_findings, row = self._timed_detector("pci_dss", lambda: classify_pci_content(content, record, custom_keywords), timeout_seconds)
                detector_rows.append(row)
                for finding in pci_findings:
                    dedupe_key = (
                        finding.get("type"),
                        finding.get("protection_state"),
                        tuple(finding.get("secure_fingerprints") or []),
                    )
                    existing_keys = {
                        (
                            item.get("type"),
                            item.get("protection_state"),
                            tuple(item.get("secure_fingerprints") or []),
                        )
                        for item in findings
                    }
                    if dedupe_key not in existing_keys:
                        findings.append(finding)
            if NIST_FRAMEWORK_ID in framework_ids:
                custom_keywords = self._custom_keywords_for_framework(NIST_FRAMEWORK_ID)
                nist_findings, row = self._timed_detector(NIST_FRAMEWORK_ID, lambda: classify_nist_content(content, record, custom_keywords), timeout_seconds)
                detector_rows.append(row)
                existing_keys = {
                    (
                        item.get("framework"),
                        item.get("rule_id") or item.get("type"),
                        item.get("logical_boundary_id") or item.get("location_id"),
                    )
                    for item in findings
                }
                for finding in nist_findings:
                    dedupe_key = (
                        finding.get("framework"),
                        finding.get("rule_id") or finding.get("type"),
                        finding.get("logical_boundary_id") or finding.get("location_id"),
                    )
                    if dedupe_key not in existing_keys:
                        findings.append(finding)
                        existing_keys.add(dedupe_key)

        slow = [
            row
            for row in detector_rows
            if row.get("degraded_mode") or row.get("timed_out") or row.get("elapsed_ms", 0) > timeout_seconds * 1000 > 0
        ]
        metrics = {
            "cache_hit": False,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "detector_timeout_seconds": timeout_seconds,
            "slow_detector_degraded_mode": bool(slow),
            "slow_detectors": [row["name"] for row in slow],
            "triage_route": decision["route"],
            "triage_score": decision["score"],
            "detectors": detector_rows,
        }
        return findings, metrics

    def _timed_detector(self, name: str, detector: Callable[[], list[dict]], timeout_seconds: float) -> tuple[list[dict], dict]:
        started = time.perf_counter()
        try:
            findings = detector()
            error = ""
        except Exception as exc:
            findings = []
            error = str(exc)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        timed_out = bool(timeout_seconds and elapsed_ms > timeout_seconds * 1000)
        row = {
            "name": name,
            "elapsed_ms": elapsed_ms,
            "finding_groups": len(findings),
            "timeout_seconds": timeout_seconds,
            "timed_out": timed_out,
            "degraded_mode": timed_out or bool(error),
        }
        if error:
            row["error"] = error
        return findings, row

    def _custom_keywords_for_framework(self, framework: str) -> list[dict]:
        with self._keyword_lock:
            if framework not in self._custom_keywords_by_framework:
                self._custom_keywords_by_framework[framework] = custom_keyword_groups_for_scan(self.config.tenant_id, framework)
            return self._custom_keywords_by_framework[framework]

    def _keyword_catalog_versions(self, framework_ids: set[str]) -> tuple[list[str], dict]:
        cache_key = tuple(sorted(framework_ids)) if self.config.compliance_enabled else tuple()
        with self._keyword_lock:
            cached = self._keyword_catalog_version_cache.get(cache_key)
            if cached is not None:
                versions, statuses = cached
                return list(versions), copy.deepcopy(statuses)
        statuses = {}
        versions = [f"gdpr_rules:{GDPR_RULE_CATALOG_VERSION}"]
        if self.config.compliance_enabled:
            for framework_id in sorted(framework_ids):
                status = nist_catalog_status() if framework_id == NIST_FRAMEWORK_ID else keyword_catalog_status(self.config.tenant_id, framework_id)
                statuses[framework_id] = status
                versions.append(f"{framework_id}:{status.get('catalog_hash') or status.get('catalog_version') or status.get('last_known_good_version') or 'built-in'}")
        with self._keyword_lock:
            self._keyword_catalog_version_cache[cache_key] = (list(versions), copy.deepcopy(statuses))
        return versions, statuses

    def _load_cached_findings(self, cache_key: tuple) -> list[dict] | None:
        with self._cache_lock:
            cached = self._finding_cache.get(cache_key)
            if cached is not None:
                return copy.deepcopy(cached)
        if not self.config.persistent_cache_enabled:
            return None
        path = self._cache_path(cache_key)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("cache_key") != _cache_key_digest(cache_key):
                return None
            findings = data.get("findings")
            if not isinstance(findings, list):
                return None
            with self._cache_lock:
                self._finding_cache[cache_key] = copy.deepcopy(findings)
            return copy.deepcopy(findings)
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def _store_cached_findings(self, cache_key: tuple, findings: list[dict], record: dict) -> None:
        with self._cache_lock:
            self._finding_cache[cache_key] = copy.deepcopy(findings)
        if not self.config.persistent_cache_enabled:
            return
        path = self._cache_path(cache_key)
        payload = {
            "cache_key": _cache_key_digest(cache_key),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tenant_id": cache_key[0],
            "asset_id": cache_key[1],
            "file_hash": cache_key[2],
            "file_size": cache_key[3],
            "modified_time": cache_key[4],
            "parser_version": cache_key[5],
            "detector_version": cache_key[6],
            "keyword_catalog_version": cache_key[7],
            "frameworks": list(cache_key[8]),
            "cache_levels": {
                "level_1_file_result": True,
                "level_2_extracted_text": {
                    "content_hash": record.get("content_hash") or "",
                    "bytes_scanned": int(record.get("bytes_scanned") or 0),
                    "scan_completeness": record.get("scan_completeness") or "UNKNOWN",
                },
                "level_3_canonical_entity": True,
                "level_4_framework_mapping": {
                    "frameworks": list(cache_key[8]),
                    "keyword_catalog_version": cache_key[7],
                },
            },
            "findings": findings,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            return
        # Also persist the metadata-first reuse sidecar so an unchanged file can
        # be reused next scan without reading its content. The sidecar records
        # which findings-cache entry it pairs with so reuse is fail-closed.
        self._write_meta_sidecar(record, cache_key)

    def _cache_path(self, cache_key: tuple) -> Path:
        return Path(self.config.cache_dir).expanduser().resolve() / f"{_cache_key_digest(cache_key)}.json"

    @staticmethod
    def _build_summary(files: list[dict]) -> ScanSummary:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        sensitive_files = 0
        hidden_files = 0
        protected_files = 0

        for item in files:
            level = item.get("risk", {}).get("level", "LOW")
            counts[level] = counts.get(level, 0) + 1
            if item.get("findings"):
                sensitive_files += 1
            if item.get("is_hidden"):
                hidden_files += 1
            protection_blob = " ".join(
                str(item.get(key, "")).lower()
                for key in ("content_status", "scan_error", "protection_type")
            )
            if item.get("protected") or any(
                marker in protection_blob
                for marker in ("protected", "password", "encrypted", "locked", "unreadable", "unsupported_archive", "bad_archive")
            ):
                protected_files += 1

        return ScanSummary(
            total_files=len(files),
            critical=counts["CRITICAL"],
            high=counts["HIGH"],
            medium=counts["MEDIUM"],
            low=counts["LOW"],
            sensitive_files=sensitive_files,
            hidden_files=hidden_files,
            protected_files=protected_files,
        )


def _safe_preview(content: str, max_lines: int = 8, max_chars: int = 1800) -> dict:
    if not content:
        return {"available": False, "lines": [], "truncated": False}

    # Sanitize a bounded head slice (larger than what is displayed) so a secret
    # sitting near the display cutoff is still fully masked before truncation,
    # without paying to scan an entire (up to 100 MB) file for a preview.
    head = content[: max(max_chars * 8, 16384)]
    sanitized = sanitize_evidence_text(head)
    lines = sanitized.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    selected = lines[:max_lines]
    text = "\n".join(selected)
    truncated = len(content) > len(head) or len(lines) > max_lines or len(text) > max_chars

    if len(text) > max_chars:
        text = text[:max_chars]
        selected = text.split("\n")

    return {
        "available": True,
        "lines": selected,
        "truncated": truncated,
    }


def _decorate_finding_taxonomy(finding: dict) -> None:
    framework = str(finding.get("framework") or "").lower()
    finding_type = str(finding.get("type") or "").lower()
    category = str(finding.get("category") or "").lower()
    frameworks = finding.get("frameworks")
    if not isinstance(frameworks, list):
        frameworks = []
    if framework and framework not in frameworks:
        frameworks.append(framework)
    if finding.get("requirement_mappings") and "pci_dss" not in frameworks:
        frameworks.append("pci_dss")
    if finding.get("gdpr_article_mappings") and "gdpr" not in frameworks:
        frameworks.append("gdpr")
    finding["frameworks"] = frameworks

    if not finding.get("data_category"):
        finding["data_category"] = finding.get("personal_data_type") or finding.get("category") or finding.get("pci_category") or "sensitive_data"
    if not finding.get("finding_category"):
        if finding.get("pci_category") in {"CHD", "SAD"}:
            finding["finding_category"] = "PCI Account Data"
        elif category in {"credentials", "credentials_secrets"}:
            finding["finding_category"] = "Credential Exposure"
        elif framework == "gdpr":
            finding["finding_category"] = "Personal Data"
        else:
            finding["finding_category"] = "Sensitive Data"
    if finding.get("classification_domain"):
        return
    if framework == "pci_dss" or finding_type.startswith("pci_") or category.startswith("pci_"):
        finding["classification_domain"] = "regulated_payment_card"
    elif framework == "nist_sp800_60_enterprise" or category.startswith("nist_"):
        finding["classification_domain"] = "nist_information_type"
    elif framework == "gdpr" or category in {"personal_data", "pii", "government_ids", "health_data", "biometric_data", "genetic_data"}:
        finding["classification_domain"] = "privacy_personal_data"
    elif category in {"credentials", "credentials_secrets"} or finding["finding_category"] == "Credential Exposure":
        finding["classification_domain"] = "secrets"
    else:
        finding["classification_domain"] = "sensitive_data"


def _redact_pci_preview(content: str) -> str:
    from classification.compliance.pci_keywords import CVV_KEYWORDS, PIN_KEYWORDS
    from classification.compliance.pci_validators import PAN_CANDIDATE_RE, is_valid_pan, mask_pan, mask_track_data, parse_track_data, redact_cvv_fields, redact_pin_fields

    def replace_candidate(match) -> str:
        value = match.group(0)
        return mask_pan(value) if is_valid_pan(value) else value

    redacted = redact_pin_fields(redact_cvv_fields(content, CVV_KEYWORDS), PIN_KEYWORDS)
    for track in parse_track_data(content):
        raw = str(track.get("raw") or "")
        if raw:
            redacted = redacted.replace(raw, mask_track_data(track))
    return PAN_CANDIDATE_RE.sub(replace_candidate, redacted)


# Generic detector rules whose match IS a sensitive value (not a routing
# keyword). Only these get masked in evidence text; context-keyword rules
# (redact=False) are left intact so previews stay legible.
_EVIDENCE_MASKING_RULES = tuple(rule for rule in RULES if rule.redact)

# SC-1 hardening: an unbounded private-key block matcher. The generic
# private_key detection rule caps the body at ~2000 chars, so RSA-3072/4096,
# OpenSSH-format, or encrypted PEM keys (base64 bodies well over 2000 chars)
# slip past the rule-based masking below and would leak into the preview. This
# masks a key block of ANY length (or a truncated block up to end-of-slice).
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def sanitize_evidence_text(content: str) -> str:
    """Mask every detected sensitive class in free text before it is persisted
    or served as evidence (SC-1).

    PCI card data is masked by the dedicated PCI pipeline; all other detector
    classes (private keys, tokens, credentials, connection strings, PII) are
    replaced with a non-reversible ``[redacted:<class>]`` marker. This is the
    single choke point that generalises the previous PCI-only preview redaction
    to every sensitive class. Raw, unmasked passthrough is opt-in via
    ``DSPM_RAW_EVIDENCE_PREVIEW=1`` and is OFF by default.
    """
    if not content:
        return content
    if os.getenv("DSPM_RAW_EVIDENCE_PREVIEW", "0") == "1":
        return content
    return _sanitize_evidence_cached(content)


@lru_cache(maxsize=512)
def _sanitize_evidence_cached(content: str) -> str:
    """The masking itself, memoized on the exact input.

    PERF: every record is sanitized twice (once for the served preview, once
    for the reuse snapshot) and each pass runs ~90 masking regexes, which made
    this the single hottest project function. The function is pure, so the
    second pass is now free. Head slices are bounded (<=16 KB), so the cache
    is a few MB at most.
    """
    masked = _redact_pci_preview(content)
    # Mask private-key blocks of ANY size first (the rule-based pass below caps
    # the body length and would otherwise leak large keys).
    masked = _PRIVATE_KEY_BLOCK_RE.sub("[redacted:private_key]", masked)
    for rule in _EVIDENCE_MASKING_RULES:
        masked = rule.pattern.sub(lambda match, name=rule.name: f"[redacted:{name}]", masked)
    return masked


def _detector_version(framework_ids: set[str]) -> str:
    parts = [GENERIC_DETECTOR_VERSION]
    if "gdpr" in framework_ids:
        parts.append(GDPR_DETECTOR_VERSION)
    if "pci_dss" in framework_ids:
        parts.append(PCI_DETECTOR_VERSION)
    if NIST_FRAMEWORK_ID in framework_ids:
        parts.append(NIST_DETECTOR_VERSION)
    # P-C: a triage skip changes WHICH detectors run without changing content, so
    # the active triage policy must invalidate the findings cache / durable
    # baseline - otherwise a "skipped -> []" result could be reused after triage
    # is turned off (or vice-versa).
    parts.append(triage.triage_signature())
    return "+".join(parts)


def _cache_key_digest(cache_key: tuple) -> str:
    raw = json.dumps(cache_key, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def _record_cache_key(
    *,
    tenant_id: str,
    record: dict,
    file_hash: str,
    content_hash: str,
    parser_version: str,
    detector_version: str,
    rule_catalog_version: str,
    framework_ids: set[str],
) -> tuple:
    asset_id = str(record.get("asset_id") or record.get("path") or record.get("name") or file_hash or content_hash or "unknown")
    file_size = int(record.get("size") or record.get("total_bytes") or 0)
    modified_time = str(record.get("modified_at") or record.get("mtime") or record.get("last_write_time") or "")
    keyword_catalog_version = rule_catalog_version
    return (
        tenant_id,
        asset_id,
        file_hash,
        file_size,
        modified_time,
        parser_version,
        detector_version,
        keyword_catalog_version,
        tuple(sorted(framework_ids)),
        content_hash,
    )


def _safe_scan_error(exc: Exception) -> str:
    raw = str(exc or "").lower()
    if "invalid literal" in raw or "base 16" in raw:
        return "Malformed encoded data was skipped during analysis."
    if "cancel" in raw:
        return "Scan cancelled."
    return "Record analysis failed; see detector metrics and backend logs."
