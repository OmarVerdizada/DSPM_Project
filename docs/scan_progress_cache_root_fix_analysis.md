# SENTRO DSPM — Scan Progress & Cache Root-Cause Analysis

Date: 2026-07-15

## Scope and method

Focused stabilization of the scan pipeline: the scan was reported as "stuck at
14% and very slow, even though cache logic exists." This is **not** the
enterprise roadmap. Every conclusion is verified from source and from a real
runtime probe: a 120-file local dataset scanned cold, then warm (unchanged),
then with one changed file, capturing timing, progress stages, reuse counters,
and finding/risk parity.

## Reports / PDF read

- `docs/dspm_system_stabilization_analysis.md` and
  `docs/dspm_system_stabilization_fix_report.md` (the prior pass that added the
  collection **heartbeat** to 14 + wall-clock deadline).
- `docs/Sentro_DSPM_Enterprise_Full_Technical_Assessment_2026.pdf` (context
  only). Relevant warnings applied here: collect-all pipeline; cache only after
  collection/analyze; full hash/read cost; per-file ACL/PowerShell overhead; no
  real collection progress; timeout measured/surfaced, not true interruption.

## Source areas inspected

`backend/jobs.py` (job lifecycle, progress mapping, heartbeat/deadline);
`discovery/discovery_engine.py` (`run`, `_collect_records`, `_analyze_records`,
`_analyze_record`, the persistent finding cache, `_record_cache_key`);
`collectors/file_scanner.py` (`scan_directory`, `add_file`,
`read_text_preview_and_sha256`, `sha256_file`, `file_owner`);
`collectors/smb_scanner.py` (`scan`, `_walk_share`, `_acl_for_path`,
`_hash_file`, `_read_file_preview`); `backend/app.py` (scan routes);
`frontend/app.js` (`pollScan`, `setScanProgress`, `smoothProgress`); scan tests.

## Runtime measurement (120-file local dataset)

| Scan | Time | Reused | Findings | Risk parity |
| --- | --- | --- | --- | --- |
| 1 — cold cache | **178,504 ms** | 0 | 360 | baseline |
| 2 — warm, unchanged | **4,247 ms** (≈42× faster) | 120/120 | 360 (identical) | identical |
| 3 — one file changed | 1,764 ms | 119 (changed file re-read) | 357 (correct) | correct |

Collection emitted 9 real `collecting` stages; peak mapped job progress reached
95 across stages (well past 14).

## Analysis questions

1. **Why does progress stop at 14%?** 14 is the heartbeat ceiling
   (`jobs.COLLECT_HEARTBEAT_CEILING`) added in the prior pass. Collection
   (`scan_directory` / SMB `_walk_share`) is one blocking call that emitted **no
   progress**, so before the first `"collected"` callback (→15) the bar could
   only be nudged up to 14 by the heartbeat. For a slow collection it sat there.
2. **Which stage is running at 14%?** File **collection**: walking the tree and,
   per file, resolving the owner, reading content, and hashing.
3. **Does cache run before or after collection?** **After.** The persistent
   finding cache is consulted in `_analyze_record`, which runs after
   `_collect_records` has already produced fully-read, hashed records.
4. **Does it still enumerate all files even when unchanged?** Yes — the walk
   visits every file every scan (that is unavoidable and cheap). The problem was
   the per-file *work* during enumeration, not the walk.
5. **Does it still read content before cache lookup?** Yes (was true).
   `add_file` called `read_text_preview_and_sha256(item)` for every non-protected
   file during collection, before any cache check.
6. **Does it still compute full SHA before cache lookup?** Yes (was true).
   `read_text_preview_and_sha256` streams the **whole file** through SHA-256
   even though the preview is byte-limited; metadata-only files still paid a
   full-file `sha256_file`. All before the cache was consulted.
7. **Does it still fetch ACL/owner per file before cache lookup?** Yes (was true,
   and it was the dominant cost). `file_owner(item)` calls `Path.owner()`, which
   raises `NotImplementedError` on Windows, then falls back to spawning
   `powershell.exe Get-Acl` **once per file** (3 s timeout each). For 120 files
   this alone accounted for ~178 s.
8. **Which scan types are affected?** All three share the collect-all shape.
   **Local** (`scan_directory`) and **SMB** (`_walk_share` → `_acl_for_path` +
   `_hash_file`) do per-file owner/ACL + full hash during collection; **WinRM**
   does the equivalent work remotely on the endpoint and returns one big array.
9. **Is frontend polling accurate?** Yes — `pollScan` renders the backend's
   authoritative `job.progress` and `job.message`; the freeze was a backend
   stale-progress problem, not a frontend one.
10. **Smallest safe MVP fix?** (a) Emit **real collection progress** from the
    walk; (b) add a **metadata-first reuse** step so an unchanged file
    (path+size+mtime, same version signature) reuses a stored snapshot and skips
    owner + content read + full hash + reclassification. Keep the existing
    finding cache, results, and the deadline unchanged.

## Where the cache currently applies

The persistent cache stores **findings** keyed by
`_record_cache_key = (tenant, asset_id, file_hash, size, mtime, parser_version,
detector_version, keyword_catalog_version, frameworks, content_hash)`. Because
`file_hash`/`content_hash` require the content to have been read, the cache can
only be consulted **after** collection has already paid the expensive I/O. So
the cache saved the *classifier* cost, never the *collection* cost — exactly why
"cache exists but the scan is still slow."

## Why the cache did not speed up collection enough

The cache key was content-derived, so there was no way to decide "this file is
unchanged, skip reading it" without first reading it. The heaviest per-file
costs (owner PowerShell subprocess, full content read, full-file SHA) all
happened in collection, upstream of the cache. The prior pass's heartbeat made
the bar move to 14 but could not remove that work — hence "stuck at 14 and slow."

## Local / SMB / WinRM impact

- **Local** — fixed in this pass: metadata-first reuse + real collection
  progress (measured 42× faster warm scan).
- **SMB / WinRM** — same collect-all cost pattern. They continue to use the
  existing finding cache and are protected by the heartbeat + wall-clock
  deadline (hang → failed). Collection-time metadata reuse and per-file
  collection progress for SMB/WinRM are a documented follow-up (their collectors
  read remotely / via a different protocol); this pass keeps them unchanged to
  avoid untestable risk in an environment without `pysmb`/`pywinrm`.

## Chosen fix plan

1. **Real collection progress.** Thread a `progress_callback(visited, matched,
   reused)` into `scan_directory`; the engine bridges it to a `collecting`
   stage; `jobs._update_scan_job_progress` maps `collecting` into an 8→40 band
   (message shows discovered + reused counts), `collected`→42, `analyzing`
   45→95. Progress now moves past 14 with real counts.
2. **Metadata-first reuse.** When a file is first classified, store a small
   `.meta.json` **sidecar** (owner, hashes, content_status, preview, and the
   version signature) keyed by a digest of `(version_signature, path, size,
   mtime)`. On the next scan, a `reuse_probe(path, size, mtime)` in `add_file`
   finds the sidecar and emits the record from the snapshot with `content=""`,
   skipping the owner subprocess, content read, and full hash. `_analyze_record`
   then reuses the stored findings (existing finding cache) and, as a safety
   net, **re-reads** the file if the findings cache entry is missing so reuse can
   never drop findings. The version signature guarantees a detector/parser/rule/
   framework upgrade forces a full re-read.
3. **Correctness & isolation preserved.** Reuse only fires for unchanged
   files under the same tenant + version signature; changed files (mtime/size)
   miss and are fully re-read; findings/risk/preview are identical on reuse.

## Rejected alternatives

- **Fake/animated progress past 14.** Rejected — the task requires progress to
  reflect real state; a cosmetic bar would hide the real bottleneck.
- **Content-hash cache only (status quo).** Rejected — it cannot avoid the
  collection I/O because the key needs the content.
- **Interrupt/kill a hung collection thread.** Rejected for this MVP — true
  mid-parse cancellation is roadmap work (SCAN-002). The wall-clock deadline
  already surfaces a hang as `failed`, which satisfies the requirement.
- **Drop the per-file owner lookup entirely.** Rejected — owner is real report
  metadata; removing it on cold scans would silently change output. Reuse skips
  it safely for unchanged files instead.
- **A single global cache index file.** Rejected for MVP — a per-file sidecar
  keyed by a metadata digest gives O(1) lookup without a shared-write hot spot
  and without scanning the whole cache directory.
- **Rewriting the scanner / adding native ACL (pywin32) or async streaming.**
  Out of scope (no new dependencies, no rewrite).
