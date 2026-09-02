# Scan performance — 13 minutes to 30 seconds

**Status:** Complete. P1-P5 implemented, measured, and confirmed on the production share.
**Date:** diagnosed and delivered 2026-08-28.
**Goal set:** >=90% faster with zero loss of accuracy or detail. **Delivered:** 96-99%.

---

## 1. Outcome

| Scenario | Before | After | Cut |
| --- | --- | --- | --- |
| **Real SMB share, full re-read** (453 files, 9 shares) | **780 s (13 min)** | **30.4 s** | **96.1%** |
| **Real SMB share, incremental rescan** | 780 s | **10.8 s** | **98.6%** |
| Local scan, engine only (360 files) | 151.2 s | **4.21 s** | 97.2% |
| Local scan, engine only, warm cache | 151.2 s | **2.00 s** | 98.7% |
| Local scan, end to end via `/api/scan` | 157.3 s | **6.6 s** | 95.8% |
| Owner/ACL resolution, per file | 487 ms | **0.77 ms** | **631x** |

Findings are unchanged. Both SMB runs report CRITICAL 147, HIGH 207, MEDIUM 82,
LOW 17 - identical to a control scan taken before any of this work (section 4).

---

## 2. Diagnosis: where the time actually went

Nothing was guessed. Two evidence sources: per-file telemetry stored inside the
real 13-minute scan (`20260826070358374549`), and a cProfile of the full local
pipeline run against a throwaway database.

| Stage | Measured (362 files) | Share |
| --- | --- | --- |
| **Owner/ACL resolution - one `powershell.exe Get-Acl` per file** | **143.3 s** | **91%** |
| File reads + SHA-256 | 7.0 s | 4.5% |
| Persistence (report dump 4.1 s + history 1.8 s) | 6.1 s | 3.9% |
| Per-file cache sidecar writes (724) | 2.7 s | 1.7% |
| Binary text extraction (82 office/PDF files) | 1.9 s | 1.2% |
| **Content classification - every detector, every framework** | **0.9 s** | **0.6%** |
| Compliance mapping | 0.1 s | 0.1% |

The instinctive suspects were innocent. **The work Sentro exists to do cost
0.6% of the runtime.** The SMB scan's own diagnostics showed the same mechanism
dominating there: `owner_read_attempts = 667`, each one a PowerShell process
launched across the network - roughly 11 of the 13 minutes.

That framed the whole effort: the target was never the detectors, so accuracy
was never the thing being traded away. The 90% lived entirely in *how metadata
was fetched and stored*.

---

## 3. What shipped

### P1 - In-process security descriptors - `55641a4`

`collectors/win_security.py` reads owner and DACL through Win32
(`GetNamedSecurityInfoW` + `LookupAccountSidW`, SID-to-name memoized).

The decisive detail: **that API accepts UNC paths**, so one implementation
replaced the subprocess in both collectors - the SMB fix came free with the
local one. `file_scanner.file_owner()` tries it before the old subprocess;
`smb_scanner` resolves single paths and whole prefetch batches in-process,
falling back to the credential-mapped PowerShell only when a descriptor is
genuinely unreadable.

Output is byte-compatible: owner as `DOMAIN\Account`, and access masks rendered
through .NET's `FileSystemRights` flag algorithm (ground truth captured from
.NET itself).

*487 ms -> 0.77 ms per file. For 421 files: 205 s -> 0.33 s.*

### P3 - One manifest, one compact report - `adb3523`

With the ACL wall gone, the profiler exposed the file-handle churn underneath:

- Reuse metadata was **one small file open per scanned file** inside the probe
  (~33 ms each under real-time AV - 11.9 s of a 14 s scan) plus one write per
  record (724 writes, 2.7 s). Both now go through an in-memory index persisted
  as a single manifest. Legacy per-file sidecars are still *read*, so caches
  written by older builds keep working.
- The findings-cache pairing check did a `stat()` per probe -> one directory
  listing, taken once.
- The cache directory was re-resolved (`expanduser().resolve()`) per file.
- The report was written with `indent=2`: 1.09 M encoder calls, 4.1 s spent on
  whitespace no consumer reads -> compact separators, one write.
- The reuse snapshot deep-copied every record (2.5 s) only to serialize it
  immediately -> shallow copy minus the heavy keys.

### P2 - I/O workers budgeted for latency - `917247b`

Collector I/O workers wait on network round-trips (an SMB file is ~3 RTTs) but
were sized at 2x CPU - 12 on a 6-core host - leaving the link idle and making
collection the wall-clock floor of every remote scan. The auto policy now
budgets 6x CPU (min 16, still capped at 64, still gated by the process-wide
admission budget), with a pipeline buffer deep enough that collectors never
block on an analysis slot. Measured active: 36 workers, buffer 72.

### P4 - Reuse verified, and a premise corrected - `088bf8b`

The plan assumed cache reuse was broken, because the 13-minute scan reported
`cache_reused_files = 0`. **It was not broken.** That was simply the first scan
of that share - there was nothing to reuse. Reuse engages correctly (359/360 on
an unchanged local rescan; 453/453 on the SMB rescan) and is now covered by a
test so it cannot silently regress.

### P5 - Re-derived from a fresh profile - `acb3046`

P5 was planned from the *original* profile. By the time P1-P4 landed the hot
spots had moved entirely, so it was re-measured rather than executed as written:

| Planned | Reality after P1-P4 |
| --- | --- |
| Binary extraction parallelism (1.9 s) | Out of the top 20 - **skipped deliberately** |
| `pathlib.resolve` caching (2.0 s) | Still real: 5,696 syscalls / 0.48 s - **done** |
| Preview sanitize pooling (~2 s) | Badly understated: masking was **the** hottest project function at 1.8 s - **done** |

1. **Redaction catalogs are built once.** `redact_cvv_fields` /
   `redact_pin_fields` escaped 189 keywords and recompiled a large alternation
   *on every call* - 132,678 `re.escape` calls per scan - and every record is
   sanitized twice (served preview + reuse snapshot). Patterns are memoized per
   catalog and the sanitizer memoized on its bounded (<=16 KB) input. `re.sub`
   left the profile entirely; the redaction helper alone is **14x faster**.
2. **Containment checks resolve directories, not files.** The scan-root escape
   check ran one `_getfinalpathname` per entry (5,696 -> 2,846 calls). This is
   not a weakening: `is_symlink()` is still tested first, and a non-symlink
   entry's real path *is* `realpath(parent)/name`.

---

## 4. How accuracy was proven

Speed claims are easy. These are the checks that make them safe to believe.

| Check | Result |
| --- | --- |
| Per-file comparison against a control scan taken **before** any of this work - risk level, score, finding count, reason count, owner, ACL principals | **449 / 449 shared files identical. Zero differences.** |
| ACL output vs. PowerShell `Get-Acl` on real files (owner + every access entry) | Byte-identical |
| Access-mask rendering vs. .NET `FileSystemRights.ToString()` | Exact on all cases |
| Old vs. new redaction over generated keyword/value inputs | **816 comparisons, zero differences** |
| Symlink / directory-symlink / junction escapes after resolve-caching | All contained; legitimate files still scanned |
| Cold vs. warm scan of the same tree | **360 / 360 files identical** |
| Owner resolution completeness | **Improved**: `owner_missing` 6 -> 0 |

Finding counts rose only in step with files genuinely added to the share
(private_key 123 -> 142, password 124 -> 143) - no detection was lost or invented.

---

## 5. Guardrails (`tests/test_scan_performance.py`)

Nine tests exist so this cannot quietly regress:

- Owner resolution **spawns no subprocess** (patches `subprocess.run` to raise)
  and answers in **under 10 ms/call** - the pattern that cost 91% of scan time
  now fails the suite instantly.
- The in-process reader must match `Get-Acl` exactly, including mask names.
- A full local scan must finish inside a **wall-clock budget**, and an unchanged
  rescan must **reuse its cache** and report identical totals.
- Redaction keyword patterns must compile **exactly once**; masking must still
  redact private keys and CVV values.
- Links must not escape the scan root.
- The report must be written compactly and round-trip identically.

---

## 6. Traps worth remembering

**Asset override rules live in the browser.** The first confirmation run
reported `CRITICAL = 0` and looked like a serious scoring regression. It was
not: the console sends `asset_overrides` with every scan request, and a raw API
call omits them - the missing reason was *"MSSP asset override: Credential files
are crown-jewel assets"*. Re-running with the rules the UI sends reproduced
CRITICAL = 147 exactly. **Any API-level benchmarking must include
`asset_overrides`, or it will silently under-score every credential file.**

**Temp directories are excluded from scanning.** A containment test written
against `tempfile.TemporaryDirectory()` "passes" while scanning zero files -
i.e. proves nothing. Security tests must run somewhere scanning actually works.

**Profile after every phase.** Each fix changed which code was hot. Working from
a stale profile would have spent P5 on binary extraction, irrelevant by then,
and missed the redaction cost entirely.

---

## 7. What is left

The remaining time is genuine work - file reads, JSON encoding, and the
detectors themselves. Nothing in the current profile is an obvious defect.

- **Persistence** is now the largest single share of a local scan (~2-3 s of
  6.6 s): findings/occurrence inserts and history writes. Worth attacking only
  if scan sizes grow by an order of magnitude; the insert path is already
  batched.
- **SMB wall-clock** is now dominated by real protocol round-trips.
  `DSPM_IO_WORKERS` above 36 is the remaining knob if the target server and link
  tolerate it.
- **ML/NER classification is disabled** on this host (spaCy not installed).
  Enabling it will add real per-file cost - measure before and after, since it
  lands in the one part of the pipeline this work deliberately never touched.

---

## Commit trail

| Phase | Commit |
| --- | --- |
| P1 - in-process security descriptors | `55641a4` |
| P3 - cache manifest + compact report | `adb3523` |
| P2 - I/O worker budget | `917247b` |
| P4 - guardrail tests | `088bf8b` |
| P5 - redaction + resolve caching | `acb3046` |
| Docs - outcome, real-share confirmation, P5 | `10a0daf`, `38389fb`, `232b634` |
