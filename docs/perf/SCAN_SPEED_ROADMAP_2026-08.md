# Scan speed roadmap — cut 13 minutes to about one

**Status:** IMPLEMENTED 2026-08-28 (P1-P4 landed; results in §6)
**Date:** 2026-08-28 · **Target:** ≥90% faster with zero loss of accuracy or detail.
**Evidence:** per-file telemetry mined from the real 13-minute SMB scan
(`20260826070358374549`, 421 files, 9 shares) plus a sandboxed cProfile of the
full local pipeline (362 files, throwaway DB — production data untouched).

---

## 1. Where the 13 minutes actually go

The instinctive suspects are innocent. Measured:

| Stage | Local scan (measured, 362 files) | Share of total |
| --- | --- | --- |
| **Owner/ACL resolution — one `powershell.exe Get-Acl` process per file** | **143.3 s** | **91%** |
| File reads + SHA-256 | 7.0 s | 4.5% |
| Persistence (report JSON dump 4.1 s + history write 1.8 s) | 6.1 s | 3.9% |
| Per-file meta sidecar writes (724 files) | 2.7 s | 1.7% |
| Binary text extraction (82 office/pdf files) | 1.9 s | 1.2% |
| **Content classification — all detectors, all frameworks** | **0.9 s** | **0.6%** |
| Compliance mapping | 0.1 s | 0.1% |

(Columns overlap slightly because collection and analysis run pipelined; the
ranking is what matters.)

The same mechanism dominates the SMB scan. Its diagnostics show
`owner_read_attempts = 667` — a PowerShell-backed security-descriptor query
went out for **every record**, over the network to `10.10.33.149`, where each
one costs 0.5–1.5 s instead of 0.4 s. That alone accounts for roughly **11 of
the 13 minutes**. Everything Sentro is *supposed* to be doing — reading,
hashing, classifying, mapping to frameworks — fits in well under a minute.

Also in the diagnostics: `cache_reused_files = 0` and 6 analysis workers
sitting effectively idle behind the serialized ACL wall
(`peak_in_flight = 12` but the pipeline drains at subprocess speed).

**Accuracy is not the trade-off here.** The detector work we must never touch
costs half a percent of the runtime. The 90% lives entirely in *how* metadata
is fetched and stored.

---

## 2. Roadmap

### P1 — Kill the per-process ACL fetch  *(the 90% itself)*

**Local paths.** `collectors/file_scanner.py:file_owner()` falls back to
spawning `powershell.exe` per file (Python's `Path.owner()` raises on this
runtime). Replace with an in-process Win32 call via `ctypes`
(`GetNamedSecurityInfoW` + `LookupAccountSidW`), with a SID→name cache. Cost
drops from ~400 ms to microseconds per file. Same owner string, same detail.

**SMB paths.** Two options, in order of preference:
1. Read the owner from the **SMB security descriptor** the protocol already
   provides (pysmb `getSecurity`), resolving SIDs once per unique SID against
   the server. No subprocess at all.
2. If descriptor access proves unreliable on some targets: the batch machinery
   already exists (`_prefetch_acl_paths` — one PowerShell for a whole batch)
   but the diagnostics show it **did not engage** in the 13-minute scan
   (no `acl_batch_paths` counter). Find why `_acl_batch_enabled()` gated it
   off, turn it on by default, and make the batch script use
   `GetAccessControl` in a single long-lived process (~10 ms/path).

**Expected:** local 157 s → ~12 s. SMB 780 s → **~2–2.5 min** from this step
alone. Detail preserved: owner, principals, and permissions still collected —
only the transport changes.

### P2 — Feed the parallelism  *(user mandate: burn RAM/CPU)*

The engine already pipelines collection↔analysis, but the knobs are
conservative: `io_workers = 12`, `analysis_workers = 6`,
`pipeline_buffer = 12`. Once P1 removes the wall:
- SMB IO workers → 24–32 (network-latency-bound; each worker owns its
  retry-safe connection already).
- Pipeline buffer → 64 so collectors never stall waiting for analysis slots.
- Keep analysis workers = CPU count (detection is already nearly free).

**Expected:** the remaining SMB wall-clock is per-file protocol round-trips
(open/read/close ≈ 3 RTTs); 421 files at 32 workers ≈ **10–25 s** of
collection. Combined with P1: **500 SMB files in ~60–90 s** — the 90% target.

### P3 — Persistence diet

- The report blob is serialized with pretty-printed `json.dump`
  (1.09 M encoder calls, 4.1 s). Compact separators / single `dumps` →
  ~4–6× faster; nothing downstream reads the whitespace.
- 724 per-file meta sidecar files (2.7 s of `_write_meta_sidecar`) →
  one manifest per scan.
- Confirm findings/occurrences/index inserts run as `executemany` inside one
  transaction (persist is already only 6.1 s; keep it flat as file counts grow).

**Expected:** persist 6.1 s → ~1.5 s, and it stays linear at 10× the files.

### P4 — Make rescans nearly free  *(the second 90%)*

`cache_reused_files = 0` despite `incremental: enabled`. Two known hazards:
1. The cache `version_signature` embeds **live environment values** including
   `DSPM_OCR_*`. The new runtime OCR toggle mutates `os.environ`, so flipping
   any feature invalidates every cached verdict. Pin the signature to the
   persisted setting value read once at scan start.
2. Verify the metadata-first path (size+mtime from `listPath`) actually
   short-circuits unchanged files on a true rescan of the same scope; add a
   regression test that scans twice and asserts `cache_reused_files > 0` and
   a ≥80% second-run speedup.

**Expected:** repeat scans of an unchanged share ≈ listing time — seconds.

### P5 — Only after the above (small change, small win)

Binary extraction parallelism for office/PDF batches (1.9 s), `pathlib.resolve`
caching (2.0 s), preview sanitize pooling (~2 s). Worth ~4–5 s combined; not
worth touching until P1–P4 land.

---

## 3. Budget: 500 SMB files, before → after

| Phase | Today | After P1–P3 |
| --- | --- | --- |
| Owner/ACL | ~660 s | ~5 s (descriptor/batch) |
| File reads + hash | ~60 s | ~15 s (32 workers) |
| Classification + compliance | ~1 s | ~1 s (untouched) |
| Persistence + report | ~8 s | ~2 s |
| Orchestration/overheads | ~50 s | ~40 s |
| **Total** | **~13 min** | **~60–75 s (≈91–92% cut)** |
| Rescan, unchanged data (P4) | ~13 min | **seconds** |

---

## 4. Guardrails

- **No detector, catalog, threshold, or evidence change anywhere** — the
  accuracy-bearing code is not on this roadmap's critical path (it is 0.6% of
  runtime).
- Owner/principal/permission detail is still collected in full; only the
  transport (API call vs. spawned shell) changes. A contract test asserts the
  owner strings match the PowerShell output on a fixture tree.
- Perf regression harness: scanning `enterprise_test_data` must finish under a
  budget (e.g. 20 s) in the suite's slow lane, so the subprocess pattern can
  never quietly return.

## 5. Order of work

1. **P1-local** (ctypes owner) — smallest diff, validates the approach, makes
   every dev-loop scan instant. ~1 session.
2. **P1-SMB** (descriptor read, batch fallback default-on). ~1 session.
3. **P2 + P3** together (config + serialization). ~half a session.
4. **P4** (cache reuse investigation + signature fix + regression test). ~1 session.


---

## 6. Results — measured after implementation

| Scenario | Before | After | Cut |
| --- | --- | --- | --- |
| Local scan, engine only (362 files) | 151.2 s | **4.94 s** | **96.7%** |
| Local scan, end to end via `/api/scan` | 157.3 s | **6.6 s** | **95.8%** |
| Same scan, unchanged rescan | 157.3 s | **2.3 s** | **98.5%** |
| Owner/ACL resolution, per file | 487 ms | **0.77 ms** | **631×** |
| Owner/ACL for 421 files | 205 s | **0.33 s** | — |

**Accuracy held exactly.** Every run reports identical totals (362 files,
283 high, 75 medium) and identical findings; the ACL fidelity test compares
owner strings and every access-mask rendering against PowerShell/.NET ground
truth on real files.

Your 421-file SMB scan is dominated by the same fixed cost that fell 631× here,
so it should land in the **1–1.5 minute** range instead of 13 — the residual
being genuine network round-trips, now served by 36 I/O workers instead of 12.

### What actually shipped

| Phase | Commit | Change |
| --- | --- | --- |
| P1 | `55641a4` | `collectors/win_security.py`: Win32 security-descriptor reads (UNC-capable, SID-name cached) wired into both collectors, with the old subprocess kept as fallback |
| P3 | `adb3523` | One in-memory cache manifest instead of a sidecar open/write per file; one directory listing instead of a stat per probe; compact report serialization; no per-record deep copy |
| P2 | `917247b` | I/O workers 12 → 36 (6× CPU, latency-budgeted), pipeline buffer 12 → 72 |
| P4 | `088bf8b` | Guardrail tests: no subprocess per file, <10 ms/call, Get-Acl fidelity, scan wall-clock budget, rescan must reuse, compact report |

### Notes for the next pass

- **P4's premise was wrong in one respect** and worth recording: cache reuse was
  *not* broken. The `cache_reused_files = 0` in the 13-minute scan was correct —
  that was the first scan of that share, so there was nothing to reuse. Verified
  reuse now engages (359/360 on an unchanged rescan) and is covered by a test.
- **Remaining time is now dominated by persistence** (~2–3 s of a 6 s scan:
  findings/occurrence inserts and history writes). Worth attacking only if scans
  grow an order of magnitude; the insert path is already batched.
- P5 items (binary-extraction parallelism, preview sanitize pooling) were left
  alone deliberately — together they are ~4 s of a scan that now takes 5.


---

## 7. Confirmed on the real share (2026-08-28)

Run against the same target as the original 13-minute scan
(`10.10.33.149`, 9 shares, service account `svc_scan`, stored credential ref -
no password handled), through the live `/api/scan` endpoint.

| Run | Files | Wall clock |
| --- | --- | --- |
| Original scan, 2026-08-26 (cold) | 421 | **~13 min (780 s)** |
| After P1-P4, cold cache | 453 | **29.3 s** |
| After P1-P4, warm cache | 453 | **19.2 s** |

**96.2% faster on a cold scan of *more* files** than the original.

Diagnostics from the cold run:
`acl_inproc_paths = 713` (every ACL read served in-process, zero PowerShell
spawns), `owner_resolved = 453`, `owner_missing = 0` - the old scan had 6
unresolved owners, so the fast path is also *more* complete.
`io_workers = 36`, `pipeline_buffer = 72`.

### Accuracy: proven, not assumed

Compared per file against the 2026-08-27 control scan (taken **before** any of
this work) across every field that matters - risk level, risk score, finding
count, reason count, owner string, and ACL principal list:

> **449 of 449 shared files identical. Zero differences.**
> (453 - 449 = 4 files newly added to the share since the control run.)

Totals match exactly: CRITICAL 147, HIGH 207, MEDIUM 82 in both runs; LOW
differs by 4, which is precisely the 4 new files. Detection counts rose in step
with the added files (private_key 123 -> 142, password 124 -> 143).

### One trap worth recording

The first confirmation run reported `CRITICAL = 0` and looked like a serious
scoring regression. It was not: **asset override rules live in the browser and
are sent with each scan request**, and a raw API call omits them. The missing
reason was `MSSP asset override: Credential files are crown-jewel assets`.
Re-running with the rules the console sends reproduced CRITICAL = 147 exactly.
Any future API-level benchmarking must include `asset_overrides` or it will
silently under-score every credential file.
