# Performance Baseline — Local Scan Path (Phase 0 item 12)

## Track P-A incremental result (2026-08-06)

The original cold result below remains the control for per-file full-scan cost. Track P-A
now publishes a fail-on-accuracy-drift comparison with `scripts/incremental_benchmark.py`.
It uses a disposable database and cache, performs an explicit full scan, an unchanged L1
scan, then deletes that disposable L1 cache and proves recovery from the durable baseline.

| Mode | Files | Time | Throughput | Speedup | Content-read ratio | Semantic parity |
|---|---:|---:|---:|---:|---:|---:|
| Explicit full | 360 | 201.952 s | 1.783 files/s | 1× | 100% | control |
| Unchanged, warm L1 | 360 | 13.658 s | 26.357 files/s | 14.79× | **0%** | exact |
| Unchanged, cache deleted / durable DB | 360 | 4.930 s | 73.023 files/s | 40.96× | **0%** | exact |

The semantic gate compares findings, risk, permissions, and sanitized preview while excluding
only volatile per-run timestamps/metrics. Both unchanged paths beat the last release's
published 2.5 files/s result. The durable pass recorded 360 database-baseline hits.

Reproduce:

```powershell
python scripts/incremental_benchmark.py --path enterprise_test_data --json
```

These are developer-host results, not NAS/WAN endpoint-impact certification. The existing
infrastructure caveats below still apply to target CPU, latency, handle, and soak gates.

## Track P-B parallelism (2026-08-10)

All three benchmarks are **semantic-parity gated** (findings/risk/permissions/preview identical
between serial and parallel — a faster scan that changed the answer fails the run). 6-core dev host.

### Serial vs adaptive analysis — `scripts/parallelism_benchmark.py`

| Mode | Files | Time | files/s | Speedup | Parity |
|---|---:|---:|---:|---:|---:|
| Serial (`max_workers=1`, pipeline off) | 360 | 130.1 s | 2.77 | 1× | control |
| Adaptive (`max_workers=0`, pipeline on) | 360 | 121.9 s | 2.95 | **1.07×** | **exact** |

Honest read: only **1.07×**, with pipeline `peak_in_flight=1`. This local corpus is
**collection-bound**, not analysis-bound — the per-file `Get-Acl` subprocess (SCAN-006, see
below) dominates, so the analysis pool is starved and there is little analysis time to overlap.
The adaptive pipeline is *correct* (exact parity) and helps proportionally to how analysis-bound
the workload is (heavy compliance detectors / large text files); it is not a lever for
ACL-collection-bound scans. That is the collector-parallelism story:

### WinRM collector parallelism (in-session runspace pool) — `scripts/winrm_parallel_benchmark.py`

Real per-file work (content + SHA256 + ACL), 300 files, no modeled latency: **~1.8×** (plateaus
near 4 workers; local `Get-Acl`/disk are cheap).

**NAS/WAN modeled** (`--latency-ms` injects a per-file network-round-trip delay — the work the
pool parallelizes — so the win *grows* with latency; 80 files × 100 ms):

| Workers | Time | Speedup | Parity |
|---:|---:|---:|---:|
| 1 | 13.76 s | 1× | control |
| 2 | 7.33 s | 1.88× | OK |
| 4 | 4.82 s | 2.85× | OK |
| 6 | 4.08 s | **3.37×** | OK |

This is the NAS/WAN case the hardware lab would measure: a network-latency-bound endpoint scan is
divided by the worker pool (toward core count, minus fixed pool/dot-source overhead). It is a
**model** (injected `Start-Sleep`), not a measurement on real NAS/WAN hardware, but it exercises
the real runspace-pool code path with exact parity at every worker count. Parallel SMB shares are
the analogous lever for multi-share file servers (mock-tested; same real-target caveat).

## Track P-D detector throughput — `scripts/detector_benchmark.py` (2026-08-10)

The generic catalog ran one regex `finditer` pass per rule (63 passes/file). The necessary-substring
prefilter skips any rule whose mandatory literal (`AKIA`, `BEGIN PRIVATE KEY`, `password`, …) is
absent — **recall-exact** (a skipped rule would have matched nothing). Per-`classify_content` cost:

| Content | Prefilter OFF | Prefilter ON | Speedup | Parity |
|---|---:|---:|---:|---:|
| Content-heavy prose (few anchors present) | 469 ms | 155 ms | **3.0×** | byte-identical |
| Secret-dense (a handful of anchors present) | 229 ms | 93 ms | **2.5×** | byte-identical |

Workload-dependent but robust: the win is largest on ordinary text (most of the 63 rules are
skipped), and even secret-dense content stays ~2.5× because a single file realistically contains
only a handful of the 63 distinct anchor types — the rest are still skipped. It approaches 1× only
in the (unrealistic) limit of content carrying every anchor. Zero recall cost — proven by
`tests/test_regex_prefilter.py` (prefilter ≡ full scan across a per-rule positive corpus + the whole
`enterprise_test_data` set). The four numeric rules (card/IBAN/FIN/phone) have no fixed literal and
always run.

**Harness:** `scripts/perf_baseline.py` (reusable). **Method:** cold scan (persistent cache off) of a generated synthetic dataset through `DSPMDiscoveryEngine`, wall-clock timed, peak Python memory via `tracemalloc`.
**Environment:** this dev host (Windows Server 2019, Python 3.14). Numbers are indicative, not a certified result.

## Result (cold, compliance off)

| Metric | Value |
|---|---|
| Files | 424 |
| Data | 0.31 MB |
| Wall time | **168.7 s** |
| Throughput | **2.5 files/s** |
| Peak Python memory | 33.25 MB |

## Key finding

Throughput is ~**2.5 files/s** on tiny files, so the cost is **per-file overhead, not I/O** (only 0.3 MB was read). This quantifies the assessment's SCAN-006 / SCAN-012: cold scans pay a per-file ACL/permission cost (a `Get-Acl`-style subprocess per file on Windows). Extrapolated:

- 10,000 files ≈ **1.1 hours**
- 1,000,000 files ≈ **4.6 days**

That is not viable at enterprise scale and is the primary Phase 2 target (ACL inheritance/security-descriptor cache + native/persistent session instead of per-file subprocess). Memory is not a concern at this size; the streaming-pipeline work (SCAN-001) matters more for large files than for this file-count-bound case.

## What this baseline does NOT cover (still infrastructure-blocked)

The endpoint-impact certification lab from the assessment (§5.5) needs a real Windows file server / NAS and OS-level telemetry that this environment cannot provide:
- CPU / disk-latency / network / open-handle budgets under load
- foreground p95 latency regression on the target (< 5% gate)
- 1M / 10M-file datasets, backup/AV coexistence, WAN throttling, 24–72 h soak

`scripts/perf_baseline.py` is the reusable core for that lab; it just needs to be pointed at SMB/WinRM targets with a telemetry collector attached.

## Reproduce

```bash
python scripts/perf_baseline.py --files-per-share 12
# larger:
python scripts/perf_baseline.py --path /path/to/corpus --frameworks gdpr,pci_dss
```
