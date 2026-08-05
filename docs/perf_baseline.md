# Performance Baseline — Local Scan Path (Phase 0 item 12)

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
