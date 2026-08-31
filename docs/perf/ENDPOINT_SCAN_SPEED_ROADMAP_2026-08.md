# Endpoint scan performance — two minutes for two files

**Status:** Roadmap. Measured 2026-08-28 against the live endpoint `10.10.33.52`
(DESKTOP-3NRPN49, user profile `hr01`); P1's core mechanism prototyped live.
**Goal:** >=90% faster than today, zero loss of accuracy, zero weakening of the
WinRM security posture.

---

## 1. The problem, measured

| Scan | Files | Wall clock | Per file |
| --- | --- | --- | --- |
| Endpoint scan (incremental rescan) | **2** | **119.5 s** | ~60 s |
| Endpoint scan (first scan) | 1 | 123.7 s | ~124 s |
| File-server SMB scan, same day | 449 | 28.3 s | 0.06 s |

The endpoint collector is ~1,000× slower per file than the SMB collector we
just fixed. The remote profile genuinely holds only 5 files (see §6), so almost
the entire two minutes is **fixed overhead that would be paid identically on a
500-file profile — plus worse** (§4).

## 2. Where the 120 seconds actually go

Attribution from code reading plus live measurements against the real endpoint:

| Operation (measured live) | Cost |
| --- | --- |
| One WinRM `run_cmd` that spawns `powershell.exe` | **1.72–1.83 s** |
| One WinRM `run_cmd` running a `cmd.exe` builtin (no PS spawn) | **0.17 s** |
| → therefore `powershell.exe` cold start alone | **~1.55 s (90% of every call)** |
| `test_connection` | 2.54 s |

**The defect (same species as the SMB Get-Acl finding):** the 37,150-char
remote scan script is base64-encoded (49,536 chars) and uploaded in **1,800-char
chunks — each chunk one `run_cmd` that spawns a fresh `powershell.exe` on the
target**. Delivery of one script = init + 28 appends + materialize + execute =
**31 sequential PowerShell spawns, ~124 HTTP round trips ≈ 53 s** — before the
scan does any scanning.

**The multiplier:** the incremental flow pays that delivery **repeatedly**:

1. Metadata pass — full `scan()` → chunked delivery #1 (~53 s)
2. Content fetch — **one `scan()` per 32 changed paths**, each with its own
   full chunked delivery (~53 s per batch)
3. Analysis — sub-second (classification was never the problem, again)

For the observed scans: 53 s + 53 s + walks/overhead ≈ **~119 s. Fully
explained.** The rescan is no faster than the first scan because delivery,
not content, dominates both.

## 3. Roadmap

### P1 — One-command script delivery *(the 90% itself)* — **prototyped live**

**Implementation update (2026-08-28):** integrated in
`collectors/winrm_endpoint_scanner.py`. The primary path now runs one command and
streams a gzip+base64 payload through WS-Man stdin; transport exceptions fall
back to disk delivery with `cmd.exe` chunk appends and two PowerShell spawns
(initialize + execute). Focused/unit and local real-process parity checks pass;
an integrated re-profile against the live endpoint remains to close P1.

Replace the chunked temp-file upload with **stdin streaming + gzip**:

- gzip + base64 shrinks the script 49,536 → **10,344 chars** (4.8×)
- one `run_command` starts `powershell.exe -EncodedCommand <400-char bootstrap>`
  (read stdin → base64-decode → gunzip → execute ScriptBlock)
- the payload streams via `Protocol.send_command_input` (pywinrm 0.5.0 supports
  it — verified); output returns on the same command

> **Measured prototype against the live endpoint: 3.47 s for delivery + the
> complete remote walk + results.** One PowerShell spawn instead of 31.
> Delivery cost alone: ~53 s → ~2 s (**96%**).

Accuracy is preserved *by construction*: the script content is byte-identical —
only the transport changes. Fallback: keep the legacy chunked path for targets
where stdin streaming fails, with `cmd.exe /c echo` appends (0.17 s/call)
instead of PowerShell spawns even there (53 s → ~7 s worst case).

Bonus hardening: no `dspm_*.b64` temp script artifacts ever touch the target's
disk.

### P2 — One delivery per scan, not one per 32 files

**Implementation update (2026-08-28):** integrated in `backend/app.py`. A cold
incremental scan now detects the empty durable scope before collection and runs
one normal content scan, with no metadata pre-pass. Warm scans retain the
metadata comparison and fetch changed paths in bounded batches of 256 (one
content invocation for ordinary endpoint profiles). Missing/degraded fetches
mark the scan incomplete so an older good baseline cannot be pruned, and changed
archive children survive the metadata merge. Focused orchestration tests pass;
live first-scan and rescan timings remain to close P2.

- **Skip the metadata pre-pass when the baseline is empty** — on a first scan
  everything is new; the pre-pass is pure waste (saves a full delivery).
- **Batch all changed paths into one invocation.** The scan script already
  accepts a path list; fetch changed content in batches of ~256 in a single
  delivery instead of one `scan()` per 32 paths.
- With P1+P2 a rescan is: 1 metadata delivery (~2 s) + 1 content delivery
  (~2 s) + remote walk. A first scan is a single delivery.

### P3 — Compress the response

**Implementation update (2026-08-28):** integrated in
`collectors/winrm_endpoint_scanner.py`. The remote script now emits a versioned
gzip+base64 frame and falls back to byte-equivalent plain JSON if compression is
unavailable. The backend accepts both formats, validates base64/gzip/UTF-8,
enforces `DSPM_WINRM_RESPONSE_MAX_BYTES`, and records wire bytes, JSON bytes, and
the compression ratio in scan diagnostics. A real generated-PowerShell run over
a 100-file local fixture reduced 5,384,598 JSON bytes to 72,804 wire bytes
(73.96×; deliberately repetitive fixture, not a live-endpoint claim). Serial vs.
parallel records remain exact. Live response-envelope and wall-clock measurement
remain to close P3.

Output travels back as plain JSON in ~150 KB WS-Man envelopes (one receive
round trip each, 0.17 s). A 500-file scan with content slices is tens of MB =
hundreds of receive round trips. Emit `gzip+base64` from the remote script and
decode locally: **~5× fewer envelopes**, and file content compresses far better
than 5×. Matters little at 2 files; decisive at 500.

### P4 — Session and negotiation reuse

Every `scan()` re-iterates connection candidates, re-resolves DNS pins, and
builds a fresh `winrm.Session`. Within one scan job, negotiate once and reuse
the working (host, transport, session) across the metadata pass, content
batches, and test-connection — saving ~2.5 s per extra pass and removing
redundant candidate timeouts on hosts with multiple addresses.

### P5 — Guardrails and parity *(after the above)*

- **Test: delivery uses ≤3 remote commands** — the 31-spawn pattern fails the
  suite instantly (mirror of the SMB no-subprocess guardrail).
- **Test: stdin delivery returns byte-identical records** to the legacy path.
- **Wall-clock budget test** for a local-loopback endpoint scan.
- **Diagnostics:** `delivery_ms`, `remote_commands`, `response_envelopes` in
  `scan_diagnostics`, so a regression is visible in every saved report.
- **ACL parity (accuracy gain):** endpoint scans currently run `read_acl:
  false` by default while SMB returns full owner + DACL. With delivery fixed,
  remote Get-Acl in the existing runspace pool is affordable — offer parity.

## 4. Projections

| Scenario | Today | After P1–P4 |
| --- | --- | --- |
| 2-file profile, first scan | 123.7 s | **~5–7 s (95%)** |
| 2-file profile, rescan | 119.5 s | **~5 s (96%)** |
| 500-file profile, first scan | ~53 s + 16 batches × ~55 s ≈ **16 min** (projected) | **~40–70 s** |
| Delivery mechanism alone | ~53 s | **3.47 s (measured)** |

Target ≥90%: met with margin on every row.

## 5. What must NOT change (security posture)

The endpoint collector carries deliberate hardening (assessment 2026-07: both
HIGHs were WinRM). Every phase preserves:

- `resolve_and_pin` target validation (M12) — pinned IPs, rebind refusal
- SSL policy: `DSPM_REQUIRE_WINRM_SSL`, cert validation default `validate`
- Transport order (Kerberos-first option, M11) and NTLM fallback semantics
- Credentials never on a command line — session auth only; the stdin payload
  contains the script text, which holds **no secrets** (paths and flags only)
- Host admission budget slot around the remote session
- Activation/deactivation lifecycle untouched (H1 env-block credential passing)

P1 *improves* the posture: no script artifacts written to the target's disk.

## 6. "It finds only 2 files" — answered

That number is true, not a defect: the scan targets user `hr01`'s Desktop,
Documents and Downloads (resolved correctly on the target), which contain **5
files total**. Three are `desktop.ini` (hidden+system → filtered by policy);
the remaining `.lnk` and `.txt` are the 2 reported. The diagnostics already
record all of this (`visited_files: 5`, `extension_histogram`, `skipped_dirs:
3`); the gap is that the UI doesn't surface it, so a small result looks like a
scanner failure. Roadmap: show "visited / matched / filtered, roots resolved"
in the scan summary so coverage is legible. Widening scope (more roots, deeper
depth, AppData) is a product decision the config already supports — not a
scanner limitation.

## 7. Order of work

1. **P1** — stdin+gzip delivery with legacy fallback (the 90%; mechanism already
   proven live)
2. **P2** — single-delivery incremental flow (kills the ×N multiplier)
3. **P4** — session reuse (small, unlocked by P1/P2 structure)
4. **P3** — compressed response (matters as file counts grow)
5. **P5** — guardrails, diagnostics, ACL parity, coverage UI

Re-profile after each phase — the SMB campaign proved the hot spots move.

---

## 8. P1-P3 review (2026-08-28) - defects found and fixed

A review of the integrated P1-P3 work. Four defects were found; all are fixed
with regression tests. The full suite is green.

### 8.1 Unreachable endpoints paid every timeout twice  *(regression, fixed)*

`_run_ps_file_with_session` fell back to the legacy path on **any** exception.
The legacy path re-dials the **same** session, so a dead socket, an expired
timeout, or rejected credentials failed there identically - the retry only
doubled the time an unreachable endpoint took to report failure, and the
connect loop repeats that per host *and* per transport candidate.

Measured against a genuinely unreachable endpoint with an 8 s timeout:

| | legacy attempts | elapsed |
| --- | --- | --- |
| Before | 1 | **16.0 s** (2x the timeout) |
| After | 0 | **8.0 s** |

At the shipped 30 s default with two host candidates that is 120 s -> 60 s.

Fix: `_is_stdin_capability_error()` classifies the failure. Connection errors
(`ConnectionError`, `ConnectTimeout`, `ReadTimeout`, `SSLError`, `OSError`) and
credential rejections (`InvalidCredentialsError`, `AuthenticationError`,
WS-Man 401/403) propagate immediately so the caller moves to the next
candidate. Only WS-Man/protocol refusals - a target that will not accept
command input - are worth the compatible path; an unrecognised error still
falls back, so genuinely odd targets keep working.

### 8.2 A silent demotion to the slow path was invisible  *(gap, fixed)*

Nothing recorded which delivery path ran. An endpoint that quietly rejected
stdin would take the 31-spawn path forever with no signal in any saved report -
the exact regression this work removes, undetectable in production.

Fix: `delivery_mode` (`stdin_gzip` / `legacy_disk_chunks` / `failed`),
`delivery_ms`, `delivery_remote_commands`, and `delivery_fallback_reason` now
land in `scan_diagnostics` on every scan. This also delivers part of P5 early.

### 8.3 One oversized stdin envelope could demote a large scan  *(gap, fixed)*

The gzip payload was pushed in a single `send_command_input`. P2 batches up to
256 changed paths into one script, so the payload grows with the batch; a
single envelope over the target's `MaxEnvelopeSize` (default ~150-500 KB) is
refused, silently demoting a large scan to the legacy path. The payload is now
sent in bounded 48 KB slices, closing stdin exactly once, still one remote
command.

### 8.4 A truncated scan could prune the baseline  *(data-integrity bug, fixed)*

`complete` gates baseline pruning: a complete scan deletes every baseline
object it did not see. `_finalize_incremental_diagnostics` did not treat
`record_limit_reached` or `worker_errors` as incompleteness markers, so a scan
that stopped at its record cap - or whose remote workers errored - was marked
complete and the pruner deleted objects that were simply **never enumerated**.
They then read as deletions and left the estate until a later full scan re-added
them. P2 checked these markers for the content-fetch pass only, which made the
inconsistency visible.

Both markers are now incompleteness markers in the engine, which covers every
path (metadata pass, content pass, cold single-pass, full scan) and every
collector that reports them.

### 8.5 Verified, not assumed

- **The shipped stdin bootstrap now executes under a real `powershell.exe`.**
  Every other delivery test drives a fake WS-Man protocol, so the bootstrap
  PowerShell string itself had never been run - a syntax error there would
  break every fast-path delivery while the suite stayed green. A new test pipes
  the real gzip payload of a real scan script through the real bootstrap over
  stdin and asserts the records, content, and P3 frame come back correctly.
- The generated scan script is still executed end-to-end by the parity test,
  which also asserts the P3 compressed frame.
- Delivery, response, and remote diagnostics were confirmed to survive into the
  saved report together.
- `hidden_filter_enabled` / `system_filter_enabled` are **selection** filters
  ("match only hidden/system"), not exclusions - confirmed against the script
  logic before concluding anything was wrong with them. They default off, and
  the observed behaviour is correct.

### 8.6 Still open

**Live endpoint verification remains outstanding for all three phases.** The
target `10.10.33.52` went offline during this review (port 5985 stopped
answering; the file server at `10.10.33.149` is still up), so end-to-end
wall-clock numbers on real hardware could not be taken. What is proven so far:
the delivery mechanism at **3.47 s** live (P1 prototype, measured before the
host went down), the bootstrap and generated script under real PowerShell, and
the failure-path timing above. The remaining measurement is a first scan and a
rescan against the live endpoint once it is reachable, to close P1/P2/P3 with
the same rigour as the SMB campaign.
