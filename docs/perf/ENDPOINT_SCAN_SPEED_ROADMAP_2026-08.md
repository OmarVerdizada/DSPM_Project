# Endpoint scan performance — two minutes for two files

**Status:** P1–P5 implemented, reviewed twice, and regression-tested (760 passed,
17 skipped, 0 failures). Every mechanism is verified; the one thing still
outstanding is an integrated wall-clock run against the live endpoint, which
went offline mid-review — see §10.
**Goal:** ≥90% faster, zero loss of accuracy, zero weakening of the WinRM
security posture.

---

## 1. The problem, measured

| Scan | Files | Wall clock | Per file |
| --- | --- | --- | --- |
| Endpoint scan (incremental rescan) | **2** | **119.5 s** | ~60 s |
| Endpoint scan (first scan) | 1 | 123.7 s | ~124 s |
| File-server SMB scan, same day | 449 | 28.3 s | 0.06 s |

The endpoint collector was ~1,000× slower *per file* than the SMB collector.
The target profile genuinely holds only 5 files (§8), so almost the entire two
minutes was **fixed overhead** — paid identically on a 500-file profile, and
then multiplied (§2).

## 2. Where the 120 seconds went

Attribution from code reading plus live measurement against the real endpoint:

| Operation (measured live) | Cost |
| --- | --- |
| One WinRM `run_cmd` that spawns `powershell.exe` | **1.72–1.83 s** |
| One WinRM `run_cmd` running a `cmd.exe` builtin (no PS spawn) | **0.17 s** |
| → therefore `powershell.exe` cold start alone | **~1.55 s (90% of every call)** |
| `test_connection` | 2.54 s |

**The defect** (same species as the SMB `Get-Acl` finding, one layer up): the
37,150-char remote scan script was base64-encoded to 49,536 chars and uploaded
in **1,800-char chunks — each chunk one `run_cmd` spawning a fresh
`powershell.exe` on the target**. One delivery = init + 28 appends +
materialize + execute = **31 sequential PowerShell spawns, ~124 HTTP round
trips ≈ 53 s**, before any scanning happened.

**The multiplier:** the incremental flow paid that delivery repeatedly — once
for the metadata pass, then **once per 32 changed paths**. Analysis itself was
sub-second; classification was never the problem, again.

53 s + 53 s + walk ≈ **119 s. Fully explained.** The rescan was no faster than
the first scan because delivery, not content, dominated both.

---

## 3. What shipped

### P1 — One-command script delivery *(the 90% itself)*

The chunked temp-file upload is replaced by **stdin streaming + gzip**:

- gzip + base64 shrinks the script 49,536 → **10,344 chars** (4.8×)
- one `run_command` starts `powershell.exe -EncodedCommand <bootstrap>` that
  reads stdin → base64-decodes → gunzips → executes the ScriptBlock
- the payload streams via `Protocol.send_command_input` in bounded 48 KB slices
- a legacy disk path remains for targets that refuse command input, but now
  appends with `cmd.exe` (0.17 s/call) instead of PowerShell spawns

> **Measured live: 3.47 s** for delivery + the complete remote walk + results,
> against ~53 s for delivery alone. **One** PowerShell spawn instead of 31.

Accuracy is preserved *by construction* — the script bytes are identical, only
the transport changes. Bonus hardening: no `dspm_*.b64` artifact is ever written
to the target's disk.

### P2 — One delivery per scan, not one per 32 files

- **The metadata pre-pass is skipped when the baseline is empty.** On a first
  scan everything is new, so the pre-pass was pure waste — a whole delivery.
- **Changed paths batch 32 → 256 per invocation**, one content delivery for an
  ordinary profile.
- Degraded or missing fetches mark the scan incomplete so a good older baseline
  cannot be pruned; changed archive children survive the metadata merge.

A rescan is now: one metadata delivery + one content delivery. A first scan is
a single delivery.

### P3 — Compress the response

The remote script emits a versioned `DSPM-GZIP-BASE64-V1:` frame, falling back
to byte-equivalent plain JSON where compression is unavailable. The collector
accepts both, validates base64/gzip/UTF-8, enforces
`DSPM_WINRM_RESPONSE_MAX_BYTES` **before** decompressing (zip-bomb safe), and
records wire bytes, JSON bytes, and ratio.

> A real generated-PowerShell run over a 100-file fixture reduced **5,384,598
> JSON bytes to 72,804 wire bytes (73.96×)**. The fixture is deliberately
> repetitive — treat it as a mechanism proof, not a live-endpoint claim.

### P4 — Session and negotiation reuse

One scan job owns one scanner, which retains the first successful
`(host, transport, Session)` binding across the metadata pass and every content
batch; `test_connection()` shares it too. Connection candidates resolve once per
scanner/host.

The reuse boundary is deliberately narrow:

- the binding is **job-local, never process-global** — credentials and session
  state never outlive the request that supplied them;
- scan-only fields (paths, filters, read/hash/ACL modes) reuse the binding, but
  a host, domain-qualified username, password, SSL, port, certificate
  validation, or transport-policy change forces a fresh negotiation;
- `resolve_and_pin` validation still runs before any session is created;
- a failed cached session is discarded and the normal candidate/transport
  failover renegotiates — safe because the scan scripts are read-only;
- the host-admission slot still surrounds every remote scan command.

### P5 — Guardrails, diagnostics, and ACL parity

**Guardrails.** Primary delivery must stay within
`WINRM_FAST_DELIVERY_COMMAND_BUDGET` (3) remote commands — the old 31-command
upload fails the suite instantly. Stdin and legacy delivery must return
byte-identical records. A loopback scan must finish inside a wall-clock budget.

**Diagnostics** now in every saved report: `delivery_mode`, `delivery_ms` (job
total), `delivery_last_ms`, `remote_commands`, `response_envelopes`,
`delivery_invocations`, `delivery_fallback_reason`, plus `session_reused`,
`session_creations`, `session_negotiations`, `session_failovers`, and
`connection_transport`. Receive envelopes are counted from pywinrm's raw WS-Man
pages, so the number is real rather than assumed.

**ACL parity — an accuracy gain, and it is free.** Endpoint scans previously ran
`read_acl=False` while SMB returned full owner + DACL. It now defaults **on** at
the API, collector, and UI. Local endpoint scans compute owner and DACL through
the same Win32 reader P1 built for the SMB campaign.

> **Measured:** 150 files through the real generated script — `read_acl=False`
> **2.32 s**, `read_acl=True` **2.01 s**. The ACL cost is below the noise floor,
> because the reads happen inside the single remote session's runspace pool
> rather than as separate round trips.
>
> **End-to-end (local endpoint, real API path):** 40/40 records carry a full
> DACL (owner + 4 principals + 4 permissions); findings are **identical** with
> ACLs on and off; a warm rescan keeps 40/40 DACLs through cache reuse.

ACL read failures use `-ErrorAction SilentlyContinue`, so they degrade to an
empty DACL rather than throwing — they never poison `worker_errors` and so never
wrongly mark a scan incomplete (§6.3).

---

## 4. Projections

| Scenario | Before | After P1–P4 |
| --- | --- | --- |
| 2-file profile, first scan | 123.7 s | **~5–7 s (95%)** |
| 2-file profile, rescan | 119.5 s | **~5 s (96%)** |
| 500-file profile, first scan | ~16 min (projected) | **~40–70 s** |
| Delivery mechanism alone | ~53 s | **3.47 s (measured)** |

Target ≥90%: met with margin on every row. The 2-file rows await the live
confirmation in §10.

---

## 5. Review round 1 (P1–P3) — defects found and fixed

### 5.1 Unreachable endpoints paid every timeout twice *(regression)*

The stdin fallback ran on **any** exception, but the legacy path re-dials the
**same** session — a dead socket, a timeout, or a rejected password fails there
identically. The retry only doubled the time an unreachable endpoint took to
fail, once per host *and* per transport candidate.

| | legacy attempts | elapsed |
| --- | --- | --- |
| Before | 1 | **16.0 s** (2× the 8 s timeout) |
| After | 0 | **8.0 s** |

At the shipped 30 s default with two host candidates: 120 s → 60 s.
`_is_stdin_capability_error()` now classifies failures — connection errors and
credential rejections propagate immediately; only WS-Man capability refusals
take the compatible path, and an unrecognised error still falls back so odd
targets keep working.

### 5.2 A silent demotion to the slow path was invisible *(gap)*

Nothing recorded which delivery path ran, so an endpoint quietly rejecting stdin
would take the 31-spawn path forever with no signal in any report — the exact
regression this work removes, undetectable in production. The delivery
diagnostics in §3 (P5) fixed this.

### 5.3 One oversized stdin envelope could demote a large scan *(gap)*

The payload was pushed in a single `send_command_input`. P2 batches up to 256
paths into one script, so a single envelope can exceed the target's
`MaxEnvelopeSize` (~150–500 KB) and be refused — silently demoting a large scan.
It now streams in bounded 48 KB slices, closing stdin exactly once.

### 5.4 A truncated scan could prune the baseline *(data-integrity bug)*

`complete` gates baseline pruning: a complete scan deletes every baseline object
it did not see. `record_limit_reached` and `worker_errors` were **not**
incompleteness markers, so a scan that stopped at its record cap — or whose
remote workers errored — was marked complete and the pruner deleted objects that
were simply **never enumerated**. They then read as deletions and vanished from
the estate until a later full scan re-added them. Both are now markers in the
engine, covering every path and collector.

---

## 6. Review round 2 (P4–P5) — findings

### 6.1 A UI change that would never have reached users *(fixed)*

`frontend/app.js` gained the coverage summary (`Filtered:`) but
`frontend/index.html` still requested `app.js?v=172` — the version last bumped
by an unrelated commit. Every returning browser would have kept the stale bundle
and shown no coverage line. Bumped to `v=173`.

### 6.2 Dead counter *(fixed)*

`_legacy_remote_commands` was incremented in three places and read nowhere once
delivery accounting moved to `_delivery_remote_commands_current`. Removed.

### 6.3 Checked and found correct — no change made

Verifying rather than assuming mattered here; each of these looked like a bug:

- **ACL default flip to `True`** — measured free (§3, P5) rather than assumed
  affordable. Justified.
- **ACL failures vs. the §5.4 completeness gate** — a plausible bad interaction:
  if remote `Get-Acl` failures reached `worker_errors`, enabling ACLs by default
  would mark every scan on a restrictive host incomplete and stop pruning
  forever. They use `-ErrorAction SilentlyContinue` and degrade to an empty
  DACL, so the interaction does not exist.
- **Domain in the session identity** — `_username()` is domain-qualified, so a
  domain change does force renegotiation.
- **Scanner config mutation vs. the heartbeat thread** — the heartbeat only
  touches `job.progress`/`cancel_requested`, never the scanner. No race.
- **Envelope-counting loop** — suspected untested; it is covered, including the
  `WinRMOperationTimeoutError` path and multi-page accumulation.
- **`hidden_filter_enabled` / `system_filter_enabled`** — these are *selection*
  filters ("match only hidden/system"), not exclusions. A test harness that
  treated them as exclusions produced a false "ordinary files are being
  filtered" alarm. The product is correct; the harness was wrong.

---

## 7. Verified, not assumed

| Check | Result |
| --- | --- |
| Shipped stdin bootstrap executed by a **real `powershell.exe`** | Expands the gzip payload, runs the scan, returns correct records and content |
| Generated scan script executed end-to-end (parity test) | Serial vs. parallel byte-identical; emits the P3 frame |
| Delivery + response + remote diagnostics in one saved report | All present together |
| Record parity across delivery paths | Stdin and legacy byte-identical |
| ACL parity end-to-end on a real corpus | 40/40 DACLs; findings identical with ACLs on and off; warm reuse preserves them |
| Failure-path latency after the §5.1 fix | 16.0 s → 8.0 s, 0 legacy retries |
| Full suite | **760 passed, 17 skipped, 0 failures** |

Two gaps of the "never actually executed" kind were closed during review: the
bootstrap PowerShell (round 1) and the raw envelope loop (confirmed covered in
round 2). Both would have failed only against real hardware while the suite
stayed green.

---

## 8. "It finds only 2 files" — answered

True, not a defect. The scan targets `hr01`'s Desktop, Documents and Downloads,
which hold **5 files**; three are `desktop.ini` (hidden + system, filtered by
policy), leaving the `.lnk` and `.txt` that were reported. The diagnostics
always recorded this (`visited_files: 5`, `extension_histogram`,
`skipped_dirs: 3`) — the real gap was that the UI never showed it, so an honest
small result looked like a scanner failure.

The scan summary now reads **Visited / Matched / Filtered / Roots**, so coverage
is legible without opening a report. Widening scope (more roots, greater depth,
AppData) remains a product decision the config already supports.

---

## 9. What must NOT change (security posture)

Both HIGH findings in the 2026-07 assessment were WinRM. Every phase preserves:

- `resolve_and_pin` target validation (M12) — pinned IPs, rebind refusal
- SSL policy `DSPM_REQUIRE_WINRM_SSL`; certificate validation defaults to
  `validate`
- Transport order (Kerberos-first option, M11) with NTLM fallback semantics
- Credentials never on a command line — session auth only. The stdin payload
  carries the script text, which holds **no secrets** (paths and flags only)
- Host admission budget around every remote scan command
- Activation/deactivation lifecycle untouched (H1 env-block credential passing)
- P4's session binding is job-local and never crosses a host, credential, or
  transport boundary

P1 *improves* the posture: no script artifact is written to the target's disk.

---

## 10. Still open

**An integrated live wall-clock run against the endpoint.** The target
`10.10.33.52` went offline during review (port 5985 stopped answering; the file
server at `10.10.33.149` stayed up), so the combined first-scan and rescan
numbers on real hardware could not be taken.

Proven so far: the delivery mechanism at **3.47 s live**, the bootstrap and
generated script under real PowerShell, ACL parity end-to-end on a real corpus,
the failure-path timing, and 760 green tests. The remaining measurement is one
first scan plus one rescan once the host is reachable, to close the campaign
with the same rigour as the SMB one.

**Optional next:** `DSPM_WINRM_WORKERS` above the current cap is the last knob
if a large profile is still collector-bound; re-profile before turning it.

---

## Commit trail

| Phase | Commit |
| --- | --- |
| Roadmap, measured attribution, live P1 proof | `c097408` |
| P1–P3 + round-1 review fixes | `238aad7` |
| P4–P5 + round-2 review fixes | `HEAD` |
