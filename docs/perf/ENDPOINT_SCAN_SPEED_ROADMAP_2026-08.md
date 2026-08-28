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

- **Skip the metadata pre-pass when the baseline is empty** — on a first scan
  everything is new; the pre-pass is pure waste (saves a full delivery).
- **Batch all changed paths into one invocation.** The scan script already
  accepts a path list; fetch changed content in batches of ~256 in a single
  delivery instead of one `scan()` per 32 paths.
- With P1+P2 a rescan is: 1 metadata delivery (~2 s) + 1 content delivery
  (~2 s) + remote walk. A first scan is a single delivery.

### P3 — Compress the response

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
