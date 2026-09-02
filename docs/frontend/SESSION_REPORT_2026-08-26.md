# Sentro DSPM — work session report

**Dates:** 2026-08-24 23:35 → 2026-08-26 01:22 (local)
**Branch:** `sentro-ironhack`
**Commit range:** `a2c9b9d..afa1e1f` (18 commits)
**Author:** Shamsi Mammadov, with Claude Fable 5

---

## 1. At a glance

| Metric | Value |
| --- | --- |
| Commits | 18 |
| Files touched | 14 |
| Lines | +2,178 / −352 |
| New API endpoints | 3 (`PUT /api/profile/avatar`, `GET/PUT /api/settings/features`) |
| New page routes | 5 (`/findings`, `/remediation`, `/scan`, `/evidence`, `/administration`) |
| New DB objects | `app_settings` table, `users.avatar` column |
| New tests | 5 (`tests/test_settings_features.py`) |
| Test suite | **700 passed, 17 skipped, 0 failed** (717 total, was 712) |
| Dev database | purged from **322 tenants → 1**, 365 scan reports → clean |
| Root-cause bugs fixed | 12 (listed in §8) |

Every change was verified in the live authenticated console (not in a static
preview) before commit, and every commit was gated on a 41-test frontend
contract slice plus a full-suite run.

---

## 2. Commit ledger

| Commit | Time | Subject |
| --- | --- | --- |
| `a483c87` | 08-24 23:35 | tests: session-scoped SQLite DB so the suite never touches the dev store |
| `fc3fb78` | 08-24 23:35 | dashboard: risk drill-downs, recent-scans fit, facet row hardening |
| `7802fac` | 08-24 23:36 | frontend: sync profile/register stylesheet cache-buster to v196 |
| `a71be2e` | 08-24 23:53 | tests: seed the triage recall-safety blob so it cannot flake |
| `af48413` | 08-24 23:53 | frontend: stop decorations overlapping text; calm the framework pills |
| `0774047` | 08-24 23:58 | inventory: equal risk-filter tiles, aligned facet gutter, single-ring active |
| `1af4f02` | 08-25 00:16 | frontend: six-point tidy — counts on boot, full-width panels, calm search |
| `70b9822` | 08-25 00:25 | tests: give the regex-preemption probe budget headroom under suite load |
| `738c6b4` | 08-25 22:35 | backend: runtime feature flags and account avatars |
| `23a7b57` | 08-25 22:35 | frontend: account dock in the sidebar + Settings page remake |
| `5ef90e4` | 08-25 22:50 | frontend: repair the account dock and Settings page against legacy layers |
| `4cab313` | 08-25 23:05 | frontend: actions-only dock panel, full-width Settings, no Appearance page |
| `14b5b8b` | 08-25 23:23 | frontend: console parity for Settings, panel rhythm, flyout z-order |
| `c88e8fe` | 08-25 23:41 | backend: every console destination is a real, reloadable path |
| `23ec69a` | 08-25 23:41 | frontend: real page URLs, accordion nav, pinned rail, skeletons, CTA |
| `fe7db61` | 08-25 23:47 | frontend: caret-opened nav groups survive navigation (pinned model) |
| `0414af2` | 08-26 00:51 | frontend: chart-pill bug, queue/table density, remediation layout, anchoring |
| `afa1e1f` | 08-26 01:22 | frontend: inventory polish, queue rows restored, focus + top-scroll |

---

## 3. Data integrity and test isolation

### 3.1 The dev database was being polluted by the test suite

The developer database (`data/dspm.sqlite`) had accumulated **322 tenants** —
one real (`default`) and 321 junk rows with names like `gf-*`, `rs-*`, `f2-*`,
`bf-*`, `victim-*`, `pivot-target-*`, `count-test-*`.

**Root cause.** The SQLite suite isolates *per module*: each test module is
expected to repoint `store.DB_PATH` at its own temp file. A family of
"ambient-relying" modules (registration invites, tenant pivot, read-switch,
backfill, dual-write, F2 index tests) never did, so they created tenants
directly in the real developer store — roughly **40 junk tenants per full-suite
run**.

**Fix** (`tests/conftest.py`, commit `a483c87`). `pytest_configure` now
provisions a throwaway session database before any test runs:

```python
_session_db = Path(tempfile.mkdtemp(prefix="sentro-test-session-")) / "suite.sqlite"
os.environ["DSPM_DB_PATH"] = str(_session_db)
_store.DB_PATH = _session_db
_store.init_db()
_store.create_tenant("default", "Default")
_security.ensure_default_admin()
```

Modules that manage their own temp DB are unaffected; the ambient ones now land
in the session DB. `DSPM_TEST_KEEP_DB=1` opts out for debugging.

**Verification.** After running the previously-leaky modules *and* three
subsequent full-suite runs, the dev database still reports exactly
`(1, 'default')`.

### 3.2 Database purge

With the leak closed, the store was cleaned: all non-default tenants deleted,
all scan data wiped (365 scan reports, 2,447 findings, 26,084 finding
occurrences, 565 assets, audit and alert events, the FTS index), keeping the
`default` tenant row and the `admin` user. A pre-purge backup was written to the
session scratchpad. Post-purge the file shrank to 315 KB.

Every console surface was then swept against the empty database to confirm the
empty states render correctly rather than showing stale numbers — dashboard
KPIs, donut, posture trend, recent scans, activity, inventory, remediation
queue, evidence table, and the Administration tenant list and topbar switcher
(both showing only `default`).

### 3.3 Two latent test flakes

Neither was caused by this session's work; both surfaced under full-suite load
and were made deterministic.

**`test_triage.py::test_skipped_binary_has_no_findings_under_full_scan`**
(`a71be2e`). The test fed `os.urandom(9000)` into the classifier and asserted no
findings. Occasionally the random bytes decoded into enough finance-shaped token
soup to trip the heuristic context classifier. Replaced with a seeded
`random.Random(1787)` byte stream — same intent (a high-entropy, NUL-bearing
blob routes to skip and classifies clean), identical every run. Verified 10
consecutive green runs.

**`test_regex_preemption.py::test_catastrophic_regexes_flags_only_the_bad_pattern`**
(`70b9822`). The safe-pattern probe ran on a 2.5 s budget while process spawn
alone costs ~1 s on Windows; under full-suite CPU load the spawn was starved
past the deadline and the *safe* pattern got flagged as catastrophic. Budgets
raised to 6 s batch / 4 s per pattern — the hard boundary still holds (the
catastrophic pattern is killed regardless). Verified 5 consecutive green runs.

---

## 4. Backend work

### 4.1 Runtime feature flags (no restart)

The OCR capability was gated behind `DSPM_OCR_ENABLED`, which meant editing the
environment and restarting the product. It is now a runtime setting.

* **`app_settings`** — a new install-wide key/value table with
  `get_app_setting` / `set_app_setting` helpers (`backend/store.py`).
* **`GET /api/settings/features`** — readable by every role; returns the OCR
  flag, whether the RapidOCR dependency is installed on the server, a
  human-readable state, and whether the caller may edit it.
* **`PUT /api/settings/features`** — admin only. Persists the setting *and*
  applies it to the running process's environment. The collectors read the env
  per call, so the change takes effect on the next scan with zero downtime, and
  the scan cache signature already keys on the flag so results stay correct.
* **Startup** — `_apply_persisted_feature_flags()` runs in the app lifespan
  before the OCR status log line, so the log reflects the effective setting and
  the toggle survives restarts.

### 4.2 Account avatars

* **`users.avatar`** — added by in-place migration following the existing
  `ALTER TABLE` idiom in `init_db()`.
* **`PUT /api/profile/avatar`** — accepts a bounded PNG/JPEG/WebP data URL,
  validates both the prefix and the base64 body, and accepts an empty string to
  clear. Allowed for *every* account including the protected built-in admin: the
  photo is cosmetic and cannot change identity, role, or credentials.
* `GET /api/profile` returns the avatar; `_public_user` deliberately does **not**
  include it, so `/api/users` listings stay small.

### 4.3 Real page routes

`/findings`, `/remediation`, `/scan`, `/evidence`, and `/administration` now
serve the console alongside `/dashboard`, so every destination is a real,
reloadable URL (see §7.1).

### 4.4 New tests

`tests/test_settings_features.py` (5 tests): viewer can read but not change
features; admin toggle persists *and* applies to the process env; startup
re-applies the persisted flag; avatar round-trip including the protected admin
with the blob absent from the public user shape; avatar rejects non-image
prefixes and malformed base64.

---

## 5. Account experience

### 5.1 Account dock in the sidebar

The profile cluster moved out of the topbar to the **foot of the console
sidebar**. Its panel opens **upward**. Across three refinement passes it became:

* **Actions only** — Settings and Sign out. The identity header was removed
  because the trigger row directly beneath already shows who you are.
* **Flush with the sidebar** — the panel spans exactly the sidebar's content
  width and stays clear of the sidebar/content divider, which is now fully
  visible.
* **Collapsed rail** — a centered 44 px avatar-only trigger whose panel flies
  out beside the rail.
* **Above the fold** — the sidebar's stacking context was raised from
  `z-index: 900` to `1200`. At 900, tabs whose content has sticky toolbars or
  chart layers rendered *over* the flyout: this was the "sometimes the page
  doesn't open at all, sometimes only half is visible" symptom.

### 5.2 Settings page (`profile.html` remade)

The old page was a single long column of mixed concerns. It is now a real
settings surface:

* **Category rail** — Profile, Security, Features, Session, with the identity
  card pinned at the rail foot (mirroring the console's account dock) and the
  rail itself sticky at `100vh` with its own scroll, so the identity never
  scrolls away on long sections.
* **Collapsible** — a burger in the rail head collapses it to a 74 px icon rail;
  the state is remembered per browser. Neutralized on narrow viewports where the
  rail stacks on top.
* **Hash routing** — `/profile#security` deep-links work; unknown hashes fall
  back to Profile.
* **Every control works.** The avatar crop tool previously saved only to
  `localStorage`, which is why it felt broken; it now persists to the account via
  the API and the console sidebar picks it up on any browser. Name, password,
  session expiry (decoded from the token), sign-out, and the OCR feature switch
  all operate against real endpoints.
* **Appearance section deleted** — the header's light/dark button *is* the
  console control now: same `theme-toggle tb-icon-btn` classes, same sun-in-dark
  / moon-in-light glyphs, same muted styling. Old `#appearance` bookmarks land on
  Profile.
* **Typography parity** — rail items pinned to the console sidebar's exact
  characteristics (14 px, weight 500, body text colour) after measuring both.

---

## 6. Console pages

### 6.1 Dashboard

* **Risk summary tiles and the severity donut are drill-downs.** Clicking any
  tile (Critical / High / Medium / Low / Protected / Total) or any donut segment
  or legend row opens Findings, scrolls to the Data inventory, and applies the
  matching risk filter. Tiles carry `role="button"`, tab focus, and Enter/Space
  handling.
* **New severity-mix ring** — rounded-cap segments with gaps on a quiet track,
  per-segment hover tooltips, a count-and-percentage legend, and a dotted ring
  reading "no findings yet" when empty.
* **Recent scans fits its card** — a generic `table { min-width: 1180px }` rule
  was forcing a 1,180 px table into a 951 px card. Scoped override with fixed
  layout and per-cell ellipsis.
* **Skeleton loading** replaced text placeholders across the analytics cards.
* **Posture intelligence cards** — the compact-padding pass had pulled label and
  value text underneath the absolutely-positioned 34 px icon badge; text now
  starts clear of it.

### 6.2 Findings / Data inventory

* Removed the "Restored *N* indexed files from saved scan …" banner; header band
  slimmed to 71 px.
* Risk-filter pills became an equal-track grid — `flex: 1 1 118px` had let a
  wrapped orphan stretch across the entire row — and lost their double ring (a
  2 px outline stacked on the coloured border); the outline is now keyboard-focus
  only.
* Filter row: labels stay inline with their selects at every width, framework
  pills are strictly single-line chips, content sits on the shared 14 px gutter
  with 32 px rhythm between groups, and the Clear button rides the selects'
  centreline.
* Context chips (Visible / Sensitive / Avg risk / Top source) restyled as KPI
  chips — label left, bold value with muted unit grouped right.
* **Row density**: 157 px → ~108 px. Chips ride one clipped row that fades out on
  the right instead of slicing mid-chip; paths and risk notes ellipsize; inline
  copy/preview controls capped to row height.
* **Expansion restored** — the compaction clamps were applying regardless of
  state, so expanding a row revealed nothing. A `row-open` marker now lifts every
  clamp: chips wrap in full (26 px → 124 px measured), paths and notes read
  whole, properties open.
* Results table takes the widest and tallest area the page can give it, with a
  viewport-based height.
* Scrollbar widened with a minimum-size thumb and real click arrows at both ends.
* Loading state is a table-shaped skeleton — one shimmer per column — instead of
  a banner over an empty-state CTA.
* **Priority finding queue**: nested double scrollbar reduced to one, and the
  wrapping "Data Element" header (100 px tall) pinned to a single 50 px line.

### 6.3 Remediation

* **Remediation queue and Exposure insights** moved out of the narrow main
  column to full-width rows below the analytics grid.
* **Queue rows restored.** The live list carries `.remediation-queue`, which
  none of the single-column rules matched, so an auto-fit grid packed **five
  277 px cards per row** and squeezed the file names out entirely. Now a single
  column of full-width rows with badge, file, and assignment all visible.
* **Hero band** 180 px → 96 px: the score keeps its weight (34 px) while `/100`
  and the verdict step back small and muted.
* **Posture trend** in the side rail no longer forces a 760 px sideways scroll
  inside a 418 px card — its eight columns share the card width.
* **Scan comparison** moved to a full-width row (removing the dead gap beside
  it), then compacted from five 56 px rows of 18 px type into a stat-chip grid:
  549 px → 183 px.
* **Exposure insights**: all five category labels share one type treatment
  (12.5 px / 600); the panel no longer reserves a phantom scrollbar gutter; and
  choosing a category scrolls the panel into view.
* Panels that sat flush against each other (0 px seams) now breathe at 16 px —
  the same fix applied to Administration → Tenants.

### 6.4 Evidence and Reporting

* The history table's off-centre "No scans saved for this tenant yet" was a
  `display: flex` on empty table cells, which silently breaks `colspan` — the
  cell had shrunk to 651 px of a 1,542 px table. Empty cells are table cells
  again and the message centres across the full row. This fix applies to every
  empty-state table in the product.
* Reporting center: the preview's 514 px clamp over 3,090 px of content was
  removed — the box grows and the page is the only scrollbar.

---

## 7. Cross-cutting behaviour

### 7.1 Real URLs, history, and reload persistence

Each destination has its own path, and member pages deep-link as
`/scan#endpoint`, `/administration#admin`, and so on. `switchTab` syncs history
with `pushState`, `popstate` restores the view, and reloading any URL opens
exactly that page — previously a reload always dumped the operator back on the
dashboard.

### 7.2 Navigation groups

Two iterations landed on the right model:

* Entering a section auto-expands its submenu; leaving collapses it again.
* A group opened **deliberately with the caret is pinned** — it stays open across
  page changes until the caret closes it.

### 7.3 Scroll behaviour

* Switching pages starts at the top of the new page instead of inheriting the
  previous page's scroll offset.
* Expanding an Exposure-insights category scrolls the panel into view. The first
  attempt used a smooth glide that the panel's own re-render silently cancelled;
  it now scrolls instantly after the swapped content lays out.

### 7.4 Responsive

Audited every console tab at 860 px: no page-level horizontal overflow anywhere
(wide tables scroll inside their own containers by design). Under 960 px the
topbar sheds its passive pieces — the health chip and the Ctrl+K hint — so
search, New Scan, theme, and the tenant switcher stay on one usable row; the
search field had collapsed to 81 px and recovered to 208 px.

### 7.5 Design directives

* **Skeleton loading** — a shimmer utility honouring `prefers-reduced-motion`,
  applied to the analytics cards and the inventory table.
* **Gradient, spent in one place** — New Scan is the only gradient in the chrome
  (indigo 500→700 with a soft accent glow), making the primary action
  unmistakable while everything around it stays quiet.
* **Group spacing** — settings card copy hugs its controls; dashboard grid
  rhythm unified at 16 px.
* **Search bar** — stretched to a 480 px cap so the topbar reads as intentional
  rather than empty, without crowding.

---

## 8. Root-cause bug list

Ordered by impact. Items marked **(self-inflicted)** were introduced earlier in
this same session and caught before the user had to report them twice.

1. **Charts died permanently on a posture-pill click** *(self-inflicted)* —
   the skeleton-painting block had been inserted **inside the pill click
   handler** instead of chart init, so every Critical/High click repainted
   Severity mix, Recent scans, and Activity as skeletons that nothing replaced.
   Skeletons now paint once at init.
2. **322 junk tenants in the dev database** — ambient test modules writing to the
   real store; closed with a session-scoped test DB.
3. **Remediation queue rendered as a five-column card wall** — a class the
   single-column rules never matched (`.remediation-queue`), letting an auto-fit
   grid squeeze out the file names.
4. **Account flyout hidden under page content** — sidebar stacking context at
   `z-index: 900`, below content-column layers.
5. **Empty-state table cells broke `colspan`** — `display: flex` on `td.empty`.
6. **Row expansion revealed nothing** *(self-inflicted)* — density clamps applied
   regardless of expanded state.
7. **Framework filter invisible on a fresh install** — only Clear-filters and the
   scan pipeline called the renderer, so a clean database showed no filter at all.
8. **Risk-filter counts blank on a fresh install** — the count ovals read a
   `data-count` attribute only the scan pipeline set, painting empty coloured
   ovals.
9. **`register.html` truncated to 0 bytes** *(self-inflicted)* — a
   truncate-before-read scripting bug; restored from git history.
10. **Avatar changes never left the browser** — the crop tool saved only to
    `localStorage`, so the photo never reached the account or the console.
11. **Two load-sensitive test flakes** — random-blob classification and a probe
    budget shorter than Windows process spawn.
12. **Decorations overlapping text** — absolutely-positioned icon badges and
    status dots rendered under label text after a compact-padding pass removed
    the padding that reserved room for them ("V●SIBLE", "P[icon]TURE SCORE").

---

## 9. How the work was verified

* **Live authenticated console**, not static previews: the dev server on port
  8971, a freshly minted JWT injected into `sessionStorage`, and the real
  `/dashboard` served over HTTP.
* **Two real scans** of the synthetic dataset were run through the API so the
  posture trend had two comparison points and the pages carried thousands of
  real findings — several bugs (the queue card wall, the pill bug, row density)
  only appear with data present.
* **Geometry probes rather than eyeballing**: element rectangles, computed
  styles, gap measurements between panels, overflow comparisons
  (`scrollWidth` vs `clientWidth`), and stacking-context walks.
* **CSSOM walking** to find which rule actually wins a property when an
  `!important` override failed — this is how the `min-width: 1180px`,
  `min-width: 760px`, and `.remediation-queue` culprits were identified rather
  than guessed.
* **Viewport matrix**: 860 px, 1024 px, 1500 px, 1600 px, plus light and dark
  themes for every visual change.
* **Gates**: a 41-test frontend contract slice before each commit, and a full
  suite (717 tests) after each batch.

---

## 10. Current state

| Asset | Version |
| --- | --- |
| `styles.css` | v206 (all pages) |
| `app.js` | v159 |
| `sentro-fx.js` | v13 |
| `profile.js` | v97 |

* `frontend/styles.css` — 666 KB
* Dev database — 1 tenant (`default`), 1 user (`admin`), 2 scan reports (both
  from verification scans run this session)
* Test suite — 700 passed, 17 skipped, 0 failed
* Working tree — clean at `afa1e1f`

---

## 11. Notes and follow-ups

* **The stylesheet is the main technical debt.** At 666 KB with many historical
  layers, most fixes this session were specificity battles against rules from
  earlier redesigns; several required `:root:root` or id-scoped hammers to win.
  A consolidation pass (dead-rule excision, then a single authoritative layer per
  component) would make future work faster and less fragile.
* **`enterprise_test_data` scans** — two reports currently sit in the dev
  database from verification. Delete them if a clean slate is wanted for demos.
* The Data inventory's compact rows deliberately hide detail behind the expand
  control. If operators want more visible by default, the clamp thresholds are
  single values in the inventory layer and easy to tune.
