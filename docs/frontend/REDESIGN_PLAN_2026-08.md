# Sentro DSPM — Frontend Redesign Plan

**Date:** 2026-08-23 · **Status:** proposal for review (no code changed yet)
**Brief (operator's words):** professional, user-friendly, compact, useful. The design is good but
complicated because the product has many features. Remove the informational main page — keep only
login and dashboard. Colors may change.

**Design stance:** Sentro is an on-prem operator console for security admins and MSSP analysts on
long monitoring sessions. Its job is a loop: *find exposure → triage → prove*. Every visual decision
below is judged against that loop. This is an **evolution of the existing identity** (the teal is
kept and disciplined), not a rebrand, and **not a rewrite** — the vanilla HTML/CSS/JS stack stays.

---

## 1. Current state (measured, not guessed)

### Pages & routes

| Route | Serves | What it is |
|---|---|---|
| `/`, `/login` | `frontend-landing/dist` (fallback `login.html`) | **A second frontend**: React + Vite + Tailwind + GSAP marketing page, 59 tracked dist files + untracked `node_modules`/`src` (backend/app.py:677-690) |
| `/register` | `register.html` (79 lines) | Invite registration |
| `/profile` | `profile.html` (168 lines) | Profile/password |
| `/dashboard` | `index.html` (~1,300 lines) + `app.js` (357 KB) + `styles.css` (648 KB) | The actual product |

### Fonts (all from Google Fonts CDN)

| Face | Loaded on | Actually used |
|---|---|---|
| Inter | all pages | everywhere (UI body) |
| JetBrains Mono | dashboard | 34 rules — already the de-facto data voice |
| Space Grotesk | dashboard | **3 rules** — dead weight |
| Audiowide | login | wordmark only — sci-fi flavor at odds with "professional" |

### Navigation: 11 destinations for ~6 jobs

`Command:` overview, risk · `Discover:` file-servers, endpoint · `Analyze:` findings, reports,
history · `Operate:` security, admin, settings, logic (index.html:56-103).

### Palette today

Light: teal `#146c63` accent on cool gray; Dark: slate `#111827` + teal `#2dd4bf`; severity
crimson/orange/amber/**green** (`--low: #4ade80` — green means both "low risk" and "success",
a semantic collision).

---

## 2. Diagnosis — what is wrong, what is not enough

1. **Three frontends, three design systems.** The React landing, the self-styled auth pages
   (635-line `login.html` with its own inline CSS + Audiowide), and the dashboard don't share
   tokens, type, or theme code (`auth-theme.js` duplicates `app.js` theming). Every visual change
   costs ×3.
2. **11 top-level tabs is the "complicated" feeling.** The product has ~6 operator jobs. Depth
   inside pages is fine (tab-risk alone has 9 panels + 5 sub-tabs); breadth at the top level is
   what disorients.
3. **CSS cascade debt.** `styles.css` is 648 KB / ~21k lines, version-layered (v80 → v104 →
   later) with `!important` accumulation — this session's density work had to fight it with
   `:root:root` specificity hacks. Every future change pays this tax.
4. **CDN fonts break the on-prem story.** An air-gapped customer gets FOUC + a privacy leak; the
   combined remediation roadmap already flags the Google Fonts CDN as a gap.
5. **Login page leaks `admin / admin123`** (login.html:385) — already security-roadmap item L2.
6. **No sorting/filtering outside inventory.** Findings queue, remediation list, priority files
   are capped pre-sorted arrays — operators can't reorder what they see.
7. **Decorative-card clusters remain** on the Risk page (`#priority-risk-files`,
   `#remediation-workflow` kanban cards) where dense rows would scan faster — the one U-C item
   deliberately deferred.
8. **Copy debt in dynamic strings.** The static markup was cut in U-B; app.js still renders
   verbose captions and empty-states (overview stat tiles, report memos).
9. **"Gamer" flourishes undercut "professional":** custom cursor + ambient mouse spotlight
   (`sentro-fx.js`), Audiowide wordmark, marketing hero panels.
10. **No rendered-page regression harness.** The dashboard is auth-gated; tests are
    source-contract only. Structural refactors are safe; *visual* refactors fly partially blind —
    the plan sequences around this.

### Already fixed this cycle (don't redo)

Compact density is the permanent default (U-A + follow-up); static decorative copy cut (~136
lines, U-B); scan forms behind `<details>` expanders, findings table 15→8 columns + per-row
expander, integrity detail collapsed (U-C); 6 targeted polish fixes (heroes, steppers, nested
scrollbar, risk-engine memo). The plan builds on this baseline.

---

## 3. Design direction

### 3.1 Palette — "Harbor / Sonar" (dark-first, light derived)

Keep Sentro's teal identity; deepen the ground, and make **color carry information**: severity is
the only place strong color appears in quantity; green is reserved exclusively for success/pass.

| Token | Dark (primary) | Light | Role |
|---|---|---|---|
| `--bg` Harbor | `#0F151C` | `#F5F7F9` | page ground (graphite-blue, never pure black) |
| `--surface` Hull | `#161E27` | `#FFFFFF` | cards, tables |
| `--line` Waterline | `#26313D` | `#DCE2E9` | borders, dividers |
| `--text` | `#E7EEF4` | `#1A2430` | ink |
| `--muted` Fog | `#8C9AA8` | `#64707E` | secondary text |
| `--accent` Sonar | `#2AB9A9` | `#0F7A6E` | interactive, focus, scan progress — **the only brand color** |

Severity ramp (information, not decoration): Critical `#E5484D` · High `#F76B15` · Medium
`#F3C63F` · **Low `#5B93C4` (steel — no longer green)** · Success/pass `#3FB950`. Rationale:
today "low risk" and "OK" share green, so a wall of green low-risk rows reads as "all clear."
Steel-blue low keeps the ramp monotonic (hot → cold) and frees green to mean *good* only.

Gradients: the body keeps one quiet ground gradient; all other gradient/glass effects retire.
Surfaces are flat, separated by `--line` and one shadow level.

### 3.2 Typography — two voices, self-hosted, no display face

| Voice | Face | Use |
|---|---|---|
| UI | **Inter** (self-hosted woff2, weights 400/500/600/700) | everything human-written |
| Data | **JetBrains Mono** (self-hosted, 400/500) + `font-variant-numeric: tabular-nums` | paths, hashes, IDs, counts, deltas, SLA dates |

Drop Audiowide and Space Grotesk. The deliberate aesthetic risk is **no display face at all**:
in an operator console the character comes from the *data voice* — mono paths and hashes set in
tabular figures are Sentro's equivalent of a signature headline face. Headings are Inter 600 with
tightened tracking, sized by the existing compact scale. (Also closes the CDN/air-gap gap: fonts
ship in `/static/fonts/`.)

### 3.3 Signature element — the severity spine

One unifying visual grammar across the whole product: **every row, card, and queue item carries a
3px left-edge spine colored by its severity** (already half-present on risk cards — promoted to a
system-wide rule: findings rows, inventory rows, remediation rows, report register, alert toasts).
An operator's eye learns one thing that is true everywhere: *left edge = how much this matters.*

### 3.4 Motion budget (absorbs Track U-D)

- **One hero motion:** the sonar sweep on active scan progress (exists as `.scan-pulse`/sweep) —
  it means "Sentro is scanning" and appears nowhere else.
- Micro-transitions ≤ 160 ms, opacity/transform only; row-entrance staggers capped; count-up
  animation kept on KPI numbers only.
- **Remove** the custom cursor + ambient mouse spotlight (`sentro-fx.js`) — professional consoles
  don't replace the pointer.
- `prefers-reduced-motion` already zeroes durations; this stays load-bearing.

---

## 4. Information architecture — 11 tabs → 6 destinations

| New destination | Absorbs (today's tabs) | How |
|---|---|---|
| **Dashboard** | overview (incl. inventory workspace) | unchanged home |
| **Scan** | file-servers + endpoint | one page, source switcher (File server ⧸ Endpoint) reusing the existing radio-tab pattern (index.html:649-653 precedent) |
| **Findings** | findings | unchanged |
| **Remediation** | risk | unchanged (its internal depth already tabbed) |
| **Evidence** | reports + history | report center + scan history/audit as sibling views — both are "prove it" surfaces |
| **Administration** | security + admin + settings + logic | one destination, 4 sub-sections (users/keys · tenants · asset rules · scoring reference) |

Nav groups (`Command/Discover/Analyze/Operate`) retire — 6 flat, titled destinations need no
grouping layer. `data-tab-jump` aliases keep old names working (`resolveTabName` already aliases
`inventory → overview`; extend the same map so nothing deep-linked breaks).

### Page removal (the explicit ask)

- **Delete `frontend-landing/`** (React app: 59 tracked dist files + untracked src/node_modules).
- **backend/app.py:** remove `LANDING_DIST`, the `/assets` landing mount, and the landing branches
  so `/` and `/login` always serve `login.html` (backend/app.py:133-143, 251, 677-690).
- **Tests:** rewrite `test_root_serves_built_sentro_landing` → "root serves the login page";
  keep `test_dashboard_remains_separate_from_landing` as "dashboard serves the console"
  (tests/test_landing_route.py:15-29).
- Login page becomes the product's front door: same Harbor/Sonar tokens, wordmark in Inter 600
  (Audiowide retired), **`admin / admin123` hint deleted** (closes L2).

---

## 5. Roadmap (each phase = one isolated, testable commit series)

**Standing constraint:** Track S owns uncommitted changes in `index.html` / `app.js` /
`styles.css` (inventory table, windowed paging, search) and `backend/app.py|store.py`. Every
phase below stages around those hunks (the extraction discipline used all cycle); anything
touching the inventory surface itself waits until Track S lands.

| Phase | Scope | Files | Risk | Acceptance |
|---|---|---|---|---|
| **P1 — Remove the main page** ✅ **DONE (2b4ecea)** | deleted `frontend-landing/` (66 files, −17,585 lines incl. tracked src); `/` + `/login` always serve login.html; landing CORS origins (:5173) dropped; CI landing jobs removed; tests rewritten (`RootRouteTests`, asserts no `admin123` on the page); all four `admin/admin123` hints deleted (login.html, login.js, app.js, v101 changelog) — closes L2 | app.py, ci.yml, tests/test_landing_route.py, login.html/js, app.js, changelog | Low (route fallback already existed) | ✅ `/` serves login; 45-test slice green; full-suite run pending confirmation |
| **P2 — Token refit (colors + fonts)** ✅ **DONE (8011500)** | Harbor/Sonar shipped as ONE authoritative EOF token layer (the file turned out to hold FOUR full palette layers — teal→blue→v98→indigo — live cascade measured in-browser, not hand-traced); mirrors the indigo layer's complete color-token set incl. status/info/focus/copilot/sidebar; low=steel + new `--ok` with 9 success-semantic rules re-declared onto it; ALL Google-Fonts CDN links removed (system stacks: Inter→Segoe UI, JetBrains Mono→Cascadia/Consolas — vendored woff2 optional later); Audiowide + Space Grotesk retired; login re-skinned (both micro-token blocks + hardcoded blue button gradient) and its theme key unified `s-theme`→`dspm-theme` | styles.css EOF layer + 2 font rules, 4 HTML heads, login tokens | Landed low-risk | ✅ tokens win both themes (probed live); 0 external font requests; 37-test slice green. Residual: ~75 raw indigo/purple hexes in older layers → P4 rendered sweep |
| **P3 — Nav consolidation 11→6** ✅ **DONE (6f5f53e)** | Sidebar = 6 flat destinations (Dashboard, Scan, Findings, Remediation, Evidence, Administration); Command/Discover/Analyze/Operate group labels retired. Member panels stayed physically unchanged — merged destinations switch via in-page `.subnav` pill strips reusing the existing `data-tab-jump` wiring (zero new handlers): Scan = File server/Endpoint, Evidence = Reports/History (decision ②), Administration = Security/Tenants/Asset rules/Risk logic. `NAV_DESTINATIONS` + `navDestination()` light the owning sidebar button for any member; every old tab name stays a valid deep link | index.html nav + 8 strips, app.js destination map, styles.css `.subnav` | Landed low-risk (no markup moves) | ✅ served DOM: 6 tabs / 8 strips / 0 group labels; destination logic 8/8; contracts 37 green |
| **P4 — Surface refits** | Risk page cards→dense spine rows (`#priority-risk-files`, `#remediation-workflow`); severity spine rolled out product-wide; client-side sort on findings/remediation columns; dynamic copy cut (stat-tile captions, verbose empty-states) | app.js renderers, styles.css | Medium (visual-critical: wants a rendered check) | more rows above fold on Risk; sortable findings/remediation; spine everywhere |
| **P5 — Motion budget (U-D)** | sonar sweep as sole hero motion; ≤160 ms micro-transitions; remove custom cursor + mouse spotlight | sentro-fx.js, styles.css keyframes | Low | interaction never blocked; reduced-motion audit passes |
| **P6 — CSS consolidation (debt)** | rebuild styles.css as ordered layers (tokens → base → components → pages), collapsing the v80/v104 override chains and `!important` wars; byte-budget target ≤ 250 KB | styles.css (mechanical, behind visual-diff checks) | High effort, do last — after P2-P4 stop churning styles | identical rendering (spot-check), file halved, no `:root:root` hacks needed |

**Sequencing logic:** P1 is the user's explicit ask and pure deletion — first. P2 is global but
rides existing tokens — early, so every later screenshot is in the new skin. P3 before P4 so
surface work happens in the final page structure. P6 last, once the styling churn is over.
P4's rendered-page check is the one step that benefits from an authenticated browser session —
schedule it when the app can be run (`python main.py serve`) and eyeballed.

### Non-goals (explicit)

- **No React/component rewrite** (roadmap U-F stays optional) — the vanilla stack is an asset
  on-prem.
- **No inventory-surface changes** until Track S lands (its columns/filters are Track S's call).
- **No new marketing surface** — the product starts at login, by design.

---

## 6. Decisions wanted from you

1. **Severity low = steel-blue instead of green** (green reserved for success) — approve?
2. **Merge Reports + History into "Evidence"** — or keep History separate (7 destinations)?
3. **Custom cursor / mouse spotlight removal** — any attachment to keeping them?
4. P1 deletes the React landing workspace entirely (recoverable from git history) — confirm.
