# Sentro Frontend — UX Assessment and Roadmap

**Date:** 2026-09-02
**Scope:** the operator console (`frontend/index.html`, `app.js`, `styles.css`, `sentro-fx.js`) and the sign-in page (`frontend/login.html`)
**Method:** every number below was measured on the running product at 1366×768 (with checks at 1280×720 and 1024×768), light and dark, default tenant with real scan data; the CSS and markup were audited statically. Competitor observations come from public reviews and documentation, not hands-on sessions, and are labelled as such.
**Status:** the assessment below is unchanged. Section 0 records what has since been built against it.

---

## 0. Implementation record

Appended as each phase lands. Numbers are re-measured on the running product at
1366x768 unless stated; the "before" column is section 2.

### 0.1 F0 — the token contract *(done)*

`frontend/styles/tokens.css` is the single place a colour, size, radius,
shadow, stacking level or duration is decided, in both themes.
`scripts/check_frontend_tokens.py` enforces it **on changed lines only**, so the
debt is frozen rather than rewritten in one go. Five dead `:root` blocks (78
declarations, every one already overridden later in the cascade) were deleted
in the same change.

### 0.2 F1 — the shell *(done)*

| | Before | After |
| --- | ---: | ---: |
| Top bar height | 104 px | **56 px** |
| Sidebar element / its grid column | 220 px / 236 px | **220 px / 220 px** |
| Content starts at | ~180 px | **96 px** |
| Pages carrying an `h2` | 0 of 11 | **11 of 11** |
| Ledger strip | — | **11 of 11 pages, one size** |

Three things were harder than they look and are worth recording:

- The floating pill's box survived the first pass because every part of it was
  set with `!important` — a 12 px radius, a shared border/gradient/44 px-shadow
  rule it inherited from the card family, a 14 px backdrop blur, and a 3 px
  indigo-to-violet gradient painted across its top edge by a `::before`. The
  bar was flush and still read as a card parked next to the nav. All four are
  deleted; the hairline underneath is the only thing separating the band from
  the page.
- **The shell grid disagreed with itself twenty times.** Declarations for the
  sidebar column ranged from 208 px to 300 px across the file; the winner said
  236 px while the sidebar element said 220 px, leaving a 16 px dead strip the
  register head began after — the reason it never looked attached on the left.
  Below 980 px it was worse: a 220 px sidebar inside a 208 px column overlapped
  the content. Every expanded-width declaration is now deleted and shell.css
  states it once from `--shell-sidebar-w`. The collapsed rail keeps its own
  rules; it is a more specific selector and it already agreed.
- The band's gutter is now the page gutter (24 px) at every width, so the
  search field lines up with the page title beneath it and the actions line up
  with the content's right edge.

**The ledger strip states three facts and no more:** which scan, how much it
covered, when it finished — `HR file share · 421 files · Aug 31, 10:02 PM`. The
collector protocol used to sit between the first two. It is not something the
reader decides anything with, and a strip that has to be parsed is not a strip;
the protocol stays on the scan itself. (This narrows §5.1, deliberately.)

### 0.3 F2 — motion *(done)*

Three page-transition systems ran at once — a JS `animate`, a CSS `dspmFade`,
and a 450 ms staggered rise on every child, in four stacked layers each added
to tame the one before — while filter changes, data arrival and the theme had
none at all. Measured live afterwards: **1 running animation on a page change,
0 child-stagger animations.** The theme cross-fades over 320 ms.
`prefers-reduced-motion` collapses everything in one place, in the tokens.

### 0.4 F3 — page compaction *(Dashboard, Findings and Remediation done)*

**The dashboard is one screen.** Not "shorter" — sized to the window, with
`height: calc(100dvh - var(--shell-topbar-h))` and `overflow: hidden` on the
panel itself. When a list holds more than fits, *that list* scrolls inside its
card. The distinction matters: "the dashboard is long" was never true, "there
are more risky folders than fit" always was, and only the second should move.
Measured at 1366x768: `scrollHeight` 768, `clientHeight` 768.

| | Before | After |
| --- | ---: | ---: |
| Dashboard scroll depth | 1.91 screens | **1.00** |
| Panels | 6 | **3 + the band** |
| Remediation scroll depth | 2.46 screens | **1.00** |
| Findings panels above the table | 2 | **0** |

Four panels were deleted outright — posture trend, recent scans, posture
intelligence, activity — along with the per-page scan strip. The strip was the
signature element of F1 and it is worth saying plainly why it went: it printed
the same sentence on eleven pages, and a sentence that never changes stops
being read. Findings keeps the fact, once, above the table it describes.

**Three cards replaced the four panels**, each answering a different question
and each a way into the page that answers it:

- **Security posture** — the score, a sparkline of the last twelve saved scans,
  and the folders costing it. Every row opens Remediation.
- **Top data classes** — what kind of data is exposed, with the worst severity
  it has been found at as a dot. A row opens Findings searched for that class.
- **Compliance frameworks** — which framework is on the hook, by file count. A
  row opens Findings filtered to it.

The frameworks card deliberately does **not** copy the reference's segmented
pass/warn/fail bar: the product does not compute a pass/fail split per
framework, and a bar that implies one would be a picture of data we do not
have.

**The severity band now reads as colour.** The assessment was right that six
figures on one line is the correct density and wrong about the emphasis: a
10x2px tick beside a label is only visible to someone already reading that
cell. Each column is now capped by a full-width 4px rule in its severity colour
and the figure is set in that colour — same 76px, legible across a desk. Each
cell is a button that opens Findings at that level, which is the behaviour that
went missing when the KPI tiles were replaced.

That change forced a token correction. `--sev-medium` was amber-600 (`#ca8a04`),
which measures **2.94:1** on paper — under even the large-text floor once it is
carrying a 28px figure. It is amber-700 now, and all five levels pass as text
(4.83 / 5.02 / 4.92 / 5.01 / 4.55).

**And it exposed a real colour bug.** Medium rendered *blue* (`#3b82f6`) in the
legacy badges and pills while the band renders it amber, so one finding changed
colour between two panels on the same screen — and blue-on-blue measured
3.28:1 in the remediation queue. The bridge table in `tokens.css` had called
this out; repointing `--medium` and `--status-medium` at `--sev-medium` fixes
the ramp in all 43 places at once.

**Findings is the inventory.** The detection-signal panel and the priority
queue above the table both restated the table's own first rows and the
dashboard's band. Both are gone, with their renderer (74 lines). The card that
said "Data inventory" above the inventory is gone too — the page is the
inventory, and a page does not need to introduce itself.

**Remediation had become a second dashboard**: a hero band, a workspace status
card, a two-column analytics grid nested three deep, a distribution donut, a
posture trend, a scan comparison, an exposure tab deck and a topology block.
All of it restated what the dashboard now says once. What is left is the same
severity band, the queue, and the folders the queue points at — sized to the
window on the same terms.

Traffic between the two pages runs one way now: the dashboard's top risks are
the entry point to Remediation, so Remediation no longer carries a link back to
the page the reader just came from.

Remaining, in order: Evidence (2.30x), Administration (2.23x), Risk logic
(13.27x).

### 0.4b Dashboard, second pass — the cards stop being generic

The first pass was right about density and wrong about character: three cards
that were three identical bar lists, a posture panel three rows tall, and a
header still spending 56px of every page on a row of its own. This pass takes
the reference console's good instincts (a glyph per row, a gauge for the
score, a mark per framework, the header on the title row) without its lavender
hero card or its rounded-pill everything.

**The header sits on the title row.** The band is gone; search, New scan,
theme, Connected and tenant are an absolutely positioned cluster at the
top-right of `main`, vertically centred on each page's h2, and every title
row reserves its footprint (`--shell-head-reserve`) so title and controls
never overlap. Not sticky — the dashboard and Remediation never scroll, and on
pages that do the controls scroll away like any page header. Every page gains
56px. Three legacy rules had to go first: `.topbar { position: relative
!important }`, the pre-F1 card treatment of page headers (24px radius,
gradient, shadow, 18×20 padding, all `!important`), and the flat-header rule's
`padding: 0 !important`.

**Iconography as a system.** Every row in every card opens with a **coin**: a
28px rounded square holding a lucide line glyph, tinted by what the row means.
A risk's coin takes its severity; a data class's takes the worst level it has
been found at (28 glyphs, matched on the display name); a framework's is that
framework's own mark — EU stars on EU blue for GDPR, a card on PCI green, a
cross on health blue for HIPAA, a lock on ISO red, a shield on NIST navy. Those
five colours are declared as `--mark-*` tokens with a comment that they are
third-party identity, not palette: they appear inside a badge with a white
glyph and nowhere else.

**Security posture** is one 64px head instead of three rows: the score inside
a ring whose arcs are the workspace's severity mix (so a 68 made of mostly-low
files and a 68 made of a few criticals look different), the band and the
change over N scans beside it, the sparkline on the right. **Top risks are
categories, not folders** — exposed credentials, unprotected critical files,
payment and bank data, health records, regulated personal data, changed since
last scan, locked or unreadable — computed with the predicates the product
already had (`isSecretFinding`, `isRegulatedFinding`, `isProtectedFile`,
`hasHashChanged`). Folders stay on Remediation, where you act on them. No
"change %" is fabricated: it appears only when a previous scan exists.

**Top data classes** carry a ten-cell meter filled in proportion to the
largest class and coloured by severity — cells rather than a bar because they
read as units and never look like a percentage of something unmeasured.

**Compliance frameworks** show a severity-stacked bar (critical | high |
medium | low share of that framework's files) with each segment's count as a
title and the full legend as the bar's label, so colour is never the only
channel. `standard_scan` — the absence of a framework — is not a row. Counting
runs over `getFileFrameworks` directly rather than `inventoryFrameworkOptions`,
which hard-codes four ids and would drop HIPAA and ISO 27001 if a scan ever
produced them.

Measured at 1366×768: page `scrollHeight` 768, three cards at 546px, no
horizontal overflow, contrast **light 0 / dark 1 (the avatar, §0.6)**, every
coin and mark glyph ≥ 3:1 in both themes, 25 of 25 new row buttons show the
focus ring. The new JS boots on the real console with zero exceptions.

One thing deliberately not copied from the reference: a pass/warn/fail split
per framework. The product does not compute one, and a bar that implies it
would be a picture of data we do not have.

### 0.4c Two scales, two jobs — the colour pass

**The measured complaint.** The dashboard painted 16 distinct colours drawn
from only **4 hue families**, and **50% of its painted area was red, orange or
amber**. The cause was structural, not aesthetic: one scale — severity — was
answering three different questions across seven surfaces (the band's column
caps, the band's figures, the posture ring's arcs, the posture card's coins,
the data-class coins, the ten-cell meters, the framework bars). Because a real
workspace is critical/high-dominant, that came out as a red wash, and the three
cards looked like each other.

**The fix is a second scale, not more paint.** "How bad is it" and "what kind
of data is this" are two questions, so they get two scales in two shapes:

| | scale | shape it paints |
| --- | --- | --- |
| Severity | the five-step ramp | the band's 4px caps, its figures, the framework bars, a severity **word** |
| Kind of data | eight categorical hues (`--cat-*`) | the 28px coin, and the meter under it |
| Framework identity | the five `--mark-*` colours | the 28px badge only |

Because the two scales never share a shape, they sit 12px apart without being
confusable. The eight kinds — people, reachable, money, health, keys, legal,
records, code — come from the same table that picks the row's glyph
(`DATA_CLASS_KINDS`), verified against all 304 display names the classifiers
can produce.

**Result at 1366×768:** hue families **4 → 7**, warm share **50% → 16%**,
distinct colours 16 → 28. Contrast: light **0** failures, dark 1 (the avatar,
§0.6), and every coin, mark and meter clears the 3:1 non-text floor in both
themes.

**Four things stopped spending the ramp where it was not saying severity**,
each removing a red object and a duplicated statement:

- *The posture ring* carried four severity arcs restating the band 40px above
  it — and at r=24 the low arc is a 6px sliver, so the mix was illegible as
  well as redundant. It is now one accent arc showing score out of 100, which
  is the one thing nothing else on the page says.
- *The "All files" cap* was indigo, nine degrees from the protected violet in
  the cell immediately left of it, so the two rightmost columns read as one
  purple pair. A total is not a severity and not the accent: it is ink.
- *The score numeral* was ramp-coloured inside an accent ring; the word beside
  it already names the band.
- *The trend delta* used low-green and critical-red for **direction**, which
  the arrow glyph and the printed sign already carry unambiguously.

**Framework bars got their length back.** Five rows with similar severity mixes
rendered as the same four-colour gradient five times, because each bar spanned
the same grid column. Length is now the framework's share of the largest
(measured: 280 / 215 / 106 / 78 / 50px), which is a fact the card was not
showing at all. Each row also hovers in its own mark colour rather than the
shared accent.

**One limit, stated plainly.** A dichromacy simulation (Viénot–Brettel–Mollon,
ΔE2000) shows **no eight-role palette can be colour-blind-safe** in this gamut —
an exhaustive search peaked at ΔE 10.4 against a floor of 12, and under
deuteranopia `identity`/`secret` collapse to one colour. That is acceptable
*here and only here* because the categorical colour is never the identifying
channel: every row carries a distinct glyph and its full name, and the data
class card additionally prints its severity as a word. If this palette is ever
reused where colour is the only channel, it must be cut to four roles.

`--cat-identity` is indigo-700, not `--indigo` itself: the accent is reserved
for primary action, active nav and focus, and a data category that *is* the
accent makes an identity coin look like a control.

### 0.4d Three reports, one stale process — and what it hid

Three symptoms arrived together: Top data classes showed **low** for every
row, the framework severity gradient had disappeared, and Remediation was
empty. They had one cause. The dev server had been started on 2026-09-02
23:43 with no `--reload`, so it was still executing the backend as it stood
two days earlier — before `severity_file_counts` existed on the inventory
facets and before `/api/findings` returned a `items`/`summary`/`total`
envelope. The old endpoint still returned `{"findings": [...]}`, so the
rebuilt queue read `data.items`, got `[]`, and rendered its empty state
honestly. Nothing in the frontend was wrong.

*Restarting the server fixed all three.* The lesson is not "restart the
server" — it is that a UI verified only against the file system verifies
nothing about what the browser is served.

**The harness now runs the real app.** The previous one stripped the app.js
`<script>` tag, which is how the blank page in §0.4a got through. To rebuild
it: a throwaway `scripts/_harness_server.py` that imports `backend.app`,
overrides `require_principal` with a fixed `Principal(subject="admin",
role="admin", tenant_id=<tenant>)`, and runs uvicorn on another port; a
`frontend/_harness_boot.js` that seeds `dspm-access-token` and
`dspm-tenant-id` in `sessionStorage`; and a copy of `index.html` with that
script inserted before `app.js` and every `?v=` cache-buster rewritten. The
browser then drives the real console against real tenant data with no
sign-in. The files are deleted afterwards — a checked-in script that disables
authentication has no business living in a data-security product.

#### What the restart then revealed

**"All low" became "all critical", which is the same non-readout.** With
correct data, `worst seen` is CRITICAL for every one of the top eight data
classes, because in a real estate the largest classes all touch at least one
critical file. The dominant level is HIGH for all eight. No scalar summary
varies. So the severity readout is now the **mix**, in the same stacked bar
the framework rows use: length is the row's share of the largest, fill is the
severity split. That deletes the ten-cell meter and the severity word, and
leaves the two cards speaking one row language. The categorical scale still
lives on the coin alone, so the two-scale rule from §0.4c holds.

**The ramp had two steps that were the same colour.** Once it had to work as
adjacent *fills* in one bar, `--sev-medium` and `--sev-high` measured 9.5
ΔE2000 apart in light and **5.1 in dark** — a medium segment and the high
segment beside it read as one block, so the bar did not climb. Every value
still passed its contrast check, which is why the pinned-hex test never
caught it. Medium moves to `#8a6d0b` in light (4.91:1, gap 20.6) and high to
orange `#f97316` in dark (6.33:1, gap 31.4), and the bar now runs least
severe first: green, yellow, amber, red.

The contract test no longer pins four hex values. It parses the ramp out of
`tokens.css` for both themes and asserts the two properties that matter:
every step ≥ 4.5:1 on its own background, and adjacent steps ≥ 12 ΔE2000.

### 0.4e Remediation wears the inventory's controls

The queue was a second design language on one page: daisyUI selects, buttons,
table, stats and pagination, next to the console's own everywhere else. Two
lists that answer "which of these should I look at first" were two different
controls.

The queue now uses the data inventory's toolbar (`.table-toolbar`,
`.inventory-search-box`), its severity pill row (`.risk-filter-group`, with
counts from the API summary), its labelled facet shells
(`.inventory-facet-row`, `.field-shell.facet-shell`), its context strip
(`.inventory-context-metrics`) and its Clear filters button — and **sorting
moved from a select onto the column headers**, which is the mechanic the
inventory already uses and which removed the eighth control from a row with
room for four.

Two traps worth recording:

- **`.inventory-table` is not borrowable.** It freezes its first column at
  `left: 0` and pins it to 380px `!important`, plus a 1280px table
  `min-width`, all sized for a file-name column the queue does not have.
  Borrowing the class filed the Finding column *behind* Affected asset. The
  queue takes the appearance on its own class instead.
- **`.inventory-facet-row` is written 28 times across four `!important`
  layers, every one scoped to `#inventory-workspace`.** Widening those
  selectors would have dragged the whole pile onto a second page. The shared
  panel chrome comes from the unscoped rules; the queue's own layout is ~40
  clean lines in `remediation.css`.

Row buttons needed `plain-btn` again — the ten `button:not(.tab)...` chains
in styles.css are still the default, and any new button that is not a primary
action has to opt out. This is the third time; §0.7 keeps the entry.

An unterminated comment in `remediation.css` silently swallowed eighty rules
during this work and the page still loaded — it just lost every style after
the typo. The contract test now checks comment and brace balance in all four
contract sheets.

### 0.4f Five cards, two of them new — and the six that were not built

Three equal full-height columns left four of five panels two-thirds empty. The
board is now two rows: **Security posture** and **Compliance frameworks**
stacked in a narrow left column, **Top data classes** (five rows, not eight)
over **Assessment coverage** in the middle, and one card that earns the full
height on the right.

Of the eight candidates, only two could be built honestly against this
product's data. The measurements, so the rejections are auditable:

| candidate | measured on the live estate | verdict |
| --- | --- | --- |
| Risk concentration | shares vary 215 / 78 / 49 / 44 / 35 / 33 / 7 / 2, with distinct severity mixes | **built** |
| Classification coverage | 463 assessed, 447 classified, 16 clear, 1 unreadable | **built** |
| Crown jewels at risk | the top-risk list already names credentials, regulated data and payment data | redundant |
| Unprotected sensitive data | already the first row of Top risks | redundant |
| Exposed credentials | already a Top risks row | redundant |
| Stale sensitive data | 449 of 463 files carry the same `modified_at` month | degenerate |
| Sprawl / duplicates | `duplicate_hash_path_count` is 0 | degenerate |
| Approved vs unapproved locations | no approved-location policy is modelled | not computable |
| *New risks since last scan* | the trend holds a 539-file sweep followed by two 2-file scans | **would lie** — see below |

**Where the risk is** is backed by a new `locations` facet on
`/api/inventory/facets`: one row per share with its severity counts, ordered
server-side by weighted severity so a share holding ten critical files
outranks one holding a hundred low ones. It reuses the `.stack` bar, so the
severity language is identical to the other two list cards.

**Assessment coverage** is the qualifier every other figure on the page needed:
"97% of assessed files carry at least one finding", with classified / nothing
found / unreadable as one meter and three click-throughs. It deliberately does
NOT use the severity ramp — completeness is not severity — so it reads as ink,
a wash of ink, and the protected violet that already means "could not open".

#### The bug the "new risks" widget uncovered

A posture score is the mean risk of whatever that scan covered. The card
compared the newest scan against the **oldest** point in the trend, and this
tenant's history is a 539-file estate sweep followed by two 2-file spot checks
— so the dashboard was printing **"+68 over 3 scans"**, an improvement that
never happened. Wrong in the flattering direction, which is the worst way for a
security console to be wrong.

`comparablePosturePoints()` now walks back for the most recent earlier scan
that covered comparable ground (within `POSTURE_COMPARABLE_RATIO`, 0.6), and
shows nothing when there is none. On this tenant the delta became "+0 vs 09-01"
— true.

### 0.4g The queue's density, measured against the inventory

The queue borrowed the inventory's controls last round but not the layer that
compacts them: every one of those rules is scoped to `#inventory-workspace`.

| at 1366x768 | Findings | queue before | queue after |
| --- | ---: | ---: | ---: |
| toolbar | 65 | 79 | 66 |
| severity pills | 29 | 54 | 46 |
| facet row | 38 | 168 | 101 |
| context strip | 35 | 131 | **31** |
| chrome above the first row | **279** | **624** | **436** |
| row height | 108 | 59 | **46** |
| findings visible | — | 4 | **6** |

The two that mattered most: the facet label was **stacked above** its control,
which turned one 38px row into two, and the five workload figures were stacked
label-over-value-over-note at a 27px numeral, reading as the subject of the
page rather than context for the queue. Both now match the inventory exactly —
label beside control, figures inline in a pill. A fixed-width cell that wraps
also makes every row in the table taller, so Data type, Asset and Owner
ellipsise with the full value on the cell's title.

### 0.4h daisyUI's `.status` broke every scan page

A finished scan rendered its completion message **one word per line**, behind
the demo-data card and the workspace footer. The cause was not the scan page:
`daisyui.css`, added in 0.4e for the remediation drawer and dialogs, defines
`.status` as an 8px **dot** (`aspect-ratio: 1; width: .5rem; display:
inline-block`). The console's `.status` is a full-width text box. Every scan
page's status line collapsed to 26px.

Only three daisyUI class names collide with the console's own, across 32
elements: `.hidden` (both mean `display: none`), `.tab` (daisyUI's only matches
under a `.tabs-border` ancestor the console never renders) and `.status` (the
one that bit). Nothing in the console uses daisyUI's dot, so the console's box
is re-asserted in `shell.css`. **Check that list before introducing a generic
class name while daisyui.css is loaded** — it is a landmine field, and the
permanent fix is to drop daisyUI once the drawer and the five dialogs have
native equivalents.

Two other things on that page:

- The completion message was eight diagnostics joined with `". "`. It is now a
  headline (`Scan completed in 2m 18s`) plus one chip per figure, and the two
  entries that were settings rather than results — the allowed-extension list
  and the local path — are gone from it.
- The latest-workspace strip already had `margin-top: auto`, but its panel
  stopped where its content did, so there was nothing to push against. `main`
  starts at the top of the window and carries no padding, so the panel now
  takes `min-height: 100dvh` and the strip is `position: sticky; bottom: 0`.

### 0.4i Six cards, and a mini widget that had to be built on degenerate data

The board is now four columns: posture over frameworks on the left, **Top data
classes spanning the width of the coverage/staleness pair** beneath it, and
locations still full height on the right. All six fit 1366x768 with zero
scroll.

**Stale sensitive data** was requested explicitly, and it is the right widget
for a customer estate — but on the demo dataset it is degenerate: 436 of 448
sensitive files fall in one age bucket and 12 are undated. It is built anyway,
honestly: three bands (Active / Ageing / Abandoned) over `sensitive_age`, a new
facet counted server-side over files with at least one finding. Age is ordered
but it is **not** severity, so it takes a single-hue sequential that darkens
with neglect rather than a third meaning for the five ramp colours.

Both new cards now distinguish *"no scan yet"* from *"this service build does
not send that field"*. The first version of the locations card reported the
second as the first, and cost an operator a support round-trip looking for a
scan that had already run.

**Clicking a data class opens the Finding type facet**, not the search box.
Typing the class name into search matched it as free text against paths and
file names too, so "Email" also returned every file with `email` in its path.

### 0.4j The ramp, one step back inside the cards

The severity band across the top is the headline and should be loud. The same
five values repeated inside every card's bar put six saturated blocks on one
screen. The cards take `--sev-*-soft`: the ramp mixed **80%** toward the card
it sits on, which softens in both themes (toward white on paper, toward the
dark ground at night).

Measured against the card: **3.37-3.77:1 in light, 4.52-7.89:1 in dark** — the
band stays at 4.83-5.02 / 6.33-11.58. 80% rather than less because at 74% the
softest step measured 3.02:1, and 3:1 is the floor for a graphic that carries
meaning.

*Known and deliberate:* the "Nothing found" and "Active" segments sit at
1.6-2.9:1. They are the benign majority, and each has a legend row printing its
label and its count, so no information is carried by colour alone.

### 0.4k The queue's command line

The queue carries seven facets to the inventory's two, so matching the
inventory's absolute chrome height is not achievable without dropping controls.
What was removed instead: the toolbar's scope line (which restated the Scope
select below it and the OPEN / FILES AFFECTED figures below that), and the
severity pill row, which now shares the command line with the search box.

| chrome above the first finding | before | 0.4g | now |
| --- | ---: | ---: | ---: |
| at 1366x768 | 624 | 436 | **371** |
| at 1920x1030 | — | — | **337** |
| findings visible at 1920x1030 | — | — | **14** |

The facet row also flows now instead of reserving four fixed columns, so it
takes one line at 1920 and two at 1366.

### 0.4l Six cards, six shapes

Five of the six cards drew the same object - a name, a number and a stacked
bar - so the board read as one widget repeated. Compliance frameworks keeps
that shape; the rest take the form their own question needs.

| card | question | shape |
| --- | --- | --- |
| Security posture | how are we doing | a 38px score and a spline wave |
| Top data classes | how much of each kind | a lollipop on a shared axis |
| Compliance frameworks | which regulator, how bad | the stacked severity bar |
| Assessment coverage | how much did we read | three columns on a baseline |
| Stale sensitive data | how much is abandoned | a 240-degree dial |
| Where the risk is | where do I go | a two-level tree |

**The wave** is a Catmull-Rom spline converted to cubic beziers. Straight
segments between eight scans drew a saw; one curve is what "the shape of the
last few scans" actually means. The band never compresses below ten points of
score, so a flat history reads as flat rather than as noise amplified to fill
the box. The score ring is gone - the score is the figure now.

**The tree** needed a backend facet: `_location_tree()` returns shares each
followed by their heaviest folders, flat and ordered with a `depth`, so the
client draws the indent and the payload keeps the same shape as every other
facet. The first path segment is one dialect-branched SQL expression
(`split_part` on Postgres, `substr`/`instr` on SQLite).

**Assessment coverage** columns carry a 14% floor: 448 / 14 / 1 on a linear
scale makes two of the three columns one pixel tall. The exact value is
printed above each column, so the number is never read off the bar's height.

Two things had to be pinned to make it fit 1366x768 with no scroll and no
slack: `button { min-height: 40px }` in styles.css was adding 14px to every
one of the eighteen tree rows, and the row heights are now declared once, in
one block, because the board's fit depends on them.

**Every figure is set in `--font-text` with tabular numerals.** Nine of them
had drifted to `--font-data`, which is a *monospace* face - a count set in it
reads as a different kind of number from the count in the band 40px above,
which is the whole reason the band was moved off the display face in 0.5.
Alignment comes from `tabular-nums`, which is what the mono was being used
for. The contract now asserts no `--font-data` on this page.

### 0.4m The inventory's filters become five dropdowns

Six severity pills, two selects and a wrapping row of framework chips took
three bands and still could not say which folder you were looking at. It is
five labelled selects on one flowing line: Severity, Scan source, Finding
type, Framework, Folder / path. Each shows its current value, which the pills
and chips only did by which ones happened to be lit.

The folder select is populated from the dashboard's own location tree, so both
pages name the same places the same way. It drives the inventory's text search
rather than a filter of its own - `list_inventory` has no folder parameter,
and adding one is a larger change than this round could carry honestly.

Also: **the per-row severity rule is gone.** Every row carried a coloured bar
down its left edge repeating the severity badge two columns to its right; with
a hundred rows on screen that is a hundred red lines saying what the badge
already says. And the context strip lost its fourth chip - "Top source"
duplicates the Source column and was the one overflowing the row.

### 0.4n The queue's second scrollbar, and where a row goes

`#remediation-workflow` scrolled *and* the table wrap inside it scrolled, so a
long queue drew two bars a few pixels apart. Setting `overflow-y: visible`
alone did nothing: **`visible` on one axis computes to `auto` when the other
is `hidden`**, which is exactly how the panel kept its bar. Both axes now.

A queue row opens the file it is about: Findings, searched to that path, then
the row's own detail once it lands. Findings is paginated, so it retries for
three seconds and, failing that, leaves the reader on the right search rather
than on nothing.

### 0.4o What was asked for and deliberately not done

The closing paragraph of the request listed several trends that contradict
each other or the product:

- **"use emoji"** against **"professional"** - emoji as UI icons is an
  explicit anti-pattern in the same guidance this work is following, and a
  data-security console is the last place for it. The SVG sprite stays.
- **"use liquid glass"** against **"don't use blurry light spots"** in the
  same paragraph. Glass *is* blur; the two cannot both hold. Kept flat.
- **"purple-black palette"** - the user confirmed on being asked that the
  brand stays blue/indigo, as recorded in 4.1.
- **"not a bento box layout"** - the user confirmed the card grid stays.
- **"don't use rounded corners"** followed from the layout direction, which
  was declined with it.

Applied from that paragraph: `--surface` moved off `#ffffff` (pure white beside
a `#f8fafc` page is a hard step the eye reads as a seam), a soft two-stage
shadow and a 2px accent rule down the left of every card, colour transitions
on the same duration as everything else with a reduced-motion escape, and one
typeface for every figure.

### 0.4p "No empty space" meant the bottom of the card, not the gaps

I read it as "tighten everything" and squeezed the row rhythm to 25-30px, so
the elements got cramped **and** the dead band at the bottom of each card
stayed - because every card was still stretched to fill its grid row. It is
the other way round: the rows get their spacing back (36px list rows, 29px
tree rows) and the rows of the *grid* are sized to their content, so a card
that has finished stops there.

**The board is two full-height columns bracketing two stacked pairs**, and the
pairs are matched by height rather than by topic: a five-row list over a
three-row list, a column chart over a dial. Posture takes a column of its own
because it is the page's headline and its wave wants the room; locations takes
the other because a ranked tree is the one list long enough to use it. Measured
at 1366x768 afterwards: **every card reports zero dead space**, row one ends at
465px for both its cards and row two at 744 for all four.

Four rendering faults, all measured before and after:

| fault | cause | fix |
| --- | --- | --- |
| wave clipped at the top | the crest sat exactly on y=0 of its own box | asymmetric padding - a Catmull-Rom curve overshoots its control points, so the crest needs more clearance than the trough |
| lollipop dots cut off | the dot is centred on its value, so at 100% half of it hung past the track | travel clamped to one radius in from each end; the stem still runs the full share |
| tree bars staggered | the indent was on the whole row, so every column after it moved | mark and name share a `.place-lead` cell that carries the indent; the bar and count keep their own columns |
| columns floating mid-card | the chart had a fixed height in a taller card | the chart is the flexible child, so the baseline is the card's bottom edge |

The 2px accent rule on the left of each card is removed - the card's own edge
is what the rest of the console uses.

### 0.4q Scrollbars

The window never scrolls in this console: every page now sizes to the viewport
and its own panels scroll. **Findings was the exception** - it overflowed by
about a hundred pixels, and with the window bar hidden that is a page which
scrolls with nothing to say so. It sizes to the window like the dashboard and
the queue, and its table scrolls instead.

Inside a panel the bar is drawn but its thumb is transparent until the pointer
is over that panel. **The gutter is always there** - fading the whole bar in
and out reflows the content under it every time the mouse crosses a card, so
only the thumb's colour changes. Measured: the gutter holds at 10px in both
states.

### 0.4r The board fills the window, and the lists fill the board

Two wrong answers preceded the right one. Sizing the grid rows to their
content left a band of page under all six cards. Sizing them to the window put
the band back **inside** whichever card ran out of rows first. Neither works
alone, because the amount of content was fixed and the amount of room was not.

So the room is fixed and the content adapts:

- the rows take the window (`minmax(0, 1fr)` twice), so the board always ends
  where the viewport does;
- the two lists long enough to matter render **as many rows as their card can
  hold** - `dashListCapacity()` divides the body's height by the row height,
  and the body's height comes from the grid rather than from its own contents,
  so reading it back after a render cannot feed a loop;
- every list's rows then **share whatever is left over** (`flex: 1 1 auto`
  between a min and a max), so the remainder never collects at the bottom.

Measured on a fresh load at four sizes, with the deepest rendered element in
each card compared against that card's bottom edge:

| viewport | data classes | places | gap in any card | page scroll |
| --- | ---: | ---: | ---: | ---: |
| 1280x720 | 4 | 13 | 0 | 0 |
| 1366x768 | 5 | 15 | 0 | 0 |
| 1600x900 | 7 | 20 | 0 | 0 |
| 1920x1030 | 9 | 25 | 0 | 0 |

The row heights in `pages.css` are the numbers `dashListCapacity()` divides
by; the contract test asserts the two agree, because a disagreement shows up
as a card that overflows by one row.

**A resize needs two triggers.** `window.resize` is the common case and always
fires; a `ResizeObserver` on the board additionally catches it changing size
without the window doing so, such as the sidebar collapsing. Both funnel into
one guarded function that returns immediately if the capacity has not changed,
so dragging a window edge does not re-render on every frame. Worth recording:
**ResizeObserver does not deliver at all inside the harness's embedded
browser** - it fired zero times on a real height change - so the resize path
was verified by dispatching the event and confirming the counts and gaps
changed (4 / 13 / gap 0 at 1280x720).

The hero's wave is capped at 132px. Uncapped it took every pixel the score and
the risk list left and became a dome half the card high; the risk list takes
that slack instead, and has more to say than three rows.

Card shadows are removed - six cards each lifted off the page is six shadows
on one screen, and the hairline border already separates a card from its
ground. Confirmed with the user: no liquid glass, no emoji.

### 0.4s A card that shows part of a list, a row that opens, a filter that travels

Four things, all of them the same complaint in different places: the interface
knew something and did not hand it over.

**The card shows 7 of 43.** The count was flat text, which made the other 36
look like a limit rather than a fold. It is a button now - `7 of 43 · View all`
- and it opens a `<dialog class="sheet">` holding every class in the same row
the card draws, so a class looks identical in both places and clicking it does
the same thing. The list is built from `estateFacets.finding_types`, which the
card already had, so the panel costs no request.

**The row opens the file.** Two small buttons on the name did what the whole
row implied. A delegated listener on `#results-body tr[data-file-key]` now
forwards to the row's existing expand button, bailing out on
`button, select, a, input, label, [data-detail-type]` so the manual-risk select,
the reason and action counts and the copy-path button still mean what they say.
Verified: a plain cell opens the asset detail
(`#asset-detail-modal`, `status_report_m&a_009.md`), the risk select does not,
and the original buttons still work.

**The meta line is one line.** Extension, size, source and flags wrapped to two
or three lines on narrow columns and dragged every row below out of rhythm.
`fileMetaLine()` shows `FILE_META_VISIBLE = 3` and collapses the rest into a
`+N` chip whose `title` lists them. A fixed cap rather than a measured one:
measuring a hundred rows to hide a chip costs a reflow per row, and at every
width this column is used at the answer is three. Measured after: one distinct
row height, 24px, across the page.

**A top risk carries its filter.** Clicking "Regulated personal data" opened
the queue showing all 6,831 findings, which is the same as not clicking it.
Each `RISK_CATEGORIES` entry now has a `go` descriptor, and five of them resolve
to an exact server-side filter over the `category` column the classifiers
already write (`credentials_secrets` = 852, `pii,government_ids,biometric_data`
= 1,045). Two of them - a changed hash, an unreadable file - are properties of a
*file*, not of a finding, so they go to the inventory instead of asking the
queue a question it cannot answer.

That needed a `category` filter end to end: `_remediation_filter_sql` splits a
comma list into an `IN (...)`, `list_remediation_findings` takes `category`,
`/api/findings` passes it, and the facets return `categories`. Severity became a
select at the same time - it was the one control on this page that worked
differently from its neighbours, and the pill band cost a whole row of chrome to
say five words. The counts the pills carried moved onto the option labels.

One trap: `remediationSelectOptions` rebuilds a select's `innerHTML` from the
facets, which wiped an applied multi-value filter on the next load.
`openRemediationFiltered` records the applied value and label on the element's
dataset, and the rebuild re-adds any value the facets do not list - so the
control keeps showing what is actually applied.

### 0.4t Four things that were each two answers to one question

**The risk cell said the level twice and the override lived in a column.**
Under every badge sat a 7px meter filled with
`linear-gradient(90deg, low, medium, high, critical)` - the same four hues in
every row whatever the row's level, so a LOW row and a CRITICAL row painted
the identical rainbow and only the fill length differed. The badge already
carries the word and the score. It is gone.

Beside it, a whole column - measured at 191px of a 1326px table that has to
show a path - held a `Manual risk` select that almost no row uses. The
override is now a 20px caret on the badge with the platform's own `<select>`
laid transparent over it: a real menu, its keyboard, its screen reader, and no
open/close state of ours. It reads at 20px, which is the size of every other
control in this table, and offers a 28x32 target taken from the space around
it - only 2px of that from the badge, so clicking the badge still opens the
row. A row set by hand says so where the level is (`is-manual`, "Set
manually"), which is what the column used to be for.

That freed the width for `Immediate remediation` to stop being
`Immediate remediat…`. It was ellipsised by
`:root:root #results-body td:nth-child(4) .subtext { white-space: nowrap
!important }` - a rule written for paths that had caught a sentence of advice.
The path keeps the treatment; the advice wraps.

**The queue's command line held one control and 1150px of white.** Measured
at 1600px: a 234px search box and a 97px Refresh, sitting together at the left
of a 1482px band, 5px out of vertical alignment with each other because
styles.css gives that button a 14px top margin for a layout it no longer sits
in. Below them, nine facets flowed ragged across two rows - cells from 155px
to 254px - with Clear filters orphaned at the end of the second.

Now the search takes the line, the two "run it again" buttons sit at its end at
the same 32px height, and the facets are a grid of equal cells
(`repeat(auto-fit, minmax(132px, 1fr))`) with the label above the control. The
label had to move: beside a control, nine facets leave about 70px for the
value, which is how `All severities (6,831)` came to be painted over by the
select's own arrow. Above, at 12px on a 28px control, the pair is 45px - not
the 84px that label-above cost when the control was 40px tall, which is what
0.4n warned about. Nine on one row at 1600px, eight plus one at 1366px, and
the chrome above the first finding is 50px shorter than before.

Every facet select on both tables now draws one chevron of ours, because the
platform's arrow is a different mark on every OS and on this one it sat on top
of the value.

**Scrollbars: sixty-three declarations, two opposite bugs.** styles.css
declared the appearance of a scrollbar sixty-three times over eleven groups of
containers - 8px here, 12px there, 14px forced somewhere else, several with a
thumb pinned visible in the accent colour and one in cyan. On screen: the two
tables carried a permanent grey stripe 20px wide, and every panel written since
the contract sheets carried nothing at all, because the contract's hover rule
(zero specificity) lost to all of it. "There is no scrollbar" and "there is an
ugly one that never goes away" were the same bug seen from two pages.

The pile is deleted rather than out-specified - a sixty-fourth rule would not
have made the answer clearer. shell.css now holds the only definition: a 10px
track that always reserves its width, a 6px thumb at 34% of the text colour
that appears when the pointer is over that container and darkens to 52% under
the pointer. One selector had to change with it: `*:hover > ::-webkit-scrollbar-thumb`
matches nothing, because a thumb is a *part* of the scrolling element, not a
child of it.

The window gets the same bar instead of none. `scrollbar-width: none` on
`html` meant Administration - which overflows by 846px - scrolled with no
indication that it could.

**The all-classes panel was a second answer to "how does a modal work".** It
was a `<dialog class="sheet">` leaning on `::backdrop`, which computes here
(`getComputedStyle` reports the colour) but paints nothing, so the page behind
stayed bright and the panel read as a white slab; it closed only from a text
`Close` button. Three hundred lines below it in the same document, the asset
detail modal already answers this: a real backdrop element at
`rgba(2, 6, 23, .55)` with `blur(3px)`, an icon close, click-outside, Escape
and focus return. The panel takes that markup and those handlers. It needed
two rules of its own - the asset panel pins 1120px and 92vh with `!important`
for four tabs of content, and a list of classes is one column that should stop
where the list ends. `.sheet`, `.sheet::backdrop` and `.sheet-head` are
deleted; `.sheet-body` stays because it is the list, not the frame.

### 0.4a The regression F3 shipped, and the fragility it exposed

Deleting Remediation's second dashboard left one reference behind:
`msspPortfolio.addEventListener(...)` bound a click handler to
`#mssp-portfolio`, a panel that no longer exists. Every *write* to a removed
panel went through `setPanelHtml()`, which null-guards deliberately — this one
listener was the single site that did not.

The consequence was out of all proportion to the cause. `index.html` ships
`<body class="auth-locked">`, `.auth-locked .app-shell` is `display: none`, and
that document has no login screen to fall back to — so while the class is on,
the page is **literally empty**. The only code that removed it was
`setAuthState()`, called at top level on line 8886. The throw was on line 8875.
Eleven lines earlier. One dead listener took the whole console to a white
screen, and starved the `/login` redirect with it.

Two fixes, because those are two faults:

- The dead listener is deleted.
- **Unhiding the shell no longer depends on the whole file executing.** It is
  a function of one thing — is there a token — so it now happens where the
  token is read (line ~341) rather than 8,500 lines later. A failure below that
  point now costs the widget that failed, not the session. `setAuthState()`
  still runs later and remains the single entry point for login and logout.

Two tests guard it: one pins the unlock to the token read, and one enforces the
general invariant — *no top-level statement may read a property off a
`document.querySelector` handle whose selector is absent from `index.html`*.
That second test was verified by reintroducing the bug and watching it fail
with the exact file, line, handle and selector.

The lesson for the remaining F3 pages: in a 9.7k-line script with no module
boundaries, deleting a panel is not finished when the markup is gone. Fourteen
other handles now resolve to null; all of them are guarded, and the test is
what keeps it that way.

### 0.5 F4 — copy and accessibility *(done)*

**Copy.** Twenty-four strings stopped describing the implementation. The three
the assessment named are the shape of all of them:

| Was | Is |
| --- | --- |
| Summary from the normalized inventory index… | Summary only — open the row for the full evidence. |
| The browser keeps only a bounded page window while the database filters and sorts. | Loading the next page… |
| Showing built-in GDPR keywords from static fallback. Restart backend to enable import/preview API. | Import is unavailable until the service restarts. Showing the built-in GDPR keyword list. |

"Backend host" — the machine Sentro itself runs on, as opposed to the machine
being scanned — became "this server" in all ten places it appeared, which is
the distinction the reader actually has to make while holding two sets of
credentials. The health chip says `Connected` / `Not connected` rather than
`API online` / `API unavailable`.

Two words survive the §5.9 ban list on purpose: **API key** is the user's own
noun for a thing they create and revoke on the Administration page, and
**schema fields** appears only in the detector documentation panel, which is
written for the person tuning detectors. Everything else the audit found is a
loop variable named `index`, not a string.

WinRM, SMB and MSSP carry their expansion at first use, as `abbr[title]`.

**Accessibility.**

- *Focus.* Six global focus systems were layered on each other — four with
  `!important`, two of them pointing at a `--focus-ring` variable that resolves
  to nothing outside two theme blocks. The net effect on a sidebar nav button
  was an outline with style `none` and no shadow: **a keyboard user could not
  see where they were.** A seventh rule, commented "no extra border/ring on
  focus", deliberately removed the ring from the search field. All seven are
  deleted; shell.css states one ring from the token. The search field gets it
  via `:has(input:focus-visible)`, so it appears for keyboard focus and not for
  a mouse click — which is what the rule that removed it was trying to avoid.
  Measured live: **21 of 21 focusable controls show a ring; before, 7 of 21
  showed nothing.**
- *Contrast.* An automated sweep of every panel in both themes, compositing
  translucent layers: **light 9 failures → 0.** The worst was the sidebar's
  secondary labels at `#9ca3af` on a white sidebar — **2.54:1**, barely half
  the floor, on six primary destinations. The 2026-08 tone pass darkened the
  tokens used as text on white and missed this one because it assumed a tinted
  sidebar. Dark went 7 → 1.
- *A role that could not be one value.* The accent has to be a surface that
  carries white text and text that sits on a near-black ground; on dark it
  cannot be both (`#6366f1` measures 4.47:1 under white and 3.97:1 as text).
  `--indigo-ink` splits it: identical to `--indigo` on light paper, lighter on
  dark. The ledger strip's scan label and the active nav label use it.
- *Size floor.* The 10 px keyboard hint and the dashboard's 11 px card type are
  on the scale. Five sub-12 px labels remain, all on pages F3 has not reached.
- *Named controls.* 147 buttons scanned across the markup and the rendered
  templates; **0 have no accessible name.** The assessment's count of 17 has
  been closed by earlier work.

**Validation now attaches to its field.** Every wizard message landed in one
footer line — the single place a reader is not looking when a field is empty,
and a line no screen reader ever associated with the field it was about.
`showFieldError()` marks the input `aria-invalid`, wires `aria-describedby`,
puts a 12 px message under it with `role="alert"`, moves focus there, and
clears itself as soon as the reader starts typing. The endpoint step also
stopped reporting "username and password" as one problem when only one of them
is missing.

### 0.6 One known miss

The 34 px profile avatar renders white on `--indigo`, which measures **4.47:1**
in dark against a 4.5 floor. Fixing it means either deepening the dark accent
(it is also the button surface and the focus ring) or growing a 14 px initial
to 19 px so it counts as large text. Neither is worth the change for a
decorative initial that sits beside the same name in readable text, so it is
recorded rather than papered over.

### 0.7 Debt at this point

| | Baseline | Now |
| --- | ---: | ---: |
| `styles.css` lines | 24,043 | 23,755 |
| `!important` | 3,760 | 3,814 |
| `:root:root` | 352 | 352 |
| `focus-visible` rules | 62 | 44 |

`!important` moved the wrong way: the count rises with unrelated work landing
in the same file while these phases were in flight, and the deletions so far
have targeted whole *rules* rather than the override pile. That pile comes out
in F5, page by page, as each page's legacy block is deleted — the deletions
recorded above (twenty shell widths, seven focus systems, the topbar's card
treatment) are the pattern F5 repeats at scale.

---

## 1. The short version

Sentro's frontend is not bad. It has a working information architecture (six destinations, clean URLs, per-member deep links), a real dark theme, a scan setup flow that fits on one screen, and no horizontal overflow at any tested width. Those are the hard parts, and they are done.

What it does not have is **discipline**. The same product renders 43 different font sizes, 10 font weights on one page, three overlapping page-transition systems, a 104-pixel header that eats 14% of a laptop screen, and a stylesheet of 24,043 lines held together by 3,760 `!important` declarations. Every page was designed to look good on its own; nothing enforces that they look like each other. The result is exactly what you described: elements land where they land, some changes animate and some snap, and moving between pages feels like being teleported rather than travelling.

The fix is not a redesign. It is a **refit around one system**: one set of tokens, one type scale, one motion vocabulary, one shell — applied page by page, with the scan setup page (the best one) as the reference. And one addition that no competitor foregrounds, which turns Sentro's on-prem nature into a visible advantage: **provenance**. Every number in a DSPM console is the output of a specific scan of a specific place at a specific time. Sentro should say so, always, in the same spot. That single device answers the question behind most of the disorientation: *what am I looking at, and where did it come from?*

---

## 2. What the console looks like today, in numbers

### 2.1 Shell geometry (1366×768)

| Element | Measured | Comment |
| --- | ---: | --- |
| Sidebar width | 236 px | Collapses to a 68 px rail at 1024 — good |
| Top bar height | **104 px** | 13.5% of the viewport; 14.4% at 720 px tall. Competitor consoles run 48–64 px |
| Content width | 1115 px | Fine |
| Dashboard KPI band | **270 px tall** at 1280×720 | Six large tiles for six numbers: 37% of the viewport before any chart |

### 2.2 Per-page density and consistency

Measured on the live DOM after each page settled. "Font sizes" and "text colours" are the distinct computed values in use on that one page.

| Page | Scroll depth (× viewport) | Visible controls | Font sizes | Font weights | Text colours | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Dashboard | 1.86 | 3 | 11 | 4 | 5 | 2.93× at 1280×720 |
| Findings | 1.98 | **739** | 12 | **10** | 9 | 101 table rows × per-row buttons; could not be screen-captured inside a 5 s render budget |
| Remediation | 2.48 | 8 | **16** | 5 | 6 | includes **3 px and 7 px** text; cards nested 3 deep; 9 animations fire on entry |
| Scan → File server | **1.00** | 8 | 9 | 4 | 4 | fits the screen — the reference page |
| Scan → Endpoint | **1.00** | 5 | 8 | 3 | 4 | as above |
| Evidence → Reports | 2.32 | 3 | 10 | 5 | 9 | a dark gradient hero used nowhere else |
| Evidence → History | 1.03 | 2 | 6 | 6 | 8 | fine |
| Administration → Security ops | 2.24 | 17 | 10 | 4 | **11** | three cards, each with a black "terminal" output block |
| Administration → Tenants | 1.14 | 16 | 6 | 4 | 3 | fine |
| Administration → Asset rules | 1.00 | 10 | 6 | 5 | 5 | fine |
| Administration → Risk logic | **13.27** | 39 (0 above the fold) | 12 | **8** (400–950) | 12 | 50 headings on one scrolling page |

Two pages are already what the whole product should be: the two scan pages. Everything else is between two and thirteen screens tall, and the variance between pages (6 to 16 font sizes, 3 to 12 text colours) is the measurable form of "it does not feel like one product".

### 2.3 Motion — why some changes feel like teleporting

| Transition | What happens | Verdict |
| --- | --- | --- |
| Sidebar page change | **Three systems run at once**: a JS `animate()` fade + 8 px rise (180 ms), a CSS `dspmFade` (200 ms), and a staggered `mc-rise` (450 ms) on every child of the panel — then `window.scrollTo(0, {behavior: "auto"})` snaps the scroll | Overlapping, inconsistent per page, and the scroll snap defeats the fade |
| Sub-page change (Reports → History) | Same as above | Same |
| Content arriving after load | Skeleton rows are replaced by real rows via `innerHTML` (77 such replacements in `app.js`) with no cross-fade | **Snap** |
| Filter or sort change in Findings | Table body replaced instantly; 0 animations measured | **Snap** |
| Show/hide sections | 34 `classList.toggle("hidden")` sites, no transition | **Snap** |
| Theme toggle | Body `transition-duration` ≈ 0 | **Snap** — the whole screen inverts in one frame |
| Scan wizard open | Dedicated `wizardArrive` keyframe | Good — this is the model |
| Asset detail modal | `asset-modal-rise` keyframe exists | Good |
| Sign in → console | Different page, different fonts (Audiowide vs Space Grotesk), 289 lines of its own inline CSS | **The first teleport a user experiences** |

The pattern: the *places you designed deliberately* (wizard, modal) animate well; the *default paths* (page change, data arrival, filters, theme) either snap or over-animate. Users feel the inconsistency more than they would feel either extreme applied uniformly.

### 2.4 The stylesheet

| Measure | Value | Why it matters |
| --- | ---: | --- |
| Lines | 24,043 | Roughly 4× what this UI needs |
| `!important` | **3,760** | Every new rule must out-shout the last one |
| `:root:root` specificity hammers | 352 | The same problem, escalated |
| Layered "v1 … v9" override blocks | 42 | Fixes stacked on fixes; nothing is ever removed |
| Distinct `font-size` values | **43** | A type *scale* has 6–8 |
| Distinct `border-radius` values | 21 | Should be 3 |
| `box-shadow` declarations | 422 | Elevation is not a system, it is a habit |
| `text-transform: uppercase` rules | 83 | Eyebrows everywhere → nothing is emphasised |
| Distinct z-index values | 25 (0 → 20000) | Stacking is unpredictable |
| Hard-coded hex colours | 246 | vs 16 tokens declared in `:root` |
| `--accent` redefined | **13 times** | The `:root` block declares a teal `#146c63`; the accent users actually see is indigo `#4f46e5`, set 12,000 lines later. The root tokens are dead |
| `@media` blocks | 114 | Responsive behaviour is scattered rather than designed |

This is the root cause of the visual inconsistency. Position, size and spacing are not wrong because someone chose badly; they are wrong because there is no single place where the choice is made.

### 2.5 Structure, copy and accessibility

- **Heading levels:** h1 = 1, **h2 = 0**, h3 = 15, h4 = 28. Every page skips a level, so screen readers and skim-readers get no page structure.
- **Icon-only buttons:** 15 of 17 have no accessible name.
- **Implementation language on screen:** "Summary from the normalized inventory index", "The browser keeps only a bounded page window while the database filters and sorts", "Restart backend to enable import/preview API", "Local backend WinRM failed". These describe how the system is built, not what the user can do.
- **Unexplained acronyms** in labels: MSSP, WinRM, SMB, DLP, ACL. The tenant switcher's tooltip is "Switch MSSP customer".
- **Validation placement:** in the scan wizard, pressing Next with an empty name shows "Give this scan a name." as faint grey footer text, far from the empty field. The field itself does not change.
- **Tiny text:** 10 px and 10.5 px eyebrows on most pages; 3 px and 7 px labels inside remediation charts.
- **Duplicated affordances:** "New Scan" exists in the top bar and on the scan deck; the top-bar search only suggests page names.

### 2.6 What is already right (keep it)

- Six destinations with stable URLs and addressable sub-members (`/scan#endpoint`, `/evidence#history`).
- The scan deck + three-step wizard: fits one screen, animates in, reads calmly. **This is the design language the rest of the product should adopt.**
- Sidebar collapses to a rail at 1024 px; no horizontal overflow at 1024, 1280 or 1366.
- Dark theme has real parity (564 rules), not an afterthought.
- Command palette (Ctrl/Cmd+K), KPI count-ups, per-tenant guarded rendering.
- The severity palette is consistent across pages.

---

## 3. What the other DSPM consoles do — and what Sentro should not copy

Sources are public reviews and vendor documentation (linked in the appendix). No competitor console was operated hands-on for this report, so these are pattern-level observations, not pixel comparisons.

| Vendor | Organising idea of the UI | What reviewers praise | What reviewers complain about |
| --- | --- | --- | --- |
| **Wiz** | The Security Graph: everything is a node with edges; data findings correlated to identity, exposure, vulnerabilities; AI-generated graph queries | "Easy, not clunky"; context eliminates noise | Infrastructure-first; data is one lens among many |
| **Cyera** | Continuous discovery at scale; asset inventory as the centre | Speed and breadth | UI lag reported above ~200k objects in one view |
| **BigID** | Privacy-first "data map"; app-style modules | Clear bird's-eye dashboard | **"Slow and clunky"**; fine at the macro level, **tedious when you drill into a file** |
| **Varonis** | Deep enterprise permissions analytics | Actionable insights, customisable executive dashboard | **"Not very friendly", "dated", "easy to get lost in the weeds"** |
| **Securiti** | Data Command Graph unifying security, privacy and AI governance | "Great UI", good in-product education | Steep learning curve; feature complexity |
| **Microsoft Purview DSPM** | A posture dashboard of three percentages (discovered / protected / investigated), a 30-day trend, Copilot prompts | Simple, opinionated first screen | Tied to the Microsoft estate |
| **Sentra** | A seven-step executive posture briefing (dashboard → alerts → rating → compliance → risk → sensitivity → threats) | Narrative structure for executives | — |
| **Normalyze, Rubrik (Laminar)** | Conventional cloud console | Repeatedly called "intuitive", "easy to learn" | — |

**The template they share.** A cloud-console shell (dark or light), a left nav of 8–14 items, a row of 4–6 KPI tiles, a severity donut, a "top risks" table, a findings grid with a side drawer, and a **graph or map as the hero**. Sentro today looks like a competent instance of this template — which is the problem, because the template was designed for cloud estates and Sentro is not a cloud product.

**What the reviews actually tell us.** The two most-criticised consoles (Varonis, BigID) fail for the same reason: depth without a path — you can see everything and find nothing, and drilling from macro to micro is slow. The two most-praised (Wiz, Normalyze/Rubrik) win on **speed of orientation**: you always know what you are looking at and what to do next. That is a UX property, not a feature count.

### 3.1 Where Sentro is genuinely different, and should look it

Sentro is **on-prem, per-customer, and physical**: file servers, shares, folders, owners, workstations, WinRM sessions, scans that run at a time and finish. Competitors show *clouds*. Sentro shows *places*. Its numbers are not live telemetry; they are the result of a named scan of a named share at a known time — and the console already stores all of that (scan labels, run timestamps, per-scan reports, per-tenant workspaces).

That suggests a design thesis nobody in the table above owns:

> **Sentro is a ledger, not a graph.** Calm, dense, typographic, one column of truth per page — and every figure on screen carries its provenance: which scan, of what, when.

Concretely, that means: no graph hero, no gradient hero bands, no six-tile KPI walls. Numbers set in one confident display face, in one row, with the scan they came from printed beside them. It reads as *audit-grade* — which is exactly the register an on-prem security buyer trusts, and exactly what "compact, convenient, good-looking" means for this audience.

---

## 4. The target system

This is the single system every page will be refit to. It is deliberately small: the smallness *is* the design.

### 4.1 Colour — indigo stays; the palette shrinks

Sentro is blue/indigo. The refit changes **tone and discipline, never hue**. Six roles, no others in component CSS:

| Role | Value | Use |
| --- | --- | --- |
| Ink | `#0F172A` | All primary text |
| Ink-muted | `#5B6472` | Secondary text; never below 12 px |
| Paper | `#F8F9FB` | Page background (already the effective value) |
| Surface | `#FFFFFF` | Cards, tables, inputs |
| Line | `#E2E6EE` | Every border and divider — one weight, one colour |
| Indigo | `#4F46E5` | The one accent: primary action, active nav, focus ring, links. Wash: `#E0E7FF` |

Severity colours (critical / high / medium / low / protected) keep their current hues but are **reserved for severity**. Today they also colour decorative tile borders and icon chips; after the refit, if something is red it is because it is critical. Dark theme maps the same six roles onto the existing dark values; it is a token swap, not a second design.

The dead `:root` block (teal `#146c63`) is deleted; there will be exactly one `:root` and one `[data-theme="dark"]`.

### 4.2 Type — three faces, three jobs, six sizes

The product already loads the right fonts; it just uses them without a contract.

| Role | Face | Where |
| --- | --- | --- |
| **Display** | Space Grotesk 600 | Page titles and the ledger numbers only. This is what makes the console recognisably Sentro — used with restraint, it is a signature; used everywhere, it is noise |
| **Text** | Inter 400 / 500 / 600 | Everything else. Three weights, not ten |
| **Data** | JetBrains Mono 400 | Paths, scan ids, hostnames, hashes, timestamps — anything an operator might copy. Already loaded, currently applied inconsistently |

Scale: **12 · 13 · 14 · 16 · 20 · 28 px**, line-heights 1.45 for text and 1.1 for display. Eyebrow labels become 12 px / 600 / sentence case with a 6 px accent tick — not 10 px uppercase. Nothing renders below 12 px; chart labels are 12 px or are omitted and moved to a tooltip.

### 4.3 Space, radius, elevation, stacking

- Spacing scale: **4 · 8 · 12 · 16 · 24 · 32** — replaces 39 distinct padding values.
- Radius: **6** (inputs, chips), **10** (cards), **14** (modals) — replaces 21.
- Elevation: two shadows — `raised` for cards on paper, `overlay` for modals and menus. Tables and panels inside cards get borders, not shadows. Replaces 422 declarations.
- z-index: five named levels (`base 0, raised 10, sticky 100, overlay 1000, toast 1100`) — replaces 25 values.

### 4.4 Motion — one vocabulary

| Token | Duration | Easing | Used for |
| --- | ---: | --- | --- |
| `fast` | 120 ms | ease-out | Hover, focus, chip toggles, table body swaps |
| `base` | 200 ms | ease-out | Page and sub-page change (fade + 6 px rise, **no stagger**), drawer and menu open |
| `slow` | 320 ms | ease-in-out | Wizard arrival, modal, theme cross-fade |

Rules: page changes cross-fade the *panel* once — the three overlapping systems (`animate()`, `dspmFade`, `mc-rise`) become one; new content replaces skeletons through a 120 ms fade instead of an `innerHTML` snap; scroll position changes animate with the panel, never via `behavior: "auto"`; `prefers-reduced-motion` collapses everything to opacity-only at 80 ms. Anything that appears must come from somewhere; anything that leaves must go somewhere.

### 4.5 Shell — the frame every page sits in

```
┌──────────┬──────────────────────────────────────────────────────────────┐
│ SENTRO   │  ⌕ Search               [+ New scan]  ● Ready  default ▾  ☾ │ 56 px
│          ├──────────────────────────────────────────────────────────────┤
│ Dashboard│  Findings                                                    │ title row 28 px
│ Findings │  ▎HR file share · \\10.10.33.149 · 421 files · Sep 1, 05:02 │ ledger strip 36 px
│ Remediat.│──────────────────────────────────────────────────────────────│
│ Scan   ▾ │                                                              │
│ Evidence▾│              page content starts 120 px from the top,        │
│ Admin  ▾ │              not 180                                         │
│          │                                                              │
│ ● admin  │                                                              │
└──────────┴──────────────────────────────────────────────────────────────┘
```

- Top bar 104 → **56 px**. Search stays only if it searches *content*; a page-name suggester is a command palette, which already exists behind ⌘K.
- **The ledger strip** (§5.1) sits under every page title in the same place, always.
- Sidebar 236 → 220 px, rail 64 px. Unchanged structure; tightened rhythm.
- Sign-in page rebuilt on the same tokens and fonts, from the same stylesheet.

---

## 5. Page-by-page: findings and the target

### 5.1 The signature: the ledger strip

Every destination gets one 36 px line beneath its title that states the provenance of what is on screen — `scan label · file count · finished at` — in the Data face, with the scan label as the one indigo element. (This originally also carried the source and the mode; see §0.2 for why it does not.) When the user changes the scan filter, switches tenant, or a scan completes, **this line changes first**, with a 200 ms fade. Nothing else in the product tells the user *why* the numbers just changed; this does. It costs one component and pays for itself on every page, and it is the one place Sentro's on-prem, named-scan model becomes a visible advantage over consoles that show undated cloud aggregates.

### 5.2 Dashboard

*Now:* six KPI tiles 270 px tall, then a trend chart and a donut, then "Recent scans" and "Activity"; 1.86–2.93 screens.
*Target:* fits one screen at 1366×768 (≤ 1.2×).

```
Dashboard
▎HR file share · 421 files · Sep 1, 05:02 · incremental
 Critical 147   High 207   Medium 82   Low 19   Protected 1   Total 455   ← one 56 px ledger row, display face
┌────────────────────────────────────┬───────────────────────┐
│ Posture trend (14 d)               │ Where the risk is     │
│                                    │ top 6 folders / owners │
└────────────────────────────────────┴───────────────────────┘
┌────────────────────────────────────┬───────────────────────┐
│ Recent scans (5, with status dots) │ What changed since    │
│                                    │ the previous scan     │
└────────────────────────────────────┴───────────────────────┘
```

The severity donut duplicates the ledger row and is removed; "Activity" merges into "Recent scans". Four panels, two rows, no scrolling.

### 5.3 Findings (Data Inventory)

*Now:* a KPI grid, then a two-row toolbar, then a command bar of chips + three facets + framework toggles + context metrics, then a 100-row table with an expand button per row — 739 controls, 12 sizes, 10 weights.
*Target:*

- One toolbar row: search · scan selector · severity chips · **"More filters"** disclosure (finding type, framework) · density toggle · export. Two rows become one; the framework toggles leave the primary surface.
- The KPI grid goes; the ledger row already says it.
- Table: 13 px Inter, 40 px rows (a "compact" density at 32 px), sticky header, **virtualised** rows so 100 rows do not mean 700 live buttons. Row actions appear on hover and focus, not permanently.
- Detail opens in a **right-hand drawer** (480 px) rather than a full modal, so the list stays in view and drilling from macro to micro — the thing BigID is criticised for — is one click each way.
- Filter changes cross-fade the body (120 ms) and update the ledger strip's count.

### 5.4 Remediation

*Now:* a hero band, a workspace/status card, a 2-column analytics grid with cards nested three deep, a queue, an insights tab set, and a topology block — 2.5 screens, 16 font sizes including 3 px and 7 px, 9 animations on entry.
*Target:* **one queue is the page.** Ledger row on top (score · items needing review · critical/high counts). Then a single prioritised list with severity, path, owner, recommended action and a one-click "Mark reviewed / Assign". The distribution donut and top-folder bars move into a collapsible side panel. Nesting depth 3 → 1. No text under 12 px; chart labels move to tooltips.

### 5.5 Scan (File server, Endpoint)

Already the reference. Two small fixes: inline validation attached to the empty field (border + 12 px message under the input) instead of footer text; and the deck's "Latest workspace data" bar adopts the ledger-strip component so the same information appears in the same form everywhere.

### 5.6 Evidence (Reports, History)

*Now:* "Reporting center" with a dark gradient hero card, a highlighted focus paragraph, six severity tiles, then distribution and detection panels — 2.3 screens, 9 colours. History is fine.
*Target:* the hero and the six tiles go; the ledger row carries the numbers. The page becomes **a list of report packs** (one per scan, with generated date and format badges) and a composer panel. History keeps its table; its four KPI tiles adopt the ledger-row style so they match the dashboard instead of inventing a third tile design.

### 5.7 Administration (Security ops, Tenants, Asset rules, Risk logic)

- **Security ops:** three cards each ending in a black terminal block. Replace the terminals with a single status line + copyable value in the Data face; put the three forms in one 2-column layout. 11 text colours → 5.
- **Risk logic:** 13 screens tall, 50 headings, all 39 controls below the fold. Restructure as **sections with a left anchor rail** (Frameworks · Detectors · Weights · Keyword libraries), each section collapsed to a summary row that expands in place. Target ≤ 2 screens per open section.
- Tenants and Asset rules: fine; adopt tokens.

### 5.8 Sign in

Rebuild on the shared stylesheet and fonts (drop Audiowide and the 289 inline lines). Same indigo, same radius, same display face for the title. The illustration panel can stay; it should use the same six colour roles. This removes the first teleport.

### 5.9 Copy

- Replace system-speak with user-speak: "Summary from the normalized inventory index" → "Summary — open the row for full evidence"; "The browser keeps only a bounded page window…" → "Loading the next page…"; "Restart backend to enable import/preview API" → "Import is unavailable until the service restarts".
- First-use expansions for acronyms as small chips with a tooltip: **WinRM** "Windows Remote Management", **SMB** "Windows file share", **MSSP** "customer workspace".
- Verbs on buttons say what happens: "Save scan", "Start scan", "Export PDF". The toast repeats the verb: "Scan saved".
- Empty states are already good ("Run a file-server or endpoint scan to build…") — keep their voice and apply it to errors.

---

## 6. Roadmap

Effort classes: **S** = days, **M** = one to two weeks, **L** = three weeks or more. Sequencing is dependency-driven; F0 and F1 unblock everything else. Each item ends with a measurable acceptance check so "done" is not a matter of taste.

### F0 — Foundation *(S–M)* — the token contract

1. Write `styles/tokens.css`: the six colour roles + severity, the six-step type scale, spacing, radius, elevation, z-index and motion tokens from §4. One `:root`, one `[data-theme="dark"]`.
2. Delete the dead teal `:root` block and the 12 duplicate `--accent`/`--bg`/`--surface` redefinitions.
3. Add lint gates: no new `!important`, no hex outside `tokens.css`, no `font-size` outside the scale, no `text-transform: uppercase` outside `.eyebrow`. Enforce in CI on changed lines only, so the debt is frozen without a big-bang rewrite.
4. Baseline capture: screenshot every destination at 1366×768 and 1280×720, light and dark; record the density numbers from §2.2 as the "before".

**Accept when:** the token file exists and is the only place colours, sizes and durations are defined; CI blocks the four rule classes; the baseline is committed.

### F1 — Shell *(M)* — the frame

1. Top bar 104 → 56 px; single "New scan" entry; search becomes content search or is removed in favour of ⌘K.
2. Build the **ledger strip** component and mount it under every page title, fed from the existing scan-label / run / tenant state.
3. Sidebar rhythm to the spacing scale; restore an `h2` per page; page title row 28 px display face.
4. Rebuild `login.html` on the shared stylesheet and fonts.

**Accept when:** content starts ≤ 120 px from the top on every page; the ledger strip is present and identical in position on all 11 pages; sign-in and console share fonts and tokens; every page has exactly one `h1` and one `h2`.

### F2 — Motion and continuity *(S–M)*

1. Replace the three page-transition systems with one 200 ms panel cross-fade; remove `mc-rise` staggering and the `dspmFade` layer; animate scroll restoration with the panel.
2. Wrap the 77 `innerHTML` swap sites that touch visible content in a `swapContent()` helper that fades (120 ms) — table bodies, panels, KPI values.
3. Theme toggle cross-fades background, surface and text over 320 ms.
4. Findings detail moves from modal to right drawer (200 ms slide).
5. Respect `prefers-reduced-motion` in one place.

**Accept when:** an automated check finds exactly one running animation on a page change; no visible content is replaced without a transition; theme change has a measurable transition duration > 0.

### F3 — Page compaction *(L)* — one page at a time, scan deck first as the template

Order: Dashboard → Findings → Remediation → Evidence → Administration/Security ops → Risk logic. Each page: apply tokens, remove its legacy layered rules (delete, do not override), rebuild to the §5 target, compare against the baseline capture.

**Accept when (per page):** scroll depth ≤ 1.0× at 1366×768 for Dashboard and Remediation (the panel is sized to the window; a list scrolls inside its card), ≤ 1.3× for Scan, Evidence/Reports and Admin; ≤ 2.0× for Findings and Remediation; ≤ 2.0× per open section for Risk logic; ≤ 6 font sizes, ≤ 3 weights, ≤ 8 text colours on any page; nothing under 12 px; card nesting ≤ 1; visible controls above the fold on Findings ≤ 30.

### F4 — Copy and accessibility *(S)*

1. Rewrite the system-speak strings (§5.9); acronym chips.
2. Field-attached validation in the wizard and every form.
3. `aria-label` on all 17 icon-only buttons; visible focus ring from the indigo token on every interactive element; contrast ≥ 4.5:1 for all text ≥ 12 px.

**Accept when:** zero icon-only buttons without a name; an automated contrast pass is clean; no user-facing string contains "normalized", "backend", "API", "bounded", "index" or "materialized".

### F5 — Stylesheet debt *(L, runs alongside F3)*

Split `styles.css` into `tokens / base / shell / components / pages/*`. As each page is refit in F3, its legacy block is deleted. Targets at the end: `!important` < 300 (from 3,760), `:root:root` = 0 (from 352), layered "v" blocks = 0 (from 42), total ≤ 8,000 lines, 6 font sizes, 3 radii, 2 shadows, 5 z-levels.

**Accept when:** the numbers above hold and the visual regression suite (F0 baselines, updated per page) passes in light and dark at both widths.

### F6 — Verification and hand-off *(S)*

Re-run the §2 measurements; publish the before/after table; record the design system in one short page (`docs/frontend/DESIGN_SYSTEM.md`) so the next feature is built inside the contract rather than beside it.

### Sequence and effort

| Phase | Effort | Depends on | Delivers |
| --- | --- | --- | --- |
| F0 Foundation | S–M | — | The contract, the lint gates, the baseline |
| F1 Shell | M | F0 | 56 px bar, ledger strip, matching sign-in |
| F2 Motion | S–M | F0 | No more teleporting |
| F3 Compaction | L | F1, F2 | Each page fits and matches |
| F4 Copy & a11y | S | F1 | Plain language, named controls |
| F5 CSS debt | L (parallel) | F3 | A stylesheet that can be changed safely |
| F6 Verification | S | all | Numbers, not opinions |

Realistically **six to eight weeks** for one frontend engineer with design review, front-loaded: after F0–F2 (about three weeks) the product already feels like one thing, before any page has been rebuilt.

---

## 7. Risks and how the plan handles them

- **The `!important` stylesheet fights every change.** New rules cannot be layered on top; that is how it got here. The plan therefore *replaces per page* — a refit page gets clean, scoped styles and its legacy block is deleted the same day. The lint gates stop the debt from returning.
- **Regressions during the refit.** Baseline screenshots in F0 and per-page acceptance numbers in F3 make regressions visible before merge; the scan pages, which already meet the bar, act as the control.
- **Losing the dark theme.** Tokens are swapped, not restyled; both themes are in the regression set.
- **Scope creep into a redesign.** The system is intentionally small and the pages keep their information architecture. Anything not in §4–§5 is out of scope for this roadmap.
- **In-flight frontend work.** There are uncommitted changes to `app.js`, `index.html`, `sentro-fx.js` and `styles.css` in the working tree. F0 should land after they merge, so the baseline captures the real starting point.

---

## Appendix A — Measurement details

- Viewports: 1366×768 (primary), 1280×720, 1024×768. Browser pane forced `prefers-reduced-motion: reduce`, so animation *counts* were read from the Web Animations API and CSS rather than observed visually.
- Density figures count visible elements inside the active panel only; "controls" = `input | select | textarea | button`.
- Findings could not be captured as a screenshot within the pane's 5-second render budget across four attempts; all other pages captured normally. Treat that as a paint-cost signal for the 100-row table.
- CSS figures are `grep` counts over `frontend/styles.css` as of 2026-09-02.

## Appendix B — Competitor sources (public material only)

- [Top DSPM Vendors 2026 — Proofpoint comparison](https://www.proofpoint.com/us/industry-comparison/dspm)
- [Securiti alternatives: 7 DSPM platforms compared — Sentra](https://sentra.io/learn/securiti-alternatives)
- [Top 10 DSPM solutions — Cyberhaven](https://www.cyberhaven.com/blog/top-dspm-solutions)
- [9 best DSPM vendors compared — Sentra](https://sentra.io/blog/best-dspm-tools-top-9-vendors-compared)
- [Best DSPM tools — Orca Security](https://orca.security/resources/cloud-security-learning/best-dspm-tools/)
- [Wiz DSPM alternatives — Sentra](https://sentra.io/learn/wiz-dspm-alternatives)
- [Cyera data security competitors — BigID](https://bigid.com/blog/cyera-data-security-competitors/)
- [Varonis Data Security Platform reviews — Gartner Peer Insights](https://www.gartner.com/reviews/product/varonis-data-security-platform)
- [Varonis reviews — TrustRadius](https://www.trustradius.com/products/varonis-data-security-platform/reviews)
- [Varonis reviews — PeerSpot](https://www.peerspot.com/products/varonis-platform-reviews)
- [BigID pros and cons — G2](https://www.g2.com/products/bigid/reviews?qs=pros-and-cons)
- [Honest BigID review 2025 — Praxi](https://www.praxi.ai/honest-bigid-review-2025)
- [BigID Next reviews — Gartner](https://www.gartner.com/reviews/product/bigid-next)
- [Securiti pros and cons — G2](https://www.g2.com/products/securiti/reviews?qs=pros-and-cons)
- [Securiti DSPM reviews — Gartner](https://www.gartner.com/reviews/market/data-security-posture-management/vendor/securiti)
- [Wiz sensitive data security](https://www.wiz.io/blog/wiz-sensitive-data-security)
- [Identify and prioritize risks with Wiz Security Graph — Google Cloud](https://docs.cloud.google.com/architecture/partners/id-prioritize-security-risks-with-wiz)
- [Wiz adds DSPM to FedRAMP offering](https://www.wiz.io/blog/dspm-for-fedramp)
- [Cyera AI-SPM](https://www.cyera.com/platform/ai-spm)
- [Cyera features and review — Secret Digital Tools](https://secretdigitaltools.com/tools/cyera)
- [Sentra: DSPM vs legacy data security tools](https://www.sentra.io/learn/dspm-vs-legacy-data-tools)
- [Microsoft Purview DSPM — Learn](https://learn.microsoft.com/en-us/purview/data-security-posture-management-learn-about)
- [New DSPM in Microsoft Purview — Tech Community](https://techcommunity.microsoft.com/blog/microsoftmechanicsblog/new-data-security-posture-management--microsoft-purview/4471379)
- [Concentric AI vs Normalyze — PeerSpot](https://www.peerspot.com/products/comparisons/concentric-ai_vs_normalyze)
- [Rubrik DSPM reviews — Gartner](https://www.gartner.com/reviews/product/rubrik-dspm)
- [Concentric AI reviews — PeerSpot](https://www.peerspot.com/products/concentric-ai-reviews)
