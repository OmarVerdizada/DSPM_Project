# Enterprise Database Roadmap

**Status:** Roadmap — sequenced engineering plan derived from the
[Enterprise Database Readiness Assessment (2026-08-30)](ENTERPRISE_DATABASE_ASSESSMENT_2026-08-30.md).
**Verdict being remediated:** NO-GO for enterprise production; strong PostgreSQL
foundation; hardening and operating-model gaps, not a technology problem.
**Strategy:** Harden PostgreSQL as the single system of record. No rewrite.

---

## 1. What changed since the assessment (verified 2026-09-01)

The assessment describes the repository on 2026-08-30. Three facts have since
changed and reshape the plan:

| Assessment fact | Current fact | Roadmap impact |
| --- | --- | --- |
| `data/insights.db` (41 rows) + Copilot conversations/artifacts on the filesystem | **Gone** — Copilot was removed in full (`53205fb`); the insight store no longer exists | DB-08 shrinks: the second SQLite consistency domain is retired. Remaining fragmented state: `data/reports/` JSON, `data/reports_artifacts/` PDFs, `data/scan_cache/` |
| Migration script omits 3 tables | Omits **4 of 21** — `scan_profiles` (saved scan decks, added `3fbc3ae`) is new durable product state on top of `app_settings`, `scan_object_baselines`, `search_reconciliation_state` | DB-06's gap widened; static table lists rot. Migration v2 must discover schema, not enumerate it |
| 20 application tables | 21 (scan_profiles); `assets` gained `scan_label` | Any manifest, backup inventory, or RLS policy set must be generated from the live schema |

Also re-verified: SQLite journal mode is `delete` (not even WAL) and
`PRAGMA foreign_keys` is off — the assessment's integrity findings stand.

## 2. Guiding principles (fixed for every phase)

1. **PostgreSQL is the only writable authority in production.** SQLite remains
   for development, demos, and tests only.
2. **Projections are disposable.** Meilisearch, caches, and the finding index
   must be rebuildable and reconciled; losing them loses nothing.
3. **Artifacts are immutable.** Full reports and exports become
   content-addressed, encrypted objects referenced by hash — never re-written.
4. **Enforcement lives below the application.** Constraints, RLS, and role
   separation must hold even when application code is wrong.
5. **Every claim ships with evidence.** A control that has not produced an
   artifact (restore timing, reconciliation report, CI run) does not count.
6. **Preserve what works:** parameterized SQL, pooling with checkout
   validation, keyset pagination, bounded exports, data minimization (no raw
   file bodies stored), the destructive-test opt-in guard, and externalized
   production secrets.

---

## 3. Phase plan

Each phase lists its risk coverage, the work, and a hard exit gate. Phases 0–4
are the P0 set: all must close before an enterprise pilot. Sizes are
engineering effort classes (S ≈ days, M ≈ 1–2 weeks, L ≈ 3+ weeks).

### Phase 0 — One authority *(DB-01, part of DB-10)* — size S

The most dangerous current property: two supported launch paths serve
different data (SQLite fresh, PostgreSQL 24 days stale).

- Production startup **fails** unless `DSPM_DB_URL` selects PostgreSQL;
  `DSPM_ENV=production` + SQLite = refusal with a clear operator message.
- Startup validates connected **database identity** (cluster/system
  identifier + database name) against the deployment's expected identity, so
  a mis-pointed DSN cannot silently serve the wrong estate.
- Operator diagnostics (health payload + admin page) display the active
  backend and non-secret identity; the console shows it in Administration.
- The writable-SQLite path is fenced: local mode only, and `run_app.ps1` and
  `main.py serve` agree on the same selection logic.

**Exit gate:** a production-mode boot against SQLite or a wrong-identity
PostgreSQL refuses to serve; evidence is the startup log + a test.

### Phase 1 — Recovery is real *(DB-02, backup half of DB-09)* — size M

Recovery is a release gate, not an operations follow-up. Nothing else in this
roadmap matters if the estate cannot be restored.

- Enable continuous WAL archiving (`archive_mode=on`) and scheduled encrypted
  base backups (pgBackRest or pg_basebackup + age/AES, per ops preference).
- Off-host immutable copy (object-lock or equivalent write-once retention).
- The recovery inventory covers **everything durable**: PostgreSQL, the
  vault key, JWT/evidence keys, `data/reports/`, `data/reports_artifacts/`,
  and configuration. A database-only restore is not a product restore.
- Alerting on backup age and archive failure.
- **A timed, documented PITR restore drill** into an isolated environment,
  with integrity checks (tenant totals, latest scan id, findings counts).

**Exit gate:** restore drill artifact showing RPO ≤ 15 min / RTO ≤ 4 h
(pilot targets, §6), signed off by an owner.

### Phase 2 — Versioned schema control *(DB-05)* — size M

Startup-driven DDL (`CREATE TABLE IF NOT EXISTS` + ad hoc `ALTER` in
`backend/store.py init_db`) cannot support multi-node upgrades.

- Adopt Alembic (or equivalent): revision table, immutable migration graph,
  up/down scripts, lock strategy for concurrent starters.
- Snapshot the current schema as the **baseline revision**; new DDL lands as
  revisions, never in `init_db`. `init_db` shrinks to a compatibility check.
- Expand/contract discipline documented: additive first, backfill, contract
  in a later release; no destructive change in the same release that
  deploys code depending on it.
- Application refuses to serve when the schema revision is ahead/behind its
  supported range.

**Exit gate:** clean install and upgrade-from-previous-release both pass in
CI via migrations only; `init_db` performs no DDL in production mode.

### Phase 3 — Migration v2 and the one-time cutover *(DB-06)* — size M

- Rebuild `scripts/migrate_sqlite_to_postgres.py` around **schema
  discovery**: enumerate tables from the live SQLite catalog (minus FTS
  internals) so a new table can never be silently dropped again. The current
  script's 17-table list already misses 4.
- Include filesystem state in the cutover manifest: reports, report
  artifacts, scan cache disposition (cache may be declared rebuildable —
  but declared, in writing).
- Reconciliation beyond row counts: primary keys, canonical row hashes per
  table, per-tenant totals, and business invariants (assets per scan,
  findings per asset, latest scan ids, estate facet totals).
- Rehearse on a copy; then production cutover: quiesce writes → back up both
  ends → migrate → reconcile → flip `DSPM_DB_URL` → Phase 0 gate keeps it
  flipped. SQLite file is archived read-only, not deleted.

**Exit gate:** reconciliation report artifact with zero unexplained deltas;
Phase 0's identity check now points at the migrated cluster.

### Phase 4 — Integrity and tenancy in the schema *(DB-03, DB-04, rest of DB-10)* — size L

The riskiest phase; runs only on PostgreSQL, after cutover, via Phase 2
migrations.

- **Constraint graph:** tenant-aware foreign keys for every tenant-owned
  child (assets→tenants, findings→assets, occurrences→findings,
  asset_versions→assets, scan_runs/reports/jobs/profiles→tenants, …), added
  `NOT VALID`, orphan repair, then `VALIDATE CONSTRAINT`. Unique constraints
  for stable identities (asset id, run id, finding id, occurrence identity,
  profile id) and check constraints for enums/counters/timestamps.
- **Role separation:** `sentro_owner` (DDL, used by migrations only),
  `sentro_app` (DML only, owns nothing, cannot CREATE), `sentro_readonly`
  (support), `sentro_backup`. Runtime credentials rotate into the approved
  secret store.
- **RLS:** enable + `FORCE ROW LEVEL SECURITY` on every tenant-owned table;
  tenant context set **transaction-locally** (`SET LOCAL`) by the request
  layer so pooled connections cannot leak context; policies default-deny.
- **Identity decision:** resolve the global `users.username` key —
  recommended: stable surrogate user id + unique `(tenant_id, username)`.
  This is a product decision; the roadmap only forces the decision date.
- **Hostile tests:** automated cross-tenant denial tests for every query
  family, running in PostgreSQL CI, written to fail if RLS is off.
- **Transport:** `sslmode=verify-full` required for any non-local DSN.

**Exit gate:** zero orphans; runtime role demonstrably cannot DDL; a
deliberately broken application predicate still cannot read another
tenant's rows (test artifact); TLS enforced remotely.

### Phase 5 — Authoritative normalized model and the artifact tier *(DB-07, residual DB-08)* — size L

79.9% of the 361 MB SQLite file is four JSON surfaces; the largest report is
12.5 MB. The normalized model must stop being a mirror.

- Normalized writes become **transactional and authoritative**: a scan save
  that cannot write assets/findings/index fails the save, instead of the
  current best-effort savepoint mirror.
- `scan_reports.report_json` (129 MB) and export artifacts move to an
  **immutable, encrypted, content-addressed artifact store** (filesystem
  object layout first, S3-compatible later); the database keeps hash +
  object key + metadata. The PDF pipeline (`backend/reporting`) reads
  through the same reference.
- Re-evaluate `finding_index.response_json` (80 MB) and
  `scan_object_baselines.snapshot_json` (56 MB): keep what measured read
  paths justify, bound or compress what they don't. Decisions recorded with
  the measurements.
- The read-switch flags (`DSPM_READ_FROM_NORMALIZED`,
  `DSPM_INVENTORY_FROM_NORMALIZED`) graduate: normalized becomes the only
  path; blob fallbacks retire after a parity soak.

**Exit gate:** a scan save is atomic across normalized surfaces; the
database no longer stores full report bodies; storage growth tracks asset
count, not report size.

### Phase 6 — Operate, observe, certify *(DB-09, DB-11, DB-12, DB-13, DB-14 + P1 HA)* — size L, parallelizable

- **Truthful health:** liveness vs readiness split; readiness performs a
  bounded read+write probe and schema-revision check. Metrics: pool
  saturation, query latency, transaction errors, DB size, locks, WAL/archive
  lag, replication lag, backup age, storage headroom.
- **Query diagnostics:** `pg_stat_statements` + I/O timing on; dashboards
  and a slow-query review threshold; query text treated as sensitive.
- **PostgreSQL CI:** every migration and DB integration suite runs against a
  disposable PostgreSQL service on every change; adds
  migration-from-prior-release and concurrent-deployment tests. (Today's
  clean test path is SQLite-first; PG certification is opt-in.)
- **HA:** monitored streaming standby, documented failover *and failback*,
  quarterly failover exercise.
- **Retention & governance:** per-data-class retention (scan history,
  findings lifecycle, audit events, artifacts), tenant erasure that provably
  spans PostgreSQL + artifacts, legal hold, partitioning for high-growth
  tables once production growth is measured.
- **Patch discipline:** supported major versions, patch SLA, rehearsal,
  rollback, evidence.

**Exit gate:** the §7 gates for GA all evidenced; one full quarter of
green backup/restore/failover exercises.

### Phase 7 — Scale and regulated tiers *(P2)* — size L, demand-driven

Capacity/soak/lock-contention tests at projected 12–24-month scale;
corruption game days; regional recovery or multi-region per contract;
database activity monitoring where customers require it; automated evidence
packages (backup success, restore results, access reviews, retention runs,
schema changes, patch compliance).

---

## 4. Sequencing rationale

- **Authority before recovery** (0→1): backing up the wrong database is
  evidence theater. One authority makes the backup target unambiguous.
- **Recovery before schema surgery** (1→2–4): constraint validation, orphan
  repair, and cutover are exactly the operations that occasionally go wrong;
  they are only safe above a rehearsed restore.
- **Versioned migrations before constraints** (2→4): the FK/RLS work is the
  first big consumer of the migration system — it must not land as startup
  DDL, which is the anti-pattern being retired.
- **Cutover before RLS** (3→4): validating constraints and policies twice
  (once per engine) doubles the riskiest work; SQLite cannot express RLS at
  all.
- **Artifact tier after authority + recovery** (5): moving 288 MB of JSON is
  a data migration in its own right and belongs on the hardened platform.
- **Observability continuously, certified last** (6): metrics land with each
  phase; the phase closes when a quarter of evidence exists.

## 5. Risk-to-phase map

| Risk | Phase | | Risk | Phase |
| --- | --- | --- | --- | --- |
| DB-01 authority split | 0 | | DB-08 fragmented state | 1 (inventory) + 5 (artifacts) — *partially retired by Copilot removal* |
| DB-02 no recovery | 1 | | DB-09 observability | 1 + 6 |
| DB-03 no foreign keys | 4 | | DB-10 TLS / ownership | 0 + 4 |
| DB-04 no RLS | 4 | | DB-11 retention | 6 |
| DB-05 unversioned schema | 2 | | DB-12 query diagnostics | 6 |
| DB-06 incomplete migration | 3 | | DB-13 PG CI | 2 + 6 |
| DB-07 report-JSON authority | 5 | | DB-14 patch discipline | 6 |

## 6. Service objectives (carried from the assessment, pending owner sign-off)

| Tier | RPO | RTO | Minimum topology |
| --- | ---: | ---: | --- |
| Controlled enterprise pilot (after Phases 0–4) | 15 min | 4 h | Primary + WAL archive + encrypted off-host backup + rehearsed restore |
| General enterprise production (after Phase 6) | 5 min | 60 min | + monitored standby/failover, quarterly recovery exercise |
| Higher-assurance tier (Phase 7) | business-defined | typically < 30 min | Synchronous/regional design, automated failover, game days |

Objectives cover PostgreSQL **and** artifacts, keys, and configuration.

## 7. Milestones and acceptance gates

**M1 — Enterprise pilot** = Phases 0–4 exit gates, plus:
production refuses SQLite; migration manifest covers 100% of durable state
with invariant reconciliation; timed PITR restore inside pilot RPO/RTO;
RLS forced with passing hostile tests; runtime role cannot DDL; TLS
verify-full for non-local clients.

**M2 — General availability** = M1 + Phase 5–6 gates:
atomic normalized writes; artifact tier live; standby with exercised
failover; retention/erasure/legal hold automated and tested; PG CI
certifying every change; a quarter of operating evidence.

**M3 — Regulated / high-scale tiers** = M2 + Phase 7 evidence packages.

## 8. Immediate next actions (the first backlog slice)

1. Add the production SQLite-refusal + database-identity check to startup
   (Phase 0 — small, high leverage, unblocks nothing-but-protects-everything).
2. Stand up WAL archiving + encrypted base backup on the provisioned
   instance and run the first restore drill (Phase 1).
3. Introduce Alembic with the baseline revision; freeze `init_db` DDL
   (Phase 2).
4. Rewrite the migration script around schema discovery and add the
   invariant reconciliation report (Phase 3 prep).
5. Draft the FK/unique/check constraint graph and the RLS policy set from
   the live 21-table schema, as migration files awaiting Phase 4.
6. Decide the tenant-scoped user-identity model (product decision with a
   date, not code).

---

*Roadmap only — no changes have been made to the database, schema, or
runtime as part of this document.*
