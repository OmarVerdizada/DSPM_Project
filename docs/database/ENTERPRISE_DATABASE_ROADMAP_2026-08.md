# Enterprise Database Roadmap

**Status:** In implementation — Phases 0-5 closed, 6 closed except HA, 7 not
started. Audited end to end on 2026-09-02; §0.4b records what that found. §0 is the implementation record; §3 keeps the original plan with
per-phase status. Sequenced engineering plan derived from the
[Enterprise Database Readiness Assessment (2026-08-30)](ENTERPRISE_DATABASE_ASSESSMENT_2026-08-30.md).
**Verdict being remediated:** NO-GO for enterprise production; strong PostgreSQL
foundation; hardening and operating-model gaps, not a technology problem.
**Strategy:** Harden PostgreSQL as the single system of record. No rewrite.

---

## 0. Implementation record (as of 2026-09-02)

Written after the work, not before it. Every claim names the commit, the
artifact under [`docs/database/evidence/`](evidence/), or the test that proves
it. Where the implementation deliberately departed from the plan in §3, §0.3
says so and why.

### 0.1 Status at a glance

| Phase | Status | Commits | Principal proof |
| --- | --- | --- | --- |
| **0 — One authority** | **Closed** | `5721279` | Production refuses SQLite and identity mismatch; `tests/test_database_authority.py` |
| **1 — Recovery is real** | **Closed for the pilot tier** | `1b94d02` | Encrypted backup + manifest; WAL archiving live; timed restore drills PASS |
| **2 — Versioned schema control** | **Closed** | `5d238a0` | `backend/migrations.py`; revisions 0001-0004 recorded; production verify-or-refuse |
| **3 — Migration v2 + cutover** | **Closed (dev cluster)** | `d230bf3` | Schema discovery; 21 tables / 125,472 rows reconciled PASS |
| **4 — Integrity & tenancy** | **Closed for FK + roles + RLS** | `132a1c7`, `a13a038`, `b1083fb` | 16 validated FKs; role matrix verified; 16 FORCE-RLS tables; hostile rehearsal 8/8 |
| **5 — Authoritative model + artifacts** | **Closed** | `dba41b7`, `df6af2a` | Authoritative writes; report bodies in an encrypted content-addressed tier; SQLite 679→414 MB, PostgreSQL 259→185 MB |
| **6 — Operate, observe, certify** | **Closed except HA** | `d0ce540`, `a260e55`, `+` | Readiness gate; metrics surface; slow-query review; deployment + concurrency tests; retention with legal hold |
| **7 — Scale & regulated tiers** | **Not started** | — | Demand-driven by design |

Live state of `sentro_dev` on the provisioned cluster (PostgreSQL 18.4, port
5442) after the Phase 5 cutover: **185 MB, 21 application tables plus
`schema_migrations`, schema revision 7, 19 primary keys, 16 tenant foreign
keys, and 16 tables under FORCE row-level security with one isolation policy
each**, alongside a **37.3 MB artifact store holding 24 report bodies**. The
suite is **816 tests**, green on SQLite; the PostgreSQL CI job runs the same
suite against a disposable cluster.

### 0.2 What shipped, phase by phase

**Phase 0 — One authority** (`5721279`)
`backend/db.py` gained `database_identity()` (PostgreSQL: cluster system
identifier + database name via `pg_control_system()`; SQLite: resolved path)
and `enforce_database_authority()`, called from `backend/app.py` at import.
Production (`DSPM_ENV=production`) plus a SQLite DSN is a refusal with an
operator message; a mismatch against `DSPM_DB_EXPECTED_IDENTITY` is a refusal
in **any** environment. `/api/health` reports backend and non-secret identity.

**Phase 1 — Recovery is real** (`1b94d02`)
`backend/backup.py` (192 lines) writes `pg_dump -Fc` archives encrypted with a
**dedicated** Fernet key — never the vault key, so a stolen backup does not
also unlock stored scan credentials — chunked at 8 MiB with length-prefixed
tokens so backups larger than memory stream in both directions. Each backup
writes a manifest: UTC timestamp, sizes, SHA-256 of plaintext **and**
ciphertext, and per-table row counts captured at dump time.
`scripts/db_restore_drill.py` decrypts, verifies the hash, restores into a
scratch database, reconciles every table against the manifest, times each
stage, drops the scratch database, and emits evidence. WAL archiving is live
(`archive_mode=on`, `archive_timeout=300`, archiving to
`C:\SentroPostgres\wal_archive`); the archiver has since survived a service
restart at `archived_count=126, failed_count=0`.

**Phase 2 — Versioned schema control** (`5d238a0`)
`backend/migrations.py` (205 lines) records every applied revision in
`schema_migrations` (revision, name, source **checksum**, applied_at), so an
edit to an already-applied revision is detectable rather than silently
divergent. Concurrent starters serialize on a PostgreSQL advisory lock.
`store.init_db`'s DDL was extracted verbatim into
`store.apply_baseline_schema(conn)` and registered as revision 0001, so a
database built by migrations is byte-for-byte the schema the product has
always built. Startup policy moved into `store.ensure_schema_ready()`:
development auto-applies pending revisions, **production never runs DDL** — it
verifies the recorded revision equals the build's and refuses to serve
otherwise. Two details that matter operationally: `current_revision()` is a
**pure read** (it does not create its own table), so the runtime role needs no
DDL privilege to pass the gate; and the CLI sets `DSPM_MIGRATIONS_CLI=1` before
importing the store, because otherwise that import would refuse on the exact
unmigrated state the CLI exists to fix. Revision 0002 (`saved_scan_labels`)
added the indexed `scan_reports.scan_label` with a one-time JSON backfill.

**Phase 3 — Migration v2** (`d230bf3`)
`scripts/migrate_sqlite_to_postgres.py` was rebuilt (310 lines) around **schema
discovery**: tables come from `sqlite_master`, FTS5 virtual tables and their
shadow tables are excluded *structurally* (by finding the virtual tables, not
by name prefix, so a renamed index cannot leak), and the destination schema is
built by the migration runner so the copy passes the production revision gate.
Rows stream in 5,000-row batches; identity columns are discovered from the
destination catalog; reconciliation covers per-table **and per-tenant** counts
and writes a JSON artifact. The v1 hardcoded list was losing 4 of 21 tables
carrying **3,021 real rows** (`scan_object_baselines` 3,015, `scan_profiles` 5,
`app_settings` 1, `search_reconciliation_state` 0). Pinned by
`tests/test_migration_discovery.py`.

**Phase 4a — Referential integrity** (`132a1c7`, revision 0003)
Every tenant-scoped table — discovered from `information_schema`, so a new
table is covered automatically — gained a foreign key to `tenants` with **`ON
DELETE RESTRICT`**, added `NOT VALID` (short lock) then `VALIDATE` (weak lock).
Erasure stays the deliberate, audited `delete_tenant_with_data()` path; the
database now refuses a tenant delete that would strand data. The migration
**refuses to run** when orphans exist, naming them per table: a schema upgrade
never deletes data, so repair is an explicit operator decision.

**Phase 4b — Role separation** (`a13a038`)
`scripts/db_roles.py` (256 lines) establishes and *verifies* four roles:
`sentro_owner` (owns every table, runs migrations), `sentro_app` (DML only),
`sentro_backup` and `sentro_readonly` (SELECT only). `ALTER DEFAULT PRIVILEGES`
makes tables created by future migrations inherit the matrix automatically,
which is what stops the Phase 1 grant gap from reopening. Verification proves
the matrix from the catalog with `has_table_privilege()` and fails on any
deviation. Idempotent; generated passwords are appended to the operator
credentials file and never printed.

**Phase 4c — Row-level security** (`b1083fb`, revision 0004)
Sixteen tenant-scoped tables got `ENABLE` + **`FORCE`** row-level security with
one `tenant_isolation` policy each (`USING` and `WITH CHECK`), keyed on
`current_setting('app.tenant_id')`. The application side is a connection seam:
`db.tenant_scope(tenant)` sets a `ContextVar`, and `db.connect()` issues
`set_config('app.tenant_id', ..., true)` — a **`SET LOCAL`** that dies with the
transaction, so a pooled connection cannot leak one request's scope into the
next checkout. A `store._tenant_scoped` decorator wraps the ten user-facing
store functions (inventory list/facets/detail/export, scan report reads, scan
persistence). Result: inside a scoped transaction, a query with a missing *or
hostile* predicate returns nothing and writes nothing for another tenant.

**Cutover onto the provisioned cluster** (in `b1083fb`)
Executed as a real operation, in order: orphan repair (80 rows, evidence) ->
migrate v2 from the live SQLite (21 tables, 125,472 rows, PASS) -> revisions
1-4 recorded -> role matrix converged and verified -> encrypted backup taken as
`sentro_backup` -> restore drill of that backup (**25.4 s**, 125,476 rows, zero
count mismatches, hash match).

**Phase 5a — Authoritative normalized writes** (`dba41b7`)
A scan save wrote the report row and then mirrored the normalized surfaces
best-effort: a failure was logged and swallowed, so the database could hold a
report whose assets/findings projection did not exist, and the inventory read
path would then serve an estate silently missing that scan. The projection now
shares the report's transaction — if it cannot be written, the whole save fails
and nothing is persisted, in either direction.
``DSPM_NORMALIZED_WRITE_BEST_EFFORT=1`` restores the old behaviour for
emergency operation only.

**Phase 5b — The artifact tier** (`df6af2a`)
Revision 0005 adds reference columns to ``scan_reports``; bodies move to
``backend/artifacts.py``, an immutable store of gzip-compressed, encrypted
objects named by the SHA-256 of their plaintext. Reads verify that hash, so
corruption on disk surfaces as an error rather than as wrong data, and a body
re-saved unchanged (which finding-lifecycle updates do constantly) is stored
once. Three properties were built in from the start rather than bolted on,
because without them this change would have been a *recoverability
regression*:

1. **Backups cover the tier.** A backup set is now the dump plus an artifact
   archive, with object count and an inventory digest in the manifest. The
   restore drill reconciles them and fails if they disagree — a restore that
   brings back rows referencing bodies that did not come back is not a
   recovery.
2. **Erasure reaches the bodies.** ``delete_tenant_with_data()`` removes the
   tenant's subtree. Paths are tenant-scoped *precisely so* erasure is
   expressible; global content dedup would have made "delete this customer's
   data" a reference-counting problem the filesystem layout cannot state.
3. **Compression is not optional.** Fernet base64-inflates by a third, so the
   uncompressed store was **335 MB for 251 MB of JSON** — larger than the rows
   it replaced. Compressed it is **37 MB**.

Measured result of the live migration: ``scan_reports.report_json`` went from
251.6 MB to 0, SQLite from **679.4 MB to 414.2 MB**, the PostgreSQL database
from 259 MB to **185 MB**, and the restore drill got **38% faster** (25.4 s →
15.8 s) while now also restoring and reconciling 24 artifact objects. The
migration verifies every body by read-back and hash before clearing the
inline column, so a row is only emptied once its body is provably retrievable.

The work also exposed that the **test suite was writing real objects into
``data/artifacts/``** — the same leak ``conftest`` already fixed for the
database, one tier down. 513 leaked objects were collected by the new
``prune``, and the suite now gets its own artifact root.

**Phase 6 — Operate and certify** (`d0ce540`)
`/api/ready` is the serving gate: a bounded database **read *and* write** probe
plus a schema-revision match, returning 503 with reasons when it cannot serve;
backup staleness is a *warning* so an advisory signal never pulls a healthy
instance out of rotation. CI gained a PostgreSQL job that builds the schema
from empty via migrations on a disposable `postgres:18` service and runs the
whole suite against it. On the cluster, `pg_stat_statements` and
`track_io_timing` are enabled, with `pg_read_all_stats` granted to
`sentro_readonly` so operators diagnose without superuser (query text stays
privileged). `scripts/db_retention.py` prunes alert and audit history per
data-class policy, dry-run by default.

**Phase 6 — Operate, observe, certify** (`d0ce540`, `a260e55`, and the legal-hold
revision)
`/api/ready` was the first half: a bounded read **and write** probe plus a
schema-revision match, 503 with reasons when it cannot serve, and backup
staleness reported as a *warning* so an advisory signal never pulls a healthy
instance from rotation. The second half is `/api/admin/db-metrics`, which
reports the signals whose absence is how this product fails silently — pool
saturation measured against capacity, database and artifact size with disk
headroom, backup age, WAL archive health, replication lag, long transactions
and lock waits, schema revision. Every collector is individually guarded: a
metrics endpoint that dies because one optional signal is unavailable is worse
than one that reports the rest and names what it could not read. The
`warnings` list is the actionable part, and it is deliberately quiet on a
healthy installation.

`/api/admin/db-slow-queries` exposes `pg_stat_statements` timings against a
review threshold. Query text stays privileged: where PostgreSQL redacts it for
a role without `pg_read_all_stats`, the endpoint says so and points at
`sentro_readonly` **rather than widening the runtime role** — the cosmetic fix
would have been a real privilege increase.

CI gained the two deployment-shaped tests the plan asked for: every revision is
verified to be a serving state on its own (so upgrading from *any* older build
lands somewhere that works), an upgrade applies only what is missing, an older
build refuses a newer database, and concurrent starters serialize — including a
PostgreSQL test that the advisory lock is *released* rather than left held,
which would block every later deployment on the cluster.

Governance closed with **legal hold** (revision 0007): a tenant under hold
cannot be erased or pruned. It lives in the database rather than a runbook
because the code paths that delete data are the ones that must honour it —
`delete_tenant_with_data()` refuses, the retention tool excludes held tenants,
placing a hold requires a stated reason, and both directions are audited.
Verified live: the delete returns **409 while held** and succeeds only once the
hold is lifted.

### 0.3 Deliberate deviations from the plan

| Plan said | What was built | Why |
| --- | --- | --- |
| Adopt **Alembic** | A purpose-built runner (`backend/migrations.py`) | The store is a hand-rolled DB-API seam over `sqlite3` and `psycopg` with `?`->`%s` translation; Alembic assumes SQLAlchemy, which this codebase does not use anywhere. Adopting it would introduce a second connection and typing model for migrations alone. The runner keeps revisions as plain functions on the existing seam. **Cost accepted:** no autogenerate. |
| **Up/down scripts** | Forward-only revisions plus `stamp` | The rehearsed recovery path is restore-from-backup (Phase 1), proven in 25 s. A down-migration against a database holding data is usually more dangerous than that restore. `stamp` covers adopting an existing database. |
| RLS policies **default-deny** | Deny when a scope is set; unset scope (`'*'`) is permissive | Background writers — scan workers, search reconciliation, login and tenant lookup, migrations, backups — are not yet scoped. Flipping to default-deny today would break them. The policy already enforces on every path carrying user input; tightening the default is ranked follow-up #2. |
| Full **constraint graph** (child FKs, unique, check) | 16 tenant FKs only | Child FKs (`findings`->`assets`, `occurrences`->`findings`, `asset_versions`->`assets`) need composite unique keys that do not exist yet; the uniqueness work and those FKs are one unit, deferred together (§0.5 #4). |
| Compress the other **JSON surfaces** | Left as row values, with the measurement recorded (§0.4a) | PostgreSQL already compresses them via TOAST at 1.9–3.3x. Application-level gzip would add roughly 30 MB of saving on a 185 MB database while making the columns opaque to SQL — revision 0002's own backfill reads `report_json::jsonb ->> 'scan_label'` — costing CPU per read and a 57,000-row migration. Measured, then declined. |
| Production **cutover** | Cutover onto the development cluster | The user-facing server on `:8000` still serves SQLite by design — this host is the lab. Migration, reconciliation, roles, RLS, and restore are all proven against real data at production scale; flipping `DSPM_DB_URL` is a deployment decision, and Phase 0's gate keeps it honest once flipped. |

### 0.4 Defects found by the work (none were in the plan)

Building the controls surfaced real bugs. Each is fixed and regression-tested.

1. **Saved scan profiles survived tenant erasure.** `scan_profiles` rows -
   which reference vaulted credentials — were missing from
   `_TENANT_ERASURE_TABLES`, so deleting a tenant left its connection settings
   behind. Found by revision 0003's foreign keys; fixed with a regression test.
2. **The runtime role could create objects.** `sentro_app` held `CREATE` on
   schema `public` from the original single-role setup. Revoked; the role
   matrix now asserts its absence.
3. **`pg_dump` cannot dump under RLS.** It refuses rather than risk a silently
   partial dump, so the read-only backup role was granted `BYPASSRLS` — the
   correct resolution, since a backup must be complete or it is not a backup.
4. **The Phase 1 grant gap is closed.** `sentro_app` could not read
   `scan_object_baselines`; backups now run as a dedicated `sentro_backup` role
   instead of a superuser, and default privileges keep new tables covered.
5. **80 orphaned `scan_jobs` rows** referencing deleted tenants (test artifacts
   from suite runs predating session isolation) blocked FK validation on the
   real database. Repaired as a recorded operator action.
6. **The test suite built its database with legacy `init_db`**, so it carried
   no schema revisions — which masked the readiness gate. `tests/conftest.py`
   now builds through the migration runner, exactly like a real install.
7. **Alphabetical copy order violated the new foreign keys** (`alert_events`
   loaded before `tenants`). The migration now topologically sorts tables by
   the destination's FK graph.
8. **Revision 0004's RLS predicate denied every unscoped statement on a reused
   connection.** When a `SET LOCAL` scope ends, PostgreSQL reverts the GUC to
   its *session* value, which for a custom GUC that was never set at session
   level is the **empty string**, not NULL. The policy's `COALESCE` replaced
   only NULL, so `''` matched neither `'*'` nor any tenant. The bug was
   invisible on `sentro_dev` **because `db_roles.py` had set a role default of
   `'*'`** — a security control silently depending on a separate script having
   run. Found by writing the Phase 6 deployment tests against a fresh database;
   fixed in revision 0006 with a `NULLIF` guard and a regression test.
9. **The test suite wrote real objects into `data/artifacts/`** (Phase 5b), and
   **`scan_profiles` bled between tests on PostgreSQL** — both are the same
   class of isolation gap `conftest` already closed for the database.

### 0.4a Measured decision on the remaining JSON surfaces

Phase 5 asked for the other large JSON columns to be re-evaluated with
measurements recorded rather than assumed. Measured on this installation
(2026-09-02), *after* report bodies moved out:

| Surface | Rows | Logical | Stored (PostgreSQL) | TOAST ratio | gzip would give | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `finding_index.response_json` | 52,657 | 152.6 MB | 78.8 MB | 1.9× | 2.2× | **Keep** |
| `scan_object_baselines.snapshot_json` | 3,015 | 105.2 MB | 32.2 MB | 3.3× | 5.5× | **Keep** |
| `assets.detail_json` | 1,369 | 59.1 MB | 18.5 MB | 3.2× | 5.2× | **Keep** |

Reasoning, which is why the measurement mattered:

- **PostgreSQL already compresses them.** These are TOAST-eligible values and
  the production engine stores them compressed. The 679 MB SQLite figure that
  motivated this item is a *development* number; the same data is 185 MB on
  the backend Phase 0 makes mandatory in production.
- **The marginal gain is small and the cost is not.** Application-level gzip
  would save roughly 30 MB more, at the price of columns SQL can no longer
  read (revision 0002's backfill does exactly that), a CPU cost on every read,
  and a migration across 57,000 rows.
- **All three are already bounded.** `finding_index` is deleted and rewritten
  per scan and holds zero orphans; `assets.detail_json` is current-estate, one
  row per asset. Their growth tracks findings and assets — which is the
  property the exit gate asks for.
- **The real lever is retention, not encoding.** `finding_index` is the
  largest table (95 MB) because scan history is retained indefinitely.
  Choosing how long to keep scan history is a policy number an owner sets, so
  `scripts/db_retention.py` deliberately does not invent one; it does now
  collect unreferenced artifact objects, which is garbage collection rather
  than retention.

Unlike the three above, report bodies were **not** bounded — 24 rows, 251.6 MB,
a single 45 MB value, growing with report size rather than estate size. That
asymmetry is why they moved and these did not.

### 0.4b Cross-phase audit (2026-09-02)

Phases 0-6 were re-read against their own claims and probed on a live
database. Six gaps surfaced. All are fixed; each one is the kind that only
appears when a later phase changes an assumption an earlier phase made.

| # | Gap | Why it existed | Fix |
| --- | --- | --- | --- |
| 1 | **`reset_default_tenant_data` left report bodies on disk** | Phase 5b moved bodies out of the database and taught *tenant erasure* to follow them. Reset is a second erasure path and was not updated, so "reset this tenant" deleted the rows and left findings, paths and owners readable. | Both paths now share `_erase_tenant_artifacts()`, which raises rather than swallowing — an erasure that half-succeeds is worse than one that fails loudly. |
| 2 | **The migration checksum was recorded but never compared** | The module docstring claimed it made edits to an applied revision "detectable". Nothing ever read the column back. | `checksum_drift()` implements the comparison. Running it immediately found drift on revisions 0001 and 0004 — see the note below, because the finding changed the design. |
| 3 | **Tenant isolation coverage was a point-in-time fact** | Revisions 0003 and 0004 enumerate the tables that exist *when they run*. A table added by a later revision would silently have neither a tenant foreign key nor RLS, and nothing would say so. | `store.tenant_isolation_coverage()` reports the gap; a PostgreSQL test fails the build on it, and readiness warns at runtime. Proven by adding an uncovered table to a scratch database and watching the gate catch it. |
| 4 | **A missing report body surfaced as an opaque 500** | Phase 5b introduced a new failure mode — a database restored without its artifact tier — with no handler. | `ArtifactMissing` and `ArtifactCorrupted` map to 503 with the operator's next step in the body, not a stack trace. |
| 5 | **The migration copied artifact *references* but never checked the bodies** | Bodies live on the filesystem. A row-perfect migration to another host loses every report unless the object store travels too, and nothing said so. | The migration reconciles referenced bodies and reports them; the module header states the requirement. |
| 6 | **The migration died mid-copy on source referential problems** | SQLite runs with foreign keys off, so the source can hold rows whose tenant is gone. Revision 0003's foreign keys then reject them — halfway through, with a driver traceback and a half-populated destination. | `preflight_source()` refuses up front, naming the tables, counts and tenants, exactly as revision 0003 does. It fired immediately on 13 real orphaned `scan_jobs` rows. |

**The checksum finding changed its own design.** Comparing sources reported
drift on revisions 0001 and 0004 — both correct. `apply_baseline_schema` is a
deliberately *convergent* baseline whose `CREATE IF NOT EXISTS` gains the
columns that later revisions `ALTER` in, and revision 0006 re-runs 0004 on
purpose. Every revision in this project is idempotent by design, so a strict
checksum alarm would fire permanently on healthy installations. It is therefore
recorded and reported as **information** — `status` prints it, the metrics
payload carries it, and `status --strict` exits non-zero for anyone who wants
it enforced — with the docstring stating plainly that drift matters for a
revision performing a one-way data change, and is expected otherwise. A control
that cries wolf is worse than no control, and the honest version of this one is
a diagnostic rather than a gate.

Also closed in the audit: every `DSPM_*` variable the code reads is now
documented in `.env.example` (five were not, including
`DSPM_BACKUP_MAX_AGE_HOURS` and `DSPM_SLOW_QUERY_MEAN_MS`).

### 0.5 Open work, ranked

1. **Tighten the RLS unset scope to fail-closed** once background writers carry
   an explicit scope. Sequence: scope the writers, add a scoped-writer test,
   then flip the policy default in a new revision.
2. **Unique + check constraints and the child FK graph** (rest of Phase 4a).
3. **Retire `report_json`** (the contract step of revision 0005) once every
   install has run `scripts/migrate_report_bodies.py`, and retire the blob
   inventory read path after a parity soak.
4. **Add the artifact key and store to the documented recovery inventory** and
   to whatever off-host copy exists — the tier is in the backup set, but the
   key that decrypts it must be held separately and deliberately.
5. **Identity model decision** (Phase 4): `users.username` is still a **global**
   primary key, so usernames collide across tenants. Recommended: surrogate
   user id + unique `(tenant_id, username)`. Product decision, not code.
6. **TLS `sslmode=verify-full` enforcement** for non-local DSNs — currently
   documented in `.env.example`, not enforced in code. Local-only today.
7. **HA standby, failover/failback exercises, patch SLA** — infrastructure
   bound: this host has one cluster, so a standby cannot be stood up or
   exercised here. `/api/admin/db-metrics` reports the absence explicitly
   (`configured: false`) rather than letting "no lag" read as healthy.
8. **Off-host immutable backup copy** (object lock) and backup-age alerting in
   a real monitor — the metrics surface reports staleness, but nothing pages.
9. **Partitioning for high-growth tables**, once production growth is measured.
   Nothing on this host justifies it (§0.4a).

### 0.6 Evidence index

| Artifact | What it proves |
| --- | --- |
| `restore_drill_20260901T062753Z.json` | First timed restore: 19 tables, 196,818 rows, 27.3 s, PASS |
| `restore_drill_20260902T060821Z.json` | Restore of the revision-4 backup: 22 tables, 125,476 rows, hash match, 25.4 s, PASS |
| `migration_20260902T052604Z.json` | Migration v2 rehearsal with schema discovery, 21 tables |
| `migration_20260902T054714Z.json` | Rehearsal with revision 0003 FKs and topological copy order |
| `migration_20260902T060654Z.json` | **The cutover**: 125,472 rows, revision 4, zero per-tenant mismatches |
| `orphan_repair_20260902T060448Z.json` | Operator repair of 80 orphaned rows, per-tenant breakdown |
| `db_roles_20260902T060709Z.json` | Role privilege matrix verified across 22 tables, PASS |
| `rls_rehearsal_20260902T060123Z.json` | 8/8 isolation checks as the unprivileged runtime role against real data |
| `report_bodies_20260902T065106Z.json` | Report-body migration: 24 bodies, 251.6 MB moved out of the database |
| `migration_20260902T065511Z.json` | Post-artifact cutover into PostgreSQL at revision 5 |
| `restore_drill_20260902T065545Z.json` | Restore drill **including the artifact tier**: 24/24 objects, inventory match, 15.8 s |
| `orphan_repair_20260902T082407Z.json` | Source-side repair of 13 orphaned `scan_jobs` rows the new migration pre-flight refused |
| `migration_20260902T082517Z.json` | Post-audit cutover: 125,477 rows at revision 7, **24/24 report bodies reconciled present** |

Test coverage: `test_phase_audit_fixes.py` (the six gaps in §0.4b),
`test_observability.py` (metric families, guarded collectors,
warning rules), `test_migration_deployment.py` (every revision a serving
state, upgrade from a prior release, older build refuses a newer database,
concurrent starters, advisory lock released), `test_legal_hold.py` (hold
blocks erasure and retention), `test_report_artifacts.py` (round trip, content addressing,
ciphertext opacity, corruption detection, path-traversal refusal, erasure,
backup/restore of the tier), `test_normalized_write_authority.py` (atomic
saves in both directions), `test_database_authority.py` (authority + readiness),
`test_database_backup.py` (encryption round-trip, truncation refusal, key
policy), `test_schema_migrations.py` (fresh upgrade, idempotence, verify gate
both directions, stamp, startup policy), `test_migration_discovery.py`
(discovery contract), `test_tenant_rls.py` (hostile isolation, PostgreSQL
only), `test_tenant_erasure.py` (erasure completeness).

### 0.7 Operator runbook

```bash
python -m backend.migrations status
```
```bash
python -m backend.migrations status --strict
```
```bash
python -m backend.migrations upgrade
```
```bash
python scripts/db_roles.py --dbname sentro_dev --evidence-dir docs/database/evidence
```
```bash
python scripts/db_backup.py --keep 7
```
```bash
python scripts/db_restore_drill.py
```
```bash
python scripts/db_retention.py
```
```bash
python -m scripts.migrate_sqlite_to_postgres --evidence-dir docs/database/evidence
```
```bash
python scripts/migrate_report_bodies.py --dry-run
```
```bash
python scripts/db_artifacts.py verify
```
```bash
python scripts/db_artifacts.py prune --apply
```
```bash
curl -s localhost:8000/api/admin/db-metrics
```
```bash
curl -s localhost:8000/api/admin/db-slow-queries
```

`migrations status --strict` exits non-zero on checksum drift (informational
by default — see §0.4b). `db_artifacts.py verify` is the one to run after any
restore: it reads every
body the database references, through the same path the application uses.
`status` reports applied vs expected revision; `upgrade` applies pending
revisions and must run as `sentro_owner`; `stamp` adopts an existing database
without executing DDL. `db_retention.py` is a dry run until `--apply`.
DSNs and passwords are read from the environment or
`C:\SentroPostgres\credentials.env` — never passed as flags, never printed.

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

> **Status: CLOSED** (`5721279`). Implemented as planned. See §0.2.

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

> **Status: CLOSED for the pilot tier** (`1b94d02`). Backups, WAL archiving and
> timed restore drills are live. Outstanding: off-host immutable copy and
> paging alerts (§0.5 #9); RPO/RTO owner sign-off.

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

> **Status: CLOSED** (`5d238a0`), with one deviation: a purpose-built runner
> instead of Alembic, forward-only. Rationale in §0.3.

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

> **Status: CLOSED on the development cluster** (`d230bf3`, cutover in `b1083fb`).
> Reconciliation covers per-table and per-tenant counts. Outstanding: row-hash and
> business-invariant reconciliation, and the filesystem-state manifest.

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

> **Status: CLOSED for tenant FKs, role separation and RLS**
> (`132a1c7`, `a13a038`, `b1083fb`). Outstanding: unique/check constraints and the
> child FK graph (§0.5 #4), the user-identity decision (#5), TLS verify-full (#6),
> and the fail-closed RLS default (#2).

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

> **Status: CLOSED** (`dba41b7`, `df6af2a`). Normalized writes are authoritative;
> report bodies live in an encrypted content-addressed tier covered by backup,
> restore and erasure. The other JSON surfaces were measured and deliberately
> kept — see §0.4a. Remaining: dropping `report_json` (the contract step) and
> retiring the blob read path after a parity soak.

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

> **Status: CLOSED EXCEPT HA** (`d0ce540`, `a260e55`, legal hold). Readiness
> gate, metrics surface, slow-query review, PostgreSQL CI with
> migration-from-prior-release and concurrent-deployment tests, retention with
> legal hold. Outstanding and infrastructure-bound: a streaming standby and its
> failover exercises, and a patch SLA cadence — both need a second host and an
> owner, not code.

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

> **Status: NOT STARTED**, by design — demand-driven, and nothing on this host
> justifies it yet.

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

Status column added 2026-09-02: **[x]** closed, **[~]** partial, **[ ]** open.

| Risk | Phase | Status | Where it stands |
| --- | --- | :---: | --- |
| DB-01 authority split | 0 | **[x]** | Production refuses SQLite and wrong identity |
| DB-02 no recovery | 1 | **[x]** | Encrypted backups, WAL archiving, drills PASS; off-host copy open |
| DB-03 no foreign keys | 4 | **[~]** | 16 validated tenant FKs; child FK graph + unique/check open |
| DB-04 no RLS | 4 | **[x]** | 16 FORCE-RLS tables, transaction-local scope, hostile rehearsal 8/8 |
| DB-05 unversioned schema | 2 | **[x]** | Recorded revisions 0001-0004; production runs no DDL |
| DB-06 incomplete migration | 3 | **[x]** | Schema discovery; v1 was losing 4 tables / 3,021 rows |
| DB-07 report-JSON authority | 5 | **[x]** | Authoritative writes; bodies in the artifact tier; 251.6 MB out of the database |
| DB-08 fragmented state | 1 + 5 | **[~]** | Copilot store retired; report bodies now a managed, backed-up tier; `data/reports*` and `scan_cache` still undeclared |
| DB-09 observability | 1 + 6 | **[x]** | Health, readiness and a guarded metrics surface with an actionable warnings list |
| DB-10 TLS / ownership | 0 + 4 | **[~]** | Ownership and roles done; `sslmode=verify-full` not enforced |
| DB-11 retention | 6 | **[~]** | Alert/audit retention, artifact GC and legal hold done; scan-history policy needs an owner's number |
| DB-12 query diagnostics | 6 | **[x]** | `pg_stat_statements` + `track_io_timing` live |
| DB-13 PG CI | 2 + 6 | **[x]** | Migrations-from-empty + full suite on `postgres:18` per change |
| DB-14 patch discipline | 6 | **[ ]** | Needs an owner and a cadence, not code |
| P1 HA standby | 6 | **[ ]** | Single host; absence is reported explicitly rather than as healthy |

## 6. Service objectives (carried from the assessment, pending owner sign-off)

| Tier | RPO | RTO | Minimum topology |
| --- | ---: | ---: | --- |
| Controlled enterprise pilot (after Phases 0–4) | 15 min | 4 h | Primary + WAL archive + encrypted off-host backup + rehearsed restore |
| General enterprise production (after Phase 6) | 5 min | 60 min | + monitored standby/failover, quarterly recovery exercise |
| Higher-assurance tier (Phase 7) | business-defined | typically < 30 min | Synchronous/regional design, automated failover, game days |

Objectives cover PostgreSQL **and** artifacts, keys, and configuration.

## 7. Milestones and acceptance gates

**M1 — Enterprise pilot** = Phases 0–4 exit gates, plus the gate list below.
Status as of 2026-09-02: **6 of 8 met.**

| M1 gate | Met | Evidence / what is missing |
| --- | :---: | --- |
| Production refuses SQLite | **yes** | Phase 0 gate + `tests/test_database_authority.py` |
| Migration covers 100% of durable **database** state | **yes** | Schema discovery, 21/21 tables, zero mismatches |
| Migration manifest covers durable **filesystem** state | no | `data/reports/`, `data/reports_artifacts/`, `data/scan_cache/` still undeclared |
| Invariant reconciliation beyond counts | partial | Per-table and per-tenant counts done; row hashes and business invariants (assets per scan, findings per asset) open |
| Timed restore inside pilot RPO/RTO | **yes** | 25.4 s restore, 125,476 rows, hash match — far inside the 4 h RTO |
| RLS forced, hostile tests pass | **yes** | 16 FORCE-RLS tables; rehearsal 8/8; `tests/test_tenant_rls.py` |
| Runtime role cannot DDL | **yes** | `CREATE` revoked and asserted in the role matrix |
| TLS `verify-full` for non-local clients | no | Not enforced in the connection seam (§0.5 #6). Local-only deployment today, so not yet exposed |

The two unmet gates are both small and well understood; neither blocks the
work in §8, and both should close before any off-host pilot.

**M2 — General availability** = M1 + Phase 5–6 gates:
atomic normalized writes; artifact tier live; standby with exercised
failover; retention/erasure/legal hold automated and tested; PG CI
certifying every change; a quarter of operating evidence.

M2's outstanding items are the artifact tier, atomic normalized writes, HA
standby with exercised failover, and a quarter of operating evidence.

**M3 — Regulated / high-scale tiers** = M2 + Phase 7 evidence packages.

## 8. Next actions (refreshed 2026-09-02)

The original list is complete: items 1-5 shipped, item 6 remains a product
decision. The current backlog slice, in dependency order:

1. **Scope the background writers, then flip RLS to fail-closed** (§0.5 #1).
   This is now the largest remaining correctness item — and revision 0006
   showed why the unscoped case deserves care: its behaviour was resting on a
   role default set by a separate script.
2. **Land unique and check constraints, then the child FK graph** as one
   revision pair (§0.5 #2).
3. **Run `migrate_report_bodies.py` on every install, then drop `report_json`**
   in a contract revision (§0.5 #3). Until the column is gone, both shapes are
   served and the change stays reversible.
4. **Put the artifact key in the recovery inventory** and the artifact store in
   the off-host copy (§0.5 #4). The tier is inside the backup set; the key that
   decrypts it must not be.
5. **Decide the tenant-scoped user identity model** (§0.5 #5) — `users.username`
   is still globally unique, so two tenants cannot both have an `admin`.
6. **Enforce `sslmode=verify-full` for non-local DSNs** in the connection seam
   (§0.5 #6), with a test that a non-local DSN without it is refused.

---

*This document is no longer roadmap-only. Phases 0-5 are implemented, and
Phase 6 is closed except for the high-availability work a single host cannot
carry. The `sentro_dev` database on the provisioned cluster has been
migrated, constrained, role-separated, placed under row-level security, and
relieved of the report bodies that made up most of its size — which now live in
an encrypted content-addressed tier that backup, restore and erasure all reach.
§0 is the record of what changed and what remains.*
