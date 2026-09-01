# Sentro DSPM Enterprise Database Readiness Assessment

**Assessment date:** 2026-08-30  
**Scope:** Product database architecture, schema, persistence code, local runtime state, migration tooling, test coverage, security, recoverability, scalability, and operating controls  
**Decision:** **NO-GO for enterprise production in the current state**  
**Strategic recommendation:** Keep PostgreSQL as the target database and harden it; do not attempt to scale the current SQLite deployment into an enterprise control plane.

## 1. Executive decision

Sentro has a credible PostgreSQL foundation: parameterized data access, connection pooling, normalized inventory and finding tables, keyset pagination, indexed search, bounded exports, durable job records, and a rebuildable external search projection. These are appropriate building blocks for an enterprise DSPM product.

The deployed database posture is not yet enterprise-ready. The freshest product data is in the default SQLite database, while the provisioned PostgreSQL database contains older, divergent data. Neither database has declared foreign keys. PostgreSQL row-level security is not enabled, schema changes are performed by application startup instead of a versioned migration system, the SQLite-to-PostgreSQL migration omits current state, and no verifiable backup, point-in-time recovery, replication, or restore exercise was found.

The correct conclusion is therefore:

- **Local development and demonstration:** Ready.
- **Controlled, single-node pilot:** Conditional, after a verified PostgreSQL cutover and minimum recovery/security controls.
- **Enterprise single-site production:** Not ready.
- **Highly available or multi-node enterprise service:** Not ready.

This is a hardening and operating-model problem, not a reason to replace PostgreSQL. Closing the Priority 0 gates in this report would move the product toward a defensible enterprise pilot.

## 2. Scope and methodology

The assessment used four evidence classes:

1. Repository documentation, including the product, security, performance, search, inventory, and endpoint-scan roadmaps.
2. Database and persistence implementation, especially [`backend/db.py`](../../backend/db.py), [`backend/store.py`](../../backend/store.py), [`scripts/migrate_sqlite_to_postgres.py`](../../scripts/migrate_sqlite_to_postgres.py), [`scripts/provision_postgres.py`](../../scripts/provision_postgres.py), and [`backend/copilot/insight_store.py`](../../backend/copilot/insight_store.py).
3. Read-only inspection of the current SQLite databases and the locally provisioned PostgreSQL instance. Credentials and sensitive finding samples were not included in this report.
4. Comparison with official SQLite and PostgreSQL guidance, the OWASP Database Security Cheat Sheet, and NIST SP 800-53 Rev. 5.1 controls.

The operating observations describe this inspected workstation on the assessment date. External infrastructure controls not represented in the repository or visible on this host may exist; they should be supplied as evidence before changing any conclusion.

## 3. Current-state architecture

| Persistence surface | Current role | Observed state | Enterprise implication |
|---|---|---|---|
| `data/dspm.sqlite` | Default primary product database | Freshest data; 361.2 MB; 20 application tables plus FTS internals | Suitable for local/single-process use, not an HA enterprise control plane |
| PostgreSQL `sentro_dev` | Optional primary selected through `DSPM_DB_URL` | PostgreSQL 18.4; 17 application tables; data is older than SQLite | Correct target technology, but not the current source of truth and not fully operated |
| `data/insights.db` | Copilot insight store | SQLite-only; 41 insight rows | Creates a second backup, failover, and multi-node consistency domain |
| Filesystem JSON/JSONL/HTML/PDF | Copilot conversations, session state, and artifacts | Local durable files | Not covered by database HA or database restore procedures |
| Optional Meilisearch | Search projection | Designed as rebuildable metadata index | Appropriate if PostgreSQL remains authoritative and reconciliation is monitored |

### Source-of-truth finding

No active application process was present during inspection. No process, user, or machine `DSPM_DB_URL` was configured, and no project `.env` file was present. A direct `python main.py serve` launch therefore selects SQLite. [`scripts/run_app.ps1`](../../scripts/run_app.ps1) selects the locally provisioned PostgreSQL database instead.

The latest observed PostgreSQL scan report was dated 2026-08-04, while the latest SQLite report was dated 2026-08-28. PostgreSQL is therefore neither a current replica nor the active authority. Two supported launch paths can expose materially different product state. This is a critical cutover and operator-safety risk.

## 4. Data profile and storage efficiency

### Primary SQLite data

| Entity | Observed rows |
|---|---:|
| Tenants | 2 |
| Users | 1 |
| Scan reports / scan runs | 13 / 13 |
| Assets / asset versions | 904 / 904 |
| Findings | 5,614 |
| Finding occurrences / finding index | 29,231 / 29,231 |
| Object baselines | 2,136 |
| Audit events | 51 |
| Scan jobs | 11 |

Four JSON/text surfaces account for approximately 288.6 MB, or 79.9% of the entire SQLite file before other table and index overhead:

| Surface | Approximate payload bytes |
|---|---:|
| `scan_reports.report_json` | 128,988,027 |
| `finding_index.response_json` | 79,641,153 |
| `scan_object_baselines.snapshot_json` | 56,299,825 |
| `assets.detail_json` | 23,681,528 |

The largest single stored report is approximately 12.5 MB. This shows that the normalized model is still a mirror of a large report document rather than the sole authoritative model. Storage, backup, cache, write-amplification, and lifecycle costs will grow faster than the logical asset count unless this duplication is retired or moved to an immutable object-artifact tier.

### Sensitive-data minimization

No non-empty raw file `content` or `preview` field was observed across 4,669 stored file records. Finding samples were much smaller and commonly masked. That is a meaningful DSPM design strength: the control plane is not currently acting as a bulk copy of customer source data.

Paths, object identifiers, classifications, evidence samples, credentials, and scan metadata are still sensitive security data. They require encryption, tenant isolation, retention controls, access auditing, and tested erasure even when raw source files are not stored.

## 5. Enterprise readiness scorecard

| Capability | Rating | Assessment |
|---|---|---|
| Database technology | **Partial** | PostgreSQL is appropriate; SQLite remains the effective default and freshest store |
| Query and application design | **Partial/Strong** | Pooling, parameterized SQL, keyset pagination, normalized query paths, and indexed search are good foundations |
| Referential integrity | **Not ready** | Zero declared foreign keys in both inspected databases; occurrence/index tables also lack strong natural uniqueness enforcement |
| Tenant isolation | **Not ready** | Tenant filters exist in application SQL, but there is no database RLS defense and identity is globally keyed by username |
| Schema migration and upgrade safety | **Not ready** | Startup DDL and ad hoc `ALTER` logic replace versioned, reversible migrations; migration inventory is stale |
| Backup and disaster recovery | **Not ready** | No verified backup set, WAL archive, PITR, restore drill, replication, RPO, or RTO evidence was found |
| High availability | **Not ready** | Single local PostgreSQL service; no standby, replication slot, failover process, or service-level proof |
| Transport and storage protection | **Partial/Not ready** | Localhost binding and SCRAM are good; TLS is off and at-rest/backup encryption was not verified or enforced |
| Least privilege | **Partial** | Application role is not a superuser, but owns application tables and can create in the application schema |
| Observability | **Not ready** | Health endpoint does not prove DB readiness; slow-query, I/O timing, query statistics, backup age, and replication metrics are absent |
| Retention and governance | **Not ready** | Limited job pruning exists, but no complete scan/finding/audit retention, archive, legal-hold, or residency operating policy exists |
| Test posture | **Partial/Strong** | Broad SQLite suite and PostgreSQL-specific tests exist, but the current PostgreSQL schema/cutover is not continuously certified in disposable CI |

**Overall maturity:** strong product prototype and credible PostgreSQL foundation; insufficient controls for enterprise production.

## 6. Material strengths to preserve

1. **PostgreSQL compatibility is already designed in.** The DB-API seam and SQL adaptation reduce the scope of the final migration.
2. **Connection management is bounded.** PostgreSQL uses a configurable pool, validates checked-out connections, and closes the pool during application shutdown.
3. **Queries are generally parameterized.** This supports the existing security assessment's conclusion that SQL injection is not an evident systemic issue.
4. **The data model is moving in the right direction.** Assets, versions, runs, findings, occurrences, baselines, jobs, and audit events are separated into queryable tables.
5. **Enterprise query patterns have begun.** Keyset pagination, bounded counting, streaming export, PostgreSQL trigram search, and optional metadata search projection are all appropriate.
6. **Authentication control state is durable.** Login throttles and revoked tokens are not only in process memory.
7. **Production secrets are externalized.** Vault encryption keys are required outside `data/` in production, and stored secret payloads are encrypted.
8. **Observed data minimization is good.** The product did not retain raw file bodies in the inspected scan records.
9. **Test safety protects a real PostgreSQL database.** Destructive PostgreSQL tests require explicit opt-in rather than silently truncating an arbitrary configured database.

## 7. Risk register

| ID | Priority | Finding | Enterprise impact | Required treatment |
|---|---|---|---|---|
| DB-01 | **P0 / Critical** | SQLite and PostgreSQL can independently act as primary, and their data has diverged | Operators can see stale or inconsistent risk posture; writes can split across authorities | Require PostgreSQL in production, validate expected DB identity at startup, execute controlled cutover, and retire the writable SQLite primary |
| DB-02 | **P0 / Critical** | No verified backup, PITR, or restore exercise | A host, operator, ransomware, or logical-corruption event can cause unrecoverable security history | Establish encrypted off-host backups, WAL archiving/PITR, immutable copies, restore drills, owners, alerts, RPO and RTO |
| DB-03 | **P0 / High** | No foreign keys in either primary database | Orphans and cross-entity inconsistency can accumulate silently during failures or future code changes | Add tenant-aware unique keys and foreign keys, initially `NOT VALID` where necessary, repair data, then validate constraints |
| DB-04 | **P0 / High** | Tenant isolation relies on application predicates; PostgreSQL RLS is disabled | One missed predicate may become a cross-tenant disclosure in a DSPM control plane | Separate table ownership from runtime access; enable and force RLS; set transaction-local tenant context; add negative isolation tests |
| DB-05 | **P0 / High** | Schema lifecycle is startup-driven and unversioned | Multi-node startup races, partial upgrades, irreversible changes, and schema drift | Adopt a versioned migration tool and expand/contract deployment discipline; block startup on incompatible schema versions |
| DB-06 | **P0 / High** | SQLite-to-PostgreSQL migration omits current tables and the insight store | A cutover can silently lose baselines, settings, reconciliation state, or Copilot state | Build migration v2 from schema discovery; reconcile every persistent surface with row counts, keys, hashes, and business invariants |
| DB-07 | **P1 / High** | Large report JSON remains authoritative while normalized tables are best-effort mirrors | High storage and backup amplification; mirror failure can leave inconsistent query surfaces | Make normalized writes transactional and authoritative; store optional full reports as immutable, encrypted, content-addressed artifacts |
| DB-08 | **P1 / High** | Copilot state and artifacts remain in separate SQLite/filesystem stores | Database failover does not restore the full product; multi-node instances can disagree | Move transactional metadata to PostgreSQL and large artifacts to a shared encrypted object store |
| DB-09 | **P0 / High** | Database readiness and recovery posture are not observable | Service may report healthy while DB writes, replication, backups, or schema compatibility are broken | Add liveness/readiness separation, a read/write DB check, pool metrics, backup age, WAL/replication lag, migration version, and alerting |
| DB-10 | **P0 / High** | PostgreSQL TLS is disabled and runtime role owns tables | Remote production would lack verified transport identity; application compromise has DDL-level blast radius | Require `sslmode=verify-full` remotely; use separate owner, migrator, runtime, read-only, and backup roles |
| DB-11 | **P1 / High** | No complete retention, archive, partition, legal-hold, or residency policy | Unbounded cost, slower maintenance, and inability to prove governance obligations | Define per-data-class retention, legal holds, tenant erasure, archive rules, partition strategy, and audit evidence |
| DB-12 | **P1 / Medium** | PostgreSQL performance diagnostics are mostly disabled | Slow queries, index waste, I/O saturation, and regression trends will be discovered late | Enable approved query statistics and I/O timing, establish dashboards and query-review thresholds, and protect query text as sensitive metadata |
| DB-13 | **P1 / Medium** | Runtime PostgreSQL certification is not part of the default clean test path | SQLite behavior can pass while PostgreSQL syntax, migration, locking, or isolation regresses | Run every migration and integration suite against an ephemeral PostgreSQL service in CI |
| DB-14 | **P2 / Medium** | Database version maintenance evidence is absent | Known defects and security fixes may be applied inconsistently | Define supported major versions, patch SLA, pre-production rehearsal, rollback, and evidence collection |

## 8. Detailed conclusions

### 8.1 SQLite is not the enterprise production target

SQLite is an excellent embedded database and remains useful for developer setup, demonstrations, and isolated tests. Its concurrency model permits only one writer at a time, and the current product adds a process-local write lock. The inspected database also uses the rollback journal rather than WAL mode. These constraints conflict with multi-instance API servers, concurrent scan completion, durable job workers, centralized operations, and database HA.

The SQLite project itself recommends a client/server database when many clients write concurrently, when multiple application servers share the same data, or when write concurrency is important. Sentro's enterprise direction meets those conditions.

### 8.2 PostgreSQL is the right platform, but its current posture is a development posture

Positive controls include localhost-only listening, SCRAM password encryption, a non-superuser application role, revoked default public database access, full-page WAL protection, and synchronous commit.

The inspected instance is nevertheless a single local service with TLS disabled, WAL archiving disabled, no replication, no query-statistics extension, minimal connection/query logging, and no visible backup set. The application role owns all application tables and can create objects in the application schema. Those conditions are acceptable for development but not for an enterprise DSPM system of record.

### 8.3 Database-enforced tenant boundaries are required

Application tenant predicates are valuable but are not a complete isolation control. A DSPM product stores an unusually sensitive map of customer assets, locations, identities, and findings; cross-tenant disclosure would be a high-impact incident.

PostgreSQL RLS should provide a second enforcement layer. Because table owners normally bypass RLS, the runtime role must not own tables and tenant tables should use `FORCE ROW LEVEL SECURITY`. Tenant context should be set transaction-locally, never through a reusable connection-wide value that can leak through the pool. Schema keys should make cross-tenant references structurally impossible.

The current global `users.username` primary key also needs an explicit product decision. For independent enterprise tenants, prefer tenant-scoped identity such as `(tenant_id, username)` or a stable surrogate user ID with a tenant-scoped unique constraint.

### 8.4 Data integrity must move into the schema

Both inspected engines reported zero declared foreign keys. Relationships among tenants, users, scan runs, reports, assets, versions, findings, occurrences, baselines, jobs, tokens, and audit events are therefore only conventions in application code.

At minimum, the target model needs:

- Tenant-aware parent keys and foreign keys for every tenant-owned child.
- Unique constraints for stable asset, run, finding, occurrence, and idempotency identities.
- Explicit deletion behavior: restrict, cascade, soft-delete, or retention workflow according to the data class.
- Check constraints for enums, timestamps, statuses, counters, and mutually dependent fields.
- A controlled validation pass before constraints become mandatory on existing data.

### 8.5 The migration mechanism cannot yet support enterprise releases

Application import currently creates tables and applies selected columns with `CREATE TABLE IF NOT EXISTS` and ad hoc `ALTER TABLE`. This does not provide a migration graph, immutable revision history, downgrade/roll-forward procedure, locking strategy, schema compatibility contract, or auditable deployment evidence.

The current SQLite-to-PostgreSQL script lists 17 tables and omits newer primary state, including `scan_object_baselines`, `search_reconciliation_state`, and `app_settings`. It also does not migrate `data/insights.db`. Verification is mainly row-count based, while the default mode truncates the destination. This is insufficient for a controlled production cutover.

### 8.6 Recovery is a release gate, not an operations follow-up

No repository or host-local evidence of a primary database backup, scheduled backup, WAL archive, replication target, or successful restore was found. `archive_mode` is off and no replication senders or slots were active. The search runbook correctly treats the primary database backup as mandatory, but the required procedure is not implemented or evidenced.

For a DSPM system, loss of scan history, audit evidence, finding lifecycle, exception decisions, and asset ownership can undermine both operations and compliance. NIST SP 800-53 CP-9 expects backups consistent with recovery objectives, protection of backup confidentiality/integrity/availability, and testing of backup reliability and integrity.

## 9. Recommended target architecture

```text
API / worker instances
        |
        | verified TLS + bounded pool + tenant transaction context
        v
PostgreSQL primary  -------- streaming replication --------> standby / failover
        |
        +---- continuous WAL archive + encrypted base backups
        |                         |
        |                         v
        |                immutable off-host recovery store
        |
        +---- transactional metadata and normalized findings
        |
        +---- outbox/change feed ----> Meilisearch metadata projection
        |
        +---- artifact references ---> encrypted object store
                                     (immutable reports/exports; lifecycle policy)
```

Design principles:

1. PostgreSQL is the only writable system of record in production.
2. Search indexes and caches are disposable projections that can be rebuilt and reconciled.
3. Normalized tables are authoritative for operational queries and lifecycle state.
4. Large full-report artifacts are immutable, encrypted, content-addressed, and referenced by hash and object key.
5. Owner/migrator, runtime DML, read-only support, and backup roles are separate.
6. RLS and tenant-aware constraints enforce boundaries below application code.
7. Every durable product surface is included in the same recovery inventory, even if it is stored in an object store rather than PostgreSQL.

## 10. Remediation plan

### P0 — Required before an enterprise production pilot

1. **Establish one authority.** Make production startup fail if the backend is SQLite or if the connected cluster/database identity does not match the deployment's expected identity. Display the active backend and non-secret database identity in operator diagnostics.
2. **Implement versioned migrations.** Introduce a revision table and migration tool, separate DDL from normal application startup, use expand/contract changes, and validate compatibility before serving traffic.
3. **Build and rehearse migration v2.** Include every application table, `insights.db`, and required filesystem state; quiesce writes; back up both ends; migrate; compare counts, primary keys, canonical hashes, tenant totals, and scan/finding invariants; then switch once.
4. **Enforce integrity and tenancy.** Repair orphans, add unique/check/foreign-key constraints, separate ownership from runtime, enable/force RLS, and run hostile cross-tenant tests.
5. **Create a recovery service.** Enable continuous WAL archiving and encrypted base backups, retain an off-host immutable copy, alert on backup age/failure, document restore steps, and complete a timed restore exercise.
6. **Harden connection security.** Require certificate-verifying TLS for any non-local connection, rotate credentials into an enterprise secret manager, remove superuser credentials from application-host configuration, and verify storage/backup encryption.
7. **Make health operationally truthful.** Readiness must perform a bounded database operation and check schema compatibility. Add pool saturation, transaction errors, query latency, DB size, lock/deadlock, WAL/archive, replication, backup, and storage-capacity metrics.
8. **Certify PostgreSQL continuously.** Run migrations and all database integration tests against disposable PostgreSQL in CI; add migration-from-prior-release and concurrent-deployment tests.

### P1 — Required for general enterprise availability

1. Make normalized writes authoritative and transactional; remove best-effort mirror semantics.
2. Move complete reports and export artifacts to encrypted object storage with hashes, retention, and access audit.
3. Consolidate Copilot transactional state in PostgreSQL and shared artifacts in the object store.
4. Add a tested standby/failover topology and document failback.
5. Define retention and legal-hold policy; partition high-growth event/history tables after measuring production growth.
6. Enable approved query and I/O diagnostics; review the large asset index set using measured usage before pruning.
7. Make Meilisearch reconciliation lag, failed outbox work, and rebuild completion visible and alertable.

### P2 — Required for high-scale and regulated tiers

1. Execute capacity, soak, lock-contention, failover, restore, and corruption-game-day tests at projected 12–24 month scale.
2. Automate regional recovery or multi-region design according to contracted availability and residency requirements.
3. Add database activity monitoring and privileged-session controls where customer/regulatory requirements justify them.
4. Automate evidence packages for backup success, restore results, access reviews, retention execution, schema changes, and patch compliance.

## 11. Proposed service objectives

These are initial engineering targets, not contractual commitments. Product, security, and business owners should approve them from customer impact and cost analysis.

| Tier | Proposed RPO | Proposed RTO | Minimum topology |
|---|---:|---:|---|
| Controlled enterprise pilot | 15 minutes | 4 hours | PostgreSQL primary, continuous WAL archive, encrypted off-host backup, rehearsed restore |
| General enterprise production | 5 minutes | 60 minutes | Primary plus monitored standby/failover, continuous archive, quarterly recovery exercise |
| Higher-assurance tier | Business-defined, potentially near-zero | Business-defined, typically under 30 minutes | Synchronous or carefully designed regional topology, automated failover, frequent game days |

Recovery objectives must cover PostgreSQL, object artifacts, encryption keys, configuration, and any remaining filesystem state. A database-only restore is not a product restore while durable state remains fragmented.

## 12. Production acceptance gates

Enterprise production should remain blocked until all of the following are evidenced:

- [ ] Production refuses SQLite and connects only to an explicitly identified PostgreSQL authority.
- [ ] A migration manifest covers 100% of durable tables and non-database state; source and destination reconcile by business invariants and canonical hashes.
- [ ] Clean install, upgrade from the previous release, interrupted migration, and roll-forward recovery pass in disposable PostgreSQL CI.
- [ ] Every tenant-owned relationship has an approved tenant-aware key/constraint strategy and zero unexplained orphans.
- [ ] Runtime role cannot own, create, alter, or drop application schema objects.
- [ ] RLS is enabled and forced on tenant tables, with automated cross-tenant denial tests for every repository/query family.
- [ ] Non-local clients use certificate-verifying TLS; credentials and encryption keys are managed and rotated through approved secret storage.
- [ ] Encrypted backup plus PITR restore is demonstrated in an isolated environment within the approved RPO/RTO, including integrity checks.
- [ ] Readiness fails on DB outage, read-only failure, pool exhaustion, or incompatible schema; alerts cover backup age and replication/archive failure.
- [ ] Retention, legal hold, tenant erasure, and audit retention are documented, automated, and testable.
- [ ] Load/soak tests meet agreed p95/p99 latency and scan-ingest throughput at projected enterprise scale with headroom.
- [ ] Data-minimization tests prevent raw customer content from being persisted unless an explicitly approved feature and policy require it.

## 13. Final recommendation

Proceed with PostgreSQL hardening and a controlled one-time cutover. Do not certify the database for enterprise production and do not market HA or enterprise recovery guarantees until the P0 gates are demonstrated with artifacts, not only configuration intent.

No wholesale database rewrite is recommended. The highest-return sequence is:

1. Eliminate database authority ambiguity.
2. Make recovery real and tested.
3. Introduce versioned schema control.
4. Enforce integrity and tenant boundaries in PostgreSQL.
5. Make normalized data authoritative and consolidate the recovery domain.
6. Prove the result through PostgreSQL CI, scale tests, failover, and restore exercises.

With those controls, the existing PostgreSQL direction can support an enterprise DSPM product. Without them, the current deployment exposes unacceptable risks of stale state, tenant leakage, inconsistent data, and unrecoverable loss.

## 14. Authoritative references

- SQLite, [Appropriate Uses for SQLite](https://www.sqlite.org/whentouse.html) — concurrency and client/server selection guidance.
- PostgreSQL, [Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) — default-deny behavior, policy enforcement, owner bypass, and `FORCE ROW LEVEL SECURITY`.
- PostgreSQL, [Constraints](https://www.postgresql.org/docs/18/ddl-constraints.html) and [Modifying Tables](https://www.postgresql.org/docs/current/ddl-alter.html) — referential integrity and controlled constraint validation.
- PostgreSQL, [Continuous Archiving and Point-in-Time Recovery](https://www.postgresql.org/docs/current/continuous-archiving.html) — WAL archive, base backup, PITR, and standby foundations.
- PostgreSQL, [High Availability, Load Balancing, and Replication](https://www.postgresql.org/docs/current/high-availability.html) — standby and synchronous/asynchronous replication tradeoffs.
- PostgreSQL, [SSL Support for libpq](https://www.postgresql.org/docs/current/libpq-ssl.html) — certificate verification and `verify-full` guidance.
- PostgreSQL, [Monitoring Database Activity](https://www.postgresql.org/docs/current/monitoring-stats.html) and [`pg_stat_statements`](https://www.postgresql.org/docs/current/pgstatstatements.html) — database, replication, WAL, I/O, and query observability.
- OWASP, [Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html) — least privilege, TLS, protected backups, and separation of application/runtime ownership.
- NIST, [SP 800-53 Rev. 5.1](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf) — CP-9 system backup, SC-28 protection at rest, and AC-6 least privilege.

