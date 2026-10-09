# PostgreSQL WAL archive and tuning (2026-10)

Status: investigation complete; product guards shipped. The archive itself is
unchanged: nothing was deleted, and `archive_mode` was not touched. Cleaning
it up needs an operator decision (section 4).

## 1. What was found

The project's PostgreSQL 18.4 cluster (`C:\SentroPostgres\data`, port 5442)
was measured on 2026-10-05.

| Setting | Value |
|---|---|
| `wal_level` | `replica` |
| `archive_mode` | `on` |
| `archive_command` | `copy "%p" "C:\SentroPostgres\wal_archive\%f"` |
| `archive_timeout` | `5min` |
| `wal_compression` | `off` |
| `max_wal_size` | `1GB` |
| `checkpoint_timeout` | `5min` |
| `pg_stat_archiver` | 1,898 archived, 0 failed |

The archive held **1,898 segments (30 GB) and no base backup**. No
`*.backup` history file exists. The system volume had 11 GB free. During a
benchmark earlier this month it once fell to 40 MB.

Growth by day (file modification date) follows test and benchmark activity,
not idle time:

| Day | Segments | GB |
|---|---|---|
| 2026-09-01 | 158 | 2.5 |
| 2026-09-02 | 877 | 13.7 |
| 2026-09-07 | 2 | 0.0 |
| 2026-09-25 | 171 | 2.7 |
| 2026-09-28 | 174 | 2.7 |
| 2026-10-02 | 176 | 2.8 |
| 2026-10-04 | 70 | 1.1 |

Idle days add 0 to 4 segments, so `archive_timeout` is not the driver: it
switches segments only after WAL activity.

## 2. Root cause

1. **The archive cannot be restored from.** Point-in-time recovery starts from
   a physical base backup (`pg_basebackup`) and replays archived WAL from that
   backup's start. No base backup was ever taken. The product's backups
   (`backend/backup.py`) are `pg_dump` logical archives, and WAL cannot be
   replayed on top of a logical restore. So every archived segment pays its
   disk cost and protects nothing.
2. **Nothing prunes the archive.** PostgreSQL never deletes archived files;
   retention is the operator's job, normally `pg_archivecleanup` after each
   verified base backup. Nothing ran it.
3. **The write volume is large.** Every test run re-creates schemas (DDL and
   full-page images), and each benchmark writes its full estate. With
   `wal_compression=off` and a 5-minute checkpoint interval, full-page images
   dominate. For a scan save, measured on `sentro_test` with
   `scripts/pg_write_bench.py 4000 2 --partitioned` (before W2.1):

| Save | WAL | Per file | Rows | Table growth |
|---|---|---|---|---|
| First scan | 75.5 MiB | 19.3 KiB | 32,002 inserted | +47.8 MiB |
| Unchanged rescan | 109 MiB | 27.9 KiB | 16,002 inserted, 24,006 updated (15 HOT) | +38.1 MiB |

An unchanged rescan wrote more WAL than the first scan. That is W2.1's subject
(delta persistence; see the scaling roadmap). Section 7 has the numbers after
W2.1.

## 3. What not to do

- **Do not delete archive files by age or by hand.** Once a base backup
  exists, removing any segment after its start breaks every restore from it.
  Only `pg_archivecleanup`, run against the oldest base backup you keep,
  removes safely.
- **Do not turn `archive_mode` off to save space without deciding to give up
  PITR.** It needs a restart, and from then on only logical backups remain:
  recovery points become the nightly dump, not any second.
- **Do not put the archive on the data directory's volume in production.** An
  archive that fills the volume stops the database. An archive that dies with
  the volume protects against nothing but a logical error.

## 4. Decide the intent, then act (operator, superuser, not automated)

### A. PITR is intended (pilot, production)

1. **Take a base backup.** Put it on a volume other than the data
   directory's. Use a role with `REPLICATION` (the cluster superuser, or a
   dedicated replication role from the installation runbook). Never use the
   application role.

   ```
   "C:\Program Files\PostgreSQL\18\bin\pg_basebackup.exe" -h 127.0.0.1 -p 5442 -U <replication role> ^
     -D E:\SentroBackups\base\2026-10-05 -Fp -Xs -P --checkpoint=fast --manifest-checksums=SHA256
   "C:\Program Files\PostgreSQL\18\bin\pg_verifybackup.exe" E:\SentroBackups\base\2026-10-05
   ```

   The backup writes `<segment>.<offset>.backup` into the archive. That file
   name is the retention anchor.

2. **Prune what is older than the oldest base backup you keep.** Dry run
   first, then for real:

   ```
   "C:\Program Files\PostgreSQL\18\bin\pg_archivecleanup.exe" -n C:\SentroPostgres\wal_archive 000000010000000C000000XX.000000YY.backup
   "C:\Program Files\PostgreSQL\18\bin\pg_archivecleanup.exe" C:\SentroPostgres\wal_archive 000000010000000C000000XX.000000YY.backup
   ```

   On this host, the first base backup makes the 30 GB already archived
   removable. Every one of those segments predates any base backup, so none of
   them can be replayed.

3. **Schedule it.** Take a base backup nightly or weekly. On PostgreSQL 17+,
   daily incrementals with `pg_basebackup --incremental` plus
   `pg_combinebackup` are an option. After each verified backup, keep N base
   backups (two at least) and run `pg_archivecleanup` against the oldest one
   kept.
4. **Drill the restore.** Restore a base backup into a scratch instance, set
   `restore_command` and `recovery_target_time`, and record the measured RPO
   and RTO next to the drill in the database roadmap.

Size the archive volume from measurements, not guesses:

> archive volume ≥ (daily WAL × retention days) + 2 × base backup size

Daily WAL is the archive's daily growth (the operational metrics report it),
or the daily delta of `pg_stat_wal.wal_bytes`.

### B. PITR is not intended (a development or test cluster)

Logical `pg_dump` backups remain the recovery path. Setting
`archive_mode = off` and restarting stops the growth. After that, the existing
archive restores nothing and can be removed by its owner. Both steps are the
owner's decision, and neither was taken here: the archive belongs to this
host's infrastructure.

## 5. What Sentro does now

Shipped with this document:

- **Disk floor** (`backend/disk_guard.py`, `DSPM_MIN_FREE_DISK_MB`, default
  2048; 0 turns it off).
  - The floor watches the data directory, the artifact store and, when
    configured and on the same host, `DSPM_PG_DATA_DIR` and
    `DSPM_WAL_ARCHIVE_DIR`.
  - A scan is refused with HTTP 507 and says which volume is short.
  - A running partitioned scan pauses between units and stays unfinished.
    Nothing scanned is lost, and the resume sweep continues it once there is
    room. The job message says why.
- **Archive health** (`observability.wal_archive_dir_metrics`, in
  `/api/admin/db-metrics`) reports:
  - segment count and bytes;
  - oldest and newest segment age;
  - the number of base backups and the newest one's age;
  - the archive volume's free space.

  Warnings fire when:
  - the directory is missing;
  - there are segments but no base backup;
  - the archive exceeds `DSPM_WAL_ARCHIVE_WARN_GB` (default 20);
  - the volume is below 10% free.

  The archiver's own state (`pg_stat_archiver`, failures) was already
  reported.
- **Benchmark preflight.** `scripts/pg_write_bench.py` refuses to start
  unless the volume has room for about three times its estimated WAL plus
  2 GB. It reports WAL, rows inserted/updated/HOT/deleted and table growth for
  each save.

On a host where PostgreSQL runs beside Sentro, set both `DSPM_PG_DATA_DIR` and
`DSPM_WAL_ARCHIVE_DIR`. The floor then covers the volumes the database writes
to as well.

## 6. Tuning guidance

`scripts/pg_tuning_advisor.py` reads the running server's settings over
`DSPM_DB_URL` and prints each recommendation next to the current value. It
reads with any role and writes nothing. It takes the host's RAM and CPUs from
the machine it runs on, or from `--ram-gb` and `--cpus` for a separate
database host. Values are ratios of the host, not one machine's numbers.
Review them, then apply them with `ALTER SYSTEM` or in `postgresql.conf`.

In the table, "restart" means the setting needs a server restart; "reload"
means `pg_reload_conf()` is enough.

| Setting | Recommendation | Apply | Why |
|---|---|---|---|
| `shared_buffers` | ~25% of RAM, at most 16 GB | restart | estate tables are read hot |
| `effective_cache_size` | ~75% of RAM | reload | planner's view of the OS cache |
| `maintenance_work_mem` | RAM/32, 256 MB to 2 GB | reload | index builds (rev 39/40) and vacuum |
| `work_mem` | 32 MB | reload | facet GROUP BYs; per sort node, so not more |
| `wal_compression` | `lz4` (built in 18.4), else `pglz` | reload | compresses full-page images, the bulk of a save's WAL |
| `max_wal_size` / `min_wal_size` | 8 GB / 1 GB | reload | checkpoints by time during bulk writes; recycled segments |
| `checkpoint_timeout` | 15 min | reload | fewer full-page images; longer crash recovery (minutes) |
| `random_page_cost` / `effective_io_concurrency` | 1.1 / 200 on SSD | reload | index scans priced for SSD |
| `track_io_timing` | `on` (already on) | reload | I/O time in plans and statement stats |
| `shared_preload_libraries` | `pg_stat_statements` | restart | per-statement cost; then `CREATE EXTENSION pg_stat_statements` as superuser |
| `log_min_duration_statement` | 2000 ms | reload | slow statements land in the log |
| `log_autovacuum_min_duration` | 60 s | reload | long vacuums visible |
| `autovacuum_max_workers` / `autovacuum_naptime` | 4 / 30 s | restart / reload | large tables revisited sooner |
| `max_connections` | at least the sum of every process's pool + 20 | restart | see pool sizing |

### Pool sizing

Each Sentro process (the API, each queue worker) has its own pool:

- `DSPM_DB_POOL_MAX` sets the maximum (default 10);
- `DSPM_DB_POOL_MIN` sets the minimum (default 1).

The sum over all processes, plus autovacuum workers and an admin reserve, must
stay under `max_connections`. With `DSPM_PARTITION_WORKERS=1` (the default),
one scan holds one connection while it persists a unit. Raise the pool only
when the metrics show waits.

### Timeouts

Wave 1 sets these on every application connection (`backend/db.py`
`session_options`):

| Setting | Default | Variable |
|---|---|---|
| `statement_timeout` | 900 s | `DSPM_PG_STATEMENT_TIMEOUT_SECONDS` |
| `lock_timeout` | 900 s | `DSPM_PG_LOCK_TIMEOUT_SECONDS` |
| `idle_in_transaction_session_timeout` | 1800 s | `DSPM_PG_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS` |

The migration runner lifts the statement and lock timeouts for its own
transaction only. Do not lower the statement timeout below the longest unit
persist measured on the host.

### Per-table autovacuum and fillfactor

Revision 0042 sets these from the W2.1 measurements (section 7). They apply to
rows as they are written, and take only a SHARE UPDATE EXCLUSIVE lock.

| Table | Settings | Why |
|---|---|---|
| `assets` | `fillfactor = 60`, `toast_tuple_target = 256` | an unchanged file moves only `current_scan_id`; the row (about 1.4 KB with its detail inline) needs room on its page for that update to be HOT |
| `findings` | `fillfactor = 60` | an unchanged finding moves only `scan_id`, which no index covers |
| `scan_object_baselines` | `fillfactor = 80`, `toast_tuple_target = 256` | the snapshot moves out of line; presence moves `last_scan_id` |
| all three | `autovacuum_vacuum_scale_factor = 0.05`, `autovacuum_analyze_scale_factor = 0.02` | vacuumed at 5% churn, not 20% |

The heap of `assets` and `findings` takes up to about 1.7 times the pages it
did; their indexes do not change.

## 7. After W2.1

**What changed.** A row whose content is what is already stored is no longer
written again; only its presence marker moves.

- **How "unchanged" is decided.** Rows carry digests (`assets.row_digest`,
  `findings.row_digest`, `scan_object_baselines.snapshot_digest`). Each digest
  covers the content, minus the keys a reuse rewrites on every scan.
- **Assets, findings and baselines.** The presence markers move set-based: one
  statement per 900 rows.
- **Findings no longer flip twice.** They were retired and then re-asserted;
  now only the absent ones are retired.
- **Versions and access rows.** An unchanged asset version is not rewritten,
  and access rows are rewritten only for assets whose access changed.
- **Indexes.** The presence markers' indexes (revision 0039's
  `idx_assets_tenant_scan_label_current_id`, the baselines' generation index)
  were dropped. The prune reads its scope in id order instead, so presence
  updates can be HOT.

**Measured** with the same benchmark: `sentro_test`, 4,000 files with 2
findings each, partitioned, same host.

| Unchanged rescan | Before W2.1 | After W2.1 |
|---|---|---|
| Time | 9.1 s (439 files/s) | 4.2 s (943 files/s) |
| WAL | 108.6 MiB (27.8 KiB/file) | 30.0 MiB (7.7 KiB/file) |
| Row updates | 24,006 (15 HOT) | 12,006 (8,064 HOT) |
| Table growth | +37.7 MiB | +11.4 MiB |

The first save is unchanged: 76 MiB of WAL.

**Revision 0043 (W2.5) then dropped four GIN indexes that no query could
use.** Measured as the application role under FORCE RLS, with sequential scans
disabled, no plan touched them. They had been maintained on every asset and
finding write all the same.

| Same benchmark, after 0043 | WAL | Time |
|---|---|---|
| First save | 48.5 MiB (was 76.3) | 6.2 s (was 8.6) |
| Unchanged rescan | 20.8 MiB (was 30.0) | 3.9 s |

**End to end, the WAL is several times the benchmark's.** The benchmark saves
small records with 2 findings each. On 2026-10-05, the product's own
partitioned scan was run end to end on `sentro_test` with
`scripts/pg_scan_rehearsal.py`. Its corpus had about 8 findings per file, and
the WAL included each scan's records and baselines.

| Run | WAL |
|---|---|
| 4,000 files, first scan | 421.5 MiB (about 105 KiB/file) |
| 4,000 files, unchanged rescan | 179.4 MiB (about 45 KiB/file) |
| 20,000 files, first scan | 1,028 MiB (about 51 KiB/file) |

Size the archive from what the host's own estate writes, measured with that
script, not from the benchmark. The rehearsal added about 3 GB to this host's
unpruned archive.

**What remains.** Most of a rescan's WAL is now the per-scan history: one
`finding_index` row and one `finding_occurrences` row per finding per scan.
That history is kept by design. Deduplicating its response bodies is the next
step, and is listed in the scaling roadmap.

The benchmark records carry no ACL and no incremental baseline. Both paths are
covered by `tests/test_w2_delta_persistence.py`, but their WAL was not
measured here.
