# scripts/

The scripts stay in one folder because the product imports some of them (`logger.py`,
`report.py`, `generate_enterprise_test_data.py`), the tests and CI run others by path, and
several import each other. This index groups them by purpose. Run Python scripts from the
repository root with the install's interpreter (`.venv\Scripts\python.exe`). A script that
writes to a database must be given one explicitly (`--config`, `DSPM_DB_URL` or
`DSPM_DB_PATH`): an import of `backend.*` opens, and in local mode upgrades, whatever
database it resolves.

## Install and run (operators)

| Script | What it does |
|---|---|
| `preflight.ps1` | Read-only readiness checks (Windows, Python, packages, CPU/RAM/disk, config, secrets, folders, port, PostgreSQL, schema): PASS / WARN / FAIL |
| `setup.ps1` | Source install: `.venv`, hash-locked packages, folders, generated secrets, `data\config\sentro.toml`, schema, built-in admin, preflight |
| `init_install.py` | The folders/secrets/configuration step of `setup.ps1` (never overwrites, never prints a secret) |
| `start.ps1` / `stop.ps1` | Start the backend and worker of a source install (checks config and schema first) / stop them |
| `setup_postgres.ps1` | A dedicated PostgreSQL cluster as a Windows service, its role, database, extensions and schema |
| `provision_postgres.py` | Role, database and extensions on an existing PostgreSQL server (writes the URL to a protected file) |
| `db_roles.py` | Optional split roles (owner / app / backup / read-only) and their verification |
| `migrate_sqlite_to_postgres.py` | Move an existing SQLite store into PostgreSQL |
| `run_app.ps1` | Development launcher: `main.py serve` in this console against `setup_postgres.ps1`'s cluster |

## Operations and maintenance

| Script | What it does |
|---|---|
| `db_backup.py`, `db_restore_drill.py` | Encrypted PostgreSQL backup with a manifest; a timed restore drill (`main.py backup ...` is the everyday command) |
| `db_retention.py`, `db_artifacts.py`, `compact_json_columns.py` | Retention per data class; artifact store inventory/verify/collect; JSON column compaction |
| `migrate_report_bodies.py`, `backfill_normalized.py`, `backfill_asset_detail_counts.py` | One-off data migrations for databases created by old releases |
| `reindex_search.py` | The optional Meilisearch index |
| `pg_tuning_advisor.py` | Read-only PostgreSQL tuning advice for a host |
| `review_install_copy.py` | Security review of an install, on a disposable copy of its database |
| `sentro_sign.py` | The publisher's offline signing tool (licences, update packages) |
| `db_control_snapshot.py`, `db_evidence_package.py`, `db_corruption_drill.py` | Database evidence and the corruption drill |

## CI and static gates

`static_gate.py` (ruff, mypy, bandit, semgrep, eslint), `check_source_tree.py`,
`check_no_cmdline_secrets.py`, `check_frontend_tokens.py` (needs a git checkout),
`perf_gate.py`, `scale_gate.py`.

## Development tools

`generate_enterprise_test_data.py` (synthetic demo estate, also used by the console's demo
dataset), `pg_dev_cluster.ps1` (a throwaway PostgreSQL cluster), `build_report_fonts.py`,
`gdpr_confidence_eval.py`.

## Benchmarks and diagnostics (engineering only)

Measurement harnesses behind the figures in `docs/SCALING_ROADMAP_2026-10.md`. They
generate synthetic data; those that write to PostgreSQL refuse any database that is not a
`*_test` database on the local host, and several check free disk first.

`amplification_probe.py`, `c14_scale_harness.py`, `console_read_bench.py`,
`detector_benchmark.py`, `endpoint_bench.py`, `incremental_benchmark.py`,
`inventory_benchmark.py`, `parallelism_benchmark.py`, `partition_benchmark.py`,
`perf_baseline.py`, `pg_access_explain.py`, `pg_index_census.py`, `pg_scan_rehearsal.py`,
`pg_write_bench.py`, `scan_cache_cost.py`, `scan_profile.py`, `search_benchmark.py`,
`smb_bench.py`, `w22_read_bench.py`, `winrm_parallel_benchmark.py`; one-off probes
`endpoint_scope_probe.py`, `extension_scan_check.py`, `raw_endpoint_scan.py`,
`winrm_path_diagnostics.py`.
