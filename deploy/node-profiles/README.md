# Node profiles: 16 GB and 32 GB

Guidance for sizing one Sentro node - the console, its scan workers and PostgreSQL on one
host - at 16 GB or 32 GB of RAM. **Every figure here is EXTRAPOLATED** from the memory budget
of the scaling roadmap (`docs/SCALING_ROADMAP_2026-10.md`, section 26.1) and the rates
measured on the development host. **None is verified** until the G2 gate has run on a host of
each profile. Treat them as a starting point to measure from, not as a guarantee.

| File | What it is |
|---|---|
| `node-16gb.env` | Sentro settings for a 16 GB / 8 vCPU node |
| `node-32gb.env` | Sentro settings for a 32 GB / 8-16 vCPU node |
| `postgresql-16gb.conf` | PostgreSQL settings for the 16 GB node |
| `postgresql-32gb.conf` | PostgreSQL settings for the 32 GB node |

## The budget they implement (section 26.1, EXTRAPOLATED)

| Component | 16 GB | 32 GB |
|---|---|---|
| PostgreSQL `shared_buffers` | 4 GB | 8 GB |
| PostgreSQL sessions, `work_mem`, maintenance | 1 GB | 2 GB |
| File cache left to PostgreSQL | 4 GB | 10 GB |
| Scan process | 2 GB | 3 GB |
| Detector workers (up to 0.4 GiB each) | 3 GB | 5 GB |
| API and console reads | 1 GB | 1.5 GB |
| Operating system and headroom | 1 GB | 2.5 GB |

## Applying them

1. Copy the Sentro settings you want from `node-*.env` into the node's configuration file
   (`DSPM_CONFIG_FILE`) or its environment. Settings not listed keep their defaults.
2. Apply the PostgreSQL settings with `ALTER SYSTEM SET ...` or an `include` in
   `postgresql.conf`, then restart PostgreSQL. `shared_buffers` and `max_connections` need
   the restart.
3. Check the connection sum: every process that talks to PostgreSQL - the console and
   each `python main.py worker` - opens up to `DSPM_DB_POOL_MAX + DSPM_DB_POOL_MAX_API +
   DSPM_DB_POOL_MAX_HEAVY` connections (W3.4: scan, API and heavy-read pools). Keep
   `max_connections` above that sum over all processes, plus 10 for administration.
   `scripts/pg_tuning_advisor.py` does this sum for a given layout.
4. Disk: provision what section 26.2 gives for the estate (100 GB for 1M files, 150 GB
   for 2M - EXTRAPOLATED). Keep `DSPM_MIN_FREE_DISK_MB` above the WAL a unit writes: a scan
   pauses below it instead of filling the volume. When WAL is archived
   (`archive_mode = on`), the archive grows until it is pruned after a base backup; that
   pruning is the operator's to schedule.

## What changes with the estate

The profiles bound what a scan holds in memory - one unit at a time, of
`DSPM_PARTITION_MAX_FILES` files and `DSPM_PARTITION_MAX_BYTES` of reads - so the same
profile serves 200K and 2M files; what grows with the estate is disk, and the time a scan
takes (section 26.2). More than 32 GB is not needed by anything in the design.
