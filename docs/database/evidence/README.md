# Retained evidence

Measurement and drill output that a reviewer can re-read. Each file is the output of a run,
kept beside the commit that produced it; nothing here is configuration, and nothing here is
read by the product. The source-tree check (`scripts/check_source_tree.py`, run in CI by
`tests/test_source_tree_hygiene.py`) refuses measurement output anywhere else.

**Owner:** the engineering lead for the database and scale work (the roadmap's C0.5/C14
lines and their successors). A new file lands here only with the run that made it, named
`<what>_<UTC timestamp>.json`; one superseded by a later run of the same check is deleted in
the commit that adds the newer one.

## docs/database/evidence/ — database phases 1-7 (2026-08-31 .. 2026-09-03)

| Files | Produced by | What it shows |
|---|---|---|
| `restore_drill_*.json` | Phase 1, encrypted backups and WAL archiving | a backup restored into a disposable database, row counts compared |
| `migration_*.json` | Phase 3, the migration runner | a rehearsal of each revision on a copy |
| `orphan_repair_*.json` | Phase 4a, validated tenant foreign keys | rows repaired before the constraints were validated |
| `db_roles_*.json`, `db_controls_*.json` | Phase 5/6, roles and row-level security | the roles' grants and the controls each one passes |
| `report_bodies_*.json` | Phase 4, report storage | report bodies moved out of rows, counts before and after |
| `capacity_soak_*.json`, `corruption_game_day_*.json` | Phase 7, certification | the capacity soak and the corruption drill |
| `packages/p7_evidence_*.zip` | Phase 7 | the certification package as handed to review |

## docs/evidence/ — M2-M4 gates (2026-09-28 onwards)

| Files | Produced by | What it shows |
|---|---|---|
| `install-review-*.json` | `scripts/review_install_copy.py` (M2 exit review) | the checks run against a copy of the installed database |
| `c14-*.json` | the C14 scale harness | bounded memory and partition plans at 3,000 and 200,000 files |
| `d2-gdpr-confidence-*.json` | D2 | precision and recall of the GDPR confidence tiers on the labelled corpus |
| `wapiti-local-*.json` | the local DAST run (C7) | a supplementary scan; CI's nightly run is authoritative |
| `track-s/` | the search track | the search engine's certification runs |
