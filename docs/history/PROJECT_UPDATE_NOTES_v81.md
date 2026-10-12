# DSPM Project v81 - Product Frontend Polish + Protected Content Detection

## Frontend fixes
- Fixed the dashboard admin/profile dropdown so it renders above the hero section with an opaque product-style panel and higher stacking context.
- Removed the loose duplicated executive top-file cards at the bottom of the Remediation Center; the structured "Critical and high files" queue is now the single source of truth.
- Added a collapsible sidebar menu with persisted session state.
- Added risk-colored filter chips for All, Critical, High, Medium, Low, and Protected content.
- Replaced amateur text chevrons with CSS-rendered professional disclosure icons.
- Added horizontal scrolling for long Permission Exposure paths and Priority Files content.
- Compacted the Top Risky Folders card so it no longer leaves large empty visual space.
- Added timestamp-based History and Audit Trail date filtering, including custom from/to ranges.
- Added additional polish: animated panels, row transitions, hover states, risk meters, protected-content chips, and responsive layout improvements.

## Protected / unreadable content feature
- Added scanner support for password-protected ZIP entries and encrypted/protected extensions such as `.kdbx`, `.gpg`, `.pgp`, `.p12`, and `.pfx`.
- Added metadata for `content_status`, `content_scannable`, `scan_error`, `protected`, and `protection_type`.
- Added dashboard summary/category support for Protected / Locked / Unreadable files.
- Added Protected inventory filtering so these files can be reviewed separately.
- Added risk-engine treatment for protected/unreadable files with remediation recommendations.
- Added enterprise test data samples:
  - Password-protected ZIP: `Executive/BoardPackets/Secure/password_protected_board_pack.zip`
  - Encrypted vault sample: `IT/Backups/Secure/production_credential_vault.kdbx`

## Validation performed
- `node --check frontend/app.js`
- `python -m compileall` for backend, collectors, discovery, permissions, risk, scripts, and main entrypoint.
- FastAPI TestClient login, local scan, history, and audit endpoints.
- Enterprise test-data scan confirmed protected/unreadable category appears in scan summary and protected ZIP/vault samples are detected.
