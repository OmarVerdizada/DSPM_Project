# DSPM v101 Security + Frontend Hardening Fixes

## Frontend
- Remediation Center now uses a scroll-stable vertical stack with reduced vertical card gaps and horizontal/vertical overflow support.
- Detection Signal Mix now has a bounded scroll container with stable horizontal scrolling.
- Reports preview now has bounded vertical scrolling and horizontal overflow for wide report sections.
- CSS cache busting updated to `styles.css?v=101`.

## Backend security
- Removed production use of weak implicit `admin/admin123`; production now requires `DSPM_ADMIN_PASSWORD`. Local clean installs use `admin/Admin12345` unless `DSPM_DEV_ADMIN_PASSWORD` is set. Existing admin passwords are no longer reset at every startup unless `DSPM_SYNC_BUILTIN_ADMIN=1` is explicitly configured.
- JWT signing key is now persistent in local mode and required through `DSPM_SECRET_KEY` in production.
- Added server-side token revocation and `/api/logout`; frontend logout now calls the endpoint before clearing local session state.
- JWT validation now checks revocation, user existence, current role, current tenant, and active status.
- Login rate limiting moved from process-local memory to SQLite-backed persistence.
- `/api/users` and user-management operations are tenant-scoped; platform-wide tenant operations are restricted to the built-in platform admin.
- Tenant registration codes are masked in `/api/tenants`; full codes are returned only immediately after code rotation.
- Added user suspend/activate endpoint: `PUT /api/users/{username}/active`.
- Added CSP, HSTS, stricter CORS methods/headers, and production disabling of OpenAPI docs.
- Replaced raw exception details in endpoint/scan API failures with generic client-safe messages.
- Added SSRF target guard for loopback/link-local/reserved/metadata targets; private targets require `DSPM_ALLOW_PRIVATE_TARGETS=1` in production.
- Async job queue now has global and per-tenant limits, retention cleanup, and result truncation.
- Reports are written under `data/reports/` or `DSPM_REPORT_DIR` instead of the project root `report.json`.
- Removed DB filesystem path and environment name from retention summaries.
- Added scan history and audit log response limits.
- Added field length limits for asset overrides and WinRM activation input.
- Added `target_username` validation to prevent traversal/shell-like profile paths.
- Added archive compression-ratio checks and safer nested ZIP handling.
- Added symlink escape prevention during local file scans.
- Added SMB connection timeout and safer WinRM/SMB client-facing error messages.
- Vault key derivation now uses PBKDF2; production requires `DSPM_VAULT_KEY`. Local vault fallback key is written outside the DB folder by default.
- `--reload` is blocked when `DSPM_ENV=production`.

## Production environment checklist
Set at minimum:

```bash
DSPM_ENV=production
DSPM_ADMIN_PASSWORD=<strong-admin-password>
DSPM_SECRET_KEY=<64+ random chars>
DSPM_VAULT_KEY=<64+ random chars>
DSPM_CORS_ORIGINS=https://your-ui.example.com
DSPM_TRUSTED_HOSTS=your-api.example.com
DSPM_ALLOW_PRIVATE_TARGETS=1   # only when this DSPM server is intentionally allowed to scan internal hosts
```
