# DSPM Project Update v80

## Frontend UX polish
- Rebuilt the inventory experience from a plain table into a DSPM-style triage console.
- Added risk, source, and finding-type filters with live counts.
- Added inventory KPI strip for visible files, sensitive files, average risk, and top source.
- Improved file rows with file metadata, size formatting, owner/folder inference, finding chips, risk meters, and clearer action buttons.
- Added smoother transitions, row animations, polished search box, better dark/light compatibility, and responsive layout rules.
- Kept existing scan, report, endpoint, tenant, and admin workflows intact.

## Backend / secure-code hardening
- Added security response headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` for API responses.
- Added optional Trusted Host middleware through `DSPM_TRUSTED_HOSTS` without breaking local/LAN development by default.
- Added login brute-force protection with configurable `DSPM_LOGIN_WINDOW_SECONDS` and `DSPM_LOGIN_MAX_ATTEMPTS`.
- Hardened request validation for scan paths, endpoint paths, extensions, credentials, hostnames, usernames, and other user-controlled fields.
- Fixed API-key tenant isolation so an API key cannot pivot into another tenant through `X-Tenant-ID`.
- Removed hardcoded vault fallback key and replaced it with `DSPM_VAULT_KEY` or a locally generated encrypted vault key.
- Increased PBKDF2 password hashing rounds for new passwords while preserving verification support for existing hashes.
- Added archive safety limits to reduce zip-bomb style resource abuse during archive inspection.

## Validation performed
- `node --check frontend/app.js`
- Python bytecode compilation for backend, collectors, classification, discovery, permissions, risk, scripts, and `main.py`
- FastAPI TestClient health/login/risk-rules/history checks
- FastAPI TestClient local scan check against `test_data`

Note: Headless browser rendering was not completed because the sandbox has Playwright installed but does not have the Chromium browser binary downloaded.
