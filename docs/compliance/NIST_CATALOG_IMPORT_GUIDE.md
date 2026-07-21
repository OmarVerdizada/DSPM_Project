# NIST Catalog Import Guide

## Full Baseline Upgrade

1. Validate the catalog as analyst or admin:
   `POST /api/nist/catalog/validate` with `{ "catalog": { ... } }`.
2. Import as admin:
   `POST /api/nist/catalog/import` with `{ "catalog": { ... }, "dry_run": false }`.
3. Activate as admin:
   `POST /api/nist/catalog/activate` with `{ "catalog_hash": "<sha256-from-import>" }`.
4. Confirm:
   `GET /api/nist/catalog/status`.

## Rollback

Use `POST /api/nist/catalog/rollback` as admin. The service activates the last-known-good catalog copy atomically.

## Tenant Overlays

Use `/api/compliance-keywords/import` with `framework: "nist_sp800_60_enterprise"` for tenant-specific synonyms, local terms, schema field names, negative keywords, path exclusions, and owner/status metadata.

Tenant overlays do not replace baseline rules. Full baseline replacement is only available through the admin NIST catalog flow.

## Evidence Policy

NIST findings use `MASK_OR_FINGERPRINT_ONLY`. Reports and exports must not contain raw secrets or sensitive identifiers.

