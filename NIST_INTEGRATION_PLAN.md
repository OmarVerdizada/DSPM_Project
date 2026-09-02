# NIST SP 800-60 Enterprise Integration Plan

## Existing Flow Map

1. Catalog/keyword loading: GDPR and PCI DSS built-ins are loaded from Python rule modules, with tenant custom keyword overlays stored in `data/compliance_keywords`.
2. Import/validate/export: `/api/compliance-keywords/*` validates lightweight tenant overlays and exports merged built-in/custom groups.
3. Scan framework selection: backend scan requests pass `compliance_frameworks`; frontend renders framework checkboxes.
4. Detector execution: `DSPMDiscoveryEngine` always runs generic detection, then selected GDPR/PCI detectors.
5. Finding normalization: findings are decorated, canonicalized, deduplicated, and enriched with framework mappings.
6. Risk scoring: `risk/risk_engine.py` scores file risk from findings, file context, and ACL exposure.
7. Compliance mapping: `backend/compliance_service.py` maps findings/categories into framework profiles and reports.
8. Reporting/export: generated JSON reports include compliance summary plus GDPR/PCI specific report sections.
9. Frontend rendering: `frontend/app.js` renders framework selectors, finding chips, details, reports, and overlay import UI.
10. Tenant/RBAC: backend security provides viewer/analyst/admin roles; tenant custom keywords are path-scoped by tenant.

## NIST Target Architecture

- Add `nist_sp800_60_enterprise` as a separate framework from `nist_csf`.
- Store bundled baseline under `classification/compliance/catalogs/`.
- Keep schema and human reference artifacts inside repo-owned paths.
- Add structured catalog validation and management APIs separate from generic keyword import.
- Treat tenant additions as overlays only; do not allow tenant overlay imports to silently replace official baseline rules.
- Load effective runtime catalog lazily with cache invalidation based on catalog file mtime/hash.
- Include catalog status, version, hash, degraded mode, CIA impact, handling tier, confidence, and risk factor breakdown in findings and reports.

## Implementation Notes

- The provided machine-readable `nist_sp800_60_enterprise_guideline_az.json` was not present in the supplied Frameworks folder. A schema-compatible bundled baseline with 22 categories and 154 structured rules is included so the feature is operational and import-ready.
- Full authoritative JSON can be validated/imported/activated through `/api/nist/catalog/*`.
- Existing GDPR and PCI DSS behavior remains selected-framework gated and backward-compatible.

