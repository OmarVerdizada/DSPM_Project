# NIST Test Report

Final status: implementation tests added and executed. Run command:

```powershell
pytest -q
```

Environment note: `pytest.exe` was installed under the user Python Scripts directory, which is not on PATH in this PowerShell session, so the verified command was:

```powershell
python -m pytest -q
```

Result:

```text
187 passed, 1 skipped in 14.34s
```

Coverage added for:

- Catalog count and structure validation.
- Wrong framework, duplicate IDs/types, unknown category, invalid CIA, invalid detection mode, and invalid regex rejection.
- Classifier scoring, negative context, keyword-only status, and masking.
- Discovery framework selection.
- Compliance/report mapping.
- API status/catalog/validate endpoints and RBAC.
- Tenant overlay isolation.
- Rollback behavior.
- Frontend top-level `rules` parser contract.
