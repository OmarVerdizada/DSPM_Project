# Streaming inventory exports

Track S-G provides a tenant-scoped export that stays bounded as inventory size grows:

```text
GET /api/inventory/export?format=csv|ndjson&risk=&source=&framework=&finding_type=&protected=&q=&extension=
```

The route requires the `viewer` role or higher. Tenant identity comes only from the authenticated principal; the endpoint does not accept a tenant parameter. It applies the same normalized inventory filters as the interactive list, captures an upper asset ID once, and advances through `(tenant_id, id)` with `id > cursor ORDER BY id LIMIT batch_size`. Concurrent inserts therefore cannot make an export run indefinitely.

## Memory and data contract

- The database holds at most `DSPM_EXPORT_BATCH_SIZE` rows for one request (`1000` by default, clamped to `10`-`5000`).
- The encoder emits approximately 64 KiB chunks. It never builds a complete CSV, NDJSON document, report blob, or browser Blob.
- CSV and NDJSON contain inventory metadata only. Full `detail_json`, evidence samples, and `search_text` are excluded.
- CSV text cells beginning with spreadsheet formula characters are prefixed with an apostrophe.
- The export order is stable `asset_id ASC`; `X-Sentro-Export-Order: asset-id-asc` records this contract.
- The response sets `Cache-Control: no-store`, `X-Accel-Buffering: no`, and an attachment filename.

The console uses the File System Access API and pipes the authenticated response body directly to the chosen file. Current Chrome or Edge is required for the in-console action. Other clients can consume the endpoint as a normal streamed HTTP response.

## Readiness and failure behavior

Streaming export reads only the normalized `assets` mirror. If any persisted scan is not mirrored, or legacy rows still need the S-E detail backfill, the route returns HTTP `409` with an actionable message. It never falls back to loading report JSON because doing so would violate the constant-memory guarantee.

Run the repository's normalized backfill procedure after upgrading an existing installation, then retry the request. `DSPM_INVENTORY_FROM_NORMALIZED` controls the interactive read switch but is not required for export once the mirror passes its completeness gate.

## Examples

CSV, restricted to critical SMB assets:

```bash
curl --fail-with-body --no-buffer \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8000/api/inventory/export?format=csv&risk=CRITICAL&source=smb" \
  --output sentro-inventory.csv
```

NDJSON for a framework and literal search:

```bash
curl --fail-with-body --no-buffer \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8000/api/inventory/export?format=ndjson&framework=gdpr&q=finance" \
  --output sentro-inventory.ndjson
```

Reverse proxies must disable response buffering for this path. The application sends `X-Accel-Buffering: no` for nginx-compatible proxies; verify equivalent settings for other ingress products. Do not enable middleware that compresses by collecting the complete response.

## Verification

```bash
python -m pytest tests/test_inventory_streaming_export.py -q
```

The tests cover multi-batch keyset traversal, tenant isolation, every filter, CSV injection defense, NDJSON schema, response headers, readiness failure, authenticated browser streaming, and a 50,000-row memory-growth check.
