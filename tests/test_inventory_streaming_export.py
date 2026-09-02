"""Track S-G - tenant-scoped, constant-memory CSV/NDJSON inventory export."""

from __future__ import annotations

import csv
import inspect
import io
import json
import os
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from backend import inventory_export, store


def _report(scan_id: str, source: str, count: int, *, formula_name: bool = False) -> dict:
    files = []
    for index in range(count):
        name = "=HYPERLINK(\"https://invalid\")" if formula_name and index == 0 else f"asset-{index:03d}.csv"
        files.append({
            "path": f"/{source}/{name}",
            "name": name,
            "extension": ".csv",
            "size": index + 10,
            "owner": f"owner-{index % 3}",
            "protected": index % 2 == 0,
            "risk": {"level": "HIGH" if index % 2 == 0 else "LOW", "score": 80 if index % 2 == 0 else 10},
            "findings": ([{"type": "Access token", "framework": "GDPR"}] if index % 2 == 0 else []),
        })
    return {"scan_id": scan_id, "source": source, "summary": {}, "files": files}


class _SeededExport(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._original_db_path = store.DB_PATH
        store.DB_PATH = Path(self._tmp.name) / "export.sqlite"
        store.init_db()
        self.tenant_id = f"export-{uuid4().hex[:8]}"
        self.other_tenant_id = f"other-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant_id, "Export")
        store.create_tenant(self.other_tenant_id, "Other")
        store.save_scan_history(self.tenant_id, _report("scan-a", "local", 23, formula_name=True))
        store.save_scan_history(self.tenant_id, _report("scan-b", "smb", 17))
        store.save_scan_history(self.other_tenant_id, _report("scan-other", "other", 7))

    def tearDown(self) -> None:
        store.DB_PATH = self._original_db_path
        self._tmp.cleanup()


class InventoryStreamingExportTests(_SeededExport):

    def test_keyset_iterator_is_complete_filtered_and_tenant_scoped(self) -> None:
        rows = list(store.iter_inventory_export_rows(self.tenant_id, batch_size=10))
        self.assertEqual(len(rows), 40)
        self.assertEqual(len({row["id"] for row in rows}), 40)
        self.assertEqual([row["id"] for row in rows], sorted(row["id"] for row in rows))
        self.assertNotIn("other", {row["source"] for row in rows})

        filtered = list(store.iter_inventory_export_rows(
            self.tenant_id,
            source="smb",
            risk="HIGH",
            framework="gdpr",
            finding_type="Access token",
            protected=True,
            q="asset-",
            extension=".csv",
            batch_size=10,
        ))
        self.assertTrue(filtered)
        self.assertTrue(all(row["source"] == "smb" and row["risk_level"] == "HIGH" for row in filtered))

    def test_csv_stream_has_safe_cells_and_no_detail_blob(self) -> None:
        chunks = list(inventory_export.inventory_export_stream(self.tenant_id, "csv"))
        rows = list(csv.DictReader(io.StringIO(b"".join(chunks).decode("utf-8"))))
        self.assertEqual(len(rows), 40)
        formula_row = next(row for row in rows if "HYPERLINK" in row["name"])
        self.assertTrue(formula_row["name"].startswith("'="))
        self.assertNotIn("detail_json", rows[0])
        self.assertNotIn("search_text", rows[0])

    def test_ndjson_is_one_metadata_object_per_line(self) -> None:
        payload = b"".join(inventory_export.inventory_export_stream(
            self.tenant_id, "ndjson", risk="HIGH", protected=True,
        ))
        records = [json.loads(line) for line in payload.splitlines()]
        self.assertEqual(len(records), 21)
        self.assertTrue(all(record["risk_level"] == "HIGH" and record["protected"] for record in records))
        self.assertTrue(all(isinstance(record["frameworks"], list) for record in records))
        self.assertTrue(all(isinstance(record["finding_types"], list) for record in records))
        self.assertTrue(all("detail_json" not in record for record in records))

    def test_streaming_serializer_memory_does_not_scale_with_row_count(self) -> None:
        row = next(store.iter_inventory_export_rows(self.tenant_id, batch_size=10))

        def many_rows():
            for index in range(50_000):
                yield row | {"id": f"id-{index:08d}"}

        with mock.patch.object(inventory_export, "iter_inventory_export_rows", return_value=many_rows()):
            tracemalloc.start()
            total_bytes = sum(len(chunk) for chunk in inventory_export.inventory_export_stream("tenant", "ndjson"))
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        self.assertGreater(total_bytes, 1_000_000)
        self.assertLess(peak, 2_000_000)

    def test_source_contract_has_keyset_limit_and_no_blob_fallback(self) -> None:
        source = inspect.getsource(store.iter_inventory_export_rows)
        self.assertIn("id_expr} > ?", source)
        self.assertIn("LIMIT ?", source)
        self.assertNotIn("OFFSET", source.upper())
        self.assertNotIn("_inventory_blob_rows", source)
        self.assertNotIn("read_scan_report", source)


class InventoryStreamingExportEndpointTests(_SeededExport):
    def setUp(self) -> None:
        super().setUp()
        from fastapi.testclient import TestClient
        from backend.app import app
        from backend.security import create_token

        store.create_user("export-viewer", "unused", "viewer", self.tenant_id)
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {create_token('export-viewer', 'viewer', self.tenant_id)}"}

    def test_csv_route_stream_headers_filters_and_audits(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_EXPORT_BATCH_SIZE": "10"}):
            response = self.client.get(
                "/api/inventory/export?format=csv&source=smb&risk=HIGH",
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.headers["content-type"].startswith("text/csv"))
        self.assertIn("attachment;", response.headers["content-disposition"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8"))))
        self.assertEqual(len(rows), 9)
        self.assertTrue(all(row["source"] == "smb" and row["risk_level"] == "HIGH" for row in rows))
        actions = [event["action"] for event in store.read_audit_log(self.tenant_id)]
        self.assertIn("inventory.export.started", actions)

    def test_ndjson_route_is_tenant_scoped(self) -> None:
        response = self.client.get("/api/inventory/export?format=ndjson", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        records = [json.loads(line) for line in response.content.splitlines()]
        self.assertEqual(len(records), 40)
        self.assertNotIn("other", {record["source"] for record in records})

    def test_route_requires_auth_and_complete_normalized_mirror(self) -> None:
        self.assertIn(self.client.get("/api/inventory/export").status_code, (401, 403))
        with mock.patch("backend.app.inventory_export_ready", return_value=False):
            response = self.client.get("/api/inventory/export", headers=self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertIn("normalized inventory", response.json()["detail"])

    def test_route_rejects_unknown_format_before_streaming(self) -> None:
        response = self.client.get("/api/inventory/export?format=xlsx", headers=self.headers)
        self.assertEqual(response.status_code, 400)


class InventoryStreamingFrontendContractTests(unittest.TestCase):
    def test_browser_download_writes_response_stream_without_blob_materialization(self) -> None:
        script = Path("frontend/app.js").read_text(encoding="utf-8")
        markup = Path("frontend/index.html").read_text(encoding="utf-8")
        start = script.index("async function streamInventoryExport")
        end = script.index("\n}\n", start) + 2
        implementation = script[start:end]
        self.assertIn("response.body.pipeTo(writable)", implementation)
        self.assertIn("showSaveFilePicker", implementation)
        self.assertNotIn("response.blob()", implementation)
        self.assertIn('id="inventory-export-csv"', markup)
        self.assertIn('id="inventory-export-ndjson"', markup)


if __name__ == "__main__":
    unittest.main()
