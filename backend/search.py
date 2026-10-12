"""Track S-F optional dedicated inventory search (Meilisearch valve).

PostgreSQL/SQLite remains authoritative.  This module is deliberately an
optional projection: when disabled, misconfigured, stale, or unreachable the
caller falls back to the existing database/blob inventory implementation.
Only normalized metadata is indexed; ``detail_json`` and finding evidence never
leave the primary store.
"""

from __future__ import annotations

import atexit
import base64
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

SEARCHABLE_ATTRIBUTES = ["path", "name", "owner", "share", "extension", "search_text", "finding_types"]
FILTERABLE_ATTRIBUTES = [
    "id", "tenant_id", "risk_level", "source", "extension", "is_protected",
    "finding_types", "framework_keys", "finding_types_normalized",
    "framework_keys_normalized", "index_version",
]
SORTABLE_ATTRIBUTES = ["risk_score", "size", "finding_count", "modified_at", "name", "id"]
DISPLAYED_ATTRIBUTES = [
    "id", "source", "path", "name", "extension", "share", "risk_level",
    "risk_score", "size", "owner", "modified_at", "finding_count",
    "top_frameworks", "is_hidden", "is_system", "is_protected",
    "finding_types", "framework_keys",
]
INDEX_DISPLAYED_ATTRIBUTES = DISPLAYED_ATTRIBUTES + ["tenant_id", "index_version", "projection_hash"]
FACET_ATTRIBUTES = ["risk_level", "source", "is_protected", "finding_types", "framework_keys"]
INDEX_VERSION = "sf-v3"
_COUNT_CAP = 10_000


class SearchUnavailable(RuntimeError):
    """The optional engine cannot safely serve this request; use DB fallback."""


@dataclass(frozen=True, slots=True)
class SearchConfig:
    engine: str = "database"
    url: str = ""
    api_key: str = ""
    index_uid: str = "sentro_assets_v1"
    timeout_seconds: float = 2.0
    dual_write: bool = True
    read_enabled: bool = False
    batch_size: int = 500
    reconcile_interval_seconds: int = 300
    reconcile_repair: bool = True

    @property
    def enabled(self) -> bool:
        return self.engine == "meilisearch" and bool(self.url)


def config_from_env() -> SearchConfig:
    engine = os.getenv("DSPM_SEARCH_ENGINE", "database").strip().lower() or "database"
    url = os.getenv("DSPM_MEILISEARCH_URL", "").strip().rstrip("/")
    try:
        timeout = max(0.2, min(float(os.getenv("DSPM_SEARCH_TIMEOUT_SECONDS", "2")), 30.0))
    except ValueError:
        timeout = 2.0
    try:
        batch_size = max(10, min(int(os.getenv("DSPM_SEARCH_BATCH_SIZE", "500")), 5_000))
    except ValueError:
        batch_size = 500
    try:
        reconcile_interval = max(0, min(int(os.getenv("DSPM_SEARCH_RECONCILE_SECONDS", "300")), 86_400))
    except ValueError:
        reconcile_interval = 300
    return SearchConfig(
        engine=engine,
        url=url,
        api_key=os.getenv("DSPM_MEILISEARCH_API_KEY", "").strip(),
        index_uid=os.getenv("DSPM_MEILISEARCH_INDEX", "sentro_assets_v1").strip() or "sentro_assets_v1",
        timeout_seconds=timeout,
        dual_write=os.getenv("DSPM_SEARCH_DUAL_WRITE", "1") == "1",
        read_enabled=os.getenv("DSPM_SEARCH_READ_ENABLED", "0") == "1",
        batch_size=batch_size,
        reconcile_interval_seconds=reconcile_interval,
        reconcile_repair=os.getenv("DSPM_SEARCH_RECONCILE_REPAIR", "1") == "1",
    )


def external_search_requested() -> bool:
    config = config_from_env()
    return config.engine == "meilisearch" and config.read_enabled


def external_search_enabled() -> bool:
    config = config_from_env()
    return config.enabled and config.read_enabled


def _string_list(raw) -> list[str]:
    if isinstance(raw, list):
        return [str(value) for value in raw if value is not None and str(value)]
    try:
        parsed = json.loads(str(raw or "[]"))
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(value) for value in parsed if str(value)] if isinstance(parsed, list) else []


def asset_document(asset: dict) -> dict:
    """Return the metadata-only search projection for one normalized asset."""
    finding_types = _string_list(asset.get("finding_types"))
    framework_keys = _string_list(asset.get("framework_keys"))
    document = {key: asset.get(key) for key in DISPLAYED_ATTRIBUTES}
    document.update({
        "tenant_id": str(asset.get("tenant_id") or ""),
        "search_text": str(asset.get("search_text") or ""),
        "finding_types": finding_types,
        "framework_keys": framework_keys,
        # Meilisearch equality filters are exact. Keep normalized shadow fields
        # for API parity while returning/faceting on the original display labels.
        "finding_types_normalized": sorted({value.casefold() for value in finding_types}),
        "framework_keys_normalized": sorted({value.casefold() for value in framework_keys}),
        "is_hidden": bool(asset.get("is_hidden")),
        "is_system": bool(asset.get("is_system")),
        "is_protected": bool(asset.get("is_protected")),
        "risk_score": int(asset.get("risk_score") or 0),
        "size": int(asset.get("size") or 0),
        "finding_count": int(asset.get("finding_count") or 0),
        "index_version": INDEX_VERSION,
    })
    # Meilisearch primary keys must be strings or integers. Stable asset ids are
    # tenant-derived hashes, so one shared index cannot collide across tenants.
    document["id"] = str(asset.get("id") or "")
    canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    document["projection_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return document


def _filter_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(str(value or ""), ensure_ascii=False)


def can_express(filt: dict) -> bool:
    """Whether the engine can answer these filters exactly as the database does.

    The inventory filters became multi-select: a source also matches a scan's name, a
    finding type stands for every stored spelling of itself, and "Protected",
    "Classified" and "Clear" are pseudo-values that join their facet's OR group. The
    engine was handed the old single-value fields - empty for all of these - so a text
    search with them ticked came back unfiltered, its items and total disagreeing with
    the filters. Those searches stay on the database, which answers them correctly."""
    return not (filt.get("sources") or filt.get("source") or filt.get("finding_types") or filt.get("finding_type")
                or filt.get("protected_risk") or filt.get("protected_type") or filt.get("classified_type")
                or filt.get("clear_type"))


def build_filter(tenant_id: str, filt: dict) -> str:
    """Build a tenant-mandatory Meilisearch filter expression (see `can_express`)."""
    clauses = [
        f"tenant_id = {_filter_value(tenant_id)}",
        f"index_version = {_filter_value(INDEX_VERSION)}",
    ]
    risks = [value for value in filt.get("risks") or ([filt["risk"]] if filt.get("risk") else []) if value]
    if risks:
        clauses.append("(" + " OR ".join(f"risk_level = {_filter_value(value)}" for value in risks) + ")")
    if filt.get("source_group"):
        clauses.append(
            "(" + " OR ".join(f"source = {_filter_value(source)}" for source in filt["source_group"]) + ")"
        )
    elif filt.get("source"):
        clauses.append(f"source = {_filter_value(filt['source'])}")
    extensions = [value for value in filt.get("extensions") or ([filt["extension"]] if filt.get("extension") else [])
                  if value]
    if extensions:
        clauses.append("(" + " OR ".join(f"extension = {_filter_value(value)}" for value in extensions) + ")")
    if filt.get("protected") is not None:
        clauses.append(f"is_protected = {_filter_value(bool(filt['protected']))}")
    if filt.get("finding_type"):
        clauses.append(f"finding_types_normalized = {_filter_value(str(filt['finding_type']).casefold())}")
    frameworks = [value for value in filt.get("frameworks") or [] if value]
    if frameworks:
        clauses.append(
            "(" + " OR ".join(
                f"framework_keys_normalized = {_filter_value(str(value).casefold())}" for value in frameworks
            ) + ")"
        )
    return " AND ".join(clauses)


def _encode_cursor(offset: int) -> str:
    raw = json.dumps([INDEX_VERSION, max(0, min(int(offset), _COUNT_CAP))], separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> int:
    if not cursor:
        return 0
    try:
        version, offset = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        return max(0, min(int(offset), _COUNT_CAP)) if version == INDEX_VERSION else 0
    except Exception:
        return 0


class MeilisearchClient:
    def __init__(self, config: SearchConfig, transport: httpx.BaseTransport | None = None) -> None:
        self.config = config
        headers = {"Content-Type": "application/json"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        self.http = httpx.Client(timeout=config.timeout_seconds, headers=headers, transport=transport)
        self._ready = False
        self._ready_lock = threading.Lock()

    @property
    def index_path(self) -> str:
        return f"/indexes/{quote(self.config.index_uid, safe='')}"

    def close(self) -> None:
        self.http.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body=None,
        allowed: tuple[int, ...] = (200, 202),
        allowed_error_codes: tuple[str, ...] = (),
    ) -> dict:
        try:
            response = self.http.request(method, f"{self.config.url}{path}", json=json_body)
        except httpx.HTTPError as exc:
            raise SearchUnavailable(f"Meilisearch request failed: {type(exc).__name__}") from exc
        body: dict = {}
        if response.content:
            try:
                parsed = response.json()
            except ValueError as exc:
                if response.status_code in allowed:
                    raise SearchUnavailable("Meilisearch returned invalid JSON") from exc
            else:
                body = parsed if isinstance(parsed, dict) else {}
        if response.status_code not in allowed:
            error_code = str(body.get("code") or "")
            if error_code not in allowed_error_codes:
                raise SearchUnavailable(f"Meilisearch returned HTTP {response.status_code}")
        return body

    def health(self) -> dict:
        body = self.request("GET", "/health", allowed=(200,))
        self.request("GET", self.index_path, allowed=(200,))
        settings = self.request("GET", f"{self.index_path}/settings", allowed=(200,))
        configured_filters = settings.get("filterableAttributes")
        if not isinstance(configured_filters, list) or not set(FILTERABLE_ATTRIBUTES).issubset(configured_filters):
            raise SearchUnavailable("Meilisearch index settings are stale; rebuild the index")
        configured_display = settings.get("displayedAttributes")
        if not isinstance(configured_display, list) or not set(INDEX_DISPLAYED_ATTRIBUTES).issubset(configured_display):
            raise SearchUnavailable("Meilisearch projection metadata is stale; rebuild the index")
        stats = self.stats()
        return {
            "status": str(body.get("status") or "available"),
            "provider": "meilisearch",
            "index_ready": True,
            "index_version": INDEX_VERSION,
            "documents": int(stats.get("numberOfDocuments") or 0),
            "is_indexing": bool(stats.get("isIndexing")),
        }

    def stats(self) -> dict:
        return self.request("GET", f"{self.index_path}/stats", allowed=(200,))

    def wait_task(self, task_uid: int, timeout_seconds: float = 120.0) -> dict:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            task = self.request("GET", f"/tasks/{int(task_uid)}", allowed=(200,))
            status = str(task.get("status") or "")
            if status == "succeeded":
                return task
            if status in {"failed", "canceled"}:
                raise SearchUnavailable(f"Meilisearch task {task_uid} {status}")
            time.sleep(0.05)
        raise SearchUnavailable(f"Meilisearch task {task_uid} timed out")

    def ensure_index(self, *, wait: bool = False) -> list[int]:
        with self._ready_lock:
            if self._ready:
                return []
            tasks: list[int] = []
            created = self.request(
                "POST", "/indexes",
                json_body={"uid": self.config.index_uid, "primaryKey": "id"},
                allowed=(202,),
                allowed_error_codes=("index_already_exists",),
            )
            if created.get("taskUid") is not None:
                create_uid = int(created["taskUid"])
                # Index creation itself is asynchronous. Settings cannot safely
                # target the new index until that first task has completed.
                self.wait_task(create_uid)
                tasks.append(create_uid)
            settings = self.request("PATCH", f"{self.index_path}/settings", json_body={
                "searchableAttributes": SEARCHABLE_ATTRIBUTES,
                "filterableAttributes": FILTERABLE_ATTRIBUTES,
                "sortableAttributes": SORTABLE_ATTRIBUTES,
                "displayedAttributes": INDEX_DISPLAYED_ATTRIBUTES,
                "rankingRules": ["sort", "words", "typo", "proximity", "attribute", "exactness"],
                "pagination": {"maxTotalHits": _COUNT_CAP},
            })
            if settings.get("taskUid") is not None:
                tasks.append(int(settings["taskUid"]))
            if wait:
                for task_uid in tasks[1:] if created.get("taskUid") is not None else tasks:
                    self.wait_task(task_uid)
            self._ready = True
            return tasks

    def add_documents(self, documents: list[dict], *, wait: bool = False) -> int | None:
        if not documents:
            return None
        self.ensure_index(wait=wait)
        task = self.request("POST", f"{self.index_path}/documents?primaryKey=id", json_body=documents)
        task_uid = int(task["taskUid"]) if task.get("taskUid") is not None else None
        if wait and task_uid is not None:
            self.wait_task(task_uid)
        return task_uid

    def fetch_documents(self, ids: list[str]) -> dict[str, dict]:
        if not ids:
            return {}
        body = self.request(
            "POST",
            f"{self.index_path}/documents/fetch",
            json_body={
                "ids": ids,
                "fields": ["id", "tenant_id", "index_version", "projection_hash"],
                "limit": len(ids),
            },
            allowed=(200,),
        )
        results = body.get("results") if isinstance(body.get("results"), list) else []
        return {
            str(item.get("id") or ""): item
            for item in results
            if isinstance(item, dict) and item.get("id")
        }

    def iter_documents(self, batch_size: int = 500) -> Iterator[list[dict]]:
        batch_size = max(10, min(int(batch_size or 500), 5_000))
        last_id = ""
        while True:
            payload: dict = {
                "fields": ["id", "tenant_id", "index_version", "projection_hash"],
                "sort": ["id:asc"],
                "limit": batch_size,
            }
            if last_id:
                payload["filter"] = f"id > {_filter_value(last_id)}"
            body = self.request(
                "POST", f"{self.index_path}/documents/fetch", json_body=payload, allowed=(200,)
            )
            results = [item for item in body.get("results") or [] if isinstance(item, dict) and item.get("id")]
            if not results:
                return
            yield results
            next_id = str(results[-1]["id"])
            if next_id <= last_id or len(results) < batch_size:
                return
            last_id = next_id

    def delete_documents(self, ids: list[str], *, wait: bool = False) -> int | None:
        if not ids:
            return None
        task = self.request(
            "POST", f"{self.index_path}/documents/delete-batch", json_body=ids, allowed=(202,)
        )
        task_uid = int(task["taskUid"]) if task.get("taskUid") is not None else None
        if wait and task_uid is not None:
            self.wait_task(task_uid)
        return task_uid

    def delete_tenant(self, tenant_id: str, *, wait: bool = True) -> int | None:
        """Every document of one tenant, by filter - erasure's part in the index (C10).
        An index that was never created holds nothing to delete."""
        task = self.request(
            "POST", f"{self.index_path}/documents/delete",
            json_body={"filter": f"tenant_id = {_filter_value(tenant_id)}"},
            allowed=(202, 404),
        )
        task_uid = int(task["taskUid"]) if task.get("taskUid") is not None else None
        if wait and task_uid is not None:
            self.wait_task(task_uid)
        return task_uid

    def delete_index(self, *, wait: bool = True) -> None:
        deleted = self.request("DELETE", self.index_path, allowed=(202, 404))
        if wait and deleted.get("taskUid") is not None:
            self.wait_task(int(deleted["taskUid"]))
        self._ready = False

    def reset_index(self) -> None:
        deleted = self.request("DELETE", self.index_path, allowed=(202, 404))
        if deleted.get("taskUid") is not None:
            self.wait_task(int(deleted["taskUid"]))
        self._ready = False
        self.ensure_index(wait=True)

    def search(self, tenant_id: str, filt: dict, sort: str, direction: str, cursor: str, limit: int) -> dict:
        offset = _decode_cursor(cursor)
        if offset >= _COUNT_CAP:
            return {
                "items": [], "next_cursor": None, "has_more": False,
                "total": _COUNT_CAP, "total_is_estimate": True,
                "source": "meilisearch", "facets": _facet_response(None, _COUNT_CAP),
            }
        sort_direction = direction.lower()
        payload = {
            "q": str(filt.get("q") or ""),
            "filter": build_filter(tenant_id, filt),
            "sort": [f"{sort}:{sort_direction}", f"id:{sort_direction}"],
            "offset": offset,
            "limit": min(limit + 1, _COUNT_CAP - offset),
            "attributesToRetrieve": DISPLAYED_ATTRIBUTES,
            "facets": FACET_ATTRIBUTES,
            "matchingStrategy": "all",
        }
        body = self.request("POST", f"{self.index_path}/search", json_body=payload, allowed=(200,))
        raw_hits = body.get("hits") if isinstance(body.get("hits"), list) else []
        has_more = len(raw_hits) > limit
        hits = raw_hits[:limit]
        items: list[dict] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            item = {key: hit.get(key) for key in DISPLAYED_ATTRIBUTES}
            item["finding_types"] = json.dumps(_string_list(item.get("finding_types")), ensure_ascii=False, separators=(",", ":"))
            item["framework_keys"] = json.dumps(_string_list(item.get("framework_keys")), ensure_ascii=False, separators=(",", ":"))
            item["is_hidden"] = 1 if item.get("is_hidden") else 0
            item["is_system"] = 1 if item.get("is_system") else 0
            item["is_protected"] = 1 if item.get("is_protected") else 0
            items.append(item)
        total = int(body.get("estimatedTotalHits") or body.get("totalHits") or len(items))
        # Some engines return exactly limit hits even when another page exists.
        has_more = has_more or offset + len(items) < total
        return {
            "items": items,
            "next_cursor": _encode_cursor(offset + len(items)) if has_more and items else None,
            "has_more": has_more,
            "total": min(total, _COUNT_CAP),
            "total_is_estimate": "estimatedTotalHits" in body or total > _COUNT_CAP,
            "source": "meilisearch",
            "facets": _facet_response(body.get("facetDistribution"), total),
        }


def _facet_items(values: dict) -> list[dict]:
    return [
        {"value": str(value), "count": int(count)}
        for value, count in sorted((values or {}).items(), key=lambda item: (-int(item[1]), str(item[0]).lower()))
    ]


def _facet_response(distribution, total: int) -> dict:
    facets = distribution if isinstance(distribution, dict) else {}
    protected = facets.get("is_protected") if isinstance(facets.get("is_protected"), dict) else {}
    return {
        "total": min(total, _COUNT_CAP),
        "risk_counts": {str(k).upper(): int(v) for k, v in (facets.get("risk_level") or {}).items()},
        "protected": int(protected.get("true") or protected.get(True) or 0),
        "sources": _facet_items(facets.get("source") or {}),
        "finding_types": _facet_items(facets.get("finding_types") or {}),
        "frameworks": _facet_items(facets.get("framework_keys") or {}),
        "source": "meilisearch",
    }


_clients: dict[SearchConfig, MeilisearchClient] = {}
_clients_lock = threading.Lock()


def _client(config: SearchConfig | None = None) -> MeilisearchClient:
    cfg = config or config_from_env()
    if not cfg.enabled:
        raise SearchUnavailable("Meilisearch is not configured")
    with _clients_lock:
        client = _clients.get(cfg)
        if client is None:
            client = MeilisearchClient(cfg)
            _clients[cfg] = client
        return client


@atexit.register
def close_search_clients() -> None:
    with _clients_lock:
        clients = list(_clients.values())
        _clients.clear()
    for client in clients:
        client.close()


def erase_tenant(tenant_id: str) -> str:
    """Remove a tenant's documents from the optional index when the tenant is erased (C10).
    Returns "removed", or "not configured" when there is no index. Raises SearchUnavailable
    if the index cannot be reached; the caller reports that, and reconciliation removes
    the documents once it can."""
    config = config_from_env()
    if not config.enabled:
        return "not configured"
    _client(config).delete_tenant(tenant_id, wait=True)
    return "removed"


def search_inventory(tenant_id: str, filt: dict, sort: str, direction: str, cursor: str, limit: int) -> dict:
    return _client().search(tenant_id, filt, sort, direction, cursor, limit)


def index_assets(assets: Iterable[dict], *, wait: bool = False) -> int:
    config = config_from_env()
    if not config.enabled:
        return 0
    client = _client(config)
    batch: list[dict] = []
    indexed = 0
    for asset in assets:
        document = asset_document(asset)
        if not document["id"] or not document["tenant_id"]:
            continue
        batch.append(document)
        if len(batch) >= config.batch_size:
            client.add_documents(batch, wait=wait)
            indexed += len(batch)
            batch = []
    if batch:
        client.add_documents(batch, wait=wait)
        indexed += len(batch)
    return indexed


def index_scan_report(tenant_id: str, report: dict) -> int:
    config = config_from_env()
    if not config.enabled or not config.dual_write:
        return 0
    from backend.domain import iter_normalized_assets

    assets = (asset.to_dict() | {"tenant_id": tenant_id} for asset in iter_normalized_assets(tenant_id, report))
    return index_assets(assets, wait=False)


def rebuild_index(asset_batches: Iterable[list[dict]]) -> dict:
    config = config_from_env()
    if not config.enabled:
        raise SearchUnavailable("Set DSPM_SEARCH_ENGINE=meilisearch and DSPM_MEILISEARCH_URL first")
    client = _client(config)
    client.reset_index()
    indexed = 0
    batches = 0
    for batch in asset_batches:
        documents = [asset_document(asset) for asset in batch if asset.get("id") and asset.get("tenant_id")]
        if not documents:
            continue
        client.add_documents(documents, wait=True)
        indexed += len(documents)
        batches += 1
    return {"provider": "meilisearch", "index": config.index_uid, "indexed": indexed, "batches": batches}


_reconcile_lock = threading.Lock()


def reconcile_index(
    asset_batches: Iterable[list[dict]],
    lookup_assets: Callable[[list[dict]], list[dict]],
    *,
    repair: bool = False,
) -> dict:
    """Compare the bounded DB projection with Meilisearch and optionally repair drift."""
    config = config_from_env()
    if not config.enabled:
        raise SearchUnavailable("Set DSPM_SEARCH_ENGINE=meilisearch and DSPM_MEILISEARCH_URL first")
    if not _reconcile_lock.acquire(blocking=False):
        raise SearchUnavailable("Search reconciliation is already running")
    started = time.monotonic()
    checked_at = datetime.now(timezone.utc).isoformat()
    client = _client(config)
    authoritative = missing = stale = orphaned = repaired_upserts = repaired_deletes = 0
    try:
        client.ensure_index(wait=True)
        before = client.stats()
        for batch in asset_batches:
            documents = [asset_document(asset) for asset in batch if asset.get("id") and asset.get("tenant_id")]
            if not documents:
                continue
            authoritative += len(documents)
            remote = client.fetch_documents([document["id"] for document in documents])
            repair_batch: list[dict] = []
            for document in documents:
                current = remote.get(document["id"])
                if current is None:
                    missing += 1
                    repair_batch.append(document)
                elif (
                    str(current.get("tenant_id") or "") != document["tenant_id"]
                    or str(current.get("index_version") or "") != INDEX_VERSION
                    or str(current.get("projection_hash") or "") != document["projection_hash"]
                ):
                    stale += 1
                    repair_batch.append(document)
            if repair and repair_batch:
                client.add_documents(repair_batch, wait=True)
                repaired_upserts += len(repair_batch)

        # Keep lookup predicates under conservative SQLite parameter limits and
        # use each row's (tenant_id, id) pair so the authoritative composite PK
        # serves the check at multi-million-row scale.
        for remote_batch in client.iter_documents(min(config.batch_size, 400)):
            ids = [str(document["id"]) for document in remote_batch]
            source = {str(asset.get("id") or ""): asset for asset in lookup_assets(remote_batch)}
            orphan_ids = [asset_id for asset_id in ids if asset_id not in source]
            orphaned += len(orphan_ids)
            if repair and orphan_ids:
                client.delete_documents(orphan_ids, wait=True)
                repaired_deletes += len(orphan_ids)

        after = client.stats()
        detected_lag = missing + stale + orphaned
        remaining_lag = 0 if repair else detected_lag
        after_count = int(after.get("numberOfDocuments") or 0)
        if after_count != authoritative:
            remaining_lag = max(remaining_lag, abs(after_count - authoritative))
        in_sync = remaining_lag == 0
        return {
            "provider": "meilisearch",
            "index": config.index_uid,
            "index_version": INDEX_VERSION,
            "checked_at": checked_at,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "repair_requested": repair,
            "status": "repaired" if repair and detected_lag else ("in_sync" if in_sync else "drift"),
            "in_sync": in_sync,
            "authoritative_documents": authoritative,
            "engine_documents_before": int(before.get("numberOfDocuments") or 0),
            "engine_documents_after": after_count,
            "missing_documents": missing,
            "stale_documents": stale,
            "orphan_documents": orphaned,
            "lag_documents": detected_lag,
            "remaining_lag_documents": remaining_lag,
            "repaired_upserts": repaired_upserts,
            "repaired_deletes": repaired_deletes,
        }
    finally:
        _reconcile_lock.release()


def run_search_reconciliation(*, repair: bool | None = None) -> dict:
    from backend import store

    config = config_from_env()
    result = reconcile_index(
        store.iter_search_asset_batches(config.batch_size),
        store.get_search_assets_by_refs,
        repair=config.reconcile_repair if repair is None else repair,
    )
    store.save_search_reconciliation(config.index_uid, result)
    return result


_reconciler_stop = threading.Event()
_reconciler_thread: threading.Thread | None = None
_reconciler_thread_lock = threading.Lock()


def reconcile_pass() -> dict | None:
    """One pass of the automated reconciler; ``None`` - nothing compared, repaired or
    recorded - on a database a newer release has upgraded (C0.4)."""
    from backend import schema_guard

    if schema_guard.stand_down("search reconciler"):
        return None
    return run_search_reconciliation(repair=config_from_env().reconcile_repair)


def _reconciler_loop() -> None:
    while not _reconciler_stop.is_set():
        config = config_from_env()
        try:
            reconcile_pass()
        except Exception as exc:  # pragma: no cover - live optional service guard
            logger.warning("Automated search reconciliation failed: %s", type(exc).__name__)
        if _reconciler_stop.wait(max(1, config.reconcile_interval_seconds)):
            return


def start_search_reconciler() -> bool:
    global _reconciler_thread
    config = config_from_env()
    if not config.enabled or config.reconcile_interval_seconds <= 0:
        return False
    with _reconciler_thread_lock:
        if _reconciler_thread is not None and _reconciler_thread.is_alive():
            return True
        _reconciler_stop.clear()
        _reconciler_thread = threading.Thread(
            target=_reconciler_loop, name="search-reconciler", daemon=True
        )
        _reconciler_thread.start()
    return True


def stop_search_reconciler() -> None:
    global _reconciler_thread
    _reconciler_stop.set()
    with _reconciler_thread_lock:
        thread = _reconciler_thread
        _reconciler_thread = None
    if thread is not None and thread.is_alive():
        thread.join(timeout=5.0)


_health_cache: tuple[float, SearchConfig | None, dict] = (0.0, None, {})
_health_lock = threading.Lock()


def search_health() -> dict:
    global _health_cache
    config = config_from_env()
    if config.engine in {"database", "postgres", "sqlite"}:
        from backend import db

        return {"status": "database", "provider": db.backend_name(), "enabled": False, "read_enabled": False}
    if config.engine != "meilisearch":
        return {"status": "misconfigured", "provider": config.engine or "unknown", "enabled": False, "read_enabled": config.read_enabled}
    if not config.url:
        return {"status": "misconfigured", "provider": "meilisearch", "enabled": False, "read_enabled": config.read_enabled}
    now = time.monotonic()
    with _health_lock:
        if now - _health_cache[0] < 10.0 and _health_cache[1] == config and _health_cache[2]:
            return dict(_health_cache[2])
    try:
        status = _client(config).health() | {"enabled": True, "read_enabled": config.read_enabled, "index": config.index_uid}
    except SearchUnavailable as exc:
        status = {"status": "unavailable", "provider": "meilisearch", "enabled": True, "read_enabled": config.read_enabled, "detail": str(exc)}
    try:
        from backend.store import get_search_reconciliation

        status["reconciliation"] = get_search_reconciliation(config.index_uid)
    except Exception:  # pragma: no cover - health must survive optional metrics failure
        status["reconciliation"] = None
    with _health_lock:
        _health_cache = (now, config, status)
    return dict(status)
