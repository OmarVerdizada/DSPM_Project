from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
import threading
from typing import Iterable


@dataclass(slots=True)
class _Node:
    children: dict[str, int] = field(default_factory=dict)
    fail: int = 0
    outputs: list[tuple[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class KeywordIndex:
    framework: str
    catalog_version: str
    language: str
    compiled_index: str
    created_at: str
    nodes: list[_Node]

    def search(self, text: str, limit_per_type: int = 10) -> dict[str, list[str]]:
        lowered = str(text or "").lower()
        if not lowered:
            return {}
        state = 0
        matches: dict[str, list[str]] = {}
        for index, char in enumerate(lowered):
            while state and char not in self.nodes[state].children:
                state = self.nodes[state].fail
            state = self.nodes[state].children.get(char, 0)
            for keyword, finding_type in self.nodes[state].outputs:
                start = index - len(keyword) + 1
                if not _word_boundary(lowered, start, index + 1, keyword):
                    continue
                bucket = matches.setdefault(finding_type, [])
                if keyword not in bucket and len(bucket) < limit_per_type:
                    bucket.append(keyword)
        return matches


_lock = threading.RLock()
_index_cache: dict[tuple[str, str, str, str], KeywordIndex] = {}


def keyword_groups_signature(groups: Iterable[dict]) -> str:
    payload = []
    for group in groups:
        payload.append(
            {
                "framework": group.get("framework", ""),
                "language": group.get("language", ""),
                "type": group.get("type", ""),
                "terms": sorted({str(term or "").strip().lower() for term in group.get("terms") or [] if str(term or "").strip()}),
            }
        )
    raw = json.dumps(sorted(payload, key=lambda item: (item["framework"], item["language"], item["type"])), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def compiled_keyword_index(
    *,
    framework: str,
    catalog_version: str,
    language: str,
    groups: Iterable[dict],
) -> KeywordIndex:
    group_list = list(groups)
    signature = keyword_groups_signature(group_list)
    cache_key = (framework, catalog_version or "built-in", language or "all", signature)
    with _lock:
        cached = _index_cache.get(cache_key)
        if cached is not None:
            return cached
        index = _compile_index(framework, catalog_version or "built-in", language or "all", group_list)
        _index_cache[cache_key] = index
        return index


def keyword_hits_indexed(blob: str, keywords: Iterable[str], *, cache_namespace: str = "adhoc", limit: int = 10) -> list[str]:
    terms = [str(keyword or "").strip() for keyword in keywords if str(keyword or "").strip()]
    if not terms:
        return []
    groups = [{"framework": cache_namespace, "language": "all", "type": "hit", "terms": terms}]
    index = compiled_keyword_index(
        framework=cache_namespace,
        catalog_version=keyword_groups_signature(groups),
        language="all",
        groups=groups,
    )
    return index.search(blob, limit_per_type=limit).get("hit", [])[:limit]


def _compile_index(framework: str, catalog_version: str, language: str, groups: list[dict]) -> KeywordIndex:
    nodes = [_Node()]
    for group in groups:
        finding_type = str(group.get("type") or "").strip()
        if not finding_type:
            continue
        for raw_term in group.get("terms") or []:
            term = _normalize_term(raw_term)
            if not term:
                continue
            state = 0
            for char in term:
                state = nodes[state].children.setdefault(char, len(nodes))
                if state == len(nodes):
                    nodes.append(_Node())
            output = (term, finding_type)
            if output not in nodes[state].outputs:
                nodes[state].outputs.append(output)

    queue: deque[int] = deque()
    for child in nodes[0].children.values():
        queue.append(child)
        nodes[child].fail = 0
    while queue:
        current = queue.popleft()
        for char, child in nodes[current].children.items():
            queue.append(child)
            fail = nodes[current].fail
            while fail and char not in nodes[fail].children:
                fail = nodes[fail].fail
            nodes[child].fail = nodes[fail].children.get(char, 0)
            for output in nodes[nodes[child].fail].outputs:
                if output not in nodes[child].outputs:
                    nodes[child].outputs.append(output)

    return KeywordIndex(
        framework=framework,
        catalog_version=catalog_version,
        language=language,
        compiled_index=f"{framework}:{catalog_version}:{language}",
        created_at=datetime.now(timezone.utc).isoformat(),
        nodes=nodes,
    )


def _normalize_term(value: str) -> str:
    return " ".join(str(value or "").strip().split()).lower()


def _word_boundary(text: str, start: int, end: int, keyword: str) -> bool:
    if not keyword or not keyword[0].isalnum() or not keyword[-1].isalnum():
        return True
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    return not _word_char(before) and not _word_char(after)


def _word_char(char: str) -> bool:
    return bool(char and re.match(r"[A-Za-z0-9_]", char))
