from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import functools
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


# The automaton earns its keep on the 46,000-term GDPR catalog, which is
# searched once per file. It does not earn it here: this is called with 7 to 92
# terms, 145 times for one file, and each call was paying for a json dump, a
# sha256 over it, a cache lookup, and then a per-character Python walk of the
# whole blob - 167ms of PCI's 168ms.
#
# For a handful of terms, str.find is the same question asked in C. Above the
# threshold the trie is still the better answer, so both paths stay.
_ADHOC_TRIE_THRESHOLD = 200


@functools.lru_cache(maxsize=512)
def _adhoc_terms(keywords: tuple) -> tuple[str, ...]:
    """The cleaned, normalized terms for one ad-hoc keyword set.

    Stripping and normalizing them ran on every call - 2.8 million strips and
    1.6 million case-folds over one scan - to rebuild the same short list from
    the same constants each time."""
    return tuple(dict.fromkeys(
        term for term in (_normalize_term(keyword) for keyword in keywords) if term
    ))


_LOWERED_BLOB = threading.local()


def _lowered_blob(blob: str) -> str:
    """`blob.lower()` for a string this scan keeps asking about."""
    slot = getattr(_LOWERED_BLOB, "slot", None)
    if slot is not None and slot[0] is blob:
        return slot[1]
    lowered = blob.lower()
    _LOWERED_BLOB.slot = (blob, lowered)
    return lowered


def keyword_hits_indexed(blob: str, keywords: Iterable[str], *, cache_namespace: str = "adhoc", limit: int = 10) -> list[str]:
    terms = _adhoc_terms(tuple(keywords))
    if not terms:
        return []
    blob_lower = _lowered_blob(blob)
    if len(terms) > _ADHOC_TRIE_THRESHOLD:
        # A match requires the substring, so this is a correct
        # necessary-condition prefilter for the expensive path.
        if not any(term in blob_lower for term in terms):
            return []
        groups = [{"framework": cache_namespace, "language": "all", "type": "hit", "terms": list(terms)}]
        index = compiled_keyword_index(
            framework=cache_namespace,
            catalog_version=keyword_groups_signature(groups),
            language="all",
            groups=groups,
        )
        return index.search(blob, limit_per_type=limit).get("hit", [])[:limit]

    # Ordered by where each term first matches, which is the order the walk
    # above reported them in.
    found: list[tuple[int, str]] = []
    for normalized in terms:
        position = blob_lower.find(normalized)
        while position >= 0:
            end = position + len(normalized)
            if _word_boundary(blob_lower, position, end, normalized):
                found.append((end, normalized))
                break
            position = blob_lower.find(normalized, position + 1)
    found.sort(key=lambda item: item[0])
    return [term for _, term in found[:limit]]


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


@functools.lru_cache(maxsize=16384)
def _normalize_term(value: str) -> str:
    """Catalog terms are a fixed set reused on every file, so normalizing one
    is worth remembering. 8,333 of these for a single PCI pass."""
    return " ".join(str(value or "").strip().split()).lower()


def _word_boundary(text: str, start: int, end: int, keyword: str) -> bool:
    if not keyword or not keyword[0].isalnum() or not keyword[-1].isalnum():
        return True
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    return not _word_char(before) and not _word_char(after)


def _word_char(char: str) -> bool:
    return bool(char and re.match(r"[A-Za-z0-9_]", char))
