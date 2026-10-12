from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import functools
import hashlib
import json
import re
import threading
from typing import Iterable


# P3 (2026-09-24). This was an Aho-Corasick trie of Python objects: 277,280 nodes for the
# 46,000-term GDPR catalog, 100 MiB in every detector worker - about 500 MiB of a scan's
# 1.72 GiB peak across five workers - and 1.3 CPU-seconds to build in each. Searching it
# was never the cost (1.25 s over a 3,083-file scan). Persisting the trie would have saved
# the build and kept the memory, so the trie itself is gone.
#
# Each term is filed under ONE of its trigrams - the one fewest catalog terms share,
# which is the one least likely to be in any given text. A term cannot occur unless all
# of its trigrams do, so a text only has to test the terms filed under a trigram it
# contains, and it tests them with str.find and the same word-boundary rule. The answer
# is the automaton's, in the automaton's order: a keyword is reported at its first
# occurrence that passes the boundary check, earlier ends first, and at the same end the
# longer keyword first (the automaton lists a node's own keyword before the suffixes its
# fail links add) and then the catalog's order. tests/test_p3_keyword_index.py holds the
# automaton and compares the two on the real catalogs.
_TermEntry = tuple  # (term, ((insertion order, finding type), ...))


@dataclass(slots=True)
class KeywordIndex:
    framework: str
    catalog_version: str
    language: str
    compiled_index: str
    created_at: str
    buckets: dict[str, tuple[_TermEntry, ...]]
    keys: frozenset[str]
    short: tuple[_TermEntry, ...]
    term_count: int

    def search(self, text: str, limit_per_type: int = 10) -> dict[str, list[str]]:
        lowered = str(text or "").lower()
        if not lowered:
            return {}
        hits: list[tuple[int, int, int, str, str]] = []
        present = self.keys & {lowered[i:i + 3] for i in range(len(lowered) - 2)}
        for entries in (self.short, *(self.buckets[key] for key in present)):
            for term, types in entries:
                position = lowered.find(term)
                while position >= 0:
                    end = position + len(term)
                    if _word_boundary(lowered, position, end, term):
                        hits.extend((end, -len(term), order, term, finding_type) for order, finding_type in types)
                        break
                    position = lowered.find(term, position + 1)
        hits.sort()
        matches: dict[str, list[str]] = {}
        for _end, _longer_first, _order, term, finding_type in hits:
            bucket = matches.setdefault(finding_type, [])
            if term not in bucket and len(bucket) < limit_per_type:
                bucket.append(term)
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
    # Every (term, finding type) once, numbered in catalog order - the order in which the
    # automaton appended a term's types to its node.
    types_by_term: dict[str, list[tuple[int, str]]] = {}
    seen: set[tuple[str, str]] = set()
    order = 0
    for group in groups:
        finding_type = str(group.get("type") or "").strip()
        if not finding_type:
            continue
        for raw_term in group.get("terms") or []:
            term = _normalize_term(raw_term)
            if not term or (term, finding_type) in seen:
                continue
            seen.add((term, finding_type))
            types_by_term.setdefault(term, []).append((order, finding_type))
            order += 1

    # Two passes over the terms rather than every term's trigram set held at once: that
    # was a 78 MiB peak for the GDPR catalog, which the allocator does not hand back.
    shared_by: dict[str, int] = {}
    for term in types_by_term:
        for trigram in {term[i:i + 3] for i in range(len(term) - 2)}:
            shared_by[trigram] = shared_by.get(trigram, 0) + 1
    buckets: dict[str, list[_TermEntry]] = {}
    short: list[_TermEntry] = []
    for term, types in types_by_term.items():
        entry = (term, tuple(types))
        if len(term) < 3:
            short.append(entry)
            continue
        rarest = min((term[i:i + 3] for i in range(len(term) - 2)), key=lambda trigram: (shared_by[trigram], trigram))
        buckets.setdefault(rarest, []).append(entry)

    return KeywordIndex(
        framework=framework,
        catalog_version=catalog_version,
        language=language,
        compiled_index=f"{framework}:{catalog_version}:{language}",
        created_at=datetime.now(timezone.utc).isoformat(),
        buckets={trigram: tuple(entries) for trigram, entries in buckets.items()},
        keys=frozenset(buckets),
        short=tuple(short),
        term_count=len(types_by_term),
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
