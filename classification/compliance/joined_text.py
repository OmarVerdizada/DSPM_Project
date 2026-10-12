"""A candidate's context followed by the whole file, searched without being built (W4.3).

The PCI detectors decide each candidate - an expiry, a name, a card, a spreadsheet row - from
``f"{local context} {evidence}"``, where the evidence is the whole file with its name, path
and extension: a keyword anywhere in the file counts. Built per candidate, that string copied,
lowered and searched the whole file once per candidate - per row of a 16 MiB CSV, 5,000 times
- so a card-free 16 MiB export took 168 s in the PCI detector alone (MEASURED, 2026-10-08).

``Joined`` answers the same questions about that string without building it. The file is
lowered once, and each keyword's first match in it is found once per file; a candidate costs
its own context. The answers are exact, not approximate:

- ``str.lower`` is per character but for the final sigma, whose context a space ends, so the
  lowered whole is the lowered parts joined by spaces;
- a keyword's first match in ``local + " " + evidence`` is its first match that starts in
  ``local`` or on the space (found in ``local``, the space and as much of the evidence as the
  longest keyword reaches), or else its first match in the evidence, shifted - a word
  boundary at the space is a boundary at the start of the evidence;
- a marker is in the whole if it is in a part, or in the few characters either side of a
  space that joins two parts (a part shorter than the marker is taken whole).
"""
from __future__ import annotations

from typing import Iterable

from classification.compliance.keyword_index import (
    _ADHOC_TRIE_THRESHOLD,
    _adhoc_terms,
    _word_boundary,
    keyword_hits_indexed,
)


class FileEvidence:
    """The file-wide text every candidate's context is followed by: lowered once, and each
    keyword's first match in it found once."""

    __slots__ = ("text", "_lower", "_first_end", "_contains")

    def __init__(self, text: str) -> None:
        self.text = text
        self._lower: str | None = None
        self._first_end: dict[str, int | None] = {}
        self._contains: dict[str, bool] = {}

    def contains(self, marker: str) -> bool:
        """``marker in self.lower``, searched once per marker (W5). The protection-state checks
        ask the same thirty-odd markers of every candidate's ``f"{local} {evidence}"``, and
        each asked them of the whole file again: a 2 MiB card-free CSV spent 34 s in PCI."""
        found = self._contains.get(marker)
        if found is None:
            found = self._contains[marker] = marker in self.lower
        return found

    @property
    def lower(self) -> str:
        if self._lower is None:
            self._lower = self.text.lower()
        return self._lower

    def first_end(self, term: str) -> int | None:
        """Where ``term``'s first match on word boundaries ends in the lowered text, if any."""
        if term in self._first_end:
            return self._first_end[term]
        lowered = self.lower
        end = None
        position = lowered.find(term)
        while position >= 0:
            candidate = position + len(term)
            if _word_boundary(lowered, position, candidate, term):
                end = candidate
                break
            position = lowered.find(term, position + 1)
        self._first_end[term] = end
        return end

    def after(self, local: str) -> "Joined":
        """``f"{local} {self.text}"``, not built."""
        return Joined(local, self)


Part = "str | FileEvidence"


def _part_lower(part) -> str:
    return part.lower if isinstance(part, FileEvidence) else part.lower()


class _Lowered:
    """What ``.lower()`` of the joined text gives the checks that only ask ``marker in it``."""

    __slots__ = ("_joined",)

    def __init__(self, joined: "Joined") -> None:
        self._joined = joined

    def __contains__(self, marker: str) -> bool:
        return self._joined.contains_lowered(marker)


class Joined:
    """The parts joined by single spaces - ``local`` then the file's evidence - unbuilt."""

    __slots__ = ("parts", "_lowered_parts")

    def __init__(self, *parts) -> None:
        self.parts = parts
        self._lowered_parts: list[str] | None = None

    def __str__(self) -> str:
        return " ".join(part.text if isinstance(part, FileEvidence) else part for part in self.parts)

    def _lowers(self) -> list[str]:
        if self._lowered_parts is None:
            self._lowered_parts = [_part_lower(part) for part in self.parts]
        return self._lowered_parts

    def lower(self) -> _Lowered:
        return _Lowered(self)

    def contains_lowered(self, marker: str) -> bool:
        """``marker in str(self).lower()``."""
        if not marker:
            return True
        lowers = self._lowers()
        if any(part.contains(marker) if isinstance(part, FileEvidence) else marker in lowered
               for part, lowered in zip(self.parts, lowers)):
            return True
        if len(lowers) < 2:
            return False
        # A match across a joining space lies within ``len(marker)`` characters of it: the
        # parts cut to their edges (a short part whole) still contain it, and nothing that
        # is not in the whole.
        reach = len(marker)
        edges = []
        for part in lowers:
            edges.append(part if len(part) <= 2 * reach else f"{part[:reach]}\x00{part[-reach:]}")
        return marker in " ".join(edges)

    def keyword_hits(self, keywords: Iterable[str], *, cache_namespace: str = "adhoc", limit: int = 10) -> list[str]:
        """``keyword_hits_indexed(str(self), keywords, ...)`` for ``local`` then the evidence."""
        terms = _adhoc_terms(tuple(keywords))
        if not terms:
            return []
        if (len(terms) > _ADHOC_TRIE_THRESHOLD or len(self.parts) != 2
                or not isinstance(self.parts[1], FileEvidence) or isinstance(self.parts[0], FileEvidence)):
            return keyword_hits_indexed(str(self), keywords, cache_namespace=cache_namespace, limit=limit)
        evidence: FileEvidence = self.parts[1]
        local_lower = self._lowers()[0]
        offset = len(local_lower) + 1
        longest = max(len(term) for term in terms)
        # Everything a match that starts in ``local`` or on the space can touch, and the
        # character after it: identical to the whole there.
        head = f"{local_lower} {evidence.lower[:longest + 1]}"
        found: list[tuple[int, str]] = []
        for term in terms:
            end = None
            position = head.find(term)
            while 0 <= position < offset:
                candidate = position + len(term)
                if _word_boundary(head, position, candidate, term):
                    end = candidate
                    break
                position = head.find(term, position + 1)
            if end is None:
                first = evidence.first_end(term)
                if first is not None:
                    end = offset + first
            if end is not None:
                found.append((end, term))
        found.sort(key=lambda item: item[0])
        return [term for _, term in found[:limit]]
