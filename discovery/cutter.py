"""Cut a tree into bounded units in walk order, each emitted the moment it is final (W3.1).

Both planners - a local folder tree and an SMB share - cut the same way: a folder whose
walk fits one unit stays inside its parent's unit; a larger one is cut into runs of its
own entries, packed in order up to the budgets, with a subfolder too large for one run cut
in place. Every unit is consecutive entries of one folder, and the units in sequence are
exactly one walk.

The old planners finished the whole walk before the first unit was known, held the plan in
memory, and could not be continued. Here a folder is known to be too large the moment its
running weight passes a budget - not when its walk ends - and from then on every run before
it, at every level above it, is final: it is emitted at once, top-down, in walk order. So
units reach the ledger while the walk runs, the first can run before planning ends, and
what is held is one pending run per level of the path being walked.

**Order and the cursor.** Entries are walked in case-folded name order, so the walk is a
pre-order over sorted children and its order is the lexicographic order of entries' path
tuples. A unit covers every entry of its folder below its end key (and what is under those
entries); the cursor is the path tuple of the last emitted unit's end. A planner continued
from a cursor skips every entry before it - no unit is written twice - and the folders on
the cursor's path are already known to be too large.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Iterable

END = "\U0010ffff"  # sorts after every name: "the rest of the folder"
AFTER = "\x00"  # appended to a key: "just after this name"


@dataclass
class Entry:
    """One entry of a folder as the walk meets it, with the weight the scan will spend on it.

    ``digest`` (W4.2) says what the walk would find there: for a file, what the listing
    shows of it; for a folder walked inside its parent's unit, a digest of its entries;
    "" when unknown - and a unit holding an entry of unknown digest is never skipped.
    ``folders`` are the keys of the folders walked under it."""

    key: str
    name: str
    is_dir: bool = False
    files: int = 0
    bytes: int = 0
    digest: str = ""
    folders: tuple = ()


@dataclass
class _Frame:
    handle: object
    depth: int
    path: tuple
    parent: "_Frame | None"
    big: bool = False
    low: str = ""
    pending: list = field(default_factory=list)
    pending_files: int = 0
    pending_bytes: int = 0
    total_files: int = 0
    total_bytes: int = 0
    unstable: bool = False


def entries_digest(entries: Iterable[Entry], salt: str = "") -> str:
    """A digest of entries in walk order - "" if any of them has none (W4.2)."""
    digest = hashlib.sha256(salt.encode("utf-8", errors="replace"))
    for entry in entries:
        if not entry.digest:
            return ""
        digest.update(f"\x1f{entry.key}\x1e{entry.digest}".encode("utf-8", errors="replace"))
    return digest.hexdigest()


class Cutter:
    """``list_folder(handle, depth)`` yields ``(entry, child_handle)`` in walk order - a child
    handle for a folder the walk enters, ``None`` otherwise - or raises ``OSError`` for a
    folder that cannot be listed (whose walk reports it, so it stays in its parent's unit).
    ``make_unit(handle, depth, entries, low, high)`` builds a unit; ``high`` is ``END`` for
    the rest of the folder. ``emit(unit, cursor)`` receives every unit in walk order.

    A range with nothing in it at planning is not a unit: a unit walks the slice of its
    folder's listing the planner read, so an empty range would walk nothing. Unless
    ``keep_gaps(handle)`` says the folder's listing is not fully known - an SMB folder one
    of whose overlapping shares could not be listed - and its units list it themselves:
    then every range of it is a unit, so none of its names falls between two units."""

    def __init__(self, *, files_budget: int, bytes_budget: int,
                 list_folder: Callable[[object, int], Iterable[tuple[Entry, object]]],
                 make_unit: Callable[[object, int, list[Entry], str, str], dict],
                 emit: Callable[[dict, tuple], None], cursor: tuple = (),
                 stop_check: Callable[[], str | None] | None = None,
                 keep_gaps: Callable[[object], bool] | None = None,
                 name_folder: Callable[[object], str] | None = None) -> None:
        self.files_budget = max(1, int(files_budget))
        self.bytes_budget = max(1, int(bytes_budget))
        self.list_folder = list_folder
        self.make_unit = make_unit
        self.emit = emit
        self.cursor = tuple(cursor or ())
        self.stop_check = stop_check
        self.keep_gaps = keep_gaps
        # W4.2: names a folder by its key; without it no folder entry has a digest, so no
        # unit of this planner is ever skipped.
        self.name_folder = name_folder
        self.emitted = 0

    # -- the walk ------------------------------------------------------------------------

    def run(self, root) -> tuple[int, int, bool]:
        """Walk from ``root``; returns (files, bytes, whether the root had to be cut)."""
        frame = _Frame(handle=root, depth=0, path=(), parent=None, big=bool(self.cursor))
        if len(self.cursor) == 1:
            frame.low = self.cursor[0]
        self._visit(frame)
        return frame.total_files, frame.total_bytes, frame.big

    def _covered(self, path: tuple) -> bool:
        """Before the cursor and not on its path: emitted by an earlier run."""
        return bool(self.cursor) and path < self.cursor and self.cursor[:len(path)] != path

    def _on_cursor_path(self, path: tuple) -> bool:
        return bool(self.cursor) and len(path) < len(self.cursor) and self.cursor[:len(path)] == path

    def _visit(self, frame: _Frame) -> bool:
        """Walk one folder; returns whether its walk observes anything.

        A folder that holds nothing its walk would report - no file, nothing skipped or
        unreadable - is left out of its parent's run; anything else stays in some unit, so a
        folder a walk reports is never dropped (B2.2b review)."""
        if self.stop_check is not None:
            reason = self.stop_check()
            if reason:
                raise RuntimeError(reason)
        observed = False
        try:
            listing = self.list_folder(frame.handle, frame.depth)
            for entry, child in listing:
                path = frame.path + (entry.key,)
                if self._covered(path):
                    observed = True
                    continue
                if entry.is_dir and child is not None:
                    child_frame = _Frame(handle=child, depth=frame.depth + 1, path=path, parent=frame)
                    if self._on_cursor_path(path):
                        child_frame.big = True
                        if len(self.cursor) == len(path) + 1:
                            child_frame.low = self.cursor[-1]
                    child_observed = self._visit(child_frame)
                    if child_frame.big:
                        # Cut in place: its units are emitted; it still weighs in the totals.
                        frame.total_files += child_frame.total_files
                        frame.total_bytes += child_frame.total_bytes
                        frame.low = entry.key + AFTER
                        observed = True
                        continue
                    if not child_observed and not child_frame.total_files:
                        continue
                    entry.files, entry.bytes = child_frame.total_files, child_frame.total_bytes
                    if self.name_folder is not None:
                        # Walked inside this unit: it is what its entries are.
                        entry.digest = "" if child_frame.unstable else entries_digest(child_frame.pending, "dir")
                        entry.folders = (self.name_folder(child),) + tuple(
                            key for item in child_frame.pending for key in item.folders)
                observed = True
                self._add(frame, entry)
        except OSError:
            # Unreadable: its walk reports it, so it stays inside its parent's unit - and what
            # it holds is unknown, so no unit holding it is ever skipped (W4.2).
            frame.unstable = True
            return True
        if frame.big:
            self._flush(frame, END)
        return observed

    # -- packing -------------------------------------------------------------------------

    def _over(self, files: int, size: int) -> bool:
        return files > self.files_budget or size > self.bytes_budget

    def _add(self, frame: _Frame, entry: Entry) -> None:
        frame.total_files += entry.files
        frame.total_bytes += entry.bytes
        if frame.big:
            if frame.pending and self._over(frame.pending_files + entry.files, frame.pending_bytes + entry.bytes):
                self._flush(frame, entry.key)
            self._append(frame, entry)
            return
        self._append(frame, entry)
        if self._over(frame.total_files, frame.total_bytes):
            self._become_big(frame)

    @staticmethod
    def _append(frame: _Frame, entry: Entry) -> None:
        frame.pending.append(entry)
        frame.pending_files += entry.files
        frame.pending_bytes += entry.bytes

    def _become_big(self, frame: _Frame) -> None:
        if frame.big:
            return
        parent = frame.parent
        if parent is not None:
            self._become_big(parent)
            # Everything the parent holds so far comes before this folder in the walk.
            self._flush(parent, frame.path[-1])
            parent.low = frame.path[-1] + AFTER
        frame.big = True
        entries = frame.pending
        frame.pending, frame.pending_files, frame.pending_bytes = [], 0, 0
        for entry in entries:
            if frame.pending and self._over(frame.pending_files + entry.files, frame.pending_bytes + entry.bytes):
                self._flush(frame, entry.key)
            self._append(frame, entry)

    def _flush(self, frame: _Frame, high: str) -> None:
        # Nothing pending leaves the range's start where it is, so the next unit starts there.
        if not frame.pending and not (self.keep_gaps is not None and frame.low < high
                                      and self.keep_gaps(frame.handle)):
            return
        unit = self.make_unit(frame.handle, frame.depth, frame.pending, frame.low, high)
        self.emitted += 1
        self.emit(unit, frame.path + (high,))
        frame.pending, frame.pending_files, frame.pending_bytes = [], 0, 0
        if high != END:
            frame.low = high
