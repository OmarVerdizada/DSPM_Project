"""Offline check for passwords that are common or known to have been breached (C8).

A length-and-composition rule stops "abc" and lets "Password2024!" through, which is
the first thing any guessing attack tries. Refusing known-bad passwords is the control
that actually moves the needle, and it has to work without the network: Sentro is
installed on customer premises and often cannot reach the Internet at all.

Two layers:

* **Built in** - a small list of the base words that dominate real-world breach
  corpora, compared after the decorations people add to satisfy composition rules are
  taken off (case, leetspeak substitutions, trailing digits and symbols). It works out
  of the box and costs nothing.
* **Operator supplied** - ``DSPM_BREACHED_PASSWORDS_FILE`` may point at a sorted file of
  SHA-1 hashes, one per line, optionally followed by ``:count`` - the format of the
  "Pwned Passwords" offline download, ordered by hash. It is binary-searched on disk,
  so the full corpus (tens of gigabytes) costs a few dozen seeks per check and no
  memory. A missing or unreadable file is logged and the built-in list still applies:
  the check degrades, it never blocks every password change.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# The bases that account for most of every published breach corpus, plus this
# product's own name - the first thing someone setting a Sentro password reaches for.
_COMMON_BASES = frozenset({
    "password", "passwd", "passw", "pass", "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "azerty", "admin", "administrator", "root", "welcome", "letmein", "login",
    "changeme", "default", "secret", "master", "monkey", "dragon", "football", "baseball",
    "soccer", "iloveyou", "sunshine", "princess", "shadow", "superman", "batman", "trustno",
    "starwars", "whatever", "freedom", "hello", "hellothere", "abc", "abcdef", "abcdefg",
    "user", "guest", "test", "tester", "demo", "temp", "summer", "winter", "spring",
    "autumn", "company", "office", "sentro", "sentrodspm", "dspm", "security", "access",
})

# Whole passwords that survive a 12-character minimum and still top the lists.
_COMMON_EXACT = frozenset({
    "123456789012", "1234567890ab", "123456789abc", "1q2w3e4r5t6y", "1qaz2wsx3edc",
    "qazwsxedcrfv", "q1w2e3r4t5y6", "zaq12wsxcde3", "abc123abc123", "a1b2c3d4e5f6",
    "passw0rd1234", "p4ssw0rd1234", "qwerty123456", "123456qwerty", "password1234",
    "iloveyou1234", "abcdefgh1234", "abcd1234abcd",
})

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})


def _base_word(password: str) -> str:
    """What is left when the usual decorations are taken off: case, leetspeak, and the
    digits and symbols bolted onto either end to satisfy a composition rule."""
    lowered = password.strip().lower()
    trimmed = re.sub(r"^[^a-z@$]+|[^a-z]+$", "", lowered)
    return trimmed.translate(_LEET)


def is_common(password: str) -> bool:
    lowered = str(password or "").lower()
    if lowered in _COMMON_EXACT:
        return True
    base = _base_word(lowered)
    if base in _COMMON_BASES:
        return True
    # A common base doubled ("passwordpassword").
    if any(base == word * 2 for word in _COMMON_BASES):
        return True
    # Nothing but common words joined up ("sentro-admin-1", "welcome.password.2024"):
    # every piece is on the list, so the whole is as guessable as its parts.
    pieces = [piece for piece in re.split(r"[^a-z]+", base) if piece]
    return len(pieces) > 1 and all(piece in _COMMON_BASES for piece in pieces)


def _line_key(line: bytes) -> bytes:
    return line.split(b":", 1)[0].strip().upper()


def _first_line_at_or_after(handle, offset: int) -> bytes:
    if offset <= 0:
        handle.seek(0)
    else:
        handle.seek(offset - 1)
        handle.readline()  # the rest of the line that contains offset - 1
    return handle.readline()


def sorted_file_contains(path: Path, key: str) -> bool:
    """Binary search a file of sorted keys, one per line, without reading it into memory.

    The function "key of the first line starting at or after byte o" never decreases as
    o grows, so the smallest o whose key is not below the target is found in
    O(log size) seeks; the line there either is the target or the target is absent.
    """

    target = key.upper().encode("ascii")
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        low, high = 0, handle.tell()
        while low < high:
            middle = (low + high) // 2
            line = _first_line_at_or_after(handle, middle)
            if line and _line_key(line) < target:
                low = middle + 1
            else:
                high = middle
        line = _first_line_at_or_after(handle, low)
    return bool(line) and _line_key(line) == target


def breach_corpus_path() -> Path | None:
    configured = os.getenv("DSPM_BREACHED_PASSWORDS_FILE", "").strip()
    return Path(configured) if configured else None


def in_breach_corpus(password: str) -> bool:
    path = breach_corpus_path()
    if path is None:
        return False
    digest = hashlib.sha1(str(password).encode("utf-8"), usedforsecurity=False).hexdigest()
    try:
        return sorted_file_contains(path, digest)
    except OSError as exc:
        logger.warning("Breached-password file %s could not be read (%s); only the built-in list applies",
                       path, type(exc).__name__)
        return False


def password_is_breached(password: str) -> bool:
    return is_common(password) or in_breach_corpus(password)
