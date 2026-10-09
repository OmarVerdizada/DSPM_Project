"""What a client is told when a request fails (C8).

Two kinds of failure reach a route, and they deserve different answers:

* **A deliberate refusal** - a validator saying "this catalog is missing its version",
  "legal hold is active". The operator needs that exact sentence to fix the request,
  and it was written to be shown.
* **Anything else** - a library raising ValueError with a server path in it
  (`Path.relative_to` names both directories), a JSON parser echoing the byte offset
  and the input, a driver error naming a table. The client learns nothing useful from
  it and an attacker learns the layout of the server. ASVS V7.4.1: show a generic
  message with a reference support can use, and log the detail against that reference.

Routes used to do `HTTPException(400, detail=str(exc))` for any ValueError, which
cannot tell the two apart. `client_message` does: an exception is shown only when its
TYPE says it is a deliberate refusal - a plain ValueError (the convention the store's
validators follow; library subclasses such as JSONDecodeError, UnicodeError or pydantic's
ValidationError do not qualify) or a class that declares `client_safe = True` - and its
text does not look like it carries internals. Everything else gets the fallback and a
reference.
"""

from __future__ import annotations

import logging
import re
import secrets

logger = logging.getLogger("sentro.errors")

# Things that are never meant for a client: filesystem paths (Windows drive, UNC,
# common POSIX roots), tracebacks, parser positions, SQL, driver names, raw addresses.
_LOOKS_INTERNAL = re.compile(
    r"[A-Za-z]:[\\/]"
    r"|\\\\[^\s\\]+\\"
    r"|(?<![\w.])/(?:home|usr|var|etc|opt|tmp|srv|root|mnt|proc|Users)/"
    r"|Traceback|File \""
    r"|line \d+ column \d+|\(char \d+\)"
    r"|\b(?:SELECT|INSERT|UPDATE|DELETE)\b.+\b(?:FROM|INTO|SET|WHERE)\b"
    r"|sqlite3?\b|psycopg|OperationalError|IntegrityError"
    r"|0x[0-9a-fA-F]{6,}",
)

_MAX_SHOWN = 300


def new_reference() -> str:
    """A short id a support engineer can grep the log for; random, so it reveals nothing."""
    return secrets.token_hex(6)


def is_client_safe(exc: BaseException) -> bool:
    if type(exc) is ValueError:
        return True
    return bool(getattr(type(exc), "client_safe", False))


def client_message(exc: BaseException, fallback: str) -> str:
    """The message a client may see for `exc`.

    Its own text when it is a deliberate refusal that does not carry internals;
    otherwise `fallback` with a reference, logged together with what actually happened.
    """

    text = str(exc or "").strip()
    if is_client_safe(exc) and text and len(text) <= _MAX_SHOWN and not _LOOKS_INTERNAL.search(text):
        return text
    reference = new_reference()
    logger.warning("Request refused, reference %s: %s: %s", reference, type(exc).__name__, text[:1000])
    return f"{fallback} (reference {reference})"
