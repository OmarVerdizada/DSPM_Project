"""The bytes a collector read, as the text the classifiers read.

Every collector decoded what it read as UTF-8 and never looked for a byte-order mark, so
a UTF-16 file - a regedit .reg export, a PowerShell 5.1 ``>`` or ``Out-File`` log, Excel's
"Unicode Text" - came out with a NUL between every character. Triage skipped it as
binary while its record said scanned and FULL: no detector ever ran on it. Decoding each
1 MB chunk on its own also broke a multi-byte character wherever a chunk ended.

The encoding is decided once, from the start of the file: a byte-order mark (UTF-8,
UTF-16 or UTF-32, either byte order), else UTF-16 without one when the first 4 KB has a
NUL in every other byte - Latin text in UTF-16, which is what those tools write -
else UTF-8, as before. The mark is not part of the text. The bytes then go through one
incremental decoder, so a chunk may end anywhere.

Only the text is decoded here. A file's hash stays the hash of its raw bytes.
"""

from __future__ import annotations

import codecs

# How much of the start of a file decides its encoding.
SNIFF_BYTES = 4096

# UTF-32 LE before UTF-16 LE: FF FE 00 00 also starts with UTF-16's FF FE.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)

# UTF-16 with no mark: at least half the code units have a NUL high byte (Latin text),
# and almost none a NUL low byte. A UTF-8 text has no NULs at all, and binary noise
# rarely has them in only one of the two positions.
_UTF16_HIGH_NUL_SHARE = 0.5
_UTF16_LOW_NUL_SHARE = 0.1


def detect_encoding(head: bytes) -> tuple[str, int]:
    """(codec, length of the byte-order mark) for a file whose first bytes are ``head``."""
    for mark, codec in _BYTE_ORDER_MARKS:
        if head.startswith(mark):
            return codec, len(mark)
    sample = head[:SNIFF_BYTES]
    units = len(sample) // 2
    # A few bytes say nothing: one stray NUL in a tiny file would pass for UTF-16.
    if units >= 4:
        even_nuls = sample[0:units * 2:2].count(0)
        odd_nuls = sample[1:units * 2:2].count(0)
        if odd_nuls >= units * _UTF16_HIGH_NUL_SHARE and even_nuls <= units * _UTF16_LOW_NUL_SHARE:
            return "utf-16-le", 0
        if even_nuls >= units * _UTF16_HIGH_NUL_SHARE and odd_nuls <= units * _UTF16_LOW_NUL_SHARE:
            return "utf-16-be", 0
    return "utf-8", 0


class TextDecoder:
    """One file's bytes, fed in chunks of any size, as text.

    The first chunks are held until there are ``SNIFF_BYTES`` of them (or the file ends),
    then the encoding is decided and everything held is decoded. Undecodable bytes become
    U+FFFD, as they always did."""

    def __init__(self) -> None:
        self._head = bytearray()
        self._decoder = None
        self.encoding = ""

    def decode(self, chunk: bytes, final: bool = False) -> str:
        if self._decoder is None:
            self._head.extend(chunk)
            if len(self._head) < SNIFF_BYTES and not final:
                return ""
            self.encoding, mark = detect_encoding(bytes(self._head))
            self._decoder = codecs.getincrementaldecoder(self.encoding)(errors="replace")
            chunk, self._head = bytes(self._head[mark:]), bytearray()
        return self._decoder.decode(chunk, final)


def decode_text(data: bytes) -> str:
    """A whole buffer as text, with the same rules as ``TextDecoder``."""
    return TextDecoder().decode(bytes(data or b""), final=True)
