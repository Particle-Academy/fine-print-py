"""PDF text strings (metadata, outline titles, annotations) to text, as PHP's
``FinePrint\\Text\\TextString``. Invisible characters are KEPT: only the guard
decides what to do about them."""

from __future__ import annotations

from .._php import scrub, utf16
from .encodings import encoding_map


def decode(data: bytes) -> str:
    if data.startswith(b"\xfe\xff"):
        return utf16(data[2:])
    if data.startswith(b"\xff\xfe"):
        return utf16(data[2:], little=True)
    if data.startswith(b"\xef\xbb\xbf"):
        return scrub(data[3:])
    m = encoding_map("PDFDocEncoding") or {}
    return "".join(m.get(b, "�") for b in data)
