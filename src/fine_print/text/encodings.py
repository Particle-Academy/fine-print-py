"""The single-byte base encodings and the glyph-name list, as PHP's
``FinePrint\\Text\\Encodings``. The tables are generated from PHP
(``_encoding_data``); never Python's ``cp1252``/``mac_roman`` codecs, which are
not PDF's WinAnsi/MacRoman."""

from __future__ import annotations

import re

from .._php import utf16
from ._encoding_data import GLYPHS, MAPS

_maps: dict[str, dict[int, str]] = {}

# PCRE's `$` also matches before a final newline; a name can carry one (#0A).
_UNI = re.compile(r"uni((?:[0-9A-F]{4})+)\n?\Z")
_U = re.compile(r"u([0-9A-F]{4,6})\n?\Z")


def encoding_map(name: str) -> dict[int, str] | None:
    """A named base encoding as code -> text, or None for an unknown name."""
    m = _maps.get(name)
    if m is not None:
        return m
    raw = MAPS.get(name)
    if raw is None:
        return None
    m = {code: chr(cp) for code, cp in raw.items()}
    _maps[name] = m
    return m


def glyph(name: str) -> str | None:
    """A glyph name as text: AGL names, ``uniXXXX``, ``uXXXX[XX]``, suffixed
    variants (``a.sc``) and underscore ligatures (``f_f_i``)."""
    cp = GLYPHS.get(name)
    if cp is not None:
        return chr(cp)
    dot = name.find(".")
    if dot > 0:
        return glyph(name[:dot])
    if "_" in name:
        out = ""
        for part in name.split("_"):
            g = glyph(part)
            if g is None:
                return None
            out += g
        return out
    m = _UNI.match(name)
    if m is not None:
        s = utf16(bytes.fromhex(m.group(1)))
        return None if s == "" else s
    m = _U.match(name)
    if m is not None:
        v = int(m.group(1), 16)
        if v <= 0x10FFFF and (v < 0xD800 or v > 0xDFFF):
            return chr(v)
    return None
