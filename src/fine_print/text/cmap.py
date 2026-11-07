"""A ToUnicode or encoding CMap, as PHP's ``FinePrint\\Text\\CMap``.

Ranges are NEVER expanded into a table (``<0000> <FFFF>`` is one row, looked up
arithmetically) and the number of rows read is capped.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .._php import utf16 as _utf16be
from ..exceptions import PdfSyntaxError
from ..objects import Keyword, PdfName, PdfString
from ..parser import Parser
from .encodings import glyph


def _int(b: bytes) -> int:
    return int.from_bytes(b[:7], "big") if b else 0


def _utf16(b: bytes) -> str:
    if not b:
        return ""
    if len(b) % 2 == 1:
        b = b"\x00" + b
    return _utf16be(b)


class CMap:
    def __init__(self, source: bytes, max_entries: int = 100_000) -> None:
        self._codespace: list[tuple[int, int, int]] = []
        self._chars: dict[bytes, str] = {}
        self._ranges: list[tuple[int, int, int, Any]] = []
        self._cid_chars: dict[bytes, int] = {}
        self._cid_ranges: list[tuple[int, int, int, int]] = []

        p = Parser(source, refs=False)
        ops: list[Any] = []
        entries = 0
        try:
            while not p.at_end():
                v = p.parse_value()
                if not isinstance(v, Keyword):
                    ops.append(v)
                    if len(ops) > 3 * max_entries:
                        break
                    continue
                w = v.word
                if w == "endcodespacerange":
                    i = 0
                    while i + 1 < len(ops):
                        a, b = ops[i], ops[i + 1]
                        if isinstance(a, PdfString) and isinstance(b, PdfString):
                            self._codespace.append((len(a.bytes), _int(a.bytes), _int(b.bytes)))
                        i += 2
                elif w == "endbfchar":
                    i = 0
                    while i + 1 < len(ops) and entries < max_entries:
                        src, dst = ops[i], ops[i + 1]
                        if isinstance(src, PdfString):
                            if isinstance(dst, PdfName):
                                self._chars[src.bytes] = glyph(dst.value) or ""
                            else:
                                self._chars[src.bytes] = _utf16(dst.bytes if isinstance(dst, PdfString) else b"")
                        i += 2
                        entries += 1
                elif w == "endcidchar":
                    i = 0
                    while i + 1 < len(ops) and entries < max_entries:
                        a, b = ops[i], ops[i + 1]
                        if isinstance(a, PdfString) and type(b) is int and b >= 0:
                            self._cid_chars[a.bytes] = b
                        i += 2
                        entries += 1
                elif w == "endcidrange":
                    i = 0
                    while i + 2 < len(ops) and entries < max_entries:
                        lo, hi, dst = ops[i], ops[i + 1], ops[i + 2]
                        if isinstance(lo, PdfString) and isinstance(hi, PdfString) and type(dst) is int and dst >= 0:
                            self._cid_ranges.append((len(lo.bytes), _int(lo.bytes), _int(hi.bytes), dst))
                        i += 3
                        entries += 1
                elif w == "endbfrange":
                    i = 0
                    while i + 2 < len(ops) and entries < max_entries:
                        lo, hi, dst = ops[i], ops[i + 1], ops[i + 2]
                        i += 3
                        entries += 1
                        if not isinstance(lo, PdfString) or not isinstance(hi, PdfString):
                            continue
                        if isinstance(dst, list):
                            dst = [_utf16(d.bytes) if isinstance(d, PdfString) else "" for d in dst]
                        elif isinstance(dst, PdfString):
                            dst = dst.bytes
                        else:
                            continue
                        self._ranges.append((len(lo.bytes), _int(lo.bytes), _int(hi.bytes), dst))
                ops = []
        except PdfSyntaxError:
            pass  # a damaged CMap keeps what it defined before the damage

    def has_codespace(self) -> bool:
        return bool(self._codespace)

    def range_count(self) -> int:
        return len(self._ranges)

    def has_cids(self) -> bool:
        return bool(self._cid_chars) or bool(self._cid_ranges)

    def cid(self, code: bytes) -> int | None:
        if code in self._cid_chars:
            return self._cid_chars[code]
        n = len(code)
        v = _int(code)
        for ln, lo, hi, c in self._cid_ranges:
            if ln == n and lo <= v <= hi:
                return c + (v - lo)
        return None

    def each(self, data: bytes, fallback: int) -> Iterator[bytes]:
        n = len(data)
        i = 0
        cs = self._codespace
        while i < n:
            take = 0
            for ln, lo, hi in cs:
                if i + ln <= n:
                    v = _int(data[i : i + ln])
                    if lo <= v <= hi:
                        take = ln
                        break
            if take == 0:
                take = min(fallback, n - i)
            yield data[i : i + take]
            i += take

    def split(self, data: bytes, fallback: int) -> list[bytes]:
        return list(self.each(data, fallback))

    def lookup(self, code: bytes) -> str | None:
        c = self._chars.get(code)
        if c is not None:
            return c
        n = len(code)
        v = _int(code)
        for ln, lo, hi, dst in self._ranges:
            if ln != n or v < lo or v > hi:
                continue
            off = v - lo
            if isinstance(dst, list):
                return dst[off] if off < len(dst) else None
            if dst == b"":
                return None
            if len(dst) >= 2:
                last = _int(dst[-2:]) + off
                return _utf16(dst[:-2] + (last & 0xFFFF).to_bytes(2, "big"))
            return _utf16(bytes(((dst[0] + off) & 0xFF,)))
        return None
