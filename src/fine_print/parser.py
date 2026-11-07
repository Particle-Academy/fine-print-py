"""Lexer and parser for PDF object syntax, as PHP's ``FinePrint\\Parser\\Parser``.

ITERATIVE where PHP recurses: arrays and dictionaries are parsed with an
explicit stack, because Python's recursion limit (1000) is a crash a hostile
file could choose. The depth cap, the tick per value and every error are
PHP's, in PHP's order.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from ._php import int_string
from .exceptions import PdfSyntaxError, RefusedException
from .limits import Budget, Limits
from .objects import Keyword, PdfDict, PdfName, PdfRef, PdfStream, PdfString

WS = b" \t\r\n\x0c\x00"
DELIM_OR_WS = b" \t\r\n\x0c\x00()<>[]{}/%"

_SKIP = re.compile(rb"(?:[ \t\r\n\x0c\x00]+|%[^\r\n]*)*")
_WS_RUN = re.compile(rb"[ \t\r\n\x0c\x00]*")
_WORD = re.compile(rb"[^ \t\r\n\x0c\x00()<>\[\]{}/%]*")
_DIGITS = re.compile(rb"[0-9]*")
_LIT_PLAIN = re.compile(rb"[^()\\\r]*")
_HEX_ESC = re.compile(rb"#([0-9A-Fa-f]{2})")
_NOT_HEX = re.compile(rb"[^0-9A-Fa-f]")
_INT = re.compile(rb"[+-]?[0-9]+")
_REAL = re.compile(rb"[+-]?(?:[0-9]+\.[0-9]*|\.[0-9]+)")
_NUMERICISH = re.compile(rb"[+\-.0-9]+")

_SIMPLE_ESC = {
    ord("n"): b"\n",
    ord("r"): b"\r",
    ord("t"): b"\t",
    ord("b"): b"\x08",
    ord("f"): b"\x0c",
    ord("("): b"(",
    ord(")"): b")",
    ord("\\"): b"\\",
}

_NOTHING = object()


class _Array:
    __slots__ = ("depth", "items")

    def __init__(self, depth: int) -> None:
        self.depth = depth
        self.items: list[Any] = []


class _Dict:
    __slots__ = ("depth", "entries", "key")

    def __init__(self, depth: int) -> None:
        self.depth = depth
        self.entries: dict[str, Any] = {}
        self.key: str | None = None  # None: expecting a key


def number(word: bytes) -> int | float | None:
    if _INT.fullmatch(word):
        return float(word) if len(word.lstrip(b"+-0")) > 18 else int_string(word)
    if _REAL.fullmatch(word):
        return float(word)
    if _NUMERICISH.fullmatch(word):
        return 0
    return None


class Parser:
    def __init__(
        self,
        data: bytes,
        refs: bool = True,
        resolve: Callable[[PdfRef], Any] | None = None,
        budget: Budget | None = None,
    ) -> None:
        self._data = data
        self._refs = refs
        self._resolve = resolve
        self._budget = budget
        self._len = len(data)
        self._max_depth = budget.limits.max_depth if budget is not None else Limits().max_depth
        self.pos = 0

    @staticmethod
    def value(src: bytes) -> Any:
        return Parser(src).parse_value()

    def position(self) -> int:
        return self.pos

    def seek(self, pos: int) -> None:
        self.pos = max(0, min(pos, self._len))

    def data(self) -> bytes:
        return self._data

    def at_end(self) -> bool:
        self.skip_whitespace()
        return self.pos >= self._len

    def skip_whitespace(self) -> None:
        m = _SKIP.match(self._data, self.pos)
        if m is not None:
            self.pos = m.end()

    # --- values ------------------------------------------------------------------

    def parse_value(self, depth: int = 0) -> Any:
        """The next value, or a :class:`Keyword` for a bare word."""
        data = self._data
        frames: list[_Array | _Dict] = []
        d = depth
        while True:
            # Parse one value at depth d (PHP's parseValue prologue).
            if d > self._max_depth:
                raise RefusedException(
                    "too_deep", f"Arrays and dictionaries nest deeper than the limit of {self._max_depth}."
                )
            if self._budget is not None:
                self._budget.tick()
            self.skip_whitespace()
            if self.pos >= self._len:
                raise PdfSyntaxError("Unexpected end of data")
            c = data[self.pos]
            v: Any = _NOTHING
            if c == 0x2F:  # /
                v = self._parse_name()
            elif c == 0x28:  # (
                v = self._parse_literal()
            elif c == 0x3C:  # <
                if self.pos + 1 < self._len and data[self.pos + 1] == 0x3C:
                    self.pos += 2
                    frames.append(_Dict(d))
                else:
                    v = self._parse_hex()
            elif c == 0x5B:  # [
                self.pos += 1
                frames.append(_Array(d))
            elif c in b"]>){}":
                self.pos += 1
                raise PdfSyntaxError("Unexpected " + chr(c))
            else:
                v = self._parse_word()

            # Deliver finished values upward, and find the next value to parse.
            while True:
                if v is not _NOTHING:
                    if not frames:
                        return v
                    f = frames[-1]
                    if isinstance(f, _Array):
                        if not isinstance(v, Keyword):
                            f.items.append(v)
                    elif f.key is None:
                        if not isinstance(v, PdfName):
                            if isinstance(v, Keyword) and v.word in ("endobj", "stream", "obj"):
                                raise PdfSyntaxError("Unterminated dictionary")
                        else:
                            self.skip_whitespace()
                            if self.pos + 1 < self._len and data[self.pos] == 0x3E and data[self.pos + 1] == 0x3E:
                                f.entries[v.value] = None
                            else:
                                f.key = v.value
                    else:
                        f.entries[f.key] = None if isinstance(v, Keyword) else v
                        f.key = None
                    v = _NOTHING
                f = frames[-1]
                if isinstance(f, _Array):
                    self.skip_whitespace()
                    if self.pos >= self._len:
                        raise PdfSyntaxError("Unterminated array")
                    if data[self.pos] == 0x5D:
                        self.pos += 1
                        frames.pop()
                        v = f.items
                        continue
                    d = f.depth + 1
                    break
                if f.key is None:
                    self.skip_whitespace()
                    if self.pos >= self._len:
                        raise PdfSyntaxError("Unterminated dictionary")
                    if data[self.pos] == 0x3E and self.pos + 1 < self._len and data[self.pos + 1] == 0x3E:
                        self.pos += 2
                        frames.pop()
                        v = PdfDict(f.entries)
                        continue
                d = f.depth + 1
                break

    def parse_indirect(self) -> dict[str, Any]:
        """``num gen obj <value> [stream ... endstream] endobj`` at the cursor."""
        num = self.parse_value()
        gen = self.parse_value()
        kw = self.parse_value()
        if type(num) is not int or type(gen) is not int or not isinstance(kw, Keyword) or kw.word != "obj":
            raise PdfSyntaxError("Not an indirect object header")
        value = self.parse_value()
        if isinstance(value, Keyword):
            return {"num": num, "gen": gen, "value": None}
        self.skip_whitespace()
        if isinstance(value, PdfDict) and self._data.startswith(b"stream", self.pos):
            self.pos += 6
            value = self._read_stream_body(value, num)
        return {"num": num, "gen": gen, "value": value}

    def _read_stream_body(self, d: PdfDict, num: int) -> PdfStream:
        data = self._data
        if self.pos < self._len and data[self.pos] == 0x0D:
            self.pos += 1
        if self.pos < self._len and data[self.pos] == 0x0A:
            self.pos += 1
        start = self.pos
        length = d.get("Length")
        if isinstance(length, PdfRef) and self._resolve is not None:
            length = self._resolve(length)
        if type(length) is int and length >= 0 and start + length <= self._len:
            after = start + length
            m = _WS_RUN.match(data, after)
            after = m.end() if m else after
            if data.startswith(b"endstream", after):
                self.pos = after + 9
                return PdfStream(d, data[start : start + length], num)
        end = data.find(b"endstream", start)
        if end < 0:
            end = data.find(b"endobj", start)
            end = self._len if end < 0 else end
            self.pos = end
        else:
            self.pos = end + 9
        raw = data[start:end]
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n") or raw.endswith(b"\r"):
            raw = raw[:-1]
        return PdfStream(d, raw, num)

    def _parse_name(self) -> PdfName:
        self.pos += 1
        m = _WORD.match(self._data, self.pos)
        assert m is not None
        raw = m.group(0)
        self.pos = m.end()
        if b"#" in raw:
            raw = _HEX_ESC.sub(lambda mm: bytes((int(mm.group(1), 16),)), raw)
        return PdfName(raw.decode("latin-1"))

    def _parse_literal(self) -> PdfString:
        data = self._data
        n = self._len
        self.pos += 1
        depth = 1
        out = bytearray()
        while self.pos < n:
            m = _LIT_PLAIN.match(data, self.pos)
            assert m is not None
            out += m.group(0)
            self.pos = m.end()
            if self.pos >= n:
                break
            c = data[self.pos]
            self.pos += 1
            if c == 0x28:
                depth += 1
                out += b"("
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    return PdfString(bytes(out))
                out += b")"
            elif c == 0x0D:
                if self.pos < n and data[self.pos] == 0x0A:
                    self.pos += 1
                out += b"\n"
            else:
                out += self._escape()
        return PdfString(bytes(out))

    def _escape(self) -> bytes:
        data = self._data
        if self.pos >= self._len:
            self.pos += 1
            return b""
        e = data[self.pos]
        self.pos += 1
        simple = _SIMPLE_ESC.get(e)
        if simple is not None:
            return simple
        if e == 0x0D:
            if self.pos < self._len and data[self.pos] == 0x0A:
                self.pos += 1
            return b""
        if e == 0x0A:
            return b""
        if 0x30 <= e <= 0x37:
            v = e - 0x30
            for _ in range(2):
                if self.pos >= self._len:
                    break
                dch = data[self.pos]
                if dch < 0x30 or dch > 0x37:
                    break
                v = v * 8 + (dch - 0x30)
                self.pos += 1
            return bytes((v & 0xFF,))
        return bytes((e,))

    def _parse_hex(self) -> PdfString:
        self.pos += 1
        end = self._data.find(b">", self.pos)
        end = self._len if end < 0 else end
        h = _NOT_HEX.sub(b"", self._data[self.pos : end])
        self.pos = min(self._len, end + 1)
        if len(h) % 2 == 1:
            h += b"0"
        return PdfString(bytes.fromhex(h.decode("ascii")), True)

    def _parse_word(self) -> Any:
        m = _WORD.match(self._data, self.pos)
        assert m is not None
        word = m.group(0)
        if not word:
            self.pos += 1
            return Keyword(chr(self._data[self.pos - 1]))
        self.pos = m.end()
        c = word[0]
        if 0x30 <= c <= 0x39 or c in b"+-.":
            num = number(word)
            if num is None:
                return Keyword(word.decode("latin-1"))
            if type(num) is int and num >= 0 and self._refs:
                return self._maybe_ref(num)
            return num
        if word == b"true":
            return True
        if word == b"false":
            return False
        if word == b"null":
            return None
        return Keyword(word.decode("latin-1"))

    def _maybe_ref(self, num: int) -> int | PdfRef:
        save = self.pos
        data = self._data
        self.skip_whitespace()
        m = _DIGITS.match(data, self.pos)
        assert m is not None
        n = m.end() - self.pos
        if 0 < n <= 10:
            gen = int(data[self.pos : m.end()])
            after = m.end()
            w = _WS_RUN.match(data, after)
            assert w is not None
            if w.end() > after:
                p = w.end()
                if p < self._len and data[p] == 0x52:
                    nxt = data[p + 1] if p + 1 < self._len else 0x20
                    if nxt in DELIM_OR_WS:
                        self.pos = p + 1
                        return PdfRef(num, gen)
        self.pos = save
        return num
