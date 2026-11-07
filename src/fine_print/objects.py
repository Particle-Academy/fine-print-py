"""PDF object types, as PHP's ``FinePrint\\Objects``.

Names and keywords are ``str`` decoded as Latin-1, so every byte survives and
comparisons against ASCII constants work; :func:`name_text` turns one into
text for a report. Strings stay ``bytes``.
"""

from __future__ import annotations

from typing import Any

from ._php import scrub


class PdfName:
    """A name WITHOUT the slash, every ``#xx`` already decoded."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f"PdfName({self.value!r})"


class PdfString:
    """Raw bytes, escapes decoded."""

    __slots__ = ("bytes", "hex")

    def __init__(self, data: bytes, hex: bool = False) -> None:
        self.bytes = data
        self.hex = hex

    def __repr__(self) -> str:
        return f"PdfString({self.bytes!r})"


class PdfRef:
    __slots__ = ("num", "gen")

    def __init__(self, num: int, gen: int) -> None:
        self.num = num
        self.gen = gen

    def key(self) -> str:
        return f"{self.num} {self.gen}"

    def __repr__(self) -> str:
        return f"PdfRef({self.num}, {self.gen})"


class PdfDict:
    __slots__ = ("entries",)

    def __init__(self, entries: dict[str, Any] | None = None) -> None:
        self.entries: dict[str, Any] = entries if entries is not None else {}

    def get(self, key: str) -> Any:
        return self.entries.get(key)

    def has(self, key: str) -> bool:
        return key in self.entries

    def name(self, key: str) -> str | None:
        v = self.entries.get(key)
        return v.value if isinstance(v, PdfName) else None

    def keys(self) -> list[str]:
        return list(self.entries.keys())

    def __repr__(self) -> str:
        return f"PdfDict({self.entries!r})"


class PdfStream:
    """A dictionary and its still-ENCODED bytes."""

    __slots__ = ("dict", "raw", "object_number")

    def __init__(self, d: PdfDict, raw: bytes, object_number: int | None = None) -> None:
        self.dict = d
        self.raw = raw
        self.object_number = object_number


class Keyword:
    """A bare word that is not a value: ``obj``, ``stream``, an operator."""

    __slots__ = ("word",)

    def __init__(self, word: str) -> None:
        self.word = word

    def __repr__(self) -> str:
        return f"Keyword({self.word!r})"


def name_text(s: str) -> str:
    """A Latin-1 name or key as report text: its bytes read as UTF-8, scrubbed."""
    return scrub(s.encode("latin-1"))
