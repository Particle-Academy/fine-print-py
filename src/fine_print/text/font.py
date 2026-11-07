"""Show-string bytes to text and advance widths, as PHP's ``FinePrint\\Text\\Font``.

Authority, per ISO 32000-1 9.10.2: the ToUnicode CMap, then the font's encoding
(base encoding plus ``/Differences``), then, for printable ASCII in a simple
font only, the byte itself. Anything else is U+FFFD, visible as unreadable.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from .._php import is_int, is_num, utf16
from ..objects import PdfDict, PdfName, PdfStream
from .cmap import CMap
from .encodings import encoding_map, glyph

if TYPE_CHECKING:
    from ..document import Document

DEFAULT_ASCENT = 800.0
DEFAULT_DESCENT = -200.0

#: ``StandardMetrics::VERTICAL`` (AFM ascent, descent) for the faces
#: ``StandardFonts::match`` can name; every Courier shares one entry.
_VERTICAL = {
    "Helvetica": (718, -207),
    "Helvetica-Bold": (718, -207),
    "Times-Roman": (683, -217),
    "Times-Bold": (683, -217),
    "Times-Italic": (683, -217),
    "Times-BoldItalic": (683, -217),
    "Courier": (629, -157),
}

_SUBSET = re.compile(r"^[A-Z]{6}\+")
_STYLE = re.compile(r"^(?:bold|italic|oblique|roman|regular|ps|mt)*$")
_UCS2 = re.compile(r"^Uni.*-(UCS2|UTF16)-[HV]$")


def standard_face(base_font: str) -> str | None:
    """``StandardFonts::match()``: the standard-14 text face a BaseFont names."""
    n = _SUBSET.sub("", base_font, count=1)
    n = "".join(ch.lower() if "A" <= ch <= "Z" else ch for ch in n)
    for sep in (" ", "-", ",", "_"):
        n = n.replace(sep, "")
    for prefix, family in (
        ("timesnewroman", "serif"),
        ("times", "serif"),
        ("couriernew", "mono"),
        ("courier", "mono"),
        ("helvetica", "sans"),
        ("arial", "sans"),
    ):
        if not n.startswith(prefix):
            continue
        style = n[len(prefix) :]
        if not _STYLE.match(style):
            return None
        bold = "bold" in style
        italic = "italic" in style or "oblique" in style
        if family == "sans":
            return "Helvetica" + (("-" + ("Bold" if bold else "") + ("Oblique" if italic else "")) if bold or italic else "")
        if family == "mono":
            return "Courier" + (("-" + ("Bold" if bold else "") + ("Oblique" if italic else "")) if bold or italic else "")
        return "Times-" + ((("Bold" if bold else "") + ("Italic" if italic else "")) if bold or italic else "Roman")
    return None


def _vertical(face: str) -> tuple[int, int]:
    if face.startswith("Courier"):
        return _VERTICAL["Courier"]
    table = {"Helvetica-Oblique": "Helvetica", "Helvetica-BoldOblique": "Helvetica-Bold"}.get(face, face)
    return _VERTICAL[table]


def _code_int(b: bytes) -> int:
    return int.from_bytes(b[:7], "big") if b else 0


class Font:
    def __init__(self) -> None:
        self._composite = False
        self._to_unicode: CMap | None = None
        self._encoding_cmap: CMap | None = None
        self._ucs2 = False
        self._encoding: dict[int, str] = {}
        self._widths: dict[int, float] = {}
        self._default_width = 500.0
        self._width_scale = 1.0
        self._has_encoding = False
        self._ascent: float | None = None
        self._descent: float | None = None

    @staticmethod
    def from_dict(d: PdfDict, doc: Document) -> Font:
        f = Font()
        subtype = d.name("Subtype")
        tu = doc.resolve(d.get("ToUnicode"))
        if isinstance(tu, PdfStream):
            f._to_unicode = CMap(doc.stream_data(tu) or b"")
        if subtype == "Type0":
            f._composite = True
            f._load_composite(d, doc)
        else:
            f._load_simple(d, doc, subtype)
        f._load_vertical(d, doc)
        return f

    def ascent(self) -> float:
        return (self._ascent if self._ascent is not None else DEFAULT_ASCENT) * self._width_scale

    def descent(self) -> float:
        return (self._descent if self._descent is not None else DEFAULT_DESCENT) * self._width_scale

    def _load_vertical(self, d: PdfDict, doc: Document) -> None:
        holder: PdfDict | None = d
        if self._composite:
            desc = doc.resolve(d.get("DescendantFonts"))
            first = doc.resolve(desc[0] if desc else None) if isinstance(desc, list) else None
            holder = first if isinstance(first, PdfDict) else None
        fd = doc.resolve(holder.get("FontDescriptor")) if holder is not None else None
        if isinstance(fd, PdfDict):
            a = doc.resolve(fd.get("Ascent"))
            de = doc.resolve(fd.get("Descent"))
            if is_num(a) and 0 < a <= 2000:
                self._ascent = float(a)
            if is_num(de) and -1000 <= de <= 0:
                self._descent = float(de)
        if self._ascent is None or self._descent is None:
            face = standard_face(d.name("BaseFont") or "")
            if face is not None:
                va, vd = _vertical(face)
                if self._ascent is None:
                    self._ascent = float(va)
                if self._descent is None:
                    self._descent = float(vd)

    def decode(self, data: bytes) -> Iterator[tuple[str, float, bool]]:
        """The codes of a show string as (text, width in 1/1000 text space, is
        single-byte code 32), ONE AT A TIME: a generator, never a list."""
        tu = self._to_unicode
        scale = self._width_scale
        widths = self._widths
        dw = self._default_width
        if self._composite:
            for code in self.codes(data):
                if code == b"":
                    continue
                cid = _code_int(code)
                u = tu.lookup(code) if tu is not None else None
                if u is None:
                    u = utf16(code) if self._ucs2 else "�"
                yield u, widths.get(cid, dw) * scale, False
            return
        enc = self._encoding
        for c in data:
            u = tu.lookup(bytes((c,))) if tu is not None else None
            if u is None:
                u = enc.get(c)
                if u is None:
                    u = chr(c) if 0x20 <= c < 0x7F else "�"
            yield u, widths.get(c, dw) * scale, c == 32

    def code_cost(self) -> int:
        return 1 + (self._to_unicode.range_count() if self._to_unicode is not None else 0) // 64

    def composite(self) -> bool:
        return self._composite

    def codes(self, data: bytes) -> Iterator[bytes]:
        n = len(data)
        if not self._composite:
            for i in range(n):
                yield data[i : i + 1]
            return
        cmap = self._encoding_cmap if self._encoding_cmap is not None else self._to_unicode
        if cmap is not None and cmap.has_codespace():
            yield from cmap.each(data, 2)
            return
        for i in range(0, n, 2):
            yield data[i : i + 2]

    def _load_composite(self, d: PdfDict, doc: Document) -> None:
        enc = doc.resolve(d.get("Encoding"))
        if isinstance(enc, PdfName):
            self._ucs2 = _UCS2.match(enc.value) is not None
        elif isinstance(enc, PdfStream):
            self._encoding_cmap = CMap(doc.stream_data(enc) or b"")
        descendants = doc.resolve(d.get("DescendantFonts"))
        desc = doc.resolve(descendants[0] if descendants else None) if isinstance(descendants, list) else None
        self._default_width = 1000.0
        if not isinstance(desc, PdfDict):
            return
        dw = doc.resolve(desc.get("DW"))
        if is_num(dw):
            self._default_width = float(dw)
        w = doc.resolve(desc.get("W"))
        if not isinstance(w, list):
            return
        n = len(w)
        budget = 200_000
        i = 0
        while i < n and budget > 0:
            first = doc.resolve(w[i])
            second = doc.resolve(w[i + 1] if i + 1 < n else None)
            if not is_int(first):
                i += 1
                continue
            if isinstance(second, list):
                for k, width in enumerate(second):
                    width = doc.resolve(width)
                    if is_num(width):
                        self._widths[first + k] = float(width)
                    budget -= 1
                i += 2
            else:
                width = doc.resolve(w[i + 2] if i + 2 < n else None)
                if is_int(second) and is_num(width):
                    last = min(second, first + budget)
                    for c in range(first, last + 1):
                        self._widths[c] = float(width)
                    budget -= max(0, last - first + 1)
                i += 3

    def _load_simple(self, d: PdfDict, doc: Document, subtype: str | None) -> None:
        base = d.name("BaseFont") or ""
        symbolic = base in ("Symbol", "ZapfDingbats")
        if _SUBSET.sub("", base, count=1).startswith("Courier"):
            self._default_width = 600.0
        first = doc.resolve(d.get("FirstChar"))
        widths = doc.resolve(d.get("Widths"))
        if is_int(first) and isinstance(widths, list):
            for k, w in enumerate(widths[:256]):
                w = doc.resolve(w)
                if is_num(w):
                    self._widths[first + k] = float(w)
        fd = doc.resolve(d.get("FontDescriptor"))
        if isinstance(fd, PdfDict):
            mw = doc.resolve(fd.get("MissingWidth"))
            if is_num(mw) and mw > 0:
                self._default_width = float(mw)
        if subtype == "Type3":
            matrix = doc.resolve(d.get("FontMatrix"))
            a = doc.resolve(matrix[0] if matrix else None) if isinstance(matrix, list) else None
            self._width_scale = float(a) * 1000 if is_num(a) else 1.0
        enc = doc.resolve(d.get("Encoding"))
        base_name: str | None = None if symbolic else ("WinAnsiEncoding" if subtype == "TrueType" else "StandardEncoding")
        differences: Any = None
        self._has_encoding = isinstance(enc, (PdfName, PdfDict))
        if isinstance(enc, PdfName):
            base_name = enc.value
        elif isinstance(enc, PdfDict):
            named = enc.name("BaseEncoding")
            base_name = named if named is not None else base_name
            differences = doc.resolve(enc.get("Differences"))
        m = encoding_map(base_name) if base_name is not None else None
        self._encoding = dict(m) if m is not None else {}
        if isinstance(differences, list):
            code = 0
            for item in differences:
                item = doc.resolve(item)
                if is_int(item):
                    code = item
                elif isinstance(item, PdfName):
                    if 0 <= code <= 255:
                        g = glyph(item.value)
                        if g is not None:
                            self._encoding[code] = g
                        else:
                            self._encoding.pop(code, None)
                    code += 1
