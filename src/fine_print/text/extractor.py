"""The text subset of the content-stream interpreter, as PHP's
``FinePrint\\Text\\TextExtractor``.

It tracks what text extraction needs (CTM, text and line matrices, text state,
fill colour) and emits one run per shown string. It interprets; nothing in a
content stream executes, and unknown operators are skipped.
"""

from __future__ import annotations

import math
from array import array
from typing import TYPE_CHECKING, Any

from .._php import int_cast, is_num, pmax as _pmax, pmin as _pmin
from ..exceptions import PdfSyntaxError, RefusedException
from ..objects import Keyword, PdfDict, PdfName, PdfRef, PdfStream, PdfString
from ..parser import Parser
from .font import Font

if TYPE_CHECKING:
    from ..document import Document

#: Accounted bytes (D7) for one run and one word piece, modelled on PHP's own
#: (a six-key array plus its strings; a 40-byte packed record).
RUN_COST = 400
PIECE_COST = 48

_WS_CHARS = " \t\n\r\x0c\x0b"


def mul(a: list[float], b: list[float]) -> list[float]:
    """a x b for PDF's affine matrices [a b c d e f]."""
    return [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
    ]


def _arg(o: list[Any], i: int, default: Any) -> Any:
    """PHP's ``$o[$i] ?? $default``: missing OR null takes the default."""
    v = o[i] if i < len(o) else None
    return default if v is None else v


def _num(v: Any) -> float:
    return float(v) if is_num(v) else 0.0


def _nums(o: list[Any], n: int) -> list[float]:
    o = o[-n:] if n > 0 else []
    out = [_num(v) for v in o]
    return out + [0.0] * (n - len(out))


def _cmyk(c: list[float]) -> list[float]:
    c = c + [0.0] * (4 - len(c))
    cy, m, y, k = c[0], c[1], c[2], c[3]
    return [(1 - cy) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k)]


def _colour(o: list[Any]) -> list[float]:
    n = [float(v) for v in o if is_num(v)]
    if len(n) in (1, 3):
        return n
    if len(n) == 4:
        return _cmyk(n)
    return [0.0]


def _is_white(c: list[float]) -> bool:
    if not c:
        return False
    return all(not (v < 0.95) for v in c)


def _initial_state() -> dict[str, Any]:
    return {
        "ctm": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        "font": None,
        "size": 0.0,
        "tc": 0.0,
        "tw": 0.0,
        "th": 1.0,
        "tl": 0.0,
        "ts": 0.0,
        "tr": 0,
        "fill": [0.0],
        "stroke": [0.0],
    }


class TextExtractor:
    def __init__(self, doc: Document, crop_box: list[float], rotate: int = 0, words: bool = False) -> None:
        self._doc = doc
        self._crop = crop_box
        self._rotate = rotate
        self._words = words
        self._fonts: dict[Any, Font] = {}
        self._runs: list[dict[str, Any]] = []
        self._gs = _initial_state()
        self._stack: list[dict[str, Any]] = []
        self._tm: list[float] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
        self._tlm: list[float] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
        self._path: list[float] | None = None
        self._regions: list[tuple[float, float, float, float, bool]] = []
        self._budget = doc.budget()
        self._operators = 0
        self._forms: list[str] = []
        #: run index -> packed records (start, end, x0, x1, top, bottom), as doubles
        self._pieces: dict[int, array[float]] = {}

    def pieces(self) -> dict[int, array[float]]:
        return self._pieces

    def extract(self, content: bytes, resources: PdfDict | None) -> list[dict[str, Any]]:
        self._runs = []
        self._pieces = {}
        self._interpret(content, resources, 0)
        return self._runs

    def _interpret(self, content: bytes, resources: PdfDict | None, depth: int) -> None:
        p = Parser(content, refs=False, budget=self._budget)
        ops: list[Any] = []
        cap = self._budget.limits.max_operators
        while True:
            try:
                if p.at_end():
                    break
                v = p.parse_value()
            except PdfSyntaxError:
                if p.at_end():
                    break
                ops = []
                continue
            if not isinstance(v, Keyword):
                ops.append(v)
                continue
            self._operators += 1
            if self._operators > cap:
                raise RefusedException("too_many_operators", f"A page has more than {cap} content-stream operators.")
            self._op(v.word, ops, p, resources, depth)
            ops = []

    def _op(self, op: str, o: list[Any], p: Parser, resources: PdfDict | None, depth: int) -> None:
        gs = self._gs
        first = o[0] if o else None
        if op == "q":
            self._stack.append(dict(gs))
        elif op == "Q":
            if self._stack:
                self._gs = self._stack.pop()
        elif op == "cm":
            if len(o) >= 6:
                gs["ctm"] = mul(_nums(o, 6), gs["ctm"])
        elif op == "BT":
            self._tm = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            self._tlm = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
        elif op == "Tf":
            if len(o) >= 2 and isinstance(o[0], PdfName):
                gs["font"] = self._font(o[0].value, resources)
                gs["size"] = _num(o[1])
        elif op == "Tc":
            gs["tc"] = _num(_arg(o, 0, 0))
        elif op == "Tw":
            gs["tw"] = _num(_arg(o, 0, 0))
        elif op == "Tz":
            gs["th"] = _num(_arg(o, 0, 100)) / 100
        elif op == "TL":
            gs["tl"] = _num(_arg(o, 0, 0))
        elif op == "Ts":
            gs["ts"] = _num(_arg(o, 0, 0))
        elif op == "Tr":
            gs["tr"] = int_cast(_num(_arg(o, 0, 0)))
        elif op == "Td":
            self._move_line(_num(_arg(o, 0, 0)), _num(_arg(o, 1, 0)))
        elif op == "TD":
            gs["tl"] = -_num(_arg(o, 1, 0))
            self._move_line(_num(_arg(o, 0, 0)), _num(_arg(o, 1, 0)))
        elif op == "Tm":
            if len(o) >= 6:
                self._tm = _nums(o, 6)
                self._tlm = list(self._tm)
        elif op == "T*":
            self._move_line(0.0, -gs["tl"])
        elif op == "Tj":
            self._show(first)
        elif op == "'":
            self._move_line(0.0, -gs["tl"])
            self._show(first)
        elif op == '"':
            gs["tw"] = _num(_arg(o, 0, 0))
            gs["tc"] = _num(_arg(o, 1, 0))
            self._move_line(0.0, -gs["tl"])
            self._show(o[2] if len(o) > 2 else None)
        elif op == "TJ":
            for item in first if isinstance(first, list) else []:
                if isinstance(item, PdfString):
                    self._show(item)
                elif is_num(item):
                    g = self._gs
                    tx = -item / 1000 * g["size"] * g["th"]
                    self._tm = mul([1, 0, 0, 1, tx, 0], self._tm)
        elif op == "g":
            gs["fill"] = _nums(o, 1)
        elif op == "G":
            gs["stroke"] = _nums(o, 1)
        elif op == "rg":
            gs["fill"] = _nums(o, 3)
        elif op == "RG":
            gs["stroke"] = _nums(o, 3)
        elif op == "k":
            gs["fill"] = _cmyk(_nums(o, 4))
        elif op == "K":
            gs["stroke"] = _cmyk(_nums(o, 4))
        elif op in ("sc", "scn"):
            gs["fill"] = _colour(o)
        elif op in ("SC", "SCN"):
            gs["stroke"] = _colour(o)
        elif op == "cs":
            gs["fill"] = [0.0]
        elif op == "CS":
            gs["stroke"] = [0.0]
        elif op == "Do":
            if isinstance(first, PdfName):
                self._xobject(first.value, resources, depth)
        elif op == "BI":
            _skip_inline_image(p)
        elif op == "re":
            if len(o) >= 4:
                x, y, w, h = _nums(o, 4)
                for px, py in ((x, y), (x + w, y), (x, y + h), (x + w, y + h)):
                    self._path_point(px, py)
        elif op in ("m", "l"):
            n = _nums(o, 2)
            self._path_point(n[0], n[1])
        elif op in ("c", "v", "y"):
            n = _nums(o, 6 if op == "c" else 4)
            for i in range(0, len(n) - 1, 2):
                self._path_point(n[i], n[i + 1])
        elif op in ("f", "F", "f*", "B", "B*", "b", "b*"):
            if self._path is not None:
                x0, y0, x1, y1 = self._path
                self._regions.append((x0, y0, x1, y1, _is_white(self._gs["fill"])))
            self._path = None
        elif op in ("S", "s", "n"):
            self._path = None

    def _path_point(self, x: float, y: float) -> None:
        c = self._gs["ctm"]
        dx = x * c[0] + y * c[2] + c[4]
        dy = x * c[1] + y * c[3] + c[5]
        if self._path is None:
            self._path = [dx, dy, dx, dy]
        else:
            pa = self._path
            self._path = [_pmin(pa[0], dx), _pmin(pa[1], dy), _pmax(pa[2], dx), _pmax(pa[3], dy)]

    def _hidden_because(self, x0: float, y: float, x1: float, size: float) -> list[str]:
        flags: list[str] = []
        tr = self._gs["tr"]
        if tr in (3, 7):
            flags.append("invisible")
        else:
            paint = self._gs["stroke"] if tr in (1, 5) else self._gs["fill"]
            if _is_white(paint) and not self._on_painted_ground((x0 + x1) / 2, y):
                flags.append("white")
        if size < 1.0:
            flags.append("tiny")
        bx0, by0, bx1, by1 = self._crop[0], self._crop[1], self._crop[2], self._crop[3]
        if y < by0 - 1 or y > by1 + 1 or _pmax(x0, x1) < bx0 - 1 or _pmin(x0, x1) > bx1 + 1:
            flags.append("off-page")
        return flags

    def _on_painted_ground(self, x: float, y: float) -> bool:
        # Ticked by the regions inspected: PHP does not tick here, so a page of a
        # million fills and a million white strings is quadratic and unbounded
        # there. Reported as a PHP finding; bounded here by the time budget.
        self._budget.tick(len(self._regions))
        for x0, y0, x1, y1, white in self._regions:
            if not white and x0 <= x <= x1 and y0 <= y <= y1:
                return True
        return False

    def _move_line(self, tx: float, ty: float) -> None:
        self._tlm = mul([1, 0, 0, 1, tx, ty], self._tlm)
        self._tm = self._tlm

    def _show(self, s: Any) -> None:
        g = self._gs
        font = g["font"]
        if not isinstance(s, PdfString) or not isinstance(font, Font):
            return
        size = g["size"]
        th = g["th"]
        tc = g["tc"]
        tw = g["tw"]
        start = self._render_matrix_at(self._tm)
        parts: list[str] = []
        length = 0
        run = len(self._runs)
        words = self._words
        p_start = -1
        p_end = 0
        p_tm = last_tm = self._tm
        last_w = 0.0
        cost = font.code_cost()
        tick = self._budget.tick
        tm = self._tm
        for u, w, is_space in font.decode(s.bytes):
            tick(cost)
            if words:
                if u != "" and all(ch in _WS_CHARS for ch in u):
                    if p_start >= 0:
                        self._piece(run, font, p_start, p_end, p_tm, last_tm, last_w)
                        p_start = -1
                else:
                    if p_start < 0:
                        p_start = length
                        p_tm = tm
                    last_tm = tm
                    last_w = w
                    p_end = length + len(u)
            parts.append(u)
            length += len(u)
            tx = (w / 1000 * size + tc + (tw if is_space else 0)) * th
            tm = [
                tm[0] + 0 * tm[2],
                tm[1] + 0 * tm[3],
                0 * tm[0] + tm[2],
                0 * tm[1] + tm[3],
                tx * tm[0] + 0 * tm[2] + tm[4],
                tx * tm[1] + 0 * tm[3] + tm[5],
            ]
        self._tm = tm
        if p_start >= 0:
            self._piece(run, font, p_start, p_end, p_tm, last_tm, last_w)
        text = "".join(parts)
        end = self._render_matrix_at(self._tm)
        height = math.hypot(start[2], start[3])
        self._budget.hold(RUN_COST + len(text))
        self._runs.append(
            {
                "text": text,
                "x0": start[4],
                "y": start[5],
                "x1": end[4],
                "size": height,
                "flags": self._hidden_because(start[4], start[5], end[4], height),
            }
        )

    def _render_matrix_at(self, tm: list[float]) -> list[float]:
        g = self._gs
        return mul([g["size"] * g["th"], 0, 0, g["size"], 0, g["ts"]], mul(tm, g["ctm"]))

    def _piece(self, run: int, font: Font, start: int, end: int, first_tm: list[float], last_tm: list[float], last_w: float) -> None:
        a = font.ascent() / 1000
        d = font.descent() / 1000
        w = last_w / 1000
        m0 = self._render_matrix_at(first_tm)
        m1 = self._render_matrix_at(last_tm)
        x0 = y0 = math.inf
        x1 = y1 = -math.inf
        for m, u, v in ((m0, 0.0, d), (m0, 0.0, a), (m1, w, d), (m1, w, a)):
            px, py = self._to_page(u * m[0] + v * m[2] + m[4], u * m[1] + v * m[3] + m[5])
            if not math.isfinite(px) or not math.isfinite(py):
                return
            x0 = min(x0, px)
            x1 = max(x1, px)
            y0 = min(y0, py)
            y1 = max(y1, py)
        rec = self._pieces.get(run)
        if rec is None:
            rec = self._pieces[run] = array("d")
        rec.extend((float(start), float(end), x0, x1, y0, y1))
        self._budget.hold(PIECE_COST)

    def _to_page(self, x: float, y: float) -> tuple[float, float]:
        bx0, by0, bx1, by1 = self._crop[0], self._crop[1], self._crop[2], self._crop[3]
        r = self._rotate
        if r == 90:
            return y - by0, x - bx0
        if r == 180:
            return bx1 - x, y - by0
        if r == 270:
            return by1 - y, bx1 - x
        return x - bx0, by1 - y

    def _font(self, name: str, resources: PdfDict | None) -> Font | None:
        fonts = self._doc.resolve(resources.get("Font")) if resources is not None else None
        if not isinstance(fonts, PdfDict):
            return None
        ref = fonts.get(name)
        d = self._doc.resolve(ref)
        if not isinstance(d, PdfDict):
            return None
        key: Any = ref.key() if isinstance(ref, PdfRef) else ("d", id(d))
        f = self._fonts.get(key)
        if f is None:
            f = self._fonts[key] = Font.from_dict(d, self._doc)
        return f

    def _xobject(self, name: str, resources: PdfDict | None, depth: int) -> None:
        doc = self._doc
        xobjects = doc.resolve(resources.get("XObject")) if resources is not None else None
        if not isinstance(xobjects, PdfDict):
            return
        ref = xobjects.get(name)
        x = doc.resolve(ref)
        if isinstance(x, PdfStream) and x.dict.name("Subtype") == "Image":
            saved = self._path
            self._path = None
            for ux, uy in ((0, 0), (1, 0), (0, 1), (1, 1)):
                self._path_point(ux, uy)
            assert self._path is not None
            x0, y0, x1, y1 = self._path
            self._regions.append((x0, y0, x1, y1, False))
            self._path = saved
            return
        if not isinstance(x, PdfStream) or x.dict.name("Subtype") != "Form":
            return
        key = ref.key() if isinstance(ref, PdfRef) else f"d{id(x)}"
        if key in self._forms:
            doc.warn(f"form XObject {key} draws itself; the inner draw was skipped")
            return
        cap = self._budget.limits.max_form_depth
        if len(self._forms) >= cap:
            doc.warn(f"form XObjects nest deeper than {cap}; the rest were skipped")
            return
        content = doc.stream_data(x)
        if content is None:
            return
        form_res = doc.resolve(x.dict.get("Resources"))
        saved = (self._gs, self._stack, self._tm, self._tlm)
        self._gs = dict(self._gs)
        matrix = doc.resolve(x.dict.get("Matrix"))
        if isinstance(matrix, list) and len(matrix) >= 6:
            self._gs["ctm"] = mul(_nums([doc.resolve(v) for v in matrix], 6), self._gs["ctm"])
        self._stack = []
        self._forms.append(key)
        try:
            self._interpret(content, form_res if isinstance(form_res, PdfDict) else resources, depth + 1)
        finally:
            self._forms.pop()
            self._gs, self._stack, self._tm, self._tlm = saved


def _skip_inline_image(p: Parser) -> None:
    """``BI <pairs> ID <binary> EI``: skip to an ``EI`` between whitespace."""
    while True:
        try:
            v = p.parse_value()
        except PdfSyntaxError:
            return
        if isinstance(v, Keyword) and v.word == "ID":
            break
        if p.at_end():
            return
    data = p.data()
    pos = p.position() + 1
    n = len(data)
    ws = b" \t\r\n\x0c\x00"
    after_ok = b" \t\r\n\x0c\x00/[<("
    while True:
        i = data.find(b"EI", pos)
        if i < 0:
            break
        before = data[i - 1] if i - 1 >= 0 else 0x20
        after = data[i + 2] if i + 2 < n else 0x20
        if before in ws and (i + 2 >= n or after in after_ok):
            p.seek(i + 2)
            return
        pos = i + 2
    p.seek(n)
