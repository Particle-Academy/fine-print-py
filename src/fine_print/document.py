"""A parsed PDF: the HOST's raw view, as PHP's ``FinePrint\\Document``.

Nothing here is filtered for an agent: text, metadata and annotations come back
as the file wrote them, invisible characters and hidden text included. Give an
agent :func:`fine_print.read` instead, which runs every string through the
agent-read guard.

Objects load lazily; opening reads the cross-reference data and trailer only.
"""

from __future__ import annotations

import re
from typing import Any

from ._php import int_cast, int_string, is_int, is_num, scrub, var_export_float, wrap64
from .exceptions import OpaqueStream, PdfSyntaxError, RefusedException
from .filters import decode_chain
from .limits import Budget, Limits
from .objects import PdfDict, PdfName, PdfRef, PdfStream, PdfString, name_text
from .parser import Parser
from .security.active import ActiveContentScanner
from .security.standard import StandardSecurity
from .text import layout as _layout
from .text import textstring
from .text import words as _words
from .text.extractor import TextExtractor

#: Accounted bytes (D7) for one cached object, beyond a stream's own bytes.
OBJECT_COST = 200

_VERSION = re.compile(rb"%PDF-(\d\.\d)")
_SCAN = re.compile(rb"(?<![0-9])(\d{1,10})[\x00\t\n\x0c\r ]+(\d{1,5})[\x00\t\n\x0c\r ]+obj\b")
_TRAILER = re.compile(rb"trailer[\x00\t\n\x0c\r ]*<<")
_STARTXREF = re.compile(rb"startxref\s+(\d+)")
_SUBSECTION = re.compile(rb"\s*(\d+)\s+(\d+)[ \t]*[\r\n]+")
_ENTRY = re.compile(rb"\s*(\d{1,10})\s+(\d{1,5})\s+([nf])")


def _intval(v: Any) -> int:
    """PHP ``(int)`` of an operand of unknown type."""
    if v is None or v is False:
        return 0
    if v is True:
        return 1
    if type(v) is int:
        return v
    if type(v) is float:
        return int_cast(v)
    return 1  # an object: PHP warns and gives 1


class Document:
    def __init__(self, data: bytes, limits: Limits) -> None:
        self._data = data
        self._version = "1.4"
        self._base = 0
        self._xref: dict[int, dict[str, int]] = {}
        self._trailer = PdfDict()
        self._cache: dict[int, Any] = {}
        self._obj_streams: dict[int, dict[str, Any]] = {}
        self._repaired = False
        self._pages: list[dict[str, Any]] | None = None
        self._budget = Budget(limits)
        self._loading: set[int] = set()
        self._scanned: dict[int, int] | None = None
        self._warnings: list[str] = []
        self._security: StandardSecurity | None = None
        self._encrypt_num: int | None = None
        self._cache_bytes = 0
        self._parser = Parser(data, True, self.resolve, self._budget)

    # ------------------------------------------------------------------ open

    @staticmethod
    def open(data: bytes, limits: Limits | None = None) -> Document:
        """Open a PDF from its bytes; :class:`RefusedException` when it is not a
        PDF, needs a password, is damaged beyond repair, or breaches a limit."""
        limits = limits if limits is not None else Limits()
        data = bytes(data)
        if len(data) > limits.max_file_bytes:
            raise RefusedException("too_large", f"The file is larger than the {limits.max_file_bytes}-byte limit.")
        doc = Document(data, limits)
        doc._load()
        return doc

    def _load(self) -> None:
        head = self._data[:1024]
        at = head.find(b"%PDF-")
        if at < 0:
            raise RefusedException("not_pdf", "There is no PDF header in the first 1024 bytes.")
        self._base = at
        m = _VERSION.search(head)
        if m is not None:
            self._version = m.group(1).decode("ascii")
        try:
            self._read_xref()
            self._secure()
            ok = isinstance(self.resolve(self._trailer.get("Root")), PdfDict)
        except PdfSyntaxError:
            ok = False
        if not ok:
            self._repair()
            self._secure()

    def _reset_cache(self, keep: dict[int, Any] | None = None) -> None:
        self._budget.release(self._cache_bytes)
        self._cache_bytes = 0
        self._cache = dict(keep) if keep else {}
        self._obj_streams = {}

    def _secure(self) -> None:
        ref = self._trailer.get("Encrypt")
        if ref is None or self._security is not None:
            return
        enc = self.resolve(ref)
        if not isinstance(enc, PdfDict):
            raise RefusedException("corrupt", "The file's encryption dictionary is missing or is not a dictionary.")
        ident = self.resolve(self._trailer.get("ID"))
        id0 = ident[0].bytes if isinstance(ident, list) and ident and isinstance(ident[0], PdfString) else b""
        self._security = StandardSecurity.open(enc, id0, self.resolve, self._budget)
        self._encrypt_num = ref.num if isinstance(ref, PdfRef) else None
        self._reset_cache({self._encrypt_num: enc} if self._encrypt_num is not None else None)

    def encryption(self) -> dict[str, Any] | None:
        """How the file was encrypted and its permission flags, or None. Never
        the key or a password. Permissions are reported, never enforced."""
        return self._security.report() if self._security is not None else None

    def _decrypt_value(self, v: Any, num: int, gen: int) -> Any:
        sec = self._security
        assert sec is not None
        if isinstance(v, PdfString):
            plain = sec.string(v.bytes, num, gen)
            if plain is None:
                self.warn("a string could not be decrypted; read as empty")
            return PdfString(plain if plain is not None else b"", v.hex)
        if isinstance(v, PdfStream):
            kind = v.dict.name("Type")
            if kind == "XRef":
                return v
            d = self._decrypt_value(v.dict, num, gen)
            raw = v.raw
            plain_meta = kind == "Metadata" and not sec.encrypt_metadata
            if not plain_meta and not self._identity_crypt(v.dict):
                dec = sec.stream(raw, num, gen)
                if dec is None:
                    self.warn("a stream could not be decrypted; read as empty")
                    dec = b""
                raw = dec
            return PdfStream(d, raw, v.object_number)
        if isinstance(v, PdfDict):
            sig = v.name("Type") == "Sig" or v.has("ByteRange")
            return PdfDict(
                {k: (c if sig and k == "Contents" else self._decrypt_value(c, num, gen)) for k, c in v.entries.items()}
            )
        if isinstance(v, list):
            return [self._decrypt_value(c, num, gen) for c in v]
        return v

    @staticmethod
    def _identity_crypt(d: PdfDict) -> bool:
        f = d.get("Filter")
        names = [f] if isinstance(f, PdfName) else (f if isinstance(f, list) else [])
        for idx, n in enumerate(names):
            if isinstance(n, PdfName) and n.value == "Crypt":
                parms = d.get("DecodeParms")
                if isinstance(parms, list):
                    # array_search($n, $names, true): the first identical object.
                    pos = next(i for i, x in enumerate(names) if x is n)
                    parms = parms[pos] if pos < len(parms) else None
                return not isinstance(parms, PdfDict) or parms.name("Name") is None or parms.name("Name") == "Identity"
        return False

    def budget(self) -> Budget:
        return self._budget

    def warn(self, message: str) -> None:
        """Record damage that was survived. Never file content."""
        if len(self._warnings) < 100 and message not in self._warnings:
            self._warnings.append(message)

    def warnings(self) -> list[str]:
        return list(self._warnings)

    # ------------------------------------------------------------------ public

    def version(self) -> str:
        return self._version

    def repaired(self) -> bool:
        return self._repaired

    def page_count(self) -> int:
        return len(self._page_list())

    def pages(self) -> list[dict[str, Any]]:
        """Geometry: ``width``/``height`` are the crop box AS DISPLAYED."""
        out = []
        for p in self._page_list():
            w = p["cropBox"][2] - p["cropBox"][0]
            h = p["cropBox"][3] - p["cropBox"][1]
            if p["rotate"] % 180 != 0:
                w, h = h, w
            out.append(
                {
                    "number": p["number"],
                    "width": w,
                    "height": h,
                    "rotate": p["rotate"],
                    "mediaBox": list(p["mediaBox"]),
                    "cropBox": list(p["cropBox"]),
                }
            )
        return out

    def page(self, page: int) -> dict[str, Any]:
        return self._page_at(page)

    def _page_at(self, page: int) -> dict[str, Any]:
        lst = self._page_list()
        if type(page) is not int or page < 1 or page > len(lst):
            raise IndexError(f"No page {page}")
        return lst[page - 1]

    def page_contents(self, page: int) -> bytes:
        return self._page_content(self._page_at(page)["dict"])

    def text(self, page: int) -> str:
        return str(self.page_text(page)["text"])

    def page_text(self, page: int) -> dict[str, Any]:
        """``{"text", "spans", "runs"}``: the page's text in reading order."""
        mark = self._budget.live
        try:
            return self._page_text(page)
        finally:
            self._budget.live = mark

    def _page_text(self, page: int) -> dict[str, Any]:
        p = self._page_at(page)
        content = self._page_content(p["dict"])
        runs = TextExtractor(self, p["cropBox"]).extract(content, p["resources"])
        composed = _layout.compose(runs)
        composed["runs"] = runs
        return composed

    def page_words(self, page: int) -> list[dict[str, Any]]:
        """``{text, x0, x1, top, bottom}`` per word, in reading order.

        Points on the DISPLAYED page: origin at the crop box's top-left after
        ``/Rotate``, ``top`` and ``bottom`` measured down (top < bottom). The
        host's raw view: hidden text included, nothing redacted."""
        out = []
        for w in self.page_text_with_words(page)["words"]:
            out.append({k: w[k] for k in ("text", "x0", "x1", "top", "bottom")})
        return out

    def page_text_with_words(self, page: int) -> dict[str, Any]:
        """:meth:`page_text` and the words from ONE interpretation; each word
        also carries ``start``/``end``, its range in ``text``."""
        mark = self._budget.live
        try:
            return self._page_text_with_words(page)
        finally:
            self._budget.live = mark

    def _page_text_with_words(self, page: int) -> dict[str, Any]:
        p = self._page_at(page)
        content = self._page_content(p["dict"])
        ex = TextExtractor(self, p["cropBox"], p["rotate"], words=True)
        runs = ex.extract(content, p["resources"])
        offsets: dict[int, int] = {}
        composed = _layout.compose(runs, offsets)
        composed["runs"] = runs
        composed["words"] = _words.assemble(ex.pieces(), offsets, composed["text"], self._budget)
        return composed

    def metadata(self) -> dict[str, str]:
        info = self.resolve(self._trailer.get("Info"))
        if not isinstance(info, PdfDict):
            return {}
        out: dict[str, str] = {}
        for key, v in info.entries.items():
            v = self.resolve(v)
            k = name_text(key)
            if isinstance(v, PdfString):
                out[k] = textstring.decode(v.bytes)
            elif isinstance(v, PdfName):
                out[k] = name_text(v.value)
            elif type(v) is bool:
                out[k] = "true" if v else "false"
            elif type(v) is int:
                out[k] = str(v)
            elif type(v) is float:
                out[k] = var_export_float(v)
        return out

    def xmp(self) -> str | None:
        m = self.resolve(self.catalog().get("Metadata"))
        if not isinstance(m, PdfStream):
            return None
        data = self.stream_data(m)
        return None if data is None else scrub(data)

    def outline(self) -> list[dict[str, Any]]:
        root = self.resolve(self.catalog().get("Outlines"))
        if not isinstance(root, PdfDict):
            return []
        return self._outline(root.get("First"))

    def annotations(self, page: int) -> list[dict[str, Any]]:
        p = self._page_at(page)
        annots = self.resolve(p["dict"].get("Annots"))
        if not isinstance(annots, list):
            return []
        out = []
        for ref in annots:
            a = self.resolve(ref)
            if not isinstance(a, PdfDict):
                continue
            contents = self.resolve(a.get("Contents"))
            author = self.resolve(a.get("T"))
            sub = a.name("Subtype")
            out.append(
                {
                    "subtype": None if sub is None else name_text(sub),
                    "object": ref.key() if isinstance(ref, PdfRef) else None,
                    "contents": textstring.decode(contents.bytes) if isinstance(contents, PdfString) else None,
                    "author": textstring.decode(author.bytes) if isinstance(author, PdfString) else None,
                }
            )
        return out

    def active_content(self) -> list[dict[str, Any]]:
        """Scripts, launch actions, forms, embedded files: reported only."""
        return ActiveContentScanner(self).scan()

    def trailer(self) -> PdfDict:
        return self._trailer

    def catalog(self) -> PdfDict:
        c = self.resolve(self._trailer.get("Root"))
        return c if isinstance(c, PdfDict) else PdfDict()

    def object_numbers(self) -> list[int]:
        return [num for num, e in self._xref.items() if e["type"] != 0]

    # ------------------------------------------------------------------ objects

    def resolve(self, v: Any) -> Any:
        """Follow references to a direct value; a missing object is None."""
        hops = 0
        seen: set[int] = set()
        while isinstance(v, PdfRef):
            hops += 1
            if v.num in seen or hops > self._budget.limits.max_depth:
                self.warn(f"reference cycle through object {v.num}; read as null")
                return None
            seen.add(v.num)
            v = self.object(v.num)
        return v

    def object(self, num: int) -> Any:
        if num in self._cache:
            return self._cache[num]
        if num in self._loading:
            self.warn(f"reference cycle while loading object {num}; read as null")
            return None
        self._loading.add(num)
        try:
            e = self._xref.get(num)
            value = None
            if e is not None and e["type"] == 1:
                value = self._load_at(e["offset"], num)
            elif e is not None and e["type"] == 2:
                value = self._load_compressed(e["stm"], num)
        finally:
            self._loading.discard(num)
        cost = OBJECT_COST + (len(value.raw) if isinstance(value, PdfStream) else 0)
        self._cache_bytes += cost
        self._budget.hold(cost)
        self._cache[num] = value
        return value

    def stream_data(self, s: PdfStream, budget: Budget | None = None) -> bytes | None:
        """A stream's decoded bytes, or None when it is image-encoded (opaque)."""
        flt = self.resolve(s.dict.get("Filter"))
        parms = self.resolve(s.dict.get("DecodeParms"))
        names: list[str] = []
        for f in [flt] if isinstance(flt, PdfName) else (flt if isinstance(flt, list) else []):
            f = self.resolve(f)
            if isinstance(f, PdfName):
                names.append(f.value)
        plist: list[PdfDict | None] = []
        for pp in [parms] if isinstance(parms, PdfDict) else (parms if isinstance(parms, list) else []):
            pp = self.resolve(pp)
            plist.append(pp if isinstance(pp, PdfDict) else None)
        try:
            return decode_chain(names, s.raw, plist, budget if budget is not None else self._budget)
        except OpaqueStream:
            return None

    def _load_at(self, offset: int, expect: int) -> Any:
        tried: list[int] = []
        for at in (offset, offset + self._base):
            if at in tried:
                continue
            tried.append(at)
            found, value = self._parse_at(at, expect)
            if found:
                return value
        scanned = self._scan_index().get(expect)
        if scanned is not None and scanned != offset:
            found, value = self._parse_at(scanned, expect)
            if found:
                self._repaired = True
                self.warn("cross-reference offsets did not match their objects; located by scanning")
                return value
        return None

    def _parse_at(self, at: int, expect: int) -> tuple[bool, Any]:
        try:
            self._parser.seek(at)
            o = self._parser.parse_indirect()
            if o["num"] == expect:
                value = o["value"]
                if self._security is not None and o["num"] != self._encrypt_num:
                    value = self._decrypt_value(value, o["num"], o["gen"])
                return True, value
        except PdfSyntaxError:
            pass
        return False, None

    def _scan_index(self) -> dict[int, int]:
        if self._scanned is not None:
            return self._scanned
        self._scanned = {}
        cap = self._budget.limits.max_objects
        count = 0
        found: dict[int, int] = {}
        for m in _SCAN.finditer(self._data):
            count += 1
            if count > cap:
                raise RefusedException("too_many_objects", f"The file holds more than {cap} objects.")
            if count & 0x3FF == 0:
                self._budget.check()
            found[int(m.group(1))] = m.start()
        self._scanned = found
        self._budget.check()
        return found

    def _repair(self) -> None:
        self._xref = {}
        self._reset_cache()
        self._trailer = PdfDict()
        index = self._scan_index()
        if not index:
            raise RefusedException("corrupt", "The file has a PDF header but no readable objects.")
        for num, offset in index.items():
            self._xref[num] = {"type": 1, "offset": offset}
        for m in reversed(list(_TRAILER.finditer(self._data))):
            try:
                self._parser.seek(m.start() + 7)
                t = self._parser.parse_value()
            except PdfSyntaxError:
                continue
            if isinstance(t, PdfDict):
                self._merge_trailer(t)
        for num in list(index.keys()):
            v = self.object(num)
            if isinstance(v, PdfStream) and v.dict.name("Type") == "XRef":
                self._merge_trailer(v.dict)
            elif isinstance(v, PdfStream) and v.dict.name("Type") == "ObjStm":
                for inner in self._object_stream_offsets(num):
                    if inner not in self._xref:
                        self._xref[inner] = {"type": 2, "stm": num, "idx": 0}
        cap = self._budget.limits.max_objects
        if len(self._xref) > cap:
            raise RefusedException("too_many_objects", f"The file holds more than {cap} objects.")
        if not isinstance(self.resolve(self._trailer.get("Root")), PdfDict):
            catalog = None
            for num in list(self._xref.keys()):
                v = self.object(num)
                if isinstance(v, PdfDict) and v.name("Type") == "Catalog":
                    catalog = num
            if catalog is None:
                raise RefusedException(
                    "corrupt", "The cross-reference data is unusable and no document catalog could be found."
                )
            self._trailer.entries["Root"] = PdfRef(catalog, 0)
        self._repaired = True
        self.warn("cross-reference data was rebuilt by scanning the file")

    def _merge_trailer(self, t: PdfDict) -> None:
        for k in ("Root", "Info", "Encrypt", "ID"):
            if t.has(k) and not self._trailer.has(k):
                self._trailer.entries[k] = t.get(k)

    def _object_stream_offsets(self, stm: int) -> dict[int, int]:
        self._load_object_stream(stm)
        os_ = self._obj_streams.get(stm)
        return os_["offsets"] if os_ is not None else {}

    def _load_object_stream(self, stm: int) -> None:
        if stm in self._obj_streams:
            return
        self._obj_streams[stm] = {"data": b"", "first": 0, "offsets": {}}
        s = self.object(stm)
        if not isinstance(s, PdfStream):
            return
        data = self.stream_data(s) or b""
        n = self.resolve(s.dict.get("N"))
        first = self.resolve(s.dict.get("First"))
        offsets: dict[int, int] = {}
        if is_int(n) and is_int(first):
            hp = Parser(data, refs=False, budget=self._budget)
            for _ in range(min(n, self._budget.limits.max_objects)):
                try:
                    on = hp.parse_value()
                    oo = hp.parse_value()
                except PdfSyntaxError:
                    break
                if is_int(on) and is_int(oo):
                    offsets[on] = first + oo
        self._cache_bytes += len(data)
        self._budget.hold(len(data))
        self._obj_streams[stm] = {"data": data, "first": first if is_int(first) else 0, "offsets": offsets}

    def _load_compressed(self, stm: int, num: int) -> Any:
        if self._xref.get(stm, {"type": 1})["type"] == 2:
            return None
        self._load_object_stream(stm)
        os_ = self._obj_streams[stm]
        if num not in os_["offsets"]:
            return None
        try:
            p = Parser(os_["data"], budget=self._budget)
            p.seek(os_["offsets"][num])
            return p.parse_value()
        except PdfSyntaxError:
            return None

    # ------------------------------------------------------------------ xref

    def _read_xref(self) -> None:
        at = self._data.rfind(b"startxref")
        m = _STARTXREF.search(self._data, at) if at >= 0 else None
        if m is None:
            raise PdfSyntaxError("No startxref")
        offset: int | None = int_string(m.group(1))
        visited: set[int] = set()
        cap = self._budget.limits.max_objects
        while offset is not None:
            if offset in visited or len(visited) >= 1000:
                self.warn("the cross-reference /Prev chain loops; stopped following it")
                break
            visited.add(offset)
            entries, trailer = self._read_section(offset)
            stm = trailer.get("XRefStm")
            if is_int(stm):
                try:
                    extra, _ = self._read_section(stm)
                    for num, e in extra.items():
                        if num not in entries or entries[num]["type"] == 0:
                            entries[num] = e
                except PdfSyntaxError:
                    pass
            for num, e in entries.items():
                if num not in self._xref:
                    self._xref[num] = e
            if len(self._xref) > cap:
                raise RefusedException("too_many_objects", f"The file lists more than {cap} objects.")
            for k, v in trailer.entries.items():
                if k not in ("Prev", "XRefStm", "Type", "W", "Index", "Filter", "DecodeParms", "Length") and not self._trailer.has(k):
                    self._trailer.entries[k] = v
            prev = trailer.get("Prev")
            offset = prev if is_int(prev) else None

    def _read_section(self, offset: int) -> tuple[dict[int, dict[str, int]], PdfDict]:
        tried: list[int] = []
        for at in (offset, offset + self._base):
            if at in tried:
                continue
            tried.append(at)
            self._parser.seek(at)
            self._parser.skip_whitespace()
            pos = self._parser.position()
            if self._data.startswith(b"xref", pos):
                return self._read_table(pos + 4)
            try:
                o = self._parser.parse_indirect()
                v = o["value"]
                if isinstance(v, PdfStream) and v.dict.name("Type") == "XRef":
                    return self._read_stream(v)
            except PdfSyntaxError:
                pass
        raise PdfSyntaxError(f"No cross-reference section at {offset}")

    def _read_table(self, pos: int) -> tuple[dict[int, dict[str, int]], PdfDict]:
        data = self._data
        entries: dict[int, dict[str, int]] = {}
        cap = self._budget.limits.max_objects
        done = False
        while not done:
            m = _SUBSECTION.match(data, pos)
            if m is None:
                break
            pos = m.end()
            start = int_string(m.group(1))
            count = int_string(m.group(2))
            if count + len(entries) > cap:
                raise RefusedException(
                    "too_many_objects", f"The cross-reference table declares more than {cap} objects."
                )
            for i in range(count):
                self._budget.tick()
                e = _ENTRY.match(data, pos)
                if e is None:
                    done = True
                    break
                pos = e.end()
                num = start + i
                if num not in entries:
                    entries[num] = {"type": 1, "offset": int(e.group(1))} if e.group(3) == b"n" else {"type": 0}
        t = data.find(b"trailer", pos)
        if t < 0:
            raise PdfSyntaxError("No trailer")
        self._parser.seek(t + 7)
        trailer = self._parser.parse_value()
        if not isinstance(trailer, PdfDict):
            raise PdfSyntaxError("Trailer is not a dictionary")
        entries.pop(0, None)
        return entries, trailer

    def _read_stream(self, s: PdfStream) -> tuple[dict[int, dict[str, int]], PdfDict]:
        data = self.stream_data(s) or b""
        w = self.resolve(s.dict.get("W"))
        if not isinstance(w, list) or len(w) < 3:
            raise PdfSyntaxError("Bad /W")
        widths = [max(0, v) if is_int(v) else 0 for v in w[:3]]
        row = widths[0] + widths[1] + widths[2]
        size = self.resolve(s.dict.get("Size"))
        index = self.resolve(s.dict.get("Index"))
        if not isinstance(index, list):
            index = [0, size if is_int(size) else 0]
        declared = 0
        for k in range(1, len(index), 2):
            declared += max(0, index[k]) if is_int(index[k]) else 0
        cap = self._budget.limits.max_objects
        if declared > cap:
            raise RefusedException("too_many_objects", f"A cross-reference stream declares more than {cap} objects.")
        entries: dict[int, dict[str, int]] = {}
        pos = 0
        n = len(data)
        for k in range(0, len(index) - 1, 2):
            start = _intval(index[k])
            count = _intval(index[k + 1])
            i = 0
            while i < count and pos + row <= n:
                # PHP does not tick here: an /Index count that is not an int
                # escapes the declared-count check, and with /W [0 0 0] the loop
                # spins. Reported as a PHP finding; bounded here by the budget.
                self._budget.tick()
                f1 = 1 if widths[0] == 0 else _be(data, pos, widths[0])
                f2 = _be(data, pos + widths[0], widths[1])
                f3 = _be(data, pos + widths[0] + widths[1], widths[2])
                pos += row
                num = start + i
                if f1 == 1:
                    entries[num] = {"type": 1, "offset": f2}
                elif f1 == 2:
                    entries[num] = {"type": 2, "stm": f2, "idx": f3}
                else:
                    entries[num] = {"type": 0}
                i += 1
        entries.pop(0, None)
        return entries, s.dict

    # ------------------------------------------------------------------ pages

    def _page_list(self) -> list[dict[str, Any]]:
        if self._pages is not None:
            return self._pages
        self._pages = []
        self._walk_pages(self.catalog().get("Pages"))
        return self._pages

    def _walk_pages(self, root: Any) -> None:
        """PHP's recursive page-tree walk, with an explicit stack (same order)."""
        assert self._pages is not None
        visited: set[Any] = set()
        inherited0 = {"MediaBox": None, "CropBox": None, "Rotate": None, "Resources": None}
        stack: list[tuple[Any, dict[str, Any], int]] = [(root, inherited0, 0)]
        lim = self._budget.limits
        while stack:
            node, inherited, depth = stack.pop()
            ref = node if isinstance(node, PdfRef) else None
            d = self.resolve(node)
            if not isinstance(d, PdfDict):
                continue
            key: Any = ref.key() if ref is not None else ("d", id(d))
            if key in visited or depth > lim.max_depth:
                shown = key if isinstance(key, str) else f"d{id(d)}"
                self.warn(f"the page tree loops back on itself at {shown}; the repeat was skipped")
                continue
            visited.add(key)
            self._budget.tick()
            inherited = dict(inherited)
            for k in list(inherited.keys()):
                if d.has(k):
                    inherited[k] = d.get(k)
            kids = self.resolve(d.get("Kids"))
            kind = d.name("Type")
            if kind == "Pages" or (kind != "Page" and isinstance(kids, list)):
                for kid in reversed(kids if isinstance(kids, list) else []):
                    stack.append((kid, inherited, depth + 1))
                continue
            if len(self._pages) >= lim.max_pages:
                raise RefusedException("too_many_pages", f"The document has more than {lim.max_pages} pages.")
            media = self._box(inherited["MediaBox"]) or [0.0, 0.0, 612.0, 792.0]
            crop = self._box(inherited["CropBox"]) or media
            rotate = self.resolve(inherited["Rotate"])
            rotate = ((rotate % 360) + 360) % 360 if is_int(rotate) else 0
            resources = self.resolve(inherited["Resources"])
            self._pages.append(
                {
                    "number": len(self._pages) + 1,
                    "dict": d,
                    "ref": ref,
                    "mediaBox": media,
                    "cropBox": crop,
                    "rotate": rotate - rotate % 90,
                    "resources": resources if isinstance(resources, PdfDict) else None,
                }
            )

    def _box(self, v: Any) -> list[float] | None:
        v = self.resolve(v)
        if not isinstance(v, list) or len(v) < 4:
            return None
        n = [float(x) if is_num(x) else 0.0 for x in (self.resolve(x) for x in v[:4])]
        lo_x = n[2] if n[2] < n[0] else n[0]
        lo_y = n[3] if n[3] < n[1] else n[1]
        hi_x = n[2] if (n[2] != n[0] and not n[2] < n[0]) else n[0]
        hi_y = n[3] if (n[3] != n[1] and not n[3] < n[1]) else n[1]
        return [lo_x, lo_y, hi_x, hi_y]

    def _page_content(self, page: PdfDict) -> bytes:
        c = self.resolve(page.get("Contents"))
        streams = [c] if isinstance(c, PdfStream) else (c if isinstance(c, list) else [])
        out = bytearray()
        for s in streams:
            s = self.resolve(s)
            if isinstance(s, PdfStream):
                piece = self.stream_data(s) or b""
                # Held as it accumulates (D7): the joined content is live while
                # the next stream decodes, as PHP's measured growth counts it.
                self._budget.hold(len(piece) + 1)
                out += piece
                out += b"\n"
        return bytes(out)

    def page_number_of(self, ref: Any) -> int | None:
        if type(ref) is int:
            return ref + 1 if 0 <= ref < self.page_count() else None
        if not isinstance(ref, PdfRef):
            return None
        for p in self._page_list():
            if p["ref"] is not None and p["ref"].num == ref.num:
                return int(p["number"])
        return None

    # ------------------------------------------------------------------ outline

    def _outline(self, first: Any) -> list[dict[str, Any]]:
        """PHP's recursive outline walk, iteratively: the same order, the same
        shared ``seen`` set and the same 10 000-item cap."""
        seen: set[int] = set()
        top: list[dict[str, Any]] = []
        # Each frame: the list being filled and the next sibling to visit.
        frames: list[tuple[list[dict[str, Any]], Any]] = [(top, first)]
        while frames:
            out, node = frames.pop()
            if node is None:
                continue
            key = node.num if isinstance(node, PdfRef) else None
            if (key is not None and key in seen) or len(seen) >= 10_000:
                self.warn("the outline loops back on itself; the repeat was skipped")
                continue
            if key is not None:
                seen.add(key)
            item = self.resolve(node)
            if not isinstance(item, PdfDict):
                continue
            title = self.resolve(item.get("Title"))
            entry: dict[str, Any] = {
                "title": textstring.decode(title.bytes) if isinstance(title, PdfString) else "",
                "page": self._destination_page(item),
                "children": [],
            }
            out.append(entry)
            # Children first (PHP recurses before moving to Next), then Next.
            frames.append((out, item.get("Next")))
            frames.append((entry["children"], item.get("First")))
        return top

    def _destination_page(self, item: PdfDict) -> int | None:
        dest = self.resolve(item.get("Dest"))
        if dest is None:
            action = self.resolve(item.get("A"))
            if isinstance(action, PdfDict) and action.name("S") == "GoTo":
                dest = self.resolve(action.get("D"))
        if isinstance(dest, (PdfName, PdfString)):
            dest = self._named_destination(dest)
        if isinstance(dest, PdfDict):
            dest = self.resolve(dest.get("D"))
        if isinstance(dest, list):
            return self.page_number_of(dest[0] if dest else None)
        return None

    def _named_destination(self, name: PdfName | PdfString) -> Any:
        if isinstance(name, PdfName):
            dests = self.resolve(self.catalog().get("Dests"))
            return self.resolve(dests.get(name.value)) if isinstance(dests, PdfDict) else None
        names = self.resolve(self.catalog().get("Names"))
        tree = self.resolve(names.get("Dests")) if isinstance(names, PdfDict) else None
        return self._name_tree_get(tree, name.bytes) if isinstance(tree, PdfDict) else None

    def _name_tree_get(self, root: PdfDict, key: bytes) -> Any:
        queue = [root]
        visited = 0
        qi = 0
        while qi < len(queue) and visited < 10_000:
            visited += 1
            node = queue[qi]
            qi += 1
            names = self.resolve(node.get("Names"))
            if isinstance(names, list):
                for i in range(0, len(names) - 1, 2):
                    k = self.resolve(names[i])
                    if isinstance(k, PdfString) and k.bytes == key:
                        return self.resolve(names[i + 1])
            kids = self.resolve(node.get("Kids"))
            for kid in kids if isinstance(kids, list) else []:
                kid = self.resolve(kid)
                if isinstance(kid, PdfDict):
                    queue.append(kid)
        return None


def _be(data: bytes, at: int, width: int) -> int:
    v = 0
    n = len(data)
    for i in range(width):
        j = at + i
        v = wrap64((v << 8) | (data[j] if 0 <= j < n else 0))
    return v
