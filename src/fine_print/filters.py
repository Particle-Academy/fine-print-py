"""The stream filters, as PHP's ``FinePrint\\Filters\\Filters``.

FlateDecode, LZWDecode, ASCII85Decode, ASCIIHexDecode, RunLengthDecode and the
PNG / TIFF predictors. Image codecs and crypt filters are kept opaque.

**Decompression is judged while it runs.** Flate is fed in 4 KB chunks through
``zlib.decompressobj``, and every expanding stage checks the byte cap and the
ratio as it grows, exactly where PHP does.
"""

from __future__ import annotations

import math
import re
import zlib

from ._php import is_int
from .exceptions import OpaqueStream, RefusedException
from .limits import Budget, Limits
from .objects import PdfDict

MAX_INFLATE_PIECE = 4200 * 1024
MAX_LZW_GROWTH = 1024 * 3839
MAX_RUN_GROWTH = 1024 * 128
MAX_A85_GROWTH = 1024 * 4

ALIASES = {
    "Fl": "FlateDecode",
    "LZW": "LZWDecode",
    "A85": "ASCII85Decode",
    "AHx": "ASCIIHexDecode",
    "RL": "RunLengthDecode",
    "DCT": "DCTDecode",
    "CCF": "CCITTFaxDecode",
}

OPAQUE = ("DCTDecode", "JPXDecode", "CCITTFaxDecode", "JBIG2Decode", "Crypt")

_WS = re.compile(rb"\s+")
_NOT_HEX = re.compile(rb"[^0-9A-Fa-f]")


def decode_chain(names: list[str], data: bytes, parms: list[PdfDict | None] | None = None, budget: Budget | None = None) -> bytes:
    """Apply filters in order. Raises :class:`OpaqueStream` for image codecs."""
    if budget is None:
        budget = Budget(Limits())
    parms = parms or []
    for i, name in enumerate(names):
        name = ALIASES.get(name, name)
        p = parms[i] if i < len(parms) else None
        p = p if isinstance(p, PdfDict) else None
        if name in OPAQUE:
            raise OpaqueStream(name)
        n_in = len(data)
        if name == "FlateDecode":
            data = _predict(_flate(data, budget), p, budget)
        elif name == "LZWDecode":
            data = _predict(_lzw(data, _early(p), budget), p, budget)
        elif name == "ASCII85Decode":
            data = _ascii85(data, budget)
        elif name == "ASCIIHexDecode":
            data = _ascii_hex(data, budget)
        elif name == "RunLengthDecode":
            data = _run_length(data, budget)
        else:
            raise OpaqueStream(name)
        budget.decoding(len(data), n_in)
        budget.decoded(len(data))
    return data


def _flate(data: bytes, budget: Budget) -> bytes:
    out, ended = _inflate(data, 15, budget)
    if not out and data and not ended:
        # Raw deflate with no zlib header; an empty stream that ENDED is empty.
        out, ended = _inflate(data, -15, budget)
    return out


def _inflate(data: bytes, wbits: int, budget: Budget) -> tuple[bytes, bool]:
    try:
        d = zlib.decompressobj(wbits)
    except zlib.error:
        return b"", False
    out = bytearray()
    n = len(data)
    for i in range(0, n, 4096):
        budget.decoding(len(out), max(1, i), len(out) + 2 * MAX_INFLATE_PIECE)
        try:
            piece = d.decompress(data[i : i + 4096])
        except zlib.error:
            break
        out += piece
        budget.decoding(len(out), min(n, i + 4096))
        if d.eof:
            return bytes(out), True
    return bytes(out), False


def _early(p: PdfDict | None) -> int:
    v = p.get("EarlyChange") if p is not None else None
    return v if is_int(v) else 1


def _lzw(data: bytes, early: int, budget: Budget) -> bytes:
    out = bytearray()
    n = len(data)
    table: list[bytes] = [bytes((c,)) for c in range(256)] + [b"", b""]
    nxt = 258
    width = 9
    prev: bytes | None = None
    buf = 0
    bits = 0
    i = 0
    codes = 0
    while True:
        while bits < width:
            if i >= n:
                return bytes(out)
            buf = (buf << 8) | data[i]
            i += 1
            bits += 8
        code = (buf >> (bits - width)) & ((1 << width) - 1)
        bits -= width
        buf &= (1 << bits) - 1
        if code == 256:
            table = table[:258]
            nxt = 258
            width = 9
            prev = None
            continue
        if code == 257:
            break
        if prev is None:
            if code >= len(table) or code in (256, 257):
                break
            out += table[code]
            prev = table[code]
            continue
        if code < len(table) and code not in (256, 257):
            entry = table[code]
        elif code == nxt:
            entry = prev + prev[:1]
        else:
            break
        out += entry
        codes += 1
        if codes & 0x3FF == 0:
            budget.decoding(len(out), i, len(out) + MAX_LZW_GROWTH)
        if nxt < 4096:
            table.append(prev + entry[:1])
            nxt += 1
        prev = entry
        if nxt + early >= (1 << width) and width < 12:
            width += 1
    return bytes(out)


def _ascii85(data: bytes, budget: Budget) -> bytes:
    budget.allocation(len(data))
    data = _WS.sub(b"", data)
    if data.startswith(b"<~"):
        data = data[2:]
    end = data.find(b"~")
    if end >= 0:
        data = data[:end]
    out = bytearray()
    group: list[int] = []
    for i, o in enumerate(data):
        if i & 0x3FF == 0:
            budget.decoding(len(out), max(1, i), len(out) + MAX_A85_GROWTH)
        if o == 0x7A and not group:
            out += b"\x00\x00\x00\x00"
            continue
        if o < 33 or o > 117:
            continue
        group.append(o - 33)
        if len(group) == 5:
            out += _a85_group(group, 4)
            group = []
    if len(group) > 1:
        k = len(group)
        out += _a85_group(group + [84] * (5 - k), k - 1)
    return bytes(out)


def _a85_group(g: list[int], nbytes: int) -> bytes:
    v = 0
    for d in g:
        v = v * 85 + d
    return (v & 0xFFFFFFFF).to_bytes(4, "big")[:nbytes]


def _ascii_hex(data: bytes, budget: Budget) -> bytes:
    budget.allocation(2 * len(data))
    end = data.find(b">")
    if end >= 0:
        data = data[:end]
    h = _NOT_HEX.sub(b"", data)
    if len(h) % 2 == 1:
        h += b"0"
    return bytes.fromhex(h.decode("ascii"))


def _run_length(data: bytes, budget: Budget) -> bytes:
    out = bytearray()
    n = len(data)
    i = 0
    runs = 0
    while i < n:
        runs += 1
        if runs & 0x3FF == 0:
            budget.decoding(len(out), i, len(out) + MAX_RUN_GROWTH)
        c = data[i]
        i += 1
        if c == 128:
            break
        if c < 128:
            out += data[i : i + c + 1]
            i += c + 1
        else:
            if i >= n:
                break
            out += bytes((data[i],)) * (257 - c)
            i += 1
    return bytes(out)


def _predict(data: bytes, p: PdfDict | None, budget: Budget) -> bytes:
    predictor = p.get("Predictor") if p is not None else None
    if not is_int(predictor) or predictor < 2:
        return data
    assert p is not None
    colors = p.get("Colors")
    colors = 1 if colors is None else colors
    bpc = p.get("BitsPerComponent")
    bpc = 8 if bpc is None else bpc
    columns = p.get("Columns")
    columns = 1 if columns is None else columns
    if (
        not is_int(colors)
        or colors < 1
        or colors > 32
        or not (is_int(bpc) and bpc in (1, 2, 4, 8, 16))
        or not is_int(columns)
        or columns < 1
        or predictor not in (2, 10, 11, 12, 13, 14, 15)
    ):
        raise RefusedException("corrupt", "Invalid stream predictor parameters.")
    if math.ceil(float(colors) * bpc * columns / 8) > min(budget.limits.max_stream_bytes, ((1 << 63) - 1) / 16):
        raise RefusedException("too_large", "A predictor row exceeds the decoded stream limit.")
    budget.allocation(2 * len(data))
    bpp = max(1, (colors * bpc + 7) // 8)
    row_len = (colors * bpc * columns + 7) // 8
    n = len(data)

    if predictor == 2:
        out = bytearray()
        mask = (1 << bpc) - 1
        for pos in range(0, n, row_len):
            row = data[pos : pos + row_len]
            previous = [0] * colors
            acc = 0
            used = 0
            samples = min(colors * columns, (len(row) * 8) // bpc)
            budget.tick(samples)
            for i in range(samples):
                bit = i * bpc
                byte = bit // 8
                if bpc == 16:
                    sample = (row[byte] << 8) | row[byte + 1]
                else:
                    sample = (row[byte] >> (8 - (bit & 7) - bpc)) & mask
                value = (sample + previous[i % colors]) & mask
                previous[i % colors] = value
                if bpc == 16:
                    out += value.to_bytes(2, "big")
                else:
                    acc = (acc << bpc) | value
                    used += bpc
                    if used == 8:
                        out.append(acc)
                        acc = used = 0
            if used > 0:
                out.append((acc << (8 - used)) & 0xFF)
        return bytes(out)

    out = bytearray()
    prior = b""
    pos = 0
    while pos + 1 <= n:
        kind = data[pos]
        row = bytearray(data[pos + 1 : pos + 1 + row_len])
        if not row:
            break
        if kind > 4:
            raise RefusedException("corrupt", "Invalid PNG predictor filter.")
        m = len(row)
        budget.tick(m)
        lp = len(prior)
        if kind == 1:
            for i in range(bpp, m):
                row[i] = (row[i] + row[i - bpp]) & 0xFF
        elif kind == 2:
            for i in range(min(m, lp)):
                row[i] = (row[i] + prior[i]) & 0xFF
        elif kind == 3:
            for i in range(m):
                left = row[i - bpp] if i >= bpp else 0
                up = prior[i] if i < lp else 0
                row[i] = (row[i] + ((left + up) >> 1)) & 0xFF
        elif kind == 4:
            for i in range(m):
                left = row[i - bpp] if i >= bpp else 0
                up = prior[i] if i < lp else 0
                ul = prior[i - bpp] if i >= bpp and i - bpp < lp else 0
                pp = left + up - ul
                pa = abs(pp - left)
                pb = abs(pp - up)
                pc = abs(pp - ul)
                if pa <= pb and pa <= pc:
                    pr = left
                elif pb <= pc:
                    pr = up
                else:
                    pr = ul
                row[i] = (row[i] + pr) & 0xFF
        out += row
        prior = bytes(row)
        pos += row_len + 1
    return bytes(out)
