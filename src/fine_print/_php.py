"""The PHP behaviours the reader reproduces, in one place.

PHP is normative for semantics, and these are the spots where Python's
builtin answer differs: mbstring's ``?`` substitution (Python gives U+FFFD and
counts bad sequences its own way), mbstring's UTF-16 decoder, PHP's
float-to-string conversions, ``(int)`` on a float, ``trim()``'s character set,
and the ``<=>`` operator on floats. Each was measured against PHP 8.4
(``sandbox/fp-probe/probe.php`` in the envelope) before it was written.
"""

from __future__ import annotations

import codecs
import math
from decimal import Decimal

PHP_INT_MAX = (1 << 63) - 1

#: ``trim()``'s default set. NOT Python's whitespace: no form feed, no Unicode.
TRIM_CHARS = " \t\n\r\0\x0b"


def _scrub_handler(err: UnicodeError) -> tuple[str, int]:
    assert isinstance(err, UnicodeDecodeError)
    return "?", err.end


codecs.register_error("fine_print_php_scrub", _scrub_handler)


def scrub(data: bytes) -> str:
    """``mb_scrub($s, 'UTF-8')``: each maximal invalid subpart becomes one ``?``.

    Python's decoder reports exactly the maximal subparts mbstring replaces
    (measured: truncated sequences, surrogates, overlongs, F5..FF).
    """
    return data.decode("utf-8", "fine_print_php_scrub")


def utf16(data: bytes, little: bool = False) -> str:
    """``mb_convert_encoding($s, 'UTF-8', 'UTF-16BE'|'UTF-16LE')``.

    A surrogate pair combines; a lone surrogate (high not followed by low, or a
    stray low) is one ``?`` and consumes one unit; a trailing odd byte is ``?``.
    """
    out: list[str] = []
    n = len(data)
    i = 0
    while i + 1 < n:
        u = (data[i + 1] << 8) | data[i] if little else (data[i] << 8) | data[i + 1]
        i += 2
        if 0xD800 <= u <= 0xDBFF:
            if i + 1 < n:
                lo = (data[i + 1] << 8) | data[i] if little else (data[i] << 8) | data[i + 1]
                if 0xDC00 <= lo <= 0xDFFF:
                    i += 2
                    out.append(chr(0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)))
                    continue
            out.append("?")
        elif 0xDC00 <= u <= 0xDFFF:
            out.append("?")
        else:
            out.append(chr(u))
    if i < n:
        out.append("?")
    return "".join(out)


def trim(s: str, chars: str = TRIM_CHARS) -> str:
    return s.strip(chars)


def rtrim(s: str, chars: str = TRIM_CHARS) -> str:
    return s.rstrip(chars)


def ltrim(s: str, chars: str = TRIM_CHARS) -> str:
    return s.lstrip(chars)


def is_int(v: object) -> bool:
    """``is_int``: a bool is NOT an int here."""
    return type(v) is int


def is_num(v: object) -> bool:
    """``is_int($v) || is_float($v)``."""
    return type(v) is int or type(v) is float


def int_cast(v: float) -> int:
    """``(int)`` of a float: truncate, non-finite is 0, out of range wraps mod 2**64."""
    if not math.isfinite(v):
        return 0
    i = int(v) & 0xFFFFFFFFFFFFFFFF
    return i - (1 << 64) if i >= 1 << 63 else i


def wrap64(i: int) -> int:
    """A Python int as PHP's 64-bit int after shifts that dropped high bits."""
    i &= 0xFFFFFFFFFFFFFFFF
    return i - (1 << 64) if i >= 1 << 63 else i


def int_string(word: bytes) -> int:
    """``(int)`` of an all-digit string: it saturates rather than wraps."""
    v = int(word)
    return max(-PHP_INT_MAX - 1, min(PHP_INT_MAX, v))


def cmp(a: float, b: float) -> int:
    """``$a <=> $b`` on numbers: equal is 0, less is -1, anything else (NAN) 1."""
    if a == b:
        return 0
    return -1 if a < b else 1


def pmin(a: float, b: float) -> float:
    """``min($a, $b)``: the second only when it compares below the first."""
    return b if b < a else a


def pmax(a: float, b: float) -> float:
    """``max($a, $b)``: the second whenever ``$b <=> $a`` is 1, NAN included."""
    return b if (b != a and not b < a) else a


def _digits(v: float, sig: int | None) -> tuple[str, int]:
    """Significant digits (trailing zeros stripped) and the decimal point position."""
    if sig is None:
        d = Decimal(repr(v))
    else:
        d = Decimal(f"{v:.{sig - 1}e}")
    t = d.as_tuple()
    digits = "".join(str(x) for x in t.digits).rstrip("0") or "0"
    exp = int(t.exponent)
    decpt = len(t.digits) + exp
    if digits == "0":
        decpt = 1
    return digits, decpt


def _gcvt(v: float, sig: int | None, ndigit: int) -> str:
    if math.isnan(v):
        return "NAN"
    if math.isinf(v):
        return "INF" if v > 0 else "-INF"
    neg = math.copysign(1.0, v) < 0
    digits, decpt = _digits(abs(v), sig)
    sign = "-" if neg else ""
    if v == 0:
        return sign + "0"
    if decpt < -3 or decpt > ndigit:
        e = decpt - 1
        mant = digits[0] + "." + (digits[1:] or "0")
        return f"{sign}{mant}E{'+' if e >= 0 else '-'}{abs(e)}"
    if decpt <= 0:
        return sign + "0." + "0" * (-decpt) + digits
    if len(digits) <= decpt:
        return sign + digits + "0" * (decpt - len(digits))
    return sign + digits[:decpt] + "." + digits[decpt:]


def float_str(v: float) -> str:
    """``(string) $float``: 14 significant digits (PHP's ``precision``)."""
    return _gcvt(v, 14, 14)


def var_export_float(v: float) -> str:
    """``var_export($float, true)``: the shortest repr, always with a fraction."""
    s = _gcvt(v, None, 17)
    if s in ("INF", "-INF", "NAN"):
        return s
    if all(c.isdigit() or c == "-" for c in s):
        s += ".0"
    return s


def num_str(v: int | float) -> str:
    """PHP's string conversion of an int or a float."""
    return str(v) if type(v) is int else float_str(float(v))
