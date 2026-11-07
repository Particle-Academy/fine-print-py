"""The PHP behaviours ``fine_print._php`` reproduces, checked against live PHP.

mbstring's ``?`` substitution and UTF-16 decoding, PHP's float-to-string
conversions (``(string)`` and ``var_export``), ``(int)`` of a float, and
``trim()``'s set. Each one decides output text somewhere in the reader.
"""

from __future__ import annotations

import json
import random
import struct
import subprocess
import tempfile
from pathlib import Path

import _oracle
from fine_print import _php

SCRIPT = Path(__file__).parent / "oracle" / "php_semantics.php"


def _inputs() -> dict[str, list[str]]:
    rng = random.Random(11)
    fixed = [
        "80", "61c3", "c328", "e282", "e28228", "f09f98", "f09f9828", "eda080", "f4908080", "c0af", "fffe",
        "f888808080", "6f6be282ac6f6b", "e08080", "efbfbd", "0041", "00", "d800", "d8000041", "dc00",
        "dc000041", "d83dde00", "004100", "d83dd83dde00", "dbffdfff", "", "d800d800", "0c0b2009410a0d00",
        "200941", "c2a0",
    ]
    rand = [bytes(rng.randrange(256) for _ in range(rng.randint(1, 12))).hex() for _ in range(300)]
    floats = [
        "0.05", "30", "1500", "1e15", "1e14", "123456789012345", "1e20", "0.0001", "0.00001", "-0.0", "1.5",
        "0.1", "0.3333333333333333", "2.5e-5", "1e100", "INF", "-INF", "NAN", "99999999999999.9",
        "0.30000000000000004", "1e16", "1e17", "1e18", "-123.456", "5e-324", "1.7976931348623157e308",
        "1e19", "-1e19", "3.9", "-3.9", "1e30", "12345678901234567890",
    ]
    floats += [repr(struct.unpack("<d", rng.randbytes(8))[0]) for _ in range(200)]
    floats = [f for f in floats if f not in ("nan", "inf", "-inf")]
    return {"bytes": fixed + rand, "floats": floats}


def test_reproduces_php_exactly() -> None:
    binary, _src = _oracle.require_oracle()
    inputs = _inputs()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "in.json"
        path.write_text(json.dumps(inputs), encoding="utf-8")
        proc = subprocess.run([binary, str(SCRIPT), str(path)], capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    php = json.loads(proc.stdout)

    for i, h in enumerate(inputs["bytes"]):
        b = bytes.fromhex(h)
        assert _php.scrub(b).encode("utf-8").hex() == php["scrub"][i], ("scrub", h)
        assert _php.utf16(b).encode("utf-8").hex() == php["u16be"][i], ("utf16be", h)
        assert _php.utf16(b, little=True).encode("utf-8").hex() == php["u16le"][i], ("utf16le", h)
        assert _php.trim(b.decode("latin-1")).encode("latin-1").hex() == php["trim"][i], ("trim", h)

    for i, s in enumerate(inputs["floats"]):
        f = {"INF": float("inf"), "-INF": float("-inf"), "NAN": float("nan")}.get(s)
        f = float(s) if f is None else f
        assert _php.float_str(f) == php["floatStr"][i], ("(string)", s)
        assert _php.var_export_float(f) == php["varExport"][i], ("var_export", s)
        assert str(_php.int_cast(f)) == php["intCast"][i], ("(int)", s)


def test_compares_numbers_as_the_spaceship_operator_does() -> None:
    nan = float("nan")
    assert (_php.cmp(1, 2), _php.cmp(2, 1), _php.cmp(1, 1)) == (-1, 1, 0)
    assert _php.cmp(nan, 1) == 1 and _php.cmp(1, nan) == 1
    assert _php.pmax(1.0, nan) != _php.pmax(1.0, nan)  # max(1, NAN) is NAN in PHP
    assert _php.pmax(nan, 1.0) == 1.0
    assert _php.is_int(True) is False and _php.is_num(True) is False
