"""Text runs into READING order, as PHP's ``FinePrint\\Text\\Layout``: lines top
to bottom by baseline, pieces left to right, a space where the horizontal gap
says one was meant, a blank line where the vertical gap says a paragraph ended.
Multi-column pages read row by row across columns: a stated limit."""

from __future__ import annotations

from functools import cmp_to_key
from typing import Any

from .._php import cmp, pmax, pmin

WORD_GAP = 0.15
PARAGRAPH_GAP = 1.8


def _key_cmp(a: tuple[dict[str, Any], int], b: tuple[dict[str, Any], int]) -> int:
    # [-y, x0, index] <=> [-y, x0, index], element by element.
    ra, ia = a
    rb, ib = b
    c = cmp(-ra["y"], -rb["y"])
    if c:
        return c
    c = cmp(ra["x0"], rb["x0"])
    if c:
        return c
    return cmp(ia, ib)


def compose(runs: list[dict[str, Any]], offsets: dict[int, int] | None = None) -> dict[str, Any]:
    """``{"text", "spans"}``; ``offsets`` (when given) receives run index ->
    offset of that run in the text. Offsets are in characters: every offset in
    this port is, consistently (PHP's are bytes of the same UTF-8 text)."""
    if offsets is not None:
        offsets.clear()
    keyed = [(r, i) for i, r in enumerate(runs) if r["text"] != ""]
    if not keyed:
        return {"text": "", "spans": []}
    keyed.sort(key=cmp_to_key(_key_cmp))

    lines: list[dict[str, Any]] = []
    for r, i in keyed:
        if lines:
            last = lines[-1]
            tol = pmax(1.0, 0.5 * pmin(r["size"], last["size"]))
            if abs(last["y"] - r["y"]) <= tol:
                last["runs"].append((r, i))
                last["size"] = pmax(last["size"], r["size"])
                continue
        lines.append({"y": r["y"], "size": r["size"], "runs": [(r, i)]})

    parts: list[str] = []
    length = 0
    spans: list[dict[str, Any]] = []
    prev_line: dict[str, Any] | None = None
    for line in lines:
        if prev_line is not None:
            gap = prev_line["y"] - line["y"]
            big = pmax(pmax(prev_line["size"], line["size"]), 1.0)
            sep = "\n\n" if gap > PARAGRAPH_GAP * big else "\n"
            parts.append(sep)
            length += len(sep)
        line_runs = sorted(line["runs"], key=cmp_to_key(lambda a, b: cmp(a[0]["x0"], b[0]["x0"])))
        prev: dict[str, Any] | None = None
        for r, i in line_runs:
            if prev is not None:
                if r["text"] == prev["text"] and abs(r["x0"] - prev["x0"]) < 1.0:
                    continue
                gap = r["x0"] - prev["x1"]
                if (
                    gap > WORD_GAP * pmax(r["size"], prev["size"])
                    and not prev["text"].endswith(" ")
                    and not r["text"].startswith(" ")
                ):
                    parts.append(" ")
                    length += 1
            if r["flags"]:
                spans.append({"start": length, "length": len(r["text"]), "flags": r["flags"]})
            if offsets is not None:
                offsets[i] = length
            parts.append(r["text"])
            length += len(r["text"])
            prev = r
        prev_line = line
    return {"text": "".join(parts), "spans": spans}
