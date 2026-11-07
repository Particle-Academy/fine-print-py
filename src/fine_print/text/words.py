"""Word boxes from the extractor's pieces and the composed page text, as PHP's
``FinePrint\\Text\\Words``.

A word is a maximal stretch of the composed text with no whitespace. Pieces of
separate runs join ONLY when their ranges are contiguous in that text, which is
exactly the layout's gap rule, so every word is a substring of the text the
agent-read guard scans. Never join by geometry: a word that is not a substring
of the guarded text is a way round the redaction.
"""

from __future__ import annotations

from array import array
from typing import Any

from ..limits import Budget

#: Accounted bytes (D7) per word: PHP's seven-key array.
WORD_COST = 400


def assemble(pieces: dict[int, array[float]], offsets: dict[int, int], text: str, budget: Budget) -> list[dict[str, Any]]:
    words: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for run, base in sorted(offsets.items(), key=lambda kv: kv[1]):
        rec = pieces.get(run)
        if rec is None:
            continue
        for j in range(0, len(rec) - 5, 6):
            budget.tick()
            start = base + int(rec[j])
            end = base + int(rec[j + 1])
            if end <= start:
                continue
            px0, px1, pt, pb = rec[j + 2], rec[j + 3], rec[j + 4], rec[j + 5]
            if cur is not None and cur["end"] == start:
                cur["x0"] = min(cur["x0"], px0)
                cur["x1"] = max(cur["x1"], px1)
                cur["top"] = min(cur["top"], pt)
                cur["bottom"] = max(cur["bottom"], pb)
                cur["end"] = end
                continue
            if cur is not None:
                words.append(_finish(cur, text))
                budget.hold(WORD_COST)
            cur = {"x0": px0, "x1": px1, "top": pt, "bottom": pb, "start": start, "end": end}
    if cur is not None:
        words.append(_finish(cur, text))
        budget.hold(WORD_COST)
    budget.check()
    return words


def _finish(w: dict[str, Any], text: str) -> dict[str, Any]:
    return {
        "text": text[w["start"] : w["end"]],
        "x0": w["x0"],
        "x1": w["x1"],
        "top": w["top"],
        "bottom": w["bottom"],
        "start": w["start"],
        "end": w["end"],
    }
