"""The layer between a PDF and an agent's read, as PHP's
``FinePrint\\Security\\AgentReadGuard``.

Rules: ``instruction``, ``hidden-text``, ``off-page``, ``invisible-chars``.
Policies: ``flag`` (content unchanged), ``redact`` (the default: cut what is
at or above the threshold), ``discard`` (no content at all). Findings carry a
location and never, by default, the offending text: an excerpt of an injection
is still an injection.

Offsets here are characters throughout (PHP's are bytes of the same UTF-8 text
and are converted to characters for every report, so the output is equal).
"""

from __future__ import annotations

import re
from bisect import bisect_right
from typing import Any

from .._php import ltrim, rtrim, trim
from .patterns import PATTERNS

POLICIES = ("flag", "redact", "discard")
SEVERITIES = {"low": 1, "medium": 2, "high": 3}
INSTRUCTION_MARKER = "[fine-print: redacted instruction]"
HIDDEN_MARKER = "[fine-print: removed hidden text]"

#: Invisible characters. Public because extraction strips exactly this class.
INVISIBLE = re.compile(
    "[​-‏‪-‮⁠-⁤⁦-⁩﻿᠎؜\U000e0000-\U000e007f]+"
)
_INVISIBLE_ONE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿᠎؜\U000e0000-\U000e007f]")
_XMP_HEAD = re.compile(rb"<\?xpacket\s+begin=[\"']$")
_ASCII_SPACE = " \t\n\x0b\x0c\r"


class AgentReadGuard:
    def __init__(self, policy: str = "redact", threshold: str = "medium", excerpts: bool = False) -> None:
        if policy not in POLICIES:
            raise ValueError(f'Unknown policy "{policy}"; expected one of: {", ".join(POLICIES)}.')
        if threshold not in SEVERITIES:
            raise ValueError(f'Unknown threshold "{threshold}"; expected low, medium or high.')
        self._policy = policy
        self._threshold = SEVERITIES[threshold]
        self._excerpts = excerpts

    def apply(self, segments: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        ranges: list[list[tuple[int, int, int]]] = []
        for seg in segments:
            f, r = self._scan(seg)
            findings.extend(f)
            ranges.append(r)
        actionable = [f for f in findings if SEVERITIES[f["severity"]] >= self._threshold]
        discarded = self._policy == "discard" and bool(actionable)
        texts: list[str | None] = []
        cut: list[list[tuple[int, int, int]]] = []
        for i, seg in enumerate(segments):
            merged = _merge(ranges[i]) if self._policy == "redact" else []
            cut.append(merged)
            if discarded:
                texts.append(None)
            elif self._policy == "redact":
                texts.append(_redact(seg["text"], merged))
            else:
                texts.append(seg["text"])
        return {
            "texts": texts,
            "findings": findings,
            "discarded": discarded,
            "acted": [] if self._policy == "flag" else actionable,
            "ranges": cut,
        }

    def _scan(self, seg: dict[str, Any]) -> tuple[list[dict[str, Any]], list[tuple[int, int, int]]]:
        text: str = seg["text"]
        loc: dict[str, Any] = seg["location"]
        non_page = loc.get("source", "") != "page"
        findings: list[dict[str, Any]] = []
        ranges: list[tuple[int, int, int]] = []

        hidden: list[tuple[int, int]] = []
        for span in _merge_spans(seg.get("spans") or [], text):
            s0, ln = span["start"], span["length"]
            chunk = text[s0 : s0 + ln]
            if trim(chunk) == "":
                continue
            rule = "off-page" if "off-page" in span["flags"] else "hidden-text"
            f = {
                "rule": rule,
                "severity": "medium",
                "reasons": span["flags"],
                "location": {**loc, **_at(s0, ln)},
            }
            findings.append(self._with_excerpt(f, chunk))
            hidden.append((s0, s0 + ln))
            self._range(ranges, "medium", s0, s0 + ln, 2)

        for m in INVISIBLE.finditer(text):
            cluster = m.group(0)
            start = m.start()
            if _is_xmp_packet_mark(text, cluster, start):
                continue
            chars: dict[str, bool] = {}
            severity = "low"
            smuggled = []
            for ch in cluster:
                cp = ord(ch)
                chars[f"U+{cp:04X}"] = True
                severity = _max_severity(severity, _invisible_severity(cp))
                if 0xE0020 <= cp <= 0xE007E:
                    smuggled.append(chr(cp - 0xE0000))
            where = {**loc, **_at(start, len(cluster))}
            f = {"rule": "invisible-chars", "severity": severity, "chars": list(chars), "location": where}
            findings.append(self._with_excerpt(f, _visible(cluster)))
            self._range(ranges, severity, start, start + len(cluster), 1)
            if smuggled:
                sm = "".join(smuggled)
                for pid, _sev, _txt, ms, ml in _instruction_matches(sm):
                    findings.append(
                        self._with_excerpt(
                            {
                                "rule": "instruction",
                                "severity": "high",
                                "pattern": pid,
                                "hidden": True,
                                "smuggled": True,
                                "location": where,
                            },
                            sm[ms : ms + ml],
                        )
                    )

        norm, keys, deltas = _normalise(text)
        for pid, sev, _txt, n_start, n_len in _instruction_matches(norm):
            start = _original(keys, deltas, n_start)
            end = _original(keys, deltas, n_start + n_len)
            end = start + len(rtrim(text[start:end]))
            is_hidden = any(start < he and end > hs for hs, he in hidden)
            if is_hidden or non_page:
                sev = "high"
            f = {
                "rule": "instruction",
                "severity": sev,
                "pattern": pid,
                "hidden": is_hidden,
                "smuggled": False,
                "location": {**loc, **_at(start, end - start)},
            }
            findings.append(self._with_excerpt(f, text[start:end]))
            self._range(ranges, sev, start, end, 3)

        findings.sort(key=lambda f: f["location"].get("offset", 0))
        return findings, ranges

    def _range(self, ranges: list[tuple[int, int, int]], severity: str, start: int, end: int, priority: int) -> None:
        if SEVERITIES[severity] >= self._threshold and end > start:
            ranges.append((start, end, priority))

    def _with_excerpt(self, finding: dict[str, Any], excerpt: str) -> dict[str, Any]:
        if self._excerpts:
            finding["excerpt"] = excerpt[:200]
        return finding


def _instruction_matches(norm: str) -> list[tuple[str, str, str, int, int]]:
    out: list[tuple[str, str, str, int, int]] = []
    for pid, (severity, rx) in PATTERNS.items():
        for m in rx.finditer(norm):
            match = m.group(0)
            lead = len(match) - len(ltrim(match))
            t = trim(match)
            out.append((pid, severity, t, m.start() + lead, len(t)))
    return out


def _normalise(text: str) -> tuple[str, list[int], list[int]]:
    """Normalised text plus breakpoints (normalised offset, delta) mapping back."""
    norm: list[str] = []
    norm_len = 0
    keys: list[int] = []
    deltas: list[int] = []
    delta = 0
    last_space = True
    pos = 0
    for ch in text:
        o = ord(ch)
        if o >= 0x80 and _INVISIBLE_ONE.match(ch):
            pos += 1
            continue
        if ch == "\xa0" or (o < 0x80 and ch in _ASCII_SPACE):
            if not last_space:
                if pos - norm_len != delta or not keys:
                    delta = pos - norm_len
                    keys.append(norm_len)
                    deltas.append(delta)
                norm.append(" ")
                norm_len += 1
                last_space = True
            pos += 1
            continue
        if pos - norm_len != delta or not keys:
            delta = pos - norm_len
            keys.append(norm_len)
            deltas.append(delta)
        norm.append(ch.lower() if "A" <= ch <= "Z" else ch)
        norm_len += 1
        last_space = False
        pos += 1
    if pos - norm_len != delta or not keys:
        delta = pos - norm_len
        keys.append(norm_len)
        deltas.append(delta)
    return "".join(norm), keys, deltas


def _original(keys: list[int], deltas: list[int], off: int) -> int:
    i = bisect_right(keys, off) - 1
    return off + (deltas[i] if i >= 0 else 0)


def _merge(ranges: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    merged: list[list[int]] = []
    for r in sorted(ranges, key=lambda r: r[0]):
        if merged and r[0] <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], r[1])
            merged[-1][2] = max(merged[-1][2], r[2])
            continue
        merged.append([r[0], r[1], r[2]])
    return [(a, b, c) for a, b, c in merged]


def _redact(text: str, merged: list[tuple[int, int, int]]) -> str:
    if not merged:
        return text
    out: list[str] = []
    pos = 0
    for s, e, p in merged:
        out.append(text[pos:s] if s > pos else "")
        out.append(INSTRUCTION_MARKER if p == 3 else HIDDEN_MARKER if p == 2 else "")
        pos = e
    out.append(text[pos:])
    return "".join(out)


def _merge_spans(spans: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for s in spans:
        if out and out[-1]["flags"] == s["flags"]:
            end = out[-1]["start"] + out[-1]["length"]
            if s["start"] >= end and trim(text[end : s["start"]]) == "" and s["start"] - end <= 2:
                out[-1]["length"] = s["start"] + s["length"] - out[-1]["start"]
                continue
        out.append(dict(s))
    return out


def _at(start: int, length: int) -> dict[str, int]:
    return {"offset": start, "length": length}


def _is_xmp_packet_mark(text: str, cluster: str, start: int) -> bool:
    if cluster != "﻿":
        return False
    # PHP counts BYTES: at least 7 before, and the 18 bytes before it.
    before = text[max(0, start - 18) : start].encode("utf-8")
    if start < 7 and len(text[:start].encode("utf-8")) < 7:
        return False
    return _XMP_HEAD.search(before[-18:]) is not None


def _invisible_severity(cp: int) -> str:
    if cp >= 0xE0000:
        return "high"
    if cp in (0x200C, 0x200D, 0x200E, 0x200F, 0x061C):
        return "low"
    return "medium"


def _max_severity(a: str, b: str) -> str:
    return a if SEVERITIES[a] >= SEVERITIES[b] else b


def _visible(s: str) -> str:
    return "".join(f"<U+{ord(ch):04X}>" for ch in s)
