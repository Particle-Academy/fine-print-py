"""Active content, DETECTED and REPORTED, never acted on, as PHP's
``FinePrint\\Security\\ActiveContentScanner``.

Every indirect object the cross-reference data lists is scanned. Names are
compared decoded. A finding never carries a script body, a launch target or a
URI: scripts are identified by length and SHA-256.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from ..objects import PdfDict, PdfStream, PdfString, name_text

if TYPE_CHECKING:
    from ..document import Document

SEVERITY = {
    "javascript": "high",
    "launch": "high",
    "submit-form": "high",
    "import-data": "high",
    "xfa": "high",
    "open-action": "medium",
    "additional-actions": "medium",
    "embedded-file": "medium",
    "rich-media": "medium",
    "remote-goto": "medium",
    "uri": "low",
    "acroform": "low",
}

ACTIONS = {
    "Launch": "launch",
    "URI": "uri",
    "SubmitForm": "submit-form",
    "ImportData": "import-data",
    "GoToR": "remote-goto",
    "GoToE": "remote-goto",
}

MAX_DEPTH = 32


class ActiveContentScanner:
    def __init__(self, doc: Document) -> None:
        self._doc = doc
        self._findings: dict[str, dict[str, Any]] = {}

    def scan(self) -> list[dict[str, Any]]:
        self._findings = {}
        for num in sorted(self._doc.object_numbers()):
            value = self._doc.object(num)
            self._walk(value, f"{num} 0", "", 0)
        return list(self._findings.values())

    def _walk(self, v: Any, obj: str, path: str, depth: int) -> None:
        # Explicit stack, in PHP's recursive pre-order.
        stack: list[tuple[Any, str, int]] = [(v, path, depth)]
        while stack:
            v, path, depth = stack.pop()
            if depth > MAX_DEPTH:
                continue
            if isinstance(v, PdfStream):
                self._inspect(v.dict, obj, path, True)
                v = v.dict
            elif isinstance(v, PdfDict):
                self._inspect(v, obj, path, False)
            children: list[tuple[Any, str, int]] = []
            if isinstance(v, PdfDict):
                for k, child in v.entries.items():
                    if isinstance(child, (PdfDict, list)):
                        children.append((child, path + "/" + name_text(k), depth + 1))
            elif isinstance(v, list):
                for i, child in enumerate(v):
                    if isinstance(child, (PdfDict, list)):
                        children.append((child, f"{path}[{i}]", depth + 1))
            stack.extend(reversed(children))

    def _inspect(self, d: PdfDict, obj: str, path: str, is_stream: bool) -> None:
        s = d.name("S")
        if s == "JavaScript" or d.has("JS"):
            self._add("javascript", obj, path, self._script_detail(d.get("JS")))
        if s is not None and s in ACTIONS:
            self._add(ACTIONS[s], obj, path)
        if d.has("OpenAction"):
            oa = self._doc.resolve(d.get("OpenAction"))
            if isinstance(oa, PdfDict):
                act = oa.name("S")
                self._add("open-action", obj, path + "/OpenAction", {"action": None if act is None else name_text(act)})
        if d.has("AA"):
            aa = self._doc.resolve(d.get("AA"))
            self._add(
                "additional-actions",
                obj,
                path + "/AA",
                {"triggers": [name_text(k) for k in aa.keys()] if isinstance(aa, PdfDict) else []},
            )
        if d.has("JavaScript") and not d.has("S"):
            self._add("javascript", obj, path + "/JavaScript", {"namesTree": True})
        if (is_stream and d.name("Type") == "EmbeddedFile") or d.has("EF") or d.has("EmbeddedFiles"):
            self._add("embedded-file", obj, path)
        if d.name("Subtype") == "RichMedia" or d.has("RichMediaContent"):
            self._add("rich-media", obj, path)
        if d.has("XFA"):
            self._add("xfa", obj, path + "/XFA")
        if d.has("AcroForm"):
            self._add("acroform", obj, path + "/AcroForm")

    def _script_detail(self, js: Any) -> dict[str, Any]:
        js = self._doc.resolve(js)
        source: bytes | None = None
        if isinstance(js, PdfString):
            source = js.bytes
        elif isinstance(js, PdfStream):
            data = self._doc.stream_data(js)
            source = data if data is not None else js.raw
        if source is None:
            return {"length": 0}
        return {"length": len(source), "sha256": hashlib.sha256(source).hexdigest()}

    def _add(self, kind: str, obj: str, path: str, detail: dict[str, Any] | None = None) -> None:
        key = f"{kind}|{obj}|{path}"
        if key not in self._findings:
            self._findings[key] = {
                "kind": kind,
                "severity": SEVERITY[kind],
                "object": obj,
                "path": path,
                "detail": detail if detail is not None else {},
            }
