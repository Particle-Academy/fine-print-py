"""The cross-runtime oracle: PHP fine-print's READER, driven as a subprocess.

Why parity is a test result here and not a claim:

1. **A missing PHP is a FAILURE, never a skip** (plan decision D12, stricter
   than holy-sheet-py's local skip): the live oracle must not be able to pass
   by not running. ``FINE_PRINT_PHP_SRC`` first, then the sibling checkout.
2. **The corpus is harvested from the PHP suite** (``scripts/harvest_php_corpus.php``):
   every PDF PHP's own tests open, with the Limits they open it under. The
   port never builds its own fixtures, so it cannot quietly test an easier set.
3. **Both sides are normalised the same way** before comparing: non-finite
   floats become strings, strings are scrubbed UTF-8 (PHP's are bytes), and an
   empty object equals an empty list (PHP's ``[]`` is both).
"""

from __future__ import annotations

import gzip
import json
import math
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import fine_print as fp

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "tests" / "fixtures" / "php-corpus"
PHP_SCRIPT = REPO_ROOT / "tests" / "oracle" / "php_read.php"

#: Words and page geometry are compared within this (absolute, per point).
FLOAT_TOL = 1e-6


def php_binary() -> str | None:
    explicit = os.environ.get("PHP_BIN")
    if explicit:
        return explicit if Path(explicit).exists() else None
    return shutil.which("php")


def php_src() -> Path | None:
    override = os.environ.get("FINE_PRINT_PHP_SRC")
    if override:
        return Path(override) if (Path(override) / "Agent.php").is_file() else None
    sibling = REPO_ROOT.parent / "fine-print" / "src"
    return sibling if (sibling / "Agent.php").is_file() else None


def require_oracle() -> tuple[str, Path]:
    """The interpreter and the PHP sources, or a RuntimeError. Never a skip."""
    binary = php_binary()
    src = php_src()
    if binary is None:
        raise RuntimeError("the PHP oracle needs a PHP interpreter (php on PATH, or PHP_BIN)")
    if src is None:
        raise RuntimeError("the PHP oracle needs PHP fine-print's src/ (FINE_PRINT_PHP_SRC or ../fine-print/src)")
    return binary, src


def manifest() -> dict[str, Any]:
    data = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    if not data:
        raise RuntimeError("the PHP corpus is empty; run scripts/harvest_php_corpus.php")
    return data


def case_bytes(case_id: str) -> bytes:
    return gzip.decompress((CORPUS / f"{case_id}.pdf.gz").read_bytes())


def case_limits(case_id: str) -> dict[str, Any]:
    full = {k: v for k, v in _php_default_limits().items()}
    full.update(manifest_cache()[case_id]["limits"] or {})
    return full


_MANIFEST: dict[str, Any] | None = None


def manifest_cache() -> dict[str, Any]:
    global _MANIFEST
    if _MANIFEST is None:
        _MANIFEST = manifest()
    return _MANIFEST


def _php_default_limits() -> dict[str, Any]:
    return {
        "maxFileBytes": 256 * 1024 * 1024,
        "maxObjects": 1_000_000,
        "maxDepth": 64,
        "maxStreamBytes": 64 * 1024 * 1024,
        "maxTotalDecodedBytes": 512 * 1024 * 1024,
        "maxRatio": 1500.0,
        "ratioFloorBytes": 1024 * 1024,
        "maxOperators": 2_000_000,
        "maxFormDepth": 12,
        "maxPages": 50_000,
        "timeSeconds": 30.0,
        "memoryBytes": 256 * 1024 * 1024,
        "maxRenderPixels": 25_000_000,
        "renderTimeSeconds": 30.0,
        "maxImagePixels": 16_000_000,
    }


def run_php(ids: list[str]) -> dict[str, dict[str, Any]]:
    """PHP's results for these cases: id -> variant -> {result, seconds}."""
    binary, src = require_oracle()
    with tempfile.TemporaryDirectory(prefix="fine-print-oracle-") as tmp:
        ids_file = Path(tmp) / "ids.txt"
        out_file = Path(tmp) / "out.jsonl"
        ids_file.write_text("\n".join(ids), encoding="utf-8")
        env = dict(os.environ)
        env["FINE_PRINT_PHP_SRC"] = str(src)
        proc = subprocess.run(
            [binary, str(PHP_SCRIPT), str(CORPUS), str(ids_file), str(out_file)],
            capture_output=True,
            env=env,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"the PHP oracle exited {proc.returncode}: {proc.stderr.decode('utf-8', 'replace')[:2000]}")
        rows = [json.loads(line) for line in out_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != len(ids):
        raise RuntimeError(f"the PHP oracle answered {len(rows)} of {len(ids)} cases")
    return {r["id"]: r["variants"] for r in rows}


# --- the Python side, in the same shapes --------------------------------------


def norm(v: Any) -> Any:
    if isinstance(v, float):
        if math.isnan(v):
            return "NAN"
        if math.isinf(v):
            return "INF" if v > 0 else "-INF"
        return v
    if isinstance(v, dict):
        return {str(k): norm(c) for k, c in v.items()}
    if isinstance(v, (list, tuple)):
        return [norm(c) for c in v]
    return v


def _host(data: bytes, lim: dict[str, Any]) -> dict[str, Any]:
    try:
        doc = fp.Document.open(data, fp.Limits.from_value(lim))
    except fp.RefusedException as e:
        return {"refused": {"reason": e.reason, "message": e.message}}
    r: dict[str, Any] = {"pages": [], "perPage": []}
    try:
        r["pages"] = doc.pages()
        for p in r["pages"]:
            t = doc.page_text(p["number"])
            r["perPage"].append({"text": t["text"], "spans": t["spans"], "words": doc.page_words(p["number"])})
        r["metadata"] = doc.metadata()
        r["xmp"] = doc.xmp()
        r["outline"] = doc.outline()
        r["activeContent"] = doc.active_content()
        r["encryption"] = doc.encryption()
    except fp.RefusedException as e:
        r["refusedLater"] = {"reason": e.reason, "message": e.message}
    r["warnings"] = doc.warnings()
    return r


VARIANTS = {
    "read": lambda b, lim: fp.read(b, limits=lim),
    "read-words": lambda b, lim: fp.read(b, limits=lim, words=True),
    "read-flag-low-excerpts": lambda b, lim: fp.read(b, limits=lim, words=True, policy="flag", threshold="low", excerpts=True),
    "read-discard": lambda b, lim: fp.read(b, limits=lim, policy="discard"),
    "read-unredacted": lambda b, lim: fp.read_unredacted(b, limits=lim, words=True),
    "host": _host,
}


def run_python(case_id: str, variant: str) -> Any:
    data = case_bytes(case_id)
    lim = case_limits(case_id)
    try:
        res = VARIANTS[variant](data, lim)
    except Exception as e:  # recorded, so a crash is a comparable result
        res = {"threw": type(e).__name__}
    return norm(res)


# --- comparison ---------------------------------------------------------------


def _empty(v: Any) -> bool:
    return v == [] or v == {}


def diff(php: Any, py: Any, path: str = "$") -> str | None:
    """The first difference, as a path and both values, or None."""
    if _empty(php) and _empty(py):
        return None
    if isinstance(php, float) or isinstance(py, float):
        if isinstance(php, (int, float)) and isinstance(py, (int, float)) and not isinstance(php, bool) and not isinstance(py, bool):
            if abs(float(php) - float(py)) <= FLOAT_TOL * max(1.0, abs(float(php))):
                return None
        return f"{path}: PHP {php!r} vs Python {py!r}"
    if isinstance(php, dict) and isinstance(py, dict):
        if set(php) != set(py):
            return f"{path}: keys PHP {sorted(php)} vs Python {sorted(py)}"
        for k in php:
            d = diff(php[k], py[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(php, list) and isinstance(py, list):
        if len(php) != len(py):
            return f"{path}: length PHP {len(php)} vs Python {len(py)}"
        for i, (a, b) in enumerate(zip(php, py)):
            d = diff(a, b, f"{path}[{i}]")
            if d:
                return d
        return None
    if type(php) is not type(py) or php != py:
        return f"{path}: PHP {php!r:.300} vs Python {py!r:.300}"
    return None


#: Limits under which the OUTCOME is timing- or allocator-dependent: PHP
#: measures time and memory, Python accounts memory (D7) and runs slower.
BUDGETED = ("timeSeconds", "memoryBytes")


def outcome(result: Any) -> str:
    if not isinstance(result, dict):
        return "?"
    if "threw" in result:
        return "threw:" + str(result["threw"])
    if result.get("ok") is False:
        return "refused:" + str(result["refused"]["reason"])
    if "refused" in result:
        return "refused:" + str(result["refused"]["reason"])
    if "refusedLater" in result:
        return "refused:" + str(result["refusedLater"]["reason"])
    return "ok"
