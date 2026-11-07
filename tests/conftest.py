from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import _oracle

HEAVY = json.loads((Path(__file__).parent / "oracle" / "heavy.json").read_text(encoding="utf-8"))["heavy"]
HEAVY_VARIANTS = ("read", "read-words")


@pytest.fixture(scope="session")
def php_results() -> dict[str, dict[str, Any]]:
    """PHP fine-print's answers for the whole corpus, from ONE PHP process."""
    ids = sorted(_oracle.manifest_cache())
    lines = [f"{i} {','.join(HEAVY_VARIANTS)}" if i in HEAVY else i for i in ids]
    return _oracle.run_php(lines)


def corpus_id(origin: str, index: int = 0) -> str:
    """The corpus case a PHP test line produced (cases are named by content)."""
    hits = sorted(k for k, v in _oracle.manifest_cache().items() if v["origin"] == origin)
    if len(hits) <= index:
        raise LookupError(f"no corpus case from {origin}; re-harvest (scripts/harvest_php_corpus.php)")
    return hits[index]
