"""The surface: names, shapes, options, and what this package must never do."""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

import _oracle
import fine_print as fp
from conftest import corpus_id
from fine_print import Document

SRC = Path(__file__).resolve().parents[1] / "src" / "fine_print"


def pdf(origin: str = "WordsTest.php:111") -> bytes:
    return _oracle.case_bytes(corpus_id(origin))


def test_read_returns_php_s_shape() -> None:
    r = fp.read(pdf())
    assert list(r) == [
        "ok", "version", "pageCount", "repaired", "pages", "metadata", "outline", "annotations",
        "activeContent", "warnings", "guard", "redacted", "unredacted", "notice", "encryption",
    ]
    assert r["ok"] is True and r["pageCount"] == 1 and r["unredacted"] is False
    assert r["pages"][0]["page"] == 1 and r["pages"][0]["width"] == 612.0
    assert list(r["guard"]) == ["policy", "threshold", "discarded", "findings"]


def test_the_options_are_php_s_and_no_others() -> None:
    assert list(inspect.signature(fp.read).parameters) == ["data", "policy", "threshold", "excerpts", "limits", "words"]
    # read_unredacted cannot be talked back into redacting: it has no policy.
    assert list(inspect.signature(fp.read_unredacted).parameters) == ["data", "threshold", "excerpts", "limits", "words"]
    with pytest.raises(ValueError, match="Unknown policy"):
        fp.read(pdf(), policy="ignore")
    with pytest.raises(ValueError, match="Unknown threshold"):
        fp.read(pdf(), threshold="extreme")
    with pytest.raises(ValueError, match="Unknown limit"):
        fp.read(pdf(), limits={"maxBananas": 1})


def test_reads_from_a_path_too(tmp_path: Path) -> None:
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf())
    assert fp.read(str(p))["pageCount"] == 1
    assert fp.page_count(p) == 1
    assert fp.read(str(p), limits={"maxFileBytes": 10})["refused"]["reason"] == "too_large"


def test_the_host_surface() -> None:
    d = Document.open(pdf())
    assert [p["number"] for p in d.pages()] == [1]
    assert set(d.pages()[0]) == {"number", "width", "height", "rotate", "mediaBox", "cropBox"}
    assert d.page_text(1)["text"] == "Hello World" and d.text(1) == "Hello World"
    assert set(d.page_text(1)) == {"text", "spans", "runs"}
    assert [w["text"] for w in d.page_words(1)] == ["Hello", "World"]
    with pytest.raises(IndexError):
        d.page_text(0)


def test_reports_the_php_release_it_matches() -> None:
    assert fp.version() == {"version": "0.1.0", "phpReference": "0.7.0"}


def test_nothing_in_src_can_execute_follow_or_fetch() -> None:
    banned = re.compile(r"^\s*(?:import|from)\s+(?:subprocess|socket|urllib|http|ftplib|smtplib|ssl|asyncio|multiprocessing|ctypes|pickle|marshal|shelve)\b|\bos\.(?:system|popen|exec|spawn|fork)|\beval\(|\bexec\(", re.M)
    for f in SRC.rglob("*.py"):
        assert not banned.search(f.read_text(encoding="utf-8")), f


def test_has_one_refusal_type_and_never_lets_another_escape_the_agent() -> None:
    assert issubclass(fp.RefusedException, Exception)
    r = fp.read(b"%PDF-1.7\n" + b"[" * 200_000)
    assert r["ok"] is False and r["refused"]["reason"] in fp.REASONS
