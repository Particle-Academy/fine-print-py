"""PHP's guard tests, ported: every hostile file must end in a CLEAN outcome,
a refusal with PHP's reason, or a repaired read. Never a crash, never a hang.

Fixtures are the PHP suite's own (looked up by the PHP test line that opened
them, see ``conftest.corpus_id``); each test names its PHP original.
"""

from __future__ import annotations

import time
import zlib
from typing import Any

import pytest

import _oracle
import fine_print as fp
from conftest import corpus_id
from fine_print import Document, Limits, RefusedException
from fine_print.filters import decode_chain
from fine_print.limits import Budget


def refusal(fn: Any) -> str | None:
    try:
        fn()
    except RefusedException as e:
        return e.reason
    return None


def case(origin: str, index: int = 0) -> tuple[bytes, Limits]:
    cid = corpus_id(origin, index)
    return _oracle.case_bytes(cid), Limits.from_value(_oracle.case_limits(cid))


# --- the limits themselves -------------------------------------------------------


def test_the_limits_and_reasons_are_php_s() -> None:
    lim = Limits()
    assert (lim.max_file_bytes, lim.max_objects, lim.max_depth) == (256 << 20, 1_000_000, 64)
    assert (lim.max_stream_bytes, lim.max_total_decoded_bytes) == (64 << 20, 512 << 20)
    assert (lim.max_ratio, lim.ratio_floor_bytes) == (1500.0, 1 << 20)
    assert (lim.max_operators, lim.max_form_depth, lim.max_pages) == (2_000_000, 12, 50_000)
    assert (lim.time_seconds, lim.memory_bytes) == (30.0, 256 << 20)
    assert lim.max_ratio > 1363.0  # above a conforming LZW run (owner ruling 2026-11-03)
    assert fp.REASONS == (
        "not_pdf", "corrupt", "encrypted", "too_large", "decompression_bomb", "too_deep",
        "too_many_objects", "too_many_pages", "too_many_operators", "time_budget", "memory_budget", "too_many_pixels",
    )


def test_limits_take_php_s_names_and_refuse_unknown_ones() -> None:
    assert Limits.from_value({"maxFileBytes": 10}).max_file_bytes == 10
    assert Limits.from_value({"timeSeconds": 1}).time_seconds == 1.0
    with pytest.raises(ValueError, match='Unknown limit "maxBananas"'):
        Limits.from_value({"maxBananas": 1})
    with pytest.raises(TypeError):
        Limits(max_objects=1.5)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Limits(max_objects=True)


# --- refusals (HostileInputTest) ---------------------------------------------------


def test_refuses_something_that_is_not_a_pdf() -> None:
    assert refusal(lambda: Document.open(b"PK\x03\x04 this is a zip")) == "not_pdf"
    r = fp.read(b"just some text")
    assert r["ok"] is False and r["refused"]["reason"] == "not_pdf"
    assert set(r) == {"ok", "refused"} and isinstance(r["refused"]["message"], str)


def test_stops_a_decompression_bomb_at_the_byte_cap_quickly() -> None:
    # HostileInputTest: 'stops a decompression bomb at the byte cap'
    data, _ = case("DecompressionRatioTest.php:184")
    t = time.perf_counter()
    r = fp.read(data)
    assert r["ok"] is False and r["refused"]["reason"] == "too_large"
    assert str(Limits().max_stream_bytes) in r["refused"]["message"]
    assert time.perf_counter() - t < 10.0


def test_refuses_a_bomb_no_conforming_filter_could_produce_on_ratio_alone() -> None:
    data, _ = case("HostileInputTest.php:68")
    r = fp.read(data)
    assert r["refused"]["reason"] == "decompression_bomb"
    assert "1500" in r["refused"]["message"]


def test_caps_a_decoded_stream_at_its_size_limit_even_when_the_ratio_looks_innocent() -> None:
    data, lim = case("HostileInputTest.php:84")
    assert lim.max_stream_bytes == 1 << 20
    assert refusal(lambda: Document.open(data, lim).text(1)) == "too_large"


def test_refuses_a_file_over_the_size_limit_before_parsing_it() -> None:
    data, lim = case("HostileInputTest.php:88")
    assert refusal(lambda: Document.open(data, lim)) == "too_large"


def test_refuses_nesting_deeper_than_the_limit_without_recursing() -> None:
    data, _ = case("HostileInputTest.php:95")
    assert fp.read(data)["refused"]["reason"] == "too_deep"
    data, _ = case("HostileInputTest.php:103")
    assert refusal(lambda: Document.open(data).text(1)) == "too_deep"


def test_parses_far_past_the_recursion_limit_when_the_host_raises_max_depth() -> None:
    # The parser is iterative: 5 000 nested arrays at a raised depth limit are
    # a value, not a RecursionError.
    data, _ = case("HostileInputTest.php:95")
    r = fp.read(data, limits={"maxDepth": 10_000})
    assert r["ok"] is True


def test_refuses_more_objects_than_the_limit() -> None:
    data, lim = case("HostileInputTest.php:109")
    assert refusal(lambda: Document.open(data, lim)) == "too_many_objects"


def test_refuses_an_absurd_xref_stream_declaration_before_allocating() -> None:
    data, _ = case("HostileInputTest.php:120")
    t = time.perf_counter()
    assert refusal(lambda: Document.open(data)) == "too_many_objects"
    assert time.perf_counter() - t < 2.0


def test_refuses_a_page_with_more_operators_than_the_limit() -> None:
    data, lim = case("HostileInputTest.php:127")
    assert lim.max_operators == 10_000
    assert refusal(lambda: Document.open(data, lim).text(1)) == "too_many_operators"


def test_counts_operators_on_the_words_path() -> None:
    data, lim = case("WordsTest.php:396")
    assert refusal(lambda: Document.open(data, lim).page_words(1)) == "too_many_operators"


def test_stops_at_the_time_budget() -> None:
    data, lim = case("HostileInputTest.php:133")
    assert refusal(lambda: Document.open(data, lim).text(1)) == "time_budget"


def test_stops_at_the_time_budget_inside_one_show_string() -> None:
    data, lim = case("HostileInputTest.php:260")
    t = time.perf_counter()
    r = fp.read(data, limits=lim)
    assert r["refused"]["reason"] == "time_budget"
    assert time.perf_counter() - t < 3.0


def test_stops_at_the_memory_budget() -> None:
    data, lim = case("HostileInputTest.php:144")
    assert lim.memory_bytes == 2 << 20
    assert refusal(lambda: Document.open(data, lim).text(1)) == "memory_budget"


def test_refuses_when_the_words_outgrow_the_memory_budget() -> None:
    data, lim = case("WordsTest.php:405")
    assert Document.open(data, lim).page_text(1)["text"].startswith("a a a")
    assert refusal(lambda: Document.open(data, lim).page_words(1)) == "memory_budget"
    r = fp.read(data, words=True, limits=lim)
    assert r["refused"]["reason"] == "memory_budget"


def test_ends_several_flat_streams_on_one_page_in_a_refusal_never_a_crash() -> None:
    # DecompressionRatioTest's eight 60 MB flat streams, read by the PHP child.
    cid = "773357d0ec14b1df"
    assert _oracle.manifest_cache()[cid]["origin"] == "agent-read-child.php:23"
    r = fp.read(_oracle.case_bytes(cid))
    assert r["ok"] is False and r["refused"]["reason"] in ("too_large", "memory_budget")


def test_refuses_a_password_and_a_stub_encryption_dictionary() -> None:
    data, _ = case("HostileInputTest.php:272")
    assert refusal(lambda: Document.open(data)) == "encrypted"
    data, _ = case("HostileInputTest.php:280")
    assert refusal(lambda: Document.open(data)) == "corrupt"


def test_refuses_garbage_after_a_header() -> None:
    assert refusal(lambda: Document.open(b"%PDF-1.7\nnot an object in sight\n%%EOF\n")) == "corrupt"
    assert fp.read(b"%PDF-1.7\nnope")["refused"]["reason"] == "corrupt"
    with pytest.raises(RefusedException):
        fp.page_count(b"%PDF-1.7\nnope")


# --- the decompression ratio (DecompressionRatioTest) ----------------------------


def test_reads_flat_content_at_deflate_s_own_ceiling() -> None:
    bomb = zlib.compress(b" " * (32 << 20), 9)
    assert (32 << 20) / len(bomb) > 1000.0
    assert len(decode_chain(["FlateDecode"], bomb)) >= 32 << 20


def test_holds_the_byte_cap_inside_an_ascii85_stage() -> None:
    budget = Budget(Limits(max_stream_bytes=1 << 20))
    with pytest.raises(RefusedException) as e:
        decode_chain(["ASCII85Decode"], b"z" * (8 << 20), [], budget)
    assert e.value.reason == "too_large"


@pytest.mark.parametrize("index", range(4))
def test_holds_the_byte_cap_through_every_filter_chain(index: int) -> None:
    data, _ = case("DecompressionRatioTest.php:193", index)
    r = fp.read(data)
    assert r["ok"] is False and r["refused"]["reason"] == "too_large"


class _Watching(Budget):
    """Records the largest stage output any check saw."""

    def __init__(self, limits: Limits) -> None:
        super().__init__(limits)
        self.largest = 0

    def decoding(self, out_bytes: int, in_bytes: int, need_bytes: int = 0) -> None:
        self.largest = max(self.largest, out_bytes)
        super().decoding(out_bytes, in_bytes, need_bytes)


def test_stops_flate_while_it_expands_not_after() -> None:
    # 128 MB of zeros, judged per 4 KB of input, is stopped within one chunk's
    # output (deflate's ~1032:1 of 4 KB) of the 1 MB cap, never inflated whole.
    comp = zlib.compressobj(9)
    bomb = b"".join(comp.compress(b"\0" * (1 << 20)) for _ in range(128)) + comp.flush()
    budget = _Watching(Limits(max_stream_bytes=1 << 20))
    with pytest.raises(RefusedException) as e:
        decode_chain(["FlateDecode"], bomb, [], budget)
    assert e.value.reason == "too_large"
    assert budget.largest <= (1 << 20) + 4200 * 1024


def test_accounts_the_runs_a_page_holds() -> None:
    # The memory-budget fixture's content (6 MB) fits a 16 MB budget; its
    # 280 000 runs do not, as in PHP, where each run is an array.
    data, _ = case("HostileInputTest.php:144")
    lim = Limits(memory_bytes=16 << 20)
    assert refusal(lambda: Document.open(data, lim).text(1)) == "memory_budget"


# --- loops and repair ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("origin", "warning"),
    [
        ("HostileInputTest.php:302", "cycle"),
        ("HostileInputTest.php:313", "page tree"),
        ("HostileInputTest.php:322", "form"),
        ("HostileInputTest.php:333", "outline"),
    ],
)
def test_survives_cycles_and_says_so(origin: str, warning: str) -> None:
    data, _ = case(origin)
    doc = Document.open(data)
    doc.outline()
    doc.text(1)
    assert warning in " ".join(doc.warnings())


@pytest.mark.parametrize("origin", ["HostileInputTest.php:352", "HostileInputTest.php:360", "HostileInputTest.php:370", "HostileInputTest.php:379"])
def test_repairs_damaged_cross_reference_data(origin: str) -> None:
    data, _ = case(origin)
    doc = Document.open(data)
    assert doc.repaired() is True
    assert doc.text(1) != ""


def test_never_lets_a_python_error_escape_the_agent_surface() -> None:
    # Seeded byte flips over real fixtures: every result is a dict, ok or refused.
    import random

    rng = random.Random(7)
    ids = sorted(_oracle.manifest_cache())
    for cid in rng.sample(ids, 40):
        base = bytearray(_oracle.case_bytes(cid))
        if len(base) > 200_000:
            continue
        for _ in range(5):
            b = bytearray(base)
            for _ in range(rng.randint(1, 8)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            r = fp.read(bytes(b), words=True)
            assert isinstance(r, dict) and isinstance(r["ok"], bool)
            if not r["ok"]:
                assert r["refused"]["reason"] in fp.REASONS
