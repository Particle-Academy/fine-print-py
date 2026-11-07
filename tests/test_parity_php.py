"""Reader parity with PHP fine-print: the definition of done.

Every case of the harvested corpus (every PDF PHP's own suite opens, with its
Limits) is read by PHP and by this port, through six variants: ``read``,
``read`` with words, ``flag``/``low``/excerpts with words, ``discard``,
``readUnredacted`` with words, and the host view (``pages()``, per page
``pageText`` text and spans and ``pageWords``, metadata, XMP, outline, active
content, encryption, warnings). The results must be EQUAL, floats within
``_oracle.FLOAT_TOL``, page by page.

Two declared tiers, each named rather than hidden:

- cases opened under a non-default ``timeSeconds`` or ``memoryBytes`` compare
  the OUTCOME (ok, or the refusal reason): PHP measures time and memory, this
  port runs slower and ACCOUNTS memory (plan decision D7);
- cases in ``oracle/heavy.json`` (PHP over 3 s) run ``read`` and ``read-words``
  only.
"""

from __future__ import annotations

from typing import Any

import pytest

import _oracle
from conftest import HEAVY

CASES = sorted(_oracle.manifest_cache())


def test_the_corpus_is_the_php_suite_s_and_large_enough_to_mean_something() -> None:
    m = _oracle.manifest_cache()
    origins = {v["origin"].split(":")[0] for v in m.values()}
    # Not a toy set: hundreds of files from the reader, writer and renderer suites.
    assert len(m) > 700
    for suite in ("HostileInputTest.php", "WordsTest.php", "EncryptionTest.php", "TextExtractionTest.php", "AgentReadGuardTest.php"):
        assert suite in origins
    assert set(HEAVY) <= set(m)


def test_the_oracle_answered_every_case(php_results: dict[str, Any]) -> None:
    assert sorted(php_results) == CASES


@pytest.mark.parametrize("case_id", CASES)
def test_reads_like_php(case_id: str, php_results: dict[str, Any]) -> None:
    case = _oracle.manifest_cache()[case_id]
    budgeted = any(k in (case["limits"] or {}) for k in _oracle.BUDGETED)
    variants = php_results[case_id]
    assert "read" in variants
    problems = []
    for name, v in variants.items():
        php = v["result"]
        py = _oracle.run_python(case_id, name)
        if budgeted:
            if _oracle.outcome(php) != _oracle.outcome(py):
                problems.append(f"{name}: PHP {_oracle.outcome(php)} vs Python {_oracle.outcome(py)}")
            continue
        d = _oracle.diff(php, py)
        if d:
            problems.append(f"{name}: {d}")
    assert not problems, f"{case_id} ({case['origin']}): " + " | ".join(problems)
