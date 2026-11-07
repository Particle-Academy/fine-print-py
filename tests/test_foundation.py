"""The claims this repository makes about itself.

1. It reproduces a NAMED PHP release, and the PHP checkout the oracle uses is
   that release (plan section 6: pinned, with a test asserting the ref).
2. It has zero runtime dependencies.
3. Its version is stated once.

A missing PHP reference is a FAILURE, never a skip (plan decision D12): the
live oracle must not be able to pass by not running.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import _oracle
from fine_print import PHP_REFERENCE, VERSION, version

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_names_the_php_release_it_ports_and_the_oracle_runs_exactly_that() -> None:
    _binary, src = _oracle.require_oracle()
    agent = (src / "Agent.php").read_text(encoding="utf-8")
    declared = re.search(r"const VERSION = '([^']+)';", agent)
    assert declared is not None
    assert declared.group(1) == PHP_REFERENCE


def test_ci_checks_out_that_release() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert f"ref: v{PHP_REFERENCE}" in ci


def test_has_no_runtime_dependencies() -> None:
    assert PYPROJECT["project"]["dependencies"] == []


def test_states_its_version_once() -> None:
    assert PYPROJECT["project"]["version"] == VERSION
    assert version() == {"version": VERSION, "phpReference": PHP_REFERENCE}
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    first = re.search(r"^## \[(\d[^\]]*)\]", changelog, re.M)
    assert first is not None and first.group(1) == VERSION
