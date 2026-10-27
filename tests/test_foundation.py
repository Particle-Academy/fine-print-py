"""The W0 placeholder suite: the claims this repository makes before it has PDF code.

1. It reproduces a NAMED PHP release, and the PHP checkout CI uses is that
   release (plan section 6: pinned, with a test asserting the ref).
2. It has zero runtime dependencies.
3. Its version is stated once.

``FINE_PRINT_PHP_SRC`` is REQUIRED. A missing PHP reference is a failure, never
a skip (plan decision D12): the live oracle this becomes must not be able to
pass by not running.
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path

from fine_print import PHP_REFERENCE, VERSION, version

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_names_the_php_release_it_ports_and_ci_checked_out_exactly_that() -> None:
    src = os.environ.get("FINE_PRINT_PHP_SRC")
    assert src, "FINE_PRINT_PHP_SRC must point at the PHP fine-print src/ checkout"
    agent = (Path(src) / "Agent.php").read_text(encoding="utf-8")
    declared = re.search(r"const VERSION = '([^']+)';", agent)
    assert declared is not None
    assert declared.group(1) == PHP_REFERENCE


def test_has_no_runtime_dependencies() -> None:
    assert PYPROJECT["project"]["dependencies"] == []


def test_states_its_version_once() -> None:
    assert PYPROJECT["project"]["version"] == VERSION
    assert version() == {"version": VERSION, "phpReference": PHP_REFERENCE}
