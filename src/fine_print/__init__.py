"""fancy-fine-print: the Python port of PHP particle-academy/fine-print.

Phase W0 (foundation): this package has no PDF code yet. The contract it will
be held to is the ``fine-print/*`` suites in fancy-conformance, exported from
the PHP reference; see AGENTS.md.
"""

from __future__ import annotations

#: This package's own version. Independent of PHP's (plan decision D10).
VERSION = "0.0.0"

#: The PHP fine-print release this port reproduces, row for row.
PHP_REFERENCE = "0.5.0"

__version__ = VERSION
__all__ = ["PHP_REFERENCE", "VERSION", "version"]


def version() -> dict[str, str]:
    """``version()``, as PHP's ``Agent::version()``, plus the parity it claims."""
    return {"version": VERSION, "phpReference": PHP_REFERENCE}
