"""fancy-fine-print: the Python port of PHP particle-academy/fine-print.

This release is the READER only: open a PDF from bytes under every PHP guard,
extract text in reading order with per-word boxes, and read it for an agent
through the agent-read guard. Parity with the PHP reference is a test result
(``tests/test_parity_php.py``), not a claim. There is no writer yet.

Agent surface: :func:`read`, :func:`read_unredacted`, :func:`page_count`.
Host surface: :class:`Document` (``pages()``, ``page_text(n)``, ``page_words(n)``).
"""

from __future__ import annotations

from .agent import page_count, read, read_unredacted
from .document import Document
from .exceptions import REASONS, RefusedException
from .limits import Limits

#: This package's own version. Independent of PHP's (plan decision D10).
VERSION = "0.1.0"

#: The PHP fine-print release whose READER this port reproduces.
PHP_REFERENCE = "0.7.0"

__version__ = VERSION
__all__ = [
    "PHP_REFERENCE",
    "REASONS",
    "VERSION",
    "Document",
    "Limits",
    "RefusedException",
    "page_count",
    "read",
    "read_unredacted",
    "version",
]


def version() -> dict[str, str]:
    """``version()``, as PHP's ``Agent::version()``, plus the parity it claims."""
    return {"version": VERSION, "phpReference": PHP_REFERENCE}
