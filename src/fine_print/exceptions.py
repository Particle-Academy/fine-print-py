"""The one refusal type, and the internal ones that never leave the package."""

from __future__ import annotations

#: The stable machine codes, in PHP's order (``RefusedException::REASONS``).
REASONS = (
    "not_pdf",
    "corrupt",
    "encrypted",
    "too_large",
    "decompression_bomb",
    "too_deep",
    "too_many_objects",
    "too_many_pages",
    "too_many_operators",
    "time_budget",
    "memory_budget",
    "too_many_pixels",
)


class RefusedException(Exception):
    """The file was refused: not a PDF, damaged beyond repair, encrypted, or
    over one of the :class:`~fine_print.Limits`.

    ``reason`` is a stable machine code from :data:`REASONS`; the message is
    for humans and never quotes the file's own content.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


class PdfSyntaxError(Exception):
    """Internal: the bytes are not valid PDF syntax here. The document layer
    decides whether that is repairable or a refusal."""


class OpaqueStream(Exception):
    """Internal: an image codec or crypt filter this reader keeps as bytes."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Stream is {name}-encoded and is kept as opaque bytes.")
        self.filter = name
