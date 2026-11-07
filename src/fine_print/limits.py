"""Hostile-input limits and the running budget against them.

Every default, and every refusal reason and message, is PHP's
(``FinePrint\\Limits``, ``FinePrint\\Budget``).

**Memory is accounted, not measured** (plan decision D7). PHP compares
``memory_get_usage()`` growth with ``memoryBytes``; Python has no cheap
equivalent, so the reader *holds* what it keeps alive (decoded content, cached
objects, text runs, word pieces, words) at costs modelled on PHP's own, and the
same checks compare that account with the same limit. PHP's second check, the
headroom under ``memory_limit``, has no Python counterpart and is not ported.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, fields, replace
from typing import Any

from ._php import float_str
from .exceptions import RefusedException

#: PHP's argument names, the form agent tool options arrive in, to attributes.
_PHP_NAMES = {
    "maxFileBytes": "max_file_bytes",
    "maxObjects": "max_objects",
    "maxDepth": "max_depth",
    "maxStreamBytes": "max_stream_bytes",
    "maxTotalDecodedBytes": "max_total_decoded_bytes",
    "maxRatio": "max_ratio",
    "ratioFloorBytes": "ratio_floor_bytes",
    "maxOperators": "max_operators",
    "maxFormDepth": "max_form_depth",
    "maxPages": "max_pages",
    "timeSeconds": "time_seconds",
    "memoryBytes": "memory_bytes",
    "maxRenderPixels": "max_render_pixels",
    "renderTimeSeconds": "render_time_seconds",
    "maxImagePixels": "max_image_pixels",
}

_FLOATS = {"max_ratio", "time_seconds", "render_time_seconds"}


@dataclass(frozen=True)
class Limits:
    """Breaching any one refuses the file with a :class:`RefusedException`."""

    max_file_bytes: int = 256 * 1024 * 1024
    max_objects: int = 1_000_000
    max_depth: int = 64
    max_stream_bytes: int = 64 * 1024 * 1024
    max_total_decoded_bytes: int = 512 * 1024 * 1024
    max_ratio: float = 1500.0
    ratio_floor_bytes: int = 1024 * 1024
    max_operators: int = 2_000_000
    max_form_depth: int = 12
    max_pages: int = 50_000
    time_seconds: float = 30.0
    memory_bytes: int = 256 * 1024 * 1024
    max_render_pixels: int = 25_000_000
    render_time_seconds: float = 30.0
    max_image_pixels: int = 16_000_000

    def __post_init__(self) -> None:
        # PHP's typed, strict_types constructor: an int field takes only an
        # int (never a bool or a float); a float field takes an int or float.
        for f in fields(self):
            v = getattr(self, f.name)
            if f.name in _FLOATS:
                if type(v) not in (int, float):
                    raise TypeError(f'Limit "{f.name}" must be a number.')
                object.__setattr__(self, f.name, float(v))
            elif type(v) is not int:
                raise TypeError(f'Limit "{f.name}" must be an integer.')

    def with_(self, **changes: Any) -> Limits:
        return replace(self, **changes)

    @staticmethod
    def from_value(v: Limits | dict[str, Any] | None) -> Limits:
        """A Limits, None (the defaults) or a dict of PHP's argument names
        (``{"maxFileBytes": 10}``), the form agent tool options arrive in."""
        if isinstance(v, Limits):
            return v
        if v is None:
            return Limits()
        if not isinstance(v, dict):
            raise TypeError("limits must be a Limits, a dict or None.")
        kwargs: dict[str, Any] = {}
        for k, value in v.items():
            if k not in _PHP_NAMES:
                raise ValueError(f'Unknown limit "{k}".')
            kwargs[_PHP_NAMES[k]] = value
        return Limits(**kwargs)


class Budget:
    """The running account against :class:`Limits` for one open document."""

    def __init__(self, limits: Limits, activity: str = "Reading") -> None:
        self.limits = limits
        self._activity = activity
        self._deadline = time.perf_counter_ns() + int(limits.time_seconds * 1e9)
        self._decoded = 0
        self._ticks = 0
        #: bytes held alive by the reader (D7): PHP's memory_get_usage() growth.
        self.live = 0

    # --- accounting ----------------------------------------------------------

    def hold(self, n: int) -> None:
        self.live += n

    def release(self, n: int) -> None:
        self.live -= n

    # --- checks -----------------------------------------------------------------

    def tick(self, n: int = 1) -> None:
        self._ticks += n
        if self._ticks >= 512:
            self._ticks = 0
            self._guard(0)

    def check(self) -> None:
        self._guard(0)

    def allocation(self, nbytes: float) -> None:
        self._guard(nbytes)

    def _guard(self, nbytes: float, extra: int = 0) -> None:
        if time.perf_counter_ns() > self._deadline:
            raise RefusedException(
                "time_budget",
                f"{self._activity} took longer than the {float_str(self.limits.time_seconds)}s time budget.",
            )
        growth = self.live + extra
        mem = self.limits.memory_bytes
        if growth > mem:
            raise RefusedException(
                "memory_budget", f"{self._activity} needed more than the {mem}-byte memory budget."
            )
        if not math.isfinite(float(nbytes)) or nbytes < 0 or nbytes > mem - growth:
            raise RefusedException(
                "memory_budget", f"{self._activity} would exceed the available memory during allocation."
            )

    def decoding(self, out_bytes: int, in_bytes: int, need_bytes: int = 0) -> None:
        """One filter stage's output, judged against the byte cap and the ratio.

        ``need_bytes`` is the stage's worst-case allocation. The stage's output
        is counted as live while it is judged, as PHP's measured growth counts it.
        """
        lim = self.limits
        if out_bytes > lim.max_stream_bytes:
            raise RefusedException("too_large", f"A stream decodes past the {lim.max_stream_bytes}-byte limit.")
        if out_bytes > lim.ratio_floor_bytes and out_bytes > lim.max_ratio * max(1, in_bytes):
            raise RefusedException(
                "decompression_bomb",
                f"A stream expands more than {float_str(lim.max_ratio)} times: a decompression bomb.",
            )
        self._guard(need_bytes, out_bytes if need_bytes else 0)

    def decoded(self, nbytes: int) -> None:
        self._decoded += nbytes
        if self._decoded > self.limits.max_total_decoded_bytes:
            raise RefusedException(
                "too_large", f"Streams decode past the {self.limits.max_total_decoded_bytes}-byte total limit."
            )
