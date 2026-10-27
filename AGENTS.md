# AGENTS.md — fine-print-py

This file describes **this repository's code**: what it is, the invariants it
must keep, and the traps in porting to it. Process rules (publishing, version
policy, backports) live in the envelope's `RULES.md` and are never copied here.

## What this is

`fancy-fine-print` (import `fine_print`): the Python port of PHP
`particle-academy/fine-print`. **It is a port of fine-print 0.5.0**
(`PHP_REFERENCE` in `src/fine_print/__init__.py`), and parity is a test result, not a claim:
the `fine-print/*` suites in fancy-conformance are exported from PHP 0.5.0 and
this package must pass them row for row.

**Status: W0 (foundation).** No PDF code exists yet. The writer comes first
(phase W), then the reader (R), the renderer (X1 to X4) and page serving (S).
The plan is the envelope's `.ai/plans/fine-print-ports.md`.

- **Zero runtime dependencies.** The standard library only: `bytes`,
  `bytearray`, `memoryview`, `struct`, `zlib`, `hashlib` (md5 with
  `usedforsecurity=False`). `zlib.decompressobj().decompress(chunk,
  max_length)` mirrors PHP's 4 KB bomb judgement exactly. **Our own AES: the
  standard library has none**, plus RC4. Never the `cp1252`/`mac_roman`
  codecs: they are not PDF WinAnsi/MacRoman. Anything third-party (numpy
  included) is an approval request to the owner.
- **Never regenerate a conformance row.** The bytes are the contract. If a row
  looks wrong, the PHP reference is wrong or the port is; raise it, and the fix
  lands in PHP and is re-exported.
- **The PHP oracle is required.** CI checks out PHP fine-print at the pinned
  tag (`FINE_PRINT_PHP_SRC`), and a missing PHP fails the run (D12).

## The contract

| suite | what it pins |
|---|---|
| `fine-print/php-semantics` | the PHP behaviours a `php` helper module must reproduce: `%.4F` ties (half-to-even on exact ties), `round()` pre-rounding, `number_format`, mbstring `?` substitution, WinAnsi by table |
| `fine-print/writer-model` | validate, validateAndRepair, fromArray, describe, lint, jsonSchema, guide |
| `fine-print/writer-bytes` | the PDF: raw byte identity, or identity after `canon()` |

Normative text: fancy-conformance `suites/fine-print/SPEC.md` (file
references, `canon()`, tiers, the PHP empty-object rule, pixel tolerances).

## Invariants (restated from PHP; every one is enforced by rows)

1. `Agent` is the only agent surface; `Document` is the host's raw view.
2. Nothing executes, follows or fetches: no network or process API in `src`
   (a source-grep test will enforce it).
3. No attacker text in reports by default; scripts by length + SHA-256;
   excerpts only on request.
4. Names are compared decoded (`#xx`).
5. Every loop a file can lengthen is bounded, in the same change as the loop.
6. Refusals use the 12 REASONS, never a crash, hang or partial result. One
   refusal exception type.
7. Text streams through generators and never materialises.
8. Decompression is judged while it runs, in 4 KB chunks.
9. The extractor keeps hidden text; only the guard removes it.
10. Encryption: the empty password only; `secure()` before any resolve; never
    report key, O or U; our own RC4/AES.
11. Writer: nothing active is emitted; links are checked twice; model text is
    hex-only; names are sanitised; output is deterministic; images are bounded.
12. Renderer: pixels judged before allocating; operators counted; form depth
    and `q` stack capped; its own budget; everything undrawn reported.
13. Per-edge work is bounded by the canvas (`MAX_SEGMENTS`, `MAX_DASHES`,
    INF/NAN to 0).
14. Font cache and glyph limits; hinting is never executed.
15. Image bounds are checked before decoding; JPEG planes are checked.
16. Group/mask buffers are cropped before allocation.
17. Serving: authorise before the cache; never open client paths; checksummed
    packets, no `pickle`; the watermark fails closed.

## Python traps (plan section 5)

- **Recursion and escapes.** The recursion limit is 1000, so the parser is
  iterative. `RecursionError`, `MemoryError` and `OverflowError` must never
  escape `Agent`.
- **Bytes.** `b[i]` is an int and raises past the end, so forgiving-read
  helpers reproduce PHP; use `bytearray`/`memoryview`, never `list[int]`.
- **Arithmetic.** `%` and `//` floor while PHP truncates; `round` is
  half-to-even; `bool` is an int; ints are unbounded while PHP overflows to
  float. The `php-semantics` rows are the arbiter.
- **Codecs.** mbstring substitutes `?`, Python's `errors="replace"` gives
  U+FFFD, and the two differ in how many characters a bad sequence becomes.
- **zlib-ng.** CPython on Windows ships zlib-ng, so compressed bytes differ
  from PHP's; the canon tier is mandatory and CI includes Windows.
- **Memory and speed.** Memory is accounted, not measured (D7). The renderer
  is pure Python and measured (D1); its multiple is published, not hidden.
