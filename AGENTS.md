# AGENTS.md — fine-print-py

This file describes **this repository's code**: what it is, the invariants it
must keep, and the traps in porting to it. Process rules (publishing, version
policy, backports) live in the envelope's `RULES.md` and are never copied here.

## What this is

`fancy-fine-print` (import `fine_print`): the Python port of PHP
`particle-academy/fine-print`. **Its reader is a port of fine-print 0.7.0's**
(`PHP_REFERENCE` in `src/fine_print/__init__.py`), and parity is a test
result, not a claim: `tests/test_parity_php.py` runs PHP and this port over
the harvested corpus and requires equal results.

**Status: 0.1.0, the READER only** (owner, 2026-11-07, council CC-fancy-0010:
"we need a python fine print, not force them to use php"; the first consumer
is LiftPoint's Python engine, which replaces pdfplumber's `extract_words`).
This reverses the plan's writer-first order. The writer (phase W), the
renderer (X1 to X4) and page serving (S) are still to come; the plan is the
envelope's `.ai/plans/fine-print-ports.md`. The writer conformance rows below
(`writer-model`, `writer-bytes`) are not run yet: there is no writer to run.

## The reader (0.1.0)

Module map, each mirroring a PHP class: `parser` (Parser, ITERATIVE),
`filters` (Filters), `limits` (Limits, Budget), `document` (Document),
`agent` (Agent's read half), `text/` (Encodings from generated tables, CMap,
Font, TextExtractor as `extractor`, Layout, Words, TextString), `security/`
(AgentReadGuard as `guard`, InstructionPatterns, ActiveContentScanner as
`active`, StandardSecurity as `standard`), `crypto/` (Aes, Rc4), `_php`
(every PHP behaviour reproduced, each probed against PHP 8.4).

- **Offsets are characters, PHP's are bytes.** Every text in the reader is
  valid UTF-8 (mbstring-scrubbed), so a byte offset in PHP and a character
  offset here name the same place, and the reports PHP converts to characters
  come out equal. Do not mix the two: spans, word ranges and guard ranges are
  all characters.
- **Names and keys are Latin-1 `str`**; turn one into report text with
  `objects.name_text` (UTF-8, scrubbed), as PHP's json output of raw bytes.
- **`??` is not `or`.** PHP's null-coalescing keeps `''` and `0`; use an
  explicit `is None` (`extractor._arg`). `min`/`max` are `_php.pmin`/`pmax`
  (PHP's NAN behaviour), comparisons are `_php.cmp`.
- **Memory is accounted (D7).** `Budget.hold()`: content as it is joined,
  cached objects, runs (`RUN_COST`), pieces (`PIECE_COST`), words
  (`WORD_COST`); `Document.page_text` and friends restore the account on
  return; `agent.read` keeps it for the whole read, as PHP's growth does.
  Adding a structure that a file can grow means holding it.
- **The corpus is harvested, never built here.** `scripts/harvest_php_corpus.php`
  records every `Document::open` PHP's suite makes. Re-harvest when the PHP
  reference moves, and update `PHP_REFERENCE`, the CI pin and
  `tests/oracle/heavy.json` with it.
- **`scripts/gen_encodings.php` generates `text/_encoding_data.py`.** Never
  retype a table.

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
