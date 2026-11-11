# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Pre-1.0, breaking changes land in MINOR releases.** The version number is not
promising otherwise until 1.0.

## [Unreleased]

### Changed

- **Releases need a lab-run certificate.** `publish.yml` gains a read-only
  `lab-certificate` job that every publishing job needs: a tag is published only
  when the fancy-labs lab has certified that exact version and commit. Consumers
  do nothing; this changes how releases are cut, not what the package does.

## [0.1.0] - 2026-11-07

The first release, and it is **the reader only**: there is no writer and no
renderer yet. It is a port of PHP fine-print 0.7.0's reader
(`PHP_REFERENCE = "0.7.0"`), held to PHP by a live oracle rather than by claim.
Pre-1.0: the API may still change in a minor release.

### Added

- `read(data, *, policy, threshold, excerpts, limits, words)` and
  `read_unredacted(data, *, threshold, excerpts, limits, words)`: PHP's
  `Agent::read` / `Agent::readUnredacted`, with the same result shape, the same
  redaction policies (`redact` by default, `flag`, `discard`), thresholds,
  findings, notices and refusals (`{"ok": false, "refused": {reason, message}}`).
  `words=True` gives each page `{text, x0, x1, top, bottom}` boxes, redacted as
  the page text is (the pdfplumber `extract_words` shape).
- `page_count(data, limits)`, which raises `RefusedException` as PHP's does.
- `Document`, the host's raw view: `open()`, `pages()`, `page_text(n)`,
  `text(n)`, `page_words(n)`, `page_text_with_words(n)`, `metadata()`,
  `xmp()`, `outline()`, `annotations(n)`, `active_content()`,
  `encryption()`, `warnings()`, `repaired()`, `version()`.
- Every PHP guard, with PHP's limits, reasons and messages: file bytes,
  objects, nesting depth, stream bytes, the decompression ratio and its floor,
  total decoded bytes, operators, form depth, pages, time and memory. One
  refusal type, `RefusedException`, and the 12 PHP reasons.
- Text extraction as PHP's: Flate, LZW, ASCII85, ASCIIHex and RunLength with
  the PNG and TIFF predictors; simple and Type0 fonts, the four base encodings,
  `/Differences` and glyph names, `ToUnicode` and encoding CMaps; `TJ`
  kerning and the layout's word and paragraph gaps; the CTM, `/Rotate` and the
  crop box; form XObjects; hidden, white, tiny and off-page text.
- Empty-password decryption (RC4, AES-128, AES-256; R2 to R6) with our own
  RC4 and AES, the active-content scanner and the agent-read guard.
- `tests/test_parity_php.py`: PHP fine-print and this port read the same 801
  files (harvested from PHP's own test suite by
  `scripts/harvest_php_corpus.php`) through six read variants and must agree,
  words within 1e-6 pt. A missing PHP fails the suite.

### Changed

- CI checks the PHP reference out at `v0.7.0` (was `v0.5.0`).

### Known differences from PHP

- Memory is ACCOUNTED, not measured (plan decision D7), so a read near
  `memoryBytes` may refuse at a slightly different point; PHP's second check,
  the headroom under `memory_limit`, has no Python counterpart.
- A page-tree warning about a direct (unreferenced) node names it by an object
  id, which differs between runtimes.
- Python bounds two loops PHP leaves unbudgeted (reported upstream): the
  painted-ground lookup behind white-text detection, and a cross-reference
  stream's rows when `/Index` holds a non-integer count.
