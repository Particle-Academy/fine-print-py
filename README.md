# fancy-fine-print

The Python port of [particle-academy/fine-print](https://github.com/Particle-Academy/fine-print)'s
PDF **reader**: text in reading order, per-word boxes, and an agent-read guard
against prompt injection, with every hostile-input guard of the PHP reference.
Zero runtime dependencies: the standard library only, including our own RC4
and AES.

**Status: 0.1.0, pre-1.0, reader only.** There is no writer and no renderer
yet; they follow. Pre-1.0, a minor release may change the API.

```
pip install fancy-fine-print
```

```python
import fine_print

result = fine_print.read(pdf_bytes, words=True)
if result["ok"]:
    for page in result["pages"]:
        print(page["page"], page["width"], page["height"])
        print(page["text"])
        for w in page["words"]:          # {text, x0, x1, top, bottom}
            ...
else:
    print(result["refused"]["reason"])   # e.g. "decompression_bomb"
```

Python 3.11 or later. Install as `fancy-fine-print`, import as `fine_print`.

## Parity with PHP

This package reproduces **PHP fine-print 0.7.0**'s reader
(`fine_print.version()` says so). Parity is a test result, not a claim:
`tests/test_parity_php.py` runs PHP fine-print and this port over the same
801 PDFs, harvested from PHP's own test suite (every file PHP's tests open,
with the limits they open it under), through six read variants, and requires
the results to be equal: text, findings, notices, refusals and messages
exactly, words and page geometry within 1e-6 pt. CI runs it on Linux and
Windows against the PHP checkout pinned at `v0.7.0`, and a missing PHP fails
the run.

The agent-facing texts are PHP's verbatim, including the redaction notice that
names `Agent::readUnredacted()`; in Python that call is `read_unredacted()`.

## The agent surface

`read(data, *, policy="redact", threshold="medium", excerpts=False, limits=None, words=False)`

- `data`: PDF bytes, or a path.
- `policy`: `redact` (default) cuts instructions and hidden text at or above
  the threshold, replacing them with `[fine-print: ...]` markers and removing
  invisible characters; `flag` leaves the text and attaches findings;
  `discard` withholds all content if anything reaches the threshold.
- `threshold`: `low`, `medium` (default) or `high`.
- `excerpts`: include the offending text in each finding. For a human audit
  log only: an excerpt of an injection is one.
- `limits`: a `Limits`, or a dict of PHP's names (`{"maxFileBytes": ...}`).
- `words`: also give each page `words`.

The result: `ok`, `version`, `pageCount`, `repaired`, `pages`
(`{page, width, height, text, words?}`), `metadata`, `outline`,
`annotations`, `activeContent`, `warnings`, `guard`, `redacted`,
`unredacted`, `notice`, `encryption`. A refused file returns
`{"ok": False, "refused": {"reason", "message"}}`; bad options raise.

`read_unredacted(data, *, threshold, excerpts, limits, words)` is the
deliberate second step: the same read, never redacted, with the findings
attached. It takes no `policy`, so it cannot be turned back into a redacting
read by accident; a host that must never show unredacted text does not expose
it.

`page_count(data, limits=None)` raises `RefusedException` on a refused file.

## Words

`{text, x0, x1, top, bottom}` per word, in reading order, in points on the
DISPLAYED page: origin at the top-left of the crop box after `/Rotate`, x to
the right, `top` and `bottom` measured down (`top < bottom`). A box runs from
its first glyph's origin to its last glyph's advance, through the text matrix
and the CTM, and from the font's descent to its ascent: the font descriptor's
`/Ascent` and `/Descent` when sane (an ascent in (0, 2000], a descent in
[-1000, 0]), else the standard-14 face the BaseFont names, else 0.8 / -0.2 em.
A word whose box is not finite is dropped.

Every word is a substring of its page's `text`. Pieces of separate runs join
only where the layout put them side by side with nothing between, never by
geometry, and under `redact` a word touching an instruction or hidden text is
dropped, and invisible characters are removed from inside a word, exactly as
from the text.

## The host surface

`Document.open(data, limits=None)` is the raw, unguarded view: `pages()`,
`page_text(n)` (`{text, spans, runs}`), `text(n)`, `page_words(n)`,
`metadata()`, `xmp()`, `outline()`, `annotations(n)`, `active_content()`,
`encryption()`, `warnings()`, `repaired()`. Hidden text is included and
nothing is redacted: never hand it to an agent.

## Guards

Every byte of a PDF is attacker-authored. Each limit refuses with a
`RefusedException` whose `reason` is one of `fine_print.REASONS`, never a
crash, a hang or a partial result:

| limit (PHP name) | default | reason |
|---|---|---|
| `maxFileBytes` | 256 MB | `too_large` |
| `maxObjects` | 1 000 000 | `too_many_objects` |
| `maxDepth` | 64 | `too_deep` |
| `maxStreamBytes` | 64 MB | `too_large` |
| `maxRatio` above `ratioFloorBytes` | 1500 above 1 MB | `decompression_bomb` |
| `maxTotalDecodedBytes` | 512 MB | `too_large` |
| `maxOperators` | 2 000 000 | `too_many_operators` |
| `maxFormDepth` | 12 | (skipped, with a warning) |
| `maxPages` | 50 000 | `too_many_pages` |
| `timeSeconds` | 30 | `time_budget` |
| `memoryBytes` | 256 MB | `memory_budget` |

Decompression is judged while it runs, in 4 KB chunks. Memory is accounted,
not measured: the reader holds what it keeps alive at costs modelled on PHP's,
so a read near `memoryBytes` may refuse at a slightly different point than PHP.

Encrypted files open with the empty user password only (RC4, AES-128,
AES-256); anything needing a password is refused as `encrypted`. Nothing
executes, follows or fetches: active content is reported by kind, location,
length and SHA-256, never its body.

## What is not here (yet)

- The writer, the renderer and page serving (later phases).
- Exchange (`extract`, `export`, portable content).
- Unsupported in PHP's text path and therefore here: CFF/Type 3 glyph
  programs are never run, image codecs (DCT, JPX, CCITT, JBIG2) are kept as
  opaque bytes, vertical writing is read as horizontal, and multi-column
  pages read row by row across the columns.

## License

MIT
