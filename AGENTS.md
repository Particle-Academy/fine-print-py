# Using fancy-fine-print — guide for agents

How an agent installs and uses this package in a consumer app. What the package
is, is in [README.md](./README.md). Notes for working ON this repo's code are in
[CONTRIBUTING.md](./CONTRIBUTING.md).

## Install

```bash
pip install fancy-fine-print
```

- Install as `fancy-fine-print`, **import as `fine_print`**.
- **Python:** `>=3.11`. Zero runtime dependencies.
- **Reader only** (0.1.0). There is no writer or renderer yet; to write PDFs,
  use the PHP package `particle-academy/fine-print`.

## Find it on the Fancy MCP server

The catalog server is `https://ui.particle.academy/mcp` (streamable HTTP, no API
key; MCP id `fancy-ui`). The package is the registry entry `fine-print-py`;
find it with `search-backend-packages` (stack `python`), then
`install-instructions`.

## API essentials

- `fine_print.read(data, *, policy="redact", threshold="medium",
  excerpts=False, limits=None, words=False)`. `data` is PDF bytes or a path.
  Returns a dict: `ok`, `pages` (`{page, width, height, text, words?}`),
  `metadata`, `outline`, `annotations`, `activeContent`, `warnings`, `guard`,
  `redacted`, `notice`, ...
- `policy`: `redact` (default) cuts instructions and hidden text at or above
  `threshold` and leaves `[fine-print: ...]` markers; `flag` keeps the text
  and attaches findings; `discard` withholds everything if anything reaches the
  threshold.
- `words=True` adds `{text, x0, x1, top, bottom}` per word, in points on the
  displayed page, origin top-left, `top < bottom`.
- `read_unredacted(...)` is the deliberate unredacted read; it takes no
  `policy`.
- `page_count(data, limits=None)`; `Limits` (or a dict of PHP's names such as
  `{"maxFileBytes": ...}`); `fine_print.version()`.

## Traps

- **Check `result["ok"]` first.** A refused file does not raise from `read`:
  it returns `{"ok": False, "refused": {"reason", "message"}}`, with `reason`
  one of `fine_print.REASONS` (`decompression_bomb`, `too_large`,
  `encrypted`, ...). Bad options do raise. `page_count` raises
  `RefusedException`.
- **Never hand `Document.open(...)` output to an agent.** `Document` is the
  raw host view: hidden text included, nothing redacted. `read` is the agent
  surface.
- **`excerpts=True` is for a human audit log only**; an excerpt of an
  injection is one.
- Only expose `read_unredacted` where showing unredacted text is acceptable.
- Encrypted files open with the empty user password only; anything else is
  refused as `encrypted`.
- Multi-column pages read row by row across the columns; vertical writing is
  read as horizontal.
