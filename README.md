# fancy-fine-print

The Python port of [particle-academy/fine-print](https://github.com/Particle-Academy/fine-print):
a zero-dependency PDF writer, reader and renderer for agentic documents. It
writes PDF from the last-word JSON document model, never writes active content,
and reads hostile PDFs with an agent-read guard against prompt injection.

**Status: not released.** This repository is at its foundation (phase W0). The
writer is the first phase to ship; until then there is nothing to install.

## Parity

This package targets **PHP fine-print 0.5.0**. Parity is measured, not claimed:
the shared `fine-print/*` suites in
[fancy-conformance](https://github.com/Particle-Academy/fancy-conformance) are
exported from the PHP reference, and CI runs them here on Linux and Windows,
with the PHP writer as a live oracle.

## Requirements

Python 3.11 or later. No runtime dependencies. Install as `fancy-fine-print`, import as `fine_print`.

## License

MIT
