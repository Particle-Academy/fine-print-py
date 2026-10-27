# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Pre-1.0, breaking changes land in MINOR releases.** The version number is not
promising otherwise until 1.0.

## [Unreleased]

### Added

- The repository foundation (plan phase W0): package manifest with zero runtime
  dependencies, `VERSION` / `PHP_REFERENCE` (`0.5.0`) / `version()`, CI on
  Linux and Windows across Python 3.11 to 3.13 against the PHP fine-print
  checkout pinned at `v0.5.0`, and a foundation test asserting that pin.
  Nothing is published until the writer (phase W) ships as `0.1.0`.
