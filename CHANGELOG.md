# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-01-29

### Changed

- Various structs resynchronized with recent Keystone changes.
- Enclave loading is now done using Keystone runtime loader binary.
- The loader ELF file (note: not text section loader.bin) given as a parameter.

### Added

- The version has been tested with a real hardware (StarFive VisionFive2).

### Removed

- Page table handling code has been removed as the loader is now used.

