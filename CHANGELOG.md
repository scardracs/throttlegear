# Changelog

All notable changes to the ThrottleGear project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] - 2026-06-21

### Added
- **CLI Optional Output Value**: Made the `-o` / `--output` command line argument optional. When used as a valueless flag, the output filename is derived automatically from the input XML's cryptography status (appending or replacing the `_decrypted` or `_encrypted` suffix while preserving directory structures).
- **Superseded Model Matching**: The patch generator now detects when a laptop's board name is superseded by a broader prefix match already in `asus-armoury.h` (e.g. `GU604V` matching `GU604VI`), reporting it to the user.
- **In-Place Driver Quirk Updates**: Rewrote the quirk entry replacement engine to perform in-place updates of `asus-armoury.h` table entries. This preserves the original field ordering, indentation, comments, and extra fields (such as default limit values) present in the mainline header, generating minimal and clean contribution diffs.
- **Developer Documentation**: Added `Documentation/CODEBASE.md` outlining module architecture and responsibilities of each file in `src/`. Restructured `Documentation/DETAILS.md` into logical sections starting with XML specifications and followed by Rust tool implementation details.

---

## [0.2.0] - 2026-06-20

### Added
- **Intel CPU Support**: Added support for Intel CPU limits extraction, parsing the Intel-specific `<PL1>` and `<PL2>` XML tags in addition to the AMD-specific `<STAPM>` and `<PPTLimit>` tags.
- **Makefile Build Automation**: Added a `Makefile` to automate compilation and naming of versioned binaries (e.g. `ThrottleGear-$(VERSION)`).

### Removed
- **Redundant build.rs script**: Removed the obsolete `build.rs` script.

---

## [0.1.0] - 2026-06-20

### Added
- **Rust Migration**: Complete migration from Python to Rust, rewriting all core cryptographic, XML processing, and quirk extraction logic to form a standalone utility.
- **Zero Crate Dependencies**: The tool is compiled without third-party crates, utilizing standard library modules and direct FFI bindings to the system's pre-installed OpenSSL `libcrypto` library.
- **CLI Enhancements**: Added multi-word username parsing (e.g., `-U First Last`) for patch author metadata formatting.
- **Unit Testing**: Introduced a unit test suite covering Base64 codecs, key/IV derivation, and AES CBC cryptors.
