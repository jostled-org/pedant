# Changelog

All notable changes to this project will be documented in this file.

## [0.7.2](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.7.1...pedant-lang-v0.7.2) - 2026-08-30

### Other

- updated the following local packages: pedant-types, pedant-syntax

## [0.7.1](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.7.0...pedant-lang-v0.7.1) - 2026-08-23

### Added

- *(syntax)* extract Go grammar facts once for every consumer

### Other

- hoist every duplicated language check into one owner

## [0.7.0](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.6.0...pedant-lang-v0.7.0) - 2026-08-18

### Added

- *(lang)* [**breaking**] attribute non-Rust capability findings to their callables

### Other

- give each attribution rule one owner and one query

## [0.5.0](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.4.0...pedant-lang-v0.5.0) - 2026-08-02

### Added

- [**breaking**] implement syntax-substrate-and-snippet-tool

### Fixed

- require pedant-syntax 0.2.0 so packaged builds use one pedant-types version

### Other

- *(lang)* split string analysis by concern
- *(lang)* cover retained syntax migration behavior

## [0.4.0](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.3.2...pedant-lang-v0.4.0) - 2026-07-18

### Fixed

- [**breaking**] honor .pedant.toml max_depth and stop counting closure nesting

## [0.3.2](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.3.1...pedant-lang-v0.3.2) - 2026-07-18

### Fixed

- *(capabilities)* stop reading OIDs, paths, and versions as network endpoints

## [0.3.1](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.3.0...pedant-lang-v0.3.1) - 2026-07-17

### Other

- *(lang)* split lib.rs into classify and analyze modules

## [0.3.0](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.2.0...pedant-lang-v0.3.0) - 2026-07-15

### Other

- *(deps)* [**breaking**] update workspace dependencies and raise MSRV to 1.96

## [0.2.0](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.1.2...pedant-lang-v0.2.0) - 2026-06-12

### Added

- [**breaking**] record skipped-file analysis errors in attestations

## [0.1.2](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.1.1...pedant-lang-v0.1.2) - 2026-04-25

### Other

- updated the following local packages: pedant-types

## [0.1.1](https://github.com/jostled-org/pedant/compare/pedant-lang-v0.1.0...pedant-lang-v0.1.1) - 2026-04-20

### Other

- updated the following local packages: pedant-types

## [0.1.0] - 2026-04-19

### Added

- Multi-language capability detection for Python, JavaScript/TypeScript, Go, and Bash
- Tree-sitter AST extraction with regex fallback per language
- Manifest analysis for package.json, setup.py, pyproject.toml, Makefile, justfile, and go:generate
- String literal scanning for endpoints, PEM blocks, key material, and credential prefixes
- Shebang-based language detection for extensionless scripts
