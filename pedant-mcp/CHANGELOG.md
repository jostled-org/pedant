# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.1](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.14.0...pedant-mcp-v0.14.1) - 2026-08-23

### Other

- *(process-guard)* prove each row ran under the ceiling it stated

## [0.14.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.13.5...pedant-mcp-v0.14.0) - 2026-08-18

### Added

- *(lang)* [**breaking**] attribute non-Rust capability findings to their callables
- *(core)* [**breaking**] attribute Rust capability findings to their callables
- [**breaking**] implement module-boundary-integrity

### Other

- give each attribution rule one owner and one query
- *(mcp)* prove the watcher reindexes an edit to a live source
- *(mcp)* prove indexed attribution status comes from language analysis

## [0.13.5](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.13.4...pedant-mcp-v0.13.5) - 2026-08-13

### Fixed

- *(mcp)* preserve final watcher state

## [0.13.4](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.13.3...pedant-mcp-v0.13.4) - 2026-08-13

### Other

- updated the following local packages: pedant-core

## [0.13.3](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.13.2...pedant-mcp-v0.13.3) - 2026-08-13

### Other

- updated the following local packages: pedant-core

## [0.13.2](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.13.1...pedant-mcp-v0.13.2) - 2026-08-10

### Other

- updated the following local packages: pedant-core

## [0.13.1](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.13.0...pedant-mcp-v0.13.1) - 2026-08-10

### Other

- updated the following local packages: pedant-core

## [0.12.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.11.1...pedant-mcp-v0.12.0) - 2026-08-02

### Added

- [**breaking**] implement syntax-substrate-and-snippet-tool
- [**breaking**] implement analysis-surface-split

## [0.11.1](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.11.0...pedant-mcp-v0.11.1) - 2026-07-18

### Other

- updated the following local packages: pedant-core, pedant-lang

## [0.11.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.10.1...pedant-mcp-v0.11.0) - 2026-07-18

### Added

- *(mcp)* run the cross-file type-footprint check via threaded FileShapes
- *(checks)* [**breaking**] count high-method-count across files, add scattered-inherent-impl

### Fixed

- *(mcp)* [**breaking**] honor .pedant.toml, run project checks, and expose severity

### Other

- *(supply-chain)* gate on new-dependency to catch injected crates

## [0.10.1](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.10.0...pedant-mcp-v0.10.1) - 2026-07-17

### Other

- correct the README against what pedant actually does
- move definitions out of module roots into leaf modules

## [0.10.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.9.0...pedant-mcp-v0.10.0) - 2026-07-16

### Added

- *(checks)* [**breaking**] add feature-boundary check over Cargo metadata
- *(checks)* [**breaking**] add flat-module-family check
- *(checks)* [**breaking**] add project-level pass and conflicting-module-root check
- *(checks)* [**breaking**] add ungated-test-api check
- *(checks)* [**breaking**] add item-visibility-policy check
- *(checks)* [**breaking**] add forwarder-aware high-method-count check
- *(checks)* [**breaking**] add large-source-file check with warn/deny severity
- *(checks)* [**breaking**] add module-root-definitions check
- *(checks)* [**breaking**] add long-function-body check

## [0.9.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.8.0...pedant-mcp-v0.9.0) - 2026-07-15

### Other

- *(deps)* [**breaking**] update workspace dependencies and raise MSRV to 1.96

## [0.8.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.7.0...pedant-mcp-v0.8.0) - 2026-06-12

### Added

- [**breaking**] record skipped-file analysis errors in attestations

## [0.7.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.6.1...pedant-mcp-v0.7.0) - 2026-04-25

### Added

- *(cli)* [**breaking**] migrate to subcommands and cargo supply-chain

## [0.6.1](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.6.0...pedant-mcp-v0.6.1) - 2026-04-21

### Other

- release

## [0.6.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.5.1...pedant-mcp-v0.6.0) - 2026-04-20

### Added

- add supply chain check action and rewrite documentation
- [**breaking**] multi-language capability detection, semantic cache, and CLI stream fix

### Fixed

- bump pedant-types to 0.10.0 and register all crates with release-plz

## [0.5.1](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.5.0...pedant-mcp-v0.5.1) - 2026-04-02

### Other

- updated the following local packages: pedant-core

## [0.5.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.4.0...pedant-mcp-v0.5.0) - 2026-03-28

### Added

- [**breaking**] high-param-count check, immutable-growable detection, structural duplicate tool

## [0.4.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.3.1...pedant-mcp-v0.4.0) - 2026-03-26

### Other

- [**breaking**] split semantic.rs into submodules and fix audit findings

## [0.3.1](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.3.0...pedant-mcp-v0.3.1) - 2026-03-25

### Other

- update Cargo.lock dependencies

## [0.3.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.2.0...pedant-mcp-v0.3.0) - 2026-03-25

### Added

- [**breaking**] add data flow analysis with taint tracking and reachability

### Fixed

- match glob overrides against absolute paths and opt-in MCP semantic
- *(mcp)* drop SemanticContext after indexing to satisfy Sync bound

## [0.2.0](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.1.1...pedant-mcp-v0.2.0) - 2026-03-23

### Other

- fix formatting in query.rs and watcher.rs
- [**breaking**] audit fixes and single-crate MCP support

## [0.1.1](https://github.com/jostled-org/pedant/compare/pedant-mcp-v0.1.0...pedant-mcp-v0.1.1) - 2026-03-22

### Other

- release

## [0.1.0](https://github.com/jostled-org/pedant/releases/tag/pedant-mcp-v0.1.0) - 2026-03-22

### Added

- add pedant-mcp server for MCP-based capability queries
- [**breaking**] auto-discover and analyze build scripts for capability detection
- [**breaking**] add IR extraction, let-underscore-result check, and extract pedant-core library
- [**breaking**] add --diff flag to compare capability profiles

### Other

- separate linting and capability detection in README
- add attestation usage to README and capability detection guide
- add capability detection guide and update READMEs
- add generic-naming to README, examples, and fix CI glob
- rewrite README following org guidelines
- updated README and added example configs
- update install instructions to use crates.io
- pedant 0.1.0
