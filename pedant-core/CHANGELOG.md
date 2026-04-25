# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.11.1...pedant-core-v0.12.0) - 2026-04-25

### Added

- *(cli)* [**breaking**] migrate to subcommands and cargo supply-chain

## [0.11.1](https://github.com/jostled-org/pedant/compare/pedant-core-v0.11.0...pedant-core-v0.11.1) - 2026-04-21

### Other

- release

## [0.11.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.10.0...pedant-core-v0.11.0) - 2026-04-20

### Added

- add supply chain check action and rewrite documentation
- [**breaking**] multi-language capability detection, semantic cache, and CLI stream fix

### Fixed

- bump pedant-types to 0.10.0 and register all crates with release-plz

## [0.10.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.9.0...pedant-core-v0.10.0) - 2026-04-02

### Added

- [**breaking**] add swallowed-ok and unobserved-spawn detection

## [0.9.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.8.0...pedant-core-v0.9.0) - 2026-03-28

### Added

- [**breaking**] high-param-count check, immutable-growable detection, structural duplicate tool

### Fixed

- eliminate dead_code warnings and add CI dependency caching
- *(test)* update data_flow_fact_default_empty for immutable-growable

## [0.8.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.7.1...pedant-core-v0.8.0) - 2026-03-26

### Other

- [**breaking**] split semantic.rs into submodules and fix audit findings

## [0.7.1](https://github.com/jostled-org/pedant/compare/pedant-core-v0.7.0...pedant-core-v0.7.1) - 2026-03-25

### Other

- *(deps)* bump ra_ap_* 0.0.324 → 0.0.325 and update lockfile

## [0.7.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.6.0...pedant-core-v0.7.0) - 2026-03-25

### Added

- [**breaking**] add data flow analysis with taint tracking and reachability

### Fixed

- match glob overrides against absolute paths and opt-in MCP semantic

## [0.6.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.5.1...pedant-core-v0.6.0) - 2026-03-23

### Other

- [**breaking**] audit fixes and single-crate MCP support

## [0.5.1](https://github.com/jostled-org/pedant/compare/pedant-core-v0.5.0...pedant-core-v0.5.1) - 2026-03-22

### Added

- add pedant-mcp server for MCP-based capability queries

## [0.5.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.4.0...pedant-core-v0.5.0) - 2026-03-22

### Added

- [**breaking**] add semantic analysis via ra_ap_ide with performance audit fixes

### Fixed

- *(ir)* remove unused SemanticContext parameter from enrich_method_calls

## [0.4.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.3.0...pedant-core-v0.4.0) - 2026-03-22

### Added

- [**breaking**] add gate rules engine for capability profile evaluation

## [0.3.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.2.0...pedant-core-v0.3.0) - 2026-03-22

### Added

- [**breaking**] expand key material pattern detection in string literals

## [0.2.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.1.1...pedant-core-v0.2.0) - 2026-03-21

### Added

- [**breaking**] auto-discover and analyze build scripts for capability detection

## [0.1.1](https://github.com/jostled-org/pedant/compare/pedant-core-v0.1.0...pedant-core-v0.1.1) - 2026-03-21

### Other

- *(pedant-core)* add missing doc comments and update CI for workspace
