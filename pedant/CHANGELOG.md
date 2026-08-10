# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.27.2](https://github.com/jostled-org/pedant/compare/pedant-v0.27.1...pedant-v0.27.2) - 2026-08-10

### Other

- updated the following local packages: pedant-core

## [0.27.1](https://github.com/jostled-org/pedant/compare/pedant-v0.27.0...pedant-v0.27.1) - 2026-08-10

### Other

- updated the following local packages: pedant-core

## [0.26.0](https://github.com/jostled-org/pedant/compare/pedant-v0.25.0...pedant-v0.26.0) - 2026-08-02

### Added

- [**breaking**] implement syntax-substrate-and-snippet-tool
- [**breaking**] implement analysis-surface-split

## [0.25.0](https://github.com/jostled-org/pedant/compare/pedant-v0.24.0...pedant-v0.25.0) - 2026-07-18

### Fixed

- [**breaking**] honor .pedant.toml max_depth and stop counting closure nesting

## [0.24.0](https://github.com/jostled-org/pedant/compare/pedant-v0.23.0...pedant-v0.24.0) - 2026-07-18

### Added

- *(checks)* [**breaking**] count high-method-count across files, add scattered-inherent-impl

### Fixed

- *(supply-chain)* retain baselines for every concurrent crate version

### Other

- *(supply-chain)* gate on new-dependency to catch injected crates

## [0.23.0](https://github.com/jostled-org/pedant/compare/pedant-v0.22.0...pedant-v0.23.0) - 2026-07-17

### Added

- *(cli)* [**breaking**] resolve directory arguments and de-duplicate input files
- *(cli)* add github output format for check and gate

### Other

- correct the README against what pedant actually does
- *(cli)* split supply_chain.rs along its data pipeline

## [0.22.0](https://github.com/jostled-org/pedant/compare/pedant-v0.21.0...pedant-v0.22.0) - 2026-07-16

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

## [0.21.0](https://github.com/jostled-org/pedant/compare/pedant-v0.20.0...pedant-v0.21.0) - 2026-07-15

### Fixed

- *(supply-chain)* isolate tests from CI GITHUB_OUTPUT

### Other

- *(deps)* [**breaking**] update workspace dependencies and raise MSRV to 1.96

## [0.20.0](https://github.com/jostled-org/pedant/compare/pedant-v0.19.0...pedant-v0.20.0) - 2026-06-12

### Added

- [**breaking**] record skipped-file analysis errors in attestations
- *(supply-chain)* [**breaking**] surface rust-version in cargo attestations

## [0.19.0](https://github.com/jostled-org/pedant/compare/pedant-v0.18.1...pedant-v0.19.0) - 2026-04-25

### Added

- *(supply-chain)* follow mod declarations to hash only reachable source files
- *(cli)* [**breaking**] migrate to subcommands and cargo supply-chain

### Fixed

- *(supply-chain)* [**breaking**] separate hashing from dependency analysis
- *(supply-chain)* satisfy formatting and clippy checks
- *(supply-chain)* derive cargo inputs from package targets

## [0.18.1](https://github.com/jostled-org/pedant/compare/pedant-v0.18.0...pedant-v0.18.1) - 2026-04-21

### Other

- release

## [0.18.0](https://github.com/jostled-org/pedant/compare/pedant-v0.17.1...pedant-v0.18.0) - 2026-04-20

### Added

- add supply chain check action and rewrite documentation
- [**breaking**] multi-language capability detection, semantic cache, and CLI stream fix

### Fixed

- bump pedant-types to 0.10.0 and register all crates with release-plz

## [0.17.1](https://github.com/jostled-org/pedant/compare/pedant-v0.17.0...pedant-v0.17.1) - 2026-04-02

### Other

- updated the following local packages: pedant-core

## [0.17.0](https://github.com/jostled-org/pedant/compare/pedant-v0.16.0...pedant-v0.17.0) - 2026-03-28

### Added

- [**breaking**] high-param-count check, immutable-growable detection, structural duplicate tool

## [0.16.0](https://github.com/jostled-org/pedant/compare/pedant-v0.15.1...pedant-v0.16.0) - 2026-03-26

### Other

- [**breaking**] split semantic.rs into submodules and fix audit findings

## [0.15.1](https://github.com/jostled-org/pedant/compare/pedant-v0.15.0...pedant-v0.15.1) - 2026-03-25

### Other

- update Cargo.lock dependencies

## [0.15.0](https://github.com/jostled-org/pedant/compare/pedant-v0.14.0...pedant-v0.15.0) - 2026-03-25

### Added

- [**breaking**] add data flow analysis with taint tracking and reachability

### Fixed

- match glob overrides against absolute paths and opt-in MCP semantic

## [0.14.0](https://github.com/jostled-org/pedant/compare/pedant-v0.13.2...pedant-v0.14.0) - 2026-03-23

### Other

- [**breaking**] audit fixes and single-crate MCP support

## [0.13.2](https://github.com/jostled-org/pedant/compare/pedant-v0.13.1...pedant-v0.13.2) - 2026-03-22

### Added

- add pedant-mcp server for MCP-based capability queries

## [0.13.1](https://github.com/jostled-org/pedant/compare/pedant-v0.13.0...pedant-v0.13.1) - 2026-03-22

### Fixed

- *(pedant)* stop docs.rs from failing on binary-only crate

## [0.13.0](https://github.com/jostled-org/pedant/compare/pedant-v0.12.0...pedant-v0.13.0) - 2026-03-22

### Added

- [**breaking**] add semantic analysis via ra_ap_ide with performance audit fixes

## [0.12.0](https://github.com/jostled-org/pedant/compare/pedant-v0.11.0...pedant-v0.12.0) - 2026-03-22

### Added

- [**breaking**] add gate rules engine for capability profile evaluation

## [0.11.0](https://github.com/jostled-org/pedant/compare/pedant-v0.10.0...pedant-v0.11.0) - 2026-03-22

### Added

- [**breaking**] expand key material pattern detection in string literals

## [0.10.0](https://github.com/jostled-org/pedant/compare/pedant-v0.9.0...pedant-v0.10.0) - 2026-03-21

### Added

- [**breaking**] auto-discover and analyze build scripts for capability detection

## [0.9.0](https://github.com/jostled-org/pedant/compare/pedant-v0.8.0...pedant-v0.9.0) - 2026-03-21

### Added

- [**breaking**] add IR extraction, let-underscore-result check, and extract pedant-core library

### Other

- *(pedant)* add crate-level doc comment to main.rs
- bump pedant-types to 0.5.0 for Box<[CapabilityFinding]> breaking change

## [0.8.0](https://github.com/jostled-org/pedant/compare/pedant-v0.7.2...pedant-v0.8.0) - 2026-03-14

### Added

- [**breaking**] add --diff flag to compare capability profiles

## [0.7.2](https://github.com/jostled-org/pedant/compare/pedant-v0.7.1...pedant-v0.7.2) - 2026-03-13

### Other

- separate linting and capability detection in README

## [0.7.1](https://github.com/jostled-org/pedant/compare/pedant-v0.7.0...pedant-v0.7.1) - 2026-03-13

### Other

- add attestation usage to README and capability detection guide

## [0.7.0](https://github.com/jostled-org/pedant/compare/pedant-v0.6.1...pedant-v0.7.0) - 2026-03-13

### Other

- [**breaking**] audit remediation across pedant and pedant-types

## [0.6.1](https://github.com/jostled-org/pedant/compare/pedant-v0.6.0...pedant-v0.6.1) - 2026-03-08

### Other

- add capability detection guide and update READMEs

## [0.6.0](https://github.com/jostled-org/pedant/compare/pedant-v0.5.0...pedant-v0.6.0) - 2026-03-08

### Added

- *(pedant)* [**breaking**] add capability detection for unsafe, ffi, crypto, time, proc macros, and string literals

## [0.5.0](https://github.com/jostled-org/pedant/compare/pedant-v0.4.1...pedant-v0.5.0) - 2026-03-07

### Added

- *(pedant)* [**breaking**] add capability detection for network, filesystem, process, and env

### Fixed

- *(pedant)* add explicit version to pedant-types dependency

## [0.4.1](https://github.com/jostled-org/pedant/compare/pedant-v0.4.0...pedant-v0.4.1) - 2026-03-07

### Other

- *(reporter)* replace hand-rolled JSON with serde_json serialization

## [0.4.0](https://github.com/jostled-org/pedant/compare/pedant-v0.3.4...pedant-v0.4.0) - 2026-03-07

### Other

- [**breaking**] restructure into cargo workspace with pedant-types crate
