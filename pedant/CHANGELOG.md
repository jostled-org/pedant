# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
