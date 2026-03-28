# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
