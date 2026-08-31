# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1](https://github.com/jostled-org/pedant/compare/pedant-graph-v0.5.0...pedant-graph-v0.5.1) - 2026-08-31

### Other

- updated the following local packages: pedant-core, pedant-core

## [0.5.0](https://github.com/jostled-org/pedant/compare/pedant-graph-v0.4.0...pedant-graph-v0.5.0) - 2026-08-30

### Added

- [**breaking**] implement code-intelligence-index-and-surfaces

## [0.4.0](https://github.com/jostled-org/pedant/compare/pedant-graph-v0.3.0...pedant-graph-v0.4.0) - 2026-08-23

### Added

- *(graph)* [**breaking**] project a go resolution into the same code graph
- *(resolution)* [**breaking**] widen the shared report vocabulary for Go

### Other

- hoist every duplicated body into the one owner that states it
- hoist every duplicated language check into one owner
- *(graph)* read every go graph after its repository is gone
- *(graph)* prove retention stays rust-only after the neutral split
- *(graph)* mint every graph through one language-neutral assembler

## [0.3.0](https://github.com/jostled-org/pedant/compare/pedant-graph-v0.2.0...pedant-graph-v0.3.0) - 2026-08-18

### Added

- [**breaking**] implement module-boundary-integrity

## [0.2.0](https://github.com/jostled-org/pedant/compare/pedant-graph-v0.1.2...pedant-graph-v0.2.0) - 2026-08-14

### Added

- [**breaking**] implement graph-incremental-cache
- implement graph-queries-and-condensation

### Fixed

- *(graph)* enforce concrete cache example errors

## [0.1.2](https://github.com/jostled-org/pedant/compare/pedant-graph-v0.1.1...pedant-graph-v0.1.2) - 2026-08-13

### Other

- updated the following local packages: pedant-core, pedant-core

## [0.1.1](https://github.com/jostled-org/pedant/compare/pedant-graph-v0.1.0...pedant-graph-v0.1.1) - 2026-08-13

### Other

- updated the following local packages: pedant-core, pedant-core

## [0.1.0](https://github.com/jostled-org/pedant/releases/tag/pedant-graph-v0.1.0) - 2026-08-13

### Added

- [**breaking**] implement code-structure-graph
- [**breaking**] implement syntax-substrate-and-snippet-tool
- *(checks)* [**breaking**] count high-method-count across files, add scattered-inherent-impl
- *(checks)* [**breaking**] add feature-boundary check over Cargo metadata
- *(checks)* [**breaking**] add flat-module-family check
- *(checks)* [**breaking**] add project-level pass and conflicting-module-root check
- *(checks)* [**breaking**] add ungated-test-api check
- *(checks)* [**breaking**] add item-visibility-policy check
- *(checks)* [**breaking**] add forwarder-aware high-method-count check
- *(checks)* [**breaking**] add large-source-file check with warn/deny severity
- *(checks)* [**breaking**] add module-root-definitions check
- *(checks)* [**breaking**] add long-function-body check
- *(cli)* [**breaking**] migrate to subcommands and cargo supply-chain
- add supply chain check action and rewrite documentation
- [**breaking**] high-param-count check, immutable-growable detection, structural duplicate tool
- [**breaking**] add data flow analysis with taint tracking and reachability
- add pedant-mcp server for MCP-based capability queries
- [**breaking**] auto-discover and analyze build scripts for capability detection
- [**breaking**] add IR extraction, let-underscore-result check, and extract pedant-core library
- [**breaking**] add --diff flag to compare capability profiles

### Fixed

- *(ci)* pin shellcheck and defer unsafe releases
- match glob overrides against absolute paths and opt-in MCP semantic

### Other

- *(supply-chain)* gate on new-dependency to catch injected crates
- correct the README against what pedant actually does
- [**breaking**] split semantic.rs into submodules and fix audit findings
- separate linting and capability detection in README
- add attestation usage to README and capability detection guide
- add capability detection guide and update READMEs
- add generic-naming to README, examples, and fix CI glob
- rewrite README following org guidelines
- updated README and added example configs
- update install instructions to use crates.io
- pedant 0.1.0
