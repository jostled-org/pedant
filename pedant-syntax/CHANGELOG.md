# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/jostled-org/pedant/releases/tag/pedant-syntax-v0.1.0) - 2026-08-02

### Added

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
