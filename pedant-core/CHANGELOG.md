# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.22.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.21.2...pedant-core-v0.22.0) - 2026-08-18

### Added

- *(lang)* [**breaking**] attribute non-Rust capability findings to their callables
- *(core)* [**breaking**] attribute Rust capability findings to their callables
- [**breaking**] implement module-boundary-integrity

### Other

- give each attribution rule one owner and one query
- *(release)* prove one workspace-wide packaging invocation
- *(release)* prove absolute packaged target roots
- *(release)* prove packaged members are extracted archives
- *(release)* prove exact packaged budget mapping
- split the packaged workspace proof into tool and release stages
- *(ci)* prove the packaged graph refuses every unreleaseable shape
- prove the packaged release archives compile together
- add tracked cargo infrastructure classifier

## [0.21.2](https://github.com/jostled-org/pedant/compare/pedant-core-v0.21.1...pedant-core-v0.21.2) - 2026-08-13

### Fixed

- *(resolution)* anchor inline paths to declaring sources

## [0.21.1](https://github.com/jostled-org/pedant/compare/pedant-core-v0.21.0...pedant-core-v0.21.1) - 2026-08-13

### Fixed

- *(resolution)* resolve children beside path overrides

## [0.21.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.20.2...pedant-core-v0.21.0) - 2026-08-13

### Added

- [**breaking**] implement code-structure-graph

### Fixed

- *(ci)* relocate checks and pin cargo-deny
- *(ci)* isolate lifecycle tooling from repository checks
- *(ci)* pin shellcheck and defer unsafe releases

### Other

- *(lifecycle)* enforce implemented graph status

## [0.20.2](https://github.com/jostled-org/pedant/compare/pedant-core-v0.20.1...pedant-core-v0.20.2) - 2026-08-10

### Other

- *(release)* derive published versions from the manifests

## [0.20.1](https://github.com/jostled-org/pedant/compare/pedant-core-v0.20.0...pedant-core-v0.20.1) - 2026-08-10

### Fixed

- *(ci)* allow private path dependencies
- *(ci)* repair platform and release validation

## [0.19.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.18.0...pedant-core-v0.19.0) - 2026-08-02

### Added

- [**breaking**] implement syntax-substrate-and-snippet-tool
- [**breaking**] implement analysis-surface-split

## [0.18.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.17.0...pedant-core-v0.18.0) - 2026-07-18

### Fixed

- [**breaking**] honor .pedant.toml max_depth and stop counting closure nesting

## [0.17.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.16.0...pedant-core-v0.17.0) - 2026-07-18

### Added

- *(checks)* [**breaking**] count high-method-count across files, add scattered-inherent-impl

### Fixed

- *(capabilities)* stop reading OIDs, paths, and versions as network endpoints

### Other

- *(supply-chain)* gate on new-dependency to catch injected crates

## [0.16.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.15.0...pedant-core-v0.16.0) - 2026-07-17

### Other

- correct the README against what pedant actually does
- *(core)* [**breaking**] split extract.rs into responsibility-scoped modules
- *(core)* extract detector run out of SemanticFileAnalysis::build
- move definitions out of module roots into leaf modules

## [0.15.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.14.0...pedant-core-v0.15.0) - 2026-07-16

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

### Other

- *(core)* restore ConfigFile doc comment

## [0.14.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.13.0...pedant-core-v0.14.0) - 2026-07-15

### Other

- *(deps)* [**breaking**] update workspace dependencies and raise MSRV to 1.96

## [0.13.0](https://github.com/jostled-org/pedant/compare/pedant-core-v0.12.0...pedant-core-v0.13.0) - 2026-06-12

### Added

- [**breaking**] record skipped-file analysis errors in attestations

### Other

- *(core)* document workspace member resolution API

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
