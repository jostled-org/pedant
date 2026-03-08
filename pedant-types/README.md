[![crates.io](https://img.shields.io/crates/v/pedant-types)](https://crates.io/crates/pedant-types)
[![docs.rs](https://img.shields.io/docsrs/pedant-types)](https://docs.rs/pedant-types)
[![CI](https://github.com/jostled-org/pedant/actions/workflows/ci.yml/badge.svg)](https://github.com/jostled-org/pedant/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/pedant-types)](https://crates.io/crates/pedant-types)

You want to consume pedant's capability analysis output without pulling in the linter.

**pedant-types** is the shared type library for [pedant](https://crates.io/crates/pedant) capability attestations. It defines the serialization-stable types that flow between analysis, diffing, and reporting.

## Types

| Type | Purpose |
|------|---------|
| `Capability` | Enum of 10 capabilities a crate may exercise (network, file I/O, process exec, etc.) |
| `CapabilityFinding` | A capability detected at a specific `SourceLocation` with evidence |
| `CapabilityProfile` | Collection of findings with dedup and filtering |
| `AttestationContent` | Full attestation: source hash, crate identity, analysis tier, profile |
| `CapabilityDiff` | Diff between two profiles — added/removed findings and capabilities |
| `AnalysisTier` | Depth of analysis: `Syntactic`, `Semantic`, `DataFlow` |

## Usage

```rust
use pedant_types::{Capability, CapabilityDiff, CapabilityProfile};

let old: CapabilityProfile = serde_json::from_str(&old_json)?;
let new: CapabilityProfile = serde_json::from_str(&new_json)?;
let diff = CapabilityDiff::compute(&old, &new);

for cap in &diff.new_capabilities {
    println!("new capability: {cap:?}");
}
```

## Installation

```bash
cargo add pedant-types
```

## License

[MIT](https://github.com/jostled-org/pedant/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/jostled-org/pedant/blob/main/LICENSE-APACHE), at your option.
