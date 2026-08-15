//! Gate rules engine: judges capability profiles, data flows, and declared
//! module boundaries against local policy.
//!
//! Capability-combination rules fire on suspicious co-occurrence of
//! capabilities, flow-aware rules fire when taint analysis detects a data path
//! from source to sink, and module-boundary rules fire on validated
//! graph-neutral structural facts supplied by a composition owner. No rule in
//! this family names a graph type or recomputes graph structure.

mod capability;
mod catalog;
mod module_boundary;
mod verdict;

pub use capability::{GateInputSummary, evaluate_gate_rules};
pub use catalog::{
    GateRuleInfo, all_gate_rules, all_module_boundary_rules, is_gate_rule, is_module_boundary_rule,
};
pub use module_boundary::{
    ModuleBoundaryFact, ModuleBoundaryInput, ModuleBoundaryInputError,
    evaluate_module_boundary_rules,
};
pub use verdict::{
    GateAnchor, GateEvidence, GateLocation, GateSeverity, GateVerdict, ModuleBoundaryEntity,
    ModuleBoundaryEvidence, ModuleBoundaryMeasurement,
};
