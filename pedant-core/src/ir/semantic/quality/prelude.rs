//! Imports shared by quality detector implementation modules.

pub(super) use std::collections::BTreeMap;

pub(super) use ra_ap_hir::Semantics;
pub(super) use ra_ap_ide::RootDatabase;
pub(super) use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, ast};

pub(super) use super::super::super::facts::{DataFlowFact, DataFlowKind, IrSpan};
pub(super) use super::super::common::{
    FnContext, expr_references_binding, extract_binding_name, quality_fact,
    resolve_call_to_function, span_from_node,
};
