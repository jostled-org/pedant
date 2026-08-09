//! Capability-sink classification.

use super::prelude::*;

// ---------------------------------------------------------------------------
// Capability sink classification (shared with taint detection)
// ---------------------------------------------------------------------------

/// Known module segments that indicate a capability sink.
pub(super) const SINK_MODULES: &[(&str, Capability)] = &[
    ("net", Capability::Network),
    ("process", Capability::ProcessExec),
];

/// Classify a resolved function as a capability sink by checking its module path.
pub(super) fn classify_function_as_sink(
    func: ra_ap_hir::Function,
    db: &RootDatabase,
) -> Option<Capability> {
    match_sink_in_module(func.module(db), db)
}

/// Walk a module's ancestors to find a known sink module segment.
pub(super) fn match_sink_in_module(
    module: ra_ap_hir::Module,
    db: &RootDatabase,
) -> Option<Capability> {
    let mut current = Some(module);
    while let Some(m) = current {
        let cap = m
            .name(db)
            .and_then(|name| classify_segment_as_sink(name.as_str()));
        match cap {
            Some(_) => return cap,
            None => current = m.parent(db),
        }
    }
    None
}

/// Check whether a single module name matches a known sink.
pub(super) fn classify_segment_as_sink(name: &str) -> Option<Capability> {
    SINK_MODULES
        .iter()
        .find_map(|(segment, cap)| (*segment == name).then_some(*cap))
}

/// Classify an associated function call by resolving the qualifier type's module.
///
/// Handles calls like `TcpStream::connect` where `resolve_call_to_function`
/// returns `None` but the qualifier resolves to an ADT in a known sink module.
pub(super) fn classify_qualified_call_by_type(
    sema: &Semantics<'_, RootDatabase>,
    call: &ast::CallExpr,
    db: &RootDatabase,
) -> Option<Capability> {
    let expr = call.expr()?;
    let path_expr = ast::PathExpr::cast(expr.syntax().clone())?;
    let path = path_expr.path()?;
    let qualifier = path.qualifier()?;
    let resolution = sema.resolve_path(&qualifier)?;
    match resolution {
        ra_ap_hir::PathResolution::Def(module_def) => {
            let module = module_def_module(module_def, db)?;
            match_sink_in_module(module, db)
        }
        _ => None,
    }
}

/// Get the defining module for a `ModuleDef`.
pub(super) fn module_def_module(
    def: ra_ap_hir::ModuleDef,
    db: &RootDatabase,
) -> Option<ra_ap_hir::Module> {
    match def {
        ra_ap_hir::ModuleDef::Adt(adt) => Some(adt.module(db)),
        ra_ap_hir::ModuleDef::Function(f) => Some(f.module(db)),
        ra_ap_hir::ModuleDef::Module(m) => Some(m),
        ra_ap_hir::ModuleDef::TypeAlias(ta) => Some(ta.module(db)),
        ra_ap_hir::ModuleDef::Trait(t) => Some(t.module(db)),
        _ => None,
    }
}
