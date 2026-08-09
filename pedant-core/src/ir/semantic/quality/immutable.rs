//! Immutable-growable detection.

use super::prelude::*;

// --- Immutable growable detection ---

/// Detect Vec/String bindings that are never mutated after construction.
///
/// Uses precomputed mutation, return, and `&mut` pass flags from `FnContext`
/// instead of rescanning the statement list per binding.
pub(super) fn detect_immutable_growable(ctx: &FnContext<'_, '_>, out: &mut Vec<DataFlowFact>) {
    for stmt in ctx.stmts.iter() {
        let ast::Stmt::LetStmt(let_stmt) = &stmt else {
            continue;
        };
        let Some(pat) = let_stmt.pat() else { continue };
        let Some(name) = extract_binding_name(&pat) else {
            continue;
        };
        let ann = classify_via_annotation(let_stmt);
        let sem = classify_via_semantics(ctx.sema, let_stmt, ctx.db);
        let Some(type_label) = ann.or(sem) else {
            continue;
        };

        if ctx.binding_is_mutated(&name)
            || ctx.binding_is_returned(&name)
            || ctx.binding_passed_as_mut_ref(&name)
        {
            continue;
        }

        let span = ctx.span(let_stmt.syntax());
        out.push(quality_fact(
            DataFlowKind::ImmutableGrowable,
            span,
            span,
            format!(
                "`{name}` is a {type_label} that is never mutated; consider Box<[T]> or Box<str>"
            )
            .into_boxed_str(),
        ));
    }
}

/// Classify via RA semantic type resolution.
fn classify_via_semantics(
    sema: &Semantics<'_, RootDatabase>,
    let_stmt: &ast::LetStmt,
    db: &RootDatabase,
) -> Option<&'static str> {
    let ty = let_stmt
        .initializer()
        .and_then(|init| sema.type_of_expr(&init))
        .map(|ti| ti.original)
        .or_else(|| {
            let_stmt
                .pat()
                .and_then(|pat| sema.type_of_pat(&pat))
                .map(|ti| ti.original)
        })?;

    let adt = ty.as_adt()?;
    let adt_name = adt.name(db);
    match adt_name.as_str() {
        "Vec" => Some("Vec"),
        "String" => Some("String"),
        _ => None,
    }
}

/// Classify via explicit type annotation on the let statement.
fn classify_via_annotation(let_stmt: &ast::LetStmt) -> Option<&'static str> {
    let ty = let_stmt.ty()?;
    let syntax_text = ty.syntax().text();
    if syntax_text == "String" {
        return Some("String");
    }
    // SyntaxText lacks starts_with; allocate only for the Vec prefix check.
    let text = syntax_text.to_string();
    match text.starts_with("Vec<") || text.starts_with("Vec ") || text == "Vec" {
        true => Some("Vec"),
        false => None,
    }
}
