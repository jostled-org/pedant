//! What one bounded Go fact inventory states as the type evidence a resolver
//! reads.
//!
//! A submodule of `tests/enclosing_unit.rs`, reached through a `#[path]`
//! attribute. It shares [`go_fact_source`](crate::go_fact_source)'s fixture
//! with the completeness case, because the types a source writes are only
//! meaningful beside the declarations and bindings that same inventory states.
//!
//! Every table here is written over every binding or every declaration rather
//! than over the ones that carry the evidence, so a walk that started guessing
//! a type where the grammar proves none fails as loudly as one that stopped
//! stating the type it does prove.

use pedant_syntax::go::{GoBindingFact, GoDeclarationFact, GoFileFacts, GoInitializerForm};

use crate::go_fact_source::complete_facts;

/// What every bound name's initializer states, in binding order.
///
/// A short variable declaration writes no type, so the initializer is the whole
/// evidence of what it binds. A map, a slice, a channel conversion, an address
/// taken of a call, and a declaration distributing results across several names
/// state none.
const INITIALIZERS: &[&str] = &[
    "n|none",
    "count|none",
    "sum|none",
    "local|none",
    "inner|none",
    "c|none",
    "n|none",
    "label|none",
    "raw|none",
    "value|literal|-|Config|false",
    "pointed|literal-address|-|Config|true",
    "foreign|literal|alias|Client|false",
    "called|call|-|build|false",
    "remote|call|alias|Get|false",
    "converted|call|-|Handle|false",
    "mapped|none",
    "sliced|none",
    "piped|none",
    "taken|none",
    "first|none",
    "second|none",
    "blocked|none",
    "client|none",
    "held|none",
    "linked|none",
];

/// What every bound name's own declaration writes as its type, in binding order.
///
/// A receiver, a parameter, a named result, and a `var` inside a body all write
/// their type, and the package that type belongs to is written beside it. A walk
/// that folded `alias.Client` into `Client` fails here as loudly as one that
/// stopped stating the type at all: the qualifier is what decides which package
/// a receiver's method set is read from, and `Client` and `Config` are both
/// names this file can see bare.
const DECLARED_TYPES: &[&str] = &[
    "n|-|int|false",
    "count|-|int|false",
    "sum|-|int|false",
    "local|-|-|false",
    "inner|-|int|false",
    "c|-|Config|true",
    "n|-|int|false",
    "label|-|-|false",
    "raw|-|int|false",
    "value|-|-|false",
    "pointed|-|-|false",
    "foreign|-|-|false",
    "called|-|-|false",
    "remote|-|-|false",
    "converted|-|-|false",
    "mapped|-|-|false",
    "sliced|-|-|false",
    "piped|-|-|false",
    "taken|-|-|false",
    "first|-|-|false",
    "second|-|-|false",
    "blocked|-|-|false",
    "client|alias|Client|false",
    "held|-|Config|false",
    "linked|alias|Client|true",
];

/// What every declaration states as the single type its callable returns, in
/// declaration order.
///
/// A call's value carries a type only when the source writes exactly one. A
/// declaration that is no callable, a callable stating no result, several
/// results, an unnamed composite, and a pointer wrapping a shape the model names
/// no type for all state none here.
const DECLARED_RESULTS: &[&str] = &[
    "Limit|-|-|false",
    "Shared|-|-|false",
    "Config|-|-|false",
    "Retries|-|-|false",
    "Stringer|-|-|false",
    "Runner|-|-|false",
    "Run|-|error|false",
    "Handle|-|-|false",
    "Alias|-|-|false",
    "build|-|-|false",
    "Run|-|error|false",
    "shapes|-|-|false",
    "spawn|-|Config|true",
    "fetch|alias|Client|false",
    "pair|-|-|false",
    "table|-|-|false",
    "boxed|-|-|true",
    "serve|-|-|false",
];

/// 5.T9 (Invariants 1-3): one bounded inventory states the written type, the
/// initializer, and the declared result of every name Step 5 resolves.
#[test]
fn go_file_facts_state_every_written_type_and_initializer() {
    let facts = complete_facts();

    assert_initializers(&facts);
    assert_declared_types(&facts);
    assert_declared_results(&facts);
}

/// Every binding's initializer evidence, compared as one ordered list.
fn assert_initializers(facts: &GoFileFacts<'_>) {
    let stated: Box<[String]> = facts.bindings().iter().map(initializer_row).collect();
    let borrowed: Box<[&str]> = stated.iter().map(String::as_str).collect();
    assert_eq!(
        &*borrowed, INITIALIZERS,
        "an initializer states the type its shape names, and nothing where its shape names none"
    );
}

/// One binding's initializer as this module compares it: the bound name, the
/// form, the qualifier and name it states, and whether it is a pointer.
fn initializer_row(bound: &GoBindingFact<'_>) -> String {
    let Some(stated) = bound.initializer() else {
        return format!("{}|none", bound.name());
    };
    format!(
        "{}|{}|{}|{}|{}",
        bound.name(),
        form_name(stated.form()),
        stated.qualifier().unwrap_or("-"),
        stated.name(),
        stated.pointer()
    )
}

/// The spelling one initializer form is written down as.
///
/// Spelled out rather than derived from `Debug`, so a form added to the closed
/// set is a table this module must revise rather than a row whose text changes
/// under it.
fn form_name(form: GoInitializerForm) -> &'static str {
    match form {
        GoInitializerForm::CompositeLiteral => "literal",
        GoInitializerForm::CompositeLiteralAddress => "literal-address",
        GoInitializerForm::Call => "call",
    }
}

/// Every binding's written type, compared as one ordered list.
fn assert_declared_types(facts: &GoFileFacts<'_>) {
    let stated: Box<[String]> = facts.bindings().iter().map(declared_type_row).collect();
    let borrowed: Box<[&str]> = stated.iter().map(String::as_str).collect();
    assert_eq!(
        &*borrowed, DECLARED_TYPES,
        "a binding states the type its declaration writes, with the package that type names"
    );
}

/// One binding's written type as this module compares it: the bound name, then
/// the qualifier, the name, and the pointer form of the type it writes.
fn declared_type_row(bound: &GoBindingFact<'_>) -> String {
    format!(
        "{}|{}|{}|{}",
        bound.name(),
        bound.type_qualifier().unwrap_or("-"),
        bound.type_name().unwrap_or("-"),
        bound.pointer()
    )
}

/// Every declaration's declared result, compared as one ordered list.
fn assert_declared_results(facts: &GoFileFacts<'_>) {
    let stated: Box<[String]> = facts.declarations().iter().map(result_row).collect();
    let borrowed: Box<[&str]> = stated.iter().map(String::as_str).collect();
    assert_eq!(
        &*borrowed, DECLARED_RESULTS,
        "a declaration states the single result type its source writes, and none where it writes no single type"
    );
}

/// One declaration's result as this module compares it: the declared name, then
/// the qualifier, the name, and the pointer form of the result it states.
///
/// The pointer form is rendered even where the result names no type, because it
/// is read off the source rather than derived from the name: `*[]Config` states
/// a pointer to a shape the model names no single type for.
fn result_row(declared: &GoDeclarationFact<'_>) -> String {
    format!(
        "{}|{}|{}|{}",
        declared.name(),
        declared.result_qualifier().unwrap_or("-"),
        declared.result_name().unwrap_or("-"),
        declared.result_pointer()
    )
}
